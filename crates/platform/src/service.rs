//! The CleanDesk Service (spec §24).
//!
//! # Why a supervisor + helper
//!
//! A Windows service runs in *session 0*, which has no interactive desktop:
//! Desktop Duplication and `SendInput` only work from inside the console
//! session (the one showing the login screen or the user's desktop). So the
//! service itself never captures anything. It is a small supervisor that:
//!
//! 1. finds the active console session (`WTSGetActiveConsoleSessionId`),
//! 2. duplicates its own `LocalSystem` token into that session and launches
//!    `cleandesk.exe --host --data-dir <dir>` there with `CreateProcessAsUserW`
//!    (the standard technique for pre-login remote access),
//! 3. restarts the helper whenever it exits or the console session changes
//!    (logon, logoff, fast user switching all recreate the session).
//!
//! The helper is the ordinary headless host: it only accepts unattended
//! connections, and it stays idle while the GUI is open (see
//! [`crate::presence`]).
//!
//! # Install / uninstall
//!
//! Managing services needs administrator rights. [`request_install`] and
//! [`request_uninstall`] re-launch the executable elevated (UAC prompt) with
//! `--install-service` / `--uninstall-service`; those modes call
//! [`install_here`] / [`uninstall_here`], which drive `sc.exe`.

use crate::Result;
use std::path::{Path, PathBuf};

/// Service name registered with the SCM.
pub const SERVICE_NAME: &str = "CleanDesk";
/// Human-readable display name.
pub const DISPLAY_NAME: &str = "CleanDesk Remote Access";
/// Description shown in `services.msc`.
pub const DESCRIPTION: &str =
    "Keeps CleanDesk available for unattended access before sign-in and after sign-out.";

/// Installed state as reported by the SCM.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceStatus {
    NotInstalled,
    Stopped,
    Running,
    /// Installed but in a transient state (starting, stopping, paused…).
    Other,
}

/// Command-line arguments for the service's helper host.
pub fn helper_args(data_dir: &Path) -> Vec<String> {
    vec![
        "--host".to_string(),
        "--data-dir".to_string(),
        data_dir.to_string_lossy().to_string(),
        "--log-file".to_string(),
        data_dir.join("host.log").to_string_lossy().to_string(),
    ]
}

/// Parse `sc.exe query` output into a [`ServiceStatus`]. Pure; tested.
pub fn parse_sc_query(exit_code: i32, output: &str) -> ServiceStatus {
    // 1060 = ERROR_SERVICE_DOES_NOT_EXIST.
    if exit_code == 1060 || output.contains("1060") {
        return ServiceStatus::NotInstalled;
    }
    let upper = output.to_uppercase();
    if upper.contains("RUNNING") {
        ServiceStatus::Running
    } else if upper.contains("STOPPED") {
        ServiceStatus::Stopped
    } else if upper.contains("STATE") {
        ServiceStatus::Other
    } else {
        ServiceStatus::NotInstalled
    }
}

#[cfg(windows)]
mod imp {
    use super::*;
    use crate::{build_command_line, PlatformError};
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::process::CommandExt;
    use std::process::Command;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::time::Duration;
    use tracing::{error, info, warn};
    use windows::core::PWSTR;
    use windows::Win32::Foundation::{CloseHandle, HANDLE, WAIT_OBJECT_0};
    use windows::Win32::Security::{
        DuplicateTokenEx, SecurityIdentification, SetTokenInformation, TokenPrimary, TokenSessionId,
        TOKEN_ALL_ACCESS,
    };
    use windows::Win32::System::Environment::{CreateEnvironmentBlock, DestroyEnvironmentBlock};
    use windows::Win32::System::RemoteDesktop::WTSGetActiveConsoleSessionId;
    use windows::Win32::System::Threading::{
        CreateProcessAsUserW, GetCurrentProcess, OpenProcessToken, TerminateProcess,
        WaitForSingleObject, CREATE_NO_WINDOW, CREATE_UNICODE_ENVIRONMENT, PROCESS_INFORMATION, STARTUPINFOW,
    };
    use windows_service::service::{
        ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus as WsStatus,
        ServiceType,
    };
    use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
    use windows_service::service_dispatcher;

    fn sc(args: &[&str]) -> (i32, String) {
        // CREATE_NO_WINDOW: sin ventana de consola parpadeando sobre la GUI.
        match Command::new("sc.exe").args(args).creation_flags(0x0800_0000).output() {
            Ok(out) => (
                out.status.code().unwrap_or(-1),
                String::from_utf8_lossy(&out.stdout).to_string() + &String::from_utf8_lossy(&out.stderr),
            ),
            Err(e) => (-1, e.to_string()),
        }
    }

    fn sc_ok(args: &[&str]) -> Result<String> {
        let (code, out) = sc(args);
        if code == 0 {
            Ok(out)
        } else {
            Err(PlatformError::Tool { tool: "sc.exe", code, output: out })
        }
    }

    /// Query the SCM. Never needs elevation.
    pub fn status() -> ServiceStatus {
        let (code, out) = sc(&["query", SERVICE_NAME]);
        parse_sc_query(code, &out)
    }

    /// Create + start the service. Must already run elevated.
    pub fn install_here(exe: &Path, data_dir: &Path) -> Result<()> {
        let bin = build_command_line([
            exe.to_string_lossy().as_ref(),
            "--service",
            "--data-dir",
            data_dir.to_string_lossy().as_ref(),
        ]);
        // sc.exe parses `option=` and its value as two separate argv tokens
        // ("start=", "auto"). Passing "start= auto" as one argument (what a
        // quoted string with a space becomes) is rejected with exit 1639.
        match status() {
            ServiceStatus::NotInstalled => {
                sc_ok(&["create", SERVICE_NAME, "binPath=", &bin, "start=", "auto", "DisplayName=", DISPLAY_NAME])?;
            }
            _ => {
                // Already installed: update the path (exe may have moved).
                sc_ok(&["config", SERVICE_NAME, "binPath=", &bin, "start=", "auto"])?;
            }
        }
        let _ = sc(&["description", SERVICE_NAME, DESCRIPTION]);
        // Restart automatically if it ever dies.
        let _ = sc(&["failure", SERVICE_NAME, "reset=", "86400", "actions=", "restart/5000/restart/10000/restart/30000"]);
        if status() != ServiceStatus::Running {
            sc_ok(&["start", SERVICE_NAME])?;
        }
        Ok(())
    }

    /// Stop + delete the service. Must already run elevated.
    pub fn uninstall_here() -> Result<()> {
        if status() == ServiceStatus::NotInstalled {
            return Ok(());
        }
        let _ = sc(&["stop", SERVICE_NAME]);
        // Give the SCM a moment to finish stopping before deleting.
        for _ in 0..20 {
            if status() != ServiceStatus::Running {
                break;
            }
            std::thread::sleep(Duration::from_millis(250));
        }
        sc_ok(&["delete", SERVICE_NAME])?;
        Ok(())
    }

    fn wide(s: &OsStr) -> Vec<u16> {
        s.encode_wide().chain(std::iter::once(0)).collect()
    }

    /// Ask (with a UAC prompt) to install and start the service for `exe`.
    pub fn request_install(exe: &Path, data_dir: &Path) -> Result<()> {
        let code = crate::elevation::run_elevated_wait(exe, &["--install-service", "--data-dir", &data_dir.to_string_lossy()])?;
        if code != 0 {
            return Err(PlatformError::Other(format!(
                "installation exited with code {code}; see service-install.log in the data folder"
            )));
        }
        Ok(())
    }

    /// Ask (with a UAC prompt) to stop and remove the service.
    pub fn request_uninstall(exe: &Path) -> Result<()> {
        let code = crate::elevation::run_elevated_wait(exe, &["--uninstall-service"])?;
        if code != 0 {
            return Err(PlatformError::Other(format!("uninstall exited with code {code}")));
        }
        Ok(())
    }

    /// A child process launched into the console session.
    pub struct Helper {
        process: HANDLE,
        thread: HANDLE,
        pub session: u32,
        pub pid: u32,
    }

    impl Helper {
        pub fn is_running(&self) -> bool {
            // SAFETY: `process` is a valid handle we own.
            unsafe { WaitForSingleObject(self.process, 0) != WAIT_OBJECT_0 }
        }

        pub fn kill(&self) {
            // SAFETY: valid handle; TerminateProcess on our own child.
            unsafe {
                let _ = TerminateProcess(self.process, 0);
            }
        }
    }

    impl Drop for Helper {
        fn drop(&mut self) {
            // SAFETY: handles are valid and owned; closing twice is prevented by Drop.
            unsafe {
                let _ = CloseHandle(self.thread);
                let _ = CloseHandle(self.process);
            }
        }
    }

    /// The session id when no console session exists (0xFFFFFFFF).
    const NO_SESSION: u32 = u32::MAX;

    /// Launch `exe args...` as LocalSystem inside the active console session.
    pub fn spawn_in_console_session(exe: &Path, args: &[String]) -> Result<Helper> {
        // SAFETY: sequence of documented Win32 calls; every handle obtained is
        // closed on all paths, and all pointers refer to live locals.
        unsafe {
            let session = WTSGetActiveConsoleSessionId();
            if session == NO_SESSION {
                return Err(PlatformError::Other("no active console session".into()));
            }

            let mut own = HANDLE::default();
            OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &mut own)
                .map_err(|e| PlatformError::Win(format!("OpenProcessToken: {e}")))?;
            let mut token = HANDLE::default();
            let dup = DuplicateTokenEx(own, TOKEN_ALL_ACCESS, None, SecurityIdentification, TokenPrimary, &mut token);
            let _ = CloseHandle(own);
            dup.map_err(|e| PlatformError::Win(format!("DuplicateTokenEx: {e}")))?;

            let set = SetTokenInformation(
                token,
                TokenSessionId,
                &session as *const u32 as *const std::ffi::c_void,
                std::mem::size_of::<u32>() as u32,
            );
            if let Err(e) = set {
                let _ = CloseHandle(token);
                return Err(PlatformError::Win(format!("SetTokenInformation(session): {e}")));
            }

            let mut env: *mut std::ffi::c_void = std::ptr::null_mut();
            if let Err(e) = CreateEnvironmentBlock(&mut env, Some(token), false) {
                let _ = CloseHandle(token);
                return Err(PlatformError::Win(format!("CreateEnvironmentBlock: {e}")));
            }

            let exe_str = exe.to_string_lossy();
            let all = std::iter::once(exe_str.as_ref()).chain(args.iter().map(String::as_str));
            let mut cmdline = wide(OsStr::new(&build_command_line(all)));
            let mut desktop = wide(OsStr::new("winsta0\\default"));
            let si = STARTUPINFOW {
                cb: std::mem::size_of::<STARTUPINFOW>() as u32,
                lpDesktop: PWSTR(desktop.as_mut_ptr()),
                ..Default::default()
            };
            let mut pi = PROCESS_INFORMATION::default();
            let created = CreateProcessAsUserW(
                Some(token),
                None,
                Some(PWSTR(cmdline.as_mut_ptr())),
                None,
                None,
                false,
                CREATE_UNICODE_ENVIRONMENT | CREATE_NO_WINDOW,
                Some(env),
                None,
                &si,
                &mut pi,
            );
            let _ = DestroyEnvironmentBlock(env);
            let _ = CloseHandle(token);
            created.map_err(|e| PlatformError::Win(format!("CreateProcessAsUserW: {e}")))?;
            info!(session, pid = pi.dwProcessId, "helper host launched in console session");
            Ok(Helper { process: pi.hProcess, thread: pi.hThread, session, pid: pi.dwProcessId })
        }
    }

    /// Body of the service: keep a helper alive in the console session until
    /// `stop` is set.
    fn supervise(exe: PathBuf, data_dir: PathBuf, stop: Arc<AtomicBool>) {
        let args = helper_args(&data_dir);
        let mut helper: Option<Helper> = None;
        let mut backoff = Duration::from_secs(2);
        while !stop.load(Ordering::Relaxed) {
            // SAFETY: no preconditions.
            let session = unsafe { WTSGetActiveConsoleSessionId() };
            let needs_restart = match &helper {
                None => true,
                Some(h) => !h.is_running() || (session != NO_SESSION && h.session != session),
            };
            if needs_restart {
                if let Some(h) = helper.take() {
                    if h.is_running() {
                        info!(pid = h.pid, old = h.session, new = session, "console session changed; restarting helper");
                        h.kill();
                    } else {
                        info!(pid = h.pid, "helper exited; relaunching");
                    }
                }
                if session != NO_SESSION {
                    match spawn_in_console_session(&exe, &args) {
                        Ok(h) => {
                            helper = Some(h);
                            backoff = Duration::from_secs(2);
                        }
                        Err(e) => {
                            warn!(error = %e, ?backoff, "could not launch helper; will retry");
                            std::thread::sleep(backoff);
                            backoff = (backoff * 2).min(Duration::from_secs(60));
                        }
                    }
                }
            }
            std::thread::sleep(Duration::from_secs(2));
        }
        if let Some(h) = helper.take() {
            h.kill();
        }
    }

    /// Entry point for `--service`: hands control to the SCM dispatcher.
    /// Blocks until the service is stopped.
    pub fn run_service(exe: PathBuf, data_dir: PathBuf) -> Result<()> {
        // The dispatcher calls back on another thread with no arguments, so
        // stash what it needs in statics.
        SERVICE_ARGS.set((exe, data_dir)).map_err(|_| PlatformError::Other("service already started".into()))?;
        service_dispatcher::start(SERVICE_NAME, ffi_service_main)
            .map_err(|e| PlatformError::Win(format!("service dispatcher: {e}")))
    }

    static SERVICE_ARGS: std::sync::OnceLock<(PathBuf, PathBuf)> = std::sync::OnceLock::new();

    windows_service::define_windows_service!(ffi_service_main, service_main);

    fn service_main(_arguments: Vec<std::ffi::OsString>) {
        let Some((exe, data_dir)) = SERVICE_ARGS.get().cloned() else {
            error!("service arguments missing");
            return;
        };
        let stop = Arc::new(AtomicBool::new(false));
        let stop_for_handler = stop.clone();
        let handler = move |control| match control {
            ServiceControl::Stop | ServiceControl::Shutdown => {
                stop_for_handler.store(true, Ordering::Relaxed);
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        };
        let status_handle = match service_control_handler::register(SERVICE_NAME, handler) {
            Ok(h) => h,
            Err(e) => {
                error!(error = %e, "could not register service control handler");
                return;
            }
        };
        let set = |state: ServiceState| {
            let _ = status_handle.set_service_status(WsStatus {
                service_type: ServiceType::OWN_PROCESS,
                current_state: state,
                controls_accepted: ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
                exit_code: ServiceExitCode::Win32(0),
                checkpoint: 0,
                wait_hint: Duration::from_secs(10),
                process_id: None,
            });
        };
        set(ServiceState::Running);
        info!("CleanDesk Service running");
        supervise(exe, data_dir, stop);
        set(ServiceState::Stopped);
        info!("CleanDesk Service stopped");
    }
}

#[cfg(not(windows))]
mod imp {
    use super::*;
    use crate::PlatformError;

    pub fn status() -> ServiceStatus {
        ServiceStatus::NotInstalled
    }
    pub fn install_here(_exe: &Path, _data_dir: &Path) -> Result<()> {
        Err(PlatformError::Unsupported)
    }
    pub fn uninstall_here() -> Result<()> {
        Err(PlatformError::Unsupported)
    }
    pub fn request_install(_exe: &Path, _data_dir: &Path) -> Result<()> {
        Err(PlatformError::Unsupported)
    }
    pub fn request_uninstall(_exe: &Path) -> Result<()> {
        Err(PlatformError::Unsupported)
    }
    pub fn run_service(_exe: PathBuf, _data_dir: PathBuf) -> Result<()> {
        Err(PlatformError::Unsupported)
    }
}

pub use imp::{install_here, request_install, request_uninstall, run_service, status, uninstall_here};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sc_query_parsing() {
        assert_eq!(parse_sc_query(1060, "[SC] EnumQueryServicesStatus:OpenService FAILED 1060"), ServiceStatus::NotInstalled);
        assert_eq!(parse_sc_query(0, "SERVICE_NAME: CleanDesk\n        STATE              : 4  RUNNING"), ServiceStatus::Running);
        assert_eq!(parse_sc_query(0, "        STATE              : 1  STOPPED"), ServiceStatus::Stopped);
        assert_eq!(parse_sc_query(0, "        STATE              : 2  START_PENDING"), ServiceStatus::Other);
        assert_eq!(parse_sc_query(-1, ""), ServiceStatus::NotInstalled);
    }

    #[test]
    fn helper_args_shape() {
        let a = helper_args(Path::new("C:\\data dir"));
        assert_eq!(&a[..3], &["--host", "--data-dir", "C:\\data dir"]);
        assert_eq!(a[3], "--log-file");
        assert!(a[4].ends_with("host.log"));
    }
}
