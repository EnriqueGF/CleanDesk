//! Process elevation (spec §24, privileged control).
//!
//! A medium-integrity process cannot send input to windows of an elevated
//! (administrator) program: UIPI silently drops it. CleanDesk therefore offers
//! *privileged control*: preferably the CleanDesk service hosts (it runs as
//! LocalSystem and can even follow the UAC secure desktop, see
//! [`crate::desktop`]); when the service is not installed, the app can
//! relaunch itself elevated so at least administrator windows on the normal
//! desktop can be driven.

use std::path::Path;

use crate::{build_command_line, Result};

/// Is the current process running elevated (high integrity / administrator)?
pub fn is_elevated() -> bool {
    imp::is_elevated()
}

/// Start `exe args...` elevated through the UAC prompt and return at once
/// (the caller usually exits so the elevated copy takes over).
/// Errors with [`crate::PlatformError::ElevationDeclined`] when the user
/// presses "No".
pub fn relaunch_elevated(exe: &Path, args: &[String]) -> Result<()> {
    imp::spawn_elevated(exe, args, false).map(|_| ())
}

/// Run `exe args...` elevated and wait (up to two minutes) for its exit code.
/// Used by the service installer.
pub fn run_elevated_wait(exe: &Path, args: &[&str]) -> Result<i32> {
    let owned: Vec<String> = args.iter().map(|s| s.to_string()).collect();
    imp::spawn_elevated(exe, &owned, true)
}

#[cfg(windows)]
mod imp {
    use super::*;
    use crate::PlatformError;
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::Security::{GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY};
    use windows::Win32::System::Threading::{
        GetCurrentProcess, GetExitCodeProcess, OpenProcessToken, WaitForSingleObject,
    };
    use windows::Win32::UI::Shell::{ShellExecuteExW, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW};
    use windows::Win32::UI::WindowsAndMessaging::{SW_HIDE, SW_SHOWNORMAL};

    fn wide(s: &OsStr) -> Vec<u16> {
        s.encode_wide().chain(std::iter::once(0)).collect()
    }

    pub fn is_elevated() -> bool {
        // SAFETY: standard token query on our own process; handles are closed.
        unsafe {
            let mut token = Default::default();
            if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).is_err() {
                return false;
            }
            let mut info = TOKEN_ELEVATION::default();
            let mut len = 0u32;
            let ok = GetTokenInformation(
                token,
                TokenElevation,
                Some((&mut info as *mut TOKEN_ELEVATION).cast()),
                std::mem::size_of::<TOKEN_ELEVATION>() as u32,
                &mut len,
            );
            let _ = CloseHandle(token);
            ok.is_ok() && info.TokenIsElevated != 0
        }
    }

    pub fn spawn_elevated(exe: &Path, args: &[String], wait: bool) -> Result<i32> {
        let verb = wide(OsStr::new("runas"));
        let file = wide(exe.as_os_str());
        let params = wide(OsStr::new(&build_command_line(args.iter().map(String::as_str))));
        let mut info = SHELLEXECUTEINFOW {
            cbSize: std::mem::size_of::<SHELLEXECUTEINFOW>() as u32,
            fMask: SEE_MASK_NOCLOSEPROCESS,
            lpVerb: windows::core::PCWSTR(verb.as_ptr()),
            lpFile: windows::core::PCWSTR(file.as_ptr()),
            lpParameters: windows::core::PCWSTR(params.as_ptr()),
            nShow: if wait { SW_HIDE.0 } else { SW_SHOWNORMAL.0 },
            ..Default::default()
        };
        // SAFETY: all wide strings outlive the call; `info` is fully initialised.
        unsafe {
            if ShellExecuteExW(&mut info).is_err() {
                // ERROR_CANCELLED (1223): the user pressed "No" on the UAC prompt.
                let err = windows::core::Error::from_thread();
                return Err(if err.code().0 as u32 & 0xFFFF == 1223 {
                    PlatformError::ElevationDeclined
                } else {
                    PlatformError::Win(err.to_string())
                });
            }
            let h = info.hProcess;
            if h.is_invalid() {
                return Err(PlatformError::Win("no process handle from ShellExecuteEx".into()));
            }
            let mut code = 0i32;
            if wait {
                let _ = WaitForSingleObject(h, 120_000);
                let mut raw = 0u32;
                let _ = GetExitCodeProcess(h, &mut raw);
                code = raw as i32;
            }
            let _ = CloseHandle(h);
            Ok(code)
        }
    }
}

#[cfg(not(windows))]
mod imp {
    use super::*;
    use crate::PlatformError;
    pub fn is_elevated() -> bool {
        false
    }
    pub fn spawn_elevated(_exe: &Path, _args: &[String], _wait: bool) -> Result<i32> {
        Err(PlatformError::Unsupported)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_elevated_does_not_panic() {
        let _ = is_elevated();
    }
}
