//! GUI presence lock.
//!
//! When the CleanDesk Service is installed, *two* programs could act as the
//! host for the same identity: the service's headless helper and the GUI the
//! user opened. Only one may hold the server registration at a time (the
//! server replaces the older one), and the GUI is the better host while it is
//! open — it can show approval dialogs. So the GUI writes `gui.lock` (holding
//! its PID) into the data directory while it runs; the helper checks the file
//! and, if the PID is alive, stays idle until the GUI goes away.
//!
//! A stale lock (GUI crashed) is detected by checking that the PID still
//! exists, so the helper never gets stuck behind a dead process.

use std::fs;
use std::path::{Path, PathBuf};

pub const LOCK_FILE: &str = "gui.lock";

/// Held by the GUI for its whole lifetime; removes the file on drop.
pub struct PresenceLock {
    path: PathBuf,
}

impl PresenceLock {
    /// Write the lock for the current process into `data_dir`.
    pub fn acquire(data_dir: &Path) -> std::io::Result<Self> {
        fs::create_dir_all(data_dir)?;
        let path = data_dir.join(LOCK_FILE);
        fs::write(&path, std::process::id().to_string())?;
        Ok(Self { path })
    }
}

impl Drop for PresenceLock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

/// True if a GUI is currently running against `data_dir` (lock present and
/// its PID alive).
pub fn gui_is_running(data_dir: &Path) -> bool {
    let Ok(text) = fs::read_to_string(data_dir.join(LOCK_FILE)) else {
        return false;
    };
    let Ok(pid) = text.trim().parse::<u32>() else {
        return false;
    };
    pid != std::process::id() && process_alive(pid) && process_is_cleandesk(pid)
}

/// Does `pid` run a CleanDesk executable? The lock file is just a number
/// any local process can write; a PID that belongs to something else (say,
/// `4`, the System process) must not keep the headless host standing by.
#[cfg(windows)]
pub fn process_is_cleandesk(pid: u32) -> bool {
    use windows::core::PWSTR;
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Threading::{
        OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
    };
    let Some(own) = std::env::current_exe().ok().and_then(|p| p.file_name().map(|n| n.to_os_string())) else {
        return true;
    };
    // SAFETY: documented Win32 calls; the buffer outlives the call and the
    // handle is always closed.
    let name = unsafe {
        let Ok(h) = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) else {
            return false;
        };
        let mut buf = vec![0u16; 1024];
        let mut len = buf.len() as u32;
        let ok = QueryFullProcessImageNameW(h, PROCESS_NAME_WIN32, PWSTR(buf.as_mut_ptr()), &mut len).is_ok();
        let _ = CloseHandle(h);
        if !ok {
            return false;
        }
        String::from_utf16_lossy(&buf[..len as usize])
    };
    Path::new(&name)
        .file_name()
        .is_some_and(|n| n.to_string_lossy().eq_ignore_ascii_case(&own.to_string_lossy()))
}

#[cfg(not(windows))]
pub fn process_is_cleandesk(_pid: u32) -> bool {
    true
}

#[cfg(windows)]
pub fn process_alive(pid: u32) -> bool {
    use windows::Win32::Foundation::{CloseHandle, STILL_ACTIVE};
    use windows::Win32::System::Threading::{GetExitCodeProcess, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};
    // SAFETY: plain Win32 calls; a failed OpenProcess returns an error we map
    // to "not alive", and the handle is always closed.
    unsafe {
        let Ok(h) = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) else {
            return false;
        };
        let mut code = 0u32;
        let ok = GetExitCodeProcess(h, &mut code).is_ok();
        let _ = CloseHandle(h);
        ok && code == STILL_ACTIVE.0 as u32
    }
}

#[cfg(not(windows))]
pub fn process_alive(pid: u32) -> bool {
    Path::new(&format!("/proc/{pid}")).exists()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp() -> PathBuf {
        let p = std::env::temp_dir().join(format!("cleandesk-presence-{}-{}", std::process::id(), rand_suffix()));
        fs::create_dir_all(&p).unwrap();
        p
    }

    fn rand_suffix() -> u64 {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_nanos() as u64).unwrap_or(0)
    }

    #[test]
    fn own_lock_is_not_reported_as_another_gui() {
        let dir = temp();
        let lock = PresenceLock::acquire(&dir).unwrap();
        // Our own PID must not block ourselves.
        assert!(!gui_is_running(&dir));
        drop(lock);
        assert!(!dir.join(LOCK_FILE).exists());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn stale_or_garbage_lock_is_ignored() {
        let dir = temp();
        fs::write(dir.join(LOCK_FILE), "not-a-pid").unwrap();
        assert!(!gui_is_running(&dir));
        // A PID that is almost certainly not alive.
        fs::write(dir.join(LOCK_FILE), u32::MAX.to_string()).unwrap();
        assert!(!gui_is_running(&dir));
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn current_process_is_alive() {
        assert!(process_alive(std::process::id()));
        assert!(process_is_cleandesk(std::process::id()), "our own image name matches itself");
    }

    #[cfg(windows)]
    #[test]
    fn a_lock_naming_a_foreign_process_is_ignored() {
        let dir = temp();
        // PID 4 is the System process: alive, but not CleanDesk.
        fs::write(dir.join(LOCK_FILE), "4").unwrap();
        assert!(!gui_is_running(&dir));
        let _ = fs::remove_dir_all(dir);
    }
}
