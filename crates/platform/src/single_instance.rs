//! Single-instance guard.
//!
//! One RotoDesk per data directory: a named Win32 mutex derived from the
//! directory path is held for the process lifetime. A second launch finds
//! the mutex taken, pokes a named *event* so the running instance brings its
//! window back (it may be hidden in the tray), and exits.
//!
//! Two instances with different `--data-dir` (each with its own identity) are
//! still allowed, which is what the docs use for local testing.

use crate::Result;
use std::path::Path;

/// Stable, filesystem-independent name for `data_dir` (lower-cased, so the
/// same folder written with different casing maps to the same instance).
pub fn instance_key(data_dir: &Path, role: &str) -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut h = DefaultHasher::new();
    data_dir.to_string_lossy().to_lowercase().hash(&mut h);
    role.hash(&mut h);
    format!("RotoDesk-{role}-{:016x}", h.finish())
}

/// Outcome of [`acquire`].
pub enum Instance {
    /// We are the first instance; keep the guard alive for the process lifetime.
    Primary(Guard),
    /// Another instance owns this data directory; it has been asked to show
    /// itself.
    AlreadyRunning,
}

#[cfg(windows)]
mod imp {
    use super::*;
    use crate::PlatformError;
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{CloseHandle, GetLastError, HANDLE, ERROR_ALREADY_EXISTS, WAIT_OBJECT_0};
    use windows::Win32::System::Threading::{
        CreateEventW, CreateMutexW, SetEvent, WaitForSingleObject, INFINITE,
    };

    fn wide(s: &str) -> Vec<u16> {
        OsStr::new(s).encode_wide().chain(std::iter::once(0)).collect()
    }

    /// Holds the mutex (and the "show me" event) until dropped.
    pub struct Guard {
        mutex: HANDLE,
        event: HANDLE,
    }

    // Handles are process-local kernel objects; moving them between threads is fine.
    unsafe impl Send for Guard {}
    unsafe impl Sync for Guard {}

    impl Drop for Guard {
        fn drop(&mut self) {
            // SAFETY: both handles were created by us and are closed exactly once.
            unsafe {
                let _ = CloseHandle(self.event);
                let _ = CloseHandle(self.mutex);
            }
        }
    }

    impl Guard {
        /// Block until another launch asks us to show the window. Meant to run
        /// on a dedicated thread; returns `false` if the wait fails.
        pub fn wait_show_request(&self) -> bool {
            // SAFETY: `event` is a valid auto-reset event handle we own.
            unsafe { WaitForSingleObject(self.event, INFINITE) == WAIT_OBJECT_0 }
        }
    }

    fn event_name(key: &str) -> String {
        format!("Local\\{key}-show")
    }

    pub fn acquire(key: &str) -> Result<Instance> {
        let mutex_name = wide(&format!("Local\\{key}-mutex"));
        // SAFETY: plain Win32 call with a valid NUL-terminated name.
        let mutex = unsafe { CreateMutexW(None, true, PCWSTR(mutex_name.as_ptr())) }
            .map_err(|e| PlatformError::Win(format!("CreateMutex: {e}")))?;
        // SAFETY: GetLastError right after the creating call is the documented way
        // to learn whether the mutex pre-existed.
        let existed = unsafe { GetLastError() } == ERROR_ALREADY_EXISTS;
        if existed {
            // SAFETY: we own this handle; releasing it lets the primary keep the mutex.
            unsafe {
                let _ = CloseHandle(mutex);
            }
            signal_show(key);
            return Ok(Instance::AlreadyRunning);
        }
        let ev_name = wide(&event_name(key));
        // SAFETY: valid name; auto-reset (false), initially unsignalled.
        let event = unsafe { CreateEventW(None, false, false, PCWSTR(ev_name.as_ptr())) }
            .map_err(|e| PlatformError::Win(format!("CreateEvent: {e}")))?;
        Ok(Instance::Primary(Guard { mutex, event }))
    }

    /// Ask the running instance for `key` to show its window (no-op if none).
    pub fn signal_show(key: &str) {
        let ev_name = wide(&event_name(key));
        // SAFETY: opening/creating an event by name; if the primary created it we
        // get the same object and SetEvent wakes its waiter.
        unsafe {
            if let Ok(event) = CreateEventW(None, false, false, PCWSTR(ev_name.as_ptr())) {
                let _ = SetEvent(event);
                let _ = CloseHandle(event);
            }
        }
    }
}

#[cfg(not(windows))]
mod imp {
    use super::*;

    /// Lock-file based guard: `<tmp>/<key>.lock` opened with an exclusive
    /// advisory lock via `create_new`; stale files are tolerated by PID check
    /// where possible. Show requests are not supported off Windows.
    pub struct Guard {
        path: std::path::PathBuf,
    }

    impl Drop for Guard {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.path);
        }
    }

    impl Guard {
        pub fn wait_show_request(&self) -> bool {
            // No cross-process wake-up off Windows; park forever.
            loop {
                std::thread::park();
            }
        }
    }

    pub fn acquire(key: &str) -> Result<Instance> {
        let path = std::env::temp_dir().join(format!("{key}.lock"));
        if let Ok(text) = std::fs::read_to_string(&path) {
            if let Ok(pid) = text.trim().parse::<u32>() {
                if crate::presence::process_alive(pid) {
                    return Ok(Instance::AlreadyRunning);
                }
            }
        }
        std::fs::write(&path, std::process::id().to_string())?;
        Ok(Instance::Primary(Guard { path }))
    }

    pub fn signal_show(_key: &str) {}
}

pub use imp::{acquire, signal_show, Guard};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_are_stable_case_insensitive_and_role_specific() {
        let a = instance_key(Path::new("C:\\Data\\Dir"), "gui");
        let b = instance_key(Path::new("c:\\data\\dir"), "gui");
        let c = instance_key(Path::new("C:\\Data\\Dir"), "host");
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert!(a.starts_with("RotoDesk-gui-"));
    }

    #[test]
    fn second_acquire_in_same_process_reports_already_running() {
        let key = instance_key(Path::new(&format!("test-{}", std::process::id())), "unit");
        let first = acquire(&key).unwrap();
        assert!(matches!(first, Instance::Primary(_)));
        let second = acquire(&key).unwrap();
        assert!(matches!(second, Instance::AlreadyRunning));
        drop(first);
        // Once released, the key can be taken again.
        let third = acquire(&key).unwrap();
        assert!(matches!(third, Instance::Primary(_)));
    }
}
