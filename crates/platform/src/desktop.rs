//! Following the *input desktop* (spec §24, privileged control).
//!
//! Windows keeps several desktops per session: `Default` (the user's), the
//! `Winlogon` secure desktop (UAC prompts, Ctrl+Alt+Del, the lock screen) and
//! the screen-saver one. Screen capture and `SendInput` only reach the
//! desktop the *calling thread* is attached to, so a host that wants to show
//! and drive a UAC prompt must re-attach its capture and input threads to
//! whatever desktop currently receives input. Only a process running as
//! LocalSystem (the CleanDesk service) is allowed to open the secure desktop;
//! for everybody else [`attach_input_desktop`] simply reports `Ok(false)`.

use crate::Result;

/// Attach the calling thread to the desktop that currently receives input.
/// Returns `Ok(true)` when the thread switched desktops, `Ok(false)` when it
/// was already there or the input desktop is not accessible to this process
/// (normal for non-system processes while UAC is up), and an error only for
/// unexpected API failures.
pub fn attach_input_desktop() -> Result<bool> {
    imp::attach_input_desktop()
}

/// Name of the desktop the calling thread is attached to ("Default",
/// "Winlogon", …), for diagnostics.
pub fn current_desktop_name() -> Option<String> {
    imp::current_desktop_name()
}

#[cfg(windows)]
mod imp {
    use super::*;
    use crate::PlatformError;
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::StationsAndDesktops::{
        CloseDesktop, GetThreadDesktop, GetUserObjectInformationW, OpenInputDesktop, SetThreadDesktop,
        DESKTOP_ACCESS_FLAGS, DESKTOP_CONTROL_FLAGS, HDESK, UOI_NAME,
    };
    use windows::Win32::System::Threading::GetCurrentThreadId;

    // GENERIC_ALL: read + write + switch; what capture and input need.
    const DESKTOP_ALL: DESKTOP_ACCESS_FLAGS = DESKTOP_ACCESS_FLAGS(0x1000_0000);

    fn desktop_name(h: HDESK) -> Option<String> {
        let mut buf = [0u16; 128];
        let mut needed = 0u32;
        // SAFETY: `buf` is a valid writable buffer of the given byte length.
        let ok = unsafe {
            GetUserObjectInformationW(
                windows::Win32::Foundation::HANDLE(h.0),
                UOI_NAME,
                Some(buf.as_mut_ptr().cast()),
                (buf.len() * 2) as u32,
                Some(&mut needed),
            )
        };
        if ok.is_err() {
            return None;
        }
        let len = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
        Some(String::from_utf16_lossy(&buf[..len]))
    }

    pub fn current_desktop_name() -> Option<String> {
        // SAFETY: GetThreadDesktop returns a handle owned by the system; it
        // must not be closed.
        let h = unsafe { GetThreadDesktop(GetCurrentThreadId()) }.ok()?;
        desktop_name(h)
    }

    pub fn attach_input_desktop() -> Result<bool> {
        // SAFETY: plain API call; a null/error result is handled below.
        let input = match unsafe { OpenInputDesktop(DESKTOP_CONTROL_FLAGS(0), false, DESKTOP_ALL) } {
            Ok(h) if !h.is_invalid() => h,
            // Access denied is the normal answer for a non-system process
            // while the secure desktop is active: nothing we can do.
            _ => return Ok(false),
        };
        let current = unsafe { GetThreadDesktop(GetCurrentThreadId()) }.ok();
        let same = match (current.and_then(desktop_name), desktop_name(input)) {
            (Some(a), Some(b)) => a.eq_ignore_ascii_case(&b),
            _ => false,
        };
        if same {
            // SAFETY: we own `input`.
            let _ = unsafe { CloseDesktop(input) };
            return Ok(false);
        }
        // SAFETY: `input` is a valid desktop handle; SetThreadDesktop fails if
        // the thread owns windows or hooks, which our worker threads never do.
        let switched = unsafe { SetThreadDesktop(input) };
        match switched {
            Ok(()) => {
                // The thread now references the desktop; the handle itself
                // can be closed (the system keeps the desktop alive).
                let _ = unsafe { CloseDesktop(input) };
                tracing::info!(desktop = ?current_desktop_name(), "thread attached to the input desktop");
                Ok(true)
            }
            Err(e) => {
                let _ = unsafe { CloseDesktop(input) };
                Err(PlatformError::Win(format!("SetThreadDesktop: {e}")))
            }
        }
    }

    // Silence "unused import" on configurations where HANDLE conversion is inlined.
    #[allow(dead_code)]
    fn _close(h: windows::Win32::Foundation::HANDLE) {
        let _ = unsafe { CloseHandle(h) };
    }
}

#[cfg(not(windows))]
mod imp {
    use super::*;
    pub fn attach_input_desktop() -> Result<bool> {
        Ok(false)
    }
    pub fn current_desktop_name() -> Option<String> {
        None
    }
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;

    #[test]
    fn attaching_from_an_interactive_session_is_a_no_op_or_a_switch() {
        // On a developer desktop the input desktop is our own "Default":
        // the call must succeed and report no switch.
        let r = attach_input_desktop();
        assert!(r.is_ok(), "{r:?}");
        let name = current_desktop_name();
        assert!(name.is_some());
    }
}
