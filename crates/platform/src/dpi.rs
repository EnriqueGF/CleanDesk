//! Process DPI awareness.
//!
//! Screen capture (DXGI) always works in physical pixels, but a process that
//! does not declare itself DPI-aware gets *virtualised* screen metrics from
//! `GetSystemMetrics` (scaled by 125 %, 150 %…). The input injector maps the
//! viewer's normalised coordinates onto those metrics, so without this call a
//! headless host (the one the service launches) clicks in the wrong place on
//! any display with scaling. The GUI is unaffected only because its window
//! toolkit makes the same call; doing it here, first thing in `main`, covers
//! every mode.

use crate::Result;

/// Declare the current process per-monitor-DPI-aware (v2). Must run before
/// any window is created. Returns `Ok(false)` when awareness was already set
/// by someone else (harmless), `Ok(true)` when this call set it.
pub fn make_process_dpi_aware() -> Result<bool> {
    imp::make_process_dpi_aware()
}

#[cfg(windows)]
mod imp {
    use super::*;
    use windows::Win32::UI::HiDpi::{
        SetProcessDpiAwarenessContext, DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2,
    };

    pub fn make_process_dpi_aware() -> Result<bool> {
        // SAFETY: plain API call with a constant context handle.
        match unsafe { SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2) } {
            Ok(()) => Ok(true),
            // ERROR_ACCESS_DENIED (5): already set for this process.
            Err(e) if e.code().0 as u32 & 0xFFFF == 5 => Ok(false),
            Err(e) => Err(crate::PlatformError::Win(format!("SetProcessDpiAwarenessContext: {e}"))),
        }
    }
}

#[cfg(not(windows))]
mod imp {
    use super::*;
    pub fn make_process_dpi_aware() -> Result<bool> {
        Ok(false)
    }
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;

    #[test]
    fn setting_awareness_twice_is_fine() {
        let first = make_process_dpi_aware().expect("first call");
        let second = make_process_dpi_aware().expect("second call");
        // Whichever call was first in this test binary set it; the other
        // must report "already set" rather than fail.
        assert!(!(first && second));
    }
}
