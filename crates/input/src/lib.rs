//! cleandesk-input
//!
//! Input **injection** for CleanDesk's host role: it replays the
//! [`InputEvent`]s that arrived from the viewer onto the local desktop via the
//! Windows `SendInput` API.
//!
//! ## Key codes
//!
//! `InputEvent::Key { code, .. }` is treated as a **Windows Virtual-Key (VK)
//! code** (`VK_*`; e.g. `0x41` = `A`, `0x1B` = `VK_ESCAPE`, `0x11` =
//! `VK_CONTROL`). The viewer maps its own platform key identifiers to VK codes
//! before sending them; this crate passes `code` straight into
//! `KEYBDINPUT.wVk`. Scan codes (`KEYEVENTF_SCANCODE`) are not used in the MVP.
//!
//! ## Coordinates
//!
//! [`InputEvent::MouseMove`] carries coordinates normalized `0.0..=1.0` over the
//! *selected monitor*. Injection maps them to absolute virtual-desktop pixels
//! using the monitor geometry, then to the `0..=65535` range that
//! `MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_VIRTUALDESK` expects. The mapping is the
//! pure function [`axis_to_absolute`] (and [`mouse_move_absolute`]), kept free
//! of any Windows call so it is unit-tested without a desktop.

use cleandesk_proto::message::{InputEvent, MonitorInfo};

/// Crate version string, handy for diagnostics.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Largest virtual-key code `SendInput` accepts (`VK_OEM_CLEAR`); anything
/// above it is not a key and would be truncated into one.
pub const MAX_VIRTUAL_KEY: u32 = 0xFE;

/// Injects viewer input events onto the local desktop.
pub trait InputInjector: Send {
    /// Inject one event. `monitor` gives the target monitor geometry so that
    /// normalized (0..=1) mouse coordinates map to absolute virtual-desktop
    /// pixels.
    fn inject(&mut self, ev: InputEvent, monitor: &MonitorInfo) -> anyhow::Result<()>;

    /// Block (`true`) or unblock (`false`) the *local* keyboard and mouse so
    /// only injected input reaches the desktop. Windows only lets the thread
    /// that blocked input unblock it, so this rides the injector's own
    /// thread; the block is always released when the injector is dropped.
    fn set_local_input_blocked(&mut self, blocked: bool) -> anyhow::Result<()>;
}

// ---------------------------------------------------------------------------
// Pure coordinate mapping (platform independent, unit-tested everywhere)
// ---------------------------------------------------------------------------

/// The virtual-desktop rectangle in pixels: origin (`x`, `y`) and extent
/// (`cx`, `cy`). On Windows these come from `GetSystemMetrics(SM_*VIRTUALSCREEN)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VirtualScreen {
    pub x: i32,
    pub y: i32,
    pub cx: i32,
    pub cy: i32,
}

/// Map one normalized axis coordinate to the `0..=65535` absolute range that
/// `MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_VIRTUALDESK` uses.
///
/// * `norm` — position on the monitor, clamped to `0.0..=1.0`.
/// * `mon_origin` / `mon_size` — the monitor's origin and extent (one axis).
/// * `vs_origin` / `vs_size` — the virtual desktop's origin and extent (same
///   axis).
///
/// The absolute pixel is `mon_origin + norm * mon_size`; it is then rescaled so
/// the whole virtual desktop spans `0..=65535`. Endpoints land exactly on `0`
/// and `65535` when the monitor coincides with the virtual desktop.
pub fn axis_to_absolute(norm: f32, mon_origin: i32, mon_size: u32, vs_origin: i32, vs_size: i32) -> i32 {
    if vs_size <= 0 {
        return 0;
    }
    let n = norm.clamp(0.0, 1.0) as f64;
    let abs_px = mon_origin as f64 + n * mon_size as f64;
    let scaled = (abs_px - vs_origin as f64) * 65535.0 / vs_size as f64;
    scaled.round().clamp(0.0, 65535.0) as i32
}

/// Map a normalized mouse position over `monitor` to absolute `(x, y)` in the
/// `0..=65535` virtual-desktop space.
pub fn mouse_move_absolute(x: f32, y: f32, monitor: &MonitorInfo, vs: &VirtualScreen) -> (i32, i32) {
    (
        axis_to_absolute(x, monitor.origin_x, monitor.width, vs.x, vs.cx),
        axis_to_absolute(y, monitor.origin_y, monitor.height, vs.y, vs.cy),
    )
}

// ---------------------------------------------------------------------------
// Windows implementation
// ---------------------------------------------------------------------------

#[cfg(windows)]
mod win;
#[cfg(windows)]
pub use win::WinInputInjector;

/// Non-Windows stub so the crate type-checks off Windows; injection errors.
#[cfg(not(windows))]
pub struct WinInputInjector;

#[cfg(not(windows))]
impl InputInjector for WinInputInjector {
    fn inject(&mut self, _ev: InputEvent, _monitor: &MonitorInfo) -> anyhow::Result<()> {
        anyhow::bail!("cleandesk-input: SendInput is only available on Windows")
    }

    fn set_local_input_blocked(&mut self, _blocked: bool) -> anyhow::Result<()> {
        anyhow::bail!("cleandesk-input: BlockInput is only available on Windows")
    }
}

/// Construct the platform input injector.
#[cfg(windows)]
pub fn new_injector() -> Box<dyn InputInjector> {
    Box::new(WinInputInjector::new())
}

/// Construct the platform input injector (stub off Windows).
#[cfg(not(windows))]
pub fn new_injector() -> Box<dyn InputInjector> {
    Box::new(WinInputInjector)
}

// ---------------------------------------------------------------------------
// Remote actions (spec section 6: lock workstation, block local input, SAS)
// ---------------------------------------------------------------------------

/// Lock the interactive session (the equivalent of Win+L). The screen stays
/// captured; the viewer sees the lock screen.
#[cfg(windows)]
pub fn lock_workstation() -> anyhow::Result<()> {
    win::lock_workstation()
}

/// Block (`true`) or unblock (`false`) the *local* keyboard and mouse on the
/// **calling thread**. Prefer [`InputInjector::set_local_input_blocked`]:
/// only the thread that called `BlockInput(TRUE)` can undo it, and an async
/// task may resume on another thread.
#[cfg(windows)]
pub fn block_local_input(blocked: bool) -> anyhow::Result<()> {
    win::block_local_input(blocked)
}

/// Best-effort substitute for the secure attention sequence (Ctrl+Alt+Del).
///
/// A real SAS can only be raised from a Windows service holding
/// `SeTcbPrivilege` (`SendSAS`); an interactive process cannot. This sends
/// Ctrl+Shift+Esc through `SendInput` instead, which opens Task Manager — the
/// most common reason a support technician reaches for Ctrl+Alt+Del. When
/// CleanDesk runs as a service the real sequence can replace this.
#[cfg(windows)]
pub fn send_secure_attention() -> anyhow::Result<()> {
    win::send_secure_attention()
}

#[cfg(not(windows))]
pub fn lock_workstation() -> anyhow::Result<()> {
    anyhow::bail!("cleandesk-input: LockWorkStation is only available on Windows")
}

#[cfg(not(windows))]
pub fn block_local_input(_blocked: bool) -> anyhow::Result<()> {
    anyhow::bail!("cleandesk-input: BlockInput is only available on Windows")
}

#[cfg(not(windows))]
pub fn send_secure_attention() -> anyhow::Result<()> {
    anyhow::bail!("cleandesk-input: secure attention is only available on Windows")
}

#[cfg(test)]
mod tests {
    use super::*;
    use cleandesk_proto::message::MonitorInfo;

    fn mon(width: u32, height: u32, ox: i32, oy: i32) -> MonitorInfo {
        MonitorInfo { index: 0, width, height, primary: true, origin_x: ox, origin_y: oy }
    }

    #[test]
    fn axis_corners_and_center_full_screen() {
        // Monitor coincides with the virtual desktop.
        assert_eq!(axis_to_absolute(0.0, 0, 1920, 0, 1920), 0);
        assert_eq!(axis_to_absolute(1.0, 0, 1920, 0, 1920), 65535);
        // 0.5 -> 32767.5 rounds to 32768.
        assert_eq!(axis_to_absolute(0.5, 0, 1920, 0, 1920), 32768);
    }

    #[test]
    fn axis_clamps_out_of_range_norm() {
        assert_eq!(axis_to_absolute(-1.0, 0, 1920, 0, 1920), 0);
        assert_eq!(axis_to_absolute(2.0, 0, 1920, 0, 1920), 65535);
    }

    #[test]
    fn axis_secondary_monitor_right_half() {
        // Two 1920-wide monitors side by side; virtual desktop is 3840 wide.
        // The right monitor starts at x=1920 (the middle of the desktop).
        assert_eq!(axis_to_absolute(0.0, 1920, 1920, 0, 3840), 32768); // 1920/3840
        assert_eq!(axis_to_absolute(1.0, 1920, 1920, 0, 3840), 65535); // far right
        assert_eq!(axis_to_absolute(0.5, 1920, 1920, 0, 3840), 49151); // 2880/3840
    }

    #[test]
    fn axis_negative_origin_monitor() {
        // A monitor to the left of primary: desktop spans x = -1920..1920.
        assert_eq!(axis_to_absolute(0.0, -1920, 1920, -1920, 3840), 0);
        assert_eq!(axis_to_absolute(1.0, -1920, 1920, -1920, 3840), 32768); // its right edge = center
    }

    #[test]
    fn axis_degenerate_virtual_screen_is_safe() {
        assert_eq!(axis_to_absolute(0.5, 0, 1920, 0, 0), 0);
    }

    #[test]
    fn mouse_move_maps_corners_and_center() {
        let m = mon(1920, 1080, 0, 0);
        let vs = VirtualScreen { x: 0, y: 0, cx: 1920, cy: 1080 };
        assert_eq!(mouse_move_absolute(0.0, 0.0, &m, &vs), (0, 0));
        assert_eq!(mouse_move_absolute(1.0, 1.0, &m, &vs), (65535, 65535));
        assert_eq!(mouse_move_absolute(0.5, 0.5, &m, &vs), (32768, 32768));
    }
}
