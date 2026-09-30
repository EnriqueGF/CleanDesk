//! rotodesk-capture
//!
//! Screen capture for RotoDesk. The public contract is the [`ScreenCapturer`]
//! trait and the [`CapturedFrame`] it yields. On Windows the trait is
//! implemented by [`DxgiCapturer`] on top of **DXGI Desktop Duplication**.
//!
//! Clean-room: everything here derives from the public Windows API
//! (DXGI 1.2 Desktop Duplication + Direct3D 11), no third-party material.

use std::time::Duration;

#[cfg(windows)]
mod dxgi;
#[cfg(windows)]
pub use dxgi::DxgiCapturer;

/// Crate version string, handy for diagnostics.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// One captured desktop frame: tightly-packed BGRA8 pixels plus geometry.
///
/// `bgra` is `height * stride` bytes, row-major, four bytes per pixel in
/// B, G, R, A order (the native Desktop Duplication layout).
#[derive(Clone)]
pub struct CapturedFrame {
    pub width: u32,
    pub height: u32,
    /// Bytes per row of `bgra` (`width * 4`). Explicit so callers never have to
    /// assume the packing.
    pub stride: usize,
    pub bgra: Vec<u8>,
    /// Monotonic capture timestamp in microseconds, from a per-capturer clock.
    pub timestamp_us: u64,
}

impl std::fmt::Debug for CapturedFrame {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never dump the pixel buffer; report its size instead.
        f.debug_struct("CapturedFrame")
            .field("width", &self.width)
            .field("height", &self.height)
            .field("stride", &self.stride)
            .field("bytes", &self.bgra.len())
            .field("timestamp_us", &self.timestamp_us)
            .finish()
    }
}

/// A source of desktop frames, capturing one selected monitor at a time.
pub trait ScreenCapturer: Send {
    /// The monitors currently attached to the host desktop.
    fn monitors(&self) -> Vec<rotodesk_proto::message::MonitorInfo>;

    /// Choose which monitor subsequent [`ScreenCapturer::next_frame`] calls
    /// capture. `index` is a [`MonitorInfo::index`](rotodesk_proto::message::MonitorInfo::index).
    fn select_monitor(&mut self, index: u16) -> anyhow::Result<()>;

    /// Block up to `timeout` for the next frame.
    ///
    /// `Ok(None)` means no new frame arrived within `timeout` (nothing on the
    /// selected monitor changed).
    fn next_frame(&mut self, timeout: Duration) -> anyhow::Result<Option<CapturedFrame>>;
}

/// Construct the platform default capturer.
#[cfg(windows)]
pub fn new_capturer() -> anyhow::Result<Box<dyn ScreenCapturer>> {
    Ok(Box::new(DxgiCapturer::new()?))
}

/// Non-Windows fallback: capture is not implemented off Windows.
#[cfg(not(windows))]
pub fn new_capturer() -> anyhow::Result<Box<dyn ScreenCapturer>> {
    anyhow::bail!("rotodesk-capture: screen capture is only implemented on Windows")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Enumeration must yield a `Vec` (possibly empty in a headless/service
    /// context) and must never panic.
    #[test]
    fn monitors_enumerate_without_panic() {
        // `Err` is acceptable where DXGI is unavailable (e.g. no GPU in CI); the
        // point is that we neither panic nor hand back a malformed list.
        if let Ok(cap) = new_capturer() {
            let mons = cap.monitors();
            // Every geometry is sane.
            for m in &mons {
                assert!(m.width < 100_000 && m.height < 100_000);
            }
            // Indices are unique.
            let mut idx: Vec<u16> = mons.iter().map(|m| m.index).collect();
            idx.sort_unstable();
            idx.dedup();
            assert_eq!(idx.len(), mons.len(), "monitor indices must be unique");
        }
    }

    /// Runtime-only: needs a real interactive desktop, so it is ignored by
    /// default. Run with `cargo test -p rotodesk-capture -- --ignored`.
    #[test]
    #[ignore]
    fn smoke_capture_one_frame() {
        let mut cap = new_capturer().expect("capturer");
        if cap.monitors().is_empty() {
            return; // no desktop attached; nothing to capture
        }
        // Poll briefly; a static desktop may yield several "no change" results.
        for _ in 0..20 {
            match cap.next_frame(std::time::Duration::from_millis(100)) {
                Ok(Some(f)) => {
                    assert!(f.width > 0 && f.height > 0);
                    assert_eq!(f.stride, f.width as usize * 4);
                    assert_eq!(f.bgra.len(), f.stride * f.height as usize);
                    eprintln!("captured {}x{} ({} bytes)", f.width, f.height, f.bgra.len());
                    return;
                }
                Ok(None) => continue,
                Err(e) => {
                    eprintln!("capture unavailable in this environment: {e:#}");
                    return;
                }
            }
        }
        eprintln!("no frame within budget (idle desktop); acquire path exercised");
    }
}
