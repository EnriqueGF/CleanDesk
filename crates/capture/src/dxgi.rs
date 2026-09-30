//! DXGI Desktop Duplication capturer (Windows).
//!
//! Pipeline, straight from the public Windows API:
//!
//! 1. `CreateDXGIFactory1` → enumerate adapters (`EnumAdapters1`) and their
//!    outputs (`EnumOutputs`). Each desktop-attached output is one monitor.
//! 2. For the selected output, create a D3D11 device on the *owning* adapter and
//!    call `IDXGIOutput1::DuplicateOutput`.
//! 3. `AcquireNextFrame` hands back a GPU texture; copy it into a CPU-readable
//!    staging texture, `Map` it, and copy each row (honoring the row pitch) into
//!    a tightly-packed BGRA buffer. `ReleaseFrame` returns the frame.
//!
//! Duplication can be lost at any time (resolution change, mode switch, a
//! full-screen app taking over) — `DXGI_ERROR_ACCESS_LOST` tears the pipeline
//! down and the next call transparently rebuilds it.

use std::time::{Duration, Instant};

use anyhow::Context as _;
use rotodesk_proto::message::MonitorInfo;
use windows::core::Interface as _;
use windows::Win32::Foundation::HMODULE;
use windows::Win32::Graphics::Direct3D::D3D_DRIVER_TYPE_UNKNOWN;
use windows::Win32::Graphics::Direct3D11::{
    D3D11CreateDevice, ID3D11Device, ID3D11DeviceContext, ID3D11Texture2D, D3D11_CPU_ACCESS_READ,
    D3D11_CREATE_DEVICE_BGRA_SUPPORT, D3D11_MAPPED_SUBRESOURCE, D3D11_MAP_READ, D3D11_SDK_VERSION,
    D3D11_TEXTURE2D_DESC, D3D11_USAGE_STAGING,
};
use windows::Win32::Graphics::Dxgi::Common::DXGI_SAMPLE_DESC;
use windows::Win32::Graphics::Dxgi::{
    CreateDXGIFactory1, IDXGIAdapter1, IDXGIFactory1, IDXGIOutput, IDXGIOutput1,
    IDXGIOutputDuplication, IDXGIResource, DXGI_ERROR_ACCESS_LOST, DXGI_ERROR_NOT_FOUND,
    DXGI_ERROR_WAIT_TIMEOUT, DXGI_OUTDUPL_FRAME_INFO,
};

use crate::{CapturedFrame, ScreenCapturer};

/// A monitor plus the DXGI coordinates needed to duplicate it.
struct MonitorEntry {
    info: MonitorInfo,
    adapter_index: u32,
    output_index: u32,
}

/// Screen capturer backed by DXGI Desktop Duplication.
pub struct DxgiCapturer {
    monitors: Vec<MonitorEntry>,
    /// Index into `monitors` of the currently selected monitor.
    selected: usize,
    /// Active duplication state, built lazily on first `next_frame` and torn
    /// down on access loss or monitor switch.
    device: Option<ID3D11Device>,
    context: Option<ID3D11DeviceContext>,
    duplication: Option<IDXGIOutputDuplication>,
    staging: Option<ID3D11Texture2D>,
    staging_desc: Option<D3D11_TEXTURE2D_DESC>,
    /// Monotonic clock base for frame timestamps.
    start: Instant,
}

impl DxgiCapturer {
    /// Enumerate monitors and pick the primary (or first) as the initial target.
    ///
    /// Enumeration failure is not fatal: we log and expose an empty monitor
    /// list so construction always succeeds.
    pub fn new() -> anyhow::Result<Self> {
        let monitors = match enumerate_monitors() {
            Ok(m) => m,
            Err(e) => {
                tracing::warn!("DXGI monitor enumeration failed: {e:#}");
                Vec::new()
            }
        };
        let selected = monitors
            .iter()
            .position(|m| m.info.primary)
            .unwrap_or(0);
        Ok(Self {
            monitors,
            selected,
            device: None,
            context: None,
            duplication: None,
            staging: None,
            staging_desc: None,
            start: Instant::now(),
        })
    }

    /// Drop the active device/duplication so it is rebuilt on the next frame.
    fn teardown(&mut self) {
        self.duplication = None;
        self.device = None;
        self.context = None;
        self.staging = None;
        self.staging_desc = None;
    }

    /// Ensure a device + duplication exist for the selected monitor.
    fn ensure_duplication(&mut self) -> anyhow::Result<()> {
        if self.duplication.is_some() {
            return Ok(());
        }
        // Desktop Duplication only sees the desktop this thread is attached
        // to. After a UAC switch the old duplication dies with ACCESS_LOST; a
        // LocalSystem host re-attaches here and keeps showing the secure
        // desktop. For ordinary processes this is a harmless no-op.
        match rotodesk_platform::desktop::attach_input_desktop() {
            Ok(true) => tracing::info!("capture thread followed the input desktop"),
            Ok(false) => {}
            Err(e) => tracing::debug!(error = %e, "could not follow the input desktop"),
        }
        let entry = self
            .monitors
            .get(self.selected)
            .context("no monitor selected / no monitors available")?;
        let adapter_index = entry.adapter_index;
        let output_index = entry.output_index;

        // SAFETY: no preconditions; returns a new factory or an error HRESULT.
        let factory: IDXGIFactory1 =
            unsafe { CreateDXGIFactory1() }.context("CreateDXGIFactory1")?;
        // SAFETY: `adapter_index` was produced by enumeration; out-of-range is
        // reported as an error rather than UB.
        let adapter: IDXGIAdapter1 =
            unsafe { factory.EnumAdapters1(adapter_index) }.context("EnumAdapters1")?;

        let mut device: Option<ID3D11Device> = None;
        let mut context: Option<ID3D11DeviceContext> = None;
        // SAFETY: FFI call. `&adapter` is a live adapter (driver type must be
        // UNKNOWN when an explicit adapter is given); the two out-params are
        // valid `Option` slots the callee fills. `None` feature levels lets the
        // runtime pick a supported default.
        unsafe {
            D3D11CreateDevice(
                &adapter,
                D3D_DRIVER_TYPE_UNKNOWN,
                HMODULE::default(),
                D3D11_CREATE_DEVICE_BGRA_SUPPORT,
                None,
                D3D11_SDK_VERSION,
                Some(&mut device),
                None,
                Some(&mut context),
            )
        }
        .context("D3D11CreateDevice")?;
        let device = device.context("D3D11CreateDevice yielded no device")?;
        let context = context.context("D3D11CreateDevice yielded no context")?;

        // SAFETY: `output_index` was produced by enumeration for this adapter.
        let output: IDXGIOutput =
            unsafe { adapter.EnumOutputs(output_index) }.context("EnumOutputs")?;
        let output1: IDXGIOutput1 = output.cast().context("IDXGIOutput1 unavailable")?;
        // SAFETY: `device` is a live D3D11 device on the adapter that owns this
        // output — the precondition for duplicating it. Fails gracefully if
        // there is no interactive desktop or the output is already duplicated.
        let duplication = unsafe { output1.DuplicateOutput(&device) }
            .context("DuplicateOutput (needs an interactive desktop; output may already be duplicated)")?;

        self.device = Some(device);
        self.context = Some(context);
        self.duplication = Some(duplication);
        self.staging = None;
        self.staging_desc = None;
        Ok(())
    }

    /// (Re)create the staging texture if it does not match `desc`.
    fn ensure_staging(
        &mut self,
        device: &ID3D11Device,
        desc: &D3D11_TEXTURE2D_DESC,
    ) -> anyhow::Result<()> {
        let matches = self.staging_desc.as_ref().is_some_and(|s| {
            s.Width == desc.Width && s.Height == desc.Height && s.Format == desc.Format
        });
        if matches && self.staging.is_some() {
            return Ok(());
        }

        let staging_desc = D3D11_TEXTURE2D_DESC {
            Width: desc.Width,
            Height: desc.Height,
            MipLevels: 1,
            ArraySize: 1,
            Format: desc.Format,
            SampleDesc: DXGI_SAMPLE_DESC {
                Count: 1,
                Quality: 0,
            },
            Usage: D3D11_USAGE_STAGING,
            BindFlags: 0,
            CPUAccessFlags: D3D11_CPU_ACCESS_READ.0 as u32,
            MiscFlags: 0,
        };
        let mut tex: Option<ID3D11Texture2D> = None;
        // SAFETY: `staging_desc` is a valid staging description; `pinitialdata`
        // is None (no initial contents); the out-param receives the texture.
        unsafe { device.CreateTexture2D(&staging_desc, None, Some(&mut tex)) }
            .context("CreateTexture2D (staging)")?;
        self.staging = Some(tex.context("CreateTexture2D yielded no texture")?);
        self.staging_desc = Some(staging_desc);
        Ok(())
    }

    /// Copy `src` (a GPU frame texture) into a packed BGRA [`CapturedFrame`].
    fn copy_to_frame(&mut self, src: &ID3D11Texture2D) -> anyhow::Result<CapturedFrame> {
        let device = self.device.clone().context("device missing")?;
        let context = self.context.clone().context("context missing")?;

        let mut desc = D3D11_TEXTURE2D_DESC::default();
        // SAFETY: `src` is a valid texture handed to us by AcquireNextFrame;
        // GetDesc writes into `desc`.
        unsafe { src.GetDesc(&mut desc) };

        self.ensure_staging(&device, &desc)?;
        let staging = self.staging.clone().context("staging missing")?;

        // SAFETY: both are live textures with matching format/size (staging was
        // created from `desc`); CopyResource copies GPU→staging.
        unsafe { context.CopyResource(&staging, src) };

        let mut mapped = D3D11_MAPPED_SUBRESOURCE::default();
        // SAFETY: `staging` is CPU-readable (USAGE_STAGING + CPU_ACCESS_READ);
        // Map fills `mapped` with a valid pointer and row pitch. Paired with
        // Unmap below.
        unsafe { context.Map(&staging, 0, D3D11_MAP_READ, 0, Some(&mut mapped)) }
            .context("Map staging texture")?;

        let width = desc.Width;
        let height = desc.Height;
        let src_pitch = mapped.RowPitch as usize;
        let dst_stride = (width as usize) * 4;
        let row_copy = dst_stride.min(src_pitch);
        let total = dst_stride
            .checked_mul(height as usize)
            .context("frame dimensions overflow")?;
        let mut bgra = vec![0u8; total];

        // SAFETY: `mapped.pData` points to at least `height * src_pitch` bytes.
        // For each row we copy `row_copy` (<= src_pitch and <= dst_stride)
        // bytes; source and destination ranges are within their allocations and
        // never overlap.
        unsafe {
            let base = mapped.pData as *const u8;
            for row in 0..height as usize {
                let s = base.add(row * src_pitch);
                let d = bgra.as_mut_ptr().add(row * dst_stride);
                std::ptr::copy_nonoverlapping(s, d, row_copy);
            }
        }

        // SAFETY: matches the successful Map above on the same subresource.
        unsafe { context.Unmap(&staging, 0) };

        Ok(CapturedFrame {
            width,
            height,
            stride: dst_stride,
            bgra,
            timestamp_us: self.start.elapsed().as_micros() as u64,
        })
    }
}

impl ScreenCapturer for DxgiCapturer {
    fn monitors(&self) -> Vec<MonitorInfo> {
        self.monitors.iter().map(|m| m.info.clone()).collect()
    }

    fn select_monitor(&mut self, index: u16) -> anyhow::Result<()> {
        let pos = self
            .monitors
            .iter()
            .position(|m| m.info.index == index)
            .with_context(|| format!("no monitor with index {index}"))?;
        if pos != self.selected {
            self.selected = pos;
            // Force the duplication to be rebuilt for the new output.
            self.teardown();
        }
        Ok(())
    }

    fn next_frame(&mut self, timeout: Duration) -> anyhow::Result<Option<CapturedFrame>> {
        self.ensure_duplication()?;
        // Clone the COM handle so `self` stays free for `copy_to_frame`'s
        // &mut borrow (COM clone is a refcount bump).
        let dup = self
            .duplication
            .clone()
            .context("duplication missing after ensure")?;

        let timeout_ms = timeout.as_millis().min(u32::MAX as u128) as u32;
        let mut frame_info = DXGI_OUTDUPL_FRAME_INFO::default();
        let mut resource: Option<IDXGIResource> = None;

        // SAFETY: `dup` is a live duplication; the two out-params are valid
        // pointers the callee fills.
        let acquired =
            unsafe { dup.AcquireNextFrame(timeout_ms, &mut frame_info, &mut resource) };
        match acquired {
            Ok(()) => {}
            Err(e) if e.code() == DXGI_ERROR_WAIT_TIMEOUT => return Ok(None),
            Err(e) if e.code() == DXGI_ERROR_ACCESS_LOST => {
                tracing::debug!("DXGI access lost; rebuilding duplication");
                self.teardown();
                return Ok(None);
            }
            Err(e) => return Err(anyhow::Error::new(e).context("AcquireNextFrame")),
        }

        // A frame is now held; we must ReleaseFrame before the next Acquire on
        // every path. Do the fallible work in a closure, then release.
        let outcome = (|| -> anyhow::Result<Option<CapturedFrame>> {
            // `LastPresentTime == 0` means only the mouse pointer moved: no new
            // desktop image, so report "no change".
            if frame_info.LastPresentTime == 0 {
                return Ok(None);
            }
            let resource = resource.context("AcquireNextFrame returned no surface")?;
            let texture: ID3D11Texture2D =
                resource.cast().context("frame surface is not a texture")?;
            Ok(Some(self.copy_to_frame(&texture)?))
        })();

        // SAFETY: exactly one ReleaseFrame per successful AcquireNextFrame.
        let released = unsafe { dup.ReleaseFrame() };
        match released {
            Ok(()) => {}
            Err(e) if e.code() == DXGI_ERROR_ACCESS_LOST => self.teardown(),
            Err(e) => tracing::debug!("ReleaseFrame: {e}"),
        }

        outcome
    }
}

/// Enumerate every desktop-attached output across all adapters into a flat list
/// with monotonically increasing `index`.
fn enumerate_monitors() -> anyhow::Result<Vec<MonitorEntry>> {
    // SAFETY: no preconditions; returns a new factory or an error.
    let factory: IDXGIFactory1 = unsafe { CreateDXGIFactory1() }.context("CreateDXGIFactory1")?;

    let mut monitors = Vec::new();
    let mut global_index: u16 = 0;
    let mut adapter_index = 0u32;
    loop {
        // SAFETY: end of enumeration is signaled by DXGI_ERROR_NOT_FOUND.
        let adapter: IDXGIAdapter1 = match unsafe { factory.EnumAdapters1(adapter_index) } {
            Ok(a) => a,
            Err(e) if e.code() == DXGI_ERROR_NOT_FOUND => break,
            Err(e) => return Err(anyhow::Error::new(e).context("EnumAdapters1")),
        };

        let mut output_index = 0u32;
        loop {
            // SAFETY: end of enumeration is signaled by DXGI_ERROR_NOT_FOUND.
            let output: IDXGIOutput = match unsafe { adapter.EnumOutputs(output_index) } {
                Ok(o) => o,
                Err(e) if e.code() == DXGI_ERROR_NOT_FOUND => break,
                // Skip a single flaky output rather than abandoning the scan.
                Err(_) => {
                    output_index += 1;
                    continue;
                }
            };

            // SAFETY: `output` is live; GetDesc returns its descriptor by value.
            if let Ok(desc) = unsafe { output.GetDesc() } {
                if desc.AttachedToDesktop.as_bool() {
                    let r = desc.DesktopCoordinates;
                    monitors.push(MonitorEntry {
                        info: MonitorInfo {
                            index: global_index,
                            width: (r.right - r.left).max(0) as u32,
                            height: (r.bottom - r.top).max(0) as u32,
                            // The primary monitor is the one anchored at the
                            // virtual-desktop origin.
                            primary: r.left == 0 && r.top == 0,
                            origin_x: r.left,
                            origin_y: r.top,
                        },
                        adapter_index,
                        output_index,
                    });
                    global_index = global_index.saturating_add(1);
                }
            }
            output_index += 1;
        }
        adapter_index += 1;
    }
    Ok(monitors)
}
