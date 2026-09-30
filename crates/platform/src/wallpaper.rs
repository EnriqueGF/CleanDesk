//! Read the logged-in user's wallpaper without capturing their open windows.
use anyhow::{bail, Context, Result};
#[cfg(any(windows, test))]
use image::ImageDecoder;
use image::{ImageReader, RgbImage};
use rotodesk_proto::wallpaper::{MAX_BYTES, MAX_HEIGHT, MAX_WIDTH};
use std::io::Cursor;
#[cfg(windows)]
use std::io::Read;

#[cfg(windows)]
const MAX_SOURCE_BYTES: u64 = 32 * 1024 * 1024;

/// A small preview for an authenticated viewer. Other OSes have no preview yet.
pub fn preview() -> Result<Option<Vec<u8>>> {
    #[cfg(windows)]
    {
        let _user = native::SessionUser::enter();
        let (path, color) = native::background()?;
        let image = if let Some(path) = path {
            let mut bytes = Vec::new();
            std::fs::File::open(path)?
                .take(MAX_SOURCE_BYTES + 1)
                .read_to_end(&mut bytes)?;
            if bytes.len() as u64 > MAX_SOURCE_BYTES {
                bail!("wallpaper source is too large");
            }
            thumbnail(&bytes)?
        } else {
            RgbImage::from_pixel(1, 1, image::Rgb(color))
        };
        Ok(Some(encode(&image)?))
    }
    #[cfg(not(windows))]
    {
        Ok(None)
    }
}

#[cfg(any(windows, test))]
fn thumbnail(bytes: &[u8]) -> Result<RgbImage> {
    let mut reader = ImageReader::new(Cursor::new(bytes)).with_guessed_format()?;
    let mut limits = image::Limits::default();
    limits.max_image_width = Some(8192);
    limits.max_image_height = Some(8192);
    limits.max_alloc = Some(128 * 1024 * 1024);
    reader.limits(limits);
    let decoder = reader.into_decoder()?;
    let (w, h) = decoder.dimensions();
    if w == 0 || h == 0 || u64::from(w) * u64::from(h) > 32 * 1024 * 1024 {
        bail!("wallpaper dimensions are too large");
    }
    Ok(image::DynamicImage::from_decoder(decoder)?
        .thumbnail(MAX_WIDTH, MAX_HEIGHT)
        .to_rgb8())
}

#[cfg(any(windows, test))]
fn encode(image: &RgbImage) -> Result<Vec<u8>> {
    let mut jpeg = Vec::new();
    image::codecs::jpeg::JpegEncoder::new_with_quality(&mut jpeg, 65).encode(
        image.as_raw(),
        image.width(),
        image.height(),
        image::ExtendedColorType::Rgb8,
    )?;
    if jpeg.len() > MAX_BYTES {
        bail!("wallpaper preview is too large");
    }
    Ok(jpeg)
}

/// Bound image size and allocation before decoding peer-controlled bytes.
pub fn decode_preview(jpeg: &[u8]) -> Result<RgbImage> {
    if !rotodesk_proto::wallpaper::valid_payload(jpeg) {
        bail!("invalid wallpaper preview");
    }
    let mut reader = ImageReader::with_format(Cursor::new(jpeg), image::ImageFormat::Jpeg);
    let mut limits = image::Limits::default();
    limits.max_image_width = Some(MAX_WIDTH);
    limits.max_image_height = Some(MAX_HEIGHT);
    limits.max_alloc = Some(1024 * 1024);
    reader.limits(limits);
    reader
        .decode()
        .context("decoding wallpaper preview")
        .map(|image| image.to_rgb8())
}

#[cfg(windows)]
mod native {
    use super::*;
    use std::path::PathBuf;
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::Graphics::Gdi::{GetSysColor, COLOR_BACKGROUND};
    use windows::Win32::Security::{ImpersonateLoggedOnUser, RevertToSelf};
    use windows::Win32::System::RemoteDesktop::{WTSGetActiveConsoleSessionId, WTSQueryUserToken};
    use windows::Win32::UI::WindowsAndMessaging::{
        SystemParametersInfoW, SPI_GETDESKWALLPAPER, SYSTEM_PARAMETERS_INFO_UPDATE_FLAGS,
    };

    /// The service helper runs as SYSTEM: read the console user's settings.
    /// On ordinary GUI hosts WTSQueryUserToken fails and no impersonation occurs.
    pub struct SessionUser(bool);
    impl SessionUser {
        pub fn enter() -> Self {
            let mut token = HANDLE::default();
            // SAFETY: Windows supplies the handle; close it after impersonation.
            unsafe {
                if WTSQueryUserToken(WTSGetActiveConsoleSessionId(), &mut token).is_err() {
                    return Self(false);
                }
                let active = ImpersonateLoggedOnUser(token).is_ok();
                let _ = CloseHandle(token);
                Self(active)
            }
        }
    }
    impl Drop for SessionUser {
        fn drop(&mut self) {
            if self.0 {
                // SAFETY: this guard established impersonation on this thread.
                if unsafe { RevertToSelf() }.is_err() {
                    // A pool thread must never be reused with the user's token.
                    std::process::abort();
                }
            }
        }
    }

    pub fn background() -> Result<(Option<PathBuf>, [u8; 3])> {
        let mut path = vec![0u16; 32768];
        // SAFETY: the live UTF-16 buffer is sized by uiParam; no settings change.
        unsafe {
            SystemParametersInfoW(
                SPI_GETDESKWALLPAPER,
                path.len() as u32,
                Some(path.as_mut_ptr().cast()),
                SYSTEM_PARAMETERS_INFO_UPDATE_FLAGS(0),
            )
        }?;
        let len = path.iter().position(|c| *c == 0).unwrap_or(path.len());
        let path = (len != 0).then(|| PathBuf::from(String::from_utf16_lossy(&path[..len])));
        // SAFETY: reading the desktop color has no preconditions.
        let color = unsafe { GetSysColor(COLOR_BACKGROUND) };
        Ok((path, [color as u8, (color >> 8) as u8, (color >> 16) as u8]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preview_scales_the_background_and_rejects_hostile_images() {
        let source = RgbImage::from_pixel(1920, 1080, image::Rgb([34, 211, 167]));
        let mut png = Cursor::new(Vec::new());
        source.write_to(&mut png, image::ImageFormat::Png).unwrap();
        let small = thumbnail(png.get_ref()).unwrap();
        assert_eq!(small.dimensions(), (320, 180));
        assert_eq!(
            decode_preview(&encode(&small).unwrap())
                .unwrap()
                .dimensions(),
            (320, 180)
        );
        let oversized = RgbImage::from_pixel(MAX_WIDTH + 1, MAX_HEIGHT, image::Rgb([34, 211, 167]));
        assert!(decode_preview(&encode(&oversized).unwrap()).is_err());
        assert!(decode_preview(&vec![0; MAX_BYTES + 1]).is_err());
        assert!(decode_preview(&[0xff, 0xd8, 0, 1]).is_err());
    }
}
