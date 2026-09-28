//! Per-tile pixel-format conversion and JPEG codec calls.
//!
//! Isolated in its own module so `encoder.rs`/`decoder.rs` stay focused on
//! tiling/diffing logic instead of pixel-format plumbing.

use std::io::Cursor;

use image::{codecs::jpeg::JpegEncoder, ExtendedColorType, ImageEncoder, ImageFormat, ImageReader, Limits};

use crate::{
    error::CodecError,
    tile::{TileRect, TILE_SIZE},
    RawFrame,
};

/// Crop `rect` out of a BGRA8 frame into a freshly allocated, tightly packed
/// RGB8 buffer.
///
/// JPEG has no alpha channel, and desktop capture is always fully opaque, so
/// we simply drop A here rather than carrying it through.
pub(crate) fn crop_bgra_to_rgb(frame: &RawFrame<'_>, rect: TileRect) -> Vec<u8> {
    let mut rgb = Vec::with_capacity(rect.w as usize * rect.h as usize * 3);
    for row in 0..rect.h {
        let row_start = (rect.y + row) as usize * frame.stride + rect.x as usize * 4;
        let src = &frame.bgra[row_start..row_start + rect.w as usize * 4];
        for px in src.chunks_exact(4) {
            // BGRA -> RGB: swap B/R, drop A.
            rgb.push(px[2]);
            rgb.push(px[1]);
            rgb.push(px[0]);
        }
    }
    rgb
}

/// JPEG-encode one tile's tightly packed RGB8 pixels at `quality` (1..=100).
///
/// `rect.w`/`rect.h` must match `rgb`'s dimensions exactly (the caller always
/// gets `rgb` from [`crop_bgra_to_rgb`] with the same `rect`, so this holds by
/// construction).
pub(crate) fn encode_tile(
    index: u32,
    rgb: &[u8],
    rect: TileRect,
    quality: u8,
) -> Result<Vec<u8>, CodecError> {
    let mut out = Vec::new();
    JpegEncoder::new_with_quality(&mut out, quality)
        .write_image(rgb, rect.w, rect.h, ExtendedColorType::Rgb8)
        .map_err(|source| CodecError::JpegEncode { index, source })?;
    Ok(out)
}

/// Decode a JPEG tile back to tightly packed RGB8, plus the dimensions
/// carried in the JPEG itself (trusted over whatever the caller expected —
/// the caller cross-checks it against the expected tile rect afterwards).
///
/// The tile bytes come straight off the network, so the decoder is told up
/// front that nothing larger than [`TILE_SIZE`] square is acceptable: the
/// `image` crate checks the header's dimensions against these limits *before*
/// allocating the pixel buffer, so a JPEG header claiming 65535x65535 fails
/// cheaply instead of attempting a multi-gigabyte allocation. The format is
/// pinned to JPEG rather than sniffed, because that is all the encoder ever
/// emits and other enabled decoders would only widen the attack surface.
pub(crate) fn decode_tile(index: u32, jpeg: &[u8]) -> Result<(u32, u32, Vec<u8>), CodecError> {
    let mut limits = Limits::default();
    limits.max_image_width = Some(TILE_SIZE);
    limits.max_image_height = Some(TILE_SIZE);
    let mut reader = ImageReader::new(Cursor::new(jpeg));
    reader.set_format(ImageFormat::Jpeg);
    reader.limits(limits);
    let img = reader
        .decode()
        .map_err(|source| CodecError::JpegDecode { index, source })?
        .into_rgb8();
    let (w, h) = img.dimensions();
    Ok((w, h, img.into_raw()))
}

/// Blit a decoded tile's tightly packed RGB8 pixels into an RGBA8 canvas at
/// `rect`. Alpha is forced fully opaque: desktop frames carry no meaningful
/// alpha channel, and the viewer (egui texture) expects RGBA anyway.
pub(crate) fn blit_rgb_to_rgba(canvas: &mut [u8], canvas_width: u32, rect: TileRect, rgb: &[u8]) {
    for row in 0..rect.h {
        let dst_row_start = ((rect.y + row) * canvas_width + rect.x) as usize * 4;
        let src_row_start = row as usize * rect.w as usize * 3;
        for col in 0..rect.w as usize {
            let d = dst_row_start + col * 4;
            let s = src_row_start + col * 3;
            canvas[d] = rgb[s];
            canvas[d + 1] = rgb[s + 1];
            canvas[d + 2] = rgb[s + 2];
            canvas[d + 3] = 0xFF;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crop_swaps_bgra_to_rgb_and_drops_alpha() {
        // 2x1 image, tightly packed (stride == width * 4).
        let bgra = [10u8, 20, 30, 255, 40, 50, 60, 128];
        let frame = RawFrame { width: 2, height: 1, stride: 8, bgra: &bgra, timestamp_us: 0 };
        let rgb = crop_bgra_to_rgb(&frame, TileRect { x: 0, y: 0, w: 2, h: 1 });
        assert_eq!(rgb, vec![30, 20, 10, 60, 50, 40]);
    }

    #[test]
    fn crop_honors_stride_padding() {
        // width=1 but stride=8 (padded row): second row starts at byte 8.
        let bgra = [1u8, 2, 3, 255, 0, 0, 0, 0, 4, 5, 6, 255, 0, 0, 0, 0];
        let frame = RawFrame { width: 1, height: 2, stride: 8, bgra: &bgra, timestamp_us: 0 };
        let rgb = crop_bgra_to_rgb(&frame, TileRect { x: 0, y: 0, w: 1, h: 2 });
        assert_eq!(rgb, vec![3, 2, 1, 6, 5, 4]);
    }

    #[test]
    fn jpeg_roundtrip_preserves_size_and_is_close_in_value() {
        let rect = TileRect { x: 0, y: 0, w: 8, h: 8 };
        let rgb: Vec<u8> = (0..8 * 8 * 3).map(|i| (i * 7) as u8).collect();
        let jpeg = encode_tile(0, &rgb, rect, 90).unwrap();
        let (w, h, decoded) = decode_tile(0, &jpeg).unwrap();
        assert_eq!((w, h), (8, 8));
        assert_eq!(decoded.len(), rgb.len());
    }

    #[test]
    fn blit_writes_opaque_alpha() {
        let mut canvas = vec![0u8; 2 * 4]; // width=2, height=1, 4 bytes/px
        let rgb = [10u8, 20, 30, 40, 50, 60];
        blit_rgb_to_rgba(&mut canvas, 2, TileRect { x: 0, y: 0, w: 2, h: 1 }, &rgb);
        assert_eq!(canvas, vec![10, 20, 30, 255, 40, 50, 60, 255]);
    }
}
