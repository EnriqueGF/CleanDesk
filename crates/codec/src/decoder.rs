//! [`TileDecoder`]: reverses [`TileEncoder`](crate::TileEncoder)'s wire
//! format, maintaining a persistent RGBA8 canvas that successive delta frames
//! patch in place.
//!
//! Everything in a [`VideoFrame`] is untrusted: the dimensions, the flags and
//! the compressed bytes all come from the remote peer. The rules here are
//! that no field may drive an allocation before it has been bounded, and
//! that any malformed input surfaces as a [`CodecError`], never a panic.

use std::io::Read;

use cleandesk_proto::message::VideoFrame;
use tracing::{debug, trace};

use crate::{
    error::CodecError,
    jpeg, payload,
    tile::{grid_dims, tile_coords, tile_rect, MAX_DIMENSION},
    DecodedImage, VideoDecoder,
};

/// Extra slack (on top of the uncompressed RGBA size implied by the frame's
/// own `width`/`height`) allowed when zstd-decompressing a payload.
///
/// The payload is always *much* smaller than a raw RGBA copy of the frame
/// (it's JPEG tiles plus a tiny header), so this is a generous ceiling, not a
/// tight budget. It mostly matters for tiny frames, where the per-tile JPEG
/// headers can outweigh the pixel data itself.
const DECOMPRESS_SLACK_BYTES: u64 = 1024 * 1024;

/// Absolute ceiling on the decompressed payload size, regardless of what the
/// frame's dimensions would otherwise allow.
///
/// An 8192x8192 frame implies a raw RGBA size of 256 MiB, but the payload
/// never approaches that: JPEG at any usable quality is an order of
/// magnitude smaller than raw pixels. Capping here keeps the worst case a
/// hostile peer can force — even with valid, maximal dimensions — at a size
/// the viewer can absorb without being taken down.
const MAX_PAYLOAD_BYTES: u64 = 64 * 1024 * 1024;

/// Largest zstd window (as log2 bytes) the decoder will honor: 32 MiB.
///
/// The encoder compresses at a low level whose window is far below this, so
/// no legitimate frame is affected; the point is that zstd allocates its
/// window buffer from the frame header before producing a single byte of
/// output, and without a cap that header alone can demand 128 MiB.
const MAX_WINDOW_LOG: u32 = 25;

/// Size of the scratch buffer used while streaming decompressed bytes out.
/// Small enough to live on the stack, large enough that the per-call
/// overhead of the zstd streaming API is negligible.
const DECOMPRESS_CHUNK_BYTES: usize = 64 * 1024;

/// The persistent framebuffer a [`TileDecoder`] patches in place.
struct Canvas {
    width: u32,
    height: u32,
    rgba: Vec<u8>,
}

impl Canvas {
    /// Only ever called with dimensions that already passed
    /// [`check_dimensions`], so the product is bounded (at most 256 MiB).
    fn blank(width: u32, height: u32) -> Self {
        Self { width, height, rgba: vec![0u8; width as usize * height as usize * 4] }
    }

    /// Reset to black for a new keyframe, keeping the existing allocation
    /// when the resolution hasn't changed (the common "forced keyframe"
    /// case, e.g. after packet loss) so a keyframe doesn't cost a fresh
    /// multi-megabyte allocation on top of its decode work.
    fn reset(&mut self, width: u32, height: u32) {
        if self.width == width && self.height == height {
            self.rgba.fill(0);
        } else {
            *self = Self::blank(width, height);
        }
    }
}

/// Reject dimensions the codec is not willing to allocate for.
fn check_dimensions(width: u32, height: u32) -> Result<(), CodecError> {
    if width == 0 || height == 0 {
        return Err(CodecError::EmptyFrame);
    }
    if width > MAX_DIMENSION || height > MAX_DIMENSION {
        return Err(CodecError::FrameTooLarge { width, height, max: MAX_DIMENSION });
    }
    Ok(())
}

/// How many decompressed bytes a `width`x`height` frame may carry.
///
/// Computed in `u64` so the arithmetic can't overflow on any target, and
/// clamped to [`MAX_PAYLOAD_BYTES`]; the dimensions have already been
/// validated, so the result always fits a `usize`.
fn payload_limit(width: u32, height: u32) -> usize {
    let raw_rgba = u64::from(width) * u64::from(height) * 4;
    let limit = raw_rgba.saturating_add(DECOMPRESS_SLACK_BYTES).min(MAX_PAYLOAD_BYTES);
    usize::try_from(limit).unwrap_or(usize::MAX)
}

/// Decompress `data`, refusing to produce more than `limit` bytes.
///
/// Streams rather than using the one-shot API on purpose: the one-shot
/// variant pre-allocates its whole output budget up front, which is exactly
/// the allocation a hostile frame wants to provoke. Streaming lets the
/// output grow with what the stream *actually* produces and abort the moment
/// it oversteps, so a decompression bomb costs at most `limit` bytes (plus
/// zstd's bounded window) before it is rejected.
fn decompress_bounded(data: &[u8], limit: usize) -> Result<Vec<u8>, CodecError> {
    let mut decoder = zstd::stream::read::Decoder::with_buffer(data).map_err(CodecError::Decompress)?;
    decoder.window_log_max(MAX_WINDOW_LOG).map_err(CodecError::Decompress)?;

    let mut out = Vec::new();
    let mut chunk = [0u8; DECOMPRESS_CHUNK_BYTES];
    loop {
        let n = decoder.read(&mut chunk).map_err(CodecError::Decompress)?;
        if n == 0 {
            break;
        }
        if out.len() + n > limit {
            return Err(CodecError::PayloadTooLarge { limit });
        }
        out.extend_from_slice(&chunk[..n]);
    }
    Ok(out)
}

/// Tile-based [`VideoDecoder`]: the mirror image of [`TileEncoder`](crate::TileEncoder).
///
/// Holds the last fully-painted frame as an RGBA8 canvas so callers (the
/// egui viewer) always get a complete image back from [`decode`](VideoDecoder::decode),
/// never just the patch.
pub struct TileDecoder {
    canvas: Option<Canvas>,
}

impl TileDecoder {
    /// Create a decoder with no canvas yet. The first [`decode`](VideoDecoder::decode)
    /// call must be given a keyframe — see [`CodecError::MissingKeyframe`].
    pub fn new() -> Self {
        Self { canvas: None }
    }

    /// Decode `frame` onto the persistent canvas and copy the full canvas
    /// into `out`, returning the canvas `(width, height)`.
    ///
    /// This is the allocation-friendly form of [`VideoDecoder::decode`]: the
    /// trait method must hand back an owned [`DecodedImage`] every call,
    /// which means a fresh full-screen `Vec` per frame. Callers that own a
    /// texture-upload staging buffer can pass it here instead; `out` is
    /// cleared and refilled in place, so once it has reached canvas size no
    /// further allocation happens per frame. The copy itself is kept
    /// (rather than lending a `&[u8]` into the canvas) so the returned pixels
    /// stay valid while the decoder moves on to the next frame on another
    /// thread.
    ///
    /// On error the canvas is left in whatever state the failed frame
    /// reached; the encoder's next keyframe repaints it fully, and a delta
    /// only ever touches the tiles it carries, so nothing outside the frame
    /// that failed can be corrupted.
    pub fn decode_into(&mut self, frame: &VideoFrame, out: &mut Vec<u8>) -> Result<(u32, u32), CodecError> {
        // Bound the dimensions *before* they drive any allocation.
        check_dimensions(frame.width, frame.height)?;

        let raw = decompress_bounded(&frame.data, payload_limit(frame.width, frame.height))?;
        let parsed = payload::decode(&raw)?;

        // The grid check below already implies a non-empty grid (a non-empty
        // frame always needs at least one tile), but `tile_coords` divides by
        // `cols`, so make the guarantee explicit rather than rely on the
        // ordering of checks staying this way.
        if parsed.cols == 0 || parsed.rows == 0 {
            return Err(CodecError::EmptyGrid { cols: parsed.cols, rows: parsed.rows });
        }
        let (expected_cols, expected_rows) = grid_dims(frame.width, frame.height);
        if parsed.cols != expected_cols || parsed.rows != expected_rows {
            return Err(CodecError::GridMismatch { width: frame.width, height: frame.height });
        }

        // A delta can only patch a canvas that already matches this frame's
        // resolution; if it doesn't, the only way forward is a keyframe,
        // which redefines the canvas.
        let dims_differ = self
            .canvas
            .as_ref()
            .is_none_or(|c| c.width != frame.width || c.height != frame.height);
        if dims_differ && !frame.keyframe {
            return Err(CodecError::MissingKeyframe);
        }
        let canvas = match (&mut self.canvas, frame.keyframe) {
            (Some(canvas), true) => {
                debug!(width = frame.width, height = frame.height, "cleandesk-codec: resetting canvas");
                canvas.reset(frame.width, frame.height);
                canvas
            }
            (Some(canvas), false) => canvas,
            (slot @ None, _) => {
                debug!(width = frame.width, height = frame.height, "cleandesk-codec: allocating canvas");
                slot.insert(Canvas::blank(frame.width, frame.height))
            }
        };

        for tile in &parsed.tiles {
            let (tx, ty) = tile_coords(tile.index, parsed.cols);
            if tx >= parsed.cols || ty >= parsed.rows {
                return Err(CodecError::TileOutOfRange {
                    index: tile.index,
                    cols: parsed.cols,
                    rows: parsed.rows,
                });
            }
            let rect = tile_rect(tx, ty, frame.width, frame.height);
            let (w, h, rgb) = jpeg::decode_tile(tile.index, &tile.jpeg)?;
            if w != rect.w || h != rect.h {
                return Err(CodecError::TileSizeMismatch {
                    index: tile.index,
                    expected_w: rect.w,
                    expected_h: rect.h,
                    got_w: w,
                    got_h: h,
                });
            }
            jpeg::blit_rgb_to_rgba(&mut canvas.rgba, canvas.width, rect, &rgb);
        }

        trace!(
            sequence = frame.sequence,
            keyframe = frame.keyframe,
            tiles = parsed.tiles.len(),
            "cleandesk-codec: decoded frame"
        );

        out.clear();
        out.extend_from_slice(&canvas.rgba);
        Ok((canvas.width, canvas.height))
    }
}

impl Default for TileDecoder {
    fn default() -> Self {
        Self::new()
    }
}

impl VideoDecoder for TileDecoder {
    /// Allocates one full-canvas `Vec` per call by contract (the caller owns
    /// the result). See [`TileDecoder::decode_into`] to reuse a buffer.
    fn decode(&mut self, frame: &VideoFrame) -> anyhow::Result<DecodedImage> {
        let mut rgba = Vec::new();
        let (width, height) = self.decode_into(frame, &mut rgba)?;
        Ok(DecodedImage { width, height, rgba })
    }
}

/// Hostile-payload tests that need to hand-craft the private tile payload
/// (the public API can only produce well-formed frames). Everything here
/// must come back as `Err`, never a panic or a runaway allocation.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        payload::{Payload, TileEntry},
        tile::{TileRect, TILE_SIZE},
    };

    /// Wrap a crafted payload in a `VideoFrame` exactly as the encoder would.
    fn frame_from_payload(width: u32, height: u32, keyframe: bool, p: &Payload) -> VideoFrame {
        let raw = payload::encode(p).unwrap();
        let data = zstd::encode_all(&raw[..], 3).unwrap();
        VideoFrame { sequence: 0, width, height, keyframe, timestamp_us: 0, data }
    }

    fn solid_jpeg(index: u32, w: u32, h: u32) -> Vec<u8> {
        let rgb = vec![128u8; (w * h * 3) as usize];
        jpeg::encode_tile(index, &rgb, TileRect { x: 0, y: 0, w, h }, 80).unwrap()
    }

    fn decode(width: u32, height: u32, p: &Payload) -> Result<(u32, u32), CodecError> {
        TileDecoder::new().decode_into(&frame_from_payload(width, height, true, p), &mut Vec::new())
    }

    #[test]
    fn tile_index_out_of_range_is_rejected() {
        // 64x64 => 1x1 grid; index 1 is one past the end.
        let p = Payload::new(1, 1, vec![TileEntry { index: 1, jpeg: solid_jpeg(1, 64, 64) }]);
        let err = decode(64, 64, &p);
        assert!(matches!(err, Err(CodecError::TileOutOfRange { index: 1, cols: 1, rows: 1 })), "{err:?}");
    }

    #[test]
    fn tile_index_u32_max_is_rejected_without_panicking() {
        let p = Payload::new(2, 2, vec![TileEntry { index: u32::MAX, jpeg: vec![] }]);
        let err = decode(128, 128, &p);
        assert!(matches!(err, Err(CodecError::TileOutOfRange { .. })), "{err:?}");
    }

    #[test]
    fn grid_mismatch_is_rejected() {
        // 128x128 needs a 2x2 grid; the payload claims 1x1.
        let p = Payload::new(1, 1, vec![]);
        let err = decode(128, 128, &p);
        assert!(matches!(err, Err(CodecError::GridMismatch { width: 128, height: 128 })), "{err:?}");
    }

    #[test]
    fn empty_grid_is_rejected_before_any_division() {
        for (cols, rows) in [(0, 0), (0, 1), (1, 0)] {
            let p = Payload::new(cols, rows, vec![TileEntry { index: 0, jpeg: vec![] }]);
            let err = decode(64, 64, &p);
            assert!(matches!(err, Err(CodecError::EmptyGrid { .. })), "{cols}x{rows}: {err:?}");
        }
    }

    #[test]
    fn jpeg_tile_with_wrong_dimensions_is_rejected() {
        // Full 64x64 tile expected, a 32x32 JPEG delivered.
        let p = Payload::new(1, 1, vec![TileEntry { index: 0, jpeg: solid_jpeg(0, 32, 32) }]);
        let err = decode(64, 64, &p);
        assert!(
            matches!(
                err,
                Err(CodecError::TileSizeMismatch { index: 0, expected_w: 64, expected_h: 64, got_w: 32, got_h: 32 })
            ),
            "{err:?}"
        );
    }

    #[test]
    fn jpeg_tile_larger_than_a_tile_is_rejected_by_the_decoder_limits() {
        // A "tile" twice the tile size must not even be decoded: the image
        // reader's limits reject it from the header alone.
        let big = TILE_SIZE * 2;
        let p = Payload::new(1, 1, vec![TileEntry { index: 0, jpeg: solid_jpeg(0, big, big) }]);
        let err = decode(64, 64, &p);
        assert!(matches!(err, Err(CodecError::JpegDecode { index: 0, .. })), "{err:?}");
    }

    #[test]
    fn non_jpeg_tile_bytes_are_rejected() {
        let p = Payload::new(1, 1, vec![TileEntry { index: 0, jpeg: b"definitely not a jpeg".to_vec() }]);
        let err = decode(64, 64, &p);
        assert!(matches!(err, Err(CodecError::JpegDecode { index: 0, .. })), "{err:?}");
    }

    #[test]
    fn payload_limit_is_generous_for_small_frames_and_capped_for_large_ones() {
        assert_eq!(payload_limit(1, 1), 4 + DECOMPRESS_SLACK_BYTES as usize);
        assert_eq!(payload_limit(MAX_DIMENSION, MAX_DIMENSION), MAX_PAYLOAD_BYTES as usize);
        // Never below what a real 4K keyframe could plausibly need.
        assert!(payload_limit(3840, 2160) > 16 * 1024 * 1024);
    }

    #[test]
    fn bounded_decompress_rejects_output_over_the_limit_without_reading_it_all() {
        let zeros = vec![0u8; 4 * 1024 * 1024];
        let bomb = zstd::encode_all(&zeros[..], 3).unwrap();
        assert!(bomb.len() < 4096, "zeros should compress to almost nothing");
        let err = decompress_bounded(&bomb, 1024);
        assert!(matches!(err, Err(CodecError::PayloadTooLarge { limit: 1024 })), "{err:?}");
        // Exactly at the limit is still fine: the bound is inclusive.
        assert_eq!(decompress_bounded(&bomb, zeros.len()).unwrap().len(), zeros.len());
    }
}
