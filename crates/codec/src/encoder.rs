//! [`TileEncoder`]: splits frames into [`TILE_SIZE`](crate::TILE_SIZE) tiles,
//! JPEG-encodes only the ones that changed since the last frame, and
//! zstd-compresses the batch into `VideoFrame.data`.

use cleandesk_proto::{message::VideoFrame, quality::QualityParams};
use tracing::{debug, trace};

use crate::{
    error::CodecError,
    jpeg,
    payload::{self, Payload, TileEntry},
    tile::{grid_dims, tile_index, tile_rect, TileRect, MAX_DIMENSION},
    RawFrame, VideoEncoder,
};

/// zstd level used to compress the tile payload.
///
/// Kept low on purpose: the payload is dominated by JPEG bytes, which are
/// already entropy-coded and barely compress further, and this codec targets
/// interactive latency over squeezing out the last few percent of ratio.
/// Level 3 still meaningfully shrinks the cheap parts (headers, tile
/// indices, and fully flat/synthetic content such as a solid background or a
/// terminal) for a small, predictable fraction of the CPU cost of the higher
/// levels.
const ZSTD_LEVEL: i32 = 3;

/// Snapshot of the last frame handed to [`TileEncoder::encode`], kept around
/// so the *next* frame can be diffed against it.
///
/// We keep raw pixels rather than a hash of each tile: comparing a tile's
/// bytes is a `memcmp` the optimizer already knows how to vectorize, it's
/// cheap next to the JPEG encode it might save, and — unlike a hash — it can
/// never falsely call a changed tile "clean" due to a collision.
struct PrevFrame {
    width: u32,
    height: u32,
    /// Tightly packed BGRA8, row-major, no stride padding. Repacking here
    /// decouples the comparison from whatever stride any given captured
    /// frame happened to use.
    bgra: Vec<u8>,
}

/// Tile-based [`VideoEncoder`]: JPEG per dirty tile, zstd over the batch.
///
/// See the crate-level docs for the overall design and `docs/ARCHITECTURE.md`
/// for how this fits into the host/client pipeline.
pub struct TileEncoder {
    params: QualityParams,
    sequence: u64,
    prev: Option<PrevFrame>,
    force_keyframe: bool,
}

impl TileEncoder {
    /// Create an encoder with the given initial quality parameters. The very
    /// first frame handed to [`encode`](VideoEncoder::encode) is always a
    /// keyframe, regardless of this setting.
    pub fn new(params: QualityParams) -> Self {
        Self { params, sequence: 0, prev: None, force_keyframe: false }
    }

    /// A tile is dirty if any of its bytes differ from the same rectangle in
    /// the previous frame. Only ever called when `self.prev` is `Some` *and*
    /// at the same resolution (callers short-circuit past this otherwise), so
    /// the rectangle is guaranteed to be in bounds on both buffers.
    fn tile_changed(&self, frame: &RawFrame<'_>, rect: TileRect) -> bool {
        let prev = self
            .prev
            .as_ref()
            .expect("tile_changed is only called once a previous frame exists");
        let prev_stride = prev.width as usize * 4;
        for row in 0..rect.h {
            let cur_start = (rect.y + row) as usize * frame.stride + rect.x as usize * 4;
            let cur = &frame.bgra[cur_start..cur_start + rect.w as usize * 4];
            let prev_start = (rect.y + row) as usize * prev_stride + rect.x as usize * 4;
            let old = &prev.bgra[prev_start..prev_start + rect.w as usize * 4];
            if cur != old {
                return true;
            }
        }
        false
    }

    /// Repack the current frame into a tightly packed buffer and store it as
    /// the diff baseline for the next call.
    fn store_prev(&mut self, frame: &RawFrame<'_>) {
        let row_bytes = frame.width as usize * 4;
        let mut packed = vec![0u8; row_bytes * frame.height as usize];
        for y in 0..frame.height as usize {
            let src = &frame.bgra[y * frame.stride..y * frame.stride + row_bytes];
            packed[y * row_bytes..(y + 1) * row_bytes].copy_from_slice(src);
        }
        self.prev = Some(PrevFrame { width: frame.width, height: frame.height, bgra: packed });
    }
}

impl VideoEncoder for TileEncoder {
    fn encode(&mut self, frame: RawFrame<'_>) -> anyhow::Result<VideoFrame> {
        if frame.width == 0 || frame.height == 0 {
            return Err(CodecError::EmptyFrame.into());
        }
        // Mirror of the decoder's check: anything we'd produce here would be
        // rejected by every conforming decoder, so fail early and loudly.
        if frame.width > MAX_DIMENSION || frame.height > MAX_DIMENSION {
            return Err(CodecError::FrameTooLarge {
                width: frame.width,
                height: frame.height,
                max: MAX_DIMENSION,
            }
            .into());
        }
        let min_stride = frame.width as usize * 4;
        if frame.stride < min_stride {
            return Err(
                CodecError::StrideTooSmall { stride: frame.stride, width: frame.width, min: min_stride }
                    .into(),
            );
        }
        let needed = frame.stride * frame.height as usize;
        if frame.bgra.len() < needed {
            return Err(CodecError::BufferTooSmall {
                stride: frame.stride,
                height: frame.height,
                needed,
                got: frame.bgra.len(),
            }
            .into());
        }

        // Keyframe iff: this is the first frame ever, the caller explicitly
        // asked for one, or the resolution changed (a delta can only patch a
        // canvas of the same size, so a resize must restart from scratch).
        let is_first = self.prev.is_none();
        let resized = self
            .prev
            .as_ref()
            .is_some_and(|p| p.width != frame.width || p.height != frame.height);
        let keyframe = self.force_keyframe || is_first || resized;

        let (cols, rows) = grid_dims(frame.width, frame.height);
        let mut tiles = Vec::new();
        for ty in 0..rows {
            for tx in 0..cols {
                let rect = tile_rect(tx, ty, frame.width, frame.height);
                // Short-circuits past `tile_changed` on a keyframe, so it's
                // never called when there is nothing valid to diff against.
                let dirty = keyframe || self.tile_changed(&frame, rect);
                if !dirty {
                    continue;
                }
                let index = tile_index(tx, ty, cols);
                let rgb = jpeg::crop_bgra_to_rgb(&frame, rect);
                let jpeg_bytes = jpeg::encode_tile(index, &rgb, rect, self.params.quality)?;
                tiles.push(TileEntry { index, jpeg: jpeg_bytes });
            }
        }
        let included = tiles.len();
        let total = (cols as usize) * (rows as usize);

        // Diff against *original* source pixels every time (never against
        // what the decoder reconstructed from a previous JPEG), so encoding
        // error never accumulates across deltas: every included tile is a
        // fresh, independent compression of ground truth.
        self.store_prev(&frame);

        let raw = payload::encode(&Payload::new(cols, rows, tiles))?;
        let data = zstd::encode_all(&raw[..], ZSTD_LEVEL).map_err(CodecError::Compress)?;

        let sequence = self.sequence;
        self.sequence += 1;
        self.force_keyframe = false;

        debug!(
            sequence,
            keyframe,
            tiles = included,
            total_tiles = total,
            bytes = data.len(),
            "cleandesk-codec: encoded frame"
        );
        trace!(width = frame.width, height = frame.height, cols, rows, "tile grid");

        Ok(VideoFrame {
            sequence,
            width: frame.width,
            height: frame.height,
            keyframe,
            timestamp_us: frame.timestamp_us,
            data,
        })
    }

    fn force_keyframe(&mut self) {
        self.force_keyframe = true;
    }

    fn set_quality(&mut self, params: QualityParams) {
        self.params = params;
    }
}
