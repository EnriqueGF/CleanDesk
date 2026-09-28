//! cleandesk-codec
//!
//! Tile-based video codec for CleanDesk's host→viewer media plane: produces
//! and consumes [`cleandesk_proto::message::VideoFrame`] so it can later be
//! swapped for a hardware codec (H.264/HEVC via NVENC) without touching
//! `host`/`client` — see `docs/ARCHITECTURE.md`.
//!
//! # Design
//!
//! The frame is split into fixed [`TILE_SIZE`]×[`TILE_SIZE`] tiles.
//! [`TileEncoder`] keeps the previous frame's raw pixels and only
//! JPEG-encodes tiles whose bytes changed since then (a *delta* frame); the
//! first frame, a forced keyframe, or a resolution change encodes every tile
//! (a *keyframe*, self-contained). The included tiles are packed into a small
//! internal payload (see the private `payload` module) and zstd-compressed
//! into [`cleandesk_proto::message::VideoFrame::data`].
//!
//! [`TileDecoder`] mirrors this: it keeps a persistent RGBA8 canvas and blits
//! each incoming frame's tiles onto it, always returning the *full* canvas so
//! callers (the egui viewer) never have to track partial state themselves.
//!
//! Original implementation built from public-domain knowledge of JPEG, zstd and
//! tiled/dirty-rect video diffing.
//!
//! # Chroma subsampling
//!
//! [`cleandesk_proto::quality::QualityParams::subsample`] is accepted by
//! [`TileEncoder::set_quality`] but currently has no effect: the `image`
//! crate's JPEG encoder (the one available under this crate's dependency, see
//! `Cargo.toml`) does not expose a public way to pick 4:2:0 vs. 4:4:4 chroma
//! sampling — it always encodes with its own fixed internal scheme. The field
//! is kept and threaded through so a future encoder swap (or a lower-level
//! JPEG library that does expose it) can honor it without changing the public
//! API again.

mod decoder;
mod encoder;
mod error;
mod jpeg;
mod payload;
mod tile;

pub use decoder::TileDecoder;
pub use encoder::TileEncoder;
pub use error::CodecError;
pub use tile::{MAX_DIMENSION, TILE_SIZE};

use cleandesk_proto::{message::VideoFrame, quality::QualityParams};

/// Crate version string, handy for diagnostics.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// A raw captured frame in BGRA8, as produced by `cleandesk-capture`.
///
/// Borrows its pixel buffer so the capture crate can hand over a mapped /
/// double-buffered region without an extra copy. `stride` is the number of
/// bytes per row and may be larger than `width * 4`: DXGI Desktop Duplication
/// typically pads rows to a hardware-friendly alignment.
pub struct RawFrame<'a> {
    pub width: u32,
    pub height: u32,
    pub stride: usize,
    pub bgra: &'a [u8],
    pub timestamp_us: u64,
}

/// A fully decoded image in RGBA8, ready to upload as a texture.
///
/// RGBA (not BGRA) because that's what egui's texture API consumes; the
/// channel swap happens once per tile at decode time in the `jpeg` module.
pub struct DecodedImage {
    pub width: u32,
    pub height: u32,
    pub rgba: Vec<u8>,
}

/// Hand-written so a `Debug` dump (test failures, logs) shows the shape of
/// the image instead of megabytes of pixel bytes.
impl std::fmt::Debug for DecodedImage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DecodedImage")
            .field("width", &self.width)
            .field("height", &self.height)
            .field("rgba_len", &self.rgba.len())
            .finish()
    }
}

/// Encodes [`RawFrame`]s into wire [`VideoFrame`]s.
///
/// Implementations decide internally whether a given call produces a
/// keyframe or a delta; callers can only request one explicitly via
/// [`force_keyframe`](VideoEncoder::force_keyframe) (e.g. after detecting
/// packet loss upstream, or when a new viewer joins mid-session).
pub trait VideoEncoder: Send {
    /// Encode one frame. Pure CPU work — never blocks on I/O.
    fn encode(&mut self, frame: RawFrame<'_>) -> anyhow::Result<VideoFrame>;
    /// Force the *next* `encode` call to produce a self-contained keyframe.
    fn force_keyframe(&mut self);
    /// Change encode parameters (quality/fps target) for subsequent frames.
    fn set_quality(&mut self, params: QualityParams);
}

/// Decodes wire [`VideoFrame`]s back into full [`DecodedImage`]s.
pub trait VideoDecoder: Send {
    /// Decode one frame, patching it onto (or, for a keyframe, replacing) the
    /// persistent canvas, and returning the full current image every time.
    fn decode(&mut self, frame: &VideoFrame) -> anyhow::Result<DecodedImage>;
}
