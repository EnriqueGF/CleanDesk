//! Codec-specific error type.
//!
//! Kept separate from [`cleandesk_proto::ProtoError`]: failures here are about
//! pixels, tiling and compression, not about the wire envelope those bytes
//! eventually travel in.

use thiserror::Error;

/// Errors produced while encoding or decoding CleanDesk video frames.
#[derive(Debug, Error)]
pub enum CodecError {
    #[error("cannot encode/decode a frame with zero width or height")]
    EmptyFrame,

    #[error(
        "frame {width}x{height} exceeds the maximum supported dimension          of {max} px per side"
    )]
    FrameTooLarge { width: u32, height: u32, max: u32 },

    #[error("frame {width}x{height} exceeds the maximum supported area of {max} pixels")]
    FrameAreaTooLarge { width: u32, height: u32, max: u64 },

    #[error("tile payload carries {count} tiles for a grid of {cols}x{rows}")]
    TooManyTiles { count: usize, cols: u32, rows: u32 },

    #[error("tile index {index} repeats or is out of order in the payload")]
    TileOrder { index: u32 },

    #[error(
        "stride {stride} bytes is too small for width {width} \
         (need >= {min} bytes/row for BGRA8)"
    )]
    StrideTooSmall { stride: usize, width: u32, min: usize },

    #[error(
        "raw frame buffer too small: stride {stride} x height {height} \
         needs {needed} bytes, got {got}"
    )]
    BufferTooSmall { stride: usize, height: u32, needed: usize, got: usize },

    #[error("JPEG encode failed for tile {index}: {source}")]
    JpegEncode { index: u32, #[source] source: image::ImageError },

    #[error("JPEG decode failed for tile {index}: {source}")]
    JpegDecode { index: u32, #[source] source: image::ImageError },

    #[error("zstd compression failed: {0}")]
    Compress(#[source] std::io::Error),

    #[error("zstd decompression failed: {0}")]
    Decompress(#[source] std::io::Error),

    #[error("decompressed tile payload exceeds the {limit}-byte limit for this frame size")]
    PayloadTooLarge { limit: usize },

    #[error("failed to serialize tile payload: {0}")]
    Serialize(#[source] postcard::Error),

    #[error("failed to deserialize tile payload: {0}")]
    Deserialize(#[source] postcard::Error),

    #[error("unsupported tile payload version {found} (this build supports {supported})")]
    UnsupportedVersion { found: u8, supported: u8 },

    #[error("tile payload declares an empty {cols}x{rows} grid")]
    EmptyGrid { cols: u32, rows: u32 },

    #[error("tile index {index} is out of range for a {cols}x{rows} grid")]
    TileOutOfRange { index: u32, cols: u32, rows: u32 },

    #[error("tile payload grid does not match frame dimensions {width}x{height}")]
    GridMismatch { width: u32, height: u32 },

    #[error("decoded tile {index} is {got_w}x{got_h}, expected {expected_w}x{expected_h}")]
    TileSizeMismatch { index: u32, expected_w: u32, expected_h: u32, got_w: u32, got_h: u32 },

    #[error("received a delta frame with no matching keyframe to patch onto")]
    MissingKeyframe,
}
