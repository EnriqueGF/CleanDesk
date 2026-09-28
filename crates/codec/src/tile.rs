//! Tile grid geometry shared by the encoder and decoder.

/// Edge length, in pixels, of one (square) tile.
///
/// 64 is a middle ground: large enough that per-tile JPEG overhead (headers,
/// the DC coefficient, block boundaries) stays small relative to the pixel
/// data it carries, small enough that a tiny local change (a blinking cursor,
/// a spinner) doesn't force re-encoding a big chunk of the screen. It also
/// matches the dirty-rect granularity `cleandesk-capture` computes on the
/// DXGI side (see `docs/ARCHITECTURE.md`), so the two line up.
pub const TILE_SIZE: u32 = 64;

/// Largest width or height (in pixels) the codec will encode or decode.
///
/// 8192 comfortably covers 8K desktops and any multi-monitor layout the host
/// is expected to capture. Its real purpose is on the decoder side: a frame's
/// `width`/`height` arrive from the network, and every allocation the decoder
/// makes (canvas, decompression budget) is derived from them, so an unbounded
/// value would let a hostile peer force a multi-gigabyte allocation with a
/// few bytes. The encoder applies the same limit so both ends agree on what
/// a valid frame is.
pub const MAX_DIMENSION: u32 = 8192;

/// Number of tile columns/rows needed to cover a `width`×`height` image.
///
/// Rounds up so a width/height that isn't a multiple of [`TILE_SIZE`] still
/// gets fully covered — the last column/row is simply narrower/shorter, see
/// [`tile_rect`].
pub(crate) fn grid_dims(width: u32, height: u32) -> (u32, u32) {
    (width.div_ceil(TILE_SIZE), height.div_ceil(TILE_SIZE))
}

/// Row-major index of tile `(tx, ty)` in a grid `cols` tiles wide.
pub(crate) fn tile_index(tx: u32, ty: u32, cols: u32) -> u32 {
    ty * cols + tx
}

/// Inverse of [`tile_index`]: recover `(tx, ty)` from a row-major index.
pub(crate) fn tile_coords(index: u32, cols: u32) -> (u32, u32) {
    (index % cols, index / cols)
}

/// The pixel rectangle covered by tile `(tx, ty)` in a grid over a
/// `width`×`height` image.
///
/// Edge tiles are *cropped*, not padded: `w`/`h` are clamped to whatever
/// pixels are actually left, so they can be smaller than [`TILE_SIZE`]. This
/// is what makes non-multiple-of-64 resolutions work correctly end to end.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TileRect {
    pub x: u32,
    pub y: u32,
    pub w: u32,
    pub h: u32,
}

pub(crate) fn tile_rect(tx: u32, ty: u32, width: u32, height: u32) -> TileRect {
    let x = tx * TILE_SIZE;
    let y = ty * TILE_SIZE;
    let w = TILE_SIZE.min(width.saturating_sub(x));
    let h = TILE_SIZE.min(height.saturating_sub(y));
    TileRect { x, y, w, h }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grid_dims_exact_multiple() {
        assert_eq!(grid_dims(128, 64), (2, 1));
    }

    #[test]
    fn grid_dims_rounds_up_for_partial_edge_tiles() {
        assert_eq!(grid_dims(100, 70), (2, 2));
    }

    #[test]
    fn edge_tile_is_cropped_not_padded() {
        // 100x70 => grid 2x2; tile (1,1) covers x=[64,100), y=[64,70) => 36x6.
        let rect = tile_rect(1, 1, 100, 70);
        assert_eq!(rect, TileRect { x: 64, y: 64, w: 36, h: 6 });
    }

    #[test]
    fn full_tile_is_64x64() {
        let rect = tile_rect(0, 0, 200, 200);
        assert_eq!(rect, TileRect { x: 0, y: 0, w: 64, h: 64 });
    }

    #[test]
    fn index_roundtrip() {
        let cols = 5;
        for index in 0..20 {
            let (tx, ty) = tile_coords(index, cols);
            assert_eq!(tile_index(tx, ty, cols), index);
        }
    }
}
