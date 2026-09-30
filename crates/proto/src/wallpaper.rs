//! Bounded desktop-background previews, introduced in protocol 2.5.
pub const MAX_WIDTH: u32 = 320;
pub const MAX_HEIGHT: u32 = 180;
pub const MAX_BYTES: usize = 48 * 1024;

/// Cheap envelope validation before forwarding a preview to the image decoder.
pub fn valid_payload(jpeg: &[u8]) -> bool {
    jpeg.len() <= MAX_BYTES && jpeg.starts_with(&[0xff, 0xd8])
}
