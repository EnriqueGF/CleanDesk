//! Internal wire format carried inside `VideoFrame.data`, *before* zstd
//! compression. Private to this crate — nothing outside `cleandesk-codec`
//! ever needs to parse it, so it's free to evolve independently of
//! `PROTOCOL_VERSION` (which only gates the outer message set).
//!
//! We describe the payload as a small Rust struct and serialize it with
//! `postcard` — the same compact, non-self-describing binary format the rest
//! of CleanDesk already uses for its peer-to-peer wire messages (see
//! `cleandesk_proto::frame`) — then hand the resulting bytes to zstd. So the
//! full pipeline for `VideoFrame.data` is:
//!
//! ```text
//! Payload { version, cols, rows, tiles: Vec<TileEntry> }
//!   └─ postcard::to_allocvec  →  raw bytes
//!        └─ zstd::encode_all  →  VideoFrame.data
//! ```
//!
//! Logically, `Payload` is:
//!
//! ```text
//! Payload {
//!     version: u8,           // FORMAT_VERSION, so a decode failure caused by
//!                            // a future format change reads as a clear
//!                            // "unsupported version" instead of a confusing
//!                            // deserialization error.
//!     cols: u32,             // tile grid width
//!     rows: u32,             // tile grid height
//!     tiles: Vec<TileEntry>, // only the *included* tiles: every tile for a
//!                            // keyframe, just the dirty ones for a delta.
//! }
//! TileEntry {
//!     index: u32,    // row-major (ty * cols + tx) position in the grid
//!     jpeg: Vec<u8>, // one baseline JPEG (RGB8), exactly one tile's pixels
//! }
//! ```
//!
//! `cols`/`rows` duplicate information derivable from `VideoFrame.width`/
//! `height`, on purpose: it keeps this payload self-describing and lets
//! [`TileDecoder`](crate::TileDecoder) cross-check the two instead of
//! blindly trusting either one.

use serde::{Deserialize, Serialize};

use crate::error::CodecError;

/// Bumped whenever the shape of [`Payload`]/[`TileEntry`] changes in a way
/// that isn't backward compatible.
pub(crate) const FORMAT_VERSION: u8 = 1;

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct TileEntry {
    pub index: u32,
    pub jpeg: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct Payload {
    pub version: u8,
    pub cols: u32,
    pub rows: u32,
    pub tiles: Vec<TileEntry>,
}

impl Payload {
    pub(crate) fn new(cols: u32, rows: u32, tiles: Vec<TileEntry>) -> Self {
        Self { version: FORMAT_VERSION, cols, rows, tiles }
    }
}

pub(crate) fn encode(payload: &Payload) -> Result<Vec<u8>, CodecError> {
    postcard::to_allocvec(payload).map_err(CodecError::Serialize)
}

pub(crate) fn decode(bytes: &[u8]) -> Result<Payload, CodecError> {
    let payload: Payload = postcard::from_bytes(bytes).map_err(CodecError::Deserialize)?;
    if payload.version != FORMAT_VERSION {
        return Err(CodecError::UnsupportedVersion {
            found: payload.version,
            supported: FORMAT_VERSION,
        });
    }
    Ok(payload)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let payload = Payload::new(
            3,
            2,
            vec![
                TileEntry { index: 0, jpeg: vec![1, 2, 3] },
                TileEntry { index: 5, jpeg: vec![] },
            ],
        );
        let bytes = encode(&payload).unwrap();
        let back = decode(&bytes).unwrap();
        assert_eq!(back.version, FORMAT_VERSION);
        assert_eq!(back.cols, 3);
        assert_eq!(back.rows, 2);
        assert_eq!(back.tiles.len(), 2);
        assert_eq!(back.tiles[0].index, 0);
        assert_eq!(back.tiles[0].jpeg, vec![1, 2, 3]);
        assert_eq!(back.tiles[1].index, 5);
    }

    #[test]
    fn truncated_bytes_error_instead_of_panicking() {
        let payload = Payload::new(1, 1, vec![TileEntry { index: 0, jpeg: vec![9; 32] }]);
        let bytes = encode(&payload).unwrap();
        // Network data is never trusted: a peer could deliver a cut-off
        // buffer (or an attacker could craft one). This must error, not panic.
        assert!(decode(&bytes[..bytes.len() - 5]).is_err());
    }

    #[test]
    fn future_format_version_is_rejected_explicitly() {
        let payload = Payload { version: FORMAT_VERSION + 1, cols: 1, rows: 1, tiles: vec![] };
        let bytes = encode(&payload).unwrap();
        match decode(&bytes) {
            Err(CodecError::UnsupportedVersion { found, supported }) => {
                assert_eq!(found, FORMAT_VERSION + 1);
                assert_eq!(supported, FORMAT_VERSION);
            }
            other => panic!("expected UnsupportedVersion, got {other:?}"),
        }
    }
}
