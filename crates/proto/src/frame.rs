//! Length-delimited wire framing for the peer-to-peer data channels.
//!
//! WebRTC data channels are message-oriented, but we still want a uniform,
//! self-describing envelope for the reliable control channel and for chunked
//! binary sub-streams (file transfer). Each frame is:
//!
//! ```text
//! +-----------------+-------------------------+
//! | u32 LE length N | N bytes postcard payload |
//! +-----------------+-------------------------+
//! ```
//!
//! `encode` / `decode` wrap [`postcard`] for the typed messages, and
//! [`FrameCodec`] handles the streaming case where reads arrive in arbitrary
//! chunks (e.g. over a TCP relay).

use crate::error::ProtoError;
use bytes::{Buf, BufMut, BytesMut};
use serde::{de::DeserializeOwned, Serialize};

/// Hard cap on a single frame (16 MiB) to bound memory on malicious input.
pub const MAX_FRAME_SIZE: usize = 16 * 1024 * 1024;

/// Serialize a value into a length-delimited frame appended to `out`.
pub fn encode<T: Serialize>(value: &T, out: &mut BytesMut) -> Result<(), ProtoError> {
    let payload = postcard::to_allocvec(value).map_err(|e| ProtoError::Encode(e.to_string()))?;
    if payload.len() > MAX_FRAME_SIZE {
        return Err(ProtoError::FrameTooLarge { size: payload.len(), max: MAX_FRAME_SIZE });
    }
    out.reserve(4 + payload.len());
    out.put_u32_le(payload.len() as u32);
    out.put_slice(&payload);
    Ok(())
}

/// Serialize a value into a fresh `Vec` frame (convenience for one-shot sends).
pub fn encode_vec<T: Serialize>(value: &T) -> Result<Vec<u8>, ProtoError> {
    let mut buf = BytesMut::new();
    encode(value, &mut buf)?;
    Ok(buf.to_vec())
}

/// Serialize a value into an un-framed payload (no length prefix).
///
/// Use this when the transport already delivers whole messages (WebRTC data
/// channels): each channel send carries exactly one encoded value.
pub fn encode_payload<T: Serialize>(value: &T) -> Result<Vec<u8>, ProtoError> {
    postcard::to_allocvec(value).map_err(|e| ProtoError::Encode(e.to_string()))
}

/// Decode exactly one value from a complete, un-framed payload slice.
///
/// The inverse of [`encode_payload`]; use it when the transport already delivers
/// whole messages (WebRTC data channels), so no length prefix is needed.
///
/// Strict: the value must consume the whole slice. A message is exactly one
/// channel send, so trailing bytes mean corruption (or an attempt to smuggle
/// data past a validator), never a legitimate second message.
pub fn decode_payload<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, ProtoError> {
    let (value, rest) =
        postcard::take_from_bytes(bytes).map_err(|e| ProtoError::Decode(e.to_string()))?;
    if !rest.is_empty() {
        return Err(ProtoError::Decode(format!("{} trailing bytes after message", rest.len())));
    }
    Ok(value)
}

/// A streaming decoder for length-delimited frames arriving in arbitrary chunks.
#[derive(Debug, Default)]
pub struct FrameCodec {
    buf: BytesMut,
}

impl FrameCodec {
    pub fn new() -> Self {
        Self::default()
    }

    /// Feed freshly received bytes into the internal buffer.
    pub fn feed(&mut self, chunk: &[u8]) {
        self.buf.extend_from_slice(chunk);
    }

    /// Try to pull the next complete frame's *raw payload* out of the buffer.
    ///
    /// Returns `Ok(None)` when more bytes are needed.
    pub fn next_payload(&mut self) -> Result<Option<Vec<u8>>, ProtoError> {
        if self.buf.len() < 4 {
            return Ok(None);
        }
        let len = (&self.buf[..4]).get_u32_le() as usize;
        if len > MAX_FRAME_SIZE {
            return Err(ProtoError::FrameTooLarge { size: len, max: MAX_FRAME_SIZE });
        }
        if self.buf.len() < 4 + len {
            return Ok(None);
        }
        self.buf.advance(4);
        let payload = self.buf.split_to(len).to_vec();
        Ok(Some(payload))
    }

    /// Try to decode the next complete typed frame.
    ///
    /// Named `next_message` (not `next`) on purpose: this is not an [`Iterator`]
    /// — it is fallible and generic over the decoded type per call.
    pub fn next_message<T: DeserializeOwned>(&mut self) -> Result<Option<T>, ProtoError> {
        match self.next_payload()? {
            Some(bytes) => Ok(Some(decode_payload(&bytes)?)),
            None => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::InputEvent;

    #[test]
    fn roundtrip_single() {
        let ev = InputEvent::MouseMove { x: 0.5, y: 0.25 };
        let bytes = encode_vec(&ev).unwrap();
        // Strip the 4-byte prefix for decode_payload.
        let payload = &bytes[4..];
        let back: InputEvent = decode_payload(payload).unwrap();
        assert_eq!(ev, back);
    }

    #[test]
    fn streaming_partial_then_complete() {
        let ev = InputEvent::Key { code: 65, pressed: true };
        let bytes = encode_vec(&ev).unwrap();
        let mut codec = FrameCodec::new();
        // Feed one byte at a time; only the last feed should yield a frame.
        for (i, b) in bytes.iter().enumerate() {
            codec.feed(&[*b]);
            let got: Option<InputEvent> = codec.next_message().unwrap();
            if i + 1 < bytes.len() {
                assert!(got.is_none());
            } else {
                assert_eq!(got, Some(ev));
            }
        }
    }

    #[test]
    fn rejects_oversize_prefix() {
        let mut codec = FrameCodec::new();
        codec.feed(&u32::MAX.to_le_bytes());
        codec.feed(&[0u8; 8]);
        assert!(codec.next_payload().is_err());
    }
}
