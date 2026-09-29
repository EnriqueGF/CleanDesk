//! Chunking of video frames for the media data channel.
//!
//! WebRTC/SCTP data-channel messages are bounded (~16 KiB is the safe portable
//! limit). A keyframe is far larger, so the host splits each [`VideoFrame`] into
//! [`FrameChunk`]s, sends each chunk as one channel message, and the viewer
//! reassembles them with a [`Reassembler`].
//!
//! The video channel is *unreliable and unordered* (see `cleandesk-transport`),
//! so chunks may be lost or arrive out of order. The reassembler therefore keys
//! everything by frame sequence: a fresher frame supersedes an incomplete older
//! one (drop it and wait for the next keyframe) — exactly the right behavior for
//! low-latency video.
//!
//! Every chunk comes from the network and is treated as hostile: inconsistent
//! headers, out-of-range indices and absurd chunk counts are rejected before
//! they can touch memory.

use crate::error::ProtoError;
use crate::message::VideoFrame;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Safe per-message payload budget for a data-channel send (16 KiB minus room
/// for the postcard-encoded [`FrameChunk`] header).
pub const MAX_CHUNK_PAYLOAD: usize = 16 * 1024 - 256;

/// Upper bound on the number of chunks one frame may be split into.
///
/// `FrameChunk::index`/`count` are `u16`, and a frame is capped at
/// [`crate::frame::MAX_FRAME_SIZE`] anyway, so anything beyond this is either a
/// caller bug or a hostile peer trying to make the receiver buffer forever.
pub const MAX_CHUNKS_PER_FRAME: u16 = u16::MAX;

/// Upper bound on the bytes a [`Reassembler`] holds for the frame in
/// progress. `count` × [`MAX_CHUNK_PAYLOAD`] would allow ~1 GiB, far beyond
/// any real frame (the decoder caps decompression at 64 MiB anyway), so a
/// peer announcing a huge `count` and drip-feeding chunks cannot pin memory.
pub const MAX_BUFFERED_BYTES: usize = 64 * 1024 * 1024;

/// One slice of a [`VideoFrame`], carried as a single data-channel message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FrameChunk {
    /// Frame sequence number this chunk belongs to.
    pub seq: u64,
    /// 0-based index of this chunk within the frame.
    pub index: u16,
    /// Total number of chunks in the frame.
    pub count: u16,
    pub keyframe: bool,
    pub width: u32,
    pub height: u32,
    pub timestamp_us: u64,
    /// The chunk's slice of `VideoFrame.data`.
    pub payload: Vec<u8>,
}

/// Split a frame into chunks no larger than `max_payload` bytes each.
///
/// A frame with empty data still yields exactly one (empty) chunk so the
/// receiver can observe the frame. Fails with [`ProtoError::FrameTooLarge`]
/// if the frame would need more than [`MAX_CHUNKS_PER_FRAME`] chunks — the
/// `u16` chunk index cannot address it, and silently wrapping would corrupt
/// the stream.
pub fn chunk_frame(frame: &VideoFrame, max_payload: usize) -> Result<Vec<FrameChunk>, ProtoError> {
    let max = max_payload.max(1);
    let slices: Vec<&[u8]> = if frame.data.is_empty() {
        vec![&[][..]]
    } else {
        frame.data.chunks(max).collect()
    };
    if slices.len() > MAX_CHUNKS_PER_FRAME as usize {
        return Err(ProtoError::FrameTooLarge {
            size: frame.data.len(),
            max: MAX_CHUNKS_PER_FRAME as usize * max,
        });
    }
    let count = slices.len() as u16;
    Ok(slices
        .into_iter()
        .enumerate()
        .map(|(i, slice)| FrameChunk {
            seq: frame.sequence,
            index: i as u16,
            count,
            keyframe: frame.keyframe,
            width: frame.width,
            height: frame.height,
            timestamp_us: frame.timestamp_us,
            payload: slice.to_vec(),
        })
        .collect())
}

/// Reassembles [`FrameChunk`]s back into whole [`VideoFrame`]s.
#[derive(Debug, Default)]
pub struct Reassembler {
    seq: Option<u64>,
    count: u16,
    keyframe: bool,
    width: u32,
    height: u32,
    timestamp_us: u64,
    parts: BTreeMap<u16, Vec<u8>>,
    /// Sum of the payload lengths in `parts`, kept so the cap check is O(1).
    buffered: usize,
    /// Frames that were started but abandoned because a newer frame arrived
    /// first (or the frame outgrew [`MAX_BUFFERED_BYTES`]). Consumers use
    /// this to decide whether they need to ask the sender for a fresh
    /// keyframe.
    dropped: u64,
}

impl Reassembler {
    pub fn new() -> Self {
        Self::default()
    }

    /// Feed a chunk. Returns `Some(frame)` once the frame it belongs to is
    /// complete. Chunks from superseded (older) frames are ignored, as are
    /// malformed chunks (zero `count`, `index >= count`, a payload larger
    /// than [`MAX_CHUNK_PAYLOAD`], or a header that disagrees with the chunks
    /// already held for the same sequence). A frame that would exceed
    /// [`MAX_BUFFERED_BYTES`] is abandoned (counted in
    /// [`Self::dropped_frames`]) and its later chunks ignored.
    pub fn push(&mut self, chunk: FrameChunk) -> Option<VideoFrame> {
        if chunk.count == 0 || chunk.index >= chunk.count || chunk.payload.len() > MAX_CHUNK_PAYLOAD {
            return None;
        }
        match self.seq {
            // A newer frame started: abandon whatever partial we held.
            Some(cur) if chunk.seq > cur => {
                if !self.parts.is_empty() {
                    self.dropped += 1;
                }
                self.reset_to(&chunk);
            }
            // A stale chunk from an older frame: ignore it.
            Some(cur) if chunk.seq < cur => return None,
            // Same frame in progress: every chunk must carry the same header,
            // otherwise a forged chunk could make us assemble nonsense.
            Some(_) => {
                if !self.header_matches(&chunk) {
                    return None;
                }
            }
            // First chunk ever.
            None => self.reset_to(&chunk),
        }

        // A re-delivered index replaces the old copy: account for it before
        // checking the budget so duplicates cannot inflate the count.
        let replaced = self.parts.get(&chunk.index).map_or(0, Vec::len);
        if self.buffered - replaced + chunk.payload.len() > MAX_BUFFERED_BYTES {
            // Evict the whole frame: whatever the peer sends next for it is
            // stale (below `seq`) or a duplicate and gets ignored.
            self.dropped += 1;
            self.parts.clear();
            self.buffered = 0;
            self.count = 0;
            return None;
        }
        self.buffered = self.buffered - replaced + chunk.payload.len();
        self.parts.insert(chunk.index, chunk.payload);

        if self.count != 0 && self.parts.len() == self.count as usize {
            let total: usize = self.parts.values().map(Vec::len).sum();
            let mut data = Vec::with_capacity(total);
            for (_, part) in std::mem::take(&mut self.parts) {
                data.extend_from_slice(&part);
            }
            let frame = VideoFrame {
                sequence: self.seq.take().unwrap_or(0),
                width: self.width,
                height: self.height,
                keyframe: self.keyframe,
                timestamp_us: self.timestamp_us,
                data,
            };
            // Remember the completed sequence so late duplicates of it (or of
            // anything older) are dropped instead of restarting the frame.
            self.seq = Some(frame.sequence);
            self.count = 0;
            self.buffered = 0;
            Some(frame)
        } else {
            None
        }
    }

    /// Number of partially received frames abandoned so far. Monotonic; the
    /// caller diffs successive readings to detect fresh loss.
    pub fn dropped_frames(&self) -> u64 {
        self.dropped
    }

    /// True if a frame is currently being assembled.
    pub fn in_progress(&self) -> bool {
        !self.parts.is_empty()
    }

    fn header_matches(&self, chunk: &FrameChunk) -> bool {
        self.count == chunk.count
            && self.keyframe == chunk.keyframe
            && self.width == chunk.width
            && self.height == chunk.height
            && self.timestamp_us == chunk.timestamp_us
    }

    fn reset_to(&mut self, chunk: &FrameChunk) {
        self.seq = Some(chunk.seq);
        self.count = chunk.count;
        self.keyframe = chunk.keyframe;
        self.width = chunk.width;
        self.height = chunk.height;
        self.timestamp_us = chunk.timestamp_us;
        self.parts.clear();
        self.buffered = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(seq: u64, data: Vec<u8>) -> VideoFrame {
        VideoFrame { sequence: seq, width: 8, height: 8, keyframe: seq == 0, timestamp_us: seq, data }
    }

    #[test]
    fn single_chunk_roundtrip() {
        let f = frame(0, vec![1, 2, 3]);
        let chunks = chunk_frame(&f, 1024).unwrap();
        assert_eq!(chunks.len(), 1);
        let mut r = Reassembler::new();
        assert_eq!(r.push(chunks[0].clone()), Some(f));
    }

    #[test]
    fn multi_chunk_reassembles_in_order() {
        let data: Vec<u8> = (0..1000u32).map(|x| x as u8).collect();
        let f = frame(5, data.clone());
        let chunks = chunk_frame(&f, 100).unwrap();
        assert_eq!(chunks.len(), 10);
        let mut r = Reassembler::new();
        let mut out = None;
        for c in chunks {
            out = r.push(c);
        }
        assert_eq!(out.unwrap().data, data);
    }

    #[test]
    fn out_of_order_chunks_still_reassemble() {
        let data: Vec<u8> = (0..250u32).map(|x| x as u8).collect();
        let f = frame(1, data.clone());
        let mut chunks = chunk_frame(&f, 100).unwrap();
        chunks.reverse();
        let mut r = Reassembler::new();
        let mut out = None;
        for c in chunks {
            out = r.push(c).or(out);
        }
        assert_eq!(out.unwrap().data, data);
    }

    #[test]
    fn newer_frame_supersedes_incomplete_older() {
        let old = frame(1, vec![9; 300]);
        let new = frame(2, vec![7; 150]);
        let old_chunks = chunk_frame(&old, 100).unwrap(); // 3 chunks
        let new_chunks = chunk_frame(&new, 100).unwrap(); // 2 chunks
        let mut r = Reassembler::new();
        // Only first chunk of the old frame arrives...
        assert_eq!(r.push(old_chunks[0].clone()), None);
        assert_eq!(r.dropped_frames(), 0);
        // ...then the newer frame arrives fully -> old partial is dropped.
        assert_eq!(r.push(new_chunks[0].clone()), None);
        assert_eq!(r.dropped_frames(), 1);
        let done = r.push(new_chunks[1].clone()).unwrap();
        assert_eq!(done.sequence, 2);
        assert_eq!(done.data, vec![7; 150]);
    }

    #[test]
    fn stale_or_duplicate_chunk_after_completion_is_ignored() {
        let f1 = frame(1, vec![1; 10]);
        let f2 = frame(2, vec![2; 10]);
        let mut r = Reassembler::new();
        let c2 = chunk_frame(&f2, 100).unwrap().remove(0);
        assert!(r.push(c2.clone()).is_some());
        // Anything not newer than the last completed frame is dropped.
        assert!(r.push(chunk_frame(&f1, 100).unwrap().remove(0)).is_none());
        assert!(r.push(c2).is_none(), "a re-delivered chunk must not re-emit the frame");
        assert!(!r.in_progress());
    }

    #[test]
    fn empty_data_yields_one_chunk() {
        let f = frame(0, vec![]);
        let chunks = chunk_frame(&f, 100).unwrap();
        assert_eq!(chunks.len(), 1);
        let mut r = Reassembler::new();
        assert_eq!(r.push(chunks[0].clone()).unwrap().data, Vec::<u8>::new());
    }

    #[test]
    fn too_many_chunks_is_an_error_not_a_wrap() {
        let f = frame(0, vec![0; MAX_CHUNKS_PER_FRAME as usize + 1]);
        assert!(matches!(chunk_frame(&f, 1), Err(ProtoError::FrameTooLarge { .. })));
        // Exactly at the limit is fine.
        let f = frame(0, vec![0; MAX_CHUNKS_PER_FRAME as usize]);
        assert_eq!(chunk_frame(&f, 1).unwrap().len(), MAX_CHUNKS_PER_FRAME as usize);
    }

    fn hostile(seq: u64, index: u16, count: u16) -> FrameChunk {
        FrameChunk {
            seq,
            index,
            count,
            keyframe: true,
            width: 8,
            height: 8,
            timestamp_us: 0,
            payload: vec![0xAB; 4],
        }
    }

    #[test]
    fn zero_count_chunk_is_rejected_and_never_completes() {
        let mut r = Reassembler::new();
        assert!(r.push(hostile(1, 0, 0)).is_none());
        assert!(!r.in_progress());
    }

    #[test]
    fn index_at_or_beyond_count_is_rejected() {
        let mut r = Reassembler::new();
        assert!(r.push(hostile(1, 2, 2)).is_none());
        assert!(r.push(hostile(1, u16::MAX, 2)).is_none());
        assert!(!r.in_progress());
        // A legitimate chunk of the same frame still works afterwards.
        assert!(r.push(hostile(1, 0, 2)).is_none());
        assert!(r.push(hostile(1, 1, 2)).is_some());
    }

    #[test]
    fn header_mismatch_within_a_frame_is_rejected() {
        let mut r = Reassembler::new();
        assert!(r.push(hostile(1, 0, 3)).is_none());
        // Same seq but claims a different count: cannot be trusted.
        assert!(r.push(hostile(1, 1, 2)).is_none());
        let mut forged = hostile(1, 1, 3);
        forged.width = 4096;
        assert!(r.push(forged).is_none());
        // The frame is still assembling with its original header.
        assert!(r.in_progress());
        assert!(r.push(hostile(1, 1, 3)).is_none());
        let done = r.push(hostile(1, 2, 3)).unwrap();
        assert_eq!(done.width, 8);
        assert_eq!(done.data.len(), 12);
    }

    #[test]
    fn oversized_payload_is_rejected() {
        let mut r = Reassembler::new();
        let mut big = hostile(1, 0, 2);
        big.payload = vec![0; MAX_CHUNK_PAYLOAD + 1];
        assert!(r.push(big).is_none());
        assert!(!r.in_progress(), "an oversized chunk must not even start a frame");
        let mut ok = hostile(1, 0, 2);
        ok.payload = vec![0; MAX_CHUNK_PAYLOAD];
        assert!(r.push(ok).is_none());
        assert!(r.in_progress());
    }

    #[test]
    fn buffered_bytes_are_capped_and_the_frame_evicted() {
        let mut r = Reassembler::new();
        let per = MAX_CHUNK_PAYLOAD;
        let fits = MAX_BUFFERED_BYTES / per; // chunks that fit under the cap
        let count = (fits + 2) as u16;
        for i in 0..fits as u16 {
            let mut c = hostile(1, i, count);
            c.payload = vec![0; per];
            assert!(r.push(c).is_none());
        }
        assert!(r.in_progress());
        assert_eq!(r.dropped_frames(), 0);
        // The chunk that crosses the cap evicts everything held so far...
        let mut c = hostile(1, fits as u16, count);
        c.payload = vec![0; per];
        assert!(r.push(c).is_none());
        assert!(!r.in_progress());
        assert_eq!(r.buffered, 0);
        assert_eq!(r.dropped_frames(), 1);
        // ...and the frame can never complete afterwards.
        let mut c = hostile(1, (fits + 1) as u16, count);
        c.payload = vec![0; per];
        assert!(r.push(c).is_none());
        assert!(r.push(hostile(1, 0, count)).is_none());
        // A newer frame proceeds normally.
        assert!(r.push(hostile(2, 0, 1)).is_some());
    }

    #[test]
    fn duplicate_chunks_do_not_inflate_the_buffer_accounting() {
        let mut r = Reassembler::new();
        let mut c = hostile(1, 0, 3);
        c.payload = vec![0; 1000];
        for _ in 0..50 {
            assert!(r.push(c.clone()).is_none());
        }
        assert_eq!(r.buffered, 1000);
    }

    #[test]
    fn duplicate_chunk_does_not_double_count() {
        let mut r = Reassembler::new();
        assert!(r.push(hostile(1, 0, 2)).is_none());
        assert!(r.push(hostile(1, 0, 2)).is_none(), "a duplicate must not complete the frame");
        assert!(r.push(hostile(1, 1, 2)).is_some());
    }
}
