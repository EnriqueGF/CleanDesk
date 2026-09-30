//! File transfer (spec section 13): the wire chunk and the pure state
//! machines both roles drive. No I/O lives here — the host and viewer crates
//! wrap these in their own file/channel plumbing, so every rule about offers,
//! byte accounting, flow control and file naming is testable in isolation.
//!
//! # Protocol
//!
//! Control messages ([`FileTransferMsg`]) ride the reliable `control`
//! channel; data rides the reliable, ordered `files` channel as
//! [`FileChunk`]s. Because the channel is ordered, a chunk's `offset` must be
//! exactly the number of bytes the receiver already has — anything else is a
//! protocol violation and aborts the transfer.
//!
//! ```text
//! sender                       receiver
//!   Offer{id,name,size}   -->
//!                         <--  Accept{id}
//!   FileChunk ...         -->
//!   Progress{id,sent}     -->  (informational)
//!                         <--  Progress{id,received}  (ack + flow control)
//!   Complete{id}          -->
//!                         <--  Complete{id}           (verified & stored)
//! ```
//!
//! Either side may send `Cancel{id}` at any point.
//!
//! Control and data ride *different* channels, so the sender's `Complete`
//! can overtake the last chunk. The receiver therefore treats `Complete` as
//! "no more bytes are coming": if everything has arrived it finishes at once,
//! otherwise it finishes on the chunk that delivers the final byte
//! ([`IncomingTable::try_finish`]).
//!
//! # Transfer ids
//!
//! Both peers may initiate; to keep ids unique without negotiation the
//! viewer allocates odd ids and the host even ones ([`TransferIds`]).

use crate::message::FileTransferMsg;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Largest `data` payload in one [`FileChunk`]: leaves room for the postcard
/// header inside the 16 KiB data-channel message limit.
pub const MAX_CHUNK_DATA: usize = 15 * 1024;

/// The sender may run at most this far ahead of the receiver's last
/// `Progress` ack, so a slow disk or link never makes the SCTP send buffer
/// grow without bound.
pub const SEND_WINDOW: u64 = 1024 * 1024;

/// The receiver acks (and both sides report progress) every this many bytes.
pub const PROGRESS_INTERVAL: u64 = 256 * 1024;

/// Longest sanitised file name we will produce (bytes; UTF-8 safe).
pub const MAX_FILE_NAME_LEN: usize = 200;

/// Name used when sanitisation leaves nothing usable.
pub const FALLBACK_FILE_NAME: &str = "file";

/// Most offers (accepted or not) a peer may keep open at once. Offers that
/// are never accepted would otherwise accumulate without bound.
pub const MAX_PENDING_OFFERS: usize = 16;

/// One slice of a file, carried as a single `files` channel message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileChunk {
    pub transfer_id: u64,
    /// Byte offset of `data` within the file.
    pub offset: u64,
    pub data: Vec<u8>,
}

/// Errors from the transfer state machines.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FileError {
    #[error("transfer {0} already exists")]
    DuplicateId(u64),
    #[error("unknown transfer {0}")]
    UnknownTransfer(u64),
    #[error("transfer {0} was not accepted yet")]
    NotAccepted(u64),
    #[error("directory transfers are not supported")]
    DirectoryUnsupported,
    #[error("chunk at offset {offset} does not continue the stream (expected {expected})")]
    BadOffset { offset: u64, expected: u64 },
    #[error("chunk of {len} bytes exceeds the {max}-byte limit")]
    ChunkTooLarge { len: usize, max: usize },
    #[error("received {received} bytes but {expected} were announced")]
    SizeMismatch { received: u64, expected: u64 },
    #[error("too many transfers offered at once (limit {0})")]
    TooManyOffers(usize),
}

// ---------------------------------------------------------------------------
// Ids
// ---------------------------------------------------------------------------

/// Which peer is allocating transfer ids.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Viewer,
    Host,
}

/// Collision-free transfer id allocator: viewer ids are odd, host ids even.
#[derive(Debug, Clone)]
pub struct TransferIds {
    next: u64,
}

impl TransferIds {
    pub fn new(role: Role) -> Self {
        Self { next: match role {
            Role::Viewer => 1,
            Role::Host => 2,
        } }
    }

    pub fn allocate(&mut self) -> u64 {
        let id = self.next;
        self.next = self.next.wrapping_add(2);
        id
    }
}

// ---------------------------------------------------------------------------
// File names
// ---------------------------------------------------------------------------

/// Reduce a peer-supplied file name to something safe to create inside the
/// downloads directory: no path separators or `..` components, no control or
/// reserved characters, no leading/trailing dots or spaces, bounded length.
/// Never empty.
pub fn sanitize_file_name(name: &str) -> String {
    // Keep only the last path component the peer might have sent, then strip
    // anything a filesystem would treat specially.
    let last = name.rsplit(['/', '\\']).find(|s| !s.is_empty()).unwrap_or("");
    let mut out: String = last
        .chars()
        .filter(|c| !c.is_control() && !crate::text::is_invisible_format_char(*c))
        .map(|c| match c {
            '<' | '>' | ':' | '"' | '|' | '?' | '*' => '_',
            c => c,
        })
        .collect();
    while out.len() > MAX_FILE_NAME_LEN {
        out.pop();
    }
    let trimmed = out.trim_matches(|c| c == '.' || c == ' ');
    if trimmed.is_empty() {
        return FALLBACK_FILE_NAME.to_string();
    }
    // A Windows device name (CON, NUL, COM1...) would not create a file.
    let stem = trimmed.split('.').next().unwrap_or("").to_ascii_uppercase();
    let reserved = matches!(
        stem.as_str(),
        "CON" | "PRN" | "AUX" | "NUL"
            | "COM1" | "COM2" | "COM3" | "COM4" | "COM5" | "COM6" | "COM7" | "COM8" | "COM9"
            | "LPT1" | "LPT2" | "LPT3" | "LPT4" | "LPT5" | "LPT6" | "LPT7" | "LPT8" | "LPT9"
    );
    if reserved {
        format!("_{trimmed}")
    } else {
        trimmed.to_string()
    }
}

/// Pick a name that does not collide: `name`, then `name (2)`, `name (3)`...
/// with the extension preserved (`report (2).pdf`). `exists` answers whether
/// a candidate is already taken.
pub fn dedupe_file_name(name: &str, exists: impl Fn(&str) -> bool) -> String {
    if !exists(name) {
        return name.to_string();
    }
    let (stem, ext) = match name.rfind('.') {
        // A leading dot is a hidden file, not an extension.
        Some(i) if i > 0 => (&name[..i], &name[i..]),
        _ => (name, ""),
    };
    (2u32..)
        .map(|n| format!("{stem} ({n}){ext}"))
        .find(|candidate| !exists(candidate))
        .unwrap_or_else(|| name.to_string())
}

// ---------------------------------------------------------------------------
// Sender
// ---------------------------------------------------------------------------

/// Byte accounting for one outgoing file: what to send next, when the
/// window is full, when a progress report is due.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outgoing {
    pub transfer_id: u64,
    pub size: u64,
    sent: u64,
    acked: u64,
    last_progress: u64,
    window: u64,
}

impl Outgoing {
    pub fn new(transfer_id: u64, size: u64) -> Self {
        Self::with_window(transfer_id, size, SEND_WINDOW)
    }

    pub fn with_window(transfer_id: u64, size: u64, window: u64) -> Self {
        Self { transfer_id, size, sent: 0, acked: 0, last_progress: 0, window: window.max(1) }
    }

    pub fn sent(&self) -> u64 {
        self.sent
    }

    /// The `Offer` announcing this file.
    pub fn offer(&self, name: String) -> FileTransferMsg {
        FileTransferMsg::Offer { transfer_id: self.transfer_id, name, size: self.size, is_dir: false }
    }

    /// The next `(offset, len)` to read and send, or `None` when the file is
    /// fully sent *or* the window is full (check [`Self::is_complete`] to
    /// tell them apart; in the latter case wait for an ack).
    pub fn next_range(&self) -> Option<(u64, usize)> {
        if self.is_complete() {
            return None;
        }
        let in_flight = self.sent - self.acked;
        if in_flight >= self.window {
            return None;
        }
        let room = (self.window - in_flight).min(self.size - self.sent).min(MAX_CHUNK_DATA as u64);
        Some((self.sent, room as usize))
    }

    /// Record `len` bytes sent; returns `true` when a `Progress` report is
    /// due (every [`PROGRESS_INTERVAL`] bytes).
    pub fn on_sent(&mut self, len: usize) -> bool {
        self.sent = (self.sent + len as u64).min(self.size);
        if self.sent - self.last_progress >= PROGRESS_INTERVAL {
            self.last_progress = self.sent;
            true
        } else {
            false
        }
    }

    /// The receiver acknowledged `transferred` bytes (from its `Progress`).
    pub fn on_ack(&mut self, transferred: u64) {
        self.acked = self.acked.max(transferred.min(self.sent));
    }

    pub fn is_complete(&self) -> bool {
        self.sent >= self.size
    }

    pub fn progress(&self) -> FileTransferMsg {
        FileTransferMsg::Progress { transfer_id: self.transfer_id, transferred: self.sent }
    }
}

// ---------------------------------------------------------------------------
// Receiver
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    Offered,
    Receiving,
}

/// One incoming transfer as the receiver sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Incoming {
    pub transfer_id: u64,
    /// Already sanitised (see [`sanitize_file_name`]); not yet deduplicated
    /// against the target directory, which needs I/O.
    pub name: String,
    pub size: u64,
    received: u64,
    last_ack: u64,
    phase: Phase,
    /// The sender's `Complete` arrived (possibly before the last chunk).
    complete_requested: bool,
}

impl Incoming {
    pub fn received(&self) -> u64 {
        self.received
    }

    pub fn is_accepted(&self) -> bool {
        self.phase == Phase::Receiving
    }
}

/// What the receiver should do after applying a chunk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChunkOutcome {
    /// Total bytes received so far (write `chunk.data` at `offset` first).
    pub received: u64,
    /// Send a `Progress { transferred: received }` ack now.
    pub ack_due: bool,
    /// Every announced byte has arrived; a `Complete` should follow.
    pub all_received: bool,
}

/// Registry of offered and active incoming transfers.
#[derive(Debug, Default, Clone)]
pub struct IncomingTable {
    transfers: BTreeMap<u64, Incoming>,
}

impl IncomingTable {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a peer `Offer`. Directories are refused (MVP); the name is
    /// sanitised on the way in.
    pub fn on_offer(&mut self, transfer_id: u64, name: &str, size: u64, is_dir: bool) -> Result<&Incoming, FileError> {
        if is_dir {
            return Err(FileError::DirectoryUnsupported);
        }
        if self.transfers.contains_key(&transfer_id) {
            return Err(FileError::DuplicateId(transfer_id));
        }
        if self.transfers.len() >= MAX_PENDING_OFFERS {
            return Err(FileError::TooManyOffers(MAX_PENDING_OFFERS));
        }
        let entry = self.transfers.entry(transfer_id).or_insert(Incoming {
            transfer_id,
            name: sanitize_file_name(name),
            size,
            received: 0,
            last_ack: 0,
            phase: Phase::Offered,
            complete_requested: false,
        });
        Ok(entry)
    }

    /// Local user (or auto-accept policy) accepted the offer.
    pub fn accept(&mut self, transfer_id: u64) -> Result<&Incoming, FileError> {
        let t = self.transfers.get_mut(&transfer_id).ok_or(FileError::UnknownTransfer(transfer_id))?;
        t.phase = Phase::Receiving;
        Ok(t)
    }

    pub fn get(&self, transfer_id: u64) -> Option<&Incoming> {
        self.transfers.get(&transfer_id)
    }

    /// Validate a chunk against the stream position. On error the transfer
    /// is removed from the table (the caller should `Cancel` it and delete
    /// the partial file).
    pub fn on_chunk(&mut self, chunk: &FileChunk) -> Result<ChunkOutcome, FileError> {
        let id = chunk.transfer_id;
        let res = self.apply_chunk(chunk);
        if res.is_err() {
            self.transfers.remove(&id);
        }
        res
    }

    fn apply_chunk(&mut self, chunk: &FileChunk) -> Result<ChunkOutcome, FileError> {
        let t = self.transfers.get_mut(&chunk.transfer_id).ok_or(FileError::UnknownTransfer(chunk.transfer_id))?;
        if t.phase != Phase::Receiving {
            return Err(FileError::NotAccepted(chunk.transfer_id));
        }
        if chunk.data.len() > MAX_CHUNK_DATA {
            return Err(FileError::ChunkTooLarge { len: chunk.data.len(), max: MAX_CHUNK_DATA });
        }
        if chunk.offset != t.received {
            return Err(FileError::BadOffset { offset: chunk.offset, expected: t.received });
        }
        let end = t.received + chunk.data.len() as u64;
        if end > t.size {
            return Err(FileError::SizeMismatch { received: end, expected: t.size });
        }
        t.received = end;
        let all_received = t.received == t.size;
        let ack_due = all_received || t.received - t.last_ack >= PROGRESS_INTERVAL;
        if ack_due {
            t.last_ack = t.received;
        }
        Ok(ChunkOutcome { received: t.received, ack_due, all_received })
    }

    /// The sender says it has sent everything. Returns `Some` (and removes
    /// the transfer) when every byte has already arrived; `None` when chunks
    /// are still in flight on the data channel — [`Self::try_finish`] after
    /// the chunk that completes it. Errors remove the transfer.
    pub fn on_complete(&mut self, transfer_id: u64) -> Result<Option<Incoming>, FileError> {
        let t = self.transfers.get_mut(&transfer_id).ok_or(FileError::UnknownTransfer(transfer_id))?;
        if t.phase != Phase::Receiving {
            self.transfers.remove(&transfer_id);
            return Err(FileError::NotAccepted(transfer_id));
        }
        t.complete_requested = true;
        Ok(self.try_finish(transfer_id))
    }

    /// If the sender announced completion *and* every byte has arrived,
    /// remove and return the finished transfer.
    pub fn try_finish(&mut self, transfer_id: u64) -> Option<Incoming> {
        let done = self
            .transfers
            .get(&transfer_id)
            .is_some_and(|t| t.complete_requested && t.received == t.size);
        if done {
            self.transfers.remove(&transfer_id)
        } else {
            None
        }
    }

    /// Forget a transfer (cancelled by either side).
    pub fn remove(&mut self, transfer_id: u64) -> Option<Incoming> {
        self.transfers.remove(&transfer_id)
    }

    pub fn is_empty(&self) -> bool {
        self.transfers.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitises_hostile_names() {
        assert_eq!(sanitize_file_name("../../etc/passwd"), "passwd");
        assert_eq!(sanitize_file_name("..\\..\\win.ini"), "win.ini");
        assert_eq!(sanitize_file_name("C:\\Users\\x\\report.pdf"), "report.pdf");
        assert_eq!(sanitize_file_name("a\u{0}b\nc.txt"), "abc.txt");
        assert_eq!(sanitize_file_name("what?.txt"), "what_.txt");
        assert_eq!(sanitize_file_name(".."), FALLBACK_FILE_NAME);
        assert_eq!(sanitize_file_name(""), FALLBACK_FILE_NAME);
        assert_eq!(sanitize_file_name("   "), FALLBACK_FILE_NAME);
        assert_eq!(sanitize_file_name("  spaced.txt.  "), "spaced.txt");
        assert_eq!(sanitize_file_name("CON"), "_CON");
        assert_eq!(sanitize_file_name("nul.txt"), "_nul.txt");
        assert_eq!(sanitize_file_name("informe ✓ ñ.pdf"), "informe ✓ ñ.pdf");
        // Direction overrides and zero-width characters are stripped.
        assert_eq!(sanitize_file_name("report\u{202E}txt.exe"), "reporttxt.exe");
        assert_eq!(sanitize_file_name("a\u{200B}b\u{FEFF}c.txt"), "abc.txt");
        let long = "x".repeat(500) + ".bin";
        let s = sanitize_file_name(&long);
        assert!(s.len() <= MAX_FILE_NAME_LEN);
        // Truncation never splits a multi-byte character.
        let multi = "ñ".repeat(300);
        let s = sanitize_file_name(&multi);
        assert!(s.len() <= MAX_FILE_NAME_LEN);
        assert!(s.chars().all(|c| c == 'ñ'));
    }

    #[test]
    fn dedupes_with_numbered_suffix_keeping_extension() {
        let taken = |s: &str| s == "report.pdf" || s == "report (2).pdf";
        assert_eq!(dedupe_file_name("report.pdf", taken), "report (3).pdf");
        assert_eq!(dedupe_file_name("other.pdf", taken), "other.pdf");
        assert_eq!(dedupe_file_name("README", |s| s == "README"), "README (2)");
        assert_eq!(dedupe_file_name(".bashrc", |s| s == ".bashrc"), ".bashrc (2)");
        assert_eq!(dedupe_file_name("a.tar.gz", |s| s == "a.tar.gz"), "a.tar (2).gz");
    }

    #[test]
    fn pending_offers_are_capped() {
        let mut table = IncomingTable::new();
        for id in 0..MAX_PENDING_OFFERS as u64 {
            table.on_offer(id, "f", 1, false).unwrap();
        }
        assert_eq!(
            table.on_offer(MAX_PENDING_OFFERS as u64, "f", 1, false).err(),
            Some(FileError::TooManyOffers(MAX_PENDING_OFFERS))
        );
    }

    #[test]
    fn ids_never_collide_between_roles() {
        let mut v = TransferIds::new(Role::Viewer);
        let mut h = TransferIds::new(Role::Host);
        let vs: Vec<u64> = (0..5).map(|_| v.allocate()).collect();
        let hs: Vec<u64> = (0..5).map(|_| h.allocate()).collect();
        assert_eq!(vs, vec![1, 3, 5, 7, 9]);
        assert_eq!(hs, vec![2, 4, 6, 8, 10]);
    }

    #[test]
    fn sender_chunks_respect_size_window_and_progress() {
        let size = 3 * MAX_CHUNK_DATA as u64 + 10;
        let mut out = Outgoing::with_window(1, size, 2 * MAX_CHUNK_DATA as u64);
        assert_eq!(out.next_range(), Some((0, MAX_CHUNK_DATA)));
        assert!(!out.on_sent(MAX_CHUNK_DATA));
        assert_eq!(out.next_range(), Some((MAX_CHUNK_DATA as u64, MAX_CHUNK_DATA)));
        out.on_sent(MAX_CHUNK_DATA);
        // Window full: wait for an ack.
        assert_eq!(out.next_range(), None);
        assert!(!out.is_complete());
        out.on_ack(MAX_CHUNK_DATA as u64);
        assert_eq!(out.next_range(), Some((2 * MAX_CHUNK_DATA as u64, MAX_CHUNK_DATA)));
        out.on_sent(MAX_CHUNK_DATA);
        out.on_ack(size); // an ack beyond `sent` is clamped, never negative
        assert_eq!(out.next_range(), Some((3 * MAX_CHUNK_DATA as u64, 10)));
        out.on_sent(10);
        assert!(out.is_complete());
        assert_eq!(out.next_range(), None);
        assert_eq!(out.progress(), FileTransferMsg::Progress { transfer_id: 1, transferred: size });
    }

    #[test]
    fn sender_reports_progress_every_interval() {
        let mut out = Outgoing::new(1, 3 * PROGRESS_INTERVAL);
        let mut reports = 0;
        while let Some((_, len)) = out.next_range() {
            if out.on_sent(len) {
                reports += 1;
            }
            out.on_ack(out.sent());
        }
        // Chunk boundaries do not align with the interval, so a report
        // lands on the first chunk *crossing* each multiple of it.
        assert!(reports >= 2, "{reports} progress reports");
        assert!(out.is_complete());
    }

    #[test]
    fn empty_file_is_complete_without_chunks() {
        let out = Outgoing::new(1, 0);
        assert!(out.is_complete());
        assert_eq!(out.next_range(), None);
        let mut table = IncomingTable::new();
        table.on_offer(1, "empty.txt", 0, false).unwrap();
        table.accept(1).unwrap();
        assert_eq!(table.on_complete(1).unwrap().unwrap().received(), 0);
    }

    #[test]
    fn receiver_accounts_bytes_and_acks() {
        let mut table = IncomingTable::new();
        let size = 2 * PROGRESS_INTERVAL + 100;
        let inc = table.on_offer(7, "../x/report.pdf", size, false).unwrap();
        assert_eq!(inc.name, "report.pdf");
        assert!(!inc.is_accepted());
        // Chunks before acceptance are a violation.
        let chunk = FileChunk { transfer_id: 7, offset: 0, data: vec![0; 10] };
        assert_eq!(table.on_chunk(&chunk), Err(FileError::NotAccepted(7)));
        // ...and the violation dropped the transfer.
        assert!(table.get(7).is_none());

        table.on_offer(7, "report.pdf", size, false).unwrap();
        table.accept(7).unwrap();
        let mut offset = 0u64;
        let mut acks = 0;
        let mut last_ack_due = false;
        while offset < size {
            let len = ((size - offset) as usize).min(MAX_CHUNK_DATA);
            let chunk = FileChunk { transfer_id: 7, offset, data: vec![1; len] };
            let out = table.on_chunk(&chunk).unwrap();
            offset += len as u64;
            assert_eq!(out.received, offset);
            if out.ack_due {
                acks += 1;
            }
            last_ack_due = out.ack_due;
            assert_eq!(out.all_received, offset == size);
        }
        assert!(acks >= 2, "at least one interval ack plus the final one ({acks})");
        assert!(last_ack_due, "the final chunk is always acked");
        let done = table.on_complete(7).unwrap().expect("all bytes already there");
        assert_eq!(done.received(), size);
        assert!(table.is_empty());
    }

    #[test]
    fn receiver_rejects_bad_offsets_oversize_and_short_completes() {
        let mut table = IncomingTable::new();
        table.on_offer(1, "a", 100, false).unwrap();
        table.accept(1).unwrap();
        let bad = FileChunk { transfer_id: 1, offset: 5, data: vec![0; 5] };
        assert_eq!(table.on_chunk(&bad), Err(FileError::BadOffset { offset: 5, expected: 0 }));

        table.on_offer(2, "b", 100, false).unwrap();
        table.accept(2).unwrap();
        let too_much = FileChunk { transfer_id: 2, offset: 0, data: vec![0; 101] };
        assert_eq!(table.on_chunk(&too_much), Err(FileError::SizeMismatch { received: 101, expected: 100 }));

        // `Complete` overtaking the last chunk: finish when it lands.
        table.on_offer(3, "c", 100, false).unwrap();
        table.accept(3).unwrap();
        table.on_chunk(&FileChunk { transfer_id: 3, offset: 0, data: vec![0; 50] }).unwrap();
        assert_eq!(table.on_complete(3), Ok(None), "bytes still in flight");
        assert!(table.try_finish(3).is_none());
        let out = table.on_chunk(&FileChunk { transfer_id: 3, offset: 50, data: vec![0; 50] }).unwrap();
        assert!(out.all_received);
        assert_eq!(table.try_finish(3).unwrap().received(), 100);
        assert!(table.get(3).is_none());

        table.on_offer(4, "d", MAX_CHUNK_DATA as u64 * 2, false).unwrap();
        table.accept(4).unwrap();
        let huge = FileChunk { transfer_id: 4, offset: 0, data: vec![0; MAX_CHUNK_DATA + 1] };
        assert!(matches!(table.on_chunk(&huge), Err(FileError::ChunkTooLarge { .. })));

        assert_eq!(table.on_offer(5, "dir", 0, true).unwrap_err(), FileError::DirectoryUnsupported);
        table.on_offer(6, "e", 1, false).unwrap();
        assert_eq!(table.on_offer(6, "e", 1, false).unwrap_err(), FileError::DuplicateId(6));
        assert_eq!(table.on_complete(6), Err(FileError::NotAccepted(6)));
        assert_eq!(table.accept(99).unwrap_err(), FileError::UnknownTransfer(99));
    }

    #[test]
    fn a_full_chunk_fits_in_one_channel_message() {
        let chunk = FileChunk { transfer_id: u64::MAX, offset: u64::MAX, data: vec![0xAB; MAX_CHUNK_DATA] };
        let bytes = crate::frame::encode_payload(&chunk).unwrap();
        assert!(bytes.len() <= 16 * 1024, "{} bytes", bytes.len());
        assert_eq!(crate::frame::decode_payload::<FileChunk>(&bytes).unwrap(), chunk);
    }
}
