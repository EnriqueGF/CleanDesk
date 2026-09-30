//! Incoming file transfers on the host (spec section 13): the viewer offers,
//! the host auto-accepts when `FILE_TRANSFER` is granted and writes the file
//! under the downloads directory. Byte accounting and naming rules come from
//! `rotodesk_proto::files`; this module only adds the disk and channel I/O.
//!
//! The host does not initiate transfers in this milestone (there is no local
//! UI for it), so there is no sender here.
//!
//! Offers are bounded before a single byte is written: a per-file size cap
//! (`HostConfig::max_file_size`), at most [`MAX_CONCURRENT_INCOMING`]
//! transfers in flight, and the target volume must keep
//! [`FREE_SPACE_MARGIN`] free after the file lands. A refused offer is
//! answered with `FileTransferMsg::Refused` so the viewer can show why.

use rotodesk_proto::{
    files::{dedupe_file_name, FileChunk, IncomingTable},
    message::{FileTransferMsg, SessionMessage},
};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use tokio::io::AsyncWriteExt;
use tracing::{debug, info, warn};

/// Default per-file size cap (`HostConfig::max_file_size`).
pub const DEFAULT_MAX_FILE_SIZE: u64 = 8 * 1024 * 1024 * 1024;

/// Incoming transfers a viewer may keep open at once.
pub const MAX_CONCURRENT_INCOMING: usize = 4;

/// Free space the downloads volume must retain after the file is stored, so a
/// viewer cannot fill the host's disk to the last byte.
pub const FREE_SPACE_MARGIN: u64 = 512 * 1024 * 1024;

/// Where received files go when the embedder configured nothing: the OS
/// downloads folder (or the temp dir as a last resort) plus `RotoDesk`.
pub fn default_downloads_dir() -> PathBuf {
    directories::UserDirs::new()
        .and_then(|u| u.download_dir().map(Path::to_path_buf))
        .unwrap_or_else(std::env::temp_dir)
        .join("RotoDesk")
}

/// Pick a non-colliding path for `name` inside `dir`.
pub(crate) fn unique_path(dir: &Path, name: &str) -> PathBuf {
    dir.join(dedupe_file_name(name, |candidate| dir.join(candidate).exists()))
}

struct Writer {
    file: tokio::fs::File,
    path: PathBuf,
}

/// Receiver-side plumbing for one session.
pub(crate) struct FileReceiver {
    table: IncomingTable,
    writers: HashMap<u64, Writer>,
    dir: PathBuf,
    max_file_size: u64,
}

impl FileReceiver {
    pub(crate) fn new(dir: PathBuf, max_file_size: u64) -> Self {
        Self { table: IncomingTable::new(), writers: HashMap::new(), dir, max_file_size }
    }

    /// Why an otherwise well-formed offer must be refused, if at all.
    /// Checked before anything touches the disk.
    fn refusal_reason(&self, size: u64) -> Option<String> {
        if size > self.max_file_size {
            return Some(format!(
                "file too large ({} bytes; this host accepts up to {} bytes)",
                size, self.max_file_size
            ));
        }
        if self.writers.len() >= MAX_CONCURRENT_INCOMING {
            return Some(format!("too many transfers in progress (max {MAX_CONCURRENT_INCOMING})"));
        }
        if let Some(free) = free_disk_space(&self.dir) {
            let needed = size.saturating_add(FREE_SPACE_MARGIN);
            if free < needed {
                return Some(format!("not enough free disk space on the host ({free} bytes free, {needed} needed)"));
            }
        }
        None
    }

    /// Handle a control message from the viewer; returns the replies to send.
    pub(crate) async fn on_control(&mut self, msg: FileTransferMsg) -> Vec<SessionMessage> {
        match msg {
            FileTransferMsg::Offer { transfer_id, name, size, is_dir } => {
                let incoming = match self.table.on_offer(transfer_id, &name, size, is_dir) {
                    Ok(inc) => inc.clone(),
                    Err(e) => {
                        warn!(transfer_id, error = %e, "refusing file offer");
                        return vec![refuse(transfer_id, e.to_string())];
                    }
                };
                if let Some(reason) = self.refusal_reason(size) {
                    warn!(transfer_id, size, %reason, "refusing file offer");
                    self.table.remove(transfer_id);
                    return vec![refuse(transfer_id, reason)];
                }
                if let Err(e) = tokio::fs::create_dir_all(&self.dir).await {
                    warn!(dir = %self.dir.display(), error = %e, "cannot create downloads dir");
                    self.table.remove(transfer_id);
                    return vec![cancel(transfer_id)];
                }
                let path = unique_path(&self.dir, &incoming.name);
                match tokio::fs::File::create(&path).await {
                    Ok(file) => {
                        info!(transfer_id, path = %path.display(), size, "receiving file");
                        self.writers.insert(transfer_id, Writer { file, path });
                        // Auto-accept: the permission was granted by the host user.
                        let _ = self.table.accept(transfer_id);
                        vec![SessionMessage::File(FileTransferMsg::Accept { transfer_id })]
                    }
                    Err(e) => {
                        warn!(path = %path.display(), error = %e, "cannot create file");
                        self.table.remove(transfer_id);
                        vec![cancel(transfer_id)]
                    }
                }
            }
            FileTransferMsg::Complete { transfer_id } => match self.table.on_complete(transfer_id) {
                Ok(Some(_)) => self.finish(transfer_id).await,
                // The last chunks are still in flight on the files channel.
                Ok(None) => vec![],
                Err(e) => {
                    warn!(transfer_id, error = %e, "file transfer failed");
                    self.discard(transfer_id, None).await;
                    vec![cancel(transfer_id)]
                }
            },
            FileTransferMsg::Cancel { transfer_id } => {
                if self.table.remove(transfer_id).is_some() {
                    info!(transfer_id, "file transfer cancelled by the viewer");
                }
                self.discard(transfer_id, None).await;
                vec![]
            }
            FileTransferMsg::Refused { transfer_id, reason } => {
                if self.table.remove(transfer_id).is_some() {
                    let reason = rotodesk_proto::text::sanitize_text(&reason);
                    info!(transfer_id, %reason, "file transfer refused by the viewer");
                }
                self.discard(transfer_id, None).await;
                vec![]
            }
            // The viewer does not receive files from the host yet.
            FileTransferMsg::Accept { .. } | FileTransferMsg::Progress { .. } => vec![],
        }
    }

    /// Handle a `files` channel message; returns the replies to send.
    pub(crate) async fn on_chunk(&mut self, chunk: FileChunk) -> Vec<SessionMessage> {
        let transfer_id = chunk.transfer_id;
        let outcome = match self.table.on_chunk(&chunk) {
            Ok(o) => o,
            Err(e) => {
                if self.writers.contains_key(&transfer_id) {
                    warn!(transfer_id, error = %e, "bad file chunk; aborting transfer");
                    self.discard(transfer_id, None).await;
                    return vec![cancel(transfer_id)];
                }
                debug!(transfer_id, error = %e, "chunk for unknown transfer");
                return vec![];
            }
        };
        let Some(w) = self.writers.get_mut(&transfer_id) else { return vec![] };
        if let Err(e) = w.file.write_all(&chunk.data).await {
            warn!(transfer_id, error = %e, "write failed; aborting transfer");
            self.table.remove(transfer_id);
            self.discard(transfer_id, None).await;
            return vec![cancel(transfer_id)];
        }
        let mut replies = Vec::new();
        if outcome.ack_due {
            replies.push(SessionMessage::File(FileTransferMsg::Progress { transfer_id, transferred: outcome.received }));
        }
        if outcome.all_received && self.table.try_finish(transfer_id).is_some() {
            replies.extend(self.finish(transfer_id).await);
        }
        replies
    }

    /// Every byte is on disk and the sender is done: flush and ack.
    async fn finish(&mut self, transfer_id: u64) -> Vec<SessionMessage> {
        let Some(mut w) = self.writers.remove(&transfer_id) else { return vec![] };
        if let Err(e) = w.file.flush().await {
            warn!(error = %e, "flush failed");
            self.discard(transfer_id, Some(w)).await;
            return vec![cancel(transfer_id)];
        }
        info!(transfer_id, path = %w.path.display(), "file received");
        vec![SessionMessage::File(FileTransferMsg::Complete { transfer_id })]
    }

    /// Drop the writer and delete the partial file.
    async fn discard(&mut self, transfer_id: u64, taken: Option<Writer>) {
        let w = taken.or_else(|| self.writers.remove(&transfer_id));
        if let Some(w) = w {
            drop(w.file);
            if let Err(e) = tokio::fs::remove_file(&w.path).await {
                debug!(path = %w.path.display(), error = %e, "could not delete partial file");
            }
        }
    }

    /// Is any transfer receiving bytes? Chunks for nothing are not decoded.
    pub(crate) fn has_active(&self) -> bool {
        !self.writers.is_empty()
    }

    /// Session over: delete every partial file.
    pub(crate) async fn abort_all(&mut self) {
        let ids: Vec<u64> = self.writers.keys().copied().collect();
        for id in ids {
            self.table.remove(id);
            self.discard(id, None).await;
        }
    }
}

/// The session task can be aborted at any `.await` (the local user ends the
/// session, the rendezvous rejects it); destructors still run, so partial
/// files never outlive the session even on that path.
impl Drop for FileReceiver {
    fn drop(&mut self) {
        for (id, w) in self.writers.drain() {
            drop(w.file);
            match std::fs::remove_file(&w.path) {
                Ok(()) => info!(transfer_id = id, path = %w.path.display(), "partial file removed at session end"),
                Err(e) => debug!(path = %w.path.display(), error = %e, "could not delete partial file"),
            }
        }
    }
}

fn cancel(transfer_id: u64) -> SessionMessage {
    SessionMessage::File(FileTransferMsg::Cancel { transfer_id })
}

fn refuse(transfer_id: u64, reason: String) -> SessionMessage {
    SessionMessage::File(FileTransferMsg::Refused { transfer_id, reason })
}

/// Free bytes available to this process on the volume holding `dir` (or its
/// nearest existing ancestor, since the downloads folder may not exist yet).
/// `None` when it cannot be determined; callers then skip the check rather
/// than refuse every transfer.
pub(crate) fn free_disk_space(dir: &Path) -> Option<u64> {
    let mut probe = dir;
    while !probe.exists() {
        probe = probe.parent()?;
    }
    free_disk_space_at(probe)
}

#[cfg(windows)]
fn free_disk_space_at(path: &Path) -> Option<u64> {
    use std::os::windows::ffi::OsStrExt;

    // Documented Win32 API from kernel32; declared here to avoid pulling a
    // whole bindings crate into the host for one call.
    #[link(name = "kernel32")]
    extern "system" {
        fn GetDiskFreeSpaceExW(
            directory_name: *const u16,
            free_bytes_available_to_caller: *mut u64,
            total_number_of_bytes: *mut u64,
            total_number_of_free_bytes: *mut u64,
        ) -> i32;
    }

    let wide: Vec<u16> = path.as_os_str().encode_wide().chain(std::iter::once(0)).collect();
    let mut available = 0u64;
    let mut total = 0u64;
    let mut free = 0u64;
    // SAFETY: `wide` is a valid NUL-terminated UTF-16 string that outlives the
    // call, and the three out-pointers reference live, writable u64s.
    let ok = unsafe { GetDiskFreeSpaceExW(wide.as_ptr(), &mut available, &mut total, &mut free) };
    (ok != 0).then_some(available)
}

#[cfg(not(windows))]
fn free_disk_space_at(_path: &Path) -> Option<u64> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unique_path_dedupes_against_disk() {
        let dir = std::env::temp_dir().join(format!("rotodesk-host-files-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        assert_eq!(unique_path(&dir, "a.txt"), dir.join("a.txt"));
        std::fs::write(dir.join("a.txt"), b"x").unwrap();
        assert_eq!(unique_path(&dir, "a.txt"), dir.join("a (2).txt"));
        std::fs::write(dir.join("a (2).txt"), b"x").unwrap();
        assert_eq!(unique_path(&dir, "a.txt"), dir.join("a (3).txt"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn offers_beyond_the_caps_are_refused_with_a_reason() {
        let dir = std::env::temp_dir().join(format!("rotodesk-host-caps-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let mut rx = FileReceiver::new(dir.clone(), 1000);

        // Too large.
        let replies = rx.on_control(FileTransferMsg::Offer { transfer_id: 1, name: "big".into(), size: 1001, is_dir: false }).await;
        assert!(matches!(&replies[..], [SessionMessage::File(FileTransferMsg::Refused { transfer_id: 1, reason })] if reason.contains("too large")), "{replies:?}");
        assert!(rx.table.get(1).is_none(), "a refused offer leaves no state behind");

        // Fits: accepted, and the file exists.
        for id in 2..=5u64 {
            let replies = rx.on_control(FileTransferMsg::Offer { transfer_id: id, name: format!("f{id}"), size: 10, is_dir: false }).await;
            assert!(matches!(&replies[..], [SessionMessage::File(FileTransferMsg::Accept { .. })]), "{replies:?}");
        }
        assert_eq!(rx.writers.len(), MAX_CONCURRENT_INCOMING);
        // A fifth concurrent one is refused.
        let replies = rx.on_control(FileTransferMsg::Offer { transfer_id: 6, name: "f6".into(), size: 10, is_dir: false }).await;
        assert!(matches!(&replies[..], [SessionMessage::File(FileTransferMsg::Refused { transfer_id: 6, reason })] if reason.contains("too many")), "{replies:?}");

        // Free-space probe works on the real volume of the temp dir.
        let free = free_disk_space(&dir);
        assert!(!cfg!(windows) || free.is_some_and(|f| f > 0), "{free:?}");

        rx.abort_all().await;
        assert!(rx.writers.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
