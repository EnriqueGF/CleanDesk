//! Incoming file transfers on the host (spec section 13): the viewer offers,
//! the host auto-accepts when `FILE_TRANSFER` is granted and writes the file
//! under the downloads directory. Byte accounting and naming rules come from
//! `cleandesk_proto::files`; this module only adds the disk and channel I/O.
//!
//! The host does not initiate transfers in this milestone (there is no local
//! UI for it), so there is no sender here.

use cleandesk_proto::{
    files::{dedupe_file_name, FileChunk, IncomingTable},
    message::{FileTransferMsg, SessionMessage},
};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use tokio::io::AsyncWriteExt;
use tracing::{debug, info, warn};

/// Where received files go when the embedder configured nothing: the OS
/// downloads folder (or the temp dir as a last resort) plus `CleanDesk`.
pub fn default_downloads_dir() -> PathBuf {
    directories::UserDirs::new()
        .and_then(|u| u.download_dir().map(Path::to_path_buf))
        .unwrap_or_else(std::env::temp_dir)
        .join("CleanDesk")
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
}

impl FileReceiver {
    pub(crate) fn new(dir: PathBuf) -> Self {
        Self { table: IncomingTable::new(), writers: HashMap::new(), dir }
    }

    /// Handle a control message from the viewer; returns the replies to send.
    pub(crate) async fn on_control(&mut self, msg: FileTransferMsg) -> Vec<SessionMessage> {
        match msg {
            FileTransferMsg::Offer { transfer_id, name, size, is_dir } => {
                let incoming = match self.table.on_offer(transfer_id, &name, size, is_dir) {
                    Ok(inc) => inc.clone(),
                    Err(e) => {
                        warn!(transfer_id, error = %e, "refusing file offer");
                        return vec![cancel(transfer_id)];
                    }
                };
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

    /// Session over: delete every partial file.
    pub(crate) async fn abort_all(&mut self) {
        let ids: Vec<u64> = self.writers.keys().copied().collect();
        for id in ids {
            self.table.remove(id);
            self.discard(id, None).await;
        }
    }
}

fn cancel(transfer_id: u64) -> SessionMessage {
    SessionMessage::File(FileTransferMsg::Cancel { transfer_id })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unique_path_dedupes_against_disk() {
        let dir = std::env::temp_dir().join(format!("cleandesk-host-files-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        assert_eq!(unique_path(&dir, "a.txt"), dir.join("a.txt"));
        std::fs::write(dir.join("a.txt"), b"x").unwrap();
        assert_eq!(unique_path(&dir, "a.txt"), dir.join("a (2).txt"));
        std::fs::write(dir.join("a (2).txt"), b"x").unwrap();
        assert_eq!(unique_path(&dir, "a.txt"), dir.join("a (3).txt"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
