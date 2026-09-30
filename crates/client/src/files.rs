//! File transfer on the viewer (spec section 13): sending local files to the
//! host and receiving files the host offers. Byte accounting, flow control
//! and naming rules come from `rotodesk_proto::files`; this module adds the
//! disk and channel I/O and turns everything into [`ClientEvent`]s.
//!
//! One task ([`run_files`]) owns all transfer state for a session. Each
//! outgoing file gets its own sender task so a slow disk or a full send
//! window never blocks control handling (in particular `cancel_file`).

use crate::ClientEvent;
use bytes::Bytes;
use rotodesk_proto::{
    files::{dedupe_file_name, FileChunk, IncomingTable, Outgoing, PROGRESS_INTERVAL},
    frame,
    message::{FileTransferMsg, SessionMessage},
    permissions::Permissions,
};
use rotodesk_transport::{Channel, PeerConnection};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

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

/// Commands into the files task: from the session API and from the inbound
/// dispatcher.
pub(crate) enum FileCommand {
    /// Local user wants to send `path` as transfer `transfer_id`.
    Send { transfer_id: u64, path: PathBuf },
    /// Local user accepted an offer from the host.
    Accept(u64),
    /// Local user cancelled a transfer in either direction.
    Cancel(u64),
    /// A file control message from the host.
    Control(FileTransferMsg),
    /// A `files` channel message from the host.
    Chunk(Bytes),
    /// A sender task finished (internal bookkeeping).
    Finished(u64),
}

/// Everything the files task needs from the session.
pub(crate) struct FilesCtx {
    pub peer: Arc<PeerConnection>,
    pub control_tx: mpsc::UnboundedSender<SessionMessage>,
    pub events: mpsc::Sender<ClientEvent>,
    /// Live permission bits (`Permissions::bits`), updated by the dispatcher.
    pub granted: Arc<AtomicU32>,
    pub downloads: PathBuf,
    pub cmd_tx: mpsc::UnboundedSender<FileCommand>,
}

impl FilesCtx {
    fn allowed(&self) -> bool {
        Permissions::from_bits_truncate(self.granted.load(Ordering::Relaxed)).contains(Permissions::FILE_TRANSFER)
    }

    fn send_control(&self, msg: FileTransferMsg) {
        let _ = self.control_tx.send(SessionMessage::File(msg));
    }

    async fn emit(&self, ev: ClientEvent) {
        let _ = self.events.send(ev).await;
    }
}

/// What the files task tells a sender task.
enum SenderEvent {
    Accepted,
    Ack(u64),
    Done,
    Cancelled { by_peer: bool },
    /// The host refused (or aborted) the transfer and said why.
    Refused(String),
}

struct OutgoingHandle {
    tx: mpsc::UnboundedSender<SenderEvent>,
}

struct Writer {
    file: tokio::fs::File,
    path: PathBuf,
}

/// Run until the command channel closes (session over).
pub(crate) async fn run_files(ctx: FilesCtx, mut rx: mpsc::UnboundedReceiver<FileCommand>) {
    let ctx = Arc::new(ctx);
    let mut outgoing: HashMap<u64, OutgoingHandle> = HashMap::new();
    let mut incoming = IncomingTable::new();
    let mut writers: HashMap<u64, Writer> = HashMap::new();

    while let Some(cmd) = tokio::select! {
        _ = ctx.peer.wait_closed() => None,
        cmd = rx.recv() => cmd,
    } {
        match cmd {
            FileCommand::Send { transfer_id, path } => {
                if !ctx.allowed() {
                    ctx.emit(ClientEvent::FileFailed { id: transfer_id, reason: "file transfer not granted".into() }).await;
                    continue;
                }
                let (tx, ev_rx) = mpsc::unbounded_channel();
                outgoing.insert(transfer_id, OutgoingHandle { tx });
                tokio::spawn(send_file_task(ctx.clone(), transfer_id, path, ev_rx));
            }
            FileCommand::Accept(id) => {
                let Some(inc) = incoming.get(id).cloned() else {
                    ctx.emit(ClientEvent::FileFailed { id, reason: "no such offer".into() }).await;
                    continue;
                };
                if inc.is_accepted() {
                    // A second accept would open a second file and orphan
                    // the first one's bytes.
                    debug!(id, "duplicate accept ignored");
                    continue;
                }
                if let Err(e) = tokio::fs::create_dir_all(&ctx.downloads).await {
                    incoming.remove(id);
                    ctx.send_control(FileTransferMsg::Cancel { transfer_id: id });
                    ctx.emit(ClientEvent::FileFailed { id, reason: format!("cannot create downloads dir: {e}") }).await;
                    continue;
                }
                // `create_new` closes the window between picking a free
                // name and opening it: a file (or a symlink) that appears in
                // between is never truncated.
                let mut created = None;
                for _ in 0..8 {
                    let path = unique_path(&ctx.downloads, &inc.name);
                    match tokio::fs::OpenOptions::new().write(true).create_new(true).open(&path).await {
                        Ok(file) => {
                            created = Some(Ok((file, path)));
                            break;
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                        Err(e) => {
                            created = Some(Err(e));
                            break;
                        }
                    }
                }
                let created = created.unwrap_or_else(|| {
                    Err(std::io::Error::new(std::io::ErrorKind::AlreadyExists, "no free file name"))
                });
                match created {
                    Ok((file, path)) => {
                        info!(id, path = %path.display(), size = inc.size, "receiving file");
                        writers.insert(id, Writer { file, path });
                        let _ = incoming.accept(id);
                        ctx.send_control(FileTransferMsg::Accept { transfer_id: id });
                    }
                    Err(e) => {
                        incoming.remove(id);
                        ctx.send_control(FileTransferMsg::Cancel { transfer_id: id });
                        ctx.emit(ClientEvent::FileFailed { id, reason: format!("cannot create file: {e}") }).await;
                    }
                }
            }
            FileCommand::Cancel(id) => {
                if let Some(h) = outgoing.remove(&id) {
                    let _ = h.tx.send(SenderEvent::Cancelled { by_peer: false });
                } else if incoming.remove(id).is_some() {
                    discard(&mut writers, id).await;
                    ctx.send_control(FileTransferMsg::Cancel { transfer_id: id });
                    ctx.emit(ClientEvent::FileFailed { id, reason: "cancelled".into() }).await;
                }
            }
            FileCommand::Finished(id) => {
                outgoing.remove(&id);
            }
            FileCommand::Control(msg) => match msg {
                FileTransferMsg::Offer { transfer_id, name, size, is_dir } => {
                    if !ctx.allowed() {
                        debug!(transfer_id, "file offer refused (not granted)");
                        ctx.send_control(FileTransferMsg::Cancel { transfer_id });
                        continue;
                    }
                    match incoming.on_offer(transfer_id, &name, size, is_dir) {
                        Ok(inc) => {
                            let name = inc.name.clone();
                            ctx.emit(ClientEvent::FileOffer { id: transfer_id, name, size }).await;
                        }
                        Err(e) => {
                            warn!(transfer_id, error = %e, "refusing file offer");
                            ctx.send_control(FileTransferMsg::Cancel { transfer_id });
                        }
                    }
                }
                FileTransferMsg::Accept { transfer_id } => {
                    if let Some(h) = outgoing.get(&transfer_id) {
                        let _ = h.tx.send(SenderEvent::Accepted);
                    }
                }
                FileTransferMsg::Progress { transfer_id, transferred } => {
                    if let Some(h) = outgoing.get(&transfer_id) {
                        let _ = h.tx.send(SenderEvent::Ack(transferred));
                    }
                }
                FileTransferMsg::Complete { transfer_id } => {
                    if let Some(h) = outgoing.remove(&transfer_id) {
                        let _ = h.tx.send(SenderEvent::Done);
                        continue;
                    }
                    match incoming.on_complete(transfer_id) {
                        Ok(Some(_)) => finish_incoming(&ctx, &mut writers, transfer_id).await,
                        // The last chunks are still in flight on the files channel.
                        Ok(None) => {}
                        Err(e) => {
                            if writers.contains_key(&transfer_id) {
                                warn!(transfer_id, error = %e, "file transfer failed");
                                discard(&mut writers, transfer_id).await;
                                ctx.send_control(FileTransferMsg::Cancel { transfer_id });
                                ctx.emit(ClientEvent::FileFailed { id: transfer_id, reason: e.to_string() }).await;
                            }
                        }
                    }
                }
                FileTransferMsg::Cancel { transfer_id } => {
                    if let Some(h) = outgoing.remove(&transfer_id) {
                        let _ = h.tx.send(SenderEvent::Cancelled { by_peer: true });
                    } else if incoming.remove(transfer_id).is_some() {
                        info!(transfer_id, "file transfer cancelled by the host");
                        discard(&mut writers, transfer_id).await;
                        ctx.emit(ClientEvent::FileFailed { id: transfer_id, reason: "cancelled by the host".into() }).await;
                    }
                }
                FileTransferMsg::Refused { transfer_id, reason } => {
                    if let Some(h) = outgoing.remove(&transfer_id) {
                        let _ = h.tx.send(SenderEvent::Refused(reason));
                    } else if incoming.remove(transfer_id).is_some() {
                        info!(transfer_id, %reason, "file transfer refused by the host");
                        discard(&mut writers, transfer_id).await;
                        ctx.emit(ClientEvent::FileFailed { id: transfer_id, reason: format!("refused by the host: {reason}") }).await;
                    }
                }
            },
            FileCommand::Chunk(bytes) => {
                let Ok(chunk) = frame::decode_payload::<FileChunk>(&bytes) else { continue };
                let id = chunk.transfer_id;
                let outcome = match incoming.on_chunk(&chunk) {
                    Ok(o) => o,
                    Err(e) => {
                        if writers.contains_key(&id) {
                            warn!(id, error = %e, "bad file chunk; aborting transfer");
                            discard(&mut writers, id).await;
                            ctx.send_control(FileTransferMsg::Cancel { transfer_id: id });
                            ctx.emit(ClientEvent::FileFailed { id, reason: e.to_string() }).await;
                        }
                        continue;
                    }
                };
                let Some(w) = writers.get_mut(&id) else { continue };
                if let Err(e) = w.file.write_all(&chunk.data).await {
                    warn!(id, error = %e, "write failed; aborting transfer");
                    incoming.remove(id);
                    discard(&mut writers, id).await;
                    ctx.send_control(FileTransferMsg::Cancel { transfer_id: id });
                    ctx.emit(ClientEvent::FileFailed { id, reason: format!("write failed: {e}") }).await;
                    continue;
                }
                if outcome.ack_due {
                    ctx.send_control(FileTransferMsg::Progress { transfer_id: id, transferred: outcome.received });
                    let total = incoming.get(id).map(|i| i.size).unwrap_or(outcome.received);
                    ctx.emit(ClientEvent::FileProgress { id, transferred: outcome.received, total }).await;
                }
                if outcome.all_received && incoming.try_finish(id).is_some() {
                    finish_incoming(&ctx, &mut writers, id).await;
                }
            }
        }
    }

    // Session over: partial downloads are worthless, remove them.
    let ids: Vec<u64> = writers.keys().copied().collect();
    for id in ids {
        discard(&mut writers, id).await;
    }
    for (_, h) in outgoing.drain() {
        let _ = h.tx.send(SenderEvent::Cancelled { by_peer: true });
    }
}

/// Every byte is on disk and the sender is done: flush, ack, report.
async fn finish_incoming(ctx: &FilesCtx, writers: &mut HashMap<u64, Writer>, id: u64) {
    let Some(mut w) = writers.remove(&id) else { return };
    if let Err(e) = w.file.flush().await {
        warn!(id, error = %e, "flush failed");
        let _ = tokio::fs::remove_file(&w.path).await;
        ctx.send_control(FileTransferMsg::Cancel { transfer_id: id });
        ctx.emit(ClientEvent::FileFailed { id, reason: format!("write failed: {e}") }).await;
        return;
    }
    info!(id, path = %w.path.display(), "file received");
    ctx.send_control(FileTransferMsg::Complete { transfer_id: id });
    ctx.emit(ClientEvent::FileDone { id, path: w.path }).await;
}

/// Drop a writer and delete its partial file.
async fn discard(writers: &mut HashMap<u64, Writer>, id: u64) {
    if let Some(w) = writers.remove(&id) {
        drop(w.file);
        if let Err(e) = tokio::fs::remove_file(&w.path).await {
            debug!(path = %w.path.display(), error = %e, "could not delete partial file");
        }
    }
}

/// Offer, wait for acceptance, stream the file, wait for the receiver's
/// verification. Reports the outcome as a `FileDone` / `FileFailed` event.
async fn send_file_task(
    ctx: Arc<FilesCtx>,
    id: u64,
    path: PathBuf,
    mut events: mpsc::UnboundedReceiver<SenderEvent>,
) {
    let outcome = send_file_inner(&ctx, id, &path, &mut events).await;
    match outcome {
        Ok(()) => {
            info!(id, path = %path.display(), "file sent");
            ctx.emit(ClientEvent::FileDone { id, path }).await;
        }
        Err(SendFailure { reason, notify_peer }) => {
            if notify_peer {
                ctx.send_control(FileTransferMsg::Cancel { transfer_id: id });
            }
            debug!(id, %reason, "file send ended");
            ctx.emit(ClientEvent::FileFailed { id, reason }).await;
        }
    }
    let _ = ctx.cmd_tx.send(FileCommand::Finished(id));
}

struct SendFailure {
    reason: String,
    /// False when the peer already knows (it cancelled).
    notify_peer: bool,
}

fn local_failure(reason: impl Into<String>) -> SendFailure {
    SendFailure { reason: reason.into(), notify_peer: true }
}

async fn send_file_inner(
    ctx: &FilesCtx,
    id: u64,
    path: &Path,
    events: &mut mpsc::UnboundedReceiver<SenderEvent>,
) -> Result<(), SendFailure> {
    let meta = tokio::fs::metadata(path).await.map_err(|e| SendFailure { reason: format!("cannot read file: {e}"), notify_peer: false })?;
    if !meta.is_file() {
        return Err(SendFailure { reason: "not a regular file".into(), notify_peer: false });
    }
    let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    let mut out = Outgoing::new(id, meta.len());
    ctx.send_control(out.offer(name));

    // Wait for the host's verdict.
    loop {
        match events.recv().await {
            Some(SenderEvent::Accepted) => break,
            Some(SenderEvent::Cancelled { by_peer }) => {
                return Err(SendFailure { reason: if by_peer { "refused by the host".into() } else { "cancelled".into() }, notify_peer: !by_peer });
            }
            Some(SenderEvent::Refused(reason)) => {
                return Err(SendFailure { reason: format!("refused by the host: {reason}"), notify_peer: false });
            }
            Some(_) => {}
            None => return Err(local_failure("session ended")),
        }
    }

    let mut file = tokio::fs::File::open(path).await.map_err(|e| local_failure(format!("cannot open file: {e}")))?;
    let mut buf = vec![0u8; rotodesk_proto::files::MAX_CHUNK_DATA];
    let mut last_event_at = 0u64;
    loop {
        // Apply whatever arrived without blocking (acks widen the window).
        while let Ok(ev) = events.try_recv() {
            apply_event(ev, &mut out)?;
        }
        match out.next_range() {
            Some((offset, len)) => {
                file.seek(std::io::SeekFrom::Start(offset)).await.map_err(|e| local_failure(format!("seek failed: {e}")))?;
                file.read_exact(&mut buf[..len]).await.map_err(|e| local_failure(format!("read failed: {e}")))?;
                let chunk = FileChunk { transfer_id: id, offset, data: buf[..len].to_vec() };
                let bytes = frame::encode_payload(&chunk).map_err(|e| local_failure(format!("encode failed: {e}")))?;
                ctx.peer.send(Channel::Files, Bytes::from(bytes)).await.map_err(|e| local_failure(format!("send failed: {e}")))?;
                if out.on_sent(len) {
                    ctx.send_control(out.progress());
                }
                if out.sent() - last_event_at >= PROGRESS_INTERVAL || out.is_complete() {
                    last_event_at = out.sent();
                    ctx.emit(ClientEvent::FileProgress { id, transferred: out.sent(), total: out.size }).await;
                }
                // The data channel is reliable but the send call returns as
                // soon as bytes are queued; let other tasks run between chunks.
                tokio::task::yield_now().await;
            }
            None if out.is_complete() => break,
            // Window full: block until the receiver acks (or cancels).
            None => match events.recv().await {
                Some(ev) => apply_event(ev, &mut out)?,
                None => return Err(local_failure("session ended")),
            },
        }
    }
    ctx.send_control(FileTransferMsg::Complete { transfer_id: id });

    // Wait for the receiver to verify and store the file.
    loop {
        match events.recv().await {
            Some(SenderEvent::Done) => return Ok(()),
            Some(SenderEvent::Cancelled { by_peer }) => {
                return Err(SendFailure { reason: if by_peer { "rejected by the host".into() } else { "cancelled".into() }, notify_peer: !by_peer });
            }
            Some(SenderEvent::Refused(reason)) => {
                return Err(SendFailure { reason: format!("rejected by the host: {reason}"), notify_peer: false });
            }
            Some(_) => {}
            None => return Err(local_failure("session ended")),
        }
    }
}

fn apply_event(ev: SenderEvent, out: &mut Outgoing) -> Result<(), SendFailure> {
    match ev {
        SenderEvent::Ack(n) => out.on_ack(n),
        SenderEvent::Cancelled { by_peer } => {
            return Err(SendFailure { reason: if by_peer { "cancelled by the host".into() } else { "cancelled".into() }, notify_peer: !by_peer });
        }
        SenderEvent::Refused(reason) => {
            return Err(SendFailure { reason: format!("aborted by the host: {reason}"), notify_peer: false });
        }
        // A premature Done is meaningless while we are still sending.
        SenderEvent::Accepted | SenderEvent::Done => {}
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unique_path_sanitised_names_dedupe_against_disk() {
        let dir = std::env::temp_dir().join(format!("rotodesk-client-files-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let name = rotodesk_proto::files::sanitize_file_name("..\\..\\report.pdf");
        assert_eq!(name, "report.pdf");
        assert_eq!(unique_path(&dir, &name), dir.join("report.pdf"));
        std::fs::write(dir.join("report.pdf"), b"x").unwrap();
        assert_eq!(unique_path(&dir, &name), dir.join("report (2).pdf"));
        std::fs::write(dir.join("report (2).pdf"), b"x").unwrap();
        assert_eq!(unique_path(&dir, &name), dir.join("report (3).pdf"));
        // The chosen path always stays inside the downloads dir.
        assert!(unique_path(&dir, &rotodesk_proto::files::sanitize_file_name("../../x")).starts_with(&dir));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
