//! RotoDesk viewer (client) role.
//!
//! A client registers with the RotoDesk Server, sends a connection request to a
//! target RotoDesk ID, and — once accepted — establishes a P2P session as the
//! WebRTC *answerer*, then:
//! * receives the video stream, reassembles and decodes it into [`DecodedImage`]s,
//! * forwards local input events to the host,
//! * surfaces control-plane events (permissions, stats, chat, disconnect) to the
//!   embedding UI, and answers the host's unattended-auth challenge if any.
//!
//! Before any of that, right after DTLS comes up, both peers exchange an
//! `IdentityProof` (see `rotodesk_crypto::session`): the host's Ed25519 key
//! is bound to this very DTLS session, so no rendezvous — server, LAN link,
//! DHT or Nostr — can sit in the middle. The verified key is returned in
//! [`ClientSession::peer_public_key`] for the UI to pin (trust on first use)
//! and checked against [`ClientConfig::expected_host_key`] when one is known.
//!
//! The UI drives a [`ClientSession`]: it pulls decoded frames from `frames`,
//! reads [`ClientEvent`]s from `events`, and pushes input / quality / chat /
//! clipboard / files / remote actions back. Everything the viewer sends is
//! gated on the permissions the host announced (`PermissionsUpdated`); the
//! host re-checks on its side regardless.
//!
//! # Loss recovery
//!
//! The video channel is lossy and the codec is delta-based, so a lost frame
//! would corrupt every later frame until the next keyframe. [`FrameGate`]
//! tracks the sequence numbers: on a gap (or a decode error) it discards
//! deltas and asks the host for a keyframe, rate-limited so a lossy link
//! does not turn into a keyframe storm.

use anyhow::{bail, Context, Result};
use bytes::Bytes;
use rotodesk_codec::{DecodedImage, TileDecoder, VideoDecoder};
use rotodesk_crypto::{
    identity::{derive_id_from_public_key_b64, Identity},
    session::{sign_session_proof, verify_peer_session_proof, SessionRole},
};
use rotodesk_proto::{
    frame,
    id::RotoDeskId,
    media::{FrameChunk, Reassembler},
    message::{
        AuthProof, ClipboardData, InputEvent, MonitorInfo, RemoteAction, SessionMessage,
        SignalMessage, SignalPayload,
    },
    permissions::Permissions,
    quality::QualityProfile,
    session::{DeviceInfo, SessionId, SessionStats},
    PROTOCOL_VERSION,
};
use rotodesk_transport::{Channel, IceConfig, PeerConnection, SignalOut, SignalingClient};

mod clipboard;
pub mod community;
mod files;
pub use community::connect_community;
pub use files::default_downloads_dir;
use files::{FileCommand, FilesCtx};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use zeroize::Zeroizing;
use tracing::{debug, info, warn};

/// How long to wait for the host to Accept/Reject.
pub const ACCEPT_TIMEOUT: Duration = Duration::from_secs(45);

/// How long ICE/DTLS may take after acceptance.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

/// Minimum spacing between keyframe requests.
pub const KEYFRAME_REQUEST_INTERVAL: Duration = Duration::from_millis(500);

/// How long the host has, once the peer connection is up, to send its
/// `IdentityProof`.
pub const PROOF_TIMEOUT: Duration = Duration::from_secs(10);

/// Failures of [`connect`] / [`connect_community`] that the UI treats
/// specially (everything else is a plain `anyhow` error with context).
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    /// The host proved a key that differs from the one this device remembers
    /// (or was told to expect) for that ID. Either the machine was
    /// reinstalled or someone is impersonating it: never connect silently.
    #[error("the remote device's identity has changed: expected key {expected}, but it proved {actual}")]
    IdentityMismatch { expected: String, actual: String },
    /// The host never sent its proof.
    #[error("the host did not prove its identity within {0:?}")]
    ProofTimeout(Duration),
    /// The host's proof did not verify (wrong key for the ID, wrong session,
    /// or fingerprints that do not match this DTLS session — a relay in the
    /// middle).
    #[error("the host's identity proof is invalid: {0}")]
    ProofRejected(String),
    /// The host sent something else before its proof.
    #[error("protocol violation: {0} before the identity proof")]
    ProofProtocol(&'static str),
    /// The link closed before the proof arrived.
    #[error("the session closed before the host proved its identity")]
    ProofClosed,
}

/// Configuration for opening a viewer session.
#[derive(Clone)]
pub struct ClientConfig {
    pub signal_url: String,
    pub device: DeviceInfo,
    /// The device identity: announced at registration and used to sign the
    /// server's challenge.
    pub identity: Identity,
    pub target: RotoDeskId,
    pub requested: Permissions,
    pub quality: QualityProfile,
    /// When set, the session uses unattended access and this password answers the
    /// host's challenge.
    pub unattended_password: Option<String>,
    /// Alternative to `unattended_password`: an already-derived key (as stored
    /// by the address book when the user chose "remember password"). Takes
    /// precedence over the password when both are set.
    pub unattended_key: Option<[u8; 32]>,
    /// STUN/TURN servers for ICE.
    pub ice: IceConfig,
    /// Where files the host sends are stored. `None` means
    /// [`default_downloads_dir`] (`<Downloads>/RotoDesk`).
    pub downloads_dir: Option<PathBuf>,
    /// The host's Ed25519 public key (base64) this session must end up
    /// talking to. Community mode fills it from the resolved record; in
    /// server mode the caller sets it from its pinned keys. When the host
    /// proves a different key, `connect` fails with
    /// [`ClientError::IdentityMismatch`]. `None` = trust on first use (the
    /// proven key is still returned in [`ClientSession::peer_public_key`]).
    pub expected_host_key: Option<String>,
}

impl ClientConfig {
    /// A config with sane defaults for everything but the required fields.
    pub fn new(signal_url: String, device: DeviceInfo, identity: Identity, target: RotoDeskId) -> Self {
        Self {
            signal_url,
            device,
            identity,
            target,
            requested: Permissions::interactive(),
            quality: QualityProfile::Auto,
            unattended_password: None,
            unattended_key: None,
            ice: IceConfig::from_env(),
            downloads_dir: None,
            expected_host_key: None,
        }
    }
}

/// Control-plane events surfaced to the embedding UI.
#[derive(Debug, Clone)]
pub enum ClientEvent {
    Connected,
    /// The host introduced itself.
    Hello(DeviceInfo),
    PermissionsUpdated(Permissions),
    Stats(SessionStats),
    Chat(String),
    Monitors(Vec<MonitorInfo>),
    AuthResult(bool),
    Disconnected(String),
    /// Text the host put on its clipboard (only with `CLIPBOARD` granted).
    /// Also applied locally when [`ClientSession::enable_clipboard_sync`] is on.
    Clipboard(String),
    /// The host offers a file; answer with [`ClientSession::accept_file`] or
    /// [`ClientSession::cancel_file`].
    FileOffer { id: u64, name: String, size: u64 },
    /// Progress of a transfer in either direction.
    FileProgress { id: u64, transferred: u64, total: u64 },
    /// A transfer finished: `path` is where the file was stored (incoming)
    /// or the local file that was sent (outgoing).
    FileDone { id: u64, path: PathBuf },
    /// A transfer failed or was cancelled.
    FileFailed { id: u64, reason: String },
}

/// A live viewer session. Frames and events flow *out*; input/quality/chat flow
/// *in* through the helper methods (all non-blocking, safe to call from a GUI
/// thread).
pub struct ClientSession {
    pub session: SessionId,
    pub granted: Permissions,
    /// Which rendezvous path carried the signaling ("servidor", "LAN",
    /// "directo", "nostr"), for the UI.
    pub via: &'static str,
    /// The host's Ed25519 public key (base64), proven over this DTLS session
    /// (`IdentityProof`) in every mode; the UI pins it in the address book.
    pub peer_public_key: Option<String>,
    /// The host's MAC address as announced in its rendezvous record, for
    /// Wake-on-LAN from the address book (community mode only).
    pub peer_mac: Option<String>,
    /// Decoded frames to render (bounded; stale frames are dropped under load).
    pub frames: mpsc::Receiver<DecodedImage>,
    /// Control-plane events.
    pub events: mpsc::Receiver<ClientEvent>,
    input_tx: mpsc::Sender<InputEvent>,
    control_tx: mpsc::UnboundedSender<SessionMessage>,
    files_tx: mpsc::UnboundedSender<FileCommand>,
    /// Viewer-initiated transfer ids are odd (see `rotodesk_proto::files`).
    next_transfer_id: AtomicU64,
    /// Permissions as last announced by the host (`Permissions::bits`).
    granted_live: Arc<AtomicU32>,
    /// Outbound side of the built-in clipboard sync; `None` until enabled.
    clipboard: Arc<Mutex<Option<clipboard::ClipboardSync>>>,
    clipboard_tx: mpsc::UnboundedSender<String>,
    host_protocol_minor: Arc<AtomicU32>,
}

impl std::fmt::Debug for ClientSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientSession").field("session", &self.session).field("via", &self.via).finish()
    }
}

impl ClientSession {
    /// Forward a local input event to the host (best-effort; dropped if the
    /// input queue is full).
    pub fn send_input(&self, ev: InputEvent) {
        let _ = self.input_tx.try_send(ev);
    }

    /// Ask the host to switch quality profile.
    pub fn set_quality(&self, profile: QualityProfile) {
        let _ = self.control_tx.send(SessionMessage::SetQuality { profile });
    }

    /// Send a chat message.
    pub fn send_chat(&self, text: String) {
        let _ = self.control_tx.send(SessionMessage::Chat { text });
    }

    /// Ask the host to switch the captured monitor.
    pub fn select_monitor(&self, index: u16) {
        let _ = self.control_tx.send(SessionMessage::SelectMonitor { index });
    }

    /// Ask the host for a fresh keyframe.
    pub fn request_keyframe(&self) {
        let _ = self.control_tx.send(SessionMessage::RequestKeyframe);
    }

    /// Gracefully end the session.
    pub fn disconnect(&self) {
        let _ = self
            .control_tx
            .send(SessionMessage::Disconnect { reason: "viewer closed".into() });
    }

    /// The permissions currently in force, as last announced by the host
    /// (`granted` is the initial grant from the accept).
    pub fn current_permissions(&self) -> Permissions {
        Permissions::from_bits_truncate(self.granted_live.load(Ordering::Relaxed))
    }

    /// Put `text` on the host's clipboard. Dropped unless `CLIPBOARD` is granted.
    pub fn send_clipboard(&self, text: String) {
        if !self.current_permissions().contains(Permissions::CLIPBOARD) {
            debug!("clipboard send dropped: not granted");
            return;
        }
        if text.len() > clipboard::MAX_TEXT_LEN {
            debug!(len = text.len(), "clipboard send dropped: too large");
            return;
        }
        let _ = self.control_tx.send(SessionMessage::Clipboard(ClipboardData::Text { content: text }));
    }

    /// Whether the host supports applying text before injecting paste.
    pub fn supports_clipboard_paste(&self) -> bool {
        self.host_protocol_minor.load(Ordering::Relaxed) >= 4
    }

    /// Set the remote clipboard and paste only after the host applied it.
    pub fn paste_clipboard(&self, text: String) {
        if !self.supports_clipboard_paste()
            || !self.current_permissions().contains(Permissions::CLIPBOARD | Permissions::CONTROL_KEYBOARD)
            || text.len() > clipboard::MAX_TEXT_LEN
        {
            return;
        }
        let _ = self.control_tx.send(SessionMessage::PasteClipboard { content: text });
    }

    /// Turn on automatic two-way text clipboard sync: local changes are sent
    /// to the host every 100 ms and host changes are applied locally (the
    /// `Clipboard` event is still emitted). Idempotent; everything is gated
    /// on the `CLIPBOARD` permission. Safe to call from a GUI thread.
    pub fn enable_clipboard_sync(&self) {
        let mut guard = lock(&self.clipboard);
        if guard.is_none() {
            *guard = Some(clipboard::ClipboardSync::start(self.clipboard_tx.clone()));
        }
    }

    /// Stop the automatic clipboard sync (explicit sends still work).
    pub fn disable_clipboard_sync(&self) {
        *lock(&self.clipboard) = None;
    }

    /// Offer the local file at `path` to the host. Returns the transfer id
    /// used in the subsequent `FileProgress` / `FileDone` / `FileFailed`
    /// events (a `FileFailed` follows immediately if `FILE_TRANSFER` is not
    /// granted).
    pub fn send_file(&self, path: PathBuf) -> u64 {
        let transfer_id = self.next_transfer_id.fetch_add(2, Ordering::Relaxed);
        let _ = self.files_tx.send(FileCommand::Send { transfer_id, path });
        transfer_id
    }

    /// Accept a file the host offered (`FileOffer`); it lands in the
    /// downloads directory and completes with `FileDone`.
    pub fn accept_file(&self, id: u64) {
        let _ = self.files_tx.send(FileCommand::Accept(id));
    }

    /// Cancel or reject a transfer in either direction.
    pub fn cancel_file(&self, id: u64) {
        let _ = self.files_tx.send(FileCommand::Cancel(id));
    }

    /// Ask the host for a privileged action. Dropped locally when the matching
    /// permission is not granted; the host checks again anyway.
    pub fn remote_action(&self, action: RemoteAction) {
        let needed = match action {
            RemoteAction::RestartMachine => Permissions::RESTART_MACHINE,
            RemoteAction::LockWorkstation | RemoteAction::SecureAttention => Permissions::CONTROL_KEYBOARD,
            RemoteAction::LockLocalInput { .. } => Permissions::LOCK_LOCAL_INPUT,
        };
        if !self.current_permissions().contains(needed) {
            debug!(?action, "remote action dropped: not granted");
            return;
        }
        let _ = self.control_tx.send(SessionMessage::RemoteAction { action });
    }
}

/// Lock a `Mutex`, recovering from poisoning (the guarded value is a plain
/// handle; a poisoned lock is safe to reuse).
fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Open a session to `config.target`. Returns once the P2P link is connected, or
/// an error if the request is rejected / times out / fails to connect.
pub async fn connect(config: ClientConfig) -> Result<ClientSession> {
    let mut signal = SignalingClient::connect(&config.signal_url)
        .await
        .context("connecting to RotoDesk Server")?;
    let identity = config.identity.clone();
    let signer = move |msg: &[u8]| identity.sign_b64(msg);
    let id = signal
        .register(config.device.clone(), config.identity.public_key_b64(), &signer)
        .await
        .context("registering viewer")?;
    info!(%id, target = %config.target, "viewer registered; requesting connection");

    let events_rx = signal.events()?;
    let signal: Arc<dyn SignalOut> = Arc::new(signal);
    connect_over(config, signal, events_rx, "servidor", None, None).await
}

/// The rendezvous-independent part of [`connect`]: request, wait for the
/// host's answer, negotiate WebRTC over `signal`/`events_rx`, bind identities
/// over the DTLS session, wire the session.
///
/// `rendezvous_key` is the host key the rendezvous itself authenticated
/// (community mode's direct/Nostr links); it must agree with the key proven
/// on the channel, and is otherwise only informational.
pub(crate) async fn connect_over(
    config: ClientConfig,
    signal: Arc<dyn SignalOut>,
    mut events_rx: mpsc::Receiver<SignalMessage>,
    via: &'static str,
    rendezvous_key: Option<String>,
    peer_mac: Option<String>,
) -> Result<ClientSession> {
    // Signal intended unattended auth to the server via a (non-secret) proof
    // placeholder; the real challenge/response happens over the control channel.
    let unattended = config.unattended_key.is_some() || config.unattended_password.is_some();
    let auth_proof =
        unattended.then(|| AuthProof { challenge_id: String::new(), response: String::new() });

    signal
        .send(SignalMessage::ConnectRequest {
            target: config.target,
            from: config.device.clone(),
            requested: config.requested,
            quality: config.quality,
            auth_proof,
        })
        .await?;

    // Wait for Accept / Reject.
    let (session, granted) = loop {
        match tokio::time::timeout(ACCEPT_TIMEOUT, events_rx.recv()).await {
            Ok(Some(SignalMessage::Accept { session, granted })) => break (session, granted),
            Ok(Some(SignalMessage::Reject { reason, .. })) => {
                bail!("connection rejected: {reason:?}");
            }
            Ok(Some(SignalMessage::Error { code, detail })) => {
                bail!("server error: {code:?}: {detail}");
            }
            Ok(Some(SignalMessage::Ping { nonce })) => {
                let _ = signal.send(SignalMessage::Pong { nonce }).await;
            }
            Ok(Some(_)) => continue,
            Ok(None) => bail!("signaling closed before accept"),
            Err(_) => bail!("timed out waiting for the host to accept"),
        }
    };
    info!(%session, ?granted, "request accepted");

    // Establish the peer connection as the answerer.
    let mut peer = PeerConnection::new(config.ice.clone(), false).await?;
    let mut incoming = peer.incoming()?;
    let mut ice_out = peer.ice_candidates()?;
    let peer = Arc::new(peer);

    // Trickle local ICE candidates outward.
    {
        let signal = signal.clone();
        tokio::spawn(async move {
            while let Some(payload) = ice_out.recv().await {
                let _ = signal.send(SignalMessage::Signal { session, payload }).await;
            }
        });
    }

    // Apply inbound signaling (offer -> answer, ICE) for the session lifetime.
    {
        let signal = signal.clone();
        let peer = peer.clone();
        tokio::spawn(async move {
            drive_signaling(signal, peer, session, events_rx).await;
        });
    }

    peer.wait_connected_timeout(CONNECT_TIMEOUT)
        .await
        .context("peer connection failed")?;
    info!("viewer connected");

    // Channel binding before anything else. On any failure the peer
    // connection is closed so nothing stays half-open.
    let host_key = match bind_identity(&peer, &mut incoming, &config, session).await {
        Ok(key) => key,
        Err(e) => {
            let _ = peer.close().await;
            return Err(e);
        }
    };
    let expected = config.expected_host_key.as_ref().or(rendezvous_key.as_ref());
    if let Some(expected) = expected {
        if *expected != host_key {
            warn!(target = %config.target, "host proved a key that differs from the expected one");
            let _ = peer.close().await;
            return Err(ClientError::IdentityMismatch { expected: expected.clone(), actual: host_key }.into());
        }
    }
    info!(host_key = %host_key, "host identity bound to the DTLS session");

    // Wire up the session channels.
    let (frames_tx, frames_rx) = mpsc::channel::<DecodedImage>(3);
    let (cev_tx, cev_rx) = mpsc::channel::<ClientEvent>(32);
    let (input_tx, input_rx) = mpsc::channel::<InputEvent>(256);
    let (control_tx, control_rx) = mpsc::unbounded_channel::<SessionMessage>();
    let (files_tx, files_rx) = mpsc::unbounded_channel::<FileCommand>();
    let (clipboard_tx, clipboard_rx) = mpsc::unbounded_channel::<String>();
    let granted_live = Arc::new(AtomicU32::new(granted.bits()));
    let host_protocol_minor = Arc::new(AtomicU32::new(0));
    let clipboard: Arc<Mutex<Option<clipboard::ClipboardSync>>> = Arc::new(Mutex::new(None));

    let _ = cev_tx.try_send(ClientEvent::Connected);
    let _ = control_tx.send(SessionMessage::Hello { protocol: PROTOCOL_VERSION, info: config.device.clone() });

    // Inbound media + control dispatch.
    tokio::spawn(dispatch_incoming(
        peer.clone(),
        incoming,
        frames_tx,
        cev_tx.clone(),
        control_tx.clone(),
        UnattendedCredential::from_config(&config),
        config.target,
        Dispatch {
            files_tx: files_tx.clone(),
            granted: granted_live.clone(),
            clipboard: clipboard.clone(),
            host_protocol_minor: host_protocol_minor.clone(),
        },
    ));

    // File transfers.
    tokio::spawn(files::run_files(
        FilesCtx {
            peer: peer.clone(),
            control_tx: control_tx.clone(),
            events: cev_tx,
            granted: granted_live.clone(),
            downloads: config.downloads_dir.clone().unwrap_or_else(default_downloads_dir),
            cmd_tx: files_tx.clone(),
        },
        files_rx,
    ));

    // Local clipboard changes (only flowing once `enable_clipboard_sync` ran).
    {
        let control_tx = control_tx.clone();
        let granted = granted_live.clone();
        let mut rx = clipboard_rx;
        tokio::spawn(async move {
            while let Some(text) = rx.recv().await {
                if Permissions::from_bits_truncate(granted.load(Ordering::Relaxed)).contains(Permissions::CLIPBOARD) {
                    let _ = control_tx.send(SessionMessage::Clipboard(ClipboardData::Text { content: text }));
                }
            }
        });
    }

    // Outbound input.
    {
        let peer = peer.clone();
        let mut input_rx = input_rx;
        tokio::spawn(async move {
            while let Some(ev) = input_rx.recv().await {
                if let Ok(bytes) = frame::encode_payload(&ev) {
                    if peer.send(Channel::Input, Bytes::from(bytes)).await.is_err() {
                        break;
                    }
                }
            }
        });
    }

    // Outbound control.
    {
        let peer = peer.clone();
        let mut control_rx = control_rx;
        tokio::spawn(async move {
            while let Some(msg) = control_rx.recv().await {
                let disconnect = matches!(msg, SessionMessage::Disconnect { .. });
                if let Ok(bytes) = frame::encode_payload(&msg) {
                    let _ = peer.send(Channel::Control, Bytes::from(bytes)).await;
                }
                if disconnect {
                    let _ = peer.close().await;
                    break;
                }
            }
        });
    }

    Ok(ClientSession {
        session,
        granted,
        via,
        peer_public_key: Some(host_key),
        peer_mac,
        frames: frames_rx,
        events: cev_rx,
        input_tx,
        control_tx,
        files_tx,
        next_transfer_id: AtomicU64::new(1),
        granted_live,
        clipboard,
        clipboard_tx,
        host_protocol_minor,
    })
}

/// Mutual channel binding, viewer side: send our `IdentityProof` over this
/// session's DTLS fingerprints, then wait (at most [`PROOF_TIMEOUT`]) for the
/// host's and verify it against our view of the fingerprints and against the
/// ID we dialed. Returns the host's verified public key (base64).
async fn bind_identity(
    peer: &PeerConnection,
    incoming: &mut mpsc::Receiver<(Channel, Bytes)>,
    config: &ClientConfig,
    session: SessionId,
) -> Result<String> {
    let (local_fp, remote_fp) = peer.dtls_fingerprints().await.context("DTLS fingerprints unavailable")?;
    let signature_b64 = sign_session_proof(&config.identity, &session, &local_fp, &remote_fp, SessionRole::Viewer);
    let proof = SessionMessage::IdentityProof { public_key_b64: config.identity.public_key_b64(), signature_b64 };
    let bytes = frame::encode_payload(&proof).context("encoding identity proof")?;
    peer.send(Channel::Control, Bytes::from(bytes)).await.context("sending identity proof")?;

    let deadline = tokio::time::sleep(PROOF_TIMEOUT);
    tokio::pin!(deadline);
    loop {
        let next = tokio::select! {
            _ = &mut deadline => return Err(ClientError::ProofTimeout(PROOF_TIMEOUT).into()),
            next = incoming.recv() => next,
        };
        let Some((ch, bytes)) = next else { return Err(ClientError::ProofClosed.into()) };
        if ch != Channel::Control {
            // Nothing else is honoured until the host is bound.
            continue;
        }
        let msg = frame::decode_payload::<SessionMessage>(&bytes)
            .map_err(|_| ClientError::ProofProtocol("an undecodable control message"))?;
        return match msg {
            SessionMessage::IdentityProof { public_key_b64, signature_b64 } => {
                verify_host_proof(&public_key_b64, &signature_b64, config.target, session, &local_fp, &remote_fp)
            }
            SessionMessage::Disconnect { reason } => bail!("the host closed the session: {reason}"),
            other => {
                debug!(?other, "control message before identity proof");
                Err(ClientError::ProofProtocol("a control message").into())
            }
        };
    }
}

/// The host's key must derive to the ID we dialed (so a different device
/// cannot answer for it) and its signature must cover *our* fingerprints,
/// swapped, under the `Host` role.
fn verify_host_proof(
    public_key_b64: &str,
    signature_b64: &str,
    target: RotoDeskId,
    session: SessionId,
    local_fp: &str,
    remote_fp: &str,
) -> Result<String> {
    let derived = derive_id_from_public_key_b64(public_key_b64)
        .map_err(|e| ClientError::ProofRejected(format!("bad public key: {e}")))?;
    if derived != target {
        return Err(ClientError::ProofRejected(format!("key derives to {derived}, not to {target}")).into());
    }
    verify_peer_session_proof(public_key_b64, &session, local_fp, remote_fp, SessionRole::Viewer, signature_b64)
        .map_err(|_| ClientError::ProofRejected("signature does not cover this DTLS session".into()))?;
    Ok(public_key_b64.to_string())
}

/// Session-wide shared state the inbound dispatcher updates or forwards to.
struct Dispatch {
    files_tx: mpsc::UnboundedSender<FileCommand>,
    granted: Arc<AtomicU32>,
    clipboard: Arc<Mutex<Option<clipboard::ClipboardSync>>>,
    host_protocol_minor: Arc<AtomicU32>,
}

/// Background: apply offer/answer/ICE from the server to the peer. Ends with
/// the peer connection so the signaling socket (and its registration) does
/// not outlive the session.
async fn drive_signaling(
    signal: Arc<dyn SignalOut>,
    peer: Arc<PeerConnection>,
    session: SessionId,
    mut events_rx: mpsc::Receiver<SignalMessage>,
) {
    loop {
        let msg = tokio::select! {
            _ = peer.wait_closed() => break,
            msg = events_rx.recv() => match msg {
                Some(msg) => msg,
                None => break,
            },
        };
        match msg {
            SignalMessage::Signal { session: s, payload } if s == session => match payload {
                SignalPayload::Offer { sdp } => {
                    if let Err(e) = peer.set_remote_description(sdp, true).await {
                        warn!(error = %e, "set remote offer failed");
                        continue;
                    }
                    match peer.create_answer().await {
                        Ok(sdp) => {
                            let _ = signal
                                .send(SignalMessage::Signal {
                                    session,
                                    payload: SignalPayload::Answer { sdp },
                                })
                                .await;
                        }
                        Err(e) => warn!(error = %e, "create answer failed"),
                    }
                }
                SignalPayload::IceCandidate { candidate, sdp_mid, sdp_mline_index } => {
                    if let Err(e) =
                        peer.add_ice_candidate(candidate, sdp_mid, sdp_mline_index).await
                    {
                        debug!(error = %e, "add ice candidate failed");
                    }
                }
                SignalPayload::Answer { .. } => {} // we are the answerer
            },
            SignalMessage::Ping { nonce } => {
                let _ = signal.send(SignalMessage::Pong { nonce }).await;
            }
            SignalMessage::Reject { session: s, .. } if s == session => break,
            _ => {}
        }
    }
}

/// Decides whether an incoming frame may be decoded, and when to ask the host
/// for a keyframe. Pure state machine (see module docs).
#[derive(Debug)]
pub struct FrameGate {
    last_seq: Option<u64>,
    /// True while we are discarding deltas waiting for a keyframe.
    waiting_for_keyframe: bool,
    last_request: Option<Instant>,
    dropped_seen: u64,
}

impl Default for FrameGate {
    fn default() -> Self {
        Self { last_seq: None, waiting_for_keyframe: true, last_request: None, dropped_seen: 0 }
    }
}

/// What to do with a reassembled frame.
#[derive(Debug, PartialEq, Eq)]
pub enum GateAction {
    /// Decode it.
    Decode,
    /// Discard it and ask the host for a keyframe now.
    DropAndRequest,
    /// Discard it; a request was sent recently, wait for it.
    Drop,
}

impl FrameGate {
    pub fn new() -> Self {
        Self::default()
    }

    /// Classify a frame with sequence `seq`; `keyframe` says whether it is
    /// self-contained. Call with the current time for rate limiting.
    pub fn on_frame(&mut self, seq: u64, keyframe: bool, now: Instant) -> GateAction {
        if keyframe {
            self.waiting_for_keyframe = false;
            self.last_seq = Some(seq);
            return GateAction::Decode;
        }
        let contiguous = self.last_seq.is_some_and(|last| seq == last.wrapping_add(1));
        if self.waiting_for_keyframe || !contiguous {
            self.waiting_for_keyframe = true;
            return self.request(now);
        }
        self.last_seq = Some(seq);
        GateAction::Decode
    }

    /// The decoder rejected a frame we let through: resync on a keyframe.
    pub fn on_decode_error(&mut self, now: Instant) -> GateAction {
        self.waiting_for_keyframe = true;
        self.request(now)
    }

    /// The reassembler abandoned partial frames (its monotonic counter is
    /// `dropped_total`); ask for a keyframe if that number grew.
    pub fn on_reassembler_drops(&mut self, dropped_total: u64, now: Instant) -> GateAction {
        if dropped_total > self.dropped_seen {
            self.dropped_seen = dropped_total;
            self.waiting_for_keyframe = true;
            return self.request(now);
        }
        GateAction::Drop
    }

    fn request(&mut self, now: Instant) -> GateAction {
        let due = self
            .last_request
            .is_none_or(|t| now.saturating_duration_since(t) >= KEYFRAME_REQUEST_INTERVAL);
        if due {
            self.last_request = Some(now);
            GateAction::DropAndRequest
        } else {
            GateAction::Drop
        }
    }
}

/// Background: decode inbound video and handle inbound control messages.
#[allow(clippy::too_many_arguments)]
async fn dispatch_incoming(
    peer: Arc<PeerConnection>,
    mut incoming: mpsc::Receiver<(Channel, Bytes)>,
    frames_tx: mpsc::Sender<DecodedImage>,
    cev_tx: mpsc::Sender<ClientEvent>,
    control_tx: mpsc::UnboundedSender<SessionMessage>,
    credential: Option<UnattendedCredential>,
    host_id: RotoDeskId,
    shared: Dispatch,
) {
    let mut decoder = TileDecoder::new();
    let mut reassembler = Reassembler::new();
    let mut gate = FrameGate::new();
    let request_keyframe = |action: GateAction| {
        if action == GateAction::DropAndRequest {
            debug!("requesting keyframe from host");
            let _ = control_tx.send(SessionMessage::RequestKeyframe);
        }
    };

    let mut deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    loop {
        let next = tokio::select! {
            biased;
            _ = peer.wait_closed() => None,
            _ = tokio::time::sleep_until(deadline) => {
                let _ = cev_tx.send(ClientEvent::Disconnected("remote timed out after 20 seconds".into())).await;
                break;
            }
            next = incoming.recv() => next,
        };
        let Some((ch, bytes)) = next else { break };
        deadline = tokio::time::Instant::now() + Duration::from_secs(20);
        match ch {
            Channel::Video => {
                let Ok(chunk) = frame::decode_payload::<FrameChunk>(&bytes) else { continue };
                let completed = reassembler.push(chunk);
                request_keyframe(gate.on_reassembler_drops(reassembler.dropped_frames(), Instant::now()));
                let Some(vf) = completed else { continue };
                match gate.on_frame(vf.sequence, vf.keyframe, Instant::now()) {
                    GateAction::Decode => match decoder.decode(&vf) {
                        // Drop frames if the renderer is behind — video is
                        // latency-sensitive, not loss-sensitive.
                        Ok(img) => {
                            let _ = frames_tx.try_send(img);
                        }
                        Err(e) => {
                            debug!(error = %e, "decode failed");
                            request_keyframe(gate.on_decode_error(Instant::now()));
                        }
                    },
                    other => request_keyframe(other),
                }
            }
            Channel::Control => {
                let Ok(msg) = frame::decode_payload::<SessionMessage>(&bytes) else { continue };
                match msg {
                    SessionMessage::Hello { info, protocol } => {
                        shared.host_protocol_minor.store(u32::from(protocol.minor), Ordering::Relaxed);
                        if !protocol.compatible_with(PROTOCOL_VERSION) {
                            warn!(%protocol, "host speaks an incompatible protocol");
                        }
                        let _ = cev_tx.send(ClientEvent::Hello(info)).await;
                    }
                    SessionMessage::AuthChallenge { challenge_b64 } => {
                        respond_to_challenge(
                            &peer,
                            &challenge_b64,
                            credential.as_ref(),
                            host_id,
                        )
                        .await;
                    }
                    SessionMessage::AuthResult { ok } => {
                        let _ = cev_tx.send(ClientEvent::AuthResult(ok)).await;
                        if !ok {
                            let _ = cev_tx
                                .send(ClientEvent::Disconnected("authentication failed".into()))
                                .await;
                        }
                    }
                    SessionMessage::PermissionsUpdate { granted } => {
                        shared.granted.store(granted.bits(), Ordering::Relaxed);
                        let _ = cev_tx.send(ClientEvent::PermissionsUpdated(granted)).await;
                    }
                    SessionMessage::Clipboard(ClipboardData::Text { content }) => {
                        let granted = Permissions::from_bits_truncate(shared.granted.load(Ordering::Relaxed));
                        if !granted.contains(Permissions::CLIPBOARD) || content.len() > clipboard::MAX_TEXT_LEN {
                            debug!("ignoring clipboard from host");
                            continue;
                        }
                        if let Some(sync) = lock(&shared.clipboard).as_ref() {
                            sync.apply_remote(content.clone());
                        }
                        let _ = cev_tx.send(ClientEvent::Clipboard(content)).await;
                    }
                    SessionMessage::File(msg) => {
                        let _ = shared.files_tx.send(FileCommand::Control(msg));
                    }
                    SessionMessage::Stats(s) => {
                        let _ = cev_tx.send(ClientEvent::Stats(s)).await;
                    }
                    SessionMessage::Chat { text } => {
                        let _ = cev_tx.send(ClientEvent::Chat(text)).await;
                    }
                    SessionMessage::Monitors { monitors } => {
                        let _ = cev_tx.send(ClientEvent::Monitors(monitors)).await;
                    }
                    SessionMessage::Ping { nonce } => {
                        let _ = control_tx.send(SessionMessage::Pong { nonce });
                    }
                    SessionMessage::Disconnect { reason } => {
                        let _ = cev_tx.send(ClientEvent::Disconnected(reason)).await;
                        break;
                    }
                    // Binding happened before this task started; a late
                    // proof never re-binds.
                    SessionMessage::IdentityProof { .. } => debug!("duplicate identity proof ignored"),
                    _ => {}
                }
            }
            Channel::Files => {
                let _ = shared.files_tx.send(FileCommand::Chunk(bytes));
            }
            Channel::Input => {}
        }
    }
    let _ = peer.close().await;
    let _ = cev_tx.send(ClientEvent::Disconnected("session ended".into())).await;
}

/// Compute and send the HMAC response to an unattended-auth challenge.
/// What the viewer holds to answer an unattended challenge. Wiped from
/// memory when dropped.
#[derive(Clone)]
pub enum UnattendedCredential {
    Password(Zeroizing<String>),
    Key(Zeroizing<[u8; 32]>),
}

impl UnattendedCredential {
    fn from_config(config: &ClientConfig) -> Option<Self> {
        if let Some(k) = config.unattended_key {
            return Some(Self::Key(Zeroizing::new(k)));
        }
        config.unattended_password.clone().map(|pw| Self::Password(Zeroizing::new(pw)))
    }

    /// The HMAC key for `host_id`, deriving it from the password if needed.
    pub fn key_for(&self, host_id: RotoDeskId) -> Option<Zeroizing<[u8; 32]>> {
        match self {
            Self::Key(k) => Some(k.clone()),
            Self::Password(pw) => rotodesk_crypto::password::unattended_key(pw, host_id.value()).ok().map(Zeroizing::new),
        }
    }
}

async fn respond_to_challenge(
    peer: &PeerConnection,
    challenge_b64: &str,
    credential: Option<&UnattendedCredential>,
    host_id: RotoDeskId,
) {
    let Some(credential) = credential else {
        warn!("host requested unattended auth but no password is configured");
        return;
    };
    let Some(challenge) = rotodesk_crypto::proof::Challenge::from_b64(challenge_b64) else {
        warn!("received malformed auth challenge");
        return;
    };
    let Some(key) = credential.key_for(host_id) else {
        return;
    };
    let response = rotodesk_crypto::proof::respond(&key, &challenge);
    if let Ok(bytes) = frame::encode_payload(&SessionMessage::AuthResponse { response_b64: response })
    {
        let _ = peer.send(Channel::Control, Bytes::from(bytes)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gate_requires_a_keyframe_first() {
        let mut g = FrameGate::new();
        let t = Instant::now();
        assert_eq!(g.on_frame(0, false, t), GateAction::DropAndRequest);
        assert_eq!(g.on_frame(1, false, t), GateAction::Drop, "rate limited");
        assert_eq!(g.on_frame(2, true, t), GateAction::Decode);
        assert_eq!(g.on_frame(3, false, t), GateAction::Decode);
    }

    #[test]
    fn gate_detects_gaps_and_resyncs_on_keyframe() {
        let mut g = FrameGate::new();
        let t = Instant::now();
        assert_eq!(g.on_frame(10, true, t), GateAction::Decode);
        assert_eq!(g.on_frame(11, false, t), GateAction::Decode);
        // 12 lost.
        assert_eq!(g.on_frame(13, false, t), GateAction::DropAndRequest);
        assert_eq!(g.on_frame(14, false, t), GateAction::Drop);
        let later = t + KEYFRAME_REQUEST_INTERVAL;
        assert_eq!(g.on_frame(15, false, later), GateAction::DropAndRequest);
        assert_eq!(g.on_frame(16, true, later), GateAction::Decode);
        assert_eq!(g.on_frame(17, false, later), GateAction::Decode);
    }

    #[test]
    fn gate_reacts_to_decode_errors_and_reassembler_drops() {
        let mut g = FrameGate::new();
        let t = Instant::now();
        assert_eq!(g.on_frame(0, true, t), GateAction::Decode);
        assert_eq!(g.on_decode_error(t), GateAction::DropAndRequest);
        assert_eq!(g.on_frame(1, false, t), GateAction::Drop);
        assert_eq!(g.on_frame(2, true, t), GateAction::Decode);

        assert_eq!(g.on_reassembler_drops(0, t), GateAction::Drop, "no new drops");
        let later = t + KEYFRAME_REQUEST_INTERVAL;
        assert_eq!(g.on_reassembler_drops(1, later), GateAction::DropAndRequest);
        assert_eq!(g.on_reassembler_drops(1, later), GateAction::Drop);
        assert_eq!(g.on_frame(3, false, later), GateAction::Drop, "deltas ignored until keyframe");
    }

    #[test]
    fn gate_handles_sequence_wraparound() {
        let mut g = FrameGate::new();
        let t = Instant::now();
        assert_eq!(g.on_frame(u64::MAX, true, t), GateAction::Decode);
        assert_eq!(g.on_frame(0, false, t), GateAction::Decode);
    }
}

#[cfg(test)]
mod session_lifecycle_tests {
    use super::*;

    async fn silent_session() -> (Arc<PeerConnection>, mpsc::Sender<(Channel, Bytes)>, mpsc::Receiver<ClientEvent>, tokio::task::JoinHandle<()>) {
        let peer = Arc::new(PeerConnection::new(IceConfig::default(), false).await.unwrap());
        let (incoming_tx, incoming) = mpsc::channel(8);
        let (frames_tx, _frames) = mpsc::channel(8);
        let (events_tx, events) = mpsc::channel(8);
        let (control_tx, _control) = mpsc::unbounded_channel();
        let (files_tx, _files) = mpsc::unbounded_channel();
        let task = tokio::spawn(dispatch_incoming(peer.clone(), incoming, frames_tx, events_tx, control_tx, None,
            RotoDeskId::parse("123456789").unwrap(), Dispatch {
                files_tx, granted: Arc::new(AtomicU32::new(0)),
                clipboard: Arc::new(Mutex::new(None)), host_protocol_minor: Arc::new(AtomicU32::new(0)),
            }));
        (peer, incoming_tx, events, task)
    }

    #[tokio::test]
    async fn silent_remote_ends_session_after_twenty_seconds_with_sender_alive() {
        let (_peer, _sender, mut events, task) = silent_session().await;
        let start = Instant::now();
        let event = tokio::time::timeout(Duration::from_secs(23), events.recv()).await.unwrap().unwrap();
        assert!(matches!(event, ClientEvent::Disconnected(reason) if reason.contains("20 seconds")));
        assert!(start.elapsed() >= Duration::from_secs(20));
        task.await.unwrap();
    }

    #[tokio::test]
    async fn inbound_heartbeat_refreshes_timeout_and_transport_close_ends_session() {
        let (peer, sender, mut events, task) = silent_session().await;
        tokio::time::sleep(Duration::from_secs(12)).await;
        sender.send((Channel::Control, frame::encode_payload(&SessionMessage::Ping { nonce: 1 }).unwrap().into())).await.unwrap();
        assert!(tokio::time::timeout(Duration::from_secs(10), events.recv()).await.is_err(), "heartbeat must extend the original 20 second deadline");
        peer.close().await.unwrap();
        assert!(matches!(tokio::time::timeout(Duration::from_secs(2), events.recv()).await.unwrap().unwrap(), ClientEvent::Disconnected(_)));
        task.await.unwrap();
    }
}
