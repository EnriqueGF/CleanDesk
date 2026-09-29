//! CleanDesk host role.
//!
//! A host registers with the CleanDesk Server, waits for connection requests,
//! and — once a request is approved — establishes a P2P session as the WebRTC
//! *offerer*, then:
//! * captures the screen, encodes it and streams it on the video channel,
//! * receives input events and injects them (gated by the granted permissions),
//! * exchanges control messages (auth, permissions, quality, chat, disconnect).
//!
//! Approval is delegated to an [`Approver`] so the same engine serves both the
//! interactive GUI (a human clicks Accept) and headless/unattended modes.
//!
//! Safety properties this module guarantees:
//! * Nothing is sent or honoured on a session until the viewer proved, with
//!   its Ed25519 key, that it sits at the far end of *this* DTLS session
//!   (`IdentityProof`, see `cleandesk_crypto::session`), so a rendezvous
//!   cannot sit in the middle even though it relayed the SDP fingerprints.
//! * No input is injected before the session is authenticated and never
//!   beyond the granted [`Permissions`].
//! * Every key/button the viewer pressed is released when the session ends,
//!   however it ends, so a dropped connection never leaves a stuck modifier.
//! * Unattended authentication is rate-limited per verified caller key and
//!   globally ([`AuthThrottle`]) and bounded in time ([`AUTH_TIMEOUT`]).

mod clipboard;
pub mod community;
mod files;
mod media;
mod throttle;

pub use community::{serve_community, CommunityOptions};
pub use files::{default_downloads_dir, DEFAULT_MAX_FILE_SIZE, FREE_SPACE_MARGIN, MAX_CONCURRENT_INCOMING};
pub use media::MediaControl;
pub use throttle::AuthThrottle;

use anyhow::{Context, Result};
use async_trait::async_trait;
use bytes::Bytes;
use cleandesk_crypto::{
    identity::{derive_id_from_public_key_b64, Identity},
    session::{sign_session_proof, verify_peer_session_proof, SessionRole},
};
use cleandesk_proto::{
    frame,
    files::FileChunk,
    message::{
        AuthKind, ClipboardData, FileTransferMsg, InputEvent, MonitorInfo, MouseButton,
        RejectReason, RemoteAction, SessionMessage, SignalMessage, SignalPayload,
    },
    permissions::Permissions,
    quality::QualityProfile,
    session::{DeviceInfo, SessionId, SessionStats},
    PROTOCOL_VERSION,
};
use cleandesk_transport::{Channel, IceConfig, PeerConnection, SignalOut, SignalingClient};
use parking_lot::Mutex;
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, Notify};
use tracing::{debug, info, warn};

/// Errors the host loop reports besides plain transport failures.
#[derive(Debug, thiserror::Error)]
pub enum HostError {
    /// The server replaced our registration with a newer one of the same
    /// identity; the caller decides whether to retry (usually: wait until the
    /// other instance is gone).
    #[error("registration replaced by another instance of this device")]
    Replaced,
}

/// How long the peer connection may take to reach `Connected`.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

/// How long an unattended viewer has to answer the challenge.
pub const AUTH_TIMEOUT: Duration = Duration::from_secs(30);

/// How long the viewer has, once the peer connection is up, to send its
/// `IdentityProof`. Short on purpose: the proof needs no user interaction.
pub const PROOF_TIMEOUT: Duration = Duration::from_secs(10);

/// Interval between `Stats` pushes and RTT pings.
const STATS_INTERVAL: Duration = Duration::from_secs(2);

/// Static configuration for a host.
#[derive(Clone)]
pub struct HostConfig {
    pub signal_url: String,
    pub device: DeviceInfo,
    /// The device identity: its public key is announced at registration and
    /// its private key signs the server's challenge.
    pub identity: Identity,
    /// Argon2id-derived HMAC key for unattended access (from
    /// `core::Settings::unattended_key`). `None` disables unattended access —
    /// such requests are rejected.
    pub unattended_key: Option<[u8; 32]>,
    /// Default quality profile for new sessions.
    pub quality: QualityProfile,
    /// STUN/TURN servers for ICE.
    pub ice: IceConfig,
    /// Optional sink for lifecycle events (the GUI shows who is connected and
    /// records history from these).
    pub events: Option<mpsc::UnboundedSender<HostEvent>>,
    /// Optional handle through which the local user can end a session.
    pub control: Option<Arc<HostControl>>,
    /// Options for [`serve_community`] (ignored by [`serve`]).
    pub community: CommunityOptions,
    /// Where files sent by the viewer are stored. `None` means
    /// [`default_downloads_dir`] (`<Downloads>/CleanDesk`).
    pub downloads_dir: Option<PathBuf>,
    /// Largest single file a viewer may send, in bytes
    /// ([`DEFAULT_MAX_FILE_SIZE`] = 8 GiB). Larger offers are refused.
    pub max_file_size: u64,
}

impl HostConfig {
    /// A config with sane defaults for everything but the required fields.
    pub fn new(signal_url: String, device: DeviceInfo, identity: Identity) -> Self {
        Self {
            signal_url,
            device,
            identity,
            unattended_key: None,
            quality: QualityProfile::Auto,
            ice: IceConfig::from_env(),
            events: None,
            control: None,
            community: CommunityOptions::default(),
            downloads_dir: None,
            max_file_size: DEFAULT_MAX_FILE_SIZE,
        }
    }
}

/// Lifecycle notifications from the host runtime.
#[derive(Debug, Clone)]
pub enum HostEvent {
    /// Registered with the server under this ID.
    Registered(cleandesk_proto::CleanDeskId),
    /// A viewer session is live (post-authentication).
    SessionStarted { session: SessionId, peer: DeviceInfo, granted: Permissions },
    /// The session ended; `reason` is human-readable.
    SessionEnded { session: SessionId, reason: String },
}

/// Local control over the running host (spec §18 / §28: the person at the
/// host can always cut a session).
#[derive(Default)]
pub struct HostControl {
    terminate: Notify,
}

impl HostControl {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// End the active session, if any.
    pub fn terminate_session(&self) {
        self.terminate.notify_one();
    }
}

/// The outcome of evaluating an incoming connection request.
pub enum Decision {
    Accept(Permissions),
    Reject(RejectReason),
}

/// Decides whether to accept an incoming request and with which permissions.
#[async_trait]
pub trait Approver: Send + Sync + 'static {
    async fn on_request(
        &self,
        from: &DeviceInfo,
        requested: Permissions,
        auth: AuthKind,
    ) -> Decision;
}

/// An approver that accepts every request, granting the intersection of the
/// requested permissions and `allowed`. **Use only for trusted/unattended
/// deployments** — it performs no human confirmation.
pub struct AutoAccept {
    pub allowed: Permissions,
}

#[async_trait]
impl Approver for AutoAccept {
    async fn on_request(&self, _from: &DeviceInfo, requested: Permissions, _auth: AuthKind) -> Decision {
        Decision::Accept(requested & self.allowed)
    }
}

/// What a session reports back to the main loop.
#[derive(Debug)]
pub(crate) enum SessionOutcome {
    /// An unattended challenge was answered wrongly by the viewer whose
    /// verified public key is `caller` (already counted in the throttle;
    /// reported so the main loop logs lockouts in one place).
    AuthFailed { caller: String },
    Ended { session: SessionId, reason: String },
}

/// Run the host event loop until the signaling connection closes.
///
/// Handles one session at a time (MVP): while a session is active, further
/// requests are rejected as `Busy`.
pub async fn serve(config: HostConfig, approver: Arc<dyn Approver>) -> Result<()> {
    let mut signal = SignalingClient::connect(&config.signal_url)
        .await
        .context("connecting to CleanDesk Server")?;
    let identity = config.identity.clone();
    let signer = move |msg: &[u8]| identity.sign_b64(msg);
    let id = signal
        .register(config.device.clone(), config.identity.public_key_b64(), &signer)
        .await
        .context("registering host")?;
    info!(%id, "host registered and waiting for connections");
    emit(&config, HostEvent::Registered(id));

    let mut events = signal.events()?;
    let signal: Arc<dyn SignalOut> = Arc::new(signal);
    let control = config.control.clone().unwrap_or_default();
    let mut core = HostCore::new(config, approver);

    loop {
        tokio::select! {
            msg = events.recv() => {
                let Some(msg) = msg else { break };
                if let SignalMessage::Error { code: cleandesk_proto::message::ErrorCode::IdConflict, detail } = &msg {
                    // Another instance of this same identity registered (the GUI
                    // while we are the service helper, or vice versa). Stand down.
                    warn!(%detail, "registration replaced; stopping host loop");
                    core.terminate();
                    return Err(HostError::Replaced.into());
                }
                core.on_signal(msg, &signal).await;
            }
            Some(outcome) = core.outcome_rx.recv() => core.on_outcome(outcome),
            _ = control.terminate.notified() => core.terminate(),
        }
    }

    Ok(())
}

/// The rendezvous-agnostic heart of the host: one active session, the auth
/// throttle, and the bookkeeping shared by [`serve`] and [`serve_community`].
pub(crate) struct HostCore {
    pub(crate) config: HostConfig,
    approver: Arc<dyn Approver>,
    outcome_tx: mpsc::UnboundedSender<SessionOutcome>,
    pub(crate) outcome_rx: mpsc::UnboundedReceiver<SessionOutcome>,
    /// Shared with the session task, which is the only place the viewer's
    /// *verified* key (the throttle's key) is known.
    throttle: Arc<Mutex<AuthThrottle>>,
    active: Option<ActiveSession>,
}

impl HostCore {
    pub(crate) fn new(config: HostConfig, approver: Arc<dyn Approver>) -> Self {
        let (outcome_tx, outcome_rx) = mpsc::unbounded_channel();
        Self {
            config,
            approver,
            outcome_tx,
            outcome_rx,
            throttle: Arc::new(Mutex::new(AuthThrottle::default())),
            active: None,
        }
    }

    /// Feed one signaling message that arrived over `out`'s link.
    pub(crate) async fn on_signal(&mut self, msg: SignalMessage, out: &Arc<dyn SignalOut>) {
        handle_signal(msg, &self.config, &self.approver, out, &self.outcome_tx, &self.throttle, &mut self.active).await;
    }

    pub(crate) fn on_outcome(&mut self, outcome: SessionOutcome) {
        match outcome {
            SessionOutcome::AuthFailed { caller } => {
                let locked = self.throttle.lock().locked_for(&caller, Instant::now());
                warn!(%caller, ?locked, "unattended authentication failed");
            }
            SessionOutcome::Ended { session, reason } => {
                if self.active.as_ref().is_some_and(|a| a.session == session) {
                    self.active = None;
                }
                emit(&self.config, HostEvent::SessionEnded { session, reason });
            }
        }
    }

    /// End the active session (local user pressed "Finalizar").
    pub(crate) fn terminate(&mut self) {
        if let Some(a) = self.active.take() {
            info!(session = %a.session, "session terminated by local user");
            emit(&self.config, HostEvent::SessionEnded { session: a.session, reason: "terminated by the host".into() });
        }
    }

    /// The live session id, if any.
    pub(crate) fn active_session(&self) -> Option<SessionId> {
        self.active.as_ref().filter(|a| a.is_alive()).map(|a| a.session)
    }
}

fn emit(config: &HostConfig, ev: HostEvent) {
    if let Some(tx) = &config.events {
        let _ = tx.send(ev);
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_signal(
    msg: SignalMessage,
    config: &HostConfig,
    approver: &Arc<dyn Approver>,
    signal: &Arc<dyn SignalOut>,
    outcome_tx: &mpsc::UnboundedSender<SessionOutcome>,
    throttle: &Arc<Mutex<AuthThrottle>>,
    active: &mut Option<ActiveSession>,
) {
    match msg {
        SignalMessage::IncomingRequest { session, from, requested, quality, auth } => {
            if active.as_ref().is_some_and(|a| a.is_alive()) {
                let _ = signal.send(reject(session, RejectReason::Busy)).await;
                return;
            }
            info!(%session, from = %from.id, ?requested, ?auth, "incoming request");

            if matches!(auth, AuthKind::UnattendedPassword) {
                // Unattended requests need a configured key and the global
                // breaker must not be tripped. The per-caller lockout is
                // checked in the session, once the caller's key is verified
                // (the id here is only what the rendezvous told us).
                if config.unattended_key.is_none() {
                    let _ = signal.send(reject(session, RejectReason::AuthFailed)).await;
                    return;
                }
                let global_wait = {
                    let now = Instant::now();
                    let mut t = throttle.lock();
                    t.prune(now);
                    t.global_locked_for(now)
                };
                if let Some(wait) = global_wait {
                    warn!(from = %from.id, ?wait, "unattended auth globally locked out");
                    let _ = signal.send(reject(session, RejectReason::AuthFailed)).await;
                    return;
                }
            }

            let granted = match approver.on_request(&from, requested, auth).await {
                // A session without screen access is meaningless; also a
                // viewer must never get more than it asked for.
                Decision::Accept(g) => (g & requested) | Permissions::VIEW_SCREEN,
                Decision::Reject(reason) => {
                    let _ = signal.send(reject(session, reason)).await;
                    return;
                }
            };

            let _ = signal.send(SignalMessage::Accept { session, granted }).await;

            let ctx = SessionCtx {
                session,
                peer: from,
                granted,
                quality,
                auth,
                config: config.clone(),
                outcome_tx: outcome_tx.clone(),
                throttle: throttle.clone(),
            };
            match establish(signal.clone(), ctx).await {
                Ok(a) => *active = Some(a),
                Err(e) => {
                    warn!(%session, error = %e, "failed to establish session");
                    let _ = signal.send(reject(session, RejectReason::Timeout)).await;
                }
            }
        }

        SignalMessage::Signal { session, payload } => {
            if let Some(a) = active {
                if a.session == session {
                    a.apply_signal(payload).await;
                }
            }
        }

        SignalMessage::Reject { session, .. } => {
            if active.as_ref().is_some_and(|a| a.session == session) {
                *active = None; // dropping aborts the session tasks
                emit(config, HostEvent::SessionEnded { session, reason: "rejected".into() });
            }
        }

        SignalMessage::Ping { nonce } => {
            let _ = signal.send(SignalMessage::Pong { nonce }).await;
        }

        other => debug!(?other, "host ignoring signaling message"),
    }
}

/// Everything a session needs to know about itself.
#[derive(Clone)]
struct SessionCtx {
    session: SessionId,
    peer: DeviceInfo,
    granted: Permissions,
    quality: QualityProfile,
    auth: AuthKind,
    config: HostConfig,
    outcome_tx: mpsc::UnboundedSender<SessionOutcome>,
    throttle: Arc<Mutex<AuthThrottle>>,
}

/// Handle to an established session; dropping it tears the session down.
struct ActiveSession {
    session: SessionId,
    peer: Arc<PeerConnection>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl ActiveSession {
    fn is_alive(&self) -> bool {
        self.tasks.iter().any(|t| !t.is_finished())
    }

    /// Route an inbound signaling payload (Answer / ICE) into the peer.
    async fn apply_signal(&self, payload: SignalPayload) {
        match payload {
            SignalPayload::Answer { sdp } => {
                if let Err(e) = self.peer.set_remote_description(sdp, false).await {
                    warn!(error = %e, "set remote answer failed");
                }
            }
            SignalPayload::IceCandidate { candidate, sdp_mid, sdp_mline_index } => {
                if let Err(e) = self
                    .peer
                    .add_ice_candidate(candidate, sdp_mid, sdp_mline_index)
                    .await
                {
                    debug!(error = %e, "add ice candidate failed");
                }
            }
            // The host is the offerer; a remote offer is unexpected.
            SignalPayload::Offer { .. } => {}
        }
    }
}

impl Drop for ActiveSession {
    fn drop(&mut self) {
        for t in &self.tasks {
            t.abort();
        }
        let peer = self.peer.clone();
        // Drop can run while the runtime is shutting down; never panic there.
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(async move {
                let _ = peer.close().await;
            });
        }
    }
}

/// Create the peer connection (offerer), send the offer, and spawn the session.
async fn establish(signal: Arc<dyn SignalOut>, ctx: SessionCtx) -> Result<ActiveSession> {
    let session = ctx.session;
    let mut peer = PeerConnection::new(ctx.config.ice.clone(), true).await?;
    let incoming = peer.incoming()?;
    let mut ice_out = peer.ice_candidates()?;
    let peer = Arc::new(peer);

    let mut tasks = Vec::new();

    // Trickle our local ICE candidates to the peer via the server.
    {
        let signal = signal.clone();
        tasks.push(tokio::spawn(async move {
            while let Some(payload) = ice_out.recv().await {
                let _ = signal.send(SignalMessage::Signal { session, payload }).await;
            }
        }));
    }

    // Offer.
    let offer = peer.create_offer().await.context("create offer")?;
    signal
        .send(SignalMessage::Signal { session, payload: SignalPayload::Offer { sdp: offer } })
        .await?;

    // The session driver: wait for connectivity, then run the pipelines.
    tasks.push(tokio::spawn(run_session(peer.clone(), incoming, ctx)));

    Ok(ActiveSession { session, peer, tasks })
}

/// Everything that happens once the peer connection is (about to be) live.
async fn run_session(
    peer: Arc<PeerConnection>,
    mut incoming: mpsc::Receiver<(Channel, Bytes)>,
    ctx: SessionCtx,
) {
    let outcome = ctx.outcome_tx.clone();
    let reason = run_session_inner(peer.clone(), &mut incoming, &ctx).await;
    let _ = peer.close().await;
    info!(session = %ctx.session, %reason, "session ended");
    let _ = outcome.send(SessionOutcome::Ended { session: ctx.session, reason });
}

async fn run_session_inner(
    peer: Arc<PeerConnection>,
    incoming: &mut mpsc::Receiver<(Channel, Bytes)>,
    ctx: &SessionCtx,
) -> String {
    if let Err(e) = peer.wait_connected_timeout(CONNECT_TIMEOUT).await {
        warn!(error = %e, "peer never connected");
        return format!("no P2P connection: {e}");
    }
    info!("session connected");

    // Channel binding comes first: until the viewer proved it owns the key
    // at the far end of this DTLS session, nothing else is sent or honoured.
    let viewer_key = match bind_identity(&peer, incoming, ctx).await {
        Ok(key) => key,
        Err(reason) => {
            warn!(%reason, "session channel binding failed; closing");
            send_ctrl(&peer, &SessionMessage::Disconnect { reason: reason.clone() }).await;
            return reason;
        }
    };
    info!(%viewer_key, "viewer identity bound to the DTLS session");

    let unattended = matches!(ctx.auth, AuthKind::UnattendedPassword);
    if unattended {
        let locked = ctx.throttle.lock().locked_for(&viewer_key, Instant::now());
        if let Some(wait) = locked {
            warn!(%viewer_key, ?wait, "unattended auth locked out for this caller");
            send_ctrl(&peer, &SessionMessage::Disconnect { reason: "auth locked out".into() }).await;
            return "authentication locked out".to_string();
        }
    }

    // Enumerate monitors once (throwaway capturer; dropped before the capture
    // thread starts so Desktop Duplication is never held twice).
    let monitors = cleandesk_capture::new_capturer()
        .map(|c| c.monitors())
        .unwrap_or_default();
    let monitor = monitors
        .iter()
        .find(|m| m.primary)
        .or_else(|| monitors.first())
        .cloned()
        .unwrap_or_else(default_monitor);

    // Interactive sessions are already authorized by the human who clicked
    // Accept; unattended sessions must pass the challenge/response first, and
    // until then learn nothing about this machine (not even Hello/Monitors).
    let mut authed = !unattended;
    let challenge = cleandesk_crypto::proof::Challenge::issue();
    let media = MediaControl::new(ctx.quality, monitor.clone());
    let mut media_started = false;
    let auth_deadline = Instant::now() + AUTH_TIMEOUT;

    if authed {
        media_started = start_all(&peer, &media, &monitors, ctx).await;
    } else {
        send_ctrl(&peer, &SessionMessage::AuthChallenge { challenge_b64: challenge.to_b64() }).await;
    }

    let mut injector = cleandesk_input::new_injector();
    let mut pressed = PressedState::default();
    let granted = ctx.granted;

    // Clipboard sync runs only once the viewer is authenticated *and* the
    // permission was granted; until then `clipboard` stays `None` and the
    // receiver below is never polled.
    let (clip_tx, mut clip_rx) = mpsc::unbounded_channel::<String>();
    let mut clipboard: Option<clipboard::ClipboardSync> = None;
    if authed && granted.contains(Permissions::CLIPBOARD) {
        clipboard = Some(clipboard::ClipboardSync::start(clip_tx.clone()));
    }
    let downloads = ctx.config.downloads_dir.clone().unwrap_or_else(default_downloads_dir);
    let mut files = files::FileReceiver::new(downloads, ctx.config.max_file_size);
    // Whether we currently hold the host's local input blocked; must be
    // undone on every exit path.
    let mut local_input_blocked = false;

    let reason = loop {
        let next = tokio::select! {
            biased;
            _ = tokio::time::sleep_until(auth_deadline.into()), if !authed => {
                warn!("unattended auth timed out");
                send_ctrl(&peer, &SessionMessage::Disconnect { reason: "auth timeout".into() }).await;
                break "authentication timed out".to_string();
            }
            Some(text) = clip_rx.recv(), if clipboard.is_some() => {
                send_ctrl(&peer, &SessionMessage::Clipboard(ClipboardData::Text { content: text })).await;
                continue;
            }
            next = incoming.recv() => next,
        };
        let Some((ch, bytes)) = next else { break "connection closed".to_string() };
        match ch {
            Channel::Input => {
                if !authed {
                    continue; // no input before authentication
                }
                let Ok(ev) = frame::decode_payload::<InputEvent>(&bytes) else { continue };
                if input_allowed(ev, granted) {
                    pressed.observe(ev);
                    let mon = media.monitor();
                    if let Err(e) = injector.inject(ev, &mon) {
                        debug!(error = %e, "input injection failed");
                    }
                }
            }
            Channel::Files => {
                if !authed || !granted.contains(Permissions::FILE_TRANSFER) {
                    continue;
                }
                let Ok(chunk) = frame::decode_payload::<FileChunk>(&bytes) else { continue };
                for reply in files.on_chunk(chunk).await {
                    send_ctrl(&peer, &reply).await;
                }
            }
            Channel::Control => {
                let Ok(msg) = frame::decode_payload::<SessionMessage>(&bytes) else { continue };
                match msg {
                    SessionMessage::AuthResponse { response_b64 } if !authed => {
                        let ok = verify_unattended(&response_b64, &challenge, ctx.config.unattended_key);
                        send_ctrl(&peer, &SessionMessage::AuthResult { ok }).await;
                        if ok {
                            info!("unattended authentication succeeded");
                            authed = true;
                            ctx.throttle.lock().record_success(&viewer_key);
                            if !media_started {
                                media_started = start_all(&peer, &media, &monitors, ctx).await;
                            }
                            if clipboard.is_none() && granted.contains(Permissions::CLIPBOARD) {
                                clipboard = Some(clipboard::ClipboardSync::start(clip_tx.clone()));
                            }
                        } else {
                            ctx.throttle.lock().record_failure(&viewer_key, Instant::now());
                            let _ = ctx.outcome_tx.send(SessionOutcome::AuthFailed { caller: viewer_key.clone() });
                            send_ctrl(&peer, &SessionMessage::Disconnect { reason: "auth failed".into() }).await;
                            break "authentication failed".to_string();
                        }
                    }
                    // Nothing else is honoured until the viewer is authenticated.
                    _ if !authed => {}
                    SessionMessage::SetQuality { profile } => {
                        media.set_quality(profile);
                        debug!(?profile, "quality change requested");
                    }
                    SessionMessage::SelectMonitor { index } => {
                        if let Some(m) = monitors.iter().find(|m| m.index == index) {
                            media.select_monitor(m.clone());
                        } else {
                            debug!(index, "unknown monitor requested");
                        }
                    }
                    SessionMessage::RequestKeyframe => media.request_keyframe(),
                    SessionMessage::Pong { nonce } => media.observe_pong(nonce),
                    SessionMessage::Clipboard(ClipboardData::Text { content }) => {
                        // `clipboard` only exists when CLIPBOARD was granted,
                        // so this doubles as the permission check.
                        match &clipboard {
                            Some(sync) => sync.apply_remote(content),
                            None => debug!("clipboard update ignored (not granted)"),
                        }
                    }
                    SessionMessage::PasteClipboard { content } => {
                        if granted.contains(Permissions::CLIPBOARD | Permissions::CONTROL_KEYBOARD) {
                            if let Some(sync) = &clipboard {
                                if sync.apply_remote_confirmed(content).await {
                                    let mon = media.monitor();
                                    for ev in clipboard_paste_keys(&pressed) {
                                        pressed.observe(ev);
                                        if let Err(e) = injector.inject(ev, &mon) {
                                            debug!(error = %e, "clipboard paste injection failed");
                                        }
                                    }
                                }
                            }
                        }
                    }
                    SessionMessage::Clipboard(ClipboardData::Image { .. }) => {
                        debug!("image clipboard not supported");
                    }
                    SessionMessage::File(msg) => {
                        if granted.contains(Permissions::FILE_TRANSFER) {
                            for reply in files.on_control(msg).await {
                                send_ctrl(&peer, &reply).await;
                            }
                        } else {
                            let transfer_id = file_msg_id(&msg);
                            debug!(transfer_id, "file transfer refused (not granted)");
                            send_ctrl(&peer, &SessionMessage::File(FileTransferMsg::Cancel { transfer_id })).await;
                        }
                    }
                    SessionMessage::RemoteAction { action } => {
                        if !remote_action_allowed(action, granted) {
                            warn!(?action, "remote action refused (not granted)");
                            continue;
                        }
                        info!(?action, "remote action");
                        match perform_remote_action(action) {
                            Ok(()) => {
                                if let RemoteAction::LockLocalInput { locked } = action {
                                    local_input_blocked = locked;
                                }
                            }
                            Err(e) => warn!(?action, error = %e, "remote action failed"),
                        }
                    }
                    SessionMessage::Chat { .. } => {
                        // Chat is surfaced to the GUI in a later milestone.
                        debug!("chat message not yet surfaced");
                    }
                    SessionMessage::Disconnect { reason } => {
                        info!(%reason, "viewer disconnected");
                        break format!("the viewer ended the session ({reason})");
                    }
                    SessionMessage::Heartbeat | SessionMessage::Hello { .. } => {}
                    // A second proof after binding is meaningless; never
                    // re-bind mid-session.
                    SessionMessage::IdentityProof { .. } => debug!("duplicate identity proof ignored"),
                    other => debug!(?other, "unhandled control message"),
                }
            }
            Channel::Video => {}
        }
    };

    // Whatever happened, never leave a key or button held down on the host,
    // never leave its local input blocked, and never leave half a file behind.
    for ev in pressed.release_all() {
        let _ = injector.inject(ev, &media.monitor());
    }
    if local_input_blocked {
        if let Err(e) = cleandesk_input::block_local_input(false) {
            warn!(error = %e, "could not unblock local input at session end");
        }
    }
    files.abort_all().await;
    drop(clipboard);
    reason
}

/// The transfer a file control message refers to.
fn file_msg_id(msg: &FileTransferMsg) -> u64 {
    match msg {
        FileTransferMsg::Offer { transfer_id, .. }
        | FileTransferMsg::Accept { transfer_id }
        | FileTransferMsg::Cancel { transfer_id }
        | FileTransferMsg::Progress { transfer_id, .. }
        | FileTransferMsg::Complete { transfer_id }
        | FileTransferMsg::Refused { transfer_id, .. } => *transfer_id,
    }
}

/// Mutual channel binding, host side: send our `IdentityProof` over this
/// session's DTLS fingerprints, then wait (at most [`PROOF_TIMEOUT`]) for the
/// viewer's and verify it. Returns the viewer's verified public key (base64).
///
/// Anything but an `IdentityProof` on the control channel before the proof
/// is a protocol violation and fails the binding; other channels are ignored
/// meanwhile. The error string doubles as the `Disconnect` reason.
async fn bind_identity(
    peer: &PeerConnection,
    incoming: &mut mpsc::Receiver<(Channel, Bytes)>,
    ctx: &SessionCtx,
) -> Result<String, String> {
    let (local_fp, remote_fp) = peer
        .dtls_fingerprints()
        .await
        .map_err(|e| format!("DTLS fingerprints unavailable: {e}"))?;
    let signature_b64 =
        sign_session_proof(&ctx.config.identity, &ctx.session, &local_fp, &remote_fp, SessionRole::Host);
    let proof = SessionMessage::IdentityProof { public_key_b64: ctx.config.identity.public_key_b64(), signature_b64 };
    if !send_ctrl(peer, &proof).await {
        return Err("could not send the identity proof".to_string());
    }

    let deadline = tokio::time::sleep(PROOF_TIMEOUT);
    tokio::pin!(deadline);
    loop {
        let next = tokio::select! {
            _ = &mut deadline => return Err("the viewer did not prove its identity in time".to_string()),
            next = incoming.recv() => next,
        };
        let Some((ch, bytes)) = next else {
            return Err("connection closed before the identity proof".to_string());
        };
        if ch != Channel::Control {
            continue;
        }
        let msg = frame::decode_payload::<SessionMessage>(&bytes)
            .map_err(|e| format!("undecodable control message before the identity proof: {e}"))?;
        return match msg {
            SessionMessage::IdentityProof { public_key_b64, signature_b64 } => {
                verify_viewer_proof(&public_key_b64, &signature_b64, ctx, &local_fp, &remote_fp)
            }
            other => {
                debug!(?other, "control message before identity proof");
                Err("protocol violation: control message before the identity proof".to_string())
            }
        };
    }
}

/// Check the viewer's proof against *our* view of the fingerprints (the
/// viewer signed them swapped, under the `Viewer` role) and against the
/// device that requested the session: the key must derive to `ctx.peer.id`,
/// which the rendezvous bound to the caller's key, so whoever holds the far
/// end of the DTLS session is exactly who asked to connect.
fn verify_viewer_proof(
    public_key_b64: &str,
    signature_b64: &str,
    ctx: &SessionCtx,
    local_fp: &str,
    remote_fp: &str,
) -> Result<String, String> {
    let derived = derive_id_from_public_key_b64(public_key_b64).map_err(|e| format!("bad viewer public key: {e}"))?;
    if derived != ctx.peer.id {
        return Err("the viewer's key does not belong to the device that requested the session".to_string());
    }
    verify_peer_session_proof(public_key_b64, &ctx.session, local_fp, remote_fp, SessionRole::Host, signature_b64)
        .map_err(|_| "invalid identity proof for this session".to_string())?;
    Ok(public_key_b64.to_string())
}

/// True if the granted permissions allow this remote action.
pub fn remote_action_allowed(action: RemoteAction, granted: Permissions) -> bool {
    match action {
        RemoteAction::RestartMachine => granted.contains(Permissions::RESTART_MACHINE),
        RemoteAction::LockWorkstation | RemoteAction::SecureAttention => {
            granted.contains(Permissions::CONTROL_KEYBOARD)
        }
        RemoteAction::LockLocalInput { .. } => granted.contains(Permissions::LOCK_LOCAL_INPUT),
    }
}

/// Execute an already-authorised remote action on this machine.
fn perform_remote_action(action: RemoteAction) -> Result<()> {
    match action {
        RemoteAction::RestartMachine => restart_machine(),
        RemoteAction::LockWorkstation => cleandesk_input::lock_workstation(),
        RemoteAction::LockLocalInput { locked } => cleandesk_input::block_local_input(locked),
        RemoteAction::SecureAttention => cleandesk_input::send_secure_attention(),
    }
}

/// Schedule a reboot in a few seconds so the viewer sees the session end
/// cleanly rather than the link simply dying.
#[cfg(windows)]
fn restart_machine() -> Result<()> {
    let status = std::process::Command::new("shutdown")
        .args(["/r", "/t", "5", "/c", "CleanDesk remote restart"])
        .status()
        .context("running shutdown")?;
    if status.success() {
        Ok(())
    } else {
        anyhow::bail!("shutdown exited with {status}")
    }
}

#[cfg(not(windows))]
fn restart_machine() -> Result<()> {
    warn!("remote restart is only implemented on Windows; ignoring");
    Ok(())
}

/// Introduce this host (Hello, Monitors), announce permissions, start media
/// and stats, and notify the embedder. Only ever called for an authenticated
/// viewer.
async fn start_all(
    peer: &Arc<PeerConnection>,
    media: &MediaControl,
    monitors: &[MonitorInfo],
    ctx: &SessionCtx,
) -> bool {
    send_ctrl(peer, &SessionMessage::Hello { protocol: PROTOCOL_VERSION, info: ctx.config.device.clone() }).await;
    send_ctrl(peer, &SessionMessage::Monitors { monitors: monitors.to_vec() }).await;
    send_ctrl(peer, &SessionMessage::PermissionsUpdate { granted: ctx.granted }).await;
    media::start_media(peer.clone(), media.clone());
    start_stats(peer.clone(), media.clone());
    emit(
        &ctx.config,
        HostEvent::SessionStarted { session: ctx.session, peer: ctx.peer.clone(), granted: ctx.granted },
    );
    true
}

/// Periodically push session stats to the viewer's toolbar and probe RTT.
fn start_stats(peer: Arc<PeerConnection>, media: MediaControl) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(STATS_INTERVAL);
        ticker.tick().await; // the first tick fires immediately; skip it
        loop {
            ticker.tick().await;
            let nonce = media.issue_ping();
            if !send_ctrl(&peer, &SessionMessage::Ping { nonce }).await {
                break;
            }
            let snapshot = media.take_snapshot(STATS_INTERVAL);
            let mon = media.monitor();
            let stats = SessionStats {
                rtt_ms: snapshot.rtt_ms,
                fps: snapshot.fps,
                width: mon.width,
                height: mon.height,
                bandwidth_kbps: snapshot.bandwidth_kbps,
                direct: true,
                codec: "tile-zstd".to_string(),
            };
            if !send_ctrl(&peer, &SessionMessage::Stats(stats)).await {
                break;
            }
        }
    });
}

/// True if the granted permissions allow injecting this event.
pub fn input_allowed(ev: InputEvent, granted: Permissions) -> bool {
    match ev {
        InputEvent::MouseMove { .. }
        | InputEvent::MouseButton { .. }
        | InputEvent::MouseScroll { .. } => granted.contains(Permissions::CONTROL_MOUSE),
        InputEvent::Key { .. } => granted.contains(Permissions::CONTROL_KEYBOARD),
    }
}

/// Tracks which keys and mouse buttons the viewer currently holds down, so
/// they can all be released when the session ends.
#[derive(Debug, Default)]
pub struct PressedState {
    keys: HashSet<u32>,
    buttons: HashSet<MouseButton>,
}

/// Paste with Ctrl+V and restore the modifiers previously held by the viewer.
fn clipboard_paste_keys(pressed: &PressedState) -> Vec<InputEvent> {
    let mut keys = Vec::new();
    for code in [0x10, 0x12] {
        if pressed.keys.contains(&code) {
            keys.push(InputEvent::Key { code, pressed: false });
        }
    }
    if !pressed.keys.contains(&0x11) {
        keys.push(InputEvent::Key { code: 0x11, pressed: true });
    }
    keys.push(InputEvent::Key { code: 0x56, pressed: true });
    keys.push(InputEvent::Key { code: 0x56, pressed: false });
    if !pressed.keys.contains(&0x11) {
        keys.push(InputEvent::Key { code: 0x11, pressed: false });
    }
    for code in [0x10, 0x12] {
        if pressed.keys.contains(&code) {
            keys.push(InputEvent::Key { code, pressed: true });
        }
    }
    keys
}

impl PressedState {
    /// Record a press/release the host is about to inject.
    pub fn observe(&mut self, ev: InputEvent) {
        match ev {
            InputEvent::Key { code, pressed: true } => {
                self.keys.insert(code);
            }
            InputEvent::Key { code, pressed: false } => {
                self.keys.remove(&code);
            }
            InputEvent::MouseButton { button, pressed: true } => {
                self.buttons.insert(button);
            }
            InputEvent::MouseButton { button, pressed: false } => {
                self.buttons.remove(&button);
            }
            _ => {}
        }
    }

    /// The release events needed to bring the host back to "nothing held".
    /// Clears the tracked state.
    pub fn release_all(&mut self) -> Vec<InputEvent> {
        let mut out: Vec<InputEvent> = self
            .buttons
            .drain()
            .map(|button| InputEvent::MouseButton { button, pressed: false })
            .collect();
        // Release in a stable order so tests (and logs) are deterministic.
        let mut keys: Vec<u32> = self.keys.drain().collect();
        keys.sort_unstable();
        out.extend(keys.into_iter().map(|code| InputEvent::Key { code, pressed: false }));
        out
    }

    pub fn is_empty(&self) -> bool {
        self.keys.is_empty() && self.buttons.is_empty()
    }
}

/// Verify an unattended auth response against the configured derived key.
fn verify_unattended(
    response_b64: &str,
    challenge: &cleandesk_crypto::proof::Challenge,
    key: Option<[u8; 32]>,
) -> bool {
    let Some(key) = key else { return false };
    cleandesk_crypto::proof::verify(&key, challenge, response_b64)
}

async fn send_ctrl(peer: &PeerConnection, msg: &SessionMessage) -> bool {
    match frame::encode_payload(msg) {
        Ok(bytes) => peer.send(Channel::Control, Bytes::from(bytes)).await.is_ok(),
        Err(e) => {
            warn!(error = %e, "control encode failed");
            false
        }
    }
}

fn reject(session: SessionId, reason: RejectReason) -> SignalMessage {
    SignalMessage::Reject { session, reason }
}

fn default_monitor() -> MonitorInfo {
    MonitorInfo { index: 0, width: 1920, height: 1080, primary: true, origin_x: 0, origin_y: 0 }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clipboard_paste_preserves_held_modifiers() {
        let mut state = PressedState::default();
        for code in [0x10, 0x11, 0x12] {
            state.observe(InputEvent::Key { code, pressed: true });
        }
        let initial_keys = state.keys.clone();
        let paste = clipboard_paste_keys(&state);
        assert_eq!(paste, vec![
            InputEvent::Key { code: 0x10, pressed: false },
            InputEvent::Key { code: 0x12, pressed: false },
            InputEvent::Key { code: 0x56, pressed: true },
            InputEvent::Key { code: 0x56, pressed: false },
            InputEvent::Key { code: 0x10, pressed: true },
            InputEvent::Key { code: 0x12, pressed: true },
        ]);
        for ev in paste {
            state.observe(ev);
        }
        assert_eq!(state.keys, initial_keys);
    }

    #[test]
    fn input_gating_follows_permissions() {
        let mouse = Permissions::VIEW_SCREEN | Permissions::CONTROL_MOUSE;
        assert!(input_allowed(InputEvent::MouseMove { x: 0.1, y: 0.1 }, mouse));
        assert!(input_allowed(InputEvent::MouseScroll { delta_x: 0.0, delta_y: 1.0 }, mouse));
        assert!(!input_allowed(InputEvent::Key { code: 0x41, pressed: true }, mouse));
        let kb = Permissions::VIEW_SCREEN | Permissions::CONTROL_KEYBOARD;
        assert!(input_allowed(InputEvent::Key { code: 0x41, pressed: true }, kb));
        assert!(!input_allowed(InputEvent::MouseButton { button: MouseButton::Left, pressed: true }, kb));
        assert!(!input_allowed(InputEvent::MouseMove { x: 0.0, y: 0.0 }, Permissions::VIEW_ONLY));
    }

    #[test]
    fn pressed_state_releases_everything_still_held() {
        let mut p = PressedState::default();
        p.observe(InputEvent::Key { code: 0x11, pressed: true }); // Ctrl
        p.observe(InputEvent::Key { code: 0x41, pressed: true }); // A
        p.observe(InputEvent::Key { code: 0x41, pressed: false });
        p.observe(InputEvent::MouseButton { button: MouseButton::Left, pressed: true });
        p.observe(InputEvent::MouseMove { x: 0.5, y: 0.5 });
        assert!(!p.is_empty());
        let rel = p.release_all();
        assert_eq!(rel.len(), 2);
        assert!(rel.contains(&InputEvent::MouseButton { button: MouseButton::Left, pressed: false }));
        assert!(rel.contains(&InputEvent::Key { code: 0x11, pressed: false }));
        assert!(p.is_empty());
        assert!(p.release_all().is_empty());
    }

    #[test]
    fn remote_actions_follow_permissions() {
        let none = Permissions::VIEW_ONLY;
        for a in [
            RemoteAction::RestartMachine,
            RemoteAction::LockWorkstation,
            RemoteAction::LockLocalInput { locked: true },
            RemoteAction::SecureAttention,
        ] {
            assert!(!remote_action_allowed(a, none), "{a:?} must not be allowed view-only");
            assert!(remote_action_allowed(a, Permissions::full()));
        }
        let kb = Permissions::VIEW_SCREEN | Permissions::CONTROL_KEYBOARD;
        assert!(remote_action_allowed(RemoteAction::LockWorkstation, kb));
        assert!(remote_action_allowed(RemoteAction::SecureAttention, kb));
        assert!(!remote_action_allowed(RemoteAction::RestartMachine, kb));
        assert!(!remote_action_allowed(RemoteAction::LockLocalInput { locked: false }, kb));
        let restart = Permissions::VIEW_SCREEN | Permissions::RESTART_MACHINE;
        assert!(remote_action_allowed(RemoteAction::RestartMachine, restart));
        assert!(!remote_action_allowed(RemoteAction::LockWorkstation, restart));
        let lock = Permissions::VIEW_SCREEN | Permissions::LOCK_LOCAL_INPUT;
        assert!(remote_action_allowed(RemoteAction::LockLocalInput { locked: true }, lock));
        assert!(!remote_action_allowed(RemoteAction::SecureAttention, lock));
    }

    #[test]
    fn host_never_grants_more_than_requested_and_always_view() {
        // Mirrors the clamp applied in handle_signal.
        let requested = Permissions::CONTROL_MOUSE;
        let approver_says = Permissions::full();
        let granted = (approver_says & requested) | Permissions::VIEW_SCREEN;
        assert_eq!(granted, Permissions::VIEW_SCREEN | Permissions::CONTROL_MOUSE);
    }
}
