//! CleanDesk viewer (client) role.
//!
//! A client registers with the CleanDesk Server, sends a connection request to a
//! target CleanDesk ID, and — once accepted — establishes a P2P session as the
//! WebRTC *answerer*, then:
//! * receives the video stream, reassembles and decodes it into [`DecodedImage`]s,
//! * forwards local input events to the host,
//! * surfaces control-plane events (permissions, stats, chat, disconnect) to the
//!   embedding UI, and answers the host's unattended-auth challenge if any.
//!
//! The UI drives a [`ClientSession`]: it pulls decoded frames from `frames`,
//! reads [`ClientEvent`]s from `events`, and pushes input / quality / chat back.
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
use cleandesk_codec::{DecodedImage, TileDecoder, VideoDecoder};
use cleandesk_crypto::identity::Identity;
use cleandesk_proto::{
    frame,
    id::CleanDeskId,
    media::{FrameChunk, Reassembler},
    message::{
        AuthProof, InputEvent, MonitorInfo, SessionMessage, SignalMessage, SignalPayload,
    },
    permissions::Permissions,
    quality::QualityProfile,
    session::{DeviceInfo, SessionId, SessionStats},
    PROTOCOL_VERSION,
};
use cleandesk_transport::{Channel, IceConfig, PeerConnection, SignalingClient};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

/// How long to wait for the host to Accept/Reject.
pub const ACCEPT_TIMEOUT: Duration = Duration::from_secs(45);

/// How long ICE/DTLS may take after acceptance.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

/// Minimum spacing between keyframe requests.
pub const KEYFRAME_REQUEST_INTERVAL: Duration = Duration::from_millis(500);

/// Configuration for opening a viewer session.
#[derive(Clone)]
pub struct ClientConfig {
    pub signal_url: String,
    pub device: DeviceInfo,
    /// The device identity: announced at registration and used to sign the
    /// server's challenge.
    pub identity: Identity,
    pub target: CleanDeskId,
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
}

impl ClientConfig {
    /// A config with sane defaults for everything but the required fields.
    pub fn new(signal_url: String, device: DeviceInfo, identity: Identity, target: CleanDeskId) -> Self {
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
}

/// A live viewer session. Frames and events flow *out*; input/quality/chat flow
/// *in* through the helper methods (all non-blocking, safe to call from a GUI
/// thread).
pub struct ClientSession {
    pub session: SessionId,
    pub granted: Permissions,
    /// Decoded frames to render (bounded; stale frames are dropped under load).
    pub frames: mpsc::Receiver<DecodedImage>,
    /// Control-plane events.
    pub events: mpsc::Receiver<ClientEvent>,
    input_tx: mpsc::Sender<InputEvent>,
    control_tx: mpsc::UnboundedSender<SessionMessage>,
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
}

/// Open a session to `config.target`. Returns once the P2P link is connected, or
/// an error if the request is rejected / times out / fails to connect.
pub async fn connect(config: ClientConfig) -> Result<ClientSession> {
    let mut signal = SignalingClient::connect(&config.signal_url)
        .await
        .context("connecting to CleanDesk Server")?;
    let identity = config.identity.clone();
    let signer = move |msg: &[u8]| identity.sign_b64(msg);
    let id = signal
        .register(config.device.clone(), config.identity.public_key_b64(), &signer)
        .await
        .context("registering viewer")?;
    info!(%id, target = %config.target, "viewer registered; requesting connection");

    let mut events_rx = signal.events()?;
    let signal = Arc::new(signal);

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
    let incoming = peer.incoming()?;
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

    // Wire up the session channels.
    let (frames_tx, frames_rx) = mpsc::channel::<DecodedImage>(3);
    let (cev_tx, cev_rx) = mpsc::channel::<ClientEvent>(32);
    let (input_tx, input_rx) = mpsc::channel::<InputEvent>(256);
    let (control_tx, control_rx) = mpsc::unbounded_channel::<SessionMessage>();

    let _ = cev_tx.try_send(ClientEvent::Connected);
    let _ = control_tx.send(SessionMessage::Hello { protocol: PROTOCOL_VERSION, info: config.device.clone() });

    // Inbound media + control dispatch.
    tokio::spawn(dispatch_incoming(
        peer.clone(),
        incoming,
        frames_tx,
        cev_tx,
        control_tx.clone(),
        UnattendedCredential::from_config(&config),
        config.target,
    ));

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

    Ok(ClientSession { session, granted, frames: frames_rx, events: cev_rx, input_tx, control_tx })
}

/// Background: apply offer/answer/ICE from the server to the peer.
async fn drive_signaling(
    signal: Arc<SignalingClient>,
    peer: Arc<PeerConnection>,
    session: SessionId,
    mut events_rx: mpsc::Receiver<SignalMessage>,
) {
    while let Some(msg) = events_rx.recv().await {
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
            SignalMessage::Reject { .. } => break,
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
async fn dispatch_incoming(
    peer: Arc<PeerConnection>,
    mut incoming: mpsc::Receiver<(Channel, Bytes)>,
    frames_tx: mpsc::Sender<DecodedImage>,
    cev_tx: mpsc::Sender<ClientEvent>,
    control_tx: mpsc::UnboundedSender<SessionMessage>,
    credential: Option<UnattendedCredential>,
    host_id: CleanDeskId,
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

    while let Some((ch, bytes)) = incoming.recv().await {
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
                        let _ = cev_tx.send(ClientEvent::PermissionsUpdated(granted)).await;
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
                    _ => {}
                }
            }
            _ => {}
        }
    }
    let _ = peer.close().await;
    let _ = cev_tx.send(ClientEvent::Disconnected("session ended".into())).await;
}

/// Compute and send the HMAC response to an unattended-auth challenge.
/// What the viewer holds to answer an unattended challenge.
#[derive(Clone)]
pub enum UnattendedCredential {
    Password(String),
    Key([u8; 32]),
}

impl UnattendedCredential {
    fn from_config(config: &ClientConfig) -> Option<Self> {
        if let Some(k) = config.unattended_key {
            return Some(Self::Key(k));
        }
        config.unattended_password.clone().map(Self::Password)
    }

    /// The HMAC key for `host_id`, deriving it from the password if needed.
    pub fn key_for(&self, host_id: CleanDeskId) -> Option<[u8; 32]> {
        match self {
            Self::Key(k) => Some(*k),
            Self::Password(pw) => cleandesk_crypto::password::unattended_key(pw, host_id.value()).ok(),
        }
    }
}

async fn respond_to_challenge(
    peer: &PeerConnection,
    challenge_b64: &str,
    credential: Option<&UnattendedCredential>,
    host_id: CleanDeskId,
) {
    let Some(credential) = credential else {
        warn!("host requested unattended auth but no password is configured");
        return;
    };
    let Some(challenge) = cleandesk_crypto::proof::Challenge::from_b64(challenge_b64) else {
        warn!("received malformed auth challenge");
        return;
    };
    let Some(key) = credential.key_for(host_id) else {
        return;
    };
    let response = cleandesk_crypto::proof::respond(&key, &challenge);
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
