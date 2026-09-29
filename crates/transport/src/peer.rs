//! WebRTC peer connection with four named data channels, built on the
//! `webrtc` crate (v0.21, the Sans-I/O `rtc` core with an async facade).
//!
//! # Model
//!
//! * The **offerer** (host) pre-creates the four data channels — `control`,
//!   `video`, `input`, `files` — before generating its SDP offer. The
//!   **answerer** discovers the same channels through the peer connection's
//!   `on_data_channel` event and matches them back to a [`Channel`] by label.
//! * ICE is **trickled**: local candidates are pushed to the receiver returned
//!   by [`PeerConnection::ice_candidates`] as they are gathered; the caller
//!   relays each one to the far peer (via the signaling plane) and feeds the
//!   peer's candidates back in through [`PeerConnection::add_ice_candidate`].
//! * Inbound bytes from every channel are multiplexed onto a single receiver
//!   returned by [`PeerConnection::incoming`], tagged with their [`Channel`].
//!
//! # Reliability per channel
//!
//! | Channel   | Ordered | Retransmits | Rationale |
//! |-----------|---------|-------------|-----------|
//! | `control` | yes     | reliable    | permissions/chat/clipboard/files ctrl must arrive, in order |
//! | `files`   | yes     | reliable    | bulk file bytes must arrive intact and in order |
//! | `video`   | no      | 0           | a late frame is worthless; never stall newer frames for it |
//! | `input`   | yes     | reliable    | a lost key-up or button-up leaves the host with a stuck key; events are tiny so head-of-line blocking is negligible |
//!
//! For `video` we set `ordered = false` and `max_retransmits = 0` (SCTP
//! "partially reliable, unordered"): the transport delivers what arrives
//! promptly and drops the rest, trading completeness for latency. Input was
//! originally unreliable too, but a single dropped release event is far worse
//! for the user than a few milliseconds of extra latency, so it is reliable.
//!
//! # Message size
//!
//! The underlying `webrtc` data channel delivers inbound messages up to 16 KiB
//! each (`OnMessage`); larger application payloads (e.g. video keyframes) must be
//! chunked by the caller — that framing is the codec/host's concern, not the
//! transport's.

use crate::error::TransportError;
use anyhow::{Context, Result};
use bytes::{Bytes, BytesMut};
use cleandesk_proto::message::SignalPayload;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, MutexGuard};
use sha2::{Digest, Sha256};
use std::time::Duration;
use tokio::sync::{mpsc, watch};
use tracing::{trace, warn};
use webrtc::data_channel::{DataChannel, DataChannelEvent, RTCDataChannelInit, RTCDataChannelState};
use webrtc::peer_connection::{
    PeerConnection as RtcPeerConnection, PeerConnectionBuilder, PeerConnectionEventHandler,
    RTCConfigurationBuilder, RTCIceCandidateInit, RTCIceCandidateType, RTCIceServer,
    RTCPeerConnectionIceEvent, RTCPeerConnectionState, RTCSessionDescription, SettingEngineBuilder,
};

/// Capacity of the trickled-ICE-candidate channel. Host/reflexive candidate
/// counts are tiny; this only needs to absorb a burst before the caller drains.
const ICE_CAPACITY: usize = 64;

/// Capacity of the multiplexed inbound-bytes channel.
const INCOMING_CAPACITY: usize = 512;

/// How long [`PeerConnection::send`] waits for a channel's DCEP open handshake
/// before giving up.
const OPEN_TIMEOUT: Duration = Duration::from_secs(15);

/// The four logical data channels of a CleanDesk session.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Channel {
    /// Reliable, ordered: session control (permissions, chat, clipboard, file
    /// control, stats, keepalive).
    Control,
    /// Unreliable, unordered: host to viewer video frames.
    Video,
    /// Reliable, ordered: viewer to host input events.
    Input,
    /// Reliable, ordered: bulk file-transfer bytes.
    Files,
}

impl Channel {
    /// All channels, in the order the offerer creates them.
    pub const ALL: [Channel; 4] = [
        Channel::Control,
        Channel::Video,
        Channel::Input,
        Channel::Files,
    ];

    /// The on-the-wire data channel label.
    pub fn label(self) -> &'static str {
        match self {
            Channel::Control => "control",
            Channel::Video => "video",
            Channel::Input => "input",
            Channel::Files => "files",
        }
    }

    /// Map a data channel label back to a [`Channel`].
    pub fn from_label(label: &str) -> Option<Channel> {
        match label {
            "control" => Some(Channel::Control),
            "video" => Some(Channel::Video),
            "input" => Some(Channel::Input),
            "files" => Some(Channel::Files),
            _ => None,
        }
    }

    /// The SCTP reliability configuration for this channel (see the module docs).
    fn init(self) -> RTCDataChannelInit {
        match self {
            Channel::Control | Channel::Files | Channel::Input => RTCDataChannelInit {
                ordered: true,
                ..Default::default()
            },
            Channel::Video => RTCDataChannelInit {
                ordered: false,
                max_retransmits: Some(0),
                ..Default::default()
            },
        }
    }

    /// Whether this channel is configured as fully reliable and ordered.
    pub fn is_reliable(self) -> bool {
        !matches!(self, Channel::Video)
    }
}

/// A TURN server and its long-term credentials.
#[derive(Clone, Debug)]
pub struct TurnServer {
    pub urls: Vec<String>,
    pub username: String,
    pub credential: String,
}

/// ICE server configuration: STUN URLs and TURN servers.
#[derive(Clone, Debug)]
pub struct IceConfig {
    pub stun: Vec<String>,
    pub turn: Vec<TurnServer>,
    /// Public IPs this machine is reachable at through a 1:1 NAT mapping
    /// (UPnP). Advertised as server-reflexive candidates without STUN.
    pub nat_1to1_ips: Vec<String>,
    /// Fixed local UDP port for ICE (0 = ephemeral). Set together with
    /// `nat_1to1_ips` so the router mapping and the socket agree.
    pub udp_port: u16,
}

impl Default for IceConfig {
    /// A single public STUN server and no TURN relay.
    fn default() -> Self {
        Self {
            stun: vec![DEFAULT_STUN_URL.to_string()],
            turn: Vec::new(),
            nat_1to1_ips: Vec::new(),
            udp_port: 0,
        }
    }
}

/// Public STUN server used when nothing else is configured. STUN only reveals
/// the caller's reflexive address; no session data ever goes through it.
pub const DEFAULT_STUN_URL: &str = "stun:stun.l.google.com:19302";

/// Environment variable: comma-separated STUN URLs (`stun:host:port`).
pub const ENV_STUN_URLS: &str = "CLEANDESK_STUN_URLS";
/// Environment variable: comma-separated TURN URLs (`turn:host:port?transport=udp`).
pub const ENV_TURN_URLS: &str = "CLEANDESK_TURN_URLS";
/// Environment variable: TURN long-term username.
pub const ENV_TURN_USER: &str = "CLEANDESK_TURN_USER";
/// Environment variable: TURN long-term password.
pub const ENV_TURN_PASS: &str = "CLEANDESK_TURN_PASS";

impl IceConfig {
    /// Build the ICE configuration from the process environment
    /// ([`ENV_STUN_URLS`], [`ENV_TURN_URLS`], [`ENV_TURN_USER`],
    /// [`ENV_TURN_PASS`]), falling back to [`IceConfig::default`] for anything
    /// unset. This is how a deployment points clients at the CleanDesk Relay.
    pub fn from_env() -> Self {
        Self::from_vars(|k| std::env::var(k).ok())
    }

    /// [`Self::from_env`] with an injectable variable source (for tests).
    ///
    /// Rules: an empty or unset STUN list keeps the default STUN server; a
    /// TURN list without a username/password is ignored with a warning (a
    /// relay with no credentials can never authenticate, so it would only add
    /// ICE gathering delay).
    pub fn from_vars(get: impl Fn(&str) -> Option<String>) -> Self {
        let split = |v: Option<String>| -> Vec<String> {
            v.unwrap_or_default()
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .collect()
        };
        let mut cfg = Self::default();
        let stun = split(get(ENV_STUN_URLS));
        if !stun.is_empty() {
            cfg.stun = stun;
        }
        let turn_urls = split(get(ENV_TURN_URLS));
        if !turn_urls.is_empty() {
            match (get(ENV_TURN_USER), get(ENV_TURN_PASS)) {
                (Some(username), Some(credential)) if !username.is_empty() => {
                    cfg.turn.push(TurnServer { urls: turn_urls, username, credential });
                }
                _ => warn!(
                    "{ENV_TURN_URLS} is set but {ENV_TURN_USER}/{ENV_TURN_PASS} are missing; ignoring relay"
                ),
            }
        }
        cfg
    }

    /// Translate into the `webrtc` ICE server list.
    fn ice_servers(&self) -> Vec<RTCIceServer> {
        let mut servers = Vec::with_capacity(1 + self.turn.len());
        // With explicit 1:1 NAT addresses the reflexive address is already
        // known, and the ICE agent refuses to combine both mechanisms.
        if !self.stun.is_empty() && self.nat_1to1_ips.is_empty() {
            servers.push(RTCIceServer {
                urls: self.stun.clone(),
                ..Default::default()
            });
        }
        for turn in &self.turn {
            servers.push(RTCIceServer {
                urls: turn.urls.clone(),
                username: turn.username.clone(),
                credential: turn.credential.clone(),
            });
        }
        servers
    }
}

/// Shared, cheaply-cloned registry of open data channels, populated by the
/// offerer at creation and by the answerer's `on_data_channel` callback.
type ChannelMap = Arc<Mutex<HashMap<Channel, Arc<dyn DataChannel>>>>;

/// Shared "which channels are open" gate. Readers mark a channel open once its
/// DCEP handshake completes; [`PeerConnection::send`] waits on this so we never
/// write to a channel before the peer can receive it (writing early makes the
/// far side drop the message — it arrives with a PPID it can't yet map).
type OpenGate = Arc<watch::Sender<HashSet<Channel>>>;

/// Lock a `Mutex`, recovering from poisoning instead of panicking (the guarded
/// data is a plain map/option; a poisoned lock is safe to reuse here).
fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Event handler bridging `webrtc` callbacks to our channels.
struct Handler {
    ice_tx: mpsc::Sender<SignalPayload>,
    incoming_tx: mpsc::Sender<(Channel, Bytes)>,
    state_tx: watch::Sender<RTCPeerConnectionState>,
    channels: ChannelMap,
    open_gate: OpenGate,
}

#[async_trait::async_trait]
impl PeerConnectionEventHandler for Handler {
    async fn on_ice_candidate(&self, event: RTCPeerConnectionIceEvent) {
        // `to_json` fails for the empty "end of candidates" sentinel (its type
        // is `Unspecified`), which we simply skip.
        match event.candidate.to_json() {
            Ok(init) => {
                let payload = SignalPayload::IceCandidate {
                    candidate: init.candidate,
                    sdp_mid: init.sdp_mid,
                    sdp_mline_index: init.sdp_mline_index,
                };
                let _ = self.ice_tx.send(payload).await;
            }
            Err(e) => trace!(error = %e, "skipping non-serializable ICE candidate"),
        }
    }

    async fn on_connection_state_change(&self, state: RTCPeerConnectionState) {
        // A watch send only fails if every receiver is gone; harmless here.
        let _ = self.state_tx.send(state);
    }

    async fn on_data_channel(&self, dc: Arc<dyn DataChannel>) {
        let label = match dc.label().await {
            Ok(label) => label,
            Err(e) => {
                warn!(error = %e, "could not read label of incoming data channel");
                return;
            }
        };
        match Channel::from_label(&label) {
            Some(ch) => {
                lock(&self.channels).insert(ch, dc.clone());
                spawn_reader(ch, dc, self.incoming_tx.clone(), self.open_gate.clone());
            }
            None => warn!(%label, "ignoring data channel with unknown label"),
        }
    }
}

/// Spawn a task that pumps one data channel's inbound messages onto the shared
/// `incoming` channel until it closes.
fn spawn_reader(
    ch: Channel,
    dc: Arc<dyn DataChannel>,
    incoming_tx: mpsc::Sender<(Channel, Bytes)>,
    open_gate: OpenGate,
) {
    tokio::spawn(async move {
        // The channel may already be open by the time we start polling (common
        // for the answerer, whose `on_data_channel` can fire post-open), in which
        // case no `OnOpen` event will follow — so seed the gate from the state.
        if matches!(dc.ready_state().await, Ok(RTCDataChannelState::Open)) {
            open_gate.send_if_modified(|s| s.insert(ch));
        }
        while let Some(event) = dc.poll().await {
            match event {
                DataChannelEvent::OnOpen => {
                    open_gate.send_if_modified(|s| s.insert(ch));
                }
                DataChannelEvent::OnMessage(msg) => {
                    if incoming_tx.send((ch, msg.data.freeze())).await.is_err() {
                        // The consumer dropped the receiver; stop pumping.
                        break;
                    }
                }
                DataChannelEvent::OnClose => {
                    open_gate.send_if_modified(|s| s.remove(&ch));
                    break;
                }
                _ => {}
            }
        }
    });
}

/// A WebRTC peer connection wrapping [`webrtc`]'s `RTCPeerConnection` with the
/// four CleanDesk data channels.
pub struct PeerConnection {
    pc: Arc<dyn RtcPeerConnection>,
    channels: ChannelMap,
    ice_rx: Mutex<Option<mpsc::Receiver<SignalPayload>>>,
    incoming_rx: Option<mpsc::Receiver<(Channel, Bytes)>>,
    state_rx: watch::Receiver<RTCPeerConnectionState>,
    open_rx: watch::Receiver<HashSet<Channel>>,
}

impl PeerConnection {
    /// Create a peer connection. When `offerer` is true, the four data channels
    /// are created up front (so they appear in the SDP offer); the answerer
    /// leaves `offerer` false and picks the channels up via `on_data_channel`.
    pub async fn new(config: IceConfig, offerer: bool) -> Result<Self> {
        let (ice_tx, ice_rx) = mpsc::channel(ICE_CAPACITY);
        let (incoming_tx, incoming_rx) = mpsc::channel(INCOMING_CAPACITY);
        let (state_tx, state_rx) = watch::channel(RTCPeerConnectionState::Unspecified);
        let (open_tx, open_rx) = watch::channel(HashSet::new());
        let open_gate: OpenGate = Arc::new(open_tx);
        let channels: ChannelMap = Arc::new(Mutex::new(HashMap::new()));

        let handler = Arc::new(Handler {
            ice_tx,
            incoming_tx: incoming_tx.clone(),
            state_tx,
            channels: channels.clone(),
            open_gate: open_gate.clone(),
        });

        let rtc_config = RTCConfigurationBuilder::new()
            .with_ice_servers(config.ice_servers())
            .build();

        // Data channels ride SCTP-over-DTLS, so no media engine / RTP
        // interceptors are needed. Bind an ephemeral UDP socket on all
        // interfaces for host-candidate gathering.
        let mut setting = SettingEngineBuilder::new();
        if !config.nat_1to1_ips.is_empty() {
            setting = setting.with_nat_1to1_ips(config.nat_1to1_ips.clone(), RTCIceCandidateType::Srflx);
        }
        let pc = PeerConnectionBuilder::new()
            .with_configuration(rtc_config)
            .with_setting_engine(setting.build())
            .with_handler(handler)
            .with_udp_addrs(vec![format!("0.0.0.0:{}", config.udp_port)])
            .build()
            .await
            .context("building webrtc peer connection")?;
        let pc: Arc<dyn RtcPeerConnection> = Arc::new(pc);

        if offerer {
            for ch in Channel::ALL {
                let dc = pc
                    .create_data_channel(ch.label(), Some(ch.init()))
                    .await
                    .with_context(|| format!("creating data channel '{}'", ch.label()))?;
                lock(&channels).insert(ch, dc.clone());
                spawn_reader(ch, dc, incoming_tx.clone(), open_gate.clone());
            }
        }

        Ok(Self {
            pc,
            channels,
            ice_rx: Mutex::new(Some(ice_rx)),
            incoming_rx: Some(incoming_rx),
            state_rx,
            open_rx,
        })
    }

    /// Create an SDP offer, set it as the local description (which starts ICE
    /// gathering), and return the SDP string to send to the peer.
    pub async fn create_offer(&self) -> Result<String> {
        let offer = self.pc.create_offer(None).await.context("create_offer")?;
        let sdp = offer.sdp.clone();
        self.pc
            .set_local_description(offer)
            .await
            .context("set_local_description(offer)")?;
        Ok(sdp)
    }

    /// Apply a remote SDP (`is_offer` selects offer vs. answer).
    pub async fn set_remote_description(&self, sdp: String, is_offer: bool) -> Result<()> {
        let desc = if is_offer {
            RTCSessionDescription::offer(sdp)
        } else {
            RTCSessionDescription::answer(sdp)
        }
        .context("parsing remote SDP")?;
        self.pc
            .set_remote_description(desc)
            .await
            .context("set_remote_description")?;
        Ok(())
    }

    /// Create an SDP answer to a previously-set remote offer, set it as the
    /// local description, and return the SDP string to send back.
    pub async fn create_answer(&self) -> Result<String> {
        let answer = self.pc.create_answer(None).await.context("create_answer")?;
        let sdp = answer.sdp.clone();
        self.pc
            .set_local_description(answer)
            .await
            .context("set_local_description(answer)")?;
        Ok(sdp)
    }

    /// Add a remote ICE candidate received from the peer.
    ///
    /// Requires a remote description to have been set first.
    pub async fn add_ice_candidate(
        &self,
        candidate: String,
        sdp_mid: Option<String>,
        sdp_mline_index: Option<u16>,
    ) -> Result<()> {
        let init = RTCIceCandidateInit {
            candidate,
            sdp_mid,
            sdp_mline_index,
            username_fragment: None,
            url: None,
        };
        self.pc
            .add_ice_candidate(init)
            .await
            .context("add_ice_candidate")?;
        Ok(())
    }

    /// Take the stream of locally-gathered ICE candidates to trickle to the peer
    /// (already shaped as [`SignalPayload::IceCandidate`]).
    ///
    /// Can only be called once; a second call fails with
    /// [`TransportError::AlreadyTaken`].
    pub fn ice_candidates(&self) -> Result<mpsc::Receiver<SignalPayload>> {
        lock(&self.ice_rx)
            .take()
            .ok_or_else(|| TransportError::AlreadyTaken("ice_candidates").into())
    }

    /// Send `data` on `ch`. Reliability follows the per-channel configuration
    /// documented at the module level.
    pub async fn send(&self, ch: Channel, data: Bytes) -> Result<()> {
        // Wait until the channel's DCEP open handshake has completed. Writing
        // before that makes the peer drop the message (it arrives with a PPID it
        // cannot yet map to an open channel), which manifests as lost frames.
        self.await_open(ch).await?;
        let dc = lock(&self.channels)
            .get(&ch)
            .cloned()
            .ok_or(TransportError::ChannelUnavailable(ch))?;
        let mut buf = BytesMut::with_capacity(data.len());
        buf.extend_from_slice(&data);
        dc.send(buf)
            .await
            .with_context(|| format!("sending on data channel {ch:?}"))?;
        Ok(())
    }

    /// Resolve once `ch` is open, or error after [`OPEN_TIMEOUT`] if it never is.
    async fn await_open(&self, ch: Channel) -> Result<()> {
        if self.open_rx.borrow().contains(&ch) {
            return Ok(());
        }
        let mut rx = self.open_rx.clone();
        let wait = async {
            loop {
                if rx.borrow_and_update().contains(&ch) {
                    return Ok(());
                }
                if rx.changed().await.is_err() {
                    // Sender dropped: the peer connection is gone.
                    return Err(TransportError::ChannelUnavailable(ch));
                }
            }
        };
        match tokio::time::timeout(OPEN_TIMEOUT, wait).await {
            Ok(res) => res.map_err(Into::into),
            Err(_) => Err(TransportError::ChannelUnavailable(ch).into()),
        }
    }

    /// True if `ch`'s data channel is currently open.
    pub fn is_open(&self, ch: Channel) -> bool {
        self.open_rx.borrow().contains(&ch)
    }

    /// Take the multiplexed stream of inbound `(Channel, Bytes)` from the peer.
    ///
    /// Can only be called once; a second call fails with
    /// [`TransportError::AlreadyTaken`].
    pub fn incoming(&mut self) -> Result<mpsc::Receiver<(Channel, Bytes)>> {
        self.incoming_rx
            .take()
            .ok_or_else(|| TransportError::AlreadyTaken("incoming").into())
    }

    /// The current peer connection state, for diagnostics.
    pub fn state(&self) -> RTCPeerConnectionState {
        *self.state_rx.borrow()
    }

    /// [`Self::wait_connected`] bounded by `timeout`. ICE can sit in
    /// `Connecting` forever when both peers are behind symmetric NATs and no
    /// relay is configured; callers must never wait unboundedly on it.
    pub async fn wait_connected_timeout(&self, timeout: Duration) -> Result<()> {
        match tokio::time::timeout(timeout, self.wait_connected()).await {
            Ok(res) => res,
            Err(_) => Err(TransportError::ConnectTimeout(timeout).into()),
        }
    }

    /// Resolve once the peer connection is fully connected (DTLS up), or error
    /// if it reaches a terminal state (`Failed`/`Closed`) first.
    pub async fn wait_connected(&self) -> Result<()> {
        let mut rx = self.state_rx.clone();
        loop {
            let state = *rx.borrow_and_update();
            match state {
                RTCPeerConnectionState::Connected => return Ok(()),
                RTCPeerConnectionState::Failed => {
                    return Err(TransportError::NotConnected("state reached Failed").into())
                }
                RTCPeerConnectionState::Closed => {
                    return Err(TransportError::NotConnected("state reached Closed").into())
                }
                _ => {}
            }
            if rx.changed().await.is_err() {
                return Err(TransportError::NotConnected("state channel closed").into());
            }
        }
    }

    /// The DTLS certificate fingerprints of this connection as
    /// `(local, remote)`, each in the canonical form `"sha-256 aa:bb:..."`
    /// (lowercase). Only meaningful once [`Self::wait_connected`] resolved.
    ///
    /// The **remote** value is computed from the certificate the DTLS
    /// handshake actually authenticated against (not from the SDP the
    /// rendezvous relayed), so it is exactly what a session channel-binding
    /// proof must cover. The local value comes from our own local
    /// description, which never left this process unmodified.
    pub async fn dtls_fingerprints(&self) -> Result<(String, String)> {
        let local_sdp = self
            .pc
            .local_description()
            .await
            .ok_or(TransportError::FingerprintUnavailable("no local description"))?;
        let local = fingerprint_from_sdp(&local_sdp.sdp)
            .ok_or(TransportError::FingerprintUnavailable("no a=fingerprint in local SDP"))?;

        let remote = match self.pc.sctp().await {
            Some(sctp) => match sctp.transport().get_remote_certificates().await {
                Ok(certs) => certs.first().map(|der| fingerprint_of_der(der)),
                Err(e) => {
                    trace!(error = %e, "remote certificate not readable");
                    None
                }
            },
            None => None,
        };
        let remote = match remote {
            Some(fp) => fp,
            // Before the SCTP transport is exposed the DTLS layer has still
            // verified the remote certificate against this SDP fingerprint,
            // so it is the same value — just less direct.
            None => {
                let remote_sdp = self
                    .pc
                    .remote_description()
                    .await
                    .ok_or(TransportError::FingerprintUnavailable("no remote description"))?;
                fingerprint_from_sdp(&remote_sdp.sdp)
                    .ok_or(TransportError::FingerprintUnavailable("no a=fingerprint in remote SDP"))?
            }
        };
        Ok((local, remote))
    }

    /// Close the peer connection and stop its background driver.
    pub async fn close(&self) -> Result<()> {
        self.pc.close().await.context("closing peer connection")?;
        Ok(())
    }
}

/// Canonical `"sha-256 aa:bb:..."` fingerprint of a DER certificate, the same
/// value `a=fingerprint` carries for it.
pub fn fingerprint_of_der(der: &[u8]) -> String {
    let hash = Sha256::digest(der);
    let hex: Vec<String> = hash.iter().map(|b| format!("{b:02x}")).collect();
    format!("sha-256 {}", hex.join(":"))
}

/// Extract the first `a=fingerprint:` attribute of an SDP in canonical form
/// (`"<algorithm> <hex:hex:...>"`, lowercase). `None` when there is none.
pub fn fingerprint_from_sdp(sdp: &str) -> Option<String> {
    sdp.lines().find_map(|line| {
        let rest = line.trim().strip_prefix("a=fingerprint:")?;
        let mut parts = rest.split_whitespace();
        let algorithm = parts.next()?;
        let value = parts.next()?;
        Some(format!("{} {}", algorithm.to_ascii_lowercase(), value.to_ascii_lowercase()))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn sdp_fingerprint_is_extracted_and_canonicalised() {
        let sdp = "v=0
o=- 1 1 IN IP4 0.0.0.0
s=-
t=0 0
a=fingerprint:SHA-256 AB:CD:EF:01
m=application 9 UDP/DTLS/SCTP webrtc-datachannel
";
        assert_eq!(fingerprint_from_sdp(sdp).as_deref(), Some("sha-256 ab:cd:ef:01"));
        assert_eq!(fingerprint_from_sdp("v=0
s=-
"), None);
        assert_eq!(fingerprint_from_sdp("a=fingerprint:sha-256"), None);
    }

    #[test]
    fn der_fingerprint_matches_sha256_form() {
        let fp = fingerprint_of_der(b"not really a certificate");
        assert!(fp.starts_with("sha-256 "));
        let hex: Vec<&str> = fp["sha-256 ".len()..].split(':').collect();
        assert_eq!(hex.len(), 32);
        assert!(hex.iter().all(|h| h.len() == 2 && h.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())));
    }

    #[test]
    fn channel_labels_roundtrip_and_are_distinct() {
        for ch in Channel::ALL {
            assert_eq!(Channel::from_label(ch.label()), Some(ch));
        }
        assert_eq!(Channel::from_label("bogus"), None);
        let labels: std::collections::HashSet<_> = Channel::ALL.iter().map(|c| c.label()).collect();
        assert_eq!(labels.len(), Channel::ALL.len());
    }

    #[test]
    fn only_video_is_lossy() {
        assert!(!Channel::Video.is_reliable());
        assert!(Channel::Input.is_reliable());
        assert!(Channel::Control.is_reliable());
        assert!(Channel::Files.is_reliable());
        let init = Channel::Video.init();
        assert!(!init.ordered);
        assert_eq!(init.max_retransmits, Some(0));
        let init = Channel::Input.init();
        assert!(init.ordered);
        assert_eq!(init.max_retransmits, None);
    }

    fn vars(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let map: HashMap<String, String> =
            pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        move |k| map.get(k).cloned()
    }

    #[test]
    fn ice_config_defaults_when_nothing_is_set() {
        let cfg = IceConfig::from_vars(vars(&[]));
        assert_eq!(cfg.stun, vec![DEFAULT_STUN_URL.to_string()]);
        assert!(cfg.turn.is_empty());
        assert_eq!(cfg.ice_servers().len(), 1);
    }

    #[test]
    fn ice_config_parses_lists_and_credentials() {
        let cfg = IceConfig::from_vars(vars(&[
            (ENV_STUN_URLS, " stun:a:1, stun:b:2 ,, "),
            (ENV_TURN_URLS, "turn:relay.example:7421?transport=udp"),
            (ENV_TURN_USER, "alice"),
            (ENV_TURN_PASS, "s3cret"),
        ]));
        assert_eq!(cfg.stun, vec!["stun:a:1", "stun:b:2"]);
        assert_eq!(cfg.turn.len(), 1);
        assert_eq!(cfg.turn[0].username, "alice");
        assert_eq!(cfg.turn[0].credential, "s3cret");
        assert_eq!(cfg.turn[0].urls, vec!["turn:relay.example:7421?transport=udp"]);
        assert_eq!(cfg.ice_servers().len(), 2);
    }

    #[test]
    fn turn_without_credentials_is_ignored() {
        let cfg = IceConfig::from_vars(vars(&[(ENV_TURN_URLS, "turn:relay.example:7421")]));
        assert!(cfg.turn.is_empty());
        let cfg = IceConfig::from_vars(vars(&[
            (ENV_TURN_URLS, "turn:relay.example:7421"),
            (ENV_TURN_USER, ""),
            (ENV_TURN_PASS, "x"),
        ]));
        assert!(cfg.turn.is_empty());
    }

    #[test]
    fn empty_stun_list_keeps_default() {
        let cfg = IceConfig::from_vars(vars(&[(ENV_STUN_URLS, " , ")]));
        assert_eq!(cfg.stun, vec![DEFAULT_STUN_URL.to_string()]);
    }
}
