//! All wire messages, split into three planes:
//!
//! * [`SignalMessage`] — client ↔ CleanDesk Server (WebSocket JSON). Handles
//!   registration, ID resolution, connection requests and WebRTC signaling
//!   relay (SDP + ICE).
//! * [`SessionMessage`] — peer ↔ peer on the reliable *control* data channel:
//!   permission changes, chat, clipboard, file transfer, stats, keepalive.
//! * [`InputEvent`] and [`VideoFrame`] — peer ↔ peer on the dedicated input and
//!   video data channels respectively.

use crate::{
    id::CleanDeskId,
    permissions::Permissions,
    quality::QualityProfile,
    session::{DeviceInfo, SessionId, SessionStats},
    Version,
};
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Signaling plane (client ↔ server)
// ---------------------------------------------------------------------------

/// Messages exchanged with the CleanDesk Server over the signaling WebSocket.
///
/// Serialized as JSON (human-debuggable, and the signaling volume is tiny
/// compared to media).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SignalMessage {
    /// Client → Server: register this device so it can receive connections.
    ///
    /// `device.id` must be the ID derived from `public_key` (see
    /// `cleandesk_crypto::identity`); the server refuses anything else so a
    /// client cannot claim somebody else's CleanDesk ID.
    Register {
        device: DeviceInfo,
        protocol: Version,
        /// Ed25519 public key (device identity), base64.
        public_key: String,
    },
    /// Server → Client: prove you hold the private key for `public_key` by
    /// signing [`register_proof_message`]`(nonce)` and answering with
    /// [`SignalMessage::RegisterProof`]. Without this step anyone who saw a
    /// public key could impersonate that device.
    RegisterChallenge {
        /// Random server nonce, base64.
        nonce: String,
    },
    /// Client → Server: Ed25519 signature (base64) over the challenge.
    RegisterProof { signature: String },
    /// Server → Client: registration accepted; here is your (confirmed) ID.
    Registered { id: CleanDeskId },

    /// Client → Server: I want to connect to `target`.
    ConnectRequest {
        target: CleanDeskId,
        /// Info about the *caller*, shown to the callee.
        from: DeviceInfo,
        requested: Permissions,
        quality: QualityProfile,
        /// Present when the caller authenticates via unattended password/token
        /// rather than interactive approval. Never the raw secret — a proof.
        auth_proof: Option<AuthProof>,
    },
    /// Server → callee: someone wants to connect to you.
    IncomingRequest {
        session: SessionId,
        from: DeviceInfo,
        requested: Permissions,
        quality: QualityProfile,
        auth: AuthKind,
    },

    /// Callee → Server → caller: request accepted, with the granted permissions.
    Accept {
        session: SessionId,
        granted: Permissions,
    },
    /// Callee → Server → caller: request rejected.
    Reject { session: SessionId, reason: RejectReason },

    /// Either peer → Server → other peer: opaque WebRTC signaling payload
    /// (SDP offer/answer or trickled ICE candidate). The server never inspects
    /// it — it is end-to-end between peers.
    Signal {
        session: SessionId,
        payload: SignalPayload,
    },

    /// Server → Client: an error occurred handling the previous message.
    Error { code: ErrorCode, detail: String },

    /// Bidirectional keepalive / RTT probe.
    Ping { nonce: u64 },
    Pong { nonce: u64 },
}

/// Domain-separated bytes a client signs to answer a
/// [`SignalMessage::RegisterChallenge`]: a fixed prefix plus the raw nonce
/// bytes. The prefix guarantees a registration signature can never be reused
/// as a signature over some other CleanDesk message.
pub fn register_proof_message(nonce: &[u8]) -> Vec<u8> {
    const PREFIX: &[u8] = b"cleandesk-register-v1:";
    let mut out = Vec::with_capacity(PREFIX.len() + nonce.len());
    out.extend_from_slice(PREFIX);
    out.extend_from_slice(nonce);
    out
}

/// The kind of authentication the callee will require, surfaced in the request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthKind {
    Interactive,
    UnattendedPassword,
    Trusted,
}

/// A zero-knowledge-ish proof that the caller holds the unattended secret,
/// without sending the secret itself. The concrete scheme lives in
/// `cleandesk-crypto`; this is just the transported bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthProof {
    /// Server-issued challenge this proof answers.
    pub challenge_id: String,
    /// Response bytes (e.g. HMAC / PAKE message), base64.
    pub response: String,
}

/// Opaque WebRTC signaling payload relayed verbatim between peers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SignalPayload {
    Offer { sdp: String },
    Answer { sdp: String },
    IceCandidate { candidate: String, sdp_mid: Option<String>, sdp_mline_index: Option<u16> },
}

/// Reasons a connection may be rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RejectReason {
    UserDeclined,
    Busy,
    AuthFailed,
    PermissionsDenied,
    Timeout,
    /// The host runs without a person to ask (headless service) and only
    /// takes unattended-password connections; retry with the password.
    /// Appended in protocol 2.3.
    UnattendedOnly,
}

/// Signaling error codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    UnknownId,
    TargetOffline,
    RateLimited,
    BadRequest,
    Unauthorized,
    Internal,
    VersionMismatch,
    /// The derived CleanDesk ID is already registered by a different key.
    IdConflict,
}

// ---------------------------------------------------------------------------
// Session control plane (peer ↔ peer, reliable channel)
// ---------------------------------------------------------------------------

/// Messages on the reliable control data channel between two connected peers.
///
/// Externally tagged (serde default): this rides the binary `postcard` codec,
/// which is not self-describing and therefore does not support serde's
/// internally-tagged enum representation.
///
/// **Append-only.** postcard encodes the variant *index*, so inserting a
/// variant in the middle renumbers everything after it and breaks the wire
/// format; new variants go at the end (and bump `PROTOCOL_VERSION.minor`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum SessionMessage {
    /// Handshake, first message on the control channel after DTLS is up.
    Hello { protocol: Version, info: DeviceInfo },
    /// Host → viewer: unattended-access challenge (base64). Sent only when the
    /// session used [`AuthKind::UnattendedPassword`].
    AuthChallenge { challenge_b64: String },
    /// Viewer → host: response to the challenge (base64 HMAC).
    AuthResponse { response_b64: String },
    /// Host → viewer: whether unattended authentication succeeded. On failure the
    /// host follows up with `Disconnect`.
    AuthResult { ok: bool },
    /// Host → viewer: the permissions actually in force (may change mid-session).
    PermissionsUpdate { granted: Permissions },
    /// Viewer → host: please change quality profile.
    SetQuality { profile: QualityProfile },
    /// Host → viewer: periodic session statistics for the toolbar.
    Stats(SessionStats),
    /// Bidirectional in-session chat (spec section 17).
    Chat { text: String },
    /// Clipboard synchronization (spec section 14).
    Clipboard(ClipboardData),
    /// File-transfer control messages (data rides a separate binary channel).
    File(FileTransferMsg),
    /// Viewer → host: switch the captured monitor.
    SelectMonitor { index: u16 },
    /// Host → viewer: the list of available monitors changed.
    Monitors { monitors: Vec<MonitorInfo> },
    /// Either peer: graceful teardown.
    Disconnect { reason: String },
    /// Keepalive on the control channel.
    Heartbeat,
    /// Viewer → host: the viewer lost a frame (or a delta arrived that it
    /// cannot patch onto its canvas); please send a self-contained keyframe.
    RequestKeyframe,
    /// Host → viewer: RTT probe. `nonce` is opaque to the viewer, which echoes
    /// it back unchanged in [`SessionMessage::Pong`].
    Ping { nonce: u64 },
    /// Viewer → host: echo of a [`SessionMessage::Ping`].
    Pong { nonce: u64 },
    /// Viewer → host: a one-shot privileged action (spec section 6). The host
    /// checks the matching permission before acting. Added in 2.1.
    RemoteAction { action: RemoteAction },
    /// Both directions, **the first message on the control channel** (before
    /// `Hello`): binds the peer's Ed25519 identity to this very DTLS session.
    /// `signature_b64` signs `cleandesk_crypto::session::session_proof_message`
    /// over the session id and the sender's own and remote DTLS certificate
    /// fingerprints, so a relay that terminated DTLS in the middle cannot
    /// forward it. Added in 2.2.
    IdentityProof { public_key_b64: String, signature_b64: String },
}

/// Privileged one-shot actions a viewer may request from the host.
///
/// Externally tagged (postcard). **Append-only**, like [`SessionMessage`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RemoteAction {
    /// Reboot the host machine (`Permissions::RESTART_MACHINE`).
    RestartMachine,
    /// Lock the host's interactive session, like Win+L
    /// (`Permissions::CONTROL_KEYBOARD`).
    LockWorkstation,
    /// Block or unblock the host's *local* keyboard and mouse so only the
    /// viewer drives it (`Permissions::LOCK_LOCAL_INPUT`). The host always
    /// unblocks when the session ends.
    LockLocalInput { locked: bool },
    /// Secure-attention substitute (Ctrl+Alt+Del). Without a Windows service
    /// the host can only emulate it best-effort (`Permissions::CONTROL_KEYBOARD`).
    SecureAttention,
}

/// Clipboard payload. Text/URL for the MVP; binary kinds reserved.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClipboardData {
    Text { content: String },
    /// Reserved for image sync (PNG bytes, base64) — post-MVP.
    Image { png_base64: String },
}

/// A monitor on the host (spec section 15).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MonitorInfo {
    pub index: u16,
    pub width: u32,
    pub height: u32,
    pub primary: bool,
    /// Virtual-desktop origin, for multi-monitor coordinate mapping.
    pub origin_x: i32,
    pub origin_y: i32,
}

/// File-transfer control protocol (data bytes travel on the `files` channel
/// as [`crate::files::FileChunk`]s; the state machine lives in [`crate::files`]).
///
/// Roles: the *sender* offers, streams chunks once accepted, reports
/// `Progress` and finishes with `Complete`. The *receiver* accepts, acks
/// progress with `Progress` (which doubles as flow control: the sender keeps
/// at most a window of bytes beyond the last ack in flight) and, after
/// verifying the size, answers `Complete` back. Either side may `Cancel`.
///
/// Externally tagged (postcard). **Append-only**, like [`SessionMessage`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FileTransferMsg {
    /// Announce an outgoing file/folder tree.
    Offer { transfer_id: u64, name: String, size: u64, is_dir: bool },
    /// Accept a previously offered transfer.
    Accept { transfer_id: u64 },
    /// Reject / cancel a transfer.
    Cancel { transfer_id: u64 },
    /// Progress report (bytes transferred), sent by both sides.
    Progress { transfer_id: u64, transferred: u64 },
    /// Sender: all bytes sent. Receiver: all bytes verified and stored.
    Complete { transfer_id: u64 },
    /// Receiver: like `Cancel`, with a human-readable reason (too large, no
    /// disk space, too many transfers in flight...). Added in 2.2.
    Refused { transfer_id: u64, reason: String },
}

// ---------------------------------------------------------------------------
// Media plane (peer ↔ peer)
// ---------------------------------------------------------------------------

/// A single video frame envelope sent on the video data channel.
///
/// The `data` field is the codec-specific payload produced by `cleandesk-codec`.
/// A keyframe is self-contained; a delta references the previous frame.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VideoFrame {
    pub sequence: u64,
    pub width: u32,
    pub height: u32,
    pub keyframe: bool,
    /// Monotonic capture timestamp in microseconds.
    pub timestamp_us: u64,
    /// Codec-specific encoded bytes.
    pub data: Vec<u8>,
}

/// Input events forwarded viewer → host on the input data channel.
///
/// Externally tagged (serde default) so it can ride the binary `postcard` codec.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum InputEvent {
    /// Absolute mouse move, normalized 0.0..=1.0 over the current monitor.
    MouseMove { x: f32, y: f32 },
    MouseButton { button: MouseButton, pressed: bool },
    MouseScroll { delta_x: f32, delta_y: f32 },
    /// Key event by OS-independent virtual key code.
    Key { code: u32, pressed: bool },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MouseButton {
    Left,
    Right,
    Middle,
    Back,
    Forward,
}
