//! RotoDesk Server — signaling / rendezvous backend (library).
//!
//! Responsibilities (spec §19):
//! * Accept WebSocket connections from clients.
//! * Register devices and resolve RotoDesk IDs.
//! * Route connection requests (Accept/Reject) between caller and callee.
//! * Relay opaque WebRTC signaling (SDP + ICE) end-to-end between peers.
//!
//! The server never sees media, input or the DTLS keys — those are established
//! peer-to-peer. It only brokers the initial handshake. The binary in `main.rs`
//! is a thin wrapper around [`run`].
//!
//! # Registration
//!
//! ```text
//! client                                   server
//!   | Register{device, protocol, public_key}  |
//!   |---------------------------------------->|  derive_id(public_key) == device.id ?
//!   |            RegisterChallenge{nonce}     |
//!   |<----------------------------------------|
//!   | RegisterProof{signature}                |
//!   |---------------------------------------->|  Ed25519 verify(public_key, prefix||nonce)
//!   |            Registered{id}               |
//!   |<----------------------------------------|
//! ```
//!
//! Without the signed challenge, anyone who had seen a device's public key
//! could register under its ID and receive connection requests meant for it.
//!
//! # Abuse limits
//!
//! Each connection gets a token bucket for `ConnectRequest` (they cost the
//! callee a dialog / an auth attempt) and a budget of malformed messages
//! before the socket is closed. WebSocket messages are capped at
//! [`MAX_WS_MESSAGE_BYTES`], the TLS/WS handshake and registration have
//! deadlines, and a connection that never registers is dropped. Per source
//! IP, [`state::IpLimits`] caps concurrent sockets (refused before the
//! WebSocket upgrade, so they cost nothing) and registration attempts.

pub mod state;

use anyhow::Result;
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use rotodesk_proto::{
    id::RotoDeskId,
    message::{register_proof_message, AuthKind, ErrorCode, SignalMessage},
    session::DeviceInfo,
    Version, PROTOCOL_VERSION,
};
use futures_util::{SinkExt, StreamExt};
use state::{ConnId, RateLimiter, RegisterError, Role, ServerState, OUTBOUND_QUEUE};
use std::{
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::{protocol::WebSocketConfig, Message};
use tracing::{debug, error, info, warn};
use uuid::Uuid;

/// Largest WebSocket message accepted. An SDP with many candidates is a few
/// KiB; anything near this is not signaling.
pub const MAX_WS_MESSAGE_BYTES: usize = 64 * 1024;

/// Time allowed for the WebSocket upgrade handshake.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Time a fresh connection has to complete registration before it is dropped.
const REGISTER_DEADLINE: Duration = Duration::from_secs(20);

/// Idle limit: a registered client that sends nothing at all (not even the
/// transport's keepalive `Ping`) for this long is considered gone.
const IDLE_TIMEOUT: Duration = Duration::from_secs(120);

/// `ConnectRequest` budget per connection: burst of 5, refilling over 30 s.
const CONNECT_BURST: u32 = 5;
const CONNECT_WINDOW: Duration = Duration::from_secs(30);

/// `Signal` budget per connection: an SDP exchange plus ICE trickle is a
/// few dozen messages; refilling over 10 s keeps retries possible while a
/// flood aimed at the peer's queue is cut off.
const SIGNAL_BURST: u32 = 64;
const SIGNAL_WINDOW: Duration = Duration::from_secs(10);

/// Malformed / out-of-protocol messages tolerated per connection before the
/// socket is closed.
const BAD_MESSAGE_BUDGET: u32 = 10;

/// Serve signaling on an already-bound listener until an accept error occurs.
pub async fn run(listener: TcpListener) -> Result<()> {
    run_with_state(listener, Arc::new(ServerState::new())).await
}

/// [`run`] with an externally owned [`ServerState`] (tests inspect it).
pub async fn run_with_state(listener: TcpListener, state: Arc<ServerState>) -> Result<()> {
    loop {
        let (stream, peer_addr) = listener.accept().await?;
        // Cheapest possible refusal: before any handshake work.
        if !state.ip_limits().try_acquire(peer_addr.ip()) {
            drop(stream);
            continue;
        }
        let state = state.clone();
        tokio::spawn(async move {
            let slot = IpSlot { state: state.clone(), ip: peer_addr.ip() };
            if let Err(e) = handle_connection(stream, peer_addr, state).await {
                debug!(%peer_addr, error = %e, "connection closed");
            }
            drop(slot);
        });
    }
}

/// Releases the per-IP connection slot however the task ends.
struct IpSlot {
    state: Arc<ServerState>,
    ip: std::net::IpAddr,
}

impl Drop for IpSlot {
    fn drop(&mut self) {
        self.state.ip_limits().release(self.ip);
    }
}

/// Per-connection protocol state.
enum Phase {
    /// Nothing received yet.
    Unregistered,
    /// `Register` accepted; waiting for the signed challenge.
    Challenged { device: DeviceInfo, public_key: String, nonce: Vec<u8> },
    /// Fully registered under this ID.
    Registered(RotoDeskId),
}

struct Conn {
    id: ConnId,
    ip: std::net::IpAddr,
    phase: Phase,
    connect_limit: RateLimiter,
    signal_limit: RateLimiter,
    bad_messages: u32,
    tx: mpsc::Sender<SignalMessage>,
}

/// What the message loop should do after handling one message.
enum Flow {
    Continue,
    /// Close the socket (abuse, protocol violation).
    Close,
}

/// Drive a single client connection: split the socket, spawn a writer task, and
/// process inbound signaling messages until the socket closes.
async fn handle_connection(
    stream: TcpStream,
    peer_addr: SocketAddr,
    state: Arc<ServerState>,
) -> Result<()> {
    let config = WebSocketConfig {
        max_message_size: Some(MAX_WS_MESSAGE_BYTES),
        max_frame_size: Some(MAX_WS_MESSAGE_BYTES),
        ..Default::default()
    };
    let ws = tokio::time::timeout(
        HANDSHAKE_TIMEOUT,
        tokio_tungstenite::accept_async_with_config(stream, Some(config)),
    )
    .await
    .map_err(|_| anyhow::anyhow!("websocket handshake timed out"))??;
    let (mut sink, mut source) = ws.split();

    // Outbound queue: any task can push a SignalMessage to this peer. It is
    // bounded and every producer uses `try_send`: a peer that stops reading
    // loses messages instead of growing the server's memory.
    let (tx, mut rx) = mpsc::channel::<SignalMessage>(OUTBOUND_QUEUE);
    let mut writer = tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            match serde_json::to_string(&msg) {
                Ok(json) => {
                    if sink.send(Message::Text(json)).await.is_err() {
                        break;
                    }
                }
                Err(e) => error!(error = %e, "failed to serialize outbound message"),
            }
        }
        let _ = sink.close().await;
    });

    let mut conn = Conn {
        id: state.next_conn_id(),
        ip: peer_addr.ip(),
        phase: Phase::Unregistered,
        connect_limit: RateLimiter::new(CONNECT_BURST, CONNECT_WINDOW),
        signal_limit: RateLimiter::new(SIGNAL_BURST, SIGNAL_WINDOW),
        bad_messages: 0,
        tx,
    };
    let connected_at = Instant::now();

    loop {
        // The registration deadline is absolute: pinging every few seconds
        // must not let an unregistered socket hold its per-IP slot forever.
        let deadline = match conn.phase {
            Phase::Registered(_) => IDLE_TIMEOUT,
            _ => match REGISTER_DEADLINE.checked_sub(connected_at.elapsed()) {
                Some(left) => left,
                None => {
                    debug!(%peer_addr, "registration deadline passed");
                    break;
                }
            },
        };
        let frame = match tokio::time::timeout(deadline, source.next()).await {
            Ok(Some(frame)) => frame,
            Ok(None) => break,
            Err(_) => {
                debug!(%peer_addr, "connection timed out");
                break;
            }
        };
        let frame = match frame {
            Ok(f) => f,
            Err(e) => {
                debug!(%peer_addr, error = %e, "websocket error");
                break;
            }
        };
        // A newer registration of the same device replaced this connection:
        // it must not keep accepting or signalling under the ID.
        if let Phase::Registered(id) = conn.phase {
            if !state.holds(id, conn.id) {
                debug!(%peer_addr, %id, "connection superseded; closing");
                break;
            }
        }
        let flow = match frame {
            Message::Text(text) => match serde_json::from_str::<SignalMessage>(&text) {
                Ok(msg) => handle_message(msg, &state, &mut conn),
                Err(e) => {
                    warn!(%peer_addr, error = %e, "bad signaling message");
                    conn.reply(err(ErrorCode::BadRequest, "malformed message"));
                    conn.strike()
                }
            },
            Message::Ping(p) => {
                // tungstenite auto-answers pongs at the protocol level.
                debug!(bytes = p.len(), "ws ping");
                Flow::Continue
            }
            Message::Close(_) => break,
            // Binary frames are not part of the signaling protocol.
            Message::Binary(_) => conn.strike(),
            _ => Flow::Continue,
        };
        if matches!(flow, Flow::Close) {
            break;
        }
    }

    if let Phase::Registered(id) = conn.phase {
        state.unregister(id, conn.id);
    }
    // Let queued replies (e.g. the final Error) flush before tearing down;
    // a peer that will not take them does not get to keep the queue alive.
    drop(conn);
    if tokio::time::timeout(Duration::from_secs(2), &mut writer).await.is_err() {
        writer.abort();
    }
    Ok(())
}

impl Conn {
    /// Queue a message for this connection; dropped when the queue is full
    /// (the peer is not reading) or the writer is gone.
    fn reply(&self, msg: SignalMessage) {
        if let Err(e) = self.tx.try_send(msg) {
            debug!(conn = self.id, error = %e, "dropping reply; peer not draining");
        }
    }

    /// Count a protocol violation; close once the budget is exhausted.
    fn strike(&mut self) -> Flow {
        self.bad_messages += 1;
        if self.bad_messages >= BAD_MESSAGE_BUDGET {
            warn!(conn = self.id, "too many bad messages; closing");
            Flow::Close
        } else {
            Flow::Continue
        }
    }

    fn registered_id(&self) -> Option<RotoDeskId> {
        match self.phase {
            Phase::Registered(id) => Some(id),
            _ => None,
        }
    }
}

/// Handle one decoded signaling message from a peer.
fn handle_message(msg: SignalMessage, state: &Arc<ServerState>, conn: &mut Conn) -> Flow {
    match msg {
        SignalMessage::Register { mut device, protocol, public_key } => {
            rotodesk_proto::text::sanitize_device_info(&mut device);
            if !protocol.compatible_with(PROTOCOL_VERSION) {
                conn.reply(version_mismatch(protocol));
                return Flow::Close;
            }
            if let Phase::Registered(id) = conn.phase {
                // Re-registering on a live connection is not a use case; the
                // caller opens a new socket instead.
                debug!(%id, "ignoring duplicate Register");
                conn.reply(err(ErrorCode::BadRequest, "already registered"));
                return conn.strike();
            }
            // Counted before the key is even parsed: the point is to bound
            // the work one address can make the server do.
            if !state.ip_limits().allow_registration(conn.ip) {
                conn.reply(err(ErrorCode::RateLimited, "too many registrations from this address"));
                return Flow::Close;
            }
            // The claimed ID must be the one derived from the key. This is
            // what makes RotoDesk IDs unforgeable without the private key.
            let derived = match rotodesk_crypto::identity::derive_id_from_public_key_b64(&public_key) {
                Ok(id) => id,
                Err(e) => {
                    conn.reply(err(ErrorCode::BadRequest, &format!("invalid public key: {e}")));
                    return conn.strike();
                }
            };
            if derived != device.id {
                warn!(claimed = %device.id, %derived, "ID does not match public key");
                conn.reply(err(ErrorCode::Unauthorized, "id does not match public key"));
                return conn.strike();
            }
            let nonce = rotodesk_crypto::identity::random_bytes(32);
            conn.reply(SignalMessage::RegisterChallenge { nonce: B64.encode(&nonce) });
            conn.phase = Phase::Challenged { device, public_key, nonce };
            Flow::Continue
        }

        SignalMessage::RegisterProof { signature } => {
            let Phase::Challenged { device, public_key, nonce } =
                std::mem::replace(&mut conn.phase, Phase::Unregistered)
            else {
                conn.reply(err(ErrorCode::BadRequest, "no registration in progress"));
                return conn.strike();
            };
            let msg = register_proof_message(&nonce);
            if rotodesk_crypto::identity::verify_b64_sig(&public_key, &msg, &signature).is_err() {
                warn!(id = %device.id, "registration proof failed");
                conn.reply(err(ErrorCode::Unauthorized, "bad registration proof"));
                return Flow::Close;
            }
            match state.register(device, public_key, conn.id, conn.tx.clone()) {
                Ok(id) => {
                    conn.phase = Phase::Registered(id);
                    conn.reply(SignalMessage::Registered { id });
                    Flow::Continue
                }
                Err(RegisterError::IdHeldByOtherKey) => {
                    conn.reply(err(ErrorCode::IdConflict, "id already in use by another device"));
                    Flow::Close
                }
            }
        }

        SignalMessage::ConnectRequest { target, mut from, requested, quality, auth_proof } => {
            let Some(me) = conn.registered_id() else {
                conn.reply(err(ErrorCode::Unauthorized, "register first"));
                return conn.strike();
            };
            if !conn.connect_limit.allow() {
                conn.reply(err(ErrorCode::RateLimited, "too many connection requests"));
                return Flow::Continue;
            }
            if target == me {
                conn.reply(err(ErrorCode::BadRequest, "cannot connect to yourself"));
                return Flow::Continue;
            }
            let Some(target_tx) = state.sender(target) else {
                conn.reply(err(ErrorCode::TargetOffline, "target not reachable"));
                return Flow::Continue;
            };
            // Many callers from many addresses must not be able to flood
            // one host with dialogs.
            if !state.allow_incoming(target) {
                conn.reply(err(ErrorCode::RateLimited, "target is receiving too many requests"));
                return Flow::Continue;
            }
            // The callee shows `from` to a human. Never let a caller present
            // itself under a different ID than the one it registered, nor
            // with names that break the dialog or the logs.
            from.id = me;
            rotodesk_proto::text::sanitize_device_info(&mut from);
            let session = Uuid::new_v4();
            state.open_session(session, me, target);
            let auth = if auth_proof.is_some() {
                AuthKind::UnattendedPassword
            } else {
                AuthKind::Interactive
            };
            if target_tx
                .try_send(SignalMessage::IncomingRequest { session, from, requested, quality, auth })
                .is_err()
            {
                state.close_session(session);
                conn.reply(err(ErrorCode::TargetOffline, "target went away"));
                return Flow::Continue;
            }
            debug!(%session, caller = %me, %target, "connect request routed");
            Flow::Continue
        }

        // Only the callee decides.
        SignalMessage::Accept { session, granted } => {
            forward_as(state, conn, session, Some(Role::Callee), SignalMessage::Accept { session, granted });
            Flow::Continue
        }
        SignalMessage::Reject { session, reason } => {
            if forward_as(state, conn, session, Some(Role::Callee), SignalMessage::Reject { session, reason }) {
                state.close_session(session);
            }
            Flow::Continue
        }

        SignalMessage::Signal { session, payload } => {
            if !conn.signal_limit.allow() {
                conn.reply(err(ErrorCode::RateLimited, "too many signaling messages"));
                return conn.strike();
            }
            forward_as(state, conn, session, None, SignalMessage::Signal { session, payload });
            Flow::Continue
        }

        SignalMessage::PresenceQuery { devices } => {
            if conn.registered_id().is_none() {
                conn.reply(err(ErrorCode::Unauthorized, "register first"));
                return conn.strike();
            }
            if devices.len() > 512 || !conn.signal_limit.allow() {
                conn.reply(err(ErrorCode::RateLimited, "presence query exceeds budget"));
                return Flow::Continue;
            }
            let online = devices.into_iter().filter(|id| state.is_online(*id)).collect();
            conn.reply(SignalMessage::PresenceSnapshot { online });
            Flow::Continue
        }
        SignalMessage::Ping { nonce } => {
            conn.reply(SignalMessage::Pong { nonce });
            Flow::Continue
        }
        // Answer to a ping we never send; harmless.
        SignalMessage::Pong { .. } => Flow::Continue,

        SignalMessage::PresenceSnapshot { .. }
        | SignalMessage::Registered { .. }
        | SignalMessage::RegisterChallenge { .. }
        | SignalMessage::IncomingRequest { .. }
        | SignalMessage::Error { .. } => {
            warn!("ignoring server-origin message received from client");
            conn.strike()
        }
    }
}

/// Route a message to the *other* endpoint of a session, optionally requiring
/// the sender to hold a specific role. Returns whether it was forwarded.
fn forward_as(
    state: &Arc<ServerState>,
    conn: &Conn,
    session: Uuid,
    required: Option<Role>,
    msg: SignalMessage,
) -> bool {
    let Some(me) = conn.registered_id() else { return false };
    let Some(role) = state.role_in(session, me) else {
        debug!(%session, "no session for sender (already closed?)");
        return false;
    };
    if let Some(required) = required {
        if role != required {
            warn!(%session, %me, ?role, "message not allowed from this role");
            return false;
        }
    }
    match state.peer_across(session, me) {
        Some(peer) => match peer.try_send(msg) {
            Ok(()) => true,
            Err(e) => {
                debug!(%session, error = %e, "peer across session not draining; message dropped");
                false
            }
        },
        None => {
            debug!(%session, "peer across session is gone");
            false
        }
    }
}

fn err(code: ErrorCode, detail: &str) -> SignalMessage {
    SignalMessage::Error { code, detail: detail.to_string() }
}

fn version_mismatch(remote: Version) -> SignalMessage {
    SignalMessage::Error {
        code: ErrorCode::VersionMismatch,
        detail: format!("server speaks {PROTOCOL_VERSION}, client {remote}"),
    }
}

/// Log the configuration once at startup (used by the binary).
pub fn log_banner(addr: SocketAddr) {
    info!(%addr, version = %PROTOCOL_VERSION, max_message = MAX_WS_MESSAGE_BYTES, "RotoDesk Server listening");
}
