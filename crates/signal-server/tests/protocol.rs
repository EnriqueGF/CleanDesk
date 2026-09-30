//! Signaling protocol conformance tests against a raw WebSocket client, so the
//! server's security rules are checked independently of the transport crate's
//! convenience wrappers:
//!
//! * registration requires the ID derived from the key *and* a valid signature,
//! * a caller can never present itself under another ID,
//! * only the callee may Accept/Reject, and only session members may Signal,
//! * self-connect and offline targets are refused,
//! * a device reconnecting with the same key keeps its ID.

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use rotodesk_crypto::identity::Identity;
use rotodesk_proto::{
    id::RotoDeskId,
    message::{register_proof_message, ErrorCode, RejectReason, SignalMessage, SignalPayload},
    permissions::Permissions,
    quality::QualityProfile,
    session::DeviceInfo,
    Version, PROTOCOL_VERSION,
};
use rotodesk_signal_server::state::{IpLimits, ServerState};
use futures_util::{SinkExt, StreamExt};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio_tungstenite::{tungstenite::Message, MaybeTlsStream, WebSocketStream};

type Ws = WebSocketStream<MaybeTlsStream<TcpStream>>;

async fn start_server() -> (String, Arc<ServerState>) {
    start_server_with(ServerState::new()).await
}

async fn start_server_with(state: ServerState) -> (String, Arc<ServerState>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let state = Arc::new(state);
    let st = state.clone();
    tokio::spawn(async move {
        let _ = rotodesk_signal_server::run_with_state(listener, st).await;
    });
    (format!("ws://{addr}"), state)
}

fn dev(id: RotoDeskId, name: &str) -> DeviceInfo {
    DeviceInfo {
        id,
        alias: None,
        hostname: name.into(),
        os: "test".into(),
        app_version: "0".into(),
    }
}

async fn open(url: &str) -> Ws {
    let (ws, _) = tokio_tungstenite::connect_async(url).await.unwrap();
    ws
}

async fn send(ws: &mut Ws, msg: &SignalMessage) {
    ws.send(Message::Text(serde_json::to_string(msg).unwrap())).await.unwrap();
}

async fn recv(ws: &mut Ws) -> SignalMessage {
    let frame = tokio::time::timeout(Duration::from_secs(5), ws.next())
        .await
        .expect("timed out waiting for a server message")
        .expect("socket closed")
        .expect("socket error");
    match frame {
        Message::Text(t) => serde_json::from_str(&t).expect("valid SignalMessage"),
        other => panic!("unexpected frame {other:?}"),
    }
}

/// Wait for the server to close the socket (or a close frame).
async fn expect_closed(ws: &mut Ws) {
    let r = tokio::time::timeout(Duration::from_secs(5), ws.next()).await.expect("timeout");
    match r {
        None | Some(Ok(Message::Close(_))) | Some(Err(_)) => {}
        Some(Ok(other)) => panic!("expected close, got {other:?}"),
    }
}

/// Full, valid registration. Returns the confirmed ID.
async fn register(ws: &mut Ws, ident: &Identity, name: &str) -> RotoDeskId {
    send(
        ws,
        &SignalMessage::Register {
            device: dev(ident.derive_id(), name),
            protocol: PROTOCOL_VERSION,
            public_key: ident.public_key_b64(),
        },
    )
    .await;
    let SignalMessage::RegisterChallenge { nonce } = recv(ws).await else {
        panic!("expected a challenge")
    };
    let nonce = B64.decode(nonce).unwrap();
    send(ws, &SignalMessage::RegisterProof { signature: ident.sign_b64(&register_proof_message(&nonce)) })
        .await;
    match recv(ws).await {
        SignalMessage::Registered { id } => id,
        other => panic!("expected Registered, got {other:?}"),
    }
}

fn connect_request(target: RotoDeskId, from: DeviceInfo) -> SignalMessage {
    SignalMessage::ConnectRequest {
        target,
        from,
        requested: Permissions::interactive(),
        quality: QualityProfile::Auto,
        auth_proof: None,
    }
}

#[tokio::test]
async fn presence_tracks_registration_without_opening_a_session() {
    let (url, state) = start_server().await;
    let mut observer = open(&url).await;
    let peer = Identity::generate();
    let devices = vec![peer.derive_id()];
    send(&mut observer, &SignalMessage::PresenceQuery { devices: devices.clone() }).await;
    assert!(matches!(recv(&mut observer).await, SignalMessage::Error { code: ErrorCode::Unauthorized, .. }));
    register(&mut observer, &Identity::generate(), "observer").await;
    send(&mut observer, &SignalMessage::PresenceQuery { devices: devices.clone() }).await;
    assert!(matches!(recv(&mut observer).await, SignalMessage::PresenceSnapshot { online } if online.is_empty()));
    let mut host = open(&url).await;
    register(&mut host, &peer, "host").await;
    send(&mut observer, &SignalMessage::PresenceQuery { devices: devices.clone() }).await;
    assert!(matches!(recv(&mut observer).await, SignalMessage::PresenceSnapshot { online } if online == devices));
    assert_eq!(state.session_count(), 0);
    // A status lookup must not produce a connection dialog at the other end.
    assert!(tokio::time::timeout(Duration::from_millis(100), host.next()).await.is_err());
    host.close(None).await.unwrap();
    for _ in 0..20 {
        if !state.is_online(peer.derive_id()) { break; }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    send(&mut observer, &SignalMessage::PresenceQuery { devices: devices.clone() }).await;
    assert!(matches!(recv(&mut observer).await, SignalMessage::PresenceSnapshot { online } if online.is_empty()));
    send(&mut observer, &SignalMessage::PresenceQuery { devices: vec![peer.derive_id(); 513] }).await;
    assert!(matches!(recv(&mut observer).await, SignalMessage::Error { code: ErrorCode::RateLimited, .. }));
}

#[tokio::test]
async fn valid_registration_yields_the_derived_id() {
    let (url, state) = start_server().await;
    let ident = Identity::generate();
    let mut ws = open(&url).await;
    let id = register(&mut ws, &ident, "a").await;
    assert_eq!(id, ident.derive_id());
    assert!(state.is_online(id));
    ws.close(None).await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(!state.is_online(id), "closing the socket unregisters");
}

#[tokio::test]
async fn claiming_a_foreign_id_is_refused() {
    let (url, state) = start_server().await;
    let ident = Identity::generate();
    let victim = Identity::generate().derive_id();
    let mut ws = open(&url).await;
    send(
        &mut ws,
        &SignalMessage::Register {
            device: dev(victim, "evil"),
            protocol: PROTOCOL_VERSION,
            public_key: ident.public_key_b64(),
        },
    )
    .await;
    match recv(&mut ws).await {
        SignalMessage::Error { code, .. } => assert_eq!(code, ErrorCode::Unauthorized),
        other => panic!("expected Error, got {other:?}"),
    }
    assert!(!state.is_online(victim));
    assert_eq!(state.peer_count(), 0);
}

#[tokio::test]
async fn wrong_signature_is_refused_and_socket_closed() {
    let (url, state) = start_server().await;
    let ident = Identity::generate();
    let impostor = Identity::generate();
    let mut ws = open(&url).await;
    send(
        &mut ws,
        &SignalMessage::Register {
            device: dev(ident.derive_id(), "a"),
            protocol: PROTOCOL_VERSION,
            public_key: ident.public_key_b64(),
        },
    )
    .await;
    let SignalMessage::RegisterChallenge { nonce } = recv(&mut ws).await else { panic!() };
    let nonce = B64.decode(nonce).unwrap();
    // Signed by someone who does not hold the private key.
    send(
        &mut ws,
        &SignalMessage::RegisterProof { signature: impostor.sign_b64(&register_proof_message(&nonce)) },
    )
    .await;
    match recv(&mut ws).await {
        SignalMessage::Error { code, .. } => assert_eq!(code, ErrorCode::Unauthorized),
        other => panic!("expected Error, got {other:?}"),
    }
    expect_closed(&mut ws).await;
    assert_eq!(state.peer_count(), 0);
}

#[tokio::test]
async fn proof_without_register_and_garbage_are_rejected() {
    let (url, _state) = start_server().await;
    let mut ws = open(&url).await;
    send(&mut ws, &SignalMessage::RegisterProof { signature: "x".into() }).await;
    assert!(matches!(recv(&mut ws).await, SignalMessage::Error { code: ErrorCode::BadRequest, .. }));
    ws.send(Message::Text("{not json".into())).await.unwrap();
    assert!(matches!(recv(&mut ws).await, SignalMessage::Error { code: ErrorCode::BadRequest, .. }));
    // Unregistered clients cannot request connections.
    send(&mut ws, &connect_request(Identity::generate().derive_id(), dev(Identity::generate().derive_id(), "x")))
        .await;
    assert!(matches!(recv(&mut ws).await, SignalMessage::Error { code: ErrorCode::Unauthorized, .. }));
}

#[tokio::test]
async fn incompatible_protocol_version_is_refused() {
    let (url, _state) = start_server().await;
    let ident = Identity::generate();
    let mut ws = open(&url).await;
    send(
        &mut ws,
        &SignalMessage::Register {
            device: dev(ident.derive_id(), "old"),
            protocol: Version { major: PROTOCOL_VERSION.major + 1, minor: 0 },
            public_key: ident.public_key_b64(),
        },
    )
    .await;
    assert!(matches!(recv(&mut ws).await, SignalMessage::Error { code: ErrorCode::VersionMismatch, .. }));
    expect_closed(&mut ws).await;
}

#[tokio::test]
async fn caller_id_is_overwritten_and_self_or_offline_targets_refused() {
    let (url, _state) = start_server().await;
    let a = Identity::generate();
    let b = Identity::generate();
    let mut wa = open(&url).await;
    let mut wb = open(&url).await;
    let ida = register(&mut wa, &a, "a").await;
    let idb = register(&mut wb, &b, "b").await;

    // Self-connect.
    send(&mut wa, &connect_request(ida, dev(ida, "a"))).await;
    assert!(matches!(recv(&mut wa).await, SignalMessage::Error { code: ErrorCode::BadRequest, .. }));

    // Offline target.
    send(&mut wa, &connect_request(Identity::generate().derive_id(), dev(ida, "a"))).await;
    assert!(matches!(recv(&mut wa).await, SignalMessage::Error { code: ErrorCode::TargetOffline, .. }));

    // Spoofed `from.id`: B must see A's real ID.
    let spoofed = RotoDeskId::new(123_456_789).unwrap();
    send(&mut wa, &connect_request(idb, dev(spoofed, "a"))).await;
    match recv(&mut wb).await {
        SignalMessage::IncomingRequest { from, .. } => assert_eq!(from.id, ida),
        other => panic!("expected IncomingRequest, got {other:?}"),
    }
}

#[tokio::test]
async fn only_callee_may_accept_and_only_members_may_signal() {
    let (url, state) = start_server().await;
    let a = Identity::generate();
    let b = Identity::generate();
    let c = Identity::generate();
    let mut wa = open(&url).await;
    let mut wb = open(&url).await;
    let mut wc = open(&url).await;
    let ida = register(&mut wa, &a, "a").await;
    let idb = register(&mut wb, &b, "b").await;
    let _idc = register(&mut wc, &c, "c").await;

    send(&mut wa, &connect_request(idb, dev(ida, "a"))).await;
    let SignalMessage::IncomingRequest { session, .. } = recv(&mut wb).await else { panic!() };

    // The caller trying to accept its own request is dropped.
    send(&mut wa, &SignalMessage::Accept { session, granted: Permissions::full() }).await;
    // An outsider signaling into the session is dropped.
    send(&mut wc, &SignalMessage::Signal { session, payload: SignalPayload::Offer { sdp: "evil".into() } }).await;

    // The real callee accepts; A must receive exactly that.
    send(&mut wb, &SignalMessage::Accept { session, granted: Permissions::VIEW_ONLY }).await;
    match recv(&mut wa).await {
        SignalMessage::Accept { session: s, granted } => {
            assert_eq!(s, session);
            assert_eq!(granted, Permissions::VIEW_ONLY);
        }
        other => panic!("expected the callee's Accept, got {other:?}"),
    }
    // B never got anything but the request (no forged Accept/Offer).
    send(&mut wa, &SignalMessage::Ping { nonce: 7 }).await;
    assert!(matches!(recv(&mut wa).await, SignalMessage::Pong { nonce: 7 }));

    // Signal flows both ways between members.
    send(&mut wa, &SignalMessage::Signal { session, payload: SignalPayload::Offer { sdp: "o".into() } }).await;
    assert!(matches!(recv(&mut wb).await, SignalMessage::Signal { payload: SignalPayload::Offer { .. }, .. }));

    // Reject from the callee closes the session.
    send(&mut wb, &SignalMessage::Reject { session, reason: RejectReason::UserDeclined }).await;
    assert!(matches!(recv(&mut wa).await, SignalMessage::Reject { .. }));
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(state.session_count(), 0);
}

#[tokio::test]
async fn reconnecting_with_the_same_key_keeps_the_id() {
    let (url, state) = start_server().await;
    let ident = Identity::generate();
    let mut first = open(&url).await;
    let id1 = register(&mut first, &ident, "a").await;
    // Do NOT close `first`: simulate a half-open socket the server hasn't noticed.
    let mut second = open(&url).await;
    let id2 = register(&mut second, &ident, "a").await;
    assert_eq!(id1, id2);
    assert_eq!(state.peer_count(), 1);
    // Now the stale one goes away; the fresh registration must survive.
    first.close(None).await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(state.is_online(id2));
    // And it is still routable.
    let b = Identity::generate();
    let mut wb = open(&url).await;
    let idb = register(&mut wb, &b, "b").await;
    send(&mut wb, &connect_request(id2, dev(idb, "b"))).await;
    assert!(matches!(recv(&mut second).await, SignalMessage::IncomingRequest { .. }));
}

#[tokio::test]
async fn connect_requests_are_rate_limited() {
    let (url, _state) = start_server().await;
    let a = Identity::generate();
    let b = Identity::generate();
    let mut wa = open(&url).await;
    let mut wb = open(&url).await;
    let ida = register(&mut wa, &a, "a").await;
    let idb = register(&mut wb, &b, "b").await;
    let mut limited = false;
    for _ in 0..8 {
        send(&mut wa, &connect_request(idb, dev(ida, "a"))).await;
    }
    // Drain A's inbox: at least one RateLimited must appear.
    for _ in 0..8 {
        match tokio::time::timeout(Duration::from_millis(500), wa.next()).await {
            Ok(Some(Ok(Message::Text(t)))) => {
                if let Ok(SignalMessage::Error { code: ErrorCode::RateLimited, .. }) =
                    serde_json::from_str::<SignalMessage>(&t)
                {
                    limited = true;
                    break;
                }
            }
            _ => break,
        }
    }
    assert!(limited, "spamming ConnectRequest must trip the rate limiter");
}

#[tokio::test]
async fn connections_per_ip_are_capped() {
    let (url, state) = start_server_with(ServerState::with_ip_limits(IpLimits::new(2, 30, Duration::from_secs(60)))).await;
    let _a = open(&url).await;
    let _b = open(&url).await;
    // The third socket is dropped before the WebSocket upgrade: either the
    // connect fails outright or the stream ends at once.
    match tokio_tungstenite::connect_async(&url).await {
        Err(_) => {}
        Ok((mut ws, _)) => expect_closed(&mut ws).await,
    }
    let ip = "127.0.0.1".parse().unwrap();
    assert_eq!(state.ip_limits().connections(ip), 2);
    // Closing one frees a slot.
    drop(_a);
    tokio::time::timeout(Duration::from_secs(5), async {
        while state.ip_limits().connections(ip) != 1 {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("slot released after close");
    let mut c = open(&url).await;
    send(&mut c, &SignalMessage::Ping { nonce: 9 }).await;
    assert!(matches!(recv(&mut c).await, SignalMessage::Pong { nonce: 9 }));
}

#[tokio::test]
async fn registrations_per_ip_are_rate_limited() {
    let (url, _state) = start_server_with(ServerState::with_ip_limits(IpLimits::new(20, 2, Duration::from_secs(60)))).await;
    let a = Identity::generate();
    let b = Identity::generate();
    let mut ws_a = open(&url).await;
    register(&mut ws_a, &a, "a").await;
    let mut ws_b = open(&url).await;
    register(&mut ws_b, &b, "b").await;
    // Third registration attempt from the same address within the window:
    // refused before the key is looked at, and the socket is closed.
    let c = Identity::generate();
    let mut ws_c = open(&url).await;
    send(
        &mut ws_c,
        &SignalMessage::Register { device: dev(c.derive_id(), "c"), protocol: PROTOCOL_VERSION, public_key: c.public_key_b64() },
    )
    .await;
    assert!(matches!(recv(&mut ws_c).await, SignalMessage::Error { code: ErrorCode::RateLimited, .. }));
    expect_closed(&mut ws_c).await;
    // Already-registered devices keep working.
    send(&mut ws_a, &SignalMessage::Ping { nonce: 1 }).await;
    assert!(matches!(recv(&mut ws_a).await, SignalMessage::Pong { nonce: 1 }));
}
