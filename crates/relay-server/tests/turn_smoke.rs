//! In-process smoke test: start the relay on an ephemeral loopback port and
//! drive it with the `turn` crate's client, the same TURN implementation the
//! WebRTC stack uses.

use std::{net::IpAddr, sync::Arc, time::Duration};

use rotodesk_relay_server::{
    RelayConfig, RelayError, RelayHandle, DEFAULT_REALM, ENV_ALLOW_PRIVATE_PEERS, ENV_BIND,
    ENV_MAX_ALLOCATIONS_PER_IP, ENV_PORT, ENV_PUBLIC_IP, ENV_USERS,
};
use tokio::net::UdpSocket;
use turn::client::{Client, ClientConfig};
use webrtc_util::Conn;

const USERS: &str = "alice:correct-horse";

async fn start_relay() -> RelayHandle {
    start_relay_with(&[]).await
}

async fn start_relay_with(extra: &[(&str, &str)]) -> RelayHandle {
    let mut vars = vec![
        (ENV_BIND, "127.0.0.1"),
        (ENV_PORT, "0"),
        (ENV_PUBLIC_IP, "127.0.0.1"),
        (ENV_USERS, USERS),
    ];
    vars.extend_from_slice(extra);
    let cfg = RelayConfig::from_vars(vars).expect("config");
    rotodesk_relay_server::run(cfg)
        .await
        .expect("relay starts")
}

async fn client(server: &str, username: &str, password: &str) -> Client {
    let conn = UdpSocket::bind("127.0.0.1:0").await.expect("client socket");
    let client = Client::new(ClientConfig {
        stun_serv_addr: server.to_owned(),
        turn_serv_addr: server.to_owned(),
        username: username.to_owned(),
        password: password.to_owned(),
        realm: DEFAULT_REALM.to_owned(),
        software: String::new(),
        rto_in_ms: 0,
        conn: Arc::new(conn),
        vnet: None,
    })
    .await
    .expect("client");
    client.listen().await.expect("client listen");
    client
}

#[tokio::test]
async fn allocates_relayed_address_with_valid_credentials() {
    let relay = start_relay().await;
    let server = relay.local_addr().to_string();
    assert_ne!(
        relay.local_addr().port(),
        0,
        "ephemeral port must be resolved"
    );

    let client = client(&server, "alice", "correct-horse").await;
    let relayed = tokio::time::timeout(Duration::from_secs(10), client.allocate())
        .await
        .expect("allocate did not time out")
        .expect("allocation succeeds");
    let relayed_addr = relayed.local_addr().expect("relayed addr");
    assert_eq!(relayed_addr.ip(), "127.0.0.1".parse::<IpAddr>().unwrap());
    assert_ne!(relayed_addr.port(), 0);
    assert_ne!(
        relayed_addr,
        relay.local_addr(),
        "relay socket must be distinct from listener"
    );

    client.close().await.expect("client close");
    relay.shutdown().await.expect("relay shutdown");
}

/// Relay a datagram to a peer on loopback. With the default policy the peer
/// is a private address and nothing arrives; with the opt-in it does.
async fn relay_to_loopback_peer(allow_private: bool) -> bool {
    let extra: &[(&str, &str)] = if allow_private {
        &[(ENV_ALLOW_PRIVATE_PEERS, "1")]
    } else {
        &[]
    };
    let relay = start_relay_with(extra).await;
    let server = relay.local_addr().to_string();
    let peer = UdpSocket::bind("127.0.0.1:0").await.expect("peer socket");
    let peer_addr = peer.local_addr().expect("peer addr");

    let client = client(&server, "alice", "correct-horse").await;
    let relayed = tokio::time::timeout(Duration::from_secs(10), client.allocate())
        .await
        .expect("allocate did not time out")
        .expect("allocation succeeds");
    // `send_to` on the relayed conn issues CreatePermission first.
    let mut delivered = false;
    let mut buf = [0u8; 64];
    for _ in 0..5 {
        let _ = relayed.send_to(b"through the relay", peer_addr).await;
        if let Ok(Ok((n, _))) =
            tokio::time::timeout(Duration::from_millis(400), peer.recv_from(&mut buf)).await
        {
            assert_eq!(&buf[..n], b"through the relay");
            delivered = true;
            break;
        }
    }
    client.close().await.expect("client close");
    relay.shutdown().await.expect("relay shutdown");
    delivered
}

#[tokio::test]
async fn private_peers_are_refused_by_default() {
    assert!(
        !relay_to_loopback_peer(false).await,
        "a loopback peer must receive nothing unless the operator opted in"
    );
}

#[tokio::test]
async fn private_peers_relay_when_opted_in() {
    assert!(relay_to_loopback_peer(true).await);
}

#[tokio::test]
async fn rejects_wrong_password_and_unknown_user() {
    let relay = start_relay().await;
    let server = relay.local_addr().to_string();

    for (user, pw) in [("alice", "wrong"), ("mallory", "correct-horse")] {
        let client = client(&server, user, pw).await;
        let res = tokio::time::timeout(Duration::from_secs(10), client.allocate())
            .await
            .expect("allocate did not time out");
        // Must be an explicit TURN error response from the server, not a
        // timeout or a local socket failure.
        let err = res
            .err()
            .unwrap_or_else(|| panic!("{user}:{pw} must be refused"));
        assert!(
            err.to_string().contains("error response"),
            "{user}:{pw}: unexpected failure kind: {err}"
        );
        client.close().await.expect("client close");
    }

    relay.shutdown().await.expect("relay shutdown");
}

#[tokio::test]
async fn bind_failure_is_reported_not_panicked() {
    let first = start_relay().await;
    let port = first.local_addr().port().to_string();
    let cfg = RelayConfig::from_vars([
        (ENV_BIND, "127.0.0.1"),
        (ENV_PORT, port.as_str()),
        (ENV_USERS, USERS),
    ])
    .expect("config");
    let err = rotodesk_relay_server::run(cfg)
        .await
        .err()
        .expect("second bind fails");
    assert!(matches!(err, RelayError::Bind { .. }));
    first.shutdown().await.expect("relay shutdown");
}

#[tokio::test]
async fn allocations_per_source_are_capped_and_released() {
    let relay = start_relay_with(&[(ENV_MAX_ALLOCATIONS_PER_IP, "1")]).await;
    let server = relay.local_addr().to_string();

    let first = client(&server, "alice", "correct-horse").await;
    let relayed = tokio::time::timeout(Duration::from_secs(10), first.allocate())
        .await
        .expect("allocate did not time out")
        .expect("first allocation succeeds");

    // A second allocation from the same address is dropped before the
    // engine sees it: the client only observes a timeout.
    let second = client(&server, "alice", "correct-horse").await;
    let res = tokio::time::timeout(Duration::from_secs(4), second.allocate()).await;
    assert!(
        matches!(res, Err(_) | Ok(Err(_))),
        "second allocation from the same source must not succeed"
    );
    second.close().await.expect("client close");

    // Releasing the first frees the slot.
    relayed.close().await.expect("relayed close");
    first.close().await.expect("client close");
    let mut freed = false;
    for _ in 0..20 {
        let third = client(&server, "alice", "correct-horse").await;
        if let Ok(Ok(_)) = tokio::time::timeout(Duration::from_secs(3), third.allocate()).await {
            freed = true;
            third.close().await.expect("client close");
            break;
        }
        third.close().await.expect("client close");
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    assert!(freed, "closing the allocation must free the per-source slot");
    relay.shutdown().await.expect("relay shutdown");
}
