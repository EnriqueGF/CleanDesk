//! In-process smoke test: start the relay on an ephemeral loopback port and
//! drive it with the `turn` crate's client, the same TURN implementation the
//! WebRTC stack uses.

use std::{net::IpAddr, sync::Arc, time::Duration};

use cleandesk_relay_server::{
    RelayConfig, RelayError, RelayHandle, DEFAULT_REALM, ENV_BIND, ENV_PORT, ENV_PUBLIC_IP,
    ENV_USERS,
};
use tokio::net::UdpSocket;
use turn::client::{Client, ClientConfig};
use webrtc_util::Conn;

const USERS: &str = "alice:correct-horse";

async fn start_relay() -> RelayHandle {
    let cfg = RelayConfig::from_vars([
        (ENV_BIND, "127.0.0.1"),
        (ENV_PORT, "0"),
        (ENV_PUBLIC_IP, "127.0.0.1"),
        (ENV_USERS, USERS),
    ])
    .expect("config");
    cleandesk_relay_server::run(cfg)
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
    let err = cleandesk_relay_server::run(cfg)
        .await
        .err()
        .expect("second bind fails");
    assert!(matches!(err, RelayError::Bind { .. }));
    first.shutdown().await.expect("relay shutdown");
}
