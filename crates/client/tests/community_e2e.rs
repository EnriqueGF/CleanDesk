//! Community-mode end to end on one machine, with no server anywhere:
//! the host announces on the LAN (mDNS) and listens for direct signaling; the
//! viewer resolves the ID over mDNS, dials the direct link, both prove their
//! keys, and a real WebRTC session comes up over loopback.
//!
//! DHT, UPnP and Nostr are disabled so the test needs no Internet.

use cleandesk_client::{connect_community, ClientConfig, ClientError, ClientEvent};
use cleandesk_crypto::identity::Identity;
use cleandesk_host::{serve_community, AutoAccept, CommunityOptions, HostConfig};
use cleandesk_proto::{id::CleanDeskId, permissions::Permissions, quality::QualityProfile, session::DeviceInfo};
use std::sync::Arc;
use std::time::Duration;

fn dev_info(id: CleanDeskId, hostname: &str) -> DeviceInfo {
    DeviceInfo { id, alias: None, hostname: hostname.to_string(), os: "test".into(), app_version: "0".into() }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn lan_only_community_session() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();

    let host_ident = Identity::generate();
    let host_id = host_ident.derive_id();
    let mut host_cfg = HostConfig::new(String::new(), dev_info(host_id, "host"), host_ident.clone());
    host_cfg.quality = QualityProfile::Performance;
    host_cfg.community = CommunityOptions {
        direct_port: 0,
        ice_udp_port: 0,
        upnp: false,
        dht: false,
        // An unreachable relay makes the Nostr setup fail fast instead of
        // reaching out to the Internet.
        nostr_relays: vec!["ws://127.0.0.1:9".to_string()],
    };
    tokio::spawn(async move {
        let _ = serve_community(host_cfg, Arc::new(AutoAccept { allowed: Permissions::full() })).await;
    });
    // Let the mDNS announcement settle.
    tokio::time::sleep(Duration::from_millis(2000)).await;

    let cli_ident = Identity::generate();
    let mut cli_cfg = ClientConfig::new(String::new(), dev_info(cli_ident.derive_id(), "viewer"), cli_ident, host_id);
    cli_cfg.quality = QualityProfile::Performance;

    let mut session = tokio::time::timeout(Duration::from_secs(40), connect_community(cli_cfg, None))
        .await
        .expect("connect_community timed out")
        .expect("connect_community failed");
    assert_eq!(session.via, "LAN");
    assert_eq!(session.peer_public_key.as_deref(), Some(host_ident.public_key_b64().as_str()));

    let mut got_permissions = false;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(12);
    while tokio::time::Instant::now() < deadline && !got_permissions {
        tokio::select! {
            ev = session.events.recv() => match ev {
                Some(ClientEvent::PermissionsUpdated(p)) => {
                    assert!(p.contains(Permissions::VIEW_SCREEN));
                    got_permissions = true;
                }
                Some(ClientEvent::Disconnected(reason)) => panic!("disconnected early: {reason}"),
                Some(_) => {}
                None => break,
            },
            _ = tokio::time::sleep(Duration::from_millis(200)) => {}
        }
    }
    assert!(got_permissions, "no permissions handshake over the community P2P session");
    session.disconnect();
}

#[tokio::test]
async fn pinned_key_mismatch_is_refused() {
    let host_ident = Identity::generate();
    let host_id = host_ident.derive_id();
    let mut host_cfg = HostConfig::new(String::new(), dev_info(host_id, "host"), host_ident);
    host_cfg.community = CommunityOptions {
        direct_port: 0,
        ice_udp_port: 0,
        upnp: false,
        dht: false,
        nostr_relays: vec!["ws://127.0.0.1:9".to_string()],
    };
    tokio::spawn(async move {
        let _ = serve_community(host_cfg, Arc::new(AutoAccept { allowed: Permissions::full() })).await;
    });
    tokio::time::sleep(Duration::from_millis(2000)).await;

    let cli_ident = Identity::generate();
    let cli_cfg = ClientConfig::new(String::new(), dev_info(cli_ident.derive_id(), "viewer"), cli_ident, host_id);
    // The viewer remembers a *different* key for this ID: must refuse.
    let wrong = Identity::generate().public_key_b64();
    let err = tokio::time::timeout(Duration::from_secs(30), connect_community(cli_cfg, Some(wrong)))
        .await
        .expect("timed out")
        .expect_err("a changed identity must be refused");
    assert!(err.to_string().contains("identity"), "unexpected error: {err}");
}

/// The DTLS-bound identity proof is checked against `expected_host_key`
/// even when the rendezvous itself was not asked to pin anything: the LAN
/// resolution succeeds, the direct link comes up, WebRTC connects, and only
/// then the proven key is compared — and refused with the dedicated error.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn wrong_expected_host_key_fails_with_identity_mismatch() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();

    let host_ident = Identity::generate();
    let host_id = host_ident.derive_id();
    let mut host_cfg = HostConfig::new(String::new(), dev_info(host_id, "host"), host_ident.clone());
    host_cfg.community = CommunityOptions {
        direct_port: 0,
        ice_udp_port: 0,
        upnp: false,
        dht: false,
        nostr_relays: vec!["ws://127.0.0.1:9".to_string()],
    };
    tokio::spawn(async move {
        let _ = serve_community(host_cfg, Arc::new(AutoAccept { allowed: Permissions::full() })).await;
    });
    tokio::time::sleep(Duration::from_millis(2000)).await;

    let cli_ident = Identity::generate();
    let mut cli_cfg = ClientConfig::new(String::new(), dev_info(cli_ident.derive_id(), "viewer"), cli_ident, host_id);
    let wrong = Identity::generate().public_key_b64();
    cli_cfg.expected_host_key = Some(wrong.clone());

    let err = tokio::time::timeout(Duration::from_secs(40), connect_community(cli_cfg, None))
        .await
        .expect("timed out")
        .expect_err("a host proving a different key must be refused");
    match err.downcast_ref::<ClientError>() {
        Some(ClientError::IdentityMismatch { expected, actual }) => {
            assert_eq!(expected, &wrong);
            assert_eq!(actual, &host_ident.public_key_b64());
        }
        other => panic!("expected IdentityMismatch, got {other:?}: {err:#}"),
    }
    // The GUI maps this to its "identity changed" alarm by message text.
    let text = format!("{err:#}");
    assert!(text.contains("identity") && text.contains("changed"), "{text}");
}
