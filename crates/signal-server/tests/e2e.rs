//! End-to-end smoke test of the RotoDesk stack:
//!
//! signal server (this crate) + a real host (`rotodesk-host`) + a real viewer
//! (`rotodesk-client`), all in-process, establishing an actual WebRTC session
//! over loopback and exchanging control-plane messages.
//!
//! This exercises: WebSocket signaling, device registration & ID resolution,
//! the connect-request/accept flow, WebRTC offer/answer + ICE (host candidates
//! over loopback, so no external STUN is required), and the peer control channel
//! carrying the permissions handshake. If screen capture is available it also
//! streams video, but the assertion only requires the control-plane handshake so
//! the test is robust on headless CI.

use rotodesk_client::{connect, ClientConfig, ClientEvent};
use rotodesk_crypto::identity::Identity;
use rotodesk_host::{serve, AutoAccept, HostConfig};
use rotodesk_proto::{
    id::RotoDeskId, permissions::Permissions, quality::QualityProfile, session::DeviceInfo,
};
use std::sync::Arc;
use std::time::Duration;

fn dev_info(id: RotoDeskId, hostname: &str) -> DeviceInfo {
    DeviceInfo {
        id,
        alias: None,
        hostname: hostname.to_string(),
        os: "test".to_string(),
        app_version: "0.0.0".to_string(),
    }
}

// Full-stack smoke: drives a real WebRTC ICE negotiation + SCTP data channels
// over loopback. It tolerates hosts with many virtual adapters (ICE logs some
// "network unreachable" candidates but converges on a working pair). If a locked
// down CI cannot open UDP sockets at all, re-add `#[ignore]`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn end_to_end_connect_and_control_handshake() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();

    // 1. Signaling server on an ephemeral loopback port.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = rotodesk_signal_server::run(listener).await;
    });
    let url = format!("ws://{addr}");

    // 2. Host registers and auto-accepts (granting the intersection with `full`).
    let host_ident = Identity::generate();
    let host_id = host_ident.derive_id();
    let mut host_cfg = HostConfig::new(url.clone(), dev_info(host_id, "host"), host_ident);
    host_cfg.quality = QualityProfile::Performance;
    tokio::spawn(async move {
        let _ = serve(host_cfg, Arc::new(AutoAccept { allowed: Permissions::full() })).await;
    });

    // Give the host a moment to register with the server.
    tokio::time::sleep(Duration::from_millis(600)).await;

    // 3. Viewer connects to the host's RotoDesk ID.
    let cli_ident = Identity::generate();
    let mut cli_cfg =
        ClientConfig::new(url, dev_info(cli_ident.derive_id(), "viewer"), cli_ident, host_id);
    cli_cfg.quality = QualityProfile::Performance;

    let mut session = tokio::time::timeout(Duration::from_secs(25), connect(cli_cfg))
        .await
        .expect("connect() timed out — WebRTC did not establish")
        .expect("connect() failed");

    // 4. The control channel must deliver the permissions handshake, which proves
    //    the P2P session is fully live. A decoded frame is a bonus if capture works.
    let mut got_permissions = false;
    let mut got_frame = false;
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
            frame = session.frames.recv() => {
                if frame.is_some() { got_frame = true; }
            }
            _ = tokio::time::sleep(Duration::from_millis(200)) => {}
        }
    }

    assert!(
        got_permissions,
        "did not receive the permissions handshake over the P2P control channel"
    );
    tracing::info!(video_frame_received = got_frame, "e2e session established");

    session.disconnect();
}
