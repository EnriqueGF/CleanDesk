//! Viewer → host file transfer over a real community-mode session on one
//! machine (same setup as `community_e2e`): the viewer offers a 200 KiB file,
//! the host auto-accepts (FILE_TRANSFER granted) and stores it under its
//! configured downloads directory, and the viewer sees `FileDone` only once
//! the host verified the byte count.

use cleandesk_client::{connect_community, ClientConfig, ClientEvent};
use cleandesk_crypto::identity::Identity;
use cleandesk_host::{serve_community, AutoAccept, CommunityOptions, HostConfig};
use cleandesk_proto::{id::CleanDeskId, permissions::Permissions, quality::QualityProfile, session::DeviceInfo};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

fn dev_info(id: CleanDeskId, hostname: &str) -> DeviceInfo {
    DeviceInfo { id, alias: None, hostname: hostname.to_string(), os: "test".into(), app_version: "0".into() }
}

fn scratch_dir(tag: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let dir = std::env::temp_dir().join(format!("cleandesk-{tag}-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn viewer_sends_a_file_to_the_host() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();

    let downloads = scratch_dir("downloads");
    let src_dir = scratch_dir("src");
    // 200 KiB of non-trivial content so a truncated or reordered file is caught.
    let payload: Vec<u8> = (0..200 * 1024u32).map(|i| (i.wrapping_mul(2654435761) >> 13) as u8).collect();
    let src = src_dir.join("informe (final).bin");
    std::fs::write(&src, &payload).unwrap();

    let host_ident = Identity::generate();
    let host_id = host_ident.derive_id();
    let mut host_cfg = HostConfig::new(String::new(), dev_info(host_id, "host"), host_ident.clone());
    host_cfg.quality = QualityProfile::Performance;
    host_cfg.downloads_dir = Some(downloads.clone());
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
    cli_cfg.quality = QualityProfile::Performance;
    cli_cfg.requested = Permissions::interactive() | Permissions::FILE_TRANSFER;

    let mut session = tokio::time::timeout(Duration::from_secs(40), connect_community(cli_cfg, None))
        .await
        .expect("connect_community timed out")
        .expect("connect_community failed");

    // Wait for the permission handshake so the send is not dropped locally.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(12);
    let mut granted = None;
    while tokio::time::Instant::now() < deadline && granted.is_none() {
        match tokio::time::timeout(Duration::from_millis(500), session.events.recv()).await {
            Ok(Some(ClientEvent::PermissionsUpdated(p))) => granted = Some(p),
            Ok(Some(ClientEvent::Disconnected(reason))) => panic!("disconnected early: {reason}"),
            Ok(Some(_)) | Err(_) => {}
            Ok(None) => break,
        }
    }
    let granted = granted.expect("no permissions handshake");
    assert!(granted.contains(Permissions::FILE_TRANSFER));
    assert!(session.current_permissions().contains(Permissions::FILE_TRANSFER));

    let id = session.send_file(src.clone());
    assert_eq!(id % 2, 1, "viewer transfer ids are odd");

    let mut done_path = None;
    let mut saw_progress = false;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    while tokio::time::Instant::now() < deadline && done_path.is_none() {
        match tokio::time::timeout(Duration::from_millis(500), session.events.recv()).await {
            Ok(Some(ClientEvent::FileProgress { id: pid, transferred, total })) => {
                assert_eq!(pid, id);
                assert_eq!(total, payload.len() as u64);
                assert!(transferred <= total);
                saw_progress = true;
            }
            Ok(Some(ClientEvent::FileDone { id: did, path })) => {
                assert_eq!(did, id);
                done_path = Some(path);
            }
            Ok(Some(ClientEvent::FileFailed { id: fid, reason })) => panic!("transfer {fid} failed: {reason}"),
            Ok(Some(ClientEvent::Disconnected(reason))) => panic!("disconnected: {reason}"),
            Ok(Some(_)) | Err(_) => {}
            Ok(None) => break,
        }
    }
    let done_path = done_path.expect("no FileDone within the deadline");
    assert_eq!(done_path, src, "outgoing FileDone reports the local source path");
    assert!(saw_progress);

    // The host stored it under its downloads dir with the (sanitised) name.
    let stored = downloads.join("informe (final).bin");
    let got = std::fs::read(&stored).unwrap_or_else(|e| panic!("host did not store {}: {e}", stored.display()));
    assert_eq!(got.len(), payload.len());
    assert!(got == payload, "stored bytes differ from the source");

    // A second send of the same name does not overwrite: it gets " (2)".
    let id2 = session.send_file(src.clone());
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    let mut done2 = false;
    while tokio::time::Instant::now() < deadline && !done2 {
        match tokio::time::timeout(Duration::from_millis(500), session.events.recv()).await {
            Ok(Some(ClientEvent::FileDone { id: did, .. })) if did == id2 => done2 = true,
            Ok(Some(ClientEvent::FileFailed { id: fid, reason })) => panic!("transfer {fid} failed: {reason}"),
            Ok(Some(_)) | Err(_) => {}
            Ok(None) => break,
        }
    }
    assert!(done2, "second transfer did not complete");
    let stored2 = downloads.join("informe (final) (2).bin");
    assert_eq!(std::fs::read(&stored2).expect("deduped copy").len(), payload.len());
    assert_eq!(std::fs::read(&stored).unwrap(), payload, "first copy untouched");

    session.disconnect();
    let _ = std::fs::remove_dir_all(&downloads);
    let _ = std::fs::remove_dir_all(&src_dir);
}
