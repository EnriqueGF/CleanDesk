//! Wire-format contract tests.
//!
//! Every message that rides `postcard` must survive an encode/decode round
//! trip *and* keep its variant index stable: postcard is not self-describing,
//! so the numeric tags in `EXPECTED_SESSION_TAGS` below are effectively part of
//! `PROTOCOL_VERSION`. If one of these assertions fails you changed the wire
//! format — bump the version and update the table on purpose, never by
//! accident.

use cleandesk_proto::{
    frame::{decode_payload, encode_payload, encode_vec, FrameCodec},
    id::CleanDeskId,
    files::{FileChunk, MAX_CHUNK_DATA},
    media::FrameChunk,
    message::{
        ClipboardData, FileTransferMsg, InputEvent, MonitorInfo, MouseButton, RemoteAction,
        SessionMessage, VideoFrame,
    },
    permissions::Permissions,
    quality::QualityProfile,
    session::{DeviceInfo, SessionStats},
    Version, PROTOCOL_VERSION,
};

fn device() -> DeviceInfo {
    DeviceInfo {
        id: CleanDeskId::new(548_291_743).unwrap(),
        alias: Some("pc-oficina.clean".into()),
        hostname: "OFICINA-PC".into(),
        os: "Windows 11 Pro".into(),
        app_version: "0.1.0".into(),
    }
}

fn stats() -> SessionStats {
    SessionStats {
        rtt_ms: 12,
        fps: 30,
        width: 1920,
        height: 1080,
        bandwidth_kbps: 4200,
        direct: true,
        codec: "tile-zstd".into(),
    }
}

/// One instance of every `SessionMessage` variant, in declaration order.
fn every_session_message() -> Vec<SessionMessage> {
    vec![
        SessionMessage::Hello { protocol: PROTOCOL_VERSION, info: device() },
        SessionMessage::AuthChallenge { challenge_b64: "Y2hhbGxlbmdl".into() },
        SessionMessage::AuthResponse { response_b64: "cmVzcG9uc2U=".into() },
        SessionMessage::AuthResult { ok: true },
        SessionMessage::PermissionsUpdate { granted: Permissions::interactive() },
        SessionMessage::SetQuality { profile: QualityProfile::Performance },
        SessionMessage::Stats(stats()),
        SessionMessage::Chat { text: "hola ✓ ñ".into() },
        SessionMessage::Clipboard(ClipboardData::Text { content: "https://example.invalid".into() }),
        SessionMessage::File(FileTransferMsg::Offer {
            transfer_id: 7,
            name: "informe.pdf".into(),
            size: 1 << 20,
            is_dir: false,
        }),
        SessionMessage::SelectMonitor { index: 1 },
        SessionMessage::Monitors {
            monitors: vec![MonitorInfo {
                index: 0,
                width: 2560,
                height: 1440,
                primary: true,
                origin_x: 0,
                origin_y: 0,
            }],
        },
        SessionMessage::Disconnect { reason: "viewer closed".into() },
        SessionMessage::Heartbeat,
        SessionMessage::RequestKeyframe,
        SessionMessage::Ping { nonce: 0xDEAD_BEEF_CAFE },
        SessionMessage::Pong { nonce: 0xDEAD_BEEF_CAFE },
        SessionMessage::RemoteAction { action: RemoteAction::LockLocalInput { locked: true } },
        SessionMessage::IdentityProof {
            public_key_b64: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into(),
            signature_b64: "c2ln".into(),
        },
        SessionMessage::PasteClipboard { content: "Texto con ñ y 日本語\nsegunda línea".into() },
    ]
}

/// postcard variant tags (the first byte of each encoded message), pinned.
const EXPECTED_SESSION_TAGS: [u8; 20] =
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19];

/// Every `RemoteAction`, in declaration order, with its pinned tag.
fn every_remote_action() -> Vec<RemoteAction> {
    vec![
        RemoteAction::RestartMachine,
        RemoteAction::LockWorkstation,
        RemoteAction::LockLocalInput { locked: false },
        RemoteAction::SecureAttention,
    ]
}
const EXPECTED_REMOTE_ACTION_TAGS: [u8; 4] = [0, 1, 2, 3];

/// Every `FileTransferMsg`, in declaration order, with its pinned tag.
fn every_file_msg() -> Vec<FileTransferMsg> {
    vec![
        FileTransferMsg::Offer { transfer_id: 1, name: "a.bin".into(), size: 3, is_dir: false },
        FileTransferMsg::Accept { transfer_id: 1 },
        FileTransferMsg::Cancel { transfer_id: 1 },
        FileTransferMsg::Progress { transfer_id: 1, transferred: 2 },
        FileTransferMsg::Complete { transfer_id: 1 },
        FileTransferMsg::Refused { transfer_id: 1, reason: "too large".into() },
    ]
}
const EXPECTED_FILE_TAGS: [u8; 6] = [0, 1, 2, 3, 4, 5];

#[test]
fn every_session_message_roundtrips_through_postcard() {
    for msg in every_session_message() {
        let bytes = encode_payload(&msg).expect("encode");
        let back: SessionMessage = decode_payload(&bytes).expect("decode");
        assert_eq!(msg, back);
    }
}

#[test]
fn session_message_variant_tags_are_stable() {
    let msgs = every_session_message();
    assert_eq!(msgs.len(), EXPECTED_SESSION_TAGS.len(), "add new variants to both lists");
    for (msg, expected) in msgs.iter().zip(EXPECTED_SESSION_TAGS) {
        let bytes = encode_payload(msg).unwrap();
        assert_eq!(bytes[0], expected, "variant index changed for {msg:?}");
    }
}

#[test]
fn remote_action_and_file_msg_tags_are_stable() {
    let actions = every_remote_action();
    assert_eq!(actions.len(), EXPECTED_REMOTE_ACTION_TAGS.len());
    for (a, expected) in actions.iter().zip(EXPECTED_REMOTE_ACTION_TAGS) {
        let bytes = encode_payload(a).unwrap();
        assert_eq!(bytes[0], expected, "variant index changed for {a:?}");
        assert_eq!(decode_payload::<RemoteAction>(&bytes).unwrap(), *a);
        // Nested inside the session envelope too.
        let msg = SessionMessage::RemoteAction { action: *a };
        let bytes = encode_payload(&msg).unwrap();
        assert_eq!(bytes[0], 17);
        assert_eq!(decode_payload::<SessionMessage>(&bytes).unwrap(), msg);
    }
    let files = every_file_msg();
    assert_eq!(files.len(), EXPECTED_FILE_TAGS.len());
    for (m, expected) in files.iter().zip(EXPECTED_FILE_TAGS) {
        let bytes = encode_payload(m).unwrap();
        assert_eq!(bytes[0], expected, "variant index changed for {m:?}");
        let msg = SessionMessage::File(m.clone());
        let bytes = encode_payload(&msg).unwrap();
        assert_eq!(decode_payload::<SessionMessage>(&bytes).unwrap(), msg);
    }
}

#[test]
fn file_chunk_roundtrips_and_fits_a_channel_message() {
    let chunk = FileChunk { transfer_id: 9, offset: 1 << 40, data: vec![7; MAX_CHUNK_DATA] };
    let bytes = encode_payload(&chunk).unwrap();
    assert!(bytes.len() <= 16 * 1024);
    assert_eq!(decode_payload::<FileChunk>(&bytes).unwrap(), chunk);
    assert!(decode_payload::<FileChunk>(&bytes[..bytes.len() - 1]).is_err());
}

#[test]
fn every_input_event_roundtrips() {
    let events = [
        InputEvent::MouseMove { x: 0.25, y: 0.75 },
        InputEvent::MouseButton { button: MouseButton::Left, pressed: true },
        InputEvent::MouseButton { button: MouseButton::Forward, pressed: false },
        InputEvent::MouseScroll { delta_x: -1.5, delta_y: 3.0 },
        InputEvent::Key { code: 0x41, pressed: true },
    ];
    for ev in events {
        let bytes = encode_payload(&ev).unwrap();
        let back: InputEvent = decode_payload(&bytes).unwrap();
        assert_eq!(ev, back);
    }
}

#[test]
fn frame_chunk_and_video_frame_roundtrip() {
    let vf = VideoFrame {
        sequence: 42,
        width: 1280,
        height: 720,
        keyframe: false,
        timestamp_us: 1_234_567,
        data: (0..300u32).map(|x| x as u8).collect(),
    };
    let bytes = encode_payload(&vf).unwrap();
    assert_eq!(decode_payload::<VideoFrame>(&bytes).unwrap(), vf);

    let chunk = FrameChunk {
        seq: 42,
        index: 3,
        count: 9,
        keyframe: true,
        width: 1280,
        height: 720,
        timestamp_us: 1,
        payload: vec![1, 2, 3],
    };
    let bytes = encode_payload(&chunk).unwrap();
    assert_eq!(decode_payload::<FrameChunk>(&bytes).unwrap(), chunk);
}

#[test]
fn garbage_and_truncated_payloads_error_instead_of_panicking() {
    assert!(decode_payload::<SessionMessage>(&[]).is_err());
    assert!(decode_payload::<SessionMessage>(&[0xFF, 0xFF, 0xFF]).is_err());
    let good = encode_payload(&SessionMessage::Chat { text: "x".repeat(50) }).unwrap();
    for cut in 1..good.len() {
        assert!(decode_payload::<SessionMessage>(&good[..cut]).is_err(), "cut at {cut}");
    }
    // Trailing bytes after a complete message are also rejected: a message is
    // exactly one channel send, never a prefix of one.
    let mut padded = good.clone();
    padded.push(0);
    assert!(decode_payload::<SessionMessage>(&padded).is_err());
}

#[test]
fn frame_codec_splits_concatenated_frames() {
    let a = SessionMessage::Heartbeat;
    let b = SessionMessage::Ping { nonce: 9 };
    let mut stream = encode_vec(&a).unwrap();
    stream.extend(encode_vec(&b).unwrap());
    let mut codec = FrameCodec::new();
    codec.feed(&stream);
    assert_eq!(codec.next_message::<SessionMessage>().unwrap(), Some(a));
    assert_eq!(codec.next_message::<SessionMessage>().unwrap(), Some(b));
    assert_eq!(codec.next_message::<SessionMessage>().unwrap(), None);
}

#[test]
fn permissions_roundtrip_in_both_codecs_and_ignore_unknown_bits_safely() {
    let p = Permissions::interactive() | Permissions::FILE_TRANSFER;
    let bin = encode_payload(&p).unwrap();
    assert_eq!(decode_payload::<Permissions>(&bin).unwrap(), p);
    let json = serde_json::to_string(&p).unwrap();
    assert_eq!(serde_json::from_str::<Permissions>(&json).unwrap(), p);
}

#[test]
fn version_compatibility_is_major_only() {
    let v = Version { major: PROTOCOL_VERSION.major, minor: PROTOCOL_VERSION.minor + 5 };
    assert!(PROTOCOL_VERSION.compatible_with(v));
    let v = Version { major: PROTOCOL_VERSION.major + 1, minor: 0 };
    assert!(!PROTOCOL_VERSION.compatible_with(v));
    assert_eq!(Version { major: 2, minor: 1 }.to_string(), "2.1");
    assert_eq!(PROTOCOL_VERSION, Version { major: 2, minor: 4 });
}

#[test]
fn cleandesk_id_edge_cases() {
    // Non-digit noise is stripped, but a completely non-numeric string fails.
    assert!(CleanDeskId::parse("abc").is_err());
    assert!(CleanDeskId::parse("").is_err());
    assert_eq!(CleanDeskId::parse(" 548.291.743 ").unwrap().value(), 548_291_743);
    // Leading zeros can't make a valid 9-digit ID.
    assert!(CleanDeskId::parse("000 000 001").is_err());
    // Ten digits are accepted (future headroom) and still group in threes.
    let ten = CleanDeskId::new(1_234_567_890).unwrap();
    assert_eq!(ten.to_string(), "1 234 567 890");
    // Eleven digits overflow the allowed range.
    assert!(CleanDeskId::new(12_345_678_901).is_err());
    // A huge numeric string doesn't panic on u64 overflow either.
    assert!(CleanDeskId::parse("99999999999999999999999").is_err());
}

#[test]
fn reject_reasons_roundtrip_in_json_and_postcard() {
    use cleandesk_proto::message::RejectReason;
    for r in [
        RejectReason::UserDeclined,
        RejectReason::Busy,
        RejectReason::AuthFailed,
        RejectReason::PermissionsDenied,
        RejectReason::Timeout,
        RejectReason::UnattendedOnly,
    ] {
        let json = serde_json::to_string(&r).unwrap();
        assert_eq!(serde_json::from_str::<RejectReason>(&json).unwrap(), r);
        let bin = encode_payload(&r).unwrap();
        assert_eq!(decode_payload::<RejectReason>(&bin).unwrap(), r);
    }
    assert_eq!(serde_json::to_string(&RejectReason::UnattendedOnly).unwrap(), "\"unattended_only\"");
}
