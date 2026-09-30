//! Every `SignalMessage` variant must survive a JSON round-trip unchanged.
//!
//! `SignalMessage` has no `PartialEq`, so instead of comparing values we compare
//! the parsed JSON (`serde_json::Value`, which is order-independent for objects):
//! encode the original, decode it, re-encode the decoded value, and assert the
//! two JSON documents are equal. Any field the decoder dropped or altered shows
//! up as a mismatch.

use rotodesk_proto::{
    id::RotoDeskId,
    message::{
        AuthKind, AuthProof, ErrorCode, RejectReason, SignalMessage, SignalPayload,
    },
    permissions::Permissions,
    quality::QualityProfile,
    session::DeviceInfo,
    PROTOCOL_VERSION,
};
use uuid::Uuid;

fn device() -> DeviceInfo {
    DeviceInfo {
        id: RotoDeskId::new(548_291_743).expect("valid id"),
        alias: Some("pc-oficina.roto".to_string()),
        hostname: "OFICINA-PC".to_string(),
        os: "Windows 11 Pro".to_string(),
        app_version: "0.1.0".to_string(),
    }
}

fn id() -> RotoDeskId {
    RotoDeskId::new(100_200_300).expect("valid id")
}

fn session() -> Uuid {
    Uuid::from_u128(0x1234_5678_9abc_def0_1122_3344_5566_7788)
}

/// Encode -> decode -> re-encode, comparing the two JSON documents.
fn assert_roundtrip(msg: &SignalMessage) {
    let json = serde_json::to_string(msg).expect("serialize");
    let decoded: SignalMessage = serde_json::from_str(&json).expect("deserialize");
    let reencoded = serde_json::to_string(&decoded).expect("re-serialize");

    let before: serde_json::Value = serde_json::from_str(&json).unwrap();
    let after: serde_json::Value = serde_json::from_str(&reencoded).unwrap();
    assert_eq!(before, after, "round-trip changed the message: {json}");
}

#[test]
fn every_signal_message_variant_roundtrips() {
    let messages = vec![
        SignalMessage::Register {
            device: device(),
            protocol: PROTOCOL_VERSION,
            public_key: "TWFuIGlzIGRpc3Rpbmd1aXNoZWQ=".to_string(),
        },
        SignalMessage::Registered { id: id() },
        SignalMessage::ConnectRequest {
            target: id(),
            from: device(),
            requested: Permissions::interactive(),
            quality: QualityProfile::Balanced,
            auth_proof: None,
        },
        SignalMessage::ConnectRequest {
            target: id(),
            from: device(),
            requested: Permissions::full(),
            quality: QualityProfile::Performance,
            auth_proof: Some(AuthProof {
                challenge_id: "chal-42".to_string(),
                response: "c2lnbmF0dXJl".to_string(),
            }),
        },
        SignalMessage::IncomingRequest {
            session: session(),
            from: device(),
            requested: Permissions::VIEW_ONLY,
            quality: QualityProfile::Auto,
            auth: AuthKind::UnattendedPassword,
        },
        SignalMessage::IncomingRequest {
            session: session(),
            from: device(),
            requested: Permissions::interactive(),
            quality: QualityProfile::Max,
            auth: AuthKind::Trusted,
        },
        SignalMessage::Accept {
            session: session(),
            granted: Permissions::interactive(),
        },
        SignalMessage::Reject {
            session: session(),
            reason: RejectReason::UserDeclined,
        },
        SignalMessage::Reject {
            session: session(),
            reason: RejectReason::AuthFailed,
        },
        SignalMessage::Signal {
            session: session(),
            payload: SignalPayload::Offer {
                sdp: "v=0\r\no=- 42 2 IN IP4 127.0.0.1\r\n".to_string(),
            },
        },
        SignalMessage::Signal {
            session: session(),
            payload: SignalPayload::Answer {
                sdp: "v=0\r\no=- 24 2 IN IP4 127.0.0.1\r\n".to_string(),
            },
        },
        SignalMessage::Signal {
            session: session(),
            payload: SignalPayload::IceCandidate {
                candidate: "candidate:1 1 udp 2130706431 192.168.1.10 54321 typ host".to_string(),
                sdp_mid: Some("0".to_string()),
                sdp_mline_index: Some(0),
            },
        },
        SignalMessage::Signal {
            session: session(),
            payload: SignalPayload::IceCandidate {
                candidate: "candidate:2 1 udp 1694498815 203.0.113.7 40000 typ srflx".to_string(),
                sdp_mid: None,
                sdp_mline_index: None,
            },
        },
        SignalMessage::Error {
            code: ErrorCode::TargetOffline,
            detail: "no such device".to_string(),
        },
        SignalMessage::Error {
            code: ErrorCode::VersionMismatch,
            detail: "server 1.0, client 2.0".to_string(),
        },
        SignalMessage::Ping { nonce: 0xDEAD_BEEF },
        SignalMessage::Pong { nonce: 0xDEAD_BEEF },
        SignalMessage::PresenceQuery { devices: vec![id()] },
        SignalMessage::PresenceSnapshot { online: vec![id()] },
    ];

    for msg in &messages {
        assert_roundtrip(msg);
    }
}

/// Spot-check that the wire tag is what the server expects (snake_case `type`).
#[test]
fn tags_are_snake_case() {
    let json = serde_json::to_string(&SignalMessage::ConnectRequest {
        target: id(),
        from: device(),
        requested: Permissions::interactive(),
        quality: QualityProfile::Auto,
        auth_proof: None,
    })
    .unwrap();
    let value: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(value["type"], "connect_request");

    let signal = serde_json::to_string(&SignalMessage::Signal {
        session: session(),
        payload: SignalPayload::IceCandidate {
            candidate: "candidate:x".to_string(),
            sdp_mid: None,
            sdp_mline_index: None,
        },
    })
    .unwrap();
    let value: serde_json::Value = serde_json::from_str(&signal).unwrap();
    assert_eq!(value["type"], "signal");
    assert_eq!(value["payload"]["kind"], "ice_candidate");
}
