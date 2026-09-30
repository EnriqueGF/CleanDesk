//! Library error type for the transport crate.
//!
//! The public async API surfaces [`anyhow::Result`] (as the crate contract
//! prescribes), but the *meaningful*, matchable failure modes are modeled here
//! with `thiserror` so callers can downcast when they need to distinguish, say,
//! a registration timeout from a hard rejection.

use crate::Channel;
use cleandesk_proto::message::ErrorCode;
use std::time::Duration;

/// Errors produced by the signaling client and the WebRTC peer connection.
#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    /// The signaling WebSocket is gone: the writer/reader task has exited.
    #[error("signaling connection closed")]
    SignalingClosed,

    /// Plaintext `ws://` towards a server outside the local network.
    #[error("refusing plaintext signaling to {0}: use wss:// (or set CLEANDESK_ALLOW_INSECURE_SIGNALING=1 on a trusted network)")]
    InsecureSignaling(String),

    /// The server did not confirm registration within the allotted time.
    #[error("registration timed out after {0:?}")]
    RegisterTimeout(Duration),

    /// The server answered `Register` with an `Error` frame.
    #[error("server rejected registration ({code:?}): {detail}")]
    RegisterRejected { code: ErrorCode, detail: String },

    /// A `send` targeted a data channel that has not been opened (or was named
    /// with a label the peer never created).
    #[error("data channel {0:?} is not available")]
    ChannelUnavailable(Channel),

    /// The peer connection reached a terminal state before becoming connected.
    #[error("peer connection did not reach the connected state: {0}")]
    NotConnected(&'static str),

    /// The peer connection did not become connected within the allowed time.
    #[error("peer connection timed out after {0:?}")]
    ConnectTimeout(Duration),

    /// A single-shot receiver (`events()`, `incoming()`, `ice_candidates()`)
    /// was requested twice. An API-usage error, reported instead of panicking
    /// because it surfaces inside session code paths.
    #[error("{0}() can only be called once")]
    AlreadyTaken(&'static str),

    /// The server deviated from the registration protocol.
    #[error("registration protocol error: {0}")]
    RegisterProtocol(String),

    /// The DTLS certificate fingerprints are not available yet (no
    /// description set, or the handshake has not completed).
    #[error("DTLS fingerprint unavailable: {0}")]
    FingerprintUnavailable(&'static str),
}
