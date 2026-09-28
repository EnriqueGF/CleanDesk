//! cleandesk-transport
//!
//! The transport backbone shared by the CleanDesk host and client:
//!
//! * [`SignalingClient`] — speaks JSON [`SignalMessage`](cleandesk_proto::message::SignalMessage)
//!   over a WebSocket to the CleanDesk Server (registration, connection
//!   requests, and SDP/ICE relay).
//! * [`PeerConnection`] — a WebRTC peer connection (ICE/STUN/TURN + DTLS) with
//!   the four named data channels ([`Channel`]) CleanDesk sessions use.
//!
//! Both are implemented from public standards (WebRTC, ICE/STUN/TURN,
//! WebSocket); the wire contract itself lives in `cleandesk-proto`.

pub mod error;
pub mod peer;
pub mod signaling;

pub use error::TransportError;
pub use peer::{Channel, IceConfig, PeerConnection, TurnServer};
pub use signaling::{ChallengeSigner, SignalingClient};

/// Crate version string, handy for diagnostics.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
