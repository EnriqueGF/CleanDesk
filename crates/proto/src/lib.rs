//! CleanDesk shared protocol.
//!
//! This crate is the single source of truth for every wire-level contract in
//! CleanDesk: the [`CleanDeskId`](id::CleanDeskId) device identifier, the
//! per-session [`Permissions`](permissions::Permissions), the quality profiles,
//! the signaling messages exchanged with the CleanDesk Server, the session
//! messages exchanged peer-to-peer, and the length-delimited [`frame`] codec
//! used on data channels.
//!
//! Everything here is transport-agnostic and platform-agnostic on purpose, so
//! the client, host, signal server and relay all agree on the same types.

pub mod error;
pub mod files;
pub mod frame;
pub mod id;
pub mod media;
pub mod message;
pub mod permissions;
pub mod quality;
pub mod session;

pub use error::ProtoError;
pub use id::CleanDeskId;
pub use permissions::Permissions;
pub use quality::QualityProfile;

/// Wire protocol version. Bumped on any breaking change to the message set.
///
/// Peers exchange this during the hello handshake and refuse to proceed when
/// the major component differs.
///
/// History:
/// * 1.0 — initial message set.
/// * 1.1 — chunked video (`media::FrameChunk`).
/// * 2.0 — registration requires a signed challenge
///   (`SignalMessage::RegisterChallenge` / `RegisterProof`); older clients can
///   no longer register, hence the major bump. Also adds
///   `SessionMessage::{RequestKeyframe, Ping, Pong}`.
/// * 2.1 — `SessionMessage::RemoteAction` and the file-transfer data format
///   (`files::FileChunk` on the `files` channel).
pub const PROTOCOL_VERSION: Version = Version { major: 2, minor: 1 };

/// Default TCP port for the signaling (CleanDesk Server) WebSocket endpoint.
///
/// CleanDesk's own registered-by-convention port; not shared with any other
/// remote-desktop product.
pub const DEFAULT_SIGNAL_PORT: u16 = 7420;

/// Default UDP/TCP port for the relay (fallback) endpoint.
pub const DEFAULT_RELAY_PORT: u16 = 7421;

/// A semantic-ish protocol version. Only `major` gates compatibility.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Version {
    pub major: u16,
    pub minor: u16,
}

impl Version {
    /// Two versions are compatible when their major numbers match.
    pub fn compatible_with(self, other: Version) -> bool {
        self.major == other.major
    }
}

impl core::fmt::Display for Version {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}.{}", self.major, self.minor)
    }
}
