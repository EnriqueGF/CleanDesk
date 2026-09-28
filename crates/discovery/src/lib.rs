//! cleandesk-discovery — rendezvous without a CleanDesk server ("modo
//! comunitario").
//!
//! The private mode keeps a CleanDesk Server in the loop for registration and
//! signaling. Community mode replaces it with public infrastructure nobody in
//! the project has to run:
//!
//! | Need | Mechanism | Module |
//! |---|---|---|
//! | Find a host on the same LAN instantly | mDNS (`_cleandesk._tcp`) | [`lan`] |
//! | Find a host anywhere from its ID | BitTorrent mainline DHT, BEP 44 mutable items | [`dht`] |
//! | Exchange SDP/ICE when the host is reachable | direct TCP link, mutual Ed25519 challenge | [`direct`] |
//! | Exchange SDP/ICE when it is not | public Nostr relays, NIP-44 encrypted ephemeral events | [`nostr_link`] |
//! | Make the host reachable through its router | UPnP/IGD port mapping | [`upnp`] |
//! | Find community relays when there is no direct route | DHT `announce_peer` on a well-known infohash | [`dht`] |
//!
//! Everything a host publishes is a signed [`Record`]; everything a viewer
//! learns is verified against the host's Ed25519 key and the CleanDesk ID
//! derived from it, so the public rendezvous systems only ever act as *hints*.
//!
//! # ID binding caveat
//!
//! A 9-digit ID carries ~30 bits, so a determined attacker can generate a key
//! whose derived ID collides with a target's in minutes. In private mode the
//! server prevents this by first-come registration; in community mode the
//! viewer pins the host's key after the first successful session (see
//! [`Record::matches_id`] and the address book) and shows the fingerprint for
//! out-of-band verification.

pub mod dht;
pub mod direct;
pub mod lan;
pub mod nostr_link;
pub mod record;
pub mod resolver;
pub mod upnp;
pub mod wol;

pub use lan::browse_all;
pub use record::Record;
pub use resolver::{Resolved, Resolver};

use thiserror::Error;

/// Crate version string, handy for diagnostics.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Errors from the rendezvous layer.
#[derive(Debug, Error)]
pub enum DiscoveryError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("crypto error: {0}")]
    Crypto(#[from] cleandesk_crypto::CryptoError),
    #[error("record rejected: {0}")]
    BadRecord(String),
    #[error("peer failed authentication: {0}")]
    AuthFailed(String),
    #[error("protocol error: {0}")]
    Protocol(String),
    #[error("timed out: {0}")]
    Timeout(&'static str),
    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, DiscoveryError>;

/// Version byte of the on-the-wire [`Record`] and of every derived key /
/// infohash below. Bump together when the format changes.
pub const RENDEZVOUS_VERSION: u8 = 1;

/// Name prefix for the mDNS service type, DHT salts and infohashes.
pub const NAMESPACE: &str = "cleandesk-v1";

/// Deadline helpers shared by the backends.
pub(crate) mod time {
    use std::time::{SystemTime, UNIX_EPOCH};

    pub fn unix_now() -> u64 {
        SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
    }
}

/// Long-term TURN credentials community relays accept from anybody. They add
/// no secrecy (the relayed traffic is DTLS end to end anyway); they exist
/// because TURN requires *some* credential and lets operators rate-limit.
pub const COMMUNITY_TURN_USER: &str = "cleandesk";
pub const COMMUNITY_TURN_PASS: &str = "cleandesk-community";

/// Default TCP port for direct signaling and UDP port for ICE in community
/// mode (both forwarded through UPnP when possible).
pub const DEFAULT_DIRECT_PORT: u16 = 7423;
pub const DEFAULT_ICE_UDP_PORT: u16 = 7424;
