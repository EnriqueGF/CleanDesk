//! rotodesk-discovery — rendezvous without a RotoDesk server ("modo
//! comunitario").
//!
//! The private mode keeps a RotoDesk Server in the loop for registration and
//! signaling. Community mode replaces it with public infrastructure nobody in
//! the project has to run:
//!
//! | Need | Mechanism | Module |
//! |---|---|---|
//! | Find a host on the same LAN instantly | mDNS (`_rotodesk._tcp`) | [`lan`] |
//! | Find a host anywhere from its ID | BitTorrent mainline DHT, BEP 44 mutable items | [`dht`] |
//! | Exchange SDP/ICE when the host is reachable | direct TCP link, mutual Ed25519 challenge | [`direct`] |
//! | Exchange SDP/ICE when it is not | public Nostr relays, NIP-44 encrypted ephemeral events | [`nostr_link`] |
//! | Make the host reachable through its router | UPnP/IGD port mapping | [`upnp`] |
//! | Find community relays when there is no direct route | DHT `announce_peer` on a well-known infohash | [`dht`] |
//!
//! Everything a host publishes is a signed [`Record`]; everything a viewer
//! learns is verified against the host's Ed25519 key and the RotoDesk ID
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
pub use record::{Record, RelayRecord};
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
    Crypto(#[from] rotodesk_crypto::CryptoError),
    #[error("record rejected: {0}")]
    BadRecord(String),
    #[error("peer failed authentication: {0}")]
    AuthFailed(String),
    /// Several valid records signed by *different* keys claim the same ID
    /// (a 9-digit ID is only ~30 bits, so a collision can be manufactured).
    /// Nothing was chosen: the caller must refuse or ask the user to verify a
    /// fingerprint and pin the right key.
    #[error("several keys claim this id ({} candidates); verify the fingerprint and pin the right key", keys.len())]
    AmbiguousIdentity {
        /// Base64 public keys seen, newest record first.
        keys: Vec<String>,
    },
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
///
/// History: v1 signed the same challenge message as the server registration
/// (a host's direct handshake signature could be replayed to register its ID
/// on a RotoDesk Server); v2 binds the direct proof to both keys and the
/// role, bounds a record's clock skew, and requires signed relay records.
pub const RENDEZVOUS_VERSION: u8 = 2;

/// Name prefix for the mDNS service type, DHT salts and infohashes.
pub const NAMESPACE: &str = rotodesk_proto::compat::DISCOVERY_NAMESPACE;

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
/// The trade-off (an open relay anyone can use as a UDP proxy) is what the
/// relay's peer-address filter and per-allocation quotas bound; see
/// `docs/SECURITY.md`.
pub const COMMUNITY_TURN_USER: &str = rotodesk_proto::compat::TURN_USER;
pub const COMMUNITY_TURN_PASS: &str = rotodesk_proto::compat::TURN_PASSWORD;

/// Default TCP port for direct signaling and UDP port for ICE in community
/// mode (both forwarded through UPnP when possible).
pub const DEFAULT_DIRECT_PORT: u16 = 7423;
pub const DEFAULT_ICE_UDP_PORT: u16 = 7424;

/// Address-class checks shared by every path that turns a peer-supplied
/// address into a connection attempt. A DHT record, a relay announcement or
/// an mDNS reply names *some* address; nothing about it proves the address
/// is what it claims to be, so the kind of address must fit the source.
pub mod addr {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    /// Loopback, link-local, RFC 1918 / ULA, carrier-grade NAT.
    pub fn is_private(ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => v4_private(v4),
            IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
                Some(v4) => v4_private(v4),
                None => v6_private(v6),
            },
        }
    }

    fn v4_private(v4: Ipv4Addr) -> bool {
        let o = v4.octets();
        v4.is_loopback() || v4.is_link_local() || v4.is_private() || (o[0] == 100 && (64..=127).contains(&o[1]))
    }

    fn v6_private(v6: Ipv6Addr) -> bool {
        let s = v6.segments();
        v6.is_loopback() || (s[0] & 0xffc0) == 0xfe80 || (s[0] & 0xfe00) == 0xfc00
    }

    /// Never worth a packet: unspecified, multicast, broadcast, the zero
    /// network, documentation and benchmarking ranges.
    pub fn is_bogus(ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => {
                let o = v4.octets();
                v4.is_unspecified()
                    || v4.is_broadcast()
                    || v4.is_multicast()
                    || v4.is_documentation()
                    || o[0] == 0
                    || (o[0] == 198 && (o[1] == 18 || o[1] == 19))
                    || o[0] >= 240
            }
            IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
                Some(v4) => is_bogus(IpAddr::V4(v4)),
                None => v6.is_unspecified() || v6.is_multicast() || (v6.segments()[0] == 0x2001 && v6.segments()[1] == 0x0db8),
            },
        }
    }

    /// Reachable across the Internet: neither bogus nor private.
    pub fn is_global(ip: IpAddr) -> bool {
        !is_bogus(ip) && !is_private(ip)
    }

    /// Acceptable as a *LAN* endpoint (learned from mDNS): a private or
    /// link-local unicast address, never loopback.
    pub fn is_lan(ip: IpAddr) -> bool {
        !is_bogus(ip) && is_private(ip) && !ip.is_loopback()
    }

    /// Acceptable as a direct endpoint from a signed record: global, or a
    /// private one (a host may list its LAN address for viewers nearby).
    pub fn is_dialable(ip: IpAddr) -> bool {
        !is_bogus(ip) && !ip.is_loopback()
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn ip(s: &str) -> IpAddr {
            s.parse().unwrap()
        }

        #[test]
        fn classes() {
            assert!(!is_global(ip("203.0.113.5")), "TEST-NET-3 is documentation");
            assert!(is_global(ip("8.8.8.8")));
            assert!(is_global(ip("2606:4700::1111")));
            for s in ["10.0.0.1", "192.168.1.1", "172.16.0.1", "169.254.1.1", "100.64.0.1", "fd00::1", "fe80::1", "::ffff:10.1.2.3"] {
                assert!(is_private(ip(s)), "{s}");
                assert!(!is_global(ip(s)), "{s}");
                assert!(is_lan(ip(s)), "{s}");
                assert!(is_dialable(ip(s)), "{s}");
            }
            for s in ["0.0.0.0", "255.255.255.255", "224.0.0.1", "198.18.0.1", "240.0.0.1", "::", "ff02::1", "2001:db8::1"] {
                assert!(is_bogus(ip(s)), "{s}");
                assert!(!is_dialable(ip(s)), "{s}");
                assert!(!is_lan(ip(s)), "{s}");
            }
            assert!(!is_dialable(ip("127.0.0.1")));
            assert!(!is_lan(ip("127.0.0.1")));
            assert!(!is_lan(ip("8.8.8.8")));
        }
    }
}
