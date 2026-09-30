//! The host's rendezvous record and the deterministic keys/hashes that name
//! it in each system.
//!
//! A [`Record`] says: "device with Ed25519 key *K* (RotoDesk ID *I*) can be
//! reached for signaling at these TCP endpoints and/or this Nostr key, as of
//! time *T*". It is small (the DHT caps values at 1000 bytes), JSON encoded,
//! and carries its own Ed25519 signature so it can travel over unauthenticated
//! channels (mDNS TXT, the ID-indexed DHT slot anyone can write to).

use crate::{DiscoveryError, Result, NAMESPACE, RENDEZVOUS_VERSION};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use rotodesk_crypto::identity::{derive_id_from_public_key, verify_b64_sig, Identity};
use rotodesk_proto::RotoDeskId;
use ed25519_dalek::SigningKey;
use nostr::key::{Keys as NostrKeys, SecretKey as NostrSecretKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::net::SocketAddr;

/// Records older than this are treated as stale (host probably offline).
pub const MAX_RECORD_AGE_SECS: u64 = 45 * 60;

/// Records dated more than this far in the future are rejected. Without an
/// upper bound a record with `ts = u64::MAX` would never go stale and, being
/// "newest", would win every by-ID lookup forever.
pub const MAX_FUTURE_SKEW_SECS: u64 = 5 * 60;

/// Version of the signed [`RelayRecord`]. Before it existed relays announced
/// only an unauthenticated `announce_peer` on the infohash.
pub const RELAY_RECORD_VERSION: u8 = 1;

/// Upper bound the DHT enforces on a mutable value.
pub const MAX_RECORD_BYTES: usize = 1000;

/// Signed rendezvous information published by a host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Record {
    /// [`RENDEZVOUS_VERSION`].
    pub v: u8,
    /// Ed25519 public key, base64.
    pub pk: String,
    /// Nostr (secp256k1 x-only) public key, hex; where encrypted signaling
    /// events for this host must be addressed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nostr: Option<String>,
    /// Direct signaling endpoints (TCP), most preferred first.
    #[serde(default)]
    pub ep: Vec<SocketAddr>,
    /// Unix seconds when this record was produced.
    pub ts: u64,
    /// Optional human alias, truncated to keep the record small.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alias: Option<String>,
    /// MAC address of the host's primary adapter (`AA:BB:CC:DD:EE:FF`), so a
    /// viewer that finds the record can Wake-on-LAN the machine later.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mac: Option<String>,
    /// Ed25519 signature (base64) over [`Record::signing_bytes`].
    #[serde(default)]
    pub sig: String,
}

impl Record {
    /// Build and sign a record for `identity`.
    pub fn new(
        identity: &Identity,
        nostr_pubkey_hex: Option<String>,
        endpoints: Vec<SocketAddr>,
        alias: Option<String>,
        ts: u64,
    ) -> Self {
        let mut r = Self {
            v: RENDEZVOUS_VERSION,
            pk: identity.public_key_b64(),
            nostr: nostr_pubkey_hex,
            ep: endpoints,
            ts,
            alias: alias.map(|a| a.chars().take(32).collect()),
            mac: None,
            sig: String::new(),
        };
        // Keep well under the DHT limit even with many endpoints.
        while r.ep.len() > 8 {
            r.ep.pop();
        }
        r.sig = identity.sign_b64(&r.signing_bytes());
        r
    }

    /// Set (or clear) the MAC address and re-sign. `identity` must be the
    /// same key the record was built for, or verification fails afterwards.
    pub fn set_mac(&mut self, identity: &Identity, mac: Option<String>) {
        self.mac = mac.map(|m| m.chars().take(17).collect());
        self.sig = identity.sign_b64(&self.signing_bytes());
    }

    /// Canonical bytes covered by the signature (everything but `sig`).
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut h = Sha256::new();
        h.update(NAMESPACE.as_bytes());
        h.update([self.v]);
        h.update(self.pk.as_bytes());
        h.update([0]);
        h.update(self.nostr.as_deref().unwrap_or("").as_bytes());
        h.update([0]);
        for ep in &self.ep {
            h.update(ep.to_string().as_bytes());
            h.update([0]);
        }
        h.update(self.ts.to_le_bytes());
        h.update(self.alias.as_deref().unwrap_or("").as_bytes());
        // Records from before the MAC field hashed nothing past the alias; an
        // absent MAC keeps that exact input so old signatures stay valid.
        if let Some(mac) = &self.mac {
            h.update([0]);
            h.update(mac.as_bytes());
        }
        h.finalize().to_vec()
    }

    /// Verify version, signature and freshness (relative to `now`).
    pub fn verify(&self, now: u64) -> Result<()> {
        if self.v != RENDEZVOUS_VERSION {
            return Err(DiscoveryError::BadRecord(format!("unsupported record version {}", self.v)));
        }
        verify_b64_sig(&self.pk, &self.signing_bytes(), &self.sig)
            .map_err(|_| DiscoveryError::BadRecord("bad signature".into()))?;
        check_freshness(self.ts, now)
    }

    /// The RotoDesk ID this record's key derives to.
    pub fn id(&self) -> Result<RotoDeskId> {
        let pk = rotodesk_crypto::identity::decode_public_key(&self.pk)?;
        Ok(derive_id_from_public_key(&pk))
    }

    /// True if the record's key derives to `id` (the binding a viewer checks
    /// before trusting anything the record says).
    pub fn matches_id(&self, id: RotoDeskId) -> bool {
        self.id().map(|mine| mine == id).unwrap_or(false)
    }

    pub fn to_json(&self) -> Result<Vec<u8>> {
        let bytes = serde_json::to_vec(self)?;
        if bytes.len() > MAX_RECORD_BYTES {
            return Err(DiscoveryError::BadRecord(format!("record too large: {} bytes", bytes.len())));
        }
        Ok(bytes)
    }

    pub fn from_json(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_RECORD_BYTES {
            return Err(DiscoveryError::BadRecord("record too large".into()));
        }
        Ok(serde_json::from_slice(bytes)?)
    }

    pub fn public_key_bytes(&self) -> Result<[u8; 32]> {
        Ok(rotodesk_crypto::identity::decode_public_key(&self.pk)?)
    }
}

/// Stale or too-far-in-the-future timestamps are both rejected.
fn check_freshness(ts: u64, now: u64) -> Result<()> {
    if ts.saturating_add(MAX_RECORD_AGE_SECS) < now {
        return Err(DiscoveryError::BadRecord("record is stale".into()));
    }
    if ts > now.saturating_add(MAX_FUTURE_SKEW_SECS) {
        return Err(DiscoveryError::BadRecord("record is dated in the future".into()));
    }
    Ok(())
}

/// What a community relay publishes about itself: "the relay with Ed25519
/// key *K* serves TURN at `addr`, as of *T*", signed by *K*. Stored as a
/// BEP 44 mutable item under [`relay_index_key`]`(addr)` so a client that
/// learned `addr` from the (unauthenticated) `get_peers` directory can fetch
/// and verify it before handing the address to ICE.
///
/// What it proves: the record was produced by the holder of `pk` and names
/// that exact address, so the relay has a stable identity clients can pin or
/// block and a stranger cannot inject arbitrary addresses by `announce_peer`
/// alone. What it does **not** prove: that `pk`'s owner controls `addr` (the
/// DHT cannot attest that); a hostile operator can still run a relay.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayRecord {
    /// [`RELAY_RECORD_VERSION`].
    pub v: u8,
    /// The relay's Ed25519 public key, base64.
    pub pk: String,
    /// Public TURN endpoint (`host:port`, UDP).
    pub addr: SocketAddr,
    /// Unix seconds when produced.
    pub ts: u64,
    /// Ed25519 signature (base64) over [`RelayRecord::signing_bytes`].
    #[serde(default)]
    pub sig: String,
}

impl RelayRecord {
    pub fn new(identity: &Identity, addr: SocketAddr, ts: u64) -> Self {
        let mut r = Self { v: RELAY_RECORD_VERSION, pk: identity.public_key_b64(), addr, ts, sig: String::new() };
        r.sig = identity.sign_b64(&r.signing_bytes());
        r
    }

    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut h = Sha256::new();
        h.update(NAMESPACE.as_bytes());
        h.update(b":relay-record:");
        h.update([self.v]);
        h.update(self.pk.as_bytes());
        h.update([0]);
        h.update(self.addr.to_string().as_bytes());
        h.update([0]);
        h.update(self.ts.to_le_bytes());
        h.finalize().to_vec()
    }

    /// Verify version, signature, freshness and — when the record was fetched
    /// for a particular address — that it names that address.
    pub fn verify(&self, now: u64, expected_addr: Option<SocketAddr>) -> Result<()> {
        if self.v != RELAY_RECORD_VERSION {
            return Err(DiscoveryError::BadRecord(format!("unsupported relay record version {}", self.v)));
        }
        verify_b64_sig(&self.pk, &self.signing_bytes(), &self.sig)
            .map_err(|_| DiscoveryError::BadRecord("bad relay record signature".into()))?;
        if let Some(expected) = expected_addr {
            if self.addr != expected {
                return Err(DiscoveryError::BadRecord("relay record names another address".into()));
            }
        }
        check_freshness(self.ts, now)
    }

    pub fn to_json(&self) -> Result<Vec<u8>> {
        let bytes = serde_json::to_vec(self)?;
        if bytes.len() > MAX_RECORD_BYTES {
            return Err(DiscoveryError::BadRecord(format!("relay record too large: {} bytes", bytes.len())));
        }
        Ok(bytes)
    }

    pub fn from_json(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_RECORD_BYTES {
            return Err(DiscoveryError::BadRecord("relay record too large".into()));
        }
        Ok(serde_json::from_slice(bytes)?)
    }
}

/// The DHT index keypair for a relay address: derived from `host:port`
/// alone so a client can look the relay's signed record up knowing only the
/// address `get_peers` returned. Anyone can write the slot, which is why the
/// record inside is self-signed and must name the same address.
pub fn relay_index_key(addr: SocketAddr) -> SigningKey {
    let mut h = Sha256::new();
    h.update(NAMESPACE.as_bytes());
    h.update(b":relay-index:");
    h.update(addr.to_string().as_bytes());
    let seed: [u8; 32] = h.finalize().into();
    SigningKey::from_bytes(&seed)
}

/// Salt for [`RelayRecord`] items.
pub fn relay_record_salt() -> Vec<u8> {
    format!("{NAMESPACE}:relay-record").into_bytes()
}

/// The DHT "index" keypair for a RotoDesk ID: derived from the ID alone, so
/// a viewer that knows only the number can look the record up. Anyone can
/// derive it (and therefore overwrite the slot), which is why the record is
/// self-signed and checked against the ID before use.
pub fn id_index_key(id: RotoDeskId) -> SigningKey {
    let mut h = Sha256::new();
    h.update(NAMESPACE.as_bytes());
    h.update(b":id-index:");
    h.update(id.value().to_le_bytes());
    let seed: [u8; 32] = h.finalize().into();
    SigningKey::from_bytes(&seed)
}

/// Salt used for the record stored under the host's *real* key.
pub fn record_salt() -> Vec<u8> {
    format!("{NAMESPACE}:record").into_bytes()
}

/// 20-byte infohash under which community relays announce themselves.
pub fn relay_infohash() -> [u8; 20] {
    let h = Sha256::digest(format!("{NAMESPACE}:relay").as_bytes());
    let mut out = [0u8; 20];
    out.copy_from_slice(&h[..20]);
    out
}

/// Nostr key for a device: secp256k1 secret derived from the Ed25519 seed,
/// so one identity covers both systems without storing a second key.
pub fn nostr_keys(identity: &Identity) -> NostrKeys {
    let mut h = Sha256::new();
    h.update(NAMESPACE.as_bytes());
    h.update(b":nostr:");
    h.update(identity.seed());
    let mut secret: [u8; 32] = h.finalize().into();
    // A SHA-256 output is a valid secp256k1 scalar with overwhelming
    // probability; loop for the astronomically unlikely exception.
    loop {
        if let Ok(sk) = NostrSecretKey::from_slice(&secret) {
            return NostrKeys::new(sk);
        }
        secret = Sha256::digest(secret).into();
    }
}

/// The message a device signs to bind its Nostr key to its Ed25519 identity.
pub fn nostr_binding_message(nostr_pubkey_hex: &str) -> Vec<u8> {
    format!("{NAMESPACE}:nostr-binding:{nostr_pubkey_hex}").into_bytes()
}

/// Encode a public key for TXT records / JSON.
pub fn b64(bytes: &[u8]) -> String {
    B64.encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ident() -> Identity {
        Identity::generate()
    }

    #[test]
    fn record_roundtrip_and_verify() {
        let id = ident();
        let r = Record::new(
            &id,
            Some("ab".repeat(32)),
            vec!["192.168.1.10:7423".parse().unwrap(), "203.0.113.5:7423".parse().unwrap()],
            Some("Laptop".into()),
            1_000_000,
        );
        let bytes = r.to_json().unwrap();
        assert!(bytes.len() < MAX_RECORD_BYTES);
        let back = Record::from_json(&bytes).unwrap();
        assert_eq!(back, r);
        back.verify(1_000_000 + 60).unwrap();
        assert!(back.matches_id(id.derive_id()));
        assert_eq!(back.id().unwrap(), id.derive_id());
    }

    #[test]
    fn tampering_or_staleness_is_rejected() {
        let id = ident();
        let r = Record::new(&id, None, vec!["10.0.0.1:1".parse().unwrap()], None, 1000);
        let mut t = r.clone();
        t.ep.push("10.0.0.2:2".parse().unwrap());
        assert!(t.verify(1000).is_err(), "endpoint tampering must break the signature");
        let mut t = r.clone();
        t.nostr = Some("00".repeat(32));
        assert!(t.verify(1000).is_err());
        let mut t = r.clone();
        t.ts += 1;
        assert!(t.verify(1000).is_err());
        assert!(r.verify(1000 + MAX_RECORD_AGE_SECS + 1).is_err(), "stale");
        assert!(r.verify(1000 + MAX_RECORD_AGE_SECS).is_ok());
        // A record dated too far ahead of the viewer's clock is rejected: it
        // would otherwise never expire and always be "the newest".
        assert!(r.verify(1000 - MAX_FUTURE_SKEW_SECS).is_ok(), "small skew tolerated");
        assert!(r.verify(1000 - MAX_FUTURE_SKEW_SECS - 1).is_err(), "future-dated");
        let far = Record::new(&id, None, vec![], None, u64::MAX);
        assert!(far.verify(1000).is_err(), "u64::MAX ts must not win forever");
        // A record signed by another key never matches this ID.
        let other = Record::new(&ident(), None, vec![], None, 1000);
        assert!(!other.matches_id(id.derive_id()));
    }

    #[test]
    fn mac_roundtrips_and_is_signed() {
        let id = ident();
        let mut r = Record::new(&id, None, vec!["10.0.0.1:1".parse().unwrap()], Some("pc".into()), 1000);
        let without = String::from_utf8(r.to_json().unwrap()).unwrap();
        assert!(!without.contains("\"mac\""), "absent mac is not serialised");
        r.set_mac(&id, Some("AA:BB:CC:DD:EE:FF".into()));
        let bytes = r.to_json().unwrap();
        let back = Record::from_json(&bytes).unwrap();
        assert_eq!(back, r);
        assert_eq!(back.mac.as_deref(), Some("AA:BB:CC:DD:EE:FF"));
        back.verify(1000).unwrap();
        // Tampering with the MAC (or removing it) must break the signature.
        let mut t = r.clone();
        t.mac = Some("AA:BB:CC:DD:EE:00".into());
        assert!(t.verify(1000).is_err());
        let mut t = r.clone();
        t.mac = None;
        assert!(t.verify(1000).is_err());
        // Adding a MAC to a record signed without one is tampering too.
        let mut t = Record::new(&id, None, vec![], None, 1000);
        t.mac = Some("AA:BB:CC:DD:EE:FF".into());
        assert!(t.verify(1000).is_err());
        // Clearing it through the API re-signs.
        r.set_mac(&id, None);
        r.verify(1000).unwrap();
        assert!(r.mac.is_none());
    }

    #[test]
    fn record_never_exceeds_dht_limit() {
        let id = ident();
        let eps: Vec<SocketAddr> = (0..40).map(|i| format!("203.0.113.{i}:65535").parse().unwrap()).collect();
        let mut r = Record::new(&id, Some("f".repeat(64)), eps, Some("x".repeat(500)), u64::MAX);
        r.set_mac(&id, Some("F".repeat(100)));
        assert!(r.ep.len() <= 8);
        assert!(r.alias.as_ref().unwrap().len() <= 32);
        assert!(r.mac.as_ref().unwrap().len() <= 17);
        assert!(r.to_json().unwrap().len() <= MAX_RECORD_BYTES);
        r.verify(u64::MAX).unwrap();
    }

    #[test]
    fn relay_record_roundtrip_binding_and_tampering() {
        let relay = ident();
        let addr: SocketAddr = "203.0.113.7:7421".parse().unwrap();
        let r = RelayRecord::new(&relay, addr, 5000);
        let back = RelayRecord::from_json(&r.to_json().unwrap()).unwrap();
        assert_eq!(back, r);
        back.verify(5000, Some(addr)).unwrap();
        back.verify(5000, None).unwrap();
        // Fetched under another address's index slot: refused even if valid.
        assert!(back.verify(5000, Some("203.0.113.8:7421".parse().unwrap())).is_err());
        let mut t = r.clone();
        t.addr = "203.0.113.8:7421".parse().unwrap();
        assert!(t.verify(5000, None).is_err(), "address is signed");
        let mut t = r.clone();
        t.pk = ident().public_key_b64();
        assert!(t.verify(5000, None).is_err(), "key swap breaks the signature");
        let mut t = r.clone();
        t.v = 0;
        assert!(t.verify(5000, None).is_err(), "old unsigned-era version refused");
        assert!(r.verify(5000 + MAX_RECORD_AGE_SECS + 1, None).is_err(), "stale");
        assert!(r.verify(5000 - MAX_FUTURE_SKEW_SECS - 1, None).is_err(), "future");
        assert_eq!(relay_index_key(addr).to_bytes(), relay_index_key(addr).to_bytes());
        assert_ne!(relay_index_key(addr).to_bytes(), relay_index_key("203.0.113.7:7422".parse().unwrap()).to_bytes());
    }

    #[test]
    fn derived_keys_are_deterministic_and_distinct() {
        let a = RotoDeskId::new(548_291_743).unwrap();
        let b = RotoDeskId::new(548_291_744).unwrap();
        assert_eq!(id_index_key(a).to_bytes(), id_index_key(a).to_bytes());
        assert_ne!(id_index_key(a).to_bytes(), id_index_key(b).to_bytes());
        assert_eq!(relay_infohash(), relay_infohash());
        let id = ident();
        assert_eq!(nostr_keys(&id).public_key(), nostr_keys(&id).public_key());
        assert_ne!(nostr_keys(&id).public_key(), nostr_keys(&ident()).public_key());
    }
}
