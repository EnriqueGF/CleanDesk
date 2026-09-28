//! The host's rendezvous record and the deterministic keys/hashes that name
//! it in each system.
//!
//! A [`Record`] says: "device with Ed25519 key *K* (CleanDesk ID *I*) can be
//! reached for signaling at these TCP endpoints and/or this Nostr key, as of
//! time *T*". It is small (the DHT caps values at 1000 bytes), JSON encoded,
//! and carries its own Ed25519 signature so it can travel over unauthenticated
//! channels (mDNS TXT, the ID-indexed DHT slot anyone can write to).

use crate::{DiscoveryError, Result, NAMESPACE, RENDEZVOUS_VERSION};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use cleandesk_crypto::identity::{derive_id_from_public_key, verify_b64_sig, Identity};
use cleandesk_proto::CleanDeskId;
use ed25519_dalek::SigningKey;
use nostr::key::{Keys as NostrKeys, SecretKey as NostrSecretKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::net::SocketAddr;

/// Records older than this are treated as stale (host probably offline).
pub const MAX_RECORD_AGE_SECS: u64 = 45 * 60;

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
            sig: String::new(),
        };
        // Keep well under the DHT limit even with many endpoints.
        while r.ep.len() > 8 {
            r.ep.pop();
        }
        r.sig = identity.sign_b64(&r.signing_bytes());
        r
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
        h.finalize().to_vec()
    }

    /// Verify version, signature and freshness (relative to `now`).
    pub fn verify(&self, now: u64) -> Result<()> {
        if self.v != RENDEZVOUS_VERSION {
            return Err(DiscoveryError::BadRecord(format!("unsupported record version {}", self.v)));
        }
        verify_b64_sig(&self.pk, &self.signing_bytes(), &self.sig)
            .map_err(|_| DiscoveryError::BadRecord("bad signature".into()))?;
        if self.ts.saturating_add(MAX_RECORD_AGE_SECS) < now {
            return Err(DiscoveryError::BadRecord("record is stale".into()));
        }
        Ok(())
    }

    /// The CleanDesk ID this record's key derives to.
    pub fn id(&self) -> Result<CleanDeskId> {
        let pk = cleandesk_crypto::identity::decode_public_key(&self.pk)?;
        Ok(derive_id_from_public_key(&pk))
    }

    /// True if the record's key derives to `id` (the binding a viewer checks
    /// before trusting anything the record says).
    pub fn matches_id(&self, id: CleanDeskId) -> bool {
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
        Ok(cleandesk_crypto::identity::decode_public_key(&self.pk)?)
    }
}

/// The DHT "index" keypair for a CleanDesk ID: derived from the ID alone, so
/// a viewer that knows only the number can look the record up. Anyone can
/// derive it (and therefore overwrite the slot), which is why the record is
/// self-signed and checked against the ID before use.
pub fn id_index_key(id: CleanDeskId) -> SigningKey {
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
        // A record signed by another key never matches this ID.
        let other = Record::new(&ident(), None, vec![], None, 1000);
        assert!(!other.matches_id(id.derive_id()));
    }

    #[test]
    fn record_never_exceeds_dht_limit() {
        let id = ident();
        let eps: Vec<SocketAddr> = (0..40).map(|i| format!("203.0.113.{i}:65535").parse().unwrap()).collect();
        let r = Record::new(&id, Some("f".repeat(64)), eps, Some("x".repeat(500)), u64::MAX);
        assert!(r.ep.len() <= 8);
        assert!(r.alias.as_ref().unwrap().len() <= 32);
        assert!(r.to_json().unwrap().len() <= MAX_RECORD_BYTES);
        r.verify(u64::MAX).unwrap();
    }

    #[test]
    fn derived_keys_are_deterministic_and_distinct() {
        let a = CleanDeskId::new(548_291_743).unwrap();
        let b = CleanDeskId::new(548_291_744).unwrap();
        assert_eq!(id_index_key(a).to_bytes(), id_index_key(a).to_bytes());
        assert_ne!(id_index_key(a).to_bytes(), id_index_key(b).to_bytes());
        assert_eq!(relay_infohash(), relay_infohash());
        let id = ident();
        assert_eq!(nostr_keys(&id).public_key(), nostr_keys(&id).public_key());
        assert_ne!(nostr_keys(&id).public_key(), nostr_keys(&ident()).public_key());
    }
}
