//! Device identity: an Ed25519 keypair that uniquely and verifiably identifies
//! a CleanDesk installation, plus derivation of the human CleanDesk ID.

use crate::CryptoError;
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use ed25519_dalek::{
    pkcs8::{DecodePrivateKey, EncodePrivateKey},
    Signature, Signer, SigningKey, Verifier, VerifyingKey,
};
use rand_core::RngCore;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// A device's long-lived identity keypair.
///
/// `Clone` is deliberate: the host and viewer runtimes each need to sign the
/// registration challenge, and cloning a 32-byte seed is cheaper and simpler
/// than threading an `Arc` through every config struct.
#[derive(Clone)]
pub struct Identity {
    signing: SigningKey,
}

impl std::fmt::Debug for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print key material; the fingerprint is enough to tell identities apart.
        f.debug_struct("Identity").field("fingerprint", &self.fingerprint()).finish()
    }
}

impl Identity {
    /// Generate a brand-new random identity.
    pub fn generate() -> Self {
        let signing = SigningKey::generate(&mut crate::os_rng());
        Self { signing }
    }

    /// The public verifying key.
    pub fn public_key(&self) -> VerifyingKey {
        self.signing.verifying_key()
    }

    /// Base64 of the raw 32-byte public key, for transport in signaling.
    pub fn public_key_b64(&self) -> String {
        B64.encode(self.public_key().to_bytes())
    }

    /// A short, stable fingerprint (hex of SHA-256 of the public key, first 16
    /// bytes) shown to users for out-of-band verification.
    pub fn fingerprint(&self) -> String {
        let hash = Sha256::digest(self.public_key().to_bytes());
        hash[..16].iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join("")
    }

    /// Derive a deterministic 9-digit CleanDesk ID from the public key.
    ///
    /// Deterministic derivation means the same identity always maps to the same
    /// ID; collisions are resolved by the server at registration time.
    pub fn derive_id(&self) -> cleandesk_proto::CleanDeskId {
        derive_id_from_public_key(&self.public_key().to_bytes())
    }

    /// Sign a message with the device key.
    pub fn sign(&self, msg: &[u8]) -> Signature {
        self.signing.sign(msg)
    }

    /// Sign a message and return the signature base64-encoded, ready for a
    /// JSON signaling message.
    pub fn sign_b64(&self, msg: &[u8]) -> String {
        B64.encode(self.sign(msg).to_bytes())
    }

    /// A copy of the raw signing key, for libraries that sign with it
    /// directly (the BitTorrent DHT BEP 44 records). Handle with care.
    pub fn signing_key(&self) -> SigningKey {
        self.signing.clone()
    }

    /// The 32-byte seed, for deriving *other* keys (e.g. the Nostr secp256k1
    /// key) so the device has one identity across every rendezvous system.
    pub fn seed(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.signing.to_bytes())
    }
}

/// The CleanDesk ID that belongs to a raw 32-byte Ed25519 public key.
///
/// This is the *only* legitimate way an ID comes into existence: the server
/// recomputes it at registration and refuses a client whose claimed ID does
/// not match its key, which is what stops ID hijacking.
pub fn derive_id_from_public_key(public_key: &[u8; 32]) -> cleandesk_proto::CleanDeskId {
    let hash = Sha256::digest(public_key);
    let mut n = 0u64;
    for b in &hash[..8] {
        n = (n << 8) | *b as u64;
    }
    cleandesk_proto::CleanDeskId::generate(|| n)
}

/// Same as [`derive_id_from_public_key`], starting from the base64 form that
/// travels in signaling. Fails on malformed base64 or a wrong-length key.
pub fn derive_id_from_public_key_b64(
    public_key_b64: &str,
) -> Result<cleandesk_proto::CleanDeskId, CryptoError> {
    Ok(derive_id_from_public_key(&decode_public_key(public_key_b64)?))
}

/// Decode and validate a base64 Ed25519 public key.
pub fn decode_public_key(public_key_b64: &str) -> Result<[u8; 32], CryptoError> {
    let raw = B64
        .decode(public_key_b64)
        .map_err(|e| CryptoError::Base64(e.to_string()))?;
    let bytes: [u8; 32] = raw.try_into().map_err(|_| CryptoError::Key("bad key length".into()))?;
    // Reject points that are not valid Ed25519 keys up front, so a bogus key
    // never gets an ID assigned.
    VerifyingKey::from_bytes(&bytes).map_err(|e| CryptoError::Key(e.to_string()))?;
    Ok(bytes)
}

/// Verify a base64 signature made by a peer, given its base64 public key.
pub fn verify_b64_sig(public_key_b64: &str, msg: &[u8], sig_b64: &str) -> Result<(), CryptoError> {
    let raw = B64
        .decode(sig_b64)
        .map_err(|e| CryptoError::Base64(e.to_string()))?;
    let sig = Signature::from_slice(&raw).map_err(|_| CryptoError::AuthFailed)?;
    verify_b64(public_key_b64, msg, &sig)
}

// Kept as a separate impl block so the helpers above read as free functions
// (they are used by the server, which never holds an `Identity`).
impl Identity {

    /// Serialize the private key to PKCS#8 PEM for on-disk storage.
    ///
    /// The caller is responsible for storing this at rest with OS protection
    /// (DPAPI / restrictive ACLs); never commit it.
    pub fn to_pem(&self) -> Result<Zeroizing<String>, CryptoError> {
        self.signing
            .to_pkcs8_pem(Default::default())
            .map_err(|e| CryptoError::Key(e.to_string()))
    }

    /// Load an identity from PKCS#8 PEM.
    pub fn from_pem(pem: &str) -> Result<Self, CryptoError> {
        let signing = SigningKey::from_pkcs8_pem(pem).map_err(|e| CryptoError::Key(e.to_string()))?;
        Ok(Self { signing })
    }
}

/// Verify a signature made by a peer, given its base64 public key.
pub fn verify_b64(public_key_b64: &str, msg: &[u8], sig: &Signature) -> Result<(), CryptoError> {
    let bytes = decode_public_key(public_key_b64)?;
    let vk = VerifyingKey::from_bytes(&bytes).map_err(|e| CryptoError::Key(e.to_string()))?;
    vk.verify(msg, sig).map_err(|_| CryptoError::AuthFailed)
}

/// Generate `n` random bytes from the OS CSPRNG.
pub fn random_bytes(n: usize) -> Vec<u8> {
    let mut v = vec![0u8; n];
    crate::os_rng().fill_bytes(&mut v);
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pem_roundtrip_preserves_key() {
        let id = Identity::generate();
        let pem = id.to_pem().unwrap();
        let loaded = Identity::from_pem(&pem).unwrap();
        assert_eq!(id.public_key().to_bytes(), loaded.public_key().to_bytes());
    }

    #[test]
    fn sign_and_verify() {
        let id = Identity::generate();
        let msg = b"cleandesk-session-42";
        let sig = id.sign(msg);
        assert!(verify_b64(&id.public_key_b64(), msg, &sig).is_ok());
        assert!(verify_b64(&id.public_key_b64(), b"tampered", &sig).is_err());
    }

    #[test]
    fn derived_id_is_stable() {
        let id = Identity::generate();
        assert_eq!(id.derive_id(), id.derive_id());
    }

    #[test]
    fn server_side_derivation_matches_the_device() {
        let id = Identity::generate();
        assert_eq!(derive_id_from_public_key_b64(&id.public_key_b64()).unwrap(), id.derive_id());
        let other = Identity::generate();
        assert_ne!(derive_id_from_public_key_b64(&other.public_key_b64()).unwrap(), id.derive_id());
    }

    #[test]
    fn bogus_public_keys_are_rejected() {
        assert!(derive_id_from_public_key_b64("not base64!").is_err());
        assert!(derive_id_from_public_key_b64(&B64.encode([0u8; 31])).is_err());
        assert!(derive_id_from_public_key_b64(&B64.encode([0u8; 33])).is_err());
    }

    #[test]
    fn b64_signature_roundtrip_and_tamper_detection() {
        let id = Identity::generate();
        let msg = cleandesk_proto::message::register_proof_message(b"nonce-bytes");
        let sig = id.sign_b64(&msg);
        assert!(verify_b64_sig(&id.public_key_b64(), &msg, &sig).is_ok());
        assert!(verify_b64_sig(&id.public_key_b64(), b"other", &sig).is_err());
        assert!(verify_b64_sig(&Identity::generate().public_key_b64(), &msg, &sig).is_err());
        assert!(verify_b64_sig(&id.public_key_b64(), &msg, "garbage").is_err());
        assert!(verify_b64_sig(&id.public_key_b64(), &msg, &B64.encode([0u8; 10])).is_err());
    }

    #[test]
    fn debug_never_leaks_key_material() {
        let id = Identity::generate();
        let dbg = format!("{id:?}");
        assert!(dbg.contains(&id.fingerprint()));
        assert!(!dbg.contains(id.to_pem().unwrap().as_str()));
    }
}
