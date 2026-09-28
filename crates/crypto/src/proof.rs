//! Challenge/response proof of knowledge for the unattended password.
//!
//! Flow (the **host** is the verifier; the signaling server only relays):
//! 1. The caller wants unattended access. The host issues a random `challenge`.
//! 2. Both sides derive `key = Argon2id(password, salt)` where `salt` is tied to
//!    the host identity (stable, non-secret).
//! 3. The caller sends `response = HMAC-SHA256(key, challenge)`.
//! 4. The host recomputes and compares in constant time.
//!
//! The plaintext password never crosses the wire. Note: because the server
//! *relays* challenge+response, a malicious server could mount an offline
//! dictionary attack; the MVP accepts this (the server is first-party infra)
//! and a PAKE (e.g. SPAKE2/OPAQUE) is the planned post-MVP upgrade — tracked in
//! docs/SECURITY.md.

use crate::identity::random_bytes;
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// A random challenge issued by the host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Challenge(pub [u8; 32]);

impl Challenge {
    /// Issue a fresh random challenge.
    pub fn issue() -> Self {
        let mut c = [0u8; 32];
        c.copy_from_slice(&random_bytes(32));
        Self(c)
    }

    /// Base64 for transport.
    pub fn to_b64(&self) -> String {
        B64.encode(self.0)
    }

    /// Parse from base64.
    pub fn from_b64(s: &str) -> Option<Self> {
        let bytes = B64.decode(s).ok()?;
        let arr: [u8; 32] = bytes.try_into().ok()?;
        Some(Self(arr))
    }
}

/// Compute the response for a derived key and challenge, base64-encoded.
pub fn respond(key: &[u8; 32], challenge: &Challenge) -> String {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(&challenge.0);
    B64.encode(mac.finalize().into_bytes())
}

/// Verify a base64 response against the expected key + challenge (constant-time).
pub fn verify(key: &[u8; 32], challenge: &Challenge, response_b64: &str) -> bool {
    let Ok(got) = B64.decode(response_b64) else {
        return false;
    };
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(&challenge.0);
    // `verify_slice` compares in constant time and rejects a wrong-length tag.
    mac.verify_slice(&got).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::password::derive_key;

    #[test]
    fn correct_password_proves() {
        let salt = b"host-identity-salt-16";
        let key = derive_key("hunter2", salt).unwrap();
        let challenge = Challenge::issue();
        let response = respond(&key, &challenge);
        assert!(verify(&key, &challenge, &response));
    }

    #[test]
    fn wrong_password_fails() {
        let salt = b"host-identity-salt-16";
        let good = derive_key("hunter2", salt).unwrap();
        let bad = derive_key("wrong", salt).unwrap();
        let challenge = Challenge::issue();
        let response = respond(&bad, &challenge);
        assert!(!verify(&good, &challenge, &response));
    }

    #[test]
    fn challenge_b64_roundtrips() {
        let c = Challenge::issue();
        assert_eq!(Challenge::from_b64(&c.to_b64()), Some(c));
    }

    #[test]
    fn malformed_responses_never_verify() {
        let key = [7u8; 32];
        let challenge = Challenge::issue();
        assert!(!verify(&key, &challenge, ""));
        assert!(!verify(&key, &challenge, "not base64!"));
        assert!(!verify(&key, &challenge, &B64.encode([0u8; 31])));
        assert!(!verify(&key, &challenge, &B64.encode([0u8; 32])));
        // A valid response for a *different* challenge is a replay and must fail.
        let other = Challenge::issue();
        assert!(!verify(&key, &challenge, &respond(&key, &other)));
    }

    #[test]
    fn challenges_are_random_and_fixed_length() {
        assert_ne!(Challenge::issue(), Challenge::issue());
        assert!(Challenge::from_b64(&B64.encode([1u8; 31])).is_none());
        assert!(Challenge::from_b64("").is_none());
    }
}
