//! Cryptographic primitives for RotoDesk.
//!
//! Scope (spec section 18):
//! * [`identity`] — a per-device Ed25519 keypair (the device's cryptographic
//!   identity) with a stable fingerprint, plus RotoDesk ID generation.
//! * [`password`] — Argon2id hashing for the *unattended access* password, so
//!   it is never stored in plaintext.
//! * [`token`] — random, expiring session tokens for trusted devices.
//! * [`proof`] — an HMAC challenge/response the host uses to verify a caller
//!   knows the unattended password, without the password crossing the wire.
//! * [`session`] — the session channel-binding proof: an Ed25519 signature
//!   over the session id and both DTLS fingerprints, so the identity is tied
//!   to the actual encrypted channel and a rendezvous cannot sit in the middle.
//!
//! Transport encryption itself (DTLS/SRTP) is provided by the WebRTC stack in
//! `rotodesk-transport`; this crate covers identity and authentication.

pub mod identity;
pub mod password;
pub mod proof;
pub mod session;
pub mod token;

use thiserror::Error;

/// Errors from cryptographic operations.
#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("key encode/decode failed: {0}")]
    Key(String),
    #[error("password hashing failed: {0}")]
    Password(String),
    #[error("authentication failed")]
    AuthFailed,
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("base64 decode failed: {0}")]
    Base64(String),
}

/// A cryptographically secure random source used across this crate.
pub fn os_rng() -> rand::rngs::OsRng {
    rand::rngs::OsRng
}
