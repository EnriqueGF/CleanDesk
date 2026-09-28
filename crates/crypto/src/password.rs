//! Unattended-access password hashing with Argon2id.
//!
//! The spec is explicit (section 18): unattended credentials must never be
//! stored in plaintext. We store only the Argon2id PHC string and verify
//! against it in constant time.

use crate::CryptoError;
use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};

/// Hash an unattended password into a PHC string suitable for on-disk storage.
pub fn hash_password(password: &str) -> Result<String, CryptoError> {
    let salt = SaltString::generate(&mut argon2::password_hash::rand_core::OsRng);
    let argon = Argon2::default();
    argon
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| CryptoError::Password(e.to_string()))
}

/// Verify a candidate password against a stored PHC hash.
pub fn verify_password(password: &str, phc: &str) -> Result<bool, CryptoError> {
    let parsed = PasswordHash::new(phc).map_err(|e| CryptoError::Password(e.to_string()))?;
    Ok(Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok())
}

/// Derive a fixed-length symmetric key from a password + salt, for the auth
/// [`proof`](crate::proof) HMAC. Uses Argon2id as the KDF.
pub fn derive_key(password: &str, salt: &[u8]) -> Result<[u8; 32], CryptoError> {
    let mut out = [0u8; 32];
    Argon2::default()
        .hash_password_into(password.as_bytes(), salt, &mut out)
        .map_err(|e| CryptoError::Password(e.to_string()))?;
    Ok(out)
}

/// Derive the shared key for CleanDesk unattended-access authentication.
///
/// The salt is bound to the host's numeric CleanDesk ID so that both the host
/// and the connecting viewer derive the *same* key from the shared password,
/// without any secret salt needing to be exchanged.
pub fn unattended_key(password: &str, host_id: u64) -> Result<[u8; 32], CryptoError> {
    let salt = format!("cleandesk-unattended-{host_id}");
    derive_key(password, salt.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_verifies_correctly() {
        let phc = hash_password("correct horse").unwrap();
        assert!(verify_password("correct horse", &phc).unwrap());
        assert!(!verify_password("wrong", &phc).unwrap());
    }

    #[test]
    fn derive_key_is_deterministic_per_salt() {
        let salt = b"0123456789abcdef";
        let a = derive_key("pw", salt).unwrap();
        let b = derive_key("pw", salt).unwrap();
        assert_eq!(a, b);
        let c = derive_key("pw2", salt).unwrap();
        assert_ne!(a, c);
    }
}
