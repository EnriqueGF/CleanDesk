//! Random, expiring session tokens for trusted devices (spec sections 10, 18).

use crate::{identity::random_bytes, CryptoError};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

/// A bearer token that lets a previously trusted device reconnect without
/// interactive approval, until it expires.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionToken {
    /// Opaque random value, base64url.
    pub value: String,
    /// Absolute expiry, Unix seconds.
    pub expires_at: u64,
}

impl SessionToken {
    /// Mint a new token valid for `ttl_secs` from now.
    pub fn issue(ttl_secs: u64) -> Self {
        let value = B64.encode(random_bytes(32));
        Self { value, expires_at: now() + ttl_secs }
    }

    /// True if the token is still within its validity window.
    pub fn is_valid(&self) -> bool {
        now() < self.expires_at
    }

    /// Constant-time comparison against a presented token value.
    pub fn matches(&self, presented: &str) -> bool {
        if !self.is_valid() {
            return false;
        }
        ct_eq(self.value.as_bytes(), presented.as_bytes())
    }
}

/// Verify a presented token against a set of stored tokens, dropping expired
/// ones. Returns whether any valid token matched.
pub fn verify_any(stored: &[SessionToken], presented: &str) -> bool {
    stored.iter().any(|t| t.matches(presented))
}

fn now() -> u64 {
    // A clock before the epoch is broken; treat "now" as the far future so
    // every token reads as expired rather than as valid forever.
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(u64::MAX)
}

/// Constant-time byte-slice equality (length mismatch short-circuits: the
/// length of a bearer token is not secret).
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    a.len() == b.len() && bool::from(a.ct_eq(b))
}

impl From<base64::DecodeError> for CryptoError {
    fn from(e: base64::DecodeError) -> Self {
        CryptoError::Base64(e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_token_is_valid_and_matches_itself() {
        let t = SessionToken::issue(3600);
        assert!(t.is_valid());
        assert!(t.matches(&t.value));
        assert!(!t.matches("nope"));
    }

    #[test]
    fn expired_token_never_matches() {
        let t = SessionToken { value: "abc".into(), expires_at: 0 };
        assert!(!t.is_valid());
        assert!(!t.matches("abc"));
    }
}
