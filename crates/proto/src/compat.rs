//! Compatibility identifiers from releases before the RotoDesk branding.
//! These bytes are cryptographic domain separators or migration lookups, not
//! product labels. Changing them would invalidate existing unattended keys,
//! signatures and discovery records or leave installed users behind.

pub const LEGACY_PRODUCT: &str = "CleanDesk";
pub const LEGACY_BINARY: &str = "cleandesk";
pub const LEGACY_ENV_PREFIX: &str = "CLEANDESK_";
pub const REGISTER_PROOF_PREFIX: &[u8] = b"cleandesk-register-v1:";
pub const DIRECT_PROOF_PREFIX: &[u8] = b"cleandesk-direct-v1:";
pub const SESSION_PROOF_PREFIX: &[u8] = b"cleandesk-session-v1:";
pub const UNATTENDED_SALT_NAMESPACE: &str = "cleandesk-unattended";
pub const DISCOVERY_NAMESPACE: &str = "cleandesk-v2";
pub const LEGACY_MDNS: &str = "_cleandesk._tcp.local.";
pub const LEGACY_DPAPI_MAGIC: &[u8] = b"CLEANDESK-DPAPI-1\n";
pub const TURN_USER: &str = "cleandesk";
pub const TURN_PASSWORD: &str = "cleandesk-community";

/// New variable names take precedence; older deployment configurations keep
/// working while their operators transition to ROTODESK_*.
pub fn env(name: &str) -> Result<String, std::env::VarError> {
    match std::env::var(name) {
        Err(std::env::VarError::NotPresent) if name.starts_with("ROTODESK_") => {
            std::env::var(format!("{LEGACY_ENV_PREFIX}{}", &name[9..]))
        }
        result => result,
    }
}
