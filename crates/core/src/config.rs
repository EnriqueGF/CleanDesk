//! User-configurable settings (spec §3, §8, §9, §24).

use cleandesk_crypto::password;
use cleandesk_proto::QualityProfile;
use serde::{Deserialize, Serialize};

use crate::Result;

/// Persistent, user-editable settings for this installation.
///
/// `#[serde(default)]` at struct level: any field added in a later build is
/// simply absent from an older `appdata.json` and must take its default
/// rather than fail the whole load.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    /// Default outbound quality profile (spec §8).
    pub quality: QualityProfile,
    /// Whether this device accepts unattended connections at all. Kept
    /// separate from `unattended_password_hash` so a password can be
    /// configured ahead of time without immediately turning the feature on.
    pub unattended_enabled: bool,
    /// Argon2id PHC hash of the unattended-access password (spec §9, §18 —
    /// never stored in plaintext). `None` until the user sets one.
    pub unattended_password_hash: Option<String>,
    /// Argon2id-*derived* HMAC key used to answer the challenge/response during
    /// unattended connections. This is a derived key, **not** the password
    /// (spec §18), stored so unattended access survives restarts without keeping
    /// the plaintext. `None` until configured. 32 bytes.
    #[serde(default)]
    pub unattended_key_bytes: Option<Vec<u8>>,
    /// Launch CleanDesk when Windows starts (spec §24).
    pub start_with_windows: bool,
    /// Install/run as a background Windows service, enabling pre-login and
    /// post-logout unattended access (spec §24).
    pub install_service: bool,
    /// Optional human-friendly alias for this device (spec §3), e.g.
    /// `pc-oficina.clean`.
    pub alias: Option<String>,
}

impl Settings {
    /// Hash `password` with Argon2id and store it as the unattended-access
    /// secret. Does **not** flip [`Self::unattended_enabled`] — callers
    /// decide separately when the feature should actually be live.
    pub fn set_unattended_password(&mut self, password: &str) -> Result<()> {
        self.unattended_password_hash = Some(password::hash_password(password)?);
        Ok(())
    }

    /// Clear the stored password hash. Unattended auth then has nothing to
    /// verify against regardless of `unattended_enabled`.
    pub fn clear_unattended_password(&mut self) {
        self.unattended_password_hash = None;
    }

    /// True only when unattended access is enabled *and* `password` matches
    /// the stored Argon2id hash. Never panics: a disabled feature, a missing
    /// hash, or a hashing-library error all simply fail the check.
    pub fn verify_unattended(&self, password: &str) -> bool {
        if !self.unattended_enabled {
            return false;
        }
        match &self.unattended_password_hash {
            Some(hash) => password::verify_password(password, hash).unwrap_or(false),
            None => false,
        }
    }

    /// Enable unattended access with `password`, binding the derived key to this
    /// device's numeric CleanDesk ID. Stores the Argon2id hash (for local
    /// checks) and the derived HMAC key (for the challenge/response) — never the
    /// plaintext (spec §18).
    pub fn enable_unattended(&mut self, password: &str, host_id: u64) -> Result<()> {
        self.unattended_password_hash = Some(password::hash_password(password)?);
        self.unattended_key_bytes = Some(password::unattended_key(password, host_id)?.to_vec());
        self.unattended_enabled = true;
        Ok(())
    }

    /// Turn unattended access off and forget its secrets.
    pub fn disable_unattended(&mut self) {
        self.unattended_enabled = false;
        self.unattended_password_hash = None;
        self.unattended_key_bytes = None;
    }

    /// The derived unattended HMAC key, if the feature is enabled and configured.
    pub fn unattended_key(&self) -> Option<[u8; 32]> {
        if !self.unattended_enabled {
            return None;
        }
        self.unattended_key_bytes.as_ref()?.as_slice().try_into().ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_unattended_accepts_correct_rejects_wrong() {
        let mut settings = Settings {
            unattended_enabled: true,
            ..Default::default()
        };
        settings
            .set_unattended_password("correct horse battery staple")
            .unwrap();

        assert!(settings.verify_unattended("correct horse battery staple"));
        assert!(!settings.verify_unattended("wrong password"));
    }

    #[test]
    fn verify_unattended_false_when_feature_disabled() {
        let mut settings = Settings::default();
        settings.set_unattended_password("secret").unwrap();
        // unattended_enabled left at its default (false).
        assert!(!settings.verify_unattended("secret"));
    }

    #[test]
    fn verify_unattended_false_when_no_password_set() {
        let settings = Settings {
            unattended_enabled: true,
            ..Default::default()
        };
        assert!(!settings.verify_unattended("anything"));
    }

    #[test]
    fn clear_unattended_password_revokes_access() {
        let mut settings = Settings {
            unattended_enabled: true,
            ..Default::default()
        };
        settings.set_unattended_password("secret").unwrap();
        assert!(settings.verify_unattended("secret"));

        settings.clear_unattended_password();
        assert!(!settings.verify_unattended("secret"));
    }

    #[test]
    fn default_quality_is_auto() {
        assert_eq!(Settings::default().quality, QualityProfile::Auto);
    }

    #[test]
    fn partial_settings_json_missing_newer_fields_still_loads() {
        // An appdata.json written before `alias`, `install_service` and the
        // unattended key existed.
        let json = r#"{ "unattended_enabled": true, "start_with_windows": true }"#;
        let settings: Settings = serde_json::from_str(json).unwrap();
        assert!(settings.unattended_enabled);
        assert!(settings.start_with_windows);
        assert_eq!(settings.quality, QualityProfile::Auto);
        assert_eq!(settings.alias, None);
        assert_eq!(settings.unattended_key_bytes, None);
        assert!(!settings.install_service);

        let empty: Settings = serde_json::from_str("{}").unwrap();
        assert_eq!(empty, Settings::default());
    }
}
