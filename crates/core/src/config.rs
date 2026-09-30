//! User-configurable settings (spec §3, §8, §9, §24).

/// Shortest unattended-access password accepted (characters).
pub const MIN_UNATTENDED_PASSWORD_LEN: usize = 10;

use rotodesk_crypto::password;
use rotodesk_proto::QualityProfile;
use serde::{Deserialize, Serialize};

use crate::Result;

/// Persistent, user-editable settings for this installation.
///
/// `#[serde(default)]` at struct level: any field added in a later build is
/// simply absent from an older `appdata.json` and must take its default
/// rather than fail the whole load.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
    /// Launch RotoDesk when Windows starts (spec §24).
    pub start_with_windows: bool,
    /// Install/run as a background Windows service, enabling pre-login and
    /// post-logout unattended access (spec §24).
    pub install_service: bool,
    /// Optional human-friendly alias for this device (spec §3), e.g.
    /// `pc-oficina.roto`.
    pub alias: Option<String>,
    /// How this device finds and is found by peers.
    #[serde(default)]
    pub network: NetworkMode,
    /// Trust-on-first-use pins: RotoDesk ID (numeric) → Ed25519 public key
    /// (base64) seen in the first successful session. In community mode a
    /// different key under the same ID is refused (see `rotodesk-discovery`).
    #[serde(default)]
    pub pinned_keys: std::collections::BTreeMap<u64, String>,
    /// UI language as a BCP-47-ish tag (`"en"`, `"es"`). `None` follows the
    /// system locale.
    #[serde(default)]
    pub language: Option<String>,
    /// Closing the main window hides it to the system tray instead of quitting
    /// (the host keeps serving). Default on.
    #[serde(default = "default_true")]
    pub minimize_to_tray: bool,
    /// Look for new releases on GitHub at startup and every few hours, and
    /// offer to install them (the download is verified against the
    /// published checksums). Default on.
    #[serde(default = "default_true")]
    pub check_updates: bool,
    /// Privileged control (spec §24): let viewers drive administrator windows
    /// and UAC prompts. With the RotoDesk service installed the service hosts
    /// as LocalSystem; otherwise the app relaunches itself elevated. Off by
    /// default because it prompts for elevation at startup.
    #[serde(default)]
    pub privileged_control: bool,
    /// Keep retrying a lost outgoing session every five seconds. Opt-in.
    #[serde(default)]
    pub auto_reconnect: bool,
}

/// Rendezvous mode.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum NetworkMode {
    /// No server: LAN mDNS, the BitTorrent DHT and public Nostr relays.
    #[default]
    Community,
    /// A private RotoDesk Server (companies, closed networks).
    Server { url: String },
}

fn default_true() -> bool {
    true
}

// Manual `Default` so that in-memory defaults and serde's field defaults agree
// (`minimize_to_tray` is on unless the user turned it off).
impl Default for Settings {
    fn default() -> Self {
        Self {
            quality: QualityProfile::default(),
            unattended_enabled: false,
            unattended_password_hash: None,
            unattended_key_bytes: None,
            start_with_windows: false,
            install_service: false,
            alias: None,
            network: NetworkMode::default(),
            pinned_keys: Default::default(),
            language: None,
            minimize_to_tray: true,
            check_updates: true,
            privileged_control: false,
            auto_reconnect: false,
        }
    }
}

impl NetworkMode {
    pub fn is_community(&self) -> bool {
        matches!(self, NetworkMode::Community)
    }

    pub fn server_url(&self) -> Option<&str> {
        match self {
            NetworkMode::Server { url } => Some(url),
            NetworkMode::Community => None,
        }
    }
}

impl Settings {
    /// The pinned key for `id`, if any.
    pub fn pinned_key(&self, id: rotodesk_proto::RotoDeskId) -> Option<&str> {
        self.pinned_keys.get(&id.value()).map(String::as_str)
    }

    /// Remember `key` for `id`. Returns `true` if it was new or changed.
    pub fn pin_key(&mut self, id: rotodesk_proto::RotoDeskId, key: &str) -> bool {
        self.pinned_keys.insert(id.value(), key.to_string()).as_deref() != Some(key)
    }

    /// Forget the pin for `id` (the user verified a legitimate identity change).
    pub fn unpin_key(&mut self, id: rotodesk_proto::RotoDeskId) -> bool {
        self.pinned_keys.remove(&id.value()).is_some()
    }

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
    /// device's numeric RotoDesk ID. Stores the Argon2id hash (for local
    /// checks) and the derived HMAC key (for the challenge/response) — never the
    /// plaintext (spec §18).
    pub fn enable_unattended(&mut self, password: &str, host_id: u64) -> Result<()> {
        // The derived key is stored on disk and answers an offline-crackable
        // challenge; a short password would fall in minutes.
        if password.chars().count() < MIN_UNATTENDED_PASSWORD_LEN {
            return Err(crate::CoreError::WeakPassword(MIN_UNATTENDED_PASSWORD_LEN));
        }
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
