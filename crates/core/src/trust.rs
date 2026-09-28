//! Trusted-device registry (spec §10): "permitir siempre, recordar permisos,
//! no pedir confirmación, permitir desatendido".

use cleandesk_crypto::token::{verify_any, SessionToken};
use cleandesk_proto::CleanDeskId;
use serde::{Deserialize, Serialize};

/// The trust policy for one previously-approved device, plus any bearer
/// tokens it has been issued for unattended reconnection (spec §18).
///
/// Every policy flag is `#[serde(default)]` — i.e. *off* when absent — so
/// an entry from an older `appdata.json` can only ever load with fewer
/// privileges than it was saved with, never more.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustedDevice {
    pub id: CleanDeskId,
    /// Always allow connections from this device without a per-request prompt.
    #[serde(default)]
    pub always_allow: bool,
    /// Remember (and reapply) the last granted permission set.
    #[serde(default)]
    pub remember_permissions: bool,
    /// Never show the accept/reject confirmation dialog at all.
    #[serde(default)]
    pub no_confirm: bool,
    /// This device may use unattended auth even when it would otherwise be
    /// gated behind interactive approval.
    #[serde(default)]
    pub allow_unattended: bool,
    /// Issued session tokens (bearer reconnection, spec §18).
    #[serde(default)]
    pub tokens: Vec<SessionToken>,
}

impl TrustedDevice {
    /// A newly trusted device with every policy flag off — the caller opts
    /// each one in explicitly.
    pub fn new(id: CleanDeskId) -> Self {
        Self {
            id,
            always_allow: false,
            remember_permissions: false,
            no_confirm: false,
            allow_unattended: false,
            tokens: Vec::new(),
        }
    }

    pub fn add_token(&mut self, token: SessionToken) {
        self.tokens.push(token);
    }

    /// Drop expired tokens from this device's list.
    pub fn prune_expired_tokens(&mut self) {
        self.tokens.retain(SessionToken::is_valid);
    }

    /// Prune expired tokens, then check whether `presented` matches a
    /// remaining live one.
    pub fn verify_token(&mut self, presented: &str) -> bool {
        self.prune_expired_tokens();
        verify_any(&self.tokens, presented)
    }
}

/// The set of devices this installation has chosen to trust.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct TrustRegistry {
    pub devices: Vec<TrustedDevice>,
}

impl TrustRegistry {
    pub fn is_trusted(&self, id: CleanDeskId) -> bool {
        self.get(id).is_some()
    }

    pub fn get(&self, id: CleanDeskId) -> Option<&TrustedDevice> {
        self.devices.iter().find(|d| d.id == id)
    }

    pub fn get_mut(&mut self, id: CleanDeskId) -> Option<&mut TrustedDevice> {
        self.devices.iter_mut().find(|d| d.id == id)
    }

    /// Insert a new trust entry, or replace the existing one for the same device.
    pub fn set(&mut self, device: TrustedDevice) {
        match self.get_mut(device.id) {
            Some(existing) => *existing = device,
            None => self.devices.push(device),
        }
    }

    pub fn remove(&mut self, id: CleanDeskId) -> Option<TrustedDevice> {
        let idx = self.devices.iter().position(|d| d.id == id)?;
        Some(self.devices.remove(idx))
    }

    // Policy lookups (spec §10). Each defaults to `false` for an untrusted or
    // unknown device, so callers never need a separate `is_trusted` guard.

    pub fn always_allow(&self, id: CleanDeskId) -> bool {
        self.get(id).is_some_and(|d| d.always_allow)
    }

    pub fn remember_permissions(&self, id: CleanDeskId) -> bool {
        self.get(id).is_some_and(|d| d.remember_permissions)
    }

    pub fn no_confirm(&self, id: CleanDeskId) -> bool {
        self.get(id).is_some_and(|d| d.no_confirm)
    }

    pub fn allow_unattended(&self, id: CleanDeskId) -> bool {
        self.get(id).is_some_and(|d| d.allow_unattended)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id() -> CleanDeskId {
        CleanDeskId::new(548_291_743).unwrap()
    }

    #[test]
    fn unknown_device_is_not_trusted_and_every_policy_is_false() {
        let reg = TrustRegistry::default();
        assert!(!reg.is_trusted(id()));
        assert!(!reg.always_allow(id()));
        assert!(!reg.remember_permissions(id()));
        assert!(!reg.no_confirm(id()));
        assert!(!reg.allow_unattended(id()));
    }

    #[test]
    fn set_then_lookup_policy_flags() {
        let mut reg = TrustRegistry::default();
        let mut dev = TrustedDevice::new(id());
        dev.always_allow = true;
        dev.allow_unattended = true;
        reg.set(dev);

        assert!(reg.is_trusted(id()));
        assert!(reg.always_allow(id()));
        assert!(reg.allow_unattended(id()));
        assert!(!reg.no_confirm(id()));
        assert!(!reg.remember_permissions(id()));
    }

    #[test]
    fn set_replaces_existing_entry() {
        let mut reg = TrustRegistry::default();
        reg.set(TrustedDevice::new(id()));
        let mut replacement = TrustedDevice::new(id());
        replacement.no_confirm = true;
        reg.set(replacement);

        assert_eq!(reg.devices.len(), 1);
        assert!(reg.no_confirm(id()));
    }

    #[test]
    fn remove_deletes_entry() {
        let mut reg = TrustRegistry::default();
        reg.set(TrustedDevice::new(id()));
        assert!(reg.remove(id()).is_some());
        assert!(!reg.is_trusted(id()));
    }

    #[test]
    fn token_verification_prunes_expired_and_matches_live() {
        let mut dev = TrustedDevice::new(id());
        dev.add_token(SessionToken {
            value: "expired".into(),
            expires_at: 0,
        });
        let live = SessionToken::issue(3600);
        dev.add_token(live.clone());

        assert!(dev.verify_token(&live.value));
        assert!(!dev.verify_token("expired"));
        assert_eq!(dev.tokens.len(), 1, "expired token should have been pruned");
    }
}
