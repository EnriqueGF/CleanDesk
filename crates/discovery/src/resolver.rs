//! Viewer-side resolution: turn a CleanDesk ID into something dialable.
//!
//! Order (fastest and most trustworthy first):
//! 1. LAN (mDNS) — instant, no Internet.
//! 2. DHT by key — when the address book already knows the host's key.
//! 3. DHT by ID — first contact over the Internet.
//!
//! Every result is a verified [`Record`] (signature valid, key derives to the
//! ID, fresh). If a pinned key is supplied and the record's key differs, the
//! result is refused: that is the "the host's identity changed" alarm.

use crate::dht::DhtNode;
use crate::lan;
use crate::record::Record;
use crate::{time::unix_now, DiscoveryError, Result};
use cleandesk_proto::CleanDeskId;
use std::net::SocketAddr;
use std::time::Duration;
use tracing::{info, warn};

/// How long to wait for a LAN answer before going to the DHT.
pub const LAN_TIMEOUT: Duration = Duration::from_millis(2500);

/// Where a host was found and how to reach it.
#[derive(Debug, Clone)]
pub struct Resolved {
    pub record: Record,
    /// Direct signaling endpoints to try, in order.
    pub endpoints: Vec<SocketAddr>,
    /// Human label for the UI ("LAN", "DHT").
    pub via: &'static str,
}

/// Resolution strategy holder.
pub struct Resolver {
    dht: Option<DhtNode>,
}

impl Resolver {
    pub fn new(dht: Option<DhtNode>) -> Self {
        Self { dht }
    }

    /// Resolve `id`. `pinned_key` is the base64 key remembered from a previous
    /// session, if any.
    pub async fn resolve(&self, id: CleanDeskId, pinned_key: Option<&str>) -> Result<Resolved> {
        // 1. LAN. Without a DHT this is the only path, so wait longer.
        let lan_budget = if self.dht.is_some() { LAN_TIMEOUT } else { LAN_TIMEOUT * 3 };
        if let Some(peer) = lan::find(id, lan_budget).await {
            match self.check_pin(&peer.public_key, pinned_key) {
                Ok(()) => {
                    // The LAN answer carries no signed record; the direct
                    // handshake proves the key, so we synthesise a minimal one.
                    let record = Record {
                        v: crate::RENDEZVOUS_VERSION,
                        pk: peer.public_key.clone(),
                        nostr: None,
                        ep: peer.endpoints.clone(),
                        ts: unix_now(),
                        alias: peer.alias.clone(),
                        mac: peer.mac.clone(),
                        sig: String::new(),
                    };
                    if record.matches_id(id) {
                        info!(%id, "resolved on the LAN");
                        return Ok(Resolved { endpoints: peer.endpoints, record, via: "LAN" });
                    }
                    warn!(%id, "LAN announcement key does not derive to the id; ignoring");
                }
                Err(e) => return Err(e),
            }
        }

        let Some(dht) = &self.dht else {
            return Err(DiscoveryError::Other("not found on the LAN and the DHT is unavailable".into()));
        };
        if !dht.ready().await {
            warn!("DHT not bootstrapped yet; trying anyway");
        }

        // 2. By key.
        if let Some(pk) = pinned_key {
            if let Ok(bytes) = cleandesk_crypto::identity::decode_public_key(pk) {
                if let Some(record) = dht.lookup_by_key(&bytes, id).await {
                    info!(%id, "resolved on the DHT by pinned key");
                    return Ok(Resolved { endpoints: record.ep.clone(), record, via: "DHT" });
                }
            }
        }

        // 3. By ID.
        if let Some(record) = dht.lookup_by_id(id).await {
            self.check_pin(&record.pk, pinned_key)?;
            info!(%id, "resolved on the DHT by id");
            return Ok(Resolved { endpoints: record.ep.clone(), record, via: "DHT" });
        }

        Err(DiscoveryError::Other(
            "the device is not announced (is it on, with CleanDesk running?)".into(),
        ))
    }

    fn check_pin(&self, found: &str, pinned: Option<&str>) -> Result<()> {
        match pinned {
            Some(p) if p != found => Err(DiscoveryError::AuthFailed(
                "the remote device identity changed from the pinned one; verify its fingerprint before trusting the new key".into(),
            )),
            _ => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pin_mismatch_is_refused() {
        let r = Resolver::new(None);
        assert!(r.check_pin("A", Some("A")).is_ok());
        assert!(r.check_pin("A", None).is_ok());
        assert!(matches!(r.check_pin("B", Some("A")), Err(DiscoveryError::AuthFailed(_))));
    }
}
