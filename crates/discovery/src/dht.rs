//! BitTorrent mainline DHT rendezvous (BEP 5 + BEP 44).
//!
//! Three uses, all through the `mainline` crate:
//!
//! * **Record by key** — a BEP 44 mutable item signed with the host's own
//!   Ed25519 key (salt [`record_salt`]). Unforgeable; needs the viewer to know
//!   the key (address book).
//! * **Record by ID** — the same record stored under the ID-derived
//!   [`id_index_key`]. Anyone can overwrite that slot, so the viewer verifies
//!   the record's signature and that its key derives to the ID. A squatter can
//!   only cause a miss, never an impersonation.
//! * **Relay directory** — community relays `announce_peer` on
//!   [`relay_infohash`]; clients `get_peers` there.
//!
//! The DHT is UDP and takes a few seconds to bootstrap; one [`DhtNode`] is
//! shared per process and kept alive.

use crate::record::{id_index_key, record_salt, relay_infohash, Record};
use crate::{time::unix_now, DiscoveryError, Result};
use cleandesk_crypto::identity::Identity;
use cleandesk_proto::CleanDeskId;
use futures_util::StreamExt;
use mainline::{async_dht::AsyncDht, Dht, Id, MutableItem};
use std::net::{SocketAddr, SocketAddrV4};
use std::time::Duration;
use tracing::{debug, info, warn};

/// How long to wait for the DHT to find routing peers before giving up on a
/// lookup (it keeps bootstrapping in the background either way).
const BOOTSTRAP_WAIT: Duration = Duration::from_secs(8);

/// Per-lookup budget.
const LOOKUP_TIMEOUT: Duration = Duration::from_secs(10);

/// Budget for the relay directory lookup.
pub const RELAY_LOOKUP_TIMEOUT: Duration = Duration::from_secs(4);

/// A running DHT node.
#[derive(Clone)]
pub struct DhtNode {
    dht: AsyncDht,
}

impl DhtNode {
    /// Start a client node (does not serve storage to others) with the
    /// default public bootstrap nodes.
    pub fn start() -> Result<Self> {
        let dht = Dht::client().map_err(|e| DiscoveryError::Other(format!("dht: {e}")))?;
        Ok(Self { dht: dht.as_async() })
    }

    /// Start a full node bound to `port` (used by the relay so its announce
    /// carries a stable port).
    pub fn start_server(port: u16) -> Result<Self> {
        let dht = Dht::builder()
            .server_mode()
            .port(port)
            .build()
            .map_err(|e| DiscoveryError::Other(format!("dht: {e}")))?;
        Ok(Self { dht: dht.as_async() })
    }

    /// Wait until the node has some routing table, up to [`BOOTSTRAP_WAIT`].
    pub async fn ready(&self) -> bool {
        let deadline = tokio::time::Instant::now() + BOOTSTRAP_WAIT;
        loop {
            if self.dht.bootstrapped().await {
                return true;
            }
            if tokio::time::Instant::now() >= deadline {
                return false;
            }
            tokio::time::sleep(Duration::from_millis(300)).await;
        }
    }

    /// Our public IPv4:port as seen by other nodes, if learned yet.
    pub async fn public_address(&self) -> Option<SocketAddrV4> {
        self.dht.info().await.public_address()
    }

    /// Publish `record` under both the host's key and the ID index.
    pub async fn publish(&self, identity: &Identity, record: &Record) -> Result<()> {
        let value = record.to_json()?;
        let seq = record.ts as i64;
        // `mainline` pins its own ed25519-dalek major; bridge by raw seed bytes.
        let key_of = |seed: [u8; 32]| mainline::SigningKey::from_bytes(&seed);
        let by_key = MutableItem::new(key_of(identity.seed()), &value, seq, Some(&record_salt()));
        let by_id = MutableItem::new(
            key_of(id_index_key(identity.derive_id()).to_bytes()),
            &value,
            seq,
            Some(&record_salt()),
        );
        let a = tokio::time::timeout(LOOKUP_TIMEOUT, self.dht.put_mutable(by_key, None)).await;
        let b = tokio::time::timeout(LOOKUP_TIMEOUT, self.dht.put_mutable(by_id, None)).await;
        match (a, b) {
            (Ok(Ok(_)), Ok(Ok(_))) => {
                info!(id = %identity.derive_id(), "record published to the DHT");
                Ok(())
            }
            (a, b) => {
                fn describe<T, E: std::fmt::Display>(
                    r: std::result::Result<std::result::Result<T, E>, tokio::time::error::Elapsed>,
                ) -> String {
                    match r {
                        Ok(Ok(_)) => "ok".to_string(),
                        Ok(Err(e)) => e.to_string(),
                        Err(_) => "timeout".to_string(),
                    }
                }
                let (ra, rb) = (describe(a), describe(b));
                // Partial success is still useful; only fail if both failed.
                if ra == "ok" || rb == "ok" {
                    warn!(by_key = %ra, by_id = %rb, "record published partially");
                    Ok(())
                } else {
                    Err(DiscoveryError::Other(format!("dht put failed: by_key={ra}, by_id={rb}")))
                }
            }
        }
    }

    /// Look a host up by its public key (most trustworthy path).
    pub async fn lookup_by_key(&self, public_key: &[u8; 32], id: CleanDeskId) -> Option<Record> {
        let item = tokio::time::timeout(
            LOOKUP_TIMEOUT,
            self.dht.get_mutable_most_recent(public_key, Some(&record_salt())),
        )
        .await
        .ok()
        .flatten()?;
        self.accept(item, id)
    }

    /// Look a host up by ID alone (index slot; verified before use).
    pub async fn lookup_by_id(&self, id: CleanDeskId) -> Option<Record> {
        let key = id_index_key(id).verifying_key().to_bytes();
        // The index slot can hold garbage from squatters: scan every response
        // and keep the newest *valid* one instead of trusting "most recent".
        let mut stream = self.dht.get_mutable(&key, Some(&record_salt()), None);
        let deadline = tokio::time::Instant::now() + LOOKUP_TIMEOUT;
        let mut best: Option<Record> = None;
        loop {
            let next = tokio::select! {
                item = stream.next() => item,
                _ = tokio::time::sleep_until(deadline) => None,
            };
            let Some(item) = next else { break };
            if let Some(r) = self.accept(item, id) {
                if best.as_ref().is_none_or(|b| r.ts > b.ts) {
                    best = Some(r);
                }
            }
        }
        best
    }

    fn accept(&self, item: MutableItem, id: CleanDeskId) -> Option<Record> {
        let record = match Record::from_json(item.value()) {
            Ok(r) => r,
            Err(e) => {
                debug!(error = %e, "ignoring undecodable DHT record");
                return None;
            }
        };
        if let Err(e) = record.verify(unix_now()) {
            debug!(error = %e, "ignoring invalid DHT record");
            return None;
        }
        if !record.matches_id(id) {
            warn!(%id, "DHT record key does not derive to the requested ID (squatter?)");
            return None;
        }
        Some(record)
    }

    /// Announce this process as a community relay listening on `port`.
    pub async fn announce_relay(&self, port: u16) -> Result<()> {
        let hash = Id::from_bytes(relay_infohash()).map_err(|e| DiscoveryError::Other(e.to_string()))?;
        tokio::time::timeout(LOOKUP_TIMEOUT, self.dht.announce_peer(hash, Some(port)))
            .await
            .map_err(|_| DiscoveryError::Timeout("relay announce"))?
            .map_err(|e| DiscoveryError::Other(format!("announce_peer: {e}")))?;
        Ok(())
    }

    /// Find community relays (TURN endpoints), deduplicated. Bounded by
    /// [`RELAY_LOOKUP_TIMEOUT`]: relays are a fallback, not worth stalling a
    /// connection for.
    pub async fn find_relays(&self, max: usize) -> Vec<SocketAddr> {
        let Ok(hash) = Id::from_bytes(relay_infohash()) else { return Vec::new() };
        let mut stream = self.dht.get_peers(hash);
        let deadline = tokio::time::Instant::now() + RELAY_LOOKUP_TIMEOUT;
        let mut out: Vec<SocketAddr> = Vec::new();
        loop {
            let next = tokio::select! {
                batch = stream.next() => batch,
                _ = tokio::time::sleep_until(deadline) => None,
            };
            let Some(batch) = next else { break };
            for p in batch {
                let addr = SocketAddr::V4(p);
                if p.port() != 0 && !out.contains(&addr) {
                    out.push(addr);
                }
            }
            if out.len() >= max {
                break;
            }
        }
        out.truncate(max);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Live network test: publishes a record to the real DHT and reads it
    /// back by ID and by key. Needs outbound UDP; run with `-- --ignored`.
    #[tokio::test]
    #[ignore]
    async fn publish_and_lookup_on_the_real_dht() {
        let node = DhtNode::start().unwrap();
        assert!(node.ready().await, "could not bootstrap the DHT");
        let ident = Identity::generate();
        let record = Record::new(&ident, None, vec!["203.0.113.9:7423".parse().unwrap()], None, unix_now());
        node.publish(&ident, &record).await.unwrap();
        let by_id = node.lookup_by_id(ident.derive_id()).await.expect("record by id");
        assert_eq!(by_id.pk, record.pk);
        let by_key = node
            .lookup_by_key(&ident.public_key().to_bytes(), ident.derive_id())
            .await
            .expect("record by key");
        assert_eq!(by_key.ep, record.ep);
    }
}
