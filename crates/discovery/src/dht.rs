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
//!   only cause a miss, never an impersonation — unless it went to the trouble
//!   of grinding a key that derives to the same ID, which is why several valid
//!   records under different keys are reported as [`DiscoveryError::AmbiguousIdentity`]
//!   instead of silently picking one.
//! * **Relay directory** — community relays `announce_peer` on
//!   [`relay_infohash`] and publish a signed [`RelayRecord`] under
//!   [`relay_index_key`]`(addr)`; clients `get_peers` there and only keep the
//!   addresses whose record verifies.
//!
//! The DHT is UDP and takes a few seconds to bootstrap; one [`DhtNode`] is
//! shared per process and kept alive.
//!
//! # Sequence numbers
//!
//! BEP 44 keeps, per slot, the item with the highest `seq`. We use the record
//! timestamp as `seq`. Anyone can derive the ID index key, so a squatter can
//! park an item with a huge `seq` there and every later put of ours would be
//! refused as "not most recent". [`DhtNode::publish`] therefore reads the
//! slot back after such a refusal and retries with `max(current + 1, ts)`:
//! the fight is winnable because our record is what the viewer verifies and
//! the squatter's is not, whatever its `seq`. Residual: a squatter that keeps
//! bumping the slot between our republishes can still cause misses on the
//! by-ID path (never on the by-key path, which only the host can write).

use crate::record::{id_index_key, record_salt, relay_index_key, relay_infohash, relay_record_salt, Record, RelayRecord};
use crate::{time::unix_now, DiscoveryError, Result};
use cleandesk_crypto::identity::Identity;
use cleandesk_proto::CleanDeskId;
use futures_util::StreamExt;
use mainline::{async_dht::AsyncDht, errors::PutMutableError, Dht, Id, MutableItem};
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

/// Budget for fetching one relay's signed record after `get_peers`.
const RELAY_VERIFY_TIMEOUT: Duration = Duration::from_secs(4);

/// How many `get_peers` candidates are checked per `find_relays` call at most
/// (each costs a DHT lookup; the directory may hold junk).
const MAX_RELAY_CANDIDATES: usize = 16;
/// Most by-ID records collected per lookup; a squatter spraying valid-looking
/// records must not grow the candidate list without bound.
const MAX_ID_CANDIDATES: usize = 64;

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

    /// Put a mutable item; on a sequence conflict read the slot back and
    /// retry once with a `seq` above whatever is stored there (see the module
    /// docs). `signer` builds the item for a given `seq`.
    async fn put_with_seq_recovery(
        &self,
        signer: &mainline::SigningKey,
        salt: &[u8],
        value: &[u8],
        seq: i64,
        what: &'static str,
    ) -> std::result::Result<(), String> {
        let item = MutableItem::new(signer.clone(), value, seq, Some(salt));
        let first = tokio::time::timeout(LOOKUP_TIMEOUT, self.dht.put_mutable(item, None)).await;
        match first {
            Ok(Ok(_)) => return Ok(()),
            Ok(Err(PutMutableError::Concurrency(e))) => {
                debug!(%what, error = %e, "put refused on seq; reading the slot back");
            }
            Ok(Err(e)) => return Err(e.to_string()),
            Err(_) => return Err("timeout".into()),
        }
        let key = signer.verifying_key().to_bytes();
        let current = tokio::time::timeout(LOOKUP_TIMEOUT, self.dht.get_mutable_most_recent(&key, Some(salt)))
            .await
            .ok()
            .flatten()
            .map(|i| i.seq());
        let Some(current) = current else {
            return Err("seq conflict but the slot could not be read back".into());
        };
        let bumped = current.saturating_add(1).max(seq);
        warn!(%what, stored_seq = current, our_seq = seq, retry_seq = bumped, "slot holds a higher seq (squatter?); retrying above it");
        let item = MutableItem::new(signer.clone(), value, bumped, Some(salt));
        match tokio::time::timeout(LOOKUP_TIMEOUT, self.dht.put_mutable(item, Some(current))).await {
            Ok(Ok(_)) => Ok(()),
            Ok(Err(e)) => Err(format!("retry with seq {bumped}: {e}")),
            Err(_) => Err("timeout on retry".into()),
        }
    }

    /// Publish `record` under both the host's key and the ID index.
    pub async fn publish(&self, identity: &Identity, record: &Record) -> Result<()> {
        let value = record.to_json()?;
        let seq = record.ts as i64;
        // `mainline` pins its own ed25519-dalek major; bridge by raw seed bytes.
        let key_of = |seed: &[u8; 32]| mainline::SigningKey::from_bytes(seed);
        let by_key_signer = key_of(&identity.seed());
        let by_id_signer = key_of(&id_index_key(identity.derive_id()).to_bytes());
        let salt = record_salt();
        let a = self.put_with_seq_recovery(&by_key_signer, &salt, &value, seq, "record by key").await;
        let b = self.put_with_seq_recovery(&by_id_signer, &salt, &value, seq, "record by id").await;
        match (a, b) {
            (Ok(()), Ok(())) => {
                info!(id = %identity.derive_id(), "record published to the DHT");
                Ok(())
            }
            (Ok(()), Err(rb)) => {
                warn!(by_id = %rb, "record published partially (by key only)");
                Ok(())
            }
            (Err(ra), Ok(())) => {
                warn!(by_key = %ra, "record published partially (by id only)");
                Ok(())
            }
            (Err(ra), Err(rb)) => Err(DiscoveryError::Other(format!("dht put failed: by_key={ra}, by_id={rb}"))),
        }
    }

    /// Look a host up by its public key (most trustworthy path). The record
    /// must be signed by exactly that key: the slot is keyed by it, but the
    /// JSON inside carries its own `pk`, which is what everything else checks.
    pub async fn lookup_by_key(&self, public_key: &[u8; 32], id: CleanDeskId) -> Option<Record> {
        let item = tokio::time::timeout(
            LOOKUP_TIMEOUT,
            self.dht.get_mutable_most_recent(public_key, Some(&record_salt())),
        )
        .await
        .ok()
        .flatten()?;
        let record = self.accept(item, id)?;
        if record.public_key_bytes().ok()? != *public_key {
            warn!(%id, "DHT record under a key is signed by a different key; ignoring");
            return None;
        }
        Some(record)
    }

    /// Look a host up by ID alone (index slot; verified before use).
    ///
    /// Every valid record whose key derives to `id` is a candidate. With one
    /// key among them the newest record wins. With several keys — someone
    /// ground a colliding key — the record matching `pinned_key` wins if one
    /// is given; otherwise [`DiscoveryError::AmbiguousIdentity`] is returned
    /// and the caller decides (refuse, or ask the user to verify a
    /// fingerprint).
    pub async fn lookup_by_id(&self, id: CleanDeskId, pinned_key: Option<&str>) -> Result<Option<Record>> {
        let key = id_index_key(id).verifying_key().to_bytes();
        // The index slot can hold garbage from squatters: scan every response
        // instead of trusting "most recent".
        let mut stream = self.dht.get_mutable(&key, Some(&record_salt()), None);
        let deadline = tokio::time::Instant::now() + LOOKUP_TIMEOUT;
        let mut candidates: Vec<Record> = Vec::new();
        loop {
            let next = tokio::select! {
                item = stream.next() => item,
                _ = tokio::time::sleep_until(deadline) => None,
            };
            let Some(item) = next else { break };
            if let Some(r) = self.accept(item, id) {
                candidates.push(r);
                if candidates.len() >= MAX_ID_CANDIDATES {
                    break;
                }
            }
        }
        select_by_id(candidates, pinned_key)
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

    /// Announce this process as a community relay reachable at `public_addr`
    /// (UDP TURN): a signed [`RelayRecord`] under the address's index slot,
    /// plus `announce_peer` on the directory infohash so clients find the
    /// address in the first place.
    pub async fn announce_relay(&self, identity: &Identity, public_addr: SocketAddr) -> Result<()> {
        let record = RelayRecord::new(identity, public_addr, unix_now());
        let value = record.to_json()?;
        let signer = mainline::SigningKey::from_bytes(&relay_index_key(public_addr).to_bytes());
        self.put_with_seq_recovery(&signer, &relay_record_salt(), &value, record.ts as i64, "relay record")
            .await
            .map_err(|e| DiscoveryError::Other(format!("relay record put: {e}")))?;
        let hash = Id::from_bytes(relay_infohash()).map_err(|e| DiscoveryError::Other(e.to_string()))?;
        tokio::time::timeout(LOOKUP_TIMEOUT, self.dht.announce_peer(hash, Some(public_addr.port())))
            .await
            .map_err(|_| DiscoveryError::Timeout("relay announce"))?
            .map_err(|e| DiscoveryError::Other(format!("announce_peer: {e}")))?;
        Ok(())
    }

    /// Fetch and verify the signed record of the relay at `addr`.
    pub async fn verify_relay(&self, addr: SocketAddr) -> Option<RelayRecord> {
        let key = relay_index_key(addr).verifying_key().to_bytes();
        let mut stream = self.dht.get_mutable(&key, Some(&relay_record_salt()), None);
        let deadline = tokio::time::Instant::now() + RELAY_VERIFY_TIMEOUT;
        loop {
            let next = tokio::select! {
                item = stream.next() => item,
                _ = tokio::time::sleep_until(deadline) => None,
            };
            let item = next?;
            match RelayRecord::from_json(item.value()).and_then(|r| r.verify(unix_now(), Some(addr)).map(|()| r)) {
                Ok(r) => return Some(r),
                Err(e) => debug!(%addr, error = %e, "ignoring invalid relay record"),
            }
        }
    }

    /// Find community relays (TURN endpoints) whose signed record verifies,
    /// deduplicated. Bounded: relays are a fallback, not worth stalling a
    /// connection for.
    pub async fn find_verified_relays(&self, max: usize) -> Vec<RelayRecord> {
        let candidates = self.relay_candidates(MAX_RELAY_CANDIDATES.max(max)).await;
        if candidates.is_empty() {
            return Vec::new();
        }
        let checks = futures_util::future::join_all(candidates.into_iter().map(|addr| self.verify_relay(addr))).await;
        let mut out: Vec<RelayRecord> = Vec::new();
        for record in checks.into_iter().flatten() {
            if !out.iter().any(|r| r.addr == record.addr) {
                out.push(record);
            }
            if out.len() >= max {
                break;
            }
        }
        out
    }

    /// [`Self::find_verified_relays`] reduced to the addresses ICE needs.
    pub async fn find_relays(&self, max: usize) -> Vec<SocketAddr> {
        self.find_verified_relays(max).await.into_iter().map(|r| r.addr).collect()
    }

    /// Raw `get_peers` on the directory infohash: unauthenticated hints.
    async fn relay_candidates(&self, max: usize) -> Vec<SocketAddr> {
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
                // A community relay must be globally routable: anyone can
                // announce, and a private address here would make every
                // client send TURN traffic into its own network.
                if p.port() != 0 && crate::addr::is_global(addr.ip()) && !out.contains(&addr) {
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

/// Choose among valid by-ID candidates (see [`DhtNode::lookup_by_id`]).
/// Separate from the DHT so the policy is unit-testable.
fn select_by_id(mut candidates: Vec<Record>, pinned_key: Option<&str>) -> Result<Option<Record>> {
    if candidates.is_empty() {
        return Ok(None);
    }
    // Newest first, so "first match" below is also "newest match".
    candidates.sort_by_key(|r| std::cmp::Reverse(r.ts));
    if let Some(pinned) = pinned_key {
        if let Some(r) = candidates.iter().find(|r| r.pk == pinned) {
            return Ok(Some(r.clone()));
        }
    }
    let mut keys: Vec<String> = Vec::new();
    for r in &candidates {
        if !keys.contains(&r.pk) {
            keys.push(r.pk.clone());
        }
    }
    if keys.len() > 1 {
        warn!(candidates = keys.len(), "several keys claim the same id on the DHT; refusing to guess");
        return Err(DiscoveryError::AmbiguousIdentity { keys });
    }
    Ok(candidates.into_iter().next())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Two keys with the same derived ID are the setup of every test below;
    /// grinding one for real takes ~2^30 tries, so the records are built with
    /// whatever key and only `select_by_id`'s policy is exercised (it never
    /// re-derives: `accept` did that already).
    fn rec(ident: &Identity, ts: u64) -> Record {
        Record::new(ident, None, vec!["203.0.113.9:7423".parse().unwrap()], None, ts)
    }

    #[test]
    fn single_key_picks_the_newest() {
        let a = Identity::generate();
        let out = select_by_id(vec![rec(&a, 10), rec(&a, 30), rec(&a, 20)], None).unwrap().unwrap();
        assert_eq!(out.ts, 30);
        assert!(select_by_id(vec![], None).unwrap().is_none());
    }

    #[test]
    fn two_keys_without_a_pin_is_ambiguous() {
        let a = Identity::generate();
        let b = Identity::generate();
        let err = select_by_id(vec![rec(&a, 10), rec(&b, 50)], None).unwrap_err();
        match err {
            DiscoveryError::AmbiguousIdentity { keys } => {
                assert_eq!(keys.len(), 2);
                assert_eq!(keys[0], b.public_key_b64(), "newest first");
            }
            other => panic!("expected AmbiguousIdentity, got {other}"),
        }
    }

    #[test]
    fn pinned_key_wins_even_if_older() {
        let a = Identity::generate();
        let b = Identity::generate();
        let pinned = a.public_key_b64();
        let out = select_by_id(vec![rec(&a, 10), rec(&b, 50), rec(&a, 5)], Some(&pinned)).unwrap().unwrap();
        assert_eq!(out.pk, pinned);
        assert_eq!(out.ts, 10, "newest record of the pinned key");
        // A pin that matches nobody does not resolve the ambiguity.
        let c = Identity::generate().public_key_b64();
        assert!(matches!(
            select_by_id(vec![rec(&a, 10), rec(&b, 50)], Some(&c)),
            Err(DiscoveryError::AmbiguousIdentity { .. })
        ));
        // A pin with a single foreign key: not ambiguous here (the resolver's
        // pin check refuses it with the "identity changed" alarm).
        assert_eq!(select_by_id(vec![rec(&b, 50)], Some(&c)).unwrap().unwrap().pk, b.public_key_b64());
    }

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
        let by_id = node.lookup_by_id(ident.derive_id(), None).await.unwrap().expect("record by id");
        assert_eq!(by_id.pk, record.pk);
        let by_key = node
            .lookup_by_key(&ident.public_key().to_bytes(), ident.derive_id())
            .await
            .expect("record by key");
        assert_eq!(by_key.ep, record.ep);
    }

    /// Live: a relay record round-trips through the directory. Run with
    /// `-- --ignored`.
    #[tokio::test]
    #[ignore]
    async fn announce_and_verify_relay_on_the_real_dht() {
        let node = DhtNode::start().unwrap();
        assert!(node.ready().await, "could not bootstrap the DHT");
        let relay = Identity::generate();
        let addr: SocketAddr = "203.0.113.77:7421".parse().unwrap();
        node.announce_relay(&relay, addr).await.unwrap();
        let record = node.verify_relay(addr).await.expect("relay record");
        assert_eq!(record.pk, relay.public_key_b64());
    }
}
