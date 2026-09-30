//! Shared server state: the device registry and active session routing table.
//!
//! Security invariants enforced here (see `docs/SECURITY.md`):
//! * A RotoDesk ID is *derived* from the device's Ed25519 public key. The
//!   registry only ever stores an ID together with the key it was derived
//!   from, so two different keys can never hold the same ID and a key can
//!   never sit under a foreign ID.
//! * Every registry entry remembers which connection created it. A stale
//!   connection that dies *after* the same device reconnected must not evict
//!   the fresh entry.
//! * `Accept`/`Reject` are only honoured from the session's callee; `Signal`
//!   from either endpoint. Anyone else gets silently dropped.
//! * Per source IP, at most [`MAX_CONNS_PER_IP`] sockets at once and
//!   [`REGISTRATIONS_PER_IP`] registrations per minute ([`IpLimits`]): the
//!   per-connection budgets alone would let one machine open thousands of
//!   sockets and grind registrations (each costs an Ed25519 verify).

use rotodesk_proto::{
    id::RotoDeskId,
    message::SignalMessage,
    session::{DeviceInfo, SessionId},
};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc::Sender;
use tracing::{info, warn};

/// Outbound messages queued per connection before the server starts
/// dropping them. ICE trickle is a few dozen candidates; a peer that cannot
/// drain this many is dead or deliberately not reading.
pub const OUTBOUND_QUEUE: usize = 64;

/// `IncomingRequest`s one callee may receive per [`CALLEE_WINDOW`], across
/// every caller. Bounds the dialogs / auth attempts a host can be flooded
/// with from many addresses.
pub const CALLEE_BURST: u32 = 10;
pub const CALLEE_WINDOW: Duration = Duration::from_secs(60);

/// How long a RotoDesk ID stays reserved for the key that last registered
/// it. A different key that derives to the same ID (a ground collision, see
/// `docs/SECURITY.md`) is refused for this long after the owner was last
/// seen, even while the owner is offline.
pub const ID_HOLD: Duration = Duration::from_secs(30 * 24 * 3600);

/// Most ID->key ownership records kept; beyond this the oldest are evicted.
const MAX_OWNERS: usize = 1_000_000;

/// Concurrent WebSocket connections accepted from one IP.
pub const MAX_CONNS_PER_IP: usize = 20;
/// `Register` attempts accepted from one IP per [`REGISTRATION_WINDOW`].
pub const REGISTRATIONS_PER_IP: u32 = 30;
pub const REGISTRATION_WINDOW: Duration = Duration::from_secs(60);
/// Above this many tracked IPs, buckets that have fully refilled are dropped
/// (they carry no information any more), bounding memory under a scan from
/// many addresses.
const IP_TABLE_SOFT_CAP: usize = 10_000;

/// Per-IP abuse limits shared by every connection. NAT means several honest
/// devices can share an address, so the numbers are generous for people and
/// tight for scripts.
pub struct IpLimits {
    conns: DashMap<IpAddr, usize>,
    registrations: DashMap<IpAddr, RateLimiter>,
    max_conns: usize,
    reg_burst: u32,
    reg_window: Duration,
}

impl Default for IpLimits {
    fn default() -> Self {
        Self::new(MAX_CONNS_PER_IP, REGISTRATIONS_PER_IP, REGISTRATION_WINDOW)
    }
}

impl IpLimits {
    pub fn new(max_conns: usize, reg_burst: u32, reg_window: Duration) -> Self {
        Self {
            conns: DashMap::new(),
            registrations: DashMap::new(),
            max_conns: max_conns.max(1),
            reg_burst,
            reg_window,
        }
    }

    /// Count a new connection from `ip`; `false` means the cap is reached
    /// and the socket must be dropped (nothing was counted).
    pub fn try_acquire(&self, ip: IpAddr) -> bool {
        let mut entry = self.conns.entry(ip).or_insert(0);
        if *entry >= self.max_conns {
            warn!(%ip, count = *entry, "connection cap per IP reached; dropping");
            return false;
        }
        *entry += 1;
        true
    }

    /// Release a connection counted by [`Self::try_acquire`].
    pub fn release(&self, ip: IpAddr) {
        if let Some(mut entry) = self.conns.get_mut(&ip) {
            *entry = entry.saturating_sub(1);
            if *entry == 0 {
                drop(entry);
                self.conns.remove_if(&ip, |_, n| *n == 0);
            }
        }
    }

    pub fn connections(&self, ip: IpAddr) -> usize {
        self.conns.get(&ip).map(|n| *n).unwrap_or(0)
    }

    /// May `ip` start another registration now?
    pub fn allow_registration(&self, ip: IpAddr) -> bool {
        self.allow_registration_at(ip, Instant::now())
    }

    /// [`Self::allow_registration`] with an injected clock.
    pub fn allow_registration_at(&self, ip: IpAddr, now: Instant) -> bool {
        if self.registrations.len() > IP_TABLE_SOFT_CAP {
            self.registrations.retain(|_, rl| !rl.is_replenished_at(now));
        }
        let allowed = self
            .registrations
            .entry(ip)
            .or_insert_with(|| RateLimiter::new(self.reg_burst, self.reg_window))
            .allow_at(now);
        if !allowed {
            warn!(%ip, "registration rate limit per IP exceeded");
        }
        allowed
    }

    pub fn tracked_ips(&self) -> usize {
        self.registrations.len()
    }
}

/// Identifies one WebSocket connection for the life of the process.
pub type ConnId = u64;

/// A connected, registered peer and the channel to reach its writer task.
pub struct Peer {
    pub info: DeviceInfo,
    pub public_key: String,
    pub conn: ConnId,
    pub tx: Sender<SignalMessage>,
}

/// Which key last held an ID and when it was last seen (Unix seconds).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Owner {
    pub public_key: String,
    pub last_seen: u64,
}

/// Persistent ID->key ownership. The live registry only knows who is online;
/// this remembers who *was*, so an attacker who grinds a key colliding with
/// a victim's ID cannot register while the victim is merely offline.
#[derive(Default)]
pub struct OwnerRegistry {
    owners: Mutex<HashMap<RotoDeskId, Owner>>,
    path: Option<PathBuf>,
    hold: Duration,
}

impl OwnerRegistry {
    /// In-memory only (tests, ephemeral deployments).
    pub fn ephemeral() -> Self {
        Self { owners: Mutex::new(HashMap::new()), path: None, hold: ID_HOLD }
    }

    /// Backed by a JSON file; a missing file starts empty, a corrupt one is
    /// set aside rather than overwritten.
    pub fn load(path: PathBuf) -> Self {
        let owners = match std::fs::read(&path) {
            Ok(bytes) => match serde_json::from_slice::<HashMap<RotoDeskId, Owner>>(&bytes) {
                Ok(map) => map,
                Err(e) => {
                    let aside = path.with_extension("json.corrupt");
                    warn!(path = %path.display(), error = %e, aside = %aside.display(), "owner registry unreadable; starting empty");
                    let _ = std::fs::rename(&path, &aside);
                    HashMap::new()
                }
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => HashMap::new(),
            Err(e) => {
                warn!(path = %path.display(), error = %e, "owner registry unreadable; starting empty");
                HashMap::new()
            }
        };
        info!(path = %path.display(), count = owners.len(), "owner registry loaded");
        Self { owners: Mutex::new(owners), path: Some(path), hold: ID_HOLD }
    }

    #[cfg(test)]
    fn with_hold(mut self, hold: Duration) -> Self {
        self.hold = hold;
        self
    }

    /// Record that `public_key` proved ownership of `id` now. `Err` when a
    /// different key still holds the ID.
    pub fn claim(&self, id: RotoDeskId, public_key: &str) -> Result<(), RegisterError> {
        self.claim_at(id, public_key, unix_now())
    }

    fn claim_at(&self, id: RotoDeskId, public_key: &str, now: u64) -> Result<(), RegisterError> {
        let mut owners = self.owners.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(owner) = owners.get(&id) {
            let held = now.saturating_sub(owner.last_seen) < self.hold.as_secs();
            if owner.public_key != public_key && held {
                warn!(%id, "id held by another key; refusing registration");
                return Err(RegisterError::IdHeldByOtherKey);
            }
        }
        owners.insert(id, Owner { public_key: public_key.to_string(), last_seen: now });
        if owners.len() > MAX_OWNERS {
            // Drop the stalest fifth so this does not run on every claim.
            let mut by_age: Vec<(RotoDeskId, u64)> = owners.iter().map(|(k, v)| (*k, v.last_seen)).collect();
            by_age.sort_by_key(|(_, seen)| *seen);
            for (k, _) in by_age.iter().take(MAX_OWNERS / 5) {
                owners.remove(k);
            }
        }
        if let Some(path) = &self.path {
            let snapshot = serde_json::to_vec(&*owners);
            drop(owners);
            match snapshot {
                Ok(bytes) => {
                    let tmp = path.with_extension("json.tmp");
                    let res = std::fs::write(&tmp, &bytes).and_then(|_| std::fs::rename(&tmp, path));
                    if let Err(e) = res {
                        warn!(path = %path.display(), error = %e, "could not persist owner registry");
                    }
                }
                Err(e) => warn!(error = %e, "could not serialise owner registry"),
            }
        }
        Ok(())
    }

    pub fn len(&self) -> usize {
        self.owners.lock().unwrap_or_else(|e| e.into_inner()).len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

fn unix_now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// A pending or active session, used to route Accept/Reject/Signal messages
/// between the two endpoints.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Session {
    pub caller: RotoDeskId,
    pub callee: RotoDeskId,
}

/// Why a registration was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegisterError {
    /// The ID is held by a *different* public key (a genuine 9-digit
    /// collision, or an attempt to squat on someone else's ID).
    IdHeldByOtherKey,
}

/// Which side of a session a peer is on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Caller,
    Callee,
}

/// Process-wide server state. Cheap to clone via `Arc`.
#[derive(Default)]
pub struct ServerState {
    peers: DashMap<RotoDeskId, Peer>,
    sessions: DashMap<SessionId, Session>,
    next_conn: AtomicU64,
    ip_limits: IpLimits,
    owners: OwnerRegistry,
    callee_limits: DashMap<RotoDeskId, RateLimiter>,
}

impl ServerState {
    pub fn new() -> Self {
        Self::default()
    }

    /// State with custom per-IP limits (tests, or an operator behind a
    /// large NAT).
    pub fn with_ip_limits(ip_limits: IpLimits) -> Self {
        Self { ip_limits, ..Self::default() }
    }

    /// State whose ID ownership survives restarts.
    pub fn with_owners(owners: OwnerRegistry) -> Self {
        Self { owners, ..Self::default() }
    }

    pub fn ip_limits(&self) -> &IpLimits {
        &self.ip_limits
    }

    pub fn owners(&self) -> &OwnerRegistry {
        &self.owners
    }

    /// May `callee` receive another `IncomingRequest` now?
    pub fn allow_incoming(&self, callee: RotoDeskId) -> bool {
        let now = Instant::now();
        if self.callee_limits.len() > IP_TABLE_SOFT_CAP {
            self.callee_limits.retain(|_, rl| !rl.is_replenished_at(now));
        }
        self.callee_limits
            .entry(callee)
            .or_insert_with(|| RateLimiter::new(CALLEE_BURST, CALLEE_WINDOW))
            .allow_at(now)
    }

    /// Is `conn` still the connection that holds `id`? A connection that
    /// was replaced by a newer registration of the same device must stop
    /// acting under the ID.
    pub fn holds(&self, id: RotoDeskId, conn: ConnId) -> bool {
        self.peers.get(&id).map(|p| p.conn == conn).unwrap_or(false)
    }

    /// Hand out a fresh connection identifier.
    pub fn next_conn_id(&self) -> ConnId {
        self.next_conn.fetch_add(1, Ordering::Relaxed)
    }

    /// Register a peer under the ID derived from `public_key` (the caller has
    /// already verified `info.id` matches and that the key was proven).
    ///
    /// If the same key is already registered — typically a device whose old
    /// socket has not been noticed as dead yet — the old entry is replaced and
    /// its writer is told to go away, so a reconnecting host keeps its stable
    /// ID instead of being handed a random one nobody knows about.
    pub fn register(
        &self,
        info: DeviceInfo,
        public_key: String,
        conn: ConnId,
        tx: Sender<SignalMessage>,
    ) -> Result<RotoDeskId, RegisterError> {
        let id = info.id;
        if let Some(existing) = self.peers.get(&id) {
            if existing.public_key != public_key {
                return Err(RegisterError::IdHeldByOtherKey);
            }
            info!(%id, old_conn = existing.conn, new_conn = conn, "device re-registered; replacing stale connection");
            // Tell the old connection it lost the registration, so a host that
            // is still alive there (e.g. the service helper while the GUI runs)
            // can stand down instead of believing it is reachable.
            let _ = existing.tx.try_send(SignalMessage::Error {
                code: rotodesk_proto::message::ErrorCode::IdConflict,
                detail: "replaced by a newer registration of the same device".into(),
            });
            // Sessions that belonged to the old connection are dead: the peer
            // on the other end will get nothing back, so drop them now.
            self.sessions.retain(|_, s| s.caller != id && s.callee != id);
        }
        // Offline owners keep their ID for `ID_HOLD`.
        self.owners.claim(id, &public_key)?;
        self.peers.insert(id, Peer { info, public_key, conn, tx });
        info!(%id, count = self.peers.len(), "device registered");
        Ok(id)
    }

    /// Remove a peer and any sessions it participates in — but only if the
    /// entry still belongs to connection `conn`. A stale connection closing
    /// after a re-registration must not evict the live entry.
    pub fn unregister(&self, id: RotoDeskId, conn: ConnId) {
        let removed = self.peers.remove_if(&id, |_, p| p.conn == conn).is_some();
        if removed {
            self.sessions.retain(|_, s| s.caller != id && s.callee != id);
            info!(%id, count = self.peers.len(), "device unregistered");
        }
    }

    /// Look up a peer's outbound channel.
    pub fn sender(&self, id: RotoDeskId) -> Option<Sender<SignalMessage>> {
        self.peers.get(&id).map(|p| p.tx.clone())
    }

    pub fn is_online(&self, id: RotoDeskId) -> bool {
        self.peers.contains_key(&id)
    }

    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    /// Create a session routing entry. Any previous session between the same
    /// two endpoints (in this direction) is superseded, so a caller retrying
    /// cannot accumulate entries.
    pub fn open_session(&self, session: SessionId, caller: RotoDeskId, callee: RotoDeskId) {
        self.sessions.retain(|_, s| !(s.caller == caller && s.callee == callee));
        self.sessions.insert(session, Session { caller, callee });
    }

    pub fn close_session(&self, session: SessionId) {
        self.sessions.remove(&session);
    }

    /// The role `me` plays in `session`, if `me` is part of it at all.
    pub fn role_in(&self, session: SessionId, me: RotoDeskId) -> Option<Role> {
        let s = *self.sessions.get(&session)?;
        if s.caller == me {
            Some(Role::Caller)
        } else if s.callee == me {
            Some(Role::Callee)
        } else {
            None
        }
    }

    /// Given a session and one endpoint, return the *other* endpoint's channel.
    pub fn peer_across(
        &self,
        session: SessionId,
        me: RotoDeskId,
    ) -> Option<Sender<SignalMessage>> {
        let s = *self.sessions.get(&session)?;
        let other = match self.role_in(session, me)? {
            Role::Caller => s.callee,
            Role::Callee => s.caller,
        };
        self.sender(other)
    }
}

/// A small token bucket: `burst` actions allowed at once, refilling one token
/// every `interval / burst`. Used per connection to bound `ConnectRequest`
/// spam (each one costs the callee a dialog or an auth check) and to cap how
/// many malformed messages a client may send before it is disconnected.
#[derive(Debug, Clone)]
pub struct RateLimiter {
    capacity: f64,
    tokens: f64,
    refill_per_sec: f64,
    last: std::time::Instant,
}

impl RateLimiter {
    pub fn new(burst: u32, per: std::time::Duration) -> Self {
        let capacity = f64::from(burst.max(1));
        Self {
            capacity,
            tokens: capacity,
            refill_per_sec: capacity / per.as_secs_f64().max(f64::EPSILON),
            last: std::time::Instant::now(),
        }
    }

    /// Try to spend one token now.
    pub fn allow(&mut self) -> bool {
        self.allow_at(std::time::Instant::now())
    }

    /// [`Self::allow`] with an injected clock.
    pub fn allow_at(&mut self, now: std::time::Instant) -> bool {
        let elapsed = now.saturating_duration_since(self.last).as_secs_f64();
        self.last = now;
        self.tokens = (self.tokens + elapsed * self.refill_per_sec).min(self.capacity);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// Would the bucket be full at `now`? A full bucket is indistinguishable
    /// from a fresh one, so its entry can be forgotten.
    pub fn is_replenished_at(&self, now: std::time::Instant) -> bool {
        let elapsed = now.saturating_duration_since(self.last).as_secs_f64();
        self.tokens + elapsed * self.refill_per_sec >= self.capacity
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};
    use tokio::sync::mpsc;
    use uuid::Uuid;

    fn id(n: u64) -> RotoDeskId {
        RotoDeskId::new(n).unwrap()
    }

    fn info(n: u64) -> DeviceInfo {
        DeviceInfo {
            id: id(n),
            alias: None,
            hostname: "h".into(),
            os: "test".into(),
            app_version: "0".into(),
        }
    }

    fn chan() -> (Sender<SignalMessage>, mpsc::Receiver<SignalMessage>) {
        mpsc::channel(OUTBOUND_QUEUE)
    }

    #[test]
    fn offline_owner_keeps_its_id_until_the_hold_expires() {
        let reg = OwnerRegistry::ephemeral().with_hold(Duration::from_secs(100));
        reg.claim_at(id(100_000_001), "KEY-A", 1_000).unwrap();
        assert_eq!(reg.claim_at(id(100_000_001), "KEY-B", 1_050), Err(RegisterError::IdHeldByOtherKey));
        // The owner coming back refreshes the hold.
        reg.claim_at(id(100_000_001), "KEY-A", 1_090).unwrap();
        assert_eq!(reg.claim_at(id(100_000_001), "KEY-B", 1_150), Err(RegisterError::IdHeldByOtherKey));
        // Once the owner has been gone for the hold period the ID is free.
        reg.claim_at(id(100_000_001), "KEY-B", 1_200).unwrap();
        assert_eq!(reg.claim_at(id(100_000_001), "KEY-A", 1_201), Err(RegisterError::IdHeldByOtherKey));
    }

    #[test]
    fn owner_registry_round_trips_through_disk() {
        let dir = std::env::temp_dir().join(format!("rotodesk-owners-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("owners.json");
        let reg = OwnerRegistry::load(path.clone());
        reg.claim(id(100_000_001), "KEY-A").unwrap();
        let reloaded = OwnerRegistry::load(path.clone());
        assert_eq!(reloaded.len(), 1);
        assert_eq!(reloaded.claim(id(100_000_001), "KEY-B"), Err(RegisterError::IdHeldByOtherKey));
        // Garbage on disk is set aside, not trusted and not clobbered.
        std::fs::write(&path, b"{not json").unwrap();
        let fresh = OwnerRegistry::load(path.clone());
        assert!(fresh.is_empty());
        assert!(path.with_extension("json.corrupt").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_replaced_connection_no_longer_holds_the_id() {
        let st = ServerState::new();
        let (tx1, _rx1) = chan();
        let (tx2, _rx2) = chan();
        st.register(info(100_000_001), "KEY".into(), 1, tx1).unwrap();
        assert!(st.holds(id(100_000_001), 1));
        st.register(info(100_000_001), "KEY".into(), 2, tx2).unwrap();
        assert!(!st.holds(id(100_000_001), 1));
        assert!(st.holds(id(100_000_001), 2));
    }

    #[test]
    fn incoming_requests_per_callee_are_bounded() {
        let st = ServerState::new();
        let callee = id(100_000_009);
        let allowed = (0..CALLEE_BURST + 5).filter(|_| st.allow_incoming(callee)).count();
        assert_eq!(allowed, CALLEE_BURST as usize);
        assert!(st.allow_incoming(id(100_000_010)), "another callee has its own budget");
    }

    #[test]
    fn same_key_reconnect_replaces_entry_and_stale_close_keeps_it() {
        let st = ServerState::new();
        let (tx1, _rx1) = chan();
        let (tx2, _rx2) = chan();
        let c1 = st.next_conn_id();
        let c2 = st.next_conn_id();
        st.register(info(100_000_001), "KEY".into(), c1, tx1).unwrap();
        st.register(info(100_000_001), "KEY".into(), c2, tx2).unwrap();
        assert_eq!(st.peer_count(), 1);
        // The stale connection closing must not evict the fresh registration.
        st.unregister(id(100_000_001), c1);
        assert!(st.is_online(id(100_000_001)));
        st.unregister(id(100_000_001), c2);
        assert!(!st.is_online(id(100_000_001)));
    }

    #[test]
    fn different_key_cannot_take_a_held_id() {
        let st = ServerState::new();
        let (tx1, _r1) = chan();
        let (tx2, _r2) = chan();
        st.register(info(100_000_001), "KEY-A".into(), 1, tx1).unwrap();
        assert_eq!(
            st.register(info(100_000_001), "KEY-B".into(), 2, tx2),
            Err(RegisterError::IdHeldByOtherKey)
        );
        assert_eq!(st.peer_count(), 1);
    }

    #[test]
    fn roles_and_routing_across_a_session() {
        let st = ServerState::new();
        let (txa, _ra) = chan();
        let (txb, mut rb) = chan();
        let (txc, _rc) = chan();
        st.register(info(100_000_001), "A".into(), 1, txa).unwrap();
        st.register(info(100_000_002), "B".into(), 2, txb).unwrap();
        st.register(info(100_000_003), "C".into(), 3, txc).unwrap();
        let s = Uuid::new_v4();
        st.open_session(s, id(100_000_001), id(100_000_002));
        assert_eq!(st.role_in(s, id(100_000_001)), Some(Role::Caller));
        assert_eq!(st.role_in(s, id(100_000_002)), Some(Role::Callee));
        assert_eq!(st.role_in(s, id(100_000_003)), None);
        assert!(st.peer_across(s, id(100_000_003)).is_none());
        st.peer_across(s, id(100_000_001)).unwrap().try_send(SignalMessage::Ping { nonce: 1 }).unwrap();
        assert!(matches!(rb.try_recv(), Ok(SignalMessage::Ping { nonce: 1 })));
    }

    #[test]
    fn reopening_the_same_pair_supersedes_the_old_session() {
        let st = ServerState::new();
        let s1 = Uuid::new_v4();
        let s2 = Uuid::new_v4();
        st.open_session(s1, id(100_000_001), id(100_000_002));
        st.open_session(s2, id(100_000_001), id(100_000_002));
        assert_eq!(st.session_count(), 1);
        assert!(st.role_in(s1, id(100_000_001)).is_none());
        assert!(st.role_in(s2, id(100_000_001)).is_some());
        // The reverse direction is a different session and coexists.
        st.open_session(Uuid::new_v4(), id(100_000_002), id(100_000_001));
        assert_eq!(st.session_count(), 2);
    }

    #[test]
    fn unregister_drops_that_peers_sessions() {
        let st = ServerState::new();
        let (txa, _ra) = chan();
        st.register(info(100_000_001), "A".into(), 1, txa).unwrap();
        st.open_session(Uuid::new_v4(), id(100_000_001), id(100_000_002));
        st.open_session(Uuid::new_v4(), id(100_000_003), id(100_000_004));
        st.unregister(id(100_000_001), 1);
        assert_eq!(st.session_count(), 1);
    }

    #[test]
    fn per_ip_connection_cap() {
        let limits = IpLimits::new(2, 30, Duration::from_secs(60));
        let a: IpAddr = "203.0.113.1".parse().unwrap();
        let b: IpAddr = "203.0.113.2".parse().unwrap();
        assert!(limits.try_acquire(a));
        assert!(limits.try_acquire(a));
        assert!(!limits.try_acquire(a), "third socket from the same IP is refused");
        assert_eq!(limits.connections(a), 2, "the refused one was not counted");
        assert!(limits.try_acquire(b), "another IP is unaffected");
        limits.release(a);
        assert!(limits.try_acquire(a), "a closed socket frees a slot");
        limits.release(a);
        limits.release(a);
        assert_eq!(limits.connections(a), 0);
        limits.release(a);
        assert_eq!(limits.connections(a), 0, "never underflows");
    }

    #[test]
    fn per_ip_registration_rate_and_table_bound() {
        let limits = IpLimits::new(20, 2, Duration::from_secs(2));
        let a: IpAddr = "203.0.113.1".parse().unwrap();
        let t0 = Instant::now();
        assert!(limits.allow_registration_at(a, t0));
        assert!(limits.allow_registration_at(a, t0));
        assert!(!limits.allow_registration_at(a, t0), "burst spent");
        assert!(limits.allow_registration_at("203.0.113.2".parse().unwrap(), t0), "other IP has its own bucket");
        assert!(limits.allow_registration_at(a, t0 + Duration::from_secs(1)), "one token per second");
        // A scan from many addresses must not grow the table without bound:
        // once over the soft cap, replenished buckets are dropped.
        let later = t0 + Duration::from_secs(3);
        for i in 0..(IP_TABLE_SOFT_CAP as u32 + 5) {
            let ip = IpAddr::V4(std::net::Ipv4Addr::from(0x0A00_0000 + i));
            assert!(limits.allow_registration_at(ip, later));
        }
        assert!(limits.tracked_ips() <= IP_TABLE_SOFT_CAP + 5);
        // Everything so far is replenished after a window; the next call
        // prunes the table down to (nearly) nothing.
        let _ = limits.allow_registration_at(a, later + Duration::from_secs(10));
        assert!(limits.tracked_ips() < 10, "tracked {}", limits.tracked_ips());
    }

    #[test]
    fn rate_limiter_allows_burst_then_refills() {
        let t0 = Instant::now();
        let mut rl = RateLimiter::new(3, Duration::from_secs(3));
        assert!(rl.allow_at(t0));
        assert!(rl.allow_at(t0));
        assert!(rl.allow_at(t0));
        assert!(!rl.allow_at(t0));
        // One token per second refills.
        assert!(!rl.allow_at(t0 + Duration::from_millis(900)));
        assert!(rl.allow_at(t0 + Duration::from_millis(1000)));
        assert!(!rl.allow_at(t0 + Duration::from_millis(1000)));
        // Never exceeds capacity even after a long idle.
        assert!(rl.allow_at(t0 + Duration::from_secs(100)));
        assert!(rl.allow_at(t0 + Duration::from_secs(100)));
        assert!(rl.allow_at(t0 + Duration::from_secs(100)));
        assert!(!rl.allow_at(t0 + Duration::from_secs(100)));
    }
}
