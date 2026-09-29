//! Shared server state: the device registry and active session routing table.
//!
//! Security invariants enforced here (see `docs/SECURITY.md`):
//! * A CleanDesk ID is *derived* from the device's Ed25519 public key. The
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

use cleandesk_proto::{
    id::CleanDeskId,
    message::SignalMessage,
    session::{DeviceInfo, SessionId},
};
use dashmap::DashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::mpsc::UnboundedSender;
use tracing::{info, warn};

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
    pub tx: UnboundedSender<SignalMessage>,
}

/// A pending or active session, used to route Accept/Reject/Signal messages
/// between the two endpoints.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Session {
    pub caller: CleanDeskId,
    pub callee: CleanDeskId,
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
    peers: DashMap<CleanDeskId, Peer>,
    sessions: DashMap<SessionId, Session>,
    next_conn: AtomicU64,
    ip_limits: IpLimits,
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

    pub fn ip_limits(&self) -> &IpLimits {
        &self.ip_limits
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
        tx: UnboundedSender<SignalMessage>,
    ) -> Result<CleanDeskId, RegisterError> {
        let id = info.id;
        if let Some(existing) = self.peers.get(&id) {
            if existing.public_key != public_key {
                return Err(RegisterError::IdHeldByOtherKey);
            }
            info!(%id, old_conn = existing.conn, new_conn = conn, "device re-registered; replacing stale connection");
            // Tell the old connection it lost the registration, so a host that
            // is still alive there (e.g. the service helper while the GUI runs)
            // can stand down instead of believing it is reachable.
            let _ = existing.tx.send(SignalMessage::Error {
                code: cleandesk_proto::message::ErrorCode::IdConflict,
                detail: "replaced by a newer registration of the same device".into(),
            });
            // Sessions that belonged to the old connection are dead: the peer
            // on the other end will get nothing back, so drop them now.
            self.sessions.retain(|_, s| s.caller != id && s.callee != id);
        }
        self.peers.insert(id, Peer { info, public_key, conn, tx });
        info!(%id, count = self.peers.len(), "device registered");
        Ok(id)
    }

    /// Remove a peer and any sessions it participates in — but only if the
    /// entry still belongs to connection `conn`. A stale connection closing
    /// after a re-registration must not evict the live entry.
    pub fn unregister(&self, id: CleanDeskId, conn: ConnId) {
        let removed = self.peers.remove_if(&id, |_, p| p.conn == conn).is_some();
        if removed {
            self.sessions.retain(|_, s| s.caller != id && s.callee != id);
            info!(%id, count = self.peers.len(), "device unregistered");
        }
    }

    /// Look up a peer's outbound channel.
    pub fn sender(&self, id: CleanDeskId) -> Option<UnboundedSender<SignalMessage>> {
        self.peers.get(&id).map(|p| p.tx.clone())
    }

    pub fn is_online(&self, id: CleanDeskId) -> bool {
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
    pub fn open_session(&self, session: SessionId, caller: CleanDeskId, callee: CleanDeskId) {
        self.sessions.retain(|_, s| !(s.caller == caller && s.callee == callee));
        self.sessions.insert(session, Session { caller, callee });
    }

    pub fn close_session(&self, session: SessionId) {
        self.sessions.remove(&session);
    }

    /// The role `me` plays in `session`, if `me` is part of it at all.
    pub fn role_in(&self, session: SessionId, me: CleanDeskId) -> Option<Role> {
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
        me: CleanDeskId,
    ) -> Option<UnboundedSender<SignalMessage>> {
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

    fn id(n: u64) -> CleanDeskId {
        CleanDeskId::new(n).unwrap()
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

    fn chan() -> (UnboundedSender<SignalMessage>, mpsc::UnboundedReceiver<SignalMessage>) {
        mpsc::unbounded_channel()
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
        st.peer_across(s, id(100_000_001)).unwrap().send(SignalMessage::Ping { nonce: 1 }).unwrap();
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
