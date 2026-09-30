//! Relay-side abuse controls the TURN engine does not offer by itself.
//!
//! The `turn` crate exposes two hooks: the credential lookup
//! ([`turn::auth::AuthHandler`]) and the relay socket factory
//! ([`RelayAddressGenerator`]). There is no callback on `CreatePermission`,
//! `ChannelBind` or `Send`, so the peer-address filter and the quotas live in
//! a wrapper around the relay socket itself ([`GuardedConn`]): every datagram
//! the engine relays *to* a peer or accepts *from* a peer goes through it.
//!
//! * **Peer filter.** A TURN server is a UDP proxy for whoever holds a
//!   credential, and the community credential is public. Relaying towards
//!   loopback, link-local, private (RFC 1918 / ULA), shared-address-space and
//!   multicast ranges would let any client poke at the relay operator's own
//!   machine and network; those datagrams are silently dropped unless the
//!   operator opts in (`ROTODESK_RELAY_ALLOW_PRIVATE_PEERS=1`, for a relay
//!   that serves a private LAN). Datagrams *from* such sources are dropped
//!   too, so a spoofed "peer" inside the network cannot be reflected out.
//! * **Quotas.** Each allocation (one relay socket) may live at most
//!   [`Quotas::max_secs`] and carry at most [`Quotas::max_bytes`] in both
//!   directions together, at no more than [`Quotas::max_kbps`]. Once a total
//!   is exceeded the socket reports an error: the engine treats that as the
//!   allocation dying and removes it, and the client has to allocate again
//!   (and re-authenticate). Datagrams over the rate are dropped.
//! * **Allocation caps.** The engine has no quota on allocations at all, and
//!   in community mode the credential is public, so without a cap one
//!   address could open thousands of relay sockets. [`Ledger`] counts live
//!   allocations per source IP and globally; [`ListenerGuard`] wraps the
//!   listening socket to enforce those caps before the engine sees an
//!   `Allocate`, and to rate-limit unauthenticated STUN requests per source
//!   (each one makes the engine remember a fresh nonce for an hour).

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use tracing::{debug, trace, warn};
use turn::relay::RelayAddressGenerator;
use webrtc_util::Conn;

/// Per-allocation limits. `0` means unlimited.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Quotas {
    pub max_secs: u64,
    pub max_bytes: u64,
    /// Sustained throughput cap per allocation, both directions together,
    /// in kilobits per second (`0` = unlimited).
    pub max_kbps: u64,
}

/// How many allocations may exist at once. `0` means unlimited.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AllocationCaps {
    pub per_ip: usize,
    pub total: usize,
}

/// Unauthenticated STUN requests (no MESSAGE-INTEGRITY) accepted from one
/// source per [`UNAUTH_WINDOW`]: a legitimate client needs one per
/// allocation (to learn the nonce) plus a few for STUN binding.
pub const UNAUTH_BURST: u32 = 20;
pub const UNAUTH_WINDOW: Duration = Duration::from_secs(10);
/// Authenticated `Allocate` requests accepted from one source per minute.
pub const ALLOCATE_BURST: u32 = 10;
pub const ALLOCATE_WINDOW: Duration = Duration::from_secs(60);
/// Above this many tracked sources, replenished buckets are dropped.
const SOURCE_TABLE_SOFT_CAP: usize = 10_000;

const STUN_MAGIC_COOKIE: [u8; 4] = [0x21, 0x12, 0xA4, 0x42];
const STUN_HEADER: usize = 20;
const ATTR_MESSAGE_INTEGRITY: u16 = 0x0008;
const METHOD_ALLOCATE_REQUEST: u16 = 0x0003;

/// A small token bucket (same shape as the signaling server's).
#[derive(Debug, Clone)]
pub struct TokenBucket {
    capacity: f64,
    tokens: f64,
    refill_per_sec: f64,
    last: Instant,
}

impl TokenBucket {
    pub fn new(burst: u32, per: Duration) -> Self {
        let capacity = f64::from(burst.max(1));
        Self { capacity, tokens: capacity, refill_per_sec: capacity / per.as_secs_f64().max(f64::EPSILON), last: Instant::now() }
    }

    /// A bucket for `bytes_per_sec` with one second of burst.
    pub fn bytes(bytes_per_sec: f64) -> Self {
        let capacity = bytes_per_sec.max(1.0);
        Self { capacity, tokens: capacity, refill_per_sec: capacity, last: Instant::now() }
    }

    pub fn take(&mut self, amount: f64) -> bool {
        self.take_at(amount, Instant::now())
    }

    pub fn take_at(&mut self, amount: f64, now: Instant) -> bool {
        let elapsed = now.saturating_duration_since(self.last).as_secs_f64();
        self.last = now;
        self.tokens = (self.tokens + elapsed * self.refill_per_sec).min(self.capacity);
        if self.tokens >= amount {
            self.tokens -= amount;
            true
        } else {
            false
        }
    }

    pub fn is_replenished_at(&self, now: Instant) -> bool {
        let elapsed = now.saturating_duration_since(self.last).as_secs_f64();
        self.tokens + elapsed * self.refill_per_sec >= self.capacity
    }
}

/// Live allocation accounting shared by the listener guard (which decides
/// whether an `Allocate` may reach the engine) and the relay sockets (which
/// release their slot when the engine drops them).
#[derive(Debug)]
pub struct Ledger {
    caps: AllocationCaps,
    per_ip: Mutex<HashMap<IpAddr, usize>>,
    total: AtomicUsize,
    /// Source of the datagram the engine is currently handling. The engine
    /// processes one datagram at a time per listener, so the relay socket
    /// allocated while handling an `Allocate` belongs to this source.
    current: Mutex<Option<IpAddr>>,
}

impl Ledger {
    pub fn new(caps: AllocationCaps) -> Self {
        Self { caps, per_ip: Mutex::new(HashMap::new()), total: AtomicUsize::new(0), current: Mutex::new(None) }
    }

    pub fn caps(&self) -> AllocationCaps {
        self.caps
    }

    pub fn live_total(&self) -> usize {
        self.total.load(Ordering::Relaxed)
    }

    pub fn live_for(&self, ip: IpAddr) -> usize {
        self.per_ip.lock().unwrap_or_else(|e| e.into_inner()).get(&ip).copied().unwrap_or(0)
    }

    fn set_current(&self, ip: IpAddr) {
        *self.current.lock().unwrap_or_else(|e| e.into_inner()) = Some(ip);
    }

    /// Would one more allocation for `ip` stay within the caps?
    pub fn has_room(&self, ip: IpAddr) -> bool {
        let caps = self.caps;
        if caps.total != 0 && self.live_total() >= caps.total {
            return false;
        }
        caps.per_ip == 0 || self.live_for(ip) < caps.per_ip
    }

    /// Reserve a slot for the source currently being served. `None` when the
    /// caps are reached (or no source is known, which cannot happen through
    /// the guarded listener).
    fn reserve_current(self: &Arc<Self>) -> Option<Slot> {
        let ip = (*self.current.lock().unwrap_or_else(|e| e.into_inner()))?;
        if !self.has_room(ip) {
            return None;
        }
        *self.per_ip.lock().unwrap_or_else(|e| e.into_inner()).entry(ip).or_insert(0) += 1;
        self.total.fetch_add(1, Ordering::Relaxed);
        Some(Slot { ledger: self.clone(), ip })
    }

    fn release(&self, ip: IpAddr) {
        let mut per_ip = self.per_ip.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(n) = per_ip.get_mut(&ip) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                per_ip.remove(&ip);
            }
        }
        let _ = self.total.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| Some(n.saturating_sub(1)));
    }
}

/// One counted allocation; releases its slot when dropped (the engine drops
/// the relay socket when the allocation is deleted or expires).
#[derive(Debug)]
pub struct Slot {
    ledger: Arc<Ledger>,
    ip: IpAddr,
}

impl Drop for Slot {
    fn drop(&mut self) {
        self.ledger.release(self.ip);
    }
}

/// Classification of one inbound datagram on the listening socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Inbound {
    /// STUN request without MESSAGE-INTEGRITY (costs the engine a nonce).
    Unauthenticated,
    /// Authenticated `Allocate` request.
    Allocate,
    /// Anything else (authenticated non-Allocate STUN, ChannelData, junk).
    Other,
}

/// Look at a datagram just enough to know how to rate-limit it. Never
/// panics on short or malformed input; the engine does the real parsing.
pub fn classify(datagram: &[u8]) -> Inbound {
    if datagram.len() < STUN_HEADER || datagram[0] & 0xC0 != 0 || datagram[4..8] != STUN_MAGIC_COOKIE {
        return Inbound::Other;
    }
    let msg_type = u16::from_be_bytes([datagram[0], datagram[1]]);
    let declared_len = u16::from_be_bytes([datagram[2], datagram[3]]) as usize;
    let body = &datagram[STUN_HEADER..datagram.len().min(STUN_HEADER + declared_len)];
    let mut has_integrity = false;
    let mut i = 0;
    while i + 4 <= body.len() {
        let attr_type = u16::from_be_bytes([body[i], body[i + 1]]);
        let attr_len = u16::from_be_bytes([body[i + 2], body[i + 3]]) as usize;
        if attr_type == ATTR_MESSAGE_INTEGRITY {
            has_integrity = true;
            break;
        }
        // Attributes are padded to four bytes.
        i += 4 + attr_len.div_ceil(4) * 4;
    }
    // Only requests (class bits 00) carry MESSAGE-INTEGRITY obligations;
    // indications and responses from clients are ignored by the engine.
    let is_request = msg_type & 0x0110 == 0;
    if !is_request {
        return Inbound::Other;
    }
    if !has_integrity {
        Inbound::Unauthenticated
    } else if msg_type == METHOD_ALLOCATE_REQUEST {
        Inbound::Allocate
    } else {
        Inbound::Other
    }
}

/// Per-source rate limiting applied to the listening socket.
#[derive(Debug)]
pub struct SourceLimits {
    unauth: Mutex<HashMap<IpAddr, TokenBucket>>,
    allocate: Mutex<HashMap<IpAddr, TokenBucket>>,
}

impl Default for SourceLimits {
    fn default() -> Self {
        Self::new()
    }
}

impl SourceLimits {
    pub fn new() -> Self {
        Self { unauth: Mutex::new(HashMap::new()), allocate: Mutex::new(HashMap::new()) }
    }

    fn allow(table: &Mutex<HashMap<IpAddr, TokenBucket>>, ip: IpAddr, burst: u32, per: Duration, now: Instant) -> bool {
        let mut table = table.lock().unwrap_or_else(|e| e.into_inner());
        if table.len() > SOURCE_TABLE_SOFT_CAP {
            table.retain(|_, b| !b.is_replenished_at(now));
        }
        table.entry(ip).or_insert_with(|| TokenBucket::new(burst, per)).take_at(1.0, now)
    }

    pub fn allow_unauthenticated(&self, ip: IpAddr, now: Instant) -> bool {
        Self::allow(&self.unauth, ip, UNAUTH_BURST, UNAUTH_WINDOW, now)
    }

    pub fn allow_allocate(&self, ip: IpAddr, now: Instant) -> bool {
        Self::allow(&self.allocate, ip, ALLOCATE_BURST, ALLOCATE_WINDOW, now)
    }
}

/// The listening socket with per-source limits and allocation caps applied
/// before the TURN engine sees a datagram.
pub struct ListenerGuard {
    inner: Arc<dyn Conn + Send + Sync>,
    ledger: Arc<Ledger>,
    limits: SourceLimits,
}

impl ListenerGuard {
    pub fn new(inner: Arc<dyn Conn + Send + Sync>, ledger: Arc<Ledger>) -> Self {
        Self { inner, ledger, limits: SourceLimits::new() }
    }

    /// Decide whether a datagram from `src` may reach the engine.
    fn admit(&self, datagram: &[u8], src: SocketAddr, now: Instant) -> bool {
        match classify(datagram) {
            Inbound::Other => true,
            Inbound::Unauthenticated => {
                let ok = self.limits.allow_unauthenticated(src.ip(), now);
                if !ok {
                    trace!(%src, "dropping unauthenticated STUN request over the per-source rate");
                }
                ok
            }
            Inbound::Allocate => {
                if !self.limits.allow_allocate(src.ip(), now) {
                    debug!(%src, "dropping Allocate over the per-source rate");
                    return false;
                }
                if !self.ledger.has_room(src.ip()) {
                    warn!(%src, live = self.ledger.live_for(src.ip()), total = self.ledger.live_total(), "allocation caps reached; dropping Allocate");
                    return false;
                }
                true
            }
        }
    }
}

#[async_trait]
impl Conn for ListenerGuard {
    async fn connect(&self, addr: SocketAddr) -> webrtc_util::Result<()> {
        self.inner.connect(addr).await
    }

    async fn recv(&self, buf: &mut [u8]) -> webrtc_util::Result<usize> {
        self.inner.recv(buf).await
    }

    async fn recv_from(&self, buf: &mut [u8]) -> webrtc_util::Result<(usize, SocketAddr)> {
        loop {
            let (n, src) = self.inner.recv_from(buf).await?;
            if self.admit(&buf[..n], src, Instant::now()) {
                self.ledger.set_current(src.ip());
                return Ok((n, src));
            }
        }
    }

    async fn send(&self, buf: &[u8]) -> webrtc_util::Result<usize> {
        self.inner.send(buf).await
    }

    async fn send_to(&self, buf: &[u8], target: SocketAddr) -> webrtc_util::Result<usize> {
        self.inner.send_to(buf, target).await
    }

    fn local_addr(&self) -> webrtc_util::Result<SocketAddr> {
        self.inner.local_addr()
    }

    fn remote_addr(&self) -> Option<SocketAddr> {
        self.inner.remote_addr()
    }

    async fn close(&self) -> webrtc_util::Result<()> {
        self.inner.close().await
    }

    fn as_any(&self) -> &(dyn std::any::Any + Send + Sync) {
        self
    }
}

/// Which peer addresses the relay agrees to talk to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerPolicy {
    /// Relay to loopback / link-local / private / multicast peers too.
    pub allow_private: bool,
    pub quotas: Quotas,
}

impl PeerPolicy {
    pub fn allows(&self, ip: IpAddr) -> bool {
        is_peer_allowed(ip, self.allow_private)
    }
}

/// Is `ip` an acceptable relay peer? Public unicast always is; the ranges
/// that reach the operator's own host or network only when `allow_private`.
/// Unspecified and broadcast addresses are never acceptable.
pub fn is_peer_allowed(ip: IpAddr, allow_private: bool) -> bool {
    match ip {
        IpAddr::V4(v4) => is_v4_allowed(v4, allow_private),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            // `::ffff:a.b.c.d` is the same host as `a.b.c.d`.
            Some(v4) => is_v4_allowed(v4, allow_private),
            None => is_v6_allowed(v6, allow_private),
        },
    }
}

fn is_v4_allowed(ip: Ipv4Addr, allow_private: bool) -> bool {
    let o = ip.octets();
    if ip.is_unspecified() || ip.is_broadcast() || o[0] == 0 {
        return false;
    }
    let local_or_private = ip.is_loopback()
        || ip.is_link_local()
        || ip.is_private()
        // Shared address space (RFC 6598), used by carrier-grade NAT.
        || (o[0] == 100 && (64..=127).contains(&o[1]))
        || ip.is_multicast();
    !local_or_private || allow_private
}

fn is_v6_allowed(ip: Ipv6Addr, allow_private: bool) -> bool {
    if ip.is_unspecified() {
        return false;
    }
    let s = ip.segments();
    let local_or_private = ip.is_loopback()
        // fe80::/10 link-local.
        || (s[0] & 0xffc0) == 0xfe80
        // fc00::/7 unique local.
        || (s[0] & 0xfe00) == 0xfc00
        // ff00::/8 multicast.
        || ip.is_multicast();
    !local_or_private || allow_private
}

/// Wraps any relay generator so every relay socket it hands the engine is a
/// [`GuardedConn`] counted in the [`Ledger`].
pub struct GuardedRelayGenerator {
    inner: Box<dyn RelayAddressGenerator + Send + Sync>,
    policy: Arc<PeerPolicy>,
    ledger: Arc<Ledger>,
}

impl GuardedRelayGenerator {
    pub fn new(inner: Box<dyn RelayAddressGenerator + Send + Sync>, policy: PeerPolicy, ledger: Arc<Ledger>) -> Self {
        Self { inner, policy: Arc::new(policy), ledger }
    }
}

#[async_trait]
impl RelayAddressGenerator for GuardedRelayGenerator {
    fn validate(&self) -> std::result::Result<(), turn::Error> {
        self.inner.validate()
    }

    async fn allocate_conn(
        &self,
        use_ipv4: bool,
        requested_port: u16,
    ) -> std::result::Result<(Arc<dyn Conn + Send + Sync>, SocketAddr), turn::Error> {
        // The listener guard already refused over-cap `Allocate`s; this is
        // the authoritative count (and the fallback for any other path).
        let Some(slot) = self.ledger.reserve_current() else {
            return Err(turn::Error::Other("allocation caps reached".into()));
        };
        let (conn, relay_addr) = self.inner.allocate_conn(use_ipv4, requested_port).await?;
        let guarded: Arc<dyn Conn + Send + Sync> =
            Arc::new(GuardedConn::new(conn, self.policy.clone()).with_slot(slot));
        Ok((guarded, relay_addr))
    }
}

/// One allocation's relay socket with the policy applied.
pub struct GuardedConn {
    inner: Arc<dyn Conn + Send + Sync>,
    policy: Arc<PeerPolicy>,
    created: Instant,
    bytes: AtomicU64,
    rate: Option<Mutex<TokenBucket>>,
    _slot: Option<Slot>,
}

impl GuardedConn {
    pub fn new(inner: Arc<dyn Conn + Send + Sync>, policy: Arc<PeerPolicy>) -> Self {
        let rate = match policy.quotas.max_kbps {
            0 => None,
            kbps => Some(Mutex::new(TokenBucket::bytes(kbps as f64 * 1000.0 / 8.0))),
        };
        Self { inner, policy, created: Instant::now(), bytes: AtomicU64::new(0), rate, _slot: None }
    }

    fn with_slot(mut self, slot: Slot) -> Self {
        self._slot = Some(slot);
        self
    }

    /// Does `n` more bytes fit the sustained rate right now?
    fn within_rate(&self, n: usize) -> bool {
        match &self.rate {
            None => true,
            Some(bucket) => bucket.lock().unwrap_or_else(|e| e.into_inner()).take(n as f64),
        }
    }

    /// Time left before the time quota closes this allocation, if any.
    fn time_left(&self) -> Option<Duration> {
        let max = self.policy.quotas.max_secs;
        if max == 0 {
            return None;
        }
        Some(Duration::from_secs(max).saturating_sub(self.created.elapsed()))
    }

    fn exhausted(&self) -> webrtc_util::Result<()> {
        if self.time_left().is_some_and(|left| left.is_zero()) {
            debug!(local = ?self.inner.local_addr().ok(), "allocation time quota exhausted");
            return Err(webrtc_util::Error::Other("allocation time quota exhausted".into()));
        }
        let max = self.policy.quotas.max_bytes;
        if max != 0 && self.bytes.load(Ordering::Relaxed) >= max {
            debug!(local = ?self.inner.local_addr().ok(), "allocation byte quota exhausted");
            return Err(webrtc_util::Error::Other("allocation byte quota exhausted".into()));
        }
        Ok(())
    }

    fn account(&self, n: usize) {
        self.bytes.fetch_add(n as u64, Ordering::Relaxed);
    }
}

#[async_trait]
impl Conn for GuardedConn {
    async fn connect(&self, addr: SocketAddr) -> webrtc_util::Result<()> {
        if !self.policy.allows(addr.ip()) {
            return Err(webrtc_util::Error::Other("peer address not allowed".into()));
        }
        self.inner.connect(addr).await
    }

    async fn recv(&self, buf: &mut [u8]) -> webrtc_util::Result<usize> {
        self.exhausted()?;
        let n = self.inner.recv(buf).await?;
        self.account(n);
        Ok(n)
    }

    /// Datagrams from disallowed sources are dropped and the wait continues,
    /// so the engine only ever sees traffic from acceptable peers. The wait
    /// itself is bounded by the time quota.
    async fn recv_from(&self, buf: &mut [u8]) -> webrtc_util::Result<(usize, SocketAddr)> {
        loop {
            self.exhausted()?;
            let recv = self.inner.recv_from(buf);
            let (n, src) = match self.time_left() {
                Some(left) => match tokio::time::timeout(left, recv).await {
                    Ok(r) => r?,
                    Err(_) => continue, // re-checks the quota and fails
                },
                None => recv.await?,
            };
            if !self.policy.allows(src.ip()) {
                trace!(%src, "dropping datagram from a disallowed peer");
                continue;
            }
            if !self.within_rate(n) {
                trace!(%src, "dropping datagram over the allocation rate");
                continue;
            }
            self.account(n);
            return Ok((n, src));
        }
    }

    async fn send(&self, buf: &[u8]) -> webrtc_util::Result<usize> {
        self.exhausted()?;
        self.account(buf.len());
        self.inner.send(buf).await
    }

    /// A datagram towards a disallowed peer is swallowed (reported as sent):
    /// the client gets no signal it could use to probe the network.
    async fn send_to(&self, buf: &[u8], target: SocketAddr) -> webrtc_util::Result<usize> {
        self.exhausted()?;
        if !self.policy.allows(target.ip()) {
            debug!(%target, "refusing to relay to a disallowed peer address");
            return Ok(buf.len());
        }
        if !self.within_rate(buf.len()) {
            trace!(%target, "dropping datagram over the allocation rate");
            return Ok(buf.len());
        }
        self.account(buf.len());
        self.inner.send_to(buf, target).await
    }

    fn local_addr(&self) -> webrtc_util::Result<SocketAddr> {
        self.inner.local_addr()
    }

    fn remote_addr(&self) -> Option<SocketAddr> {
        self.inner.remote_addr()
    }

    async fn close(&self) -> webrtc_util::Result<()> {
        self.inner.close().await
    }

    fn as_any(&self) -> &(dyn std::any::Any + Send + Sync) {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn public_unicast_is_always_allowed() {
        for s in ["8.8.8.8", "203.0.113.5", "1.1.1.1", "2001:db8::1", "2606:4700::1111", "::ffff:8.8.8.8"] {
            assert!(is_peer_allowed(ip(s), false), "{s}");
            assert!(is_peer_allowed(ip(s), true), "{s}");
        }
    }

    #[test]
    fn local_and_private_ranges_are_refused_by_default_and_opt_in() {
        let cases = [
            "127.0.0.1",
            "127.255.255.254",
            "169.254.1.1",
            "10.0.0.1",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.1.1",
            "100.64.0.1",
            "100.127.255.255",
            "224.0.0.1",
            "239.255.255.250",
            "::1",
            "fe80::1",
            "febf::1",
            "fc00::1",
            "fd12:3456::1",
            "ff02::1",
            "::ffff:127.0.0.1",
            "::ffff:192.168.0.10",
            "::ffff:10.1.2.3",
        ];
        for s in cases {
            assert!(!is_peer_allowed(ip(s), false), "{s} must be refused by default");
            assert!(is_peer_allowed(ip(s), true), "{s} allowed when opted in");
        }
    }

    #[test]
    fn unspecified_and_broadcast_are_never_allowed() {
        for s in ["0.0.0.0", "0.1.2.3", "255.255.255.255", "::", "::ffff:0.0.0.0"] {
            assert!(!is_peer_allowed(ip(s), false), "{s}");
            assert!(!is_peer_allowed(ip(s), true), "{s}");
        }
    }

    #[test]
    fn boundaries_of_private_ranges() {
        assert!(is_peer_allowed(ip("172.15.255.255"), false));
        assert!(is_peer_allowed(ip("172.32.0.0"), false));
        assert!(is_peer_allowed(ip("100.63.255.255"), false));
        assert!(is_peer_allowed(ip("100.128.0.0"), false));
        assert!(is_peer_allowed(ip("9.255.255.255"), false));
        assert!(is_peer_allowed(ip("11.0.0.0"), false));
        assert!(is_peer_allowed(ip("fe00::1"), false));
        assert!(is_peer_allowed(ip("fec0::1"), false), "fec0::/10 is deprecated site-local, not link-local");
        assert!(is_peer_allowed(ip("fb00::1"), false));
    }

    /// The guard as the engine sees it: a loopback socket pair with a
    /// deny-private policy relays nothing, with allow-private it does, and
    /// the byte quota tears the socket down.
    #[tokio::test]
    async fn guarded_conn_filters_and_meters() {
        let a = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let peer = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer_addr = peer.local_addr().unwrap();
        let deny = GuardedConn::new(
            a.clone(),
            Arc::new(PeerPolicy { allow_private: false, quotas: Quotas { max_secs: 0, max_bytes: 0, max_kbps: 0 } }),
        );
        assert_eq!(deny.send_to(b"hi", peer_addr).await.unwrap(), 2, "swallowed, reported as sent");
        let mut buf = [0u8; 16];
        assert!(tokio::time::timeout(Duration::from_millis(300), peer.recv_from(&mut buf)).await.is_err());

        let allow = GuardedConn::new(
            a.clone(),
            Arc::new(PeerPolicy { allow_private: true, quotas: Quotas { max_secs: 0, max_bytes: 5, max_kbps: 0 } }),
        );
        assert_eq!(allow.send_to(b"hi", peer_addr).await.unwrap(), 2);
        let (n, _) = peer.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"hi");
        // Inbound from an allowed peer is metered too; 2 + 3 = 5 hits the quota.
        peer.send_to(b"abc", a.local_addr().unwrap()).await.unwrap();
        let (n, src) = allow.recv_from(&mut buf).await.unwrap();
        assert_eq!((n, src), (3, peer_addr));
        assert!(allow.send_to(b"x", peer_addr).await.is_err(), "quota exhausted closes the allocation");
        assert!(allow.recv_from(&mut buf).await.is_err());
    }

    #[tokio::test]
    async fn time_quota_expires_a_waiting_recv() {
        let a = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let c = GuardedConn::new(
            a,
            Arc::new(PeerPolicy { allow_private: true, quotas: Quotas { max_secs: 1, max_bytes: 0, max_kbps: 0 } }),
        );
        let mut buf = [0u8; 16];
        let started = Instant::now();
        let r = tokio::time::timeout(Duration::from_secs(5), c.recv_from(&mut buf)).await;
        assert!(matches!(r, Ok(Err(_))), "recv must fail once the time quota is over, not hang");
        assert!(started.elapsed() >= Duration::from_millis(900));
    }

    /// Minimal STUN request builder for the classifier tests.
    fn stun(msg_type: u16, attrs: &[(u16, &[u8])]) -> Vec<u8> {
        let mut body = Vec::new();
        for (t, v) in attrs {
            body.extend_from_slice(&t.to_be_bytes());
            body.extend_from_slice(&(v.len() as u16).to_be_bytes());
            body.extend_from_slice(v);
            while body.len() % 4 != 0 {
                body.push(0);
            }
        }
        let mut m = Vec::new();
        m.extend_from_slice(&msg_type.to_be_bytes());
        m.extend_from_slice(&(body.len() as u16).to_be_bytes());
        m.extend_from_slice(&STUN_MAGIC_COOKIE);
        m.extend_from_slice(&[7u8; 12]);
        m.extend_from_slice(&body);
        m
    }

    #[test]
    fn classifies_stun_requests_without_panicking() {
        assert_eq!(classify(&[]), Inbound::Other);
        assert_eq!(classify(&[0x40; 30]), Inbound::Other, "ChannelData");
        assert_eq!(classify(&stun(0x0001, &[])), Inbound::Unauthenticated, "Binding without integrity");
        assert_eq!(classify(&stun(0x0003, &[(0x0019, &[17, 0, 0, 0])])), Inbound::Unauthenticated);
        assert_eq!(classify(&stun(0x0003, &[(0x0006, b"alice"), (0x0008, &[0u8; 20])])), Inbound::Allocate);
        assert_eq!(classify(&stun(0x0004, &[(0x0008, &[0u8; 20])])), Inbound::Other, "authenticated Refresh");
        assert_eq!(classify(&stun(0x0103, &[])), Inbound::Other, "a response, not a request");
        // Truncated / lying lengths never panic.
        let mut lying = stun(0x0003, &[(0x0008, &[0u8; 20])]);
        lying[2] = 0xff;
        lying[3] = 0xff;
        assert_eq!(classify(&lying), Inbound::Allocate);
        lying.truncate(23);
        let _ = classify(&lying);
        let mut short_attr = stun(0x0003, &[]);
        short_attr.extend_from_slice(&[0, 8, 0xff, 0xff]);
        short_attr[3] = 4;
        assert_eq!(classify(&short_attr), Inbound::Allocate);
    }

    #[test]
    fn source_limits_and_ledger_enforce_caps() {
        let t0 = Instant::now();
        let limits = SourceLimits::new();
        let src = ip("203.0.113.9");
        let unauth = (0..UNAUTH_BURST + 3).filter(|_| limits.allow_unauthenticated(src, t0)).count();
        assert_eq!(unauth, UNAUTH_BURST as usize);
        assert!(limits.allow_unauthenticated(ip("203.0.113.10"), t0));
        let allocs = (0..ALLOCATE_BURST + 3).filter(|_| limits.allow_allocate(src, t0)).count();
        assert_eq!(allocs, ALLOCATE_BURST as usize);
        assert!(limits.allow_allocate(src, t0 + ALLOCATE_WINDOW), "refilled after the window");

        let ledger = Arc::new(Ledger::new(AllocationCaps { per_ip: 2, total: 3 }));
        ledger.set_current(src);
        let a = ledger.reserve_current().expect("first slot");
        let _b = ledger.reserve_current().expect("second slot");
        assert!(!ledger.has_room(src), "per-IP cap");
        assert!(ledger.reserve_current().is_none());
        let other = ip("203.0.113.10");
        ledger.set_current(other);
        let _c = ledger.reserve_current().expect("other IP has room");
        assert!(!ledger.has_room(ip("203.0.113.11")), "global cap");
        drop(a);
        assert_eq!(ledger.live_for(src), 1);
        assert_eq!(ledger.live_total(), 2);
        assert!(ledger.has_room(src));
    }

    #[tokio::test]
    async fn per_allocation_rate_drops_excess_datagrams() {
        let a = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let peer = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer_addr = peer.local_addr().unwrap();
        // 8 kbit/s = 1000 bytes/s with a one-second burst.
        let c = GuardedConn::new(
            a,
            Arc::new(PeerPolicy { allow_private: true, quotas: Quotas { max_secs: 0, max_bytes: 0, max_kbps: 8 } }),
        );
        let payload = [0u8; 400];
        for _ in 0..4 {
            assert_eq!(c.send_to(&payload, peer_addr).await.unwrap(), 400, "always reported as sent");
        }
        let mut buf = [0u8; 512];
        let mut delivered = 0;
        while let Ok(Ok(_)) = tokio::time::timeout(Duration::from_millis(200), peer.recv_from(&mut buf)).await {
            delivered += 1;
        }
        assert_eq!(delivered, 2, "only the burst worth of bytes went through");
    }
}
