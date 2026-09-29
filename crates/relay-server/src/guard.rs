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
//!   operator opts in (`CLEANDESK_RELAY_ALLOW_PRIVATE_PEERS=1`, for a relay
//!   that serves a private LAN). Datagrams *from* such sources are dropped
//!   too, so a spoofed "peer" inside the network cannot be reflected out.
//! * **Quotas.** Each allocation (one relay socket) may live at most
//!   [`Quotas::max_secs`] and carry at most [`Quotas::max_bytes`] in both
//!   directions together. Once exceeded the socket reports an error: the
//!   engine treats that as the allocation dying and removes it, and the
//!   client has to allocate again (and re-authenticate).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use tracing::{debug, trace};
use turn::relay::RelayAddressGenerator;
use webrtc_util::Conn;

/// Per-allocation limits. `0` means unlimited.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Quotas {
    pub max_secs: u64,
    pub max_bytes: u64,
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
/// [`GuardedConn`].
pub struct GuardedRelayGenerator {
    inner: Box<dyn RelayAddressGenerator + Send + Sync>,
    policy: Arc<PeerPolicy>,
}

impl GuardedRelayGenerator {
    pub fn new(inner: Box<dyn RelayAddressGenerator + Send + Sync>, policy: PeerPolicy) -> Self {
        Self { inner, policy: Arc::new(policy) }
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
        let (conn, relay_addr) = self.inner.allocate_conn(use_ipv4, requested_port).await?;
        let guarded: Arc<dyn Conn + Send + Sync> = Arc::new(GuardedConn::new(conn, self.policy.clone()));
        Ok((guarded, relay_addr))
    }
}

/// One allocation's relay socket with the policy applied.
pub struct GuardedConn {
    inner: Arc<dyn Conn + Send + Sync>,
    policy: Arc<PeerPolicy>,
    created: Instant,
    bytes: AtomicU64,
}

impl GuardedConn {
    pub fn new(inner: Arc<dyn Conn + Send + Sync>, policy: Arc<PeerPolicy>) -> Self {
        Self { inner, policy, created: Instant::now(), bytes: AtomicU64::new(0) }
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
            Arc::new(PeerPolicy { allow_private: false, quotas: Quotas { max_secs: 0, max_bytes: 0 } }),
        );
        assert_eq!(deny.send_to(b"hi", peer_addr).await.unwrap(), 2, "swallowed, reported as sent");
        let mut buf = [0u8; 16];
        assert!(tokio::time::timeout(Duration::from_millis(300), peer.recv_from(&mut buf)).await.is_err());

        let allow = GuardedConn::new(
            a.clone(),
            Arc::new(PeerPolicy { allow_private: true, quotas: Quotas { max_secs: 0, max_bytes: 5 } }),
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
            Arc::new(PeerPolicy { allow_private: true, quotas: Quotas { max_secs: 1, max_bytes: 0 } }),
        );
        let mut buf = [0u8; 16];
        let started = Instant::now();
        let r = tokio::time::timeout(Duration::from_secs(5), c.recv_from(&mut buf)).await;
        assert!(matches!(r, Ok(Err(_))), "recv must fail once the time quota is over, not hang");
        assert!(started.elapsed() >= Duration::from_millis(900));
    }
}
