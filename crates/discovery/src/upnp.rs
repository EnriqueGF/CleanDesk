//! UPnP / IGD port mapping so a host behind a home router is reachable.
//!
//! Two mappings are requested: the direct-signaling TCP port and the WebRTC
//! UDP port. Leases are renewed periodically; dropping the [`PortMapping`]
//! removes them (best effort).

use crate::{DiscoveryError, Result};
use igd_next::{aio::tokio::search_gateway, PortMappingProtocol, SearchOptions};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tracing::{debug, info, warn};

/// Lease requested from the router; renewed at half this interval.
pub const LEASE_SECS: u32 = 3600;

/// Which local address the router should forward to.
#[derive(Debug, Clone, Copy)]
pub struct MapRequest {
    pub protocol: Protocol,
    pub port: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    Tcp,
    Udp,
}

impl From<Protocol> for PortMappingProtocol {
    fn from(p: Protocol) -> Self {
        match p {
            Protocol::Tcp => PortMappingProtocol::TCP,
            Protocol::Udp => PortMappingProtocol::UDP,
        }
    }
}

/// An active set of router mappings.
pub struct PortMapping {
    gateway: igd_next::aio::Gateway<igd_next::aio::tokio::Tokio>,
    local_ip: IpAddr,
    pub external_ip: IpAddr,
    mapped: Vec<MapRequest>,
}

impl PortMapping {
    /// Discover the gateway and map every request with the same external
    /// port as the local one. Fails if no UPnP gateway answers within
    /// `timeout` or the external IP cannot be learned.
    pub async fn create(requests: &[MapRequest], timeout: Duration) -> Result<Self> {
        let opts = SearchOptions { timeout: Some(timeout), ..Default::default() };
        let gateway = search_gateway(opts)
            .await
            .map_err(|e| DiscoveryError::Other(format!("no UPnP gateway: {e}")))?;
        let external_ip = gateway
            .get_external_ip()
            .await
            .map_err(|e| DiscoveryError::Other(format!("UPnP external ip: {e}")))?;
        let local_ip = local_ip_towards(gateway.addr.ip())?;
        let mut me = Self { gateway, local_ip, external_ip, mapped: Vec::new() };
        for req in requests {
            me.map(*req).await?;
        }
        info!(%external_ip, ports = ?me.mapped.iter().map(|m| m.port).collect::<Vec<_>>(), "UPnP mappings active");
        Ok(me)
    }

    async fn map(&mut self, req: MapRequest) -> Result<()> {
        let local = SocketAddr::new(self.local_ip, req.port);
        self.gateway
            .add_port(req.protocol.into(), req.port, local, LEASE_SECS, "CleanDesk")
            .await
            .map_err(|e| DiscoveryError::Other(format!("UPnP add_port {:?} {}: {e}", req.protocol, req.port)))?;
        if !self.mapped.iter().any(|m| m.port == req.port && m.protocol == req.protocol) {
            self.mapped.push(req);
        }
        Ok(())
    }

    /// Re-request every lease (call every `LEASE_SECS / 2`).
    pub async fn renew(&mut self) {
        for req in self.mapped.clone() {
            if let Err(e) = self.map(req).await {
                warn!(error = %e, "UPnP lease renewal failed");
            }
        }
        match self.gateway.get_external_ip().await {
            Ok(ip) if ip != self.external_ip => {
                info!(old = %self.external_ip, new = %ip, "external IP changed");
                self.external_ip = ip;
            }
            Ok(_) => {}
            Err(e) => debug!(error = %e, "could not refresh external ip"),
        }
    }

    /// The externally reachable address for one of our mapped ports.
    pub fn external_addr(&self, port: u16) -> SocketAddr {
        SocketAddr::new(self.external_ip, port)
    }

    /// Remove the mappings. Best effort; the lease expires anyway.
    pub async fn release(self) {
        for req in &self.mapped {
            let _ = self.gateway.remove_port(req.protocol.into(), req.port).await;
        }
    }
}

/// The local interface address that routes towards `target` (the gateway),
/// found by connecting a UDP socket (no packets are sent).
fn local_ip_towards(target: IpAddr) -> Result<IpAddr> {
    let sock = std::net::UdpSocket::bind(if target.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" })?;
    sock.connect(SocketAddr::new(target, 1900))?;
    Ok(sock.local_addr()?.ip())
}

/// All non-loopback local IPv4/IPv6 addresses, for LAN endpoints in records.
pub fn local_addresses() -> Vec<IpAddr> {
    // Without a dedicated interface-enumeration dependency, the routing trick
    // above gives the primary address; a second probe towards a public IPv6
    // address adds the v6 one when present.
    let mut out = Vec::new();
    if let Ok(ip) = local_ip_towards("1.1.1.1".parse().unwrap_or(IpAddr::from([1, 1, 1, 1]))) {
        if !ip.is_loopback() {
            out.push(ip);
        }
    }
    if let Ok(ip) = local_ip_towards("2606:4700:4700::1111".parse().unwrap_or(IpAddr::from([0u16; 8]))) {
        if !ip.is_loopback() && !out.contains(&ip) && !ip.is_unspecified() {
            out.push(ip);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_address_probe_does_not_panic() {
        // Whatever the machine's connectivity, this must not fail loudly.
        let addrs = local_addresses();
        for a in addrs {
            assert!(!a.is_loopback());
        }
    }

    /// Live: needs a UPnP-capable router. Run with `-- --ignored`.
    #[tokio::test]
    #[ignore]
    async fn map_and_release_on_the_real_router() {
        let m = PortMapping::create(
            &[MapRequest { protocol: Protocol::Tcp, port: 47423 }],
            Duration::from_secs(3),
        )
        .await
        .expect("UPnP gateway");
        assert_eq!(m.external_addr(47423).port(), 47423);
        m.release().await;
    }
}
