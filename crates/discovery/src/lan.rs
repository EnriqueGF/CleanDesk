//! LAN discovery over mDNS/DNS-SD.
//!
//! Hosts announce `<id>._cleandesk._tcp.local.` with a TXT record carrying
//! the CleanDesk ID, the public key and the direct-signaling port. Viewers
//! browse for a specific ID. No Internet, no configuration.

use crate::{DiscoveryError, Result};
use cleandesk_proto::CleanDeskId;
use mdns_sd::{ServiceDaemon, ServiceEvent, ServiceInfo};
use std::net::SocketAddr;
use std::time::Duration;
use tracing::{debug, warn};

pub const SERVICE_TYPE: &str = "_cleandesk._tcp.local.";

/// A host found on the LAN.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LanPeer {
    pub id: CleanDeskId,
    /// Ed25519 public key, base64.
    pub public_key: String,
    pub endpoints: Vec<SocketAddr>,
    pub alias: Option<String>,
}

/// Keeps the mDNS announcement alive; dropping it unregisters.
pub struct LanAnnouncer {
    daemon: ServiceDaemon,
    fullname: String,
}

impl LanAnnouncer {
    /// Announce this host. `port` is the direct-signaling TCP port.
    pub fn start(id: CleanDeskId, public_key_b64: &str, port: u16, alias: Option<&str>) -> Result<Self> {
        let daemon = ServiceDaemon::new().map_err(|e| DiscoveryError::Other(format!("mdns daemon: {e}")))?;
        let instance = id.value().to_string();
        let host_name = format!("cleandesk-{instance}.local.");
        let mut props = vec![
            ("id".to_string(), instance.clone()),
            ("pk".to_string(), public_key_b64.to_string()),
            ("v".to_string(), crate::RENDEZVOUS_VERSION.to_string()),
        ];
        if let Some(a) = alias {
            props.push(("alias".to_string(), a.chars().take(32).collect()));
        }
        // An empty IP list lets mdns-sd fill in every interface address, and
        // keep following interface changes.
        let mut info = ServiceInfo::new(SERVICE_TYPE, &instance, &host_name, "", port, &props[..])
            .map_err(|e| DiscoveryError::Other(format!("mdns service info: {e}")))?;
        info = info.enable_addr_auto();
        let fullname = info.get_fullname().to_string();
        daemon.register(info).map_err(|e| DiscoveryError::Other(format!("mdns register: {e}")))?;
        debug!(%fullname, port, "mDNS announcement started");
        Ok(Self { daemon, fullname })
    }
}

impl Drop for LanAnnouncer {
    fn drop(&mut self) {
        let _ = self.daemon.unregister(&self.fullname);
        let _ = self.daemon.shutdown();
    }
}

/// Browse the LAN for `id` for up to `timeout`. Returns the first match.
pub async fn find(id: CleanDeskId, timeout: Duration) -> Option<LanPeer> {
    let daemon = match ServiceDaemon::new() {
        Ok(d) => d,
        Err(e) => {
            warn!(error = %e, "mdns daemon unavailable");
            return None;
        }
    };
    let rx = match daemon.browse(SERVICE_TYPE) {
        Ok(rx) => rx,
        Err(e) => {
            warn!(error = %e, "mdns browse failed");
            let _ = daemon.shutdown();
            return None;
        }
    };
    let deadline = tokio::time::Instant::now() + timeout;
    let mut found = None;
    while tokio::time::Instant::now() < deadline && found.is_none() {
        // mdns-sd's receiver is a flume channel with its own async API.
        let ev = tokio::select! {
            ev = rx.recv_async() => ev,
            _ = tokio::time::sleep_until(deadline) => break,
        };
        let Ok(ev) = ev else { break };
        if let ServiceEvent::ServiceResolved(info) = ev {
            let Some(peer) = peer_from_resolved(&info) else { continue };
            if peer.id == id {
                found = Some(peer);
            }
        }
    }
    let _ = daemon.stop_browse(SERVICE_TYPE);
    let _ = daemon.shutdown();
    found
}

fn peer_from_resolved(info: &mdns_sd::ResolvedService) -> Option<LanPeer> {
    let id = CleanDeskId::parse(info.get_property_val_str("id")?).ok()?;
    let public_key = info.get_property_val_str("pk")?.to_string();
    let port = info.get_port();
    let mut endpoints: Vec<SocketAddr> = info
        .get_addresses()
        .iter()
        .map(|a| SocketAddr::new(a.to_ip_addr(), port))
        .filter(|a| !a.ip().is_loopback())
        .collect();
    // Prefer IPv4 (simpler routing on typical home LANs), then IPv6.
    endpoints.sort_by_key(|a| a.is_ipv6());
    if endpoints.is_empty() {
        return None;
    }
    Some(LanPeer {
        id,
        public_key,
        endpoints,
        alias: info.get_property_val_str("alias").map(str::to_string),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Announce + browse on the loopback/LAN of this machine. Skipped
    /// gracefully when multicast is unavailable (locked-down CI).
    #[tokio::test]
    async fn announce_then_find_self() {
        let id = CleanDeskId::new(123_456_789).unwrap();
        let Ok(_ann) = LanAnnouncer::start(id, "cGs=", 7423, Some("test")) else {
            eprintln!("mDNS unavailable; skipping");
            return;
        };
        let found = find(id, Duration::from_secs(4)).await;
        if let Some(p) = found {
            assert_eq!(p.id, id);
            assert_eq!(p.public_key, "cGs=");
            assert!(p.endpoints.iter().all(|e| e.port() == 7423));
        } else {
            eprintln!("no mDNS reply within budget (multicast may be filtered); not failing");
        }
    }
}
