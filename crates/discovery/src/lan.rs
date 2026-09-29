//! LAN discovery over mDNS/DNS-SD.
//!
//! Hosts announce `<id>._cleandesk._tcp.local.` with a TXT record carrying
//! the CleanDesk ID, the public key and the direct-signaling port. Viewers
//! browse for a specific ID. No Internet, no configuration.
//!
//! The TXT record is **unsigned**: anything on the LAN can announce any
//! `id`/`pk` pair. What comes out of here is a hint about where to dial and
//! which key to expect; the direct handshake is what proves the key, and a
//! key seen here must not be pinned until that handshake succeeded.

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
    /// MAC address of the announcing interface (for Wake-on-LAN), if known.
    pub mac: Option<String>,
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
        // Lets viewers wake this machine later (Wake-on-LAN) without any
        // extra configuration.
        if let Some(mac) = crate::wol::local_mac_address() {
            props.push(("mac".to_string(), mac));
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
    let mut found = None;
    browse(timeout, |peer| {
        if peer.id == id {
            found = Some(peer);
            return false;
        }
        true
    })
    .await;
    found
}

/// Every CleanDesk host announced on the LAN within `timeout`, one entry per
/// ID (a host re-announcing after an interface change only adds endpoints),
/// sorted by alias then ID for the UI.
pub async fn browse_all(timeout: Duration) -> Vec<LanPeer> {
    let mut peers: Vec<LanPeer> = Vec::new();
    browse(timeout, |peer| {
        match peers.iter_mut().find(|p| p.id == peer.id) {
            Some(existing) => {
                for ep in peer.endpoints {
                    if !existing.endpoints.contains(&ep) {
                        existing.endpoints.push(ep);
                    }
                }
                if existing.alias.is_none() {
                    existing.alias = peer.alias;
                }
            }
            None => peers.push(peer),
        }
        true
    })
    .await;
    peers.sort_by(|a, b| {
        let ka = a.alias.as_deref().map(str::to_lowercase);
        let kb = b.alias.as_deref().map(str::to_lowercase);
        // Named hosts first (alphabetically), anonymous ones after, by ID.
        match (ka, kb) {
            (Some(x), Some(y)) => x.cmp(&y).then(a.id.value().cmp(&b.id.value())),
            (Some(_), None) => std::cmp::Ordering::Less,
            (None, Some(_)) => std::cmp::Ordering::Greater,
            (None, None) => a.id.value().cmp(&b.id.value()),
        }
    });
    peers
}

/// Shared browse loop: feeds every resolved CleanDesk service to `on_peer`
/// until it returns `false` or `timeout` elapses. Errors are logged, not
/// returned: a LAN with no multicast simply yields nothing.
async fn browse(timeout: Duration, mut on_peer: impl FnMut(LanPeer) -> bool) {
    let daemon = match ServiceDaemon::new() {
        Ok(d) => d,
        Err(e) => {
            warn!(error = %e, "mdns daemon unavailable");
            return;
        }
    };
    let rx = match daemon.browse(SERVICE_TYPE) {
        Ok(rx) => rx,
        Err(e) => {
            warn!(error = %e, "mdns browse failed");
            let _ = daemon.shutdown();
            return;
        }
    };
    let deadline = tokio::time::Instant::now() + timeout;
    while tokio::time::Instant::now() < deadline {
        // mdns-sd's receiver is a flume channel with its own async API.
        let ev = tokio::select! {
            ev = rx.recv_async() => ev,
            _ = tokio::time::sleep_until(deadline) => break,
        };
        let Ok(ev) = ev else { break };
        if let ServiceEvent::ServiceResolved(info) = ev {
            let Some(peer) = peer_from_resolved(&info) else { continue };
            if !on_peer(peer) {
                break;
            }
        }
    }
    let _ = daemon.stop_browse(SERVICE_TYPE);
    let _ = daemon.shutdown();
}

fn peer_from_resolved(info: &mdns_sd::ResolvedService) -> Option<LanPeer> {
    // A host speaking another rendezvous version would fail the direct
    // handshake anyway; skipping it here yields "not found" rather than an
    // authentication error that looks like an attack.
    if info.get_property_val_str("v") != Some(crate::RENDEZVOUS_VERSION.to_string().as_str()) {
        return None;
    }
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
        mac: info
            .get_property_val_str("mac")
            .and_then(|m| crate::wol::parse_mac(m).ok())
            .map(|m| crate::wol::format_mac(&m)),
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

    /// Two announcers, one browse: both must show up once each, with their
    /// aliases, in alias order. Same multicast tolerance as above.
    #[tokio::test]
    async fn announce_two_then_browse_all() {
        let a = CleanDeskId::new(223_456_789).unwrap();
        let b = CleanDeskId::new(323_456_789).unwrap();
        let (Ok(_ann_a), Ok(_ann_b)) = (
            LanAnnouncer::start(a, "cGtB", 7431, Some("Zeta")),
            LanAnnouncer::start(b, "cGtC", 7432, Some("alpha")),
        ) else {
            eprintln!("mDNS unavailable; skipping");
            return;
        };
        let peers = browse_all(Duration::from_secs(4)).await;
        let ours: Vec<&LanPeer> = peers.iter().filter(|p| p.id == a || p.id == b).collect();
        if ours.len() < 2 {
            eprintln!("saw {} of 2 announcements (multicast may be filtered); not failing", ours.len());
            return;
        }
        assert_eq!(ours.len(), 2, "each ID exactly once");
        assert_eq!(ours[0].id, b, "sorted by alias, case-insensitively");
        assert_eq!(ours[0].alias.as_deref(), Some("alpha"));
        assert_eq!(ours[0].public_key, "cGtC");
        assert!(ours[0].endpoints.iter().all(|e| e.port() == 7432));
        assert_eq!(ours[1].id, a);
        assert_eq!(ours[1].alias.as_deref(), Some("Zeta"));
        assert!(ours[1].endpoints.iter().all(|e| e.port() == 7431));
    }
}
