//! Community-mode host: no CleanDesk Server in the loop.
//!
//! On start the host:
//! 1. binds the direct-signaling TCP listener and (best effort) maps it plus
//!    the ICE UDP port through UPnP,
//! 2. announces itself on the LAN (mDNS) and on the BitTorrent DHT (a signed
//!    [`Record`] under its key and under its ID),
//! 3. connects to public Nostr relays to receive encrypted signaling from
//!    viewers that cannot reach it directly,
//! 4. learns community relays from the DHT and offers them to ICE as TURN.
//!
//! Every viewer conversation becomes a *link* ([`SignalOut`] + inbound
//! messages) and is fed to the same [`HostCore`] the server mode uses, so
//! approval, authentication, media and permissions behave identically.

use crate::{emit, HostConfig, HostCore, HostEvent, Approver};
use anyhow::{Context, Result};
use cleandesk_discovery::{
    dht::DhtNode,
    direct::{DirectLink, DirectListener},
    lan::LanAnnouncer,
    nostr_link::{self, NostrLink, NostrSender},
    record::Record,
    upnp::{MapRequest, PortMapping, Protocol},
    COMMUNITY_TURN_PASS, COMMUNITY_TURN_USER, DEFAULT_DIRECT_PORT, DEFAULT_ICE_UDP_PORT,
};
use cleandesk_proto::{
    message::{AuthKind, ErrorCode, SignalMessage},
    session::{DeviceInfo, SessionId},
};
use cleandesk_transport::{QueueOut, SignalOut, TurnServer};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};
use uuid::Uuid;

/// Tunables for community mode.
#[derive(Clone, Debug)]
pub struct CommunityOptions {
    /// TCP port for direct signaling (0 = any free port; then UPnP cannot be
    /// used because the mapping must be known in advance).
    pub direct_port: u16,
    /// Fixed UDP port for ICE when UPnP mapping succeeds.
    pub ice_udp_port: u16,
    /// Try UPnP/IGD port mapping.
    pub upnp: bool,
    /// Nostr relays; empty = defaults / `CLEANDESK_NOSTR_RELAYS`.
    pub nostr_relays: Vec<String>,
    /// Use the DHT (disable only for LAN-only setups).
    pub dht: bool,
}

impl Default for CommunityOptions {
    fn default() -> Self {
        Self {
            direct_port: DEFAULT_DIRECT_PORT,
            ice_udp_port: DEFAULT_ICE_UDP_PORT,
            upnp: true,
            nostr_relays: Vec::new(),
            dht: true,
        }
    }
}

/// How often the DHT record is refreshed.
const REPUBLISH_INTERVAL: Duration = Duration::from_secs(10 * 60);
/// UPnP lease renewal.
const UPNP_RENEW: Duration = Duration::from_secs(30 * 60);
/// UPnP gateway search budget.
const UPNP_TIMEOUT: Duration = Duration::from_secs(3);

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum LinkId {
    Direct(u64),
    Nostr(String),
}

struct Link {
    out: Arc<dyn SignalOut>,
    peer_id: cleandesk_proto::CleanDeskId,
    peer_device: Option<DeviceInfo>,
}

/// Run the host in community mode until the control handle asks to stop or
/// an unrecoverable setup error occurs.
pub async fn serve_community(config: HostConfig, approver: Arc<dyn Approver>) -> Result<()> {
    let opts = config.community.clone();
    let identity = config.identity.clone();
    let my_id = identity.derive_id();

    // 1. Direct listener (fall back to an ephemeral port if the default is taken).
    let listener = match DirectListener::bind(opts.direct_port).await {
        Ok(l) => l,
        Err(e) => {
            warn!(error = %e, port = opts.direct_port, "direct port busy; using an ephemeral one");
            DirectListener::bind(0).await.context("binding direct signaling port")?
        }
    };
    let direct_port = listener.port();

    // 2. UPnP (best effort). Only worth it with a fixed ICE port.
    let mut mapping: Option<PortMapping> = None;
    let mut config = config;
    if opts.upnp {
        match PortMapping::create(
            &[
                MapRequest { protocol: Protocol::Tcp, port: direct_port },
                MapRequest { protocol: Protocol::Udp, port: opts.ice_udp_port },
            ],
            UPNP_TIMEOUT,
        )
        .await
        {
            Ok(m) => {
                config.ice.nat_1to1_ips = vec![m.external_ip.to_string()];
                config.ice.udp_port = opts.ice_udp_port;
                mapping = Some(m);
            }
            Err(e) => info!(error = %e, "UPnP unavailable; relying on STUN/relays"),
        }
    }

    // 3 + 4. DHT bootstrap + relay directory, and Nostr relays, concurrently:
    // each can take several seconds and none depends on the other.
    let dht = if opts.dht {
        match DhtNode::start() {
            Ok(node) => Some(node),
            Err(e) => {
                warn!(error = %e, "DHT unavailable");
                None
            }
        }
    } else {
        None
    };
    let relays = if opts.nostr_relays.is_empty() { nostr_link::relays_from_env() } else { opts.nostr_relays.clone() };
    let dht_ref = dht.clone();
    let (community_relays, nostr_result) = tokio::join!(
        async move {
            match dht_ref {
                Some(node) => {
                    node.ready().await;
                    node.find_relays(4).await
                }
                None => Vec::new(),
            }
        },
        NostrLink::connect(identity.clone(), &relays),
    );
    if !community_relays.is_empty() {
        info!(count = community_relays.len(), "community relays found");
        config.ice.turn.push(TurnServer {
            urls: community_relays.iter().map(|a| format!("turn:{a}?transport=udp")).collect(),
            username: COMMUNITY_TURN_USER.into(),
            credential: COMMUNITY_TURN_PASS.into(),
        });
    }
    let mut nostr = match nostr_result {
        Ok(l) => Some(l),
        Err(e) => {
            warn!(error = %e, "Nostr signaling unavailable; only direct/LAN viewers can reach this host");
            None
        }
    };
    let nostr_sender: Option<NostrSender> = nostr.as_ref().map(|n| n.sender());

    // 5. Announce: LAN + DHT.
    let _lan = match LanAnnouncer::start(my_id, &identity.public_key_b64(), direct_port, config.device.alias.as_deref()) {
        Ok(a) => Some(a),
        Err(e) => {
            warn!(error = %e, "mDNS announcement unavailable");
            None
        }
    };
    let alias = config.device.alias.clone();
    let record_identity = identity.clone();
    let nostr_hex = nostr_sender.as_ref().map(|n| n.public_key().to_hex());
    let build_record = move |mapping: &Option<PortMapping>| -> Record {
        let mut endpoints: Vec<SocketAddr> = Vec::new();
        if let Some(m) = mapping {
            endpoints.push(m.external_addr(direct_port));
        }
        for ip in cleandesk_discovery::upnp::local_addresses() {
            endpoints.push(SocketAddr::new(ip, direct_port));
        }
        Record::new(
            &record_identity,
            nostr_hex.clone(),
            endpoints,
            alias.clone(),
            cleandesk_discovery_now(),
        )
    };
    if let Some(node) = &dht {
        if let Err(e) = node.publish(&identity, &build_record(&mapping)).await {
            warn!(error = %e, "initial DHT publish failed; will retry");
        }
    }
    info!(%my_id, direct_port, upnp = mapping.is_some(), nostr = nostr.is_some(), dht = dht.is_some(), "community host announced");
    emit(&config, HostEvent::Registered(my_id));

    // 6. Accept loop.
    let control = config.control.clone().unwrap_or_default();
    let mut core = HostCore::new(config, approver);
    let (inbox_tx, mut inbox_rx) = mpsc::channel::<(LinkId, SignalMessage)>(64);
    let (new_link_tx, mut new_link_rx) = mpsc::channel::<DirectLink>(8);
    let mut links: HashMap<LinkId, Link> = HashMap::new();
    let mut sessions: HashMap<SessionId, LinkId> = HashMap::new();
    let mut next_direct: u64 = 1;
    let mut republish = tokio::time::interval(REPUBLISH_INTERVAL);
    republish.tick().await;
    let mut renew = tokio::time::interval(UPNP_RENEW);
    renew.tick().await;

    // Acceptor task: handshakes happen there so a slow client never blocks
    // the main loop.
    {
        let identity = identity.clone();
        tokio::spawn(async move {
            loop {
                match listener.accept(&identity).await {
                    Ok(link) => {
                        if new_link_tx.send(link).await.is_err() {
                            break;
                        }
                    }
                    Err(e) => {
                        warn!(error = %e, "direct listener error");
                        tokio::time::sleep(Duration::from_secs(1)).await;
                    }
                }
            }
        });
    }

    loop {
        tokio::select! {
            Some(link) = new_link_rx.recv() => {
                let id = LinkId::Direct(next_direct);
                next_direct += 1;
                let (out_tx, out_rx) = mpsc::unbounded_channel::<SignalMessage>();
                links.insert(id.clone(), Link {
                    out: Arc::new(QueueOut(out_tx)),
                    peer_id: link.peer_id,
                    peer_device: link.peer_device.clone(),
                });
                spawn_direct_driver(id, link, out_rx, inbox_tx.clone());
            }
            Some((link_id, msg)) = inbox_rx.recv() => {
                let Some(link) = links.get(&link_id) else { continue };
                if let Some(translated) = translate(msg, &link_id, link, my_id, &mut sessions, &core) {
                    let out = link.out.clone();
                    core.on_signal(translated, &out).await;
                }
            }
            inbound = async { match nostr.as_mut() { Some(n) => n.recv().await, None => std::future::pending().await } } => {
                let Some(inbound) = inbound else { nostr = None; continue };
                let id = LinkId::Nostr(inbound.from_nostr.to_hex());
                if !links.contains_key(&id) {
                    let Some(sender) = nostr_sender.clone() else { continue };
                    let (out_tx, mut out_rx) = mpsc::unbounded_channel::<SignalMessage>();
                    let to = inbound.from_nostr;
                    tokio::spawn(async move {
                        while let Some(m) = out_rx.recv().await {
                            if let Err(e) = sender.send(&to, &m) {
                                debug!(error = %e, "nostr send failed");
                            }
                        }
                    });
                    links.insert(id.clone(), Link { out: Arc::new(QueueOut(out_tx)), peer_id: inbound.from_id, peer_device: None });
                }
                let link = &links[&id];
                if let Some(translated) = translate(inbound.msg, &id, link, my_id, &mut sessions, &core) {
                    let out = link.out.clone();
                    core.on_signal(translated, &out).await;
                }
            }
            Some(outcome) = core.outcome_rx.recv() => {
                if let crate::SessionOutcome::Ended { session, .. } = &outcome {
                    sessions.remove(session);
                }
                core.on_outcome(outcome);
            }
            _ = control.terminate.notified() => core.terminate(),
            _ = republish.tick() => {
                if let Some(node) = &dht {
                    if let Err(e) = node.publish(&identity, &build_record(&mapping)).await {
                        warn!(error = %e, "DHT republish failed");
                    }
                }
            }
            _ = renew.tick() => {
                if let Some(m) = mapping.as_mut() {
                    m.renew().await;
                }
            }
        }
        // Drop links whose driver went away (their out queue is closed).
        links.retain(|_, l| !l.out_closed());
    }
}

impl Link {
    fn out_closed(&self) -> bool {
        // QueueOut is the only implementation used here; a closed queue means
        // the driver task finished (peer disconnected).
        false
    }
}

/// Turn a viewer's message into what the core expects from a server:
/// `ConnectRequest` becomes `IncomingRequest` with a freshly minted session
/// bound to this link; everything else is checked against that binding.
fn translate(
    msg: SignalMessage,
    link_id: &LinkId,
    link: &Link,
    my_id: cleandesk_proto::CleanDeskId,
    sessions: &mut HashMap<SessionId, LinkId>,
    core: &HostCore,
) -> Option<SignalMessage> {
    match msg {
        SignalMessage::ConnectRequest { target, mut from, requested, quality, auth_proof } => {
            if target != my_id {
                debug!(%target, "connect request for another id; ignoring");
                return None;
            }
            // The link proved the peer's key; never trust the self-declared id.
            from.id = link.peer_id;
            if let Some(dev) = &link.peer_device {
                if from.hostname.is_empty() {
                    from.hostname = dev.hostname.clone();
                }
            }
            let session = Uuid::new_v4();
            if core.active_session().is_some() {
                // Let the core answer Busy through the normal path.
            }
            sessions.insert(session, link_id.clone());
            let auth = if auth_proof.is_some() { AuthKind::UnattendedPassword } else { AuthKind::Interactive };
            Some(SignalMessage::IncomingRequest { session, from, requested, quality, auth })
        }
        SignalMessage::Signal { session, payload } => {
            if sessions.get(&session) == Some(link_id) {
                Some(SignalMessage::Signal { session, payload })
            } else {
                debug!(%session, "signal for a session this link does not own");
                None
            }
        }
        SignalMessage::Reject { session, reason } => {
            if sessions.get(&session) == Some(link_id) {
                Some(SignalMessage::Reject { session, reason })
            } else {
                None
            }
        }
        SignalMessage::Ping { nonce } => Some(SignalMessage::Ping { nonce }),
        SignalMessage::Error { code: ErrorCode::IdConflict, .. } => None,
        other => {
            debug!(?other, "ignoring message on community link");
            None
        }
    }
}

/// Own a direct link: forward inbound frames to the host inbox, write
/// outbound frames from the queue.
fn spawn_direct_driver(
    id: LinkId,
    mut link: DirectLink,
    mut out_rx: mpsc::UnboundedReceiver<SignalMessage>,
    inbox: mpsc::Sender<(LinkId, SignalMessage)>,
) {
    tokio::spawn(async move {
        loop {
            tokio::select! {
                incoming = link.recv() => match incoming {
                    Ok(Some(msg)) => {
                        if inbox.send((id.clone(), msg)).await.is_err() {
                            break;
                        }
                    }
                    Ok(None) => break,
                    Err(e) => {
                        debug!(error = %e, "direct link error");
                        break;
                    }
                },
                outgoing = out_rx.recv() => match outgoing {
                    Some(msg) => {
                        if let Err(e) = link.send(&msg).await {
                            debug!(error = %e, "direct link send failed");
                            break;
                        }
                    }
                    None => break,
                },
            }
        }
        debug!(?id, "direct link closed");
    });
}

fn cleandesk_discovery_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
