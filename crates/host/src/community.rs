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
//!
//! # Resource bounds
//!
//! Anyone who can reach the direct port or our Nostr key can open a link, so
//! the tables here are bounded: a link is dropped when its driver ends or
//! after [`LINK_IDLE`] without traffic (unless it owns a session), a minted
//! session the core never activated is forgotten after
//! [`SESSION_PENDING_TTL`], there are at most [`MAX_LINKS`] links, and
//! `ConnectRequest`s — each one costs a dialog or an auth attempt — are
//! rate-limited per sender key and globally ([`ConnectLimiter`]).

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
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
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
/// A link with no inbound message for this long, and no session, is dropped.
const LINK_IDLE: Duration = Duration::from_secs(10 * 60);
/// A session minted for a `ConnectRequest` that the core never activated
/// (viewer went away, request rejected without an outcome) is forgotten
/// after this.
const SESSION_PENDING_TTL: Duration = Duration::from_secs(5 * 60);
/// How often the tables are pruned even when nothing else happens.
const HOUSEKEEPING: Duration = Duration::from_secs(30);
/// Upper bound on simultaneous links (direct + Nostr).
const MAX_LINKS: usize = 256;
/// `ConnectRequest` budget: per sender key and for the whole host, per window.
const CONNECT_PER_KEY: u32 = 5;
const CONNECT_GLOBAL: u32 = 30;
const CONNECT_WINDOW: Duration = Duration::from_secs(60);
/// Keys remembered by the limiter before replenished buckets are dropped.
const LIMITER_SOFT_CAP: usize = 1024;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum LinkId {
    Direct(u64),
    Nostr(String),
}

struct Link {
    out: Arc<dyn SignalOut>,
    peer_id: cleandesk_proto::CleanDeskId,
    /// The peer's Ed25519 key (base64), proven by the link's handshake or
    /// envelope; what the rate limiter keys on.
    peer_key: String,
    peer_device: Option<DeviceInfo>,
    /// Last inbound message.
    last_seen: Instant,
    /// Set by the driver task when the transport ended (direct links).
    closed: Arc<AtomicBool>,
}

impl Link {
    fn new(out: Arc<dyn SignalOut>, peer_id: cleandesk_proto::CleanDeskId, peer_key: String, peer_device: Option<DeviceInfo>, now: Instant) -> Self {
        Self { out, peer_id, peer_key, peer_device, last_seen: now, closed: Arc::new(AtomicBool::new(false)) }
    }

    fn out_closed(&self) -> bool {
        self.closed.load(Ordering::Relaxed)
    }

    /// Gone: the driver ended, or idle for [`LINK_IDLE`] with no session.
    fn is_dead(&self, now: Instant, owns_session: bool) -> bool {
        self.out_closed() || (!owns_session && now.saturating_duration_since(self.last_seen) > LINK_IDLE)
    }
}

/// A session minted here for a viewer's `ConnectRequest`, bound to the link
/// it came over.
struct SessionBinding {
    link: LinkId,
    created: Instant,
}

/// Token bucket (same shape as the server's): `burst` at once, refilling
/// over `per`.
struct TokenBucket {
    capacity: f64,
    tokens: f64,
    refill_per_sec: f64,
    last: Instant,
}

impl TokenBucket {
    fn new(burst: u32, per: Duration, now: Instant) -> Self {
        let capacity = f64::from(burst.max(1));
        Self { capacity, tokens: capacity, refill_per_sec: capacity / per.as_secs_f64().max(f64::EPSILON), last: now }
    }

    fn allow_at(&mut self, now: Instant) -> bool {
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

    fn is_replenished_at(&self, now: Instant) -> bool {
        let elapsed = now.saturating_duration_since(self.last).as_secs_f64();
        self.tokens + elapsed * self.refill_per_sec >= self.capacity
    }
}

/// Limits `ConnectRequest`s per sender key and overall.
struct ConnectLimiter {
    per_key: HashMap<String, TokenBucket>,
    global: TokenBucket,
    per_key_burst: u32,
    window: Duration,
}

impl ConnectLimiter {
    fn new(per_key_burst: u32, global_burst: u32, window: Duration, now: Instant) -> Self {
        Self { per_key: HashMap::new(), global: TokenBucket::new(global_burst, window, now), per_key_burst, window }
    }

    /// May `key` make a connection request now?
    fn allow(&mut self, key: &str, now: Instant) -> bool {
        if self.per_key.len() > LIMITER_SOFT_CAP {
            self.per_key.retain(|_, b| !b.is_replenished_at(now));
        }
        let (burst, window) = (self.per_key_burst, self.window);
        let bucket = self.per_key.entry(key.to_string()).or_insert_with(|| TokenBucket::new(burst, window, now));
        if !bucket.allow_at(now) {
            return false;
        }
        self.global.allow_at(now)
    }
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
        let mut record = Record::new(
            &record_identity,
            nostr_hex.clone(),
            endpoints,
            alias.clone(),
            cleandesk_discovery_now(),
        );
        // Viewers keep the MAC with the contact so they can wake this
        // machine later (Wake-on-LAN); `set_mac` re-signs the record.
        record.set_mac(&record_identity, cleandesk_discovery::wol::local_mac_address());
        record
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
    let mut sessions: HashMap<SessionId, SessionBinding> = HashMap::new();
    let mut limiter = ConnectLimiter::new(CONNECT_PER_KEY, CONNECT_GLOBAL, CONNECT_WINDOW, Instant::now());
    let mut next_direct: u64 = 1;
    let mut republish = tokio::time::interval(REPUBLISH_INTERVAL);
    republish.tick().await;
    let mut renew = tokio::time::interval(UPNP_RENEW);
    renew.tick().await;
    let mut housekeeping = tokio::time::interval(HOUSEKEEPING);
    housekeeping.tick().await;

    // Acceptor task: handshakes happen there so a slow client never blocks
    // the main loop.
    {
        let identity = identity.clone();
        let mut listener = listener;
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
                let now = Instant::now();
                if !make_room(&mut links, &sessions, now) {
                    warn!(peer = %link.peer_id, "link table full; dropping new direct link");
                    continue;
                }
                let id = LinkId::Direct(next_direct);
                next_direct += 1;
                let (out_tx, out_rx) = mpsc::unbounded_channel::<SignalMessage>();
                let entry = Link::new(
                    Arc::new(QueueOut(out_tx)),
                    link.peer_id,
                    link.peer_public_key.clone(),
                    link.peer_device.clone(),
                    now,
                );
                let closed = entry.closed.clone();
                links.insert(id.clone(), entry);
                spawn_direct_driver(id, link, out_rx, inbox_tx.clone(), closed);
            }
            Some((link_id, msg)) = inbox_rx.recv() => {
                let now = Instant::now();
                let Some(link) = links.get_mut(&link_id) else { continue };
                link.last_seen = now;
                let link = &links[&link_id];
                if !gate_connect(&msg, link, &mut limiter, now).await {
                    continue;
                }
                if let Some(translated) = translate(msg, &link_id, link, my_id, &mut sessions, now) {
                    let out = link.out.clone();
                    core.on_signal(translated, &out).await;
                }
            }
            inbound = async { match nostr.as_mut() { Some(n) => n.recv().await, None => std::future::pending().await } } => {
                let Some(inbound) = inbound else { nostr = None; continue };
                let now = Instant::now();
                let id = LinkId::Nostr(inbound.from_nostr.to_hex());
                if !links.contains_key(&id) {
                    let Some(sender) = nostr_sender.clone() else { continue };
                    if !make_room(&mut links, &sessions, now) {
                        warn!(peer = %inbound.from_id, "link table full; ignoring new Nostr peer");
                        continue;
                    }
                    let (out_tx, mut out_rx) = mpsc::unbounded_channel::<SignalMessage>();
                    let to = inbound.from_nostr;
                    let entry = Link::new(Arc::new(QueueOut(out_tx)), inbound.from_id, inbound.from_public_key.clone(), None, now);
                    let closed = entry.closed.clone();
                    tokio::spawn(async move {
                        while let Some(m) = out_rx.recv().await {
                            if let Err(e) = sender.send(&to, &m) {
                                debug!(error = %e, "nostr send failed");
                            }
                        }
                        closed.store(true, Ordering::Relaxed);
                    });
                    links.insert(id.clone(), entry);
                }
                if let Some(link) = links.get_mut(&id) {
                    link.last_seen = now;
                }
                let link = &links[&id];
                if !gate_connect(&inbound.msg, link, &mut limiter, now).await {
                    continue;
                }
                if let Some(translated) = translate(inbound.msg, &id, link, my_id, &mut sessions, now) {
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
            _ = housekeeping.tick() => {}
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
        prune(&mut links, &mut sessions, core.active_session(), Instant::now());
    }
}

/// Forget dead links and stale sessions (see the module docs).
fn prune(
    links: &mut HashMap<LinkId, Link>,
    sessions: &mut HashMap<SessionId, SessionBinding>,
    active: Option<SessionId>,
    now: Instant,
) {
    // Sessions first: a pending one that timed out, or whose link is gone,
    // no longer keeps anything alive.
    sessions.retain(|id, s| {
        if Some(*id) == active {
            return links.get(&s.link).is_some_and(|l| !l.out_closed());
        }
        links.get(&s.link).is_some_and(|l| !l.out_closed())
            && now.saturating_duration_since(s.created) <= SESSION_PENDING_TTL
    });
    let before = links.len();
    links.retain(|id, l| !l.is_dead(now, sessions.values().any(|s| &s.link == id)));
    if links.len() != before {
        debug!(dropped = before - links.len(), remaining = links.len(), "pruned community links");
    }
}

/// Ensure there is room for one more link: prune, then evict the longest
/// idle link that owns no session. `false` if every link is busy.
fn make_room(links: &mut HashMap<LinkId, Link>, sessions: &HashMap<SessionId, SessionBinding>, now: Instant) -> bool {
    if links.len() < MAX_LINKS {
        return true;
    }
    links.retain(|id, l| !l.is_dead(now, sessions.values().any(|s| &s.link == id)));
    if links.len() < MAX_LINKS {
        return true;
    }
    let victim = links
        .iter()
        .filter(|(id, _)| !sessions.values().any(|s| &s.link == *id))
        .min_by_key(|(_, l)| l.last_seen)
        .map(|(id, _)| id.clone());
    match victim {
        Some(id) => {
            debug!(?id, "evicting idle link to make room");
            links.remove(&id);
            true
        }
        None => false,
    }
}

/// Apply the `ConnectRequest` rate limit. `true` lets the message through;
/// `false` means it was answered with `RateLimited` and must be dropped.
async fn gate_connect(msg: &SignalMessage, link: &Link, limiter: &mut ConnectLimiter, now: Instant) -> bool {
    if !matches!(msg, SignalMessage::ConnectRequest { .. }) {
        return true;
    }
    if limiter.allow(&link.peer_key, now) {
        return true;
    }
    warn!(peer = %link.peer_id, "connection requests rate-limited");
    let _ = link
        .out
        .send(SignalMessage::Error { code: ErrorCode::RateLimited, detail: "too many connection requests".into() })
        .await;
    false
}

/// Turn a viewer's message into what the core expects from a server:
/// `ConnectRequest` becomes `IncomingRequest` with a freshly minted session
/// bound to this link; everything else is checked against that binding.
fn translate(
    msg: SignalMessage,
    link_id: &LinkId,
    link: &Link,
    my_id: cleandesk_proto::CleanDeskId,
    sessions: &mut HashMap<SessionId, SessionBinding>,
    now: Instant,
) -> Option<SignalMessage> {
    let owns = |session: &SessionId| sessions.get(session).is_some_and(|s| &s.link == link_id);
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
            // One pending session per link: a retry replaces the previous
            // one instead of accumulating (the core answers Busy on its own
            // if a session is already active).
            sessions.retain(|_, s| &s.link != link_id);
            let session = Uuid::new_v4();
            sessions.insert(session, SessionBinding { link: link_id.clone(), created: now });
            let auth = if auth_proof.is_some() { AuthKind::UnattendedPassword } else { AuthKind::Interactive };
            Some(SignalMessage::IncomingRequest { session, from, requested, quality, auth })
        }
        SignalMessage::Signal { session, payload } => {
            if owns(&session) {
                Some(SignalMessage::Signal { session, payload })
            } else {
                debug!(%session, "signal for a session this link does not own");
                None
            }
        }
        SignalMessage::Reject { session, reason } => {
            if owns(&session) {
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
/// outbound frames from the queue. Flags `closed` when the link ends so the
/// main loop drops its entry.
fn spawn_direct_driver(
    id: LinkId,
    mut link: DirectLink,
    mut out_rx: mpsc::UnboundedReceiver<SignalMessage>,
    inbox: mpsc::Sender<(LinkId, SignalMessage)>,
    closed: Arc<AtomicBool>,
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
        closed.store(true, Ordering::Relaxed);
        debug!(?id, "direct link closed");
    });
}

fn cleandesk_discovery_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use cleandesk_proto::CleanDeskId;

    fn link(now: Instant, key: &str) -> (Link, mpsc::UnboundedReceiver<SignalMessage>) {
        let (tx, rx) = mpsc::unbounded_channel();
        (Link::new(Arc::new(QueueOut(tx)), CleanDeskId::new(100_000_001).unwrap(), key.into(), None, now), rx)
    }

    #[test]
    fn connect_limiter_per_key_then_global() {
        let t0 = Instant::now();
        let mut l = ConnectLimiter::new(2, 3, Duration::from_secs(60), t0);
        assert!(l.allow("a", t0));
        assert!(l.allow("a", t0));
        assert!(!l.allow("a", t0), "per-key burst spent");
        assert!(l.allow("b", t0), "another key still has its own budget");
        assert!(!l.allow("c", t0), "but the global budget (3) is spent");
        // Refill: 2 per 60 s per key, 3 per 60 s globally.
        let t1 = t0 + Duration::from_secs(30);
        assert!(l.allow("a", t1));
        assert!(!l.allow("a", t1));
    }

    #[test]
    fn connect_limiter_table_is_bounded() {
        let t0 = Instant::now();
        let mut l = ConnectLimiter::new(1, u32::MAX, Duration::from_secs(1), t0);
        for i in 0..(LIMITER_SOFT_CAP + 10) {
            let _ = l.allow(&format!("k{i}"), t0);
        }
        assert!(l.per_key.len() <= LIMITER_SOFT_CAP + 10);
        // After a window every bucket is full again and gets forgotten.
        let _ = l.allow("z", t0 + Duration::from_secs(2));
        assert!(l.per_key.len() < 10, "{}", l.per_key.len());
    }

    #[test]
    fn prune_drops_closed_idle_and_stale() {
        let t0 = Instant::now();
        let mut links = HashMap::new();
        let mut sessions = HashMap::new();
        let (closed, _r1) = link(t0, "closed");
        closed.closed.store(true, Ordering::Relaxed);
        let (idle, _r2) = link(t0, "idle");
        let (busy, _r3) = link(t0, "busy");
        let (fresh, _r4) = link(t0 + LINK_IDLE, "fresh");
        links.insert(LinkId::Direct(1), closed);
        links.insert(LinkId::Direct(2), idle);
        links.insert(LinkId::Nostr("busy".into()), busy);
        links.insert(LinkId::Direct(4), fresh);
        let active = Uuid::new_v4();
        sessions.insert(active, SessionBinding { link: LinkId::Nostr("busy".into()), created: t0 });
        let stale = Uuid::new_v4();
        sessions.insert(stale, SessionBinding { link: LinkId::Direct(4), created: t0 });
        let orphan = Uuid::new_v4();
        sessions.insert(orphan, SessionBinding { link: LinkId::Direct(1), created: t0 + LINK_IDLE });

        let later = t0 + LINK_IDLE + Duration::from_secs(1);
        prune(&mut links, &mut sessions, Some(active), later);
        assert!(!links.contains_key(&LinkId::Direct(1)), "closed link dropped");
        assert!(!links.contains_key(&LinkId::Direct(2)), "idle link dropped");
        assert!(links.contains_key(&LinkId::Nostr("busy".into())), "idle but owns the active session");
        assert!(links.contains_key(&LinkId::Direct(4)), "recently seen");
        assert!(sessions.contains_key(&active));
        assert!(!sessions.contains_key(&stale), "pending session past its TTL");
        assert!(!sessions.contains_key(&orphan), "session of a closed link");
    }

    #[test]
    fn make_room_evicts_longest_idle_without_session() {
        let t0 = Instant::now();
        let mut links = HashMap::new();
        let mut sessions = HashMap::new();
        let mut keep = Vec::new();
        for i in 0..MAX_LINKS as u64 {
            let (l, r) = link(t0 + Duration::from_secs(i), &format!("k{i}"));
            keep.push(r);
            links.insert(LinkId::Direct(i), l);
        }
        // The oldest one is busy: the next oldest goes instead.
        sessions.insert(Uuid::new_v4(), SessionBinding { link: LinkId::Direct(0), created: t0 });
        assert!(make_room(&mut links, &sessions, t0 + Duration::from_secs(5)));
        assert_eq!(links.len(), MAX_LINKS - 1);
        assert!(links.contains_key(&LinkId::Direct(0)));
        assert!(!links.contains_key(&LinkId::Direct(1)));
        // Everything busy: no room.
        let (l, r) = link(t0, "x");
        keep.push(r);
        links.insert(LinkId::Direct(999), l);
        for id in links.keys() {
            sessions.insert(Uuid::new_v4(), SessionBinding { link: id.clone(), created: t0 });
        }
        assert!(!make_room(&mut links, &sessions, t0 + Duration::from_secs(5)));
    }

    #[test]
    fn translate_binds_sessions_to_their_link() {
        let t0 = Instant::now();
        let my_id = CleanDeskId::new(100_000_009).unwrap();
        let mut sessions = HashMap::new();
        let (a, _ra) = link(t0, "a");
        let (b, _rb) = link(t0, "b");
        let req = |from: CleanDeskId| SignalMessage::ConnectRequest {
            target: my_id,
            from: DeviceInfo { id: from, alias: None, hostname: String::new(), os: "t".into(), app_version: "0".into() },
            requested: cleandesk_proto::permissions::Permissions::interactive(),
            quality: cleandesk_proto::quality::QualityProfile::Auto,
            auth_proof: None,
        };
        let forged = CleanDeskId::new(100_000_002).unwrap();
        let Some(SignalMessage::IncomingRequest { session, from, .. }) =
            translate(req(forged), &LinkId::Direct(1), &a, my_id, &mut sessions, t0)
        else {
            panic!("expected IncomingRequest")
        };
        assert_eq!(from.id, a.peer_id, "self-declared id is replaced by the proven one");
        // Signals on that session from another link are dropped.
        let sig = SignalMessage::Signal { session, payload: cleandesk_proto::message::SignalPayload::Answer { sdp: String::new() } };
        assert!(translate(sig.clone(), &LinkId::Direct(2), &b, my_id, &mut sessions, t0).is_none());
        assert!(translate(sig, &LinkId::Direct(1), &a, my_id, &mut sessions, t0).is_some());
        // A retry from the same link replaces its pending session.
        let _ = translate(req(forged), &LinkId::Direct(1), &a, my_id, &mut sessions, t0);
        assert_eq!(sessions.len(), 1);
        assert!(!sessions.contains_key(&session));
        // Requests for another id are ignored.
        let other = SignalMessage::ConnectRequest {
            target: CleanDeskId::new(100_000_003).unwrap(),
            from: DeviceInfo { id: forged, alias: None, hostname: String::new(), os: "t".into(), app_version: "0".into() },
            requested: cleandesk_proto::permissions::Permissions::interactive(),
            quality: cleandesk_proto::quality::QualityProfile::Auto,
            auth_proof: None,
        };
        assert!(translate(other, &LinkId::Direct(1), &a, my_id, &mut sessions, t0).is_none());
    }

    #[tokio::test]
    async fn gate_connect_answers_rate_limited() {
        let t0 = Instant::now();
        let mut limiter = ConnectLimiter::new(1, 10, Duration::from_secs(60), t0);
        let (l, mut rx) = link(t0, "k");
        let req = SignalMessage::ConnectRequest {
            target: CleanDeskId::new(100_000_009).unwrap(),
            from: DeviceInfo { id: l.peer_id, alias: None, hostname: String::new(), os: "t".into(), app_version: "0".into() },
            requested: cleandesk_proto::permissions::Permissions::interactive(),
            quality: cleandesk_proto::quality::QualityProfile::Auto,
            auth_proof: None,
        };
        assert!(gate_connect(&req, &l, &mut limiter, t0).await);
        assert!(!gate_connect(&req, &l, &mut limiter, t0).await);
        assert!(matches!(rx.try_recv(), Ok(SignalMessage::Error { code: ErrorCode::RateLimited, .. })));
        // Other messages are never gated.
        assert!(gate_connect(&SignalMessage::Ping { nonce: 1 }, &l, &mut limiter, t0).await);
    }
}
