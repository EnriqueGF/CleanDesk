//! Live presence of contacts and recent peers. Discovery records alone are
//! never evidence of being online: require a proven direct handshake or a
//! fresh, authenticated Nostr pong. No approval or remote-control session.
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use cleandesk_core::{config::NetworkMode, AppState};
use cleandesk_crypto::identity::Identity;
use cleandesk_discovery::{
    dht::DhtNode,
    direct,
    nostr_link::{self, NostrLink, NostrPublicKey},
    Resolved, Resolver,
};
use cleandesk_proto::{message::SignalMessage, session::DeviceInfo, CleanDeskId};
use cleandesk_transport::SignalingClient;

use crate::notifications::{Notification, Notifications};

const INTERVAL: Duration = Duration::from_secs(15);
const RECORD_TTL: Duration = Duration::from_secs(600);

pub struct Presence {
    task: tokio::task::JoinHandle<()>,
    pub online: Arc<Mutex<HashSet<CleanDeskId>>>,
}

impl Drop for Presence {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[derive(Default)]
struct Tracker {
    states: HashMap<CleanDeskId, (bool, u8)>,
}

impl Tracker {
    /// First observation is a quiet baseline. Require two failed probes for
    /// offline; unknown infrastructure failures neither count nor change it.
    fn observe(&mut self, id: CleanDeskId, online: Option<bool>) -> Option<bool> {
        let Some(online) = online else {
            self.states.entry(id).or_insert((false, 0));
            return None;
        };
        let Some((was_online, misses)) = self.states.get_mut(&id) else {
            self.states.insert(id, (online, 0));
            return None;
        };
        if online {
            *misses = 0;
        } else {
            *misses = misses.saturating_add(1);
        }
        if *was_online != online && (online || *misses >= 2) {
            *was_online = online;
            *misses = 0;
            return Some(online);
        }
        None
    }
}

fn known_devices(state: &AppState) -> HashMap<CleanDeskId, (String, Option<String>)> {
    collect_known(
        &state.history.read(),
        &state.addressbook.read(),
        state.identity.derive_id(),
    )
}

fn collect_known(
    history: &cleandesk_core::history::History,
    book: &cleandesk_core::addressbook::AddressBook,
    me: CleanDeskId,
) -> HashMap<CleanDeskId, (String, Option<String>)> {
    let mut known = HashMap::new();
    for record in history.recent(usize::MAX) {
        known
            .entry(record.device)
            .or_insert_with(|| (record.user.clone(), None));
    }
    for entry in &book.entries {
        known.insert(entry.id, (entry.name.clone(), entry.pinned_key.clone()));
    }
    known.remove(&me);
    for (id, (name, _)) in &mut known {
        *name = cleandesk_proto::text::sanitize(name, 64);
        if name.is_empty() {
            *name = id.to_string();
        }
    }
    known
}

impl Presence {
    pub fn start(
        rt: &tokio::runtime::Runtime,
        state: Arc<AppState>,
        device: DeviceInfo,
        signal_override: Option<String>,
        ctx: egui::Context,
        hwnd: Option<isize>,
    ) -> Self {
        let online = Arc::new(Mutex::new(HashSet::new()));
        let shared = online.clone();
        let notifications = Notifications::new(hwnd);
        let task = rt.spawn(async move {
            // A separate ephemeral identity avoids replacing our host's server
            // registration or consuming signaling replies addressed to the host.
            let identity = Identity::generate();
            let mut probe_device = device;
            probe_device.id = identity.derive_id();
            let mut tracker = Tracker::default();
            let mut cache: HashMap<CleanDeskId, (Resolved, Instant)> = HashMap::new();
            let mut dht = None;
            let mut server: Option<(
                String,
                SignalingClient,
                tokio::sync::mpsc::Receiver<SignalMessage>,
            )> = None;
            let mut previous_mode = None;
            loop {
                let mode = signal_override
                    .as_ref()
                    .map(|url| NetworkMode::Server { url: url.clone() })
                    .unwrap_or_else(|| state.settings.read().network.clone());
                if previous_mode.as_ref() != Some(&mode) {
                    tracker.states.clear();
                    cache.clear();
                    server = None;
                    shared.lock().unwrap_or_else(|e| e.into_inner()).clear();
                    previous_mode = Some(mode.clone());
                }
                let known = known_devices(&state);
                tracker.states.retain(|id, _| known.contains_key(id));
                cache.retain(|id, _| known.contains_key(id));
                cache.retain(|id, (r, t)| {
                    t.elapsed() < RECORD_TTL
                        && known[id].1.as_ref().is_none_or(|p| p == &r.record.pk)
                });
                let mut results = HashMap::new();
                if !known.is_empty() {
                    match mode {
                        NetworkMode::Server { url } => {
                            if server
                                .as_ref()
                                .is_none_or(|(u, c, _)| u != &url || !c.is_connected())
                            {
                                server = connect_server(&url, &identity, &probe_device)
                                    .await
                                    .map(|(c, rx)| (url.clone(), c, rx));
                            }
                            if let Some((_, client, rx)) = &mut server {
                                let ids: Vec<_> = known.keys().copied().collect();
                                for chunk in ids.chunks(512) {
                                    if client
                                        .send(SignalMessage::PresenceQuery {
                                            devices: chunk.to_vec(),
                                        })
                                        .await
                                        .is_err()
                                    {
                                        break;
                                    }
                                    let snapshot =
                                        tokio::time::timeout(Duration::from_secs(5), async {
                                            while let Some(msg) = rx.recv().await {
                                                match msg {
                                                    SignalMessage::PresenceSnapshot { online } => {
                                                        return Some(online)
                                                    }
                                                    SignalMessage::Error { .. } => return None,
                                                    _ => {}
                                                }
                                            }
                                            None
                                        })
                                        .await
                                        .ok()
                                        .flatten();
                                    let Some(snapshot) = snapshot else {
                                        server = None;
                                        break;
                                    };
                                    let found: HashSet<_> = snapshot.into_iter().collect();
                                    for id in chunk {
                                        results.insert(*id, Some(found.contains(id)));
                                    }
                                }
                            }
                        }
                        NetworkMode::Community => {
                            if dht.is_none() {
                                dht = DhtNode::start().ok();
                            }
                            // One shared relay subscription per pass, not one per device.
                            let mut nostr = NostrLink::connect(
                                identity.clone(),
                                &nostr_link::relays_from_env(),
                            )
                            .await
                            .ok();
                            let mut jobs = tokio::task::JoinSet::new();
                            let mut devices = known.iter();
                            let nonce = u64::from_le_bytes(
                                cleandesk_crypto::identity::random_bytes(8)
                                    .try_into()
                                    .unwrap(),
                            );
                            let mut pending = HashMap::new();
                            loop {
                                while jobs.len() < 8 {
                                    let Some((&id, (_, pin))) = devices.next() else {
                                        break;
                                    };
                                    let cached = cache
                                        .get(&id)
                                        .filter(|(r, t)| {
                                            t.elapsed() < RECORD_TTL
                                                && pin.as_ref().is_none_or(|p| p == &r.record.pk)
                                        })
                                        .map(|(r, _)| r.clone());
                                    let resolver = Resolver::new(dht.clone());
                                    let pin = pin.clone();
                                    let identity = identity.clone();
                                    let dev = probe_device.clone();
                                    jobs.spawn(async move {
                                        let resolved = match cached {
                                            Some(r) => Some(r),
                                            None => tokio::time::timeout(
                                                Duration::from_secs(25),
                                                resolver.resolve(id, pin.as_deref()),
                                            )
                                            .await
                                            .ok()
                                            .and_then(Result::ok),
                                        };
                                        let mut live = false;
                                        if let Some(r) = &resolved {
                                            for ep in r.endpoints.iter().take(4) {
                                                let allowed = if r.via == "LAN" {
                                                    cleandesk_discovery::addr::is_lan(ep.ip())
                                                } else {
                                                    cleandesk_discovery::addr::is_dialable(ep.ip())
                                                };
                                                if allowed
                                                    && tokio::time::timeout(
                                                        Duration::from_secs(5),
                                                        direct::dial(
                                                            *ep,
                                                            &identity,
                                                            dev.clone(),
                                                            &r.record.pk,
                                                            id,
                                                        ),
                                                    )
                                                    .await
                                                    .is_ok_and(|r| r.is_ok())
                                                {
                                                    live = true;
                                                    break;
                                                }
                                            }
                                        }
                                        (id, resolved, live)
                                    });
                                }
                                let Some(job) = jobs.join_next().await else {
                                    break;
                                };
                                let Ok((id, resolved, live)) = job else {
                                    continue;
                                };
                                let local_probe = resolved.as_ref().is_some_and(|r| r.via == "LAN");
                                if let Some(r) = resolved {
                                    cache
                                        .entry(id)
                                        .or_insert_with(|| (r.clone(), Instant::now()));
                                    if !live {
                                        if let (Some(link), Some(key)) = (&nostr, &r.record.nostr) {
                                            if let Ok(to) = NostrPublicKey::from_hex(key) {
                                                if link
                                                    .sender()
                                                    .send(&to, &SignalMessage::Ping { nonce })
                                                    .is_ok()
                                                {
                                                    pending.insert(id, r.record.pk);
                                                }
                                            }
                                        }
                                    }
                                }
                                results.insert(
                                    id,
                                    if live {
                                        Some(true)
                                    } else if nostr.is_some() || local_probe {
                                        Some(false)
                                    } else {
                                        None
                                    },
                                );
                                // Drain replies during long discovery passes so early
                                // pongs cannot wait behind hundreds of lookups.
                                if let Some(link) = &mut nostr {
                                    receive_pongs(
                                        link,
                                        &mut pending,
                                        &mut results,
                                        nonce,
                                        Duration::from_millis(1),
                                    )
                                    .await;
                                }
                            }
                            if let Some(link) = &mut nostr {
                                receive_pongs(
                                    link,
                                    &mut pending,
                                    &mut results,
                                    nonce,
                                    Duration::from_secs(5),
                                )
                                .await;
                            }
                        }
                    }
                }
                for (id, result) in results {
                    // Keep records for live Nostr peers too. Rediscover on a
                    // failed probe so address changes can recover promptly.
                    if result == Some(false) {
                        cache.remove(&id);
                    }
                    if let Some(online) = tracker.observe(id, result) {
                        if let Some((name, _)) = known.get(&id) {
                            notifications.send(Notification {
                                name: name.clone(),
                                id,
                                online,
                            });
                        }
                    }
                }
                *shared.lock().unwrap_or_else(|e| e.into_inner()) = tracker
                    .states
                    .iter()
                    .filter_map(|(id, (live, _))| live.then_some(*id))
                    .collect();
                ctx.request_repaint();
                tokio::time::sleep(INTERVAL).await;
            }
        });
        Self { task, online }
    }
}

async fn receive_pongs(
    link: &mut NostrLink,
    pending: &mut HashMap<CleanDeskId, String>,
    results: &mut HashMap<CleanDeskId, Option<bool>>,
    nonce: u64,
    budget: Duration,
) {
    let deadline = tokio::time::Instant::now() + budget;
    while !pending.is_empty() {
        let Ok(Some(reply)) = tokio::time::timeout_at(deadline, link.recv()).await else {
            break;
        };
        if matches!(reply.msg, SignalMessage::Pong { nonce: n } if n == nonce)
            && pending.get(&reply.from_id) == Some(&reply.from_public_key)
        {
            pending.remove(&reply.from_id);
            results.insert(reply.from_id, Some(true));
        }
    }
}

async fn connect_server(
    url: &str,
    identity: &Identity,
    device: &DeviceInfo,
) -> Option<(SignalingClient, tokio::sync::mpsc::Receiver<SignalMessage>)> {
    tokio::time::timeout(Duration::from_secs(12), async {
        let mut client = SignalingClient::connect(url).await.ok()?;
        let signer = |bytes: &[u8]| identity.sign_b64(bytes);
        client
            .register(device.clone(), identity.public_key_b64(), &signer)
            .await
            .ok()?;
        let rx = client.events().ok()?;
        Some((client, rx))
    })
    .await
    .ok()
    .flatten()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn recent_devices_need_no_contact_and_contact_name_takes_priority() {
        use cleandesk_core::{
            addressbook::{AddressBook, DeviceEntry},
            history::{History, SessionRecord},
        };
        let recent = CleanDeskId::new(123456789).unwrap();
        let contact = CleanDeskId::new(234567891).unwrap();
        let me = CleanDeskId::new(345678912).unwrap();
        let mut history = History::default();
        for (id, name) in [
            (recent, "Older"),
            (recent, "Recent PC"),
            (contact, "Old alias"),
            (me, "Self"),
        ] {
            let mut record = SessionRecord::start(Default::default(), id, name, "p2p");
            record.started_at = history.records.len() as u64;
            history.push(record);
        }
        let mut book = AddressBook::default();
        book.add(DeviceEntry::new(contact, "Favourite PC"));
        let known = collect_known(&history, &book, me);
        assert_eq!(known.len(), 2);
        assert_eq!(known[&recent].0, "Recent PC");
        assert_eq!(known[&contact].0, "Favourite PC");
        assert!(!known.contains_key(&me));
    }
    #[test]
    fn baseline_transitions_debounce_and_unknown_failures() {
        let id = CleanDeskId::new(123456789).unwrap();
        let mut tracker = Tracker::default();
        assert_eq!(tracker.observe(id, Some(false)), None);
        assert_eq!(tracker.observe(id, Some(true)), Some(true));
        assert_eq!(tracker.observe(id, Some(true)), None);
        assert_eq!(tracker.observe(id, Some(false)), None);
        assert_eq!(tracker.observe(id, None), None);
        assert!(tracker.states[&id].0);
        assert_eq!(tracker.observe(id, Some(true)), None);
        assert_eq!(tracker.observe(id, Some(false)), None);
        assert_eq!(tracker.observe(id, Some(false)), Some(false));
        assert_eq!(tracker.observe(id, Some(false)), None);
        assert_eq!(tracker.observe(id, Some(true)), Some(true));
    }
}
