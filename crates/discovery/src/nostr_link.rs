//! Signaling over public Nostr relays.
//!
//! Each device derives a secp256k1 key from its Ed25519 seed
//! ([`crate::record::nostr_keys`]). A [`SignalMessage`] travels as an
//! *ephemeral* event (kind [`KIND`], never stored by relays) addressed with a
//! `p` tag to the recipient and NIP-44 encrypted to it. The envelope inside
//! carries the sender's Ed25519 key and a signature binding it to the Nostr
//! key, so the recipient can verify who is talking regardless of which relay
//! delivered the event.
//!
//! Several relays are used at once; every event is sent to all of them and
//! duplicates are dropped by event id, so any single relay may be slow, down
//! or censoring without breaking signaling.
//!
//! Events are accepted only if their `created_at` is within
//! [`MAX_CLOCK_SKEW`] of now (a relay, or anyone who captured an event, could
//! otherwise replay old signaling for as long as the ids are forgotten) and
//! the dedup set is a bounded ring that evicts the oldest entries one by one
//! rather than being wiped, so a burst of junk cannot reopen the window for a
//! replay of a recent event.

use crate::record::{nostr_binding_message, nostr_keys};
use crate::{DiscoveryError, Result};
use rotodesk_crypto::identity::{derive_id_from_public_key_b64, verify_b64_sig, Identity};
use rotodesk_proto::{message::SignalMessage, RotoDeskId};
use futures_util::{SinkExt, StreamExt};
use nostr::prelude::*;

/// Re-exported so callers can address a host without depending on `nostr`.
pub use nostr::key::PublicKey as NostrPublicKey;
use serde::{Deserialize, Serialize};
use std::collections::{HashSet, VecDeque};
use std::time::Duration;
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Message as WsMessage;
use tracing::{debug, warn};

/// Ephemeral event kind reserved for RotoDesk signaling (20000..30000).
pub const KIND: u16 = 27420;

/// Public relays used when none are configured. Any NIP-01 relay works; these
/// are large, long-lived community relays.
pub const DEFAULT_RELAYS: &[&str] = &[
    "wss://relay.damus.io",
    "wss://nos.lol",
    "wss://relay.nostr.band",
    "wss://relay.primal.net",
    "wss://nostr.mom",
];

/// Environment variable overriding the relay list (comma separated).
pub const ENV_RELAYS: &str = "ROTODESK_NOSTR_RELAYS";

/// Relay connect timeout.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(6);

/// Events whose `created_at` is further than this from our clock (either
/// way) are dropped.
pub const MAX_CLOCK_SKEW: Duration = Duration::from_secs(10 * 60);

/// How many event ids the dedup ring remembers. Signaling is a handful of
/// events per session, so this covers far more than [`MAX_CLOCK_SKEW`] worth
/// of legitimate traffic.
const SEEN_CAPACITY: usize = 4096;

/// Bounded set of recently seen event ids with oldest-first eviction.
pub(crate) struct SeenSet {
    set: HashSet<EventId>,
    order: VecDeque<EventId>,
    capacity: usize,
}

impl SeenSet {
    pub(crate) fn new(capacity: usize) -> Self {
        Self { set: HashSet::new(), order: VecDeque::new(), capacity: capacity.max(1) }
    }

    /// Record `id`; returns `false` if it was already present. When full, the
    /// oldest id is forgotten — only that one, never the whole set.
    pub(crate) fn insert(&mut self, id: EventId) -> bool {
        if !self.set.insert(id) {
            return false;
        }
        self.order.push_back(id);
        while self.order.len() > self.capacity {
            if let Some(old) = self.order.pop_front() {
                self.set.remove(&old);
            }
        }
        true
    }

    pub(crate) fn contains(&self, id: &EventId) -> bool {
        self.set.contains(id)
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.set.len()
    }
}

/// The relay list from the environment or the defaults.
pub fn relays_from_env() -> Vec<String> {
    let custom: Vec<String> = rotodesk_proto::compat::env(ENV_RELAYS)
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect();
    if custom.is_empty() {
        DEFAULT_RELAYS.iter().map(|s| s.to_string()).collect()
    } else {
        custom
    }
}

/// What travels (encrypted) inside an event.
#[derive(Debug, Serialize, Deserialize)]
struct Envelope {
    /// Sender's Ed25519 public key, base64.
    pk: String,
    /// Ed25519 signature over [`nostr_binding_message`] of the sender's Nostr key.
    bind: String,
    msg: SignalMessage,
}

/// An inbound, authenticated signaling message.
#[derive(Debug)]
pub struct Inbound {
    pub from_public_key: String,
    pub from_id: RotoDeskId,
    pub from_nostr: PublicKey,
    pub msg: SignalMessage,
}

/// A connection to several relays, subscribed to events addressed to us.
pub struct NostrLink {
    sender: NostrSender,
    in_rx: mpsc::Receiver<Inbound>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

/// Cloneable send-only handle to a [`NostrLink`].
#[derive(Clone)]
pub struct NostrSender {
    keys: Keys,
    identity: Identity,
    out_tx: mpsc::UnboundedSender<String>,
}

impl NostrSender {
    /// Send `msg` to the device whose Nostr key is `to`.
    pub fn send(&self, to: &PublicKey, msg: &SignalMessage) -> Result<()> {
        let env = Envelope {
            pk: self.identity.public_key_b64(),
            bind: self.identity.sign_b64(&nostr_binding_message(&self.keys.public_key().to_hex())),
            msg: msg.clone(),
        };
        let plain = serde_json::to_string(&env)?;
        let content = self
            .keys
            .nip44_encrypt(to, &plain)
            .map_err(|e| DiscoveryError::Other(format!("nip44: {e}")))?;
        let event = EventBuilder::new(Kind::Custom(KIND), content)
            .tag(Tag::public_key(*to))
            .finalize(&self.keys)
            .map_err(|e| DiscoveryError::Other(format!("event: {e}")))?;
        let json = serde_json::to_string(&ClientMessage::event(event))?;
        self.out_tx.send(json).map_err(|_| DiscoveryError::Other("nostr link closed".into()))?;
        Ok(())
    }

    pub fn public_key(&self) -> PublicKey {
        self.keys.public_key()
    }
}

impl NostrLink {
    /// Our Nostr public key (hex) to publish in the record.
    pub fn public_key_hex(identity: &Identity) -> String {
        nostr_keys(identity).public_key().to_hex()
    }

    /// Connect to `relays` (at least one must succeed).
    pub async fn connect(identity: Identity, relays: &[String]) -> Result<Self> {
        // rustls needs exactly one process-wide crypto provider; installing is
        // idempotent from our point of view (a second call just fails).
        let _ = rustls::crypto::ring::default_provider().install_default();
        let keys = nostr_keys(&identity);
        let (out_tx, out_rx) = mpsc::unbounded_channel::<String>();
        let (in_tx, in_rx) = mpsc::channel::<Inbound>(64);
        let out_rx = std::sync::Arc::new(tokio::sync::Mutex::new(out_rx));
        let seen = std::sync::Arc::new(std::sync::Mutex::new(SeenSet::new(SEEN_CAPACITY)));
        let mut tasks = Vec::new();
        let mut connected = 0;

        // Broadcast: every outbound JSON goes to every relay. A small fan-out
        // task per relay pulls from a shared queue via a broadcast channel.
        let (bcast_tx, _) = tokio::sync::broadcast::channel::<String>(64);
        {
            let bcast_tx = bcast_tx.clone();
            let out_rx = out_rx.clone();
            tasks.push(tokio::spawn(async move {
                let mut rx = out_rx.lock().await;
                while let Some(json) = rx.recv().await {
                    let _ = bcast_tx.send(json);
                }
            }));
        }

        let filter = Filter::new().kind(Kind::Custom(KIND)).pubkey(keys.public_key()).since(Timestamp::now());
        let sub_id = SubscriptionId::generate();
        let req = ClientMessage::req(sub_id.clone(), vec![filter]);
        let req_json = serde_json::to_string(&req)?;

        // Dial every relay at once: a slow or dead relay must not delay the rest.
        let attempts = futures_util::future::join_all(relays.iter().map(|url| async move {
            (url.clone(), tokio::time::timeout(CONNECT_TIMEOUT, tokio_tungstenite::connect_async(url)).await)
        }))
        .await;
        for (url, attempt) in attempts {
            let url = &url;
            match attempt {
                Ok(Ok((ws, _))) => {
                    connected += 1;
                    let (mut sink, mut source) = ws.split();
                    let mut bcast_rx = bcast_tx.subscribe();
                    let in_tx = in_tx.clone();
                    let keys = keys.clone();
                    let seen = seen.clone();
                    let url = url.clone();
                    let req_json = req_json.clone();
                    tasks.push(tokio::spawn(async move {
                        if sink.send(WsMessage::Text(req_json)).await.is_err() {
                            return;
                        }
                        loop {
                            tokio::select! {
                                out = bcast_rx.recv() => match out {
                                    Ok(json) => {
                                        if sink.send(WsMessage::Text(json)).await.is_err() {
                                            debug!(%url, "relay sink closed");
                                            break;
                                        }
                                    }
                                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                                    Err(_) => break,
                                },
                                frame = source.next() => match frame {
                                    Some(Ok(WsMessage::Text(text))) => {
                                        if let Some(inbound) = decode_relay_message(&text, &keys, &seen, Timestamp::now()) {
                                            if in_tx.send(inbound).await.is_err() {
                                                break;
                                            }
                                        }
                                    }
                                    Some(Ok(WsMessage::Ping(p))) => {
                                        let _ = sink.send(WsMessage::Pong(p)).await;
                                    }
                                    Some(Ok(WsMessage::Close(_))) | None => {
                                        debug!(%url, "relay closed");
                                        break;
                                    }
                                    Some(Ok(_)) => {}
                                    Some(Err(e)) => {
                                        debug!(%url, error = %e, "relay error");
                                        break;
                                    }
                                }
                            }
                        }
                    }));
                }
                Ok(Err(e)) => warn!(%url, error = %e, "relay connect failed"),
                Err(_) => warn!(%url, "relay connect timed out"),
            }
        }
        if connected == 0 {
            for t in &tasks {
                t.abort();
            }
            return Err(DiscoveryError::Other("no Nostr relay reachable".into()));
        }
        debug!(connected, "nostr link up");
        Ok(Self { sender: NostrSender { keys, identity, out_tx }, in_rx, tasks })
    }

    /// Send `msg` to the device whose Nostr key is `to`.
    pub fn send(&self, to: &PublicKey, msg: &SignalMessage) -> Result<()> {
        self.sender.send(to, msg)
    }

    /// A cloneable handle that can send while `recv` is being awaited elsewhere.
    pub fn sender(&self) -> NostrSender {
        self.sender.clone()
    }

    pub fn public_key(&self) -> PublicKey {
        self.sender.public_key()
    }

    /// Next authenticated inbound message.
    pub async fn recv(&mut self) -> Option<Inbound> {
        self.in_rx.recv().await
    }
}

impl Drop for NostrLink {
    fn drop(&mut self) {
        for t in &self.tasks {
            t.abort();
        }
    }
}

/// Parse one relay frame; returns an [`Inbound`] for a valid, new, timely,
/// addressed event and `None` for everything else (notices, EOSE, duplicates,
/// stale or future-dated events, junk). `now` is injected for tests.
fn decode_relay_message(
    text: &str,
    keys: &Keys,
    seen: &std::sync::Mutex<SeenSet>,
    now: Timestamp,
) -> Option<Inbound> {
    let msg: RelayMessage<'_> = serde_json::from_str(text).ok()?;
    let RelayMessage::Event { event, .. } = msg else { return None };
    let event = event.into_owned();
    if event.kind != Kind::Custom(KIND) || event.verify().is_err() {
        return None;
    }
    if !within_skew(event.created_at, now) {
        debug!(created_at = %event.created_at, "dropping event outside the accepted time window");
        return None;
    }
    {
        let s = seen.lock().unwrap_or_else(|p| p.into_inner());
        if s.contains(&event.id) {
            return None;
        }
    }
    let plain = keys.nip44_decrypt(&event.pubkey, &event.content).ok()?;
    let env: Envelope = serde_json::from_str(&plain).ok()?;
    // Bind the Ed25519 identity to the Nostr key that signed the event.
    verify_b64_sig(&env.pk, &nostr_binding_message(&event.pubkey.to_hex()), &env.bind).ok()?;
    let from_id = derive_id_from_public_key_b64(&env.pk).ok()?;
    // Only an event that decrypted and verified occupies a replay slot:
    // junk from throwaway keys must not be able to evict a genuine event
    // and reopen its replay window.
    {
        let mut s = seen.lock().unwrap_or_else(|p| p.into_inner());
        if !s.insert(event.id) {
            return None;
        }
    }
    Some(Inbound { from_public_key: env.pk, from_id, from_nostr: event.pubkey, msg: env.msg })
}

/// `created_at` within [`MAX_CLOCK_SKEW`] of `now`, either side.
fn within_skew(created_at: Timestamp, now: Timestamp) -> bool {
    let (a, b) = (created_at.as_secs(), now.as_secs());
    a.abs_diff(b) <= MAX_CLOCK_SKEW.as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seen() -> std::sync::Mutex<SeenSet> {
        std::sync::Mutex::new(SeenSet::new(SEEN_CAPACITY))
    }

    /// A signaling event from `a` to `b`, dated `created_at`, as a relay
    /// would frame it.
    fn event_json(a: &Identity, kb: &Keys, msg: SignalMessage, created_at: Timestamp) -> (String, Event) {
        let ka = nostr_keys(a);
        let env = Envelope {
            pk: a.public_key_b64(),
            bind: a.sign_b64(&nostr_binding_message(&ka.public_key().to_hex())),
            msg,
        };
        let plain = serde_json::to_string(&env).unwrap();
        let cipher = ka.nip44_encrypt(&kb.public_key(), &plain).unwrap();
        let event = EventBuilder::new(Kind::Custom(KIND), cipher)
            .tag(Tag::public_key(kb.public_key()))
            .custom_created_at(created_at)
            .finalize(&ka)
            .unwrap();
        let json = serde_json::to_string(&RelayMessage::Event {
            subscription_id: std::borrow::Cow::Owned(SubscriptionId::new("s")),
            event: std::borrow::Cow::Borrowed(&event),
        })
        .unwrap();
        (json, event)
    }

    #[test]
    fn envelope_roundtrips_through_nip44_and_binding_is_checked() {
        let a = Identity::generate();
        let b = Identity::generate();
        let kb = nostr_keys(&b);
        let now = Timestamp::now();
        let (relay_json, _) = event_json(&a, &kb, SignalMessage::Ping { nonce: 3 }, now);
        let seen = seen();
        let inbound = decode_relay_message(&relay_json, &kb, &seen, now).expect("valid event");
        assert_eq!(inbound.from_id, a.derive_id());
        assert_eq!(inbound.from_public_key, a.public_key_b64());
        assert!(matches!(inbound.msg, SignalMessage::Ping { nonce: 3 }));
        // Duplicate delivery from a second relay is dropped.
        assert!(decode_relay_message(&relay_json, &kb, &seen, now).is_none());
        // A third party cannot read it.
        let kc = nostr_keys(&Identity::generate());
        assert!(decode_relay_message(&relay_json, &kc, &self::seen(), now).is_none());
    }

    #[test]
    fn events_outside_the_time_window_are_dropped() {
        let a = Identity::generate();
        let kb = nostr_keys(&Identity::generate());
        let now = Timestamp::from_secs(1_800_000_000);
        let skew = MAX_CLOCK_SKEW.as_secs();
        let cases = [
            (now.as_secs() - skew - 1, false, "too old (replay)"),
            (now.as_secs() - skew, true, "oldest accepted"),
            (now.as_secs() + skew, true, "newest accepted"),
            (now.as_secs() + skew + 1, false, "future-dated"),
        ];
        for (created_at, accepted, why) in cases {
            let (json, _) = event_json(&a, &kb, SignalMessage::Ping { nonce: 1 }, Timestamp::from_secs(created_at));
            let got = decode_relay_message(&json, &kb, &seen(), now);
            assert_eq!(got.is_some(), accepted, "{why}");
        }
    }

    #[test]
    fn seen_set_evicts_oldest_one_at_a_time() {
        let a = Identity::generate();
        let kb = nostr_keys(&Identity::generate());
        let now = Timestamp::now();
        let ids: Vec<EventId> = (0..5u64)
            .map(|n| event_json(&a, &kb, SignalMessage::Ping { nonce: n }, now).1.id)
            .collect();
        let mut s = SeenSet::new(3);
        for id in &ids[..3] {
            assert!(s.insert(*id));
        }
        assert!(!s.insert(ids[0]), "duplicate while still remembered");
        assert!(s.insert(ids[3]), "new id");
        assert_eq!(s.len(), 3, "bounded");
        assert!(!s.contains(&ids[0]), "only the oldest was evicted");
        assert!(s.contains(&ids[1]) && s.contains(&ids[2]) && s.contains(&ids[3]));
        assert!(s.insert(ids[4]));
        assert!(!s.contains(&ids[1]));
        assert!(!s.insert(ids[2]), "recent ids survive a churn of new ones");
    }

    /// End to end through the decoder: filling the ring with junk events must
    /// not let a recent event be replayed.
    #[test]
    fn duplicate_is_still_rejected_after_many_other_events() {
        let a = Identity::generate();
        let kb = nostr_keys(&Identity::generate());
        let now = Timestamp::now();
        let seen = std::sync::Mutex::new(SeenSet::new(8));
        let (first, _) = event_json(&a, &kb, SignalMessage::Ping { nonce: 100 }, now);
        assert!(decode_relay_message(&first, &kb, &seen, now).is_some());
        for n in 0..6u64 {
            let (json, _) = event_json(&a, &kb, SignalMessage::Ping { nonce: n }, now);
            assert!(decode_relay_message(&json, &kb, &seen, now).is_some());
        }
        assert!(decode_relay_message(&first, &kb, &seen, now).is_none(), "replay within capacity");
    }

    #[test]
    fn forged_binding_is_rejected() {
        let a = Identity::generate();
        let liar = Identity::generate();
        let ka = nostr_keys(&a);
        let kb = nostr_keys(&Identity::generate());
        // Event signed by `a`'s nostr key, but claims to be `liar`'s identity.
        let env = Envelope {
            pk: liar.public_key_b64(),
            bind: liar.sign_b64(&nostr_binding_message(&nostr_keys(&liar).public_key().to_hex())),
            msg: SignalMessage::Ping { nonce: 0 },
        };
        let plain = serde_json::to_string(&env).unwrap();
        let cipher = ka.nip44_encrypt(&kb.public_key(), &plain).unwrap();
        let event = EventBuilder::new(Kind::Custom(KIND), cipher).finalize(&ka).unwrap();
        let relay_json = serde_json::to_string(&RelayMessage::Event {
            subscription_id: std::borrow::Cow::Owned(SubscriptionId::new("s")),
            event: std::borrow::Cow::Borrowed(&event),
        })
        .unwrap();
        assert!(decode_relay_message(&relay_json, &kb, &seen(), Timestamp::now()).is_none());
    }

    /// Live: talks to public relays. Run with `-- --ignored`.
    #[tokio::test]
    #[ignore]
    async fn two_devices_exchange_a_message_over_public_relays() {
        let a = Identity::generate();
        let b = Identity::generate();
        let relays = relays_from_env();
        let la = NostrLink::connect(a.clone(), &relays).await.unwrap();
        let mut lb = NostrLink::connect(b.clone(), &relays).await.unwrap();
        tokio::time::sleep(Duration::from_millis(500)).await;
        la.send(&nostr_keys(&b).public_key(), &SignalMessage::Ping { nonce: 42 }).unwrap();
        let got = tokio::time::timeout(Duration::from_secs(15), lb.recv()).await.unwrap().unwrap();
        assert_eq!(got.from_id, a.derive_id());
        assert!(matches!(got.msg, SignalMessage::Ping { nonce: 42 }));
    }
}
