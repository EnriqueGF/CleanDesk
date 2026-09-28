//! Community-mode viewer: find the host without a server and talk to it.
//!
//! 1. Resolve the ID: LAN (mDNS), then the DHT (by pinned key, then by ID).
//! 2. Try every direct endpoint from the record (authenticated TCP link).
//! 3. Otherwise go through public Nostr relays (encrypted events).
//! 4. Hand the resulting link to the shared [`connect_over`](crate::connect_over)
//!    flow, adding any community relays found on the DHT as TURN fallbacks.

use crate::{connect_over, ClientConfig, ClientSession};
use anyhow::{bail, Context, Result};
use cleandesk_discovery::{
    dht::DhtNode,
    direct::{self, DirectLink},
    nostr_link::{self, NostrLink},
    Resolver, COMMUNITY_TURN_PASS, COMMUNITY_TURN_USER,
};
use cleandesk_proto::message::SignalMessage;
use cleandesk_transport::{QueueOut, SignalOut, TurnServer};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

/// Overall budget for finding the host.
pub const RESOLVE_TIMEOUT: Duration = Duration::from_secs(25);

/// Open a session to `config.target` without a CleanDesk Server.
///
/// `pinned_key` is the host's key remembered from a previous session; a
/// different key for the same ID is refused.
pub async fn connect_community(mut config: ClientConfig, pinned_key: Option<String>) -> Result<ClientSession> {
    let dht = match DhtNode::start() {
        Ok(n) => Some(n),
        Err(e) => {
            warn!(error = %e, "DHT unavailable; LAN only");
            None
        }
    };
    // Relay directory lookup runs while we resolve; it is only needed once
    // ICE starts.
    let relay_lookup = {
        let dht = dht.clone();
        tokio::spawn(async move {
            match dht {
                Some(node) => node.find_relays(4).await,
                None => Vec::new(),
            }
        })
    };
    let resolver = Resolver::new(dht.clone());
    let resolved = tokio::time::timeout(RESOLVE_TIMEOUT, resolver.resolve(config.target, pinned_key.as_deref()))
        .await
        .map_err(|_| anyhow::anyhow!("device {} not found (timed out)", config.target))?
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    info!(target = %config.target, via = resolved.via, endpoints = resolved.endpoints.len(), "host resolved");

    // Community relays as ICE fallback.
    if let Ok(relays) = relay_lookup.await {
        if !relays.is_empty() {
            config.ice.turn.push(TurnServer {
                urls: relays.iter().map(|a| format!("turn:{a}?transport=udp")).collect(),
                username: COMMUNITY_TURN_USER.into(),
                credential: COMMUNITY_TURN_PASS.into(),
            });
        }
    }

    let host_key = resolved.record.pk.clone();

    // 2. Direct endpoints.
    for ep in &resolved.endpoints {
        match direct::dial(*ep, &config.identity, config.device.clone(), &host_key, config.target).await {
            Ok(link) => {
                let via = if resolved.via == "LAN" { "LAN" } else { "directo" };
                let (out, rx) = drive_direct(link);
                return connect_over(config, out, rx, via, Some(host_key)).await;
            }
            Err(e) => debug!(%ep, error = %e, "direct endpoint failed"),
        }
    }

    // 3. Nostr.
    let Some(nostr_hex) = resolved.record.nostr.clone() else {
        bail!("the device is not reachable directly and announces no Nostr signaling");
    };
    let to = nostr_link::NostrPublicKey::from_hex(&nostr_hex).context("host nostr key")?;
    let relays = nostr_link::relays_from_env();
    let mut link = NostrLink::connect(config.identity.clone(), &relays)
        .await
        .map_err(|e| anyhow::anyhow!("no Nostr relays reachable: {e}"))?;
    let sender = link.sender();
    let (out_tx, mut out_rx) = mpsc::unbounded_channel::<SignalMessage>();
    tokio::spawn(async move {
        while let Some(m) = out_rx.recv().await {
            if let Err(e) = sender.send(&to, &m) {
                debug!(error = %e, "nostr send failed");
            }
        }
    });
    let (in_tx, in_rx) = mpsc::channel::<SignalMessage>(64);
    let expect_key = host_key.clone();
    let target = config.target;
    tokio::spawn(async move {
        while let Some(inbound) = link.recv().await {
            // Only the host we dialed, proven by its Ed25519 binding.
            if inbound.from_id != target || inbound.from_public_key != expect_key {
                debug!(from = %inbound.from_id, "ignoring nostr message from another device");
                continue;
            }
            if in_tx.send(inbound.msg).await.is_err() {
                break;
            }
        }
    });
    let out: Arc<dyn SignalOut> = Arc::new(QueueOut(out_tx));
    connect_over(config, out, in_rx, "nostr", Some(host_key)).await
}

/// Own a direct link: outbound queue → socket, socket → inbound channel.
fn drive_direct(mut link: DirectLink) -> (Arc<dyn SignalOut>, mpsc::Receiver<SignalMessage>) {
    let (out_tx, mut out_rx) = mpsc::unbounded_channel::<SignalMessage>();
    let (in_tx, in_rx) = mpsc::channel::<SignalMessage>(64);
    tokio::spawn(async move {
        loop {
            tokio::select! {
                incoming = link.recv() => match incoming {
                    Ok(Some(msg)) => {
                        if in_tx.send(msg).await.is_err() {
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
    });
    (Arc::new(QueueOut(out_tx)), in_rx)
}
