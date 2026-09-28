//! Signaling client: JSON [`SignalMessage`]s over a WebSocket to the CleanDesk
//! Server.
//!
//! The socket is split in two: a background *reader* task decodes inbound text
//! frames into [`SignalMessage`]s and forwards them to an mpsc channel, and a
//! background *writer* task drains an outbound mpsc and serializes to the sink.
//! Keeping the sink behind a task (rather than a shared `Mutex<SplitSink>`) lets
//! [`SignalingClient::send`] stay `&self` and lock-free, and never holds a lock
//! across an `.await`.
//!
//! The writer also emits a protocol-level `Ping` whenever the connection has
//! been idle for [`KEEPALIVE_INTERVAL`]. NAT bindings and some proxies drop
//! silent TCP connections; a host that sits idle for hours would otherwise
//! believe it is registered while nobody can reach it.

use crate::error::TransportError;
use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use cleandesk_proto::{
    id::CleanDeskId,
    message::{register_proof_message, SignalMessage},
    session::DeviceInfo,
    PROTOCOL_VERSION,
};
use futures_util::{SinkExt, StreamExt};
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::Message;
use tracing::{debug, trace, warn};

/// How long [`SignalingClient::register`] waits for each server reply.
const REGISTER_TIMEOUT: Duration = Duration::from_secs(10);

/// Idle time after which the writer sends a keepalive `Ping`.
pub const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(30);

/// Capacity of the inbound event channel. Signaling traffic is low-volume, so a
/// small buffer is plenty; back-pressure here only slows the socket reader.
const INBOUND_CAPACITY: usize = 128;

/// Signs the server's registration challenge with the device's private key.
///
/// Kept as a trait rather than a dependency on `cleandesk-crypto` so this
/// crate stays a pure transport; `cleandesk_crypto::identity::Identity`
/// implements the same shape via [`SignalingClient::register`]'s closure form.
pub trait ChallengeSigner: Send + Sync {
    /// Ed25519 signature, base64, over the given message bytes.
    fn sign_b64(&self, msg: &[u8]) -> String;
}

impl<F> ChallengeSigner for F
where
    F: Fn(&[u8]) -> String + Send + Sync,
{
    fn sign_b64(&self, msg: &[u8]) -> String {
        self(msg)
    }
}

/// A connected signaling session with the CleanDesk Server.
pub struct SignalingClient {
    /// Outbound queue drained by the writer task.
    out_tx: mpsc::UnboundedSender<SignalMessage>,
    /// Inbound queue fed by the reader task. Taken out by [`Self::events`];
    /// consumed in place by [`Self::register`] until then.
    in_rx: Option<mpsc::Receiver<SignalMessage>>,
    reader: JoinHandle<()>,
    writer: JoinHandle<()>,
}

impl SignalingClient {
    /// Connect to `ws://host:port/` (or `wss://…`) and start the reader/writer
    /// tasks.
    pub async fn connect(url: &str) -> Result<Self> {
        let (ws, _resp) = connect_async(url)
            .await
            .with_context(|| format!("connecting to signaling server at {url}"))?;
        let (mut sink, mut source) = ws.split();

        let (out_tx, mut out_rx) = mpsc::unbounded_channel::<SignalMessage>();
        let (in_tx, in_rx) = mpsc::channel::<SignalMessage>(INBOUND_CAPACITY);

        // Writer: JSON-encode outbound messages and push them onto the socket,
        // injecting a keepalive Ping when nothing else has been sent for a while.
        let writer = tokio::spawn(async move {
            let mut nonce: u64 = 0;
            loop {
                let msg = tokio::select! {
                    m = out_rx.recv() => match m {
                        Some(m) => m,
                        None => break,
                    },
                    _ = tokio::time::sleep(KEEPALIVE_INTERVAL) => {
                        nonce = nonce.wrapping_add(1);
                        SignalMessage::Ping { nonce }
                    }
                };
                match serde_json::to_string(&msg) {
                    Ok(json) => {
                        if let Err(e) = sink.send(Message::Text(json)).await {
                            debug!(error = %e, "signaling sink closed");
                            break;
                        }
                    }
                    // A message we produced failed to serialize: log and skip,
                    // rather than tearing down the whole connection.
                    Err(e) => warn!(error = %e, "dropping unserializable outbound signal"),
                }
            }
            let _ = sink.close().await;
        });

        // Reader: decode inbound text frames and forward them to `in_tx`.
        let reader = tokio::spawn(async move {
            while let Some(frame) = source.next().await {
                match frame {
                    Ok(Message::Text(text)) => match serde_json::from_str::<SignalMessage>(&text) {
                        // Keepalive answers carry no information for the caller.
                        Ok(SignalMessage::Pong { .. }) => trace!("keepalive pong"),
                        Ok(msg) => {
                            if in_tx.send(msg).await.is_err() {
                                // Receiver dropped: nobody is listening anymore.
                                break;
                            }
                        }
                        Err(e) => warn!(error = %e, "ignoring undecodable signaling frame"),
                    },
                    Ok(Message::Close(_)) => {
                        debug!("signaling server closed the connection");
                        break;
                    }
                    // Ping/Pong are handled by tungstenite; Binary is unused here.
                    Ok(_) => trace!("ignoring non-text signaling frame"),
                    Err(e) => {
                        debug!(error = %e, "signaling socket error");
                        break;
                    }
                }
            }
        });

        Ok(Self {
            out_tx,
            in_rx: Some(in_rx),
            reader,
            writer,
        })
    }

    /// Register this device and await the server-confirmed [`CleanDeskId`].
    ///
    /// Flow: send `Register`, receive `RegisterChallenge { nonce }`, answer with
    /// `RegisterProof { signature }` produced by `signer` over
    /// [`register_proof_message`], and wait for `Registered { id }`. Each step
    /// is bounded by [`REGISTER_TIMEOUT`]. An `Error` frame at any point is
    /// surfaced as [`TransportError::RegisterRejected`].
    ///
    /// Must be called before [`Self::events`], which takes ownership of the
    /// inbound stream.
    pub async fn register(
        &mut self,
        device: DeviceInfo,
        public_key_b64: String,
        signer: &dyn ChallengeSigner,
    ) -> Result<CleanDeskId> {
        self.send(SignalMessage::Register {
            device,
            protocol: PROTOCOL_VERSION,
            public_key: public_key_b64,
        })
        .await?;

        // Split the borrows: the writer handle is cloned so we can keep the
        // inbound receiver mutably borrowed across the whole exchange.
        let out_tx = self.out_tx.clone();
        let rx = self
            .in_rx
            .as_mut()
            .ok_or(TransportError::AlreadyTaken("events"))?;

        loop {
            match tokio::time::timeout(REGISTER_TIMEOUT, rx.recv()).await {
                Ok(Some(SignalMessage::RegisterChallenge { nonce })) => {
                    let nonce_bytes = B64.decode(&nonce).map_err(|e| {
                        TransportError::RegisterProtocol(format!("malformed challenge nonce: {e}"))
                    })?;
                    let signature = signer.sign_b64(&register_proof_message(&nonce_bytes));
                    out_tx
                        .send(SignalMessage::RegisterProof { signature })
                        .map_err(|_| TransportError::SignalingClosed)?;
                }
                Ok(Some(SignalMessage::Registered { id })) => return Ok(id),
                Ok(Some(SignalMessage::Error { code, detail })) => {
                    return Err(TransportError::RegisterRejected { code, detail }.into());
                }
                Ok(Some(other)) => {
                    debug!(?other, "ignoring message received before registration");
                    continue;
                }
                Ok(None) => return Err(TransportError::SignalingClosed.into()),
                Err(_elapsed) => {
                    return Err(TransportError::RegisterTimeout(REGISTER_TIMEOUT).into())
                }
            }
        }
    }

    /// Send any [`SignalMessage`] to the server. Non-blocking: the message is
    /// queued for the writer task.
    pub async fn send(&self, msg: SignalMessage) -> Result<()> {
        self.out_tx
            .send(msg)
            .map_err(|_| TransportError::SignalingClosed)?;
        Ok(())
    }

    /// Take ownership of the inbound stream of [`SignalMessage`]s
    /// (`IncomingRequest`, `Accept`, `Reject`, `Signal`, `Ping`, …).
    ///
    /// Can only be called once (after [`Self::register`]); a second call fails
    /// with [`TransportError::AlreadyTaken`].
    pub fn events(&mut self) -> Result<mpsc::Receiver<SignalMessage>> {
        self.in_rx
            .take()
            .ok_or_else(|| TransportError::AlreadyTaken("events").into())
    }

    /// True while both socket tasks are still running.
    pub fn is_connected(&self) -> bool {
        !self.reader.is_finished() && !self.writer.is_finished()
    }
}

impl Drop for SignalingClient {
    fn drop(&mut self) {
        // Stop the background tasks so a dropped client does not leak them.
        self.reader.abort();
        self.writer.abort();
    }
}

/// Anything that can carry a [`SignalMessage`] to the other side of a
/// rendezvous: the CleanDesk Server socket, a direct TCP link, a Nostr
/// relay. Host and viewer code are written against this so every rendezvous
/// mechanism reuses the same session logic.
#[async_trait::async_trait]
pub trait SignalOut: Send + Sync {
    async fn send(&self, msg: SignalMessage) -> Result<()>;
}

#[async_trait::async_trait]
impl SignalOut for SignalingClient {
    async fn send(&self, msg: SignalMessage) -> Result<()> {
        SignalingClient::send(self, msg).await
    }
}

/// [`SignalOut`] backed by an unbounded queue drained by some other task
/// (a direct link driver, a Nostr sender loop).
pub struct QueueOut(pub tokio::sync::mpsc::UnboundedSender<SignalMessage>);

#[async_trait::async_trait]
impl SignalOut for QueueOut {
    async fn send(&self, msg: SignalMessage) -> Result<()> {
        self.0.send(msg).map_err(|_| TransportError::SignalingClosed)?;
        Ok(())
    }
}
