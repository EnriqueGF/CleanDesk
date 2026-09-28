//! Direct TCP signaling link between a viewer and a reachable host.
//!
//! Frames are `u32 LE length + JSON SignalMessage` (the same JSON the
//! CleanDesk Server speaks), so host/viewer code reuses every message type.
//!
//! # Handshake (mutual proof of identity)
//!
//! ```text
//! viewer → host   Register { device, protocol, public_key: V }
//! viewer → host   RegisterChallenge { nonce: nv }
//! host   → viewer RegisterChallenge { nonce: nh }
//! viewer → host   RegisterProof { signature: sign_V(prefix || nh) }
//! host   → viewer RegisterProof { signature: sign_H(prefix || nv) }
//! host   → viewer Registered { id: host id }
//! ```
//!
//! The viewer already knows (and has verified) the host's key from the LAN
//! or DHT record, and checks it derives to the ID it dialed. The host learns
//! the viewer's key and verifies it derives to the ID inside `device`. Bytes
//! are not encrypted on this link: it carries only SDP/ICE, whose DTLS
//! fingerprints are what the peers authenticate; an on-path attacker could
//! still attempt a substitution, which the Nostr path prevents and a future
//! Noise wrap will close here too.

use crate::{DiscoveryError, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use cleandesk_crypto::identity::{derive_id_from_public_key_b64, random_bytes, verify_b64_sig, Identity};
use cleandesk_proto::{
    frame::FrameCodec,
    message::{register_proof_message, SignalMessage},
    session::DeviceInfo,
    CleanDeskId, PROTOCOL_VERSION,
};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, warn};

/// Largest accepted frame (an SDP is a few KiB).
const MAX_FRAME: usize = 64 * 1024;

/// Handshake step deadline.
const STEP_TIMEOUT: Duration = Duration::from_secs(8);

/// Dial timeout per endpoint.
pub const DIAL_TIMEOUT: Duration = Duration::from_secs(4);

/// One authenticated, framed connection.
pub struct DirectLink {
    stream: TcpStream,
    codec: FrameCodec,
    /// The remote's Ed25519 public key (base64), proven during the handshake.
    pub peer_public_key: String,
    pub peer_id: CleanDeskId,
    /// The remote's device info (from `Register`), host side only.
    pub peer_device: Option<DeviceInfo>,
}

impl DirectLink {
    pub async fn send(&mut self, msg: &SignalMessage) -> Result<()> {
        let json = serde_json::to_vec(msg)?;
        if json.len() > MAX_FRAME {
            return Err(DiscoveryError::Protocol("frame too large".into()));
        }
        let mut buf = Vec::with_capacity(4 + json.len());
        buf.extend_from_slice(&(json.len() as u32).to_le_bytes());
        buf.extend_from_slice(&json);
        self.stream.write_all(&buf).await?;
        Ok(())
    }

    /// Next message, or `None` when the peer closed the connection.
    pub async fn recv(&mut self) -> Result<Option<SignalMessage>> {
        loop {
            if let Some(payload) = self.codec.next_payload().map_err(|e| DiscoveryError::Protocol(e.to_string()))? {
                if payload.len() > MAX_FRAME {
                    return Err(DiscoveryError::Protocol("frame too large".into()));
                }
                return Ok(Some(serde_json::from_slice(&payload)?));
            }
            let mut chunk = [0u8; 4096];
            let n = self.stream.read(&mut chunk).await?;
            if n == 0 {
                return Ok(None);
            }
            self.codec.feed(&chunk[..n]);
        }
    }

    async fn recv_step(&mut self) -> Result<SignalMessage> {
        match tokio::time::timeout(STEP_TIMEOUT, self.recv()).await {
            Ok(Ok(Some(m))) => Ok(m),
            Ok(Ok(None)) => Err(DiscoveryError::Protocol("peer closed during handshake".into())),
            Ok(Err(e)) => Err(e),
            Err(_) => Err(DiscoveryError::Timeout("handshake")),
        }
    }

    pub fn peer_addr(&self) -> Option<SocketAddr> {
        self.stream.peer_addr().ok()
    }
}

impl std::fmt::Debug for DirectLink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DirectLink").field("peer_id", &self.peer_id).field("addr", &self.peer_addr()).finish()
    }
}

/// Listening side (host).
pub struct DirectListener {
    listener: TcpListener,
}

impl DirectListener {
    /// Bind on all interfaces; `port` 0 picks one.
    pub async fn bind(port: u16) -> Result<Self> {
        let listener = TcpListener::bind(("0.0.0.0", port)).await?;
        Ok(Self { listener })
    }

    pub fn port(&self) -> u16 {
        self.listener.local_addr().map(|a| a.port()).unwrap_or(0)
    }

    /// Accept one TCP connection and run the host side of the handshake.
    /// Failed handshakes are logged and skipped; this only returns links
    /// whose peer proved its identity.
    pub async fn accept(&self, identity: &Identity) -> Result<DirectLink> {
        loop {
            let (stream, addr) = self.listener.accept().await?;
            match tokio::time::timeout(STEP_TIMEOUT * 3, host_handshake(stream, identity)).await {
                Ok(Ok(link)) => return Ok(link),
                Ok(Err(e)) => warn!(%addr, error = %e, "direct link handshake failed"),
                Err(_) => warn!(%addr, "direct link handshake timed out"),
            }
        }
    }
}

async fn host_handshake(stream: TcpStream, identity: &Identity) -> Result<DirectLink> {
    let mut link = DirectLink {
        stream,
        codec: FrameCodec::new(),
        peer_public_key: String::new(),
        peer_id: identity.derive_id(),
        peer_device: None,
    };
    let SignalMessage::Register { device, protocol, public_key } = link.recv_step().await? else {
        return Err(DiscoveryError::Protocol("expected Register".into()));
    };
    if !protocol.compatible_with(PROTOCOL_VERSION) {
        return Err(DiscoveryError::Protocol(format!("incompatible protocol {protocol}")));
    }
    let derived = derive_id_from_public_key_b64(&public_key)?;
    if derived != device.id {
        return Err(DiscoveryError::AuthFailed("viewer id does not derive from its key".into()));
    }
    let SignalMessage::RegisterChallenge { nonce: viewer_nonce } = link.recv_step().await? else {
        return Err(DiscoveryError::Protocol("expected viewer challenge".into()));
    };
    let viewer_nonce = B64.decode(viewer_nonce).map_err(|e| DiscoveryError::Protocol(e.to_string()))?;

    let my_nonce = random_bytes(32);
    link.send(&SignalMessage::RegisterChallenge { nonce: B64.encode(&my_nonce) }).await?;
    let SignalMessage::RegisterProof { signature } = link.recv_step().await? else {
        return Err(DiscoveryError::Protocol("expected viewer proof".into()));
    };
    verify_b64_sig(&public_key, &register_proof_message(&my_nonce), &signature)
        .map_err(|_| DiscoveryError::AuthFailed("bad viewer proof".into()))?;

    link.send(&SignalMessage::RegisterProof {
        signature: identity.sign_b64(&register_proof_message(&viewer_nonce)),
    })
    .await?;
    link.send(&SignalMessage::Registered { id: identity.derive_id() }).await?;

    link.peer_public_key = public_key;
    link.peer_id = device.id;
    link.peer_device = Some(device);
    debug!(peer = %link.peer_id, "direct link authenticated (host side)");
    Ok(link)
}

/// Dial `endpoint` and run the viewer side of the handshake, expecting the
/// host to hold `host_public_key` (base64) and to be `host_id`.
pub async fn dial(
    endpoint: SocketAddr,
    identity: &Identity,
    device: DeviceInfo,
    host_public_key: &str,
    host_id: CleanDeskId,
) -> Result<DirectLink> {
    if derive_id_from_public_key_b64(host_public_key)? != host_id {
        return Err(DiscoveryError::AuthFailed("host key does not derive to the dialed id".into()));
    }
    let stream = tokio::time::timeout(DIAL_TIMEOUT, TcpStream::connect(endpoint))
        .await
        .map_err(|_| DiscoveryError::Timeout("dial"))??;
    let _ = stream.set_nodelay(true);
    let mut link = DirectLink {
        stream,
        codec: FrameCodec::new(),
        peer_public_key: host_public_key.to_string(),
        peer_id: host_id,
        peer_device: None,
    };
    link.send(&SignalMessage::Register {
        device,
        protocol: PROTOCOL_VERSION,
        public_key: identity.public_key_b64(),
    })
    .await?;
    let my_nonce = random_bytes(32);
    link.send(&SignalMessage::RegisterChallenge { nonce: B64.encode(&my_nonce) }).await?;

    let SignalMessage::RegisterChallenge { nonce } = link.recv_step().await? else {
        return Err(DiscoveryError::Protocol("expected host challenge".into()));
    };
    let nonce = B64.decode(nonce).map_err(|e| DiscoveryError::Protocol(e.to_string()))?;
    link.send(&SignalMessage::RegisterProof { signature: identity.sign_b64(&register_proof_message(&nonce)) })
        .await?;

    let SignalMessage::RegisterProof { signature } = link.recv_step().await? else {
        return Err(DiscoveryError::Protocol("expected host proof".into()));
    };
    verify_b64_sig(host_public_key, &register_proof_message(&my_nonce), &signature)
        .map_err(|_| DiscoveryError::AuthFailed("bad host proof".into()))?;
    let SignalMessage::Registered { id } = link.recv_step().await? else {
        return Err(DiscoveryError::Protocol("expected Registered".into()));
    };
    if id != host_id {
        return Err(DiscoveryError::AuthFailed("host announced a different id".into()));
    }
    debug!(%endpoint, host = %host_id, "direct link authenticated (viewer side)");
    Ok(link)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dev(id: CleanDeskId) -> DeviceInfo {
        DeviceInfo { id, alias: None, hostname: "v".into(), os: "t".into(), app_version: "0".into() }
    }

    #[tokio::test]
    async fn mutual_handshake_then_messages_flow() {
        let host = Identity::generate();
        let viewer = Identity::generate();
        let listener = DirectListener::bind(0).await.unwrap();
        let ep: SocketAddr = format!("127.0.0.1:{}", listener.port()).parse().unwrap();
        let host_pk = host.public_key_b64();
        let host_id = host.derive_id();
        let h = tokio::spawn(async move {
            let mut link = listener.accept(&host).await.unwrap();
            assert_eq!(link.peer_id, viewer_id_holder());
            let msg = link.recv().await.unwrap().unwrap();
            assert!(matches!(msg, SignalMessage::Ping { nonce: 7 }));
            link.send(&SignalMessage::Pong { nonce: 7 }).await.unwrap();
        });
        set_viewer_id(viewer.derive_id());
        let mut link = dial(ep, &viewer, dev(viewer.derive_id()), &host_pk, host_id).await.unwrap();
        link.send(&SignalMessage::Ping { nonce: 7 }).await.unwrap();
        assert!(matches!(link.recv().await.unwrap(), Some(SignalMessage::Pong { nonce: 7 })));
        h.await.unwrap();
    }

    // Tiny cross-task handoff for the test above (avoids capturing the
    // viewer identity in the host task).
    static VIEWER_ID: std::sync::OnceLock<CleanDeskId> = std::sync::OnceLock::new();
    fn set_viewer_id(id: CleanDeskId) {
        let _ = VIEWER_ID.set(id);
    }
    fn viewer_id_holder() -> CleanDeskId {
        *VIEWER_ID.get().expect("set before accept")
    }

    #[tokio::test]
    async fn impostor_host_is_rejected() {
        let real = Identity::generate();
        let impostor = Identity::generate();
        let impostor_id = impostor.derive_id();
        let viewer = Identity::generate();
        let listener = DirectListener::bind(0).await.unwrap();
        let ep: SocketAddr = format!("127.0.0.1:{}", listener.port()).parse().unwrap();
        tokio::spawn(async move {
            // The impostor answers with its own key; the viewer expects `real`.
            let _ = listener.accept(&impostor).await;
        });
        let err = dial(ep, &viewer, dev(viewer.derive_id()), &real.public_key_b64(), real.derive_id())
            .await
            .unwrap_err();
        assert!(matches!(err, DiscoveryError::AuthFailed(_)), "got {err}");
        // Dialing with a key that does not derive to the id fails before any I/O.
        let err = dial(ep, &viewer, dev(viewer.derive_id()), &real.public_key_b64(), impostor_id)
            .await
            .unwrap_err();
        assert!(matches!(err, DiscoveryError::AuthFailed(_)));
    }

    #[tokio::test]
    async fn viewer_with_mismatched_id_is_rejected_by_host() {
        let host = Identity::generate();
        let viewer = Identity::generate();
        let listener = DirectListener::bind(0).await.unwrap();
        let ep: SocketAddr = format!("127.0.0.1:{}", listener.port()).parse().unwrap();
        let host_pk = host.public_key_b64();
        let host_id = host.derive_id();
        let accept = tokio::spawn(async move {
            tokio::time::timeout(Duration::from_secs(3), listener.accept(&host)).await
        });
        // Claim somebody else's id in `device`.
        let bogus = dev(Identity::generate().derive_id());
        let r = dial(ep, &viewer, bogus, &host_pk, host_id).await;
        assert!(r.is_err());
        // The host never yields a link for it (accept keeps waiting until timeout).
        assert!(accept.await.unwrap().is_err());
    }
}
