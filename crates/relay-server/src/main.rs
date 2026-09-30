//! RotoDesk Relay binary — a thin wrapper around [`rotodesk_relay_server::run`].
//!
//! Configuration comes from `ROTODESK_RELAY_*` environment variables (see the
//! library docs). Runs until Ctrl-C, then closes the TURN server so live
//! allocations are released.
//!
//! In community mode the relay also keeps a small Ed25519 identity on disk
//! and publishes a signed record of its public address on the DHT, which is
//! what clients require before using a relay they found there.

use anyhow::{Context, Result};
use rotodesk_crypto::identity::Identity;
use rotodesk_relay_server::{
    RelayConfig, ENV_BIND, ENV_COMMUNITY, ENV_MAX_PORT, ENV_MIN_PORT, ENV_PORT, ENV_PUBLIC_IP,
    ENV_REALM, ENV_USERS,
};
use std::net::{IpAddr, SocketAddr};
use std::path::Path;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let config = RelayConfig::from_env().with_context(|| {
        format!(
            "invalid relay configuration; environment: {ENV_PORT} (default {}), {ENV_BIND} \
             (default 0.0.0.0), {ENV_PUBLIC_IP} (public IP advertised to peers), {ENV_REALM} \
             (default {}), {ENV_USERS}=user:pass[,user:pass...] (required), \
             {ENV_MIN_PORT}/{ENV_MAX_PORT} (optional relay port range), {ENV_COMMUNITY}=1 \n             (community mode: public credentials + DHT announcement)",
            rotodesk_proto::DEFAULT_RELAY_PORT,
            rotodesk_relay_server::DEFAULT_REALM,
        )
    })?;
    // Usernames only: passwords are never logged.
    tracing::info!(
        version = %rotodesk_proto::PROTOCOL_VERSION,
        bind = %config.bind,
        port = config.port,
        public_ip = %config.public_ip,
        realm = %config.realm,
        users = ?config.users.iter().map(|u| u.username.as_str()).collect::<Vec<_>>(),
        port_range = ?config.port_range,
        community = config.community,
        allow_private_peers = config.allow_private_peers,
        quotas = ?config.quotas,
        "RotoDesk Relay configuration"
    );

    let community = config.community;
    let port = config.port;
    let public_ip = config.public_ip;
    let identity_path = config.identity_path.clone();
    let handle = rotodesk_relay_server::run(config)
        .await
        .context("starting relay")?;

    // Community relays announce themselves on the BitTorrent DHT so clients
    // that have never heard of this machine can still find it. The record is
    // signed with a persistent key so the relay keeps one identity across
    // restarts (clients can pin or block it).
    let _announcer = if community {
        let identity = load_or_create_identity(&identity_path)
            .with_context(|| format!("relay identity at {}", identity_path.display()))?;
        tracing::info!(fingerprint = %identity.fingerprint(), "relay identity");
        match rotodesk_discovery::dht::DhtNode::start_server(port.wrapping_add(1)) {
            Ok(node) => Some(tokio::spawn(async move {
                node.ready().await;
                loop {
                    // Prefer the configured public IP; fall back to what the
                    // DHT peers see us as.
                    // The DHT-learned address is peer-supplied: only a
                    // globally routable one is worth signing and publishing.
                    let ip: Option<IpAddr> = if public_ip.is_loopback() || public_ip.is_unspecified() {
                        node.public_address()
                            .await
                            .map(|a| IpAddr::V4(*a.ip()))
                            .filter(|ip| rotodesk_relay_server::guard::is_peer_allowed(*ip, false))
                    } else {
                        Some(public_ip)
                    };
                    match ip {
                        Some(ip) => {
                            let addr = SocketAddr::new(ip, port);
                            match node.announce_relay(&identity, addr).await {
                                Ok(()) => tracing::info!(%addr, "relay announced on the DHT"),
                                Err(e) => tracing::warn!(%addr, error = %e, "relay announce failed"),
                            }
                        }
                        None => tracing::warn!(
                            "public address unknown ({ENV_PUBLIC_IP} unset and not learned from the DHT yet); \
                             not announcing"
                        ),
                    }
                    tokio::time::sleep(std::time::Duration::from_secs(15 * 60)).await;
                }
            })),
            Err(e) => {
                tracing::warn!(error = %e, "DHT unavailable; relay will not be discoverable");
                None
            }
        }
    } else {
        None
    };

    tokio::signal::ctrl_c()
        .await
        .context("waiting for Ctrl-C")?;
    tracing::info!("shutdown requested, closing TURN server");
    handle.shutdown().await.context("closing relay")?;
    Ok(())
}

/// Load the relay identity from `path`, or generate one and store it there.
/// The file holds a private key: keep it readable by the relay user only.
fn load_or_create_identity(path: &Path) -> Result<Identity> {
    if path.exists() {
        let pem = std::fs::read_to_string(path).context("reading identity")?;
        return Identity::from_pem(&pem).context("parsing identity PEM");
    }
    // Preserve the community relay's pinned identity across the product rename.
    let legacy = path.with_file_name(format!("{}-relay-identity.pem", rotodesk_proto::compat::LEGACY_BINARY));
    let identity = if path == Path::new(rotodesk_relay_server::DEFAULT_IDENTITY_PATH) && legacy.exists() {
        Identity::from_pem(&std::fs::read_to_string(&legacy).context("reading previous relay identity")?)
            .context("parsing previous relay identity")?
    } else {
        Identity::generate()
    };
    let pem = identity.to_pem().context("encoding identity")?;
    write_private(path, pem.as_bytes()).context("writing identity")?;
    tracing::info!(path = %path.display(), "generated a new relay identity");
    Ok(identity)
}

#[cfg(unix)]
fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(path)?;
    f.write_all(bytes)
}

/// Windows: create the file, then cut inheritance and leave only the current
/// user (plus SYSTEM and Administrators) on its ACL via `icacls`, so the key
/// is not readable by every account that can read the working directory.
#[cfg(not(unix))]
fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let mut f = std::fs::OpenOptions::new().write(true).create_new(true).open(path)?;
    f.write_all(bytes)?;
    drop(f);
    let user = std::env::var("USERNAME").unwrap_or_default();
    let mut cmd = std::process::Command::new("icacls");
    cmd.arg(path).arg("/inheritance:r").arg("/grant:r").arg("*S-1-5-18:F").arg("/grant:r").arg("*S-1-5-32-544:F");
    if !user.is_empty() {
        cmd.arg("/grant:r").arg(format!("{user}:F"));
    }
    match cmd.output() {
        Ok(out) if out.status.success() => Ok(()),
        Ok(out) => {
            tracing::warn!(status = %out.status, "could not restrict the identity file ACL; it inherits the directory's");
            Ok(())
        }
        Err(e) => {
            tracing::warn!(error = %e, "icacls unavailable; identity file inherits the directory ACL");
            Ok(())
        }
    }
}
