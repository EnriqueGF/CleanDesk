//! CleanDesk Relay binary — a thin wrapper around [`cleandesk_relay_server::run`].
//!
//! Configuration comes from `CLEANDESK_RELAY_*` environment variables (see the
//! library docs). Runs until Ctrl-C, then closes the TURN server so live
//! allocations are released.

use anyhow::{Context, Result};
use cleandesk_relay_server::{
    RelayConfig, ENV_BIND, ENV_COMMUNITY, ENV_MAX_PORT, ENV_MIN_PORT, ENV_PORT, ENV_PUBLIC_IP,
    ENV_REALM, ENV_USERS,
};

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
            cleandesk_proto::DEFAULT_RELAY_PORT,
            cleandesk_relay_server::DEFAULT_REALM,
        )
    })?;
    // Usernames only: passwords are never logged.
    tracing::info!(
        version = %cleandesk_proto::PROTOCOL_VERSION,
        bind = %config.bind,
        port = config.port,
        public_ip = %config.public_ip,
        realm = %config.realm,
        users = ?config.users.iter().map(|u| u.username.as_str()).collect::<Vec<_>>(),
        port_range = ?config.port_range,
        community = config.community,
        "CleanDesk Relay configuration"
    );

    let community = config.community;
    let port = config.port;
    let handle = cleandesk_relay_server::run(config)
        .await
        .context("starting relay")?;

    // Community relays announce themselves on the BitTorrent DHT so clients
    // that have never heard of this machine can still find it.
    let _announcer = if community {
        match cleandesk_discovery::dht::DhtNode::start_server(port.wrapping_add(1)) {
            Ok(node) => Some(tokio::spawn(async move {
                node.ready().await;
                if let Some(addr) = node.public_address().await {
                    tracing::info!(public = %addr.ip(), "public address learned from the DHT");
                }
                loop {
                    match node.announce_relay(port).await {
                        Ok(()) => tracing::info!(port, "relay announced on the DHT"),
                        Err(e) => tracing::warn!(error = %e, "relay announce failed"),
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
