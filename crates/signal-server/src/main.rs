//! CleanDesk Server binary — a thin wrapper around [`cleandesk_signal_server::run`].

use anyhow::{Context, Result};
use cleandesk_signal_server::state::{OwnerRegistry, ServerState};
use std::{net::SocketAddr, path::PathBuf, sync::Arc};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let port: u16 = std::env::var("CLEANDESK_SIGNAL_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(cleandesk_proto::DEFAULT_SIGNAL_PORT);
    let addr = SocketAddr::from(([0, 0, 0, 0], port));

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .with_context(|| format!("binding {addr}"))?;
    cleandesk_signal_server::log_banner(addr);

    // ID ownership survives restarts so an offline device keeps its ID
    // (`CLEANDESK_SIGNAL_STATE_DIR`, default `./data`).
    let state_dir = std::env::var_os("CLEANDESK_SIGNAL_STATE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("data"));
    std::fs::create_dir_all(&state_dir).with_context(|| format!("creating {}", state_dir.display()))?;
    let owners = OwnerRegistry::load(state_dir.join("owners.json"));
    let state = Arc::new(ServerState::with_owners(owners));

    cleandesk_signal_server::run_with_state(listener, state).await
}
