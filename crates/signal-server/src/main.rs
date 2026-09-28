//! CleanDesk Server binary — a thin wrapper around [`cleandesk_signal_server::run`].

use anyhow::{Context, Result};
use std::net::SocketAddr;

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

    cleandesk_signal_server::run(listener).await
}
