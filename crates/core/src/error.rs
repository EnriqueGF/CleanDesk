//! Crate-wide error type.

use thiserror::Error;

/// Errors produced by `cleandesk-core`: storage I/O, (de)serialization, and
/// illegal session state usage. Network/protocol errors belong to their own
/// crates and are wrapped here only when this crate's own operations can
/// produce them (e.g. loading an identity file written in a corrupt format).
#[derive(Debug, Error)]
pub enum CoreError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("json (de)serialization failed: {0}")]
    Json(#[from] serde_json::Error),

    #[error("crypto error: {0}")]
    Crypto(#[from] cleandesk_crypto::CryptoError),

    #[error("could not determine the application data directory for this platform")]
    NoDataDir,

    #[error("illegal session state transition: {from} -> {attempted}")]
    IllegalTransition {
        from: &'static str,
        attempted: &'static str,
    },

    #[error("cannot activate a session before permissions have been granted")]
    MissingGrantedPermissions,

    #[error("{0}")]
    Other(String),
}

/// This crate's `Result` alias. Exported from the crate root as
/// `cleandesk_core::Result`.
pub type Result<T> = std::result::Result<T, CoreError>;
