//! Protocol-level error type.

use thiserror::Error;

/// Errors produced while encoding, decoding or validating protocol data.
#[derive(Debug, Error)]
pub enum ProtoError {
    #[error("serialization failed: {0}")]
    Encode(String),

    #[error("deserialization failed: {0}")]
    Decode(String),

    #[error("frame exceeds maximum size: {size} > {max}")]
    FrameTooLarge { size: usize, max: usize },

    #[error("incomplete frame: need {needed} more bytes")]
    Incomplete { needed: usize },

    #[error("invalid CleanDesk ID: {0}")]
    InvalidId(String),

    #[error("incompatible protocol version: local {local}, remote {remote}")]
    IncompatibleVersion { local: crate::Version, remote: crate::Version },
}
