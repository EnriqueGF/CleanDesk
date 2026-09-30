//! Session-level value types shared by both peers.

use crate::{id::RotoDeskId, permissions::Permissions};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Descriptive information about a device, shown in connection requests and the
/// address book.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceInfo {
    pub id: RotoDeskId,
    /// Optional user alias, e.g. `pc-oficina.roto`.
    pub alias: Option<String>,
    /// OS-reported hostname.
    pub hostname: String,
    /// Human-readable OS string, e.g. "Windows 11 Pro".
    pub os: String,
    /// RotoDesk client version.
    pub app_version: String,
}

/// Reported online/offline/session state of a device (spec section 29).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeviceState {
    Online,
    Offline,
    InSession,
    Unavailable,
}

/// How a peer authenticates an incoming connection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuthMethod {
    /// A human on the host clicks Accept/Reject (interactive).
    Interactive,
    /// Unattended access using the configured password.
    UnattendedPassword,
    /// A previously issued session token (trusted device).
    Token,
}

/// Identifier for a live session.
pub type SessionId = Uuid;

/// A snapshot of live session statistics (spec section 26), pushed to the
/// viewer's toolbar periodically.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionStats {
    pub rtt_ms: u32,
    pub fps: u16,
    pub width: u32,
    pub height: u32,
    /// Estimated throughput in kilobits per second.
    pub bandwidth_kbps: u32,
    /// True when the media path is direct P2P; false when relayed.
    pub direct: bool,
    /// Codec identifier, e.g. "tile-zstd", "h264".
    pub codec: String,
}

/// The permissions a viewer asks for, and (later) what the host grants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PermissionRequest {
    pub requested: Permissions,
}

impl PermissionRequest {
    pub fn new(requested: Permissions) -> Self {
        Self { requested }
    }
}
