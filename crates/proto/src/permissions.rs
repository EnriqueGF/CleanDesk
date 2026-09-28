//! Per-session permissions, matching section 6 of the CleanDesk spec.
//!
//! Permissions are a bitset so they can be negotiated compactly and modified
//! mid-session (the spec requires live changes). The *host* is always the
//! authority: the viewer requests a set, the host grants a (possibly reduced)
//! set, and every subsequent action is checked against the granted set.

use bitflags::bitflags;
use serde::{Deserialize, Serialize};

bitflags! {
    /// The set of capabilities a viewer may exercise on a host during a session.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
    pub struct Permissions: u32 {
        /// See the remote screen (video stream). Baseline for any session.
        const VIEW_SCREEN        = 1 << 0;
        /// Send keyboard input.
        const CONTROL_KEYBOARD   = 1 << 1;
        /// Send mouse movement / clicks / scroll.
        const CONTROL_MOUSE      = 1 << 2;
        /// Share clipboard contents both ways.
        const CLIPBOARD          = 1 << 3;
        /// Transfer files between peers.
        const FILE_TRANSFER      = 1 << 4;
        /// Stream remote audio to the viewer.
        const AUDIO              = 1 << 5;
        /// Restart the remote machine.
        const RESTART_MACHINE    = 1 << 6;
        /// Restart the CleanDesk client on the remote machine.
        const RESTART_CLEANDESK  = 1 << 7;
        /// Run privileged / administrative actions (UAC elevation).
        const ADMIN_ACTIONS      = 1 << 8;
        /// Blank / lock the local keyboard and mouse on the host.
        const LOCK_LOCAL_INPUT   = 1 << 9;
    }
}

impl Permissions {
    /// A safe view-only default: screen only, no control.
    pub const VIEW_ONLY: Permissions = Permissions::VIEW_SCREEN;

    /// The typical interactive support set: view + full input + clipboard.
    pub fn interactive() -> Permissions {
        Permissions::VIEW_SCREEN
            | Permissions::CONTROL_KEYBOARD
            | Permissions::CONTROL_MOUSE
            | Permissions::CLIPBOARD
    }

    /// Everything — used only for fully trusted / unattended devices.
    pub fn full() -> Permissions {
        Permissions::all()
    }

    /// True if `self` grants every permission in `required`.
    pub fn allows(self, required: Permissions) -> bool {
        self.contains(required)
    }
}

impl Default for Permissions {
    fn default() -> Self {
        Permissions::interactive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn view_only_denies_control() {
        assert!(!Permissions::VIEW_ONLY.allows(Permissions::CONTROL_KEYBOARD));
        assert!(Permissions::VIEW_ONLY.allows(Permissions::VIEW_SCREEN));
    }

    #[test]
    fn full_allows_everything() {
        assert!(Permissions::full().allows(Permissions::ADMIN_ACTIONS));
    }
}
