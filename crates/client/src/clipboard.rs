//! Text clipboard synchronisation (spec section 14).
//!
//! One dedicated OS thread owns the clipboard handle: it polls the local
//! clipboard every [`POLL_INTERVAL`] and reports changes, and it applies
//! text the peer sent. Doing both on the same thread makes echo suppression
//! trivial — the thread remembers the last value it saw or set, so applying
//! remote text never bounces it straight back to the peer.
//!
//! The same module exists in the host crate: the roles are symmetric and
//! there is no shared crate below both that may depend on the clipboard.

use std::sync::mpsc as std_mpsc;
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::{debug, warn};

/// How often the local clipboard is checked for changes.
pub const POLL_INTERVAL: Duration = Duration::from_millis(500);

/// Largest text (bytes) we send or accept; bigger contents are ignored.
pub const MAX_TEXT_LEN: usize = 1024 * 1024;

/// Handle to the sync thread. Dropping it stops the thread.
pub(crate) struct ClipboardSync {
    to_thread: std_mpsc::Sender<String>,
}

impl ClipboardSync {
    /// Start polling. Local changes are delivered on `on_change`; the thread
    /// ends when `on_change`'s receiver or this handle is dropped.
    pub(crate) fn start(on_change: mpsc::UnboundedSender<String>) -> Self {
        let (to_thread, from_session) = std_mpsc::channel::<String>();
        let spawned = std::thread::Builder::new()
            .name("cleandesk-clipboard".into())
            .spawn(move || sync_loop(from_session, on_change));
        if let Err(e) = spawned {
            warn!(error = %e, "failed to spawn clipboard thread");
        }
        Self { to_thread }
    }

    /// Put text the peer sent onto the local clipboard.
    pub(crate) fn apply_remote(&self, text: String) {
        if text.len() > MAX_TEXT_LEN {
            debug!(len = text.len(), "ignoring oversized remote clipboard");
            return;
        }
        let _ = self.to_thread.send(text);
    }
}

fn sync_loop(from_session: std_mpsc::Receiver<String>, on_change: mpsc::UnboundedSender<String>) {
    let mut clipboard = match arboard::Clipboard::new() {
        Ok(c) => c,
        Err(e) => {
            warn!(error = %e, "clipboard unavailable; sync disabled");
            return;
        }
    };
    // Seed with the current contents so the session start does not push
    // whatever happened to be on the clipboard.
    let mut last: Option<String> = clipboard.get_text().ok();
    loop {
        match from_session.recv_timeout(POLL_INTERVAL) {
            Ok(text) => {
                if let Err(e) = clipboard.set_text(text.clone()) {
                    debug!(error = %e, "setting clipboard failed");
                }
                last = Some(text);
            }
            Err(std_mpsc::RecvTimeoutError::Timeout) => {
                // A non-text clipboard (image, files) reads as an error; that
                // is not a change we sync.
                let Ok(text) = clipboard.get_text() else { continue };
                if text.len() > MAX_TEXT_LEN || last.as_deref() == Some(text.as_str()) {
                    continue;
                }
                last = Some(text.clone());
                if on_change.send(text).is_err() {
                    break;
                }
            }
            Err(std_mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
    debug!("clipboard sync stopped");
}
