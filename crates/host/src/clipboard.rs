//! Text clipboard sync with echo suppression and transient-error retries.
use std::sync::mpsc as std_mpsc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, warn};

pub const POLL_INTERVAL: Duration = Duration::from_millis(100);
pub const MAX_TEXT_LEN: usize = 1024 * 1024;
const WRITE_TIMEOUT: Duration = Duration::from_secs(2);

struct Update {
    text: String,
    applied: Option<oneshot::Sender<bool>>,
    deadline: Instant,
}

pub(crate) struct ClipboardSync {
    to_thread: std_mpsc::Sender<Update>,
}

impl ClipboardSync {
    pub(crate) fn start(on_change: mpsc::UnboundedSender<String>) -> Self {
        let (to_thread, from_session) = std_mpsc::channel();
        if let Err(e) = std::thread::Builder::new()
            .name("cleandesk-clipboard".into())
            .spawn(move || sync_loop(from_session, on_change))
        {
            warn!(error = %e, "failed to spawn clipboard thread");
        }
        Self { to_thread }
    }

    pub(crate) fn apply_remote(&self, text: String) {
        if text.len() <= MAX_TEXT_LEN {
            let _ = self.to_thread.send(Update {
                text,
                applied: None,
                deadline: Instant::now() + WRITE_TIMEOUT,
            });
        }
    }

    /// Acknowledge only a successful OS write; never paste stale text.
    pub(crate) async fn apply_remote_confirmed(&self, text: String) -> bool {
        if text.len() > MAX_TEXT_LEN {
            return false;
        }
        let (tx, rx) = oneshot::channel();
        if self
            .to_thread
            .send(Update {
                text,
                applied: Some(tx),
                deadline: Instant::now() + WRITE_TIMEOUT,
            })
            .is_err()
        {
            return false;
        }
        rx.await.unwrap_or(false)
    }
}

fn apply_pending(
    pending: &mut Option<Update>,
    last: &mut Option<String>,
    set_text: impl FnOnce(&str) -> Result<(), arboard::Error>,
) {
    let Some(update) = pending.as_ref() else {
        return;
    };
    if Instant::now() >= update.deadline {
        if let Some(tx) = pending.take().and_then(|update| update.applied) {
            let _ = tx.send(false);
        }
        return;
    }
    if let Err(e) = set_text(&update.text) {
        debug!(error = %e, "setting clipboard failed; will retry");
        return;
    }
    let update = pending.take().unwrap();
    *last = Some(update.text);
    if let Some(tx) = update.applied {
        let _ = tx.send(true);
    }
}

fn sync_loop(from_session: std_mpsc::Receiver<Update>, on_change: mpsc::UnboundedSender<String>) {
    let mut clipboard = None;
    let mut last = None;
    let mut pending = None;
    loop {
        match from_session.recv_timeout(POLL_INTERVAL) {
            Ok(update) => pending = Some(update),
            Err(std_mpsc::RecvTimeoutError::Timeout) => {}
            Err(std_mpsc::RecvTimeoutError::Disconnected) => break,
        }
        if on_change.is_closed() {
            break;
        }
        if clipboard.is_none() {
            match arboard::Clipboard::new() {
                Ok(mut c) => {
                    // Do not overwrite the peer's clipboard on session start.
                    last = c.get_text().ok();
                    clipboard = Some(c);
                }
                Err(e) => {
                    debug!(error = %e, "clipboard unavailable; will retry");
                    apply_pending(&mut pending, &mut last, |_| {
                        Err(arboard::Error::ClipboardOccupied)
                    });
                    continue;
                }
            }
        }
        let c = clipboard.as_mut().unwrap();
        if pending.is_some() {
            apply_pending(&mut pending, &mut last, |text| c.set_text(text.to_owned()));
            // Never echo old local contents while applying remote text.
            continue;
        }
        match c.get_text() {
            Ok(text) if text.len() <= MAX_TEXT_LEN && last.as_deref() != Some(text.as_str()) => {
                last = Some(text.clone());
                if on_change.send(text).is_err() {
                    break;
                }
            }
            // Copying the same text after an image/file must still be detected.
            Err(arboard::Error::ContentNotAvailable) => last = None,
            _ => {}
        }
    }
    debug!("clipboard sync stopped");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn occupied_clipboard_retries_without_echo_or_early_ack() {
        let (tx, mut rx) = oneshot::channel();
        let mut pending = Some(Update {
            text: "nuevo ñ 日本語".into(),
            applied: Some(tx),
            deadline: Instant::now() + WRITE_TIMEOUT,
        });
        let mut last = Some("anterior".into());
        apply_pending(&mut pending, &mut last, |_| {
            Err(arboard::Error::ClipboardOccupied)
        });
        assert!(pending.is_some());
        assert_eq!(last.as_deref(), Some("anterior"));
        assert!(matches!(
            rx.try_recv(),
            Err(oneshot::error::TryRecvError::Empty)
        ));
        apply_pending(&mut pending, &mut last, |text| {
            assert_eq!(text, "nuevo ñ 日本語");
            Ok(())
        });
        assert!(pending.is_none());
        assert_eq!(last.as_deref(), Some("nuevo ñ 日本語"));
        assert_eq!(rx.try_recv(), Ok(true));
    }

    #[test]
    fn expired_write_does_not_paste_or_suppress_local_text() {
        let (tx, mut rx) = oneshot::channel();
        let mut pending = Some(Update {
            text: "nuevo".into(),
            applied: Some(tx),
            deadline: Instant::now(),
        });
        let mut last = Some("anterior".into());
        apply_pending(&mut pending, &mut last, |_| {
            panic!("expired write must not run")
        });
        assert!(pending.is_none());
        assert_eq!(last.as_deref(), Some("anterior"));
        assert_eq!(rx.try_recv(), Ok(false));
    }
}
