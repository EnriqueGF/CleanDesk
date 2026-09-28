//! Connection history (spec §12).

use cleandesk_proto::{session::SessionId, CleanDeskId};
use serde::{Deserialize, Serialize};

use crate::unix_now;

/// Upper bound on [`History::records`]. The log is a user-facing "recent
/// connections" list, not an audit trail, so it is capped rather than left
/// to grow `appdata.json` (rewritten on every save) without limit. Oldest
/// records by `started_at` are dropped first.
pub const MAX_RECORDS: usize = 500;

/// One logged connection, past or in progress.
///
/// `id`, `device`, `user` and `started_at` are required; the end-of-session
/// fields and the free-form labels are `#[serde(default)]` so a record from
/// an older `appdata.json` still loads.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionRecord {
    pub id: SessionId,
    pub device: CleanDeskId,
    pub user: String,
    /// Unix seconds.
    pub started_at: u64,
    /// Unix seconds; `None` while the session is still open.
    #[serde(default)]
    pub ended_at: Option<u64>,
    #[serde(default)]
    pub duration_secs: Option<u64>,
    /// Free-form label, e.g. `"p2p"` / `"relay"`.
    #[serde(default)]
    pub connection_kind: String,
    /// Free-form label mirroring `session::SessionState::label()`, e.g.
    /// `"active"`, `"closed"`, `"rejected"`, `"failed"`.
    #[serde(default)]
    pub state: String,
}

impl SessionRecord {
    /// Start a new open-ended record: `started_at` is "now", `ended_at` /
    /// `duration_secs` are filled in later by [`Self::finish`].
    pub fn start(
        id: SessionId,
        device: CleanDeskId,
        user: impl Into<String>,
        connection_kind: impl Into<String>,
    ) -> Self {
        Self {
            id,
            device,
            user: user.into(),
            started_at: unix_now(),
            ended_at: None,
            duration_secs: None,
            connection_kind: connection_kind.into(),
            state: "active".to_string(),
        }
    }

    /// Close out the record: stamps `ended_at` = now, derives
    /// `duration_secs` from `started_at`, and records the final `state`
    /// (e.g. `"closed"`, `"rejected"`, `"failed"`).
    pub fn finish(&mut self, state: impl Into<String>) {
        let ended = unix_now();
        self.ended_at = Some(ended);
        self.duration_secs = Some(ended.saturating_sub(self.started_at));
        self.state = state.into();
    }

    /// True while [`Self::finish`] has not been called.
    pub fn is_open(&self) -> bool {
        self.ended_at.is_none()
    }
}

/// The full connection log.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct History {
    pub records: Vec<SessionRecord>,
}

impl History {
    /// Append a record, then drop the oldest (by `started_at`) if the log
    /// now exceeds [`MAX_RECORDS`].
    pub fn push(&mut self, record: SessionRecord) {
        self.records.push(record);
        self.trim();
    }

    /// Enforce [`MAX_RECORDS`], keeping the newest records. Also applied on
    /// `push`, but exposed so a log loaded from disk (possibly written by a
    /// build with no cap) can be brought within bounds.
    pub fn trim(&mut self) {
        if self.records.len() <= MAX_RECORDS {
            return;
        }
        // Stable sort so records sharing a `started_at` keep insertion
        // order; then everything past the cap is the oldest.
        self.records
            .sort_by_key(|r| std::cmp::Reverse(r.started_at));
        self.records.truncate(MAX_RECORDS);
    }

    /// The still-open record for session `id`, if any. Finished records are
    /// ignored so a stale/duplicate session id never resurrects an old row.
    pub fn open_record_mut(&mut self, id: SessionId) -> Option<&mut SessionRecord> {
        self.records
            .iter_mut()
            .find(|r| r.id == id && r.is_open())
    }

    /// Finish the open record for `id` with `state` (see
    /// [`SessionRecord::finish`]). Returns `false` if there is no open
    /// record for that session — e.g. it was already finished, or never
    /// recorded.
    pub fn finish(&mut self, id: SessionId, state: impl Into<String>) -> bool {
        match self.open_record_mut(id) {
            Some(record) => {
                record.finish(state);
                true
            }
            None => false,
        }
    }

    /// The `n` most recent records, newest (`started_at`) first.
    pub fn recent(&self, n: usize) -> Vec<&SessionRecord> {
        let mut sorted: Vec<&SessionRecord> = self.records.iter().collect();
        sorted.sort_by_key(|r| std::cmp::Reverse(r.started_at));
        sorted.truncate(n);
        sorted
    }

    /// All records for a given device, newest first.
    pub fn for_device(&self, device: CleanDeskId) -> Vec<&SessionRecord> {
        let mut matching: Vec<&SessionRecord> =
            self.records.iter().filter(|r| r.device == device).collect();
        matching.sort_by_key(|r| std::cmp::Reverse(r.started_at));
        matching
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn dev() -> CleanDeskId {
        CleanDeskId::new(548_291_743).unwrap()
    }

    fn record_at(started_at: u64) -> SessionRecord {
        let mut r = SessionRecord::start(Uuid::new_v4(), dev(), "alice", "p2p");
        r.started_at = started_at;
        r
    }

    #[test]
    fn push_and_recent_orders_newest_first() {
        let mut h = History::default();
        h.push(record_at(100));
        h.push(record_at(200));

        let recent = h.recent(1);
        assert_eq!(recent.len(), 1);
        assert_eq!(recent[0].started_at, 200);

        let all = h.recent(10);
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].started_at, 200);
        assert_eq!(all[1].started_at, 100);
    }

    #[test]
    fn for_device_filters_by_device() {
        let mut h = History::default();
        let other = CleanDeskId::new(111_111_111).unwrap();
        h.push(SessionRecord::start(Uuid::new_v4(), dev(), "alice", "p2p"));
        h.push(SessionRecord::start(Uuid::new_v4(), other, "bob", "relay"));

        assert_eq!(h.for_device(dev()).len(), 1);
        assert_eq!(h.for_device(other).len(), 1);
        assert_eq!(h.for_device(dev())[0].user, "alice");
    }

    #[test]
    fn finish_sets_end_state_and_duration() {
        let mut r = SessionRecord::start(Uuid::new_v4(), dev(), "alice", "p2p");
        r.started_at = unix_now().saturating_sub(5);
        assert!(r.is_open());
        r.finish("closed");
        assert_eq!(r.state, "closed");
        assert!(!r.is_open());
        assert!(r.ended_at.is_some());
        assert!(r.duration_secs.unwrap() >= 5);
    }

    #[test]
    fn push_trims_oldest_beyond_max_records() {
        let mut h = History::default();
        // Insert out of order so trimming is by started_at, not position.
        for i in (0..MAX_RECORDS as u64 + 10).rev() {
            h.push(record_at(i));
        }
        assert_eq!(h.records.len(), MAX_RECORDS);
        let oldest_kept = h.records.iter().map(|r| r.started_at).min().unwrap();
        assert_eq!(oldest_kept, 10, "the ten oldest records must be dropped");
        assert!(h.records.iter().all(|r| r.started_at >= 10));
    }

    #[test]
    fn trim_bounds_a_log_loaded_over_the_cap() {
        // Bypass push() to simulate an uncapped file from an older build.
        let mut h = History {
            records: (0..MAX_RECORDS as u64 * 2).map(record_at).collect(),
        };
        h.trim();
        assert_eq!(h.records.len(), MAX_RECORDS);
        assert_eq!(h.recent(1)[0].started_at, MAX_RECORDS as u64 * 2 - 1);
    }

    #[test]
    fn finish_by_id_closes_only_the_open_record() {
        let mut h = History::default();
        let id = Uuid::new_v4();
        h.push(SessionRecord::start(id, dev(), "alice", "p2p"));

        assert!(h.open_record_mut(id).is_some());
        assert!(h.finish(id, "closed"));
        assert_eq!(h.records[0].state, "closed");
        assert!(h.records[0].ended_at.is_some());

        // Already finished: not open any more, so a second finish is a no-op.
        assert!(h.open_record_mut(id).is_none());
        assert!(!h.finish(id, "failed"));
        assert_eq!(h.records[0].state, "closed");

        // Unknown id.
        assert!(!h.finish(Uuid::new_v4(), "closed"));
    }
}
