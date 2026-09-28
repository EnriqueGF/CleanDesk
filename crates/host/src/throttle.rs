//! Per-caller lockout for unattended authentication (spec §18, "protección
//! anti fuerza bruta").
//!
//! Every failed challenge/response from a CleanDesk ID counts against it. From
//! [`AuthThrottle::FREE_ATTEMPTS`] failures on, the caller is locked out for a
//! window that doubles with each further failure, capped at
//! [`AuthThrottle::MAX_LOCKOUT`]. A success clears the record. Pure logic with
//! an injected clock so it is fully unit-tested.

use cleandesk_proto::CleanDeskId;
use std::collections::HashMap;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy)]
struct Record {
    failures: u32,
    locked_until: Option<Instant>,
}

/// Failure counters and lockouts keyed by caller ID.
#[derive(Debug, Default)]
pub struct AuthThrottle {
    records: HashMap<CleanDeskId, Record>,
}

impl AuthThrottle {
    /// Failures tolerated before the first lockout.
    pub const FREE_ATTEMPTS: u32 = 3;
    /// Lockout after the first over-limit failure; doubles afterwards.
    pub const BASE_LOCKOUT: Duration = Duration::from_secs(30);
    /// Ceiling for the doubling lockout.
    pub const MAX_LOCKOUT: Duration = Duration::from_secs(15 * 60);

    /// If `id` is currently locked out, how much longer it must wait.
    pub fn locked_for(&self, id: CleanDeskId, now: Instant) -> Option<Duration> {
        let until = self.records.get(&id)?.locked_until?;
        if until > now {
            Some(until - now)
        } else {
            None
        }
    }

    /// Record a failed authentication attempt.
    pub fn record_failure(&mut self, id: CleanDeskId, now: Instant) {
        let rec = self.records.entry(id).or_insert(Record { failures: 0, locked_until: None });
        rec.failures += 1;
        if rec.failures >= Self::FREE_ATTEMPTS {
            let over = rec.failures - Self::FREE_ATTEMPTS;
            let factor = 1u32.checked_shl(over.min(31)).unwrap_or(u32::MAX);
            let lockout = Self::BASE_LOCKOUT
                .checked_mul(factor)
                .unwrap_or(Self::MAX_LOCKOUT)
                .min(Self::MAX_LOCKOUT);
            rec.locked_until = Some(now + lockout);
        }
    }

    /// Record a successful authentication, clearing the caller's history.
    pub fn record_success(&mut self, id: CleanDeskId) {
        self.records.remove(&id);
    }

    /// Drop records whose lockout expired long ago, so the map cannot grow
    /// without bound under a distributed guessing attack.
    pub fn prune(&mut self, now: Instant) {
        self.records.retain(|_, r| match r.locked_until {
            Some(until) => until + Self::MAX_LOCKOUT > now,
            None => true,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id() -> CleanDeskId {
        CleanDeskId::new(548_291_743).unwrap()
    }

    #[test]
    fn first_failures_are_free_then_lockout_doubles_and_caps() {
        let mut t = AuthThrottle::default();
        let t0 = Instant::now();
        t.record_failure(id(), t0);
        t.record_failure(id(), t0);
        assert!(t.locked_for(id(), t0).is_none());

        t.record_failure(id(), t0); // 3rd -> 30 s
        assert_eq!(t.locked_for(id(), t0), Some(Duration::from_secs(30)));
        assert!(t.locked_for(id(), t0 + Duration::from_secs(30)).is_none());

        t.record_failure(id(), t0); // 4th -> 60 s
        assert_eq!(t.locked_for(id(), t0), Some(Duration::from_secs(60)));
        t.record_failure(id(), t0); // 5th -> 120 s
        assert_eq!(t.locked_for(id(), t0), Some(Duration::from_secs(120)));

        for _ in 0..40 {
            t.record_failure(id(), t0);
        }
        assert_eq!(t.locked_for(id(), t0), Some(AuthThrottle::MAX_LOCKOUT));
    }

    #[test]
    fn success_clears_history_and_other_ids_are_independent() {
        let mut t = AuthThrottle::default();
        let t0 = Instant::now();
        let other = CleanDeskId::new(111_111_111).unwrap();
        for _ in 0..5 {
            t.record_failure(id(), t0);
        }
        assert!(t.locked_for(id(), t0).is_some());
        assert!(t.locked_for(other, t0).is_none());
        t.record_success(id());
        assert!(t.locked_for(id(), t0).is_none());
        t.record_failure(id(), t0);
        assert!(t.locked_for(id(), t0).is_none(), "counter restarted from zero");
    }

    #[test]
    fn prune_forgets_stale_records() {
        let mut t = AuthThrottle::default();
        let t0 = Instant::now();
        for _ in 0..3 {
            t.record_failure(id(), t0);
        }
        t.prune(t0);
        assert_eq!(t.records.len(), 1);
        t.prune(t0 + Duration::from_secs(30) + AuthThrottle::MAX_LOCKOUT + Duration::from_secs(1));
        assert!(t.records.is_empty());
    }
}
