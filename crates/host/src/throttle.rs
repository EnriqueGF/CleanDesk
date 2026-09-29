//! Lockouts for unattended authentication (spec §18, "protección anti
//! fuerza bruta"), on two levels:
//!
//! * **Per caller.** Every failed challenge/response counts against the
//!   caller's *verified* Ed25519 public key (the one bound to the DTLS
//!   session by `IdentityProof`, never a self-declared id). From
//!   [`AuthThrottle::FREE_ATTEMPTS`] failures on, the caller is locked out
//!   for a window that doubles with each further failure, capped at
//!   [`AuthThrottle::MAX_LOCKOUT`]. A success clears the record.
//! * **Global.** A fresh key is free to mint, so per-caller counters alone
//!   let an attacker rotate identities and keep guessing. Once
//!   [`AuthThrottle::GLOBAL_FREE_ATTEMPTS`] failures from *any* callers
//!   land within [`AuthThrottle::GLOBAL_WINDOW`], unattended access is
//!   closed for everyone for [`AuthThrottle::GLOBAL_BASE_LOCKOUT`], doubling
//!   on every further trip up to [`AuthThrottle::GLOBAL_MAX_LOCKOUT`]. The
//!   owner can still connect interactively.
//!
//! Pure logic with an injected clock so it is fully unit-tested.

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};
use tracing::warn;

#[derive(Debug, Clone, Copy)]
struct Record {
    failures: u32,
    locked_until: Option<Instant>,
}

/// Failure counters and lockouts keyed by the caller's public key, plus the
/// global circuit breaker.
#[derive(Debug, Default)]
pub struct AuthThrottle {
    records: HashMap<String, Record>,
    /// Timestamps of recent failures from every caller, oldest first, trimmed
    /// to [`Self::GLOBAL_WINDOW`].
    global_failures: VecDeque<Instant>,
    global_locked_until: Option<Instant>,
    /// How many times the global breaker tripped without a quiet period.
    global_trips: u32,
}

impl AuthThrottle {
    /// Failures tolerated per caller before the first lockout.
    pub const FREE_ATTEMPTS: u32 = 3;
    /// Per-caller lockout after the first over-limit failure; doubles afterwards.
    pub const BASE_LOCKOUT: Duration = Duration::from_secs(30);
    /// Ceiling for the doubling per-caller lockout.
    pub const MAX_LOCKOUT: Duration = Duration::from_secs(15 * 60);

    /// Failures from any callers, within [`Self::GLOBAL_WINDOW`], that trip
    /// the global lockout.
    pub const GLOBAL_FREE_ATTEMPTS: usize = 10;
    /// Sliding window over which global failures are counted.
    pub const GLOBAL_WINDOW: Duration = Duration::from_secs(10 * 60);
    /// First global lockout; doubles on each further trip.
    pub const GLOBAL_BASE_LOCKOUT: Duration = Duration::from_secs(5 * 60);
    /// Ceiling for the doubling global lockout.
    pub const GLOBAL_MAX_LOCKOUT: Duration = Duration::from_secs(60 * 60);

    /// If `caller` may not attempt unattended auth right now (own lockout or
    /// the global one), how much longer it must wait.
    pub fn locked_for(&self, caller: &str, now: Instant) -> Option<Duration> {
        let own = self
            .records
            .get(caller)
            .and_then(|r| r.locked_until)
            .and_then(|until| until.checked_duration_since(now))
            .filter(|d| !d.is_zero());
        match (own, self.global_locked_for(now)) {
            (Some(a), Some(b)) => Some(a.max(b)),
            (a, b) => a.or(b),
        }
    }

    /// If the global breaker is tripped, how much longer everyone waits.
    pub fn global_locked_for(&self, now: Instant) -> Option<Duration> {
        self.global_locked_until
            .and_then(|until| until.checked_duration_since(now))
            .filter(|d| !d.is_zero())
    }

    /// Record a failed authentication attempt by `caller`.
    pub fn record_failure(&mut self, caller: &str, now: Instant) {
        let rec = self
            .records
            .entry(caller.to_string())
            .or_insert(Record { failures: 0, locked_until: None });
        rec.failures += 1;
        if rec.failures >= Self::FREE_ATTEMPTS {
            let over = rec.failures - Self::FREE_ATTEMPTS;
            rec.locked_until = Some(now + doubling(Self::BASE_LOCKOUT, over, Self::MAX_LOCKOUT));
        }

        self.global_failures.push_back(now);
        self.trim_global(now);
        if self.global_failures.len() >= Self::GLOBAL_FREE_ATTEMPTS {
            let lockout = doubling(Self::GLOBAL_BASE_LOCKOUT, self.global_trips, Self::GLOBAL_MAX_LOCKOUT);
            self.global_trips = self.global_trips.saturating_add(1);
            self.global_locked_until = Some(now + lockout);
            self.global_failures.clear();
            warn!(
                ?lockout,
                trips = self.global_trips,
                "too many failed unattended attempts from all callers; unattended access locked for everyone"
            );
        }
    }

    /// Record a successful authentication, clearing the caller's history.
    /// The global counters are untouched: an attacker who also knows a valid
    /// password must not be able to reset the breaker.
    pub fn record_success(&mut self, caller: &str) {
        self.records.remove(caller);
    }

    /// Drop records whose lockout expired long ago, so the map cannot grow
    /// without bound under a distributed guessing attack; and forget the
    /// global trip count after a quiet [`Self::GLOBAL_WINDOW`].
    pub fn prune(&mut self, now: Instant) {
        self.records.retain(|_, r| match r.locked_until {
            Some(until) => until + Self::MAX_LOCKOUT > now,
            None => true,
        });
        self.trim_global(now);
        if let Some(until) = self.global_locked_until {
            if until + Self::GLOBAL_WINDOW <= now {
                self.global_locked_until = None;
                self.global_trips = 0;
            }
        }
    }

    fn trim_global(&mut self, now: Instant) {
        while let Some(t) = self.global_failures.front() {
            if now.saturating_duration_since(*t) > Self::GLOBAL_WINDOW {
                self.global_failures.pop_front();
            } else {
                break;
            }
        }
    }
}

/// `base × 2^n`, saturating at `max`.
fn doubling(base: Duration, n: u32, max: Duration) -> Duration {
    let factor = 1u32.checked_shl(n.min(31)).unwrap_or(u32::MAX);
    base.checked_mul(factor).unwrap_or(max).min(max)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: &str = "viewer-key-A";
    const OTHER: &str = "viewer-key-B";

    #[test]
    fn first_failures_are_free_then_lockout_doubles_and_caps() {
        let mut t = AuthThrottle::default();
        let t0 = Instant::now();
        t.record_failure(ID, t0);
        t.record_failure(ID, t0);
        assert!(t.locked_for(ID, t0).is_none());

        t.record_failure(ID, t0); // 3rd -> 30 s
        assert_eq!(t.locked_for(ID, t0), Some(Duration::from_secs(30)));
        assert!(t.locked_for(ID, t0 + Duration::from_secs(30)).is_none());

        t.record_failure(ID, t0); // 4th -> 60 s
        assert_eq!(t.locked_for(ID, t0), Some(Duration::from_secs(60)));
        t.record_failure(ID, t0); // 5th -> 120 s
        assert_eq!(t.locked_for(ID, t0), Some(Duration::from_secs(120)));

        for _ in 0..40 {
            t.record_failure(ID, t0);
        }
        // The global breaker tripped long ago by now; look at the own record.
        assert_eq!(t.records[ID].locked_until, Some(t0 + AuthThrottle::MAX_LOCKOUT));
    }

    #[test]
    fn success_clears_history_and_other_callers_are_independent() {
        let mut t = AuthThrottle::default();
        let t0 = Instant::now();
        for _ in 0..5 {
            t.record_failure(ID, t0);
        }
        assert!(t.locked_for(ID, t0).is_some());
        assert!(t.locked_for(OTHER, t0).is_none());
        t.record_success(ID);
        assert!(t.locked_for(ID, t0).is_none());
        t.record_failure(ID, t0);
        assert!(t.locked_for(ID, t0).is_none(), "counter restarted from zero");
    }

    #[test]
    fn prune_forgets_stale_records() {
        let mut t = AuthThrottle::default();
        let t0 = Instant::now();
        for _ in 0..3 {
            t.record_failure(ID, t0);
        }
        t.prune(t0);
        assert_eq!(t.records.len(), 1);
        t.prune(t0 + Duration::from_secs(30) + AuthThrottle::MAX_LOCKOUT + Duration::from_secs(1));
        assert!(t.records.is_empty());
    }

    #[test]
    fn rotating_keys_trips_the_global_lockout_which_doubles() {
        let mut t = AuthThrottle::default();
        let t0 = Instant::now();
        // Nine fresh identities, one failure each: nobody is locked yet.
        for i in 0..AuthThrottle::GLOBAL_FREE_ATTEMPTS - 1 {
            t.record_failure(&format!("key-{i}"), t0);
        }
        assert!(t.global_locked_for(t0).is_none());
        assert!(t.locked_for("brand-new-key", t0).is_none());
        // The tenth trips the breaker for everyone, including a key never seen.
        t.record_failure("key-9", t0);
        assert_eq!(t.global_locked_for(t0), Some(AuthThrottle::GLOBAL_BASE_LOCKOUT));
        assert_eq!(t.locked_for("brand-new-key", t0), Some(AuthThrottle::GLOBAL_BASE_LOCKOUT));
        // A success does not lift it.
        t.record_success("key-9");
        assert!(t.global_locked_for(t0).is_some());
        // It expires...
        let t1 = t0 + AuthThrottle::GLOBAL_BASE_LOCKOUT;
        assert!(t.global_locked_for(t1).is_none());
        // ...and the next burst locks twice as long.
        for i in 0..AuthThrottle::GLOBAL_FREE_ATTEMPTS {
            t.record_failure(&format!("again-{i}"), t1);
        }
        assert_eq!(t.global_locked_for(t1), Some(2 * AuthThrottle::GLOBAL_BASE_LOCKOUT));
        // Many more trips saturate at the ceiling.
        let mut now = t1;
        for round in 0..12 {
            now += AuthThrottle::GLOBAL_MAX_LOCKOUT;
            for i in 0..AuthThrottle::GLOBAL_FREE_ATTEMPTS {
                t.record_failure(&format!("r{round}-{i}"), now);
            }
        }
        assert_eq!(t.global_locked_for(now), Some(AuthThrottle::GLOBAL_MAX_LOCKOUT));
    }

    #[test]
    fn global_window_slides_and_quiet_period_resets_trips() {
        let mut t = AuthThrottle::default();
        let t0 = Instant::now();
        for i in 0..AuthThrottle::GLOBAL_FREE_ATTEMPTS - 1 {
            t.record_failure(&format!("k{i}"), t0);
        }
        // Past the window those failures no longer count.
        let later = t0 + AuthThrottle::GLOBAL_WINDOW + Duration::from_secs(1);
        t.record_failure("late", later);
        assert!(t.global_locked_for(later).is_none());
        assert_eq!(t.global_failures.len(), 1);

        // Trip it once, then stay quiet: prune resets the doubling.
        for i in 0..AuthThrottle::GLOBAL_FREE_ATTEMPTS {
            t.record_failure(&format!("x{i}"), later);
        }
        assert_eq!(t.global_trips, 1);
        let quiet = later + AuthThrottle::GLOBAL_BASE_LOCKOUT + AuthThrottle::GLOBAL_WINDOW;
        t.prune(quiet);
        assert_eq!(t.global_trips, 0);
        assert!(t.global_locked_until.is_none());
    }

    #[test]
    fn per_caller_and_global_lockouts_combine_to_the_longer_one() {
        let mut t = AuthThrottle::default();
        let t0 = Instant::now();
        // Own lockout of 30 s on ID, then a global trip of 5 min from others.
        for _ in 0..3 {
            t.record_failure(ID, t0);
        }
        for i in 0..AuthThrottle::GLOBAL_FREE_ATTEMPTS {
            t.record_failure(&format!("o{i}"), t0);
        }
        assert_eq!(t.locked_for(ID, t0), Some(AuthThrottle::GLOBAL_BASE_LOCKOUT));
    }
}
