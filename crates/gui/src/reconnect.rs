//! Five-second retry scheduling, independent of rendering and network latency.
use rotodesk_proto::RotoDeskId;
use std::time::{Duration, Instant};

pub const RETRY_DELAY: Duration = Duration::from_secs(5);

pub struct Reconnect {
    pub target: RotoDeskId,
    pub attempts: u64,
    pub last_error: String,
    next_attempt: Instant,
}

impl Reconnect {
    pub fn new(target: RotoDeskId, error: String, now: Instant) -> Self {
        Self {
            target,
            attempts: 0,
            last_error: error,
            next_attempt: now + RETRY_DELAY,
        }
    }
    pub fn due(&self, now: Instant) -> bool {
        now >= self.next_attempt
    }
    pub fn remaining(&self, now: Instant) -> u64 {
        self.next_attempt
            .saturating_duration_since(now)
            .as_secs_f64()
            .ceil() as u64
    }
    pub fn begin_attempt(&mut self) {
        self.attempts = self.attempts.saturating_add(1);
    }
    pub fn failed(&mut self, error: String, now: Instant) {
        self.last_error = error;
        self.next_attempt = now + RETRY_DELAY;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn retries_keep_the_target_and_have_no_attempt_limit() {
        let target = RotoDeskId::new(123456789).unwrap();
        let mut now = Instant::now();
        let mut retry = Reconnect::new(target, "offline".into(), now);
        for n in 1..=1000 {
            assert!(!retry.due(now + Duration::from_millis(4999)));
            assert_eq!(retry.remaining(now), 5);
            now += RETRY_DELAY;
            assert!(retry.due(now));
            retry.begin_attempt();
            assert_eq!(retry.attempts, n);
            assert_eq!(retry.target, target);
            retry.failed("offline".into(), now);
        }
    }
}
