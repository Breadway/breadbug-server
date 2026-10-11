//! In-memory sliding-window rate limiter.
//!
//! Keys are opaque 64-bit values derived with a server secret (see
//! `crypto::keyed_u64`), so neither IP addresses nor install ids are kept in
//! the clear, and nothing here is ever persisted.

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::time::{Duration, Instant};

const PRUNE_AT: usize = 50_000;

pub struct Limiter {
    limit: usize,
    window: Duration,
    hits: Mutex<HashMap<u64, VecDeque<Instant>>>,
}

impl Limiter {
    pub fn new(limit: usize, window: Duration) -> Self {
        Self {
            limit,
            window,
            hits: Mutex::new(HashMap::new()),
        }
    }

    /// Record an attempt for `key`. `Ok` if allowed, otherwise `Err` with how
    /// long until a slot frees up.
    pub fn check(&self, key: u64, now: Instant) -> Result<(), Duration> {
        let mut hits = self.hits.lock().unwrap_or_else(|p| p.into_inner());
        if hits.len() > PRUNE_AT {
            hits.retain(|_, q| {
                q.back()
                    .is_some_and(|t| now.duration_since(*t) < self.window)
            });
        }
        let q = hits.entry(key).or_default();
        while q
            .front()
            .is_some_and(|t| now.saturating_duration_since(*t) >= self.window)
        {
            q.pop_front();
        }
        if q.len() >= self.limit {
            let wait = q.front().map_or(self.window, |t| {
                self.window
                    .saturating_sub(now.saturating_duration_since(*t))
            });
            return Err(wait);
        }
        q.push_back(now);
        Ok(())
    }

    #[cfg(test)]
    pub fn tracked(&self) -> usize {
        self.hits.lock().unwrap().len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_up_to_the_limit_then_blocks_until_the_window_slides() {
        let l = Limiter::new(3, Duration::from_secs(60));
        let t0 = Instant::now();
        for i in 0..3 {
            assert!(l.check(1, t0 + Duration::from_secs(i)).is_ok());
        }
        let wait = l.check(1, t0 + Duration::from_secs(10)).unwrap_err();
        assert_eq!(wait, Duration::from_secs(50));
        assert!(l.check(1, t0 + Duration::from_secs(61)).is_ok());
    }

    #[test]
    fn keys_are_independent() {
        let l = Limiter::new(1, Duration::from_secs(60));
        let t0 = Instant::now();
        assert!(l.check(1, t0).is_ok());
        assert!(l.check(2, t0).is_ok());
        assert!(l.check(1, t0).is_err());
    }

    #[test]
    fn rejected_attempts_do_not_extend_the_block() {
        let l = Limiter::new(1, Duration::from_secs(60));
        let t0 = Instant::now();
        l.check(1, t0).unwrap();
        for s in 1..50 {
            assert!(l.check(1, t0 + Duration::from_secs(s)).is_err());
        }
        assert!(l.check(1, t0 + Duration::from_secs(61)).is_ok());
    }

    #[test]
    fn old_keys_are_pruned() {
        let l = Limiter::new(1, Duration::from_secs(1));
        let t0 = Instant::now();
        for k in 0..(PRUNE_AT as u64 + 10) {
            l.check(k, t0).unwrap();
        }
        l.check(u64::MAX, t0 + Duration::from_secs(5)).unwrap();
        assert!(l.tracked() < 100);
    }
}
