//! Aggregate rate admission; caller labels cannot multiply the allowance.
use std::collections::VecDeque;
use std::time::{Duration, Instant};

pub(crate) struct RateWindow {
    limit: usize,
    admitted: VecDeque<Instant>,
}

impl RateWindow {
    pub(crate) fn new(limit: usize) -> Self {
        Self {
            limit,
            admitted: VecDeque::with_capacity(limit),
        }
    }

    pub(crate) fn admit(&mut self, now: Instant) -> bool {
        while self
            .admitted
            .front()
            .is_some_and(|first| now.saturating_duration_since(*first) >= Duration::from_secs(1))
        {
            self.admitted.pop_front();
        }
        if self.admitted.len() >= self.limit {
            return false;
        }
        self.admitted.push_back(now);
        true
    }
}
