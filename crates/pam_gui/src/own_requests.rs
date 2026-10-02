//! The GUI's own control requests, so they never feed back into its refresh loop.
//!
//! The daemon publishes lifecycle events (`started`, `done`) for every public request, the GUI's
//! own `status`, `query` and `cancel` calls included, and the GUI subscribes to every topic. A
//! frontend that refetches on every event would therefore trigger its own next poll: one status
//! call, two events, one more status call, round after round, until the daemon's control budget
//! (`request_capacity_exhausted`) is spent. The bridge generates the id of each such request
//! itself, [`register`]s it **before** sending, and the event pump drops events whose topic
//! ([`crate::events`]) is a registered id ([`is_own`]). Ids expire after [`TTL`] and the registry
//! is bounded ([`CAPACITY`]), so it never grows with uptime.

use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// How long an id stays registered: far longer than any control request lives, so its late
/// `done` event is still recognised.
pub const TTL: Duration = Duration::from_secs(120);

/// Most ids kept at once; the oldest is dropped first.
pub const CAPACITY: usize = 1_024;

/// A bounded, expiring set of request ids.
#[derive(Debug, Default)]
pub struct OwnRequests {
    ids: Mutex<VecDeque<(String, Instant)>>,
}

impl OwnRequests {
    /// An empty registry.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            ids: Mutex::new(VecDeque::new()),
        }
    }

    /// Records `id` as one of the GUI's own requests, as of `now`.
    pub fn register_at(&self, id: &str, now: Instant) {
        let mut ids = self
            .ids
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        prune(&mut ids, now);
        if ids.len() >= CAPACITY {
            ids.pop_front();
        }
        ids.push_back((id.to_owned(), now));
    }

    /// Whether `id` is a live own request, as of `now`.
    #[must_use]
    pub fn contains_at(&self, id: &str, now: Instant) -> bool {
        let mut ids = self
            .ids
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        prune(&mut ids, now);
        ids.iter().any(|(known, _)| known == id)
    }
}

/// Drops expired ids from the front (entries are in registration order).
fn prune(ids: &mut VecDeque<(String, Instant)>, now: Instant) {
    while ids
        .front()
        .is_some_and(|(_, at)| now.saturating_duration_since(*at) >= TTL)
    {
        ids.pop_front();
    }
}

/// The process-wide registry the bridge writes and the event pump reads.
static OWN: OwnRequests = OwnRequests::new();

/// Marks `id` as a request the GUI itself is about to send.
pub fn register(id: &str) {
    OWN.register_at(id, Instant::now());
}

/// True when `id` is a live request the GUI sent itself.
#[must_use]
pub fn is_own(id: &str) -> bool {
    OWN.contains_at(id, Instant::now())
}
