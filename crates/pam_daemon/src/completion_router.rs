//! The in-daemon fan-out of a request's single terminal [`Response`] to every
//! pipeline task waiting for it: the requester plus any attached duplicates.
//!
//! This is not a transport: whoever carries the reply to the client owns that.
//! The router only answers "who inside the daemon is parked on this id", and for
//! a short time afterwards "what was the answer", so a duplicate that attaches
//! just after the finish is not left to wait out its deadline.
//!
//! **Both maps are bounded.**
//! - `waiting`: a sender whose receiver was dropped (the caller's own deadline
//!   elapsed, or its connection went away) is pruned on every
//!   [`CompletionRouter::register`], [`CompletionRouter::finish`] and
//!   [`CompletionRouter::prune`]; an id with no live waiter left is removed.
//!   Nothing accumulates for requests that end without a finish.
//! - `finished`: at most [`MAX_FINISHED_ENTRIES`] responses and
//!   [`MAX_FINISHED_BYTES`] in total, each kept for [`FINISHED_TTL`], oldest
//!   evicted first, pruned on insert and on the reaper's tick rather than only
//!   when another request happens to finish. A response too large to keep is
//!   delivered to the waiters present and not retained.
//!
//! Retention is a courtesy, not the record: the terminal state of every request
//! is durable in the store, so a late registrant whose answer was evicted (or
//! never kept) recovers it through `query` / `flow.result`. The pipeline hands
//! such a caller a ticket instead of parking it on an answer that already left.

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::Duration;

use pam_proto::Response;
use tokio::sync::{Mutex, oneshot};
use tokio::time::Instant;

/// How long the router remembers a terminal response, to close the
/// attach-after-finish race.
pub const FINISHED_TTL: Duration = Duration::from_mins(1);

/// Most terminal responses the router retains at once.
pub const MAX_FINISHED_ENTRIES: usize = 256;

/// Most bytes of retained terminal responses (approximate JSON size).
pub const MAX_FINISHED_BYTES: usize = 8 * 1024 * 1024;

/// Routes each request's single terminal [`Response`] to every pipeline
/// task waiting for it (the requester plus any attached duplicates).
#[derive(Debug, Clone, Default)]
pub struct CompletionRouter {
    inner: Arc<Mutex<RouterInner>>,
}

#[derive(Debug)]
struct Finished {
    at: Instant,
    bytes: usize,
    response: Response,
}

#[derive(Debug, Default)]
struct RouterInner {
    /// request id → the waiters to answer on completion.
    waiting: HashMap<String, Vec<oneshot::Sender<Response>>>,
    /// Recently finished requests, kept for [`FINISHED_TTL`] so a waiter
    /// registering just after the finish still gets its answer.
    finished: HashMap<String, Finished>,
    /// Ids in `finished`, oldest first: the eviction order.
    order: VecDeque<String>,
    /// Sum of `Finished::bytes` over `finished`.
    finished_bytes: usize,
}

/// What [`CompletionRouter::register`] handed back.
#[derive(Debug)]
pub enum Registration {
    /// The request already finished; here is its response.
    Ready(Box<Response>),
    /// The request is still in flight; the receiver resolves with its
    /// terminal response.
    Pending(oneshot::Receiver<Response>),
}

/// How much the router currently holds (for `status` and tests).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RouterUsage {
    /// Request ids with at least one registered waiter.
    pub waiting: usize,
    /// Retained terminal responses.
    pub finished: usize,
    /// Approximate bytes of the retained responses.
    pub finished_bytes: usize,
}

impl CompletionRouter {
    /// An empty router.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers interest in `request_id`'s terminal response.
    pub async fn register(&self, request_id: &str) -> Registration {
        let mut inner = self.inner.lock().await;
        inner.expire(Instant::now());
        if let Some(finished) = inner.finished.get(request_id) {
            return Registration::Ready(Box::new(finished.response.clone()));
        }
        let (tx, rx) = oneshot::channel();
        let waiters = inner.waiting.entry(request_id.to_owned()).or_default();
        // A waiter that gave up leaves a closed sender behind; drop those
        // here so an id that is attached to and abandoned repeatedly cannot
        // grow its list.
        waiters.retain(|waiter| !waiter.is_closed());
        waiters.push(tx);
        Registration::Pending(rx)
    }

    /// Whether anyone is still waiting for `request_id`'s terminal
    /// response. A reaped expiry reads this before choosing the refusal a
    /// waiter receives: a caller that is still parked gets its elapsed
    /// deadline, while an unobserved request records only the reaper's own
    /// teardown. Entries whose receiver the caller dropped do not count —
    /// nobody is listening.
    pub async fn has_waiters(&self, request_id: &str) -> bool {
        self.inner
            .lock()
            .await
            .waiting
            .get(request_id)
            .is_some_and(|waiters| waiters.iter().any(|tx| !tx.is_closed()))
    }

    /// Delivers `response` to every waiter registered for `request_id`
    /// and remembers it for late registrants, within the bounds in the
    /// module docs.
    pub async fn finish(&self, request_id: &str, response: Response) {
        let mut inner = self.inner.lock().await;
        if let Some(waiters) = inner.waiting.remove(request_id) {
            for waiter in waiters {
                // A dropped receiver (deadline elapsed) is fine.
                let _ = waiter.send(response.clone());
            }
        }
        let now = Instant::now();
        inner.expire(now);
        inner.forget(request_id);
        let bytes = approximate_size(&response);
        if bytes > MAX_FINISHED_BYTES {
            // Too large to keep at all; the waiters present were answered
            // and a late one reads the durable result.
            return;
        }
        inner.finished_bytes += bytes;
        inner.order.push_back(request_id.to_owned());
        inner.finished.insert(
            request_id.to_owned(),
            Finished {
                at: now,
                bytes,
                response,
            },
        );
        while inner.finished.len() > MAX_FINISHED_ENTRIES
            || inner.finished_bytes > MAX_FINISHED_BYTES
        {
            let Some(oldest) = inner.order.front().cloned() else {
                break;
            };
            inner.forget(&oldest);
        }
    }

    /// Drops everything that is no longer needed: retained responses past
    /// [`FINISHED_TTL`] and waiters whose receiver is gone. Called on the
    /// reaper's tick so an idle daemon does not sit on a minute of replies
    /// until the next request finishes.
    pub async fn prune(&self) {
        let mut inner = self.inner.lock().await;
        inner.expire(Instant::now());
        inner.waiting.retain(|_, waiters| {
            waiters.retain(|waiter| !waiter.is_closed());
            !waiters.is_empty()
        });
    }

    /// What the router holds right now.
    pub async fn usage(&self) -> RouterUsage {
        let inner = self.inner.lock().await;
        RouterUsage {
            waiting: inner.waiting.len(),
            finished: inner.finished.len(),
            finished_bytes: inner.finished_bytes,
        }
    }
}

impl RouterInner {
    /// Removes `request_id`'s retained response, if any.
    fn forget(&mut self, request_id: &str) {
        if let Some(finished) = self.finished.remove(request_id) {
            self.finished_bytes = self.finished_bytes.saturating_sub(finished.bytes);
            self.order.retain(|id| id != request_id);
        }
    }

    /// Removes every retained response older than [`FINISHED_TTL`].
    /// Insertion order is age order, so only the front needs looking at.
    fn expire(&mut self, now: Instant) {
        while let Some(oldest) = self.order.front() {
            let expired = self
                .finished
                .get(oldest)
                .is_none_or(|finished| now.duration_since(finished.at) >= FINISHED_TTL);
            if !expired {
                break;
            }
            let oldest = oldest.clone();
            self.forget(&oldest);
            // `forget` is a no-op for an id with no entry; drop the stale
            // order slot so the loop always makes progress.
            if self.order.front() == Some(&oldest) {
                self.order.pop_front();
            }
        }
    }
}

/// Fixed allowance for a response's framing and each value's punctuation.
const OVERHEAD: usize = 64;

/// Approximate serialized size of `response`, computed without allocating:
/// the retention bound needs proportion, not an exact byte count.
#[must_use]
pub fn approximate_size(response: &Response) -> usize {
    match response {
        Response::Result {
            id, body, evidence, ..
        } => {
            OVERHEAD
                + id.len()
                + value_size(body)
                + evidence.iter().map(|item| item.len() + 3).sum::<usize>()
        }
        Response::Refusal {
            id,
            cause,
            detail,
            recovery,
            ..
        } => OVERHEAD + id.len() + cause.len() + detail.len() + recovery.len(),
        Response::Ticket { id, ticket, .. } => OVERHEAD + id.len() + ticket.len(),
    }
}

fn value_size(value: &serde_json::Value) -> usize {
    match value {
        serde_json::Value::Null => 4,
        serde_json::Value::Bool(_) => 5,
        serde_json::Value::Number(_) => 24,
        serde_json::Value::String(text) => text.len() + 2,
        serde_json::Value::Array(items) => {
            2 + items.iter().map(|item| value_size(item) + 1).sum::<usize>()
        }
        serde_json::Value::Object(map) => {
            2 + map
                .iter()
                .map(|(key, item)| key.len() + 4 + value_size(item))
                .sum::<usize>()
        }
    }
}
