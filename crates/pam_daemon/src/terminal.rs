//! Writing a request's terminal row so that it is not lost.
//!
//! Every terminal transition goes through [`pam_store::Store::finish_request`]
//! (state + outcome + audit row in one transaction, first finisher wins). What
//! this module adds is what happens when that call fails. It used to be
//! `let _ = store.finish_request(..)`: the error was dropped without a log line,
//! the caller was answered as if the row were recorded, and the row stayed
//! `running` — counting against the admission cap — until the next daemon boot.
//!
//! [`TerminalWriter::finish`] retries briefly ([`RETRY_BACKOFF`]), logs a write
//! that still fails, and **parks** the verdict in a bounded queue instead of
//! dropping it. [`TerminalWriter::retry_parked`] (the daemon's maintenance loop)
//! keeps offering parked verdicts to the store until one of three things is
//! true: the store took it, the row turned out to be terminal already (another
//! finisher — the reconciler, the reaper — got there first), or the row is gone.
//! The caller is told which happened ([`Written`]) so it can answer honestly:
//! a success whose audit row is not durable is not reported as a success.
//!
//! The queue is bounded ([`MAX_PARKED`]). When it is full the oldest verdict is
//! dropped with an error log; its row is then closed by the queue's reconciler
//! once its deadline has passed, with the lease-expiry outcome. Nothing strands.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use pam_store::{Actor, AuditEntry, Decision, RequestState, Store, StoreError};

/// Pauses before the second and third attempt of one terminal write.
pub const RETRY_BACKOFF: [Duration; 2] = [Duration::from_millis(25), Duration::from_millis(150)];

/// Most terminal verdicts waiting for the store at once.
pub const MAX_PARKED: usize = 256;

/// What became of a terminal write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Written {
    /// The row is terminal and audited: this call wrote it, another
    /// finisher had already, or there is no such row to finish.
    Durable,
    /// The store refused every attempt; the verdict is parked and will be
    /// retried. The row is still in flight right now.
    Parked,
}

/// A terminal verdict the store has not accepted yet.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ParkedTerminal {
    id: String,
    state: RequestState,
    outcome: Option<String>,
    action: String,
    decision: Decision,
    actor: Actor,
    detail: Option<String>,
}

impl ParkedTerminal {
    fn audit(&self) -> AuditEntry<'_> {
        AuditEntry {
            action: &self.action,
            decision: self.decision,
            actor: self.actor,
            detail: self.detail.as_deref(),
        }
    }
}

/// The one writer of terminal rows outside the queue's own lease paths.
pub struct TerminalWriter {
    store: Arc<Store>,
    parked: Mutex<VecDeque<ParkedTerminal>>,
    /// Test seam: how many upcoming store calls fail before reaching the
    /// store, standing in for a store that will not take a write.
    #[cfg(test)]
    injected_failures: std::sync::atomic::AtomicUsize,
}

impl std::fmt::Debug for TerminalWriter {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TerminalWriter")
            .field("parked", &self.parked_count())
            .finish_non_exhaustive()
    }
}

impl TerminalWriter {
    /// A writer over `store` with nothing parked.
    #[must_use]
    pub fn new(store: Arc<Store>) -> Arc<Self> {
        Arc::new(Self {
            store,
            parked: Mutex::new(VecDeque::new()),
            #[cfg(test)]
            injected_failures: std::sync::atomic::AtomicUsize::new(0),
        })
    }

    /// Makes the next `count` store calls fail without reaching the store.
    #[cfg(test)]
    pub(crate) fn fail_next(&self, count: usize) {
        self.injected_failures
            .store(count, std::sync::atomic::Ordering::SeqCst);
    }

    /// One attempt at the store's choke point.
    async fn attempt(
        &self,
        id: &str,
        state: RequestState,
        outcome: Option<&str>,
        audit: AuditEntry<'_>,
    ) -> Result<bool, StoreError> {
        #[cfg(test)]
        {
            use std::sync::atomic::Ordering;
            if self
                .injected_failures
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |left| {
                    left.checked_sub(1)
                })
                .is_ok()
            {
                return Err(StoreError::AbandonedTransaction);
            }
        }
        self.store.finish_request(id, state, outcome, audit).await
    }

    /// Records `id`'s terminal `state`, `outcome` and `audit` row (see the
    /// module docs): up to three attempts, then parked.
    pub async fn finish(
        &self,
        id: &str,
        state: RequestState,
        outcome: Option<&str>,
        audit: AuditEntry<'_>,
    ) -> Written {
        let mut pause = None;
        let mut backoff = RETRY_BACKOFF.iter();
        loop {
            if let Some(pause) = pause {
                tokio::time::sleep(pause).await;
            }
            match self.attempt(id, state, outcome, audit).await {
                // `false` is the first-wins no-op: someone else finished it.
                Ok(_) => return Written::Durable,
                Err(StoreError::NotFound { .. }) => {
                    // Refused before a row existed, or pruned since.
                    tracing::debug!(request = %id, "no request row to finish");
                    return Written::Durable;
                }
                Err(error) => {
                    let Some(next) = backoff.next() else {
                        tracing::error!(
                            request = %id,
                            state = state.as_str(),
                            %error,
                            "could not record the terminal state; parked for retry"
                        );
                        self.park(id, state, outcome, audit);
                        return Written::Parked;
                    };
                    pause = Some(*next);
                }
            }
        }
    }

    /// Parks a verdict without attempting it: for a caller whose own write
    /// path (the queue's lease completion) already failed.
    pub fn park(
        &self,
        id: &str,
        state: RequestState,
        outcome: Option<&str>,
        audit: AuditEntry<'_>,
    ) {
        let entry = ParkedTerminal {
            id: id.to_owned(),
            state,
            outcome: outcome.map(str::to_owned),
            action: audit.action.to_owned(),
            decision: audit.decision,
            actor: audit.actor,
            detail: audit.detail.map(str::to_owned),
        };
        let mut parked = self.lock();
        if parked.len() >= MAX_PARKED
            && let Some(dropped) = parked.pop_front()
        {
            tracing::error!(
                request = %dropped.id,
                "the parked terminal queue is full; dropping the oldest verdict, \
                 the reconciler will close its row at its deadline"
            );
        }
        parked.push_back(entry);
    }

    /// Offers every parked verdict to the store once. A verdict leaves the
    /// queue when the store takes it, the row is already terminal, or the
    /// row is gone; a store that still refuses keeps it for the next call.
    /// Returns how many left the queue.
    pub async fn retry_parked(&self) -> usize {
        let batch: Vec<ParkedTerminal> = self.lock().drain(..).collect();
        let mut settled = 0;
        let mut again = Vec::new();
        for entry in batch {
            match self
                .attempt(
                    &entry.id,
                    entry.state,
                    entry.outcome.as_deref(),
                    entry.audit(),
                )
                .await
            {
                Ok(_) | Err(StoreError::NotFound { .. }) => {
                    tracing::info!(request = %entry.id, "a parked terminal state is now recorded");
                    settled += 1;
                }
                Err(error) => {
                    tracing::warn!(request = %entry.id, %error, "a parked terminal state is still refused");
                    again.push(entry);
                }
            }
        }
        if !again.is_empty() {
            let mut parked = self.lock();
            // Older verdicts first, ahead of anything parked meanwhile.
            for entry in again.into_iter().rev() {
                parked.push_front(entry);
            }
            while parked.len() > MAX_PARKED {
                parked.pop_front();
            }
        }
        settled
    }

    /// How many verdicts are waiting for the store.
    #[must_use]
    pub fn parked_count(&self) -> usize {
        self.lock().len()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, VecDeque<ParkedTerminal>> {
        self.parked
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}
