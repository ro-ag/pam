//! One request's cumulative work allowance. Retries share this object.
//!
//! Reservations stay spent if a future is cancelled or fails without an exact
//! byte count. Completed bounded captures refund only unused reserved bytes.

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use pam_connectors::{HttpRequest, HttpResponse, HttpTransport, TransportError};
use serde::Serialize;
use thiserror::Error;

/// Maximum wall time of one admitted request, including queue wait.
pub const MAX_REQUEST_TIME: Duration = Duration::from_hours(1);
/// Recovery for a consumed request allowance.
pub const RECOVERY_BUDGET: &str =
    "Inspect the retained evidence and narrow the operation before starting a new request.";

/// Compiled ceilings; a caller cannot enlarge them.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// Command and connector attempts, including failed retries.
    pub attempts: u64,
    /// Physical HTTP calls, including pagination and redirects.
    pub http_calls: u64,
    /// Accepted HTTP response body bytes across all calls.
    pub http_bytes: u64,
    /// Captured command output bytes across all attempts.
    pub command_bytes: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            attempts: 256,
            http_calls: 128,
            http_bytes: 128 * 1024 * 1024,
            command_bytes: 128 * 1024 * 1024,
        }
    }
}

/// Stable refusal identifying which allowance stopped the work.
#[derive(Debug, Clone, Copy, Error, PartialEq, Eq)]
#[error("request work budget exhausted: {resource}")]
pub struct BudgetError {
    /// Machine-readable cause.
    pub cause: &'static str,
    /// The exhausted counter.
    pub resource: &'static str,
}

/// Auditable counters contain no request arguments or credentials.
#[derive(Debug, Default, Clone, Copy, Serialize)]
pub struct Usage {
    /// Attempt slots consumed.
    pub attempts: u64,
    /// HTTP call slots consumed.
    pub http_calls: u64,
    /// Captured or conservatively reserved response bytes.
    pub http_bytes: u64,
    /// Captured or conservatively reserved command bytes.
    pub command_bytes: u64,
}

/// Shared by every step and follow-up within an execution.
#[derive(Debug)]
pub struct RequestBudget {
    deadline: Instant,
    limits: Limits,
    usage: Mutex<Usage>,
}

impl RequestBudget {
    /// Start with an already-admitted absolute expiry, never a fresh step clock.
    #[must_use]
    pub fn new(deadline: Instant) -> Arc<Self> {
        Self::with_limits(deadline, Limits::default())
    }

    /// Finite injected limits, clamped to production ceilings.
    #[must_use]
    pub fn with_limits(deadline: Instant, limits: Limits) -> Arc<Self> {
        let ceiling = Limits::default();
        Arc::new(Self {
            deadline: deadline.min(Instant::now() + MAX_REQUEST_TIME),
            limits: Limits {
                attempts: limits.attempts.min(ceiling.attempts),
                http_calls: limits.http_calls.min(ceiling.http_calls),
                http_bytes: limits.http_bytes.min(ceiling.http_bytes),
                command_bytes: limits.command_bytes.min(ceiling.command_bytes),
            },
            usage: Mutex::new(Usage::default()),
        })
    }

    /// Remaining request wall time; does not reset between attempts.
    pub fn remaining(&self) -> Result<Duration, BudgetError> {
        self.deadline
            .checked_duration_since(Instant::now())
            .filter(|d| !d.is_zero())
            .ok_or(BudgetError {
                cause: "request_deadline_exhausted",
                resource: "deadline",
            })
    }

    /// Bound a step's wall-clock deadline by the request's original expiry.
    #[must_use]
    pub fn deadline(&self) -> Instant {
        self.deadline
    }

    /// Reserve an attempt before any subprocess, connector or preliminary read.
    pub fn attempt(&self) -> Result<(), BudgetError> {
        self.remaining()?;
        let mut usage = self.usage.lock().expect("budget counter mutex");
        if usage.attempts >= self.limits.attempts {
            return Err(exhausted("attempts"));
        }
        usage.attempts += 1;
        Ok(())
    }

    /// Reserve command capture before spawning the child.
    pub fn command(self: &Arc<Self>, maximum: u64) -> Result<Reservation, BudgetError> {
        self.reserve(maximum, false)
    }

    /// Reserve one physical HTTP call and its maximum accepted body together.
    pub fn http(self: &Arc<Self>, maximum: u64) -> Result<Reservation, BudgetError> {
        self.reserve(maximum, true)
    }

    fn reserve(self: &Arc<Self>, maximum: u64, http: bool) -> Result<Reservation, BudgetError> {
        self.remaining()?;
        let mut usage = self.usage.lock().expect("budget counter mutex");
        let (used, limit, resource) = if http {
            if usage.http_calls >= self.limits.http_calls {
                return Err(exhausted("http_calls"));
            }
            (usage.http_bytes, self.limits.http_bytes, "http_bytes")
        } else {
            (
                usage.command_bytes,
                self.limits.command_bytes,
                "command_bytes",
            )
        };
        if maximum == 0 || maximum > limit.saturating_sub(used) {
            return Err(exhausted(resource));
        }
        if http {
            usage.http_calls += 1;
            usage.http_bytes += maximum;
        } else {
            usage.command_bytes += maximum;
        }
        Ok(Reservation {
            budget: Arc::clone(self),
            maximum,
            http,
        })
    }

    /// Snapshot for the final evidence/handoff record.
    #[must_use]
    pub fn usage(&self) -> Usage {
        *self.usage.lock().expect("budget counter mutex")
    }
}

/// A pending reservation. Dropping it never replenishes a cancelled request.
#[derive(Debug)]
pub struct Reservation {
    budget: Arc<RequestBudget>,
    maximum: u64,
    http: bool,
}

impl Reservation {
    /// Reconcile only an exact completed capture, after checking its bound.
    pub fn finish(self, actual: u64) -> Result<(), BudgetError> {
        if actual > self.maximum {
            return Err(exhausted("capture_exceeded_reservation"));
        }
        let mut usage = self.budget.usage.lock().expect("budget counter mutex");
        let unused = self.maximum - actual;
        if self.http {
            usage.http_bytes -= unused;
        } else {
            usage.command_bytes -= unused;
        }
        Ok(())
    }
}

fn exhausted(resource: &'static str) -> BudgetError {
    BudgetError {
        cause: "request_budget_exhausted",
        resource,
    }
}

/// Meter physical sends underneath the scope/redirect adapter.
pub struct BudgetTransport<'a> {
    /// Existing bounded transport.
    pub inner: &'a dyn HttpTransport,
    /// The original request allowance.
    pub budget: Arc<RequestBudget>,
}

impl HttpTransport for BudgetTransport<'_> {
    fn send<'a>(
        &'a self,
        request: HttpRequest,
        deadline: Instant,
    ) -> Pin<Box<dyn Future<Output = Result<HttpResponse, TransportError>> + Send + 'a>> {
        Box::pin(async move {
            if request.follow_one_https_redirect_without_auth {
                return Err(TransportError::Policy {
                    cause: "unmetered_redirect",
                    detail: "An unmetered redirect is not permitted".to_owned(),
                });
            }
            let reservation =
                self.budget
                    .http(request.max_bytes)
                    .map_err(|error| TransportError::Policy {
                        cause: error.cause,
                        detail: error.to_string(),
                    })?;
            let deadline = deadline.min(self.budget.deadline());
            let response = tokio::time::timeout_at(
                tokio::time::Instant::from_std(deadline),
                self.inner.send(request, deadline),
            )
            .await
            .map_err(|_| TransportError::Policy {
                cause: "request_deadline_exhausted",
                detail: "The request's absolute HTTP deadline elapsed".to_owned(),
            })??;
            reservation
                .finish(u64::try_from(response.body.len()).unwrap_or(u64::MAX))
                .map_err(|error| TransportError::Policy {
                    cause: error.cause,
                    detail: error.to_string(),
                })?;
            Ok(response)
        })
    }
}
