//! Why a connector call failed, and the three lines pam shows for it.
//!
//! Every failure in this crate is a [`ConnectorError`], and every
//! `ConnectorError` answers the same three questions the rest of pam asks of
//! a refusal: [`cause`](ConnectorError::cause) is the stable machine name a
//! capability failure carries, [`detail`](ConnectorError::detail) is the one
//! sentence that says what happened, and
//! [`recovery`](ConnectorError::recovery) names the GUI screen or the
//! concrete edit that fixes it. A recovery line never names a security
//! command — an agent reading it must not be able to widen its own access by
//! following the instructions.

use std::time::Duration;

use pam_flow::ConnectorId;
use thiserror::Error;

use crate::descriptor::descriptor;

/// Everything that can go wrong between a flow step and a connector.
///
/// The HTTP mapping is shared by every connector: 401 is [`Self::Auth`], 403
/// is [`Self::RateLimited`] when the response carries an exhausted rate-limit
/// header and [`Self::Forbidden`] otherwise, 404 is [`Self::NotFound`], 429
/// is [`Self::RateLimited`], and 5xx is [`Self::Remote`]. Transport failures
/// map through [`From<TransportError>`](crate::TransportError).
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ConnectorError {
    /// The stored credential was rejected (HTTP 401).
    #[error("the stored credential was rejected")]
    Auth,
    /// The credential is valid but may not read this resource (HTTP 403).
    #[error("the stored credential is not allowed to read this")]
    Forbidden,
    /// The service has no such resource (HTTP 404).
    #[error("the service has no such resource")]
    NotFound,
    /// The service is throttling pam (HTTP 429, or 403 with an exhausted
    /// rate-limit budget).
    #[error("{}", rate_limit_detail(*retry_after))]
    RateLimited {
        /// How long the service asked pam to wait, when it said.
        retry_after: Option<Duration>,
    },
    /// The request ran out of time before the service answered.
    #[error("the service did not answer before the step's deadline")]
    Timeout,
    /// The TLS certificate could not be verified.
    #[error("the service's TLS certificate could not be verified")]
    Certificate,
    /// The request never reached the service.
    #[error("the service could not be reached: {0}")]
    Network(String),
    /// The service answered with a server error.
    #[error("the service answered {status}")]
    Remote {
        /// The HTTP status it answered with.
        status: u16,
    },
    /// The answer was larger than the call's budget.
    #[error("the answer was {bytes} bytes, over the {maximum} byte limit")]
    TooLarge {
        /// How many bytes arrived (or the limit, when the transport stopped
        /// reading at it).
        bytes: u64,
        /// The budget for this call.
        maximum: u64,
    },
    /// The step's `with:` arguments do not make a callable request.
    #[error("{0}")]
    BadArgs(String),
    /// The service answered, but not with what the call needs.
    #[error("{0}")]
    BadResponse(String),
    /// A local CLI ran and failed.
    #[error("{0}")]
    Cli(String),
    /// The local CLI this connector drives is not installed.
    #[error("the aws CLI is not installed, or not on the daemon's PATH")]
    CliMissing,
}

/// The `RateLimited` sentence, with the wait when the service named one.
fn rate_limit_detail(retry_after: Option<Duration>) -> String {
    match retry_after {
        Some(wait) => format!(
            "the service is rate limiting pam for another {}s",
            wait.as_secs()
        ),
        None => "the service is rate limiting pam".to_owned(),
    }
}

impl ConnectorError {
    /// The stable machine name of this failure.
    ///
    /// It travels into `connector.result` evidence and into capability
    /// failures, so it never changes wording — the human-readable half is
    /// [`Self::detail`].
    #[must_use]
    pub fn cause(&self) -> &'static str {
        match self {
            Self::Auth => "connector_auth",
            Self::Forbidden => "connector_forbidden",
            Self::NotFound => "connector_not_found",
            Self::RateLimited { .. } => "connector_rate_limited",
            Self::Timeout => "connector_timeout",
            Self::Certificate => "connector_certificate",
            Self::Network(_) => "connector_network",
            Self::Remote { .. } => "connector_remote",
            Self::TooLarge { .. } => "connector_response_too_large",
            Self::BadArgs(_) => "connector_bad_args",
            Self::BadResponse(_) => "connector_bad_response",
            Self::Cli(_) => "connector_cli",
            Self::CliMissing => "connector_cli_missing",
        }
    }

    /// One sentence saying what happened, safe to show and to store.
    ///
    /// No secret ever reaches it: the transport strips credentials before an
    /// error is built, and CLI text is excerpted, never echoed whole.
    #[must_use]
    pub fn detail(&self) -> String {
        self.to_string()
    }

    /// The concrete fix, naming the GUI screen when the fix lives there.
    #[must_use]
    pub fn recovery(&self, id: ConnectorId) -> String {
        let name = descriptor(id).name;
        match self {
            Self::Auth => format!(
                "open Pam → Settings → Connectors → {name} → replace the credential and Test"
            ),
            Self::Forbidden => format!(
                "the credential cannot read this; open Pam → Settings → Connectors → {name} → replace it with one that can and Test"
            ),
            Self::NotFound => {
                "check the identifiers in the flow step; the service has no such resource"
                    .to_owned()
            }
            Self::RateLimited { retry_after } => match retry_after {
                Some(wait) => format!("wait {}s and re-run the flow", wait.as_secs()),
                None => "wait for the service's rate limit to reset and re-run the flow".to_owned(),
            },
            Self::Timeout => {
                "raise the step's `timeout:` in the flow file, or re-run when the service is faster"
                    .to_owned()
            }
            Self::Certificate | Self::Network(_) | Self::BadResponse(_) => {
                format!("check the base URL in Pam → Settings → Connectors → {name}")
            }
            Self::Remote { .. } => {
                format!("{name} is failing on its side; re-run the flow once it recovers")
            }
            Self::TooLarge { .. } => {
                "narrow the call — a smaller `limit:`, or a shorter log — so the answer fits"
                    .to_owned()
            }
            Self::BadArgs(_) => "fix the step's `with:` arguments in the flow file".to_owned(),
            Self::Cli(_) => {
                "fix the step's `with:` arguments, or check the local AWS credentials".to_owned()
            }
            Self::CliMissing => {
                "install the aws CLI and make sure it is on the daemon's PATH".to_owned()
            }
        }
    }

    /// Whether running the same call again could plausibly succeed.
    ///
    /// A step's `retry:` block consults this: throttling, timeouts, transport
    /// failures and server errors pass, while anything the human must fix
    /// first — a rejected credential, bad arguments — does not.
    #[must_use]
    pub fn retryable(&self) -> bool {
        match self {
            Self::RateLimited { .. } | Self::Timeout | Self::Network(_) => true,
            Self::Remote { status } => *status >= 500,
            _ => false,
        }
    }
}
