//! Read-only connectors over an injected HTTP transport (system `curl`
//! in production). One module per connector; secrets never reach argv,
//! logs, or evidence. See
//! `docs/specs/2026-09-02-flows-connectors-design.md`.
//!
//! Seven services are reachable from a flow step — GitHub Actions, Jenkins,
//! `SonarQube`, Jira Data Center, Confluence Cloud, `SharePoint` through
//! Microsoft Graph, and an allowlisted passthrough to the local `aws` CLI —
//! and every one of them is read-only. There is no call in this crate that
//! creates, updates or deletes anything.
//!
//! Two entry points carry all of it. [`call`] runs one flow step's connector
//! action and answers with either JSON or a log; [`verify`] proves a stored
//! credential still works and is what the GUI's **Test** button runs. Both
//! take a `&dyn HttpTransport`, so the daemon injects
//! [`CurlTransport`] and tests inject
//! [`testing::FakeTransport`](crate::testing::FakeTransport).
//!
//! The call table itself is not written here: [`descriptor`] borrows it from
//! `pam_flow`, so the flow validator and the dispatcher can never disagree
//! about which calls exist or what arguments they take.
//!
//! ```
//! use pam_connectors::{ConnectorId, descriptor};
//!
//! let github = descriptor(ConnectorId::Github);
//! assert_eq!(github.name, "GitHub");
//! assert!(github.calls.iter().any(|call| call.name == "job_log"));
//! ```

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::time::Instant;

pub mod aws;
mod confluence;
mod curl;
mod descriptor;
mod error;
mod github;
mod jenkins;
mod jira;
mod sharepoint;
mod sonarqube;
mod transport;

#[cfg(any(test, feature = "testing"))]
pub mod testing;

pub use curl::CurlTransport;
pub use descriptor::{AuthKind, Descriptor, descriptor, descriptors};
pub use error::ConnectorError;
pub use pam_flow::{ArgValue, ConnectorId};
pub use transport::{
    AWS_BASE_URL, Connection, HttpRequest, HttpResponse, HttpTransport, MAX_JSON_BYTES,
    MAX_LOG_BYTES, Method, Secret, TransportError, validate_base_url,
};

#[cfg(test)]
mod aws_test;
#[cfg(test)]
mod confluence_test;
#[cfg(test)]
mod curl_test;
#[cfg(test)]
mod descriptor_test;
#[cfg(test)]
mod error_test;
#[cfg(test)]
mod github_test;
#[cfg(test)]
mod jenkins_test;
#[cfg(test)]
mod jira_test;
#[cfg(test)]
mod sharepoint_test;
#[cfg(test)]
mod sonarqube_test;
#[cfg(test)]
mod transport_test;

/// What one connector call produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CallResult {
    /// A structured answer, ready to become `connector.result` evidence.
    Json(serde_json::Value),
    /// A log stream, compressed by `pam_compact` rather than parsed.
    Log {
        /// A file name for the evidence row, e.g. `github-job-42.log`.
        name: String,
        /// The log bytes as the service sent them.
        bytes: Vec<u8>,
        /// The exit status the log describes, when the service says: 0 for a
        /// success, 1 for a failure, `None` while the work is still running.
        exit_status: Option<i32>,
    },
}

/// What a successful credential test found on the other end.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyReport {
    /// One line naming who pam is over there — "authenticated as octocat",
    /// "account 123456789012 arn …" — shown next to the connector in the GUI.
    pub detail: String,
}

/// Runs one connector call.
///
/// `call` and `args` come straight from a validated flow step, so the call
/// name and its argument names are already known-good; the per-connector
/// modules still check values, because a value can arrive from a flow input
/// a human typed.
pub async fn call(
    id: ConnectorId,
    conn: &Connection,
    call: &str,
    args: &BTreeMap<String, ArgValue>,
    transport: &dyn HttpTransport,
    deadline: Instant,
) -> Result<CallResult, ConnectorError> {
    match id {
        ConnectorId::Github => github::call(conn, call, args, transport, deadline).await,
        ConnectorId::Jenkins => jenkins::call(conn, call, args, transport, deadline).await,
        ConnectorId::Sonarqube => sonarqube::call(conn, call, args, transport, deadline).await,
        ConnectorId::Jira => jira::call(conn, call, args, transport, deadline).await,
        ConnectorId::Confluence => confluence::call(conn, call, args, transport, deadline).await,
        ConnectorId::Sharepoint => sharepoint::call(conn, call, args, transport, deadline).await,
        ConnectorId::Aws => aws::call(conn, call, args, deadline).await,
    }
}

/// Proves a stored credential still works.
///
/// This is what the Connectors screen's **Test** button runs, under a ten
/// second deadline. A connector that answers 200 but does not carry the
/// field that identifies the caller fails here rather than later, in a flow.
pub async fn verify(
    id: ConnectorId,
    conn: &Connection,
    transport: &dyn HttpTransport,
    deadline: Instant,
) -> Result<VerifyReport, ConnectorError> {
    match id {
        ConnectorId::Github => github::verify(conn, transport, deadline).await,
        ConnectorId::Jenkins => jenkins::verify(conn, transport, deadline).await,
        ConnectorId::Sonarqube => sonarqube::verify(conn, transport, deadline).await,
        ConnectorId::Jira => jira::verify(conn, transport, deadline).await,
        ConnectorId::Confluence => confluence::verify(conn, transport, deadline).await,
        ConnectorId::Sharepoint => sharepoint::verify(conn, transport, deadline).await,
        ConnectorId::Aws => aws::verify(conn, deadline).await,
    }
}

/// The refusal for a call name this connector does not offer.
///
/// A validated flow can never reach it — `pam_flow` refuses the step first —
/// but the daemon's `admin.connectors.*` surface takes call names from the
/// GUI, so the dispatcher answers rather than panics.
fn unknown_call(id: ConnectorId, call: &str) -> ConnectorError {
    let offered: Vec<&str> = descriptor(id).calls.iter().map(|spec| spec.name).collect();
    ConnectorError::BadArgs(format!(
        "`{id}` has no call `{call}`; it offers {}",
        offered.join(", ")
    ))
}
