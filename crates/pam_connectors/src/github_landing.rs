//! Typed landing operations. The daemon must authorize and journal each mutation.
//! Reads never create or merge a PR; mutation failures require reconciliation.
use crate::transport::{check_status, endpoint, request};
use crate::{Connection, ConnectorError, ConnectorId, HttpTransport, Method};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{collections::BTreeMap, time::Instant};

const RESPONSE_LIMIT: u64 = 1024 * 1024;

/// A same-repository branch and its frozen head. Base is observed, not atomically guarded.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Target {
    /// Exact owner/repository.
    pub repository: String,
    /// Head branch, without refs/heads prefix.
    pub head: String,
    /// Base branch, without refs/heads prefix.
    pub base: String,
    /// Expected full Git object id.
    pub head_sha: String,
}
/// Validated PR identity, suitable for a protected journal receipt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PullRequest {
    /// Positive pull number.
    pub number: u64,
    /// Repository identity.
    pub repository: String,
    /// Head branch identity.
    pub head: String,
    /// Base branch identity.
    pub base: String,
    /// Exact head commit.
    pub head_sha: String,
    /// Base commit observed during this read; no atomic merge guard is implied.
    pub base_sha: String,
    /// Provider state: open or closed.
    pub state: String,
    /// Whether GitHub records a completed merge.
    pub merged: bool,
    /// Recorded merge commit when merged.
    pub merge_sha: Option<String>,
}
/// Successful squash merge response; errors never establish that no write happened.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MergeReceipt {
    /// Provider-confirmed resulting commit.
    pub sha: String,
}
/// Conservative required-context state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckState {
    /// All selected providers report explicit success.
    Success,
    /// An identified context has not completed.
    Pending,
    /// Explicit failure, including cancellation/skipping/neutral.
    Failure,
    /// Missing, malformed or ambiguous identity/status.
    Unknown,
}
/// One configured context, never inferred from a display summary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContextCheck {
    /// Configured exact context name.
    pub name: String,
    /// Conservative normalized state.
    pub state: CheckState,
}
/// Complete bounded context membership for the exact commit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Checks {
    /// Exact queried commit.
    pub sha: String,
    /// True only when every configured context explicitly succeeds.
    pub passed: bool,
    /// One entry per required name.
    pub contexts: Vec<ContextCheck>,
}
fn invalid() -> ConnectorError {
    ConnectorError::BadResponse(
        "GitHub landing identity or complete membership could not be established".into(),
    )
}
fn bad_args() -> ConnectorError {
    ConnectorError::BadArgs(
        "Landing requires bounded exact repository, branch, SHA and context identities".into(),
    )
}
fn sha(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}
#[allow(clippy::case_sensitive_file_extension_comparisons)] // Git ref grammar reserves the literal .lock suffix.
fn branch(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && !value.starts_with('-')
        && !value.starts_with('/')
        && !value.ends_with('/')
        && !value.ends_with('.')
        && !value.contains("..")
        && !value.contains("@{")
        && !value.contains("//")
        && value != "@"
        && value
            .split('/')
            .all(|part| !part.starts_with('.') && !part.ends_with(".lock"))
        && !value
            .chars()
            .any(|c| c.is_control() || c.is_whitespace() || "~^:?*[\\".contains(c))
}
fn repo(value: &str) -> Result<(&str, &str), ConnectorError> {
    let (owner, name) = value.split_once('/').ok_or_else(bad_args)?;
    if [owner, name].iter().any(|v| {
        v.is_empty()
            || v.len() > 100
            || *v == "."
            || *v == ".."
            || !v
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
    }) {
        return Err(bad_args());
    }
    Ok((owner, name))
}
fn validate(target: &Target) -> Result<(), ConnectorError> {
    repo(&target.repository)?;
    if !branch(&target.head)
        || !branch(&target.base)
        || target.head == target.base
        || !sha(&target.head_sha)
    {
        return Err(bad_args());
    }
    Ok(())
}
fn text<'a>(value: &'a Value, pointer: &str) -> Result<&'a str, ConnectorError> {
    value
        .pointer(pointer)
        .and_then(Value::as_str)
        .ok_or_else(invalid)
}
fn receipt(
    target: &Target,
    value: &Value,
    number: Option<u64>,
) -> Result<PullRequest, ConnectorError> {
    let found = value["number"]
        .as_u64()
        .filter(|n| *n > 0)
        .ok_or_else(invalid)?;
    let state = text(value, "/state")?;
    let base_sha = text(value, "/base/sha")?;
    if number.is_some_and(|n| n != found)
        || !matches!(state, "open" | "closed")
        || !sha(base_sha)
        || text(value, "/head/repo/full_name")? != target.repository
        || text(value, "/base/repo/full_name")? != target.repository
        || text(value, "/head/ref")? != target.head
        || text(value, "/base/ref")? != target.base
        || text(value, "/head/sha")? != target.head_sha
    {
        return Err(invalid());
    }
    let merged = match value.get("merged") {
        Some(Value::Bool(merged)) => *merged,
        None => match value.get("merged_at") {
            Some(Value::Null) => false,
            Some(Value::String(value)) if !value.is_empty() && value.len() <= 64 => true,
            _ => return Err(invalid()),
        },
        _ => return Err(invalid()),
    };
    let merge_sha = if merged {
        let merged_sha = text(value, "/merge_commit_sha")?;
        if state != "closed" || !sha(merged_sha) {
            return Err(invalid());
        }
        Some(merged_sha.to_owned())
    } else {
        None
    };
    Ok(PullRequest {
        number: found,
        repository: target.repository.clone(),
        head: target.head.clone(),
        base: target.base.clone(),
        head_sha: target.head_sha.clone(),
        base_sha: base_sha.into(),
        state: state.into(),
        merged,
        merge_sha,
    })
}
async fn send(
    conn: &Connection,
    segments: &[&str],
    query: &[(&str, &str)],
    body: Option<(Method, Value)>,
    transport: &dyn HttpTransport,
    deadline: Instant,
) -> Result<Value, ConnectorError> {
    let mut url = endpoint(&conn.base_url, segments)?;
    if !query.is_empty() {
        url.query_pairs_mut().extend_pairs(query.iter().copied());
    }
    let mut req = request(ConnectorId::Github, conn, url, RESPONSE_LIMIT)?;
    let expected = if let Some((method, body)) = body {
        let bytes = serde_json::to_vec(&body).map_err(|_| bad_args())?;
        if bytes.len() > 16 * 1024 {
            return Err(bad_args());
        }
        req.method = method;
        req.body = Some(bytes);
        req.headers
            .push(("Content-Type".into(), "application/json".into()));
        if method == Method::Post { 201 } else { 200 }
    } else {
        200
    };
    let response = transport.send(req, deadline).await?;
    if response.body.len() as u64 > RESPONSE_LIMIT {
        return Err(ConnectorError::TooLarge {
            bytes: response.body.len() as u64,
            maximum: RESPONSE_LIMIT,
        });
    }
    if (300..400).contains(&response.status) {
        return Err(invalid());
    }
    // Never retain server error bodies: they may echo credentials or mutation input.
    let sanitized = crate::HttpResponse {
        status: response.status,
        headers: response.headers.clone(),
        body: Vec::new(),
    };
    check_status(&sanitized)?;
    if response.status != expected
        || response
            .header("link")
            .is_some_and(|v| v.contains("rel=\"next\"") || v.contains("rel=next"))
    {
        return Err(invalid());
    }
    serde_json::from_slice(&response.body).map_err(|_| invalid())
}
/// Read exactly one PR (one GET); never mutates.
pub async fn read_pull_request(
    conn: &Connection,
    target: &Target,
    number: u64,
    transport: &dyn HttpTransport,
    deadline: Instant,
) -> Result<PullRequest, ConnectorError> {
    validate(target)?;
    if number == 0 {
        return Err(bad_args());
    }
    let (owner, name) = repo(&target.repository)?;
    let value = send(
        conn,
        &["repos", owner, name, "pulls", &number.to_string()],
        &[],
        None,
        transport,
        deadline,
    )
    .await?;
    receipt(target, &value, Some(number))
}
/// Find the uniquely matching head/base/SHA across one complete bounded page (one GET).
/// A full page or provider continuation refuses rather than declaring absence.
pub async fn find_pull_request(
    conn: &Connection,
    target: &Target,
    transport: &dyn HttpTransport,
    deadline: Instant,
) -> Result<Option<PullRequest>, ConnectorError> {
    validate(target)?;
    let (owner, name) = repo(&target.repository)?;
    let head = format!("{owner}:{}", target.head);
    let value = send(
        conn,
        &["repos", owner, name, "pulls"],
        &[
            ("state", "all"),
            ("head", &head),
            ("base", &target.base),
            ("per_page", "100"),
        ],
        None,
        transport,
        deadline,
    )
    .await?;
    let items = value
        .as_array()
        .filter(|items| items.len() < 100)
        .ok_or_else(invalid)?;
    let mut found = None;
    for item in items {
        // A provider ignoring the requested branch/repository filter is not absence.
        if text(item, "/head/repo/full_name")? != target.repository
            || text(item, "/base/repo/full_name")? != target.repository
            || text(item, "/head/ref")? != target.head
            || text(item, "/base/ref")? != target.base
        {
            return Err(invalid());
        }
        if text(item, "/head/sha")? != target.head_sha {
            if text(item, "/state")? != "closed" {
                return Err(invalid());
            }
            continue;
        }
        if found.is_some() {
            return Err(invalid());
        }
        found = Some(receipt(target, item, None)?);
    }
    Ok(found)
}
/// Create one PR (one POST); the caller must journal intent before calling.
pub async fn create_pull_request(
    conn: &Connection,
    target: &Target,
    title: &str,
    transport: &dyn HttpTransport,
    deadline: Instant,
) -> Result<PullRequest, ConnectorError> {
    validate(target)?;
    if title.is_empty() || title.len() > 256 || title.chars().any(char::is_control) {
        return Err(bad_args());
    }
    let (owner, name) = repo(&target.repository)?;
    let value=send(conn,&["repos",owner,name,"pulls"],&[],Some((Method::Post,json!({"head":target.head,"base":target.base,"title":title,"maintainer_can_modify":false}))),transport,deadline).await?;
    let receipt = receipt(target, &value, None)?;
    if receipt.state != "open" || receipt.merged {
        return Err(invalid());
    }
    Ok(receipt)
}
/// Squash merge with GitHub's atomic expected-head guard (one PUT).
/// This endpoint provides no atomic expected-base guard.
pub async fn merge_pull_request(
    conn: &Connection,
    target: &Target,
    number: u64,
    transport: &dyn HttpTransport,
    deadline: Instant,
) -> Result<MergeReceipt, ConnectorError> {
    validate(target)?;
    if number == 0 {
        return Err(bad_args());
    }
    let (owner, name) = repo(&target.repository)?;
    let value = send(
        conn,
        &["repos", owner, name, "pulls", &number.to_string(), "merge"],
        &[],
        Some((
            Method::Put,
            json!({"sha":target.head_sha,"merge_method":"squash"}),
        )),
        transport,
        deadline,
    )
    .await?;
    let merged_sha = text(&value, "/sha")?;
    if value["merged"] != true || !sha(merged_sha) {
        return Err(invalid());
    }
    Ok(MergeReceipt {
        sha: merged_sha.into(),
    })
}
/// Read exact-SHA check runs and latest commit statuses (two GETs).
/// Any incomplete membership refuses; duplicate providers cannot produce green.
pub async fn required_checks(
    conn: &Connection,
    repository: &str,
    commit: &str,
    required: &[String],
    transport: &dyn HttpTransport,
    deadline: Instant,
) -> Result<Checks, ConnectorError> {
    let (owner, name) = repo(repository)?;
    if !sha(commit)
        || required.is_empty()
        || required.len() > 64
        || required
            .iter()
            .any(|s| s.is_empty() || s.len() > 128 || s.chars().any(char::is_control))
    {
        return Err(bad_args());
    }
    let mut counts = BTreeMap::new();
    for name in required {
        if counts.insert(name.clone(), Vec::new()).is_some() {
            return Err(bad_args());
        }
    }
    let checks = send(
        conn,
        &["repos", owner, name, "commits", commit, "check-runs"],
        &[("per_page", "100"), ("filter", "latest")],
        None,
        transport,
        deadline,
    )
    .await?;
    let items = members(&checks, "check_runs")?;
    for item in items {
        if text(item, "/head_sha")? != commit {
            return Err(invalid());
        }
        if let Some(states) = counts.get_mut(text(item, "/name")?) {
            states.push(check_state(item));
        }
    }
    let statuses = send(
        conn,
        &["repos", owner, name, "commits", commit, "status"],
        &[("per_page", "100")],
        None,
        transport,
        deadline,
    )
    .await?;
    if text(&statuses, "/sha")? != commit {
        return Err(invalid());
    }
    for item in members(&statuses, "statuses")? {
        if let Some(states) = counts.get_mut(text(item, "/context")?) {
            states.push(match item["state"].as_str() {
                Some("success") => CheckState::Success,
                Some("pending") => CheckState::Pending,
                Some("error" | "failure") => CheckState::Failure,
                _ => CheckState::Unknown,
            });
        }
    }
    let contexts = counts
        .into_iter()
        .map(|(name, states)| ContextCheck {
            name,
            state: if states.len() == 1 {
                states[0]
            } else {
                CheckState::Unknown
            },
        })
        .collect::<Vec<_>>();
    Ok(Checks {
        sha: commit.into(),
        passed: contexts.iter().all(|c| c.state == CheckState::Success),
        contexts,
    })
}
fn members<'a>(value: &'a Value, key: &str) -> Result<&'a [Value], ConnectorError> {
    let items = value[key].as_array().ok_or_else(invalid)?;
    if items.len() > 100 || value["total_count"].as_u64() != Some(items.len() as u64) {
        return Err(invalid());
    }
    Ok(items)
}
fn check_state(item: &Value) -> CheckState {
    match (item["status"].as_str(), item["conclusion"].as_str()) {
        (Some("completed"), Some("success")) => CheckState::Success,
        (
            Some("completed"),
            Some(
                "failure" | "cancelled" | "timed_out" | "action_required" | "neutral" | "skipped"
                | "stale" | "startup_failure",
            ),
        ) => CheckState::Failure,
        (Some("queued" | "in_progress" | "waiting" | "pending" | "requested"), None) => {
            CheckState::Pending
        }
        _ => CheckState::Unknown,
    }
}
