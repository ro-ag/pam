//! Typed landing operations. The daemon must authorize and journal each mutation.
//! Reads never create or merge a PR. A mutation GitHub answered with a
//! validation or conflict status (405, 409, 422) is a definite refusal with a
//! typed cause ([`ConnectorError::Rejected`]); only a failure that leaves the
//! outcome unknown (a lost answer, a server error, an unexpected success body)
//! requires reconciliation. [`definite_refusal`] tells the two apart.
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
/// How a landing merges the pull request: GitHub's `merge_method`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MergeMethod {
    /// One commit on the base with the branch's tree (the default).
    #[default]
    Squash,
    /// A merge commit with both parents.
    Merge,
    /// The branch's commits replayed onto the base.
    Rebase,
}
impl MergeMethod {
    /// Every method, in the order the settings offer them.
    pub const ALL: [Self; 3] = [Self::Squash, Self::Merge, Self::Rebase];
    /// The wire word GitHub and the settings use.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Squash => "squash",
            Self::Merge => "merge",
            Self::Rebase => "rebase",
        }
    }
    /// The method a wire word names.
    #[must_use]
    pub fn parse(word: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|method| method.as_str() == word)
    }
}
/// The merge methods a repository allows, as GitHub reports them on the
/// repository (`allow_squash_merge`, `allow_merge_commit`,
/// `allow_rebase_merge`). `None` means GitHub did not report the field (it
/// omits them for a credential without enough access); only a reported
/// `false` forbids a method.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MergeMethods {
    /// `allow_squash_merge`.
    pub squash: Option<bool>,
    /// `allow_merge_commit`.
    pub merge: Option<bool>,
    /// `allow_rebase_merge`.
    pub rebase: Option<bool>,
}
impl MergeMethods {
    /// What GitHub reported for `method`: `Some(false)` forbids it, `None`
    /// is unreported.
    #[must_use]
    pub fn reported(&self, method: MergeMethod) -> Option<bool> {
        match method {
            MergeMethod::Squash => self.squash,
            MergeMethod::Merge => self.merge,
            MergeMethod::Rebase => self.rebase,
        }
    }
}
/// One required check, matched by name and, when pinned, by the GitHub App
/// that reports it. A pinned requirement is satisfied only by a check run
/// whose `app.id` is `app_id`; a run of the same name from any other app is
/// ignored. A name-only (legacy) requirement still matches any check run or
/// commit status of that name. Serialized as a plain string when unpinned,
/// so an existing name-only list keeps its exact bytes.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "RequiredWire", into = "RequiredWire")]
pub struct RequiredCheck {
    /// Exact check run name or commit status context.
    pub name: String,
    /// The GitHub App id that must report it; `None` is unpinned.
    pub app_id: Option<u64>,
}
impl RequiredCheck {
    /// A name-only requirement.
    #[must_use]
    pub fn named(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            app_id: None,
        }
    }
    /// A requirement pinned to `app_id`.
    #[must_use]
    pub fn pinned(name: impl Into<String>, app_id: u64) -> Self {
        Self {
            name: name.into(),
            app_id: Some(app_id),
        }
    }
}
#[derive(Serialize, Deserialize)]
#[serde(untagged)]
enum RequiredWire {
    Name(String),
    Pinned(PinnedWire),
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PinnedWire {
    name: String,
    app_id: u64,
}
impl TryFrom<RequiredWire> for RequiredCheck {
    type Error = &'static str;
    fn try_from(wire: RequiredWire) -> Result<Self, Self::Error> {
        match wire {
            RequiredWire::Name(name) => Ok(Self::named(name)),
            RequiredWire::Pinned(PinnedWire { app_id: 0, .. }) => {
                Err("a pinned check needs a positive GitHub App id")
            }
            RequiredWire::Pinned(PinnedWire { name, app_id }) => Ok(Self::pinned(name, app_id)),
        }
    }
}
impl From<RequiredCheck> for RequiredWire {
    fn from(check: RequiredCheck) -> Self {
        match check.app_id {
            None => Self::Name(check.name),
            Some(app_id) => Self::Pinned(PinnedWire {
                name: check.name,
                app_id,
            }),
        }
    }
}
/// Successful merge response; errors never establish that no write happened.
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
    /// The GitHub App the requirement is pinned to; absent when unpinned.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app_id: Option<u64>,
    /// Conservative normalized state.
    pub state: CheckState,
    /// Check runs of this name from another app (or with no app identity),
    /// ignored because the requirement is pinned.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub other_apps: u32,
}
#[allow(clippy::trivially_copy_pass_by_ref)] // serde's skip_serializing_if passes a reference.
fn is_zero(value: &u32) -> bool {
    *value == 0
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
/// Which typed mutation a request is, for classifying GitHub's refusals.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Mutation {
    CreatePr,
    Merge,
}
/// A typed definite refusal.
fn rejected(cause: &'static str, detail: &'static str, recovery: &'static str) -> ConnectorError {
    ConnectorError::Rejected {
        cause,
        detail,
        recovery,
    }
}
/// The lower-cased `message` and `errors[].message` texts of a GitHub error
/// body, used only to pick a typed cause; the text itself is never kept.
fn error_messages(body: &[u8]) -> String {
    let Ok(value) = serde_json::from_slice::<Value>(body) else {
        return String::new();
    };
    let mut text = value["message"].as_str().unwrap_or_default().to_owned();
    if let Some(errors) = value["errors"].as_array() {
        for error in errors.iter().take(16) {
            if let Some(message) = error["message"].as_str() {
                text.push('\n');
                text.push_str(message);
            }
        }
    }
    text.truncate(4096);
    text.to_lowercase()
}
/// GitHub's answer to a typed mutation, when it is a definite refusal:
/// 405 (not mergeable, method not allowed), 409 (head modified) and 422
/// (validation failed) mean GitHub received the request and changed nothing.
fn classify_rejection(mutation: Mutation, status: u16, body: &[u8]) -> Option<ConnectorError> {
    if !matches!(status, 405 | 409 | 422) {
        return None;
    }
    let text = error_messages(body);
    Some(match mutation {
        Mutation::CreatePr if text.contains("already exists") => rejected(
            "landing_pr_already_exists",
            "GitHub refused to open the pull request: one already exists for this branch and base. Nothing was created.",
            "Inspect the existing pull request on GitHub; close it, or make its head the frozen commit, then start a new landing ticket, which finds it instead of opening another.",
        ),
        Mutation::CreatePr if text.contains("no commits between") => rejected(
            "landing_pr_no_commits",
            "GitHub refused to open the pull request: the branch has no commits the base does not already have. Nothing was created.",
            "Check whether the frozen commit is already on the base branch; if it is, there is nothing to land.",
        ),
        Mutation::CreatePr => rejected(
            "landing_pr_rejected",
            "GitHub refused the pull request as invalid. Nothing was created.",
            "Compare the branch, base and repository in Settings → Flows → Landing with GitHub, then start a new landing ticket.",
        ),
        Mutation::Merge if status == 409 || text.contains("head branch was modified") => rejected(
            "landing_merge_head_modified",
            "GitHub refused the merge: the pull request head is no longer the frozen commit. Nothing was merged.",
            "Someone pushed to the branch after it was frozen; inspect the branch, then freeze and land its new head with a new ticket.",
        ),
        Mutation::Merge
            if text.contains("not allowed")
                && ["merge commit", "squash", "rebase", "merge method"]
                    .iter()
                    .any(|word| text.contains(word)) =>
        {
            rejected(
                "landing_merge_method_not_allowed",
                "GitHub refused the merge: the repository does not allow this merge method. Nothing was merged.",
                "Choose a merge method the repository allows in Settings → Flows → Landing (or ask the repository's administrator to allow it), then start a new landing ticket.",
            )
        }
        Mutation::Merge if text.contains("status check") => rejected(
            "landing_merge_checks_required",
            "GitHub refused the merge: branch protection still expects required status checks. Nothing was merged.",
            "Add every check branch protection requires to the required PR checks in Settings → Flows → Landing so PAM waits for them, then start a new landing ticket.",
        ),
        Mutation::Merge if text.contains("conflict") => rejected(
            "landing_merge_conflict",
            "GitHub refused the merge: the pull request conflicts with its base. Nothing was merged.",
            "Resolve the conflict on the branch, then freeze and land its new head with a new ticket.",
        ),
        Mutation::Merge if status == 405 => rejected(
            "landing_merge_not_mergeable",
            "GitHub refused the merge: the pull request is not mergeable. Nothing was merged.",
            "Open the pull request on GitHub to see what blocks it (reviews, protection rules, draft state), resolve that, then start a new landing ticket.",
        ),
        Mutation::Merge => rejected(
            "landing_merge_rejected",
            "GitHub refused the merge as invalid. Nothing was merged.",
            "Open the pull request on GitHub to see why it cannot merge, resolve that, then start a new landing ticket.",
        ),
    })
}
/// Whether `error`, returned by a typed mutation ([`create_pull_request`],
/// [`merge_pull_request`]), proves the mutation did not happen: GitHub
/// answered it with a refusal ([`ConnectorError::Rejected`], or a 4xx the
/// shared mapping names: rejected credential, forbidden, not found,
/// throttled, bad request), or the arguments were refused before anything was
/// sent. Everything else (timeouts, transport failures, server errors,
/// redirects, an unexpected success body, a policy stop that may have come
/// after the request left) leaves the outcome unknown.
#[must_use]
pub fn definite_refusal(error: &ConnectorError) -> bool {
    matches!(
        error,
        ConnectorError::Rejected { .. }
            | ConnectorError::Auth
            | ConnectorError::Forbidden
            | ConnectorError::NotFound
            | ConnectorError::RateLimited { .. }
            | ConnectorError::BadArgs(_)
    )
}
async fn send(
    conn: &Connection,
    segments: &[&str],
    query: &[(&str, &str)],
    body: Option<(Method, Value)>,
    transport: &dyn HttpTransport,
    deadline: Instant,
) -> Result<Value, ConnectorError> {
    send_typed(conn, segments, query, body, None, transport, deadline).await
}
async fn send_typed(
    conn: &Connection,
    segments: &[&str],
    query: &[(&str, &str)],
    body: Option<(Method, Value)>,
    mutation: Option<Mutation>,
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
    if let Some(rejection) =
        mutation.and_then(|kind| classify_rejection(kind, response.status, &response.body))
    {
        return Err(rejection);
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
    let value = send_typed(
        conn,
        &["repos", owner, name, "pulls"],
        &[],
        Some((
            Method::Post,
            json!({"head":target.head,"base":target.base,"title":title,"maintainer_can_modify":false}),
        )),
        Some(Mutation::CreatePr),
        transport,
        deadline,
    )
    .await?;
    let receipt = receipt(target, &value, None)?;
    if receipt.state != "open" || receipt.merged {
        return Err(invalid());
    }
    Ok(receipt)
}
/// The merge methods the repository allows (one GET of the repository).
/// The answer must name exactly `repository`; a field of the wrong type
/// refuses rather than reading as unreported.
pub async fn merge_methods(
    conn: &Connection,
    repository: &str,
    transport: &dyn HttpTransport,
    deadline: Instant,
) -> Result<MergeMethods, ConnectorError> {
    let (owner, name) = repo(repository)?;
    let value = send(
        conn,
        &["repos", owner, name],
        &[],
        None,
        transport,
        deadline,
    )
    .await?;
    if text(&value, "/full_name")? != repository {
        return Err(invalid());
    }
    let flag = |field: &str| match value.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Bool(allowed)) => Ok(Some(*allowed)),
        Some(_) => Err(invalid()),
    };
    Ok(MergeMethods {
        squash: flag("allow_squash_merge")?,
        merge: flag("allow_merge_commit")?,
        rebase: flag("allow_rebase_merge")?,
    })
}
/// Merge by `method` with GitHub's atomic expected-head guard (one PUT).
/// This endpoint provides no atomic expected-base guard.
pub async fn merge_pull_request(
    conn: &Connection,
    target: &Target,
    number: u64,
    method: MergeMethod,
    transport: &dyn HttpTransport,
    deadline: Instant,
) -> Result<MergeReceipt, ConnectorError> {
    validate(target)?;
    if number == 0 {
        return Err(bad_args());
    }
    let (owner, name) = repo(&target.repository)?;
    let value = send_typed(
        conn,
        &["repos", owner, name, "pulls", &number.to_string(), "merge"],
        &[],
        Some((
            Method::Put,
            json!({"sha":target.head_sha,"merge_method":method.as_str()}),
        )),
        Some(Mutation::Merge),
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
/// Whether `required` needs the commit status API: only a name-only
/// requirement can be satisfied by a status, which carries no app identity.
#[must_use]
pub fn needs_statuses(required: &[RequiredCheck]) -> bool {
    required.iter().any(|check| check.app_id.is_none())
}
/// Read exact-SHA check runs and, when a requirement is name-only, the latest
/// commit statuses (one or two GETs). Any incomplete membership refuses;
/// duplicate providers cannot produce green, and a check run from another
/// app never satisfies a pinned requirement.
pub async fn required_checks(
    conn: &Connection,
    repository: &str,
    commit: &str,
    required: &[RequiredCheck],
    transport: &dyn HttpTransport,
    deadline: Instant,
) -> Result<Checks, ConnectorError> {
    let (owner, name) = repo(repository)?;
    if !sha(commit)
        || required.is_empty()
        || required.len() > 64
        || required.iter().any(|check| {
            check.name.is_empty()
                || check.name.len() > 128
                || check.name.chars().any(char::is_control)
                || check.app_id == Some(0)
        })
    {
        return Err(bad_args());
    }
    let mut counts: BTreeMap<String, (Option<u64>, Vec<CheckState>, u32)> = BTreeMap::new();
    for check in required {
        if counts
            .insert(check.name.clone(), (check.app_id, Vec::new(), 0))
            .is_some()
        {
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
        if let Some((pinned, states, other_apps)) = counts.get_mut(text(item, "/name")?) {
            match pinned {
                Some(app) if item.pointer("/app/id").and_then(Value::as_u64) != Some(*app) => {
                    *other_apps = other_apps.saturating_add(1);
                }
                _ => states.push(check_state(item)),
            }
        }
    }
    if needs_statuses(required) {
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
            if let Some((None, states, _)) = counts.get_mut(text(item, "/context")?) {
                states.push(match item["state"].as_str() {
                    Some("success") => CheckState::Success,
                    Some("pending") => CheckState::Pending,
                    Some("error" | "failure") => CheckState::Failure,
                    _ => CheckState::Unknown,
                });
            }
        }
    }
    let contexts = counts
        .into_iter()
        .map(|(name, (app_id, states, other_apps))| ContextCheck {
            name,
            app_id,
            state: if states.len() == 1 {
                states[0]
            } else {
                CheckState::Unknown
            },
            other_apps,
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
