//! GitHub Actions: which runs failed, which jobs in a run failed, and the
//! log of one failing job.
//!
//! The three calls are meant to be chained, and the `ci-failure-triage`
//! starter flow chains them: `runs` finds the newest failed run, `run` lists
//! one attempt's bounded jobs page. Failure ordering applies only within that
//! page: a partial page cannot establish that the run has no failing jobs.
//! `job_log` fetches a selected job's log. No call aggregates pages implicitly.

use std::collections::BTreeMap;
use std::time::Instant;

use pam_flow::{ArgValue, ConnectorId};
use serde_json::{Value, json};
use url::Url;

use crate::error::ConnectorError;
use crate::transport::{
    Connection, HttpTransport, MAX_LOG_BYTES, array_field, check_status, endpoint, get_json,
    id_arg, int_arg, opt_text_arg, pick, request, string_field, text_arg,
};
use crate::{CallResult, VerifyReport, unknown_call};

/// The connector this module serves.
const ID: ConnectorId = ConnectorId::Github;

/// The fields kept from a workflow run.
const RUN_FIELDS: &[&str] = &[
    "id",
    "name",
    "status",
    "conclusion",
    "html_url",
    "head_sha",
    "created_at",
    "run_attempt",
];

/// The fields kept from a job.
const JOB_FIELDS: &[&str] = &["id", "name", "status", "conclusion"];

/// The most jobs a `run` call reads back.
const MAX_JOBS: i64 = 100;
/// Explicit pagination is bounded even when the server reports more records.
const MAX_PAGE: i64 = 10_000;

/// Runs one GitHub call.
pub(crate) async fn call(
    conn: &Connection,
    call: &str,
    args: &BTreeMap<String, ArgValue>,
    transport: &dyn HttpTransport,
    deadline: Instant,
) -> Result<CallResult, ConnectorError> {
    match call {
        "run_status" => run_status(conn, args, transport, deadline).await,
        "runs" => runs(conn, args, transport, deadline).await,
        "run" => run(conn, args, transport, deadline).await,
        "job_log" => job_log(conn, args, transport, deadline).await,
        other => Err(unknown_call(ID, other)),
    }
}

/// `GET /repos/{repo}/actions/runs?status=…&per_page=…`.
async fn runs(
    conn: &Connection,
    args: &BTreeMap<String, ArgValue>,
    transport: &dyn HttpTransport,
    deadline: Instant,
) -> Result<CallResult, ConnectorError> {
    let (owner, name) = repo(args)?;
    let status = opt_text_arg(args, "status")?.unwrap_or("failure");
    let limit = int_arg(args, "limit", 5, (1, 100))?;
    let page = int_arg(args, "page", 1, (1, MAX_PAGE))?;
    let mut url = endpoint(&conn.base_url, &["repos", &owner, &name, "actions", "runs"])?;
    url.query_pairs_mut()
        .append_pair("status", status)
        .append_pair("per_page", &limit.to_string())
        .append_pair("page", &page.to_string());
    let body = get_json(conn, ID, url, transport, deadline).await?;
    let received = array_field(&body, "workflow_runs")?;
    let runs: Vec<Value> = received
        .iter()
        .take(usize::try_from(limit).unwrap_or(usize::MAX))
        .map(|run| pick(run, RUN_FIELDS))
        .collect();
    let mut result = page_coverage(&body, page, limit, received.len());
    result["runs"] = json!(runs);
    Ok(CallResult::Json(result))
}

/// A run attempt and one jobs page; never infer an attempt from missing data.
/// Uses GitHub's documented attempt-specific run and jobs endpoints:
/// <https://docs.github.com/en/rest/actions/workflow-runs#get-a-workflow-run-attempt>
/// <https://docs.github.com/en/rest/actions/workflow-jobs#list-jobs-for-a-workflow-run-attempt>
async fn run(
    conn: &Connection,
    args: &BTreeMap<String, ArgValue>,
    transport: &dyn HttpTransport,
    deadline: Instant,
) -> Result<CallResult, ConnectorError> {
    let (owner, name) = repo(args)?;
    let run_id = id_arg(args, "run_id")?;
    let page = int_arg(args, "page", 1, (1, MAX_PAGE))?;
    let pinned = args
        .contains_key("run_attempt")
        .then(|| int_arg(args, "run_attempt", 1, (1, i64::MAX)))
        .transpose()?;
    if page > 1 && pinned.is_none() {
        return Err(ConnectorError::BadArgs(
            "`run_attempt` is required after page 1; reuse the captured attempt".to_owned(),
        ));
    }
    let mut run_url = endpoint(
        &conn.base_url,
        &[
            "repos",
            &owner,
            &name,
            "actions",
            "runs",
            &run_id.to_string(),
        ],
    )?;
    if let Some(attempt) = pinned {
        run_url
            .path_segments_mut()
            .map_err(|()| {
                ConnectorError::BadArgs("GitHub base URL cannot carry path segments".to_owned())
            })?
            .extend(["attempts", &attempt.to_string()]);
    }
    let run = get_json(conn, ID, run_url, transport, deadline).await?;
    let attempt = validated_attempt(&run, run_id, pinned, &format!("{owner}/{name}"))?;
    let mut jobs_url = endpoint(
        &conn.base_url,
        &[
            "repos",
            &owner,
            &name,
            "actions",
            "runs",
            &run_id.to_string(),
            "attempts",
            &attempt.to_string(),
            "jobs",
        ],
    )?;
    jobs_url
        .query_pairs_mut()
        .append_pair("per_page", &MAX_JOBS.to_string())
        .append_pair("page", &page.to_string());
    let jobs_body = get_json(conn, ID, jobs_url, transport, deadline).await?;
    let received = array_field(&jobs_body, "jobs")?;
    let mut jobs: Vec<Value> = received
        .iter()
        .take(usize::try_from(MAX_JOBS).expect("positive bounded job limit"))
        .map(|job| pick(job, JOB_FIELDS))
        .collect();
    // Stable ordering within this page only; unseen pages can contain failures.
    jobs.sort_by_key(|job| failure_rank(job.get("conclusion").and_then(Value::as_str)));
    let mut result = page_coverage(&jobs_body, page, MAX_JOBS, received.len());
    result["run"] = reported_run(&run);
    result["source_identity"] = github_identity(&run);
    result["run_id"] = json!(run_id);
    result["run_attempt"] = json!(attempt);
    result["jobs"] = json!(jobs);
    result["ordering"] = json!("failure_first_within_page");
    result["coverage"]["snapshot"] = json!("single_jobs_response");
    Ok(CallResult::Json(result))
}

fn validated_attempt(
    run: &Value,
    run_id: i64,
    pinned: Option<i64>,
    repository: &str,
) -> Result<i64, ConnectorError> {
    let attempt = run
        .get("run_attempt")
        .and_then(Value::as_i64)
        .filter(|value| *value > 0)
        .ok_or_else(|| {
            ConnectorError::BadResponse(
                "GitHub run metadata has no valid positive run_attempt".to_owned(),
            )
        })?;
    if pinned.is_some_and(|pinned| pinned != attempt)
        || run.get("id").is_some_and(|id| id.as_i64() != Some(run_id))
        || run.pointer("/repository/full_name").is_some_and(|name| {
            !name
                .as_str()
                .is_some_and(|name| name.eq_ignore_ascii_case(repository))
        })
    {
        return Err(ConnectorError::BadResponse(
            "GitHub run metadata does not match the requested run, attempt, or repository"
                .to_owned(),
        ));
    }
    Ok(attempt)
}

/// Coverage is about this response's reported collection, not a pass verdict or
/// a stable snapshot across requests. Missing/malformed totals never mean zero.
fn page_coverage(body: &Value, page: i64, limit: i64, received: usize) -> Value {
    let page = u64::try_from(page).expect("validated page");
    let limit = u64::try_from(limit).expect("validated page size");
    let received = u64::try_from(received).unwrap_or(u64::MAX);
    let returned = received.min(limit);
    let offset = (page - 1) * limit;
    let total = body.get("total_count").and_then(Value::as_u64);
    let has_more = total.map(|total| offset.saturating_add(returned) < total);
    let next = (has_more == Some(true) || (has_more.is_none() && returned == limit))
        .then_some(page + 1)
        .filter(|next| *next <= u64::try_from(MAX_PAGE).unwrap());
    let mut gaps = Vec::new();
    if page > 1 {
        gaps.push("previous_pages_not_included");
    }
    if total.is_none() {
        gaps.push("total_count_unavailable");
    }
    if total.is_some_and(|total| received != total.saturating_sub(offset).min(limit)) {
        gaps.push("total_count_inconsistent");
    }
    if has_more == Some(true) {
        gaps.push("later_pages_not_included");
    }
    if received > limit {
        gaps.push("response_array_truncated");
    }
    if next.is_none() && (has_more == Some(true) || (has_more.is_none() && returned == limit)) {
        gaps.push("page_limit_reached");
    }
    json!({
        "page": page, "per_page": limit, "total_count": total,
        "next_page": next, "partial": !gaps.is_empty(),
        "coverage": {
            "complete": gaps.is_empty(), "basis": "single_response_reported_total",
            "returned": returned, "received": received, "omitted": received.saturating_sub(returned),
            "has_more": has_more, "gaps": gaps,
        },
    })
}

/// One job's log, with the exit status its conclusion implies.
async fn job_log(
    conn: &Connection,
    args: &BTreeMap<String, ArgValue>,
    transport: &dyn HttpTransport,
    deadline: Instant,
) -> Result<CallResult, ConnectorError> {
    let (owner, name) = repo(args)?;
    let job_id = id_arg(args, "job_id")?;
    let job_url = job_endpoint(&conn.base_url, &owner, &name, job_id, None)?;
    let job = get_json(conn, ID, job_url, transport, deadline).await?;
    let exit_status = exit_status(job.get("conclusion").and_then(Value::as_str));

    let log_url = job_endpoint(&conn.base_url, &owner, &name, job_id, Some("logs"))?;
    let mut log_request = request(ID, conn, log_url, MAX_LOG_BYTES)?;
    // GitHub answers with a redirect to signed storage; the signature is the
    // credential there, so pam's own header must not travel with it.
    log_request.follow_one_https_redirect_without_auth = true;
    let response = transport.send(log_request, deadline).await?;
    check_status(&response)?;
    let bytes = u64::try_from(response.body.len()).unwrap_or(u64::MAX);
    if bytes > MAX_LOG_BYTES {
        return Err(ConnectorError::TooLarge {
            bytes,
            maximum: MAX_LOG_BYTES,
        });
    }

    Ok(CallResult::Log {
        name: format!("github-job-{job_id}.log"),
        bytes: response.body,
        exit_status,
    })
}

/// `GET /user` — who this token belongs to.
pub(crate) async fn verify(
    conn: &Connection,
    transport: &dyn HttpTransport,
    deadline: Instant,
) -> Result<VerifyReport, ConnectorError> {
    let url = endpoint(&conn.base_url, &["user"])?;
    let body = get_json(conn, ID, url, transport, deadline).await?;
    let login = string_field(&body, "login")?;
    Ok(VerifyReport {
        detail: format!("authenticated as {login}"),
    })
}

/// `/repos/{owner}/{name}/actions/jobs/{id}[/{tail}]`.
fn job_endpoint(
    base: &Url,
    owner: &str,
    name: &str,
    job_id: i64,
    tail: Option<&str>,
) -> Result<Url, ConnectorError> {
    let job = job_id.to_string();
    let mut segments = vec!["repos", owner, name, "actions", "jobs", job.as_str()];
    if let Some(tail) = tail {
        segments.push(tail);
    }
    endpoint(base, &segments)
}

/// Splits the `repo` argument into owner and name.
fn repo(args: &BTreeMap<String, ArgValue>) -> Result<(String, String), ConnectorError> {
    let raw = text_arg(args, "repo")?;
    let mut parts = raw.split('/');
    let owner = parts.next().unwrap_or_default();
    let name = parts.next().unwrap_or_default();
    let ok = parts.next().is_none()
        && !owner.is_empty()
        && !name.is_empty()
        && !raw.contains(char::is_whitespace);
    if !ok {
        return Err(ConnectorError::BadArgs(format!(
            "`repo` must be `owner/name`, not `{raw}`"
        )));
    }
    Ok((owner.to_owned(), name.to_owned()))
}

/// Sort key that puts outright failures first, then the other bad endings.
fn failure_rank(conclusion: Option<&str>) -> u8 {
    match conclusion {
        Some("failure") => 0,
        Some("cancelled" | "timed_out") => 1,
        _ => 2,
    }
}

/// The exit status a job's conclusion implies.
fn exit_status(conclusion: Option<&str>) -> Option<i32> {
    match conclusion {
        Some("failure" | "cancelled" | "timed_out") => Some(1),
        Some("success") => Some(0),
        _ => None,
    }
}

fn bounded_repository(repository: &Value) -> Value {
    let mut value = serde_json::Map::new();
    if let Some(id) = repository.get("id").and_then(Value::as_u64) {
        value.insert("id".into(), json!(id));
    }
    for key in ["full_name", "html_url", "clone_url", "url"] {
        if let Some(text) = repository
            .get(key)
            .and_then(Value::as_str)
            .filter(|text| text.len() <= 2048 && !text.chars().any(char::is_control))
        {
            value.insert(key.into(), json!(text));
        }
    }
    Value::Object(value)
}

fn reported_run(run: &Value) -> Value {
    let mut result = pick(run, RUN_FIELDS);
    result["repository"] = bounded_repository(&run["repository"]);
    result["head_repository"] = bounded_repository(&run["head_repository"]);
    let prs = run.get("pull_requests").and_then(Value::as_array);
    result["pull_requests_partial"] = json!(prs.is_some_and(|prs| prs.len() > 16));
    result["pull_requests"] = Value::Array(
        prs.into_iter()
            .flatten()
            .take(16)
            .map(|pr| {
                let mut head = serde_json::Map::new();
                for key in ["sha", "ref"] {
                    if let Some(text) = pr["head"]
                        .get(key)
                        .and_then(Value::as_str)
                        .filter(|text| text.len() <= 2048 && !text.chars().any(char::is_control))
                    {
                        head.insert(key.into(), json!(text));
                    }
                }
                head.insert("repo".into(), bounded_repository(&pr["head"]["repo"]));
                json!({"number":pr.get("number").and_then(Value::as_u64),"head":head})
            })
            .collect(),
    );
    result
}

fn github_identity(run: &Value) -> Value {
    // head_repository is the source of the reported head; repository is the
    // workflow owner and can differ for fork PRs. Never collapse their names.
    let repository = run.get("head_repository");
    let url = repository.and_then(|repo| repo.get("clone_url").or_else(|| repo.get("html_url")));
    crate::jenkins_investigation::source_identity(
        url.into_iter().cloned().collect(),
        run.get("head_sha").into_iter().cloned().collect(),
        false,
    )
}

/// One exact-attempt status read, without job enumeration or logs.
async fn run_status(
    conn: &Connection,
    args: &BTreeMap<String, ArgValue>,
    transport: &dyn HttpTransport,
    deadline: Instant,
) -> Result<CallResult, ConnectorError> {
    let (owner, name) = repo(args)?;
    let run_id = id_arg(args, "run_id")?;
    let attempt = id_arg(args, "run_attempt")?;
    let url = endpoint(
        &conn.base_url,
        &[
            "repos",
            &owner,
            &name,
            "actions",
            "runs",
            &run_id.to_string(),
            "attempts",
            &attempt.to_string(),
        ],
    )?;
    let run = get_json(conn, ID, url, transport, deadline).await?;
    if run["id"].as_i64() != Some(run_id)
        || run
            .pointer("/repository/full_name")
            .and_then(Value::as_str)
            .is_none()
    {
        return Err(ConnectorError::BadResponse(
            "GitHub status omitted run or repository identity".to_owned(),
        ));
    }
    validated_attempt(&run, run_id, Some(attempt), &format!("{owner}/{name}"))?;
    let status = run["status"]
        .as_str()
        .ok_or_else(|| ConnectorError::BadResponse("GitHub status is missing".to_owned()))?;
    let watch_state = match status {
        "queued" | "requested" | "waiting" | "pending" | "in_progress"
            if run.get("conclusion") == Some(&Value::Null) =>
        {
            "pending"
        }
        "completed"
            if run["conclusion"].as_str().is_some_and(|v| {
                matches!(
                    v,
                    "success"
                        | "failure"
                        | "neutral"
                        | "cancelled"
                        | "skipped"
                        | "timed_out"
                        | "action_required"
                        | "stale"
                        | "startup_failure"
                )
            }) =>
        {
            "terminal"
        }
        _ => {
            return Err(ConnectorError::BadResponse(
                "GitHub status or conclusion is unknown or inconsistent".to_owned(),
            ));
        }
    };
    let mut observed = reported_run(&run);
    // Watch observations retain bounded reported identity, never arbitrary run fields.
    for key in ["name", "html_url", "head_sha", "created_at"] {
        if !observed[key]
            .as_str()
            .is_some_and(|text| text.len() <= 2048)
        {
            observed
                .as_object_mut()
                .expect("run projection")
                .remove(key);
        }
    }
    Ok(CallResult::Json(
        json!({"schema_version":1,"watch_state":watch_state,"status":status,"conclusion":run["conclusion"],"run_id":run_id,"run_attempt":attempt,"run":observed,"source_identity":github_identity(&run),"coverage":{"requests":1,"jobs_collected":false,"logs_collected":false}}),
    ))
}
