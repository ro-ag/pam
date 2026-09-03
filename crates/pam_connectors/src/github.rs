//! GitHub Actions: which runs failed, which jobs in a run failed, and the
//! log of one failing job.
//!
//! The three calls are meant to be chained, and the `ci-failure-triage`
//! starter flow chains them: `runs` finds the newest failed run, `run` lists
//! that run's jobs failed-first so `jobs[0]` is the one to look at, and
//! `job_log` fetches that job's log.

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

/// Runs one GitHub call.
pub(crate) async fn call(
    conn: &Connection,
    call: &str,
    args: &BTreeMap<String, ArgValue>,
    transport: &dyn HttpTransport,
    deadline: Instant,
) -> Result<CallResult, ConnectorError> {
    match call {
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
    let mut url = endpoint(&conn.base_url, &["repos", &owner, &name, "actions", "runs"])?;
    url.query_pairs_mut()
        .append_pair("status", status)
        .append_pair("per_page", &limit.to_string());
    let body = get_json(conn, ID, url, transport, deadline).await?;
    let runs: Vec<Value> = array_field(&body, "workflow_runs")?
        .iter()
        .take(usize::try_from(limit).unwrap_or(usize::MAX))
        .map(|run| pick(run, RUN_FIELDS))
        .collect();
    Ok(CallResult::Json(json!({ "runs": runs })))
}

/// The run itself, plus its jobs with the failing ones first.
async fn run(
    conn: &Connection,
    args: &BTreeMap<String, ArgValue>,
    transport: &dyn HttpTransport,
    deadline: Instant,
) -> Result<CallResult, ConnectorError> {
    let (owner, name) = repo(args)?;
    let run_id = id_arg(args, "run_id")?;
    let run_url = endpoint(
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
    let run = get_json(conn, ID, run_url, transport, deadline).await?;
    let attempt = run
        .get("run_attempt")
        .and_then(Value::as_i64)
        .filter(|attempt| *attempt > 0)
        .unwrap_or(1);

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
        .append_pair("per_page", &MAX_JOBS.to_string());
    let jobs_body = get_json(conn, ID, jobs_url, transport, deadline).await?;

    let mut jobs: Vec<Value> = array_field(&jobs_body, "jobs")?
        .iter()
        .map(|job| pick(job, JOB_FIELDS))
        .collect();
    // Stable, so jobs that rank the same keep the order GitHub sent, and a
    // flow's `jobs[0]` is the failing job rather than the first job.
    jobs.sort_by_key(|job| failure_rank(job.get("conclusion").and_then(Value::as_str)));

    Ok(CallResult::Json(json!({
        "run": pick(&run, RUN_FIELDS),
        "jobs": jobs,
    })))
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
