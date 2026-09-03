//! Jenkins: what jobs exist, how a job's recent builds went, and the console
//! text of one build.
//!
//! Jenkins nests jobs inside folders and spells the nesting in the URL, so
//! the `job` argument is written the way a human says it — `platform/build`
//! — and turned into `/job/platform/job/build` here.

use std::collections::BTreeMap;
use std::time::Instant;

use pam_flow::{ArgValue, ConnectorId};
use serde_json::{Value, json};
use url::Url;

use crate::error::ConnectorError;
use crate::transport::{
    Connection, HttpTransport, MAX_LOG_BYTES, array_field, check_status, endpoint, get_json,
    id_arg, int_arg, pick, request, string_field, text_arg,
};
use crate::{CallResult, VerifyReport, unknown_call};

/// The connector this module serves.
const ID: ConnectorId = ConnectorId::Jenkins;

/// The fields kept from a job listing.
const JOB_FIELDS: &[&str] = &["name", "url", "color"];

/// The fields kept from a build.
const BUILD_FIELDS: &[&str] = &["number", "result", "timestamp", "duration", "url"];

/// Runs one Jenkins call.
pub(crate) async fn call(
    conn: &Connection,
    call: &str,
    args: &BTreeMap<String, ArgValue>,
    transport: &dyn HttpTransport,
    deadline: Instant,
) -> Result<CallResult, ConnectorError> {
    match call {
        "jobs" => jobs(conn, args, transport, deadline).await,
        "builds" => builds(conn, args, transport, deadline).await,
        "console" => console(conn, args, transport, deadline).await,
        other => Err(unknown_call(ID, other)),
    }
}

/// `GET /api/json?tree=jobs[…]{0,limit}`.
async fn jobs(
    conn: &Connection,
    args: &BTreeMap<String, ArgValue>,
    transport: &dyn HttpTransport,
    deadline: Instant,
) -> Result<CallResult, ConnectorError> {
    let limit = int_arg(args, "limit", 50, (1, 200))?;
    let mut url = endpoint(&conn.base_url, &["api", "json"])?;
    url.query_pairs_mut()
        .append_pair("tree", &format!("jobs[name,url,color]{{0,{limit}}}"));
    let body = get_json(conn, ID, url, transport, deadline).await?;
    let jobs: Vec<Value> = array_field(&body, "jobs")?
        .iter()
        .map(|job| pick(job, JOB_FIELDS))
        .collect();
    Ok(CallResult::Json(json!({ "jobs": jobs })))
}

/// `GET /job/…/api/json?tree=builds[…]{0,limit}`.
async fn builds(
    conn: &Connection,
    args: &BTreeMap<String, ArgValue>,
    transport: &dyn HttpTransport,
    deadline: Instant,
) -> Result<CallResult, ConnectorError> {
    let job = text_arg(args, "job")?.to_owned();
    let limit = int_arg(args, "limit", 20, (1, 100))?;
    let mut segments = job_segments(&job)?;
    segments.push("api".to_owned());
    segments.push("json".to_owned());
    let mut url = job_url(&conn.base_url, &segments)?;
    url.query_pairs_mut().append_pair(
        "tree",
        &format!("builds[number,result,timestamp,duration,url]{{0,{limit}}}"),
    );
    let body = get_json(conn, ID, url, transport, deadline).await?;
    let builds: Vec<Value> = array_field(&body, "builds")?
        .iter()
        .map(|build| pick(build, BUILD_FIELDS))
        .collect();
    Ok(CallResult::Json(json!({ "job": job, "builds": builds })))
}

/// One build's console text, with the exit status its result implies.
async fn console(
    conn: &Connection,
    args: &BTreeMap<String, ArgValue>,
    transport: &dyn HttpTransport,
    deadline: Instant,
) -> Result<CallResult, ConnectorError> {
    let job = text_arg(args, "job")?.to_owned();
    let build = id_arg(args, "build")?;
    let base = job_segments(&job)?;

    let mut status_segments = base.clone();
    status_segments.push(build.to_string());
    status_segments.push("api".to_owned());
    status_segments.push("json".to_owned());
    let mut status_url = job_url(&conn.base_url, &status_segments)?;
    status_url
        .query_pairs_mut()
        .append_pair("tree", "result,building");
    let status = get_json(conn, ID, status_url, transport, deadline).await?;
    let exit_status = exit_status(status.get("result").and_then(Value::as_str));

    let mut log_segments = base;
    log_segments.push(build.to_string());
    log_segments.push("consoleText".to_owned());
    let log_url = job_url(&conn.base_url, &log_segments)?;
    let response = transport
        .send(request(ID, conn, log_url, MAX_LOG_BYTES)?, deadline)
        .await?;
    check_status(&response)?;

    Ok(CallResult::Log {
        name: format!("jenkins-{}-{build}.log", job.replace('/', "-")),
        bytes: response.body,
        exit_status,
    })
}

/// `GET /me/api/json` — who this user and token are.
pub(crate) async fn verify(
    conn: &Connection,
    transport: &dyn HttpTransport,
    deadline: Instant,
) -> Result<VerifyReport, ConnectorError> {
    let url = endpoint(&conn.base_url, &["me", "api", "json"])?;
    let body = get_json(conn, ID, url, transport, deadline).await?;
    let id = string_field(&body, "id")?;
    Ok(VerifyReport {
        detail: format!("authenticated as {id}"),
    })
}

/// Turns `platform/build` into `job/platform/job/build`.
fn job_segments(raw: &str) -> Result<Vec<String>, ConnectorError> {
    let parts: Vec<&str> = raw.trim_matches('/').split('/').collect();
    if parts.len() > 8
        || parts
            .iter()
            .any(|part| part.is_empty() || part.contains(char::is_whitespace))
    {
        return Err(ConnectorError::BadArgs(format!(
            "`job` must be a job name, or a folder path like `folder/job`, not `{raw}`"
        )));
    }
    let mut segments = Vec::with_capacity(parts.len() * 2);
    for part in parts {
        segments.push("job".to_owned());
        segments.push((*part).to_owned());
    }
    Ok(segments)
}

/// Joins owned segments onto the base URL.
fn job_url(base: &Url, segments: &[String]) -> Result<Url, ConnectorError> {
    let borrowed: Vec<&str> = segments.iter().map(String::as_str).collect();
    endpoint(base, &borrowed)
}

/// The exit status a build result implies; `None` while it still runs.
fn exit_status(result: Option<&str>) -> Option<i32> {
    match result {
        Some("SUCCESS") => Some(0),
        Some("FAILURE" | "ABORTED" | "UNSTABLE") => Some(1),
        _ => None,
    }
}
