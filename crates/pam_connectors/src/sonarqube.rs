//! `SonarQube`: whether a project's quality gate passes, and the open issues
//! behind it.
//!
//! `SonarQube` authenticates a token by putting it where HTTP Basic expects
//! the user name and leaving the password empty, which is why this connector
//! stores no user name of its own.

use std::collections::BTreeMap;
use std::time::Instant;

use pam_flow::{ArgValue, ConnectorId};
use serde_json::{Value, json};

use crate::error::ConnectorError;
use crate::transport::{
    Connection, HttpTransport, array_field, endpoint, get_json, int_arg, pick, text_arg,
};
use crate::{CallResult, VerifyReport, unknown_call};

/// The connector this module serves.
const ID: ConnectorId = ConnectorId::Sonarqube;

/// The fields kept from an issue.
const ISSUE_FIELDS: &[&str] = &[
    "key",
    "rule",
    "severity",
    "component",
    "line",
    "message",
    "type",
];

/// Runs one `SonarQube` call.
pub(crate) async fn call(
    conn: &Connection,
    call: &str,
    args: &BTreeMap<String, ArgValue>,
    transport: &dyn HttpTransport,
    deadline: Instant,
) -> Result<CallResult, ConnectorError> {
    match call {
        "quality_gate" => quality_gate(conn, args, transport, deadline).await,
        "issues" => issues(conn, args, transport, deadline).await,
        other => Err(unknown_call(ID, other)),
    }
}

/// `GET /api/qualitygates/project_status?projectKey=…`.
async fn quality_gate(
    conn: &Connection,
    args: &BTreeMap<String, ArgValue>,
    transport: &dyn HttpTransport,
    deadline: Instant,
) -> Result<CallResult, ConnectorError> {
    let project = text_arg(args, "project")?;
    let mut url = endpoint(&conn.base_url, &["api", "qualitygates", "project_status"])?;
    url.query_pairs_mut().append_pair("projectKey", project);
    let body = get_json(conn, ID, url, transport, deadline).await?;
    let project_status = body.get("projectStatus").ok_or_else(|| {
        ConnectorError::BadResponse("the answer carries no `projectStatus`".to_owned())
    })?;
    let status = project_status
        .get("status")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            ConnectorError::BadResponse("the quality gate carries no `status`".to_owned())
        })?;
    let conditions: Vec<Value> = array_field(project_status, "conditions")?
        .iter()
        .map(|condition| {
            json!({
                "metric": condition.get("metricKey").cloned().unwrap_or(Value::Null),
                "status": condition.get("status").cloned().unwrap_or(Value::Null),
                "actual": condition.get("actualValue").cloned().unwrap_or(Value::Null),
                "threshold": condition.get("errorThreshold").cloned().unwrap_or(Value::Null),
            })
        })
        .collect();
    Ok(CallResult::Json(json!({
        "project": project,
        "status": status,
        "conditions": conditions,
    })))
}

/// `GET /api/issues/search?componentKeys=…&resolved=false&ps=…`.
async fn issues(
    conn: &Connection,
    args: &BTreeMap<String, ArgValue>,
    transport: &dyn HttpTransport,
    deadline: Instant,
) -> Result<CallResult, ConnectorError> {
    let project = text_arg(args, "project")?;
    let limit = int_arg(args, "limit", 50, (1, 500))?;
    let mut url = endpoint(&conn.base_url, &["api", "issues", "search"])?;
    url.query_pairs_mut()
        .append_pair("componentKeys", project)
        .append_pair("resolved", "false")
        .append_pair("ps", &limit.to_string());
    let body = get_json(conn, ID, url, transport, deadline).await?;
    let issues: Vec<Value> = array_field(&body, "issues")?
        .iter()
        .take(usize::try_from(limit).unwrap_or(usize::MAX))
        .map(|issue| pick(issue, ISSUE_FIELDS))
        .collect();
    let total = body.get("total").and_then(Value::as_i64);
    // `partial` rides into evidence so a verdict never claims it saw every
    // open issue when the page was capped.
    let seen = i64::try_from(issues.len()).unwrap_or(i64::MAX);
    let partial = total.is_some_and(|total| total > seen);
    Ok(CallResult::Json(json!({
        "project": project,
        "partial": partial,
        "total": total,
        "issues": issues,
    })))
}

/// `GET /api/authentication/validate` — a 200 alone is not enough.
pub(crate) async fn verify(
    conn: &Connection,
    transport: &dyn HttpTransport,
    deadline: Instant,
) -> Result<VerifyReport, ConnectorError> {
    let url = endpoint(&conn.base_url, &["api", "authentication", "validate"])?;
    let body = get_json(conn, ID, url, transport, deadline).await?;
    // SonarQube answers 200 with `valid: false` for a token it does not
    // know, so the field, not the status, decides.
    if body.get("valid").and_then(Value::as_bool) != Some(true) {
        return Err(ConnectorError::Auth);
    }
    Ok(VerifyReport {
        detail: format!("token accepted by {}", conn.base_url),
    })
}
