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
    Connection, HttpTransport, array_field, endpoint, get_json, int_arg, opt_text_arg, pick,
    text_arg,
};
use crate::{CallResult, VerifyReport, unknown_call};

/// The connector this module serves.
const ID: ConnectorId = ConnectorId::Sonarqube;

/// The fields kept from an issue.
const ISSUE_FIELDS: &[&str] = &[
    "project",
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
    let project = project_arg(args)?;
    let selector = selector_arg(args)?;
    let mut url = endpoint(&conn.base_url, &["api", "qualitygates", "project_status"])?;
    if let Some((key, value)) = selector {
        require_contract(
            conn,
            "api/qualitygates",
            "project_status",
            &["projectKey", key],
            transport,
            deadline,
        )
        .await?;
        url.query_pairs_mut().append_pair(key, value);
    }
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
    if !matches!(status, "OK" | "ERROR" | "WARN" | "NONE") {
        return Err(ConnectorError::BadResponse(
            "unrecognized quality gate status".to_owned(),
        ));
    }
    check_echo(&body, project, selector)?;
    check_echo(project_status, project, selector)?;
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
        "requested": requested(project, selector),
        "identity_basis": "request_bound",
        "analysis_basis": "live_measure",
    })))
}

/// Advertised 10.2+ `components` contract; never retry with an ignored filter.
async fn issues(
    conn: &Connection,
    args: &BTreeMap<String, ArgValue>,
    transport: &dyn HttpTransport,
    deadline: Instant,
) -> Result<CallResult, ConnectorError> {
    let project = project_arg(args)?;
    let selector = selector_arg(args)?;
    let limit = int_arg(args, "limit", 50, (1, 500))?;
    let mut required = vec!["components", "resolved", "ps"];
    if let Some((key, _)) = selector {
        required.push(key);
    }
    require_contract(conn, "api/issues", "search", &required, transport, deadline).await?;
    let mut url = endpoint(&conn.base_url, &["api", "issues", "search"])?;
    if let Some((key, value)) = selector {
        url.query_pairs_mut().append_pair(key, value);
    }
    url.query_pairs_mut()
        .append_pair("components", project)
        .append_pair("resolved", "false")
        .append_pair("ps", &limit.to_string());
    let body = get_json(conn, ID, url, transport, deadline).await?;
    let returned = array_field(&body, "issues")?;
    for issue in returned {
        if issue.get("project").and_then(Value::as_str) != Some(project) {
            return Err(ConnectorError::BadResponse(
                "issue project identity is missing or conflicts with the request".to_owned(),
            ));
        }
        check_echo(issue, project, selector)?;
    }
    let issues: Vec<Value> = returned
        .iter()
        .take(usize::try_from(limit).unwrap_or(usize::MAX))
        .map(|issue| pick(issue, ISSUE_FIELDS))
        .collect();
    let total = body
        .pointer("/paging/total")
        .or_else(|| body.get("total"))
        .and_then(Value::as_i64)
        .filter(|total| *total >= 0);
    // `partial` rides into evidence so a verdict never claims it saw every
    // open issue when the page was capped.
    let seen = i64::try_from(issues.len()).unwrap_or(i64::MAX);
    let partial = total.is_none_or(|total| total > seen);
    Ok(CallResult::Json(json!({
        "project": project,
        "partial": partial,
        "total": total,
        "issues": issues,
        "requested": requested(project, selector),
        "identity_basis": if issues.is_empty() { "request_bound" } else { "returned_issue_project" },
        "analysis_basis": "live_issues",
    })))
}

/// Single project only: the REST filter is comma-separated.
fn project_arg(args: &BTreeMap<String, ArgValue>) -> Result<&str, ConnectorError> {
    let project = text_arg(args, "project")?;
    if project.contains(',') || project.chars().any(char::is_control) {
        return Err(ConnectorError::BadArgs(
            "`project` must be one project key".to_owned(),
        ));
    }
    Ok(project)
}

fn selector_arg(args: &BTreeMap<String, ArgValue>) -> Result<Option<(&str, &str)>, ConnectorError> {
    let branch = opt_text_arg(args, "branch")?;
    let pull_request = opt_text_arg(args, "pullRequest")?;
    match (branch, pull_request) {
        (Some(_), Some(_)) => Err(ConnectorError::BadArgs(
            "`branch` and `pullRequest` are mutually exclusive".to_owned(),
        )),
        (Some(value), None) => Ok(Some(("branch", value))),
        (None, Some(value)) => Ok(Some(("pullRequest", value))),
        (None, None) => Ok(None),
    }
}

fn requested(project: &str, selector: Option<(&str, &str)>) -> Value {
    let mut identity = json!({"project": project});
    if let Some((key, value)) = selector {
        identity[key] = json!(value);
    }
    identity
}

/// Optional echoes cannot contradict the request; absent gate echoes are not proof.
fn check_echo(
    body: &Value,
    project: &str,
    selector: Option<(&str, &str)>,
) -> Result<(), ConnectorError> {
    for key in ["project", "projectKey", "branch", "pullRequest"] {
        let Some(value) = body.get(key) else { continue };
        let expected = if matches!(key, "project" | "projectKey") {
            Some(project)
        } else {
            selector
                .filter(|(selected, _)| *selected == key)
                .map(|(_, value)| value)
        };
        if value.as_str().is_none() || value.as_str() != expected {
            return Err(ConnectorError::BadResponse(
                "returned identity conflicts with the request".to_owned(),
            ));
        }
    }
    Ok(())
}

/// Confirm required query parameters before sending a potentially unfiltered request.
/// Uses the existing 1 MiB JSON cap and caller deadline; oversized catalogs refuse.
/// SonarSource SearchAction records the `components` rename in its 10.2 changelog.
async fn require_contract(
    conn: &Connection,
    path: &str,
    action: &str,
    required: &[&str],
    transport: &dyn HttpTransport,
    deadline: Instant,
) -> Result<(), ConnectorError> {
    let url = endpoint(&conn.base_url, &["api", "webservices", "list"])?;
    let body = get_json(conn, ID, url, transport, deadline).await?;
    let supported = body
        .get("webServices")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|service| service.get("path").and_then(Value::as_str) == Some(path))
        .filter_map(|service| service.get("actions").and_then(Value::as_array))
        .flatten()
        .filter(|entry| entry.get("key").and_then(Value::as_str) == Some(action))
        .filter_map(|entry| entry.get("params").and_then(Value::as_array))
        .any(|params| {
            required.iter().all(|key| {
                params
                    .iter()
                    .any(|param| param.get("key").and_then(Value::as_str) == Some(*key))
            })
        });
    if !supported {
        return Err(ConnectorError::Policy {
            cause: "sonarqube_contract_unavailable",
            detail: "SonarQube does not advertise the required scoped API parameters (issues requires the 10.2+ components contract)".to_owned(),
        });
    }
    Ok(())
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
