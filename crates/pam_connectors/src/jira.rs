//! Jira Data Center: a JQL search, and one issue in full.
//!
//! Jira nests almost everything a human wants under `fields`, and nests the
//! readable half of that under `name` or `displayName`. Both calls flatten
//! it: an issue comes back as seven scalars, which is what a verdict can
//! actually quote.

use std::collections::BTreeMap;
use std::time::Instant;

use pam_flow::{ArgValue, ConnectorId};
use serde_json::{Value, json};

use crate::error::ConnectorError;
use crate::transport::{
    Connection, HttpTransport, array_field, endpoint, get_json, int_arg, text_arg,
};
use crate::{CallResult, VerifyReport, unknown_call};

/// The connector this module serves.
const ID: ConnectorId = ConnectorId::Jira;

/// The fields both calls ask Jira for.
const FIELDS: &str = "summary,status,issuetype,priority,assignee,updated";

/// The most description text one issue may carry back.
const MAX_DESCRIPTION_BYTES: usize = 16 * 1024;

/// Runs one Jira call.
pub(crate) async fn call(
    conn: &Connection,
    call: &str,
    args: &BTreeMap<String, ArgValue>,
    transport: &dyn HttpTransport,
    deadline: Instant,
) -> Result<CallResult, ConnectorError> {
    match call {
        "search" => search(conn, args, transport, deadline).await,
        "issue" => issue(conn, args, transport, deadline).await,
        other => Err(unknown_call(ID, other)),
    }
}

/// `GET /rest/api/2/search?jql=…&maxResults=…&fields=…`.
async fn search(
    conn: &Connection,
    args: &BTreeMap<String, ArgValue>,
    transport: &dyn HttpTransport,
    deadline: Instant,
) -> Result<CallResult, ConnectorError> {
    let jql = text_arg(args, "jql")?;
    let limit = int_arg(args, "limit", 20, (1, 100))?;
    let mut url = endpoint(&conn.base_url, &["rest", "api", "2", "search"])?;
    url.query_pairs_mut()
        .append_pair("jql", jql)
        .append_pair("maxResults", &limit.to_string())
        .append_pair("fields", FIELDS);
    let body = get_json(conn, ID, url, transport, deadline).await?;
    let issues: Vec<Value> = array_field(&body, "issues")?
        .iter()
        .take(usize::try_from(limit).unwrap_or(usize::MAX))
        .map(summarize)
        .collect();
    let total = body.get("total").and_then(Value::as_i64);
    let seen = i64::try_from(issues.len()).unwrap_or(i64::MAX);
    let partial = total.is_some_and(|total| total > seen);
    Ok(CallResult::Json(json!({
        "partial": partial,
        "total": total,
        "issues": issues,
    })))
}

/// `GET /rest/api/2/issue/{key}?fields=…,description`.
async fn issue(
    conn: &Connection,
    args: &BTreeMap<String, ArgValue>,
    transport: &dyn HttpTransport,
    deadline: Instant,
) -> Result<CallResult, ConnectorError> {
    let key = issue_key(args)?;
    let mut url = endpoint(&conn.base_url, &["rest", "api", "2", "issue", &key])?;
    url.query_pairs_mut()
        .append_pair("fields", &format!("{FIELDS},description"));
    let body = get_json(conn, ID, url, transport, deadline).await?;

    let mut issue = summarize(&body);
    let raw = body
        .get("fields")
        .and_then(|fields| fields.get("description"))
        .and_then(Value::as_str)
        .unwrap_or_default();
    let (description, cut) = cut_at(raw, MAX_DESCRIPTION_BYTES);
    if let Some(object) = issue.as_object_mut() {
        object.insert("description".to_owned(), Value::String(description));
    }
    Ok(CallResult::Json(json!({
        "partial": cut,
        "issue": issue,
    })))
}

/// `GET /rest/api/2/myself` — a 200 that does not name the caller is not a
/// working credential.
pub(crate) async fn verify(
    conn: &Connection,
    transport: &dyn HttpTransport,
    deadline: Instant,
) -> Result<VerifyReport, ConnectorError> {
    let url = endpoint(&conn.base_url, &["rest", "api", "2", "myself"])?;
    let body = get_json(conn, ID, url, transport, deadline).await?;
    let who = ["name", "key"]
        .into_iter()
        .find_map(|field| body.get(field).and_then(Value::as_str))
        .filter(|who| !who.is_empty())
        .ok_or_else(|| {
            ConnectorError::BadResponse(
                "Jira answered without a `name` or `key`; the base URL may not be a Jira root"
                    .to_owned(),
            )
        })?;
    Ok(VerifyReport {
        detail: format!("authenticated as {who}"),
    })
}

/// Flattens one issue into the scalars a verdict can quote.
fn summarize(issue: &Value) -> Value {
    let fields = issue.get("fields");
    json!({
        "key": issue.get("key").cloned().unwrap_or(Value::Null),
        "summary": field(fields, "summary", None),
        "status": field(fields, "status", Some("name")),
        "issuetype": field(fields, "issuetype", Some("name")),
        "priority": field(fields, "priority", Some("name")),
        "assignee": field(fields, "assignee", Some("displayName")),
        "updated": field(fields, "updated", None),
    })
}

/// One `fields` entry, optionally reaching one level further in.
fn field(fields: Option<&Value>, name: &str, inner: Option<&str>) -> Value {
    let value = fields.and_then(|fields| fields.get(name));
    match inner {
        Some(inner) => value.and_then(|value| value.get(inner)).cloned(),
        None => value.cloned(),
    }
    .unwrap_or(Value::Null)
}

/// Checks the `key` argument looks like `PROJ-123`.
fn issue_key(args: &BTreeMap<String, ArgValue>) -> Result<String, ConnectorError> {
    let raw = text_arg(args, "key")?;
    let ok = raw.len() <= 64
        && raw
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
        && raw.contains('-');
    if !ok {
        return Err(ConnectorError::BadArgs(format!(
            "`key` must be an issue key like `PROJ-123`, not `{raw}`"
        )));
    }
    Ok(raw.to_owned())
}

/// Cuts text to at most `maximum` bytes on a character boundary.
///
/// Answers `(text, was_cut)` so the call can report `partial` rather than
/// pretend the whole description came back.
pub(crate) fn cut_at(text: &str, maximum: usize) -> (String, bool) {
    if text.len() <= maximum {
        return (text.to_owned(), false);
    }
    let mut end = maximum;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    (text[..end].to_owned(), true)
}
