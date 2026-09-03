//! Confluence Cloud: a CQL search, and one page's storage-format body.
//!
//! Confluence Cloud authenticates with HTTP Basic over the account email and
//! an API token, so this connector is the one place a stored user name is an
//! email address.

use std::collections::BTreeMap;
use std::time::Instant;

use pam_flow::{ArgValue, ConnectorId};
use serde_json::{Value, json};

use crate::error::ConnectorError;
use crate::jira::cut_at;
use crate::transport::{
    Connection, HttpTransport, array_field, endpoint, get_json, int_arg, text_arg,
};
use crate::{CallResult, VerifyReport, unknown_call};

/// The connector this module serves.
const ID: ConnectorId = ConnectorId::Confluence;

/// The most body text one page may carry back.
const MAX_BODY_BYTES: usize = 64 * 1024;

/// Runs one Confluence call.
pub(crate) async fn call(
    conn: &Connection,
    call: &str,
    args: &BTreeMap<String, ArgValue>,
    transport: &dyn HttpTransport,
    deadline: Instant,
) -> Result<CallResult, ConnectorError> {
    match call {
        "search" => search(conn, args, transport, deadline).await,
        "page" => page(conn, args, transport, deadline).await,
        other => Err(unknown_call(ID, other)),
    }
}

/// `GET /rest/api/content/search?cql=…&limit=…&expand=space,version`.
async fn search(
    conn: &Connection,
    args: &BTreeMap<String, ArgValue>,
    transport: &dyn HttpTransport,
    deadline: Instant,
) -> Result<CallResult, ConnectorError> {
    let cql = text_arg(args, "cql")?;
    let limit = int_arg(args, "limit", 20, (1, 100))?;
    let mut url = endpoint(&conn.base_url, &["rest", "api", "content", "search"])?;
    url.query_pairs_mut()
        .append_pair("cql", cql)
        .append_pair("limit", &limit.to_string())
        .append_pair("expand", "space,version");
    let body = get_json(conn, ID, url, transport, deadline).await?;
    let results: Vec<Value> = array_field(&body, "results")?
        .iter()
        .take(usize::try_from(limit).unwrap_or(usize::MAX))
        .map(summarize)
        .collect();
    let total = body.get("totalSize").and_then(Value::as_i64);
    // Confluence says "there is more" two ways: a total over the page, or a
    // `next` link. Either one makes the answer partial.
    let has_next = body
        .get("_links")
        .and_then(|links| links.get("next"))
        .is_some_and(|next| !next.is_null());
    let seen = i64::try_from(results.len()).unwrap_or(i64::MAX);
    let partial = has_next || total.is_some_and(|total| total > seen);
    Ok(CallResult::Json(json!({
        "partial": partial,
        "total": total,
        "results": results,
    })))
}

/// `GET /rest/api/content/{id}?expand=body.storage,space,version`.
async fn page(
    conn: &Connection,
    args: &BTreeMap<String, ArgValue>,
    transport: &dyn HttpTransport,
    deadline: Instant,
) -> Result<CallResult, ConnectorError> {
    let id = content_id(args)?;
    let mut url = endpoint(&conn.base_url, &["rest", "api", "content", &id])?;
    url.query_pairs_mut()
        .append_pair("expand", "body.storage,space,version");
    let response = get_json(conn, ID, url, transport, deadline).await?;

    let raw = response
        .get("body")
        .and_then(|body| body.get("storage"))
        .and_then(|storage| storage.get("value"))
        .and_then(Value::as_str)
        .unwrap_or_default();
    let (body, cut) = cut_at(raw, MAX_BODY_BYTES);
    let mut page = summarize(&response);
    if let Some(object) = page.as_object_mut() {
        object.insert("body".to_owned(), Value::String(body));
    }
    Ok(CallResult::Json(json!({
        "partial": cut,
        "page": page,
    })))
}

/// `GET /rest/api/user/current` — a 200 that names nobody is not a working
/// credential.
pub(crate) async fn verify(
    conn: &Connection,
    transport: &dyn HttpTransport,
    deadline: Instant,
) -> Result<VerifyReport, ConnectorError> {
    let url = endpoint(&conn.base_url, &["rest", "api", "user", "current"])?;
    let body = get_json(conn, ID, url, transport, deadline).await?;
    let who = ["displayName", "accountId"]
        .into_iter()
        .find_map(|field| body.get(field).and_then(Value::as_str))
        .filter(|who| !who.is_empty())
        .ok_or_else(|| {
            ConnectorError::BadResponse(
                "Confluence answered without an `accountId` or `displayName`; the base URL may not be a Confluence root"
                    .to_owned(),
            )
        })?;
    Ok(VerifyReport {
        detail: format!("authenticated as {who}"),
    })
}

/// Flattens one content item into scalars.
fn summarize(content: &Value) -> Value {
    json!({
        "id": content.get("id").cloned().unwrap_or(Value::Null),
        "type": content.get("type").cloned().unwrap_or(Value::Null),
        "title": content.get("title").cloned().unwrap_or(Value::Null),
        "status": content.get("status").cloned().unwrap_or(Value::Null),
        "space": content
            .get("space")
            .and_then(|space| space.get("key"))
            .cloned()
            .unwrap_or(Value::Null),
        "version": content
            .get("version")
            .and_then(|version| version.get("number"))
            .cloned()
            .unwrap_or(Value::Null),
    })
}

/// Checks the `id` argument is a content id and not a path.
fn content_id(args: &BTreeMap<String, ArgValue>) -> Result<String, ConnectorError> {
    let raw = text_arg(args, "id")?;
    let ok = raw.len() <= 64 && raw.bytes().all(|byte| byte.is_ascii_alphanumeric());
    if !ok {
        return Err(ConnectorError::BadArgs(format!(
            "`id` must be a Confluence content id, not `{raw}`"
        )));
    }
    Ok(raw.to_owned())
}
