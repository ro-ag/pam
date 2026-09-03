//! `SharePoint` through Microsoft Graph: search a site's document library,
//! and list a site's lists.
//!
//! The base URL is the Graph root, so a sovereign cloud is just a different
//! base URL and needs no code here.

use std::collections::BTreeMap;
use std::time::Instant;

use pam_flow::{ArgValue, ConnectorId};
use serde_json::{Value, json};

use crate::error::ConnectorError;
use crate::transport::{
    Connection, HttpTransport, array_field, endpoint, get_json, int_arg, pick, string_field,
    text_arg,
};
use crate::{CallResult, VerifyReport, unknown_call};

/// The connector this module serves.
const ID: ConnectorId = ConnectorId::Sharepoint;

/// The fields kept from a drive item.
const DOCUMENT_FIELDS: &[&str] = &["id", "name", "webUrl", "size", "lastModifiedDateTime"];

/// The fields kept from a list.
const LIST_FIELDS: &[&str] = &["id", "name", "displayName", "webUrl"];

/// The most characters a search term may carry.
const MAX_QUERY_CHARS: usize = 256;

/// Runs one `SharePoint` call.
pub(crate) async fn call(
    conn: &Connection,
    call: &str,
    args: &BTreeMap<String, ArgValue>,
    transport: &dyn HttpTransport,
    deadline: Instant,
) -> Result<CallResult, ConnectorError> {
    match call {
        "documents" => documents(conn, args, transport, deadline).await,
        "lists" => lists(conn, args, transport, deadline).await,
        other => Err(unknown_call(ID, other)),
    }
}

/// `GET /sites/{site}/drive/root/search(q='…')?$top=…`.
async fn documents(
    conn: &Connection,
    args: &BTreeMap<String, ArgValue>,
    transport: &dyn HttpTransport,
    deadline: Instant,
) -> Result<CallResult, ConnectorError> {
    let site = site(args)?;
    let query = query(args)?;
    let limit = int_arg(args, "limit", 20, (1, 100))?;
    let search = format!("search(q='{query}')");
    let mut url = endpoint(&conn.base_url, &["sites", &site, "drive", "root", &search])?;
    // Set directly, not through `query_pairs_mut`: that would percent-encode
    // the `$` of Graph's own `$top`, and the literal spelling is what every
    // Graph example and every proxy log shows.
    url.set_query(Some(&format!("$top={limit}")));
    let body = get_json(conn, ID, url, transport, deadline).await?;
    let documents: Vec<Value> = array_field(&body, "value")?
        .iter()
        .take(usize::try_from(limit).unwrap_or(usize::MAX))
        .map(|item| pick(item, DOCUMENT_FIELDS))
        .collect();
    Ok(CallResult::Json(json!({
        "site": site,
        "partial": partial(&body, documents.len(), limit),
        "documents": documents,
    })))
}

/// `GET /sites/{site}/lists?$top=…`.
async fn lists(
    conn: &Connection,
    args: &BTreeMap<String, ArgValue>,
    transport: &dyn HttpTransport,
    deadline: Instant,
) -> Result<CallResult, ConnectorError> {
    let site = site(args)?;
    let limit = int_arg(args, "limit", 20, (1, 100))?;
    let mut url = endpoint(&conn.base_url, &["sites", &site, "lists"])?;
    // Set directly, not through `query_pairs_mut`: that would percent-encode
    // the `$` of Graph's own `$top`, and the literal spelling is what every
    // Graph example and every proxy log shows.
    url.set_query(Some(&format!("$top={limit}")));
    let body = get_json(conn, ID, url, transport, deadline).await?;
    let lists: Vec<Value> = array_field(&body, "value")?
        .iter()
        .take(usize::try_from(limit).unwrap_or(usize::MAX))
        .map(|item| pick(item, LIST_FIELDS))
        .collect();
    Ok(CallResult::Json(json!({
        "site": site,
        "partial": partial(&body, lists.len(), limit),
        "lists": lists,
    })))
}

/// `GET /sites/root` — the tenant's root site names itself.
pub(crate) async fn verify(
    conn: &Connection,
    transport: &dyn HttpTransport,
    deadline: Instant,
) -> Result<VerifyReport, ConnectorError> {
    let url = endpoint(&conn.base_url, &["sites", "root"])?;
    let body = get_json(conn, ID, url, transport, deadline).await?;
    let id = string_field(&body, "id")?;
    Ok(VerifyReport {
        detail: format!("site id {id}"),
    })
}

/// Whether Graph is holding more than this page showed.
fn partial(body: &Value, returned: usize, limit: i64) -> bool {
    body.get("@odata.nextLink").is_some() || i64::try_from(returned).unwrap_or(i64::MAX) >= limit
}

/// Checks the `site` argument is a Graph site id.
///
/// `root`, or the composite `host,siteId,webId` form. The `host:/sites/x:`
/// form is refused: its slashes would have to be percent-encoded into a
/// single path segment, and an argument that can grow path separators is not
/// one this crate wants to hand to a URL builder.
fn site(args: &BTreeMap<String, ArgValue>) -> Result<String, ConnectorError> {
    let raw = text_arg(args, "site")?;
    let ok = raw.len() <= 256
        && raw
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b',' | b'-' | b'_'));
    if !ok {
        return Err(ConnectorError::BadArgs(format!(
            "`site` must be `root` or a Graph site id like `contoso.sharepoint.com,<site>,<web>`, not `{raw}`"
        )));
    }
    Ok(raw.to_owned())
}

/// Checks the `query` argument can be embedded in `search(q='…')`.
fn query(args: &BTreeMap<String, ArgValue>) -> Result<String, ConnectorError> {
    let raw = text_arg(args, "query")?;
    if raw.contains('\'') {
        return Err(ConnectorError::BadArgs(
            "`query` must not contain a single quote; it is what closes the search term".to_owned(),
        ));
    }
    if raw.chars().count() > MAX_QUERY_CHARS {
        return Err(ConnectorError::BadArgs(format!(
            "`query` must be at most {MAX_QUERY_CHARS} characters"
        )));
    }
    if raw.chars().any(char::is_control) {
        return Err(ConnectorError::BadArgs(
            "`query` must not contain control characters".to_owned(),
        ));
    }
    Ok(raw.to_owned())
}
