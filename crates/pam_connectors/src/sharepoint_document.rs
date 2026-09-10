//! Bounded Graph text capture. A metadata recheck is not immutable remote-version proof.
//! Graph content: <https://learn.microsoft.com/graph/api/driveitem-get-content>
use std::collections::BTreeMap;
use std::time::Instant;

use pam_flow::{ArgValue, ConnectorId};
use serde_json::{Value, json};
use url::Url;

use crate::transport::{
    Connection, HttpRequest, HttpTransport, Method, array_field, endpoint, get_json, request,
    text_arg,
};
use crate::{CallResult, ConnectorError};

const ID: ConnectorId = ConnectorId::Sharepoint;
const MAX_TEXT: u64 = 64 * 1024;

/// Reads only a drive proved to occur in the approved site's bounded drive page.
pub(crate) async fn document(
    conn: &Connection,
    args: &BTreeMap<String, ArgValue>,
    transport: &dyn HttpTransport,
    deadline: Instant,
) -> Result<CallResult, ConnectorError> {
    let site = identity(args, "site")?;
    let drive = identity(args, "drive")?;
    let item = identity(args, "item")?;
    let (resolved, site_url) = site_drive(conn, &site, &drive, transport, deadline).await?;
    let item_url = endpoint(&conn.base_url, &["drives", &drive, "items", &item])?;
    let before = get_json(conn, ID, item_url.clone(), transport, deadline).await?;
    let metadata = project_metadata(&before, &item, &drive, &site_url)?;
    let mut output = json!({"schema_version":1,"site":resolved,"drive":drive,"item":item,"citation":{"provider":"sharepoint_365","id":item,"site_id":resolved,"drive_id":drive,"source_url":metadata["webUrl"],"revision_basis":"metadata_change_tags","etag":metadata["eTag"],"ctag":metadata["cTag"],"updated":metadata["lastModifiedDateTime"]},"metadata":metadata,"content":{"state":"unavailable","consistency":"not_checked","source_bytes":metadata["size"],"retained_bytes":0,"text":null},"partial":true,"limitations":[]});
    let byte_count = metadata["size"].as_u64().expect("validated size");
    if byte_count > MAX_TEXT {
        return Ok(state(
            output,
            "too_large",
            "document exceeds the 64 KiB text capture limit",
        ));
    }
    let mime = metadata["mime_type"].as_str().expect("validated MIME");
    if !text_mime(mime) {
        return Ok(state(
            output,
            "unsupported_format",
            "only allowlisted UTF-8 text formats are captured",
        ));
    }
    let text = match capture(conn, &drive, &item, &site_url, transport, deadline).await? {
        Capture::Text(text) => text,
        Capture::Unavailable(cause, detail) => return Ok(state(output, cause, detail)),
    };
    let after = get_json(conn, ID, item_url, transport, deadline).await?;
    let Ok(after) = project_metadata(&after, &item, &drive, &site_url) else {
        return Ok(state(
            output,
            "changed_during_read",
            "document metadata could not be revalidated",
        ));
    };
    let unchanged = ["id", "eTag", "cTag", "size", "mime_type", "webUrl"]
        .iter()
        .all(|key| metadata[*key] == after[*key]);
    if !unchanged || text.len() as u64 != byte_count {
        return Ok(state(
            output,
            "changed_during_read",
            "document identity, version metadata, or byte count changed during capture",
        ));
    }
    output["content"] = json!({"state":"available","consistency":"metadata_rechecked","source_bytes":byte_count,"retained_bytes":text.len(),"text":text});
    output["partial"] = json!(false);
    output["limitations"] = json!([
        "metadata recheck does not prove an immutable remote version; evidence digest identifies captured bytes"
    ]);
    Ok(CallResult::Json(output))
}

async fn site_drive(
    conn: &Connection,
    site: &str,
    drive: &str,
    transport: &dyn HttpTransport,
    deadline: Instant,
) -> Result<(String, Url), ConnectorError> {
    let site_body = get_json(
        conn,
        ID,
        endpoint(&conn.base_url, &["sites", site])?,
        transport,
        deadline,
    )
    .await?;
    let resolved = field(&site_body, "id", 256)?;
    if site != "root" && resolved != site {
        return Err(bad("Graph site identity did not match"));
    }
    let site_url = citation_url(field(&site_body, "webUrl", 2048)?)?;
    if resolved.split(',').next() != site_url.host_str() {
        return Err(bad("Graph site host did not match its identity"));
    }
    let mut drives_url = endpoint(&conn.base_url, &["sites", resolved, "drives"])?;
    drives_url.set_query(Some("$top=100&$select=id"));
    let drives = get_json(conn, ID, drives_url, transport, deadline).await?;
    let mut found = false;
    for candidate in array_field(&drives, "value")?.iter().take(100) {
        if field(candidate, "id", 1024)? == drive {
            found = true;
        }
    }
    if !found {
        return Err(bad(
            "requested drive was not established in the site's bounded drive page",
        ));
    }
    Ok((resolved.to_owned(), site_url))
}

enum Capture {
    Text(String),
    Unavailable(&'static str, &'static str),
}
async fn capture(
    conn: &Connection,
    drive: &str,
    item: &str,
    site: &Url,
    transport: &dyn HttpTransport,
    deadline: Instant,
) -> Result<Capture, ConnectorError> {
    let url = endpoint(&conn.base_url, &["drives", drive, "items", item, "content"])?;
    let response = transport
        .send(request(ID, conn, url, MAX_TEXT)?, deadline)
        .await?;
    if response.status != 302 {
        return Ok(Capture::Unavailable(
            "download_unavailable",
            "Graph did not provide the expected content redirect",
        ));
    }
    let target = response
        .header("location")
        .and_then(|raw| safe_url(raw).ok())
        .filter(|url| url.host_str() == site.host_str());
    let Some(target) = target else {
        return Ok(Capture::Unavailable(
            "unsupported_download_host",
            "download target is not the exact approved HTTPS tenant host",
        ));
    };
    // Fresh request: no inherited authorization, cookies, or automatic redirects.
    let response = transport
        .send(
            HttpRequest {
                method: Method::Get,
                body: None,
                url: target,
                headers: vec![(
                    "Accept".into(),
                    "text/plain, application/json, application/xml".into(),
                )],
                max_bytes: MAX_TEXT,
                follow_one_https_redirect_without_auth: false,
            },
            deadline,
        )
        .await;
    // Network diagnostics can contain signed URLs. Preserve policy causes, but never their URLs.
    let response = match response {
        Ok(response) => response,
        Err(crate::TransportError::TooLarge { .. }) => {
            return Ok(Capture::Unavailable(
                "too_large",
                "download exceeded the text capture limit",
            ));
        }
        Err(crate::TransportError::Network(_) | crate::TransportError::Spawn(_)) => {
            return Ok(Capture::Unavailable(
                "download_unavailable",
                "signed document download failed",
            ));
        }
        Err(error) => return Err(error.into()),
    };
    if response.status != 200 {
        return Ok(Capture::Unavailable(
            "download_unavailable",
            "download did not return a complete body; further redirects are refused",
        ));
    }
    if response.body.len() as u64 > MAX_TEXT {
        return Ok(Capture::Unavailable(
            "too_large",
            "download exceeded the text capture limit",
        ));
    }
    let Ok(text) = String::from_utf8(response.body) else {
        return Ok(Capture::Unavailable(
            "unsupported_encoding",
            "document is not valid UTF-8 text",
        ));
    };
    if text.as_bytes().contains(&0) {
        return Ok(Capture::Unavailable(
            "unsupported_encoding",
            "document contains binary NUL bytes",
        ));
    }
    Ok(Capture::Text(text))
}

fn project_metadata(
    body: &Value,
    item: &str,
    drive: &str,
    site: &Url,
) -> Result<Value, ConnectorError> {
    if field(body, "id", 1024)? != item
        || field(&body["parentReference"], "driveId", 1024)? != drive
        || body.get("remoteItem").is_some()
        || !body["file"].is_object()
    {
        return Err(bad("Graph item identity, drive, or file facet was invalid"));
    }
    let web = field(body, "webUrl", 2048)?;
    if citation_url(web)?.host_str() != site.host_str() {
        return Err(bad("Graph item citation belongs to another host"));
    }
    let byte_count = body["size"]
        .as_u64()
        .ok_or_else(|| bad("Graph item size was invalid"))?;
    let etag = field(body, "eTag", 1024)?;
    let ctag = field(body, "cTag", 1024)?;
    Ok(
        json!({"id":item,"name":field(body,"name",1024)?,"webUrl":web,"size":byte_count,"lastModifiedDateTime":field(body,"lastModifiedDateTime",128)?,"eTag":etag,"cTag":ctag,"mime_type":field(&body["file"],"mimeType",128)?}),
    )
}

fn identity(args: &BTreeMap<String, ArgValue>, key: &str) -> Result<String, ConnectorError> {
    let value = text_arg(args, key)?;
    if value.is_empty()
        || value.len() > 256
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b',' | b'-' | b'_' | b'!'))
        || matches!(value, "." | "..")
    {
        return Err(ConnectorError::BadArgs(format!(
            "`{key}` must be a bounded Graph identity"
        )));
    }
    Ok(value.to_owned())
}
fn field<'a>(value: &'a Value, key: &str, maximum: usize) -> Result<&'a str, ConnectorError> {
    value[key]
        .as_str()
        .filter(|s| !s.is_empty() && s.len() <= maximum && !s.chars().any(char::is_control))
        .ok_or_else(|| bad("Graph omitted or malformed required bounded metadata"))
}
fn citation_url(raw: &str) -> Result<Url, ConnectorError> {
    let url = safe_url(raw)?;
    if url.query().is_some() {
        return Err(bad("Graph citation must not contain query credentials"));
    }
    Ok(url)
}

fn safe_url(raw: &str) -> Result<Url, ConnectorError> {
    if raw.len() > 8192 {
        return Err(bad("Graph URL exceeded its bound"));
    }
    let url = Url::parse(raw).map_err(|_| bad("Graph URL was invalid"))?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || url.port_or_known_default() != Some(443)
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err(bad("Graph URL was not a safe HTTPS URL"));
    }
    Ok(url)
}
fn text_mime(mime: &str) -> bool {
    matches!(
        mime,
        "text/plain"
            | "text/markdown"
            | "text/csv"
            | "text/tab-separated-values"
            | "application/json"
            | "application/xml"
            | "text/xml"
            | "application/yaml"
            | "text/yaml"
    )
}
fn state(mut output: Value, state: &str, detail: &str) -> CallResult {
    output["content"]["state"] = json!(state);
    output["limitations"] = json!([detail]);
    CallResult::Json(output)
}
fn bad(detail: &str) -> ConnectorError {
    ConnectorError::BadResponse(detail.to_owned())
}
