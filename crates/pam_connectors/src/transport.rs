//! The plumbing every connector sits on: the HTTP boundary, the connection
//! a call is made over, and the small helpers that turn a step's arguments
//! and a service's answer into either a value or a [`ConnectorError`].
//!
//! Nothing here talks to a network. [`HttpTransport`] is the seam: production
//! plugs in [`CurlTransport`](crate::CurlTransport), tests plug in
//! [`FakeTransport`](crate::testing::FakeTransport), and the connector
//! modules never learn which one they got.

use std::collections::BTreeMap;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use pam_flow::{ArgValue, ConnectorId};
use thiserror::Error;
use url::Url;

use crate::descriptor::{AuthKind, descriptor};
use crate::error::ConnectorError;

/// The most a JSON answer may weigh before the call is refused.
pub const MAX_JSON_BYTES: u64 = 1024 * 1024;

/// The most a log body may weigh before the call is refused.
pub const MAX_LOG_BYTES: u64 = 64 * 1024 * 1024;

/// The base URL an AWS connection carries.
///
/// AWS has no base URL: the local `aws` CLI resolves endpoints itself. The
/// field still exists on [`Connection`] so every connector is built the same
/// way, so it is filled with a reserved name that can never resolve.
pub const AWS_BASE_URL: &str = "https://aws.invalid/";

/// The HTTP verb a connector may use. Read-only means one entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Method {
    /// `GET`.
    #[default]
    Get,
}

impl Method {
    /// The verb as it goes on the wire.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
        }
    }
}

/// One outbound request, fully resolved.
///
/// `headers` already carries the `Authorization` line, which is why a request
/// is never logged and never rendered into evidence.
#[derive(Debug, Clone)]
pub struct HttpRequest {
    /// The verb.
    pub method: Method,
    /// The absolute URL, query included.
    pub url: Url,
    /// Every header to send, in order.
    pub headers: Vec<(String, String)>,
    /// The most body bytes to accept before failing with
    /// [`TransportError::TooLarge`].
    pub max_bytes: u64,
    /// Whether one redirect hop to an `https` URL may be followed, with the
    /// `Authorization` header dropped. Only GitHub job logs set it.
    pub follow_one_https_redirect_without_auth: bool,
}

/// One inbound response.
#[derive(Debug, Clone)]
pub struct HttpResponse {
    /// The status of the final answer.
    pub status: u16,
    /// The response headers, names as the service spelled them.
    pub headers: Vec<(String, String)>,
    /// The body bytes.
    pub body: Vec<u8>,
}

impl HttpResponse {
    /// The first value of a header, matched without regard to case.
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

/// Why a transport could not produce a response.
///
/// These are the failures below HTTP: the request never became an answer.
/// Anything the service said, including 500, arrives as an [`HttpResponse`].
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum TransportError {
    /// The deadline passed with no answer.
    #[error("the request timed out")]
    Timeout,
    /// The TLS certificate could not be verified.
    #[error("the TLS certificate could not be verified")]
    Certificate,
    /// Anything else that stopped the request, excerpted for a human.
    #[error("{0}")]
    Network(String),
    /// The body passed the request's budget.
    #[error("the response passed the {maximum} byte limit")]
    TooLarge {
        /// The budget that was passed.
        maximum: u64,
    },
    /// The transport's own child process could not start.
    #[error("{0}")]
    Spawn(String),
}

impl From<TransportError> for ConnectorError {
    fn from(error: TransportError) -> Self {
        match error {
            TransportError::Timeout => Self::Timeout,
            TransportError::Certificate => Self::Certificate,
            TransportError::Network(detail) => Self::Network(detail),
            TransportError::TooLarge { maximum } => Self::TooLarge {
                bytes: maximum,
                maximum,
            },
            TransportError::Spawn(detail) => Self::Network(format!("curl could not run: {detail}")),
        }
    }
}

/// The seam between a connector and the network.
///
/// Object-safe on purpose — the daemon holds one `Arc<dyn HttpTransport>` and
/// hands `&dyn HttpTransport` to every call — which is why `send` spells its
/// future out rather than being an `async fn`.
pub trait HttpTransport: Send + Sync {
    /// Sends one request, giving up at `deadline`.
    fn send<'a>(
        &'a self,
        request: HttpRequest,
        deadline: Instant,
    ) -> Pin<Box<dyn Future<Output = Result<HttpResponse, TransportError>> + Send + 'a>>;
}

/// A credential, kept out of `Debug` output and overwritten when dropped.
pub struct Secret(String);

impl Secret {
    /// Wraps a credential.
    #[must_use]
    pub fn new(secret: String) -> Self {
        Self(secret)
    }

    /// The credential itself. Every call site is an `Authorization` header.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

impl Drop for Secret {
    /// Overwrites the bytes before the allocation goes back to the allocator.
    ///
    /// `String::clear` only moves the length, so the buffer is refilled to
    /// its old length with NULs; this crate forbids `unsafe`, so this is as
    /// close to a wipe as safe Rust reaches.
    fn drop(&mut self) {
        let len = self.0.len();
        self.0.clear();
        for _ in 0..len {
            self.0.push('\0');
        }
    }
}

/// One configured connector: where it lives and how to authenticate to it.
pub struct Connection {
    /// The service root, always with a trailing slash. For AWS this is
    /// [`AWS_BASE_URL`] and is never dialed.
    pub base_url: Url,
    /// The row's `username`: a Jenkins user, a Confluence account email, an
    /// AWS profile. `None` where the connector has no use for one.
    pub username: Option<String>,
    /// The stored credential. `None` for AWS, which has none.
    pub secret: Option<Secret>,
}

impl fmt::Debug for Connection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Connection")
            .field("base_url", &self.base_url.as_str())
            .field("username", &self.username)
            .field("secret", &self.secret)
            .finish()
    }
}

/// Checks a base URL a human typed into the Connectors screen.
///
/// `https` only, no userinfo, no query, no fragment, and a trailing slash so
/// path joining is unsurprising. Private and loopback hosts are fine — a
/// self-hosted Jenkins usually lives on one. AWS keeps no base URL at all, so
/// it accepts an empty string and answers with [`AWS_BASE_URL`].
pub fn validate_base_url(id: ConnectorId, raw: &str) -> Result<Url, ConnectorError> {
    let trimmed = raw.trim();
    if id == ConnectorId::Aws && trimmed.is_empty() {
        return Ok(Url::parse(AWS_BASE_URL).expect("the AWS placeholder URL parses"));
    }
    if trimmed.is_empty() {
        return Err(ConnectorError::BadArgs(
            "the base URL is empty; type the service's root URL".to_owned(),
        ));
    }
    let mut url = Url::parse(trimmed).map_err(|error| {
        ConnectorError::BadArgs(format!("the base URL does not parse: {error}"))
    })?;
    if url.scheme() != "https" {
        return Err(ConnectorError::BadArgs(
            "the base URL must start with https://".to_owned(),
        ));
    }
    if url.host_str().is_none_or(str::is_empty) {
        return Err(ConnectorError::BadArgs(
            "the base URL has no host".to_owned(),
        ));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(ConnectorError::BadArgs(
            "the base URL must not carry a user name or password; the credential is stored separately"
                .to_owned(),
        ));
    }
    if url.query().is_some() {
        return Err(ConnectorError::BadArgs(
            "the base URL must not carry a query string".to_owned(),
        ));
    }
    if url.fragment().is_some() {
        return Err(ConnectorError::BadArgs(
            "the base URL must not carry a fragment".to_owned(),
        ));
    }
    if !url.path().ends_with('/') {
        let path = format!("{}/", url.path());
        url.set_path(&path);
    }
    Ok(url)
}

/// Appends path segments to a base URL, percent-encoding each one.
///
/// The base's trailing slash is consumed rather than doubled, so
/// `https://host/jenkins/` plus `["api", "json"]` is
/// `https://host/jenkins/api/json`.
pub(crate) fn endpoint(base: &Url, segments: &[&str]) -> Result<Url, ConnectorError> {
    let mut url = base.clone();
    {
        let mut path = url
            .path_segments_mut()
            .map_err(|()| ConnectorError::BadArgs("the base URL cannot carry a path".to_owned()))?;
        path.pop_if_empty();
        path.extend(segments);
    }
    Ok(url)
}

/// Builds a request to `url` with this connector's auth and framing headers.
pub(crate) fn request(
    id: ConnectorId,
    conn: &Connection,
    url: Url,
    max_bytes: u64,
) -> Result<HttpRequest, ConnectorError> {
    let mut headers = vec![authorization(id, conn)?];
    headers.push(("Accept".to_owned(), "application/json".to_owned()));
    headers.push((
        "User-Agent".to_owned(),
        format!("pam/{}", env!("CARGO_PKG_VERSION")),
    ));
    if id == ConnectorId::Github {
        headers.push(("X-GitHub-Api-Version".to_owned(), "2022-11-28".to_owned()));
    }
    Ok(HttpRequest {
        method: Method::Get,
        url,
        headers,
        max_bytes,
        follow_one_https_redirect_without_auth: false,
    })
}

/// The `Authorization` header for this connector's [`AuthKind`].
fn authorization(id: ConnectorId, conn: &Connection) -> Result<(String, String), ConnectorError> {
    let name = "Authorization".to_owned();
    let secret = || {
        conn.secret
            .as_ref()
            .map(Secret::expose)
            .ok_or(ConnectorError::Auth)
    };
    let value = match descriptor(id).auth {
        AuthKind::Bearer => format!("Bearer {}", secret()?),
        AuthKind::BasicUserSecret => {
            let user = conn.username.as_deref().ok_or(ConnectorError::Auth)?;
            format!(
                "Basic {}",
                base64(format!("{user}:{}", secret()?).as_bytes())
            )
        }
        AuthKind::TokenAsUser => {
            format!("Basic {}", base64(format!("{}:", secret()?).as_bytes()))
        }
        AuthKind::AwsProfile => {
            return Err(ConnectorError::BadArgs(
                "the AWS connector makes no HTTP requests".to_owned(),
            ));
        }
    };
    Ok((name, value))
}

/// Standard base64 with padding — the only encoding this crate needs, and
/// too small to be worth a dependency.
pub(crate) fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let mut block = [0_u8; 3];
        block[..chunk.len()].copy_from_slice(chunk);
        let packed = u32::from(block[0]) << 16 | u32::from(block[1]) << 8 | u32::from(block[2]);
        let indexes = [
            (packed >> 18) & 0x3f,
            (packed >> 12) & 0x3f,
            (packed >> 6) & 0x3f,
            packed & 0x3f,
        ];
        let kept = chunk.len() + 1;
        for (position, index) in indexes.into_iter().enumerate() {
            if position < kept {
                out.push(char::from(ALPHABET[index as usize]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// Turns an HTTP status into the shared refusal, or passes a 2xx through.
pub(crate) fn check_status(response: &HttpResponse) -> Result<(), ConnectorError> {
    match response.status {
        200..=299 => Ok(()),
        400 => Err(ConnectorError::BadArgs(format!(
            "the service rejected the request: {}",
            excerpt(&response.body, 200)
        ))),
        401 => Err(ConnectorError::Auth),
        403 => Err(if let Some(retry_after) = rate_limit_wait(response) {
            ConnectorError::RateLimited {
                retry_after: Some(retry_after),
            }
        } else if rate_limited(response) {
            ConnectorError::RateLimited { retry_after: None }
        } else {
            ConnectorError::Forbidden
        }),
        404 => Err(ConnectorError::NotFound),
        429 => Err(ConnectorError::RateLimited {
            retry_after: rate_limit_wait(response),
        }),
        500..=599 => Err(ConnectorError::Remote {
            status: response.status,
        }),
        status => Err(ConnectorError::BadResponse(format!(
            "the service answered an unexpected HTTP {status}"
        ))),
    }
}

/// Whether a 403 is really an exhausted rate-limit budget.
fn rate_limited(response: &HttpResponse) -> bool {
    response
        .header("x-ratelimit-remaining")
        .is_some_and(|value| value.trim() == "0")
}

/// How long the service asked pam to wait, from either standard header.
fn rate_limit_wait(response: &HttpResponse) -> Option<Duration> {
    if let Some(seconds) = response
        .header("retry-after")
        .and_then(|value| value.trim().parse::<u64>().ok())
    {
        return Some(Duration::from_secs(seconds));
    }
    if !rate_limited(response) {
        return None;
    }
    let reset = response
        .header("x-ratelimit-reset")
        .and_then(|value| value.trim().parse::<u64>().ok())?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs();
    Some(Duration::from_secs(reset.saturating_sub(now)))
}

/// Parses a JSON body, refusing anything over the call's budget.
pub(crate) fn parse_json(body: &[u8], maximum: u64) -> Result<serde_json::Value, ConnectorError> {
    let bytes = body.len() as u64;
    if bytes > maximum {
        return Err(ConnectorError::TooLarge { bytes, maximum });
    }
    serde_json::from_slice(body).map_err(|error| {
        ConnectorError::BadResponse(format!("the service's answer is not JSON: {error}"))
    })
}

/// Sends one request and parses a JSON answer, mapping every failure.
pub(crate) async fn get_json(
    conn: &Connection,
    id: ConnectorId,
    url: Url,
    transport: &dyn HttpTransport,
    deadline: Instant,
) -> Result<serde_json::Value, ConnectorError> {
    let request = request(id, conn, url, MAX_JSON_BYTES)?;
    let response = transport.send(request, deadline).await?;
    check_status(&response)?;
    parse_json(&response.body, MAX_JSON_BYTES)
}

/// A short, control-free excerpt of a body or a stderr stream.
pub(crate) fn excerpt(bytes: &[u8], maximum: usize) -> String {
    let text = String::from_utf8_lossy(&bytes[..bytes.len().min(maximum)]);
    let mut out: String = text
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    let trimmed = out.trim().to_owned();
    out = trimmed;
    if bytes.len() > maximum {
        out.push('…');
    }
    out
}

/// A required text argument.
pub(crate) fn text_arg<'a>(
    args: &'a BTreeMap<String, ArgValue>,
    name: &str,
) -> Result<&'a str, ConnectorError> {
    match args.get(name) {
        Some(ArgValue::Text(text)) if !text.trim().is_empty() => Ok(text.trim()),
        Some(ArgValue::Text(_)) => Err(ConnectorError::BadArgs(format!(
            "`{name}` is empty; give it a value"
        ))),
        Some(ArgValue::Int(_)) => Err(ConnectorError::BadArgs(format!(
            "`{name}` must be text, not a number"
        ))),
        None => Err(ConnectorError::BadArgs(format!("`{name}` is required"))),
    }
}

/// An optional text argument, absent or non-empty.
pub(crate) fn opt_text_arg<'a>(
    args: &'a BTreeMap<String, ArgValue>,
    name: &str,
) -> Result<Option<&'a str>, ConnectorError> {
    match args.get(name) {
        None => Ok(None),
        Some(_) => text_arg(args, name).map(Some),
    }
}

/// An optional bounded integer argument, spelled as a number or as digits.
pub(crate) fn int_arg(
    args: &BTreeMap<String, ArgValue>,
    name: &str,
    default: i64,
    range: (i64, i64),
) -> Result<i64, ConnectorError> {
    let (low, high) = range;
    let value = match args.get(name) {
        None => return Ok(default),
        Some(ArgValue::Int(value)) => *value,
        Some(ArgValue::Text(text)) => text.trim().parse::<i64>().map_err(|_| {
            ConnectorError::BadArgs(format!("`{name}` must be a whole number, not `{text}`"))
        })?,
    };
    if value < low || value > high {
        return Err(ConnectorError::BadArgs(format!(
            "`{name}` must be between {low} and {high}, not {value}"
        )));
    }
    Ok(value)
}

/// A required integer argument (an id), which may also arrive as digits.
pub(crate) fn id_arg(args: &BTreeMap<String, ArgValue>, name: &str) -> Result<i64, ConnectorError> {
    let value = match args.get(name) {
        Some(ArgValue::Int(value)) => *value,
        Some(ArgValue::Text(text)) => text.trim().parse::<i64>().map_err(|_| {
            ConnectorError::BadArgs(format!("`{name}` must be a whole number, not `{text}`"))
        })?,
        None => return Err(ConnectorError::BadArgs(format!("`{name}` is required"))),
    };
    if value < 0 {
        return Err(ConnectorError::BadArgs(format!(
            "`{name}` must not be negative"
        )));
    }
    Ok(value)
}

/// Copies a fixed set of fields out of a JSON object.
///
/// Every connector answers with a small, named shape rather than whatever the
/// service sent: a verdict is built from these fields, and a service that
/// grows a new one must not silently widen what lands in evidence. A field
/// the service did not send comes through as `null`.
pub(crate) fn pick(value: &serde_json::Value, fields: &[&str]) -> serde_json::Value {
    let mut object = serde_json::Map::with_capacity(fields.len());
    for field in fields {
        object.insert(
            (*field).to_owned(),
            value
                .get(*field)
                .cloned()
                .unwrap_or(serde_json::Value::Null),
        );
    }
    serde_json::Value::Object(object)
}

/// Reads an array out of a JSON answer, or says which field is missing.
pub(crate) fn array_field<'a>(
    value: &'a serde_json::Value,
    field: &str,
) -> Result<&'a Vec<serde_json::Value>, ConnectorError> {
    value
        .get(field)
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| {
            ConnectorError::BadResponse(format!("the service's answer carries no `{field}` list"))
        })
}

/// Reads a string out of a JSON answer, or says which field is missing.
pub(crate) fn string_field<'a>(
    value: &'a serde_json::Value,
    field: &str,
) -> Result<&'a str, ConnectorError> {
    value
        .get(field)
        .and_then(serde_json::Value::as_str)
        .filter(|text| !text.is_empty())
        .ok_or_else(|| {
            ConnectorError::BadResponse(format!("the service's answer carries no `{field}`"))
        })
}
