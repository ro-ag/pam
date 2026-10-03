//! The production transport: the system `curl`, driven as a child process
//! through the one launcher pam has, [`pam_net`].
//!
//! pam does not link a TLS stack. It shells out to the `curl` the operating
//! system already trusts, which keeps the dependency tree free of C and puts
//! certificate verification in the hands of the platform. Which executable
//! that is, what its argument vector holds (a constant), what its
//! environment holds (nothing), and how the proxy and certificate trust the
//! human configured reach it are all `pam_net`'s; this module only says what
//! one connector request is and reads the answer back.
//!
//! The credential never reaches the argument vector. The URL and every
//! header — `Authorization` included — are lines of the config document the
//! launcher writes to curl's standard input, so a secret is invisible to
//! `ps`, to the audit log, and to anything that samples process arguments.
//!
//! The network profile is asked of a [`NetworkSource`] before every spawn,
//! never captured at construction: a proxy the human saves applies to the
//! next request, including the second hop of a redirect.

use std::fmt;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};

use pam_net::{CurlRequest, NetFailure, NetSettings, NetworkSource, TrustedCurl};
use url::Url;

use crate::transport::{HttpRequest, HttpResponse, HttpTransport, Method, TransportError, excerpt};

/// How much room over `max_bytes` the status line and headers may take.
const HEADER_HEADROOM: u64 = 64 * 1024;

/// How long past the request's own deadline curl is given to exit before it
/// is killed, so a wedged child cannot outlive the step.
const GRACE_SECS: u64 = 5;

/// `curl` as an [`HttpTransport`].
///
/// Only the verified operating-system curl ever executes: [`Self::trusted`]
/// proves it is present, and the launcher resolves it again before every
/// spawn, so nothing can select a PATH substitute.
#[derive(Clone)]
pub struct CurlTransport {
    source: Arc<dyn NetworkSource>,
    /// Always `false` in production: only a test build has a way to set it.
    allow_http: bool,
}

impl fmt::Debug for CurlTransport {
    /// The source may hold a proxy password, so only the shape is shown.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CurlTransport")
            .field("allow_http", &self.allow_http)
            .finish_non_exhaustive()
    }
}

impl CurlTransport {
    /// The transport over the operating-system curl, reading its network
    /// profile from `source` before every spawn; or the policy refusal
    /// when this platform has no verifiable curl. This is the constructor:
    /// there is exactly one executable a transport may run, so there is
    /// nothing for a caller to choose.
    pub fn trusted(source: Arc<dyn NetworkSource>) -> Result<Self, TransportError> {
        TrustedCurl::resolve().map_err(refusal_before_spawn)?;
        Ok(Self {
            source,
            allow_http: false,
        })
    }

    /// Lets this transport speak plain `http` as well as `https`.
    ///
    /// Only the crate's own origin tests use it, to point real `curl` at a
    /// throwaway `TcpListener`. Production always keeps `https` only.
    #[cfg(any(test, feature = "testing"))]
    #[must_use]
    pub fn allow_http_for_tests(mut self) -> Self {
        self.allow_http = true;
        self
    }

    /// The `--config -` document for one request under `settings`.
    ///
    /// Public so a test can prove the secret is here and not in argv. Treat
    /// the result as a secret: it holds the headers and, with a proxy
    /// credential configured, the proxy password.
    pub fn config_for(
        settings: &NetSettings,
        request: &HttpRequest,
        deadline_secs: u64,
    ) -> Result<String, TransportError> {
        let curl = TrustedCurl::resolve().map_err(refusal_before_spawn)?;
        build(&curl, settings, request, deadline_secs, false)
            .config()
            .map_err(refusal_before_spawn)
    }

    /// Runs curl once and turns its exit into a response or a failure.
    async fn run(
        &self,
        request: &HttpRequest,
        deadline_secs: u64,
    ) -> Result<HttpResponse, TransportError> {
        let settings = self.source.settings().await.map_err(refusal_before_spawn)?;
        let curl = TrustedCurl::resolve().map_err(refusal_before_spawn)?;
        let outcome = build(&curl, &settings, request, deadline_secs, self.allow_http)
            .run(Duration::from_secs(
                deadline_secs.saturating_add(GRACE_SECS),
            ))
            .await;
        match outcome {
            Ok(output) if request.method != Method::Get => {
                parse_response(&output.stdout).map_err(|_| {
                    TransportError::Network(
                        "curl mutation returned an unreadable response; reconcile before retrying"
                            .to_owned(),
                    )
                })
            }
            Ok(output) => parse_response(&output.stdout),
            Err(failure) => Err(failure_refusal(failure, request)),
        }
    }
}

/// One connector request as the launcher is asked for it.
fn build<'s>(
    curl: &TrustedCurl,
    settings: &'s NetSettings,
    request: &HttpRequest,
    deadline_secs: u64,
    allow_http: bool,
) -> CurlRequest<'s> {
    let mut curl = curl
        .request(settings, &request.url)
        .include_headers()
        .max_time(deadline_secs)
        .max_filesize(request.max_bytes)
        .capture_limit(request.max_bytes.saturating_add(HEADER_HEADROOM));
    curl = match request.method {
        Method::Get => curl,
        Method::Post => curl.method(pam_net::Method::Post),
        Method::Put => curl.method(pam_net::Method::Put),
    };
    if let Some(body) = &request.body {
        curl = curl.body(body);
    }
    for (name, value) in &request.headers {
        curl = curl.header(name, value);
    }
    #[cfg(any(test, feature = "testing"))]
    if allow_http {
        curl = curl.allow_http_for_tests();
    }
    #[cfg(not(any(test, feature = "testing")))]
    let _ = allow_http;
    curl
}

/// The refusal for a launcher failure that stopped the request before any
/// process ran: no curl, a profile that cannot be used, a value the config
/// cannot carry. These are policy, not network, so they keep their own
/// cause and are never retried as a transient failure.
fn refusal_before_spawn(failure: NetFailure) -> TransportError {
    match failure {
        NetFailure::CurlUnavailable => TransportError::Policy {
            cause: "trusted_curl_unavailable",
            detail:
                "A trusted operating-system curl is unavailable; no connector process was started."
                    .to_owned(),
        },
        NetFailure::Spawn(detail) => TransportError::Spawn(detail),
        NetFailure::CurlTooOld { .. }
        | NetFailure::SettingsInvalid(_)
        | NetFailure::CaBundleTampered
        | NetFailure::RequestInvalid { .. } => TransportError::Policy {
            cause: failure.cause(),
            detail: failure.sentence(),
        },
        other => TransportError::Net(other),
    }
}

/// The refusal for a launcher failure after curl ran.
///
/// Sizes and time keep the shapes the connectors already match on; the
/// rest is the launcher's own account. A mutation's failure carries the
/// reconcile hint instead: the request may have had its effect.
fn failure_refusal(failure: NetFailure, request: &HttpRequest) -> TransportError {
    match failure {
        NetFailure::TooLarge { .. } => TransportError::TooLarge {
            maximum: request.max_bytes,
        },
        NetFailure::Timeout | NetFailure::Deadline => TransportError::Timeout,
        NetFailure::CurlUnavailable
        | NetFailure::Spawn(_)
        | NetFailure::CurlTooOld { .. }
        | NetFailure::SettingsInvalid(_)
        | NetFailure::CaBundleTampered
        | NetFailure::RequestInvalid { .. } => refusal_before_spawn(failure),
        other if request.method != Method::Get => TransportError::Network(format!(
            "curl mutation failed ({}): {} Reconcile before retrying.",
            other.cause(),
            other.sentence()
        )),
        other => TransportError::Net(other),
    }
}

impl HttpTransport for CurlTransport {
    fn send<'a>(
        &'a self,
        request: HttpRequest,
        deadline: Instant,
    ) -> Pin<Box<dyn Future<Output = Result<HttpResponse, TransportError>> + Send + 'a>> {
        Box::pin(async move {
            validate_request_body(&request)?;
            validate_headers(&request)?;
            let deadline_secs = deadline
                .saturating_duration_since(Instant::now())
                .as_secs()
                .max(1);
            let response = Box::pin(self.run(&request, deadline_secs)).await?;
            if request.method != Method::Get && (300..400).contains(&response.status) {
                return Err(TransportError::Policy { cause: "mutation_redirect_refused", detail: "Mutation redirects are refused; reconcile the original operation before retrying.".to_owned() });
            }
            if !request.follow_one_https_redirect_without_auth
                || !matches!(response.status, 301 | 302 | 307 | 308)
            {
                return Ok(response);
            }
            let target = self.redirect_target(&request.url, &response)?;
            let mut next = request;
            next.url = target;
            next.headers
                .retain(|(name, _)| !name.eq_ignore_ascii_case("authorization"));
            next.follow_one_https_redirect_without_auth = false;
            let deadline_secs = deadline
                .saturating_duration_since(Instant::now())
                .as_secs()
                .max(1);
            Box::pin(self.run(&next, deadline_secs)).await
        })
    }
}

impl CurlTransport {
    /// The one hop a redirect-following request is allowed to take.
    ///
    /// GitHub answers a job-log request with a redirect to a signed storage
    /// URL; the signature is the credential there, so pam drops its own
    /// `Authorization` header before following, and refuses to follow
    /// anywhere but `https`. Each hop is its own curl process, so the proxy
    /// and the no-proxy list are evaluated for the hop's own host.
    fn redirect_target(&self, from: &Url, response: &HttpResponse) -> Result<Url, TransportError> {
        let location = response.header("location").ok_or_else(|| {
            TransportError::Network("the service redirected without a Location".to_owned())
        })?;
        let target = from.join(location).map_err(|error| {
            TransportError::Network(format!("the redirect target does not parse: {error}"))
        })?;
        let allowed = target.scheme() == "https" || (self.allow_http && target.scheme() == "http");
        if !allowed {
            return Err(TransportError::Network(
                "the redirect target is not https".to_owned(),
            ));
        }
        Ok(target)
    }
}

/// Turns `--include` output into a response.
///
/// `curl` prints one header block per hop, and a `100 Continue` prelude is a
/// block of its own, so blocks are consumed until one carries a real status.
/// A proxy's answer to the `CONNECT` is never in the output: the launcher
/// suppresses it.
pub(crate) fn parse_response(raw: &[u8]) -> Result<HttpResponse, TransportError> {
    let mut rest = raw;
    loop {
        let (head, body) = split_head(rest)?;
        let (status, headers) = parse_head(head)?;
        if (100..200).contains(&status) {
            rest = body;
            continue;
        }
        return Ok(HttpResponse {
            status,
            headers,
            body: body.to_vec(),
        });
    }
}

/// Splits one header block from the bytes that follow it.
fn split_head(raw: &[u8]) -> Result<(&[u8], &[u8]), TransportError> {
    if let Some(at) = find(raw, b"\r\n\r\n") {
        return Ok((&raw[..at], &raw[at + 4..]));
    }
    if let Some(at) = find(raw, b"\n\n") {
        return Ok((&raw[..at], &raw[at + 2..]));
    }
    Err(TransportError::Network(
        "curl produced no response headers".to_owned(),
    ))
}

/// The first index of `needle` in `haystack`.
fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// Reads a status line and the headers under it.
fn parse_head(head: &[u8]) -> Result<(u16, Vec<(String, String)>), TransportError> {
    let text = String::from_utf8_lossy(head);
    let mut lines = text.split('\n').map(|line| line.trim_end_matches('\r'));
    let status_line = lines.next().unwrap_or_default();
    if !status_line.starts_with("HTTP/") {
        return Err(TransportError::Network(format!(
            "curl produced an unreadable status line: {}",
            excerpt(status_line.as_bytes(), 120)
        )));
    }
    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse::<u16>().ok())
        .ok_or_else(|| {
            TransportError::Network(format!(
                "curl produced an unreadable status line: {}",
                excerpt(status_line.as_bytes(), 120)
            ))
        })?;
    let headers = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| (name.trim().to_owned(), value.trim().to_owned()))
        .collect();
    Ok((status, headers))
}

/// Refuses a header whose name or value holds a control character. The launcher's
/// escaping turns a line break into the two characters `\n`, which curl's config
/// parser turns back into a real line break inside the header value: one
/// `Authorization` value with an embedded newline would send an injected header line.
/// Nothing legitimate needs one. The launcher refuses the same thing; this check
/// runs first so the refusal is the connector's own, before any profile is read.
pub(crate) fn validate_headers(request: &HttpRequest) -> Result<(), TransportError> {
    if request
        .headers
        .iter()
        .any(|(name, value)| name.chars().chain(value.chars()).any(char::is_control))
    {
        return Err(TransportError::Policy {
            cause: "header_invalid",
            detail: "A request header holds a control character or line break; the request was not sent."
                .to_owned(),
        });
    }
    Ok(())
}

pub(crate) fn validate_request_body(request: &HttpRequest) -> Result<(), TransportError> {
    let valid = match (request.method, &request.body) {
        (Method::Get, None) => true,
        (Method::Post | Method::Put, Some(body)) if body.len() <= 16 * 1024 => {
            (serde_json::from_slice::<serde_json::Value>(body).is_ok_and(|value| value.is_object())
                || exact_upload_pack(request, body))
                && !request.follow_one_https_redirect_without_auth
        }
        _ => false,
    };
    if valid {
        Ok(())
    } else {
        Err(TransportError::Policy {
            cause: "mutation_body_invalid",
            detail: "HTTP mutation requires bounded JSON and disabled redirects.".to_owned(),
        })
    }
}

// The only non-JSON body admitted is a fixed read-only Git upload-pack request.
// No arbitrary packet, capability, revision expression or remote mutation body.
fn exact_upload_pack(request: &HttpRequest, body: &[u8]) -> bool {
    // "0033want <sha> \n" "0000" then at most two "0032have <sha>\n" then "0009done\n".
    let Some(rest) = body.strip_prefix(b"0033want ") else {
        return false;
    };
    let Some((sha, mut rest)) = rest.split_first_chunk::<40>() else {
        return false;
    };
    let Some(after_want) = rest.strip_prefix(b" \n0000") else {
        return false;
    };
    rest = after_want;
    let mut haves = 0;
    while let Some(after_have) = rest.strip_prefix(b"0032have ") {
        let Some((have, tail)) = after_have.split_first_chunk::<40>() else {
            return false;
        };
        let Some(tail) = tail.strip_prefix(b"\n") else {
            return false;
        };
        if !exact_sha(have) || haves == 2 {
            return false;
        }
        haves += 1;
        rest = tail;
    }
    rest == b"0009done\n"
        && exact_sha(sha)
        && request.method == Method::Post
        && request.url.scheme() == "https"
        && request.url.username().is_empty()
        && request.url.password().is_none()
        && request.url.query().is_none()
        && request.url.fragment().is_none()
        && request.url.path().ends_with("/git-upload-pack")
        && request
            .headers
            .iter()
            .filter(|(name, _)| name.eq_ignore_ascii_case("content-type"))
            .count()
            == 1
        && request.headers.iter().any(|(name, value)| {
            name.eq_ignore_ascii_case("content-type")
                && value == "application/x-git-upload-pack-request"
        })
}

fn exact_sha(sha: &[u8]) -> bool {
    sha.len() == 40
        && sha
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
        && sha.iter().any(|byte| *byte != b'0')
}
