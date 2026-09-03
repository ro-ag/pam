//! The production transport: the system `curl`, driven as a child process.
//!
//! pam does not link a TLS stack. It shells out to the `curl` the operating
//! system already trusts, which keeps the dependency tree free of C and puts
//! certificate verification in the hands of the platform.
//!
//! The credential never reaches the argument vector. `curl` is started with
//! `--config -` and the URL and every header — `Authorization` included —
//! are written to its standard input, so a secret is invisible to `ps`, to
//! the audit log, and to anything that samples process arguments.

use std::fmt::Write as _;
use std::path::PathBuf;
use std::pin::Pin;
use std::process::Stdio;
use std::time::Instant;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::{Child, Command};
use url::Url;

use crate::transport::{HttpRequest, HttpResponse, HttpTransport, TransportError, excerpt};

/// How much room over `max_bytes` the status line and headers may take.
const HEADER_HEADROOM: u64 = 64 * 1024;

/// How much of curl's standard error is kept for a failure message.
const MAX_STDERR_BYTES: u64 = 4 * 1024;

/// How long past the request's own deadline curl is given to exit before it
/// is killed, so a wedged child cannot outlive the step.
const GRACE_SECS: u64 = 5;

/// `curl` as an [`HttpTransport`].
///
/// The path is injected rather than looked up here: the daemon resolves
/// `curl` once at start-up and reports a missing one as its own refusal.
#[derive(Debug, Clone)]
pub struct CurlTransport {
    curl: PathBuf,
    allow_http: bool,
}

impl CurlTransport {
    /// A transport that runs the `curl` at `curl`.
    #[must_use]
    pub fn new(curl: PathBuf) -> Self {
        Self {
            curl,
            allow_http: false,
        }
    }

    /// Lets this transport speak plain `http` as well as `https`.
    ///
    /// Only the crate's own origin test uses it, to point real `curl` at a
    /// throwaway `TcpListener`. Production always keeps `--proto =https`.
    #[cfg(any(test, feature = "testing"))]
    #[must_use]
    pub fn allow_http_for_tests(mut self) -> Self {
        self.allow_http = true;
        self
    }

    /// The `--config -` document for one request.
    ///
    /// Public so a test can prove the secret is here and not in argv. The
    /// deadline is repeated in the argument vector; curl takes the last
    /// spelling of an option and the two are identical.
    #[must_use]
    pub fn config_for(request: &HttpRequest, deadline_secs: u64) -> String {
        let mut config = format!(
            "url = \"{}\"\nmax-time = {deadline_secs}\n",
            escape(request.url.as_str())
        );
        for (name, value) in &request.headers {
            writeln!(config, "header = \"{}: {}\"", escape(name), escape(value))
                .expect("writing into a String cannot fail");
        }
        config
    }

    /// The `--proto` restriction this transport runs under.
    fn proto(&self) -> &'static str {
        if self.allow_http {
            "=https,http"
        } else {
            "=https"
        }
    }

    /// Runs curl once and turns its exit into a response or a failure.
    async fn run(
        &self,
        request: &HttpRequest,
        deadline_secs: u64,
    ) -> Result<HttpResponse, TransportError> {
        let mut command = Command::new(&self.curl);
        command
            .arg("--config")
            .arg("-")
            .arg("--silent")
            .arg("--show-error")
            .arg("--include")
            .arg("--max-time")
            .arg(deadline_secs.to_string())
            .arg("--max-filesize")
            .arg(request.max_bytes.to_string())
            .arg("--proto")
            .arg(self.proto())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);

        let mut child = command
            .spawn()
            .map_err(|error| TransportError::Spawn(error.to_string()))?;

        let config = Self::config_for(request, deadline_secs);
        if let Some(mut stdin) = child.stdin.take() {
            // A closed stdin is not fatal on its own: curl may already have
            // failed, and its exit code says so more precisely than this
            // write does.
            let _ = stdin.write_all(config.as_bytes()).await;
            let _ = stdin.shutdown().await;
        }

        let cap = request.max_bytes.saturating_add(HEADER_HEADROOM);
        let mut stdout = child.stdout.take();
        let mut stderr = child.stderr.take();
        let ((body, truncated), (stderr_bytes, _)) = tokio::join!(
            read_capped(&mut stdout, cap),
            read_capped(&mut stderr, MAX_STDERR_BYTES),
        );
        if truncated {
            kill(&mut child).await;
            return Err(TransportError::TooLarge {
                maximum: request.max_bytes,
            });
        }

        let status =
            match tokio::time::timeout(std::time::Duration::from_secs(GRACE_SECS), child.wait())
                .await
            {
                Ok(Ok(status)) => status,
                Ok(Err(error)) => return Err(TransportError::Spawn(error.to_string())),
                Err(_) => {
                    kill(&mut child).await;
                    return Err(TransportError::Timeout);
                }
            };
        match status.code() {
            Some(0) => parse_response(&body),
            Some(28) => Err(TransportError::Timeout),
            Some(35 | 51 | 58 | 59 | 60) => Err(TransportError::Certificate),
            Some(63) => Err(TransportError::TooLarge {
                maximum: request.max_bytes,
            }),
            Some(code) => Err(TransportError::Network(format!(
                "curl exited {code}: {}",
                excerpt(&stderr_bytes, 512)
            ))),
            None => Err(TransportError::Network(
                "curl was terminated before it answered".to_owned(),
            )),
        }
    }
}

impl HttpTransport for CurlTransport {
    fn send<'a>(
        &'a self,
        request: HttpRequest,
        deadline: Instant,
    ) -> Pin<Box<dyn Future<Output = Result<HttpResponse, TransportError>> + Send + 'a>> {
        Box::pin(async move {
            let deadline_secs = deadline
                .saturating_duration_since(Instant::now())
                .as_secs()
                .max(1);
            let response = Box::pin(self.run(&request, deadline_secs)).await?;
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
    /// anywhere but `https`.
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

/// Reads a child stream, stopping once `cap` bytes have arrived.
///
/// Answers `(bytes, over_the_cap)`; a read error ends the stream rather than
/// failing the request, because the child's exit code is the better story.
pub(crate) async fn read_capped<R>(reader: &mut Option<R>, cap: u64) -> (Vec<u8>, bool)
where
    R: AsyncReadExt + Unpin,
{
    let mut buffer = Vec::new();
    let Some(reader) = reader.as_mut() else {
        return (buffer, false);
    };
    let mut chunk = [0_u8; 8192];
    loop {
        match reader.read(&mut chunk).await {
            Ok(0) | Err(_) => return (buffer, false),
            Ok(read) => {
                buffer.extend_from_slice(&chunk[..read]);
                if buffer.len() as u64 > cap {
                    return (buffer, true);
                }
            }
        }
    }
}

/// Ends a child that is no longer wanted.
async fn kill(child: &mut Child) {
    let _ = child.start_kill();
    let _ = child.wait().await;
}

/// Escapes a value for a double-quoted curl config field.
fn escape(raw: &str) -> String {
    raw.replace('\\', "\\\\").replace('"', "\\\"")
}

/// Turns `--include` output into a response.
///
/// `curl` prints one header block per hop, and a `100 Continue` prelude is a
/// block of its own, so blocks are consumed until one carries a real status.
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
