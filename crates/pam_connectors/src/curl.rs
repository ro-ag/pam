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
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::process::Stdio;
use std::time::Instant;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::{Child, Command};
use url::Url;

use crate::transport::{HttpRequest, HttpResponse, HttpTransport, Method, TransportError, excerpt};

fn untrusted_curl() -> TransportError {
    TransportError::Policy {
        cause: "trusted_curl_unavailable",
        detail: "A trusted operating-system curl is unavailable; no connector process was started."
            .to_owned(),
    }
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn trusted_curl_path() -> Result<PathBuf, TransportError> {
    use std::os::unix::fs::MetadataExt;
    let path = std::fs::canonicalize("/usr/bin/curl").map_err(|_| untrusted_curl())?;
    let binary = path.metadata().map_err(|_| untrusted_curl())?;
    if !binary.is_file() || binary.mode() & 0o111 == 0 {
        return Err(untrusted_curl());
    }
    // Canonical paths remove symlinks; every component must remain outside
    // an ordinary same-user agent's write authority.
    for ancestor in path.ancestors() {
        let metadata = ancestor.symlink_metadata().map_err(|_| untrusted_curl())?;
        if metadata.file_type().is_symlink() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0
        {
            return Err(untrusted_curl());
        }
    }
    Ok(path)
}

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
fn trusted_curl_path() -> Result<PathBuf, TransportError> {
    Err(untrusted_curl())
}

/// Windows has no root-owned file model readable without unsafe or a
/// platform crate, so trust comes from the one path the operating system
/// itself owns and services: `%SystemRoot%\System32\curl.exe`. The fixed
/// location is what rules out a planted lookalike — PATH is never searched
/// — and the canonicalized file must still resolve inside the
/// canonicalized System32 directory.
#[cfg(target_os = "windows")]
fn trusted_curl_path() -> Result<PathBuf, TransportError> {
    let system_root = std::env::var_os("SystemRoot").ok_or_else(untrusted_curl)?;
    let system32 = std::fs::canonicalize(std::path::Path::new(&system_root).join("System32"))
        .map_err(|_| untrusted_curl())?;
    let candidate = system32.join("curl.exe");
    let canonical = std::fs::canonicalize(&candidate).map_err(|_| untrusted_curl())?;
    if !canonical.is_file() {
        return Err(untrusted_curl());
    }
    Ok(canonical)
}

/// How much room over `max_bytes` the status line and headers may take.
const HEADER_HEADROOM: u64 = 64 * 1024;

/// How much of curl's standard error is kept for a failure message.
const MAX_STDERR_BYTES: u64 = 4 * 1024;

/// How long past the request's own deadline curl is given to exit before it
/// is killed, so a wedged child cannot outlive the step.
const GRACE_SECS: u64 = 5;

/// `curl` as an [`HttpTransport`].
///
/// Only the verified operating-system curl may execute: [`Self::trusted`]
/// resolves it, and a path handed to [`Self::new`] is checked against that
/// binary before every spawn, so nothing can select a PATH substitute.
#[derive(Debug, Clone)]
pub struct CurlTransport {
    curl: PathBuf,
    allow_http: bool,
}

impl CurlTransport {
    /// The transport over the operating-system curl, or the policy refusal
    /// when this platform has no verifiable one. This is the constructor:
    /// there is exactly one executable a transport may run, so there is
    /// nothing for a caller to choose.
    pub fn trusted() -> Result<Self, TransportError> {
        Ok(Self {
            curl: trusted_curl_path()?,
            allow_http: false,
        })
    }

    /// [`Self::trusted`] with the path spelled out — kept for callers that
    /// resolved [`Self::trusted_path`] themselves. The path is still checked
    /// against the trusted binary at spawn; bare `curl` is an explicit system
    /// selector, never a PATH lookup, and any other executable fails closed
    /// before spawning. New code calls [`Self::trusted`].
    #[must_use]
    pub fn new(curl: PathBuf) -> Self {
        Self {
            curl,
            allow_http: false,
        }
    }

    /// The fixed trusted operating-system executable, without searching PATH.
    /// Platforms without a verifiable operating-system curl, or unsafe
    /// filesystem ownership, fail closed.
    pub fn trusted_path() -> Result<PathBuf, TransportError> {
        trusted_curl_path()
    }

    pub(crate) fn command(
        &self,
        request: &HttpRequest,
        deadline_secs: u64,
    ) -> Result<Command, TransportError> {
        let trusted = Self::trusted_path()?;
        if self.curl != Path::new("curl")
            && std::fs::canonicalize(&self.curl).map_err(|_| untrusted_curl())? != trusted
        {
            return Err(untrusted_curl());
        }
        let mut command = Command::new(trusted);
        command
            .arg("-q") // MUST be first: disables all implicit curlrc loading.
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
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        // The cleared environment keeps nothing the daemon holds, but a
        // Windows child cannot initialize WinSock or the crypto stack
        // without the system roots, and `/` is not a working directory
        // there — the drive root is the neutral equivalent.
        #[cfg(target_os = "windows")]
        {
            for key in [
                "SystemRoot",
                "SystemDrive",
                "windir",
                "COMSPEC",
                "TEMP",
                "TMP",
            ] {
                if let Some(value) = std::env::var_os(key) {
                    command.env(key, value);
                }
            }
            let drive = std::env::var("SystemDrive").unwrap_or_else(|_| "C:".to_string());
            command.current_dir(format!("{drive}\\"));
        }
        #[cfg(not(target_os = "windows"))]
        command.current_dir("/");
        Ok(command)
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
        if request.method != Method::Get {
            writeln!(config, "request = \"{}\"", request.method.as_str()).expect("String writer");
        }
        if let Some(body) = &request.body {
            writeln!(
                config,
                "data-binary = \"{}\"",
                escape(&String::from_utf8_lossy(body))
            )
            .expect("String writer");
        }
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
        let mut command = self.command(request, deadline_secs)?;

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
            Some(0) if request.method != Method::Get => parse_response(&body).map_err(|_| {
                TransportError::Network(
                    "curl mutation returned an unreadable response; reconcile before retrying"
                        .to_owned(),
                )
            }),
            Some(0) => parse_response(&body),
            Some(28) => Err(TransportError::Timeout),
            Some(35 | 51 | 58 | 59 | 60) => Err(TransportError::Certificate),
            Some(63) => Err(TransportError::TooLarge {
                maximum: request.max_bytes,
            }),
            Some(code) if request.method != Method::Get => Err(TransportError::Network(format!(
                "curl mutation failed with exit {code}; reconcile before retrying"
            ))),
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
            validate_request_body(&request)?;
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
    raw.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace('\t', "\\t")
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
