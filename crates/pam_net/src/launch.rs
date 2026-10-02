//! Building and running one curl process.
//!
//! [`CurlRequest`] is the only place in pam that decides what a curl process
//! is given. The contract, for every request:
//!
//! * the argument vector is the constant [`CURL_ARGV`] (`-q --config -`);
//!   `-q` is first, so no curlrc is read;
//! * everything else is a line of the stdin config document, written by the
//!   one escaping function ([`crate::escape`]); standard input is closed
//!   once the document is written, so curl can read nothing else from it;
//! * the environment is empty (on Windows, the system variables in
//!   [`crate::WINDOWS_KEPT_ENV`] only) and the working directory is the
//!   filesystem root, so no proxy variable, CA variable or curlrc the daemon
//!   inherited has any effect;
//! * the proxy, its credential, the no-proxy list and the CA bundle come
//!   from the [`NetSettings`] handed in, and from nowhere else;
//! * certificate verification is never relaxed: the builder has no method
//!   that could, and a test scans this crate's source for the options that
//!   would;
//! * standard output and standard error are read with caps, and the child is
//!   killed when a cap or the caller's deadline is passed, or when the
//!   [`CurlChild`] is dropped.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::process::{Child, ChildStderr, ChildStdout, Command};
use url::{Host, Url};

use crate::config::{ConfigDoc, MAX_CONFIG_BYTES};
use crate::failure::{Diagnostics, NetFailure, Transfer, classify};
use crate::settings::{NetSettings, NoProxyRule, ProxyAuth, ProxyScheme, Route, is_loopback};
use crate::trusted::{TlsBackend, TrustedCurl, apply_environment};

/// The whole argument vector of every curl process pam starts.
pub const CURL_ARGV: [&str; 3] = ["-q", "--config", "-"];

/// What standard output may hold when the request sets no limit of its own:
/// enough for a small answer, small enough that a request writing to a file
/// cannot be used to fill memory.
pub const DEFAULT_CAPTURE_BYTES: u64 = 64 * 1024;

/// How much of curl's own error text is kept.
const MAX_STDERR_BYTES: usize = 4 * 1024;

/// The longest single line of standard error that is looked at.
const MAX_STDERR_LINE: usize = 2 * 1024;

/// How long curl may take to read its config before it is killed.
const STDIN_LIMIT: Duration = Duration::from_secs(10);

/// The first word of the diagnostics line the launcher asks curl to print.
const SENTINEL: &str = "pam-net ";

/// The diagnostics line: numbers only, on standard error, on its own line.
const WRITE_OUT: &str = "%{stderr}\npam-net http_connect=%{http_connect} http_code=%{http_code} \
                         ssl_verify=%{ssl_verify_result} num_connects=%{num_connects}\n";

/// The HTTP verbs the launcher sends.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Method {
    /// `GET`.
    #[default]
    Get,
    /// `HEAD`: headers only. What a network probe sends.
    Head,
    /// `POST`.
    Post,
    /// `PUT`.
    Put,
}

/// One request, being assembled.
///
/// Created by [`TrustedCurl::request`]. Setters only record; everything is
/// validated when the config is rendered ([`Self::config`], [`Self::spawn`],
/// [`Self::run`]), so a refused value is reported once, as a
/// [`NetFailure::RequestInvalid`], before any process starts.
///
/// There is deliberately no `Debug`: the headers usually hold a credential.
#[allow(clippy::struct_excessive_bools)] // Independent switches of one curl run; no mutually exclusive states.
pub struct CurlRequest<'a> {
    curl: TrustedCurl,
    settings: &'a NetSettings,
    url: Url,
    method: Method,
    headers: Vec<(String, String)>,
    body: Option<Vec<u8>>,
    max_time: Option<u64>,
    connect_timeout: Option<u64>,
    speed: Option<(u64, u64)>,
    max_filesize: Option<u64>,
    capture_limit: u64,
    include_headers: bool,
    fail_on_http_error: bool,
    follow_redirects: Option<u32>,
    output: Option<PathBuf>,
    etag_save: Option<PathBuf>,
    resume: bool,
    diagnostic: bool,
    unix_socket: Option<PathBuf>,
    allow_http: bool,
}

impl TrustedCurl {
    /// Starts a request to `url` under `settings`.
    #[must_use]
    pub fn request<'a>(&self, settings: &'a NetSettings, url: &Url) -> CurlRequest<'a> {
        CurlRequest {
            curl: self.clone(),
            settings,
            url: url.clone(),
            method: Method::Get,
            headers: Vec::new(),
            body: None,
            max_time: None,
            connect_timeout: None,
            speed: None,
            max_filesize: None,
            capture_limit: DEFAULT_CAPTURE_BYTES,
            include_headers: false,
            fail_on_http_error: false,
            follow_redirects: None,
            output: None,
            etag_save: None,
            resume: false,
            diagnostic: false,
            unix_socket: None,
            allow_http: false,
        }
    }
}

impl CurlRequest<'_> {
    /// Sets the verb. The default is `GET`.
    #[must_use]
    pub fn method(mut self, method: Method) -> Self {
        self.method = method;
        self
    }

    /// Adds a request header. The name must be an HTTP token and neither
    /// half may hold a control character; `Proxy-Authorization` is refused
    /// (the proxy credential comes from the settings, never from a caller).
    #[must_use]
    pub fn header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.to_owned(), value.to_owned()));
        self
    }

    /// Sets the request body, sent exactly as given. Only `POST` and `PUT`
    /// carry one; it must be UTF-8 text with no control character other
    /// than tab, line feed and carriage return.
    #[must_use]
    pub fn body(mut self, body: &[u8]) -> Self {
        self.body = Some(body.to_vec());
        self
    }

    /// curl's own limit on the whole transfer, in seconds (at least 1).
    #[must_use]
    pub fn max_time(mut self, seconds: u64) -> Self {
        self.max_time = Some(seconds.max(1));
        self
    }

    /// curl's limit on establishing the connection, in seconds (at least 1).
    #[must_use]
    pub fn connect_timeout(mut self, seconds: u64) -> Self {
        self.connect_timeout = Some(seconds.max(1));
        self
    }

    /// Abandons a transfer that stays under `bytes_per_second` for
    /// `window_seconds` (at least 1; zero would switch the check off).
    #[must_use]
    pub fn stall_limit(mut self, bytes_per_second: u64, window_seconds: u64) -> Self {
        self.speed = Some((bytes_per_second, window_seconds.max(1)));
        self
    }

    /// Asks curl to refuse a body it knows is larger than `bytes`. curl can
    /// only honour this when the server declares a length, so
    /// [`Self::capture_limit`] remains the bound that always holds.
    #[must_use]
    pub fn max_filesize(mut self, bytes: u64) -> Self {
        self.max_filesize = Some(bytes);
        self
    }

    /// The most standard output may hold (response headers included when
    /// [`Self::include_headers`] is set). One byte more and curl is killed
    /// with [`NetFailure::TooLarge`]. Defaults to [`DEFAULT_CAPTURE_BYTES`].
    #[must_use]
    pub fn capture_limit(mut self, bytes: u64) -> Self {
        self.capture_limit = bytes;
        self
    }

    /// Prints the response headers before the body on standard output. The
    /// proxy's own `CONNECT` answer is never part of that output.
    #[must_use]
    pub fn include_headers(mut self) -> Self {
        self.include_headers = true;
        self
    }

    /// Makes an HTTP status of 400 or above a failure
    /// ([`NetFailure::HttpStatus`]) instead of a saved error page.
    #[must_use]
    pub fn fail_on_http_error(mut self) -> Self {
        self.fail_on_http_error = true;
        self
    }

    /// Lets curl follow up to `max_hops` redirects, each to `https` only.
    /// Refused together with an `Authorization` or `Cookie` header: a
    /// caller that authenticates follows its own hops, one process each.
    #[must_use]
    pub fn follow_https_redirects(mut self, max_hops: u32) -> Self {
        self.follow_redirects = Some(max_hops);
        self
    }

    /// Writes the response body to `path` (absolute) instead of standard
    /// output.
    #[must_use]
    pub fn output(mut self, path: &Path) -> Self {
        self.output = Some(path.to_path_buf());
        self
    }

    /// Saves the response `ETag` to `path` (absolute).
    #[must_use]
    pub fn etag_save(mut self, path: &Path) -> Self {
        self.etag_save = Some(path.to_path_buf());
        self
    }

    /// Continues from whatever the output file already holds.
    #[must_use]
    pub fn resume(mut self) -> Self {
        self.resume = true;
        self
    }

    /// Runs with curl's verbose trace on, for the network test. Only the
    /// certificate's `issuer:`/`subject:` lines and the proxy's
    /// `Proxy-Authenticate` schemes are read from it; every other line —
    /// request headers and the `Proxy-Authorization` line among them — is
    /// dropped as it is read and never stored, logged or returned.
    #[must_use]
    pub fn diagnostic(mut self) -> Self {
        self.diagnostic = true;
        self
    }

    /// Connects through a Unix-domain socket (absolute path) instead of
    /// TCP. Such a request never uses a proxy.
    #[must_use]
    pub fn unix_socket(mut self, path: &Path) -> Self {
        self.unix_socket = Some(path.to_path_buf());
        self
    }

    /// Lets this request, and any redirect it follows, use plain `http`.
    ///
    /// Only fixtures use it, to point real curl at a throwaway loopback
    /// listener. Production requests are `https` only.
    #[cfg(any(test, feature = "testing"))]
    #[must_use]
    pub fn allow_http_for_tests(mut self) -> Self {
        self.allow_http = true;
        self
    }

    /// Where the first hop goes: [`NetSettings::route_for`], except that a
    /// Unix-socket request with a proxy configured is always a bypass.
    #[must_use]
    pub fn route(&self) -> Route {
        if self.unix_socket.is_some() && self.settings.proxy().is_some() {
            return Route::Bypass;
        }
        self.settings.route_for(&self.url)
    }

    /// The stdin config document for this request.
    ///
    /// Public so a test can prove where a secret is (here) and is not (the
    /// argument vector, the environment). Treat the result as a secret: it
    /// holds the headers and the proxy password.
    pub fn config(&self) -> Result<String, NetFailure> {
        let mut doc = ConfigDoc::default();
        self.request_lines(&mut doc)?;
        self.transfer_lines(&mut doc)?;
        self.network_lines(&mut doc)?;
        if self.curl.info().supports_stderr_write_out() {
            put(&mut doc, "write-out", WRITE_OUT, "write-out")?;
        }
        if self.diagnostic {
            doc.flag("verbose");
        }
        let text = doc.finish();
        if text.len() > MAX_CONFIG_BYTES {
            return Err(invalid(
                "request",
                format!("the request is larger than {MAX_CONFIG_BYTES} bytes"),
            ));
        }
        Ok(text)
    }

    /// The URL, the verb, the headers and the body.
    fn request_lines(&self, doc: &mut ConfigDoc) -> Result<(), NetFailure> {
        let scheme_ok = match self.url.scheme() {
            "https" => true,
            "http" => self.allow_http,
            _ => false,
        };
        if !scheme_ok {
            return Err(invalid("url", "only https addresses are requested"));
        }
        if self.url.host().is_none() {
            return Err(invalid("url", "the address has no host"));
        }
        if !self.url.username().is_empty() || self.url.password().is_some() {
            return Err(invalid(
                "url",
                "the address carries a user name or password; credentials go in a header",
            ));
        }
        put(doc, "url", self.url.as_str(), "url")?;
        // The URL is one address, never a pattern: without this curl would
        // expand `{a,b}` and `[1-9]` in it into several requests.
        doc.flag("globoff");
        doc.flag("silent");
        doc.flag("show-error");
        match self.method {
            Method::Get => {}
            Method::Head => doc.flag("head"),
            Method::Post => put(doc, "request", "POST", "method")?,
            Method::Put => put(doc, "request", "PUT", "method")?,
        }
        for (name, value) in &self.headers {
            self.header_line(doc, name, value)?;
        }
        if let Some(body) = &self.body {
            if !matches!(self.method, Method::Post | Method::Put) {
                return Err(invalid("body", "only POST and PUT carry a body"));
            }
            let text = std::str::from_utf8(body)
                .map_err(|_| invalid("body", "the body is not UTF-8 text"))?;
            // `data-raw`, not `data`: a body starting with `@` is a body,
            // never the name of a file to read.
            put(doc, "data-raw", text, "body")?;
        }
        Ok(())
    }

    fn header_line(&self, doc: &mut ConfigDoc, name: &str, value: &str) -> Result<(), NetFailure> {
        if name.is_empty() || !name.bytes().all(is_token_byte) {
            return Err(invalid("header", "a header name is not an HTTP token"));
        }
        if value.chars().any(char::is_control) {
            return Err(invalid(
                "header",
                "a header value holds a control character or a line break",
            ));
        }
        if name.eq_ignore_ascii_case("proxy-authorization") {
            return Err(invalid(
                "header",
                "the proxy credential comes from the network settings, not from a header",
            ));
        }
        let credentialed =
            name.eq_ignore_ascii_case("authorization") || name.eq_ignore_ascii_case("cookie");
        if credentialed && self.follow_redirects.is_some() {
            return Err(invalid(
                "header",
                "a request that carries a credential does not follow redirects inside curl",
            ));
        }
        let value = value.trim();
        // curl reads `Name:` as "remove this header" and `Name;` as "send
        // it empty"; an empty value means the latter.
        let line = if value.is_empty() {
            format!("{name};")
        } else {
            format!("{name}: {value}")
        };
        put(doc, "header", &line, "header")
    }

    /// Protocols, limits and where the answer goes.
    fn transfer_lines(&self, doc: &mut ConfigDoc) -> Result<(), NetFailure> {
        let protocols = if self.allow_http {
            "=https,http"
        } else {
            "=https"
        };
        put(doc, "proto", protocols, "proto")?;
        put(doc, "proto-redir", protocols, "proto")?;
        // Retry policy belongs to the caller, where it can be reported.
        doc.number("retry", 0);
        if let Some(seconds) = self.max_time {
            doc.number("max-time", seconds);
        }
        if let Some(seconds) = self.connect_timeout {
            doc.number("connect-timeout", seconds);
        }
        if let Some((rate, window)) = self.speed {
            doc.number("speed-limit", rate);
            doc.number("speed-time", window);
        }
        if let Some(bytes) = self.max_filesize {
            doc.number("max-filesize", bytes);
        }
        if self.include_headers {
            doc.flag("include");
        }
        if self.fail_on_http_error {
            doc.flag("fail");
        }
        if let Some(hops) = self.follow_redirects {
            doc.flag("location");
            doc.number("max-redirs", u64::from(hops));
        }
        if let Some(path) = &self.output {
            put(doc, "output", path_text(path, "output")?, "output")?;
        }
        if let Some(path) = &self.etag_save {
            put(doc, "etag-save", path_text(path, "etag-save")?, "etag-save")?;
        }
        if self.resume {
            if self.output.is_none() {
                return Err(invalid("resume", "only a download to a file can resume"));
            }
            put(doc, "continue-at", "-", "resume")?;
        }
        if let Some(path) = &self.unix_socket {
            put(
                doc,
                "unix-socket",
                path_text(path, "unix-socket")?,
                "unix-socket",
            )?;
        }
        Ok(())
    }

    /// The proxy, its credential, the no-proxy list and the CA bundle.
    fn network_lines(&self, doc: &mut ConfigDoc) -> Result<(), NetFailure> {
        let info = self.curl.info();
        let rules = self.settings.no_proxy();
        let proxy = self
            .settings
            .proxy()
            .filter(|_| self.unix_socket.is_none() && !rules.iter().any(NoProxyRule::is_any));
        let https_proxy = proxy.is_some_and(|proxy| proxy.scheme() == ProxyScheme::Https);
        match proxy {
            // No proxy for this request. The explicit line means "none",
            // whatever a curl build might otherwise pick up.
            None => put(doc, "noproxy", "*", "no_proxy")?,
            Some(proxy) => {
                if !info.supports_proxy() {
                    return Err(NetFailure::CurlTooOld {
                        found: info.version_text(),
                        needed: "7.63.0",
                        feature: "a proxy",
                    });
                }
                if https_proxy && !info.https_proxy {
                    return Err(NetFailure::SettingsInvalid(
                        "this computer's curl cannot use an https:// proxy; use the proxy's \
                         http:// address"
                            .to_owned(),
                    ));
                }
                if rules.iter().any(NoProxyRule::is_cidr) && !info.supports_cidr_no_proxy() {
                    return Err(NetFailure::CurlTooOld {
                        found: info.version_text(),
                        needed: "7.86.0",
                        feature: "a CIDR range in the no-proxy list",
                    });
                }
                put(doc, "proxy", &proxy.url(), "proxy.url")?;
                // Always a CONNECT tunnel, so the proxy sees a host and a
                // port and nothing of the request; and its answer to the
                // CONNECT is kept out of the response the caller parses.
                doc.flag("proxytunnel");
                doc.flag("suppress-connect-headers");
                put(doc, "noproxy", &self.no_proxy_text(), "no_proxy")?;
                if let Some((username, password)) = self.settings.proxy_credential() {
                    let pair = format!("{username}:{}", password.expose());
                    let written = put(doc, "proxy-user", &pair, "credential");
                    drop(Wiped(pair));
                    written?;
                    doc.flag(match proxy.auth() {
                        ProxyAuth::AnyAuth => "proxy-anyauth",
                        ProxyAuth::Basic | ProxyAuth::None => "proxy-basic",
                    });
                }
            }
        }
        if let Some(path) = self.settings.ca_bundle() {
            let path = path_text(path, "ca_bundle")?;
            put(doc, "cacert", path, "ca_bundle")?;
            if https_proxy {
                // The proxy's own certificate is held to the same bundle.
                put(doc, "proxy-cacert", path, "ca_bundle")?;
            }
        }
        Ok(())
    }

    /// The list curl evaluates for every hop: the human's entries, plus the
    /// target itself when it is this machine's loopback.
    ///
    /// Adding the one loopback host — instead of switching the proxy off
    /// for the whole process — keeps a redirect from a local service to an
    /// outside host on the proxy.
    fn no_proxy_text(&self) -> String {
        let mut entries: Vec<String> = self
            .settings
            .no_proxy()
            .iter()
            .map(|rule| rule.curl_text().to_owned())
            .collect();
        if is_loopback(&self.url) {
            match self.url.host() {
                Some(Host::Domain(name)) => {
                    entries.push(name.trim_end_matches('.').to_ascii_lowercase());
                }
                Some(Host::Ipv4(address)) => entries.push(address.to_string()),
                Some(Host::Ipv6(address)) => entries.push(address.to_string()),
                None => {}
            }
        }
        entries.join(",")
    }

    /// The process to start: the trusted curl, the constant arguments, an
    /// empty environment, the filesystem root, three pipes.
    pub(crate) fn command(&self) -> Command {
        let mut command = std::process::Command::new(self.curl.path());
        command
            .args(CURL_ARGV)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        apply_environment(&mut command);
        let mut command = Command::from(command);
        command.kill_on_drop(true);
        command
    }

    /// Starts curl and hands it the config.
    ///
    /// The caller then owns the transfer: [`CurlChild::wait`] to let it
    /// finish (a download watching for a cancel), [`CurlChild::wait_within`]
    /// for a hard deadline. Dropping the child kills curl.
    pub async fn spawn(self) -> Result<CurlChild, NetFailure> {
        let route = self.route();
        let config = Wiped(self.config()?);
        let mut child = self
            .command()
            .spawn()
            .map_err(|error| NetFailure::Spawn(error.to_string()))?;
        if let Some(mut stdin) = child.stdin.take() {
            // A write error is not fatal by itself: curl may already have
            // failed, and its exit code says why more precisely.
            let feed = async {
                let _ = stdin.write_all(config.0.as_bytes()).await;
                let _ = stdin.shutdown().await;
            };
            if tokio::time::timeout(STDIN_LIMIT, feed).await.is_err() {
                let _ = child.start_kill();
                let _ = child.wait().await;
                return Err(NetFailure::Spawn(
                    "curl did not read its configuration".to_owned(),
                ));
            }
        }
        drop(config);
        let stdout = child.stdout.take();
        let stderr = child.stderr.take();
        Ok(CurlChild {
            child,
            stdout,
            stderr,
            body: Vec::new(),
            capture_limit: self.capture_limit,
            sink: StderrSink::new(self.diagnostic),
            route,
            target_host: self.url.host_str().unwrap_or_default().to_owned(),
            target_port: self.url.port_or_known_default().unwrap_or(443),
            credential_sent: self.settings.sends_proxy_credential(),
            cacert_set: self.settings.ca_bundle().is_some(),
            backend: self.curl.info().backend.clone(),
            max_filesize: self.max_filesize,
        })
    }

    /// Runs the request to its end, killing curl when `deadline` passes.
    ///
    /// `deadline` is the hard limit; give curl its own shorter
    /// [`Self::max_time`] so the usual timeout is curl's clean exit and this
    /// one only ends a process that has stopped responding.
    pub async fn run(self, deadline: Duration) -> Result<CurlOutput, NetFailure> {
        let mut child = self.spawn().await?;
        child.wait_within(deadline).await
    }
}

/// A running curl process.
///
/// Dropping it kills the process.
pub struct CurlChild {
    child: Child,
    stdout: Option<ChildStdout>,
    stderr: Option<ChildStderr>,
    body: Vec<u8>,
    capture_limit: u64,
    sink: StderrSink,
    route: Route,
    target_host: String,
    target_port: u16,
    credential_sent: bool,
    cacert_set: bool,
    backend: TlsBackend,
    max_filesize: Option<u64>,
}

impl CurlChild {
    /// Waits for curl to exit, draining both of its pipes under their caps.
    ///
    /// Cancel-safe: dropping the future (a `select!` arm that lost) loses
    /// nothing, and calling `wait` again carries on. Call it to completion
    /// once.
    pub async fn wait(&mut self) -> Result<CurlOutput, NetFailure> {
        let mut out_chunk = [0_u8; 8192];
        let mut err_chunk = [0_u8; 2048];
        // Both pipes close when curl exits; reading them to the end first
        // means a full pipe can never stall the process being waited on.
        while self.stdout.is_some() || self.stderr.is_some() {
            tokio::select! {
                read = read_pipe(&mut self.stdout, &mut out_chunk), if self.stdout.is_some() => {
                    if read == 0 {
                        self.stdout = None;
                        continue;
                    }
                    self.body.extend_from_slice(&out_chunk[..read]);
                    if self.body.len() as u64 > self.capture_limit {
                        self.kill().await;
                        return Err(NetFailure::TooLarge { maximum: self.capture_limit });
                    }
                }
                read = read_pipe(&mut self.stderr, &mut err_chunk), if self.stderr.is_some() => {
                    if read == 0 {
                        self.stderr = None;
                        continue;
                    }
                    self.sink.push(&err_chunk[..read]);
                }
            }
        }
        let status = self
            .child
            .wait()
            .await
            .map_err(|error| NetFailure::Spawn(error.to_string()))?;
        let seen = self.sink.finish();
        if status.success() {
            return Ok(CurlOutput {
                stdout: std::mem::take(&mut self.body),
                http_code: seen.diagnostics.http_code,
                http_connect: seen.diagnostics.http_connect,
                route: self.route.clone(),
                issuer: seen.issuer,
                subject: seen.subject,
            });
        }
        Err(classify(&Transfer {
            exit: status.code(),
            stderr: &seen.text,
            diagnostics: seen.diagnostics,
            route: &self.route,
            target_host: &self.target_host,
            target_port: self.target_port,
            credential_sent: self.credential_sent,
            cacert_set: self.cacert_set,
            backend: &self.backend,
            max_filesize: self.max_filesize,
            offered: &seen.offered,
            issuer: seen.issuer.as_deref(),
        }))
    }

    /// [`Self::wait`] with a hard limit: when `limit` passes, curl is killed
    /// and the answer is [`NetFailure::Deadline`].
    pub async fn wait_within(&mut self, limit: Duration) -> Result<CurlOutput, NetFailure> {
        if let Ok(finished) = tokio::time::timeout(limit, self.wait()).await {
            return finished;
        }
        self.kill().await;
        Err(NetFailure::Deadline)
    }

    /// Ends the process and reaps it.
    pub async fn kill(&mut self) {
        let _ = self.child.start_kill();
        let _ = self.child.wait().await;
    }

    /// The route chosen for the first hop.
    #[must_use]
    pub fn route(&self) -> &Route {
        &self.route
    }

    /// The process id, while the process has not been reaped.
    #[must_use]
    pub fn id(&self) -> Option<u32> {
        self.child.id()
    }
}

/// What a curl process that exited zero produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CurlOutput {
    /// Standard output: the body, after the response headers when the
    /// request asked for them; empty when the body went to a file.
    pub stdout: Vec<u8>,
    /// The status of the final response, when curl reported one.
    pub http_code: Option<u16>,
    /// The proxy's status for the `CONNECT`, when a tunnel was made.
    pub http_connect: Option<u16>,
    /// The route chosen for the first hop.
    pub route: Route,
    /// The server certificate's issuer, in diagnostic mode on a backend
    /// that prints it.
    pub issuer: Option<String>,
    /// The server certificate's subject, likewise.
    pub subject: Option<String>,
}

/// Reads once from a pipe; `0` means the pipe is finished (or absent). A
/// read error ends the stream: the exit code is the better story.
async fn read_pipe<R: AsyncRead + Unpin>(pipe: &mut Option<R>, chunk: &mut [u8]) -> usize {
    match pipe.as_mut() {
        Some(pipe) => pipe.read(chunk).await.unwrap_or(0),
        None => 0,
    }
}

/// What standard error amounted to.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Seen {
    /// curl's own error lines, bounded.
    pub text: String,
    pub diagnostics: Diagnostics,
    pub issuer: Option<String>,
    pub subject: Option<String>,
    /// `Proxy-Authenticate` schemes, in the order offered.
    pub offered: Vec<String>,
}

/// Reads curl's standard error a line at a time.
///
/// Normally standard error is curl's error message and the diagnostics
/// line. In diagnostic mode it is the verbose trace, which holds request
/// headers; there a line is either one of the few kinds this sink keeps or
/// it is gone the moment its newline arrives.
pub(crate) struct StderrSink {
    diagnostic: bool,
    line: Vec<u8>,
    seen: Seen,
}

impl StderrSink {
    pub(crate) fn new(diagnostic: bool) -> Self {
        Self {
            diagnostic,
            line: Vec::new(),
            seen: Seen::default(),
        }
    }

    pub(crate) fn push(&mut self, bytes: &[u8]) {
        for byte in bytes {
            if *byte == b'\n' {
                self.take_line();
            } else if self.line.len() < MAX_STDERR_LINE {
                self.line.push(*byte);
            }
        }
    }

    pub(crate) fn finish(&mut self) -> Seen {
        self.take_line();
        std::mem::take(&mut self.seen)
    }

    fn take_line(&mut self) {
        let raw = std::mem::take(&mut self.line);
        let line = String::from_utf8_lossy(&raw);
        let line = line.trim_end_matches('\r');
        if line.is_empty() {
            return;
        }
        // The last diagnostics line wins: curl prints it once, at the end.
        if let Some(pairs) = line.strip_prefix(SENTINEL) {
            self.seen.diagnostics = Diagnostics::parse(pairs);
            return;
        }
        if self.diagnostic {
            if let Some(info) = line.strip_prefix('*') {
                let info = info.trim();
                if let Some(issuer) = info.strip_prefix("issuer:") {
                    self.seen.issuer = Some(tidy(issuer));
                } else if let Some(subject) = info.strip_prefix("subject:") {
                    self.seen.subject = Some(tidy(subject));
                }
                return;
            }
            if let Some(header) = line.strip_prefix("< ") {
                if let Some((name, value)) = header.split_once(':')
                    && name.eq_ignore_ascii_case("proxy-authenticate")
                    && let Some(scheme) = value.split_whitespace().next()
                {
                    let scheme = tidy(scheme);
                    if !self.seen.offered.contains(&scheme) && self.seen.offered.len() < 8 {
                        self.seen.offered.push(scheme);
                    }
                }
                return;
            }
            if !line.starts_with("curl: ") {
                return;
            }
        }
        if self.seen.text.len() + line.len() < MAX_STDERR_BYTES {
            self.seen.text.push_str(line);
            self.seen.text.push('\n');
        }
    }
}

/// A value read from curl's trace, made safe to show: no control
/// characters, bounded.
fn tidy(raw: &str) -> String {
    raw.trim()
        .chars()
        .filter(|c| !c.is_control())
        .take(256)
        .collect()
}

/// Whether a byte may appear in an HTTP header name (an RFC 9110 token).
fn is_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte)
}

fn invalid(field: &'static str, detail: impl Into<String>) -> NetFailure {
    NetFailure::RequestInvalid {
        field,
        detail: detail.into(),
    }
}

/// Writes one string option, naming the request field on refusal.
fn put(
    doc: &mut ConfigDoc,
    name: &'static str,
    value: &str,
    field: &'static str,
) -> Result<(), NetFailure> {
    doc.string(name, value)
        .map_err(|error| invalid(field, error.to_string()))
}

/// A path as curl's config can carry it: absolute, Unicode, one line.
fn path_text<'p>(path: &'p Path, field: &'static str) -> Result<&'p str, NetFailure> {
    if !path.is_absolute() {
        return Err(invalid(field, "the path must be absolute"));
    }
    let text = path
        .to_str()
        .ok_or_else(|| invalid(field, "the path is not valid Unicode"))?;
    if text.chars().any(char::is_control) {
        return Err(invalid(field, "the path holds a control character"));
    }
    Ok(text)
}

/// A string holding a secret, overwritten when dropped (best effort, as
/// [`crate::ProxyPassword`] is).
struct Wiped(String);

impl Drop for Wiped {
    fn drop(&mut self) {
        let len = self.0.len();
        self.0.clear();
        for _ in 0..len {
            self.0.push('\0');
        }
    }
}
