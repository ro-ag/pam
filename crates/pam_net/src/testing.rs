//! Loopback fixtures real curl is driven against. No fixture leaves the
//! machine.
//!
//! * [`Origin`](crate::testing::Origin): a plain HTTP/1.1 server that records what arrived.
//! * [`FakeProxy`](crate::testing::FakeProxy): a forward proxy. `CONNECT` to *any* name is tunnelled to
//!   one configured loopback address, so a test can ask for
//!   `origin.pam-test.invalid` and prove the proxy — not DNS — carried it.
//!   It records every request line and every `Proxy-Authorization` it saw.
//! * [`TlsOrigin`](crate::testing::TlsOrigin): `openssl s_server` with the committed test certificates
//!   under `tests/fixtures/` (a private test CA, a leaf for
//!   `origin.pam-test.invalid`/`localhost`/`127.0.0.1`, a leaf for another
//!   name, an expired leaf, and an unrelated CA). No TLS crate is involved;
//!   the tests that need it are skipped with a printed line when `openssl`
//!   is absent, unless `PAM_REQUIRE_TLS_FIXTURE=1` makes absence a failure.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use url::Url;

use crate::trusted::TrustedCurl;

/// The trusted curl, or `None` with a printed line when this machine has
/// none: every real-curl test starts with this and returns on `None`.
#[must_use]
pub fn trusted_curl_or_skip() -> Option<TrustedCurl> {
    match TrustedCurl::resolve() {
        Ok(curl) => Some(curl),
        Err(failure) => {
            eprintln!("no trusted operating-system curl ({failure}); skipping");
            None
        }
    }
}

/// The name the test leaf certificate is issued for. It never resolves
/// (`.invalid` is reserved), so a request for it succeeds only through the
/// [`FakeProxy`].
pub const TEST_HOST: &str = "origin.pam-test.invalid";

/// The most a fixture reads of one request before giving up on it.
const MAX_REQUEST_BYTES: usize = 256 * 1024;

/// What an [`Origin`] does with each request.
#[derive(Debug, Clone)]
pub enum OriginMode {
    /// Answer `200` with the JSON body `{"ok":true}`.
    Json,
    /// Answer `200` with this body.
    Body(Vec<u8>),
    /// Answer this status with an empty body.
    Status(u16),
    /// Answer `302` to this `Location`.
    Redirect(String),
    /// Read the request, then hold the connection open and say nothing.
    Stall,
}

/// A plain HTTP/1.1 origin on a loopback port.
pub struct Origin {
    address: SocketAddr,
    seen: Arc<Mutex<Vec<String>>>,
    task: JoinHandle<()>,
}

impl Origin {
    /// Starts an origin that answers every connection per `mode`.
    pub async fn start(mode: OriginMode) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("a loopback port");
        let address = listener.local_addr().expect("the bound address");
        let seen = Arc::new(Mutex::new(Vec::new()));
        let recorder = Arc::clone(&seen);
        let task = tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                tokio::spawn(serve_origin(stream, mode.clone(), Arc::clone(&recorder)));
            }
        });
        Self {
            address,
            seen,
            task,
        }
    }

    /// The loopback address the origin listens on.
    #[must_use]
    pub fn address(&self) -> SocketAddr {
        self.address
    }

    /// `http://127.0.0.1:<port><path>`.
    #[must_use]
    pub fn url(&self, path: &str) -> Url {
        Url::parse(&format!("http://{}{path}", self.address)).expect("the origin URL parses")
    }

    /// Every request received so far, head and body, in arrival order.
    #[must_use]
    pub fn requests(&self) -> Vec<String> {
        self.seen
            .lock()
            .expect("the recorder lock is never poisoned")
            .clone()
    }
}

impl Drop for Origin {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn serve_origin(mut stream: TcpStream, mode: OriginMode, seen: Arc<Mutex<Vec<String>>>) {
    let Some((head, mut rest)) = read_head(&mut stream).await else {
        return;
    };
    // A request with a declared body is read to its end, so the test sees
    // exactly what curl sent.
    let wanted = content_length(&head);
    let mut chunk = [0_u8; 4096];
    while rest.len() < wanted && rest.len() < MAX_REQUEST_BYTES {
        match stream.read(&mut chunk).await {
            Ok(0) | Err(_) => break,
            Ok(read) => rest.extend_from_slice(&chunk[..read]),
        }
    }
    seen.lock()
        .expect("the recorder lock is never poisoned")
        .push(format!("{head}{}", String::from_utf8_lossy(&rest)));

    let answer = match mode {
        OriginMode::Json => response(200, "OK", "application/json", b"{\"ok\":true}", ""),
        OriginMode::Body(body) => response(200, "OK", "application/octet-stream", &body, ""),
        OriginMode::Status(status) => response(status, "Status", "text/plain", b"", ""),
        OriginMode::Redirect(location) => response(
            302,
            "Found",
            "text/plain",
            b"",
            &format!("Location: {location}\r\n"),
        ),
        OriginMode::Stall => {
            tokio::time::sleep(Duration::from_secs(60)).await;
            return;
        }
    };
    let _ = stream.write_all(&answer).await;
    let _ = stream.shutdown().await;
}

fn response(status: u16, reason: &str, content_type: &str, body: &[u8], extra: &str) -> Vec<u8> {
    let mut answer = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\n{extra}Connection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    answer.extend_from_slice(body);
    answer
}

/// How a [`FakeProxy`] treats a request.
#[derive(Debug, Clone)]
pub enum ProxyMode {
    /// Tunnel or forward everything.
    Allow,
    /// Answer `407` until the request carries this Basic credential.
    RequireAuth {
        /// The user name that is accepted.
        username: String,
        /// The password that is accepted.
        password: String,
        /// The `Proxy-Authenticate` values offered with the `407`, for
        /// example `Basic realm="pam-test"`.
        offer: Vec<String>,
    },
    /// Refuse every request with this status.
    Deny(u16),
}

#[derive(Default)]
struct ProxyLog {
    request_lines: Vec<String>,
    authorizations: Vec<String>,
}

/// A forward proxy on a loopback port.
///
/// A successful `CONNECT` is answered `HTTP/1.1 200 Connection established`
/// — the block a launcher must keep out of the response it hands back — and
/// tunnelled to the configured upstream whatever name was asked for. An
/// absolute-form request (`GET http://host/path`) is forwarded to the same
/// upstream in origin form.
pub struct FakeProxy {
    address: SocketAddr,
    log: Arc<Mutex<ProxyLog>>,
    task: JoinHandle<()>,
}

impl FakeProxy {
    /// Starts a proxy that carries every allowed request to `upstream`.
    pub async fn start(mode: ProxyMode, upstream: SocketAddr) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("a loopback port");
        let address = listener.local_addr().expect("the bound address");
        let log = Arc::new(Mutex::new(ProxyLog::default()));
        let recorder = Arc::clone(&log);
        let task = tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                tokio::spawn(serve_proxy(
                    stream,
                    mode.clone(),
                    upstream,
                    Arc::clone(&recorder),
                ));
            }
        });
        Self { address, log, task }
    }

    /// The loopback address the proxy listens on.
    #[must_use]
    pub fn address(&self) -> SocketAddr {
        self.address
    }

    /// `http://127.0.0.1:<port>`: the value for the proxy setting.
    #[must_use]
    pub fn url(&self) -> String {
        format!("http://{}", self.address)
    }

    /// Every request line received, in arrival order
    /// (`CONNECT origin.pam-test.invalid:80 HTTP/1.1`).
    #[must_use]
    pub fn request_lines(&self) -> Vec<String> {
        self.log
            .lock()
            .expect("the proxy log lock is never poisoned")
            .request_lines
            .clone()
    }

    /// Every `Proxy-Authorization` value received, in arrival order.
    #[must_use]
    pub fn authorizations(&self) -> Vec<String> {
        self.log
            .lock()
            .expect("the proxy log lock is never poisoned")
            .authorizations
            .clone()
    }
}

impl Drop for FakeProxy {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn serve_proxy(
    mut client: TcpStream,
    mode: ProxyMode,
    upstream: SocketAddr,
    log: Arc<Mutex<ProxyLog>>,
) {
    // A 407 keeps the connection, so curl can answer the challenge on it.
    loop {
        let Some((head, rest)) = read_head(&mut client).await else {
            return;
        };
        let request_line = head.lines().next().unwrap_or_default().to_owned();
        let authorization = header_value(&head, "proxy-authorization");
        {
            let mut log = log.lock().expect("the proxy log lock is never poisoned");
            log.request_lines.push(request_line.clone());
            if let Some(value) = &authorization {
                log.authorizations.push(value.clone());
            }
        }
        match &mode {
            ProxyMode::Allow => {}
            ProxyMode::Deny(status) => {
                let answer = format!(
                    "HTTP/1.1 {status} Denied\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                );
                let _ = client.write_all(answer.as_bytes()).await;
                let _ = client.shutdown().await;
                return;
            }
            ProxyMode::RequireAuth {
                username,
                password,
                offer,
            } => {
                let expected = format!(
                    "Basic {}",
                    base64(format!("{username}:{password}").as_bytes())
                );
                if authorization.as_deref() != Some(expected.as_str()) {
                    let mut answer = String::from("HTTP/1.1 407 Proxy Authentication Required\r\n");
                    for scheme in offer {
                        answer.push_str("Proxy-Authenticate: ");
                        answer.push_str(scheme);
                        answer.push_str("\r\n");
                    }
                    answer.push_str("Content-Length: 0\r\n\r\n");
                    if client.write_all(answer.as_bytes()).await.is_err() {
                        return;
                    }
                    continue;
                }
            }
        }

        let Ok(mut server) = TcpStream::connect(upstream).await else {
            let _ = client
                .write_all(
                    b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .await;
            return;
        };
        let mut words = request_line.split_whitespace();
        let method = words.next().unwrap_or_default();
        let target = words.next().unwrap_or_default();
        if method == "CONNECT" {
            if client
                .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                .await
                .is_err()
            {
                return;
            }
        } else {
            // Absolute form to origin form: drop the scheme and authority,
            // and the proxy's own headers.
            let path = target
                .split_once("://")
                .and_then(|(_, after)| after.find('/').map(|at| &after[at..]))
                .unwrap_or("/");
            let mut forwarded = format!("{method} {path} HTTP/1.1\r\n");
            for line in head.lines().skip(1).filter(|line| !line.is_empty()) {
                if !line.to_ascii_lowercase().starts_with("proxy-") {
                    forwarded.push_str(line);
                    forwarded.push_str("\r\n");
                }
            }
            forwarded.push_str("\r\n");
            if server.write_all(forwarded.as_bytes()).await.is_err() {
                return;
            }
        }
        if !rest.is_empty() && server.write_all(&rest).await.is_err() {
            return;
        }
        let _ = tokio::io::copy_bidirectional(&mut client, &mut server).await;
        return;
    }
}

/// Reads one request head. Answers the head as text and whatever bytes
/// arrived after it.
async fn read_head(stream: &mut TcpStream) -> Option<(String, Vec<u8>)> {
    let mut bytes = Vec::new();
    let mut chunk = [0_u8; 2048];
    loop {
        if let Some(end) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
            let rest = bytes.split_off(end + 4);
            return Some((String::from_utf8_lossy(&bytes).into_owned(), rest));
        }
        if bytes.len() > MAX_REQUEST_BYTES {
            return None;
        }
        match stream.read(&mut chunk).await {
            Ok(0) | Err(_) => return None,
            Ok(read) => bytes.extend_from_slice(&chunk[..read]),
        }
    }
}

fn header_value(head: &str, name: &str) -> Option<String> {
    head.lines().skip(1).find_map(|line| {
        let (key, value) = line.split_once(':')?;
        key.trim()
            .eq_ignore_ascii_case(name)
            .then(|| value.trim().to_owned())
    })
}

fn content_length(head: &str) -> usize {
    header_value(head, "content-length")
        .and_then(|value| value.parse().ok())
        .unwrap_or(0)
}

/// Standard base64 with padding: what a Basic credential is compared to.
#[must_use]
pub fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut encoded = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for group in bytes.chunks(3) {
        let padded = [
            group[0],
            group.get(1).copied().unwrap_or(0),
            group.get(2).copied().unwrap_or(0),
        ];
        let word = u32::from(padded[0]) << 16 | u32::from(padded[1]) << 8 | u32::from(padded[2]);
        for (index, shift) in [18_u32, 12, 6, 0].into_iter().enumerate() {
            if index <= group.len() {
                encoded.push(char::from(ALPHABET[(word >> shift & 0x3f) as usize]));
            } else {
                encoded.push('=');
            }
        }
    }
    encoded
}

/// Which committed certificate a [`TlsOrigin`] presents.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsCert {
    /// Issued by the test CA for [`TEST_HOST`], `localhost` and `127.0.0.1`.
    Valid,
    /// Issued by the test CA for another name.
    WrongName,
    /// Issued by the test CA for the right names, expired in 2020.
    Expired,
}

/// The path of a committed fixture file under `tests/fixtures/`.
#[must_use]
pub fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(name)
}

/// The test CA every fixture leaf is issued by: the bundle to trust.
#[must_use]
pub fn test_ca() -> PathBuf {
    fixture("ca.pem")
}

/// A second CA that issued nothing: the bundle that must not work.
#[must_use]
pub fn unrelated_ca() -> PathBuf {
    fixture("other-ca.pem")
}

/// Whether a missing `openssl` fails the TLS tests instead of skipping
/// them: `PAM_REQUIRE_TLS_FIXTURE=1`.
#[must_use]
pub fn tls_fixture_required() -> bool {
    std::env::var_os("PAM_REQUIRE_TLS_FIXTURE").is_some_and(|value| value == "1")
}

/// The `openssl` program for the TLS origin and what it calls itself:
/// `PAM_TEST_OPENSSL` when set, else the system one on macOS, else `PATH`.
fn openssl() -> Option<(PathBuf, String)> {
    let mut candidates = Vec::new();
    if let Some(chosen) = std::env::var_os("PAM_TEST_OPENSSL") {
        candidates.push(PathBuf::from(chosen));
    } else {
        if cfg!(target_os = "macos") {
            candidates.push(PathBuf::from("/usr/bin/openssl"));
        }
        candidates.push(PathBuf::from("openssl"));
    }
    candidates.into_iter().find_map(|program| {
        let output = std::process::Command::new(&program)
            .arg("version")
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .output()
            .ok()?;
        output.status.success().then(|| {
            (
                program,
                String::from_utf8_lossy(&output.stdout).into_owned(),
            )
        })
    })
}

/// `openssl s_server -www` on a loopback port, presenting a test leaf.
///
/// Dropping it stops the server.
pub struct TlsOrigin {
    child: std::process::Child,
    port: u16,
}

impl TlsOrigin {
    /// Starts the server. `None` when no `openssl` is available and
    /// `PAM_REQUIRE_TLS_FIXTURE` is not `1`: the caller prints a line and
    /// skips.
    ///
    /// # Panics
    ///
    /// When `openssl` is required and absent, or it cannot be started.
    pub async fn start(cert: TlsCert) -> Option<Self> {
        let Some((program, version)) = openssl() else {
            assert!(
                !tls_fixture_required(),
                "PAM_REQUIRE_TLS_FIXTURE=1 but no openssl was found (set PAM_TEST_OPENSSL)"
            );
            return None;
        };
        let certificate = fixture(match cert {
            TlsCert::Valid => "leaf.pem",
            TlsCert::WrongName => "wrong-name.pem",
            TlsCert::Expired => "expired.pem",
        });
        // Another test may take the port between the probe and the bind;
        // a server that did not come up is tried again on a new one.
        for _ in 0..5 {
            let port = free_port().await;
            // OpenSSL binds one address when given one; LibreSSL's s_server
            // takes a port only.
            let accept = if version.starts_with("OpenSSL") {
                format!("127.0.0.1:{port}")
            } else {
                port.to_string()
            };
            let mut child = std::process::Command::new(&program)
                .arg("s_server")
                .arg("-accept")
                .arg(accept)
                .arg("-cert")
                .arg(&certificate)
                .arg("-key")
                .arg(fixture("leaf.key"))
                .arg("-www")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .expect("openssl s_server starts");
            for _ in 0..100 {
                if TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
                    return Some(Self { child, port });
                }
                if !matches!(child.try_wait(), Ok(None)) {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            let _ = child.kill();
            let _ = child.wait();
        }
        panic!("openssl s_server did not start listening");
    }

    /// The loopback port the server listens on.
    #[must_use]
    pub fn port(&self) -> u16 {
        self.port
    }

    /// `127.0.0.1:<port>`: the upstream for a [`FakeProxy`].
    #[must_use]
    pub fn address(&self) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], self.port))
    }

    /// `https://localhost:<port>/`: a direct request the valid leaf matches.
    #[must_use]
    pub fn local_url(&self) -> Url {
        Url::parse(&format!("https://localhost:{}/", self.port)).expect("the origin URL parses")
    }
}

impl Drop for TlsOrigin {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

async fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .await
        .expect("a loopback port")
        .local_addr()
        .expect("the bound address")
        .port()
}
