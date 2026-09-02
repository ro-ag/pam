//! A range-serving HTTP/1.1 origin, small enough to reason about.
//!
//! The download tests drive the machine's real `curl` — mocking the
//! transport would prove nothing about the one thing that can surprise us,
//! which is how curl behaves on a resume. So the fixture is a server, not a
//! stub: it speaks just enough HTTP for `HEAD`, `GET`, `Range: bytes=N-`
//! with `206`, and `ETag`, and it records the request lines it saw so a
//! test can assert that the resume really asked for a range.
//!
//! Two variants exist for failure shapes: one that drops the connection
//! after N bytes (to leave a resumable part file behind), and one that
//! trickles the body out in chunks (to leave a transfer running long enough
//! to cancel or to collide with).

use std::fmt::Write as _;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

/// How the origin should misbehave, if at all.
#[derive(Debug, Clone, Copy, Default)]
pub struct Faults {
    /// Drop the *first* connection after writing this many body bytes.
    /// Later connections are served normally, so the same origin can be
    /// interrupted once and then resumed from.
    pub drop_after: Option<usize>,
    /// Write the body in chunks of this size, pausing between them.
    pub chunk: Option<usize>,
    /// Pause between chunks.
    pub pause: Duration,
}

/// A running origin. Dropping it stops the accept loop.
pub struct TestServer {
    addr: SocketAddr,
    requests: Arc<Mutex<Vec<String>>>,
    accepting: JoinHandle<()>,
}

impl TestServer {
    /// URL for `name` on this origin.
    #[must_use]
    pub fn url(&self, name: &str) -> String {
        format!("http://{}/{name}", self.addr)
    }

    /// Every header line every request sent, in order.
    #[must_use]
    pub fn requests(&self) -> Vec<String> {
        self.requests.lock().unwrap().clone()
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.accepting.abort();
    }
}

/// An origin that serves `body` whole, with `etag`.
pub async fn serve(body: Vec<u8>, etag: &str) -> TestServer {
    serve_with(body, etag, Faults::default()).await
}

/// An origin that drops its first connection after `drop_after` body bytes
/// and serves every later one whole.
pub async fn serve_interrupting(body: Vec<u8>, etag: &str, drop_after: usize) -> TestServer {
    serve_with(
        body,
        etag,
        Faults {
            drop_after: Some(drop_after),
            ..Faults::default()
        },
    )
    .await
}

/// An origin that trickles the body out, `chunk` bytes at a time.
pub async fn serve_slowly(body: Vec<u8>, etag: &str, chunk: usize, pause: Duration) -> TestServer {
    serve_with(
        body,
        etag,
        Faults {
            chunk: Some(chunk),
            pause,
            ..Faults::default()
        },
    )
    .await
}

async fn serve_with(body: Vec<u8>, etag: &str, faults: Faults) -> TestServer {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let requests = Arc::new(Mutex::new(Vec::new()));

    let seen = Arc::clone(&requests);
    let etag = etag.to_owned();
    let served = Arc::new(AtomicUsize::new(0));
    let accepting = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let body = body.clone();
            let etag = etag.clone();
            let seen = Arc::clone(&seen);
            let first = served.fetch_add(1, Ordering::SeqCst) == 0;
            tokio::spawn(async move {
                let _ = respond(stream, &body, &etag, faults, first, &seen).await;
            });
        }
    });

    TestServer {
        addr,
        requests,
        accepting,
    }
}

/// Reads one request, writes one response, closes.
async fn respond(
    mut stream: TcpStream,
    body: &[u8],
    etag: &str,
    faults: Faults,
    first: bool,
    seen: &Mutex<Vec<String>>,
) -> std::io::Result<()> {
    let request = read_request(&mut stream).await?;
    let mut lines: Vec<String> = request.lines().map(str::to_owned).collect();
    let method = lines
        .first()
        .and_then(|line| line.split_whitespace().next())
        .unwrap_or_default()
        .to_owned();
    seen.lock().unwrap().append(&mut lines);

    let start = request
        .lines()
        .find_map(|line| {
            let value = line.strip_prefix("Range: bytes=")?;
            value.split('-').next()?.parse::<usize>().ok()
        })
        .unwrap_or(0);
    let start = start.min(body.len());
    let slice = &body[start..];

    let mut head = String::new();
    if start > 0 {
        head.push_str("HTTP/1.1 206 Partial Content\r\n");
        let last = body.len().saturating_sub(1);
        let total = body.len();
        let _ = write!(head, "Content-Range: bytes {start}-{last}/{total}\r\n");
    } else {
        head.push_str("HTTP/1.1 200 OK\r\n");
    }
    head.push_str("Accept-Ranges: bytes\r\n");
    let _ = write!(head, "ETag: \"{etag}\"\r\n");
    let length = slice.len();
    let _ = write!(head, "Content-Length: {length}\r\n");
    head.push_str("Connection: close\r\n\r\n");
    stream.write_all(head.as_bytes()).await?;

    if method == "HEAD" {
        stream.shutdown().await?;
        return Ok(());
    }

    if let Some(drop_after) = faults.drop_after
        && first
    {
        let sent = drop_after.min(slice.len());
        stream.write_all(&slice[..sent]).await?;
        stream.flush().await?;
        // No shutdown: the peer sees the connection die mid-body.
        return Ok(());
    }

    let chunk = faults.chunk.unwrap_or(slice.len()).max(1);
    for piece in slice.chunks(chunk) {
        stream.write_all(piece).await?;
        stream.flush().await?;
        if !faults.pause.is_zero() {
            tokio::time::sleep(faults.pause).await;
        }
    }
    stream.shutdown().await
}

/// Reads until the end of the request head.
async fn read_request(stream: &mut TcpStream) -> std::io::Result<String> {
    let mut request = Vec::new();
    let mut buffer = [0u8; 1024];
    loop {
        let read = stream.read(&mut buffer).await?;
        if read == 0 {
            break;
        }
        request.extend_from_slice(&buffer[..read]);
        if request.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }
    }
    Ok(String::from_utf8_lossy(&request).into_owned())
}
