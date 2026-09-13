//! A minimal HTTP/1.1 client for talking to `llama-server` over its
//! private Unix socket.
//!
//! One request per connection (`Connection: close`), JSON bodies only,
//! bounded response size, no redirects, no TLS: the peer is a process PAM
//! itself started on a socket only PAM's user can open. Dropping the
//! connection mid-generation is how a cancel reaches the server — it stops
//! decoding when the client goes away.

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// The most response bytes accepted; a completion is kilobytes, and the
/// props document is under 64 KiB.
pub const MAX_RESPONSE_BYTES: usize = 4 * 1024 * 1024;

/// One parsed response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpReply {
    /// The status code.
    pub status: u16,
    /// The body bytes.
    pub body: Vec<u8>,
}

/// Why a request did not complete.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum HttpError {
    /// The socket could not be opened.
    #[error("engine socket unavailable: {0}")]
    Connect(String),
    /// The connection died or the response was malformed.
    #[error("engine transport failed: {0}")]
    Transport(String),
    /// The response exceeded [`MAX_RESPONSE_BYTES`].
    #[error("engine response exceeded {MAX_RESPONSE_BYTES} bytes")]
    TooLarge,
    /// `deadline` elapsed.
    #[error("engine did not answer within {0:?}")]
    Timeout(Duration),
}

/// Where the server listens: a private Unix socket everywhere it exists,
/// a loopback TCP port on Windows. Either way the API key gates the peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Endpoint {
    /// A Unix domain socket path.
    Unix(std::path::PathBuf),
    /// `127.0.0.1:<port>`.
    Loopback(u16),
}

impl Endpoint {
    /// The value `llama-server --host` takes (a path ending in `.sock`
    /// binds a Unix socket; an address binds TCP).
    #[must_use]
    pub fn host_arg(&self) -> String {
        match self {
            Self::Unix(path) => path.to_string_lossy().into_owned(),
            Self::Loopback(_) => "127.0.0.1".to_owned(),
        }
    }

    /// The `--port` value for a loopback endpoint.
    #[must_use]
    pub fn port_arg(&self) -> Option<String> {
        match self {
            Self::Unix(_) => None,
            Self::Loopback(port) => Some(port.to_string()),
        }
    }
}

/// Sends one request to the server at `endpoint`.
///
/// `body` is sent as `application/json`; `api_key` becomes a bearer token.
pub async fn request(
    endpoint: &Endpoint,
    method: &str,
    path: &str,
    api_key: &str,
    body: Option<&[u8]>,
    deadline: Duration,
) -> Result<HttpReply, HttpError> {
    match endpoint {
        #[cfg(unix)]
        Endpoint::Unix(socket) => {
            let stream = tokio::net::UnixStream::connect(socket)
                .await
                .map_err(|e| HttpError::Connect(e.to_string()))?;
            Box::pin(tokio::time::timeout(
                deadline,
                exchange(stream, method, path, api_key, body),
            ))
            .await
            .map_err(|_| HttpError::Timeout(deadline))?
        }
        #[cfg(not(unix))]
        Endpoint::Unix(socket) => Err(HttpError::Connect(format!(
            "Unix sockets are unavailable on this platform ({})",
            socket.display()
        ))),
        Endpoint::Loopback(port) => {
            let stream = tokio::net::TcpStream::connect(("127.0.0.1", *port))
                .await
                .map_err(|e| HttpError::Connect(e.to_string()))?;
            Box::pin(tokio::time::timeout(
                deadline,
                exchange(stream, method, path, api_key, body),
            ))
            .await
            .map_err(|_| HttpError::Timeout(deadline))?
        }
    }
}

async fn exchange<S>(
    mut stream: S,
    method: &str,
    path: &str,
    api_key: &str,
    body: Option<&[u8]>,
) -> Result<HttpReply, HttpError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    use std::fmt::Write as _;
    let mut head = format!(
        "{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nAccept: application/json\r\nAuthorization: Bearer {api_key}\r\n"
    );
    if let Some(body) = body {
        let _ = write!(
            head,
            "Content-Type: application/json\r\nContent-Length: {}\r\n",
            body.len()
        );
    }
    head.push_str("\r\n");
    stream
        .write_all(head.as_bytes())
        .await
        .map_err(|e| HttpError::Transport(e.to_string()))?;
    if let Some(body) = body {
        stream
            .write_all(body)
            .await
            .map_err(|e| HttpError::Transport(e.to_string()))?;
    }
    stream
        .flush()
        .await
        .map_err(|e| HttpError::Transport(e.to_string()))?;

    let mut raw = Vec::with_capacity(8192);
    let mut chunk = vec![0_u8; 16 * 1024];
    loop {
        let n = stream
            .read(&mut chunk)
            .await
            .map_err(|e| HttpError::Transport(e.to_string()))?;
        if n == 0 {
            break;
        }
        raw.extend_from_slice(&chunk[..n]);
        if raw.len() > MAX_RESPONSE_BYTES {
            return Err(HttpError::TooLarge);
        }
    }
    parse(&raw)
}

/// Parses one complete HTTP/1.1 response: status line, headers, then a
/// body sized by `Content-Length`, chunked transfer coding, or the end of
/// the connection.
pub fn parse(raw: &[u8]) -> Result<HttpReply, HttpError> {
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| HttpError::Transport("response has no header block".to_owned()))?;
    let head = std::str::from_utf8(&raw[..split])
        .map_err(|_| HttpError::Transport("response headers are not UTF-8".to_owned()))?;
    let mut lines = head.split("\r\n");
    let status_line = lines.next().unwrap_or_default();
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .ok_or_else(|| HttpError::Transport(format!("bad status line {status_line:?}")))?;
    let mut content_length: Option<usize> = None;
    let mut chunked = false;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim();
        if name.eq_ignore_ascii_case("content-length") {
            content_length = value.parse().ok();
        } else if name.eq_ignore_ascii_case("transfer-encoding")
            && value.eq_ignore_ascii_case("chunked")
        {
            chunked = true;
        }
    }
    let rest = &raw[split + 4..];
    let body = if chunked {
        dechunk(rest)?
    } else if let Some(length) = content_length {
        rest.get(..length)
            .ok_or_else(|| HttpError::Transport("body shorter than Content-Length".to_owned()))?
            .to_vec()
    } else {
        rest.to_vec()
    };
    Ok(HttpReply { status, body })
}

fn dechunk(mut rest: &[u8]) -> Result<Vec<u8>, HttpError> {
    let mut body = Vec::new();
    loop {
        let line_end = rest
            .windows(2)
            .position(|w| w == b"\r\n")
            .ok_or_else(|| HttpError::Transport("chunk size line missing".to_owned()))?;
        let size_text = std::str::from_utf8(&rest[..line_end])
            .map_err(|_| HttpError::Transport("chunk size is not UTF-8".to_owned()))?;
        let size_text = size_text.split(';').next().unwrap_or_default().trim();
        let size = usize::from_str_radix(size_text, 16)
            .map_err(|_| HttpError::Transport(format!("bad chunk size {size_text:?}")))?;
        rest = &rest[line_end + 2..];
        if size == 0 {
            return Ok(body);
        }
        let data = rest
            .get(..size)
            .ok_or_else(|| HttpError::Transport("chunk shorter than its size".to_owned()))?;
        body.extend_from_slice(data);
        if body.len() > MAX_RESPONSE_BYTES {
            return Err(HttpError::TooLarge);
        }
        rest = rest
            .get(size + 2..)
            .ok_or_else(|| HttpError::Transport("chunk terminator missing".to_owned()))?;
    }
}

#[cfg(test)]
#[path = "engine_http_test.rs"]
mod tests;
