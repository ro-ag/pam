//! Real `curl` against a throwaway origin.
//!
//! The unit tests prove what `pam_connectors` builds; this one proves what
//! actually leaves the machine. A `tokio::net::TcpListener` answers plain
//! HTTP/1.1 on a loopback port, `CurlTransport` is pointed at it with
//! `allow_http_for_tests`, and the origin reports back what arrived on the
//! wire — including the `Authorization` header that never appears in the
//! child's argument vector.
//!
//! The whole file is skipped, with a printed line, when the trusted OS `curl` is unavailable.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use pam_connectors::{CurlTransport, HttpRequest, HttpTransport, Method, TransportError};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use url::Url;

/// What the origin does once a request has arrived.
#[derive(Clone, Copy)]
enum Mode {
    /// Answer a small JSON body.
    Json,
    /// Answer a body far larger than the request's budget.
    Oversized,
    /// Answer nothing at all, and hold the connection open.
    Stall,
}

#[tokio::test]
async fn the_headers_pam_builds_arrive_on_the_wire() {
    let Some(curl) = curl_on_path() else {
        eprintln!("curl not on PATH; skipping");
        return;
    };
    let (address, seen) = origin(Mode::Json).await;
    let transport = curl;

    let response = transport
        .send(request(address, "/probe", 64 * 1024), deadline(10))
        .await
        .expect("the origin answers");

    assert_eq!(response.status, 200);
    assert_eq!(response.body, b"{\"ok\":true}");
    assert_eq!(
        response.header("content-type"),
        Some("application/json"),
        "{:?}",
        response.headers
    );

    let wire = wire_text(&seen);
    assert!(wire.starts_with("GET /probe HTTP/1.1"), "{wire}");
    assert!(
        wire.contains("Authorization: Bearer wire-token"),
        "the credential never reached the wire: {wire}"
    );
    assert!(wire.contains("X-Pam-Probe: on-the-wire"), "{wire}");
    assert!(wire.contains("Accept: application/json"), "{wire}");
}

#[tokio::test]
async fn a_body_over_max_filesize_is_refused() {
    let Some(curl) = curl_on_path() else {
        eprintln!("curl not on PATH; skipping");
        return;
    };
    let (address, _seen) = origin(Mode::Oversized).await;
    let transport = curl;

    let error = transport
        .send(request(address, "/big", 64), deadline(10))
        .await
        .expect_err("a body over the budget is refused");

    assert_eq!(error, TransportError::TooLarge { maximum: 64 });
}

#[tokio::test]
async fn an_origin_that_never_answers_hits_max_time() {
    let Some(curl) = curl_on_path() else {
        eprintln!("curl not on PATH; skipping");
        return;
    };
    let (address, _seen) = origin(Mode::Stall).await;
    let transport = curl;

    let error = transport
        .send(request(address, "/slow", 64 * 1024), deadline(2))
        .await
        .expect_err("a stalled origin times out");

    assert_eq!(error, TransportError::Timeout);
}

#[tokio::test]
async fn a_refused_connection_is_a_network_failure() {
    let Some(curl) = curl_on_path() else {
        eprintln!("curl not on PATH; skipping");
        return;
    };
    // Bind and drop, so the port is almost certainly closed.
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("a loopback port");
    let address = listener.local_addr().expect("the bound address");
    drop(listener);

    let transport = curl;
    let error = transport
        .send(request(address, "/gone", 1024), deadline(5))
        .await
        .expect_err("a closed port cannot answer");

    match error {
        TransportError::Network(detail) => {
            assert!(detail.contains("curl exited"), "{detail}");
            assert!(
                !detail.contains('\n'),
                "control characters survived: {detail:?}"
            );
        }
        other => panic!("a closed port is a network failure, got {other:?}"),
    }
}

/// One request aimed at the throwaway origin.
fn request(address: SocketAddr, path: &str, max_bytes: u64) -> HttpRequest {
    HttpRequest {
        method: Method::Get,
        body: None,
        url: Url::parse(&format!("http://{address}{path}")).expect("the origin URL parses"),
        headers: vec![
            ("Authorization".to_owned(), "Bearer wire-token".to_owned()),
            ("Accept".to_owned(), "application/json".to_owned()),
            ("X-Pam-Probe".to_owned(), "on-the-wire".to_owned()),
        ],
        max_bytes,
        follow_one_https_redirect_without_auth: false,
    }
}

/// Starts a one-connection origin and answers its address.
async fn origin(mode: Mode) -> (SocketAddr, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("a loopback port");
    let address = listener.local_addr().expect("the bound address");
    let seen = Arc::new(Mutex::new(Vec::new()));
    let recorder = Arc::clone(&seen);

    tokio::spawn(async move {
        let Ok((mut stream, _)) = listener.accept().await else {
            return;
        };
        let mut head = Vec::new();
        let mut chunk = [0_u8; 1024];
        while !ends_head(&head) {
            match stream.read(&mut chunk).await {
                Ok(0) | Err(_) => break,
                Ok(read) => head.extend_from_slice(&chunk[..read]),
            }
        }
        recorder
            .lock()
            .expect("the recorder lock is never poisoned")
            .push(String::from_utf8_lossy(&head).into_owned());

        match mode {
            Mode::Json => {
                let body = b"{\"ok\":true}";
                let head = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = stream.write_all(head.as_bytes()).await;
                let _ = stream.write_all(body).await;
            }
            Mode::Oversized => {
                let body = vec![b'x'; 4096];
                let head = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = stream.write_all(head.as_bytes()).await;
                let _ = stream.write_all(&body).await;
            }
            Mode::Stall => {
                // Hold the connection open with nothing on it, so `--max-time`
                // is what ends the request.
                tokio::time::sleep(Duration::from_secs(30)).await;
            }
        }
        let _ = stream.shutdown().await;
    });

    (address, seen)
}

/// Whether a request head has been read in full.
fn ends_head(bytes: &[u8]) -> bool {
    bytes.windows(4).any(|window| window == b"\r\n\r\n")
}

/// The request text the origin recorded, once it has one.
fn wire_text(seen: &Arc<Mutex<Vec<String>>>) -> String {
    seen.lock()
        .expect("the recorder lock is never poisoned")
        .first()
        .cloned()
        .expect("the origin saw a request")
}

/// A deadline `seconds` from now.
fn deadline(seconds: u64) -> Instant {
    Instant::now() + Duration::from_secs(seconds)
}

/// The transport over the qualified OS curl, independent of the test
/// process PATH, speaking plain http to the loopback origin.
fn curl_on_path() -> Option<CurlTransport> {
    CurlTransport::trusted()
        .ok()
        .map(CurlTransport::allow_http_for_tests)
}

#[tokio::test]
async fn mutation_json_arrives_exactly_and_redirect_is_never_followed() {
    let Some(curl) = curl_on_path() else {
        return;
    };
    for method in [Method::Post, Method::Put] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut bytes = Vec::new();
            let mut chunk = [0; 1024];
            // Read until the declared body has arrived. A client that hangs
            // up early (curl killed at its deadline on a loaded runner) ends
            // the read with what came so far: the client-side assertions
            // then name the real failure instead of this task panicking on
            // `n > 0` and the join error hiding it (windows-11-arm main run
            // 34959772710).
            loop {
                let n = stream.read(&mut chunk).await.unwrap();
                if n == 0 {
                    break;
                }
                bytes.extend_from_slice(&chunk[..n]);
                assert!(bytes.len() < 8192);
                if let Some(end) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
                    let head = String::from_utf8_lossy(&bytes[..end]);
                    let size = head
                        .lines()
                        .find_map(|line| {
                            line.to_ascii_lowercase()
                                .strip_prefix("content-length:")
                                .map(|s| s.trim().parse::<usize>().unwrap())
                        })
                        .unwrap();
                    if bytes.len() >= end + 4 + size {
                        break;
                    }
                }
            }
            let response = if method == Method::Put {
                "HTTP/1.1 307 Temporary Redirect\r\nLocation: https://127.0.0.1:1/never\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            } else {
                "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}"
            };
            stream.write_all(response.as_bytes()).await.unwrap();
            bytes
        });
        let body = b"{\n\"title\":\"quote\\\" and slash\\\\\"\n}".to_vec();
        let mut req = request(address, "/mutation", 1024);
        req.method = method;
        req.body = Some(body.clone());
        // Fifteen seconds, not five: spawning curl.exe on a loaded Windows
        // runner can eat most of a short deadline before the request is sent.
        let result = curl.clone().send(req, deadline(15)).await;
        if method == Method::Put {
            assert!(matches!(
                result,
                Err(TransportError::Policy {
                    cause: "mutation_redirect_refused",
                    ..
                })
            ));
        } else {
            assert_eq!(result.unwrap().status, 200);
        }
        let wire = server.await.unwrap();
        assert!(wire.starts_with(format!("{} /mutation HTTP/1.1", method.as_str()).as_bytes()));
        assert!(wire.ends_with(&body));
    }
}
