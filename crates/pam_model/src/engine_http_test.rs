use super::*;

#[test]
fn content_length_chunked_and_eof_bodies_parse() {
    let fixed =
        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 5\r\n\r\nhelloEXTRA";
    assert_eq!(
        parse(fixed).unwrap(),
        HttpReply {
            status: 200,
            body: b"hello".to_vec()
        }
    );
    let chunked = b"HTTP/1.1 401 Unauthorized\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n2;ext=1\r\nde\r\n0\r\n\r\n";
    assert_eq!(
        parse(chunked).unwrap(),
        HttpReply {
            status: 401,
            body: b"abcde".to_vec()
        }
    );
    let eof = b"HTTP/1.1 503 Service Unavailable\r\n\r\n{\"error\":1}";
    assert_eq!(parse(eof).unwrap().body, b"{\"error\":1}");
    assert!(matches!(parse(b"garbage"), Err(HttpError::Transport(_))));
    assert!(matches!(
        parse(b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\nshort"),
        Err(HttpError::Transport(_))
    ));
    assert!(matches!(
        parse(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n"),
        Err(HttpError::Transport(_))
    ));
}

#[cfg(unix)]
#[tokio::test]
async fn a_request_carries_the_bearer_token_and_json_body_over_the_socket() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("t.sock");
    let listener = tokio::net::UnixListener::bind(&socket).unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buf = vec![0_u8; 4096];
        let mut got = Vec::new();
        loop {
            let n = stream.read(&mut buf).await.unwrap();
            got.extend_from_slice(&buf[..n]);
            if got.windows(4).any(|w| w == b"\r\n\r\n") && got.ends_with(b"{\"a\":1}") {
                break;
            }
        }
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
            .await
            .unwrap();
        got
    });
    let reply = request(
        &Endpoint::Unix(socket.clone()),
        "POST",
        "/v1/x",
        "secret-key",
        Some(b"{\"a\":1}"),
        Duration::from_secs(5),
    )
    .await
    .unwrap();
    assert_eq!(reply.status, 200);
    assert_eq!(reply.body, b"ok");
    let sent = String::from_utf8(server.await.unwrap()).unwrap();
    assert!(sent.starts_with("POST /v1/x HTTP/1.1\r\n"));
    assert!(sent.contains("Authorization: Bearer secret-key\r\n"));
    assert!(sent.contains("Content-Type: application/json\r\n"));
    assert!(sent.contains("Content-Length: 7\r\n"));
    assert!(sent.ends_with("{\"a\":1}"));

    let missing = request(
        &Endpoint::Unix(dir.path().join("none.sock")),
        "GET",
        "/health",
        "k",
        None,
        Duration::from_secs(1),
    )
    .await
    .unwrap_err();
    assert!(matches!(missing, HttpError::Connect(_)));
}

#[tokio::test]
async fn a_loopback_endpoint_speaks_the_same_protocol() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buf = vec![0_u8; 4096];
        let n = stream.read(&mut buf).await.unwrap();
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
            .await
            .unwrap();
        String::from_utf8_lossy(&buf[..n]).into_owned()
    });
    let endpoint = Endpoint::Loopback(port);
    assert_eq!(endpoint.host_arg(), "127.0.0.1");
    assert_eq!(
        endpoint.port_arg().as_deref(),
        Some(port.to_string().as_str())
    );
    let reply = request(
        &endpoint,
        "GET",
        "/health",
        "k",
        None,
        Duration::from_secs(5),
    )
    .await
    .unwrap();
    assert_eq!(reply.body, b"ok");
    assert!(server.await.unwrap().starts_with("GET /health HTTP/1.1"));
}
