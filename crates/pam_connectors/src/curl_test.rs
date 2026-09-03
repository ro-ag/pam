use url::Url;

use crate::curl::parse_response;
use crate::transport::{HttpRequest, Method};
use crate::{CurlTransport, MAX_JSON_BYTES};

#[test]
fn the_config_carries_the_url_the_deadline_and_every_header() {
    let config = CurlTransport::config_for(&request(), 12);
    let lines: Vec<&str> = config.lines().collect();
    assert_eq!(lines[0], "url = \"https://api.github.com/user\"");
    assert_eq!(lines[1], "max-time = 12");
    assert_eq!(lines[2], "header = \"Authorization: Bearer ghp_secret\"");
    assert_eq!(lines[3], "header = \"Accept: application/json\"");
    assert_eq!(lines.len(), 4);
}

#[test]
fn quotes_and_backslashes_in_a_header_are_escaped() {
    let mut request = request();
    request.headers = vec![("X-Odd".to_owned(), "a\"b\\c".to_owned())];
    let config = CurlTransport::config_for(&request, 1);
    assert!(
        config.contains("header = \"X-Odd: a\\\"b\\\\c\""),
        "{config}"
    );
}

#[test]
fn a_simple_response_parses() {
    let raw =
        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nX-Rate: 4\r\n\r\n{\"ok\":true}";
    let response = parse_response(raw).unwrap();
    assert_eq!(response.status, 200);
    assert_eq!(response.body, b"{\"ok\":true}");
    assert_eq!(response.header("content-type"), Some("application/json"));
    assert_eq!(response.header("X-RATE"), Some("4"));
}

#[test]
fn a_hundred_continue_prelude_is_skipped() {
    let raw = b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 201 Created\r\nLocation: /x\r\n\r\nbody";
    let response = parse_response(raw).unwrap();
    assert_eq!(response.status, 201);
    assert_eq!(response.body, b"body");
    assert_eq!(response.header("location"), Some("/x"));
}

#[test]
fn an_http_two_status_line_parses() {
    let raw = b"HTTP/2 429 \r\nretry-after: 30\r\n\r\n";
    let response = parse_response(raw).unwrap();
    assert_eq!(response.status, 429);
    assert_eq!(response.header("retry-after"), Some("30"));
    assert!(response.body.is_empty());
}

#[test]
fn bare_newline_separated_headers_parse() {
    let raw = b"HTTP/1.1 200 OK\nContent-Length: 2\n\nhi";
    let response = parse_response(raw).unwrap();
    assert_eq!(response.status, 200);
    assert_eq!(response.body, b"hi");
}

#[test]
fn output_that_is_not_a_response_is_a_network_failure() {
    assert!(parse_response(b"").is_err());
    assert!(parse_response(b"curl: (6) could not resolve host\r\n\r\n").is_err());
    assert!(parse_response(b"HTTP/1.1 not-a-number\r\n\r\n").is_err());
}

#[test]
fn a_body_holding_a_blank_line_survives_the_split() {
    let raw = b"HTTP/1.1 200 OK\r\n\r\nfirst\r\n\r\nsecond";
    let response = parse_response(raw).unwrap();
    assert_eq!(response.body, b"first\r\n\r\nsecond");
}

fn request() -> HttpRequest {
    HttpRequest {
        method: Method::Get,
        url: Url::parse("https://api.github.com/user").expect("the test URL parses"),
        headers: vec![
            ("Authorization".to_owned(), "Bearer ghp_secret".to_owned()),
            ("Accept".to_owned(), "application/json".to_owned()),
        ],
        max_bytes: MAX_JSON_BYTES,
        follow_one_https_redirect_without_auth: false,
    }
}
