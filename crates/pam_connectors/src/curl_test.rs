use std::pin::Pin;
use std::sync::Arc;

use pam_net::{NetFailure, NetSettings, NetworkSource};
use url::Url;

use crate::curl::parse_response;
use crate::transport::{HttpRequest, Method};
use crate::{CurlTransport, MAX_JSON_BYTES};

/// A direct profile, as the daemon passes until the Network settings exist.
fn direct() -> Arc<dyn NetworkSource> {
    Arc::new(Arc::new(NetSettings::direct()))
}

/// A source that must never be asked: a request refused before the
/// transport reads its profile proves nothing ran, because the refusal
/// would otherwise be this source's own.
struct NeverSource;

impl NetworkSource for NeverSource {
    fn settings(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<Arc<NetSettings>, NetFailure>> + Send + '_>> {
        Box::pin(async {
            Err(NetFailure::SettingsInvalid(
                "the test's network source was consulted".to_owned(),
            ))
        })
    }
}

/// The transport over the trusted curl, or `None` with a line when this
/// machine has none.
fn transport(source: Arc<dyn NetworkSource>) -> Option<CurlTransport> {
    match CurlTransport::trusted(source) {
        Ok(transport) => Some(transport),
        Err(error) => {
            eprintln!("no trusted operating-system curl ({error}); skipping");
            None
        }
    }
}

/// The config lines, or `None` with a line when there is no curl to
/// render them for.
fn config_lines(request: &HttpRequest, deadline_secs: u64) -> Option<Vec<String>> {
    match CurlTransport::config_for(&NetSettings::direct(), request, deadline_secs) {
        Ok(config) => Some(config.lines().map(str::to_owned).collect()),
        Err(error) => {
            eprintln!("no trusted operating-system curl ({error}); skipping");
            None
        }
    }
}

#[test]
fn the_config_carries_the_url_the_deadline_and_every_header() {
    let Some(lines) = config_lines(&request(), 12) else {
        return;
    };
    assert_eq!(lines[0], "url = \"https://api.github.com/user\"");
    assert!(lines.contains(&"max-time = 12".to_owned()), "{lines:?}");
    assert!(
        lines.contains(&"header = \"Authorization: Bearer ghp_secret\"".to_owned()),
        "{lines:?}"
    );
    assert!(
        lines.contains(&"header = \"Accept: application/json\"".to_owned()),
        "{lines:?}"
    );
    assert!(lines.contains(&"include".to_owned()), "{lines:?}");
    assert!(
        lines.contains(&format!("max-filesize = {MAX_JSON_BYTES}")),
        "{lines:?}"
    );
    // Production is https only, for the request and for anything curl
    // would follow; a direct profile says so about the proxy as well.
    assert!(
        lines.contains(&"proto = \"=https\"".to_owned()),
        "{lines:?}"
    );
    assert!(
        lines.contains(&"proto-redir = \"=https\"".to_owned()),
        "{lines:?}"
    );
    assert!(lines.contains(&"noproxy = \"*\"".to_owned()), "{lines:?}");
}

#[test]
fn quotes_and_backslashes_in_a_header_are_escaped() {
    let mut request = request();
    request.headers = vec![("X-Odd".to_owned(), "a\"b\\c".to_owned())];
    let Some(lines) = config_lines(&request, 1) else {
        return;
    };
    assert!(
        lines.contains(&"header = \"X-Odd: a\\\"b\\\\c\"".to_owned()),
        "{lines:?}"
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
        body: None,
        url: Url::parse("https://api.github.com/user").expect("the test URL parses"),
        headers: vec![
            ("Authorization".to_owned(), "Bearer ghp_secret".to_owned()),
            ("Accept".to_owned(), "application/json".to_owned()),
        ],
        max_bytes: MAX_JSON_BYTES,
        follow_one_https_redirect_without_auth: false,
    }
}

/// The transport has no executable of its own to hold: the launcher
/// resolves the operating system's curl itself, so there is no path a
/// caller could hand in and nothing a PATH entry could substitute.
#[test]
fn the_transport_holds_no_executable_path_of_its_own() {
    let Some(transport) = transport(direct()) else {
        return;
    };
    let shown = format!("{transport:?}");
    assert!(shown.starts_with("CurlTransport"), "{shown}");
    assert!(!shown.contains("curl"), "{shown}");
    assert!(!shown.contains('/'), "{shown}");
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
#[test]
fn platforms_without_a_verified_system_binary_fail_closed() {
    assert!(matches!(
        CurlTransport::trusted(direct()),
        Err(crate::TransportError::Policy {
            cause: "trusted_curl_unavailable",
            ..
        })
    ));
}

#[test]
fn mutation_body_and_credentials_stay_in_escaped_stdin_config() {
    let mut req = request();
    req.method = Method::Post;
    req.body = Some(b"{\n\"title\":\"secret body\\nurl = evil\"\n}".to_vec());
    let Some(lines) = config_lines(&req, 5) else {
        return;
    };
    assert!(
        lines.contains(&"request = \"POST\"".to_owned()),
        "{lines:?}"
    );
    assert_eq!(
        lines
            .iter()
            .filter(|line| line.starts_with("url ="))
            .count(),
        1
    );
    assert!(
        lines
            .iter()
            .any(|line| line.starts_with("data-raw = \"{\\n")),
        "{lines:?}"
    );
    // The launcher's argument vector is a constant; the body and the
    // credential are on standard input only.
    assert_eq!(pam_net::CURL_ARGV, ["-q", "--config", "-"]);
}

#[tokio::test]
async fn mutation_invalid_body_or_redirect_policy_refuses_before_process_start() {
    use crate::HttpTransport;
    let Some(transport) = transport(Arc::new(NeverSource)) else {
        return;
    };
    for (body, follow) in [
        (Some(vec![b'x'; 16 * 1024 + 1]), false),
        (Some(b"[]".to_vec()), false),
        (Some(b"{}".to_vec()), true),
        (None, false),
    ] {
        let mut req = request();
        req.method = Method::Put;
        req.body = body;
        req.follow_one_https_redirect_without_auth = follow;
        let error = transport
            .send(
                req,
                std::time::Instant::now() + std::time::Duration::from_secs(1),
            )
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            crate::TransportError::Policy {
                cause: "mutation_body_invalid",
                ..
            }
        ));
    }
}

#[test]
fn upload_pack_exception_accepts_only_the_fixed_read_only_packet() {
    let mut request = request();
    request.method = Method::Post;
    request.url = Url::parse("https://git.example/team/repo.git/git-upload-pack").unwrap();
    request.headers.push((
        "Content-Type".into(),
        "application/x-git-upload-pack-request".into(),
    ));
    let body = format!("0033want {} \n00000009done\n", "a".repeat(40)).into_bytes();
    request.body = Some(body.clone());
    assert!(crate::curl::validate_request_body(&request).is_ok());
    assert_eq!(body.len(), 64);
    for invalid in [
        b"0032want short\n00000009done\n".to_vec(),
        format!("0033want {} \n00000009done\n", "0".repeat(40)).into_bytes(),
        [body.as_slice(), b"0000"].concat(),
    ] {
        request.body = Some(invalid);
        assert!(crate::curl::validate_request_body(&request).is_err());
    }
    // Up to two exact have lines after the flush are the only extension.
    let want = format!("0033want {} \n0000", "a".repeat(40));
    let have = |sha: &str| format!("0032have {sha}\n");
    for valid in [
        format!("{want}{}0009done\n", have(&"b".repeat(40))),
        format!(
            "{want}{}{}0009done\n",
            have(&"b".repeat(40)),
            have(&"c".repeat(40))
        ),
    ] {
        request.body = Some(valid.into_bytes());
        assert!(crate::curl::validate_request_body(&request).is_ok());
    }
    for invalid in [
        format!(
            "{want}{}{}{}0009done\n",
            have(&"b".repeat(40)),
            have(&"c".repeat(40)),
            have(&"d".repeat(40))
        ),
        format!("{want}{}0009done\n", have(&"0".repeat(40))),
        format!("{want}{}0009done\n", have(&"B".repeat(40))),
        format!("{want}0032have {}\n", "b".repeat(40)),
        format!("{want}{}\n0009done\n", have(&"b".repeat(40))),
    ] {
        request.body = Some(invalid.into_bytes());
        assert!(crate::curl::validate_request_body(&request).is_err());
    }
    request.body = Some(body);
    request.url.set_path("/team/repo.git/git-receive-pack");
    assert!(crate::curl::validate_request_body(&request).is_err());
    request.url.set_path("/team/repo.git/git-upload-pack");
    request.follow_one_https_redirect_without_auth = true;
    assert!(crate::curl::validate_request_body(&request).is_err());
}

#[cfg(unix)]
#[test]
fn fixed_upload_pack_packet_is_accepted_by_real_local_git() {
    use std::io::Write;
    use std::process::{Command, Stdio};
    let directory = tempfile::tempdir().unwrap();
    let run = |args: &[&str]| {
        let output = Command::new("/usr/bin/git")
            .args(args)
            .current_dir(directory.path())
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .output()
            .unwrap();
        assert!(output.status.success(), "local Git fixture failed");
        String::from_utf8(output.stdout).unwrap()
    };
    run(&["init", "-q"]);
    std::fs::write(directory.path().join("file"), b"bounded fixture\n").unwrap();
    run(&["add", "file"]);
    run(&[
        "-c",
        "user.name=Fixture",
        "-c",
        "user.email=fixture@example.invalid",
        "-c",
        "commit.gpgsign=false",
        "commit",
        "-qm",
        "fixture",
    ]);
    let sha = run(&["rev-parse", "HEAD"]);
    let packet = format!("0033want {} \n00000009done\n", sha.trim());
    let mut child = Command::new("/usr/bin/git")
        .args(["upload-pack", "--stateless-rpc"])
        .arg(directory.path())
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    stdin.write_all(packet.as_bytes()).unwrap();
    drop(stdin);
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    assert!(output.stdout.starts_with(b"0008NAK\nPACK"));
    assert!(output.stdout.len() < 64 * 1024);
}

#[test]
fn upload_pack_packet_stays_exact_in_curl_stdin_config() {
    let mut req = request();
    req.method = Method::Post;
    req.url = Url::parse("https://git.example/team/repo.git/git-upload-pack").unwrap();
    req.headers.push((
        "Content-Type".into(),
        "application/x-git-upload-pack-request".into(),
    ));
    let sha = "a".repeat(40);
    req.body = Some(format!("0033want {sha} \n00000009done\n").into_bytes());
    if let Some(lines) = config_lines(&req, 5) {
        assert!(
            lines
                .iter()
                .any(|line| line == &format!("data-raw = \"0033want {sha} \\n00000009done\\n\"")),
            "{lines:?}"
        );
    }
    for method in [Method::Put, Method::Get] {
        req.method = method;
        assert!(crate::curl::validate_request_body(&req).is_err());
    }
    req.method = Method::Post;
    req.headers
        .push(("content-type".into(), "application/json".into()));
    assert!(crate::curl::validate_request_body(&req).is_err());
}

#[tokio::test]
async fn a_header_with_a_line_break_is_refused_before_curl_is_started() {
    use crate::HttpTransport as _;
    // A source that fails when read: had the request got as far as
    // reading its profile, the refusal would be `network_settings_invalid`,
    // so the cause proves nothing ran.
    let Some(transport) = transport(Arc::new(NeverSource)) else {
        return;
    };
    for value in ["Bearer abc\n", "Bearer abc\r\nX-Injected: 1", "Bearer a\0b"] {
        let mut request = request();
        request.headers = vec![("Authorization".to_owned(), value.to_owned())];
        let error = transport
            .send(
                request,
                std::time::Instant::now() + std::time::Duration::from_secs(5),
            )
            .await
            .unwrap_err();
        assert!(
            matches!(
                error,
                crate::TransportError::Policy {
                    cause: "header_invalid",
                    ..
                }
            ),
            "{value:?}: {error:?}"
        );
    }
}

/// A source that cannot produce a profile refuses the request with the
/// launcher's own cause and never falls back to a direct connection.
#[tokio::test]
async fn an_unusable_network_profile_refuses_the_request_closed() {
    use crate::HttpTransport as _;
    let Some(transport) = transport(Arc::new(NeverSource)) else {
        return;
    };
    let error = transport
        .send(
            request(),
            std::time::Instant::now() + std::time::Duration::from_secs(5),
        )
        .await
        .unwrap_err();
    assert!(
        matches!(
            error,
            crate::TransportError::Policy {
                cause: "network_settings_invalid",
                ..
            }
        ),
        "{error:?}"
    );
    let connector = crate::ConnectorError::from(error);
    assert_eq!(connector.cause(), "network_settings_invalid");
    assert!(!connector.retryable());
}

/// A source closed by the managed policy.
struct PolicyClosedSource;

impl NetworkSource for PolicyClosedSource {
    fn settings(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<Arc<NetSettings>, NetFailure>> + Send + '_>> {
        Box::pin(async {
            Err(NetFailure::PolicyInvalid(
                "network.proxy could not be put in force".to_owned(),
            ))
        })
    }
}

/// A policy closure keeps its own cause through the connector transport,
/// is never retried, and never falls back to a direct connection.
#[tokio::test]
async fn a_policy_closed_network_refuses_the_request_with_the_policy_cause() {
    use crate::HttpTransport as _;
    let Some(transport) = transport(Arc::new(PolicyClosedSource)) else {
        return;
    };
    let error = transport
        .send(
            request(),
            std::time::Instant::now() + std::time::Duration::from_secs(5),
        )
        .await
        .unwrap_err();
    assert!(
        matches!(
            error,
            crate::TransportError::Policy {
                cause: "network_policy_invalid",
                ..
            }
        ),
        "{error:?}"
    );
    let connector = crate::ConnectorError::from(error);
    assert_eq!(connector.cause(), "network_policy_invalid");
    assert!(!connector.retryable());
}
