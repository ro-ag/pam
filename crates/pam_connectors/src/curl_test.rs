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

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[test]
fn connector_command_uses_only_trusted_curl_without_argv_credentials() {
    let Ok(path) = CurlTransport::trusted_path() else {
        return;
    };
    let transport = CurlTransport::new(path.clone());
    let command = transport.command(&request(), 12).unwrap();
    let command = command.as_std();
    assert_eq!(command.get_program(), path.as_os_str());
    let args: Vec<_> = command.get_args().collect();
    assert_eq!(args[0], "-q");
    assert_eq!(args[1], "--config");
    assert_eq!(args[2], "-");
    assert_eq!(command.get_current_dir(), Some(std::path::Path::new("/")));
    assert!(command.get_envs().next().is_none());
    assert!(
        args.iter()
            .all(|arg| !arg.to_string_lossy().contains("ghp_secret"))
    );
    assert!(
        args.iter()
            .all(|arg| !arg.to_string_lossy().contains("api.github.com"))
    );
}

#[test]
fn caller_supplied_executable_cannot_replace_the_connector_bridge() {
    let transport = CurlTransport::new("/agent-controlled/curl".into());
    assert!(matches!(
        transport.command(&request(), 1),
        Err(crate::TransportError::Policy {
            cause: "trusted_curl_unavailable",
            ..
        })
    ));
}

#[cfg(target_os = "windows")]
#[test]
fn windows_resolves_the_operating_system_curl_from_system32() {
    let path = CurlTransport::trusted_path().unwrap();
    assert_eq!(path.file_name(), Some(std::ffi::OsStr::new("curl.exe")));
    assert_eq!(
        path.parent().and_then(std::path::Path::file_name),
        Some(std::ffi::OsStr::new("System32"))
    );
}

#[cfg(target_os = "windows")]
#[test]
fn windows_child_keeps_the_os_roots_and_a_neutral_working_directory() {
    let transport = CurlTransport::new(CurlTransport::trusted_path().unwrap());
    let command = transport.command(&request(), 12).unwrap();
    let command = command.as_std();
    assert!(
        command
            .get_envs()
            .any(|(key, _)| key == std::ffi::OsStr::new("SystemRoot"))
    );
    assert!(
        command
            .get_current_dir()
            .is_some_and(|dir| dir.has_root() && dir.parent().is_none())
    );
}

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
#[test]
fn platforms_without_a_verified_system_binary_fail_closed() {
    assert!(matches!(
        CurlTransport::trusted_path(),
        Err(crate::TransportError::Policy {
            cause: "trusted_curl_unavailable",
            ..
        })
    ));
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[test]
fn inherited_curl_home_cannot_enable_a_trace_file() {
    if CurlTransport::trusted_path().is_err() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let trace = dir.path().join("forbidden-trace");
    std::fs::write(
        dir.path().join(".curlrc"),
        format!("trace = \"{}\"\n", trace.display()),
    )
    .unwrap();
    // A subprocess supplies hostile inherited variables without mutating this
    // multithreaded test runner's environment.
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "curl_test::hostile_environment_child"])
        .env("PAM_CURL_ENV_PROBE", "1")
        .env("CURL_HOME", dir.path())
        .env("HOME", dir.path())
        .status()
        .unwrap();
    assert!(status.success());
    assert!(!trace.exists(), "inherited curlrc wrote a host trace file");
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[tokio::test]
async fn hostile_environment_child() {
    use tokio::io::AsyncWriteExt;
    if std::env::var_os("PAM_CURL_ENV_PROBE").is_none() {
        return;
    }
    let path = CurlTransport::trusted_path().unwrap();
    let transport = CurlTransport::new(path);
    let mut child = transport.command(&request(), 1).unwrap().spawn().unwrap();
    let mut input = child.stdin.take().unwrap();
    input
        .write_all(b"url = \"https://127.0.0.1:1/\"\n")
        .await
        .unwrap();
    input.shutdown().await.unwrap();
    drop(input);
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), child.wait_with_output())
        .await
        .unwrap()
        .unwrap();
}

#[test]
fn mutation_body_and_credentials_stay_in_escaped_stdin_config() {
    let mut req = request();
    req.method = Method::Post;
    req.body = Some(b"{\n\"title\":\"secret body\\nurl = evil\"\n}".to_vec());
    let config = CurlTransport::config_for(&req, 5);
    assert!(config.contains("request = \"POST\""));
    assert_eq!(
        config
            .lines()
            .filter(|line| line.starts_with("url ="))
            .count(),
        1
    );
    assert!(config.contains("data-binary = \"{\\n"));
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    {
        let transport = CurlTransport::new(CurlTransport::trusted_path().unwrap());
        let command = transport.command(&req, 5).unwrap();
        let argv = command
            .as_std()
            .get_args()
            .map(|arg| arg.to_string_lossy())
            .collect::<Vec<_>>()
            .join(" ");
        assert!(!argv.contains("secret body"));
        assert!(!argv.contains("ghp_secret"));
    }
}

#[tokio::test]
async fn mutation_invalid_body_or_redirect_policy_refuses_before_process_start() {
    use crate::HttpTransport;
    let transport = CurlTransport::new(std::path::PathBuf::from("untrusted-unused"));
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
