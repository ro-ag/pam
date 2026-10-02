use std::path::{Path, PathBuf};

use url::Url;

use crate::failure::{Diagnostics, NetFailure};
use crate::launch::{CURL_ARGV, CurlRequest, Method, Seen, StderrSink};
use crate::settings::{
    NetSettings, NoProxyRule, Proxy, ProxyAuth, ProxyPassword, Route, parse_no_proxy,
};
use crate::trusted::{CurlInfo, TlsBackend, TrustedCurl};

/// Options that would weaken verification or trust: none may ever be
/// rendered, whatever the request or the settings.
const FORBIDDEN: [&str; 14] = [
    "insecure",
    "proxy-insecure",
    "ssl-no-revoke",
    "ssl-revoke-best-effort",
    "ssl-allow-beast",
    "proxy-ssl-allow-beast",
    "capath",
    "proxy-capath",
    "ca-native",
    "proxy-ca-native",
    "doh-insecure",
    "ciphers",
    "tlsv1.0",
    "config",
];

fn curl() -> Option<TrustedCurl> {
    let resolved = TrustedCurl::resolve().ok();
    if resolved.is_none() {
        eprintln!("no trusted operating-system curl; skipping");
    }
    resolved
}

fn url(text: &str) -> Url {
    Url::parse(text).unwrap()
}

fn absolute(name: &str) -> PathBuf {
    if cfg!(windows) {
        PathBuf::from(format!("C:\\pam\\{name}"))
    } else {
        PathBuf::from(format!("/pam/{name}"))
    }
}

fn proxied(
    auth: ProxyAuth,
    password: Option<&str>,
    rules: &[&str],
    ca: Option<PathBuf>,
) -> NetSettings {
    let proxy = Proxy::parse("http://proxy.corp.example:3128", auth, Some("svc-pam")).unwrap();
    let password = password.map(|p| ProxyPassword::new(p).unwrap());
    NetSettings::new(Some(proxy), password, parse_no_proxy(rules).unwrap(), ca).unwrap()
}

fn lines(config: &str) -> Vec<&str> {
    config.lines().collect()
}

/// Every option name in a rendered document.
fn option_names(config: &str) -> Vec<&str> {
    config
        .lines()
        .map(|line| line.split([' ', '=']).next().unwrap_or_default())
        .collect()
}

fn assert_no_forbidden_option(config: &str) {
    for name in option_names(config) {
        assert!(!FORBIDDEN.contains(&name), "{name} rendered:\n{config}");
    }
}

#[test]
fn the_argument_vector_is_the_constant_for_every_configuration() {
    let Some(curl) = curl() else {
        return;
    };
    let direct = NetSettings::direct();
    let full = proxied(
        ProxyAuth::Basic,
        Some("hunter2"),
        &["corp.example"],
        Some(absolute("ca.pem")),
    );
    let requests: Vec<CurlRequest<'_>> = vec![
        curl.request(&direct, &url("https://api.github.com/user")),
        curl.request(&full, &url("https://jenkins.corp.example/job"))
            .method(Method::Post)
            .header("Authorization", "Bearer x")
            .body(b"{}")
            .max_time(30)
            .connect_timeout(5)
            .stall_limit(1024, 60)
            .max_filesize(4096)
            .capture_limit(8192)
            .include_headers()
            .fail_on_http_error()
            .diagnostic(),
        curl.request(
            &full,
            &url("https://huggingface.co/x/y/resolve/main/z.gguf"),
        )
        .follow_https_redirects(10)
        .output(&absolute("z.part"))
        .etag_save(&absolute("z.etag"))
        .resume(),
        curl.request(&direct, &url("https://localhost/"))
            .method(Method::Head)
            .unix_socket(&absolute("engine.sock")),
    ];
    for request in requests {
        let command = request.command();
        let std_command = command.as_std();
        assert_eq!(std_command.get_program(), curl.path().as_os_str());
        let args: Vec<_> = std_command
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert_eq!(args, CURL_ARGV);
        #[cfg(not(target_os = "windows"))]
        assert_eq!(std_command.get_envs().count(), 0);
        assert!(std_command.get_current_dir().is_some());
        // Rendering succeeds for each of these, and nothing forbidden is in it.
        assert_no_forbidden_option(&request.config().unwrap());
    }
}

#[test]
fn a_connector_request_renders_its_lines_in_order() {
    let Some(curl) = curl() else {
        return;
    };
    let settings = NetSettings::direct();
    let config = curl
        .request(&settings, &url("https://api.github.com/user?q={a,b}"))
        .header("Authorization", "Bearer ghp_secret")
        .header("Accept", "application/json")
        .include_headers()
        .max_time(12)
        .max_filesize(1024)
        .config()
        .unwrap();
    let got = lines(&config);
    let expected = [
        "url = \"https://api.github.com/user?q={a,b}\"",
        "globoff",
        "silent",
        "show-error",
        "header = \"Authorization: Bearer ghp_secret\"",
        "header = \"Accept: application/json\"",
        "proto = \"=https\"",
        "proto-redir = \"=https\"",
        "retry = 0",
        "max-time = 12",
        "max-filesize = 1024",
        "include",
        "noproxy = \"*\"",
    ];
    assert_eq!(&got[..expected.len()], &expected[..], "{config}");
    assert!(
        got[expected.len()]
            .starts_with("write-out = \"%{stderr}\\npam-net http_connect=%{http_connect}"),
        "{config}"
    );
    assert_eq!(got.len(), expected.len() + 1, "{config}");
}

#[test]
fn a_download_request_renders_its_lines() {
    let Some(curl) = curl() else {
        return;
    };
    let settings = NetSettings::direct();
    let part = absolute("model \"part\".bin");
    let config = curl
        .request(
            &settings,
            &url("https://huggingface.co/x/y/resolve/main/z.gguf"),
        )
        .header("If-Range", "\"etag-1\"")
        .fail_on_http_error()
        .follow_https_redirects(10)
        .connect_timeout(30)
        .stall_limit(1024, 60)
        .output(&part)
        .etag_save(&absolute("z.etag"))
        .resume()
        .config()
        .unwrap();
    let escaped_part = part
        .to_string_lossy()
        .replace('\\', "\\\\")
        .replace('"', "\\\"");
    for needle in [
        "header = \"If-Range: \\\"etag-1\\\"\"",
        "retry = 0",
        "connect-timeout = 30",
        "speed-limit = 1024",
        "speed-time = 60",
        "fail",
        "location",
        "max-redirs = 10",
        &format!("output = \"{escaped_part}\""),
        "continue-at = \"-\"",
        "noproxy = \"*\"",
    ] {
        assert!(
            lines(&config).contains(&needle),
            "{needle} missing:\n{config}"
        );
    }
    assert!(config.contains("etag-save = \""), "{config}");
    assert_no_forbidden_option(&config);
}

#[test]
fn the_proxy_lines_carry_the_credential_and_the_tunnel_options() {
    let Some(curl) = curl() else {
        return;
    };
    let target = url("https://jenkins.corp.example/");
    let settings = proxied(
        ProxyAuth::Basic,
        Some("p@ss \"w\\ord"),
        &[".corp.example", "10.0.0.0/8"],
        Some(absolute("ca.pem")),
    );
    let config = curl.request(&settings, &target).config().unwrap();
    let got = lines(&config);
    for needle in [
        "proxy = \"http://proxy.corp.example:3128\"",
        "proxytunnel",
        "suppress-connect-headers",
        "noproxy = \"corp.example,10.0.0.0/8\"",
        "proxy-user = \"svc-pam:p@ss \\\"w\\\\ord\"",
        "proxy-basic",
    ] {
        assert!(got.contains(&needle), "{needle} missing:\n{config}");
    }
    let ca = absolute("ca.pem").to_string_lossy().replace('\\', "\\\\");
    assert!(
        got.contains(&format!("cacert = \"{ca}\"").as_str()),
        "{config}"
    );
    // A plain http proxy's certificate is nobody's: no proxy-cacert.
    assert!(!config.contains("proxy-cacert"), "{config}");
    assert!(!config.contains("noproxy = \"*\""), "{config}");
    assert_no_forbidden_option(&config);

    // anyauth lets curl pick from the challenge.
    let settings = proxied(ProxyAuth::AnyAuth, Some("hunter2"), &[], None);
    let config = curl.request(&settings, &target).config().unwrap();
    assert!(lines(&config).contains(&"proxy-anyauth"), "{config}");
    assert!(lines(&config).contains(&"noproxy = \"\""), "{config}");
    assert!(!config.contains("cacert"), "{config}");

    // No password, or mode none: the proxy lines without a credential.
    for settings in [
        proxied(ProxyAuth::Basic, None, &[], None),
        proxied(ProxyAuth::None, Some("hunter2"), &[], None),
    ] {
        let config = curl.request(&settings, &target).config().unwrap();
        assert!(
            config.contains("proxy = \"http://proxy.corp.example:3128\""),
            "{config}"
        );
        assert!(!config.contains("proxy-user"), "{config}");
        assert!(!config.contains("hunter2"), "{config}");
    }
}

#[test]
fn an_https_proxy_gets_the_bundle_for_its_own_certificate() {
    let Some(curl) = curl() else {
        return;
    };
    let proxy = Proxy::parse("https://proxy.corp.example:443", ProxyAuth::None, None).unwrap();
    let settings =
        NetSettings::new(Some(proxy), None, Vec::new(), Some(absolute("ca.pem"))).unwrap();
    let config = curl
        .request(&settings, &url("https://jenkins.corp.example/"))
        .config();
    if curl.info().https_proxy {
        let config = config.unwrap();
        assert!(
            config.contains("proxy = \"https://proxy.corp.example:443\""),
            "{config}"
        );
        assert!(config.contains("proxy-cacert = \""), "{config}");
        assert_no_forbidden_option(&config);
    } else {
        assert_eq!(config.unwrap_err().cause(), "network_settings_invalid");
    }
}

#[test]
fn a_loopback_target_is_added_to_the_no_proxy_list_not_the_whole_proxy_removed() {
    let Some(curl) = curl() else {
        return;
    };
    let settings = proxied(ProxyAuth::None, None, &["corp.example"], None);
    for (target, entry) in [
        ("http://localhost:8080/x", "localhost"),
        ("http://LOCALHOST./x", "localhost"),
        ("http://127.0.0.1:9/", "127.0.0.1"),
        ("http://[::1]:9/", "::1"),
        ("http://dev.localhost/", "dev.localhost"),
    ] {
        let request = curl.request(&settings, &url(target)).allow_http_for_tests();
        assert_eq!(request.route(), Route::Bypass, "{target}");
        let config = request.config().unwrap();
        assert!(
            config.contains("proxy = \"http://proxy.corp.example:3128\""),
            "{target}: {config}"
        );
        assert!(
            lines(&config).contains(&format!("noproxy = \"corp.example,{entry}\"").as_str()),
            "{target}: {config}"
        );
    }
    // A `*` entry switches the proxy off for everyone.
    let settings = proxied(ProxyAuth::None, None, &["*", "corp.example"], None);
    let config = curl
        .request(&settings, &url("https://jenkins.corp.example/"))
        .config()
        .unwrap();
    assert!(
        !lines(&config).iter().any(|line| line.starts_with("proxy")),
        "{config}"
    );
    assert!(lines(&config).contains(&"noproxy = \"*\""), "{config}");
}

#[test]
fn a_unix_socket_request_never_uses_the_proxy() {
    let Some(curl) = curl() else {
        return;
    };
    let settings = proxied(ProxyAuth::Basic, Some("hunter2"), &[], None);
    let request = curl
        .request(&settings, &url("https://localhost/health"))
        .unix_socket(&absolute("engine.sock"));
    assert_eq!(request.route(), Route::Bypass);
    let config = request.config().unwrap();
    assert!(config.contains("unix-socket = \""), "{config}");
    assert!(
        !lines(&config).iter().any(|line| line.starts_with("proxy")),
        "{config}"
    );
    assert!(!config.contains("hunter2"), "{config}");
    assert!(lines(&config).contains(&"noproxy = \"*\""), "{config}");
}

#[test]
#[allow(clippy::too_many_lines)] // One refusal table; splitting it hides what is compared.
fn refused_requests_name_the_field_and_start_no_process() {
    let Some(curl) = curl() else {
        return;
    };
    let settings = NetSettings::direct();
    let refusals: Vec<(CurlRequest<'_>, &str, &str)> = vec![
        (
            curl.request(&settings, &url("http://plain.example/")),
            "url",
            "only https",
        ),
        (
            curl.request(&settings, &url("ftp://files.example/")),
            "url",
            "only https",
        ),
        (
            curl.request(&settings, &url("https://user:pw@api.example/")),
            "url",
            "user name or password",
        ),
        (
            curl.request(&settings, &url("https://api.example/"))
                .header("X-Bad", "line\nbreak"),
            "header",
            "control character",
        ),
        (
            curl.request(&settings, &url("https://api.example/"))
                .header("X-Bad", "nul\0"),
            "header",
            "control character",
        ),
        (
            curl.request(&settings, &url("https://api.example/"))
                .header("Bad Name", "v"),
            "header",
            "not an HTTP token",
        ),
        (
            curl.request(&settings, &url("https://api.example/"))
                .header("", "v"),
            "header",
            "not an HTTP token",
        ),
        (
            curl.request(&settings, &url("https://api.example/"))
                .header("@/etc/passwd", "v"),
            "header",
            "not an HTTP token",
        ),
        (
            curl.request(&settings, &url("https://api.example/"))
                .header("Proxy-Authorization", "Basic x"),
            "header",
            "network settings",
        ),
        (
            curl.request(&settings, &url("https://api.example/"))
                .header("Authorization", "Bearer x")
                .follow_https_redirects(2),
            "header",
            "does not follow redirects",
        ),
        (
            curl.request(&settings, &url("https://api.example/"))
                .header("Cookie", "a=b")
                .follow_https_redirects(2),
            "header",
            "does not follow redirects",
        ),
        (
            curl.request(&settings, &url("https://api.example/"))
                .body(b"{}"),
            "body",
            "only POST and PUT",
        ),
        (
            curl.request(&settings, &url("https://api.example/"))
                .method(Method::Post)
                .body(b"\xff\xfe"),
            "body",
            "not UTF-8",
        ),
        (
            curl.request(&settings, &url("https://api.example/"))
                .method(Method::Post)
                .body(b"nul\0"),
            "body",
            "control character",
        ),
        (
            curl.request(&settings, &url("https://api.example/"))
                .output(Path::new("relative/part")),
            "output",
            "absolute",
        ),
        (
            curl.request(&settings, &url("https://api.example/"))
                .etag_save(Path::new("relative.etag")),
            "etag-save",
            "absolute",
        ),
        (
            curl.request(&settings, &url("https://api.example/"))
                .resume(),
            "resume",
            "only a download to a file",
        ),
        (
            curl.request(&settings, &url("https://api.example/"))
                .unix_socket(Path::new("sock")),
            "unix-socket",
            "absolute",
        ),
    ];
    for (request, field, expected) in refusals {
        match request.config() {
            Err(NetFailure::RequestInvalid { field: got, detail }) => {
                assert_eq!(got, field, "{detail}");
                assert!(detail.contains(expected), "{field}: {detail}");
            }
            other => panic!("{field}: {other:?}"),
        }
    }
    let mut odd = absolute("part").into_os_string();
    odd.push("\n");
    let failure = curl
        .request(&settings, &url("https://api.example/"))
        .output(&PathBuf::from(odd))
        .config()
        .unwrap_err();
    assert_eq!(failure.cause(), "request_invalid");

    // Too large a document is refused whole.
    let huge = "x".repeat(2 * 1024 * 1024);
    let failure = curl
        .request(&settings, &url("https://api.example/"))
        .method(Method::Post)
        .body(huge.as_bytes())
        .config()
        .unwrap_err();
    assert!(
        matches!(
            failure,
            NetFailure::RequestInvalid {
                field: "request",
                ..
            }
        ),
        "{failure:?}"
    );
}

#[test]
fn the_body_and_headers_are_escaped_as_values() {
    let Some(curl) = curl() else {
        return;
    };
    let settings = NetSettings::direct();
    let config = curl
        .request(&settings, &url("https://api.example/"))
        .method(Method::Put)
        .header("X-Odd", "a\"b\\c")
        .header("X-Empty", "")
        .body(b"@file\n{\"k\":\"v\\\"\"}\r\n\ttab")
        .config()
        .unwrap();
    let got = lines(&config);
    assert!(got.contains(&"request = \"PUT\""), "{config}");
    assert!(got.contains(&"header = \"X-Odd: a\\\"b\\\\c\""), "{config}");
    assert!(got.contains(&"header = \"X-Empty;\""), "{config}");
    assert!(
        got.contains(&"data-raw = \"@file\\n{\\\"k\\\":\\\"v\\\\\\\"\\\"}\\r\\n\\ttab\""),
        "{config}"
    );
    assert!(!config.contains("data-binary"), "{config}");
    let head = curl
        .request(&settings, &url("https://api.example/"))
        .method(Method::Head)
        .config()
        .unwrap();
    assert!(lines(&head).contains(&"head"), "{head}");
}

#[test]
fn an_old_curl_is_refused_a_proxy_and_runs_without_the_diagnostics_line() {
    let Some(curl) = curl() else {
        return;
    };
    let old: &'static CurlInfo = Box::leak(Box::new(CurlInfo {
        version: (7, 55, 1),
        backend: TlsBackend::Schannel,
        banner: "curl 7.55.1 (Windows) libcurl/7.55.1 WinSSL".to_owned(),
        https_proxy: false,
    }));
    let old_curl = curl.with_info(old);
    let direct = NetSettings::direct();
    let config = old_curl
        .request(&direct, &url("https://api.example/"))
        .config()
        .unwrap();
    assert!(!config.contains("write-out"), "{config}");
    assert_no_forbidden_option(&config);

    let settings = proxied(ProxyAuth::None, None, &[], None);
    let failure = old_curl
        .request(&settings, &url("https://api.example/"))
        .config()
        .unwrap_err();
    assert_eq!(
        failure,
        NetFailure::CurlTooOld {
            found: "7.55.1".to_owned(),
            needed: "7.63.0",
            feature: "a proxy"
        }
    );

    let mid: &'static CurlInfo = Box::leak(Box::new(CurlInfo {
        version: (7, 80, 0),
        backend: TlsBackend::Schannel,
        banner: "curl 7.80.0 (Windows) libcurl/7.80.0 Schannel".to_owned(),
        https_proxy: true,
    }));
    let mid_curl = curl.with_info(mid);
    let settings = proxied(ProxyAuth::None, None, &["10.0.0.0/8"], None);
    let failure = mid_curl
        .request(&settings, &url("https://api.example/"))
        .config()
        .unwrap_err();
    assert_eq!(
        failure,
        NetFailure::CurlTooOld {
            found: "7.80.0".to_owned(),
            needed: "7.86.0",
            feature: "a CIDR range in the no-proxy list"
        }
    );
    // Without the range the same curl renders the proxy.
    let settings = proxied(ProxyAuth::None, None, &["corp.example"], None);
    assert!(
        mid_curl
            .request(&settings, &url("https://api.example/"))
            .config()
            .is_ok()
    );
}

#[test]
fn no_rendered_config_holds_a_forbidden_option() {
    let Some(curl) = curl() else {
        return;
    };
    let ca = Some(absolute("ca.pem"));
    let settings = [
        NetSettings::direct(),
        proxied(
            ProxyAuth::Basic,
            Some("hunter2"),
            &["corp.example"],
            ca.clone(),
        ),
        proxied(ProxyAuth::AnyAuth, Some("hunter2"), &["*"], None),
        NetSettings::new(None, None, Vec::new(), ca).unwrap(),
    ];
    for settings in &settings {
        for diagnostic in [false, true] {
            let mut request = curl
                .request(settings, &url("https://jenkins.corp.example/"))
                .follow_https_redirects(3)
                .fail_on_http_error()
                .include_headers();
            if diagnostic {
                request = request.diagnostic();
            }
            let config = request.config().unwrap();
            assert_no_forbidden_option(&config);
            // Verification is on and the protocols are pinned.
            assert!(lines(&config).contains(&"proto = \"=https\""), "{config}");
            assert!(
                lines(&config).contains(&"proto-redir = \"=https\""),
                "{config}"
            );
            assert_eq!(lines(&config).contains(&"verbose"), diagnostic);
        }
    }
    let rule = NoProxyRule::parse("corp.example").unwrap();
    assert_eq!(rule.curl_text(), "corp.example");
    assert_eq!(
        NoProxyRule::parse(".corp.example").unwrap().curl_text(),
        "corp.example"
    );
}

#[test]
fn standard_error_is_read_a_line_at_a_time_and_verbose_lines_are_dropped() {
    let mut plain = StderrSink::new(false);
    plain.push(
        b"curl: (60) SSL certificate problem: unable to get local issuer certificate\nMore details",
    );
    plain.push(b" here\n\npam-net http_connect=000 http_code=000 ssl_verify=20 num_connects=1\n");
    let seen = plain.finish();
    assert_eq!(
        seen,
        Seen {
            text: "curl: (60) SSL certificate problem: unable to get local issuer certificate\nMore details here\n".to_owned(),
            diagnostics: Diagnostics { ssl_verify: Some(20), num_connects: Some(1), ..Diagnostics::default() },
            issuer: None,
            subject: None,
            offered: vec![],
        }
    );

    let mut verbose = StderrSink::new(true);
    verbose.push(b"* Host localhost:18443 was resolved.\r\n> CONNECT origin.pam-test.invalid:443 HTTP/1.1\r\n> Proxy-Authorization: Basic c3ZjOnNlY3JldA==\r\n< HTTP/1.1 407 Proxy Authentication Required\r\n< Proxy-Authenticate: Basic realm=\"pam-test\"\r\n< Proxy-Authenticate: NTLM\r\n< proxy-authenticate: Basic realm=\"again\"\r\n");
    verbose.push(b"* Server certificate:\n*  subject: O=Corp; CN=jenkins.corp.example\n*  issuer: O=Corp; CN=Corp Inspection CA\n*  SSL certificate verify ok.\n");
    verbose.push(b"curl: (56) CONNECT tunnel failed, response 407\npam-net http_connect=407 http_code=000 ssl_verify=0 num_connects=1\n");
    let seen = verbose.finish();
    assert_eq!(
        seen.text,
        "curl: (56) CONNECT tunnel failed, response 407\n"
    );
    assert_eq!(seen.diagnostics.http_connect, Some(407));
    assert_eq!(
        seen.issuer.as_deref(),
        Some("O=Corp; CN=Corp Inspection CA")
    );
    assert_eq!(
        seen.subject.as_deref(),
        Some("O=Corp; CN=jenkins.corp.example")
    );
    assert_eq!(seen.offered, vec!["Basic".to_owned(), "NTLM".to_owned()]);
    let shown = format!("{seen:?}");
    assert!(!shown.contains("c3ZjOnNlY3JldA=="), "{shown}");
    assert!(!shown.contains("Proxy-Authorization"), "{shown}");

    // A line longer than the limit is cut, and the text cap holds.
    let mut flood = StderrSink::new(false);
    flood.push(&[b'x'; 10_000]);
    flood.push(b"\n");
    for _ in 0..10 {
        flood.push(&[b'y'; 1000]);
        flood.push(b"\n");
    }
    let seen = flood.finish();
    assert!(seen.text.len() <= 4 * 1024, "{}", seen.text.len());
    assert!(seen.text.starts_with(&"x".repeat(2048)));
}
