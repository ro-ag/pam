//! Real `curl` through the launcher, against loopback fixtures.
//!
//! The unit tests prove what the launcher writes; these prove what the
//! operating system's curl does with it: which listener a request reaches,
//! what arrives on the wire, and which [`NetFailure`] each way of failing
//! becomes. Nothing here leaves the machine: names under `.invalid` never
//! resolve, so a request for one succeeds only when the fake proxy carried
//! it.
//!
//! Every test returns early, with a printed line, when there is no trusted
//! operating-system curl.

use std::time::{Duration, Instant};

use pam_net::testing::{
    FakeProxy, Origin, OriginMode, ProxyMode, TEST_HOST, base64, trusted_curl_or_skip,
};
use pam_net::{
    Method, NetFailure, NetSettings, NoProxyRule, Proxy, ProxyAuth, ProxyPassword, Route, Url,
    parse_no_proxy,
};

const USER: &str = "svc-pam";
const PASSWORD: &str = "p@ss \"word\\ with:colon";

/// Settings that send everything through `proxy`.
fn through(proxy: &FakeProxy, rules: &[&str]) -> NetSettings {
    let proxy = Proxy::parse(&proxy.url(), ProxyAuth::None, None).expect("the proxy URL");
    NetSettings::new(Some(proxy), None, rules_of(rules), None).expect("the settings")
}

/// Settings that send everything through `proxy` with a credential.
fn through_with(proxy: &FakeProxy, auth: ProxyAuth, password: Option<&str>) -> NetSettings {
    let proxy = Proxy::parse(&proxy.url(), auth, Some(USER)).expect("the proxy URL");
    let password = password.map(|value| ProxyPassword::new(value).expect("the password"));
    NetSettings::new(Some(proxy), password, Vec::new(), None).expect("the settings")
}

fn rules_of(rules: &[&str]) -> Vec<NoProxyRule> {
    parse_no_proxy(rules).expect("the no-proxy list")
}

/// `http://origin.pam-test.invalid<path>`: reachable only through the proxy.
fn far(path: &str) -> Url {
    Url::parse(&format!("http://{TEST_HOST}{path}")).expect("the test URL")
}

const LIMIT: Duration = Duration::from_secs(20);

#[tokio::test]
async fn a_direct_request_arrives_with_its_headers() {
    let Some(curl) = trusted_curl_or_skip() else {
        return;
    };
    let origin = Origin::start(OriginMode::Json).await;
    let settings = NetSettings::direct();

    let output = curl
        .request(&settings, &origin.url("/probe?a={1,2}&b=[1-3]"))
        .allow_http_for_tests()
        .header("Authorization", "Bearer wire-token")
        .header("X-Odd", "quote\" backslash\\ end")
        .header("X-Empty", "")
        .include_headers()
        .max_time(10)
        .run(LIMIT)
        .await
        .expect("the origin answers");

    let text = String::from_utf8_lossy(&output.stdout);
    assert!(text.starts_with("HTTP/1.1 200 OK\r\n"), "{text}");
    assert!(text.ends_with("{\"ok\":true}"), "{text}");
    assert_eq!(output.http_code, Some(200));
    assert_eq!(output.http_connect, None);
    assert_eq!(output.route, Route::Direct);

    let requests = origin.requests();
    assert_eq!(
        requests.len(),
        1,
        "globbing made several requests: {requests:?}"
    );
    let wire = &requests[0];
    // The braces and brackets are one address, not a pattern.
    assert!(
        wire.starts_with("GET /probe?a={1,2}&b=[1-3] HTTP/1.1"),
        "{wire}"
    );
    assert!(
        wire.contains("Authorization: Bearer wire-token\r\n"),
        "{wire}"
    );
    assert!(
        wire.contains("X-Odd: quote\" backslash\\ end\r\n"),
        "{wire}"
    );
    assert!(wire.contains("X-Empty:\r\n"), "{wire}");
}

#[tokio::test]
async fn a_hostile_body_arrives_byte_for_byte() {
    let Some(curl) = trusted_curl_or_skip() else {
        return;
    };
    for method in [Method::Post, Method::Put] {
        let origin = Origin::start(OriginMode::Json).await;
        let settings = NetSettings::direct();
        // A leading `@` would be "read this file" to curl's plain `data`.
        let body = "@/etc/passwd\n{\"title\":\"quote\\\" and slash\\\\\"}\r\n\ttab\nurl = \"http://evil.invalid/\"\n";

        curl.request(&settings, &origin.url("/mutation"))
            .allow_http_for_tests()
            .method(method)
            .header("Content-Type", "application/json")
            .body(body.as_bytes())
            .max_time(10)
            .run(LIMIT)
            .await
            .expect("the origin answers");

        let requests = origin.requests();
        assert_eq!(requests.len(), 1);
        let verb = if method == Method::Post {
            "POST"
        } else {
            "PUT"
        };
        assert!(requests[0].starts_with(&format!("{verb} /mutation HTTP/1.1")));
        assert!(requests[0].ends_with(body), "{:?}", requests[0]);
    }
}

#[tokio::test]
async fn a_proxied_request_is_a_connect_tunnel_and_its_banner_is_not_the_response() {
    let Some(curl) = trusted_curl_or_skip() else {
        return;
    };
    let origin = Origin::start(OriginMode::Json).await;
    let proxy = FakeProxy::start(ProxyMode::Allow, origin.address()).await;
    let settings = through(&proxy, &[]);

    let output = curl
        .request(&settings, &far("/through"))
        .allow_http_for_tests()
        .header("Authorization", "Bearer for-the-origin-only")
        .include_headers()
        .max_time(10)
        .run(LIMIT)
        .await
        .expect("the proxy carries the request");

    let text = String::from_utf8_lossy(&output.stdout);
    // The proxy answered the CONNECT with its own 200 block; the response
    // the caller parses starts with the origin's.
    assert!(text.starts_with("HTTP/1.1 200 OK\r\n"), "{text}");
    assert!(!text.contains("Connection established"), "{text}");
    assert_eq!(text.matches("HTTP/1.1").count(), 1, "{text}");
    assert_eq!(output.http_connect, Some(200));
    assert_eq!(output.http_code, Some(200));
    assert!(matches!(output.route, Route::Proxy { .. }));

    assert_eq!(
        proxy.request_lines(),
        vec![format!("CONNECT {TEST_HOST}:80 HTTP/1.1")]
    );
    assert!(proxy.authorizations().is_empty());
    // The origin's credential travelled inside the tunnel, to the origin.
    assert!(origin.requests()[0].contains("Authorization: Bearer for-the-origin-only"));
}

/// The route preview and real curl must agree, entry by entry: a target
/// the preview sends through the proxy reaches it exactly once, and one it
/// calls a bypass never does (a `.invalid` name then fails DNS, a loopback
/// target reaches its origin, a blackholed address times out).
#[tokio::test]
#[allow(clippy::too_many_lines)] // One corpus, one loop: splitting it hides what is compared.
async fn the_route_preview_matches_what_curl_does() {
    let Some(curl) = trusted_curl_or_skip() else {
        return;
    };
    let origin = Origin::start(OriginMode::Json).await;
    let local = origin.url("/local").to_string();
    let cidr = curl.info().supports_cidr_no_proxy();
    let mut corpus: Vec<(&str, Vec<&str>, &str)> = vec![
        ("http://origin.pam-test.invalid/", vec![], "proxy"),
        (
            "http://origin.pam-test.invalid/",
            vec!["pam-test.invalid"],
            "bypass",
        ),
        (
            "http://origin.pam-test.invalid/",
            vec![".pam-test.invalid"],
            "bypass",
        ),
        (
            "http://origin.pam-test.invalid/",
            vec!["origin.pam-test.invalid"],
            "bypass",
        ),
        (
            "http://origin.pam-test.invalid/",
            vec!["ORIGIN.PAM-TEST.INVALID"],
            "bypass",
        ),
        (
            "http://origin.pam-test.invalid/",
            vec!["other.invalid", "example.com"],
            "proxy",
        ),
        // A suffix that is not on a label boundary is a different domain.
        (
            "http://origin.pam-test.invalid/",
            vec!["test.invalid"],
            "proxy",
        ),
        (
            "http://origin.pam-test.invalid/",
            vec!["rigin.pam-test.invalid"],
            "proxy",
        ),
        ("http://origin.pam-test.invalid/", vec!["*"], "bypass"),
        (
            "http://origin.pam-test.invalid/",
            vec!["192.0.2.7"],
            "proxy",
        ),
        ("http://192.0.2.7/", vec![], "proxy"),
        ("http://192.0.2.7/", vec!["192.0.2.7"], "bypass"),
        ("http://192.0.2.7/", vec!["192.0.2.8"], "proxy"),
        (local.as_str(), vec![], "bypass"),
        (local.as_str(), vec!["example.com"], "bypass"),
    ];
    if cidr {
        // A name is never resolved to be compared with a range.
        corpus.push((
            "http://origin.pam-test.invalid/",
            vec!["10.0.0.0/8"],
            "proxy",
        ));
        corpus.push(("http://192.0.2.7/", vec!["192.0.2.0/24"], "bypass"));
        corpus.push(("http://192.0.2.7/", vec!["192.0.3.0/24"], "proxy"));
    }

    for (target, rules, expected) in corpus {
        let proxy = FakeProxy::start(ProxyMode::Allow, origin.address()).await;
        let settings = through(&proxy, &rules);
        let url = Url::parse(target).expect("the corpus URL");
        let preview = settings.route_for(&url);
        assert_eq!(preview.as_str(), expected, "{target} with {rules:?}");

        let result = curl
            .request(&settings, &url)
            .allow_http_for_tests()
            .connect_timeout(1)
            .max_time(10)
            .run(LIMIT)
            .await;
        let reached_proxy = proxy.request_lines().len();
        if expected == "proxy" {
            assert!(result.is_ok(), "{target} with {rules:?}: {result:?}");
            assert_eq!(reached_proxy, 1, "{target} with {rules:?}");
            continue;
        }
        assert_eq!(
            reached_proxy, 0,
            "{target} with {rules:?} reached the proxy"
        );
        if target == local {
            assert!(result.is_ok(), "{target}: {result:?}");
        } else if target.contains("192.0.2.7") {
            // TEST-NET-1 is unrouted: the direct attempt cannot connect,
            // and says so one way or the other.
            let failure = result.expect_err("an unrouted address cannot answer");
            assert!(
                matches!(
                    failure,
                    NetFailure::ConnectTimeout { .. } | NetFailure::ConnectFailed { .. }
                ),
                "{failure:?}"
            );
        } else {
            assert_eq!(
                result.expect_err("a .invalid name cannot resolve"),
                NetFailure::DnsFailed {
                    host: TEST_HOST.to_owned()
                },
                "{target} with {rules:?}"
            );
        }
    }
}

#[tokio::test]
async fn a_loopback_target_bypasses_the_proxy_but_its_redirect_does_not() {
    let Some(curl) = trusted_curl_or_skip() else {
        return;
    };
    let far_origin = Origin::start(OriginMode::Json).await;
    let near_origin = Origin::start(OriginMode::Redirect(far("/next").to_string())).await;
    let proxy = FakeProxy::start(ProxyMode::Allow, far_origin.address()).await;
    let settings = through(&proxy, &[]);

    let output = curl
        .request(&settings, &near_origin.url("/start"))
        .allow_http_for_tests()
        .follow_https_redirects(3)
        .max_time(10)
        .run(LIMIT)
        .await
        .expect("both hops answer");

    assert_eq!(output.stdout, b"{\"ok\":true}");
    assert_eq!(output.route, Route::Bypass);
    // First hop: straight to the loopback origin. Second hop: an outside
    // name, so through the proxy — the bypass did not switch the proxy off.
    assert!(near_origin.requests()[0].starts_with("GET /start HTTP/1.1"));
    assert_eq!(
        proxy.request_lines(),
        vec![format!("CONNECT {TEST_HOST}:80 HTTP/1.1")]
    );
    assert!(far_origin.requests()[0].starts_with("GET /next HTTP/1.1"));
}

#[tokio::test]
async fn a_proxy_credential_reaches_the_proxy_and_only_the_proxy() {
    let Some(curl) = trusted_curl_or_skip() else {
        return;
    };
    let expected = format!("Basic {}", base64(format!("{USER}:{PASSWORD}").as_bytes()));
    for auth in [ProxyAuth::Basic, ProxyAuth::AnyAuth] {
        let origin = Origin::start(OriginMode::Json).await;
        let proxy = FakeProxy::start(
            ProxyMode::RequireAuth {
                username: USER.to_owned(),
                password: PASSWORD.to_owned(),
                offer: vec!["Basic realm=\"pam-test\"".to_owned()],
            },
            origin.address(),
        )
        .await;
        let settings = through_with(&proxy, auth, Some(PASSWORD));

        let output = curl
            .request(&settings, &far("/authed"))
            .allow_http_for_tests()
            .max_time(10)
            .run(LIMIT)
            .await
            .unwrap_or_else(|failure| panic!("{auth:?}: {failure:?}"));

        assert_eq!(output.stdout, b"{\"ok\":true}", "{auth:?}");
        assert_eq!(output.http_connect, Some(200), "{auth:?}");
        let seen = proxy.authorizations();
        assert_eq!(seen.last(), Some(&expected), "{auth:?}: {seen:?}");
        // Basic is sent with the first CONNECT; anyauth waits for the
        // challenge, so the proxy sees one request more.
        let connects = proxy.request_lines().len();
        match auth {
            ProxyAuth::Basic => assert_eq!(connects, 1),
            _ => assert_eq!(connects, 2),
        }
        // The origin never sees the proxy's credential.
        let wire = &origin.requests()[0];
        assert!(
            !wire.to_ascii_lowercase().contains("proxy-authorization"),
            "{wire}"
        );
    }
}

#[tokio::test]
async fn a_407_is_named_by_whether_a_credential_was_sent() {
    let Some(curl) = trusted_curl_or_skip() else {
        return;
    };
    let origin = Origin::start(OriginMode::Json).await;
    let mode = ProxyMode::RequireAuth {
        username: USER.to_owned(),
        password: PASSWORD.to_owned(),
        offer: vec!["Basic realm=\"pam-test\"".to_owned(), "NTLM".to_owned()],
    };

    // No credential configured: the proxy wants one.
    let proxy = FakeProxy::start(mode.clone(), origin.address()).await;
    let settings = through(&proxy, &[]);
    let failure = curl
        .request(&settings, &far("/"))
        .allow_http_for_tests()
        .max_time(10)
        .run(LIMIT)
        .await
        .expect_err("the proxy refuses");
    let authority = proxy.address().to_string();
    assert_eq!(
        failure,
        NetFailure::ProxyAuthRequired {
            proxy: authority.clone(),
            offered: Vec::new()
        }
    );
    assert_eq!(failure.cause(), "proxy_auth_required");

    // The same in diagnostic mode names what the proxy offers.
    let failure = curl
        .request(&settings, &far("/"))
        .allow_http_for_tests()
        .diagnostic()
        .max_time(10)
        .run(LIMIT)
        .await
        .expect_err("the proxy refuses");
    assert_eq!(
        failure,
        NetFailure::ProxyAuthRequired {
            proxy: authority.clone(),
            offered: vec!["Basic".to_owned(), "NTLM".to_owned()]
        }
    );
    assert!(failure.sentence().contains("It offers: Basic, NTLM."));

    // A sign-in mode with no stored password sends nothing either.
    let settings = through_with(&proxy, ProxyAuth::Basic, None);
    let failure = curl
        .request(&settings, &far("/"))
        .allow_http_for_tests()
        .max_time(10)
        .run(LIMIT)
        .await
        .expect_err("the proxy refuses");
    assert_eq!(failure.cause(), "proxy_auth_required");

    // A wrong password: the credential was sent and refused.
    let proxy = FakeProxy::start(mode, origin.address()).await;
    let settings = through_with(&proxy, ProxyAuth::Basic, Some("wrong-secret-value"));
    let failure = curl
        .request(&settings, &far("/"))
        .allow_http_for_tests()
        .diagnostic()
        .max_time(10)
        .run(LIMIT)
        .await
        .expect_err("the proxy refuses");
    assert_eq!(
        failure,
        NetFailure::ProxyAuthRejected {
            proxy: proxy.address().to_string()
        }
    );
    // Diagnostic mode ran curl's verbose trace, which prints the
    // Proxy-Authorization line; none of it survives into the failure.
    let shown = format!("{failure:?} {} {}", failure.sentence(), failure.recovery());
    assert!(!shown.contains("wrong-secret-value"), "{shown}");
    assert!(
        !shown.contains(&base64(format!("{USER}:wrong-secret-value").as_bytes())),
        "{shown}"
    );
    assert!(
        origin.requests().is_empty(),
        "a refused tunnel reached the origin"
    );
}

#[tokio::test]
async fn a_refusing_proxy_is_named_with_its_status() {
    let Some(curl) = trusted_curl_or_skip() else {
        return;
    };
    let origin = Origin::start(OriginMode::Json).await;
    let proxy = FakeProxy::start(ProxyMode::Deny(403), origin.address()).await;
    let settings = through(&proxy, &[]);
    let failure = curl
        .request(&settings, &far("/"))
        .allow_http_for_tests()
        .max_time(10)
        .run(LIMIT)
        .await
        .expect_err("the proxy refuses");
    assert_eq!(
        failure,
        NetFailure::ProxyDenied {
            proxy: proxy.address().to_string(),
            target: format!("{TEST_HOST}:80"),
            status: 403
        }
    );

    // An allowing proxy whose upstream is gone answers 502.
    let closed = closed_port().await;
    let proxy = FakeProxy::start(ProxyMode::Allow, closed).await;
    let settings = through(&proxy, &[]);
    let failure = curl
        .request(&settings, &far("/"))
        .allow_http_for_tests()
        .max_time(10)
        .run(LIMIT)
        .await
        .expect_err("the proxy cannot reach the origin");
    assert_eq!(failure.cause(), "proxy_denied");
    assert!(failure.sentence().contains("(HTTP 502)"), "{failure}");
}

#[tokio::test]
async fn an_unreachable_proxy_and_an_unresolvable_one_are_told_apart() {
    let Some(curl) = trusted_curl_or_skip() else {
        return;
    };
    let closed = closed_port().await;
    let proxy = Proxy::parse(&format!("http://{closed}"), ProxyAuth::None, None).unwrap();
    let settings = NetSettings::new(Some(proxy), None, Vec::new(), None).unwrap();
    let failure = curl
        .request(&settings, &far("/"))
        .allow_http_for_tests()
        .max_time(10)
        .run(LIMIT)
        .await
        .expect_err("nothing listens there");
    assert_eq!(
        failure,
        NetFailure::ProxyUnreachable {
            proxy: closed.to_string()
        }
    );

    let proxy = Proxy::parse("http://proxy.pam-test.invalid:3128", ProxyAuth::None, None).unwrap();
    let settings = NetSettings::new(Some(proxy), None, Vec::new(), None).unwrap();
    let failure = curl
        .request(&settings, &far("/"))
        .allow_http_for_tests()
        .max_time(10)
        .run(LIMIT)
        .await
        .expect_err("the proxy name does not resolve");
    assert_eq!(
        failure,
        NetFailure::ProxyDnsFailed {
            proxy: "proxy.pam-test.invalid:3128".to_owned()
        }
    );
}

#[tokio::test]
async fn direct_failures_are_named() {
    let Some(curl) = trusted_curl_or_skip() else {
        return;
    };
    let settings = NetSettings::direct();

    let closed = closed_port().await;
    let url = Url::parse(&format!("http://{closed}/gone")).unwrap();
    let failure = curl
        .request(&settings, &url)
        .allow_http_for_tests()
        .max_time(10)
        .run(LIMIT)
        .await
        .expect_err("a closed port cannot answer");
    assert_eq!(
        failure,
        NetFailure::ConnectFailed {
            host: "127.0.0.1".to_owned()
        }
    );

    let failure = curl
        .request(&settings, &far("/"))
        .allow_http_for_tests()
        .max_time(10)
        .run(LIMIT)
        .await
        .expect_err("a .invalid name cannot resolve");
    assert_eq!(
        failure,
        NetFailure::DnsFailed {
            host: TEST_HOST.to_owned()
        }
    );

    let origin = Origin::start(OriginMode::Status(404)).await;
    let failure = curl
        .request(&settings, &origin.url("/missing"))
        .allow_http_for_tests()
        .fail_on_http_error()
        .max_time(10)
        .run(LIMIT)
        .await
        .expect_err("a 404 is a failure when asked to be");
    assert_eq!(failure, NetFailure::HttpStatus { status: Some(404) });
    // Without the flag the same answer is an answer.
    let output = curl
        .request(&settings, &origin.url("/missing"))
        .allow_http_for_tests()
        .max_time(10)
        .run(LIMIT)
        .await
        .expect("a status is an answer");
    assert_eq!(output.http_code, Some(404));
}

#[tokio::test]
async fn a_stalled_origin_ends_at_curls_limit_or_at_the_hard_deadline() {
    let Some(curl) = trusted_curl_or_skip() else {
        return;
    };
    let origin = Origin::start(OriginMode::Stall).await;
    let settings = NetSettings::direct();

    // curl's own limit: a clean exit 28.
    let failure = curl
        .request(&settings, &origin.url("/slow"))
        .allow_http_for_tests()
        .max_time(1)
        .run(LIMIT)
        .await
        .expect_err("a stalled origin times out");
    assert_eq!(failure, NetFailure::Timeout);

    // No limit of curl's own: the hard deadline kills the process.
    let started = Instant::now();
    let mut child = curl
        .request(&settings, &origin.url("/slow"))
        .allow_http_for_tests()
        .spawn()
        .await
        .expect("curl starts");
    let pid = child.id().expect("a running child has an id");
    let failure = child
        .wait_within(Duration::from_millis(700))
        .await
        .expect_err("the deadline passes");
    assert_eq!(failure, NetFailure::Deadline);
    assert!(started.elapsed() < Duration::from_secs(10));
    // Killed and reaped: the process id is gone from the child.
    assert_eq!(child.id(), None, "curl {pid} is still running");
}

#[tokio::test]
async fn an_oversized_answer_is_bounded() {
    let Some(curl) = trusted_curl_or_skip() else {
        return;
    };
    let origin = Origin::start(OriginMode::Body(vec![b'x'; 512 * 1024])).await;
    let settings = NetSettings::direct();

    // The capture limit holds whatever the server declares.
    let failure = curl
        .request(&settings, &origin.url("/big"))
        .allow_http_for_tests()
        .capture_limit(1024)
        .max_time(10)
        .run(LIMIT)
        .await
        .expect_err("the answer is over the limit");
    assert_eq!(failure, NetFailure::TooLarge { maximum: 1024 });

    // With a declared length curl refuses before reading the body.
    let failure = curl
        .request(&settings, &origin.url("/big"))
        .allow_http_for_tests()
        .max_filesize(64)
        .capture_limit(1024 * 1024)
        .max_time(10)
        .run(LIMIT)
        .await
        .expect_err("the declared length is over the limit");
    assert_eq!(failure, NetFailure::TooLarge { maximum: 64 });
}

#[tokio::test]
async fn a_download_goes_to_its_file_and_wait_survives_being_cancelled() {
    let Some(curl) = trusted_curl_or_skip() else {
        return;
    };
    let body: Vec<u8> = (0..300_000_u32).map(|n| (n % 251) as u8).collect();
    let origin = Origin::start(OriginMode::Body(body.clone())).await;
    let settings = NetSettings::direct();
    let scratch = tempfile::tempdir().expect("a temp directory");
    // A path with a space and a quote: one config value, not two arguments.
    // Windows file names cannot hold a quote; the space and the backslashes
    // of its paths still prove it.
    let part = scratch.path().join(if cfg!(windows) {
        "model part.bin"
    } else {
        "model \"part\".bin"
    });
    let etag = scratch.path().join("model.etag");

    let mut child = curl
        .request(&settings, &origin.url("/weights"))
        .allow_http_for_tests()
        .fail_on_http_error()
        .follow_https_redirects(5)
        .connect_timeout(5)
        .stall_limit(1, 30)
        .output(&part)
        .etag_save(&etag)
        .resume()
        .spawn()
        .await
        .expect("curl starts");
    // A caller selects `wait` against its cancel signal; losing that race
    // repeatedly must lose no output.
    let output = loop {
        tokio::select! {
            finished = child.wait() => break finished,
            () = tokio::time::sleep(Duration::from_millis(1)) => {}
        }
    }
    .expect("the download finishes");

    assert!(output.stdout.is_empty());
    assert_eq!(output.http_code, Some(200));
    assert_eq!(std::fs::read(&part).expect("the part file"), body);

    // The same through `stdout`, cancelled the same way.
    let mut child = curl
        .request(&settings, &origin.url("/weights"))
        .allow_http_for_tests()
        .capture_limit(1024 * 1024)
        .spawn()
        .await
        .expect("curl starts");
    let output = loop {
        tokio::select! {
            finished = child.wait() => break finished,
            () = tokio::time::sleep(Duration::from_millis(1)) => {}
        }
    }
    .expect("the transfer finishes");
    assert_eq!(output.stdout, body);
}

/// What the operating system reports as the child's arguments: the
/// constant, with the proxy password and the request's credential nowhere
/// in it.
#[cfg(target_os = "macos")]
#[tokio::test]
async fn the_process_table_shows_only_the_constant_arguments() {
    let Some(curl) = trusted_curl_or_skip() else {
        return;
    };
    let origin = Origin::start(OriginMode::Stall).await;
    let proxy = FakeProxy::start(ProxyMode::Allow, origin.address()).await;
    let settings = through_with(&proxy, ProxyAuth::Basic, Some(PASSWORD));

    let mut child = curl
        .request(&settings, &far("/held"))
        .allow_http_for_tests()
        .header("Authorization", "Bearer argv-must-not-show-this")
        .spawn()
        .await
        .expect("curl starts");
    let pid = child.id().expect("a running child has an id");
    let listed = std::process::Command::new("/bin/ps")
        .args(["-ww", "-o", "args=", "-p", &pid.to_string()])
        .output()
        .expect("ps runs");
    child.kill().await;

    let arguments = String::from_utf8_lossy(&listed.stdout);
    assert_eq!(
        arguments.trim(),
        format!("{} -q --config -", curl.path().display())
    );
}

/// The fixture's other half: an absolute-form request is forwarded to the
/// upstream in origin form, without the proxy's own headers.
#[tokio::test]
async fn the_fake_proxy_forwards_an_absolute_form_request() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let origin = Origin::start(OriginMode::Json).await;
    let proxy = FakeProxy::start(ProxyMode::Allow, origin.address()).await;

    let mut stream = tokio::net::TcpStream::connect(proxy.address())
        .await
        .expect("the proxy accepts");
    stream
        .write_all(
            format!(
                "GET http://{TEST_HOST}/plain?x=1 HTTP/1.1\r\nHost: {TEST_HOST}\r\nProxy-Connection: close\r\n\r\n"
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    let mut answer = Vec::new();
    stream.read_to_end(&mut answer).await.unwrap();

    assert!(String::from_utf8_lossy(&answer).ends_with("{\"ok\":true}"));
    let wire = &origin.requests()[0];
    assert!(wire.starts_with("GET /plain?x=1 HTTP/1.1\r\n"), "{wire}");
    assert!(
        !wire.to_ascii_lowercase().contains("proxy-connection"),
        "{wire}"
    );
}

/// A loopback address nothing listens on.
async fn closed_port() -> std::net::SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("a loopback port");
    listener.local_addr().expect("the bound address")
}
