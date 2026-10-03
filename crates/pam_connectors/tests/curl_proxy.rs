//! Real `curl` through a forward proxy, driven by the connector transport.
//!
//! `pam_net` proves what its launcher does with a proxy; this file proves
//! that the connector transport on top of it keeps its own contract there:
//! the origin's answer comes back whole (never the proxy's `CONNECT`
//! banner), the connector credential reaches the origin and not the proxy,
//! the proxy credential reaches the proxy and not the origin, the one
//! redirect hop is its own process through the same proxy, and a proxy
//! failure is reported as the launcher's cause — with the proxy password
//! absent from every refusal, however it is rendered.
//!
//! Targets are `origin.pam-test.invalid`, which never resolves; a request
//! for it succeeds only when the fake proxy carried it.
//!
//! The whole file is skipped, with a printed line, when the trusted OS
//! `curl` is unavailable.

use std::sync::Arc;
use std::time::{Duration, Instant};

use pam_connectors::{
    ConnectorError, CurlTransport, HttpRequest, HttpTransport, Method, NetFailure, NetSettings,
    TransportError,
};
use pam_net::testing::{FakeProxy, Origin, OriginMode, ProxyMode, TEST_HOST, base64};
use pam_net::{Proxy, ProxyAuth, ProxyPassword, parse_no_proxy};
use url::Url;

const USER: &str = "svc-pam";
const PASSWORD: &str = "pr0xy \"secret\\ with:colon";
const TOKEN: &str = "Bearer wire-token";

/// The transport, reading a fixed profile, or `None` when there is no curl.
fn transport(settings: NetSettings) -> Option<CurlTransport> {
    match CurlTransport::trusted(Arc::new(Arc::new(settings))) {
        Ok(transport) => Some(transport.allow_http_for_tests()),
        Err(error) => {
            eprintln!("no trusted operating-system curl ({error}); skipping");
            None
        }
    }
}

/// Everything through `proxy`, with or without a credential.
fn through(proxy: &FakeProxy, auth: ProxyAuth, password: Option<&str>) -> NetSettings {
    let username = (auth != ProxyAuth::None).then_some(USER);
    let proxy = Proxy::parse(&proxy.url(), auth, username).expect("the proxy URL");
    let password = password.map(|value| ProxyPassword::new(value).expect("the password"));
    NetSettings::new(Some(proxy), password, Vec::new(), None).expect("the settings")
}

/// One connector request for a name only the proxy can reach.
fn request(path: &str, follow: bool) -> HttpRequest {
    HttpRequest {
        method: Method::Get,
        body: None,
        url: Url::parse(&format!("http://{TEST_HOST}{path}")).expect("the test URL"),
        headers: vec![
            ("Authorization".to_owned(), TOKEN.to_owned()),
            ("Accept".to_owned(), "application/json".to_owned()),
        ],
        max_bytes: 64 * 1024,
        follow_one_https_redirect_without_auth: follow,
    }
}

fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(15)
}

#[tokio::test]
async fn a_connector_get_through_the_proxy_returns_the_origins_answer() {
    let origin = Origin::start(OriginMode::Json).await;
    let proxy = FakeProxy::start(ProxyMode::Allow, origin.address()).await;
    let Some(transport) = transport(through(&proxy, ProxyAuth::None, None)) else {
        return;
    };

    let response = transport
        .send(request("/probe", false), deadline())
        .await
        .expect("the origin answers through the proxy");

    // The proxy's `200 Connection established` is not what came back.
    assert_eq!(response.status, 200);
    assert_eq!(response.body, b"{\"ok\":true}");
    assert_eq!(response.header("content-type"), Some("application/json"));

    let lines = proxy.request_lines();
    assert_eq!(lines, vec![format!("CONNECT {TEST_HOST}:80 HTTP/1.1")]);
    assert!(
        proxy.authorizations().is_empty(),
        "no proxy credential was configured, none was sent"
    );
    let wire = origin.requests().join("\n");
    assert!(wire.starts_with("GET /probe HTTP/1.1"), "{wire}");
    assert!(
        wire.contains(&format!("Authorization: {TOKEN}")),
        "the connector credential reaches the origin: {wire}"
    );
    assert!(
        !wire.contains("Proxy-Authorization"),
        "nothing for the proxy reaches the origin: {wire}"
    );
}

#[tokio::test]
async fn the_proxy_credential_goes_to_the_proxy_and_the_token_to_the_origin() {
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
    let Some(transport) = transport(through(&proxy, ProxyAuth::Basic, Some(PASSWORD))) else {
        return;
    };

    let response = transport
        .send(request("/probe", false), deadline())
        .await
        .expect("the proxy accepts the credential");
    assert_eq!(response.status, 200);

    let expected = format!("Basic {}", base64(format!("{USER}:{PASSWORD}").as_bytes()));
    assert_eq!(proxy.authorizations(), vec![expected]);
    let wire = origin.requests().join("\n");
    assert!(wire.contains(&format!("Authorization: {TOKEN}")), "{wire}");
    assert!(!wire.contains("Proxy-Authorization"), "{wire}");
    assert!(
        !wire.contains(PASSWORD) && !wire.contains(USER),
        "the proxy credential never reaches the origin: {wire}"
    );
}

#[tokio::test]
async fn a_rejected_proxy_credential_is_named_without_the_password() {
    let origin = Origin::start(OriginMode::Json).await;
    let proxy = FakeProxy::start(
        ProxyMode::RequireAuth {
            username: USER.to_owned(),
            password: "something else".to_owned(),
            offer: vec!["Basic realm=\"pam-test\"".to_owned()],
        },
        origin.address(),
    )
    .await;
    let Some(transport) = transport(through(&proxy, ProxyAuth::Basic, Some(PASSWORD))) else {
        return;
    };

    let error = transport
        .send(request("/probe", false), deadline())
        .await
        .expect_err("the proxy refuses the credential");
    assert!(
        matches!(
            error,
            TransportError::Net(NetFailure::ProxyAuthRejected { .. })
        ),
        "{error:?}"
    );
    let connector = ConnectorError::from(error.clone());
    assert_eq!(connector.cause(), "connector_network");

    // Every rendering a human, a log or an evidence row could see.
    let encoded = base64(format!("{USER}:{PASSWORD}").as_bytes());
    for rendering in [
        format!("{error:?}"),
        error.to_string(),
        format!("{connector:?}"),
        connector.detail(),
        connector.recovery(pam_connectors::ConnectorId::Jenkins),
        format!("{transport:?}"),
    ] {
        assert!(!rendering.contains(PASSWORD), "{rendering}");
        assert!(!rendering.contains(&encoded), "{rendering}");
        assert!(!rendering.contains("secret"), "{rendering}");
    }
    assert!(
        connector.detail().contains(&proxy.address().to_string()),
        "the proxy is named: {}",
        connector.detail()
    );
    assert!(origin.requests().is_empty(), "nothing reached the origin");
}

#[tokio::test]
async fn a_proxy_that_wants_a_credential_nobody_configured_is_named() {
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
    let Some(transport) = transport(through(&proxy, ProxyAuth::None, None)) else {
        return;
    };

    let error = transport
        .send(request("/probe", false), deadline())
        .await
        .expect_err("the proxy wants a credential");
    assert!(
        matches!(
            error,
            TransportError::Net(NetFailure::ProxyAuthRequired { .. })
        ),
        "{error:?}"
    );
    assert_eq!(
        ConnectorError::from(error).cause(),
        "connector_network",
        "the existing refusal shape carries the launcher's sentence"
    );
}

#[tokio::test]
async fn the_one_redirect_hop_is_its_own_process_through_the_proxy_without_the_token() {
    let origin = Origin::start(OriginMode::Redirect(format!("http://{TEST_HOST}/signed"))).await;
    let proxy = FakeProxy::start(ProxyMode::Allow, origin.address()).await;
    let Some(transport) = transport(through(&proxy, ProxyAuth::None, None)) else {
        return;
    };

    // The origin redirects every request, so after the one permitted hop
    // the second answer, a redirect again, is what the caller receives.
    let response = transport
        .send(request("/log", true), deadline())
        .await
        .expect("the hop is answered");
    assert_eq!(response.status, 302);

    assert_eq!(
        proxy.request_lines(),
        vec![
            format!("CONNECT {TEST_HOST}:80 HTTP/1.1"),
            format!("CONNECT {TEST_HOST}:80 HTTP/1.1"),
        ],
        "each hop is a curl process of its own, and each goes through the proxy"
    );
    let requests = origin.requests();
    assert_eq!(requests.len(), 2, "{requests:?}");
    assert!(
        requests[0].starts_with("GET /log HTTP/1.1"),
        "{}",
        requests[0]
    );
    assert!(
        requests[0].contains(&format!("Authorization: {TOKEN}")),
        "{}",
        requests[0]
    );
    assert!(
        requests[1].starts_with("GET /signed HTTP/1.1"),
        "{}",
        requests[1]
    );
    assert!(
        !requests[1].contains("Authorization"),
        "the credential is dropped on the hop: {}",
        requests[1]
    );
}

#[tokio::test]
async fn a_no_proxy_entry_keeps_the_target_off_the_proxy() {
    let origin = Origin::start(OriginMode::Json).await;
    let proxy = FakeProxy::start(ProxyMode::Allow, origin.address()).await;
    let bypass = Proxy::parse(&proxy.url(), ProxyAuth::None, None).expect("the proxy URL");
    let rules = parse_no_proxy(&[TEST_HOST]).expect("the no-proxy list");
    let settings = NetSettings::new(Some(bypass), None, rules, None).expect("the settings");
    let Some(transport) = transport(settings) else {
        return;
    };

    // Bypassed, the name has to resolve on its own, and `.invalid` never
    // does: the failure is DNS, and the proxy saw nothing.
    let error = transport
        .send(request("/probe", false), deadline())
        .await
        .expect_err("a bypassed .invalid name cannot resolve");
    assert!(
        matches!(error, TransportError::Net(NetFailure::DnsFailed { ref host }) if host == TEST_HOST),
        "{error:?}"
    );
    assert!(proxy.request_lines().is_empty());
    assert!(origin.requests().is_empty());
}
