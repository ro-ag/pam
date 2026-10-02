//! Real `curl` against a TLS origin with a private test CA.
//!
//! The origin is `openssl s_server` presenting one of the committed leaves
//! under `tests/fixtures/`. What is proved: the CA bundle setting is what
//! makes a private issuer trusted; without it, or with another CA, the
//! request fails as `tls_untrusted_issuer`; a wrong name and an expired
//! leaf are told apart from that; a missing bundle file is named as such;
//! and the same works through the fake proxy, as a `CONNECT` to port 443.
//!
//! Skipped with a printed line when no `openssl` is available, unless
//! `PAM_REQUIRE_TLS_FIXTURE=1`.

use std::path::PathBuf;
use std::time::Duration;

use pam_net::testing::{
    FakeProxy, ProxyMode, TEST_HOST, TlsCert, TlsOrigin, test_ca, trusted_curl_or_skip,
    unrelated_ca,
};
use pam_net::{NetFailure, NetSettings, Proxy, ProxyAuth, Route, TlsBackend, Url};

const LIMIT: Duration = Duration::from_secs(20);

fn trusting(bundle: Option<PathBuf>) -> NetSettings {
    NetSettings::new(None, None, Vec::new(), bundle).expect("the settings")
}

async fn origin(cert: TlsCert) -> Option<TlsOrigin> {
    let started = TlsOrigin::start(cert).await;
    if started.is_none() {
        eprintln!("no openssl for the TLS origin; skipping");
    }
    started
}

#[tokio::test]
async fn the_bundle_makes_the_private_issuer_trusted() {
    let Some(curl) = trusted_curl_or_skip() else {
        return;
    };
    let Some(server) = origin(TlsCert::Valid).await else {
        return;
    };
    let settings = trusting(Some(test_ca()));

    // Production mode: https, no test allowance.
    let output = curl
        .request(&settings, &server.local_url())
        .include_headers()
        .max_time(10)
        .run(LIMIT)
        .await
        .expect("the bundle trusts the test CA");

    assert!(
        output.stdout.starts_with(b"HTTP/1.0 200"),
        "{:?}",
        output.stdout
    );
    assert_eq!(output.http_code, Some(200));
    assert_eq!(output.route, Route::Direct);
}

#[tokio::test]
async fn without_the_bundle_the_issuer_is_untrusted() {
    let Some(curl) = trusted_curl_or_skip() else {
        return;
    };
    let Some(server) = origin(TlsCert::Valid).await else {
        return;
    };
    for bundle in [None, Some(unrelated_ca())] {
        let settings = trusting(bundle.clone());
        let failure = curl
            .request(&settings, &server.local_url())
            .max_time(10)
            .run(LIMIT)
            .await
            .expect_err("a private CA is not trusted by default");
        let NetFailure::TlsUntrustedIssuer {
            host,
            issuer,
            backend,
        } = &failure
        else {
            panic!("{bundle:?}: {failure:?}");
        };
        assert_eq!(host, "localhost");
        assert_eq!(backend, &curl.info().backend.to_string());
        // Recorded fact: the LibreSSL backend fails before it prints the
        // peer certificate, so the issuer cannot be named there.
        if curl.info().backend == TlsBackend::LibreSsl {
            assert_eq!(issuer, &None);
            assert!(
                failure.sentence().contains("could not be read"),
                "{failure}"
            );
        }
        assert_eq!(failure.cause(), "tls_untrusted_issuer");
        assert!(failure.recovery().contains("Settings › Network"));
    }
}

#[tokio::test]
async fn a_wrong_name_and_an_expired_leaf_are_named() {
    let Some(curl) = trusted_curl_or_skip() else {
        return;
    };
    let settings = trusting(Some(test_ca()));

    let Some(server) = origin(TlsCert::WrongName).await else {
        return;
    };
    let failure = curl
        .request(&settings, &server.local_url())
        .max_time(10)
        .run(LIMIT)
        .await
        .expect_err("the leaf is for another name");
    assert_eq!(
        failure,
        NetFailure::TlsHostnameMismatch {
            host: "localhost".to_owned()
        }
    );
    drop(server);

    let Some(server) = origin(TlsCert::Expired).await else {
        return;
    };
    let failure = curl
        .request(&settings, &server.local_url())
        .max_time(10)
        .run(LIMIT)
        .await
        .expect_err("the leaf expired in 2020");
    assert_eq!(
        failure,
        NetFailure::TlsExpired {
            host: "localhost".to_owned()
        }
    );
}

#[tokio::test]
async fn a_bundle_curl_cannot_read_is_named() {
    let Some(curl) = trusted_curl_or_skip() else {
        return;
    };
    let Some(server) = origin(TlsCert::Valid).await else {
        return;
    };
    let scratch = tempfile::tempdir().expect("a temp directory");
    let absent = scratch.path().join("absent.pem");
    let garbage = scratch.path().join("garbage.pem");
    std::fs::write(&garbage, "not a certificate\n").unwrap();

    for bundle in [absent, garbage] {
        let settings = trusting(Some(bundle.clone()));
        let failure = curl
            .request(&settings, &server.local_url())
            .max_time(10)
            .run(LIMIT)
            .await
            .expect_err("the bundle cannot be read");
        assert_eq!(
            failure,
            NetFailure::CaBundleUnreadable,
            "{}",
            bundle.display()
        );
    }
}

#[tokio::test]
async fn tls_through_the_proxy_is_a_connect_to_443() {
    let Some(curl) = trusted_curl_or_skip() else {
        return;
    };
    let Some(server) = origin(TlsCert::Valid).await else {
        return;
    };
    let proxy = FakeProxy::start(ProxyMode::Allow, server.address()).await;
    let via = Proxy::parse(&proxy.url(), ProxyAuth::None, None).unwrap();
    let settings = NetSettings::new(Some(via), None, Vec::new(), Some(test_ca())).unwrap();
    let url = Url::parse(&format!("https://{TEST_HOST}/")).unwrap();

    let output = curl
        .request(&settings, &url)
        .diagnostic()
        .max_time(10)
        .run(LIMIT)
        .await
        .expect("the proxy tunnels to the TLS origin");

    assert_eq!(output.http_code, Some(200));
    assert_eq!(output.http_connect, Some(200));
    assert_eq!(
        proxy.request_lines(),
        vec![format!("CONNECT {TEST_HOST}:443 HTTP/1.1")]
    );
    // Diagnostic mode reads the peer certificate from the verbose trace
    // once verification succeeded.
    if curl.info().backend == TlsBackend::LibreSsl {
        assert!(
            output
                .issuer
                .as_deref()
                .is_some_and(|issuer| issuer.contains("PAM Test Inspection CA")),
            "{:?}",
            output.issuer
        );
        assert!(
            output
                .subject
                .as_deref()
                .is_some_and(|subject| subject.contains(TEST_HOST)),
            "{:?}",
            output.subject
        );
    }

    // Without the bundle the tunnel is made and the handshake fails inside it.
    let settings = NetSettings::new(
        Some(Proxy::parse(&proxy.url(), ProxyAuth::None, None).unwrap()),
        None,
        Vec::new(),
        None,
    )
    .unwrap();
    let failure = curl
        .request(&settings, &url)
        .max_time(10)
        .run(LIMIT)
        .await
        .expect_err("the private CA is untrusted inside the tunnel");
    assert_eq!(failure.cause(), "tls_untrusted_issuer");
    assert!(failure.sentence().contains(TEST_HOST), "{failure}");
}

#[tokio::test]
async fn a_listener_that_speaks_no_tls_is_a_tls_failure() {
    let Some(curl) = trusted_curl_or_skip() else {
        return;
    };
    // A listener that accepts and hangs up: no handshake can happen.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let hangup = tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            drop(stream);
        }
    });
    let settings = trusting(Some(test_ca()));
    let url = Url::parse(&format!("https://{address}/")).unwrap();

    let failure = curl
        .request(&settings, &url)
        .max_time(10)
        .run(LIMIT)
        .await
        .expect_err("no handshake, no answer");
    hangup.abort();
    // Recorded fact: exit 35 with the verify result at its "unspecified" 1,
    // so this is the generic TLS failure, not a named certificate problem.
    assert_eq!(failure.cause(), "tls_error", "{failure:?}");
    assert!(matches!(failure, NetFailure::TlsFailed { ref host, .. } if host == "127.0.0.1"));
}
