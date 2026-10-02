//! The daemon's environment has no say.
//!
//! The test re-runs itself as a child process whose environment carries
//! every proxy and certificate variable curl would otherwise read — a
//! decoy proxy that records whatever reaches it, the test CA as
//! `CURL_CA_BUNDLE`/`SSL_CERT_FILE`, and a `.curlrc` under `CURL_HOME` and
//! `HOME` that trusts it too and adds a header. Inside that process, a
//! request through the launcher must behave exactly as in a clean one: the
//! decoy sees nothing, the header is not sent, and the private test CA stays
//! untrusted until the settings say otherwise.

use std::time::Duration;

use pam_net::testing::{Origin, OriginMode, TlsCert, TlsOrigin, test_ca, trusted_curl_or_skip};
use pam_net::{NetFailure, NetSettings};

const MARKER: &str = "PAM_NET_HOSTILE_ENVIRONMENT";

#[tokio::test]
async fn proxy_and_certificate_variables_in_the_environment_have_no_effect() {
    let Some(_curl) = trusted_curl_or_skip() else {
        return;
    };
    if std::env::var_os(MARKER).is_some() {
        inside_the_hostile_environment().await;
        return;
    }

    // The decoy: a listener that must never see a connection.
    let decoy = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let decoy_address = decoy.local_addr().unwrap();
    let decoy_hits = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let hits = std::sync::Arc::clone(&decoy_hits);
    let watcher = tokio::spawn(async move {
        while decoy.accept().await.is_ok() {
            hits.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    });

    let home = tempfile::tempdir().unwrap();
    std::fs::write(
        home.path().join(".curlrc"),
        format!(
            "cacert = \"{}\"\nheader = \"X-From-Curlrc: leaked\"\nproxy = \"http://{decoy_address}\"\n",
            test_ca().display()
        ),
    )
    .unwrap();
    let decoy_url = format!("http://{decoy_address}");
    let ca = test_ca();
    let ca = ca.to_str().unwrap();

    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "proxy_and_certificate_variables_in_the_environment_have_no_effect",
            "--nocapture",
        ])
        .env(MARKER, "1")
        .env("HTTPS_PROXY", &decoy_url)
        .env("https_proxy", &decoy_url)
        .env("HTTP_PROXY", &decoy_url)
        .env("http_proxy", &decoy_url)
        .env("ALL_PROXY", &decoy_url)
        .env("all_proxy", &decoy_url)
        .env("NO_PROXY", "")
        .env("CURL_CA_BUNDLE", ca)
        .env("SSL_CERT_FILE", ca)
        .env("SSL_CERT_DIR", test_ca().parent().unwrap())
        .env("CURL_HOME", home.path())
        .env("HOME", home.path())
        .env("CURL_SSL_BACKEND", "openssl")
        .status()
        .expect("the test binary re-runs");
    watcher.abort();

    assert!(status.success(), "the re-run failed: {status}");
    assert_eq!(
        decoy_hits.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "a connection reached the decoy proxy named by the environment"
    );
}

/// Runs with the hostile environment set in this process.
async fn inside_the_hostile_environment() {
    assert!(std::env::var_os("HTTPS_PROXY").is_some());
    let curl = trusted_curl_or_skip().expect("the outer run found curl");
    let settings = NetSettings::direct();

    // The plain origin is reached directly, and the curlrc's header is not
    // on the wire.
    let origin = Origin::start(OriginMode::Json).await;
    let output = curl
        .request(&settings, &origin.url("/env"))
        .allow_http_for_tests()
        .max_time(10)
        .run(Duration::from_secs(20))
        .await
        .expect("the origin answers");
    assert_eq!(output.stdout, b"{\"ok\":true}");
    let wire = &origin.requests()[0];
    assert!(!wire.contains("X-From-Curlrc"), "{wire}");

    // The private CA named by the environment is still not trusted …
    let Some(server) = TlsOrigin::start(TlsCert::Valid).await else {
        eprintln!("no openssl for the TLS origin; skipping the certificate half");
        return;
    };
    let failure = curl
        .request(&settings, &server.local_url())
        .max_time(10)
        .run(Duration::from_secs(20))
        .await
        .expect_err("an environment variable cannot add trust");
    assert_eq!(failure.cause(), "tls_untrusted_issuer", "{failure:?}");
    assert!(!matches!(failure, NetFailure::CaBundleUnreadable));

    // … until the settings say so.
    let settings = NetSettings::new(None, None, Vec::new(), Some(test_ca())).unwrap();
    curl.request(&settings, &server.local_url())
        .max_time(10)
        .run(Duration::from_secs(20))
        .await
        .expect("the settings trust the test CA");
}
