use crate::failure::{Diagnostics, NetFailure, Transfer, classify, excerpt};
use crate::settings::Route;
use crate::trusted::TlsBackend;

/// A transfer as the launcher reports it, with the recorded macOS curl
/// 8.7.1 outputs as defaults.
fn transfer<'a>(exit: Option<i32>, stderr: &'a str, line: &str, route: &'a Route) -> Transfer<'a> {
    Transfer {
        exit,
        stderr,
        diagnostics: Diagnostics::parse(line),
        route,
        target_host: "jenkins.corp.example",
        target_port: 443,
        credential_sent: false,
        cacert_set: false,
        backend: &TlsBackend::LibreSsl,
        max_filesize: Some(1024),
        offered: &[],
        issuer: None,
    }
}

fn proxied() -> Route {
    Route::Proxy {
        host: "proxy.corp.example".to_owned(),
        port: 3128,
    }
}

#[test]
fn the_diagnostics_line_is_read_and_zero_means_absent() {
    let parsed = Diagnostics::parse("http_connect=407 http_code=000 ssl_verify=0 num_connects=1");
    assert_eq!(
        parsed,
        Diagnostics {
            http_connect: Some(407),
            http_code: None,
            ssl_verify: None,
            num_connects: Some(1),
        }
    );
    assert_eq!(
        Diagnostics::parse("future=1 http_code=200 garbage"),
        Diagnostics {
            http_code: Some(200),
            ..Diagnostics::default()
        }
    );
    assert_eq!(Diagnostics::parse(""), Diagnostics::default());
}

/// The classification table over recorded macOS curl 8.7.1 output.
#[test]
fn recorded_curl_failures_are_classified_by_number_first() {
    let direct = Route::Direct;
    let via = proxied();
    let cases: Vec<(Transfer<'_>, NetFailure)> = vec![
        (
            transfer(Some(7), "curl: (7) Failed to connect to 127.0.0.1 port 9 after 0 ms: Couldn't connect to server", "http_connect=000 http_code=000 ssl_verify=0 num_connects=0", &direct),
            NetFailure::ConnectFailed { host: "jenkins.corp.example".to_owned() },
        ),
        (
            transfer(Some(7), "curl: (7) Failed to connect to proxy.corp.example port 3128", "http_connect=000 http_code=000 ssl_verify=0 num_connects=0", &via),
            NetFailure::ProxyUnreachable { proxy: "proxy.corp.example:3128".to_owned() },
        ),
        (
            transfer(Some(6), "curl: (6) Could not resolve host: jenkins.corp.example", "http_connect=000 http_code=000 ssl_verify=0 num_connects=0", &direct),
            NetFailure::DnsFailed { host: "jenkins.corp.example".to_owned() },
        ),
        (
            transfer(Some(5), "curl: (5) Could not resolve proxy: proxy.corp.example", "http_connect=000 http_code=000 ssl_verify=0 num_connects=0", &via),
            NetFailure::ProxyDnsFailed { proxy: "proxy.corp.example:3128".to_owned() },
        ),
        (
            transfer(Some(28), "curl: (28) Failed to connect to 10.255.255.1 port 80 after 2006 ms: Timeout was reached", "http_connect=000 http_code=000 ssl_verify=0 num_connects=0", &direct),
            NetFailure::ConnectTimeout { host: "jenkins.corp.example".to_owned() },
        ),
        (
            transfer(Some(28), "curl: (28) Failed to connect to proxy.corp.example port 3128 after 2006 ms: Timeout was reached", "http_connect=000 http_code=000 ssl_verify=0 num_connects=0", &via),
            NetFailure::ProxyUnreachable { proxy: "proxy.corp.example:3128".to_owned() },
        ),
        (
            transfer(Some(28), "curl: (28) Operation timed out after 1002 milliseconds with 0 bytes received", "http_connect=000 http_code=000 ssl_verify=0 num_connects=1", &direct),
            NetFailure::Timeout,
        ),
        (
            transfer(Some(28), "curl: (28) Operation timed out", "", &direct),
            NetFailure::Timeout,
        ),
        (
            transfer(Some(56), "curl: (56) CONNECT tunnel failed, response 407", "http_connect=407 http_code=000 ssl_verify=0 num_connects=1", &via),
            NetFailure::ProxyAuthRequired { proxy: "proxy.corp.example:3128".to_owned(), offered: vec![] },
        ),
        (
            transfer(Some(56), "curl: (56) CONNECT tunnel failed, response 403", "http_connect=403 http_code=000 ssl_verify=0 num_connects=1", &via),
            NetFailure::ProxyDenied { proxy: "proxy.corp.example:3128".to_owned(), target: "jenkins.corp.example:443".to_owned(), status: 403 },
        ),
        (
            transfer(Some(56), "curl: (56) CONNECT tunnel failed, response 502", "http_connect=502 http_code=000 ssl_verify=0 num_connects=1", &via),
            NetFailure::ProxyDenied { proxy: "proxy.corp.example:3128".to_owned(), target: "jenkins.corp.example:443".to_owned(), status: 502 },
        ),
        (
            transfer(Some(60), "curl: (60) SSL certificate problem: unable to get local issuer certificate\nMore details here: https://curl.se/docs/sslcerts.html", "http_connect=000 http_code=000 ssl_verify=20 num_connects=1", &direct),
            NetFailure::TlsUntrustedIssuer { host: "jenkins.corp.example".to_owned(), issuer: None, backend: "LibreSSL".to_owned() },
        ),
        (
            transfer(Some(60), "curl: (60) SSL certificate problem: unable to get local issuer certificate", "http_connect=200 http_code=000 ssl_verify=20 num_connects=1", &via),
            NetFailure::TlsUntrustedIssuer { host: "jenkins.corp.example".to_owned(), issuer: None, backend: "LibreSSL".to_owned() },
        ),
        (
            transfer(Some(60), "curl: (60) SSL certificate problem: certificate has expired", "http_connect=000 http_code=000 ssl_verify=10 num_connects=1", &direct),
            NetFailure::TlsExpired { host: "jenkins.corp.example".to_owned() },
        ),
        (
            transfer(Some(60), "curl: (60) SSL: no alternative certificate subject name matches target host name 'localhost'", "http_connect=000 http_code=000 ssl_verify=1 num_connects=1", &direct),
            NetFailure::TlsHostnameMismatch { host: "jenkins.corp.example".to_owned() },
        ),
        (
            transfer(Some(35), "curl: (35) LibreSSL SSL_connect: SSL_ERROR_SYSCALL in connection to 127.0.0.1:18502", "http_connect=000 http_code=000 ssl_verify=1 num_connects=1", &direct),
            NetFailure::TlsFailed { host: "jenkins.corp.example".to_owned(), detail: "curl: (35) LibreSSL SSL_connect: SSL_ERROR_SYSCALL in connection to 127.0.0.1:18502".to_owned() },
        ),
        (
            transfer(Some(22), "curl: (22) The requested URL returned error: 404", "http_connect=000 http_code=404 ssl_verify=0 num_connects=1", &direct),
            NetFailure::HttpStatus { status: Some(404) },
        ),
        (
            transfer(Some(63), "curl: (63) Maximum file size exceeded", "http_connect=000 http_code=200 ssl_verify=0 num_connects=1", &direct),
            NetFailure::TooLarge { maximum: 1024 },
        ),
        (transfer(Some(23), "curl: (23) Failure writing output", "", &direct), NetFailure::WriteFailed),
        (transfer(Some(18), "curl: (18) transfer closed with 10 bytes remaining", "", &direct), NetFailure::TransferInterrupted { exit: 18 }),
        (transfer(Some(56), "curl: (56) Recv failure", "http_connect=200 http_code=000 ssl_verify=0 num_connects=1", &via), NetFailure::TransferInterrupted { exit: 56 }),
        (transfer(Some(33), "curl: (33) HTTP server doesn't seem to support byte ranges", "", &direct), NetFailure::ResumeUnsupported),
        (transfer(Some(36), "curl: (36) bad range", "", &direct), NetFailure::ResumeUnsupported),
        (
            transfer(Some(47), "curl: (47) Maximum (3) redirects followed", "", &direct),
            NetFailure::Other { exit: Some(47), detail: "curl: (47) Maximum (3) redirects followed".to_owned() },
        ),
        (
            transfer(None, "", "", &direct),
            NetFailure::Other { exit: None, detail: "(curl printed nothing)".to_owned() },
        ),
    ];
    for (transfer, expected) in cases {
        let exit = transfer.exit;
        let stderr = transfer.stderr.to_owned();
        assert_eq!(classify(&transfer), expected, "exit {exit:?}: {stderr}");
    }
}

#[test]
fn the_credential_and_the_bundle_change_the_name() {
    let via = proxied();
    let mut rejected = transfer(
        Some(56),
        "curl: (56) CONNECT tunnel failed, response 407",
        "http_connect=407 num_connects=1",
        &via,
    );
    rejected.credential_sent = true;
    assert_eq!(
        classify(&rejected),
        NetFailure::ProxyAuthRejected {
            proxy: "proxy.corp.example:3128".to_owned()
        }
    );

    let offered = ["Basic".to_owned(), "NTLM".to_owned()];
    let mut required = transfer(Some(56), "", "http_connect=407 num_connects=1", &via);
    required.offered = &offered;
    let failure = classify(&required);
    assert_eq!(
        failure.sentence(),
        "The proxy proxy.corp.example:3128 wants authentication. It offers: Basic, NTLM."
    );

    let direct = Route::Direct;
    let unreadable =
        "curl: (77) error setting certificate verify locations:  CAfile: /x/ca.pem CApath: none";
    let mut with_bundle = transfer(Some(77), unreadable, "ssl_verify=1 num_connects=1", &direct);
    with_bundle.cacert_set = true;
    assert_eq!(classify(&with_bundle), NetFailure::CaBundleUnreadable);
    let without = transfer(Some(77), unreadable, "ssl_verify=1 num_connects=1", &direct);
    assert_eq!(classify(&without).cause(), "tls_error");

    // `Schannel`'s curl refuses a missing file while reading its config:
    // exit 2, no transfer, no diagnostics line.
    let missing = "curl: The file 'C:\\x\\ca.pem' provided to --cacert does not exist";
    let mut at_config = transfer(Some(2), missing, "", &direct);
    at_config.cacert_set = true;
    assert_eq!(classify(&at_config), NetFailure::CaBundleUnreadable);
    let no_bundle = transfer(Some(2), missing, "", &direct);
    assert_eq!(classify(&no_bundle).cause(), "curl_failed");

    let mut named = transfer(
        Some(60),
        "curl: (60) SSL certificate problem: unable to get local issuer certificate",
        "ssl_verify=20 num_connects=1",
        &direct,
    );
    named.issuer = Some("O=Corp; CN=Corp Inspection CA");
    assert_eq!(
        classify(&named).sentence(),
        "The certificate of jenkins.corp.example was issued by O=Corp; CN=Corp Inspection CA, which is not trusted."
    );
}

/// Where no verify result exists (Schannel), the fixed tokens of curl's
/// Windows error text decide; anything else is the generic TLS failure.
#[test]
fn schannel_text_is_matched_only_on_fixed_tokens() {
    let direct = Route::Direct;
    let schannel = TlsBackend::Schannel;
    let case = |exit: i32, text: &'static str| {
        let mut transfer = transfer(Some(exit), text, "ssl_verify=0 num_connects=1", &direct);
        transfer.backend = &schannel;
        classify(&transfer).cause()
    };
    assert_eq!(
        case(
            60,
            "curl: (60) schannel: SEC_E_UNTRUSTED_ROOT (0x80090325) - The certificate chain was issued by an authority that is not trusted."
        ),
        "tls_untrusted_issuer"
    );
    assert_eq!(
        case(
            35,
            "curl: (35) schannel: next InitializeSecurityContext failed: SEC_E_UNTRUSTED_ROOT (0x80090325)"
        ),
        "tls_untrusted_issuer"
    );
    assert_eq!(
        case(
            60,
            "curl: (60) schannel: SEC_E_WRONG_PRINCIPAL (0x80090322) - The target principal name is incorrect."
        ),
        "tls_hostname_mismatch"
    );
    assert_eq!(
        case(
            60,
            "curl: (60) schannel: CRYPT_E_NO_REVOCATION_CHECK (0x80092012) - The revocation function was unable to check revocation for the certificate."
        ),
        "tls_revocation_unavailable"
    );
    assert_eq!(
        case(
            60,
            "curl: (60) schannel: CRYPT_E_REVOCATION_OFFLINE (0x80092013)"
        ),
        "tls_revocation_unavailable"
    );
    assert_eq!(
        case(
            60,
            "curl: (60) schannel: SEC_E_CERT_EXPIRED (0x80090328) - The received certificate has expired."
        ),
        "tls_expired"
    );
    // The texts curl 8.21.0 printed on the Windows 11 VM, which name no
    // Windows error code.
    assert_eq!(
        case(60, "curl: (60) schannel: the revocation status is unknown"),
        "tls_revocation_unavailable"
    );
    // The chain-trust flag spellings of the windows-2025 runner's build.
    for (text, want) in [
        (
            "CERT_TRUST_REVOCATION_STATUS_UNKNOWN",
            "tls_revocation_unavailable",
        ),
        (
            "CERT_TRUST_IS_OFFLINE_REVOCATION",
            "tls_revocation_unavailable",
        ),
        ("CERT_TRUST_IS_PARTIAL_CHAIN", "tls_untrusted_issuer"),
        ("CERT_TRUST_IS_UNTRUSTED_ROOT", "tls_untrusted_issuer"),
        ("CERT_TRUST_IS_NOT_TIME_VALID", "tls_expired"),
    ] {
        let line = format!("curl: (60) schannel: CertGetCertificateChain trust error {text}");
        assert_eq!(case(60, &line), want, "{text}");
    }
    assert_eq!(
        case(
            60,
            "curl: (60) schannel: the certificate chain is incomplete"
        ),
        "tls_untrusted_issuer"
    );
    assert_eq!(
        case(
            60,
            "curl: (60) schannel: the certificate or certificate chain is based on an untrusted root"
        ),
        "tls_untrusted_issuer"
    );
    assert_eq!(
        case(
            60,
            "curl: (60) schannel: this certificate or one of the certificates in the certificate chain is not time valid"
        ),
        "tls_expired"
    );
    assert_eq!(
        case(
            60,
            "curl: (60) schannel: CertGetNameString() failed to match connection hostname (localhost) against server certificate names"
        ),
        "tls_hostname_mismatch"
    );
    assert_eq!(
        case(
            35,
            "curl: (35) schannel: next InitializeSecurityContext failed: Unknown error (0x80092013)"
        ),
        "tls_error"
    );
    assert_eq!(
        case(58, "curl: (58) schannel: Failed to import cert file"),
        "tls_error"
    );
}

#[test]
fn every_failure_has_a_cause_a_sentence_and_a_recovery() {
    let host = || "jenkins.corp.example".to_owned();
    let all = vec![
        NetFailure::CurlUnavailable,
        NetFailure::CurlTooOld {
            found: "7.55.1".to_owned(),
            needed: "7.63.0",
            feature: "a proxy",
        },
        NetFailure::SettingsInvalid("proxy.url: no port".to_owned()),
        NetFailure::CaBundleTampered,
        NetFailure::RequestInvalid {
            field: "header",
            detail: "control character".to_owned(),
        },
        NetFailure::Spawn("fork failed".to_owned()),
        NetFailure::ProxyDnsFailed {
            proxy: "p:1".to_owned(),
        },
        NetFailure::ProxyUnreachable {
            proxy: "p:1".to_owned(),
        },
        NetFailure::ProxyAuthRequired {
            proxy: "p:1".to_owned(),
            offered: vec![],
        },
        NetFailure::ProxyAuthRejected {
            proxy: "p:1".to_owned(),
        },
        NetFailure::ProxyDenied {
            proxy: "p:1".to_owned(),
            target: "t:443".to_owned(),
            status: 403,
        },
        NetFailure::DnsFailed { host: host() },
        NetFailure::ConnectFailed { host: host() },
        NetFailure::ConnectTimeout { host: host() },
        NetFailure::TlsUntrustedIssuer {
            host: host(),
            issuer: None,
            backend: "Schannel".to_owned(),
        },
        NetFailure::TlsHostnameMismatch { host: host() },
        NetFailure::TlsExpired { host: host() },
        NetFailure::TlsRevocationUnavailable { host: host() },
        NetFailure::TlsFailed {
            host: host(),
            detail: "x".to_owned(),
        },
        NetFailure::CaBundleUnreadable,
        NetFailure::Timeout,
        NetFailure::Deadline,
        NetFailure::TooLarge { maximum: 64 },
        NetFailure::HttpStatus { status: Some(403) },
        NetFailure::HttpStatus { status: None },
        NetFailure::WriteFailed,
        NetFailure::TransferInterrupted { exit: 18 },
        NetFailure::ResumeUnsupported,
        NetFailure::Other {
            exit: Some(2),
            detail: "x".to_owned(),
        },
        NetFailure::Other {
            exit: None,
            detail: "x".to_owned(),
        },
    ];
    let mut causes: Vec<&str> = all.iter().map(NetFailure::cause).collect();
    for failure in &all {
        assert!(
            failure
                .cause()
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b == b'_'),
            "{}",
            failure.cause()
        );
        assert!(!failure.sentence().is_empty());
        assert!(!failure.recovery().is_empty());
        assert_eq!(failure.to_string(), failure.sentence());
    }
    causes.sort_unstable();
    causes.dedup();
    // One cause per situation, except the two `HttpStatus` and `Other` shapes.
    assert_eq!(causes.len(), all.len() - 2);
    assert_eq!(
        NetFailure::CurlTooOld {
            found: "7.55.1".to_owned(),
            needed: "7.63.0",
            feature: "a proxy"
        }
        .sentence(),
        "This computer's curl is 7.55.1; a proxy needs curl 7.63.0 or newer."
    );
}

#[test]
fn an_excerpt_is_one_bounded_line() {
    assert_eq!(
        excerpt("  curl: (6)  Could not\r\n resolve\thost \n"),
        "curl: (6) Could not resolve host"
    );
    assert_eq!(excerpt(""), "(curl printed nothing)");
    let long = excerpt(&"x".repeat(2000));
    assert_eq!(long.chars().count(), 513);
    assert!(long.ends_with('…'));
}
