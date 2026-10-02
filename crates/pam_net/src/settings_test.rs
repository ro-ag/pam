use std::path::PathBuf;
use std::sync::Arc;

use url::Url;

use crate::settings::{
    NetSettings, NetworkSource, NoProxyRule, Proxy, ProxyAuth, ProxyPassword, ProxyScheme, Route,
    is_loopback, parse_no_proxy,
};

fn url(text: &str) -> Url {
    Url::parse(text).expect("a test URL")
}

#[test]
fn accepted_proxy_addresses_are_normalized() {
    let cases = [
        (
            "http://proxy.corp.example:3128",
            "http://proxy.corp.example:3128",
        ),
        (
            "HTTP://Proxy.Corp.Example:3128/",
            "http://proxy.corp.example:3128",
        ),
        (
            "https://proxy.corp.example:443",
            "https://proxy.corp.example:443",
        ),
        (
            "http://proxy.corp.example:80",
            "http://proxy.corp.example:80",
        ),
        ("http://10.1.2.3:8080", "http://10.1.2.3:8080"),
        ("http://[fd00::1]:3128", "http://[fd00::1]:3128"),
        (
            "  http://proxy.corp.example:3128  ",
            "http://proxy.corp.example:3128",
        ),
        (
            "http://bücher.example:3128",
            "http://xn--bcher-kva.example:3128",
        ),
    ];
    for (raw, normalized) in cases {
        let proxy =
            Proxy::parse(raw, ProxyAuth::None, None).unwrap_or_else(|e| panic!("{raw}: {e}"));
        assert_eq!(proxy.url(), normalized, "{raw}");
        assert_eq!(
            proxy.authority(),
            &normalized[normalized.find("://").unwrap() + 3..]
        );
    }
    let proxy = Proxy::parse(
        "https://p.example:8443",
        ProxyAuth::Basic,
        Some(" svc-pam "),
    )
    .unwrap();
    assert_eq!(proxy.scheme(), ProxyScheme::Https);
    assert_eq!(proxy.host(), "p.example");
    assert_eq!(proxy.port(), 8443);
    assert_eq!(proxy.auth(), ProxyAuth::Basic);
    assert_eq!(proxy.username(), Some("svc-pam"));
}

#[test]
fn refused_proxy_addresses_say_why() {
    let cases = [
        ("", "empty"),
        (
            "proxy.corp.example:3128",
            "did you mean http://proxy.corp.example:3128?",
        ),
        (
            "socks5://proxy.corp.example:1080",
            "SOCKS proxies are not supported",
        ),
        (
            "socks5h://proxy.corp.example:1080",
            "SOCKS proxies are not supported",
        ),
        (
            "socks4a://proxy.corp.example:1080",
            "SOCKS proxies are not supported",
        ),
        (
            "ftp://proxy.corp.example:21",
            "not a supported proxy scheme",
        ),
        ("http://proxy.corp.example", "port explicitly"),
        ("http://proxy.corp.example:", "port explicitly"),
        ("http://proxy.corp.example:0", "port explicitly"),
        ("http://proxy.corp.example:99999", "port explicitly"),
        ("http://proxy.corp.example:31a8", "port explicitly"),
        ("http://[fd00::1]", "port explicitly"),
        (
            "http://user:secret@proxy.corp.example:3128",
            "Leave the user name and password out",
        ),
        ("http://proxy.corp.example:3128/path", "takes no path"),
        ("http://proxy.corp.example:3128?x=1", "takes no query"),
        ("http://proxy.corp.example:3128#frag", "takes no fragment"),
        ("http://:3128", "no host"),
        (
            "http://proxy corp.example:3128",
            "space or a control character",
        ),
        (
            "http://proxy.corp\n.example:3128",
            "space or a control character",
        ),
    ];
    for (raw, expected) in cases {
        let error = Proxy::parse(raw, ProxyAuth::None, None)
            .expect_err(raw)
            .to_string();
        assert!(error.contains(expected), "{raw:?}: {error}");
        assert!(error.starts_with("proxy.url: "), "{error}");
    }
    let long = format!("http://{}.example:3128", "a".repeat(260));
    assert!(Proxy::parse(&long, ProxyAuth::None, None).is_err());
}

#[test]
fn user_names_and_passwords_are_validated() {
    for (name, expected) in [
        ("", "empty"),
        ("svc:pam", "colon"),
        ("svc\u{7}pam", "control character"),
        (&"u".repeat(129), "longer than 128"),
    ] {
        let error = Proxy::parse("http://p.example:3128", ProxyAuth::Basic, Some(name))
            .expect_err(name)
            .to_string();
        assert!(error.starts_with("proxy.username: "), "{error}");
        assert!(error.contains(expected), "{name:?}: {error}");
    }
    assert_eq!(
        Proxy::parse(
            "http://p.example:3128",
            ProxyAuth::AnyAuth,
            Some("CORP\\svc-pam")
        )
        .unwrap()
        .username(),
        Some("CORP\\svc-pam")
    );

    assert_eq!(
        ProxyPassword::new("  hunter2 ").unwrap().expose(),
        "hunter2"
    );
    assert_eq!(ProxyPassword::new("a:b:c").unwrap().expose(), "a:b:c");
    for (password, expected) in [
        ("", "empty"),
        ("   ", "empty"),
        ("line\nbreak", "control character"),
        (&"p".repeat(1025), "longer than 1024"),
    ] {
        let error = ProxyPassword::new(password)
            .expect_err(password)
            .to_string();
        assert!(error.starts_with("credential: "), "{error}");
        assert!(error.contains(expected), "{password:?}: {error}");
    }
    assert_eq!(
        format!("{:?}", ProxyPassword::new("hunter2").unwrap()),
        "[REDACTED]"
    );
}

#[test]
fn auth_modes_round_trip() {
    for mode in [ProxyAuth::None, ProxyAuth::Basic, ProxyAuth::AnyAuth] {
        assert_eq!(ProxyAuth::parse(mode.as_str()).unwrap(), mode);
    }
    let error = ProxyAuth::parse("ntlm").unwrap_err();
    assert_eq!(error.field, "proxy.auth");
    assert!(error.detail.contains("none, basic or anyauth"));
}

#[test]
fn no_proxy_entries_follow_the_portable_grammar() {
    let accepted = [
        ("*", "*"),
        ("corp.example", "corp.example"),
        (".corp.example", ".corp.example"),
        ("  Jenkins.CORP.example ", "jenkins.corp.example"),
        ("my_host", "my_host"),
        ("10.0.0.1", "10.0.0.1"),
        ("::1", "::1"),
        ("[fd00::1]", "fd00::1"),
        ("10.0.0.0/8", "10.0.0.0/8"),
        ("fd00::/8", "fd00::/8"),
    ];
    for (raw, stored) in accepted {
        let rule = NoProxyRule::parse(raw).unwrap_or_else(|e| panic!("{raw}: {e}"));
        assert_eq!(rule.as_str(), stored, "{raw}");
    }
    let refused = [
        ("", "empty"),
        ("   ", "empty"),
        ("http://corp.example", "is a URL"),
        ("<local>", "not supported"),
        ("corp.example:8080", "names a port"),
        ("*.corp.example", "wildcard"),
        ("corp .example", "space, a comma"),
        ("a,b", "space, a comma"),
        ("corp.example.", "not a host name"),
        ("corp..example", "not a host name"),
        ("bücher.example", "not a host name"),
        ("10.0.0.0/33", "not a CIDR range"),
        ("10.0.0/8", "not a CIDR range"),
        ("fd00::/129", "not a CIDR range"),
        ("corp.example/8", "not a CIDR range"),
        (&"a".repeat(256), "longer than 255"),
    ];
    for (raw, expected) in refused {
        let error = NoProxyRule::parse(raw).expect_err(raw).to_string();
        assert!(error.starts_with("no_proxy: "), "{error}");
        assert!(error.contains(expected), "{raw:?}: {error}");
    }
}

#[test]
fn a_no_proxy_list_is_bounded_and_deduplicated() {
    let rules = parse_no_proxy(&[
        "corp.example",
        "CORP.example",
        " corp.example",
        "10.0.0.0/8",
    ])
    .unwrap();
    assert_eq!(rules.len(), 2);
    assert!(rules[1].is_cidr());
    assert!(!rules[0].is_cidr());
    assert!(parse_no_proxy(&["*"]).unwrap()[0].is_any());

    let many: Vec<String> = (0..65).map(|n| format!("h{n}.example")).collect();
    let error = parse_no_proxy(&many).unwrap_err();
    assert!(error.detail.contains("more than 64"));
    assert!(parse_no_proxy(&["ok.example", ""]).is_err());
}

#[test]
fn no_proxy_rules_match_names_and_literals_separately() {
    let host = |text: &str| NoProxyRule::parse(text).unwrap();
    let jenkins = url("https://jenkins.corp.example/job");
    assert!(host("corp.example").matches(&jenkins));
    assert!(host(".corp.example").matches(&jenkins));
    assert!(host("jenkins.corp.example").matches(&jenkins));
    assert!(host("JENKINS.corp.example").matches(&url("https://Jenkins.Corp.Example./")));
    assert!(!host("rp.example").matches(&jenkins));
    assert!(!host("other.example").matches(&jenkins));
    assert!(!host("jenkins.corp.example.com").matches(&jenkins));
    assert!(host("*").matches(&jenkins));

    let literal = url("https://10.1.2.3:8443/");
    assert!(host("10.1.2.3").matches(&literal));
    assert!(!host("10.1.2.4").matches(&literal));
    assert!(host("10.0.0.0/8").matches(&literal));
    assert!(host("10.1.2.0/24").matches(&literal));
    assert!(!host("10.1.3.0/24").matches(&literal));
    assert!(host("0.0.0.0/0").matches(&literal));
    // A name is never resolved to be compared with a range or an address.
    assert!(!host("10.0.0.0/8").matches(&jenkins));
    assert!(!host("10.1.2.3").matches(&jenkins));
    // A name rule never matches a literal.
    assert!(!host("corp.example").matches(&literal));

    let six = url("https://[fd00::1]/");
    assert!(host("fd00::1").matches(&six));
    assert!(host("[fd00::1]").matches(&six));
    assert!(host("fd00::/8").matches(&six));
    assert!(!host("fe80::/10").matches(&six));
    assert!(!host("10.0.0.0/8").matches(&six));
}

#[test]
fn the_route_preview_follows_the_list_and_the_loopback_rule() {
    let direct = NetSettings::direct();
    assert_eq!(
        direct.route_for(&url("https://api.github.com/")),
        Route::Direct
    );

    let proxy = Proxy::parse("http://proxy.corp.example:3128", ProxyAuth::None, None).unwrap();
    let settings = NetSettings::new(
        Some(proxy),
        None,
        parse_no_proxy(&[".internal.example", "10.0.0.0/8"]).unwrap(),
        None,
    )
    .unwrap();
    assert_eq!(
        settings.route_for(&url("https://api.github.com/")),
        Route::Proxy {
            host: "proxy.corp.example".to_owned(),
            port: 3128
        }
    );
    assert_eq!(
        settings.route_for(&url("https://ci.internal.example/")),
        Route::Bypass
    );
    assert_eq!(settings.route_for(&url("https://10.3.4.5/")), Route::Bypass);
    assert_eq!(
        settings.route_for(&url("https://11.3.4.5/")).as_str(),
        "proxy"
    );
    for local in [
        "http://localhost:8080/",
        "http://LOCALHOST./",
        "http://dev.localhost/",
        "http://127.0.0.1:9/",
        "http://127.9.9.9/",
        "http://[::1]/",
        "http://[::ffff:127.0.0.1]/",
    ] {
        assert!(is_loopback(&url(local)), "{local}");
        assert_eq!(settings.route_for(&url(local)), Route::Bypass, "{local}");
    }
    for remote in [
        "http://localhost.example/",
        "http://[::ffff:10.0.0.1]/",
        "http://[::2]/",
    ] {
        assert!(!is_loopback(&url(remote)), "{remote}");
    }
    assert!(!settings.sends_proxy_credential());
}

#[test]
fn a_credential_is_sent_only_when_mode_name_and_password_agree() {
    let password = || Some(ProxyPassword::new("hunter2").unwrap());
    let with = |auth, name: Option<&str>, password| {
        let proxy = Proxy::parse("http://p.example:3128", auth, name).unwrap();
        NetSettings::new(Some(proxy), password, Vec::new(), None).unwrap()
    };
    assert!(with(ProxyAuth::Basic, Some("svc"), password()).sends_proxy_credential());
    assert!(with(ProxyAuth::AnyAuth, Some("svc"), password()).sends_proxy_credential());
    assert!(!with(ProxyAuth::None, Some("svc"), password()).sends_proxy_credential());
    assert!(!with(ProxyAuth::Basic, None, password()).sends_proxy_credential());
    assert!(!with(ProxyAuth::Basic, Some("svc"), None).sends_proxy_credential());
    assert!(!NetSettings::direct().sends_proxy_credential());
    // Debug output never carries the password.
    let shown = format!("{:?}", with(ProxyAuth::Basic, Some("svc"), password()));
    assert!(!shown.contains("hunter2"), "{shown}");
    assert!(shown.contains("[REDACTED]"), "{shown}");
}

#[test]
fn the_ca_bundle_path_must_be_absolute_and_plain() {
    let absolute = if cfg!(windows) {
        PathBuf::from("C:\\ProgramData\\pam\\net\\ca-abc.pem")
    } else {
        PathBuf::from("/var/pam/net/ca-abc.pem")
    };
    let settings = NetSettings::new(None, None, Vec::new(), Some(absolute.clone())).unwrap();
    assert_eq!(settings.ca_bundle(), Some(absolute.as_path()));

    let error =
        NetSettings::new(None, None, Vec::new(), Some(PathBuf::from("net/ca.pem"))).unwrap_err();
    assert_eq!(error.field, "ca_bundle");
    assert!(error.detail.contains("absolute"));

    let mut odd = absolute.into_os_string();
    odd.push("\n");
    let error = NetSettings::new(None, None, Vec::new(), Some(PathBuf::from(odd))).unwrap_err();
    assert!(error.detail.contains("control character"));

    let many: Vec<NoProxyRule> = (0..65)
        .map(|n| NoProxyRule::parse(&format!("h{n}.example")).unwrap())
        .collect();
    assert_eq!(
        NetSettings::new(None, None, many, None).unwrap_err().field,
        "no_proxy"
    );
}

#[tokio::test]
async fn a_fixed_profile_is_its_own_source() {
    let source: Arc<dyn NetworkSource> = Arc::new(Arc::new(NetSettings::direct()));
    let settings = source.settings().await.unwrap();
    assert!(settings.proxy().is_none());
    assert_eq!(
        settings.route_for(&url("https://example.com/")),
        Route::Direct
    );
}
