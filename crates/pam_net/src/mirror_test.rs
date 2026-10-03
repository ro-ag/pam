use url::Url;

use crate::mirror::MirrorBase;
use crate::settings::parse_no_proxy;

fn mirror(raw: &str) -> MirrorBase {
    MirrorBase::parse(raw, "engine_mirror").unwrap_or_else(|e| panic!("{raw}: {e}"))
}

#[test]
fn accepted_mirror_addresses_end_in_a_slash() {
    let cases = [
        (
            "https://artifacts.corp.example/llama.cpp/b10938/",
            "https://artifacts.corp.example/llama.cpp/b10938/",
        ),
        (
            "https://artifacts.corp.example/llama.cpp/b10938",
            "https://artifacts.corp.example/llama.cpp/b10938/",
        ),
        (
            "https://artifacts.corp.example",
            "https://artifacts.corp.example/",
        ),
        (
            "HTTPS://Artifacts.Corp.Example:8443/x",
            "https://artifacts.corp.example:8443/x/",
        ),
        ("https://10.20.30.40/models", "https://10.20.30.40/models/"),
        ("https://[fd00::10]:8443/", "https://[fd00::10]:8443/"),
        (
            " https://artifacts.corp.example/ ",
            "https://artifacts.corp.example/",
        ),
    ];
    for (raw, normalized) in cases {
        let base = mirror(raw);
        assert_eq!(base.as_str(), normalized, "{raw}");
        assert_eq!(base.url().as_str(), normalized);
    }
    assert_eq!(
        mirror("https://artifacts.corp.example/").host(),
        "artifacts.corp.example"
    );
}

#[test]
fn refused_mirror_addresses_say_why() {
    let cases = [
        ("", "empty"),
        ("http://artifacts.corp.example/", "must start with https://"),
        ("artifacts.corp.example/", "must start with https://"),
        (
            "https://user:pw@artifacts.corp.example/",
            "user names and passwords",
        ),
        ("https://artifacts.corp.example/?x=1", "no query"),
        ("https://artifacts.corp.example/#top", "no fragment"),
        ("https://artifacts.corp.example/a/../b/", "`.` or `..`"),
        ("https://artifacts.corp.example/a/./b/", "`.` or `..`"),
        ("https://artifacts.corp.example/a/%2e%2e/b/", "`.` or `..`"),
        ("https://artifacts.corp.example/a/.%2E/b/", "`.` or `..`"),
        ("https://localhost/", "localhost"),
        ("https://mirror.localhost/", "localhost"),
        ("https://127.0.0.1/", "loopback, link-local"),
        ("https://127.3.4.5:8443/", "loopback, link-local"),
        ("https://169.254.169.254/latest/", "loopback, link-local"),
        ("https://0.0.0.0/", "loopback, link-local"),
        ("https://224.0.0.1/", "loopback, link-local"),
        ("https://255.255.255.255/", "loopback, link-local"),
        ("https://[::1]/", "loopback, link-local"),
        ("https://[::]/", "loopback, link-local"),
        ("https://[fe80::1]/", "loopback, link-local"),
        ("https://[ff02::1]/", "loopback, link-local"),
        ("https://[::ffff:127.0.0.1]/", "loopback, link-local"),
        ("https://[::ffff:169.254.169.254]/", "loopback, link-local"),
        ("https://art ifacts.example/", "space or a control"),
        ("https://", "host"),
    ];
    for (raw, expected) in cases {
        let error = MirrorBase::parse(raw, "models_mirror").expect_err(raw);
        assert_eq!(error.field, "models_mirror", "{raw}");
        assert!(error.detail.contains(expected), "{raw:?}: {}", error.detail);
    }
    let long = format!("https://{}.example/", "m".repeat(520));
    assert!(MirrorBase::parse(&long, "engine_mirror").is_err());
}

#[test]
fn the_engine_asset_joins_under_the_mirror() {
    let base = mirror("https://artifacts.corp.example/llama.cpp/b10938/");
    assert_eq!(
        base.join("llama-b10938-bin-macos-arm64.tar.gz")
            .unwrap()
            .as_str(),
        "https://artifacts.corp.example/llama.cpp/b10938/llama-b10938-bin-macos-arm64.tar.gz"
    );
    for bad in [
        "",
        "/etc/passwd",
        "../b10937/llama.tar.gz",
        "a/../../x",
        "a/%2e%2e/x",
        "a\\b",
        "name\nwith-newline",
    ] {
        let error = base.join(bad).expect_err(bad);
        assert_eq!(error.field, "mirror");
        assert!(
            error.detail.contains("cannot be fetched"),
            "{bad:?}: {}",
            error.detail
        );
    }
}

#[test]
fn a_catalog_url_is_rebased_onto_the_models_mirror() {
    let base = mirror("https://artifacts.corp.example/api/huggingfaceml/hf-remote/");
    let preset = Url::parse(
        "https://huggingface.co/ggml-org/gpt-oss-20b-GGUF/resolve/main/gpt-oss-20b-MXFP4.gguf",
    )
    .unwrap();
    assert_eq!(
        base.rebase(&preset, "https://huggingface.co/")
            .unwrap()
            .as_str(),
        "https://artifacts.corp.example/api/huggingfaceml/hf-remote/ggml-org/gpt-oss-20b-GGUF/resolve/main/gpt-oss-20b-MXFP4.gguf"
    );
    // A preset not under the upstream prefix is fetched as it is.
    let elsewhere = Url::parse("https://models.example/x.gguf").unwrap();
    assert_eq!(base.rebase(&elsewhere, "https://huggingface.co/"), None);
    // A prefix match that is not on a path boundary is not a match.
    let lookalike = Url::parse("https://huggingface.co.evil.example/x.gguf").unwrap();
    assert_eq!(base.rebase(&lookalike, "https://huggingface.co/"), None);
}

#[test]
fn a_managed_allowlist_uses_the_no_proxy_grammar() {
    let base = mirror("https://artifacts.corp.example/");
    assert!(base.host_allowed(&[]));
    assert!(base.host_allowed(&parse_no_proxy(&["corp.example"]).unwrap()));
    assert!(base.host_allowed(&parse_no_proxy(&["artifacts.corp.example"]).unwrap()));
    assert!(!base.host_allowed(&parse_no_proxy(&["other.example"]).unwrap()));
    let literal = mirror("https://10.20.30.40/");
    assert!(literal.host_allowed(&parse_no_proxy(&["10.20.0.0/16"]).unwrap()));
    assert!(!literal.host_allowed(&parse_no_proxy(&["corp.example"]).unwrap()));
}
