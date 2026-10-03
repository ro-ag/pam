use std::path::Path;
use std::sync::{Arc, Mutex};

use pam_net::{NetFailure, NetworkSource, ProxyAuth};
use pam_store::Store;
use serde_json::json;

use crate::managed_policy_service::{Fingerprint, PolicyHandle, PolicySource, SourceRead};
use crate::network_service::{
    CaBundleEntry, CaImportError, DOCUMENT_VERSION, Field, FixedManagedNetwork, IGNORED_ENV, Lock,
    ManagedDefaults, ManagedNetwork, NetworkDocument, NetworkService, PROXY_CREDENTIAL_ID,
    PolicyClosed, ProxyEntry, SETTING_KEY, Source, ignored_env, resolve, resolve_layers,
    sha256_hex,
};
use crate::secrets::{FakeSecretBackend, SecretBackend, SecretError, SecretStore, account_for};

const PROXY_PASSWORD: &str = "pr0xy-s3cret";

struct Fixture {
    store: Arc<Store>,
    backend: Arc<FakeSecretBackend>,
    base: tempfile::TempDir,
    service: NetworkService,
}

async fn fixture() -> Fixture {
    let store = Arc::new(Store::open_in_memory().await.expect("store opens"));
    let backend = Arc::new(FakeSecretBackend::default());
    let base = tempfile::tempdir().expect("tempdir");
    let service = NetworkService::new(
        Arc::clone(&store),
        Some(Arc::new(SecretStore::new(Arc::clone(&backend) as Arc<_>))),
        base.path().to_path_buf(),
    );
    Fixture {
        store,
        backend,
        base,
        service,
    }
}

fn proxy(auth: &str, username: Option<&str>) -> ProxyEntry {
    ProxyEntry {
        url: "http://proxy.corp.example:3128".to_owned(),
        auth: auth.to_owned(),
        username: username.map(str::to_owned),
    }
}

/// The committed test CA, copied where the import rules accept it.
fn ca_source(dir: &Path) -> std::path::PathBuf {
    let source = dir.join("corp-ca.pem");
    std::fs::copy(pam_net::testing::test_ca(), &source).expect("copy the fixture");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o644)).unwrap();
    }
    source
}

#[test]
fn the_document_parses_only_its_own_version_and_fields() {
    let stored = json!({
        "version": 1,
        "proxy": {"url": "http://proxy.corp.example:3128", "auth": "basic", "username": "svc"},
        "no_proxy": ["corp.example", "10.0.0.0/8"],
        "ca_bundle": {"sha256": "ab".repeat(32), "certificates": 2, "source_path": "/x", "imported_ts": 1},
        "engine_mirror": "https://artifacts.corp.example/llama/",
        "models_mirror": null
    })
    .to_string();
    let document = NetworkDocument::parse(&stored).expect("parses");
    assert_eq!(document.version, DOCUMENT_VERSION);
    assert_eq!(document.proxy, Some(proxy("basic", Some("svc"))));
    assert_eq!(document.no_proxy, ["corp.example", "10.0.0.0/8"]);
    assert_eq!(document.ca_bundle.as_ref().map(|b| b.certificates), Some(2));
    // Round trip: what is written is what is read.
    assert_eq!(
        NetworkDocument::parse(&document.to_json()).unwrap(),
        document
    );
    // Missing optional fields are the defaults.
    assert_eq!(
        NetworkDocument::parse(r#"{"version":1}"#).unwrap(),
        NetworkDocument::default()
    );

    for (raw, needle) in [
        (r#"{"version":2}"#, "version 2"),
        (r#"{"version":1,"insecure":true}"#, "unknown field"),
        (
            r#"{"version":1,"proxy":{"url":"x","auth":"basic","password":"p"}}"#,
            "unknown field",
        ),
        (r#"{"version":1,"ca_bundle":"/etc/ca.pem"}"#, "do not parse"),
        ("not json", "do not parse"),
        ("", "do not parse"),
    ] {
        let detail = NetworkDocument::parse(raw).expect_err(raw);
        assert!(detail.contains(needle), "{raw}: {detail}");
    }
    let huge = format!(r#"{{"version":1,"no_proxy":["{}"]}}"#, "a".repeat(20_000));
    assert!(NetworkDocument::parse(&huge).unwrap_err().contains("bytes"));
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one refusal table; splitting it hides what is compared"
)]
fn every_field_is_validated_with_the_launcher_rules() {
    let valid = NetworkDocument {
        proxy: Some(proxy("anyauth", Some("CORP\\svc"))),
        no_proxy: vec!["corp.example".to_owned(), "CORP.example".to_owned()],
        ca_bundle: Some(CaBundleEntry {
            sha256: "0".repeat(64),
            certificates: 1,
            source_path: None,
            imported_ts: None,
        }),
        engine_mirror: Some("https://artifacts.corp.example/llama".to_owned()),
        models_mirror: Some("https://10.1.2.3:8443/hf/".to_owned()),
        ..NetworkDocument::default()
    };
    let checked = valid.validate(&[]).expect("valid");
    assert_eq!(checked.proxy.as_ref().unwrap().auth(), ProxyAuth::AnyAuth);
    assert_eq!(checked.no_proxy.len(), 1, "deduplicated");
    assert_eq!(
        checked.engine_mirror.unwrap().as_str(),
        "https://artifacts.corp.example/llama/"
    );

    let refused: [(&str, NetworkDocument, &str); 9] = [
        (
            "socks",
            NetworkDocument {
                proxy: Some(ProxyEntry {
                    url: "socks5://proxy:1080".to_owned(),
                    auth: "none".to_owned(),
                    username: None,
                }),
                ..NetworkDocument::default()
            },
            "SOCKS",
        ),
        (
            "scheme-less",
            NetworkDocument {
                proxy: Some(ProxyEntry {
                    url: "proxy.corp.example:3128".to_owned(),
                    auth: "none".to_owned(),
                    username: None,
                }),
                ..NetworkDocument::default()
            },
            "did you mean http://",
        ),
        (
            "no port",
            NetworkDocument {
                proxy: Some(ProxyEntry {
                    url: "http://proxy.corp.example".to_owned(),
                    auth: "none".to_owned(),
                    username: None,
                }),
                ..NetworkDocument::default()
            },
            "port",
        ),
        (
            "auth word",
            NetworkDocument {
                proxy: Some(proxy("ntlm", None)),
                ..NetworkDocument::default()
            },
            "ntlm",
        ),
        (
            "username with colon",
            NetworkDocument {
                proxy: Some(proxy("basic", Some("a:b"))),
                ..NetworkDocument::default()
            },
            "colon",
        ),
        (
            "no_proxy with port",
            NetworkDocument {
                no_proxy: vec!["corp.example:8080".to_owned()],
                ..NetworkDocument::default()
            },
            "no_proxy",
        ),
        (
            "http mirror",
            NetworkDocument {
                engine_mirror: Some("http://artifacts.corp.example/".to_owned()),
                ..NetworkDocument::default()
            },
            "https://",
        ),
        (
            "loopback mirror",
            NetworkDocument {
                models_mirror: Some("https://127.0.0.1/hf/".to_owned()),
                ..NetworkDocument::default()
            },
            "loopback",
        ),
        (
            "digest shape",
            NetworkDocument {
                ca_bundle: Some(CaBundleEntry {
                    sha256: "abc".to_owned(),
                    certificates: 1,
                    source_path: None,
                    imported_ts: None,
                }),
                ..NetworkDocument::default()
            },
            "SHA-256",
        ),
    ];
    for (name, document, needle) in refused {
        let error = document.validate(&[]).expect_err(name);
        assert!(error.to_string().contains(needle), "{name}: {error}");
    }

    // The policy's allowlist applies to mirrors only.
    let allowed = pam_net::parse_no_proxy(&["artifacts.corp.example"]).unwrap();
    assert!(valid.validate(&allowed).is_err(), "10.1.2.3 is not allowed");
    let on_list = NetworkDocument {
        models_mirror: None,
        ..valid.clone()
    };
    assert!(on_list.validate(&allowed).is_ok());
}

#[test]
fn the_policy_overlay_pins_fields_and_names_their_source() {
    let user = NetworkDocument {
        proxy: Some(proxy("none", None)),
        no_proxy: vec!["corp.example".to_owned()],
        ..NetworkDocument::default()
    };
    let nothing = resolve(&user, None);
    assert_eq!(nothing.document, user);
    assert_eq!(nothing.source(Field::Proxy), Source::User);
    assert_eq!(nothing.source(Field::NoProxy), Source::User);
    assert_eq!(nothing.source(Field::CaBundle), Source::Default);
    assert_eq!(nothing.source(Field::EngineMirror), Source::Default);
    assert!(nothing.locked_fields().is_empty());
    assert!(nothing.mirror_allowed_hosts.is_empty());

    let managed = ManagedNetwork {
        proxy: Some(None),
        engine_mirror: Some(Some("https://artifacts.corp.example/llama/".to_owned())),
        mirror_allowed_hosts: vec!["artifacts.corp.example".to_owned()],
        ..ManagedNetwork::default()
    };
    let pinned = resolve(&user, Some(&managed));
    // The policy pins "direct": the user's proxy is not in force, and not
    // overwritten either.
    assert_eq!(pinned.document.proxy, None);
    assert_eq!(pinned.source(Field::Proxy), Source::Policy);
    assert_eq!(pinned.document.no_proxy, user.no_proxy);
    assert_eq!(pinned.source(Field::NoProxy), Source::User);
    assert_eq!(
        pinned.document.engine_mirror.as_deref(),
        Some("https://artifacts.corp.example/llama/")
    );
    assert_eq!(pinned.source(Field::EngineMirror), Source::Policy);
    assert_eq!(pinned.locked_fields(), [Field::Proxy, Field::EngineMirror]);
    assert_eq!(pinned.mirror_allowed_hosts, ["artifacts.corp.example"]);
    assert_eq!(Source::Policy.as_str(), "policy");
    assert!(Source::Policy.locked() && !Source::User.locked());
    // Every field carries its lock next to its source.
    assert_eq!(pinned.entry(Field::Proxy), (Source::Policy, Lock::Locked));
    assert_eq!(pinned.entry(Field::NoProxy), (Source::User, Lock::Open));
    assert_eq!(pinned.entry(Field::CaBundle), (Source::Default, Lock::Open));
    assert!(pinned.is_locked(Field::EngineMirror) && !pinned.is_locked(Field::ModelsMirror));
}

/// A policy default is the value while the human has stored none: it is
/// the policy's (`source: policy`) and the field stays open. A value the
/// human stored wins, and a lock wins over both.
#[test]
fn a_policy_default_applies_only_while_the_user_has_no_value_and_stays_open() {
    let defaults = ManagedDefaults {
        no_proxy: Some(vec!["corp.example".to_owned()]),
        engine_mirror: Some(Some("https://artifacts.corp.example/llama/".to_owned())),
        models_mirror: Some(None),
    };
    assert!(!defaults.is_empty() && ManagedDefaults::default().is_empty());

    let nothing = resolve_layers(&NetworkDocument::default(), None, &defaults);
    assert_eq!(nothing.document.no_proxy, ["corp.example"]);
    assert_eq!(nothing.entry(Field::NoProxy), (Source::Policy, Lock::Open));
    assert_eq!(
        nothing.document.engine_mirror.as_deref(),
        Some("https://artifacts.corp.example/llama/")
    );
    assert_eq!(
        nothing.entry(Field::EngineMirror),
        (Source::Policy, Lock::Open)
    );
    // A default of "upstream" is still the policy's answer, and still open.
    assert_eq!(nothing.document.models_mirror, None);
    assert_eq!(
        nothing.entry(Field::ModelsMirror),
        (Source::Policy, Lock::Open)
    );
    // The proxy and the CA bundle take no default.
    assert_eq!(nothing.entry(Field::Proxy), (Source::Default, Lock::Open));
    assert_eq!(
        nothing.entry(Field::CaBundle),
        (Source::Default, Lock::Open)
    );
    assert!(nothing.locked_fields().is_empty());

    let user = NetworkDocument {
        no_proxy: vec!["mine.example".to_owned()],
        engine_mirror: Some("https://mine.example/llama/".to_owned()),
        ..NetworkDocument::default()
    };
    let own = resolve_layers(&user, None, &defaults);
    assert_eq!(own.document.no_proxy, ["mine.example"]);
    assert_eq!(own.entry(Field::NoProxy), (Source::User, Lock::Open));
    assert_eq!(
        own.document.engine_mirror.as_deref(),
        Some("https://mine.example/llama/")
    );
    assert_eq!(own.entry(Field::EngineMirror), (Source::User, Lock::Open));

    let locked = ManagedNetwork {
        no_proxy: Some(vec!["pinned.example".to_owned()]),
        ..ManagedNetwork::default()
    };
    let over = resolve_layers(&user, Some(&locked), &defaults);
    assert_eq!(over.document.no_proxy, ["pinned.example"]);
    assert_eq!(over.entry(Field::NoProxy), (Source::Policy, Lock::Locked));
}

/// Decision D6: the policy never carries a secret, so the password is the
/// policy's only when the policy pins a proxy that needs none.
#[test]
fn the_credential_is_locked_only_with_a_pinned_proxy_that_needs_none() {
    let user = NetworkDocument::default();
    let locked = |entry: Option<ProxyEntry>| {
        let managed = ManagedNetwork {
            proxy: Some(entry),
            ..ManagedNetwork::default()
        };
        resolve(&user, Some(&managed)).credential_locked()
    };
    assert!(locked(Some(proxy("none", None))), "no sign-in: locked");
    assert!(locked(None), "a pinned direct connection needs no password");
    assert!(
        !locked(Some(proxy("basic", Some("svc")))),
        "the human types it"
    );
    assert!(!locked(Some(proxy("anyauth", Some("svc")))));
    // An unlocked proxy never locks the password.
    let own = NetworkDocument {
        proxy: Some(proxy("none", None)),
        ..NetworkDocument::default()
    };
    assert!(!resolve(&own, None).credential_locked());
}

#[tokio::test]
async fn a_missing_document_is_a_direct_connection() {
    let fixture = fixture().await;
    let settings = fixture.service.settings().await.expect("the default");
    assert!(settings.proxy().is_none());
    assert!(settings.ca_bundle().is_none());
    assert!(settings.no_proxy().is_empty());
    let loaded = fixture.service.load().await.unwrap().expect("valid");
    assert_eq!(loaded.raw, None);
    assert_eq!(loaded.user, NetworkDocument::default());
}

/// Corrupt, unknown-version and invalid documents refuse every consumer
/// with `network_settings_invalid`; none of them reads as "direct".
#[tokio::test]
async fn a_document_that_cannot_be_used_refuses_and_never_falls_back_to_direct() {
    let fixture = fixture().await;
    for (raw, needle) in [
        ("{not json", "do not parse"),
        (r#"{"version":7}"#, "version 7"),
        (
            r#"{"version":1,"proxy":{"url":"socks5://p:1080","auth":"none"}}"#,
            "SOCKS",
        ),
        (
            r#"{"version":1,"engine_mirror":"http://mirror/"}"#,
            "https://",
        ),
        (r#"{"version":1,"extra":1}"#, "unknown field"),
    ] {
        fixture.store.set_setting(SETTING_KEY, raw).await.unwrap();
        fixture.service.invalidate();
        let failure = fixture.service.settings().await.expect_err(raw);
        assert_eq!(failure.cause(), "network_settings_invalid", "{raw}");
        assert!(failure.sentence().contains(needle), "{raw}: {failure}");
        assert!(!failure.recovery().is_empty());
        let invalid = fixture.service.load().await.unwrap().expect_err(raw);
        assert_eq!(invalid.raw.as_deref(), Some(raw));
        let mirrors = fixture.service.mirrors().await.expect_err(raw);
        assert_eq!(mirrors.cause(), "network_settings_invalid");
    }
    // A policy allowlist that does not parse fails closed the same way.
    fixture
        .store
        .set_setting(SETTING_KEY, &NetworkDocument::default().to_json())
        .await
        .unwrap();
    let service = NetworkService::new(
        Arc::clone(&fixture.store),
        None,
        fixture.base.path().to_path_buf(),
    )
    .with_managed(Arc::new(FixedManagedNetwork::new(Some(ManagedNetwork {
        mirror_allowed_hosts: vec!["bad host:1".to_owned()],
        ..ManagedNetwork::default()
    }))));
    let failure = service.settings().await.expect_err("bad allowlist");
    assert_eq!(failure.cause(), "network_settings_invalid");
    assert!(
        failure.sentence().contains("mirror_allowed_hosts"),
        "{failure}"
    );
}

#[tokio::test]
async fn the_password_is_read_from_the_keychain_only_when_the_sign_in_mode_needs_one() {
    let fixture = fixture().await;
    fixture
        .backend
        .set(&account_for(PROXY_CREDENTIAL_ID), PROXY_PASSWORD)
        .unwrap();
    assert_eq!(
        account_for(PROXY_CREDENTIAL_ID),
        "pam.connector.v1.network.proxy"
    );

    // Mode none: the password is not even read, so a keychain failure is
    // no failure.
    let none = NetworkDocument {
        proxy: Some(proxy("none", None)),
        ..NetworkDocument::default()
    };
    fixture.service.save(None, &none).await.unwrap();
    *fixture.backend.fail_with.lock().unwrap() = Some(SecretError::Denied);
    let settings = fixture
        .service
        .settings()
        .await
        .expect("no password needed");
    assert!(!settings.sends_proxy_credential());
    assert_eq!(
        settings.proxy().unwrap().authority(),
        "proxy.corp.example:3128"
    );
    *fixture.backend.fail_with.lock().unwrap() = None;

    // Mode basic with a user name: the stored password is sent.
    let basic = NetworkDocument {
        proxy: Some(proxy("basic", Some("svc"))),
        ..NetworkDocument::default()
    };
    let prior = fixture.service.load().await.unwrap().unwrap().raw;
    assert!(
        fixture
            .service
            .save(prior.as_deref(), &basic)
            .await
            .unwrap()
    );
    let settings = fixture.service.settings().await.expect("resolved");
    assert!(settings.sends_proxy_credential());
    // The profile's Debug keeps the password out.
    assert!(!format!("{settings:?}").contains(PROXY_PASSWORD));

    // A keychain that will not answer refuses the spawn by name, never
    // sends nothing quietly.
    *fixture.backend.fail_with.lock().unwrap() = Some(SecretError::Denied);
    fixture.service.invalidate();
    let failure = fixture
        .service
        .settings()
        .await
        .expect_err("keychain denied");
    assert_eq!(failure.cause(), "network_settings_invalid");
    assert!(failure.sentence().contains("store_denied"), "{failure}");
    *fixture.backend.fail_with.lock().unwrap() = None;

    // No password stored: the proxy will answer 407, which the Test names;
    // the spawn itself is not refused.
    assert!(fixture.service.clear_credential().await.unwrap());
    let settings = fixture
        .service
        .settings()
        .await
        .expect("resolved without a password");
    assert!(!settings.sends_proxy_credential());
    assert_eq!(fixture.service.credential_present().await, (false, true));

    // No keychain at all: a mode that needs one refuses.
    let no_keychain = NetworkService::new(
        Arc::clone(&fixture.store),
        None,
        fixture.base.path().to_path_buf(),
    );
    assert!(!no_keychain.store_available());
    let failure = no_keychain.settings().await.expect_err("no keychain");
    assert!(failure.sentence().contains("unavailable"), "{failure}");
    assert_eq!(no_keychain.credential_present().await, (false, false));
    assert_eq!(
        no_keychain
            .set_credential(crate::secrets::Secret::new("x".to_owned()))
            .await,
        Err(SecretError::Unavailable)
    );
}

#[tokio::test]
async fn ca_import_makes_a_private_digest_named_copy_the_spawn_checks() {
    let fixture = fixture().await;
    let source = ca_source(fixture.base.path());
    let entry = fixture.service.import_ca(&source).await.expect("imported");
    assert_eq!(entry.certificates, 1);
    assert_eq!(entry.sha256.len(), 64);
    assert_eq!(entry.source_path.as_deref(), Some(source.to_str().unwrap()));
    assert!(entry.imported_ts.is_some());

    let copy = fixture.service.copy_path(&entry.sha256);
    assert_eq!(
        copy,
        fixture
            .base
            .path()
            .join("net")
            .join(format!("ca-{}.pem", &entry.sha256[..12]))
    );
    let bytes = std::fs::read(&copy).expect("the private copy exists");
    assert_eq!(sha256_hex(&bytes), entry.sha256);
    assert_eq!(
        pam_net::normalize_pem(&bytes).unwrap().certificates,
        1,
        "the copy is the normalized bundle"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        assert_eq!(
            std::fs::metadata(&copy).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            std::fs::metadata(fixture.service.net_dir())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
    }
    // Importing the same bundle again is the same copy, never a rewrite.
    let again = fixture.service.import_ca(&source).await.unwrap();
    assert_eq!(again.sha256, entry.sha256);
    assert_eq!(fixture.service.source_changed(&entry).await, Some(false));

    // The spawn is pointed at the copy, once its digest matches.
    let document = NetworkDocument {
        ca_bundle: Some(entry.clone()),
        ..NetworkDocument::default()
    };
    fixture.service.save(None, &document).await.unwrap();
    let settings = fixture.service.settings().await.expect("resolved");
    assert_eq!(settings.ca_bundle(), Some(copy.as_path()));

    // A changed copy is refused as tampered; so is a missing one. No
    // direct fallback, no platform trust.
    std::fs::write(
        &copy,
        b"-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n",
    )
    .unwrap();
    fixture.service.invalidate();
    let failure = fixture.service.settings().await.expect_err("tampered");
    assert_eq!(failure, NetFailure::CaBundleTampered);
    assert_eq!(failure.cause(), "network_ca_tampered");
    std::fs::remove_file(&copy).unwrap();
    fixture.service.invalidate();
    assert_eq!(
        fixture.service.settings().await.expect_err("missing"),
        NetFailure::CaBundleTampered
    );
    // The source changed since the import: reported, behaviour unchanged.
    std::fs::write(
        &source,
        std::fs::read(pam_net::testing::unrelated_ca()).unwrap(),
    )
    .unwrap();
    assert_eq!(fixture.service.source_changed(&entry).await, Some(true));
    std::fs::remove_file(&source).unwrap();
    assert_eq!(fixture.service.source_changed(&entry).await, None);
}

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "one refusal table over one temp dir; splitting it hides what is compared"
)]
async fn ca_import_refuses_what_cannot_be_a_bundle_of_certificates_and_writes_nothing() {
    let fixture = fixture().await;
    let dir = fixture.base.path();
    let net_dir = fixture.service.net_dir();
    let copies = || std::fs::read_dir(&net_dir).map_or(0, |entries| entries.flatten().count());

    let key_file = dir.join("with-key.pem");
    std::fs::write(
        &key_file,
        format!(
            "{}{}",
            std::fs::read_to_string(pam_net::testing::test_ca()).unwrap(),
            std::fs::read_to_string(pam_net::testing::fixture("leaf.key")).unwrap()
        ),
    )
    .unwrap();
    let error = fixture
        .service
        .import_ca(&key_file)
        .await
        .expect_err("a key");
    assert_eq!(error, CaImportError::Content(pam_net::CaError::PrivateKey));
    assert!(error.to_string().contains("private key"), "{error}");

    let text = dir.join("notes.txt");
    std::fs::write(&text, "no certificates here").unwrap();
    let error = fixture.service.import_ca(&text).await.expect_err("not pem");
    assert_eq!(
        error,
        CaImportError::Content(pam_net::CaError::NoCertificate)
    );

    let missing = dir.join("absent.pem");
    let error = fixture
        .service
        .import_ca(&missing)
        .await
        .expect_err("absent");
    assert!(
        matches!(error, CaImportError::Source(ref detail) if detail.contains("cannot be opened")),
        "{error}"
    );

    let error = fixture
        .service
        .import_ca(Path::new("relative/ca.pem"))
        .await
        .expect_err("relative");
    assert!(matches!(error, CaImportError::Source(ref detail) if detail.contains("absolute")));

    let error = fixture
        .service
        .import_ca(dir)
        .await
        .expect_err("a directory");
    assert!(matches!(error, CaImportError::Source(ref detail) if detail.contains("regular file")));

    let huge = dir.join("huge.pem");
    std::fs::File::create(&huge)
        .unwrap()
        .set_len(pam_net::ca::MAX_BUNDLE_BYTES + 1)
        .unwrap();
    let error = fixture
        .service
        .import_ca(&huge)
        .await
        .expect_err("too large");
    assert!(matches!(error, CaImportError::Source(ref detail) if detail.contains("at most")));

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let writable = ca_source(dir);
        std::fs::set_permissions(&writable, std::fs::Permissions::from_mode(0o666)).unwrap();
        let error = fixture
            .service
            .import_ca(&writable)
            .await
            .expect_err("world-writable");
        assert!(
            matches!(error, CaImportError::Source(ref detail) if detail.contains("writable")),
            "{error}"
        );
        std::fs::set_permissions(&writable, std::fs::Permissions::from_mode(0o664)).unwrap();
        let error = fixture
            .service
            .import_ca(&writable)
            .await
            .expect_err("group-writable");
        assert!(matches!(error, CaImportError::Source(_)), "{error}");

        // A symlink is followed once, and the resolved file is what is checked.
        let open_dir = dir.join("shared");
        std::fs::create_dir(&open_dir).unwrap();
        let inside = ca_source(&open_dir);
        std::fs::set_permissions(&open_dir, std::fs::Permissions::from_mode(0o777)).unwrap();
        let link = dir.join("link.pem");
        std::os::unix::fs::symlink(&inside, &link).unwrap();
        let error = fixture
            .service
            .import_ca(&link)
            .await
            .expect_err("dir open");
        assert!(
            matches!(error, CaImportError::Source(ref detail) if detail.contains("directory")),
            "{error}"
        );
        std::fs::set_permissions(&open_dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        let entry = fixture
            .service
            .import_ca(&link)
            .await
            .expect("through the link");
        assert_eq!(entry.certificates, 1);
        assert_eq!(copies(), 1);
        std::fs::remove_file(fixture.service.copy_path(&entry.sha256)).unwrap();
    }
    assert_eq!(copies(), 0, "no refusal left a private copy behind");
}

#[tokio::test]
async fn unreferenced_private_copies_are_pruned_and_the_kept_one_stays() {
    let fixture = fixture().await;
    let first = fixture
        .service
        .import_ca(&ca_source(fixture.base.path()))
        .await
        .unwrap();
    let other = fixture.base.path().join("other.pem");
    std::fs::copy(pam_net::testing::unrelated_ca(), &other).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&other, std::fs::Permissions::from_mode(0o644)).unwrap();
    }
    let second = fixture.service.import_ca(&other).await.unwrap();
    assert_ne!(first.sha256, second.sha256);
    let stray = fixture.service.net_dir().join("notes.txt");
    std::fs::write(&stray, "kept: not a copy").unwrap();

    fixture.service.prune_ca_copies(Some(&second.sha256));
    assert!(!fixture.service.copy_path(&first.sha256).exists());
    assert!(fixture.service.copy_path(&second.sha256).exists());
    assert!(stray.exists());
    fixture.service.prune_ca_copies(None);
    assert!(!fixture.service.copy_path(&second.sha256).exists());
}

#[tokio::test]
async fn the_cached_profile_is_dropped_by_every_save_and_credential_change() {
    let fixture = fixture().await;
    let direct = fixture.service.settings().await.unwrap();
    assert!(Arc::ptr_eq(
        &direct,
        &fixture.service.settings().await.unwrap()
    ));

    let with_proxy = NetworkDocument {
        proxy: Some(proxy("basic", Some("svc"))),
        ..NetworkDocument::default()
    };
    assert!(fixture.service.save(None, &with_proxy).await.unwrap());
    let proxied = fixture.service.settings().await.unwrap();
    assert!(!Arc::ptr_eq(&direct, &proxied));
    assert!(proxied.proxy().is_some());
    assert!(!proxied.sends_proxy_credential());

    fixture
        .service
        .set_credential(crate::secrets::Secret::new(PROXY_PASSWORD.to_owned()))
        .await
        .unwrap();
    let with_password = fixture.service.settings().await.unwrap();
    assert!(with_password.sends_proxy_credential());
    assert_eq!(
        fixture
            .backend
            .get(&account_for(PROXY_CREDENTIAL_ID))
            .unwrap()
            .as_deref(),
        Some(PROXY_PASSWORD)
    );

    assert!(fixture.service.clear_credential().await.unwrap());
    assert!(
        !fixture
            .service
            .settings()
            .await
            .unwrap()
            .sends_proxy_credential()
    );

    // A save on stale bytes is refused and changes nothing.
    assert!(
        !fixture
            .service
            .save(None, &NetworkDocument::default())
            .await
            .unwrap()
    );
    assert!(fixture.service.settings().await.unwrap().proxy().is_some());
}

#[test]
fn ignored_environment_names_are_names_from_the_fixed_list_only() {
    for name in ignored_env() {
        assert!(IGNORED_ENV.contains(&name.as_str()), "{name}");
        assert!(!name.contains('='), "names only, never values: {name}");
    }
}

// --- The managed overlay: defaults, closure, the policy handle ---------------

fn service_over(fixture: &Fixture, layer: Arc<FixedManagedNetwork>) -> NetworkService {
    NetworkService::new(
        Arc::clone(&fixture.store),
        Some(Arc::new(SecretStore::new(
            Arc::clone(&fixture.backend) as Arc<_>
        ))),
        fixture.base.path().to_path_buf(),
    )
    .with_managed(layer)
}

#[tokio::test]
async fn unlocked_defaults_reach_the_profile_and_the_mirrors_until_the_human_saves() {
    let fixture = fixture().await;
    let layer = Arc::new(
        FixedManagedNetwork::new(None).with_defaults(ManagedDefaults {
            no_proxy: Some(vec!["corp.example".to_owned()]),
            engine_mirror: Some(Some("https://artifacts.corp.example/llama/".to_owned())),
            models_mirror: None,
        }),
    );
    let service = service_over(&fixture, layer);

    assert_eq!(service.settings().await.unwrap().no_proxy().len(), 1);
    let (engine, models) = service.mirrors().await.unwrap();
    assert_eq!(
        engine.as_ref().map(pam_net::MirrorBase::as_str),
        Some("https://artifacts.corp.example/llama/")
    );
    assert!(models.is_none());
    let loaded = service.load().await.unwrap().expect("valid");
    assert_eq!(
        loaded.resolved.entry(Field::NoProxy),
        (Source::Policy, Lock::Open)
    );
    assert_eq!(
        loaded.user,
        NetworkDocument::default(),
        "the default is never stored"
    );

    // The human's own list replaces the default; the other default stands.
    let saved = NetworkDocument {
        no_proxy: vec!["mine.example".to_owned(), "10.0.0.0/8".to_owned()],
        ..NetworkDocument::default()
    };
    assert!(service.save(None, &saved).await.unwrap());
    assert_eq!(service.settings().await.unwrap().no_proxy().len(), 2);
    assert!(service.mirrors().await.unwrap().0.is_some());
}

/// A closed overlay refuses every consumer, whatever the cache holds, and
/// never answers with a direct connection. The Network screen can still
/// read the settings.
#[tokio::test]
async fn a_closed_overlay_refuses_the_profile_and_the_mirrors_and_names_the_key_and_the_cause() {
    let fixture = fixture().await;
    let layer = Arc::new(FixedManagedNetwork::new(None));
    let service = service_over(&fixture, Arc::clone(&layer));
    service.settings().await.expect("open, and now cached");
    assert!(service.policy_closed().is_none());

    *layer.closed.lock().unwrap() = Some(PolicyClosed {
        key: "network.ca_bundle".to_owned(),
        code: "writable_by_user".to_owned(),
        detail: "the bundle can be modified by this user".to_owned(),
    });
    // Within the cache window: the closure still applies at once.
    let failure = service.settings().await.expect_err("closed");
    assert_eq!(failure.cause(), "network_policy_invalid");
    let sentence = failure.sentence();
    for needle in [
        "organization's policy",
        "network.ca_bundle",
        "writable_by_user",
        "can be modified by this user",
        "administrator",
    ] {
        assert!(sentence.contains(needle), "{needle}: {sentence}");
    }
    let mirrors = service.mirrors().await.expect_err("closed");
    assert_eq!(mirrors.cause(), "network_policy_invalid");
    assert!(mirrors.sentence().contains("network.ca_bundle"));
    assert!(
        service.load().await.unwrap().is_ok(),
        "the screen can still read"
    );
    assert_eq!(
        service.policy_closed().map(|closed| closed.code),
        Some("writable_by_user".to_owned())
    );

    *layer.closed.lock().unwrap() = None;
    service.settings().await.expect("open again");
}

// --- A real policy handle behind the overlay ----------------------------------

/// A policy source the test scripts: the file's bytes and the answer for
/// the referenced CA bundle.
pub(crate) struct Scripted {
    policy: Mutex<Vec<u8>>,
    referenced: Mutex<SourceRead>,
}

impl PolicySource for Scripted {
    fn origin(&self) -> String {
        "/fake/policy.json".to_owned()
    }

    fn read(&self) -> SourceRead {
        SourceRead::Trusted(self.policy.lock().unwrap().clone())
    }

    fn fingerprint(&self) -> Option<Fingerprint> {
        None
    }

    fn read_referenced(&self, _path: &Path, _max_bytes: u64) -> SourceRead {
        self.referenced.lock().unwrap().clone()
    }
}

/// Where a policy pins its bundle: an absolute path on this platform.
pub(crate) fn ca_pin_path() -> &'static str {
    if cfg!(windows) {
        r"C:\ProgramData\PAM\ca\corp-root.pem"
    } else {
        "/Library/Application Support/PAM/ca/corp-root.pem"
    }
}

pub(crate) fn test_ca_pem() -> Vec<u8> {
    std::fs::read(pam_net::testing::test_ca()).expect("the fixture CA")
}

pub(crate) fn normalized_digest(pem: &[u8]) -> String {
    sha256_hex(
        pam_net::normalize_pem(pem)
            .expect("a bundle")
            .pem
            .as_bytes(),
    )
}

/// A policy handle over a scripted trusted file holding `policy`, with
/// `referenced` as the answer for the pinned CA bundle's file, loaded on
/// `base`.
pub(crate) async fn load_policy(
    store: &Arc<Store>,
    base: &Path,
    policy: &serde_json::Value,
    referenced: SourceRead,
) -> Arc<PolicyHandle> {
    let source = Arc::new(Scripted {
        policy: Mutex::new(policy.to_string().into_bytes()),
        referenced: Mutex::new(referenced),
    });
    PolicyHandle::load(Arc::clone(store), source as Arc<dyn PolicySource>, base).await
}

/// A handle over `policy` loaded on the fixture's base, and the network
/// service under it.
async fn under_policy(
    fixture: &Fixture,
    policy: &serde_json::Value,
    referenced: SourceRead,
) -> (Arc<PolicyHandle>, NetworkService) {
    let handle = load_policy(&fixture.store, fixture.base.path(), policy, referenced).await;
    let service = NetworkService::new(
        Arc::clone(&fixture.store),
        Some(Arc::new(SecretStore::new(
            Arc::clone(&fixture.backend) as Arc<_>
        ))),
        fixture.base.path().to_path_buf(),
    )
    .with_policy(Arc::clone(&handle));
    (handle, service)
}

#[tokio::test]
async fn a_policy_locked_proxy_is_the_one_the_profile_uses_and_the_users_is_kept() {
    let fixture = fixture().await;
    let own = NetworkDocument {
        proxy: Some(proxy("none", None)),
        ..NetworkDocument::default()
    };
    fixture
        .store
        .set_setting(SETTING_KEY, &own.to_json())
        .await
        .unwrap();
    let (_, service) = under_policy(
        &fixture,
        &json!({
            "version": 1,
            "network": { "proxy": { "locked": {
                "url": "http://managed.example.com:8080", "auth": "none" } } },
        }),
        SourceRead::Absent,
    )
    .await;

    let settings = service.settings().await.unwrap();
    assert_eq!(settings.proxy().unwrap().host(), "managed.example.com");
    let loaded = service.load().await.unwrap().expect("valid");
    assert_eq!(
        loaded.resolved.entry(Field::Proxy),
        (Source::Policy, Lock::Locked)
    );
    assert!(loaded.resolved.credential_locked());
    assert_eq!(loaded.user, own, "the user's proxy is untouched");
}

#[tokio::test]
async fn a_policy_default_is_used_until_the_human_saves_a_value() {
    let fixture = fixture().await;
    let (_, service) = under_policy(
        &fixture,
        &json!({
            "version": 1,
            "network": {
                "no_proxy": { "default": ["corp.example"] },
                "models_mirror": { "default": "https://artifacts.example.com/hf" },
                "mirror_allowed_hosts": ["artifacts.example.com"],
            },
        }),
        SourceRead::Absent,
    )
    .await;

    assert_eq!(service.settings().await.unwrap().no_proxy().len(), 1);
    let (_, models) = service.mirrors().await.unwrap();
    assert_eq!(
        models.as_ref().map(pam_net::MirrorBase::as_str),
        Some("https://artifacts.example.com/hf/")
    );
    let loaded = service.load().await.unwrap().expect("valid");
    assert_eq!(
        loaded.resolved.entry(Field::NoProxy),
        (Source::Policy, Lock::Open)
    );
    assert_eq!(
        loaded.resolved.entry(Field::ModelsMirror),
        (Source::Policy, Lock::Open)
    );
    assert!(loaded.resolved.locked_fields().is_empty());

    // The human saves a list: it is theirs, and the policy's is not merged.
    let saved = NetworkDocument {
        no_proxy: vec!["mine.example".to_owned(), "10.0.0.0/8".to_owned()],
        ..NetworkDocument::default()
    };
    assert!(service.save(None, &saved).await.unwrap());
    assert_eq!(service.settings().await.unwrap().no_proxy().len(), 2);
    let loaded = service.load().await.unwrap().expect("valid");
    assert_eq!(
        loaded.resolved.entry(Field::NoProxy),
        (Source::User, Lock::Open)
    );
    assert_eq!(
        loaded.resolved.entry(Field::ModelsMirror),
        (Source::Policy, Lock::Open)
    );
}

#[tokio::test]
async fn a_failed_ca_import_closes_connector_calls_and_downloads_with_the_cause() {
    let fixture = fixture().await;
    let pem = test_ca_pem();
    let (handle, service) = under_policy(
        &fixture,
        &json!({
            "version": 1,
            "network": { "ca_bundle": { "locked": {
                "path": ca_pin_path(), "sha256": normalized_digest(&pem) } } },
        }),
        SourceRead::Untrusted {
            code: "writable_by_user",
            detail: "the bundle can be modified by this user".to_owned(),
        },
    )
    .await;
    // The handle, not the view, knows the import failed.
    assert!(handle.view().network_closed().is_none());
    assert_eq!(
        handle.network_closed().unwrap().key.path(),
        "network.ca_bundle"
    );

    let failure = service.settings().await.expect_err("closed");
    assert_eq!(failure.cause(), "network_policy_invalid");
    let sentence = failure.sentence();
    assert!(sentence.contains("network.ca_bundle"), "{sentence}");
    assert!(sentence.contains("writable_by_user"), "{sentence}");
    let mirrors = service.mirrors().await.expect_err("closed");
    assert!(mirrors.sentence().contains("writable_by_user"), "{mirrors}");
    assert!(
        service.load().await.unwrap().is_ok(),
        "the screen can still read"
    );
    assert_eq!(service.policy_closed().unwrap().key, "network.ca_bundle");
}

#[tokio::test]
async fn a_rejected_proxy_with_no_last_good_value_closes_the_network() {
    let fixture = fixture().await;
    // No port: the leaf is rejected, and nothing last-good holds the proxy.
    let (_, service) = under_policy(
        &fixture,
        &json!({
            "version": 1,
            "network": { "proxy": { "locked": { "url": "http://p.example.com", "auth": "none" } } },
        }),
        SourceRead::Absent,
    )
    .await;
    let failure = service.settings().await.expect_err("closed");
    assert_eq!(failure.cause(), "network_policy_invalid");
    assert!(failure.sentence().contains("network.proxy"), "{failure}");
    assert_eq!(
        service.mirrors().await.unwrap_err().cause(),
        "network_policy_invalid"
    );
}

/// The loader imported the pinned bundle; the service re-hashes that private
/// copy on every spawn and never imports a second time.
#[tokio::test]
async fn a_managed_ca_bundle_is_the_loaders_private_copy_checked_on_every_spawn() {
    let fixture = fixture().await;
    let pem = test_ca_pem();
    let digest = normalized_digest(&pem);
    let (handle, service) = under_policy(
        &fixture,
        &json!({
            "version": 1,
            "network": { "ca_bundle": { "locked": { "path": ca_pin_path(), "sha256": digest } } },
        }),
        SourceRead::Trusted(pem),
    )
    .await;
    assert!(handle.network_closed().is_none());

    let settings = service.settings().await.expect("a pinned bundle is usable");
    let copy = service.copy_path(&digest);
    assert_eq!(settings.ca_bundle(), Some(copy.as_path()));
    assert_eq!(
        sha256_hex(&std::fs::read(&copy).unwrap()),
        digest,
        "the copy is the loader's"
    );
    let loaded = service.load().await.unwrap().expect("valid");
    assert_eq!(
        loaded.resolved.entry(Field::CaBundle),
        (Source::Policy, Lock::Locked)
    );
    assert_eq!(
        loaded
            .resolved
            .document
            .ca_bundle
            .as_ref()
            .map(|bundle| bundle.sha256.as_str()),
        Some(digest.as_str())
    );

    // A save by the human prunes unreferenced copies, never the managed one.
    service.prune_ca_copies(None);
    assert!(copy.exists(), "the managed copy outlives a prune");

    // Tampering with the copy is caught at the next spawn.
    std::fs::write(&copy, b"not the bundle").unwrap();
    service.invalidate();
    assert_eq!(
        service.settings().await.expect_err("tampered").cause(),
        "network_ca_tampered"
    );
}
