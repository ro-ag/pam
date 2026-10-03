//! Grammar, key table, merge and fallback rows of the managed policy spec
//! (`docs/specs/2026-10-02-managed-policy-file.md`, "Test strategy").

use std::collections::BTreeSet;
use std::path::Path;

use pam_connectors::ConnectorId;
use pam_model::curator::AgentId;
use pam_net::Url;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::managed_policy::{
    ALL_CODES, CAUSE_POLICY_FROZEN, CAUSE_POLICY_NOT_ALLOWED, CAUSE_SETTING_LOCKED,
    CODE_CONTROL_CHARACTER, CODE_DUPLICATE_KEY, CODE_LIST_TOO_LONG, CODE_MODE_CONFLICT,
    CODE_MODE_MISSING, CODE_MODE_UNSUPPORTED, CODE_NOT_JSON, CODE_NOT_OBJECT, CODE_NOT_UTF8,
    CODE_REASON_TOO_LONG, CODE_RETENTION_PAIR, CODE_STRING_TOO_LONG, CODE_TOO_DEEP, CODE_TOO_LARGE,
    CODE_UNKNOWN_KEY, CODE_VALUE_INVALID, CODE_VERSION_MISSING, CODE_VERSION_UNSUPPORTED,
    CODE_WRONG_TYPE, EngineSource, FileFailure, Inspection, Key, KeyRefusal, LandingCeiling,
    LeafStatus, MAX_LIST_ENTRIES, MAX_POLICY_BYTES, MAX_REASON_CHARS, Mode, ModelSource,
    PolicyView, RECOVERY_MANAGED, SECTIONS, TargetPlatform, Tier, Verdict, clamp_window,
    inspect_bytes, intersect_exact, pattern_matches, stricter,
};
use crate::network_service::Source;
use crate::policy::{CapabilityClass, Profile};
use crate::retention::RetentionSettings;

const MAC: TargetPlatform = TargetPlatform::Macos;
const WIN: TargetPlatform = TargetPlatform::Windows;

fn inspect_for(text: &str, platform: TargetPlatform) -> Inspection {
    inspect_bytes(text.as_bytes(), platform)
}

fn file_error(text: &str) -> FileFailure {
    inspect_for(text, MAC)
        .result
        .expect_err("the document must fail as a whole")
}

fn view_for(document: &Value, platform: TargetPlatform) -> PolicyView {
    inspect_for(&document.to_string(), platform)
        .result
        .expect("the document must parse")
}

fn view(document: &Value) -> PolicyView {
    view_for(document, MAC)
}

/// A version-1 document holding `body`'s sections.
fn doc(body: &Value) -> Value {
    let mut document = json!({ "version": 1 });
    for (name, value) in body.as_object().expect("an object") {
        document[name] = value.clone();
    }
    document
}

/// The code a single key was rejected with.
fn rejected_code(view: &PolicyView, key: Key) -> &'static str {
    match view.status(key) {
        Some(LeafStatus::Rejected { code, .. }) => code,
        other => panic!("{key} should be rejected, is {other:?}"),
    }
}

fn applied(view: &PolicyView, key: Key) -> bool {
    view.status(key) == Some(&LeafStatus::Applied)
}

fn strings(list: &[&str]) -> Vec<String> {
    list.iter().map(|entry| (*entry).to_owned()).collect()
}

/// The spec's macOS sample with its placeholders made real: the CA digest,
/// and `*.example.com` (twice), which the no-proxy grammar refuses (a
/// domain already covers its subdomains), written `example.com`.
fn spec_sample() -> Value {
    json!({
      "version": 1,
      "revision": "2026-10-02.1",
      "organization": "Example Corp",
      "contact": "it-help@example.com",
      "comment": "Engineering laptops baseline",
      "security": {
        "profile": { "floor": "standard", "reason": "SEC-114" },
        "grants": {
          "manual": "allow",
          "remember": "deny",
          "never": ["flow.step:*/merge", "flow.step:*/deploy"],
          "never_classes": ["external"]
        }
      },
      "scopes": {
        "allowed_repository_roots": ["/Users", "/Volumes/Work"],
        "connector_wide": "deny"
      },
      "connectors": {
        "allowed_base_hosts": ["example.com"],
        "disabled": ["jira"]
      },
      "flows": {
        "programs": { "allow": ["git", "cargo", "npm", "node", "make"] },
        "extra_path": { "allow": ["/opt/homebrew/bin", "/usr/local/bin"] },
        "artifacts_root": { "default": "~/pam-artifacts" }
      },
      "landing": {
        "max_permissions": { "merge": false },
        "allowed_github_servers": ["github.example.com"]
      },
      "models": {
        "engine_source": "mirror_only",
        "allowed_sources": ["catalog", "import"],
        "allowed_curators": [],
        "idle_unload_min": { "default": 10, "max": 60 }
      },
      "retention": {
        "evidence_days": { "max": 90 },
        "audit_days": { "min": 365 }
      },
      "network": {
        "proxy": { "locked": { "url": "http://proxy.example.com:8080", "auth": "none" } },
        "no_proxy": { "locked": ["example.com", "10.0.0.0/8"] },
        "ca_bundle": { "locked": { "path": "/Library/Application Support/PAM/ca/corp-root.pem",
                                   "sha256": "ab".repeat(32) } },
        "engine_mirror": { "locked": "https://artifacts.example.com/llama.cpp" },
        "models_mirror": { "default": "https://artifacts.example.com/hf" },
        "mirror_allowed_hosts": ["artifacts.example.com"]
      },
      "service": { "require_login_unit": true }
    })
}

// --- Key table ----------------------------------------------------------

#[test]
fn every_key_is_listed_once_with_a_tier_and_a_refusal() {
    let mut paths = BTreeSet::new();
    for (index, key) in Key::ALL.into_iter().enumerate() {
        assert_eq!(key.ordinal(), index, "{key} is out of place in Key::ALL");
        assert!(paths.insert(key.path()), "{key} has a duplicate path");
        assert_eq!(Key::parse(key.path()), Some(key));
        // A tier and a refusal for every key: the matches are exhaustive,
        // so a new variant does not compile without them; this asserts the
        // answers are the deliberate ones below.
        let _ = key.tier();
        match key.refusal() {
            KeyRefusal::ByMode => {
                assert!(!key.is_plain(), "{key}: a mode refusal needs modes");
                assert_eq!(
                    key.refusal().cause(Mode::Locked),
                    Some(CAUSE_SETTING_LOCKED)
                );
                assert_eq!(
                    key.refusal().cause(Mode::Max),
                    Some(CAUSE_POLICY_NOT_ALLOWED)
                );
            }
            KeyRefusal::Fixed(cause) => {
                assert!(key.is_plain(), "{key}: a fixed refusal is for plain keys");
                assert!(!cause.is_empty());
            }
            KeyRefusal::Never => assert!(
                matches!(
                    key,
                    Key::Revision
                        | Key::Organization
                        | Key::Contact
                        | Key::Comment
                        | Key::ServiceRequireLoginUnit
                ),
                "{key} must name the cause it refuses with"
            ),
        }
        if let Some(section) = key.section() {
            assert!(SECTIONS.contains(&section), "{key} is in no section");
        }
    }
}

#[test]
fn tiers_match_the_spec() {
    let tier_a = [
        "security.profile",
        "security.grants.manual",
        "security.grants.remember",
        "security.grants.never",
        "security.grants.never_classes",
        "scopes.allowed_repository_roots",
        "scopes.connector_wide",
        "connectors.allowed_base_hosts",
        "connectors.disabled",
        "flows.programs",
        "flows.extra_path",
        "flows.read_cache_roots",
        "landing.max_permissions",
        "landing.allowed_github_servers",
        "models.allowed_sources",
        "models.allowed_curators",
        "retention.evidence_days",
        "retention.audit_days",
        "network.proxy",
        "network.no_proxy",
        "network.ca_bundle",
    ];
    for key in Key::ALL {
        let expected = if tier_a.contains(&key.path()) {
            Tier::A
        } else {
            Tier::B
        };
        assert_eq!(key.tier(), expected, "{key}");
    }
}

#[test]
fn codes_are_unique_and_stable() {
    let unique: BTreeSet<_> = ALL_CODES.iter().collect();
    assert_eq!(unique.len(), ALL_CODES.len());
    for code in ALL_CODES {
        assert!(code.starts_with("policy_"), "{code}");
    }
    // The wire words other components and MDM scripts read.
    assert_eq!(CODE_DUPLICATE_KEY, "policy_duplicate_key");
    assert_eq!(CODE_VERSION_UNSUPPORTED, "policy_version_unsupported");
    assert_eq!(CODE_UNKNOWN_KEY, "policy_unknown_key");
    assert_eq!(CAUSE_POLICY_FROZEN, "policy_frozen");
    assert_eq!(CAUSE_POLICY_NOT_ALLOWED, "policy_not_allowed");
    assert_eq!(CAUSE_SETTING_LOCKED, "setting_locked");
}

// --- Grammar: file level ------------------------------------------------

#[test]
fn the_spec_sample_parses_with_no_rejected_leaf() {
    let inspection = inspect_for(&spec_sample().to_string(), MAC);
    assert_eq!(inspection.verdict(), Verdict::Valid, "{inspection:?}");
    let view = inspection.result.expect("valid");
    assert_eq!(view.meta().organization.as_deref(), Some("Example Corp"));
    assert_eq!(view.rejected_leaves(), 0);
    assert_eq!(view.engine_source(), EngineSource::MirrorOnly);
    assert!(view.require_login_unit());
}

#[test]
fn a_wildcard_host_rule_is_a_rejected_leaf_not_a_file_failure() {
    let mut sample = spec_sample();
    sample["connectors"]["allowed_base_hosts"] = json!(["*.example.com"]);
    let view = view(&sample);
    assert_eq!(
        rejected_code(&view, Key::ConnectorsAllowedBaseHosts),
        CODE_VALUE_INVALID
    );
    assert_eq!(view.rejected_leaves(), 1);
    assert!(applied(&view, Key::SecurityProfile));
}

#[test]
fn digest_is_sha256_of_the_raw_bytes_bom_included() {
    let text = r#"{"version":1}"#;
    let mut bytes = b"\xEF\xBB\xBF".to_vec();
    bytes.extend_from_slice(text.as_bytes());
    let inspection = inspect_bytes(&bytes, MAC);
    assert!(inspection.result.is_ok(), "a BOM is accepted");
    assert_eq!(inspection.digest, hex::encode(Sha256::digest(&bytes)));
    assert_ne!(
        inspection.digest,
        hex::encode(Sha256::digest(text.as_bytes()))
    );
    let view = inspection.result.expect("valid");
    assert_eq!(view.digest(), Some(inspection.digest.as_str()));
    assert_eq!(view.digest12(), Some(&inspection.digest[..12]));
}

#[test]
fn crlf_line_endings_parse() {
    let text = "{\r\n  \"version\": 1,\r\n  \"organization\": \"Example\"\r\n}\r\n";
    assert_eq!(inspect_for(text, MAC).verdict(), Verdict::Valid);
}

#[test]
fn size_limit_is_exactly_64_kib() {
    let head = r#"{"version":1,"comment":"x"}"#;
    let mut exact = head.to_owned();
    exact.push_str(&" ".repeat(MAX_POLICY_BYTES - head.len()));
    assert_eq!(exact.len(), MAX_POLICY_BYTES);
    assert_eq!(inspect_for(&exact, MAC).verdict(), Verdict::Valid);
    exact.push(' ');
    assert_eq!(file_error(&exact).code, CODE_TOO_LARGE);
}

#[test]
fn duplicate_keys_fail_the_file_at_any_depth() {
    for text in [
        r#"{"version":1,"version":1}"#,
        r#"{"version":1,"security":{"profile":{"locked":"strict"},"profile":{"locked":"relaxed"}}}"#,
        r#"{"version":1,"security":{"profile":{"locked":"strict","locked":"relaxed"}}}"#,
        r#"{"version":1,"network":{"proxy":{"locked":{"url":"http://p:1","url":"http://q:1","auth":"none"}}}}"#,
    ] {
        let failure = file_error(text);
        assert_eq!(failure.code, CODE_DUPLICATE_KEY, "{text}: {failure}");
    }
}

#[test]
fn versions_other_than_one_fail_the_file() {
    assert_eq!(
        file_error(r#"{"organization":"x"}"#).code,
        CODE_VERSION_MISSING
    );
    for version in ["0", "2", "\"1\"", "1.5", "-1", "null"] {
        let failure = file_error(&format!(r#"{{"version":{version}}}"#));
        assert_eq!(failure.code, CODE_VERSION_UNSUPPORTED, "{version}");
    }
    assert!(file_error(r#"{"version":2}"#).detail.contains("version 2"));
}

#[test]
fn malformed_files_fail_with_their_own_codes() {
    assert_eq!(file_error(r#"{"version":"#).code, CODE_NOT_JSON);
    assert_eq!(file_error(r#"{"version":1} trailing"#).code, CODE_NOT_JSON);
    assert_eq!(file_error("[1]").code, CODE_NOT_OBJECT);
    assert_eq!(file_error("").code, CODE_NOT_JSON);
    let not_utf8 = inspect_bytes(b"{\"version\":1,\"comment\":\"\xff\"}", MAC);
    assert_eq!(not_utf8.result.expect_err("bad utf-8").code, CODE_NOT_UTF8);
    let deep = format!(
        r#"{{"version":1,"comment":{}1{}}}"#,
        "[".repeat(12),
        "]".repeat(12)
    );
    assert_eq!(file_error(&deep).code, CODE_TOO_DEEP);
}

// --- Grammar: leaf level ------------------------------------------------

#[test]
fn unknown_keys_are_rejected_at_every_depth_never_ignored() {
    let view = view(&doc(&json!({
        "telemetry": true,
        "security": {
            "profile": { "locked": "strict", "note": "x" },
            "grants": { "manual": "deny", "everything": "deny" },
            "colour": "blue"
        },
        "landing": { "max_permissions": { "merge": false, "deploy": false } },
        "network": { "proxy": { "locked": { "url": "http://p.example.com:3128", "auth": "none", "pac": "x" } } },
        "gadgets": {}
    })));
    let keys: BTreeSet<&str> = view
        .diagnostics()
        .iter()
        .filter(|diagnostic| diagnostic.code == CODE_UNKNOWN_KEY)
        .map(|diagnostic| diagnostic.key.as_str())
        .collect();
    for expected in [
        "telemetry",
        "gadgets",
        "security.grants.everything",
        "security.colour",
        "security.profile",
        "landing.max_permissions",
    ] {
        assert!(keys.contains(expected), "{expected} not in {keys:?}");
    }
    assert_eq!(rejected_code(&view, Key::NetworkProxy), CODE_WRONG_TYPE);
    assert!(applied(&view, Key::GrantsManual), "a sibling still applies");
    assert_eq!(
        inspect_for(&doc(&json!({"telemetry": true})).to_string(), MAC).verdict(),
        Verdict::LeafProblems
    );
}

#[test]
fn a_dotted_name_cannot_reach_a_key_by_a_second_spelling() {
    let view = view(&doc(&json!({
        "security.profile": { "locked": "relaxed" },
        "security": { "grants.manual": "allow" }
    })));
    assert_eq!(view.status(Key::SecurityProfile), None);
    assert_eq!(view.status(Key::GrantsManual), None);
    assert_eq!(view.diagnostics().len(), 2);
}

#[test]
fn every_key_rejects_a_value_of_the_wrong_type() {
    for key in Key::ALL {
        let mut document = json!({ "version": 1 });
        let mut slot = &mut document;
        let segments: Vec<&str> = key.path().split('.').collect();
        for segment in &segments[..segments.len() - 1] {
            if slot.get(*segment).is_none() {
                slot[*segment] = json!({});
            }
            slot = &mut slot[*segment];
        }
        slot[segments[segments.len() - 1]] = json!(7);
        let view = view(&document);
        assert_eq!(rejected_code(&view, key), CODE_WRONG_TYPE, "{key}");
    }
}

#[test]
fn a_section_of_the_wrong_type_rejects_every_key_in_it() {
    let view = view(&doc(&json!({ "security": 5 })));
    for key in [
        Key::SecurityProfile,
        Key::GrantsManual,
        Key::GrantsRemember,
        Key::GrantsNever,
        Key::GrantsNeverClasses,
    ] {
        assert_eq!(rejected_code(&view, key), CODE_WRONG_TYPE, "{key}");
    }
    let view = view.with_fallback(None);
    assert!(view.is_held(Key::SecurityProfile));
}

#[test]
fn mode_objects_are_checked_for_shape() {
    let cases = [
        (
            json!({ "locked": "strict", "floor": "standard" }),
            CODE_MODE_CONFLICT,
        ),
        (json!({ "reason": "SEC-1" }), CODE_MODE_MISSING),
        (json!({}), CODE_MODE_MISSING),
        (json!({ "allow": ["strict"] }), CODE_MODE_UNSUPPORTED),
        (json!({ "floor": "lenient" }), CODE_VALUE_INVALID),
        (
            json!({ "floor": "strict", "default": "relaxed" }),
            CODE_MODE_CONFLICT,
        ),
        (json!({ "locked": "strict", "reason": 5 }), CODE_WRONG_TYPE),
    ];
    for (leaf, code) in cases {
        let view = view(&doc(&json!({ "security": { "profile": leaf.clone() } })));
        assert_eq!(rejected_code(&view, Key::SecurityProfile), code, "{leaf}");
    }
    let ok = view(&doc(&json!({ "security": { "profile":
        { "floor": "standard", "default": "strict", "reason": "SEC-114" } } })));
    assert!(applied(&ok, Key::SecurityProfile));
    assert_eq!(
        ok.modes(Key::SecurityProfile),
        &[Mode::Default, Mode::Floor]
    );
}

#[test]
fn default_combines_with_bounds_and_must_sit_inside_them() {
    let ok = view(&doc(
        &json!({ "models": { "idle_unload_min": { "default": 10, "min": 5, "max": 60 } } }),
    ));
    assert!(applied(&ok, Key::ModelsIdleUnloadMin));
    for leaf in [
        json!({ "default": 90, "max": 60 }),
        json!({ "default": 2, "min": 5 }),
        json!({ "min": 61, "max": 60 }),
        json!({ "default": 0, "max": 60 }),
    ] {
        let view = view(&doc(
            &json!({ "models": { "idle_unload_min": leaf.clone() } }),
        ));
        assert_eq!(
            rejected_code(&view, Key::ModelsIdleUnloadMin),
            CODE_MODE_CONFLICT,
            "{leaf}"
        );
    }
    let forever_under_max = view(&doc(
        &json!({ "retention": { "audit_days": { "default": null, "max": 30 } } }),
    ));
    assert_eq!(
        rejected_code(&forever_under_max, Key::RetentionAuditDays),
        CODE_MODE_CONFLICT
    );
}

#[test]
fn list_and_string_limits() {
    let programs: Vec<String> = (0..MAX_LIST_ENTRIES).map(|n| format!("tool{n}")).collect();
    let ok = view(&doc(
        &json!({ "flows": { "programs": { "allow": programs } } }),
    ));
    assert!(applied(&ok, Key::FlowsPrograms));
    let too_many: Vec<String> = (0..=MAX_LIST_ENTRIES).map(|n| format!("tool{n}")).collect();
    let view_long = view(&doc(
        &json!({ "flows": { "programs": { "allow": too_many } } }),
    ));
    assert_eq!(
        rejected_code(&view_long, Key::FlowsPrograms),
        CODE_LIST_TOO_LONG
    );

    let long = view(&doc(&json!({ "organization": "x".repeat(1025) })));
    assert_eq!(
        rejected_code(&long, Key::Organization),
        CODE_STRING_TOO_LONG
    );
    let fits = view(&doc(&json!({ "organization": "x".repeat(1024) })));
    assert!(applied(&fits, Key::Organization));

    let control = view(&doc(&json!({ "contact": "help\u{1}desk" })));
    assert_eq!(
        rejected_code(&control, Key::Contact),
        CODE_CONTROL_CHARACTER
    );

    let reason = |chars: usize| {
        view(&doc(&json!({ "security": { "profile":
            { "locked": "strict", "reason": "é".repeat(chars) } } })))
    };
    assert!(applied(&reason(MAX_REASON_CHARS), Key::SecurityProfile));
    assert_eq!(
        rejected_code(&reason(MAX_REASON_CHARS + 1), Key::SecurityProfile),
        CODE_REASON_TOO_LONG
    );
}

#[test]
fn the_policy_program_list_is_held_to_the_humans_rule() {
    for bad in ["bash", "CMD.EXE", "/usr/bin/git", r"tools\git", ""] {
        let view = view(&doc(
            &json!({ "flows": { "programs": { "allow": ["git", bad] } } }),
        ));
        assert_eq!(
            rejected_code(&view, Key::FlowsPrograms),
            CODE_VALUE_INVALID,
            "{bad:?}"
        );
    }
    let locked = view(&doc(
        &json!({ "flows": { "programs": { "locked": ["git", " git ", "cargo"] } } }),
    ));
    let leaf = locked.policy().programs.clone().expect("applied");
    assert_eq!(
        leaf.locked,
        Some(strings(&["git", "cargo"])),
        "trimmed and deduplicated"
    );
}

#[test]
fn network_leaves_reuse_the_network_validators() {
    let cases = [
        (
            json!({ "proxy": { "locked": { "url": "socks5://p.example.com:1080", "auth": "none" } } }),
            Key::NetworkProxy,
        ),
        (
            json!({ "proxy": { "locked": { "url": "http://p.example.com", "auth": "none" } } }),
            Key::NetworkProxy,
        ),
        (
            json!({ "proxy": { "locked": { "url": "http://p.example.com:1", "auth": "kerberos" } } }),
            Key::NetworkProxy,
        ),
        (
            json!({ "no_proxy": { "locked": ["<local>"] } }),
            Key::NetworkNoProxy,
        ),
        (
            json!({ "ca_bundle": { "locked": { "path": "/etc/ca.pem", "sha256": "abc" } } }),
            Key::NetworkCaBundle,
        ),
        (
            json!({ "ca_bundle": { "locked": { "path": "ca.pem", "sha256": "ab".repeat(32) } } }),
            Key::NetworkCaBundle,
        ),
        (
            json!({ "engine_mirror": { "locked": "http://mirror.example.com/" } }),
            Key::NetworkEngineMirror,
        ),
        (
            json!({ "models_mirror": { "default": "https://127.0.0.1/hf" } }),
            Key::NetworkModelsMirror,
        ),
    ];
    for (network, key) in cases {
        let view = view(&doc(&json!({ "network": network.clone() })));
        assert_eq!(rejected_code(&view, key), CODE_VALUE_INVALID, "{network}");
    }
    let ok = view(&doc(&json!({ "network": {
        "proxy": { "locked": { "url": "HTTP://Proxy.Example.com:8080", "auth": "basic", "username": "svc" } },
        "ca_bundle": { "locked": { "path": "/etc/ca.pem", "sha256": "AB".repeat(32) } }
    } })));
    let proxy = ok
        .policy()
        .proxy
        .clone()
        .expect("applied")
        .locked
        .expect("locked")
        .expect("a proxy");
    assert_eq!(proxy.url, "http://proxy.example.com:8080");
    assert_eq!(proxy.auth, "basic");
    let pin = ok
        .policy()
        .ca_bundle
        .clone()
        .expect("applied")
        .locked
        .expect("locked")
        .expect("a pin");
    assert_eq!(pin.sha256, "ab".repeat(32));
    let direct = view(&doc(&json!({ "network": { "proxy": { "locked": null } } })));
    assert_eq!(
        direct.managed_network().expect("managed").proxy,
        Some(None),
        "a locked null pins a direct connection"
    );
}

#[test]
fn a_mirror_outside_the_allowed_hosts_is_a_tier_b_rejection() {
    let view = view(&doc(&json!({ "network": {
        "mirror_allowed_hosts": ["artifacts.example.com"],
        "engine_mirror": { "locked": "https://artifactz.example.com/llama.cpp" },
        "models_mirror": { "locked": "https://cdn.artifacts.example.com/hf" }
    } })));
    assert_eq!(
        rejected_code(&view, Key::NetworkEngineMirror),
        CODE_VALUE_INVALID
    );
    assert!(
        applied(&view, Key::NetworkModelsMirror),
        "a subdomain is covered"
    );
    let view = view.with_fallback(None);
    assert_eq!(
        rejected_code(&view, Key::NetworkEngineMirror),
        CODE_VALUE_INVALID
    );
    assert!(
        !view.is_held(Key::NetworkEngineMirror),
        "Tier B is never held"
    );
    let empty = super::managed_policy_test::view(&doc(
        &json!({ "network": { "mirror_allowed_hosts": [] } }),
    ));
    assert_eq!(
        rejected_code(&empty, Key::NetworkMirrorAllowedHosts),
        CODE_VALUE_INVALID
    );
}

#[test]
fn paths_are_checked_for_the_target_platform() {
    let mac = json!({ "scopes": { "allowed_repository_roots": ["/Users"] } });
    let win =
        json!({ "scopes": { "allowed_repository_roots": [r"C:\Users", r"\\server\share\repos"] } });
    assert!(applied(
        &view_for(&doc(&mac), MAC),
        Key::ScopesAllowedRepositoryRoots
    ));
    assert!(applied(
        &view_for(&doc(&win), WIN),
        Key::ScopesAllowedRepositoryRoots
    ));
    assert_eq!(
        rejected_code(
            &view_for(&doc(&mac), WIN),
            Key::ScopesAllowedRepositoryRoots
        ),
        CODE_VALUE_INVALID
    );
    assert_eq!(
        rejected_code(
            &view_for(&doc(&win), MAC),
            Key::ScopesAllowedRepositoryRoots
        ),
        CODE_VALUE_INVALID
    );
    for bad in ["/Users/../etc", "relative/dir", "~/repos"] {
        let view = view(&doc(
            &json!({ "scopes": { "allowed_repository_roots": [bad] } }),
        ));
        assert_eq!(
            rejected_code(&view, Key::ScopesAllowedRepositoryRoots),
            CODE_VALUE_INVALID,
            "{bad}"
        );
    }
    let home = view(&doc(
        &json!({ "flows": { "artifacts_root": { "locked": "~/pam-artifacts" } } }),
    ));
    assert!(
        applied(&home, Key::FlowsArtifactsRoot),
        "~ is fine where the human may use it"
    );
}

#[test]
fn plain_names_are_checked_against_the_closed_lists() {
    let cases = [
        (
            json!({ "connectors": { "disabled": ["aws"] } }),
            Key::ConnectorsDisabled,
        ),
        (
            json!({ "models": { "allowed_curators": ["cursor"] } }),
            Key::ModelsAllowedCurators,
        ),
        (
            json!({ "models": { "allowed_sources": ["torrent"] } }),
            Key::ModelsAllowedSources,
        ),
        (
            json!({ "models": { "engine_source": "build" } }),
            Key::ModelsEngineSource,
        ),
        (
            json!({ "security": { "grants": { "never_classes": ["read_only"] } } }),
            Key::GrantsNeverClasses,
        ),
        (
            json!({ "security": { "grants": { "never": ["flow.step:[a]/x"] } } }),
            Key::GrantsNever,
        ),
        (
            json!({ "security": { "grants": { "never": ["Flow.Run"] } } }),
            Key::GrantsNever,
        ),
        (
            json!({ "security": { "grants": { "manual": "maybe" } } }),
            Key::GrantsManual,
        ),
        (
            json!({ "scopes": { "connector_wide": "allow" } }),
            Key::ScopesConnectorWide,
        ),
        (
            json!({ "retention": { "audit_days": { "min": 0 } } }),
            Key::RetentionAuditDays,
        ),
        (
            json!({ "retention": { "audit_days": { "locked": 3651 } } }),
            Key::RetentionAuditDays,
        ),
        (
            json!({ "models": { "idle_unload_min": { "max": 0 } } }),
            Key::ModelsIdleUnloadMin,
        ),
    ];
    for (body, key) in cases {
        let view = view(&doc(&body));
        assert_eq!(rejected_code(&view, key), CODE_VALUE_INVALID, "{body}");
    }
}

// --- Merges -------------------------------------------------------------

#[test]
fn profile_floor_against_every_user_and_floor_pair() {
    use Profile::{Relaxed, Standard, Strict};
    let table = [
        (Relaxed, Relaxed, Relaxed),
        (Relaxed, Standard, Standard),
        (Relaxed, Strict, Strict),
        (Standard, Relaxed, Standard),
        (Standard, Standard, Standard),
        (Standard, Strict, Strict),
        (Strict, Relaxed, Strict),
        (Strict, Standard, Strict),
        (Strict, Strict, Strict),
    ];
    for (user, floor, expected) in table {
        assert_eq!(stricter(user, floor), expected);
        let view = view(&doc(
            &json!({ "security": { "profile": { "floor": floor.as_str() } } }),
        ));
        let (effective, entry) = view.effective_profile(Some(user));
        assert_eq!(effective, expected, "user {user:?} floor {floor:?}");
        assert_eq!(entry.clamped, effective != user);
        assert_eq!(
            entry.source,
            if entry.clamped {
                Source::Policy
            } else {
                Source::User
            }
        );
        assert!(!entry.locked);
        assert_eq!(entry.constraint, Some(json!({ "floor": floor.as_str() })));
        assert_eq!(view.check_profile(user).is_ok(), effective == user);
        if let Err(refusal) = view.check_profile(user) {
            assert_eq!(refusal.cause, CAUSE_POLICY_NOT_ALLOWED);
        }
    }
}

#[test]
fn profile_lock_and_default() {
    let locked = view(&doc(
        &json!({ "security": { "profile": { "locked": "strict", "reason": "SEC-114" } } }),
    ));
    for user in [None, Some(Profile::Relaxed), Some(Profile::Strict)] {
        let (effective, entry) = locked.effective_profile(user);
        assert_eq!(effective, Profile::Strict);
        assert!(entry.locked);
        assert_eq!(entry.source, Source::Policy);
        assert_eq!(entry.reason.as_deref(), Some("SEC-114"));
    }
    let refusal = locked.check_profile(Profile::Strict).expect_err("locked");
    assert_eq!(refusal.cause, CAUSE_SETTING_LOCKED);

    let defaulted = view(&doc(
        &json!({ "security": { "profile": { "default": "standard" } } }),
    ));
    assert_eq!(defaulted.effective_profile(None).0, Profile::Standard);
    assert_eq!(defaulted.effective_profile(None).1.source, Source::Policy);
    let (effective, entry) = defaulted.effective_profile(Some(Profile::Relaxed));
    assert_eq!(
        effective,
        Profile::Relaxed,
        "a default never replaces a user value"
    );
    assert_eq!(entry.source, Source::User);
    assert!(defaulted.check_profile(Profile::Relaxed).is_ok());

    let unmanaged = PolicyView::unmanaged();
    assert_eq!(
        unmanaged.effective_profile(None).0,
        Profile::platform_default()
    );
    assert_eq!(
        unmanaged
            .effective_profile(Some(Profile::Strict))
            .1
            .to_json(),
        json!({ "source": "user", "locked": false })
    );
}

#[test]
fn numeric_clamp_table() {
    let table: [[Option<u64>; 4]; 9] = [
        [Some(30), None, None, Some(30)],
        [Some(30), Some(60), None, Some(60)],
        [Some(30), None, Some(10), Some(10)],
        [Some(30), Some(10), Some(60), Some(30)],
        [None, None, None, None],
        [None, Some(365), None, None],
        [None, None, Some(90), Some(90)],
        [None, Some(10), Some(90), Some(90)],
        [Some(0), Some(5), None, Some(5)],
    ];
    for [value, min, max, expected] in table {
        assert_eq!(
            clamp_window(value, min, max),
            expected,
            "{value:?} [{min:?}, {max:?}]"
        );
    }
}

#[test]
fn bounded_windows_lock_clamp_and_default() {
    let view = view(&doc(&json!({ "retention": {
        "evidence_days": { "max": 90, "reason": "GDPR" },
        "audit_days": { "min": 365 }
    } })));
    let key = Key::RetentionEvidenceDays;
    let (value, entry) = view.effective_window(key, Some(None), None);
    assert_eq!(value, Some(90), "forever becomes the max");
    assert!(entry.clamped);
    assert_eq!(entry.mode, Some(Mode::Max));
    assert_eq!(entry.to_json()["constraint"], json!({ "max": 90 }));
    assert_eq!(entry.to_json()["reason"], json!("GDPR"));
    assert_eq!(view.effective_window(key, Some(Some(30)), None).0, Some(30));
    assert!(view.check_window(key, Some(30)).is_ok());
    assert_eq!(
        view.check_window(key, None).expect_err("forever").cause,
        CAUSE_POLICY_NOT_ALLOWED
    );
    assert_eq!(
        view.check_window(key, Some(91)).expect_err("over").cause,
        CAUSE_POLICY_NOT_ALLOWED
    );
    let audit = Key::RetentionAuditDays;
    let (value, entry) = view.effective_window(audit, Some(Some(30)), None);
    assert_eq!((value, entry.mode), (Some(365), Some(Mode::Min)));
    assert_eq!(
        view.effective_window(audit, Some(None), None).0,
        None,
        "forever is above any min"
    );

    let idle = super::managed_policy_test::view(&doc(
        &json!({ "models": { "idle_unload_min": { "default": 10, "max": 60 } } }),
    ));
    assert_eq!(idle.effective_idle_unload_min(None, 10).0, 10);
    assert_eq!(
        idle.effective_idle_unload_min(Some(0), 10).0,
        60,
        "never becomes the max"
    );
    assert_eq!(idle.effective_idle_unload_min(Some(90), 10).0, 60);
    assert_eq!(idle.effective_idle_unload_min(Some(5), 10).0, 5);
    let never = super::managed_policy_test::view(&doc(
        &json!({ "models": { "idle_unload_min": { "locked": 0 } } }),
    ));
    let (minutes, entry) = never.effective_idle_unload_min(Some(5), 10);
    assert_eq!(minutes, 0);
    assert!(entry.locked);
}

#[test]
fn retention_pair_that_breaks_evidence_le_audit_is_a_rejected_leaf() {
    for retention in [
        json!({ "evidence_days": { "locked": 400 }, "audit_days": { "max": 365 } }),
        json!({ "evidence_days": { "min": 100 }, "audit_days": { "locked": 30 } }),
        json!({ "evidence_days": { "default": 60 }, "audit_days": { "default": 30 } }),
    ] {
        let view = view(&doc(&json!({ "retention": retention.clone() })));
        assert_eq!(
            rejected_code(&view, Key::RetentionEvidenceDays),
            CODE_RETENTION_PAIR,
            "{retention}"
        );
        assert!(applied(&view, Key::RetentionAuditDays));
        assert!(view.policy().evidence_days.is_none());
    }
    let forever_evidence = view(&doc(&json!({ "retention": {
        "evidence_days": { "locked": null }, "audit_days": { "max": 30 } } })));
    assert!(
        applied(&forever_evidence, Key::RetentionEvidenceDays),
        "forever evidence is bounded by audit"
    );
}

#[test]
fn effective_retention_keeps_the_pair_in_order() {
    let view = view(&doc(
        &json!({ "retention": { "audit_days": { "max": 30 } } }),
    ));
    let (pair, [evidence, audit]) = view.effective_retention(Some(Some(60)), Some(Some(90)));
    assert_eq!(
        pair,
        RetentionSettings {
            evidence_days: Some(30),
            audit_days: Some(30)
        }
    );
    assert!(evidence.clamped && audit.clamped);

    let floor = super::managed_policy_test::view(&doc(
        &json!({ "retention": { "evidence_days": { "min": 100 } } }),
    ));
    let (pair, _) = floor.effective_retention(Some(Some(10)), Some(Some(50)));
    assert_eq!(
        pair,
        RetentionSettings {
            evidence_days: Some(100),
            audit_days: Some(100)
        },
        "records are kept longer, never shorter"
    );
    let (pair, _) = floor.effective_retention(None, None);
    assert_eq!(
        pair,
        RetentionSettings::default(),
        "forever stays forever above a min"
    );
}

#[test]
fn allow_intersects_and_locked_replaces() {
    let user = strings(&["git", "cargo", "python3"]);
    assert_eq!(
        intersect_exact(&user, &strings(&["git", "make"])),
        strings(&["git"])
    );
    assert!(intersect_exact(&user, &strings(&["make"])).is_empty());

    let view = view(&doc(
        &json!({ "flows": { "programs": { "allow": ["git", "cargo", "make"] } } }),
    ));
    let (programs, entry) = view.effective_programs(&user);
    assert_eq!(programs, strings(&["git", "cargo"]));
    assert!(entry.clamped);
    assert_eq!(
        entry.to_json()["constraint"],
        json!({ "allow": ["git", "cargo", "make"] })
    );
    let refusal = view
        .check_list(Key::FlowsPrograms, &user, None)
        .expect_err("python3 is outside");
    assert_eq!(refusal.cause, CAUSE_POLICY_NOT_ALLOWED);
    assert!(refusal.detail.contains("python3"));
    assert!(
        view.check_list(Key::FlowsPrograms, &strings(&["git"]), None)
            .is_ok()
    );
    let (none, _) = view.effective_programs(&strings(&["node"]));
    assert!(
        none.is_empty(),
        "an empty intersection is empty, never the default"
    );

    let locked = super::managed_policy_test::view(&doc(
        &json!({ "flows": { "programs": { "locked": ["git"] } } }),
    ));
    let (programs, entry) = locked.effective_programs(&user);
    assert_eq!(programs, strings(&["git"]));
    assert!(entry.locked);
    assert_eq!(
        locked
            .check_list(Key::FlowsPrograms, &user, None)
            .expect_err("locked")
            .cause,
        CAUSE_SETTING_LOCKED
    );
}

#[test]
fn path_prefixes_compare_by_component() {
    let view = view(&doc(&json!({
        "scopes": { "allowed_repository_roots": ["/Users", "/Volumes/Work"] },
        "flows": { "extra_path": { "allow": ["/opt/homebrew/bin", "~/.cargo"] } }
    })));
    assert!(view.repository_root_allowed(Path::new("/Users/dev/repo")));
    assert!(view.repository_root_allowed(Path::new("/Users")));
    assert!(!view.repository_root_allowed(Path::new("/UsersX/repo")));
    assert!(!view.repository_root_allowed(Path::new("/Volumes/WorkOther")));
    assert!(view.repository_root_allowed(Path::new("/Volumes/Work/a")));

    let home = Path::new("/Users/dev");
    let user = strings(&[
        "~/.cargo/bin",
        "/opt/homebrew/bin",
        "/opt/homebrew/binx",
        "/usr/local/bin",
    ]);
    let (kept, entry) = view.effective_path_list(Key::FlowsExtraPath, &user, Some(home));
    assert_eq!(kept, strings(&["~/.cargo/bin", "/opt/homebrew/bin"]));
    assert!(entry.clamped);
    let (no_home, _) = view.effective_path_list(Key::FlowsExtraPath, &user, None);
    assert_eq!(
        no_home,
        strings(&["/opt/homebrew/bin"]),
        "no home: a ~ entry is never covered"
    );

    let windows = view_for(
        &doc(&json!({ "scopes": { "allowed_repository_roots": [r"C:\Users"] } })),
        WIN,
    );
    let rules = windows
        .policy()
        .allowed_repository_roots
        .clone()
        .expect("applied");
    assert!(
        rules[0].covers(r"c:\users\dev\repo", None),
        "Windows compares case-insensitively"
    );
    assert!(rules[0].covers("C:/Users/dev", None));
    assert!(!rules[0].covers(r"C:\UsersX", None));
}

#[test]
fn never_globs_and_classes() {
    for (pattern, name, expected) in [
        ("flow.step:*/merge", "flow.step:ship/merge", true),
        ("flow.step:*/merge", "flow.step:ship/merge-all", false),
        ("flow.step:*/merge", "xflow.step:a/merge", false),
        ("*", "anything", true),
        ("echo", "echo", true),
        ("echo", "echoes", false),
        ("a*b*c", "aXbYc", true),
        ("a*b*c", "aXcYb", false),
        ("flow.*", "flow.", true),
        ("*merge", "merge", true),
    ] {
        assert_eq!(
            pattern_matches(pattern, name),
            expected,
            "{pattern} ~ {name}"
        );
    }
    let view = view(&doc(&json!({ "security": { "grants": {
        "never": ["flow.step:*/deploy"], "never_classes": ["external"], "manual": "allow"
    } } })));
    assert_eq!(
        view.never_match("flow.step:ship/deploy", None).as_deref(),
        Some("flow.step:*/deploy")
    );
    assert_eq!(
        view.never_match("echo", Some(CapabilityClass::External))
            .as_deref(),
        Some("class:external")
    );
    assert_eq!(
        view.never_match("echo", Some(CapabilityClass::Destructive)),
        None
    );
    let refusal = view
        .check_grant_add("flow.step:ship/deploy", None)
        .expect_err("never");
    assert_eq!(
        (refusal.cause, refusal.key),
        (CAUSE_POLICY_NOT_ALLOWED, Key::GrantsNever)
    );
    assert!(
        view.check_grant_add("echo", Some(CapabilityClass::NonDestructive))
            .is_ok()
    );
}

#[test]
fn grant_switches() {
    let view = view(&doc(
        &json!({ "security": { "grants": { "manual": "deny", "remember": "deny" } } }),
    ));
    assert!(view.grants_manual_denied() && view.grants_remember_denied());
    assert_eq!(
        view.check_grant_add("echo", None)
            .expect_err("manual")
            .cause,
        CAUSE_SETTING_LOCKED
    );
    assert_eq!(
        view.check_remember().expect_err("remember").cause,
        CAUSE_SETTING_LOCKED
    );
    let open = PolicyView::unmanaged();
    assert!(open.check_grant_add("echo", None).is_ok() && open.check_remember().is_ok());
}

#[test]
fn plain_constraints_only_filter() {
    let view = view(&spec_sample());
    assert_eq!(
        view.landing_ceiling(),
        LandingCeiling {
            push: true,
            create_pr: true,
            merge: false,
            sync: true
        }
    );
    assert_eq!(
        PolicyView::unmanaged().landing_ceiling(),
        LandingCeiling::default()
    );
    assert!(view.connector_wide_denied());
    let url = |raw: &str| Url::parse(raw).expect("a url");
    assert!(view.base_url_allowed(&url("https://jenkins.example.com/")));
    assert!(view.base_url_allowed(&url("https://example.com/")));
    assert!(!view.base_url_allowed(&url("https://example.org/")));
    assert!(view.github_server_allowed(&url("https://github.example.com/")));
    assert!(!view.github_server_allowed(&url("https://github.com/")));
    assert!(view.connector_disabled(ConnectorId::Jira));
    assert!(!view.connector_disabled(ConnectorId::Github));
    assert!(view.model_source_allowed(ModelSource::Catalog));
    assert!(!view.model_source_allowed(ModelSource::CustomUrl));
    assert!(
        !view.curator_allowed(AgentId::Claude),
        "[] disables every curator"
    );
    let open = PolicyView::unmanaged();
    assert!(
        open.base_url_allowed(&url("https://example.org/"))
            && open.curator_allowed(AgentId::Claude)
    );
}

#[test]
fn string_defaults_apply_only_without_a_user_value() {
    let view = view(&spec_sample());
    let key = Key::FlowsArtifactsRoot;
    let (value, entry) = view.effective_string(key, None);
    assert_eq!(value.as_deref(), Some("~/pam-artifacts"));
    assert_eq!((entry.source, entry.locked), (Source::Policy, false));
    let (value, entry) = view.effective_string(key, Some("/Volumes/Build".to_owned()));
    assert_eq!(value.as_deref(), Some("/Volumes/Build"));
    assert_eq!(entry.source, Source::User);
    assert!(view.guard_locked(key).is_ok(), "a default does not lock");
    let unmanaged = PolicyView::unmanaged();
    assert_eq!(
        unmanaged.effective_string(Key::ModelsDir, None),
        (
            None,
            crate::managed_policy::EffectiveEntry::unmanaged(Source::Default)
        )
    );
}

#[test]
fn merges_never_mutate_the_users_values() {
    let view = view(&spec_sample());
    let programs = strings(&["git", "bash", "python3"]);
    let paths = strings(&["/usr/local/bin", "/tmp/x"]);
    let before = (programs.clone(), paths.clone());
    let _ = view.effective_programs(&programs);
    let _ = view.effective_path_list(Key::FlowsExtraPath, &paths, None);
    let _ = view.check_list(Key::FlowsPrograms, &programs, None);
    assert_eq!((programs, paths), before);
}

#[test]
fn managed_network_carries_only_locked_fields() {
    let managed = view(&spec_sample()).managed_network().expect("managed");
    assert_eq!(
        managed.proxy.expect("locked").expect("a proxy").url,
        "http://proxy.example.com:8080"
    );
    assert_eq!(
        managed.no_proxy,
        Some(strings(&["example.com", "10.0.0.0/8"]))
    );
    assert_eq!(
        managed.engine_mirror,
        Some(Some("https://artifacts.example.com/llama.cpp/".to_owned()))
    );
    assert_eq!(managed.models_mirror, None, "a default is not a lock");
    assert_eq!(managed.ca_bundle, None, "the pin is imported by the loader");
    assert_eq!(
        managed.mirror_allowed_hosts,
        strings(&["artifacts.example.com"])
    );
    assert_eq!(PolicyView::unmanaged().managed_network(), None);
}

// --- Fallback, holds, refusals -----------------------------------------

#[test]
fn fallback_takes_last_good_then_holds_tier_a() {
    let good = view(&doc(&json!({
        "security": { "profile": { "locked": "strict" } },
        "network": { "engine_mirror": { "locked": "https://m.example.com/e" } }
    })));
    let damaged = || {
        view(&doc(&json!({
            "security": { "profile": { "locked": "lenient" } },
            "network": {
                "engine_mirror": { "locked": "http://m.example.com/e" },
                "proxy": { "locked": { "url": "socks5://p:1", "auth": "none" } }
            }
        })))
    };
    let degraded = damaged().with_fallback(Some(&good));
    assert!(matches!(
        degraded.status(Key::SecurityProfile),
        Some(LeafStatus::LastGood { .. })
    ));
    assert_eq!(
        degraded.effective_profile(Some(Profile::Relaxed)).0,
        Profile::Strict,
        "the profile stays strict"
    );
    assert!(matches!(
        degraded.status(Key::NetworkEngineMirror),
        Some(LeafStatus::LastGood { .. })
    ));
    assert!(
        degraded.is_held(Key::NetworkProxy),
        "no last good proxy: held"
    );
    assert_eq!(degraded.network_closed(), Some(Key::NetworkProxy));
    assert_eq!(
        degraded
            .guard_locked(Key::NetworkProxy)
            .expect_err("held")
            .cause,
        CAUSE_POLICY_FROZEN
    );

    let alone = damaged().with_fallback(None);
    assert!(alone.is_held(Key::SecurityProfile));
    let (profile, entry) = alone.effective_profile(Some(Profile::Relaxed));
    assert_eq!(
        profile,
        Profile::Relaxed,
        "a held key reads the user's value"
    );
    assert_eq!(
        entry.to_json(),
        json!({ "source": "user", "locked": true, "state": "held" })
    );
    assert_eq!(
        alone
            .check_profile(Profile::Strict)
            .expect_err("held")
            .cause,
        CAUSE_POLICY_FROZEN
    );
    assert_eq!(
        rejected_code(&alone, Key::NetworkEngineMirror),
        CODE_VALUE_INVALID
    );
    let reports = alone.key_reports();
    let profile_row = reports
        .iter()
        .find(|row| row.key == "security.profile")
        .expect("row");
    assert_eq!((profile_row.tier, profile_row.state), ("A", "held"));
}

#[test]
fn a_frozen_view_holds_every_tier_a_key_but_closes_nothing() {
    let failure = file_error(r#"{"version":"#);
    let frozen = PolicyView::frozen(&failure, Some("ab".repeat(32)));
    for key in Key::ALL {
        assert_eq!(frozen.is_held(key), key.tier() == Tier::A, "{key}");
    }
    assert_eq!(frozen.network_closed(), None, "the intent is unknown");
    assert_eq!(
        frozen.effective_profile(Some(Profile::Relaxed)).0,
        Profile::Relaxed
    );
    assert_eq!(
        frozen
            .check_profile(Profile::Relaxed)
            .expect_err("frozen")
            .cause,
        CAUSE_POLICY_FROZEN
    );
    assert_eq!(
        frozen
            .check_grant_add("echo", None)
            .expect_err("frozen")
            .cause,
        CAUSE_POLICY_FROZEN
    );
    assert!(
        frozen
            .check_window(Key::ModelsIdleUnloadMin, Some(5))
            .is_ok(),
        "Tier B stays the user's"
    );
}

#[test]
fn refusal_detail_names_the_key_reason_contact_digest_and_revision() {
    let inspection = inspect_for(
        &doc(&json!({
            "revision": "2026-10-02.1",
            "contact": "it-help@example.com",
            "security": { "profile": { "locked": "strict", "reason": "SEC-114" } }
        }))
        .to_string(),
        MAC,
    );
    let digest = inspection.digest.clone();
    let view = inspection.result.expect("valid");
    let refusal = view.check_profile(Profile::Relaxed).expect_err("locked");
    assert_eq!(refusal.recovery, RECOVERY_MANAGED);
    for part in [
        "security.profile",
        "SEC-114",
        "it-help@example.com",
        &format!("(policy {}, rev 2026-10-02.1)", &digest[..12]),
    ] {
        assert!(
            refusal.detail.contains(part),
            "{part} not in {}",
            refusal.detail
        );
    }
}

#[test]
fn inspection_verdicts() {
    assert_eq!(
        inspect_for(r#"{"version":1}"#, MAC).verdict(),
        Verdict::Valid
    );
    assert_eq!(
        inspect_for(r#"{"version":1,"x":1}"#, MAC).verdict(),
        Verdict::LeafProblems
    );
    assert_eq!(
        inspect_for(r#"{"version":3}"#, MAC).verdict(),
        Verdict::FileInvalid
    );
    let leaf = inspect_for(
        r#"{"version":1,"service":{"require_login_unit":"yes"}}"#,
        MAC,
    );
    let view = leaf.result.expect("parses");
    assert_eq!(view.rejected_leaves(), 1);
    assert_eq!(view.diagnostics()[0].key, "service.require_login_unit");
    assert!(!view.require_login_unit());
}
