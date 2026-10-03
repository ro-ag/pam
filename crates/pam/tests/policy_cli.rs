//! `pam policy check` through the compiled binary: the shipped samples
//! under `docs/policy/` pass with exit `0` (so the docs cannot drift from
//! the grammar), each verdict reaches its exit code and stream, and the
//! command needs no daemon and writes nothing.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

/// The repository's `docs/policy/`.
fn samples_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/policy")
}

/// Every `*.json` sample, sorted.
fn samples() -> Vec<PathBuf> {
    let mut samples: Vec<PathBuf> = std::fs::read_dir(samples_dir())
        .expect("docs/policy exists")
        .map(|entry| entry.expect("a readable entry").path())
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "json")
        })
        .collect();
    samples.sort();
    samples
}

/// Runs `pam policy check <args>` with the base directory pointed at a
/// path that does not exist: a command that started or dialed a daemon, or
/// wrote any state, would create it.
fn check(args: &[&str]) -> Output {
    let home = tempfile::tempdir().expect("tempdir");
    let base = home.path().join("base");
    let output = Command::new(env!("CARGO_BIN_EXE_pam"))
        .args(["policy", "check"])
        .args(args)
        .env("PAM_BASE_DIR", &base)
        .env("HOME", home.path())
        .output()
        .expect("pam runs");
    assert!(
        !base.exists(),
        "pam policy check created the base directory: it must not start a daemon or write state"
    );
    let entries = std::fs::read_dir(home.path()).expect("home").count();
    assert_eq!(entries, 0, "pam policy check wrote into the home directory");
    output
}

fn json_of(output: &Output) -> serde_json::Value {
    serde_json::from_slice(&output.stdout).unwrap_or_else(|err| {
        panic!(
            "--json prints one document ({err}): {}",
            String::from_utf8_lossy(&output.stdout)
        )
    })
}

fn path_arg(path: &Path) -> &str {
    path.to_str().expect("a UTF-8 path")
}

#[test]
fn every_shipped_sample_passes_with_exit_zero() {
    let samples = samples();
    let names: Vec<String> = samples
        .iter()
        .map(|path| path.file_name().unwrap().to_string_lossy().into_owned())
        .collect();
    for required in ["minimal.json", "network-only.json", "strict-fleet.json"] {
        assert!(names.iter().any(|name| name == required), "{names:?}");
    }
    for sample in &samples {
        // The samples are written for macOS paths, whatever runs the test.
        let output = check(&[path_arg(sample), "--platform", "macos"]);
        assert_eq!(
            output.status.code(),
            Some(0),
            "{} must pass:\n{}",
            sample.display(),
            String::from_utf8_lossy(&output.stdout)
        );
        let json = json_of(&check(&[path_arg(sample), "--platform", "macos", "--json"]));
        assert_eq!(json["verdict"], "valid", "{}: {json}", sample.display());
        assert_eq!(json["rejected_leaves"], 0);
        assert_eq!(json["diagnostics"], serde_json::json!([]));
        assert!(
            json["keys"]
                .as_array()
                .unwrap()
                .iter()
                .all(|key| key["state"] == "applied" && key.get("value").is_some()),
            "{json}"
        );
    }
}

#[test]
fn the_strict_fleet_sample_sets_what_the_guide_says_it_sets() {
    let sample = samples_dir().join("strict-fleet.json");
    let json = json_of(&check(&[path_arg(&sample), "--for", "macos", "--json"]));
    let applied: Vec<&str> = json["keys"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|key| key["key"].as_str())
        .collect();
    for key in [
        "security.profile",
        "security.grants.remember",
        "security.grants.never",
        "scopes.allowed_repository_roots",
        "connectors.allowed_base_hosts",
        "models.engine_source",
        "network.mirror_allowed_hosts",
        "network.engine_mirror",
        "network.proxy",
        "network.no_proxy",
        "retention.evidence_days",
        "retention.audit_days",
    ] {
        assert!(applied.contains(&key), "{key} missing from {applied:?}");
    }
    assert!(
        json["locks"]
            .as_array()
            .unwrap()
            .iter()
            .any(|key| key == "security.profile"),
        "{json}"
    );
}

/// `--platform` checks path syntax for the target: the macOS fleet sample
/// read as a Windows file rejects its two path lists, and the samples
/// without paths pass for Windows too.
#[test]
fn the_platform_decides_the_path_syntax() {
    let strict = samples_dir().join("strict-fleet.json");
    let output = check(&[path_arg(&strict), "--platform", "windows", "--json"]);
    assert_eq!(output.status.code(), Some(13));
    let json = json_of(&output);
    assert_eq!(json["platform"], "windows");
    let rejected: Vec<&str> = json["keys"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|key| key["state"] == "rejected")
        .filter_map(|key| key["key"].as_str())
        .collect();
    assert_eq!(
        rejected,
        ["scopes.allowed_repository_roots", "flows.extra_path"]
    );
    for sample in ["minimal.json", "network-only.json"] {
        let path = samples_dir().join(sample);
        let output = check(&[path_arg(&path), "--platform", "windows"]);
        assert_eq!(output.status.code(), Some(0), "{sample}");
    }
}

#[test]
fn each_verdict_has_its_exit_code() {
    let dir = tempfile::tempdir().unwrap();
    let write = |name: &str, text: &[u8]| {
        let path = dir.path().join(name);
        std::fs::write(&path, text).unwrap();
        path
    };
    let leafy = write(
        "leafy.json",
        br#"{"version":1,"connectors":{"allowed_base_hosts":["*.example.com"]}}"#,
    );
    let output = check(&[path_arg(&leafy)]);
    assert_eq!(output.status.code(), Some(13));
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(text.contains("policy_value_invalid"), "{text}");

    for (name, text, code) in [
        ("broken.json", &b"{\"version\":1,"[..], "policy_not_json"),
        (
            "dup.json",
            &br#"{"version":1,"version":1}"#[..],
            "policy_duplicate_key",
        ),
        (
            "v2.json",
            &br#"{"version":2}"#[..],
            "policy_version_unsupported",
        ),
    ] {
        let path = write(name, text);
        let output = check(&[path_arg(&path), "--json"]);
        assert_eq!(output.status.code(), Some(12), "{name}");
        let json = json_of(&output);
        assert_eq!(json["verdict"], "file_invalid");
        assert_eq!(json["failure"]["code"], code);
    }

    let big = dir.path().join("big.json");
    std::fs::File::create(&big)
        .unwrap()
        .set_len(1 << 30)
        .unwrap();
    let output = check(&[path_arg(&big), "--json"]);
    assert_eq!(output.status.code(), Some(12));
    let json = json_of(&output);
    assert_eq!(json["failure"]["code"], "policy_too_large");
    assert_eq!(json["digest"], serde_json::Value::Null);

    let missing = dir.path().join("missing.json");
    let output = check(&[path_arg(&missing), "--json"]);
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("cannot read"));
}

#[test]
fn trust_judges_the_file_where_it_sits_and_refuses_one_this_user_owns() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("policy.json");
    std::fs::write(&path, br#"{"version":1}"#).unwrap();
    let output = check(&[path_arg(&path), "--trust", "--json"]);
    assert_eq!(output.status.code(), Some(11));
    let json = json_of(&output);
    assert_eq!(json["verdict"], "valid", "the content is still judged");
    assert_eq!(json["trust"]["verdict"], "untrusted");
    assert_eq!(json["trust"]["at_fixed_path"], false);
    assert!(json["trust"]["code"].as_str().is_some());
    let human = check(&[path_arg(&path), "--trust"]);
    assert_eq!(human.status.code(), Some(11));
    assert!(String::from_utf8_lossy(&human.stdout).contains("trust        untrusted"));
}

/// `/private/etc/hosts` is root-owned under root-owned directories: the
/// production rules trust it, and its content is then judged on its own.
#[cfg(target_os = "macos")]
#[test]
fn trust_passes_a_root_owned_file_and_the_content_still_decides() {
    let output = check(&["/private/etc/hosts", "--trust", "--json"]);
    let json = json_of(&output);
    assert_eq!(json["trust"]["verdict"], "trusted", "{json}");
    assert_eq!(json["trust"]["observed"]["uid"], 0);
    assert!(
        json["trust"]["facts"]
            .as_object()
            .unwrap()
            .values()
            .all(|state| state == "ok")
    );
    assert_eq!(output.status.code(), Some(12), "hosts is not JSON");
}

#[test]
fn trust_is_this_machines_rules_only() {
    let sample = samples_dir().join("minimal.json");
    let other = if cfg!(windows) { "macos" } else { "windows" };
    let output = check(&[path_arg(&sample), "--trust", "--platform", other]);
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
}
