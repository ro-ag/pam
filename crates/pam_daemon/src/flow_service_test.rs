//! Unit tests for the flow library, the flow settings, and the two
//! read-only bodies (`flow.list`, `flow.show`).
//!
//! A whole run needs a pipeline — request rows, lanes, a cancel signal —
//! and is proved end to end in `tests/flows.rs`. What lives here is
//! everything a run does *not* need a daemon for.

use std::path::Path;
use std::sync::Arc;

use pam_store::Store;
use tokio::sync::mpsc;

use crate::approval::ApprovalService;
use crate::connector_service::ConnectorService;
use crate::flow_service::{
    ArtifactsRootPatch, CAUSE_ARTIFACTS_ROOT_INVALID, CAUSE_FLOW_NOT_FOUND, CAUSE_INPUT_INVALID,
    CAUSE_PROGRAM_NOT_ALLOWED, FlowService, FlowSettings, RunArgs, SETTING_ALLOWED_PROGRAMS,
    SETTING_ARTIFACTS_ROOT, SETTING_EXTRA_PATH, SettingsPatch, boundary_read_roots,
    origin_from_output, step_capability,
};
use crate::log_service::LogService;
use crate::policy::PolicyGate;
use crate::transport::{EventPublisher, IncomingRequest};

/// A flow engine over `base` and `store`, with the services a run needs
/// but a library or settings test never touches.
///
/// `pub(crate)` because the four admin test modules construct an
/// [`crate::admin::AdminService`], which now carries a flow engine.
pub(crate) async fn flows_for_tests(
    base: &Path,
    store: &Arc<Store>,
    approvals: &Arc<ApprovalService>,
    connectors: &Arc<ConnectorService>,
    logs: &Arc<LogService>,
) -> Arc<FlowService> {
    flows_for_tests_with_policy(
        base,
        store,
        approvals,
        connectors,
        logs,
        crate::managed_policy_service::PolicyHandle::none(),
    )
    .await
}

/// [`flows_for_tests`] reading through `policy`.
pub(crate) async fn flows_for_tests_with_policy(
    base: &Path,
    store: &Arc<Store>,
    approvals: &Arc<ApprovalService>,
    connectors: &Arc<ConnectorService>,
    logs: &Arc<LogService>,
    policy: Arc<crate::managed_policy_service::PolicyHandle>,
) -> Arc<FlowService> {
    // The gate gets a store of its own: `PolicyGate::new` persists the
    // platform-default profile on its first read, and no test using this
    // helper runs a step (which is the only thing that consults the
    // gate), so the store under test must not grow that setting.
    let gate_store = Arc::new(Store::open_in_memory().await.expect("store opens"));
    let gate = Arc::new(
        PolicyGate::new(
            gate_store,
            crate::managed_policy_service::PolicyHandle::none(),
        )
        .await
        .expect("the gate builds"),
    );
    Arc::new(FlowService::new(
        base,
        Arc::clone(store),
        Arc::clone(approvals),
        Arc::clone(connectors),
        Arc::clone(logs),
        gate,
        policy,
    ))
}

/// A policy handle that loaded `document` as a trusted file (its boot
/// read writes the `policy.load` row on `store`).
pub(crate) async fn managed_policy(
    store: &Arc<Store>,
    base: &Path,
    document: &serde_json::Value,
) -> Arc<crate::managed_policy_service::PolicyHandle> {
    let source = crate::daemon_test::ScriptedPolicy::new(Some(&document.to_string()));
    let handle = crate::managed_policy_service::PolicyHandle::load(
        Arc::clone(store),
        Arc::new(source),
        base,
    )
    .await;
    assert!(handle.view().is_managed(), "the test policy loaded");
    handle
}

/// A pipeline ingress with no pipeline behind it: an `admin.flows.run`
/// sent through it refuses with `submit_failed`, which is the honest
/// answer for a unit test that has no daemon.
pub(crate) fn closed_submit() -> mpsc::Sender<IncomingRequest> {
    let (submit, _) = mpsc::channel(1);
    submit
}

/// A flow engine on a fresh temp directory, plus that directory.
async fn service() -> (tempfile::TempDir, Arc<Store>, Arc<FlowService>) {
    managed_service(None).await
}

/// [`service`] under a trusted managed policy `document` (none: unmanaged).
async fn managed_service(
    document: Option<serde_json::Value>,
) -> (tempfile::TempDir, Arc<Store>, Arc<FlowService>) {
    let tmp = tempfile::tempdir().expect("tempdir");
    let store = Arc::new(Store::open_in_memory().await.expect("store opens"));
    let policy = match &document {
        Some(document) => managed_policy(&store, tmp.path(), document).await,
        None => crate::managed_policy_service::PolicyHandle::none(),
    };
    let (events, _rx) = EventPublisher::for_tests();
    let approvals = Arc::new(ApprovalService::new(
        Arc::clone(&store),
        events,
        std::time::Duration::from_mins(1),
        crate::managed_policy_service::PolicyHandle::none(),
    ));
    let models = crate::model_service::ModelService::new(
        Arc::clone(&store),
        crate::managed_policy_service::PolicyHandle::none(),
    )
    .await
    .expect("the model service builds");
    let logs = LogService::new(Arc::clone(&store), models);
    let connectors = Arc::new(ConnectorService::from_parts(
        Arc::clone(&store),
        None,
        None,
        crate::managed_policy_service::PolicyHandle::none(),
    ));
    let flows =
        flows_for_tests_with_policy(tmp.path(), &store, &approvals, &connectors, &logs, policy)
            .await;
    (tmp, store, flows)
}

/// A minimal valid flow file.
fn flow_yaml(id: &str) -> String {
    format!(
        "schema: 1\nid: {id}\nname: A local flow\ndescription: says hello\n\
         inputs:\n  who:\n    description: who to greet\n    default: world\n\
         steps:\n  - id: look\n    run: [git, status, --short]\n    env: {{ WHO: '${{inputs.who}}' }}\n"
    )
}

#[test]
fn a_step_capability_names_the_flow_and_the_step() {
    assert_eq!(
        step_capability("pr-readiness", "clippy"),
        "flow.step:pr-readiness/clippy"
    );
}

#[test]
fn the_platform_default_allowlist_carries_the_toolchain_and_no_shell() {
    let settings = FlowSettings::platform_default();
    for program in ["git", "cargo", "npm", "gh"] {
        assert!(
            settings.allows(program),
            "{program} should be allowed by default"
        );
    }
    for shell in ["sh", "bash", "pwsh", "cmd"] {
        assert!(!settings.allows(shell), "{shell} must never be allowed");
    }
    assert!(!settings.extra_path.is_empty());
}

#[tokio::test]
async fn the_first_settings_read_persists_the_platform_default() {
    let (_tmp, store, flows) = service().await;
    assert!(
        store
            .get_setting(SETTING_ALLOWED_PROGRAMS)
            .await
            .expect("get_setting ok")
            .is_none()
    );

    let settings = flows.settings().await.expect("settings read");
    assert_eq!(settings, FlowSettings::platform_default());
    assert!(
        store
            .get_setting(SETTING_ALLOWED_PROGRAMS)
            .await
            .expect("get_setting ok")
            .is_some()
    );
    assert!(
        store
            .get_setting(SETTING_EXTRA_PATH)
            .await
            .expect("get_setting ok")
            .is_some()
    );
}

#[tokio::test]
async fn setting_the_allowlist_trims_and_deduplicates() {
    let (_tmp, _store, flows) = service().await;
    let settings = flows
        .set_settings(SettingsPatch {
            allowed_programs: Some(vec![
                "  git  ".to_owned(),
                "git".to_owned(),
                String::new(),
                "cargo".to_owned(),
            ]),
            ..SettingsPatch::default()
        })
        .await
        .expect("the settings save");
    assert_eq!(settings.allowed_programs, ["git", "cargo"]);
    // The untouched half keeps its default.
    assert_eq!(
        settings.extra_path,
        FlowSettings::platform_default().extra_path
    );
}

#[tokio::test]
async fn a_shell_is_refused_from_the_allowlist() {
    let (_tmp, _store, flows) = service().await;
    let refusal = flows
        .set_settings(SettingsPatch {
            allowed_programs: Some(vec!["git".to_owned(), "bash".to_owned()]),
            ..SettingsPatch::default()
        })
        .await
        .expect_err("a shell is refused");
    assert_eq!(refusal.cause, CAUSE_PROGRAM_NOT_ALLOWED);
    assert!(refusal.detail.contains("bash"));
    assert!(refusal.recovery.contains("Settings"));
    // Nothing was written.
    assert_eq!(
        flows.settings().await.expect("settings read"),
        FlowSettings::platform_default()
    );
}

#[tokio::test]
async fn a_program_with_a_path_separator_is_refused() {
    let (_tmp, _store, flows) = service().await;
    let refusal = flows
        .set_settings(SettingsPatch {
            allowed_programs: Some(vec!["/usr/bin/git".to_owned()]),
            ..SettingsPatch::default()
        })
        .await
        .expect_err("a path is refused");
    assert_eq!(refusal.cause, CAUSE_PROGRAM_NOT_ALLOWED);
}

#[tokio::test]
async fn the_list_body_carries_every_builtin_with_its_shape() {
    let (_tmp, _store, flows) = service().await;
    let body = flows
        .list_page(&serde_json::json!({"limit":50}))
        .expect("the list is readable")
        .body;
    let entries = body["flows"].as_array().expect("flows is an array");
    assert_eq!(entries.len(), pam_flow::builtin().len());
    for entry in entries {
        assert_eq!(entry["source"], "builtin");
        assert_eq!(entry["valid"], true);
        assert!(entry["steps"].as_u64().expect("steps is a number") > 0);
        assert!(entry["inputs"].is_array());
        assert!(entry.get("digest").is_none(), "flow.list carries no digest");
    }
}

#[tokio::test]
async fn a_library_file_shadows_a_builtin_and_an_invalid_one_says_why() {
    let (tmp, _store, flows) = service().await;
    let dir = tmp.path().join("flows");
    std::fs::create_dir_all(&dir).expect("the library directory is created");
    std::fs::write(
        dir.join("after-merge-checks.yaml"),
        flow_yaml("after-merge-checks"),
    )
    .expect("the shadow is written");
    std::fs::write(dir.join("broken.yaml"), "schema: 1\nid: broken\n")
        .expect("the broken file is written");

    let body = flows.list().expect("the list is readable").body;
    let entries = body["flows"].as_array().expect("flows is an array");
    let shadow = entries
        .iter()
        .find(|entry| entry["id"] == "after-merge-checks")
        .expect("the shadowed flow is listed once");
    assert_eq!(shadow["source"], "library");
    assert_eq!(shadow["name"], "A local flow");

    let broken = entries
        .iter()
        .find(|entry| entry["id"] == "broken")
        .expect("the broken flow is listed");
    assert_eq!(broken["valid"], false);
    assert_eq!(broken["steps"], 0);
    assert!(
        broken["error"]
            .as_str()
            .expect("the error is a string")
            .contains("missing field")
    );
    // A broken file is still pickable in the GUI list.
    assert_eq!(broken["name"], "broken");
}

#[tokio::test]
async fn show_renders_the_yaml_its_normalization_and_a_digest() {
    let (_tmp, _store, flows) = service().await;
    let body = flows
        .show("after-merge-checks")
        .expect("the builtin is readable")
        .body;
    assert_eq!(body["id"], "after-merge-checks");
    assert_eq!(body["source"], "builtin");
    assert_eq!(body["valid"], true);
    assert!(
        body["yaml"]
            .as_str()
            .expect("yaml is a string")
            .contains("schema: 1")
    );
    assert!(
        body["normalized_yaml"]
            .as_str()
            .expect("normalized_yaml is a string")
            .starts_with("schema: 1\n")
    );
    assert_eq!(
        body["digest"].as_str().expect("digest is a string").len(),
        64
    );
    assert!(body.get("error").is_none());
}

#[tokio::test]
async fn show_reads_an_invalid_flow_so_a_human_can_fix_it() {
    let (tmp, _store, flows) = service().await;
    let dir = tmp.path().join("flows");
    std::fs::create_dir_all(&dir).expect("the library directory is created");
    std::fs::write(dir.join("broken.yaml"), "schema: 1\nid: broken\n")
        .expect("the broken file is written");

    let body = flows
        .show("broken")
        .expect("an invalid flow still reads")
        .body;
    assert_eq!(body["valid"], false);
    assert_eq!(body["normalized_yaml"], "");
    assert_eq!(body["digest"], "");
    assert!(body["error"].is_string());
}

#[tokio::test]
async fn showing_a_flow_nothing_carries_refuses_with_the_list_recovery() {
    let (_tmp, _store, flows) = service().await;
    let refusal = flows.show("no-such-flow").expect_err("nothing answers");
    assert_eq!(refusal.cause, CAUSE_FLOW_NOT_FOUND);
    assert!(refusal.recovery.contains("pam flow list"));
}

#[test]
fn connector_assertions_fail_closed_without_changing_observation_or_api_failure() {
    use crate::flow_exec::{StepReport, StepStatus};
    use crate::flow_service::{
        CAUSE_STATUS_ASSERTION, CAUSE_STATUS_ASSERTION_REQUIRED, apply_connector_assertion,
    };
    let mut step = pam_flow::parse("schema: 1\nid: gate\nname: Gate\nsteps:\n  - id: gate\n    connector: sonarqube\n    call: quality_gate\n    with: { project: pam }\n    role: verify\n    expect_status: OK\n").unwrap().steps.remove(0);
    for value in [
        None,
        Some(serde_json::json!({})),
        Some(serde_json::json!({"status": 1})),
        Some(serde_json::json!({"status": "UNKNOWN"})),
    ] {
        let mut report = StepReport::new("gate", "connector", StepStatus::Succeeded);
        apply_connector_assertion(&step, value.as_ref(), &mut report);
        assert_eq!(report.status, StepStatus::Failed);
        assert_eq!(report.error.unwrap().cause, CAUSE_STATUS_ASSERTION);
    }
    step.expect_status = None;
    let mut report = StepReport::new("gate", "connector", StepStatus::Succeeded);
    apply_connector_assertion(
        &step,
        Some(&serde_json::json!({"status": "OK"})),
        &mut report,
    );
    assert_eq!(report.error.unwrap().cause, CAUSE_STATUS_ASSERTION_REQUIRED);
    step.role = pam_flow::Role::Observe;
    let mut report = StepReport::new("gate", "connector", StepStatus::Succeeded);
    apply_connector_assertion(
        &step,
        Some(&serde_json::json!({"status": "ERROR"})),
        &mut report,
    );
    assert_eq!(report.status, StepStatus::Succeeded);
    let mut report = StepReport::new("gate", "connector", StepStatus::Failed);
    report.fail(
        StepStatus::Failed,
        "connector_bad_response",
        "API error".to_owned(),
        "retry".to_owned(),
    );
    apply_connector_assertion(&step, None, &mut report);
    assert_eq!(report.error.unwrap().cause, "connector_bad_response");
}

/// Issue #26: a daemon binary that lives under its own protected base (or
/// inside the repository) must not become a read root, because the profile
/// refuses any root overlapping those boundaries and every build flow then
/// fails before its first step.
#[test]
fn boundary_read_roots_drop_grants_inside_the_protected_base_or_the_repository() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let base = tmp.path().join("base");
    let repo = tmp.path().join("repo");
    let tools = tmp.path().join("tools");
    for dir in [&base.join("bin"), &repo.join("target"), &tools] {
        std::fs::create_dir_all(dir).expect("dir");
    }
    let program = tools.join("cargo");
    let elsewhere = tmp.path().join("elsewhere");
    std::fs::create_dir_all(&elsewhere).expect("elsewhere");
    for file in [
        &program,
        &base.join("bin/pam"),
        &repo.join("target/pam"),
        &elsewhere.join("pam"),
    ] {
        std::fs::write(file, b"").expect("file");
    }
    let tools = tools.canonicalize().expect("canonical tools");

    let inside_base =
        boundary_read_roots(&base, &repo, &program, Some(&base.join("bin/pam")), None);
    let canonical_base = base.canonicalize().expect("canonical base");
    assert!(
        inside_base.contains(&tools),
        "program directory stays granted"
    );
    assert!(
        inside_base
            .iter()
            .all(|root| !root.starts_with(&canonical_base)),
        "no root under the protected base: {inside_base:?}"
    );

    let inside_repo =
        boundary_read_roots(&base, &repo, &program, Some(&repo.join("target/pam")), None);
    let canonical_repo = repo.canonicalize().expect("canonical repo");
    assert!(
        inside_repo
            .iter()
            .all(|root| !root.starts_with(&canonical_repo)),
        "no root under the repository: {inside_repo:?}"
    );

    let separate = boundary_read_roots(&base, &repo, &program, Some(&elsewhere.join("pam")), None);
    assert!(
        separate.contains(&elsewhere.canonicalize().expect("canonical elsewhere")),
        "a daemon directory outside both boundaries stays granted: {separate:?}"
    );
}

#[test]
fn the_platform_default_names_the_cargo_caches_and_no_artifacts_root() {
    let settings = FlowSettings::platform_default();
    assert_eq!(settings.artifacts_root, None);
    assert_eq!(settings.artifacts_root_dir(), None);
    assert_eq!(
        settings.read_cache_roots,
        ["~/.cargo/registry", "~/.cargo/git"]
    );
    // Expansion drops nothing that exists and keeps the order.
    let home = std::env::home_dir().expect("a home");
    let dirs = settings.read_cache_dirs();
    assert!(dirs.iter().all(|dir| dir.starts_with(&home)), "{dirs:?}");
}

#[tokio::test]
async fn the_artifacts_root_is_unset_until_a_human_names_one_and_clears_again() {
    let (_tmp, store, flows) = service().await;
    assert_eq!(
        flows
            .settings()
            .await
            .expect("settings read")
            .artifacts_root,
        None
    );

    let settings = flows
        .set_settings(SettingsPatch {
            artifacts_root: ArtifactsRootPatch::Set("  ~/pam-builds ".to_owned()),
            ..SettingsPatch::default()
        })
        .await
        .expect("the root saves");
    assert_eq!(settings.artifacts_root.as_deref(), Some("~/pam-builds"));
    assert_eq!(
        settings.artifacts_root_dir(),
        Some(std::env::home_dir().expect("a home").join("pam-builds"))
    );
    assert_eq!(
        store
            .get_setting(SETTING_ARTIFACTS_ROOT)
            .await
            .expect("get_setting ok")
            .as_deref(),
        Some("\"~/pam-builds\"")
    );
    // The untouched lists keep their defaults.
    assert_eq!(
        settings.allowed_programs,
        FlowSettings::platform_default().allowed_programs
    );

    let cleared = flows
        .set_settings(SettingsPatch {
            artifacts_root: ArtifactsRootPatch::Clear,
            ..SettingsPatch::default()
        })
        .await
        .expect("the root clears");
    assert_eq!(cleared.artifacts_root, None);
    assert_eq!(
        flows
            .settings()
            .await
            .expect("settings read")
            .artifacts_root,
        None
    );
}

#[tokio::test]
async fn a_relative_or_empty_artifacts_root_is_refused_and_nothing_is_written() {
    let (_tmp, _store, flows) = service().await;
    for raw in ["builds", "./builds", "   "] {
        let refusal = flows
            .set_settings(SettingsPatch {
                artifacts_root: ArtifactsRootPatch::Set(raw.to_owned()),
                ..SettingsPatch::default()
            })
            .await
            .expect_err("a relative root is refused");
        assert_eq!(refusal.cause, CAUSE_ARTIFACTS_ROOT_INVALID, "{raw:?}");
        assert!(
            refusal.recovery.contains("Settings"),
            "{}",
            refusal.recovery
        );
    }
    assert_eq!(
        flows
            .settings()
            .await
            .expect("settings read")
            .artifacts_root,
        None
    );
}

#[tokio::test]
async fn the_read_cache_roots_are_a_list_setting_like_the_extra_path() {
    let (_tmp, _store, flows) = service().await;
    let settings = flows
        .set_settings(SettingsPatch {
            read_cache_roots: Some(vec![" ~/.cargo/registry ".to_owned(), String::new()]),
            ..SettingsPatch::default()
        })
        .await
        .expect("the caches save");
    assert_eq!(settings.read_cache_roots, ["~/.cargo/registry"]);
}

#[test]
fn a_non_scalar_input_value_is_refused_not_dropped() {
    let error = RunArgs::from_value(&serde_json::json!({
        "id": "demo",
        "inputs": { "repo": ["owner/name"] },
    }))
    .expect_err("an array cannot reach a ${…} substitution");
    assert_eq!(error.cause, CAUSE_INPUT_INVALID);

    let error = RunArgs::from_value(&serde_json::json!({
        "id": "demo",
        "inputs": "owner/name",
    }))
    .expect_err("inputs must be an object");
    assert_eq!(error.cause, CAUSE_INPUT_INVALID);

    let args = RunArgs::from_value(&serde_json::json!({
        "id": "demo",
        "inputs": { "repo": "owner/name", "page": 3 },
    }))
    .expect("strings and numbers are scalar inputs");
    assert_eq!(args.inputs.get("page").map(String::as_str), Some("3"));

    let args = RunArgs::from_value(&serde_json::json!({ "id": "demo" }))
        .expect("a run needs no inputs at all");
    assert!(args.inputs.is_empty());
}

#[test]
fn an_expected_digest_must_look_like_one() {
    let digest = "0123456789abcdef".repeat(4);
    let pinned = RunArgs::from_value(&serde_json::json!({"id": "demo", "expected_digest": digest}))
        .expect("a well-formed pin is accepted");
    assert_eq!(pinned.expected_digest.as_deref(), Some(digest.as_str()));
    for absent in [
        serde_json::json!({"id": "demo"}),
        serde_json::json!({"id": "demo", "expected_digest": null}),
    ] {
        assert_eq!(RunArgs::from_value(&absent).unwrap().expected_digest, None);
    }
    for malformed in [
        serde_json::json!("latest"),
        serde_json::json!(digest.to_uppercase()),
        serde_json::json!(&digest[..63]),
        serde_json::json!(12),
        serde_json::json!(""),
    ] {
        let refusal =
            RunArgs::from_value(&serde_json::json!({"id": "demo", "expected_digest": malformed}))
                .expect_err("a pin that can never match is refused");
        assert_eq!(refusal.cause, CAUSE_INPUT_INVALID, "{malformed}");
    }
}

/// Carried over from the 2026-09 flows review: the origin used to be whatever
/// followed the first `github.com` anywhere in the output.
#[test]
fn only_an_exact_github_host_names_the_origin() {
    for (url, expected) in [
        ("https://github.com/ro-ag/pam.git\n", Some("ro-ag/pam")),
        ("https://github.com/ro-ag/pam", Some("ro-ag/pam")),
        ("git@github.com:ro-ag/pam.git", Some("ro-ag/pam")),
        ("ssh://git@github.com/ro-ag/pam.git", Some("ro-ag/pam")),
        ("ssh://git@github.com:22/ro-ag/pam", Some("ro-ag/pam")),
        ("https://token@GitHub.com/ro-ag/pam.git", Some("ro-ag/pam")),
        // Not GitHub, whatever the name contains.
        ("https://evil.github.com.ua/ro-ag/pam.git", None),
        ("https://github.com.evil.example/ro-ag/pam", None),
        ("https://notgithub.com/ro-ag/pam", None),
        ("https://example.com/github.com/ro-ag", None),
        ("git@evilgithub.com:ro-ag/pam.git", None),
        ("https://github.com@evil.example/ro-ag/pam", None),
        ("file:///srv/github.com/ro-ag/pam", None),
        ("https://github.com/ro-ag", None),
        ("https://github.com/ro-ag/pam/extra", None),
        ("", None),
    ] {
        assert_eq!(origin_from_output(url).as_deref(), expected, "{url:?}");
    }
    // A warning on stderr is interleaved with the URL; it is not the origin,
    // and two different repositories are no answer at all.
    assert_eq!(
        origin_from_output(
            "warning: see https://example.com/github.com/x/y\nhttps://github.com/ro-ag/pam.git\n"
        )
        .as_deref(),
        Some("ro-ag/pam")
    );
    assert_eq!(
        origin_from_output("https://github.com/other/repo\nhttps://github.com/ro-ag/pam\n"),
        None
    );
}

// --- The managed policy ------------------------------------------------------

/// An absolute path on this platform for a unix-shaped `path`.
fn abs(path: &str) -> String {
    if cfg!(windows) {
        format!("C:{}", path.replace('/', "\\"))
    } else {
        path.to_owned()
    }
}

/// The flow keys of a policy, one per mode the settings honour.
fn flows_policy() -> serde_json::Value {
    serde_json::json!({
        "version": 1,
        "revision": "flows-1",
        "flows": {
            "programs": { "allow": ["git", "make"], "reason": "SEC-7" },
            "extra_path": { "allow": [abs("/opt/homebrew")] },
            "artifacts_root": { "default": "~/pam-artifacts" },
            "read_cache_roots": { "locked": ["~/.cargo/registry"] }
        }
    })
}

fn user_settings() -> FlowSettings {
    FlowSettings {
        allowed_programs: vec!["git".to_owned(), "cargo".to_owned(), "make".to_owned()],
        extra_path: vec![
            abs("/opt/homebrew/bin"),
            abs("/opt/homebrewX"),
            abs("/usr/local/bin"),
        ],
        artifacts_root: None,
        read_cache_roots: vec!["~/.cargo/git".to_owned()],
    }
}

#[test]
fn the_effective_settings_narrow_each_list_and_say_how() {
    let view = crate::scope_policy_test::view(&flows_policy());
    let user = user_settings();
    let (effective, entries) = user.managed(&view);
    assert_eq!(effective.allowed_programs, ["git", "make"]);
    // Prefixes by component: `/opt/homebrewX` is not under `/opt/homebrew`.
    assert_eq!(effective.extra_path, [abs("/opt/homebrew/bin")]);
    assert_eq!(effective.artifacts_root.as_deref(), Some("~/pam-artifacts"));
    assert_eq!(effective.read_cache_roots, ["~/.cargo/registry"]);
    assert!(!effective.allows("cargo"));
    assert_eq!(
        user,
        user_settings(),
        "the human's settings are never mutated"
    );

    let block = effective.effective_json(&entries);
    assert_eq!(
        block["allowed_programs"],
        serde_json::json!({
            "value": ["git", "make"],
            "source": "policy",
            "locked": false,
            "mode": "allow",
            "constraint": { "allow": ["git", "make"] },
            "reason": "SEC-7",
            "state": "applied",
            "clamped": true,
        })
    );
    assert_eq!(
        block["extra_path"]["constraint"]["allow"],
        serde_json::json!([abs("/opt/homebrew")])
    );
    assert_eq!(block["artifacts_root"]["source"], "policy");
    assert_eq!(block["artifacts_root"]["locked"], false);
    assert_eq!(block["artifacts_root"]["mode"], "default");
    assert_eq!(block["read_cache_roots"]["locked"], true);
    assert_eq!(block["read_cache_roots"]["mode"], "locked");

    // No policy: the values are the human's and each entry is `{ value,
    // source, locked }`.
    let (same, entries) = user.managed(&crate::managed_policy::PolicyView::unmanaged());
    assert_eq!(same, user);
    let block = same.effective_json(&entries);
    assert_eq!(
        block["allowed_programs"],
        serde_json::json!({ "value": ["git", "cargo", "make"], "source": "user", "locked": false })
    );
    assert_eq!(block["artifacts_root"]["source"], "default");
}

#[tokio::test]
async fn the_flow_service_reads_effective_settings_and_keeps_the_rows_the_human_saved() {
    let (_tmp, store, flows) = managed_service(Some(flows_policy())).await;
    let saved = flows
        .set_settings(SettingsPatch {
            allowed_programs: Some(user_settings().allowed_programs),
            extra_path: Some(user_settings().extra_path),
            ..SettingsPatch::default()
        })
        .await
        .expect("the settings save");
    assert_eq!(
        saved.allowed_programs,
        ["git", "cargo", "make"],
        "set returns what was saved"
    );
    let raw = store.get_setting(SETTING_ALLOWED_PROGRAMS).await.unwrap();

    let effective = flows.settings().await.expect("settings read");
    assert_eq!(effective.allowed_programs, ["git", "make"]);
    assert_eq!(effective.extra_path, [abs("/opt/homebrew/bin")]);
    assert_eq!(effective.read_cache_roots, ["~/.cargo/registry"]);
    assert!(
        effective.artifacts_root_dir().is_some(),
        "the policy default applies"
    );
    let user = flows.user_settings().await.expect("settings read");
    assert_eq!(user.allowed_programs, ["git", "cargo", "make"]);
    assert_eq!(user.artifacts_root, None);
    assert_eq!(
        store.get_setting(SETTING_ALLOWED_PROGRAMS).await.unwrap(),
        raw
    );
    assert!(
        store
            .get_setting(SETTING_ARTIFACTS_ROOT)
            .await
            .unwrap()
            .is_none(),
        "a policy default is never written into the human's row"
    );
}

#[test]
fn a_settings_patch_the_policy_forbids_is_refused_with_the_keys_cause() {
    use crate::flow_service::check_settings_patch;
    use crate::managed_policy::{
        CAUSE_POLICY_FROZEN, CAUSE_POLICY_NOT_ALLOWED, CAUSE_SETTING_LOCKED, Key,
    };
    let view = crate::scope_policy_test::view(&flows_policy());
    let refusal = check_settings_patch(
        &view,
        &SettingsPatch {
            allowed_programs: Some(vec!["git".to_owned(), "cargo".to_owned()]),
            ..SettingsPatch::default()
        },
    )
    .unwrap_err();
    assert_eq!(refusal.cause, CAUSE_POLICY_NOT_ALLOWED);
    assert_eq!(refusal.key, Key::FlowsPrograms);
    assert!(
        refusal.detail.contains("\"cargo\"")
            && refusal.detail.contains("(flows.programs)")
            && refusal.detail.contains("reason: SEC-7")
            && refusal.detail.contains("rev flows-1"),
        "{}",
        refusal.detail
    );
    let locked = check_settings_patch(
        &view,
        &SettingsPatch {
            read_cache_roots: Some(vec!["~/.cargo/registry".to_owned()]),
            ..SettingsPatch::default()
        },
    )
    .unwrap_err();
    assert_eq!(
        (locked.cause, locked.key),
        (CAUSE_SETTING_LOCKED, Key::FlowsReadCacheRoots)
    );
    assert_eq!(
        check_settings_patch(
            &view,
            &SettingsPatch {
                extra_path: Some(vec![abs("/usr/local/bin")]),
                ..SettingsPatch::default()
            },
        )
        .unwrap_err()
        .key,
        Key::FlowsExtraPath
    );
    // Inside the bounds, and a default-only key, pass; a field left out is
    // never checked.
    check_settings_patch(
        &view,
        &SettingsPatch {
            allowed_programs: Some(vec!["make".to_owned(), " git ".to_owned()]),
            extra_path: Some(vec![abs("/opt/homebrew/sbin")]),
            artifacts_root: ArtifactsRootPatch::Set("~/elsewhere".to_owned()),
            read_cache_roots: None,
        },
    )
    .unwrap();

    let locked_root = crate::scope_policy_test::view(&serde_json::json!({
        "version": 1, "flows": { "artifacts_root": { "locked": "~/pam-artifacts" } }
    }));
    assert_eq!(
        check_settings_patch(
            &locked_root,
            &SettingsPatch {
                artifacts_root: ArtifactsRootPatch::Clear,
                ..SettingsPatch::default()
            },
        )
        .unwrap_err()
        .cause,
        CAUSE_SETTING_LOCKED
    );
    let held = crate::scope_policy_test::view(&serde_json::json!({
        "version": 1, "flows": { "programs": { "allow": "git" } }
    }));
    assert!(held.is_held(Key::FlowsPrograms));
    assert_eq!(
        check_settings_patch(
            &held,
            &SettingsPatch {
                allowed_programs: Some(vec!["git".to_owned()]),
                ..SettingsPatch::default()
            },
        )
        .unwrap_err()
        .cause,
        CAUSE_POLICY_FROZEN
    );
}

#[test]
fn a_program_outside_the_policy_is_forbidden_whatever_the_human_allows() {
    use crate::flow_service::policy_forbids_program;
    let allow = crate::scope_policy_test::view(&flows_policy());
    assert!(policy_forbids_program(&allow, "cargo"));
    assert!(!policy_forbids_program(&allow, "git"));
    let locked = crate::scope_policy_test::view(&serde_json::json!({
        "version": 1, "flows": { "programs": { "locked": ["git"] } }
    }));
    assert!(policy_forbids_program(&locked, "make"));
    assert!(!policy_forbids_program(&locked, "git"));
    assert!(!policy_forbids_program(
        &crate::managed_policy::PolicyView::unmanaged(),
        "cargo"
    ));
}

/// Inspection follows the gate's order: a managed never-grant rule refuses
/// a step on every profile, granted or not, so inspection reports
/// `policy_denied` where the gate would; without a rule the profile and the
/// grant decide as before.
#[test]
fn inspection_reports_a_never_rule_as_policy_denied_on_every_profile() {
    use crate::flow_service::inspect_admission;
    use crate::managed_policy::{TargetPlatform, inspect_bytes};
    use crate::policy::{CapabilityClass, Profile};
    let view = inspect_bytes(
        br#"{"version":1,"security":{"grants":{"never":["flow.step:managed/*"],"never_classes":["external"]}}}"#,
        TargetPlatform::host(),
    )
    .result
    .expect("the policy parses");
    for profile in [Profile::Relaxed, Profile::Standard, Profile::Strict] {
        for granted in [false, true] {
            assert_eq!(
                inspect_admission(
                    &view,
                    profile,
                    "flow.step:managed/look",
                    granted,
                    CapabilityClass::Destructive
                ),
                "policy_denied",
                "{profile:?} granted={granted}"
            );
            assert_eq!(
                inspect_admission(
                    &view,
                    profile,
                    "flow.step:other/call",
                    granted,
                    CapabilityClass::External
                ),
                "policy_denied",
                "the class rule, {profile:?}"
            );
            assert_eq!(
                inspect_admission(
                    &view,
                    profile,
                    "flow.step:other/look",
                    granted,
                    CapabilityClass::Destructive
                ),
                profile_and_grant(profile, granted),
                "no rule matches"
            );
        }
    }
    let unmanaged = crate::managed_policy::PolicyView::unmanaged();
    assert_eq!(
        inspect_admission(
            &unmanaged,
            Profile::Relaxed,
            "flow.step:managed/look",
            true,
            CapabilityClass::Destructive
        ),
        profile_and_grant(Profile::Relaxed, true)
    );
}

/// What the profile and the grant alone decide for a destructive step, as
/// inspection labels it.
fn profile_and_grant(profile: crate::policy::Profile, granted: bool) -> &'static str {
    use crate::policy::{CapabilityClass, GrantStanding, decide_with_grant};
    let grant = if granted {
        GrantStanding::Granted
    } else {
        GrantStanding::Missing
    };
    crate::flow_service::admission_label(
        &decide_with_grant(
            profile,
            "flow.step:x/y",
            CapabilityClass::Destructive,
            &grant,
        )
        .decision("flow.step:x/y"),
    )
}

/// The one step of `steps` (a YAML step list) in a flow named `f`.
fn only_step(steps: &str) -> pam_flow::Step {
    let flow = pam_flow::parse(&format!("schema: 1\nid: f\nname: F\nsteps:\n{steps}"))
        .expect("the fixture flow parses");
    flow.steps.into_iter().next().expect("one step")
}

#[test]
fn the_effect_digest_follows_what_runs_and_ignores_how_it_is_written() {
    use crate::flow_service::{step_binding, step_effect_digest};
    let base =
        only_step("  - id: s\n    run: [git, push]\n    effect: stateful\n    env: {A: x}\n");
    let digest = step_effect_digest(&base);
    assert_eq!(digest.len(), 64);
    // Comments, block style, key order, a note and a timeout: the same step.
    let same = only_step(
        "  # tidied by hand\n  - id: s   # same\n    env:\n      A: x\n    effect: stateful\n    \
         note: a note\n    run:\n      - git\n      - push\n",
    );
    assert_eq!(step_effect_digest(&same), digest);
    // What runs changes the digest.
    for changed in [
        "  - id: s\n    run: [git, push, --force]\n    effect: stateful\n    env: {A: x}\n",
        "  - id: s\n    run: [git, push]\n    effect: stateful\n    env: {A: y}\n",
        "  - id: s\n    run: [git, push]\n    effect: stateful\n    env: {B: x}\n",
        "  - id: s\n    run: [git, push]\n    env: {A: x}\n    approval: required\n",
    ] {
        assert_ne!(step_effect_digest(&only_step(changed)), digest, "{changed}");
    }
    // The digest reads the normalized step: a stateful step always asks, so
    // saying so changes nothing.
    let spelled_out = only_step(
        "  - id: s\n    run: [git, push]\n    effect: stateful\n    env: {A: x}\n    approval: required\n",
    );
    assert_eq!(step_effect_digest(&spelled_out), digest);
    let connector = |with: &str| {
        step_effect_digest(&only_step(&format!(
            "  - id: s\n    connector: github\n    call: run\n    with: {with}\n    role: observe\n"
        )))
    };
    let call = connector("{repo: 'o/r', run_id: 1, run_attempt: 1}");
    assert_eq!(connector("{run_attempt: 1, repo: 'o/r', run_id: 1}"), call);
    assert_ne!(
        connector("{repo: 'o/other', run_id: 1, run_attempt: 1}"),
        call
    );
    assert_ne!(connector("{repo: 'o/r', run_id: 2, run_attempt: 1}"), call);
    // The binding carries the gate class the step is evaluated under.
    let flow = pam_flow::parse(
        "schema: 1\nid: f\nname: F\nsteps:\n  - id: s\n    connector: github\n    call: run\n    \
         with: {repo: 'o/r', run_id: 1, run_attempt: 1}\n    role: observe\n",
    )
    .unwrap();
    let binding = step_binding(&flow, &flow.steps[0], Some("/r".to_owned()));
    assert_eq!(binding.effect_class, "external");
    assert_eq!(binding.effect_digest, call);
    assert_eq!(binding.repository.as_deref(), Some("/r"));
}

/// `flow.inspect` and the run cannot disagree about a step's gate: for a
/// matrix of gated steps (a stateful command, an always-asking read-only
/// command, a connector call, a landing operation), every profile, every
/// way a grant can stand (none, bound to the step as it is, bound to an
/// older definition, bound to another repository, an unbound legacy row)
/// and with and without a managed never-grant rule, the pure decision
/// inspection reports is the decision the run's gate returns.
#[tokio::test]
async fn inspection_and_the_run_reach_the_same_gate_decision_for_every_step() {
    use crate::flow_service::{inspect_gate, step_binding, step_capability, step_class};
    use crate::policy::Profile;
    use pam_store::{Actor, AuditEntry, Decision, GrantChange};

    let flow = pam_flow::parse(
        "schema: 1\nid: matrix\nname: Matrix\ncorrelation:\n  repository: 'https://git.example/team/app.git'\n  \
         commit: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'\nsteps:\n  - id: build\n    run: [cargo, build]\n    \
         effect: stateful\n  - id: look\n    run: [git, status]\n    approval: required\n  \
         - id: call\n    connector: github\n    call: run\n    with: {repo: 'o/r', run_id: 1, run_attempt: 1}\n    \
         role: observe\n  - id: freeze\n    landing: freeze\n",
    )
    .expect("the matrix flow parses");
    let repository = Path::new("/repo/matrix");
    let policies = [
        None,
        Some(r#"{"version":1,"security":{"grants":{"never":["flow.step:matrix/build"]}}}"#),
        Some(r#"{"version":1,"security":{"grants":{"never_classes":["external"]}}}"#),
    ];
    let grants = ["none", "bound", "older", "elsewhere", "legacy"];
    let audit = AuditEntry {
        action: "grant_from_approval",
        decision: Decision::Allow,
        actor: Actor::Human,
        detail: None,
    };
    let mut checked = 0;
    let mut seen = std::collections::BTreeSet::new();
    for policy in policies {
        for profile in [Profile::Relaxed, Profile::Standard, Profile::Strict] {
            for grant in grants {
                let (store, handle, gate) = matrix_gate(policy, profile).await;
                for step in &flow.steps {
                    assert!(step.gated(), "{}", step.id);
                    let capability = step_capability(&flow.id, &step.id);
                    let binding =
                        step_binding(&flow, step, Some(repository.to_string_lossy().into_owned()));
                    let mut other = binding.clone();
                    match grant {
                        "older" => other.effect_digest = "0".repeat(64),
                        "elsewhere" => other.repository = Some("/repo/other".to_owned()),
                        _ => {}
                    }
                    let seeded = match grant {
                        "bound" => Some(GrantChange::Bind(&capability, &binding)),
                        "legacy" => Some(GrantChange::Add(&capability)),
                        "older" | "elsewhere" => Some(GrantChange::Bind(&capability, &other)),
                        _ => None,
                    };
                    if let Some(change) = seeded {
                        store
                            .apply_grant_change_audited("req_1", change, audit)
                            .await
                            .unwrap();
                    }
                    // Inspection first: the run binds a legacy grant.
                    let rows = store.active_grants(&capability).await.unwrap();
                    let (inspected, _) = inspect_gate(
                        &flow,
                        step,
                        Some(repository),
                        &handle.view(),
                        gate.profile(),
                        &rows,
                    );
                    let (ran, _) = gate
                        .evaluate_step("req_1", &capability, step_class(step), &binding)
                        .await
                        .unwrap();
                    assert_eq!(
                        inspected, ran,
                        "{} under {profile:?}, grant {grant}, policy {policy:?}",
                        step.id
                    );
                    seen.insert(crate::flow_service::admission_label(&ran));
                    checked += 1;
                }
            }
        }
    }
    assert_eq!(checked, 3 * 3 * 5 * 4);
    // The matrix reaches every decision a gated step can get.
    assert_eq!(
        seen.into_iter().collect::<Vec<_>>(),
        [
            "allowed",
            "approval_required",
            "not_granted",
            "policy_denied"
        ]
    );
}

/// A gate over the stored `profile` under the managed `policy`, with the
/// request row the matrix's gate decisions are audited against.
async fn matrix_gate(
    policy: Option<&str>,
    profile: crate::policy::Profile,
) -> (
    Arc<Store>,
    Arc<crate::managed_policy_service::PolicyHandle>,
    PolicyGate,
) {
    use crate::policy::PROFILE_SETTING_KEY;
    use crate::policy_test::{SwitchablePolicy, managed_handle};
    let store = Arc::new(Store::open_in_memory().await.unwrap());
    store
        .set_setting(
            PROFILE_SETTING_KEY,
            &serde_json::to_string(&profile).unwrap(),
        )
        .await
        .unwrap();
    store
        .insert_request("req_1", "flow.run", "/repo/matrix", "claude", "{}", None)
        .await
        .unwrap();
    let source = SwitchablePolicy::new(policy);
    let handle = managed_handle(&store, &source).await;
    let gate = PolicyGate::new(Arc::clone(&store), Arc::clone(&handle))
        .await
        .unwrap();
    (store, handle, gate)
}
