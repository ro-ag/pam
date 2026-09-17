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
    step_capability,
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
    // The gate gets a store of its own: `PolicyGate::new` persists the
    // platform-default profile on its first read, and no test using this
    // helper runs a step (which is the only thing that consults the
    // gate), so the store under test must not grow that setting.
    let gate_store = Arc::new(Store::open_in_memory().await.expect("store opens"));
    let gate = Arc::new(PolicyGate::new(gate_store).await.expect("the gate builds"));
    Arc::new(FlowService::new(
        base,
        Arc::clone(store),
        Arc::clone(approvals),
        Arc::clone(connectors),
        Arc::clone(logs),
        gate,
    ))
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
    let tmp = tempfile::tempdir().expect("tempdir");
    let store = Arc::new(Store::open_in_memory().await.expect("store opens"));
    let (events, _rx) = EventPublisher::for_tests();
    let approvals = Arc::new(ApprovalService::new(
        Arc::clone(&store),
        events,
        std::time::Duration::from_mins(1),
    ));
    let models = crate::model_service::ModelService::new(Arc::clone(&store))
        .await
        .expect("the model service builds");
    let logs = LogService::new(Arc::clone(&store), models);
    let connectors = Arc::new(ConnectorService::from_parts(Arc::clone(&store), None, None));
    let flows = flows_for_tests(tmp.path(), &store, &approvals, &connectors, &logs).await;
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
