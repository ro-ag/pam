use std::{
    ffi::OsStr,
    fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use pam_core::{ContentDigest, ProjectId};
use pam_platform::discover_project;
use pam_skills::{
    AgentArtifact, AgentArtifactId, ArtifactKind, ArtifactScope, CursorGlobalRulesStatus,
    EvaluatorRunConfig, LoadSemantics, LocalInventoryRoots, OriginAgent,
    SkillsAuditEvaluationStatus,
};
use pam_store::{SkillInventoryDrift, Store, StoreError, StoredAgentArtifact};
use serde_json::json;

use super::skills::{
    AuditRequest, InventoryOutput, InventoryRecords, InventoryRequest, InventorySelection,
    SkillsEnvironment, SkillsError, render_audit, render_inventory, run_audit, run_inventory,
};

static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(1);

struct TestDirectory {
    path: PathBuf,
}

impl TestDirectory {
    fn new(label: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "pam-cli-skills-{label}-{}-{}",
            std::process::id(),
            NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn write(&self, relative: &str, bytes: impl AsRef<[u8]>) {
        let path = self.path.join(relative);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, bytes).unwrap();
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.path).unwrap();
    }
}

fn toml_key(path: &Path) -> String {
    path.to_string_lossy()
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
}

fn stored(path: &str, byte: u8) -> StoredAgentArtifact {
    let artifact = AgentArtifact::new(
        "review",
        path,
        ArtifactKind::Skill,
        ArtifactScope::Project,
        OriginAgent::ClaudeCode,
        LoadSemantics::ModelSelected,
        ContentDigest::from_sha256([byte; 32]),
    )
    .unwrap();
    StoredAgentArtifact {
        id: artifact.id(),
        artifact,
        first_seen_at_ms: 10,
        last_changed_at_ms: 20,
        removed_at_ms: None,
    }
}

#[test]
fn deterministic_json_contract_contains_only_normalized_metadata() {
    let record = stored(".claude/skills/review/SKILL.md", 0xab);
    let output = InventoryOutput {
        project_id: ProjectId::from("project-one"),
        cursor_global_rules_status: CursorGlobalRulesStatus::NotLocallyDiscoverable,
        drift: SkillInventoryDrift {
            added: vec![record.clone()],
            ..SkillInventoryDrift::default()
        },
        records: InventoryRecords::List(vec![record.clone()]),
    };
    let rendered = render_inventory(&output, true).unwrap();
    assert_eq!(rendered, render_inventory(&output, true).unwrap());
    let value = serde_json::from_str::<serde_json::Value>(&rendered).unwrap();
    assert_eq!(value["schemaVersion"], 1);
    assert_eq!(value["projectId"], "project-one");
    assert_eq!(value["cursorGlobalRulesStatus"], "not_locally_discoverable");
    assert_eq!(value["drift"]["added"], json!([record.id.as_str()]));
    assert_eq!(value["artifacts"][0]["kind"], "skill");
    assert_eq!(value["artifacts"][0]["firstSeenAtMs"], 10);
    assert_eq!(value["artifacts"][0]["lastChangedAtMs"], 20);
    assert!(!rendered.contains("sourceContent"));
    assert!(!rendered.contains("private source body"));
}

#[test]
fn human_list_has_a_clear_empty_state() {
    let output = InventoryOutput {
        project_id: ProjectId::from("empty-project"),
        cursor_global_rules_status: CursorGlobalRulesStatus::NotLocallyDiscoverable,
        drift: SkillInventoryDrift::default(),
        records: InventoryRecords::List(Vec::new()),
    };
    let rendered = render_inventory(&output, false).unwrap();
    assert!(rendered.contains("No active skill artifacts discovered."));
    assert!(rendered.contains("added=0 changed=0 removed=0 resurrected=0"));
}

#[tokio::test]
async fn no_evaluator_audit_json_and_human_are_deterministic_and_private() {
    let project = TestDirectory::new("audit-fallback-project");
    let private_body = "private audit source body must never render";
    project.write("AGENTS.md", private_body);
    project.write("CLAUDE.md", b"second private source body\n");
    let state = TestDirectory::new("audit-fallback-state");
    let state_path = state.path().join("state.sqlite3");
    let project_id = ProjectId::from("audit-fallback-project");

    let output = run_audit(audit_request(&project, &state_path, &project_id, 10))
        .await
        .unwrap();
    let json = render_audit(&output, true);
    let human = render_audit(&output, false);

    assert_eq!(json, output.report_json);
    assert_eq!(json, render_audit(&output, true));
    assert_eq!(human, render_audit(&output, false));
    assert!(matches!(
        output.report.evaluation(),
        SkillsAuditEvaluationStatus::NoEvaluator
    ));
    let value = serde_json::from_str::<serde_json::Value>(&json).unwrap();
    assert_eq!(value["schemaVersion"], output.report.schema_version());
    assert_eq!(value["evaluation"]["status"], "no_evaluator");
    assert!(human.contains("Project: audit-fallback-project"));
    assert!(human.contains("Agent session totals:"));
    assert!(human.contains("All sessions: artifacts="));
    assert!(human.contains("All-session scope totals:"));
    assert!(human.contains("Ranked always-loaded artifacts:"));
    assert!(human.contains("Evaluation: no_evaluator"));
    assert!(!human.contains("Saturation grade:"));
    for rendered in [&json, &human, &format!("{output:?}")] {
        assert!(!rendered.contains(private_body));
        assert!(!rendered.contains("second private source body"));
    }
}

#[tokio::test]
async fn audit_persists_the_same_scan_and_exact_report_across_reopen() {
    let project = TestDirectory::new("audit-persistence-project");
    project.write("AGENTS.md", b"project audit instructions\n");
    project.write("CLAUDE.md", b"claude audit instructions\n");
    let state = TestDirectory::new("audit-persistence-state");
    let state_path = state.path().join("state.sqlite3");
    let project_id = ProjectId::from("audit-persistence-project");

    let output = run_audit(audit_request(&project, &state_path, &project_id, 42))
        .await
        .unwrap();

    let store = Store::open(&state_path).unwrap();
    let artifacts = store.skill_artifacts(project_id.clone()).await.unwrap();
    let stored_report = store
        .skills_audit_report(project_id.clone())
        .await
        .unwrap()
        .unwrap();
    store.shutdown().await.unwrap();

    assert!(!artifacts.is_empty());
    assert_eq!(artifacts.len(), output.report.footprint().artifacts().len());
    assert_eq!(stored_report.project_id, project_id);
    assert_eq!(stored_report.observed_at_ms, 42);
    assert_eq!(stored_report.schema_version, output.report.schema_version());
    assert_eq!(stored_report.report_json, output.report_json);
    assert_eq!(render_audit(&output, true), stored_report.report_json);
}

#[tokio::test]
async fn incomplete_audit_scan_leaves_prior_inventory_and_report_unchanged() {
    let project = TestDirectory::new("audit-incomplete-project");
    project.write("AGENTS.md", b"initial complete source\n");
    let state = TestDirectory::new("audit-incomplete-state");
    let state_path = state.path().join("state.sqlite3");
    let project_id = ProjectId::from("audit-incomplete-project");

    let initial = run_audit(audit_request(&project, &state_path, &project_id, 10))
        .await
        .unwrap();
    let store = Store::open(&state_path).unwrap();
    let prior_artifacts = store.skill_artifacts(project_id.clone()).await.unwrap();
    store.shutdown().await.unwrap();

    project.write("AGENTS.md", vec![b'x'; 1024 * 1024 + 1]);
    let error = run_audit(audit_request(&project, &state_path, &project_id, 20))
        .await
        .unwrap_err();
    assert!(matches!(error, SkillsError::IncompleteScan(_)));

    let store = Store::open(&state_path).unwrap();
    let current_artifacts = store.skill_artifacts(project_id.clone()).await.unwrap();
    let current_report = store
        .skills_audit_report(project_id)
        .await
        .unwrap()
        .unwrap();
    store.shutdown().await.unwrap();
    assert_eq!(current_artifacts, prior_artifacts);
    assert_eq!(current_report.observed_at_ms, 10);
    assert_eq!(current_report.report_json, initial.report_json);
}

#[tokio::test]
async fn merged_scan_is_persisted_idempotently_and_show_not_found_is_typed() {
    let project = TestDirectory::new("inventory-project");
    let private_body = "private agent source must never render";
    project.write("AGENTS.md", private_body);
    project.write(
        ".cursor/rules/manual.mdc",
        b"---\nalwaysApply: false\n---\nprivate cursor body\n",
    );
    let state = TestDirectory::new("inventory-state");
    let state_path = state.path().join("state.sqlite3");
    let project_id = ProjectId::from("fixture-project");

    let first = run_inventory(
        request(&project, &state_path, &project_id, 10),
        InventorySelection::List,
    )
    .await
    .unwrap();
    assert!(!first.drift.added.is_empty());
    let json = render_inventory(&first, true).unwrap();
    assert!(!json.contains(private_body));
    assert!(!json.contains("private cursor body"));

    let second = run_inventory(
        request(&project, &state_path, &project_id, 20),
        InventorySelection::List,
    )
    .await
    .unwrap();
    assert!(second.drift.is_empty());
    let InventoryRecords::List(records) = second.records else {
        panic!("expected list records");
    };
    assert!(!records.is_empty());

    let missing = AgentArtifactId::parse(format!("artifact:sha256:{}", "00".repeat(32))).unwrap();
    let error = run_inventory(
        request(&project, &state_path, &project_id, 30),
        InventorySelection::Show(missing.clone()),
    )
    .await
    .unwrap_err();
    assert!(matches!(
        error,
        SkillsError::Store(StoreError::SkillArtifactNotFound { artifact_id, .. })
            if artifact_id == missing
    ));
}

#[tokio::test]
async fn nested_discovery_scans_the_canonical_root_and_avoids_false_drift() {
    let project = TestDirectory::new("nested-inventory-project");
    project.write(
        ".pam/project.toml",
        b"version = 1\nproject_id = \"11111111-1111-4111-8111-111111111111\"\n",
    );
    project.write("AGENTS.md", b"root instructions\n");
    project.write("nested/deeper/AGENTS.md", b"nested instructions\n");
    let nested = project.path().join("nested/deeper");
    let home = TestDirectory::new("nested-inventory-home");
    let state = TestDirectory::new("nested-inventory-state");
    let state_path = state.path().join("state.sqlite3");
    let identity = discover_project(&nested).unwrap();

    let nested_environment =
        SkillsEnvironment::for_test(&nested, home.path().to_path_buf(), state_path.clone())
            .unwrap();
    assert_eq!(
        nested_environment.roots().current_working_directory,
        identity.root()
    );
    let first = run_inventory(
        InventoryRequest {
            roots: nested_environment.roots(),
            project_id: identity.id(),
            state_path: &state_path,
            observed_at_ms: 10,
        },
        InventorySelection::List,
    )
    .await
    .unwrap();

    let root_environment = SkillsEnvironment::for_test(
        project.path(),
        home.path().to_path_buf(),
        state_path.clone(),
    )
    .unwrap();
    let second = run_inventory(
        InventoryRequest {
            roots: root_environment.roots(),
            project_id: identity.id(),
            state_path: &state_path,
            observed_at_ms: 20,
        },
        InventorySelection::List,
    )
    .await
    .unwrap();

    assert!(!first.drift.added.is_empty());
    assert!(second.drift.is_empty());
    let InventoryRecords::List(records) = second.records else {
        panic!("expected list records");
    };
    assert!(
        records
            .iter()
            .all(|record| record.artifact.logical_path() != "nested/deeper/AGENTS.md")
    );
}

#[tokio::test]
async fn cli_environment_uses_exact_user_codex_trust() {
    let project = TestDirectory::new("trusted-inventory-project");
    project.write(
        ".pam/project.toml",
        b"version = 1\nproject_id = \"22222222-2222-4222-8222-222222222222\"\n",
    );
    project.write(".codex/config.toml", b"model = \"project\"\n");
    let home = TestDirectory::new("trusted-inventory-home");
    home.write(
        ".codex/config.toml",
        format!(
            "[projects.\"{}\"]\ntrust_level = \"trusted\"\n",
            toml_key(project.path())
        ),
    );
    let state = TestDirectory::new("trusted-inventory-state");
    let state_path = state.path().join("state.sqlite3");
    let environment = SkillsEnvironment::for_test(
        project.path(),
        home.path().to_path_buf(),
        state_path.clone(),
    )
    .unwrap();
    let identity = discover_project(project.path()).unwrap();

    let output = run_inventory(
        InventoryRequest {
            roots: environment.roots(),
            project_id: identity.id(),
            state_path: &state_path,
            observed_at_ms: 10,
        },
        InventorySelection::List,
    )
    .await
    .unwrap();
    let InventoryRecords::List(records) = output.records else {
        panic!("expected list records");
    };
    assert!(records.iter().any(|record| {
        record.artifact.origin() == OriginAgent::Codex
            && record.artifact.logical_path() == ".codex/config.toml"
    }));
}

fn request<'a>(
    project: &'a TestDirectory,
    state_path: &'a Path,
    project_id: &'a ProjectId,
    observed_at_ms: u64,
) -> InventoryRequest<'a> {
    InventoryRequest {
        roots: LocalInventoryRoots {
            user_home: None,
            claude_plugin_registry_root: None,
            codex_system_config_root: None,
            codex_home: None,
            project_root: project.path(),
            current_working_directory: project.path(),
            cursor_global_rule: None,
        },
        project_id,
        state_path,
        observed_at_ms,
    }
}

fn audit_request<'a>(
    project: &'a TestDirectory,
    state_path: &'a Path,
    project_id: &'a ProjectId,
    observed_at_ms: u64,
) -> AuditRequest<'a> {
    AuditRequest {
        roots: LocalInventoryRoots {
            user_home: None,
            claude_plugin_registry_root: None,
            codex_system_config_root: None,
            codex_home: None,
            project_root: project.path(),
            current_working_directory: project.path(),
            cursor_global_rule: None,
        },
        project_id,
        state_path,
        observed_at_ms,
        injected_path: OsStr::new(""),
        evaluator_config: EvaluatorRunConfig::default(),
    }
}
