use std::{fs, path::PathBuf};

use pam_core::{ContentDigest, ProjectId};
use pam_skills::{
    AgentArtifact, ArtifactKind, ArtifactScope, CursorGlobalRulesStatus, LoadSemantics, OriginAgent,
};
use pam_store::{SkillInventoryDrift, StoredAgentArtifact};
use uuid::Uuid;

use crate::skill_inventory::{
    MAX_SKILL_INVENTORY_ITEMS, SkillInventoryEnvironment, inventory_data_for_test,
    load_skill_inventory,
};

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new(name: &str) -> Self {
        let path = std::env::temp_dir().join(format!("pam-gui-{name}-{}", Uuid::new_v4()));
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }

    fn path(&self) -> &std::path::Path {
        &self.0
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn toml_key(path: &std::path::Path) -> String {
    path.to_string_lossy()
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
}

fn stored_artifact(index: usize) -> StoredAgentArtifact {
    let artifact = AgentArtifact::new(
        format!("skill-{index}"),
        format!(".claude/skills/skill-{index}/SKILL.md"),
        ArtifactKind::Skill,
        ArtifactScope::Project,
        OriginAgent::ClaudeCode,
        LoadSemantics::ModelSelected,
        ContentDigest::from_sha256([u8::try_from(index % 255).unwrap(); 32]),
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
fn inventory_dto_is_bounded_and_contains_metadata_only() {
    let records = (0..=MAX_SKILL_INVENTORY_ITEMS)
        .map(stored_artifact)
        .collect::<Vec<_>>();
    let drift = SkillInventoryDrift {
        added: vec![records[0].clone()],
        changed: vec![records[1].clone()],
        removed: vec![records[2].clone()],
        resurrected: vec![records[3].clone()],
    };

    let data = inventory_data_for_test(
        &records,
        &drift,
        CursorGlobalRulesStatus::NotLocallyDiscoverable,
    );
    let json = serde_json::to_value(&data).unwrap();

    assert_eq!(data.total, MAX_SKILL_INVENTORY_ITEMS + 1);
    assert_eq!(data.artifacts.len(), MAX_SKILL_INVENTORY_ITEMS);
    assert!(data.truncated);
    assert_eq!(data.drift.added, 1);
    assert_eq!(data.drift.changed, 1);
    assert_eq!(data.drift.removed, 1);
    assert_eq!(data.drift.resurrected, 1);
    assert!(json.get("source").is_none());
    assert!(json.get("body").is_none());
    assert!(!json.to_string().contains("SKILL source"));
}

#[tokio::test]
async fn local_scan_persists_inventory_and_reports_drift_once() {
    let directory = TestDirectory::new("skill-inventory");
    let home = directory.path().join("home");
    let project = directory.path().join("project");
    let skill = home.join(".claude/skills/review/SKILL.md");
    let rule = project.join(".cursor/rules/project.mdc");
    fs::create_dir_all(skill.parent().unwrap()).unwrap();
    fs::create_dir_all(rule.parent().unwrap()).unwrap();
    fs::write(&skill, "---\nname: review\n---\nReview changes.\n").unwrap();
    fs::write(&rule, "---\nalwaysApply: true\n---\nUse project rules.\n").unwrap();
    let state = directory.path().join("state.sqlite3");
    let project_id = ProjectId::new("inventory-project");

    let first = load_skill_inventory(
        project_id.clone(),
        SkillInventoryEnvironment::for_test(home.clone(), project.clone(), state.clone(), 10),
    )
    .await
    .unwrap();
    let second = load_skill_inventory(
        project_id,
        SkillInventoryEnvironment::for_test(home, project, state, 20),
    )
    .await
    .unwrap();

    assert_eq!(first.total, 2);
    assert_eq!(first.drift.added, 2);
    assert!(second.drift.is_empty());
    assert_eq!(second.total, 2);
    assert!(
        second
            .artifacts
            .iter()
            .all(|artifact| !artifact.id.is_empty())
    );
}

#[tokio::test]
async fn desktop_environment_uses_exact_user_codex_trust() {
    let directory = TestDirectory::new("trusted-skill-inventory");
    let home = directory.path().join("home");
    let project = directory.path().join("project");
    fs::create_dir_all(home.join(".codex")).unwrap();
    fs::create_dir_all(project.join(".codex")).unwrap();
    fs::write(
        home.join(".codex/config.toml"),
        format!(
            "[projects.\"{}\"]\ntrust_level = \"trusted\"\n",
            toml_key(&project)
        ),
    )
    .unwrap();
    fs::write(project.join(".codex/config.toml"), b"model = \"project\"\n").unwrap();
    let state = directory.path().join("state.sqlite3");

    let inventory = load_skill_inventory(
        ProjectId::new("trusted-inventory-project"),
        SkillInventoryEnvironment::for_test(home, project, state, 10),
    )
    .await
    .unwrap();

    assert!(inventory.artifacts.iter().any(|artifact| {
        artifact.origin == "codex" && artifact.logical_path == ".codex/config.toml"
    }));
}
