use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

use pam_core::ProjectId;
use pam_skills::{
    CanonicalEntryId, CanonicalLibrary, LibraryEnablementKey, LibraryProjectKey, OriginAgent,
};
use pam_store::{SkillInventoryDrift, StoredAgentArtifact};
use serde_json::Value;
use uuid::Uuid;

use super::skills::{
    InventoryOutput, InventoryRecords, InventoryRequest, InventorySelection, LibraryOperation,
    SkillsEnvironment, render_library_operation, run_inventory, run_library_operation,
};
use crate::command::SkillsAgentArg;

struct RoundTripFixture {
    root: PathBuf,
}

impl RoundTripFixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!("pam-round trip-{}", Uuid::new_v4()));
        fs::create_dir(&root).unwrap();
        Self { root }
    }

    fn path(&self) -> &Path {
        &self.root
    }
}

impl Drop for RoundTripFixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.root).unwrap();
    }
}

#[derive(Debug, Eq, PartialEq)]
enum TreeNode {
    Directory,
    File(Vec<u8>),
    Symlink(PathBuf),
    Other,
}

fn snapshot_tree(root: &Path) -> BTreeMap<PathBuf, TreeNode> {
    fn visit(root: &Path, directory: &Path, snapshot: &mut BTreeMap<PathBuf, TreeNode>) {
        let mut entries = fs::read_dir(directory)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect::<Vec<_>>();
        entries.sort();
        for path in entries {
            let relative = path.strip_prefix(root).unwrap().to_path_buf();
            let metadata = fs::symlink_metadata(&path).unwrap();
            let node = if metadata.file_type().is_symlink() {
                TreeNode::Symlink(fs::read_link(&path).unwrap())
            } else if metadata.is_dir() {
                TreeNode::Directory
            } else if metadata.is_file() {
                TreeNode::File(fs::read(&path).unwrap())
            } else {
                TreeNode::Other
            };
            snapshot.insert(relative, node);
            if metadata.is_dir() {
                visit(root, &path, snapshot);
            }
        }
    }

    let mut snapshot = BTreeMap::new();
    visit(root, root, &mut snapshot);
    snapshot
}

async fn inventory(
    environment: &SkillsEnvironment,
    project_id: &ProjectId,
    state_path: &Path,
    observed_at_ms: u64,
) -> InventoryOutput {
    run_inventory(
        InventoryRequest {
            roots: environment.roots(),
            project_id,
            state_path,
            observed_at_ms,
        },
        InventorySelection::List,
    )
    .await
    .unwrap()
}

fn records(output: &InventoryOutput) -> &[StoredAgentArtifact] {
    let InventoryRecords::List(records) = &output.records else {
        panic!("fixture inventory must be a list");
    };
    records
}

fn assert_only_added(drift: &SkillInventoryDrift, logical_path: &str) {
    assert_eq!(drift.added.len(), 1);
    assert_eq!(drift.added[0].artifact.logical_path(), logical_path);
    assert!(drift.changed.is_empty());
    assert!(drift.removed.is_empty());
    assert!(drift.resurrected.is_empty());
}

fn assert_only_changed(drift: &SkillInventoryDrift, logical_path: &str) {
    assert!(drift.added.is_empty());
    assert_eq!(drift.changed.len(), 1);
    assert_eq!(drift.changed[0].artifact.logical_path(), logical_path);
    assert!(drift.removed.is_empty());
    assert!(drift.resurrected.is_empty());
}

fn assert_only_managed(library: &CanonicalLibrary, key: &LibraryEnablementKey) {
    let managed = library.managed_copies().unwrap();
    assert_eq!(managed.len(), 1);
    assert_eq!(&managed[0], key);
}

fn operation(
    environment: &SkillsEnvironment,
    project_key: &LibraryProjectKey,
    operation: LibraryOperation,
) -> Value {
    let output = run_library_operation(environment, operation).unwrap();
    let encoded = render_library_operation(&output, true).unwrap();
    for private in [
        "project with spaces",
        "user home with spaces",
        "source skill",
        "LF line",
        "local edit with spaces",
    ] {
        assert!(!encoded.contains(private));
    }
    let value = serde_json::from_str::<Value>(&encoded).unwrap();
    let envelope = value.as_object().unwrap();
    assert_eq!(envelope.len(), 3);
    assert_eq!(envelope["schemaVersion"], 1);
    assert_eq!(envelope["projectKey"], project_key.as_str());
    assert!(envelope["result"].is_object());
    value
}

fn result(output: &Value) -> &Value {
    &output["result"]
}

fn assert_identity(
    output: &Value,
    action: &str,
    entry_id: &CanonicalEntryId,
    version: &pam_core::ContentDigest,
) {
    assert_eq!(result(output)["action"], action);
    assert_eq!(result(output)["entryId"], entry_id.as_str());
    assert_eq!(result(output)["version"], version.as_str());
    assert_eq!(result(output)["agent"], "claude");
}

fn assert_single_step(
    output: &Value,
    action: &str,
    applied: bool,
    step_action: &str,
    entry_id: &CanonicalEntryId,
    version: &pam_core::ContentDigest,
) {
    let result = result(output);
    assert_eq!(result["action"], action);
    assert_eq!(result["applied"], applied);
    let steps = result["steps"].as_array().unwrap();
    assert_eq!(steps.len(), 1);
    assert_eq!(steps[0]["entryId"], entry_id.as_str());
    assert_eq!(steps[0]["version"], version.as_str());
    assert_eq!(steps[0]["agent"], "claude");
    assert_eq!(steps[0]["action"], step_action);
}

fn backup_bytes(destination: &Path) -> Vec<u8> {
    let prefix = format!(
        ".{}.pam-backup-",
        destination.file_name().unwrap().to_string_lossy()
    );
    let mut backups = fs::read_dir(destination.parent().unwrap())
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| {
            path.file_name()
                .is_some_and(|name| name.to_string_lossy().starts_with(&prefix))
        })
        .collect::<Vec<_>>();
    backups.sort();
    assert_eq!(backups.len(), 1);
    fs::read(&backups[0]).unwrap()
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn native_skill_round_trip_preserves_exact_bytes_and_stabilizes_inventory() {
    let fixture = RoundTripFixture::new();
    let project_root = fixture.path().join("project with spaces");
    let user_home = fixture.path().join("user home with spaces");
    let library_home = user_home.join(".ptrack");
    let state_path = fixture.path().join("state with spaces.sqlite3");
    let agent_root = project_root.join(".claude");
    let source = agent_root.join("skills/source skill/SKILL.md");
    let destination = agent_root.join("skills/round-trip/SKILL.md");
    let source_logical_path = ".claude/skills/source skill/SKILL.md";
    let destination_logical_path = ".claude/skills/round-trip/SKILL.md";
    let exact_bytes = "LF line\nCRLF line\r\nUnicode: café 東京\nspaces  stay \n".as_bytes();
    let drifted_bytes = "local edit with spaces\r\nUnicode: naïve\n".as_bytes();
    let project_id = ProjectId::new("88888888-8888-4888-8888-888888888888");
    let project_key = LibraryProjectKey::parse(project_id.as_str()).unwrap();
    fs::create_dir_all(source.parent().unwrap()).unwrap();
    fs::create_dir_all(&library_home).unwrap();
    fs::create_dir_all(project_root.join(".pam")).unwrap();
    fs::write(
        project_root.join(".pam/project.toml"),
        b"version = 1\nproject_id = \"88888888-8888-4888-8888-888888888888\"\n",
    )
    .unwrap();
    fs::write(&source, exact_bytes).unwrap();
    let environment =
        SkillsEnvironment::for_test(&project_root, user_home, state_path.clone()).unwrap();

    let source_only = inventory(&environment, &project_id, &state_path, 10).await;
    assert_only_added(&source_only.drift, source_logical_path);
    let source_record = records(&source_only)
        .iter()
        .find(|record| record.artifact.logical_path() == source_logical_path)
        .unwrap()
        .clone();
    assert_eq!(source_record.first_seen_at_ms, 10);
    assert_eq!(source_record.last_changed_at_ms, 10);

    let entry_id = CanonicalEntryId::parse("round-trip").unwrap();
    let adopted = operation(
        &environment,
        &project_key,
        LibraryOperation::Adopt {
            entry_id: entry_id.clone(),
            artifact_id: source_record.id.clone(),
        },
    );
    let library = CanonicalLibrary::open(&library_home).unwrap();
    let version = library.entries().unwrap()[0].versions()[0].clone();
    assert_eq!(result(&adopted)["action"], "adopt");
    assert_eq!(result(&adopted)["entryId"], entry_id.as_str());
    assert_eq!(result(&adopted)["artifactId"], source_record.id.as_str());
    assert_eq!(result(&adopted)["version"], version.as_str());
    assert_eq!(result(&adopted)["disposition"], "inserted");
    assert_eq!(fs::read(&source).unwrap(), exact_bytes);
    assert_eq!(library.read(&entry_id, &version).unwrap(), exact_bytes);

    let enabled = operation(
        &environment,
        &project_key,
        LibraryOperation::Enable {
            entry_id: entry_id.clone(),
            version: version.clone(),
            agent: SkillsAgentArg::Claude,
        },
    );
    assert_identity(&enabled, "enable", &entry_id, &version);
    assert_eq!(result(&enabled)["changed"], true);
    let key = LibraryEnablementKey::new(
        entry_id.clone(),
        version.clone(),
        OriginAgent::ClaudeCode,
        project_key.clone(),
    );
    assert!(library.managed_copies().unwrap().is_empty());
    let before_preview = snapshot_tree(&agent_root);
    let preview = operation(
        &environment,
        &project_key,
        LibraryOperation::Materialize {
            entry_id: entry_id.clone(),
            version: version.clone(),
            agent: SkillsAgentArg::Claude,
            root: None,
            apply: false,
        },
    );
    assert_single_step(
        &preview,
        "materialize",
        false,
        "create",
        &entry_id,
        &version,
    );
    assert_eq!(snapshot_tree(&agent_root), before_preview);
    assert!(library.managed_copies().unwrap().is_empty());
    assert!(!destination.exists());

    let applied = operation(
        &environment,
        &project_key,
        LibraryOperation::Materialize {
            entry_id: entry_id.clone(),
            version: version.clone(),
            agent: SkillsAgentArg::Claude,
            root: None,
            apply: true,
        },
    );
    assert_single_step(&applied, "materialize", true, "create", &entry_id, &version);
    assert_only_managed(&library, &key);
    assert_eq!(fs::read(&source).unwrap(), exact_bytes);
    assert_eq!(library.read(&entry_id, &version).unwrap(), exact_bytes);
    assert_eq!(fs::read(&destination).unwrap(), exact_bytes);

    let destination_added = inventory(&environment, &project_id, &state_path, 11).await;
    assert_only_added(&destination_added.drift, destination_logical_path);
    let added_records = records(&destination_added).to_vec();
    assert_eq!(
        added_records
            .iter()
            .find(|record| record.id == source_record.id)
            .unwrap(),
        &source_record
    );
    let stable_after_add = inventory(&environment, &project_id, &state_path, 12).await;
    assert!(stable_after_add.drift.is_empty());
    assert_eq!(records(&stable_after_add), added_records);
    let clean = operation(
        &environment,
        &project_key,
        LibraryOperation::Drift {
            entry_id: entry_id.clone(),
            version: version.clone(),
            agent: SkillsAgentArg::Claude,
            root: None,
        },
    );
    assert_identity(&clean, "drift", &entry_id, &version);
    assert_eq!(result(&clean)["state"], "clean");

    drop(library);
    let repeated_adoption = operation(
        &environment,
        &project_key,
        LibraryOperation::Adopt {
            entry_id: entry_id.clone(),
            artifact_id: source_record.id.clone(),
        },
    );
    assert_eq!(result(&repeated_adoption)["action"], "adopt");
    assert_eq!(result(&repeated_adoption)["entryId"], entry_id.as_str());
    assert_eq!(
        result(&repeated_adoption)["artifactId"],
        source_record.id.as_str()
    );
    assert_eq!(result(&repeated_adoption)["version"], version.as_str());
    assert_eq!(result(&repeated_adoption)["disposition"], "already_present");
    let repeated_enable = operation(
        &environment,
        &project_key,
        LibraryOperation::Enable {
            entry_id: entry_id.clone(),
            version: version.clone(),
            agent: SkillsAgentArg::Claude,
        },
    );
    assert_identity(&repeated_enable, "enable", &entry_id, &version);
    assert_eq!(result(&repeated_enable)["changed"], false);
    let repeated_preview_tree = snapshot_tree(&agent_root);
    let repeated_preview = operation(
        &environment,
        &project_key,
        LibraryOperation::Materialize {
            entry_id: entry_id.clone(),
            version: version.clone(),
            agent: SkillsAgentArg::Claude,
            root: None,
            apply: false,
        },
    );
    assert_single_step(
        &repeated_preview,
        "materialize",
        false,
        "no_op",
        &entry_id,
        &version,
    );
    assert_eq!(snapshot_tree(&agent_root), repeated_preview_tree);
    let repeated_apply = operation(
        &environment,
        &project_key,
        LibraryOperation::Materialize {
            entry_id: entry_id.clone(),
            version: version.clone(),
            agent: SkillsAgentArg::Claude,
            root: None,
            apply: true,
        },
    );
    assert_single_step(
        &repeated_apply,
        "materialize",
        true,
        "no_op",
        &entry_id,
        &version,
    );
    let library = CanonicalLibrary::open(&library_home).unwrap();
    assert_only_managed(&library, &key);
    assert_eq!(fs::read(&source).unwrap(), exact_bytes);
    assert_eq!(library.read(&entry_id, &version).unwrap(), exact_bytes);
    assert_eq!(fs::read(&destination).unwrap(), exact_bytes);

    fs::write(&destination, drifted_bytes).unwrap();
    let modified = operation(
        &environment,
        &project_key,
        LibraryOperation::Drift {
            entry_id: entry_id.clone(),
            version: version.clone(),
            agent: SkillsAgentArg::Claude,
            root: None,
        },
    );
    assert_identity(&modified, "drift", &entry_id, &version);
    assert_eq!(result(&modified)["state"], "modified");
    let before_resync_preview = snapshot_tree(&agent_root);
    let resync_preview = operation(
        &environment,
        &project_key,
        LibraryOperation::Resync {
            entry_id: entry_id.clone(),
            version: version.clone(),
            agent: SkillsAgentArg::Claude,
            root: None,
            apply: false,
        },
    );
    assert_single_step(
        &resync_preview,
        "resync",
        false,
        "replace",
        &entry_id,
        &version,
    );
    assert_eq!(snapshot_tree(&agent_root), before_resync_preview);
    assert_only_managed(&library, &key);
    let modified_inventory = inventory(&environment, &project_id, &state_path, 13).await;
    assert_only_changed(&modified_inventory.drift, destination_logical_path);

    let resynced = operation(
        &environment,
        &project_key,
        LibraryOperation::Resync {
            entry_id: entry_id.clone(),
            version: version.clone(),
            agent: SkillsAgentArg::Claude,
            root: None,
            apply: true,
        },
    );
    assert_single_step(&resynced, "resync", true, "replace", &entry_id, &version);
    assert_eq!(backup_bytes(&destination), drifted_bytes);
    assert_eq!(fs::read(&source).unwrap(), exact_bytes);
    assert_eq!(library.read(&entry_id, &version).unwrap(), exact_bytes);
    assert_eq!(fs::read(&destination).unwrap(), exact_bytes);
    assert_only_managed(&library, &key);
    let clean_after_resync = operation(
        &environment,
        &project_key,
        LibraryOperation::Drift {
            entry_id: entry_id.clone(),
            version: version.clone(),
            agent: SkillsAgentArg::Claude,
            root: None,
        },
    );
    assert_identity(&clean_after_resync, "drift", &entry_id, &version);
    assert_eq!(result(&clean_after_resync)["state"], "clean");

    let restored = inventory(&environment, &project_id, &state_path, 14).await;
    assert_only_changed(&restored.drift, destination_logical_path);
    let restored_records = records(&restored).to_vec();
    let stable_restored = inventory(&environment, &project_id, &state_path, 15).await;
    assert!(stable_restored.drift.is_empty());
    assert_eq!(records(&stable_restored), restored_records);
}
