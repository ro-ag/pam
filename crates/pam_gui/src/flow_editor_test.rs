use std::{
    fmt::Write as _,
    fs,
    io::Write as _,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use pam_flow::{ApprovalMode, EffectKind, StepSemanticRole};

use super::*;

static TEST_SEQUENCE: AtomicU64 = AtomicU64::new(0);

struct TestProject(PathBuf);

impl TestProject {
    fn new(label: &str) -> Self {
        let sequence = TEST_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "pam-gui-flow-editor-{label}-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }

    fn flows(&self) -> PathBuf {
        self.0.join(".pam/flows")
    }

    fn create_catalog(&self) {
        fs::create_dir_all(self.flows()).unwrap();
    }

    fn write_flow(&self, id: &str, revision: u64, name: &str) -> String {
        self.create_catalog();
        let source = flow_source(id, revision, name);
        fs::write(self.flows().join(format!("{id}.toml")), &source).unwrap();
        source
    }
}

impl Drop for TestProject {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn flow_source(id: &str, revision: u64, name: &str) -> String {
    format!(
        r#"schema_version = 2
id = "{id}"
name = "{name}"
description = "A bounded editor flow."
revision = {revision}

[outcome]
solved = "Solved."
changed = "Changed."
verified = "Verified."
unresolved = "Unresolved."
blocked = "Blocked."

[[steps]]
id = "inspect"
description = "Inspect the worktree."
timeout_seconds = 10
effect = "read_only"
semantic = "observe"
action = {{ type = "command", program = "git", args = ["status", "--short"], working_directory = "." }}
"#
    )
}

fn write_recovery_links(project: &TestProject, id: &str, count: usize) {
    let target = project.flows().join(format!("{id}.toml"));
    for sequence in 0..count {
        fs::hard_link(
            &target,
            project.flows().join(format!(
                ".{id}.toml.backup-{}-{sequence}",
                std::process::id()
            )),
        )
        .unwrap();
    }
}

#[test]
fn checked_after_merge_flow_is_a_schema_v2_editor_golden() {
    let repository = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .unwrap()
        .to_path_buf();
    let model = FlowEditorModel::open(&repository).unwrap();
    let entry = model.entry("after-merge-checks").unwrap();
    let checked_path = repository.join(".pam/flows/after-merge-checks.toml");
    assert!(
        !fs::symlink_metadata(checked_path)
            .unwrap()
            .file_type()
            .is_symlink()
    );
    assert_eq!(entry.identity().file_name(), "after-merge-checks.toml");
    assert_eq!(
        entry.identity().file_name(),
        format!("{}.toml", entry.definition().id())
    );
    assert_eq!(entry.definition().schema_version(), 2);
    assert_eq!(
        entry
            .definition()
            .steps()
            .iter()
            .map(pam_flow::FlowStep::semantic_role)
            .collect::<Vec<_>>(),
        vec![
            StepSemanticRole::Observe,
            StepSemanticRole::Observe,
            StepSemanticRole::Verify,
        ]
    );
    let outcome = entry.definition().outcome();
    assert_eq!(
        (
            outcome.solved(),
            outcome.changed(),
            outcome.verified(),
            outcome.unresolved(),
            outcome.blocked(),
        ),
        (
            "Whether every declared after-merge observation and verification completed successfully.",
            "State changes completed by this flow; this read-only flow is not expected to satisfy this section.",
            "Whether the tracked worktree was directly verified against the index.",
            "Which observation or verification could not be completed.",
            "Which policy, workspace, or execution boundary stopped the flow.",
        )
    );
    assert_eq!(
        entry.normalized_toml(),
        entry
            .definition()
            .to_normalized_toml()
            .expect("checked definition normalizes")
    );
    assert!(model.open_document("../after-merge-checks").is_err());
    let plan = model
        .open_document("after-merge-checks.toml")
        .unwrap()
        .dry_run()
        .unwrap();
    assert!(plan.daemon_definition_eligible());
}

#[test]
fn catalog_is_sorted_direct_and_selected_only_by_exact_identity() {
    let project = TestProject::new("catalog");
    let alpha = project.write_flow("alpha", 1, "Alpha");
    project.write_flow("zeta", 1, "Zeta");
    fs::create_dir(project.flows().join("nested")).unwrap();
    fs::write(
        project.flows().join("nested/hidden.toml"),
        flow_source("hidden", 1, "Hidden"),
    )
    .unwrap();
    fs::write(project.flows().join("notes.txt"), "ignored").unwrap();

    let model = FlowEditorModel::open(project.path()).unwrap();
    assert_eq!(
        model
            .entries()
            .iter()
            .map(|entry| entry.identity().file_name())
            .collect::<Vec<_>>(),
        vec!["alpha.toml", "zeta.toml"]
    );
    for selector in ["alpha", "alpha.toml"] {
        assert_eq!(model.entry(selector).unwrap().source(), alpha);
    }
    assert!(matches!(
        model.entry("Alpha"),
        Err(FlowEditorError::NotFound(_))
    ));
    for selector in ["", ".", "..", "../alpha", "alpha/toml", "alpha\\toml"] {
        assert!(matches!(
            model.entry(selector),
            Err(FlowEditorError::InvalidSelector)
        ));
    }
    assert!(matches!(
        model.entry("hidden"),
        Err(FlowEditorError::NotFound(_))
    ));
}

#[test]
fn catalog_rejects_filename_mismatch_invalid_utf8_and_unsafe_entry_types() {
    let mismatch = TestProject::new("mismatch");
    mismatch.create_catalog();
    fs::write(
        mismatch.flows().join("wrong.toml"),
        flow_source("right", 1, "Right"),
    )
    .unwrap();
    assert!(matches!(
        FlowEditorModel::open(mismatch.path()),
        Err(FlowEditorError::FileNameMismatch { .. })
    ));

    let invalid = TestProject::new("invalid-utf8");
    invalid.create_catalog();
    fs::write(invalid.flows().join("broken.toml"), [0xff, 0xfe]).unwrap();
    assert!(matches!(
        FlowEditorModel::open(invalid.path()),
        Err(FlowEditorError::NonUtf8Definition(_))
    ));

    let malformed = TestProject::new("malformed");
    malformed.create_catalog();
    let private_value = "private-flow-value-must-not-echo";
    fs::write(
        malformed.flows().join("malformed.toml"),
        format!("invalid = [{private_value}"),
    )
    .unwrap();
    let error = FlowEditorModel::open(malformed.path()).unwrap_err();
    assert!(matches!(
        error,
        FlowEditorError::InvalidCatalogDefinition { .. }
    ));
    assert!(!error.to_string().contains(private_value));

    let reserved_directory = TestProject::new("reserved-artifact-directory");
    reserved_directory.create_catalog();
    fs::create_dir(reserved_directory.flows().join(".target.toml.backup-100-1")).unwrap();
    assert!(matches!(
        FlowEditorModel::open(reserved_directory.path()),
        Err(FlowEditorError::UnsafeEntry(_))
    ));

    #[cfg(unix)]
    {
        let fifo = TestProject::new("fifo");
        fifo.create_catalog();
        let status = std::process::Command::new("mkfifo")
            .arg(fifo.flows().join("pipe.toml"))
            .status()
            .unwrap();
        assert!(status.success());
        assert!(matches!(
            FlowEditorModel::open(fifo.path()),
            Err(FlowEditorError::UnsafeEntry(_))
        ));
    }
}

#[test]
fn catalog_enforces_entry_file_and_actual_total_byte_bounds() {
    let entries = TestProject::new("entry-bound");
    entries.create_catalog();
    for index in 0..=MAX_FLOW_CATALOG_ENTRIES {
        fs::write(entries.flows().join(format!("note-{index}")), "x").unwrap();
    }
    assert!(matches!(
        FlowEditorModel::open(entries.path()),
        Err(FlowEditorError::TooManyEntries)
    ));

    let file = TestProject::new("file-bound");
    file.create_catalog();
    fs::write(
        file.flows().join("huge.toml"),
        vec![b'x'; pam_flow::MAX_FLOW_DOCUMENT_BYTES + 1],
    )
    .unwrap();
    assert!(matches!(
        FlowEditorModel::open(file.path()),
        Err(FlowEditorError::FileTooLarge(_))
    ));

    let total = TestProject::new("total-bound");
    for index in 0..9 {
        total.write_flow(&format!("flow-{index}"), 1, &format!("Flow {index}"));
    }
    let flows = total.flows();
    let result = FlowEditorModel::open_after_metadata(total.path(), |_, file_name| {
        let path = flows.join(file_name);
        let existing = usize::try_from(fs::metadata(&path).unwrap().len()).unwrap();
        fs::OpenOptions::new()
            .append(true)
            .open(path)
            .unwrap()
            .write_all(&vec![b' '; pam_flow::MAX_FLOW_DOCUMENT_BYTES - existing])
            .unwrap();
    });
    assert!(matches!(result, Err(FlowEditorError::CatalogTooLarge)));
}

#[cfg(unix)]
#[test]
fn catalog_and_candidate_opens_never_follow_symlinks() {
    use std::os::unix::fs::symlink;

    let target = TestProject::new("link-target");
    target.write_flow("target", 1, "Target");

    let linked_pam = TestProject::new("link-pam");
    symlink(target.path().join(".pam"), linked_pam.path().join(".pam")).unwrap();
    assert!(matches!(
        FlowEditorModel::open(linked_pam.path()),
        Err(FlowEditorError::UnsafeDirectory(".pam"))
    ));

    let linked_flows = TestProject::new("link-flows");
    fs::create_dir(linked_flows.path().join(".pam")).unwrap();
    symlink(target.flows(), linked_flows.path().join(".pam/flows")).unwrap();
    assert!(matches!(
        FlowEditorModel::open(linked_flows.path()),
        Err(FlowEditorError::UnsafeDirectory("flows"))
    ));

    let linked_entry = TestProject::new("link-entry");
    linked_entry.create_catalog();
    symlink(
        target.flows().join("target.toml"),
        linked_entry.flows().join("target.toml"),
    )
    .unwrap();
    assert!(matches!(
        FlowEditorModel::open(linked_entry.path()),
        Err(FlowEditorError::UnsafeEntry(_))
    ));

    let swapped = TestProject::new("link-swap");
    swapped.write_flow("swap", 1, "Swap");
    let candidate = swapped.flows().join("swap.toml");
    let replacement = target.flows().join("target.toml");
    let mut changed = false;
    let result = FlowEditorModel::open_after_candidate(swapped.path(), |_, name| {
        if name == "swap.toml" && !changed {
            fs::remove_file(&candidate).unwrap();
            symlink(&replacement, &candidate).unwrap();
            changed = true;
        }
    });
    assert!(matches!(result, Err(FlowEditorError::UnsafeEntry(_))));
}

#[test]
fn editor_retains_bounded_invalid_text_and_returns_normalized_validation() {
    let project = TestProject::new("validation");
    let source = project.write_flow("edit", 1, "Edit");
    let model = FlowEditorModel::open(project.path()).unwrap();
    let mut document = model.open_document("edit").unwrap();
    let validation = document.validate().unwrap();
    assert_eq!(validation.identity().id(), "edit");
    assert!(
        validation
            .normalized_toml()
            .contains("depends_on = []\ncondition = { kind = \"always\" }")
    );

    document.replace_source("not = [valid").unwrap();
    assert!(matches!(
        document.validate(),
        Err(FlowEditorError::InvalidToml(_))
    ));
    assert_eq!(document.source(), "not = [valid");
    let too_large = "x".repeat(pam_flow::MAX_FLOW_DOCUMENT_BYTES + 1);
    assert!(matches!(
        document.replace_source(too_large),
        Err(FlowEditorError::DocumentTooLarge { .. })
    ));
    assert_eq!(document.source(), "not = [valid");
    document.replace_source(source).unwrap();
    assert!(document.validate().is_ok());
}

#[test]
fn normalization_expansion_cannot_create_an_unloadable_saved_document() {
    let project = TestProject::new("normalized-bound");
    let model = FlowEditorModel::open(project.path()).unwrap();
    let argument = "\\".repeat(4_096);
    let mut source = r#"schema_version = 2
id = "expanded"
name = "Expanded"
description = "Normalization expansion bound."
revision = 1

[outcome]
solved = "Solved."
changed = "Changed."
verified = "Verified."
unresolved = "Unresolved."
blocked = "Blocked."
"#
    .to_owned();
    for index in 0..pam_flow::MAX_FLOW_STEPS {
        writeln!(
            source,
            r#"
[[steps]]
id = "step-{index}"
description = "Inspect step {index}."
timeout_seconds = 10
effect = "read_only"
semantic = "observe"
action = {{ type = "command", program = "git", args = ["status", '{argument}'], working_directory = "." }}"#
        )
        .unwrap();
    }
    assert!(source.len() < pam_flow::MAX_FLOW_DOCUMENT_BYTES);
    let document = model.new_document(source).unwrap();
    assert!(matches!(
        document.validate(),
        Err(FlowEditorError::NormalizedDocumentTooLarge { .. })
    ));
}

#[test]
#[allow(clippy::too_many_lines)] // One table-like fixture covers every dry-run authority outcome.
fn dry_run_reports_every_declared_boundary_without_execution() {
    let project = TestProject::new("dry-run");
    let marker = project.path().join("must-not-exist");
    let source = format!(
        r#"schema_version = 2
id = "authority"
name = "Authority"
description = "Dry-run authority coverage."
revision = 1

[outcome]
solved = "Solved."
changed = "Changed."
verified = "Verified."
unresolved = "Unresolved."
blocked = "Blocked."

[[steps]]
id = "eligible"
description = "Eligible observation."
condition = {{ kind = "always" }}
retry = {{ max_attempts = 2, initial_backoff_ms = 10, max_backoff_ms = 20 }}
timeout_seconds = 10
effect = "read_only"
semantic = "observe"
action = {{ type = "command", program = "git", args = ["status", "--short"], working_directory = "." }}

[[steps]]
id = "nested"
description = "Nested authority."
condition = {{ kind = "succeeded", step = "eligible" }}
timeout_seconds = 10
effect = "read_only"
semantic = "observe"
action = {{ type = "command", program = "git", args = ["status"], working_directory = "nested" }}

[[steps]]
id = "program"
description = "Unsupported program."
condition = {{ kind = "failed", step = "nested" }}
timeout_seconds = 10
effect = "read_only"
semantic = "observe"
action = {{ type = "command", program = "touch", args = ["{}"], working_directory = "." }}

[[steps]]
id = "connector"
description = "Connector authority."
timeout_seconds = 10
effect = "read_only"
semantic = "observe"
action = {{ type = "connector", connector = "github.issues", capability = "issues.read", resource = {{ kind = "issue", id = "owner/repo:1" }} }}

[[steps]]
id = "stateful"
description = "Stateful authority."
approval = "required"
idempotency_key = "stateful-1"
timeout_seconds = 10
effect = "stateful"
semantic = "change"
action = {{ type = "command", program = "git", args = ["status"], working_directory = "." }}

[[steps]]
id = "approval"
description = "Approval authority."
approval = "required"
timeout_seconds = 10
effect = "read_only"
semantic = "observe"
action = {{ type = "command", program = "git", args = ["status"], working_directory = "." }}

[[steps]]
id = "arguments"
description = "Argument authority."
timeout_seconds = 10
effect = "read_only"
semantic = "observe"
action = {{ type = "command", program = "git", args = ["log"], working_directory = "." }}

[[steps]]
id = "semantic"
description = "Semantic authority."
timeout_seconds = 10
effect = "read_only"
semantic = "verify"
action = {{ type = "command", program = "git", args = ["status"], working_directory = "." }}
"#,
        marker.display()
    );
    let model = FlowEditorModel::open(project.path()).unwrap();
    let document = model.new_document(source).unwrap();
    let first = document.dry_run().unwrap();
    let second = document.dry_run().unwrap();
    assert_eq!(first, second);
    assert!(!marker.exists());
    assert!(!first.daemon_definition_eligible());
    assert_eq!(first.steps().len(), 8);
    let eligible = &first.steps()[0];
    assert_eq!(eligible.index(), 0);
    assert_eq!(eligible.semantic_role(), StepSemanticRole::Observe);
    assert_eq!(eligible.condition(), &DryRunCondition::Always);
    assert_eq!(eligible.approval(), ApprovalMode::None);
    assert_eq!(eligible.retry().max_attempts(), 2);
    assert_eq!(eligible.effect(), EffectKind::ReadOnly);
    assert!(matches!(
        eligible.action(),
        ActionAuthority::Command { program, arguments, working_directory }
            if program == "git"
                && arguments == &["status", "--short"]
                && working_directory == "."
    ));
    assert_eq!(
        eligible.daemon_authority(),
        DaemonAuthority::EligibleAfterRuntimeChecks
    );
    assert_eq!(
        first
            .steps()
            .iter()
            .skip(1)
            .map(DryRunStep::daemon_authority)
            .collect::<Vec<_>>(),
        vec![
            DaemonAuthority::Unsupported(UnsupportedDaemonAuthority::WorkingDirectory),
            DaemonAuthority::Unsupported(UnsupportedDaemonAuthority::Program),
            DaemonAuthority::Unsupported(UnsupportedDaemonAuthority::Connector),
            DaemonAuthority::Unsupported(UnsupportedDaemonAuthority::StatefulEffect),
            DaemonAuthority::Unsupported(UnsupportedDaemonAuthority::Approval),
            DaemonAuthority::Unsupported(UnsupportedDaemonAuthority::GitArguments),
            DaemonAuthority::Unsupported(UnsupportedDaemonAuthority::SemanticRole),
        ]
    );
    assert_eq!(
        first.steps()[1].condition(),
        &DryRunCondition::Succeeded {
            step_id: "eligible".to_owned()
        }
    );
    assert_eq!(
        first.steps()[2].condition(),
        &DryRunCondition::Failed {
            step_id: "nested".to_owned()
        }
    );
    assert!(matches!(
        first.steps()[3].action(),
        ActionAuthority::Connector {
            connector,
            capability,
            resource_kind,
            resource_id,
        } if connector == "github.issues"
            && capability == "issues.read"
            && resource_kind == "issue"
            && resource_id == "owner/repo:1"
    ));
}

#[test]
fn version_diff_is_normalized_deterministic_and_enforces_version_identity() {
    let project = TestProject::new("diff");
    let source = project.write_flow("diff", 1, "Before");
    let model = FlowEditorModel::open(project.path()).unwrap();
    let document = model.open_document("diff").unwrap();
    let unchanged = document.version_diff().unwrap();
    assert!(!unchanged.changed());
    assert!(
        unchanged
            .lines()
            .iter()
            .all(|line| line.kind() == FlowVersionDiffLineKind::Context)
    );

    let mut edited = model.open_document("diff").unwrap();
    let changed = source
        .replace("name = \"Before\"", "name = \"After\"")
        .replace("revision = 1", "revision = 2");
    edited.replace_source(changed).unwrap();
    let first = edited.version_diff().unwrap();
    let second = edited.version_diff().unwrap();
    assert_eq!(first, second);
    assert!(first.changed());
    assert!(!first.truncated());
    assert_eq!(first.previous().unwrap().revision(), 1);
    assert_eq!(first.edited().revision(), 2);
    assert!(first.lines().iter().any(|line| {
        line.kind() == FlowVersionDiffLineKind::Removed && line.text() == "name = \"Before\""
    }));
    assert!(first.lines().iter().any(|line| {
        line.kind() == FlowVersionDiffLineKind::Added && line.text() == "name = \"After\""
    }));

    let mut stale_revision = model.open_document("diff").unwrap();
    stale_revision
        .replace_source(source.replace("Before", "Changed"))
        .unwrap();
    assert!(matches!(
        stale_revision.validate(),
        Err(FlowEditorError::RevisionNotAdvanced { .. })
    ));
    let mut changed_id = model.open_document("diff").unwrap();
    changed_id
        .replace_source(
            source
                .replace("id = \"diff\"", "id = \"other\"")
                .replace("revision = 1", "revision = 2"),
        )
        .unwrap();
    assert!(matches!(
        changed_id.validate(),
        Err(FlowEditorError::IdentityChanged { .. })
    ));

    let new_document = model.new_document(flow_source("new", 1, "New")).unwrap();
    let new_diff = new_document.version_diff().unwrap();
    assert!(new_diff.previous().is_none());
    assert!(
        new_diff
            .lines()
            .iter()
            .all(|line| line.kind() == FlowVersionDiffLineKind::Added)
    );
}

#[test]
fn large_normalized_version_diff_is_strictly_truncated_without_quadratic_work() {
    let project = TestProject::new("large-diff");
    let model = FlowEditorModel::open(project.path()).unwrap();
    let mut source = r#"schema_version = 2
id = "large"
name = "Large"
description = "Bounded large diff."
revision = 1

[outcome]
solved = "Solved."
changed = "Changed."
verified = "Verified."
unresolved = "Unresolved."
blocked = "Blocked."
"#
    .to_owned();
    for index in 0..pam_flow::MAX_FLOW_STEPS {
        write!(
            source,
            r#"
[[steps]]
id = "step-{index}"
description = "Inspect step {index}."
depends_on = []
condition = {{ kind = "always" }}
retry = {{ max_attempts = 1, initial_backoff_ms = 0, max_backoff_ms = 0 }}
approval = "none"
timeout_seconds = 10
effect = "read_only"
semantic = "observe"
action = {{ type = "command", program = "git", args = ["status", "--short"], working_directory = "." }}
"#
        )
        .unwrap();
    }
    let diff = model.new_document(source).unwrap().version_diff().unwrap();
    assert!(diff.changed());
    assert!(diff.truncated());
    assert_eq!(diff.lines().len(), MAX_VERSION_DIFF_LINES);
    assert!(
        diff.lines()
            .iter()
            .all(|line| line.kind() == FlowVersionDiffLineKind::Added)
    );
}

#[test]
fn prepared_save_creates_and_updates_only_normalized_identity_files() {
    let project = TestProject::new("save");
    let mut model = FlowEditorModel::open(project.path()).unwrap();
    let mut document = model
        .new_document(flow_source("saved", 1, "Saved"))
        .unwrap();
    let interaction = document.prepare_save().unwrap();
    assert!(interaction.creates_file());
    assert_eq!(interaction.identity().file_name(), "saved.toml");
    assert!(interaction.diff().changed());
    let expected = interaction.normalized_toml().to_owned();
    let result = document.commit_save(interaction).unwrap();
    assert!(result.created());
    assert_eq!(result.durability_confirmed(), cfg!(unix));
    assert!(result.cleanup_complete());
    assert_eq!(document.source(), expected);
    assert_eq!(
        fs::read_to_string(project.flows().join("saved.toml")).unwrap(),
        expected
    );
    assert_eq!(
        fs::read_dir(project.flows())
            .unwrap()
            .map(Result::unwrap)
            .count(),
        1
    );

    model.reload().unwrap();
    let mut reopened = model.open_document("saved").unwrap();
    reopened
        .replace_source(flow_source("saved", 2, "Updated"))
        .unwrap();
    let update = reopened.prepare_save().unwrap();
    assert!(!update.creates_file());
    let updated = update.normalized_toml().to_owned();
    let result = reopened.commit_save(update).unwrap();
    assert!(!result.created());
    assert_eq!(result.identity().revision(), 2);
    assert_eq!(
        fs::read_to_string(project.flows().join("saved.toml")).unwrap(),
        updated
    );
    let retained_backup = fs::read_dir(project.flows()).unwrap().any(|entry| {
        entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .contains(".backup-")
    });
    assert_eq!(retained_backup, !cfg!(unix));
}

#[test]
fn bounded_owned_recovery_artifacts_do_not_exhaust_the_flow_catalog() {
    let project = TestProject::new("bounded-recovery-artifacts");
    project.write_flow("recoverable", 1, "Recoverable");
    write_recovery_links(&project, "recoverable", MAX_FLOW_CATALOG_ENTRIES);

    let mut model = FlowEditorModel::open(project.path()).unwrap();
    assert_eq!(model.entries().len(), 1);
    let mut document = model.open_document("recoverable").unwrap();
    document
        .replace_source(flow_source("recoverable", 2, "Recovered"))
        .unwrap();
    let interaction = document.prepare_save().unwrap();
    document.commit_save(interaction).unwrap();
    model.reload().unwrap();

    let retained = fs::read_dir(project.flows())
        .unwrap()
        .map(Result::unwrap)
        .filter(|entry| entry.file_name().to_string_lossy().contains(".backup-"))
        .count();
    assert!(retained <= 1, "only the latest recovery link may remain");
}

#[test]
fn owned_recovery_artifacts_have_an_independent_hard_limit() {
    let project = TestProject::new("excess-recovery-artifacts");
    project.write_flow("recoverable", 1, "Recoverable");
    write_recovery_links(&project, "recoverable", MAX_FLOW_CATALOG_ENTRIES + 1);

    assert!(matches!(
        FlowEditorModel::open(project.path()),
        Err(FlowEditorError::TooManyRecoveryArtifacts)
    ));
}

#[test]
fn directory_sync_reopens_an_fsync_capable_handle() {
    let project = TestProject::new("directory-sync");
    let durability_confirmed = flow_editor::sync_directory_path_for_test(project.path()).unwrap();
    assert_eq!(durability_confirmed, cfg!(unix));
}

#[test]
fn save_rejects_stale_interactions_disk_conflicts_and_busy_writers() {
    let project = TestProject::new("save-conflicts");
    let original = project.write_flow("conflict", 1, "Original");
    let model = FlowEditorModel::open(project.path()).unwrap();

    let mut stale = model.open_document("conflict").unwrap();
    stale
        .replace_source(flow_source("conflict", 2, "First edit"))
        .unwrap();
    let interaction = stale.prepare_save().unwrap();
    stale
        .replace_source(flow_source("conflict", 2, "Second edit"))
        .unwrap();
    assert!(matches!(
        stale.commit_save(interaction),
        Err(FlowEditorError::StaleSaveInteraction)
    ));
    assert_eq!(
        fs::read_to_string(project.flows().join("conflict.toml")).unwrap(),
        original
    );

    let mut conflict = model.open_document("conflict").unwrap();
    conflict
        .replace_source(flow_source("conflict", 2, "Edited"))
        .unwrap();
    let interaction = conflict.prepare_save().unwrap();
    let external = format!("{original}\n# external formatting change\n");
    fs::write(project.flows().join("conflict.toml"), &external).unwrap();
    assert!(matches!(
        conflict.commit_save(interaction),
        Err(FlowEditorError::SaveConflict)
    ));
    assert_eq!(
        fs::read_to_string(project.flows().join("conflict.toml")).unwrap(),
        external
    );
    assert!(!fs::read_dir(project.flows()).unwrap().any(|entry| {
        entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .contains(".tmp-")
    }));

    fs::write(project.flows().join("conflict.toml"), &original).unwrap();
    let mut busy = model.open_document("conflict").unwrap();
    busy.replace_source(flow_source("conflict", 2, "Busy"))
        .unwrap();
    let interaction = busy.prepare_save().unwrap();
    let lock_path = project.path().join(".pam/.flow-editor.lock");
    let held_lock = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&lock_path)
        .unwrap();
    held_lock.try_lock().unwrap();
    assert!(matches!(
        busy.commit_save(interaction),
        Err(FlowEditorError::SaveBusy)
    ));
    assert_eq!(
        fs::read_to_string(project.flows().join("conflict.toml")).unwrap(),
        original
    );
    drop(held_lock);
    let interaction = busy.prepare_save().unwrap();
    let result = busy.commit_save(interaction).unwrap();
    assert!(!result.created());
    let lock_stamp = fs::read_to_string(lock_path).unwrap();
    assert!(lock_stamp.contains("created_by_pid="));
    assert!(lock_stamp.contains("created_unix_ms="));
}

#[test]
fn preexisting_hard_link_lock_is_never_stamped_or_truncated() {
    let project = TestProject::new("hard-link-lock");
    let original = project.write_flow("linked-lock", 1, "Original");
    fs::hard_link(
        project.flows().join("linked-lock.toml"),
        project.path().join(".pam/.flow-editor.lock"),
    )
    .unwrap();
    let model = FlowEditorModel::open(project.path()).unwrap();
    let mut document = model.open_document("linked-lock").unwrap();
    document
        .replace_source(flow_source("linked-lock", 2, "Edited"))
        .unwrap();
    let interaction = document.prepare_save().unwrap();
    document.commit_save(interaction).unwrap();
    assert_eq!(
        fs::read_to_string(project.path().join(".pam/.flow-editor.lock")).unwrap(),
        original
    );
    assert!(
        fs::read_to_string(project.flows().join("linked-lock.toml"))
            .unwrap()
            .contains("name = \"Edited\"")
    );
}

#[cfg(unix)]
#[test]
fn preexisting_fifo_lock_fails_closed_without_blocking() {
    let project = TestProject::new("fifo-lock");
    project.write_flow("fifo-lock", 1, "Original");
    let status = std::process::Command::new("mkfifo")
        .arg(project.path().join(".pam/.flow-editor.lock"))
        .status()
        .unwrap();
    assert!(status.success());
    let model = FlowEditorModel::open(project.path()).unwrap();
    let mut document = model.open_document("fifo-lock").unwrap();
    document
        .replace_source(flow_source("fifo-lock", 2, "Edited"))
        .unwrap();
    let interaction = document.prepare_save().unwrap();
    assert!(matches!(
        document.commit_save(interaction),
        Err(FlowEditorError::Write(_))
    ));
}

#[test]
fn detected_final_publication_race_fails_closed_with_recoverable_prior_bytes() {
    let project = TestProject::new("save-race");
    project.write_flow("raced", 1, "Original");
    let model = FlowEditorModel::open(project.path()).unwrap();
    let mut document = model.open_document("raced").unwrap();
    document
        .replace_source(flow_source("raced", 2, "Edited"))
        .unwrap();
    let interaction = document.prepare_save().unwrap();
    let target = project.flows().join("raced.toml");
    let result = document.commit_save_after_final_check(interaction, || {
        fs::write(&target, "non-cooperating writer bytes").unwrap();
    });
    let recovery_file = match result {
        Err(FlowEditorError::SavePublicationUncertain {
            recovery_file: Some(recovery_file),
        }) => recovery_file,
        other => panic!("expected recoverable publication uncertainty, got {other:?}"),
    };
    assert_eq!(
        fs::read_to_string(project.flows().join(&recovery_file)).unwrap(),
        "non-cooperating writer bytes"
    );
    assert_eq!(document.saved_identity().unwrap().revision(), 1);
}

#[cfg(unix)]
#[test]
fn save_never_follows_new_target_or_catalog_directory_symlinks() {
    use std::os::unix::fs::symlink;

    let outside = TestProject::new("save-outside");
    let outside_path = outside.path().join("outside.toml");
    fs::write(&outside_path, "outside").unwrap();

    let target = TestProject::new("save-target-link");
    target.create_catalog();
    let model = FlowEditorModel::open(target.path()).unwrap();
    let mut document = model
        .new_document(flow_source("linked", 1, "Linked"))
        .unwrap();
    let interaction = document.prepare_save().unwrap();
    symlink(&outside_path, target.flows().join("linked.toml")).unwrap();
    assert!(matches!(
        document.commit_save(interaction),
        Err(FlowEditorError::SaveConflict)
    ));
    assert_eq!(fs::read_to_string(&outside_path).unwrap(), "outside");

    let directory = TestProject::new("save-directory-link");
    let model = FlowEditorModel::open(directory.path()).unwrap();
    let mut document = model
        .new_document(flow_source("linked-dir", 1, "Linked dir"))
        .unwrap();
    let interaction = document.prepare_save().unwrap();
    symlink(outside.path(), directory.path().join(".pam")).unwrap();
    assert!(matches!(
        document.commit_save(interaction),
        Err(FlowEditorError::UnsafeDirectory(".pam"))
    ));
    assert!(!outside.path().join("flows/linked-dir.toml").exists());
}
