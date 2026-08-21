use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    sync::{Arc, Barrier},
    thread,
};

#[cfg(unix)]
use std::os::unix::fs::symlink;

use crate::{
    CanonicalEntryId, CanonicalLibrary, LibraryEnablementKey, LibraryProjectKey,
    ManagedCopyCleanupDisposition, MaterializationAction, MaterializationAgent,
    MaterializationDriftConflict, MaterializationDriftState, MaterializationError,
    MaterializationIoOperation, MaterializationOutcome, MaterializationRequest, OriginAgent,
    apply_managed_materialization, apply_materialization_resync, disable_materialization,
    inspect_materialization_drift, plan_managed_materialization, plan_materialization,
    plan_materialization_resync, scan_test::TestDirectory,
};

use super::materialize::{
    PostRenameFailure, apply_managed_materialization_with_competing_root_before_record,
    apply_managed_materialization_with_disable_before_record, apply_materialization,
    apply_materialization_resync_with_disable_before_record,
    apply_materialization_with_directory_sync_failure,
    apply_materialization_with_post_publish_writer, apply_materialization_with_pre_publish_writer,
    apply_materialization_with_pre_rename_failure, apply_materialization_with_verification_failure,
    disable_materialization_with_ownership_publish_failure,
    disable_materialization_with_post_rename_failure,
    disable_materialization_with_recreated_target, inspect_file_with_after_first_read,
    record_materialization,
};

fn library() -> (TestDirectory, CanonicalLibrary) {
    let home = TestDirectory::new("materialization-library");
    let library = CanonicalLibrary::open(home.path()).unwrap();
    (home, library)
}

fn insert(
    library: &CanonicalLibrary,
    id: &str,
    bytes: &[u8],
) -> (CanonicalEntryId, pam_core::ContentDigest) {
    let id = CanonicalEntryId::parse(id).unwrap();
    let version = library.insert(id.clone(), bytes).unwrap().version().clone();
    (id, version)
}

fn enablement_key(
    outcome: &MaterializationOutcome,
    project: &LibraryProjectKey,
) -> LibraryEnablementKey {
    let origin = match outcome.agent() {
        MaterializationAgent::Claude => OriginAgent::ClaudeCode,
        MaterializationAgent::Codex => OriginAgent::Codex,
        MaterializationAgent::Cursor => OriginAgent::Cursor,
    };
    LibraryEnablementKey::new(
        outcome.entry_id().clone(),
        outcome.version().clone(),
        origin,
        project.clone(),
    )
}

fn create_owned_copy(
    library: &CanonicalLibrary,
    root: &TestDirectory,
    project: &LibraryProjectKey,
    name: &str,
    bytes: &[u8],
) -> LibraryEnablementKey {
    let (id, version) = insert(library, name, bytes);
    let batch = apply_materialization(
        library,
        &plan_materialization(
            library,
            &[MaterializationRequest::new(
                MaterializationAgent::Codex,
                root.path(),
                id,
                version,
            )],
        )
        .unwrap(),
    )
    .unwrap();
    let outcome = &batch.outcomes()[0];
    let key = enablement_key(outcome, project);
    library.enable(key.clone()).unwrap();
    record_materialization(library, project.clone(), outcome).unwrap();
    key
}

fn quarantined_managed_copy(root: &TestDirectory) -> PathBuf {
    let mut quarantines = fs::read_dir(root.path().join("prompts"))
        .unwrap()
        .filter_map(Result::ok)
        .filter(|entry| {
            entry
                .file_name()
                .to_string_lossy()
                .starts_with(".pam-quarantine-")
        })
        .map(|entry| entry.path().join("managed-copy"))
        .collect::<Vec<_>>();
    assert_eq!(quarantines.len(), 1);
    quarantines.pop().unwrap()
}

#[derive(Debug, Eq, PartialEq)]
enum RootNode {
    Directory,
    File(Vec<u8>),
}

fn snapshot_tree(root: &Path) -> BTreeMap<PathBuf, RootNode> {
    fn visit(root: &Path, directory: &Path, snapshot: &mut BTreeMap<PathBuf, RootNode>) {
        let mut entries = fs::read_dir(directory)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect::<Vec<_>>();
        entries.sort();
        for path in entries {
            let relative = path.strip_prefix(root).unwrap().to_path_buf();
            let metadata = fs::symlink_metadata(&path).unwrap();
            if metadata.is_dir() {
                snapshot.insert(relative, RootNode::Directory);
                visit(root, &path, snapshot);
            } else {
                assert!(metadata.is_file());
                snapshot.insert(relative, RootNode::File(fs::read(&path).unwrap()));
            }
        }
    }

    let mut snapshot = BTreeMap::new();
    visit(root, root, &mut snapshot);
    snapshot
}

#[test]
fn dry_run_and_apply_use_exact_recognized_agent_paths() {
    let (_home, library) = library();
    let claude_root = TestDirectory::new("materialization-claude");
    let codex_root = TestDirectory::new("materialization-codex");
    let cursor_root = TestDirectory::new("materialization-cursor");
    let claude_bytes = "# Café skill\nline with spaces\n".as_bytes();
    let codex_bytes = b"# Prompt\r\nkeep CRLF\r\n";
    let cursor_bytes = "---\ndescription: résumé rule\n---\nallow spaces\n".as_bytes();
    let (claude_id, claude_version) = insert(&library, "cafe-skill", claude_bytes);
    let (codex_id, codex_version) = insert(&library, "review-prompt", codex_bytes);
    let (cursor_id, cursor_version) = insert(&library, "resume-rule", cursor_bytes);
    let requests = [
        MaterializationRequest::new(
            MaterializationAgent::Claude,
            claude_root.path(),
            claude_id,
            claude_version,
        ),
        MaterializationRequest::new(
            MaterializationAgent::Codex,
            codex_root.path(),
            codex_id,
            codex_version,
        ),
        MaterializationRequest::new(
            MaterializationAgent::Cursor,
            cursor_root.path(),
            cursor_id,
            cursor_version,
        ),
    ];

    let plan = plan_materialization(&library, &requests).unwrap();
    assert_eq!(plan.items().len(), 3);
    assert!(
        plan.items()
            .iter()
            .all(|item| item.action() == MaterializationAction::Create)
    );
    assert_eq!(
        plan.items()[0].destination(),
        fs::canonicalize(claude_root.path())
            .unwrap()
            .join("skills/cafe-skill/SKILL.md")
    );
    assert_eq!(
        plan.items()[1].destination(),
        fs::canonicalize(codex_root.path())
            .unwrap()
            .join("prompts/review-prompt.md")
    );
    assert_eq!(
        plan.items()[2].destination(),
        fs::canonicalize(cursor_root.path())
            .unwrap()
            .join("rules/resume-rule.mdc")
    );
    assert!(!claude_root.path().join("skills").exists());
    assert!(!codex_root.path().join("prompts").exists());
    assert!(!cursor_root.path().join("rules").exists());
    assert!(!format!("{plan:?}").contains("Café skill"));

    let outcome = apply_materialization(&library, &plan).unwrap();
    assert_eq!(outcome.outcomes().len(), 3);
    assert!(
        outcome
            .outcomes()
            .iter()
            .all(|item| item.backup().is_none())
    );
    assert_eq!(
        fs::read(claude_root.path().join("skills/cafe-skill/SKILL.md")).unwrap(),
        claude_bytes
    );
    assert_eq!(
        fs::read(codex_root.path().join("prompts/review-prompt.md")).unwrap(),
        codex_bytes
    );
    assert_eq!(
        fs::read(cursor_root.path().join("rules/resume-rule.mdc")).unwrap(),
        cursor_bytes
    );
}

#[test]
fn equal_destination_is_a_no_op_and_differing_destination_keeps_exact_backup() {
    let (_home, library) = library();
    let no_op_root = TestDirectory::new("materialization-no-op");
    let exact = b"exact bytes\n";
    let (id, version) = insert(&library, "exact", exact);
    no_op_root.write("prompts/exact.md", exact);
    let plan = plan_materialization(
        &library,
        &[MaterializationRequest::new(
            MaterializationAgent::Codex,
            no_op_root.path(),
            id,
            version,
        )],
    )
    .unwrap();
    assert_eq!(plan.items()[0].action(), MaterializationAction::NoOp);
    assert_eq!(
        plan.items()[0].existing().unwrap().byte_len(),
        exact.len() as u64
    );
    let outcome = apply_materialization(&library, &plan).unwrap();
    assert!(outcome.outcomes()[0].backup().is_none());
    assert_eq!(
        fs::read(no_op_root.path().join("prompts/exact.md")).unwrap(),
        exact
    );

    let replace_root = TestDirectory::new("materialization-replace");
    let old = b"old exact bytes\r\n";
    let new = b"new exact bytes\n";
    let (id, version) = insert(&library, "replace", new);
    replace_root.write("rules/replace.mdc", old);
    let plan = plan_materialization(
        &library,
        &[MaterializationRequest::new(
            MaterializationAgent::Cursor,
            replace_root.path(),
            id,
            version,
        )],
    )
    .unwrap();
    assert_eq!(plan.items()[0].action(), MaterializationAction::Replace);
    let outcome = apply_materialization(&library, &plan).unwrap();
    let backup = outcome.outcomes()[0].backup().unwrap();
    assert_eq!(fs::read(backup.path()).unwrap(), old);
    assert_eq!(backup.byte_len(), old.len() as u64);
    assert_eq!(
        fs::read(replace_root.path().join("rules/replace.mdc")).unwrap(),
        new
    );
}

#[test]
fn managed_ownership_records_creates_and_replacements_but_never_no_ops() {
    let (home, library) = library();
    let root = TestDirectory::new("materialization-ownership-actions");
    let project = LibraryProjectKey::parse("project-actions").unwrap();
    let (id, first) = insert(&library, "owned", b"first\n");
    let (_, second) = insert(&library, "owned", b"second\n");

    let create_plan = plan_materialization(
        &library,
        &[MaterializationRequest::new(
            MaterializationAgent::Codex,
            root.path(),
            id.clone(),
            first,
        )],
    )
    .unwrap();
    let create = apply_materialization(&library, &create_plan).unwrap();
    assert_eq!(create.outcomes()[0].action(), MaterializationAction::Create);
    let disabled_record =
        record_materialization(&library, project.clone(), &create.outcomes()[0]).unwrap();
    assert!(!disabled_record.recorded());
    assert!(library.managed_copies().unwrap().is_empty());
    library
        .enable(enablement_key(&create.outcomes()[0], &project))
        .unwrap();
    let first_record =
        record_materialization(&library, project.clone(), &create.outcomes()[0]).unwrap();
    assert!(first_record.recorded());
    assert!(first_record.changed());

    let replace_plan = plan_materialization(
        &library,
        &[MaterializationRequest::new(
            MaterializationAgent::Codex,
            root.path(),
            id,
            second,
        )],
    )
    .unwrap();
    let replace = apply_materialization(&library, &replace_plan).unwrap();
    assert_eq!(
        replace.outcomes()[0].action(),
        MaterializationAction::Replace
    );
    library
        .enable(enablement_key(&replace.outcomes()[0], &project))
        .unwrap();
    let replacement_record =
        record_materialization(&library, project.clone(), &replace.outcomes()[0]).unwrap();
    assert!(replacement_record.recorded());
    assert!(replacement_record.changed());

    let no_op_plan = plan_materialization(
        &library,
        &[MaterializationRequest::new(
            MaterializationAgent::Codex,
            root.path(),
            replace.outcomes()[0].entry_id().clone(),
            replace.outcomes()[0].version().clone(),
        )],
    )
    .unwrap();
    let no_op = apply_materialization(&library, &no_op_plan).unwrap();
    assert_eq!(no_op.outcomes()[0].action(), MaterializationAction::NoOp);
    let no_op_record = record_materialization(&library, project, &no_op.outcomes()[0]).unwrap();
    assert!(!no_op_record.recorded());
    assert!(!no_op_record.changed());
    assert_eq!(
        library.managed_copies().unwrap(),
        [replacement_record.key().clone()]
    );

    drop(library);
    let reopened = CanonicalLibrary::open(home.path()).unwrap();
    assert_eq!(
        reopened.managed_copies().unwrap(),
        [replacement_record.key().clone()]
    );
}

#[test]
fn managed_preview_and_apply_reject_cross_root_ownership_without_changing_target_root() {
    let (_home, library) = library();
    let root_a = TestDirectory::new("managed-root-a");
    let root_b = TestDirectory::new("managed-root-b");
    root_b.write(".pam-materialize.lock", b"");
    let project = LibraryProjectKey::parse("cross-root-preview").unwrap();
    let bytes = b"canonical cross-root bytes\n";
    let (id, version) = insert(&library, "cross-root", bytes);
    let key = LibraryEnablementKey::new(id, version, OriginAgent::Codex, project);
    library.enable(key.clone()).unwrap();

    let stale_root_b = plan_managed_materialization(&library, &key, root_b.path()).unwrap();
    let root_a_plan = plan_managed_materialization(&library, &key, root_a.path()).unwrap();
    apply_managed_materialization(&library, &key, &root_a_plan).unwrap();

    root_b.write("prompts/cross-root.md", bytes);
    let owned_tree_before = snapshot_tree(root_a.path());
    let candidate_tree_before = snapshot_tree(root_b.path());
    assert!(matches!(
        plan_managed_materialization(&library, &key, root_b.path()).unwrap_err(),
        MaterializationError::Library(crate::LibraryError::ManagedCopyRootMismatch)
    ));
    assert!(matches!(
        apply_managed_materialization(&library, &key, &stale_root_b).unwrap_err(),
        MaterializationError::Library(crate::LibraryError::ManagedCopyRootMismatch)
    ));
    assert_eq!(snapshot_tree(root_a.path()), owned_tree_before);
    assert_eq!(snapshot_tree(root_b.path()), candidate_tree_before);
}

#[test]
fn managed_apply_rolls_back_when_another_root_claims_ownership_after_publication() {
    let (_home, library) = library();
    let root_a = TestDirectory::new("managed-race-root-a");
    let root_b = TestDirectory::new("managed-race-root-b");
    root_b.write(".pam-materialize.lock", b"");
    let project = LibraryProjectKey::parse("cross-root-record-race").unwrap();
    let bytes = b"canonical race bytes\n";
    let (id, version) = insert(&library, "record-race", bytes);
    let key = LibraryEnablementKey::new(id.clone(), version.clone(), OriginAgent::Codex, project);
    library.enable(key.clone()).unwrap();

    let source_plan = plan_materialization(
        &library,
        &[MaterializationRequest::new(
            MaterializationAgent::Codex,
            root_a.path(),
            id,
            version,
        )],
    )
    .unwrap();
    apply_materialization(&library, &source_plan).unwrap();
    let candidate_plan = plan_managed_materialization(&library, &key, root_b.path()).unwrap();
    let source_tree_before = snapshot_tree(root_a.path());
    let candidate_tree_before = snapshot_tree(root_b.path());

    let error = apply_managed_materialization_with_competing_root_before_record(
        &library,
        &key,
        &candidate_plan,
        root_a.path(),
    )
    .unwrap_err();
    assert!(
        matches!(
            error,
            MaterializationError::Library(crate::LibraryError::ManagedCopyRootMismatch)
        ),
        "unexpected error: {error:?}"
    );
    assert_eq!(snapshot_tree(root_a.path()), source_tree_before);
    assert_eq!(snapshot_tree(root_b.path()), candidate_tree_before);
    assert_eq!(
        library.managed_copies().unwrap().as_slice(),
        std::slice::from_ref(&key)
    );
    assert_eq!(
        inspect_materialization_drift(&library, &key, root_a.path())
            .unwrap()
            .state(),
        &MaterializationDriftState::Clean
    );
    assert!(matches!(
        inspect_materialization_drift(&library, &key, root_b.path()).unwrap_err(),
        MaterializationError::Library(crate::LibraryError::ManagedCopyRootMismatch)
    ));
}

#[test]
fn managed_apply_rolls_back_replacement_when_enablement_changes_before_record() {
    let (_home, library) = library();
    let root = TestDirectory::new("managed-disable-record-race");
    root.write(".pam-materialize.lock", b"");
    let old = b"user bytes before managed replace\r\n";
    root.write("prompts/disable-race.md", old);
    let (id, version) = insert(&library, "disable-race", b"canonical replacement\n");
    let key = LibraryEnablementKey::new(
        id,
        version,
        OriginAgent::Codex,
        LibraryProjectKey::parse("managed-disable-race").unwrap(),
    );
    library.enable(key.clone()).unwrap();
    let plan = plan_managed_materialization(&library, &key, root.path()).unwrap();
    assert_eq!(plan.items()[0].action(), MaterializationAction::Replace);
    let before = snapshot_tree(root.path());

    assert!(matches!(
        apply_managed_materialization_with_disable_before_record(&library, &key, &plan)
            .unwrap_err(),
        MaterializationError::ManagedConflict(MaterializationDriftConflict::Disabled)
    ));
    let mut expected = before;
    let backup = plan.items()[0].backup_destination().unwrap();
    expected.insert(
        PathBuf::from("prompts").join(backup.file_name().unwrap()),
        RootNode::File(old.to_vec()),
    );
    assert_eq!(snapshot_tree(root.path()), expected);
    assert_eq!(
        fs::read(root.path().join("prompts/disable-race.md")).unwrap(),
        old
    );
    assert!(!library.is_enabled(&key).unwrap());
    assert!(library.managed_copies().unwrap().is_empty());
}

#[test]
fn managed_no_op_succeeds_without_claiming_unowned_bytes() {
    let (_home, library) = library();
    let root = TestDirectory::new("managed-unowned-no-op");
    root.write(".pam-materialize.lock", b"");
    let bytes = b"user-identical canonical bytes\n";
    root.write("prompts/unowned-no-op.md", bytes);
    let (id, version) = insert(&library, "unowned-no-op", bytes);
    let key = LibraryEnablementKey::new(
        id,
        version,
        OriginAgent::Codex,
        LibraryProjectKey::parse("managed-unowned-no-op").unwrap(),
    );
    library.enable(key.clone()).unwrap();

    let plan = plan_managed_materialization(&library, &key, root.path()).unwrap();
    assert_eq!(plan.items()[0].action(), MaterializationAction::NoOp);
    let before = snapshot_tree(root.path());
    let applied = apply_managed_materialization(&library, &key, &plan).unwrap();
    assert_eq!(applied.outcomes()[0].action(), MaterializationAction::NoOp);
    assert!(!applied.outcomes()[0].ownership_recorded());
    assert_eq!(snapshot_tree(root.path()), before);
    assert!(library.managed_copies().unwrap().is_empty());
}

#[test]
fn managed_no_op_transfers_same_root_ownership_to_the_exact_version() {
    let (home, library) = library();
    let root = TestDirectory::new("managed-no-op-transfer");
    let project = LibraryProjectKey::parse("managed-no-op-transfer").unwrap();
    let (id, first) = insert(&library, "transfer", b"first version\n");
    let (_, second) = insert(&library, "transfer", b"second version\n");
    let first_key =
        LibraryEnablementKey::new(id.clone(), first, OriginAgent::Codex, project.clone());
    let second_key = LibraryEnablementKey::new(id, second, OriginAgent::Codex, project);
    library.enable(first_key.clone()).unwrap();
    library.enable(second_key.clone()).unwrap();
    let first_plan = plan_managed_materialization(&library, &first_key, root.path()).unwrap();
    let first_apply = apply_managed_materialization(&library, &first_key, &first_plan).unwrap();
    assert!(first_apply.outcomes()[0].ownership_recorded());

    let destination = root.path().join("prompts/transfer.md");
    fs::write(
        &destination,
        library
            .read(second_key.entry_id(), second_key.version())
            .unwrap(),
    )
    .unwrap();
    let second_plan = plan_managed_materialization(&library, &second_key, root.path()).unwrap();
    assert_eq!(second_plan.items()[0].action(), MaterializationAction::NoOp);
    let before = snapshot_tree(root.path());
    let second_apply = apply_managed_materialization(&library, &second_key, &second_plan).unwrap();
    assert!(second_apply.outcomes()[0].ownership_recorded());
    assert_eq!(snapshot_tree(root.path()), before);
    assert_eq!(
        library.managed_copies().unwrap().as_slice(),
        std::slice::from_ref(&second_key)
    );

    let repeated_plan = plan_managed_materialization(&library, &second_key, root.path()).unwrap();
    let repeated = apply_managed_materialization(&library, &second_key, &repeated_plan).unwrap();
    assert!(repeated.outcomes()[0].ownership_recorded());
    drop(library);
    let reopened = CanonicalLibrary::open(home.path()).unwrap();
    assert_eq!(
        reopened.managed_copies().unwrap().as_slice(),
        std::slice::from_ref(&second_key)
    );
}

#[test]
fn held_file_read_rejects_same_length_in_place_change() {
    let root = TestDirectory::new("materialization-held-read-change");
    let path = root.path().join("change.md");
    root.write("change.md", b"before!!");

    assert!(matches!(
        inspect_file_with_after_first_read(
            MaterializationAgent::Codex,
            root.path(),
            Path::new("change.md"),
            || fs::write(&path, b"after!!!").unwrap(),
        )
        .unwrap_err(),
        MaterializationError::StateChanged(_)
    ));
}

#[cfg(unix)]
#[test]
fn held_file_read_rejects_same_length_path_replacement() {
    let root = TestDirectory::new("materialization-held-read-replacement");
    let path = root.path().join("replace.md");
    let replacement = root.path().join("replacement.tmp");
    root.write("replace.md", b"same len");
    root.write("replacement.tmp", b"same len");

    assert!(matches!(
        inspect_file_with_after_first_read(
            MaterializationAgent::Codex,
            root.path(),
            Path::new("replace.md"),
            || fs::rename(&replacement, &path).unwrap(),
        )
        .unwrap_err(),
        MaterializationError::StateChanged(_)
    ));
}

#[test]
fn disable_removes_only_exact_owned_bytes_and_reports_missing_modified_and_unowned() {
    let (home, library) = library();
    let root = TestDirectory::new("materialization-disable-cleanup");
    let project = LibraryProjectKey::parse("project-cleanup").unwrap();
    let inputs = [
        ("exact-owned", b"exact managed\n".as_slice()),
        ("missing-owned", b"missing managed\n".as_slice()),
        ("modified-owned", b"modified managed\n".as_slice()),
    ];
    let requests = inputs
        .iter()
        .map(|(name, bytes)| {
            let (id, version) = insert(&library, name, bytes);
            MaterializationRequest::new(MaterializationAgent::Codex, root.path(), id, version)
        })
        .collect::<Vec<_>>();
    let batch = apply_materialization(
        &library,
        &plan_materialization(&library, &requests).unwrap(),
    )
    .unwrap();
    let mut keys = Vec::new();
    for outcome in batch.outcomes() {
        let key = enablement_key(outcome, &project);
        library.enable(key.clone()).unwrap();
        record_materialization(&library, project.clone(), outcome).unwrap();
        keys.push(key);
    }

    let unowned_bytes = b"unowned exact bytes\n";
    let (unowned_id, unowned_version) = insert(&library, "unowned", unowned_bytes);
    root.write("prompts/unowned.md", unowned_bytes);
    let unowned_batch = apply_materialization(
        &library,
        &plan_materialization(
            &library,
            &[MaterializationRequest::new(
                MaterializationAgent::Codex,
                root.path(),
                unowned_id,
                unowned_version,
            )],
        )
        .unwrap(),
    )
    .unwrap();
    let unowned_record =
        record_materialization(&library, project.clone(), &unowned_batch.outcomes()[0]).unwrap();
    assert!(!unowned_record.recorded());
    let unowned_key = enablement_key(&unowned_batch.outcomes()[0], &project);
    library.enable(unowned_key.clone()).unwrap();

    fs::remove_file(root.path().join("prompts/missing-owned.md")).unwrap();
    fs::write(
        root.path().join("prompts/modified-owned.md"),
        b"user modified bytes\n",
    )
    .unwrap();
    drop(library);
    let library = CanonicalLibrary::open(home.path()).unwrap();

    let exact = disable_materialization(&library, &keys[0], root.path()).unwrap();
    assert!(exact.state_changed());
    assert_eq!(exact.cleanup(), ManagedCopyCleanupDisposition::Removed);
    assert!(!root.path().join("prompts/exact-owned.md").exists());

    let missing = disable_materialization(&library, &keys[1], root.path()).unwrap();
    assert_eq!(missing.cleanup(), ManagedCopyCleanupDisposition::Missing);

    let modified = disable_materialization(&library, &keys[2], root.path()).unwrap();
    assert_eq!(
        modified.cleanup(),
        ManagedCopyCleanupDisposition::PreservedModified
    );
    assert_eq!(
        fs::read(root.path().join("prompts/modified-owned.md")).unwrap(),
        b"user modified bytes\n"
    );

    let unowned = disable_materialization(&library, &unowned_key, root.path()).unwrap();
    assert_eq!(
        unowned.cleanup(),
        ManagedCopyCleanupDisposition::PreservedUnowned
    );
    assert_eq!(
        fs::read(root.path().join("prompts/unowned.md")).unwrap(),
        unowned_bytes
    );
    for key in keys.iter().chain([&unowned_key]) {
        assert!(!library.is_enabled(key).unwrap());
    }
    assert_eq!(library.managed_copies().unwrap(), [keys[2].clone()]);
}

#[test]
fn disable_quarantine_preserves_drift_when_target_is_recreated_during_restore() {
    let (_home, library) = library();
    let root = TestDirectory::new("materialization-disable-race");
    let project = LibraryProjectKey::parse("project-race").unwrap();
    let (id, version) = insert(&library, "raced", b"managed\n");
    let batch = apply_materialization(
        &library,
        &plan_materialization(
            &library,
            &[MaterializationRequest::new(
                MaterializationAgent::Codex,
                root.path(),
                id,
                version,
            )],
        )
        .unwrap(),
    )
    .unwrap();
    let outcome = &batch.outcomes()[0];
    let key = enablement_key(outcome, &project);
    library.enable(key.clone()).unwrap();
    record_materialization(&library, project, outcome).unwrap();
    let destination = fs::canonicalize(root.path())
        .unwrap()
        .join("prompts/raced.md");
    fs::write(&destination, b"user drift\n").unwrap();

    let error = disable_materialization_with_recreated_target(
        &library,
        &key,
        root.path(),
        b"racer bytes\n",
    )
    .unwrap_err();

    let quarantine = match error {
        MaterializationError::CleanupConflict {
            destination: found,
            quarantine,
        } => {
            assert_eq!(found, destination);
            quarantine
        }
        error => panic!("unexpected cleanup error: {error:?}"),
    };
    assert!(!library.is_enabled(&key).unwrap());
    assert_eq!(library.managed_copies().unwrap(), [key]);
    assert_eq!(fs::read(&destination).unwrap(), b"racer bytes\n");
    assert_eq!(fs::read(quarantine).unwrap(), b"user drift\n");
}

#[test]
fn disable_publish_failure_leaves_disabled_state_and_recoverable_ownership() {
    let (_home, library) = library();
    let root = TestDirectory::new("materialization-disable-publish-failure");
    let project = LibraryProjectKey::parse("project-publish-failure").unwrap();
    let key = create_owned_copy(&library, &root, &project, "publish-failure", b"managed\n");
    let destination = root.path().join("prompts/publish-failure.md");

    let error = disable_materialization_with_ownership_publish_failure(&library, &key, root.path())
        .unwrap_err();

    assert_eq!(
        error,
        MaterializationError::Library(crate::LibraryError::Io(
            crate::LibraryIoOperation::WriteManifest
        ))
    );
    assert!(!library.is_enabled(&key).unwrap());
    assert_eq!(library.managed_copies().unwrap(), [key]);
    assert!(!destination.exists());
}

#[test]
fn post_rename_sync_and_read_failures_restore_exact_target() {
    for (name, failure, expected_error) in [
        (
            "sync-restore",
            PostRenameFailure::Sync,
            MaterializationIoOperation::RemoveDestination,
        ),
        (
            "read-restore",
            PostRenameFailure::Read,
            MaterializationIoOperation::ReadDestination,
        ),
    ] {
        let (_home, library) = library();
        let root = TestDirectory::new(name);
        let project = LibraryProjectKey::parse(name).unwrap();
        let key = create_owned_copy(&library, &root, &project, name, b"managed exact\n");
        let destination = root.path().join(format!("prompts/{name}.md"));

        let error =
            disable_materialization_with_post_rename_failure(&library, &key, root.path(), failure)
                .unwrap_err();

        assert_eq!(error, MaterializationError::Io(expected_error));
        assert_eq!(fs::read(destination).unwrap(), b"managed exact\n");
        assert!(!library.is_enabled(&key).unwrap());
        assert_eq!(library.managed_copies().unwrap(), [key]);
        assert!(
            !fs::read_dir(root.path().join("prompts"))
                .unwrap()
                .any(|entry| entry
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".pam-quarantine-"))
        );
    }
}

#[test]
fn exact_cleanup_sync_and_remove_failures_preserve_quarantine_and_ownership() {
    for (name, failure) in [
        ("exact-sync-failure", PostRenameFailure::ExactSync),
        ("exact-remove-failure", PostRenameFailure::ExactRemove),
    ] {
        let (_home, library) = library();
        let root = TestDirectory::new(name);
        let project = LibraryProjectKey::parse(name).unwrap();
        let key = create_owned_copy(&library, &root, &project, name, b"managed exact\n");
        let destination = root.path().join(format!("prompts/{name}.md"));

        let error =
            disable_materialization_with_post_rename_failure(&library, &key, root.path(), failure)
                .unwrap_err();

        assert_eq!(
            error,
            MaterializationError::Io(MaterializationIoOperation::RemoveDestination)
        );
        assert!(!destination.exists());
        assert_eq!(
            fs::read(quarantined_managed_copy(&root)).unwrap(),
            b"managed exact\n"
        );
        assert!(!library.is_enabled(&key).unwrap());
        assert_eq!(library.managed_copies().unwrap(), [key]);
    }
}

#[test]
fn restoration_sync_failure_keeps_exact_destination_and_recovery_quarantine() {
    let (_home, library) = library();
    let root = TestDirectory::new("restore-sync-failure");
    let project = LibraryProjectKey::parse("restore-sync-failure").unwrap();
    let key = create_owned_copy(
        &library,
        &root,
        &project,
        "restore-sync-failure",
        b"managed exact\n",
    );
    let destination = fs::canonicalize(root.path())
        .unwrap()
        .join("prompts/restore-sync-failure.md");

    let error = disable_materialization_with_post_rename_failure(
        &library,
        &key,
        root.path(),
        PostRenameFailure::RestoreSync,
    )
    .unwrap_err();

    let quarantine = match error {
        MaterializationError::CleanupConflict {
            destination: found,
            quarantine,
        } => {
            assert_eq!(found, destination);
            quarantine
        }
        error => panic!("unexpected cleanup error: {error:?}"),
    };
    assert_eq!(fs::read(&destination).unwrap(), b"managed exact\n");
    assert_eq!(fs::read(quarantine).unwrap(), b"managed exact\n");
    assert!(!library.is_enabled(&key).unwrap());
    assert_eq!(library.managed_copies().unwrap(), [key]);
}

#[test]
fn post_removal_sync_failure_rebuilds_recovery_quarantine() {
    let (_home, library) = library();
    let root = TestDirectory::new("post-removal-sync-failure");
    let project = LibraryProjectKey::parse("post-removal-sync-failure").unwrap();
    let key = create_owned_copy(
        &library,
        &root,
        &project,
        "post-removal-sync-failure",
        b"managed exact\n",
    );
    let destination = fs::canonicalize(root.path())
        .unwrap()
        .join("prompts/post-removal-sync-failure.md");

    let error = disable_materialization_with_post_rename_failure(
        &library,
        &key,
        root.path(),
        PostRenameFailure::RestorePostRemoveSync,
    )
    .unwrap_err();

    let quarantine = match error {
        MaterializationError::CleanupConflict {
            destination: found,
            quarantine,
        } => {
            assert_eq!(found, destination);
            quarantine
        }
        error => panic!("unexpected cleanup error: {error:?}"),
    };
    assert_eq!(fs::read(&destination).unwrap(), b"managed exact\n");
    assert_eq!(fs::read(quarantine).unwrap(), b"managed exact\n");
    assert!(!library.is_enabled(&key).unwrap());
    assert_eq!(library.managed_copies().unwrap(), [key]);
}

#[test]
fn post_rename_nonregular_target_retains_typed_recovery_quarantine() {
    let (_home, library) = library();
    let root = TestDirectory::new("materialization-disable-nonregular");
    let project = LibraryProjectKey::parse("project-nonregular").unwrap();
    let key = create_owned_copy(&library, &root, &project, "nonregular", b"managed\n");
    let destination = fs::canonicalize(root.path())
        .unwrap()
        .join("prompts/nonregular.md");

    let error = disable_materialization_with_post_rename_failure(
        &library,
        &key,
        root.path(),
        PostRenameFailure::NonRegular,
    )
    .unwrap_err();

    let quarantine = match error {
        MaterializationError::CleanupConflict {
            destination: found,
            quarantine,
        } => {
            assert_eq!(found, destination);
            quarantine
        }
        error => panic!("unexpected cleanup error: {error:?}"),
    };
    assert!(quarantine.is_dir());
    assert!(!destination.exists());
    assert!(!library.is_enabled(&key).unwrap());
    assert_eq!(library.managed_copies().unwrap(), [key]);
}

#[cfg(unix)]
#[test]
fn disable_preserves_symlinked_owned_destination_and_retains_drift_record() {
    let (_home, library) = library();
    let root = TestDirectory::new("materialization-disable-symlink");
    let outside = TestDirectory::new("materialization-disable-symlink-outside");
    let project = LibraryProjectKey::parse("project-symlink").unwrap();
    let (id, version) = insert(&library, "linked", b"managed\n");
    let batch = apply_materialization(
        &library,
        &plan_materialization(
            &library,
            &[MaterializationRequest::new(
                MaterializationAgent::Codex,
                root.path(),
                id,
                version,
            )],
        )
        .unwrap(),
    )
    .unwrap();
    let outcome = &batch.outcomes()[0];
    let key = enablement_key(outcome, &project);
    library.enable(key.clone()).unwrap();
    record_materialization(&library, project.clone(), outcome).unwrap();
    outside.write("target.md", b"outside\n");
    let destination = root.path().join("prompts/linked.md");
    fs::remove_file(&destination).unwrap();
    symlink(outside.path().join("target.md"), &destination).unwrap();

    let disabled = disable_materialization(&library, &key, root.path()).unwrap();

    assert_eq!(
        disabled.cleanup(),
        ManagedCopyCleanupDisposition::PreservedSymlink
    );
    assert!(!library.is_enabled(&key).unwrap());
    assert_eq!(library.managed_copies().unwrap(), [key]);
    assert!(
        fs::symlink_metadata(destination)
            .unwrap()
            .file_type()
            .is_symlink()
    );
    assert_eq!(
        fs::read(outside.path().join("target.md")).unwrap(),
        b"outside\n"
    );
}

#[test]
fn duplicate_destinations_coalesce_or_reject_conflicting_versions() {
    let (_home, library) = library();
    let root = TestDirectory::new("materialization-duplicates");
    let (id, first) = insert(&library, "duplicate", b"first\n");
    let (_, second) = insert(&library, "duplicate", b"second\n");
    let duplicate = MaterializationRequest::new(
        MaterializationAgent::Codex,
        root.path(),
        id.clone(),
        first.clone(),
    );
    let plan = plan_materialization(&library, &[duplicate.clone(), duplicate]).unwrap();
    assert_eq!(plan.items().len(), 1);

    let error = plan_materialization(
        &library,
        &[
            MaterializationRequest::new(
                MaterializationAgent::Codex,
                root.path(),
                id.clone(),
                first,
            ),
            MaterializationRequest::new(MaterializationAgent::Codex, root.path(), id, second),
        ],
    )
    .unwrap_err();
    assert!(matches!(
        error,
        MaterializationError::DestinationConflict(_)
    ));
}

#[test]
fn concurrent_plans_lock_the_root_and_never_overwrite_the_winner() {
    let (_home, library) = library();
    let root = TestDirectory::new("materialization-concurrent-root");
    let (id, first) = insert(&library, "race", b"first contender\n");
    let (_, second) = insert(&library, "race", b"second contender\n");
    let first_plan = plan_materialization(
        &library,
        &[MaterializationRequest::new(
            MaterializationAgent::Codex,
            root.path(),
            id.clone(),
            first,
        )],
    )
    .unwrap();
    let second_plan = plan_materialization(
        &library,
        &[MaterializationRequest::new(
            MaterializationAgent::Codex,
            root.path(),
            id,
            second,
        )],
    )
    .unwrap();
    let barrier = Arc::new(Barrier::new(3));

    let (first_result, second_result) = thread::scope(|scope| {
        let library = &library;
        let first_barrier = Arc::clone(&barrier);
        let first_plan = &first_plan;
        let first_apply = scope.spawn(move || {
            first_barrier.wait();
            apply_materialization(library, first_plan)
        });
        let second_barrier = Arc::clone(&barrier);
        let second_plan = &second_plan;
        let second_apply = scope.spawn(move || {
            second_barrier.wait();
            apply_materialization(library, second_plan)
        });
        barrier.wait();
        (first_apply.join().unwrap(), second_apply.join().unwrap())
    });

    let loser = match (first_result, second_result) {
        (Ok(_), Err(error)) | (Err(error), Ok(_)) => error,
        (first, second) => {
            panic!("expected one winner and one loser, got {first:?} and {second:?}")
        }
    };
    assert!(
        matches!(loser, MaterializationError::StateChanged(_)),
        "unexpected loser: {loser:?}"
    );
    let bytes = fs::read(root.path().join("prompts/race.md")).unwrap();
    assert!(bytes == b"first contender\n" || bytes == b"second contender\n");
}

#[test]
fn apply_revalidates_the_entire_batch_before_writing() {
    let (_home, library) = library();
    let root = TestDirectory::new("materialization-revalidate");
    let (first_id, first_version) = insert(&library, "first", b"first\n");
    let (second_id, second_version) = insert(&library, "second", b"second\n");
    let plan = plan_materialization(
        &library,
        &[
            MaterializationRequest::new(
                MaterializationAgent::Codex,
                root.path(),
                first_id,
                first_version,
            ),
            MaterializationRequest::new(
                MaterializationAgent::Codex,
                root.path(),
                second_id,
                second_version,
            ),
        ],
    )
    .unwrap();
    root.write("prompts/second.md", b"appeared after preflight");

    assert!(matches!(
        apply_materialization(&library, &plan).unwrap_err(),
        MaterializationError::StateChanged(_)
    ));
    assert!(!root.path().join("prompts/first.md").exists());
    assert_eq!(
        fs::read(root.path().join("prompts/second.md")).unwrap(),
        b"appeared after preflight"
    );
}

#[test]
fn noncooperating_writer_between_revalidation_and_publish_is_never_overwritten() {
    let (_home, library) = library();
    let replace_root = TestDirectory::new("materialization-pre-publish-replace-race");
    let replace_old = b"replace old\n";
    let writer = b"writer won replace race\n";
    replace_root.write("prompts/replace-race.md", replace_old);
    let (replace_id, replace_version) = insert(&library, "replace-race", b"PAM replace\n");
    let replace_plan = plan_materialization(
        &library,
        &[MaterializationRequest::new(
            MaterializationAgent::Codex,
            replace_root.path(),
            replace_id,
            replace_version,
        )],
    )
    .unwrap();

    assert!(matches!(
        apply_materialization_with_pre_publish_writer(&library, &replace_plan, 0, writer)
            .unwrap_err(),
        MaterializationError::StateChanged(_)
    ));
    assert_eq!(
        fs::read(replace_root.path().join("prompts/replace-race.md")).unwrap(),
        writer
    );
    assert_eq!(
        fs::read(replace_plan.items()[0].backup_destination().unwrap()).unwrap(),
        replace_old
    );

    let create_root = TestDirectory::new("materialization-pre-publish-create-race");
    let (create_id, create_version) = insert(&library, "create-race", b"PAM create\n");
    let create_plan = plan_materialization(
        &library,
        &[MaterializationRequest::new(
            MaterializationAgent::Codex,
            create_root.path(),
            create_id,
            create_version,
        )],
    )
    .unwrap();
    let create_writer = b"writer won create race\n";

    assert!(matches!(
        apply_materialization_with_pre_publish_writer(&library, &create_plan, 0, create_writer,)
            .unwrap_err(),
        MaterializationError::StateChanged(_)
    ));
    assert_eq!(
        fs::read(create_root.path().join("prompts/create-race.md")).unwrap(),
        create_writer
    );
}

#[test]
fn rollback_exhausts_the_batch_without_deleting_a_post_publish_writer() {
    let (_home, library) = library();
    let root = TestDirectory::new("materialization-post-publish-replace-race");
    let first_old = b"first old bytes\n";
    let second_old = b"second old bytes\n";
    let writer = b"writer after PAM publish\n";
    root.write("rules/first-race.mdc", first_old);
    root.write("rules/second-race.mdc", second_old);
    let (first_id, first_version) = insert(&library, "first-race", b"first PAM bytes\n");
    let (second_id, second_version) = insert(&library, "second-race", b"second PAM bytes\n");
    let plan = plan_materialization(
        &library,
        &[
            MaterializationRequest::new(
                MaterializationAgent::Cursor,
                root.path(),
                first_id,
                first_version,
            ),
            MaterializationRequest::new(
                MaterializationAgent::Cursor,
                root.path(),
                second_id,
                second_version,
            ),
        ],
    )
    .unwrap();

    let error =
        apply_materialization_with_post_publish_writer(&library, &plan, 1, writer).unwrap_err();
    let MaterializationError::RollbackFailed { paths } = error else {
        panic!("expected typed rollback failure, got {error:?}");
    };
    assert!(paths.iter().any(|path| path.ends_with("second-race.mdc")));
    assert!(paths.iter().any(|path| {
        path.file_name()
            .is_some_and(|name| name == "previous-destination")
    }));
    assert_eq!(
        fs::read(root.path().join("rules/first-race.mdc")).unwrap(),
        first_old
    );
    assert_eq!(
        fs::read(root.path().join("rules/second-race.mdc")).unwrap(),
        writer
    );
    assert_eq!(
        fs::read(plan.items()[1].backup_destination().unwrap()).unwrap(),
        second_old
    );
    let recovery = paths
        .iter()
        .find(|path| {
            path.file_name()
                .is_some_and(|name| name == "previous-destination")
        })
        .unwrap();
    assert_eq!(fs::read(recovery).unwrap(), second_old);
}

#[test]
fn create_rollback_preserves_a_post_publish_writer() {
    let (_home, library) = library();
    let root = TestDirectory::new("materialization-post-publish-create-race");
    let (id, version) = insert(&library, "create-writer", b"PAM create bytes\n");
    let plan = plan_materialization(
        &library,
        &[MaterializationRequest::new(
            MaterializationAgent::Codex,
            root.path(),
            id,
            version,
        )],
    )
    .unwrap();
    let writer = b"writer after create publish\n";

    assert!(matches!(
        apply_materialization_with_post_publish_writer(&library, &plan, 0, writer).unwrap_err(),
        MaterializationError::RollbackFailed { .. }
    ));
    assert_eq!(
        fs::read(root.path().join("prompts/create-writer.md")).unwrap(),
        writer
    );
}

#[test]
fn injected_verification_failure_restores_replacement_and_removes_batch_creates() {
    let (_home, library) = library();
    let replace_root = TestDirectory::new("materialization-restore");
    let old = b"old bytes kept exactly\r\n";
    let (id, version) = insert(&library, "restore", b"replacement\n");
    replace_root.write("rules/restore.mdc", old);
    let replace_plan = plan_materialization(
        &library,
        &[MaterializationRequest::new(
            MaterializationAgent::Cursor,
            replace_root.path(),
            id,
            version,
        )],
    )
    .unwrap();
    assert!(matches!(
        apply_materialization_with_verification_failure(&library, &replace_plan, 0).unwrap_err(),
        MaterializationError::VerificationFailed(_)
    ));
    assert_eq!(
        fs::read(replace_root.path().join("rules/restore.mdc")).unwrap(),
        old
    );
    assert_eq!(
        fs::read(replace_plan.items()[0].backup_destination().unwrap()).unwrap(),
        old
    );
    fs::write(
        replace_root.path().join("rules/restore.mdc"),
        b"edited after restore",
    )
    .unwrap();
    assert_eq!(
        fs::read(replace_plan.items()[0].backup_destination().unwrap()).unwrap(),
        old
    );

    let create_root = TestDirectory::new("materialization-remove-create");
    let (first_id, first_version) = insert(&library, "create-first", b"first\n");
    let (second_id, second_version) = insert(&library, "create-second", b"second\n");
    let create_plan = plan_materialization(
        &library,
        &[
            MaterializationRequest::new(
                MaterializationAgent::Codex,
                create_root.path(),
                first_id,
                first_version,
            ),
            MaterializationRequest::new(
                MaterializationAgent::Codex,
                create_root.path(),
                second_id,
                second_version,
            ),
        ],
    )
    .unwrap();
    assert!(matches!(
        apply_materialization_with_verification_failure(&library, &create_plan, 1).unwrap_err(),
        MaterializationError::VerificationFailed(_)
    ));
    assert!(!create_root.path().join("prompts/create-first.md").exists());
    assert!(!create_root.path().join("prompts/create-second.md").exists());
    assert!(!create_root.path().join("prompts").exists());
}

#[test]
fn directory_sync_failure_removes_the_just_created_directory() {
    let (_home, library) = library();
    let root = TestDirectory::new("materialization-directory-sync-failure");
    let (id, version) = insert(&library, "sync-failure", b"content\n");
    let plan = plan_materialization(
        &library,
        &[MaterializationRequest::new(
            MaterializationAgent::Codex,
            root.path(),
            id,
            version,
        )],
    )
    .unwrap();

    assert!(matches!(
        apply_materialization_with_directory_sync_failure(&library, &plan, 0).unwrap_err(),
        MaterializationError::Io(MaterializationIoOperation::CreateDirectory)
    ));
    assert!(!root.path().join("prompts").exists());
}

#[test]
fn second_item_failure_restores_every_earlier_replacement() {
    let (_home, library) = library();
    let root = TestDirectory::new("materialization-multi-restore");
    let first_old = b"first old\r\n";
    let second_old = b"second old\n";
    root.write("rules/first-replace.mdc", first_old);
    root.write("rules/second-replace.mdc", second_old);
    let (first_id, first_version) = insert(&library, "first-replace", b"first new\n");
    let (second_id, second_version) = insert(&library, "second-replace", b"second new\n");
    let plan = plan_materialization(
        &library,
        &[
            MaterializationRequest::new(
                MaterializationAgent::Cursor,
                root.path(),
                first_id,
                first_version,
            ),
            MaterializationRequest::new(
                MaterializationAgent::Cursor,
                root.path(),
                second_id,
                second_version,
            ),
        ],
    )
    .unwrap();

    assert!(matches!(
        apply_materialization_with_verification_failure(&library, &plan, 1).unwrap_err(),
        MaterializationError::VerificationFailed(_)
    ));
    assert_eq!(
        fs::read(root.path().join("rules/first-replace.mdc")).unwrap(),
        first_old
    );
    assert_eq!(
        fs::read(root.path().join("rules/second-replace.mdc")).unwrap(),
        second_old
    );
    assert_eq!(
        fs::read(plan.items()[0].backup_destination().unwrap()).unwrap(),
        first_old
    );
    assert_eq!(
        fs::read(plan.items()[1].backup_destination().unwrap()).unwrap(),
        second_old
    );
}

#[test]
fn pre_rename_failure_retains_the_live_replacement_target() {
    let (_home, library) = library();
    let root = TestDirectory::new("materialization-before-rename");
    let old = b"live old bytes\n";
    root.write("prompts/atomic.md", old);
    let (id, version) = insert(&library, "atomic", b"new bytes\n");
    let plan = plan_materialization(
        &library,
        &[MaterializationRequest::new(
            MaterializationAgent::Codex,
            root.path(),
            id,
            version,
        )],
    )
    .unwrap();
    #[cfg(unix)]
    let inode_before = {
        use std::os::unix::fs::MetadataExt as _;
        fs::metadata(root.path().join("prompts/atomic.md"))
            .unwrap()
            .ino()
    };

    assert!(matches!(
        apply_materialization_with_pre_rename_failure(&library, &plan, 0).unwrap_err(),
        MaterializationError::Io(MaterializationIoOperation::WriteDestination)
    ));
    assert_eq!(
        fs::read(root.path().join("prompts/atomic.md")).unwrap(),
        old
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        assert_eq!(
            fs::metadata(root.path().join("prompts/atomic.md"))
                .unwrap()
                .ino(),
            inode_before
        );
    }
}

#[cfg(unix)]
#[test]
fn symlink_destination_rejects_the_whole_dry_run_without_partial_writes() {
    let (_home, library) = library();
    let safe_root = TestDirectory::new("materialization-preflight-safe");
    let unsafe_root = TestDirectory::new("materialization-preflight-unsafe");
    let outside = TestDirectory::new("materialization-preflight-outside");
    let (safe_id, safe_version) = insert(&library, "safe", b"safe\n");
    let (unsafe_id, unsafe_version) = insert(&library, "unsafe", b"unsafe\n");
    unsafe_root.write("rules/.keep", b"");
    outside.write("target.mdc", b"outside");
    symlink(
        outside.path().join("target.mdc"),
        unsafe_root.path().join("rules/unsafe.mdc"),
    )
    .unwrap();

    let error = plan_materialization(
        &library,
        &[
            MaterializationRequest::new(
                MaterializationAgent::Codex,
                safe_root.path(),
                safe_id,
                safe_version,
            ),
            MaterializationRequest::new(
                MaterializationAgent::Cursor,
                unsafe_root.path(),
                unsafe_id,
                unsafe_version,
            ),
        ],
    )
    .unwrap_err();
    assert!(matches!(error, MaterializationError::UnsafePath(_)));
    assert!(!safe_root.path().join("prompts").exists());
    assert_eq!(
        fs::read(outside.path().join("target.mdc")).unwrap(),
        b"outside"
    );
}

#[test]
fn drift_inspection_is_read_only_and_reports_clean_modified_missing_and_conflict() {
    let (_home, library) = library();
    let root = TestDirectory::new("materialization-drift-states");
    let project = LibraryProjectKey::parse("drift-states").unwrap();
    let key = create_owned_copy(&library, &root, &project, "drift", b"canonical\n");
    let destination = root.path().join("prompts/drift.md");
    let root_entries_before = fs::read_dir(root.path()).unwrap().count();
    let prompt_entries_before = fs::read_dir(root.path().join("prompts")).unwrap().count();

    let clean = inspect_materialization_drift(&library, &key, root.path()).unwrap();
    assert_eq!(clean.state(), &MaterializationDriftState::Clean);
    assert_eq!(clean.expected_digest(), key.version());
    assert_eq!(
        clean.destination(),
        fs::canonicalize(root.path())
            .unwrap()
            .join("prompts/drift.md")
    );
    assert_eq!(
        fs::read_dir(root.path()).unwrap().count(),
        root_entries_before
    );
    assert_eq!(
        fs::read_dir(root.path().join("prompts")).unwrap().count(),
        prompt_entries_before
    );

    fs::write(&destination, b"locally modified\r\n").unwrap();
    let modified = inspect_materialization_drift(&library, &key, root.path()).unwrap();
    let MaterializationDriftState::Modified(actual) = modified.state() else {
        panic!("expected modified drift");
    };
    assert_ne!(actual, key.version());

    fs::remove_file(&destination).unwrap();
    assert_eq!(
        inspect_materialization_drift(&library, &key, root.path())
            .unwrap()
            .state(),
        &MaterializationDriftState::Missing
    );

    let missing_root = root.path().join("missing-agent-root");
    assert_eq!(
        inspect_materialization_drift(&library, &key, &missing_root)
            .unwrap()
            .state(),
        &MaterializationDriftState::Conflict(MaterializationDriftConflict::UnsafeRoot)
    );
    assert!(!missing_root.exists());

    let (unowned_id, unowned_version) = insert(&library, "unowned-drift", b"library\n");
    let unowned_key =
        LibraryEnablementKey::new(unowned_id, unowned_version, OriginAgent::Codex, project);
    library.enable(unowned_key.clone()).unwrap();
    root.write("prompts/unowned-drift.md", b"user bytes\n");
    assert_eq!(
        inspect_materialization_drift(&library, &unowned_key, root.path())
            .unwrap()
            .state(),
        &MaterializationDriftState::Conflict(MaterializationDriftConflict::Unowned)
    );
}

#[cfg(unix)]
#[test]
fn drift_inspection_classifies_symlink_and_nonregular_targets_as_conflicts() {
    let (_home, library) = library();
    let root = TestDirectory::new("materialization-drift-unsafe");
    let outside = TestDirectory::new("materialization-drift-unsafe-outside");
    let project = LibraryProjectKey::parse("drift-unsafe").unwrap();
    let key = create_owned_copy(&library, &root, &project, "unsafe-drift", b"canonical\n");
    let destination = root.path().join("prompts/unsafe-drift.md");
    outside.write("target.md", b"outside\n");
    fs::remove_file(&destination).unwrap();
    symlink(outside.path().join("target.md"), &destination).unwrap();
    assert_eq!(
        inspect_materialization_drift(&library, &key, root.path())
            .unwrap()
            .state(),
        &MaterializationDriftState::Conflict(MaterializationDriftConflict::Symlink)
    );
    fs::remove_file(&destination).unwrap();
    fs::create_dir(&destination).unwrap();
    assert_eq!(
        inspect_materialization_drift(&library, &key, root.path())
            .unwrap()
            .state(),
        &MaterializationDriftState::Conflict(MaterializationDriftConflict::NonRegular)
    );
}

#[test]
fn resync_preview_is_zero_write_and_apply_restores_clean_bytes_with_backup_and_restart() {
    let (home, library) = library();
    let root = TestDirectory::new("materialization-resync");
    let project = LibraryProjectKey::parse("resync").unwrap();
    let key = create_owned_copy(&library, &root, &project, "resync", b"canonical\n");
    let destination = root.path().join("prompts/resync.md");
    let drifted = b"local edit\r\n";
    fs::write(&destination, drifted).unwrap();

    let replace = plan_materialization_resync(&library, &key, root.path()).unwrap();
    assert_eq!(replace.items()[0].action(), MaterializationAction::Replace);
    assert_eq!(fs::read(&destination).unwrap(), drifted);
    let replaced = apply_materialization_resync(&library, &key, &replace).unwrap();
    assert_eq!(fs::read(&destination).unwrap(), b"canonical\n");
    assert_eq!(
        fs::read(replaced.outcomes()[0].backup().unwrap().path()).unwrap(),
        drifted
    );
    assert_eq!(
        inspect_materialization_drift(&library, &key, root.path())
            .unwrap()
            .state(),
        &MaterializationDriftState::Clean
    );

    fs::remove_file(&destination).unwrap();
    let create = plan_materialization_resync(&library, &key, root.path()).unwrap();
    assert_eq!(create.items()[0].action(), MaterializationAction::Create);
    assert!(!destination.exists());
    apply_materialization_resync(&library, &key, &create).unwrap();
    let no_op = plan_materialization_resync(&library, &key, root.path()).unwrap();
    assert_eq!(no_op.items()[0].action(), MaterializationAction::NoOp);
    apply_materialization_resync(&library, &key, &no_op).unwrap();

    drop(library);
    let reopened = CanonicalLibrary::open(home.path()).unwrap();
    assert_eq!(
        inspect_materialization_drift(&reopened, &key, root.path())
            .unwrap()
            .state(),
        &MaterializationDriftState::Clean
    );
}

#[test]
fn resync_rolls_back_when_concurrent_disable_prevents_ownership_recording() {
    let (_home, library) = library();
    let root = TestDirectory::new("materialization-resync-disable-before-record");
    let project = LibraryProjectKey::parse("resync-disable-before-record").unwrap();
    let key = create_owned_copy(
        &library,
        &root,
        &project,
        "disable-before-record",
        b"canonical\n",
    );
    let destination = root.path().join("prompts/disable-before-record.md");
    let drifted = b"user drift before resync\n";
    fs::write(&destination, drifted).unwrap();
    let preview = plan_materialization_resync(&library, &key, root.path()).unwrap();

    assert_eq!(
        apply_materialization_resync_with_disable_before_record(&library, &key, &preview)
            .unwrap_err(),
        MaterializationError::ResyncConflict(MaterializationDriftConflict::Disabled)
    );
    assert_eq!(fs::read(&destination).unwrap(), drifted);
    assert!(!library.is_enabled(&key).unwrap());
    assert_eq!(library.managed_copies().unwrap(), vec![key.clone()]);
    assert_eq!(
        inspect_materialization_drift(&library, &key, root.path())
            .unwrap()
            .state(),
        &MaterializationDriftState::Conflict(MaterializationDriftConflict::Disabled)
    );
}

#[test]
fn resync_revalidates_races_and_rejects_disabled_keys_without_overwriting() {
    let (_home, library) = library();
    let root = TestDirectory::new("materialization-resync-race");
    let project = LibraryProjectKey::parse("resync-race").unwrap();
    let key = create_owned_copy(&library, &root, &project, "race-resync", b"canonical\n");
    let destination = root.path().join("prompts/race-resync.md");
    fs::write(&destination, b"first drift\n").unwrap();
    let preview = plan_materialization_resync(&library, &key, root.path()).unwrap();
    fs::write(&destination, b"second drift\n").unwrap();
    assert!(matches!(
        apply_materialization_resync(&library, &key, &preview).unwrap_err(),
        MaterializationError::StateChanged(_)
    ));
    assert_eq!(fs::read(&destination).unwrap(), b"second drift\n");

    let disabled = disable_materialization(&library, &key, root.path()).unwrap();
    assert_eq!(
        disabled.cleanup(),
        ManagedCopyCleanupDisposition::PreservedModified
    );
    assert_eq!(
        inspect_materialization_drift(&library, &key, root.path())
            .unwrap()
            .state(),
        &MaterializationDriftState::Conflict(MaterializationDriftConflict::Disabled)
    );
    assert!(matches!(
        plan_materialization_resync(&library, &key, root.path()).unwrap_err(),
        MaterializationError::ResyncConflict(MaterializationDriftConflict::Disabled)
    ));
    assert!(matches!(
        apply_materialization_resync(&library, &key, &preview).unwrap_err(),
        MaterializationError::ResyncConflict(MaterializationDriftConflict::Disabled)
    ));
    assert_eq!(fs::read(&destination).unwrap(), b"second drift\n");
}
