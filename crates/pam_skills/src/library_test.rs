use std::{
    fs,
    path::{Path, PathBuf},
    sync::{Arc, Barrier},
    thread,
};

#[cfg(unix)]
use std::os::unix::{
    ffi::{OsStrExt as _, OsStringExt as _},
    fs::{MetadataExt as _, symlink},
};

use pam_core::ContentDigest;
use sha2::{Digest as _, Sha256};

#[cfg(unix)]
use crate::library::managed_root_digest_for_test;
use crate::scan::ScanSession;
use crate::{
    AgentArtifact, ArtifactInstallProvenance, ArtifactKind, ArtifactScope, CanonicalEntryId,
    CanonicalLibrary, CursorScanRoots, LIBRARY_MANIFEST_SCHEMA_VERSION, LibraryEnablementKey,
    LibraryError, LibraryInsertDisposition, LibraryManagedRootId, LibraryProjectKey, LoadSemantics,
    MAX_CANONICAL_ENTRY_ID_BYTES, MAX_LIBRARY_ARTIFACT_BYTES, MAX_LIBRARY_MANIFEST_BYTES,
    MAX_LIBRARY_PROJECT_KEY_BYTES, ManagedCopyCleanupDisposition, OriginAgent, ScanLimits,
    ScanReport, disable_materialization, scan_cursor, scan_test::TestDirectory,
};

fn generation_paths(home: &TestDirectory, directory: &str) -> Vec<PathBuf> {
    let mut paths = fs::read_dir(home.path().join("pam/skill-library").join(directory))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "json")
        })
        .collect::<Vec<_>>();
    paths.sort();
    paths
}

fn manifest_paths(home: &TestDirectory) -> Vec<PathBuf> {
    generation_paths(home, "manifests")
}

fn commit_paths(home: &TestDirectory) -> Vec<PathBuf> {
    generation_paths(home, "commits")
}

fn epoch_paths(home: &TestDirectory) -> Vec<PathBuf> {
    generation_paths(home, "epochs")
}

fn pending_paths(home: &TestDirectory) -> Vec<PathBuf> {
    generation_paths(home, "pending")
}

fn manifest_path(home: &TestDirectory) -> PathBuf {
    manifest_paths(home).pop().unwrap()
}

fn rewrite_latest_manifest(home: &TestDirectory, bytes: &[u8]) {
    let manifest = manifest_path(home);
    let commit = commit_paths(home).pop().unwrap();
    fs::write(manifest, bytes).unwrap();
    let generation = commit
        .file_stem()
        .unwrap()
        .to_str()
        .unwrap()
        .parse::<u64>()
        .unwrap();
    let marker = serde_json::json!({
        "schema_version": 1,
        "generation": generation,
        "manifest_digest": ContentDigest::from_sha256(Sha256::digest(bytes).into()),
    });
    let mut marker = serde_json::to_vec_pretty(&marker).unwrap();
    marker.push(b'\n');
    fs::write(commit, marker).unwrap();
}

fn populated_generation_home(label: &str) -> TestDirectory {
    let home = TestDirectory::new(label);
    let library = CanonicalLibrary::open(home.path()).unwrap();
    let entry_id = CanonicalEntryId::parse("review").unwrap();
    library.insert(entry_id.clone(), b"first").unwrap();
    library.insert(entry_id, b"second").unwrap();
    drop(library);
    home
}

fn blob_path(library: &CanonicalLibrary, version: &ContentDigest) -> PathBuf {
    library
        .root_path()
        .join("blobs/sha256")
        .join(version.sha256_hex())
}

fn managed_root_id(directory: &TestDirectory) -> LibraryManagedRootId {
    LibraryManagedRootId::from_canonical_path(&fs::canonicalize(directory.path()).unwrap()).unwrap()
}

fn assert_no_temporary_files(directory: &Path) {
    for entry in fs::read_dir(directory).unwrap() {
        let entry = entry.unwrap();
        assert!(!entry.file_name().to_string_lossy().contains(".pam-tmp-"));
        if entry.file_type().unwrap().is_dir() {
            assert_no_temporary_files(&entry.path());
        }
    }
}

fn scanned_artifact(path: &str, bytes: &[u8]) -> AgentArtifact {
    AgentArtifact::new(
        path,
        path,
        ArtifactKind::Rule,
        ArtifactScope::Project,
        OriginAgent::Cursor,
        LoadSemantics::ModelSelected,
        ContentDigest::from_sha256(Sha256::digest(bytes).into()),
    )
    .unwrap()
}

fn report_with_source(artifact: AgentArtifact, bytes: &[u8]) -> ScanReport {
    let mut session = ScanSession::new(ScanLimits::default());
    session.push_artifact_with_content(artifact, bytes.to_vec());
    session.finish()
}

#[test]
fn canonical_entry_ids_are_path_safe_and_serde_validated() {
    for value in ["skill", "review.skill-1", "a_b", "0"] {
        let entry_id = CanonicalEntryId::parse(value).unwrap();
        assert_eq!(entry_id.as_str(), value);
        assert_eq!(
            serde_json::to_string(&entry_id).unwrap(),
            format!("\"{value}\"")
        );
        assert_eq!(
            serde_json::from_str::<CanonicalEntryId>(&format!("\"{value}\""))
                .unwrap()
                .as_str(),
            value
        );
    }
    assert!(CanonicalEntryId::parse("a".repeat(MAX_CANONICAL_ENTRY_ID_BYTES)).is_ok());

    for value in [
        "",
        "Skill",
        ".skill",
        "skill.",
        "a/b",
        "a..b/",
        "a b",
        "a\0b",
        "con",
        "con.md",
        "aux.rule",
        "nul",
        "com1",
        "com9.prompt",
        "lpt1",
        "lpt9.mdc",
        "CON.txt",
    ] {
        assert!(
            CanonicalEntryId::parse(value).is_err(),
            "accepted {value:?}"
        );
        assert!(
            serde_json::from_str::<CanonicalEntryId>(&serde_json::to_string(value).unwrap())
                .is_err(),
            "deserialized {value:?}"
        );
    }
    assert!(CanonicalEntryId::parse("a".repeat(MAX_CANONICAL_ENTRY_ID_BYTES + 1)).is_err());
}

#[test]
fn project_keys_reject_paths_controls_and_unbounded_metadata() {
    for value in ["project", "project-1", "project.key_2", "0"] {
        let key = LibraryProjectKey::parse(value).unwrap();
        assert_eq!(key.as_str(), value);
        assert_eq!(
            serde_json::from_str::<LibraryProjectKey>(&serde_json::to_string(&key).unwrap())
                .unwrap(),
            key
        );
    }
    assert!(LibraryProjectKey::parse("a".repeat(MAX_LIBRARY_PROJECT_KEY_BYTES)).is_ok());
    for value in ["", "/repo", "repo/path", "repo\\path", "Repo", "repo\npath"] {
        assert!(
            LibraryProjectKey::parse(value).is_err(),
            "accepted {value:?}"
        );
        assert!(
            serde_json::from_str::<LibraryProjectKey>(&serde_json::to_string(value).unwrap())
                .is_err()
        );
    }
    assert!(LibraryProjectKey::parse("a".repeat(MAX_LIBRARY_PROJECT_KEY_BYTES + 1)).is_err());
}

#[test]
fn enablements_default_disabled_are_exact_idempotent_sorted_and_durable() {
    let home = TestDirectory::new("canonical-library-enablement");
    let agent_root = TestDirectory::new("canonical-library-enablement-agent");
    let library = CanonicalLibrary::open(home.path()).unwrap();
    let entry_id = CanonicalEntryId::parse("review").unwrap();
    let first = library.insert(entry_id.clone(), b"first").unwrap();
    let second = library.insert(entry_id.clone(), b"second").unwrap();
    let project = LibraryProjectKey::parse("project-a").unwrap();
    let other_project = LibraryProjectKey::parse("project-b").unwrap();
    let exact = LibraryEnablementKey::new(
        entry_id.clone(),
        first.version().clone(),
        OriginAgent::Codex,
        project.clone(),
    );
    let other_version = LibraryEnablementKey::new(
        entry_id.clone(),
        second.version().clone(),
        OriginAgent::Codex,
        project.clone(),
    );
    let other_agent = LibraryEnablementKey::new(
        entry_id.clone(),
        first.version().clone(),
        OriginAgent::Cursor,
        project,
    );
    let other_project = LibraryEnablementKey::new(
        entry_id,
        first.version().clone(),
        OriginAgent::Codex,
        other_project,
    );

    for key in [&exact, &other_version, &other_agent, &other_project] {
        assert!(!library.is_enabled(key).unwrap());
    }
    assert!(library.enablements().unwrap().is_empty());
    assert!(library.enable(exact.clone()).unwrap().changed());
    assert!(!library.enable(exact.clone()).unwrap().changed());
    for key in [
        other_project.clone(),
        other_agent.clone(),
        other_version.clone(),
    ] {
        assert!(library.enable(key).unwrap().changed());
    }
    let enabled = library.enablements().unwrap();
    assert!(enabled.windows(2).all(|pair| pair[0] < pair[1]));
    assert_eq!(enabled.len(), 4);
    let disabled = disable_materialization(&library, &exact, agent_root.path()).unwrap();
    assert!(disabled.state_changed());
    assert_eq!(
        disabled.cleanup(),
        ManagedCopyCleanupDisposition::PreservedUnowned
    );
    assert!(
        !disable_materialization(&library, &exact, agent_root.path())
            .unwrap()
            .state_changed()
    );
    assert!(!library.is_enabled(&exact).unwrap());
    for key in [&other_version, &other_agent, &other_project] {
        assert!(library.is_enabled(key).unwrap());
    }

    drop(library);
    let reopened = CanonicalLibrary::open(home.path()).unwrap();
    assert!(!reopened.is_enabled(&exact).unwrap());
    assert_eq!(reopened.enablements().unwrap().len(), 3);
    for key in [&other_version, &other_agent, &other_project] {
        assert!(reopened.is_enabled(key).unwrap());
    }
}

#[test]
fn managed_copy_ownership_is_bound_to_one_canonical_root_before_disable() {
    let home = TestDirectory::new("canonical-library-managed-root");
    let first_root = TestDirectory::new("canonical-library-managed-root-first");
    let second_root = TestDirectory::new("canonical-library-managed-root-second");
    let first_root_id = managed_root_id(&first_root);
    let second_root_id = managed_root_id(&second_root);
    assert_ne!(first_root_id, second_root_id);
    for rendered in [
        format!("{first_root_id:?}"),
        serde_json::to_string(&first_root_id).unwrap(),
    ] {
        assert!(!rendered.contains(&first_root.path().display().to_string()));
    }

    let library = CanonicalLibrary::open(home.path()).unwrap();
    let entry = CanonicalEntryId::parse("root-bound").unwrap();
    let inserted = library.insert(entry.clone(), b"root-bound bytes").unwrap();
    let key = LibraryEnablementKey::new(
        entry,
        inserted.version().clone(),
        OriginAgent::Codex,
        LibraryProjectKey::parse("root-bound-project").unwrap(),
    );
    library.enable(key.clone()).unwrap();
    assert!(
        library
            .record_managed_copy(key.clone(), first_root_id.clone())
            .unwrap()
            .recorded()
    );
    assert_eq!(
        library
            .record_managed_copy(key.clone(), second_root_id.clone())
            .unwrap_err(),
        LibraryError::ManagedCopyRootMismatch
    );
    let mut cleanup_called = false;
    assert_eq!(
        library
            .disable_managed_copy(&key, &second_root_id, false, |_, _| {
                cleanup_called = true;
                ((), false)
            })
            .unwrap_err(),
        LibraryError::ManagedCopyRootMismatch
    );
    assert!(!cleanup_called);
    assert!(library.is_enabled(&key).unwrap());
    assert_eq!(library.managed_copies().unwrap(), vec![key.clone()]);
    assert!(
        library
            .managed_materialization_snapshot(&key, &first_root_id)
            .unwrap()
            .2
    );
    assert_eq!(
        library
            .managed_materialization_snapshot(&key, &second_root_id)
            .unwrap_err(),
        LibraryError::ManagedCopyRootMismatch
    );
}

#[cfg(unix)]
#[test]
fn managed_root_identity_uses_explicit_unix_bytes_for_non_utf8_paths() {
    let root = PathBuf::from(std::ffi::OsString::from_vec(b"/private/root-\xff".to_vec()));
    let identity = managed_root_digest_for_test(&root).unwrap();
    let mut expected = Sha256::new();
    expected.update(b"pam-managed-root-v2-unix-bytes\0");
    expected.update(root.as_os_str().as_bytes());
    assert_eq!(
        identity,
        ContentDigest::from_sha256(expected.finalize().into())
    );
}

#[cfg(windows)]
#[test]
fn managed_root_identity_uses_explicit_windows_utf16le() {
    use std::os::windows::ffi::OsStrExt as _;

    let root = TestDirectory::new("canonical-library-managed-root-windows");
    let root = fs::canonicalize(root.path()).unwrap();
    let identity = LibraryManagedRootId::from_canonical_path(&root).unwrap();
    let mut expected = Sha256::new();
    expected.update(b"pam-managed-root-v2-windows-utf16le\0");
    for unit in root.as_os_str().encode_wide() {
        expected.update(unit.to_le_bytes());
    }
    assert_eq!(
        identity.digest(),
        &ContentDigest::from_sha256(expected.finalize().into())
    );
}

#[test]
fn managed_snapshot_rejects_cross_root_destination_owned_by_an_older_version() {
    let home = TestDirectory::new("canonical-library-managed-version-root");
    let first_root = TestDirectory::new("canonical-library-managed-version-root-first");
    let second_root = TestDirectory::new("canonical-library-managed-version-root-second");
    let first_root_id = managed_root_id(&first_root);
    let second_root_id = managed_root_id(&second_root);
    let library = CanonicalLibrary::open(home.path()).unwrap();
    let entry = CanonicalEntryId::parse("version-root-bound").unwrap();
    let first = library.insert(entry.clone(), b"first version").unwrap();
    let second = library.insert(entry.clone(), b"second version").unwrap();
    let project = LibraryProjectKey::parse("version-root-project").unwrap();
    let first_key = LibraryEnablementKey::new(
        entry.clone(),
        first.version().clone(),
        OriginAgent::Cursor,
        project.clone(),
    );
    let second_key = LibraryEnablementKey::new(
        entry,
        second.version().clone(),
        OriginAgent::Cursor,
        project,
    );
    library.enable(first_key.clone()).unwrap();
    library.enable(second_key.clone()).unwrap();
    library
        .record_managed_copy(first_key, first_root_id.clone())
        .unwrap();

    assert_eq!(
        library
            .managed_materialization_snapshot(&second_key, &second_root_id)
            .unwrap_err(),
        LibraryError::ManagedCopyRootMismatch
    );
    let (_, enabled, owned_at_root) = library
        .managed_materialization_snapshot(&second_key, &first_root_id)
        .unwrap();
    assert!(enabled);
    assert!(!owned_at_root);
}

#[test]
fn managed_no_op_transfer_is_atomic_and_never_claims_after_disable() {
    let home = TestDirectory::new("canonical-library-managed-transfer-atomic");
    let root = TestDirectory::new("canonical-library-managed-transfer-root");
    let root_id = managed_root_id(&root);
    let library = CanonicalLibrary::open(home.path()).unwrap();
    let entry = CanonicalEntryId::parse("transfer-atomic").unwrap();
    let first = library.insert(entry.clone(), b"first").unwrap();
    let second = library.insert(entry.clone(), b"second").unwrap();
    let project = LibraryProjectKey::parse("transfer-atomic-project").unwrap();
    let first_key = LibraryEnablementKey::new(
        entry.clone(),
        first.version().clone(),
        OriginAgent::Codex,
        project.clone(),
    );
    let second_key =
        LibraryEnablementKey::new(entry, second.version().clone(), OriginAgent::Codex, project);
    library.enable(first_key.clone()).unwrap();
    library.enable(second_key.clone()).unwrap();
    library
        .record_managed_copy(first_key.clone(), root_id.clone())
        .unwrap();

    assert_eq!(
        library
            .transfer_managed_no_op_with_publish_failure(second_key.clone(), root_id.clone())
            .unwrap_err(),
        LibraryError::Io(crate::LibraryIoOperation::WriteManifest)
    );
    assert_eq!(
        library.managed_copies().unwrap().as_slice(),
        std::slice::from_ref(&first_key)
    );
    drop(library);
    let library = CanonicalLibrary::open(home.path()).unwrap();
    assert_eq!(
        library.managed_copies().unwrap().as_slice(),
        std::slice::from_ref(&first_key)
    );

    library
        .disable_managed_copy(&second_key, &root_id, false, |_, _| ((), false))
        .unwrap();
    let (enabled, change) = library.transfer_managed_no_op(second_key, root_id).unwrap();
    assert!(!enabled);
    assert!(!change.recorded());
    assert_eq!(
        library.managed_copies().unwrap().as_slice(),
        std::slice::from_ref(&first_key)
    );
}

#[test]
fn store_is_isolated_versioned_content_addressed_and_idempotent() {
    let home = TestDirectory::new("canonical-library");
    let database_bytes = b"unrelated ptrack database bytes\0\xff";
    home.write("ptrack.redb", database_bytes);
    let library = CanonicalLibrary::open(home.path()).unwrap();

    assert_eq!(
        library.root_path(),
        fs::canonicalize(home.path())
            .unwrap()
            .join("pam/skill-library")
    );
    assert_eq!(
        fs::read(home.path().join("ptrack.redb")).unwrap(),
        database_bytes
    );

    let review = CanonicalEntryId::parse("review").unwrap();
    let lf = b"# Review\ncheck facts\n";
    let inserted = library.insert(review.clone(), lf).unwrap();
    assert_eq!(inserted.entry_id(), &review);
    assert_eq!(inserted.disposition(), LibraryInsertDisposition::Inserted);
    assert_eq!(
        fs::read(blob_path(&library, inserted.version())).unwrap(),
        lf
    );
    assert_eq!(library.read(&review, inserted.version()).unwrap(), lf);

    let manifest_after_insert = fs::read(manifest_path(&home)).unwrap();
    let generation_paths_after_insert = manifest_paths(&home);
    let commit_paths_after_insert = commit_paths(&home);
    let repeated = library.insert(review.clone(), lf).unwrap();
    assert_eq!(repeated.version(), inserted.version());
    assert_eq!(
        repeated.disposition(),
        LibraryInsertDisposition::AlreadyPresent
    );
    assert_eq!(
        fs::read(manifest_path(&home)).unwrap(),
        manifest_after_insert
    );
    assert_eq!(manifest_paths(&home), generation_paths_after_insert);
    assert_eq!(commit_paths(&home), commit_paths_after_insert);
    assert!(pending_paths(&home).is_empty());

    let crlf = b"# Review\r\ncheck facts\r\n";
    let second_version = library.insert(review.clone(), crlf).unwrap();
    assert_ne!(second_version.version(), inserted.version());
    assert_eq!(
        library.read(&review, second_version.version()).unwrap(),
        crlf
    );

    let audit = CanonicalEntryId::parse("audit").unwrap();
    let shared = library.insert(audit.clone(), lf).unwrap();
    assert_eq!(shared.version(), inserted.version());
    let entries = library.entries().unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].id(), &audit);
    assert_eq!(
        entries[0].versions(),
        std::slice::from_ref(inserted.version())
    );
    assert_eq!(entries[1].id(), &review);
    assert_eq!(entries[1].versions().len(), 2);
    assert!(
        entries[1]
            .versions()
            .windows(2)
            .all(|pair| pair[0].as_str() < pair[1].as_str())
    );

    assert_eq!(
        fs::read(home.path().join("ptrack.redb")).unwrap(),
        database_bytes
    );
    assert_eq!(
        fs::read_dir(library.root_path().join("blobs/sha256"))
            .unwrap()
            .count(),
        2
    );
    assert_no_temporary_files(library.root_path());
    drop(library);

    let reopened = CanonicalLibrary::open(home.path()).unwrap();
    assert_eq!(reopened.read(&audit, inserted.version()).unwrap(), lf);
    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(manifest_path(&home)).unwrap()).unwrap();
    assert_eq!(manifest["schema_version"], LIBRARY_MANIFEST_SCHEMA_VERSION);
    assert_eq!(manifest["generation"], 3);
}

#[test]
fn adoption_requires_complete_scan_and_exact_retained_source() {
    let home = TestDirectory::new("canonical-library-adoption-inputs");
    let library = CanonicalLibrary::open(home.path()).unwrap();
    let entry_id = CanonicalEntryId::parse("review").unwrap();
    let available = scanned_artifact("review.mdc", b"available");
    let artifact_id = available.id();

    let conflicting = ScanReport::merge([
        ScanReport::from_artifacts([available.clone()]),
        ScanReport::from_artifacts([scanned_artifact("review.mdc", b"changed")]),
    ]);
    assert!(!conflicting.complete());
    assert_eq!(
        library
            .adopt(entry_id.clone(), artifact_id.clone(), &conflicting)
            .unwrap_err(),
        LibraryError::IncompleteScan
    );

    let persisted = ScanReport::from_artifacts([available]);
    assert!(persisted.complete());
    let missing_id = scanned_artifact("missing.mdc", b"missing").id();
    assert_eq!(
        library
            .adopt(entry_id.clone(), missing_id.clone(), &persisted)
            .unwrap_err(),
        LibraryError::ArtifactNotFound(missing_id)
    );
    assert_eq!(
        library
            .adopt(entry_id, artifact_id.clone(), &persisted)
            .unwrap_err(),
        LibraryError::ArtifactSourceUnavailable(artifact_id)
    );
}

#[test]
fn adoption_rejects_retained_bytes_that_do_not_match_scan_metadata() {
    let home = TestDirectory::new("canonical-library-adoption-digest");
    let library = CanonicalLibrary::open(home.path()).unwrap();
    let artifact = scanned_artifact("review.mdc", b"declared bytes");
    let artifact_id = artifact.id();
    let expected = artifact.content_hash().clone();
    let actual = ContentDigest::from_sha256(Sha256::digest(b"different retained bytes").into());
    let scan = report_with_source(artifact, b"different retained bytes");

    assert_eq!(
        library
            .adopt(
                CanonicalEntryId::parse("review").unwrap(),
                artifact_id.clone(),
                &scan,
            )
            .unwrap_err(),
        LibraryError::ArtifactDigestMismatch {
            artifact_id,
            expected,
            actual,
        }
    );
    assert!(library.entries().unwrap().is_empty());
}

#[test]
fn adoption_copies_exact_bytes_without_changing_original_and_versions_changed_source() {
    let home = TestDirectory::new("canonical-library-adoption-home");
    let project = TestDirectory::new("canonical-library-adoption-project");
    let relative = ".cursor/rules/review.mdc";
    let original_path = project.path().join(relative);
    let first_bytes = b"---\ndescription: review changes\n---\nprivate first source\n";
    project.write(relative, first_bytes);
    let original_canonical_path = fs::canonicalize(&original_path).unwrap();
    let library = CanonicalLibrary::open(home.path()).unwrap();
    let entry_id = CanonicalEntryId::parse("review").unwrap();
    let first_scan = scan_cursor(
        CursorScanRoots::new(project.path(), project.path(), None),
        ScanLimits::default(),
    )
    .into_scan_report();
    assert!(first_scan.complete(), "{:?}", first_scan.diagnostics());
    let artifact_id = first_scan.artifacts()[0].id();

    let first = library
        .adopt(entry_id.clone(), artifact_id.clone(), &first_scan)
        .unwrap();
    assert_eq!(first.disposition(), LibraryInsertDisposition::Inserted);
    assert_eq!(first.entry_id(), &entry_id);
    assert_eq!(first.artifact_id(), &artifact_id);
    assert_eq!(first.artifact().logical_path(), relative);
    assert_eq!(
        library.read(&entry_id, first.version()).unwrap(),
        first_bytes
    );
    assert_eq!(fs::read(&original_path).unwrap(), first_bytes);
    assert_eq!(
        fs::canonicalize(&original_path).unwrap(),
        original_canonical_path
    );

    let repeated = library
        .adopt(entry_id.clone(), artifact_id.clone(), &first_scan)
        .unwrap();
    assert_eq!(
        repeated.disposition(),
        LibraryInsertDisposition::AlreadyPresent
    );
    assert_eq!(repeated.version(), first.version());

    let second_bytes = b"---\ndescription: review changes\n---\nprivate second source\n";
    project.write(relative, second_bytes);
    let second_scan = scan_cursor(
        CursorScanRoots::new(project.path(), project.path(), None),
        ScanLimits::default(),
    )
    .into_scan_report();
    let second_artifact_id = second_scan.artifacts()[0].id();
    assert_eq!(second_artifact_id, artifact_id);
    let second = library
        .adopt(entry_id.clone(), second_artifact_id, &second_scan)
        .unwrap();

    assert_eq!(second.disposition(), LibraryInsertDisposition::Inserted);
    assert_ne!(second.version(), first.version());
    assert_eq!(
        library.read(&entry_id, second.version()).unwrap(),
        second_bytes
    );
    assert_eq!(library.entries().unwrap()[0].versions().len(), 2);
    assert_eq!(fs::read(&original_path).unwrap(), second_bytes);
    assert_eq!(
        fs::canonicalize(&original_path).unwrap(),
        original_canonical_path
    );
}

#[test]
fn adoption_scan_and_outcome_serde_and_debug_never_expose_source_bytes() {
    let private_source = b"private adoption source: do not serialize or debug";
    let artifact = scanned_artifact("private-review.mdc", private_source);
    let artifact_id = artifact.id();
    let scan = report_with_source(artifact, private_source);
    let home = TestDirectory::new("canonical-library-adoption-privacy");
    let library = CanonicalLibrary::open(home.path()).unwrap();
    let outcome = library
        .adopt(
            CanonicalEntryId::parse("private-review").unwrap(),
            artifact_id,
            &scan,
        )
        .unwrap();

    for rendered in [
        serde_json::to_string(&scan).unwrap(),
        format!("{scan:?}"),
        format!("{outcome:?}"),
    ] {
        assert!(!rendered.contains("private adoption source"));
    }
    assert!(format!("{scan:?}").contains("<redacted:1 sources>"));
}

#[test]
fn two_instances_serialize_concurrent_inserts_without_lost_updates() {
    let home = TestDirectory::new("canonical-library-concurrent");
    let first = CanonicalLibrary::open(home.path()).unwrap();
    let second = CanonicalLibrary::open(home.path()).unwrap();
    let barrier = Arc::new(Barrier::new(3));

    thread::scope(|scope| {
        let first_barrier = Arc::clone(&barrier);
        let first_insert = scope.spawn(move || {
            first_barrier.wait();
            first.insert(CanonicalEntryId::parse("alpha").unwrap(), b"alpha")
        });
        let second_barrier = Arc::clone(&barrier);
        let second_insert = scope.spawn(move || {
            second_barrier.wait();
            second.insert(CanonicalEntryId::parse("beta").unwrap(), b"beta")
        });
        barrier.wait();
        assert_eq!(
            first_insert.join().unwrap().unwrap().disposition(),
            LibraryInsertDisposition::Inserted
        );
        assert_eq!(
            second_insert.join().unwrap().unwrap().disposition(),
            LibraryInsertDisposition::Inserted
        );
    });

    let reopened = CanonicalLibrary::open(home.path()).unwrap();
    let entries = reopened.entries().unwrap();
    assert_eq!(
        entries
            .iter()
            .map(|entry| entry.id().as_str())
            .collect::<Vec<_>>(),
        ["alpha", "beta"]
    );
    assert_eq!(manifest_paths(&home).len(), 3);
    assert_eq!(commit_paths(&home).len(), 3);
    assert!(pending_paths(&home).is_empty());
}

#[test]
fn manifest_generations_are_immutable_monotonic_and_reopenable() {
    let home = TestDirectory::new("canonical-library-generations");
    let initial = CanonicalLibrary::open(home.path()).unwrap();
    drop(initial);
    let initial_path = manifest_path(&home);
    let initial_bytes = fs::read(&initial_path).unwrap();
    let entry_id = CanonicalEntryId::parse("review").unwrap();
    let mut versions = Vec::new();

    for index in 0..3 {
        let library = CanonicalLibrary::open(home.path()).unwrap();
        let bytes = format!("version {index}");
        versions.push(library.insert(entry_id.clone(), bytes.as_bytes()).unwrap());
        drop(library);
        assert_eq!(fs::read(&initial_path).unwrap(), initial_bytes);
        assert_eq!(manifest_paths(&home).len(), index + 2);
    }

    assert_eq!(
        manifest_paths(&home)
            .iter()
            .map(|path| path.file_name().unwrap().to_string_lossy().into_owned())
            .collect::<Vec<_>>(),
        [
            "00000000000000000000.json",
            "00000000000000000001.json",
            "00000000000000000002.json",
            "00000000000000000003.json",
        ]
    );
    assert_eq!(
        commit_paths(&home)
            .iter()
            .map(|path| path.file_name().unwrap().to_string_lossy().into_owned())
            .collect::<Vec<_>>(),
        [
            "00000000000000000000.json",
            "00000000000000000001.json",
            "00000000000000000002.json",
            "00000000000000000003.json",
        ]
    );
    let reopened = CanonicalLibrary::open(home.path()).unwrap();
    for (index, version) in versions.iter().enumerate() {
        assert_eq!(
            reopened.read(&entry_id, version.version()).unwrap(),
            format!("version {index}").as_bytes()
        );
    }
}

#[test]
fn deleted_manifest_generations_and_commit_markers_are_corruption() {
    let newest_manifest = populated_generation_home("canonical-library-deleted-newest-manifest");
    fs::remove_file(manifest_paths(&newest_manifest).pop().unwrap()).unwrap();
    assert_eq!(
        CanonicalLibrary::open(newest_manifest.path()).unwrap_err(),
        LibraryError::CorruptManifest
    );

    let newest_marker = populated_generation_home("canonical-library-deleted-newest-marker");
    fs::remove_file(commit_paths(&newest_marker).pop().unwrap()).unwrap();
    assert_eq!(
        CanonicalLibrary::open(newest_marker.path()).unwrap_err(),
        LibraryError::CorruptManifest
    );

    let interior = populated_generation_home("canonical-library-deleted-interior-generation");
    let manifests = manifest_paths(&interior);
    let commits = commit_paths(&interior);
    fs::remove_file(&manifests[1]).unwrap();
    fs::remove_file(&commits[1]).unwrap();
    assert_eq!(
        CanonicalLibrary::open(interior.path()).unwrap_err(),
        LibraryError::CorruptManifest
    );
}

#[test]
fn pending_evidence_recovers_an_incomplete_manifest_publication() {
    let home = TestDirectory::new("canonical-library-pending-recovery");
    let library = CanonicalLibrary::open(home.path()).unwrap();
    let entry_id = CanonicalEntryId::parse("review").unwrap();
    let inserted = library.insert(entry_id.clone(), b"committed").unwrap();
    drop(library);

    let pending_name = "00000000000000000002.json";
    home.write(
        &format!("pam/skill-library/pending/{pending_name}"),
        b"{\n  \"schema_version\": 1,\n  \"generation\": 2\n}\n",
    );
    home.write(
        &format!("pam/skill-library/manifests/{pending_name}"),
        b"partial manifest publication",
    );

    let reopened = CanonicalLibrary::open(home.path()).unwrap();
    assert_eq!(
        reopened.read(&entry_id, inserted.version()).unwrap(),
        b"committed"
    );
    assert_eq!(manifest_paths(&home).len(), 2);
    assert_eq!(commit_paths(&home).len(), 2);
    assert!(pending_paths(&home).is_empty());
    assert!(
        !home
            .path()
            .join("pam/skill-library/manifests")
            .join(pending_name)
            .exists()
    );
}

#[test]
fn committed_manifest_success_survives_pending_cleanup_fault() {
    let home = TestDirectory::new("canonical-library-post-commit-cleanup-fault");
    let library = CanonicalLibrary::open(home.path()).unwrap();
    let entry_id = CanonicalEntryId::parse("committed").unwrap();
    let inserted = library
        .insert_with_post_commit_cleanup_fault(entry_id.clone(), b"accepted bytes")
        .unwrap();
    assert_eq!(pending_paths(&home).len(), 1);
    assert_eq!(manifest_paths(&home).len(), commit_paths(&home).len());
    drop(library);

    let reopened = CanonicalLibrary::open(home.path()).unwrap();
    assert_eq!(
        reopened.read(&entry_id, inserted.version()).unwrap(),
        b"accepted bytes"
    );
    assert!(pending_paths(&home).is_empty());
}

#[test]
fn reads_report_missing_and_corrupt_content_addressed_bytes() {
    let home = TestDirectory::new("canonical-library-corruption");
    let library = CanonicalLibrary::open(home.path()).unwrap();
    let entry_id = CanonicalEntryId::parse("review").unwrap();
    let outcome = library.insert(entry_id.clone(), b"trusted bytes").unwrap();
    let blob = blob_path(&library, outcome.version());

    fs::write(&blob, b"changed bytes").unwrap();
    let expected = outcome.version().clone();
    let error = library.read(&entry_id, outcome.version()).unwrap_err();
    assert!(
        matches!(error, LibraryError::CorruptBlob { expected: found, actual } if found == expected && actual != expected)
    );

    fs::remove_file(&blob).unwrap();
    assert_eq!(
        library.read(&entry_id, outcome.version()).unwrap_err(),
        LibraryError::MissingBlob(outcome.version().clone())
    );
}

#[test]
fn strict_manifest_reports_versions_shape_and_unknown_fields() {
    let unsupported = TestDirectory::new("canonical-library-version");
    let library = CanonicalLibrary::open(unsupported.path()).unwrap();
    drop(library);
    fs::write(
        manifest_path(&unsupported),
        br#"{"schema_version":5,"generation":0,"entries":[],"enablements":[],"managed_copies":[],"installations":[]}"#,
    )
    .unwrap();
    assert_eq!(
        CanonicalLibrary::open(unsupported.path()).unwrap_err(),
        LibraryError::UnsupportedManifestVersion(5)
    );

    let unknown = TestDirectory::new("canonical-library-unknown-field");
    let library = CanonicalLibrary::open(unknown.path()).unwrap();
    drop(library);
    fs::write(
        manifest_path(&unknown),
        br#"{"schema_version":2,"generation":0,"entries":[],"enablements":[],"managed_copies":[],"extra":true}"#,
    )
    .unwrap();
    assert_eq!(
        CanonicalLibrary::open(unknown.path()).unwrap_err(),
        LibraryError::MalformedManifest
    );

    let corrupt = TestDirectory::new("canonical-library-corrupt-manifest");
    let library = CanonicalLibrary::open(corrupt.path()).unwrap();
    library
        .insert(CanonicalEntryId::parse("review").unwrap(), b"bytes")
        .unwrap();
    drop(library);
    fs::write(
        manifest_path(&corrupt),
        br#"{"schema_version":2,"generation":1,"entries":[{"id":"review","versions":[]}],"enablements":[],"managed_copies":[]}"#,
    )
    .unwrap();
    assert_eq!(
        CanonicalLibrary::open(corrupt.path()).unwrap_err(),
        LibraryError::CorruptManifest
    );
}

#[test]
fn valid_v1_manifest_migrates_once_to_v4_without_losing_entries() {
    let home = TestDirectory::new("canonical-library-v1-migration");
    let library = CanonicalLibrary::open(home.path()).unwrap();
    let entry = CanonicalEntryId::parse("review").unwrap();
    let inserted = library.insert(entry.clone(), b"preserved bytes").unwrap();
    drop(library);
    let mut historical: serde_json::Value =
        serde_json::from_slice(&fs::read(manifest_path(&home)).unwrap()).unwrap();
    historical["schema_version"] = 1.into();
    historical
        .as_object_mut()
        .unwrap()
        .remove("base_generation");
    historical.as_object_mut().unwrap().remove("enablements");
    historical.as_object_mut().unwrap().remove("managed_copies");
    historical.as_object_mut().unwrap().remove("installations");
    let mut historical = serde_json::to_vec_pretty(&historical).unwrap();
    historical.push(b'\n');
    rewrite_latest_manifest(&home, &historical);

    let reopened = CanonicalLibrary::open(home.path()).unwrap();

    assert_eq!(
        reopened.read(&entry, inserted.version()).unwrap(),
        b"preserved bytes"
    );
    assert!(reopened.enablements().unwrap().is_empty());
    assert!(reopened.managed_copies().unwrap().is_empty());
    assert_eq!(manifest_paths(&home).len(), 1);
    assert!(commit_paths(&home).is_empty());
    assert_eq!(epoch_paths(&home).len(), 1);
    let migrated: serde_json::Value =
        serde_json::from_slice(&fs::read(manifest_path(&home)).unwrap()).unwrap();
    assert_eq!(migrated["schema_version"], 4);
    assert_eq!(migrated["generation"], 2);
    drop(reopened);
    CanonicalLibrary::open(home.path()).unwrap();
    assert_eq!(manifest_paths(&home).len(), 1);
    assert_eq!(epoch_paths(&home).len(), 1);
}

#[test]
fn valid_v2_manifest_migrates_once_to_v4_preserving_enablement_but_dropping_unbound_ownership() {
    let home = TestDirectory::new("canonical-library-v2-migration");
    let library = CanonicalLibrary::open(home.path()).unwrap();
    let entry = CanonicalEntryId::parse("review-v2").unwrap();
    let inserted = library
        .insert(entry.clone(), b"preserved v2 bytes")
        .unwrap();
    let key = LibraryEnablementKey::new(
        entry.clone(),
        inserted.version().clone(),
        OriginAgent::Codex,
        LibraryProjectKey::parse("v2-project").unwrap(),
    );
    library.enable(key.clone()).unwrap();
    let root = TestDirectory::new("canonical-library-v2-root");
    let root_id = managed_root_id(&root);
    library.record_managed_copy(key.clone(), root_id).unwrap();
    drop(library);
    let mut historical: serde_json::Value =
        serde_json::from_slice(&fs::read(manifest_path(&home)).unwrap()).unwrap();
    historical["schema_version"] = 2.into();
    historical
        .as_object_mut()
        .unwrap()
        .remove("base_generation");
    historical.as_object_mut().unwrap().remove("installations");
    historical["managed_copies"] = serde_json::json!([key]);
    let mut historical = serde_json::to_vec_pretty(&historical).unwrap();
    historical.push(b'\n');
    rewrite_latest_manifest(&home, &historical);

    let reopened = CanonicalLibrary::open(home.path()).unwrap();
    assert!(reopened.is_enabled(&key).unwrap());
    assert!(reopened.managed_copies().unwrap().is_empty());
    assert_eq!(
        reopened
            .installation_provenance(&entry, inserted.version())
            .unwrap(),
        None
    );
    let migrated: serde_json::Value =
        serde_json::from_slice(&fs::read(manifest_path(&home)).unwrap()).unwrap();
    assert_eq!(migrated["schema_version"], 4);
    assert_eq!(migrated["installations"], serde_json::json!([]));
}

#[test]
fn valid_v3_manifest_migrates_raw_git_provenance_to_non_sensitive_digests() {
    let home = TestDirectory::new("canonical-library-v3-provenance-migration");
    let library = CanonicalLibrary::open(home.path()).unwrap();
    let entry = CanonicalEntryId::parse("review-v3").unwrap();
    let inserted = library
        .install_bytes(
            entry.clone(),
            b"preserved v3 bytes",
            ArtifactInstallProvenance::Local,
        )
        .unwrap();
    let key = LibraryEnablementKey::new(
        entry.clone(),
        inserted.version().clone(),
        OriginAgent::Cursor,
        LibraryProjectKey::parse("v3-project").unwrap(),
    );
    library.enable(key.clone()).unwrap();
    let root = TestDirectory::new("canonical-library-v3-root");
    library
        .record_managed_copy(key.clone(), managed_root_id(&root))
        .unwrap();
    drop(library);
    let private_url = "https://example.invalid/private/repository.git";
    let private_path = "private/rules/review.md";
    let commit = "a".repeat(40);
    let mut historical: serde_json::Value =
        serde_json::from_slice(&fs::read(manifest_path(&home)).unwrap()).unwrap();
    historical["schema_version"] = 3.into();
    historical
        .as_object_mut()
        .unwrap()
        .remove("base_generation");
    historical["managed_copies"] = serde_json::json!([key]);
    historical["installations"][0]["provenance"] = serde_json::json!({
        "kind": "git",
        "url": private_url,
        "commit": commit,
        "artifact_path": private_path,
    });
    let mut historical = serde_json::to_vec_pretty(&historical).unwrap();
    historical.push(b'\n');
    rewrite_latest_manifest(&home, &historical);

    let reopened = CanonicalLibrary::open(home.path()).unwrap();
    assert!(reopened.is_enabled(&key).unwrap());
    assert!(reopened.managed_copies().unwrap().is_empty());
    let provenance = reopened
        .installation_provenance(&entry, inserted.version())
        .unwrap()
        .unwrap();
    let ArtifactInstallProvenance::Git(git) = provenance else {
        panic!("expected migrated Git provenance");
    };
    assert_eq!(git.commit(), "a".repeat(40));
    assert_ne!(git.repository_digest(), git.artifact_path_digest());
    let migrated = fs::read(manifest_path(&home)).unwrap();
    assert!(
        !migrated
            .windows(private_url.len())
            .any(|bytes| bytes == private_url.as_bytes())
    );
    assert!(
        !migrated
            .windows(private_path.len())
            .any(|bytes| bytes == private_path.as_bytes())
    );
    let migrated: serde_json::Value = serde_json::from_slice(&migrated).unwrap();
    assert_eq!(migrated["schema_version"], 4);
    assert_eq!(manifest_paths(&home).len(), 1);
    assert!(commit_paths(&home).is_empty());
    assert_eq!(epoch_paths(&home).len(), 1);
    for path in manifest_paths(&home) {
        let bytes = fs::read(path).unwrap();
        assert!(
            !bytes
                .windows(private_url.len())
                .any(|window| window == private_url.as_bytes())
        );
        assert!(
            !bytes
                .windows(private_path.len())
                .any(|window| window == private_path.as_bytes())
        );
    }
}

#[test]
fn migrated_epoch_marker_deletion_is_corruption_not_rollback() {
    let home = TestDirectory::new("canonical-library-migrated-epoch-deletion");
    let library = CanonicalLibrary::open(home.path()).unwrap();
    library
        .insert(CanonicalEntryId::parse("epoch").unwrap(), b"epoch bytes")
        .unwrap();
    drop(library);
    let mut historical: serde_json::Value =
        serde_json::from_slice(&fs::read(manifest_path(&home)).unwrap()).unwrap();
    historical["schema_version"] = 2.into();
    historical
        .as_object_mut()
        .unwrap()
        .remove("base_generation");
    historical.as_object_mut().unwrap().remove("installations");
    historical["managed_copies"] = serde_json::json!([]);
    let mut historical = serde_json::to_vec_pretty(&historical).unwrap();
    historical.push(b'\n');
    rewrite_latest_manifest(&home, &historical);

    drop(CanonicalLibrary::open(home.path()).unwrap());
    fs::remove_file(epoch_paths(&home).pop().unwrap()).unwrap();
    assert_eq!(
        CanonicalLibrary::open(home.path()).unwrap_err(),
        LibraryError::CorruptManifest
    );
}

#[test]
fn metadata_snapshot_is_one_committed_generation_with_all_state() {
    let home = TestDirectory::new("canonical-library-snapshot");
    let library = CanonicalLibrary::open(home.path()).unwrap();
    let entry = CanonicalEntryId::parse("snapshot").unwrap();
    let installed = library
        .install_bytes(
            entry.clone(),
            b"snapshot bytes",
            ArtifactInstallProvenance::Local,
        )
        .unwrap();
    let key = LibraryEnablementKey::new(
        entry.clone(),
        installed.version().clone(),
        OriginAgent::Codex,
        LibraryProjectKey::parse("snapshot-project").unwrap(),
    );
    library.enable(key.clone()).unwrap();
    let root = TestDirectory::new("canonical-library-snapshot-root");
    let root_id = managed_root_id(&root);
    let other_root = TestDirectory::new("canonical-library-snapshot-other-root");
    let other_root_id = managed_root_id(&other_root);
    library
        .record_managed_copy(key.clone(), root_id.clone())
        .unwrap();

    let snapshot = library.snapshot().unwrap();
    assert_eq!(snapshot.entries().len(), 1);
    assert_eq!(snapshot.installations().len(), 1);
    assert_eq!(snapshot.installations()[0].entry_id(), &entry);
    assert_eq!(snapshot.installations()[0].version(), installed.version());
    assert_eq!(
        snapshot.installations()[0].provenance(),
        &ArtifactInstallProvenance::Local
    );
    assert_eq!(snapshot.enablements(), std::slice::from_ref(&key));
    assert_eq!(snapshot.managed_copies(), std::slice::from_ref(&key));
    assert!(snapshot.is_managed_at(&key, &root_id));
    assert!(!snapshot.is_managed_at(&key, &other_root_id));
    let generation = snapshot.generation();

    library
        .insert(CanonicalEntryId::parse("later").unwrap(), b"later")
        .unwrap();
    assert!(library.snapshot().unwrap().generation() > generation);
    assert_eq!(snapshot.entries().len(), 1);
}

#[test]
fn v1_dispatch_rejects_unknown_and_malformed_historical_shapes() {
    for (label, bytes) in [
        (
            "canonical-library-v1-unknown",
            br#"{"schema_version":1,"generation":0,"entries":[],"unknown":true}"#.as_slice(),
        ),
        (
            "canonical-library-v1-malformed",
            br#"{"schema_version":1,"generation":0}"#.as_slice(),
        ),
    ] {
        let home = TestDirectory::new(label);
        drop(CanonicalLibrary::open(home.path()).unwrap());
        rewrite_latest_manifest(&home, bytes);
        assert_eq!(
            CanonicalLibrary::open(home.path()).unwrap_err(),
            LibraryError::MalformedManifest
        );
    }
}

#[test]
fn reads_and_inputs_are_bounded_and_not_found_errors_are_typed() {
    let home = TestDirectory::new("canonical-library-bounds");
    let library = CanonicalLibrary::open(home.path()).unwrap();
    let entry_id = CanonicalEntryId::parse("review").unwrap();
    assert_eq!(
        library
            .insert(entry_id.clone(), &vec![0; MAX_LIBRARY_ARTIFACT_BYTES + 1])
            .unwrap_err(),
        LibraryError::ArtifactTooLarge
    );
    let missing = ContentDigest::from_sha256([7; 32]);
    assert_eq!(
        library.read(&entry_id, &missing).unwrap_err(),
        LibraryError::EntryNotFound(entry_id.clone())
    );
    let inserted = library.insert(entry_id.clone(), b"bytes").unwrap();
    assert_eq!(
        library.read(&entry_id, &missing).unwrap_err(),
        LibraryError::VersionNotFound {
            entry_id,
            version: missing,
        }
    );
    assert_ne!(inserted.version(), &ContentDigest::from_sha256([7; 32]));
    drop(library);

    fs::write(
        manifest_path(&home),
        vec![b' '; MAX_LIBRARY_MANIFEST_BYTES + 1],
    )
    .unwrap();
    assert_eq!(
        CanonicalLibrary::open(home.path()).unwrap_err(),
        LibraryError::ManifestTooLarge
    );
}

#[cfg(unix)]
#[test]
fn library_rejects_symlink_homes_manifests_and_blobs() {
    let home_parent = TestDirectory::new("canonical-library-home-link");
    let real_home = home_parent.path().join("real");
    let linked_home = home_parent.path().join("linked");
    fs::create_dir(&real_home).unwrap();
    symlink(&real_home, &linked_home).unwrap();
    assert_eq!(
        CanonicalLibrary::open(&linked_home).unwrap_err(),
        LibraryError::InvalidHome
    );

    let manifest_home = TestDirectory::new("canonical-library-manifest-link");
    let library = CanonicalLibrary::open(manifest_home.path()).unwrap();
    drop(library);
    let manifest = manifest_path(&manifest_home);
    let replacement = manifest_home.path().join("replacement.json");
    fs::write(&replacement, br#"{"schema_version":1,"entries":[]}"#).unwrap();
    fs::remove_file(&manifest).unwrap();
    symlink(&replacement, &manifest).unwrap();
    assert_eq!(
        CanonicalLibrary::open(manifest_home.path()).unwrap_err(),
        LibraryError::UnsafePath
    );

    let blob_home = TestDirectory::new("canonical-library-blob-link");
    let library = CanonicalLibrary::open(blob_home.path()).unwrap();
    let entry_id = CanonicalEntryId::parse("review").unwrap();
    let inserted = library.insert(entry_id.clone(), b"bytes").unwrap();
    let blob = blob_path(&library, inserted.version());
    let replacement = blob_home.path().join("replacement.bin");
    fs::write(&replacement, b"bytes").unwrap();
    fs::remove_file(&blob).unwrap();
    symlink(&replacement, &blob).unwrap();
    assert_eq!(
        library.read(&entry_id, inserted.version()).unwrap_err(),
        LibraryError::UnsafePath
    );
}

#[cfg(unix)]
#[test]
fn library_creates_private_directories_and_files() {
    let home = TestDirectory::new("canonical-library-permissions");
    let library = CanonicalLibrary::open(home.path()).unwrap();
    let inserted = library
        .insert(CanonicalEntryId::parse("review").unwrap(), b"bytes")
        .unwrap();

    assert_eq!(
        fs::metadata(library.root_path()).unwrap().mode() & 0o777,
        0o700
    );
    assert_eq!(
        fs::metadata(manifest_path(&home)).unwrap().mode() & 0o777,
        0o600
    );
    assert_eq!(
        fs::metadata(blob_path(&library, inserted.version()))
            .unwrap()
            .mode()
            & 0o777,
        0o600
    );
}
