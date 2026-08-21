use std::{fs, path::PathBuf};

use pam_core::{ContentDigest, ProjectId};
use pam_skills::{
    CanonicalEntryId, CanonicalLibrary, ClaudeScanRoots, LibraryEnablementKey,
    LibraryManagedRootId, LibraryProjectKey, OriginAgent, ScanLimits,
    apply_managed_materialization, plan_managed_materialization, scan_claude_code,
};
use serde_json::json;
use uuid::Uuid;

use super::{
    desktop::{
        DesktopErrorKind, GenerationId, OperationId, ProjectHandle, active_core_for_test,
        manage_skill_library_without_io_for_test, switch_authority_for_test,
    },
    skill_library::{
        SKILL_LIBRARY_DTO_SCHEMA_VERSION, SkillLibraryAction, SkillLibraryAgentDto,
        SkillLibraryDataDto, SkillLibraryEnvironment, SkillLibraryMaterializationActionDto,
        SkillLibraryRequest, execute_skill_library, project_key, resolve_library_roots_for_test,
    },
};

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new(name: &str) -> Self {
        let path = std::env::temp_dir().join(format!("pam-gui-library-{name}-{}", Uuid::new_v4()));
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

fn digest() -> ContentDigest {
    ContentDigest::from_sha256([7; 32])
}

fn load_request(
    project: ProjectHandle,
    generation: GenerationId,
    operation: OperationId,
) -> SkillLibraryRequest {
    SkillLibraryRequest::Load {
        project_handle: project,
        generation,
        operation_id: operation,
    }
}

fn environment(
    directory: &TestDirectory,
) -> (SkillLibraryEnvironment, LibraryProjectKey, PathBuf, PathBuf) {
    let ptrack_home = directory.path().join("ptrack-home");
    let project_root = directory.path().join("project");
    let user_home = directory.path().join("home");
    for root in [
        &ptrack_home,
        &project_root.join(".claude"),
        &project_root.join(".cursor"),
        &user_home.join(".codex"),
    ] {
        fs::create_dir_all(root).unwrap();
    }
    let project = LibraryProjectKey::parse("project-test").unwrap();
    (
        SkillLibraryEnvironment::for_test(ptrack_home.clone(), &project_root, &user_home),
        project,
        ptrack_home,
        project_root,
    )
}

#[test]
fn action_requests_and_results_are_strict_bounded_and_versioned() {
    let project = ProjectHandle::new();
    let generation = GenerationId::new();
    let operation = OperationId::new();
    let valid = json!({
        "action": "enable",
        "projectHandle": project.as_str(),
        "generation": generation.as_str(),
        "operationId": operation.as_str(),
        "entryId": "review",
        "version": digest().as_str(),
        "agent": "claude"
    });
    assert!(serde_json::from_value::<SkillLibraryRequest>(valid.clone()).is_ok());

    let mut noncanonical_fence = valid.clone();
    noncanonical_fence["operationId"] = json!(operation.as_str().to_uppercase());
    assert!(serde_json::from_value::<SkillLibraryRequest>(noncanonical_fence).is_err());

    let mut unknown = valid.clone();
    unknown["root"] = json!("/tmp/untrusted");
    assert!(serde_json::from_value::<SkillLibraryRequest>(unknown).is_err());
    let mut bad_entry = valid.clone();
    bad_entry["entryId"] = json!("../escape");
    assert!(serde_json::from_value::<SkillLibraryRequest>(bad_entry).is_err());
    let mut bad_digest = valid;
    bad_digest["version"] = json!("sha256:UPPERCASE");
    assert!(serde_json::from_value::<SkillLibraryRequest>(bad_digest).is_err());

    let relative_local = json!({
        "action": "install_local",
        "projectHandle": project.as_str(),
        "generation": generation.as_str(),
        "operationId": operation.as_str(),
        "entryId": "review",
        "sourcePath": "relative.md"
    });
    assert!(serde_json::from_value::<SkillLibraryRequest>(relative_local).is_err());
    for invalid_path in [
        format!("/{}", "a".repeat(4_096)),
        "/tmp/private\nsource.md".to_owned(),
    ] {
        let local = json!({
            "action": "install_local",
            "projectHandle": project.as_str(),
            "generation": generation.as_str(),
            "operationId": operation.as_str(),
            "entryId": "review",
            "sourcePath": invalid_path
        });
        assert!(serde_json::from_value::<SkillLibraryRequest>(local).is_err());
    }
    let credential_url = json!({
        "action": "install_git",
        "projectHandle": project.as_str(),
        "generation": generation.as_str(),
        "operationId": operation.as_str(),
        "entryId": "review",
        "url": "https://user:secret@example.com/repository",
        "artifactPath": "skill.md"
    });
    let error = serde_json::from_value::<SkillLibraryRequest>(credential_url)
        .err()
        .unwrap()
        .to_string();
    assert!(!error.contains("secret"));

    let result = json!({
        "action": "load",
        "schemaVersion": SKILL_LIBRARY_DTO_SCHEMA_VERSION,
        "entries": [],
        "unexpected": true
    });
    assert!(serde_json::from_value::<SkillLibraryDataDto>(result).is_err());
}

#[test]
fn materialization_preview_is_zero_write_and_returns_no_ambient_paths() {
    let directory = TestDirectory::new("preview");
    let (environment, project, ptrack_home, project_root) = environment(&directory);
    let library = CanonicalLibrary::open(&ptrack_home).unwrap();
    let entry = CanonicalEntryId::parse("review").unwrap();
    let inserted = library
        .insert(entry.clone(), "line one\r\nCafé\n".as_bytes())
        .unwrap();
    let key = LibraryEnablementKey::new(
        entry.clone(),
        inserted.version().clone(),
        OriginAgent::ClaudeCode,
        project.clone(),
    );
    library.enable(key).unwrap();
    drop(library);
    let destination = project_root.join(".claude/skills/review/SKILL.md");

    let preview = execute_skill_library(
        &environment,
        project,
        SkillLibraryAction::PreviewMaterialization {
            entry_id: entry,
            version: inserted.version().clone(),
            agent: SkillLibraryAgentDto::Claude,
        },
    )
    .unwrap();

    assert!(!destination.exists());
    let json = serde_json::to_string(&preview).unwrap();
    assert!(!json.contains(directory.path().to_string_lossy().as_ref()));
    assert!(!json.contains("line one"));
    assert!(matches!(
        preview,
        SkillLibraryDataDto::PreviewMaterialization { items, .. }
            if items.len() == 1 && !items[0].backup_planned
    ));
}

#[test]
fn adoption_response_preserves_the_exact_scanned_artifact_identity() {
    let directory = TestDirectory::new("adoption-identity");
    let (environment, project, _, project_root) = environment(&directory);
    let source = project_root.join(".claude/skills/review/SKILL.md");
    fs::create_dir_all(source.parent().unwrap()).unwrap();
    fs::write(&source, b"exact adoption source\r\n").unwrap();
    let scan = scan_claude_code(
        ClaudeScanRoots::new(None, Some(&project_root), &[]),
        ScanLimits::default(),
    );
    let artifact_id = scan.artifacts()[0].id();

    let adopted = execute_skill_library(
        &environment,
        project,
        SkillLibraryAction::Adopt {
            entry_id: CanonicalEntryId::parse("review").unwrap(),
            artifact_id: artifact_id.clone(),
        },
    )
    .unwrap();

    assert!(matches!(
        adopted,
        SkillLibraryDataDto::Adopt {
            artifact_id: returned,
            ..
        } if returned == artifact_id.as_str()
    ));
}

#[test]
fn local_install_and_load_dtos_never_expose_source_path_or_body() {
    let directory = TestDirectory::new("privacy");
    let (environment, project, ptrack_home, _) = environment(&directory);
    let source = directory.path().join("private-source-path.md");
    fs::write(&source, b"PRIVATE_BODY_TOKEN\r\n").unwrap();

    let installed = execute_skill_library(
        &environment,
        project.clone(),
        SkillLibraryAction::InstallLocal {
            entry_id: CanonicalEntryId::parse("private-entry").unwrap(),
            source_path: source,
        },
    )
    .unwrap();
    let loaded = execute_skill_library(&environment, project, SkillLibraryAction::Load).unwrap();
    let serialized = format!(
        "{} {} {installed:?} {loaded:?}",
        serde_json::to_string(&installed).unwrap(),
        serde_json::to_string(&loaded).unwrap()
    );

    assert!(!serialized.contains("private-source-path"));
    assert!(!serialized.contains("PRIVATE_BODY_TOKEN"));
    assert!(!serialized.contains(ptrack_home.to_string_lossy().as_ref()));
    assert!(!serialized.contains("sourcePath"));
    assert!(!serialized.contains("url"));
}

#[tokio::test]
async fn library_actions_consume_operations_and_fence_stale_projects_before_and_after_work() {
    let project = ProjectHandle::new();
    let generation = GenerationId::new();
    let operation = OperationId::new();
    let core = active_core_for_test(&project, generation.clone());
    let request = load_request(project.clone(), generation.clone(), operation.clone());

    let first = manage_skill_library_without_io_for_test(&core, request.clone(), None)
        .await
        .unwrap();
    assert_eq!(first.fence.operation_id, operation);
    let duplicate = manage_skill_library_without_io_for_test(&core, request, None)
        .await
        .unwrap_err();
    assert_eq!(duplicate.kind, DesktopErrorKind::Conflict);

    let stale = load_request(project.clone(), GenerationId::new(), OperationId::new());
    let stale_error = manage_skill_library_without_io_for_test(&core, stale, None)
        .await
        .unwrap_err();
    assert_eq!(stale_error.kind, DesktopErrorKind::Stale);

    let switched_project = ProjectHandle::new();
    let switched_generation = GenerationId::new();
    let after = load_request(project.clone(), generation, OperationId::new());
    let after_error = manage_skill_library_without_io_for_test(
        &core,
        after,
        Some((switched_project.clone(), switched_generation.clone())),
    )
    .await
    .unwrap_err();
    assert_eq!(after_error.kind, DesktopErrorKind::Stale);

    switch_authority_for_test(&core, switched_project, switched_generation.clone()).await;
    let old_project = load_request(project, switched_generation, OperationId::new());
    let old_project_error = manage_skill_library_without_io_for_test(&core, old_project, None)
        .await
        .unwrap_err();
    assert_eq!(old_project_error.kind, DesktopErrorKind::Stale);
}

#[test]
fn stable_project_identity_matches_cli_ownership_across_restarts() {
    let project_id = "88D408EC-796B-4F56-B34C-F2A8D25F9128";
    let first_process = ProjectId::new(project_id);
    let restarted_process = ProjectId::new(project_id);
    let cli_key = LibraryProjectKey::parse(project_id.to_ascii_lowercase()).unwrap();
    assert_eq!(project_key(&first_process).unwrap(), cli_key,);
    assert_eq!(project_key(&restarted_process).unwrap(), cli_key);

    let directory = TestDirectory::new("stable-project-key");
    let (environment, _, ptrack_home, _) = environment(&directory);
    let library = CanonicalLibrary::open(&ptrack_home).unwrap();
    let entry = CanonicalEntryId::parse("cli-installed").unwrap();
    let inserted = library
        .insert(entry.clone(), b"installed by cli\n")
        .unwrap();
    library
        .enable(LibraryEnablementKey::new(
            entry,
            inserted.version().clone(),
            OriginAgent::Codex,
            cli_key,
        ))
        .unwrap();
    drop(library);

    let loaded = execute_skill_library(
        &environment,
        project_key(&restarted_process).unwrap(),
        SkillLibraryAction::Load,
    )
    .unwrap();
    assert!(matches!(
        loaded,
        SkillLibraryDataDto::Load { entries, .. }
            if entries[0].versions[0].enabled_agents == [SkillLibraryAgentDto::Codex]
    ));
}

#[test]
fn load_and_no_op_preview_respect_the_current_managed_root_without_exposing_it() {
    let directory = TestDirectory::new("root-bound-load");
    let (environment, project, ptrack_home, _) = environment(&directory);
    let default_root = directory.path().join("home/.codex");
    let explicit_root = directory.path().join("explicit-codex");
    fs::create_dir(&explicit_root).unwrap();
    let library = CanonicalLibrary::open(&ptrack_home).unwrap();
    let entry = CanonicalEntryId::parse("root-bound").unwrap();
    let bytes = b"root-bound GUI bytes\n";
    let version = library
        .insert(entry.clone(), bytes)
        .unwrap()
        .version()
        .clone();
    let key = LibraryEnablementKey::new(
        entry.clone(),
        version.clone(),
        OriginAgent::Codex,
        project.clone(),
    );
    library.enable(key.clone()).unwrap();
    let plan = plan_managed_materialization(&library, &key, &explicit_root).unwrap();
    apply_managed_materialization(&library, &key, &plan).unwrap();

    fs::create_dir_all(default_root.join("prompts")).unwrap();
    fs::write(default_root.join("prompts/root-bound.md"), bytes).unwrap();
    let loaded =
        execute_skill_library(&environment, project.clone(), SkillLibraryAction::Load).unwrap();
    let SkillLibraryDataDto::Load { entries, .. } = &loaded else {
        panic!("expected load DTO");
    };
    assert!(entries[0].versions[0].managed_agents.is_empty());
    let serialized = serde_json::to_string(&loaded).unwrap();
    let canonical_explicit = fs::canonicalize(&explicit_root).unwrap();
    let root_id = LibraryManagedRootId::from_canonical_path(&canonical_explicit).unwrap();
    assert!(!serialized.contains(explicit_root.to_string_lossy().as_ref()));
    assert!(!serialized.contains(default_root.to_string_lossy().as_ref()));
    assert!(!serialized.contains(root_id.digest().as_str()));

    let error = execute_skill_library(
        &environment,
        project,
        SkillLibraryAction::PreviewMaterialization {
            entry_id: entry,
            version,
            agent: SkillLibraryAgentDto::Codex,
        },
    )
    .unwrap_err();
    assert_eq!(error.kind, DesktopErrorKind::Conflict);
}

#[test]
fn apply_no_op_reports_durable_same_root_version_transfer() {
    let directory = TestDirectory::new("same-root-version-transfer");
    let (environment, project, ptrack_home, _) = environment(&directory);
    let library = CanonicalLibrary::open(&ptrack_home).unwrap();
    let entry = CanonicalEntryId::parse("version-transfer").unwrap();
    let first = library
        .insert(entry.clone(), b"first GUI version\n")
        .unwrap();
    let second = library
        .insert(entry.clone(), b"second GUI version\n")
        .unwrap();
    let first_version = first.version().clone();
    let second_version = second.version().clone();
    for version in [&first_version, &second_version] {
        library
            .enable(LibraryEnablementKey::new(
                entry.clone(),
                version.clone(),
                OriginAgent::Codex,
                project.clone(),
            ))
            .unwrap();
    }
    drop(library);

    execute_skill_library(
        &environment,
        project.clone(),
        SkillLibraryAction::ApplyMaterialization {
            entry_id: entry.clone(),
            version: first_version,
            agent: SkillLibraryAgentDto::Codex,
        },
    )
    .unwrap();
    let destination = directory
        .path()
        .join("home/.codex/prompts/version-transfer.md");
    fs::write(&destination, b"second GUI version\n").unwrap();
    let transferred = execute_skill_library(
        &environment,
        project.clone(),
        SkillLibraryAction::ApplyMaterialization {
            entry_id: entry,
            version: second_version,
            agent: SkillLibraryAgentDto::Codex,
        },
    )
    .unwrap();
    assert!(matches!(
        transferred,
        SkillLibraryDataDto::ApplyMaterialization { outcomes, .. }
            if outcomes.len() == 1
                && outcomes[0].action == SkillLibraryMaterializationActionDto::NoOp
                && outcomes[0].ownership_recorded
    ));
    let loaded = execute_skill_library(&environment, project, SkillLibraryAction::Load).unwrap();
    assert!(matches!(
        loaded,
        SkillLibraryDataDto::Load { entries, .. }
            if entries[0].versions.iter().any(|version|
                version.version == second.version().as_str()
                    && version.managed_agents == [SkillLibraryAgentDto::Codex])
    ));
}

#[test]
fn library_environment_roots_reject_oversized_and_control_paths() {
    let home = std::env::temp_dir().join(format!("pam-gui-home-{}", Uuid::new_v4()));
    let oversized = home.join("a".repeat(4_097));
    let controlled = home.join("private\nroot");

    for invalid in [oversized, controlled] {
        assert!(resolve_library_roots_for_test(&home, Some(invalid.clone()), None).is_err());
        assert!(resolve_library_roots_for_test(&home, None, Some(invalid)).is_err());
    }
}
