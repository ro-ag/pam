use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
    sync::{Arc, Barrier, mpsc},
    thread,
    time::Duration,
};

use uuid::Uuid;

use super::{CallerKind, IdentityErrorKind, discover_project, discover_project_id};
#[cfg(any(unix, windows))]
use crate::identity::strip_git_record_line_ending;
#[cfg(windows)]
use crate::identity::sync_directory;
use crate::identity::{
    MAX_IDENTITY_FILE_BYTES, PublicationMode, caller_id_in, caller_id_in_with_publication,
    discover_project_id_with_git_environment, identity_lock_path,
};

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new(name: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "pam-{name}-{}-{}",
            std::process::id(),
            Uuid::new_v4()
        ));
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        drop(fs::remove_dir_all(&self.0));
    }
}

#[test]
fn caller_ids_are_durable_distinct_uuid_labels_per_kind() {
    let data = TestDirectory::new("caller-identity");

    let first_cli = caller_id_in(data.path(), CallerKind::Cli).unwrap();
    let second_cli = caller_id_in(data.path(), CallerKind::Cli).unwrap();
    let gui = caller_id_in(data.path(), CallerKind::Gui).unwrap();

    assert_eq!(first_cli, second_cli);
    assert_ne!(first_cli.as_str(), gui.as_str());
    assert_eq!(
        Uuid::parse_str(first_cli.as_str()).unwrap().to_string(),
        first_cli.as_str()
    );
    assert_eq!(
        Uuid::parse_str(gui.as_str()).unwrap().to_string(),
        gui.as_str()
    );
    let cli_file = fs::read_to_string(data.path().join("callers/cli.toml")).unwrap();
    assert!(cli_file.starts_with("version = 1\ncaller_id = \""));
}

#[test]
fn every_declared_caller_kind_has_its_own_persisted_label() {
    let data = TestDirectory::new("caller-kinds");
    let kinds = [
        CallerKind::Cli,
        CallerKind::Gui,
        CallerKind::CodingAgent,
        CallerKind::LocalApplication,
    ];

    let ids: Vec<_> = kinds
        .into_iter()
        .map(|kind| caller_id_in(data.path(), kind).unwrap())
        .collect();

    for (index, id) in ids.iter().enumerate() {
        assert!(!ids[..index].contains(id));
    }
}

#[test]
fn atomic_rename_fallback_converges_under_concurrent_callers() {
    let data = TestDirectory::new("caller-create-new");
    let data_path = Arc::new(data.path().to_path_buf());
    let barrier = Arc::new(Barrier::new(8));
    let handles: Vec<_> = (0..8)
        .map(|_| {
            let data_path = Arc::clone(&data_path);
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                caller_id_in_with_publication(
                    &data_path,
                    CallerKind::CodingAgent,
                    PublicationMode::ForceRename,
                )
                .unwrap()
            })
        })
        .collect();

    let ids: Vec<_> = handles
        .into_iter()
        .map(|handle| handle.join().unwrap())
        .collect();
    assert!(ids.iter().all(|id| id == &ids[0]));
}

#[test]
fn an_existing_unlocked_persistent_lock_does_not_block_creation() {
    let data = TestDirectory::new("caller-stale-lock");
    let identity_path = data.path().join("callers/cli.toml");
    fs::create_dir_all(identity_path.parent().unwrap()).unwrap();
    let lock_path = identity_lock_path(&identity_path);
    fs::write(&lock_path, []).unwrap();
    let lock = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&lock_path)
        .unwrap();
    lock.try_lock().unwrap();
    lock.unlock().unwrap();

    let id =
        caller_id_in_with_publication(data.path(), CallerKind::Cli, PublicationMode::ForceRename)
            .unwrap();

    assert!(Uuid::parse_str(id.as_str()).is_ok());
    assert!(lock_path.is_file());
}

#[test]
fn managed_reader_waits_for_an_exclusive_writer_lock() {
    let data = TestDirectory::new("caller-reader-lock");
    let expected = caller_id_in(data.path(), CallerKind::Cli).unwrap();
    let identity_path = data.path().join("callers/cli.toml");
    let lock_path = identity_lock_path(&identity_path);
    let writer_lock = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(lock_path)
        .unwrap();
    writer_lock.lock().unwrap();

    let data_path = data.path().to_path_buf();
    let (started_sender, started_receiver) = mpsc::channel();
    let (result_sender, result_receiver) = mpsc::channel();
    let reader = thread::spawn(move || {
        started_sender.send(()).unwrap();
        result_sender
            .send(caller_id_in(&data_path, CallerKind::Cli))
            .unwrap();
    });
    started_receiver.recv().unwrap();
    assert!(matches!(
        result_receiver.recv_timeout(Duration::from_millis(100)),
        Err(mpsc::RecvTimeoutError::Timeout)
    ));

    writer_lock.unlock().unwrap();
    let returned = result_receiver
        .recv_timeout(Duration::from_secs(2))
        .unwrap();
    assert_eq!(returned.unwrap(), expected);
    reader.join().unwrap();
}

#[test]
fn malformed_managed_target_is_never_overwritten() {
    let data = TestDirectory::new("caller-malformed-managed");
    let identity_path = data.path().join("callers/local-application.toml");
    fs::create_dir_all(identity_path.parent().unwrap()).unwrap();
    let malformed = "version = 1\ncaller_id = 'not-a-uuid'\n";
    fs::write(&identity_path, malformed).unwrap();

    let error = caller_id_in_with_publication(
        data.path(),
        CallerKind::LocalApplication,
        PublicationMode::ForceRename,
    )
    .unwrap_err();

    assert_eq!(error.kind(), IdentityErrorKind::MalformedFile);
    assert_eq!(fs::read_to_string(identity_path).unwrap(), malformed);
}

#[test]
fn interruption_before_atomic_publication_never_leaves_a_truncated_final() {
    let data = TestDirectory::new("caller-interrupted-publication");
    let identity_path = data.path().join("callers/gui.toml");

    let error = caller_id_in_with_publication(
        data.path(),
        CallerKind::Gui,
        PublicationMode::InterruptBeforePublication,
    )
    .unwrap_err();
    assert_eq!(error.kind(), IdentityErrorKind::WriteFailed);
    assert!(!identity_path.exists());

    let id =
        caller_id_in_with_publication(data.path(), CallerKind::Gui, PublicationMode::ForceRename)
            .unwrap();
    let contents = fs::read_to_string(&identity_path).unwrap();
    assert_eq!(contents, format!("version = 1\ncaller_id = \"{id}\"\n"));
}

#[test]
fn caller_identity_rejects_a_non_regular_entry() {
    let data = TestDirectory::new("caller-directory");
    fs::create_dir_all(data.path().join("callers/cli.toml")).unwrap();

    let error = caller_id_in(data.path(), CallerKind::Cli).unwrap_err();

    assert_eq!(error.kind(), IdentityErrorKind::MalformedFile);
}

#[test]
fn nearest_project_marker_wins_and_accepts_a_file_start_path() {
    let project = TestDirectory::new("marked-project");
    let outer_id = Uuid::new_v4();
    let inner_id = Uuid::new_v4();
    write_marker(project.path(), outer_id);
    let nested = project.path().join("packages/tool");
    fs::create_dir_all(nested.join("src")).unwrap();
    write_marker(&nested, inner_id);
    let source = nested.join("src/main.rs");
    fs::write(&source, "fn main() {}\n").unwrap();

    let discovered = discover_project(&source).unwrap();

    assert_eq!(discovered.id().as_str(), inner_id.to_string());
    assert_eq!(discovered.root(), fs::canonicalize(nested).unwrap());
}

#[test]
fn git_project_identity_reports_the_canonical_worktree_root() {
    let project = TestDirectory::new("git-project-root");
    initialize_repository(project.path());
    let nested = project.path().join("crates/tool/src");
    fs::create_dir_all(&nested).unwrap();

    let discovered = discover_project(&nested).unwrap();

    assert_eq!(discovered.root(), fs::canonicalize(project.path()).unwrap());
    assert_eq!(
        discovered.id(),
        &discover_project_id(project.path()).unwrap()
    );
}

#[test]
fn malformed_marker_fails_without_being_overwritten() {
    let project = TestDirectory::new("malformed-marker");
    let marker = project.path().join(".pam/project.toml");
    fs::create_dir_all(marker.parent().unwrap()).unwrap();
    let malformed = "version = 1\nproject_id = 'not-a-uuid'\n";
    fs::write(&marker, malformed).unwrap();

    let error = discover_project_id(project.path()).unwrap_err();

    assert_eq!(error.kind(), IdentityErrorKind::MalformedFile);
    assert_eq!(
        error.path(),
        Some(fs::canonicalize(&marker).unwrap().as_path())
    );
    assert_eq!(fs::read_to_string(marker).unwrap(), malformed);
}

#[cfg(unix)]
#[test]
fn dangling_marker_symlink_is_rejected_without_following_it() {
    use std::os::unix::fs::symlink;

    let project = TestDirectory::new("dangling-marker");
    let marker = project.path().join(".pam/project.toml");
    fs::create_dir_all(marker.parent().unwrap()).unwrap();
    symlink(project.path().join("missing-target"), &marker).unwrap();

    let error = discover_project_id(project.path()).unwrap_err();

    assert_eq!(error.kind(), IdentityErrorKind::MalformedFile);
    assert!(
        fs::symlink_metadata(marker)
            .unwrap()
            .file_type()
            .is_symlink()
    );
}

#[cfg(unix)]
#[test]
fn fifo_marker_is_rejected_without_blocking_on_open() {
    let project = TestDirectory::new("fifo-marker");
    let marker = project.path().join(".pam/project.toml");
    fs::create_dir_all(marker.parent().unwrap()).unwrap();
    let output = Command::new("mkfifo").arg(&marker).output().unwrap();
    assert!(output.status.success());

    let error = discover_project_id(project.path()).unwrap_err();

    assert_eq!(error.kind(), IdentityErrorKind::MalformedFile);
}

#[test]
fn unsupported_marker_version_fails_without_being_overwritten() {
    let project = TestDirectory::new("future-marker");
    let marker = project.path().join(".pam/project.toml");
    fs::create_dir_all(marker.parent().unwrap()).unwrap();
    let future = format!(
        "version = 2\nproject_id = \"{}\"\nfuture_field = true\n",
        Uuid::new_v4()
    );
    fs::write(&marker, &future).unwrap();

    let error = discover_project_id(project.path()).unwrap_err();

    assert_eq!(error.kind(), IdentityErrorKind::UnsupportedVersion);
    assert_eq!(fs::read_to_string(marker).unwrap(), future);
}

#[test]
fn oversized_git_fallback_is_rejected_before_reading() {
    let project = TestDirectory::new("oversized-fallback");
    initialize_repository(project.path());
    let fallback = project.path().join(".git/pam/project.toml");
    fs::create_dir_all(fallback.parent().unwrap()).unwrap();
    let oversized = vec![b'x'; usize::try_from(MAX_IDENTITY_FILE_BYTES + 1).unwrap()];
    fs::write(&fallback, &oversized).unwrap();

    let error = discover_project_id(project.path()).unwrap_err();

    assert_eq!(error.kind(), IdentityErrorKind::MalformedFile);
    assert_eq!(fs::read(fallback).unwrap(), oversized);
}

#[test]
fn git_fallback_survives_moves_is_shared_by_worktrees_and_differs_in_clones() {
    let sandbox = TestDirectory::new("git-project");
    let original = sandbox.path().join("original");
    initialize_repository(&original);

    let original_id = discover_project_id(&original).unwrap();
    let moved = sandbox.path().join("moved");
    fs::rename(&original, &moved).unwrap();
    let moved_id = discover_project_id(moved.join("README.md")).unwrap();
    assert_eq!(moved_id, original_id);

    let linked = sandbox.path().join("linked");
    git(
        &moved,
        &[
            "worktree",
            "add",
            "--quiet",
            "-b",
            "linked",
            path_text(&linked),
        ],
    );
    let linked_id = discover_project_id(&linked).unwrap();
    assert_eq!(linked_id, original_id);

    let clone = sandbox.path().join("clone");
    git(
        sandbox.path(),
        &["clone", "--quiet", path_text(&moved), path_text(&clone)],
    );
    let clone_id = discover_project_id(&clone).unwrap();
    assert_ne!(clone_id, original_id);
}

#[test]
fn git_environment_cannot_redirect_project_discovery() {
    let sandbox = TestDirectory::new("git-environment");
    let primary = sandbox.path().join("primary");
    let contaminating = sandbox.path().join("contaminating");
    initialize_repository(&primary);
    initialize_repository(&contaminating);
    let contaminating_id = discover_project_id(&contaminating).unwrap();

    let primary_id = discover_project_id_with_git_environment(
        &primary,
        contaminating.join(".git").as_os_str(),
        contaminating.as_os_str(),
    )
    .unwrap();

    assert_ne!(primary_id, contaminating_id);
    assert!(primary.join(".git/pam/project.toml").is_file());
}

#[cfg(unix)]
#[test]
fn git_discovery_preserves_a_newline_path() {
    let sandbox = TestDirectory::new("git-raw-paths");
    let newline_path = sandbox.path().join("repo\nnewline");
    initialize_repository(&newline_path);
    let newline_id = discover_project_id(&newline_path).unwrap();
    assert!(Uuid::parse_str(newline_id.as_str()).is_ok());
}

#[cfg(unix)]
#[test]
fn git_record_stripping_removes_one_lf_and_preserves_a_trailing_cr() {
    let mut crlf = b"path\r\n".to_vec();
    strip_git_record_line_ending(&mut crlf);
    assert_eq!(crlf, b"path\r");

    let mut two_lf = b"path\n\n".to_vec();
    strip_git_record_line_ending(&mut two_lf);
    assert_eq!(two_lf, b"path\n");
}

#[cfg(windows)]
#[test]
fn windows_git_record_stripping_removes_one_crlf() {
    let mut crlf = b"path\r\n".to_vec();
    strip_git_record_line_ending(&mut crlf);
    assert_eq!(crlf, b"path");

    let mut two_crlf = b"path\r\n\r\n".to_vec();
    strip_git_record_line_ending(&mut two_crlf);
    assert_eq!(two_crlf, b"path\r\n");
}

#[cfg(target_os = "linux")]
#[test]
fn git_discovery_preserves_a_non_utf8_path() {
    use std::{ffi::OsString, os::unix::ffi::OsStringExt};

    let sandbox = TestDirectory::new("git-non-utf8-path");
    let non_utf8_path = sandbox
        .path()
        .join(OsString::from_vec(b"repo-\xff".to_vec()));
    initialize_repository(&non_utf8_path);
    let non_utf8_id = discover_project_id(&non_utf8_path).unwrap();
    assert!(Uuid::parse_str(non_utf8_id.as_str()).is_ok());
}

#[test]
fn directory_without_marker_or_git_repository_is_not_a_project() {
    let directory = TestDirectory::new("not-project");

    let error = discover_project_id(directory.path()).unwrap_err();

    assert_eq!(error.kind(), IdentityErrorKind::NotProject);
}

#[cfg(windows)]
#[test]
fn windows_directory_sync_is_an_explicit_supported_noop() {
    let directory = TestDirectory::new("windows-directory-sync");

    sync_directory(directory.path()).unwrap();
}

fn write_marker(root: &Path, id: Uuid) {
    let directory = root.join(".pam");
    fs::create_dir_all(&directory).unwrap();
    fs::write(
        directory.join("project.toml"),
        format!("version = 1\nproject_id = \"{id}\"\n"),
    )
    .unwrap();
}

fn initialize_repository(path: &Path) {
    fs::create_dir_all(path).unwrap();
    git(path, &["init", "--quiet", "--initial-branch=main"]);
    git(path, &["config", "user.email", "pam-tests@example.invalid"]);
    git(path, &["config", "user.name", "PAM Tests"]);
    fs::write(path.join("README.md"), "test project\n").unwrap();
    git(path, &["add", "README.md"]);
    git(path, &["commit", "--quiet", "-m", "test fixture"]);
}

fn git(working_directory: &Path, arguments: &[&str]) {
    let output = Command::new("git")
        .arg("-C")
        .arg(working_directory)
        .args(arguments)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "git {} failed: {}",
        arguments.join(" "),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn path_text(path: &Path) -> &str {
    path.to_str().unwrap()
}
