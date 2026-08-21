use std::{fs, path::Path};

#[cfg(unix)]
use std::ffi::OsStr;

#[cfg(unix)]
use std::{process::Command, thread, time::Duration};

#[cfg(unix)]
use std::os::unix::fs::{PermissionsExt as _, symlink};

use crate::{
    ArtifactInstallError, ArtifactInstallProvenance, ArtifactInstallSource, CanonicalEntryId,
    CanonicalLibrary, LibraryInsertDisposition, MAX_LIBRARY_ARTIFACT_BYTES, install_artifact,
    scan_test::TestDirectory,
};

#[cfg(unix)]
use super::install::install_git_artifact_with_execution;
use super::install::install_local_artifact_with_after_read;
#[cfg(unix)]
use super::install::{
    install_git_artifact_with_execution_limits, resolve_unix_git_executable_for_test,
};

fn library() -> (TestDirectory, CanonicalLibrary) {
    let home = TestDirectory::new("install-library");
    let library = CanonicalLibrary::open(home.path()).unwrap();
    (home, library)
}

fn entry(value: &str) -> CanonicalEntryId {
    CanonicalEntryId::parse(value).unwrap()
}

#[cfg(unix)]
fn install_temporaries(library: &CanonicalLibrary) -> usize {
    fs::read_dir(library.root_path())
        .unwrap()
        .filter_map(Result::ok)
        .filter(|entry| {
            entry
                .file_name()
                .to_string_lossy()
                .starts_with("install-tmp-")
        })
        .count()
}

#[cfg(unix)]
fn latest_manifest_bytes(library: &CanonicalLibrary) -> Vec<u8> {
    let manifests = library.root_path().join("manifests");
    let latest = fs::read_dir(manifests)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .max()
        .unwrap();
    fs::read(latest).unwrap()
}

#[test]
fn local_install_is_exact_idempotent_private_and_durable() {
    let (home, library) = library();
    let source = TestDirectory::new("install-local-source");
    let bytes = "# Café skill\r\nline with spaces\n".as_bytes();
    source.write("skill file.md", bytes);
    let path = source.path().join("skill file.md");
    let request = ArtifactInstallSource::local_file(&path);
    assert_eq!(format!("{request:?}"), "LocalFile(..)");

    let first = install_artifact(&library, entry("local-skill"), &request).unwrap();
    assert_eq!(first.disposition(), LibraryInsertDisposition::Inserted);
    assert_eq!(first.provenance(), &ArtifactInstallProvenance::Local);
    assert_eq!(
        library.read(first.entry_id(), first.version()).unwrap(),
        bytes
    );
    assert_eq!(fs::read(&path).unwrap(), bytes);

    let repeated = install_artifact(&library, entry("local-skill"), &request).unwrap();
    assert_eq!(
        repeated.disposition(),
        LibraryInsertDisposition::AlreadyPresent
    );
    drop(library);
    let reopened = CanonicalLibrary::open(home.path()).unwrap();
    assert_eq!(
        reopened
            .installation_provenance(first.entry_id(), first.version())
            .unwrap(),
        Some(ArtifactInstallProvenance::Local)
    );
}

#[test]
fn local_install_rejects_unsafe_oversized_and_changed_sources_without_entries() {
    let (_home, library) = library();
    let source = TestDirectory::new("install-local-rejections");
    source.write("changed.md", b"before\n");
    let changed_path = source.path().join("changed.md");
    let changed = ArtifactInstallSource::local_file(&changed_path);
    assert_eq!(
        install_local_artifact_with_after_read(&library, entry("changed"), &changed, || {
            fs::write(&changed_path, b"after!\n").unwrap();
        })
        .unwrap_err(),
        ArtifactInstallError::LocalSourceChanged
    );

    source.write("large.md", vec![b'x'; MAX_LIBRARY_ARTIFACT_BYTES + 1]);
    assert_eq!(
        install_artifact(
            &library,
            entry("large"),
            &ArtifactInstallSource::local_file(source.path().join("large.md")),
        )
        .unwrap_err(),
        ArtifactInstallError::SourceTooLarge
    );
    assert_eq!(
        install_artifact(
            &library,
            entry("directory"),
            &ArtifactInstallSource::local_file(source.path()),
        )
        .unwrap_err(),
        ArtifactInstallError::InvalidLocalSource
    );
    assert!(library.entries().unwrap().is_empty());
}

#[cfg(unix)]
#[test]
fn local_install_rejects_symlinks_and_devices() {
    let (_home, library) = library();
    let source = TestDirectory::new("install-local-special");
    source.write("target.md", b"target\n");
    symlink(
        source.path().join("target.md"),
        source.path().join("link.md"),
    )
    .unwrap();
    for (id, path) in [
        ("link", source.path().join("link.md")),
        ("device", Path::new("/dev/null").to_path_buf()),
    ] {
        assert_eq!(
            install_artifact(
                &library,
                entry(id),
                &ArtifactInstallSource::local_file(path),
            )
            .unwrap_err(),
            ArtifactInstallError::InvalidLocalSource
        );
    }
}

#[test]
fn git_source_validation_rejects_credentials_fragments_and_unsafe_paths_without_leaking() {
    for url in [
        "http://example.com/repo",
        "https://user:secret@example.com/repo",
        "https://example.com/repo#secret",
        "https://example.com/repo?token=secret",
        "ssh://example.com/repo",
        "file://host/path",
        "https://example.com/repo\"command",
        "https://example.com/repo|command",
    ] {
        let error = ArtifactInstallSource::git(url, "skill.md").unwrap_err();
        assert_eq!(error, ArtifactInstallError::InvalidGitUrl);
        assert!(!error.to_string().contains("secret"));
    }
    for path in [
        "../skill.md",
        "/skill.md",
        "a//b",
        "a\\b",
        "a:b",
        "a/./b",
        "a\"command.md",
        "a|command.md",
        "CON",
        "con.txt",
        "rules/AuX.md",
        "rules/LpT9.rule",
    ] {
        assert_eq!(
            ArtifactInstallSource::git("https://example.com/repo", path).unwrap_err(),
            ArtifactInstallError::InvalidGitArtifactPath
        );
    }
    assert!(
        ArtifactInstallSource::git(
            "https://example.com/repository%!^&name",
            "rules/skill%!^&name.md",
        )
        .is_ok()
    );
}

#[cfg(windows)]
#[test]
fn windows_supervisor_protocol_uses_only_fixed_script_and_bounded_environment_values() {
    use std::ffi::{OsStr, OsString};

    use super::install::{
        windows_supervisor_environment, windows_supervisor_fixed_command, windows_supervisor_script,
    };

    let marker = "%!^&";
    let environment = windows_supervisor_environment(
        OsStr::new(r"C:\Program Files%!^&\Git\bin\git.exe"),
        &[
            OsString::from("fetch"),
            OsString::from("https://example.com/repository%!^&name"),
        ],
        Path::new(r"C:\private%!^& workspace"),
        Path::new(r"C:\private%!^& workspace\status.tmp"),
        Path::new(r"C:\private%!^& workspace\status"),
        Path::new(r"C:\Windows\System32\ping.exe"),
        Path::new(r"C:\private%!^& workspace\supervisor.cmd"),
    )
    .unwrap();
    assert!(
        environment
            .iter()
            .any(|(_, value)| value.to_string_lossy().contains(marker))
    );
    let script = windows_supervisor_script();
    assert!(script.contains("setlocal DisableDelayedExpansion"));
    assert!(script.contains("set \"PAM_GIT_EXIT=%ERRORLEVEL%\""));
    assert!(script.contains("move /Y \"%PAM_STATUS_TEMP%\" \"%PAM_STATUS_FINAL%\" >NUL 2>NUL"));
    assert!(script.contains("goto pam_wait"));
    assert!(!script.contains(marker));
    assert_eq!(
        windows_supervisor_fixed_command(),
        "\"\"%PAM_SUPERVISOR_SCRIPT%\"\""
    );
    assert!(!windows_supervisor_fixed_command().contains(marker));
    assert_eq!(
        windows_supervisor_environment(
            OsStr::new("git.exe"),
            &[OsString::from("bad\"argument")],
            Path::new(r"C:\private"),
            Path::new(r"C:\private\status.tmp"),
            Path::new(r"C:\private\status"),
            Path::new(r"C:\Windows\System32\ping.exe"),
            Path::new(r"C:\private\supervisor.cmd"),
        )
        .unwrap_err(),
        ArtifactInstallError::GitCommandFailed
    );
    assert_eq!(
        windows_supervisor_environment(
            OsStr::new("git.exe"),
            &[OsString::from("bad\nargument")],
            Path::new(r"C:\private"),
            Path::new(r"C:\private\status.tmp"),
            Path::new(r"C:\private\status"),
            Path::new(r"C:\Windows\System32\ping.exe"),
            Path::new(r"C:\private\supervisor.cmd"),
        )
        .unwrap_err(),
        ArtifactInstallError::GitCommandFailed
    );
    assert_eq!(
        windows_supervisor_environment(
            OsStr::new("git.exe"),
            &vec![OsString::from("argument"); 33],
            Path::new(r"C:\private"),
            Path::new(r"C:\private\status.tmp"),
            Path::new(r"C:\private\status"),
            Path::new(r"C:\Windows\System32\ping.exe"),
            Path::new(r"C:\private\supervisor.cmd"),
        )
        .unwrap_err(),
        ArtifactInstallError::GitCommandFailed
    );
    assert_eq!(
        windows_supervisor_environment(
            OsStr::new("git.exe"),
            &[OsString::from("x".repeat(16_385))],
            Path::new(r"C:\private"),
            Path::new(r"C:\private\status.tmp"),
            Path::new(r"C:\private\status"),
            Path::new(r"C:\Windows\System32\ping.exe"),
            Path::new(r"C:\private\supervisor.cmd"),
        )
        .unwrap_err(),
        ArtifactInstallError::GitCommandFailed
    );
}

#[cfg(unix)]
#[test]
fn file_git_install_reads_head_blob_records_commit_and_cleans_workspace() {
    if !git_available() {
        return;
    }
    let (home, library) = library();
    let repository = TestDirectory::new("install-git-repository");
    initialize_repository(&repository);
    let bytes = "# Résumé\r\nline with spaces\n".as_bytes();
    repository.write("rules/skill file.md", bytes);
    repository.write(".gitmodules", b"[submodule \"unused\"]\n\tpath = unused\n");
    git(repository.path(), &["add", "."]);
    git(repository.path(), &["commit", "--quiet", "-m", "fixture"]);
    let commit = git_output(repository.path(), &["rev-parse", "HEAD"]);
    let sentinel = repository.path().join("hook-ran");
    let hook = repository.path().join(".git/hooks/post-checkout");
    fs::write(
        &hook,
        format!("#!/bin/sh\ntouch '{}'\n", sentinel.display()),
    )
    .unwrap();
    fs::set_permissions(&hook, fs::Permissions::from_mode(0o700)).unwrap();
    let url = format!("file://{}", repository.path().display());
    let source = ArtifactInstallSource::git(&url, "rules/skill file.md").unwrap();

    let installed = install_artifact(&library, entry("git-skill"), &source).unwrap();
    assert_eq!(
        library
            .read(installed.entry_id(), installed.version())
            .unwrap(),
        bytes
    );
    let ArtifactInstallProvenance::Git(provenance) = installed.provenance() else {
        panic!("expected Git provenance");
    };
    assert_eq!(provenance.commit(), commit);
    assert_ne!(
        provenance.repository_digest(),
        provenance.artifact_path_digest()
    );
    for rendered in [
        format!("{source:?}"),
        format!("{:?}", installed.provenance()),
        format!("{installed:?}"),
        String::from_utf8(latest_manifest_bytes(&library)).unwrap(),
    ] {
        assert!(!rendered.contains(&url));
        assert!(!rendered.contains("rules/skill file.md"));
    }
    assert!(!sentinel.exists());
    assert_eq!(install_temporaries(&library), 0);
    assert_eq!(
        install_artifact(&library, entry("git-skill"), &source)
            .unwrap()
            .disposition(),
        LibraryInsertDisposition::AlreadyPresent
    );

    drop(library);
    let reopened = CanonicalLibrary::open(home.path()).unwrap();
    assert_eq!(
        reopened
            .installation_provenance(installed.entry_id(), installed.version())
            .unwrap(),
        Some(installed.provenance().clone())
    );
}

#[cfg(unix)]
#[test]
fn failed_git_blob_install_leaves_no_entry_provenance_or_workspace() {
    if !git_available() {
        return;
    }
    let (_home, library) = library();
    let repository = TestDirectory::new("install-git-missing");
    initialize_repository(&repository);
    repository.write("present.md", b"present\n");
    git(repository.path(), &["add", "."]);
    git(repository.path(), &["commit", "--quiet", "-m", "fixture"]);
    let source = ArtifactInstallSource::git(
        format!("file://{}", repository.path().display()),
        "missing.md",
    )
    .unwrap();
    assert_eq!(
        install_artifact(&library, entry("missing-git"), &source).unwrap_err(),
        ArtifactInstallError::GitBlobUnavailable
    );
    repository.write("oversized.md", vec![b'x'; MAX_LIBRARY_ARTIFACT_BYTES + 1]);
    git(repository.path(), &["add", "oversized.md"]);
    git(repository.path(), &["commit", "--quiet", "-m", "oversized"]);
    let oversized = ArtifactInstallSource::git(
        format!("file://{}", repository.path().display()),
        "oversized.md",
    )
    .unwrap();
    assert_eq!(
        install_artifact(&library, entry("oversized-git"), &oversized).unwrap_err(),
        ArtifactInstallError::SourceTooLarge
    );
    assert!(library.entries().unwrap().is_empty());
    assert_eq!(install_temporaries(&library), 0);
}

#[cfg(unix)]
#[test]
fn flooding_git_output_is_bounded_terminated_and_redacted() {
    let (_home, library) = library();
    let scripts = TestDirectory::new("install-git-flood");
    let executable = scripts.path().join("git-flood");
    write_executable(
        &executable,
        "#!/bin/sh\nwhile :; do printf 'private-output-that-must-not-leak' >&2; done\n",
    );
    let source = ArtifactInstallSource::git("file:///unused", "skill.md").unwrap();
    let error = install_git_artifact_with_execution(
        &library,
        entry("flood"),
        &source,
        &executable,
        Duration::from_secs(2),
    )
    .unwrap_err();
    assert_eq!(error, ArtifactInstallError::GitOutputTooLarge);
    assert!(!format!("{error:?}").contains("private-output"));
    assert!(library.entries().unwrap().is_empty());
    assert_eq!(install_temporaries(&library), 0);
}

#[cfg(unix)]
#[test]
fn oversized_git_workspace_is_terminated_reaped_and_removed() {
    let (_home, library) = library();
    let scripts = TestDirectory::new("install-git-workspace-overflow");
    let executable = scripts.path().join("git-workspace-overflow");
    write_executable(
        &executable,
        "#!/bin/sh\ndd if=/dev/zero of=oversized.pack bs=1024 count=32 2>/dev/null\nsleep 30\n",
    );
    let source = ArtifactInstallSource::git("file:///unused", "skill.md").unwrap();
    assert_eq!(
        install_git_artifact_with_execution_limits(
            &library,
            entry("workspace-overflow"),
            &source,
            &executable,
            Duration::from_secs(2),
            8 * 1024,
        )
        .unwrap_err(),
        ArtifactInstallError::GitWorkspaceTooLarge
    );
    assert!(library.entries().unwrap().is_empty());
    assert_eq!(install_temporaries(&library), 0);
}

#[cfg(unix)]
#[test]
fn unix_git_resolution_accepts_a_path_only_fixture_and_rejects_relative_entries() {
    let scripts = TestDirectory::new("install-git-path-resolution");
    let executable = scripts.path().join("git");
    write_executable(&executable, "#!/bin/sh\nexit 0\n");
    assert_eq!(
        resolve_unix_git_executable_for_test(scripts.path().as_os_str()).unwrap(),
        fs::canonicalize(&executable).unwrap().into_os_string()
    );
    assert_eq!(
        resolve_unix_git_executable_for_test(OsStr::new("relative-only")).unwrap_err(),
        ArtifactInstallError::GitUnavailable
    );
}

#[cfg(unix)]
#[test]
fn timed_out_git_descendant_tree_is_killed_before_workspace_cleanup() {
    let (_home, library) = library();
    let scripts = TestDirectory::new("install-git-timeout-tree");
    let executable = scripts.path().join("git-timeout");
    let sentinel = scripts.path().join("descendant-survived");
    write_executable(
        &executable,
        &format!(
            "#!/bin/sh\n(sleep 0.3; touch '{}') &\nsleep 30\n",
            sentinel.display()
        ),
    );
    let source = ArtifactInstallSource::git("file:///unused", "skill.md").unwrap();
    assert_eq!(
        install_git_artifact_with_execution(
            &library,
            entry("timeout"),
            &source,
            &executable,
            Duration::from_millis(50),
        )
        .unwrap_err(),
        ArtifactInstallError::GitDeadlineExceeded
    );
    thread::sleep(Duration::from_millis(450));
    assert!(!sentinel.exists());
    assert!(library.entries().unwrap().is_empty());
    assert_eq!(install_temporaries(&library), 0);
}

#[cfg(unix)]
fn initialize_repository(repository: &TestDirectory) {
    git(repository.path(), &["init", "--quiet"]);
    git(repository.path(), &["config", "user.name", "PAM Test"]);
    git(
        repository.path(),
        &["config", "user.email", "pam@example.invalid"],
    );
}

#[cfg(unix)]
fn git_available() -> bool {
    Command::new("git")
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

#[cfg(unix)]
fn git(repository: &Path, arguments: &[&str]) {
    assert!(
        Command::new("git")
            .arg("-C")
            .arg(repository)
            .args(arguments)
            .status()
            .unwrap()
            .success()
    );
}

#[cfg(unix)]
fn git_output(repository: &Path, arguments: &[&str]) -> String {
    let output = Command::new("git")
        .arg("-C")
        .arg(repository)
        .args(arguments)
        .output()
        .unwrap();
    assert!(output.status.success());
    String::from_utf8(output.stdout).unwrap().trim().to_owned()
}

#[cfg(unix)]
fn write_executable(path: &Path, contents: &str) {
    fs::write(path, contents).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
}
