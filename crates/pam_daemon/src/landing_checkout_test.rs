use super::*;

#[test]
fn tracked_structure_rejects_escape_aliases_and_special_modes() {
    let oid = "a".repeat(40);
    for path in [
        "../escape",
        "/absolute",
        "a/../../escape",
        ".git/config",
        "nested/.GiT/config",
        "a\\b",
        "a\nb",
    ] {
        let raw = format!("100644 blob {oid} 1\t{path}\0");
        assert!(parse_manifest(raw.as_bytes()).is_err(), "{path:?}");
    }
    for mode in ["120000", "160000"] {
        assert!(parse_manifest(format!("{mode} blob {oid} 1\tfile\0").as_bytes()).is_err());
    }
    let collision =
        format!("100644 blob {oid} 1\tFile\0") + &format!("100644 blob {oid} 1\tfile\0");
    assert!(parse_manifest(collision.as_bytes()).is_err());
}

#[test]
fn manifest_and_batch_enforce_count_size_identity_and_exact_bytes() {
    let oid = "a".repeat(40);
    let row = format!("100644 blob {oid} 3\tdir/file\0");
    let mut entries = parse_manifest(row.as_bytes()).unwrap();
    let too_many = (0..=MAX_FILES)
        .map(|index| format!("100644 blob {oid} 0\tfile-{index}\0"))
        .collect::<String>();
    assert!(parse_manifest(too_many.as_bytes()).is_err());
    assert!(
        parse_manifest(format!("100644 blob {oid} {}\tlarge\0", MAX_FILE + 1).as_bytes()).is_err()
    );
    let directory = tempfile::tempdir().unwrap();
    let mut bytes = format!("{oid} blob 3\n").into_bytes();
    bytes.extend_from_slice(&[0, 255, 10, 10]);
    export_blobs(directory.path(), &mut entries, &bytes).unwrap();
    assert_eq!(
        std::fs::read(directory.path().join("dir/file")).unwrap(),
        [0, 255, 10]
    );
    assert_eq!(entries[0].sha256, pam_compact::sha256_hex(&[0, 255, 10]));
    let other = tempfile::tempdir().unwrap();
    bytes[0] = b'b';
    assert!(export_blobs(other.path(), &mut entries, &bytes).is_err());
    assert!(!other.path().join("dir/file").exists());
}

#[test]
fn references_reject_indirection_and_nonfull_commits() {
    for reference in [
        "HEAD",
        "refs/heads/../secret",
        "refs/heads/a.lock",
        "refs/heads/a@{x}",
        "refs/heads/a\nb",
    ] {
        assert!(!valid_ref(reference));
    }
    assert!(valid_ref("refs/remotes/origin/main"));
    assert!(!valid_oid(&"0".repeat(40)));
    assert!(!valid_oid(&"a".repeat(64)));
    let directory = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(directory.path().join("refs/heads")).unwrap();
    std::fs::write(
        directory.path().join("refs/heads/main"),
        "ref: refs/heads/other\n",
    )
    .unwrap();
    assert!(resolve_ref(directory.path(), "refs/heads/main").is_err());
}

#[cfg(target_os = "macos")]
struct Fixture {
    _root: tempfile::TempDir,
    request: CheckoutRequest,
}

#[cfg(target_os = "macos")]
impl Fixture {
    fn new() -> Self {
        use std::{fs, os::unix::fs::PermissionsExt};
        let root = tempfile::tempdir().unwrap();
        let root_path = root.path().canonicalize().unwrap();
        let repo = root_path.join("repo");
        let private = root_path.join("private");
        let checkouts = root_path.join("checkouts");
        for path in [&repo, &private, &checkouts] {
            fs::create_dir(path).unwrap();
        }
        fs::set_permissions(&checkouts, fs::Permissions::from_mode(0o700)).unwrap();
        let git = std::path::PathBuf::from("/Library/Developer/CommandLineTools/usr/bin/git");
        assert!(
            git.is_file(),
            "fixture requires the installed trusted command-line Git"
        );
        let mut fixture = Self {
            _root: root,
            request: CheckoutRequest {
                repository: repo.clone(),
                protected_base: private,
                checkouts_root: checkouts,
                git_program: git,
                expected_commit: String::new(),
                base_ref: "refs/heads/main".into(),
                remote_url: "https://git.example/team/repo.git".into(),
            },
        };
        fixture.git(&["init", "-q", "-b", "main"]);
        fixture.git(&["config", "user.name", "Fixture"]);
        fixture.git(&["config", "user.email", "fixture@example.invalid"]);
        fixture.git(&["config", "commit.gpgsign", "false"]);
        fixture.git(&[
            "remote",
            "add",
            "origin",
            "https://git.example/team/repo.git",
        ]);
        fs::write(repo.join(".gitignore"), "target/\n").unwrap();
        fs::write(repo.join("binary"), [0, 255, 10]).unwrap();
        fs::create_dir(repo.join("nested")).unwrap();
        fs::write(repo.join("nested/check.sh"), "#!/bin/sh\nexit 0\n").unwrap();
        fs::set_permissions(
            repo.join("nested/check.sh"),
            fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        fixture.git(&["add", "."]);
        fixture.git(&["commit", "-q", "-m", "fixture"]);
        fixture.request.expected_commit = fixture.git(&["rev-parse", "HEAD"]).trim().to_owned();
        fixture
    }
    fn git(&self, args: &[&str]) -> String {
        let output = std::process::Command::new(&self.request.git_program)
            .args(args)
            .current_dir(&self.request.repository)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "fixture Git failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).unwrap()
    }
    async fn capture(&self) -> Result<CheckoutSnapshot, CheckoutError> {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        let budget = crate::request_budget::RequestBudget::new(deadline);
        let (_sender, mut cancel) = tokio::sync::watch::channel(false);
        capture(&self.request, budget, &mut cancel, deadline).await
    }
}

#[cfg(target_os = "macos")]
#[tokio::test]
async fn actual_snapshot_is_exact_config_independent_and_revalidates_source() {
    use std::fs;
    let fixture = Fixture::new();
    let repo = &fixture.request.repository;
    fs::create_dir(repo.join("target")).unwrap();
    fs::write(repo.join("target/ignored"), "not exported").unwrap();
    let marker = fixture.request.protected_base.join("unexpected-helper");
    fixture.git(&[
        "config",
        "core.fsmonitor",
        &format!("touch {}", marker.display()),
    ]);
    fixture.git(&[
        "config",
        "include.path",
        fixture
            .request
            .protected_base
            .join("missing-config")
            .to_str()
            .unwrap(),
    ]);
    let snapshot = fixture.capture().await.unwrap();
    assert!(!marker.exists());
    assert_eq!(snapshot.receipt.commit, fixture.request.expected_commit);
    assert_eq!(snapshot.receipt.branch, "refs/heads/main");
    assert_eq!(snapshot.receipt.manifest.len(), 3);
    assert_eq!(
        fs::read(snapshot.checktree.join("binary")).unwrap(),
        [0, 255, 10]
    );
    assert!(!snapshot.checktree.join("target").exists());
    assert!(!snapshot.checktree.join(".git").exists());
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    let budget = crate::request_budget::RequestBudget::new(deadline);
    let (_sender, mut cancel) = tokio::sync::watch::channel(false);
    revalidate(
        &fixture.request,
        &snapshot.receipt,
        budget.clone(),
        &mut cancel,
        deadline,
    )
    .await
    .unwrap();
    fs::write(repo.join("binary"), "changed after checks").unwrap();
    let refusal = revalidate(
        &fixture.request,
        &snapshot.receipt,
        budget,
        &mut cancel,
        deadline,
    )
    .await
    .unwrap_err();
    assert_eq!(refusal.cause, "landing_checkout_dirty");
}

#[cfg(target_os = "macos")]
#[tokio::test]
async fn dirty_detached_and_indirect_repositories_are_explicit_refusals() {
    let fixture = Fixture::new();
    let repo = &fixture.request.repository;
    std::fs::write(repo.join("untracked"), "refuse").unwrap();
    assert_eq!(
        fixture.capture().await.unwrap_err().cause,
        "landing_checkout_dirty"
    );
    std::fs::remove_file(repo.join("untracked")).unwrap();
    fixture.git(&["checkout", "--detach", "-q"]);
    assert_eq!(
        fixture.capture().await.unwrap_err().cause,
        "landing_checkout_unsupported"
    );
    fixture.git(&["checkout", "-q", "main"]);
    std::fs::write(repo.join(".git/objects/info/alternates"), "/outside\n").unwrap();
    assert_eq!(
        fixture.capture().await.unwrap_err().cause,
        "landing_checkout_unsupported"
    );
}

#[cfg(not(target_os = "macos"))]
#[tokio::test]
async fn unsupported_host_never_spawns_git() {
    use std::fs;
    let parent = tempfile::tempdir().unwrap();
    let parent = parent.path().canonicalize().unwrap();
    let repo = parent.join("repo");
    let protected = parent.join("private");
    let checkouts = parent.join("checkouts");
    for directory in [&repo, &protected, &checkouts] {
        fs::create_dir(directory).unwrap();
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&checkouts, fs::Permissions::from_mode(0o700)).unwrap();
    }
    fs::create_dir_all(repo.join(".git/refs/heads")).unwrap();
    fs::create_dir_all(repo.join(".git/objects")).unwrap();
    let oid = "a".repeat(40);
    fs::write(repo.join(".git/HEAD"), "ref: refs/heads/main\n").unwrap();
    fs::write(repo.join(".git/refs/heads/main"), &oid).unwrap();
    let request = CheckoutRequest {
        repository: repo,
        protected_base: protected,
        checkouts_root: checkouts.clone(),
        git_program: parent.join("must-not-spawn"),
        expected_commit: oid,
        base_ref: "refs/heads/main".into(),
        remote_url: "https://git.example/team/repo.git".into(),
    };
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    let (_sender, mut cancel) = tokio::sync::watch::channel(false);
    let refused = capture(
        &request,
        crate::request_budget::RequestBudget::new(deadline),
        &mut cancel,
        deadline,
    )
    .await
    .unwrap_err();
    assert_eq!(refused.cause, "command_containment_unavailable");
    assert_eq!(fs::read_dir(checkouts).unwrap().count(), 0);
}
