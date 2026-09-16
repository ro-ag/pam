use super::*;
use std::fmt::Write as _;
struct Allow;
impl GitAuthorization for Allow {
    fn authorize(
        &self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), GitError>> + Send + '_>>
    {
        Box::pin(async { Ok(()) })
    }
}

#[test]
fn literal_refs_and_exact_leases_cannot_expand_into_other_writes() {
    for branch in [
        "", "../main", "a:b", "a b", "a\nb", "a/*", "a.lock", "/main",
    ] {
        assert!(reference(branch).is_err());
    }
    let reference = reference("feat/checked").unwrap();
    let commit = "a".repeat(40);
    let prior = "b".repeat(40);
    let args = push_args(
        "https://git.example/team/repo.git",
        &reference,
        &commit,
        Some(&prior),
    );
    assert!(args.contains(&format!("--force-with-lease={reference}:{prior}")));
    assert_eq!(args.last().unwrap(), &format!("{commit}:{reference}"));
    assert!(args.contains(&"--no-follow-tags".into()));
    assert!(
        !args
            .iter()
            .any(|arg| arg == "--force" || arg == "--all" || arg == "--mirror")
    );
    assert!(
        push_args(
            "https://git.example/team/repo.git",
            &reference,
            &commit,
            None
        )
        .contains(&format!("--force-with-lease={reference}:"))
    );
}

#[test]
fn remote_observation_requires_exact_ref_and_one_full_commit() {
    let name = "refs/heads/main";
    let commit = "a".repeat(40);
    let accepted = Capture {
        code: Some(0),
        output: format!("{commit}\t{name}\n").into_bytes(),
        diagnostics: 0,
    };
    assert_eq!(
        parse_ref(&accepted, name).unwrap().oid.as_deref(),
        Some(commit.as_str())
    );
    for output in [
        format!("{commit}\trefs/heads/other\n"),
        format!("{commit}\t{name}\n{commit}\t{name}\n"),
        format!("short\t{name}\n"),
        "credential-sentinel from server".into(),
    ] {
        let response = Capture {
            code: Some(0),
            output: output.into_bytes(),
            diagnostics: 0,
        };
        let refusal = parse_ref(&response, name).unwrap_err();
        assert!(!refusal.to_string().contains("credential-sentinel"));
    }
    assert_eq!(
        parse_ref(
            &Capture {
                code: Some(2),
                output: vec![],
                diagnostics: 0
            },
            name
        )
        .unwrap()
        .oid,
        None
    );
    assert!(
        parse_ref(
            &Capture {
                code: Some(128),
                output: vec![],
                diagnostics: 0
            },
            name
        )
        .is_err()
    );
}

#[test]
fn reconciliation_distinguishes_unchanged_matched_and_conflicting_without_retry() {
    let prepared = PushObservation {
        ref_name: "refs/heads/feat/a".into(),
        expected_old: Some("a".repeat(40)),
        requested_commit: "b".repeat(40),
        state: PushState::Uncertain,
    };
    for (oid, expected) in [
        (Some("a".repeat(40)), Reconciliation::Unchanged),
        (Some("b".repeat(40)), Reconciliation::Matched),
        (Some("c".repeat(40)), Reconciliation::Conflicting),
        (None, Reconciliation::Conflicting),
    ] {
        let observed = RemoteRef {
            ref_name: prepared.ref_name.clone(),
            oid,
        };
        assert_eq!(reconcile(&observed, &prepared).unwrap(), expected);
    }
    assert!(
        reconcile(
            &RemoteRef {
                ref_name: "refs/heads/main".into(),
                oid: Some("b".repeat(40))
            },
            &prepared
        )
        .is_err()
    );
}

#[test]
fn ephemeral_credentials_only_enter_fixed_environment_config() {
    let parent = tempfile::tempdir().unwrap();
    let root = parent.path().canonicalize().unwrap();
    let request = CheckoutRequest {
        repository: root.join("repo"),
        protected_base: root.join("private"),
        checkouts_root: root.clone(),
        git_program: "/usr/bin/git".into(),
        expected_commit: "a".repeat(40),
        base_ref: "refs/heads/main".into(),
        remote_url: "https://git.example/team/repo.git".into(),
    };
    let config = GitTransport {
        git_exec_path: "/trusted/git-core".into(),
    };
    let workspace = Workspace::create(&root, &request.repository).unwrap();
    let deadline = Instant::now() + std::time::Duration::from_secs(10);
    let session = Session {
        config: &config,
        request: &request,
        workspace,
        credential: Secret::new("credential-sentinel".into()),
        budget: RequestBudget::new(deadline),
        deadline,
        started: Arc::new(AtomicBool::new(false)),
        authorization: Arc::new(Allow),
    };
    let command = session.command(true).unwrap();
    assert!(
        command
            .as_std()
            .get_args()
            .all(|arg| !arg.to_string_lossy().contains("credential-sentinel"))
    );
    let env: std::collections::BTreeMap<_, _> = command
        .as_std()
        .get_envs()
        .map(|(name, value)| {
            (
                name.to_string_lossy().into_owned(),
                value.unwrap().to_string_lossy().into_owned(),
            )
        })
        .collect();
    assert_eq!(env["GIT_CONFIG_GLOBAL"], "/dev/null");
    assert_eq!(env["GIT_EXEC_PATH"], "/trusted/git-core");
    assert!(!env.contains_key("HTTP_PROXY"));
    let secret_header = format!(
        "Authorization: Basic {}",
        base64(b"x-access-token:credential-sentinel")
    );
    assert!(env.values().any(|value| value == &secret_header));
    let metadata = std::fs::read_to_string(session.workspace.root.join("metadata/config")).unwrap();
    assert!(!metadata.contains("credential-sentinel"));
    assert!(!metadata.contains("Authorization"));
}

#[tokio::test]
async fn transport_pipe_captures_are_bounded_before_public_projection() {
    use tokio::io::AsyncWriteExt;
    let (mut writer, reader) = tokio::io::duplex(PIPE_LIMIT + 1);
    writer.write_all(&vec![b'x'; PIPE_LIMIT + 1]).await.unwrap();
    drop(writer);
    assert!(pipe(reader).await.is_err());
}

#[test]
fn outbound_preflight_requires_exact_bounded_object_identity_and_size() {
    let id = "a".repeat(40);
    let ids = vec![id.clone()];
    let valid = Capture {
        code: Some(0),
        output: format!("{id} blob 1024\n").into_bytes(),
        diagnostics: 0,
    };
    assert_eq!(outbound_sizes(&ids, &valid).unwrap(), 1024);
    for output in [
        format!("{id} missing\n"),
        format!("{} blob 1024\n", "b".repeat(40)),
        format!("{id} blob {}\n", 4 * 1024 * 1024 + 1),
    ] {
        assert!(
            outbound_sizes(
                &ids,
                &Capture {
                    code: Some(0),
                    output: output.into_bytes(),
                    diagnostics: 0
                }
            )
            .is_err()
        );
    }
    let mut many = String::new();
    for n in 1..=MAX_OUTBOUND_OBJECTS + 1 {
        let _ = writeln!(many, "{n:040x}");
    }
    assert_eq!(
        outbound_ids(&Capture {
            code: Some(0),
            output: many.into_bytes(),
            diagnostics: 0
        })
        .unwrap_err()
        .cause,
        "landing_git_outbound_limit"
    );
    let ids = (1..=17).map(|n| format!("{n:040x}")).collect::<Vec<_>>();
    let mut output = String::new();
    for id in &ids {
        let _ = writeln!(output, "{id} blob {}", 4 * 1024 * 1024);
    }
    assert_eq!(
        outbound_sizes(
            &ids,
            &Capture {
                code: Some(0),
                output: output.into_bytes(),
                diagnostics: 0
            }
        )
        .unwrap_err()
        .cause,
        "landing_git_outbound_limit"
    );
}

#[test]
fn pat_basic_encoding_has_known_padding_and_no_raw_secret_output() {
    assert_eq!(base64(b""), "");
    assert_eq!(base64(b"f"), "Zg==");
    assert_eq!(base64(b"fo"), "Zm8=");
    assert_eq!(base64(b"foo"), "Zm9v");
    assert!(!uncertain().to_string().contains("credential-sentinel"));
}

struct Deny(AtomicBool);
impl GitAuthorization for Deny {
    fn authorize(
        &self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), GitError>> + Send + '_>>
    {
        Box::pin(async {
            self.0.store(true, Ordering::SeqCst);
            Err(error(
                "landing_authorization_changed",
                "authorization changed",
            ))
        })
    }
}
#[tokio::test]
async fn fresh_authorization_refuses_before_any_network_process_can_spawn() {
    let parent = tempfile::tempdir().unwrap();
    let root = parent.path().canonicalize().unwrap();
    let request = CheckoutRequest {
        repository: root.join("repo"),
        protected_base: root.join("private"),
        checkouts_root: root.clone(),
        git_program: root.join("must-not-spawn"),
        expected_commit: "a".repeat(40),
        base_ref: "refs/heads/main".into(),
        remote_url: "https://git.example/team/repo.git".into(),
    };
    let config = GitTransport {
        git_exec_path: root.join("trusted"),
    };
    let deadline = Instant::now() + std::time::Duration::from_secs(10);
    let guard = Arc::new(Deny(AtomicBool::new(false)));
    let started = Arc::new(AtomicBool::new(false));
    let session = Session {
        config: &config,
        request: &request,
        workspace: Workspace::create(&root, &request.repository).unwrap(),
        credential: Secret::new("fixture-only".into()),
        budget: RequestBudget::new(deadline),
        deadline,
        started: started.clone(),
        authorization: guard.clone(),
    };
    session.disconnect_source().unwrap();
    let (_sender, mut cancel) = watch::channel(false);
    let refused = session
        .run(
            &read_args(&request.remote_url, "refs/heads/main"),
            true,
            false,
            &mut cancel,
        )
        .await
        .err()
        .unwrap();
    assert_eq!(refused.cause, "landing_authorization_changed");
    assert!(guard.0.load(Ordering::SeqCst));
    assert!(!started.load(Ordering::SeqCst));
    // Earlier reads consume the original allowance; a later push cannot reset it.
    drop(
        session
            .budget
            .http_persisted(60 * 1024 * 1024)
            .await
            .unwrap(),
    );
    guard.0.store(false, Ordering::SeqCst);
    let refused = session
        .authorize_network(true, &mut cancel)
        .await
        .unwrap_err();
    assert_eq!(refused.cause, "request_budget_exhausted");
    assert!(!guard.0.load(Ordering::SeqCst));
    assert!(!started.load(Ordering::SeqCst));
}

#[cfg(target_os = "macos")]
fn local_object_fixture(parent: &Path) -> CheckoutRequest {
    use std::os::unix::fs::PermissionsExt;
    let repo = parent.join("repo");
    let private = parent.join("private");
    let checkouts = parent.join("checkouts");
    for path in [&repo, &private, &checkouts] {
        fs::create_dir(path).unwrap();
    }
    fs::set_permissions(&checkouts, fs::Permissions::from_mode(0o700)).unwrap();
    let git = PathBuf::from("/Library/Developer/CommandLineTools/usr/bin/git");
    let run = |args: &[&str]| {
        let output = std::process::Command::new(&git)
            .args(args)
            .current_dir(&repo)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .output()
            .unwrap();
        assert!(output.status.success(), "fixture Git failed");
        String::from_utf8(output.stdout).unwrap()
    };
    run(&["init", "-q", "-b", "main"]);
    run(&["config", "user.name", "Fixture"]);
    run(&["config", "user.email", "fixture@example.invalid"]);
    fs::write(repo.join("file"), "tracked\n").unwrap();
    run(&["add", "file"]);
    run(&["-c", "commit.gpgsign=false", "commit", "-qm", "fixture"]);
    let expected_commit = run(&["rev-parse", "HEAD"]).trim().to_owned();
    CheckoutRequest {
        repository: repo,
        protected_base: private,
        checkouts_root: checkouts,
        git_program: git,
        expected_commit,
        base_ref: "refs/heads/main".into(),
        remote_url: "https://git.example/team/repo.git".into(),
    }
}

#[cfg(target_os = "macos")]
#[tokio::test]
async fn local_preflight_copies_a_verified_pack_and_disconnects_source_objects() {
    let parent = tempfile::tempdir().unwrap();
    let request = local_object_fixture(&parent.path().canonicalize().unwrap());
    let deadline = Instant::now() + std::time::Duration::from_secs(30);
    let budget = RequestBudget::new(deadline);
    let (_sender, mut cancel) = watch::channel(false);
    let config = GitTransport::resolve(&request, budget.clone(), &mut cancel, deadline)
        .await
        .unwrap();
    let runtime = tokio::runtime::Handle::current();
    landing_checkout::owned_worker(&mut cancel, move |mut cancelled| {
        let workspace = Workspace::create(&request.checkouts_root, &request.repository)?;
        let session = Session {
            config: &config,
            request: &request,
            workspace,
            credential: Secret::new("unused".into()),
            budget: budget.clone(),
            deadline,
            started: Arc::new(AtomicBool::new(false)),
            authorization: Arc::new(Allow),
        };
        runtime.block_on(async {
            session.isolate_objects(None, &mut cancelled).await?;
            assert!(
                !session
                    .workspace
                    .root
                    .join("metadata/objects/info/alternates")
                    .exists()
            );
            fs::rename(
                request.repository.join(".git/objects"),
                request.repository.join(".git/source-objects-removed"),
            )
            .unwrap();
            let verified = session
                .run(
                    &[
                        "cat-file".into(),
                        "-e".into(),
                        format!("{}^{{commit}}", request.expected_commit),
                    ],
                    false,
                    false,
                    &mut cancelled,
                )
                .await?;
            assert_eq!(verified.code, Some(0));
            assert_eq!(
                budget.usage().http_calls,
                0,
                "local preparation never opens a network transaction"
            );
            Ok(())
        })
    })
    .await
    .unwrap();
}

#[test]
fn projection_boundary_parser_requires_complete_bounded_commit_identities() {
    let old = "a".repeat(40);
    let new = "b".repeat(40);
    let second = "c".repeat(40);
    let capture = |text: String| Capture {
        code: Some(0),
        output: text.into_bytes(),
        diagnostics: 0,
    };
    assert_eq!(
        projection_boundaries(&capture(format!("{new}\n-{old}\n-{second}\n")), &old, &new).unwrap(),
        vec![old.clone(), second]
    );
    assert_eq!(
        projection_boundaries(&capture(String::new()), &old, &old).unwrap(),
        vec![old.clone()]
    );
    for text in [
        format!("{new}\n"),
        format!("-{old}\n"),
        format!("{new}\n-{old}\n-{old}\n"),
        format!("{new}\n-malformed\n"),
    ] {
        assert!(projection_boundaries(&capture(text), &old, &new).is_err());
    }
}

#[cfg(target_os = "macos")]
fn projection_git(path: &Path, args: &[&str]) -> std::process::Output {
    std::process::Command::new("/Library/Developer/CommandLineTools/usr/bin/git")
        .args([
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "commit.gpgsign=false",
            "-c",
            "protocol.file.allow=always",
        ])
        .args(args)
        .current_dir(path)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .output()
        .unwrap()
}
#[cfg(target_os = "macos")]
fn projection_git_ok(path: &Path, args: &[&str]) -> String {
    let output = projection_git(path, args);
    assert!(
        output.status.success(),
        "local fixture Git failed: {args:?}"
    );
    String::from_utf8(output.stdout).unwrap().trim().to_owned()
}

#[cfg(target_os = "macos")]
fn merge_projection_fixture(parent: &Path) -> (CheckoutRequest, String, String, PathBuf) {
    let mut request = local_object_fixture(parent);
    let repo = &request.repository;
    let ancestor = request.expected_commit.clone();
    for index in 0..5 {
        fs::write(repo.join("file"), format!("history{index}")).unwrap();
        projection_git_ok(repo, &["add", "."]);
        projection_git_ok(repo, &["commit", "-qm", "history"]);
    }
    let old = projection_git_ok(repo, &["rev-parse", "HEAD"]);
    let remote = parent.join("remote.git");
    projection_git_ok(
        parent,
        &[
            "clone",
            "--bare",
            "--no-hardlinks",
            repo.to_str().unwrap(),
            remote.to_str().unwrap(),
        ],
    );
    projection_git_ok(repo, &["checkout", "-qb", "side", &ancestor]);
    fs::write(repo.join("side"), "side content").unwrap();
    projection_git_ok(repo, &["add", "."]);
    projection_git_ok(repo, &["commit", "-qm", "side"]);
    projection_git_ok(repo, &["checkout", "-q", "main"]);
    projection_git_ok(repo, &["merge", "--no-ff", "-qm", "merge side", "side"]);
    request.expected_commit = projection_git_ok(repo, &["rev-parse", "HEAD"]);
    (request, old, ancestor, remote)
}

#[cfg(target_os = "macos")]
#[tokio::test]
async fn incremental_projection_cuts_history_preserves_merge_trees_and_exact_lease() {
    let parent = tempfile::tempdir().unwrap();
    let parent = parent.path().canonicalize().unwrap();
    let (request, old, ancestor, remote) = merge_projection_fixture(&parent);
    let deadline = Instant::now() + std::time::Duration::from_secs(30);
    let budget = RequestBudget::new(deadline);
    let (_sender, mut cancel) = watch::channel(false);
    let config = GitTransport::resolve(&request, budget.clone(), &mut cancel, deadline)
        .await
        .unwrap();
    let runtime = tokio::runtime::Handle::current();
    landing_checkout::owned_worker(&mut cancel, move |mut cancelled| {
        let session = Session {
            config: &config,
            request: &request,
            workspace: Workspace::create(&request.checkouts_root, &request.repository)?,
            credential: Secret::new("unused".into()),
            budget: budget.clone(),
            deadline,
            started: Arc::new(AtomicBool::new(false)),
            authorization: Arc::new(Allow),
        };
        runtime.block_on(async {
            session.isolate_objects(Some(&old), &mut cancelled).await?;
            let metadata = session.workspace.root.join("metadata");
            let shallow = fs::read_to_string(metadata.join("shallow")).unwrap();
            assert_eq!(
                shallow.lines().count(),
                2,
                "both merge boundaries must be retained"
            );
            assert!(shallow.lines().any(|id| id == old));
            assert!(shallow.lines().any(|id| id == ancestor));
            assert!(!metadata.join("objects/info/alternates").exists());
            fs::rename(
                request.repository.join(".git/objects"),
                request.repository.join(".git/disconnected"),
            )
            .unwrap();
            projection_git_ok(
                &metadata,
                &["fsck", "--strict", "--no-reflogs", &request.expected_commit],
            );
            let lease = format!("--force-with-lease=refs/heads/main:{old}");
            let refspec = format!("{}:refs/heads/main", request.expected_commit);
            projection_git_ok(
                &metadata,
                &[
                    "push",
                    "--porcelain",
                    &lease,
                    remote.to_str().unwrap(),
                    &refspec,
                ],
            );
            assert_eq!(
                projection_git_ok(&remote, &["rev-parse", "refs/heads/main"]),
                request.expected_commit
            );
            let stale = projection_git(
                &metadata,
                &[
                    "push",
                    "--porcelain",
                    &lease,
                    remote.to_str().unwrap(),
                    &format!("{old}:refs/heads/main"),
                ],
            );
            assert!(!stale.status.success());
            assert_eq!(
                projection_git_ok(&remote, &["rev-parse", "refs/heads/main"]),
                request.expected_commit
            );
            assert_eq!(
                budget.usage().http_calls,
                0,
                "projection itself is network-free"
            );
            Ok(())
        })
    })
    .await
    .unwrap();
}

/// A source repository on `feature/work` (base `main` at one commit), a
/// remote clone that advanced `main` by one squash commit, and a thin pack
/// carrying exactly that advance — the shape sync sees after `verify_main`.
#[cfg(target_os = "macos")]
fn sync_fixture(parent: &Path) -> (CheckoutRequest, CheckoutReceipt, String, String, Vec<u8>) {
    let request = local_object_fixture(parent);
    let git = request.git_program.clone();
    let run = |dir: &Path, args: &[&str], stdin: &str| -> Vec<u8> {
        use std::io::Write as _;
        let mut child = std::process::Command::new(&git)
            .args(args)
            .current_dir(dir)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(stdin.as_bytes())
            .unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "fixture git {args:?} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        output.stdout
    };
    let text = |bytes: Vec<u8>| String::from_utf8(bytes).unwrap().trim().to_owned();
    let repo = request.repository.clone();
    let base = request.expected_commit.clone();
    // The frozen head: one commit on feature/work, checked out.
    run(&repo, &["checkout", "-q", "-b", "feature/work"], "");
    fs::write(repo.join("file"), "tracked\nchanged\n").unwrap();
    run(&repo, &["add", "file"], "");
    run(
        &repo,
        &["-c", "commit.gpgsign=false", "commit", "-qm", "feature"],
        "",
    );
    let head = text(run(&repo, &["rev-parse", "HEAD"], ""));
    let tree = text(run(&repo, &["rev-parse", "HEAD^{tree}"], ""));
    // The remote: main advanced by a squash of that tree onto base.
    let remote = parent.join("remote");
    run(
        parent,
        &[
            "-c",
            "protocol.file.allow=always",
            "clone",
            "-q",
            repo.to_str().unwrap(),
            remote.to_str().unwrap(),
        ],
        "",
    );
    let merge = text(run(
        &remote,
        &[
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "-c",
            "commit.gpgsign=false",
            "commit-tree",
            &tree,
            "-p",
            &base,
            "-m",
            "squash",
        ],
        "",
    ));
    run(&remote, &["update-ref", "refs/heads/main", &merge], "");
    let pack = run(
        &remote,
        &["pack-objects", "--revs", "--thin", "--stdout", "-q"],
        &format!("{merge}\n^{base}\n^{head}\n"),
    );
    let request = CheckoutRequest {
        expected_commit: head.clone(),
        ..request
    };
    let receipt = CheckoutReceipt {
        repository: repo,
        remote_url: request.remote_url.clone(),
        branch: "refs/heads/feature/work".into(),
        commit: head,
        base_ref: "refs/heads/main".into(),
        base_commit: base.clone(),
        tree,
        manifest: Vec::new(),
        manifest_sha256: String::new(),
    };
    (request, receipt, base, merge, pack)
}

#[cfg(target_os = "macos")]
fn sync_limits() -> crate::landing_pack::PackLimits {
    crate::landing_pack::PackLimits {
        max_objects: 16_384,
        max_object_bytes: 4 * 1024 * 1024,
        max_expanded_bytes: 64 * 1024 * 1024,
    }
}
/// Runs the source repository's own Git (scrubbed environment) and reports success.
#[cfg(target_os = "macos")]
fn source_git_ok(request: &CheckoutRequest, args: &[&str]) -> bool {
    std::process::Command::new(&request.git_program)
        .args(args)
        .current_dir(&request.repository)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .status()
        .unwrap()
        .success()
}

#[cfg(target_os = "macos")]
#[tokio::test]
async fn sync_installs_the_pack_and_fast_forwards_only_the_base_ref() {
    let parent = tempfile::tempdir().unwrap();
    let parent = parent.path().canonicalize().unwrap();
    let (request, receipt, base, merge, pack) = sync_fixture(&parent);
    let bounds = crate::landing_pack::preflight_pack(&pack, sync_limits()).unwrap();
    assert!(bounds.objects > 0);
    let deadline = Instant::now() + std::time::Duration::from_secs(60);
    let budget = RequestBudget::new(deadline);
    let (_sender, mut cancel) = watch::channel(false);
    let config = GitTransport::resolve(&request, budget.clone(), &mut cancel, deadline)
        .await
        .unwrap();
    let target = GitTarget {
        request: request.clone(),
        receipt,
        branch: "main".into(),
        expected_old: Some(base.clone()),
    };

    // A stale lease refuses before any effect.
    let stale = GitTarget {
        expected_old: Some("1".repeat(40)),
        ..target.clone()
    };
    let refused = config
        .sync_exact(
            &stale,
            &merge,
            pack.clone(),
            bounds.clone(),
            budget.clone(),
            &mut cancel,
            deadline,
            Arc::new(Allow),
        )
        .await
        .unwrap_err();
    assert_eq!(refused.cause, "landing_checkout_changed");
    assert_eq!(
        landing_checkout::resolve_local_ref(&request, "refs/heads/main").unwrap(),
        base
    );

    let observed = config
        .sync_exact(
            &target,
            &merge,
            pack.clone(),
            bounds.clone(),
            budget.clone(),
            &mut cancel,
            deadline,
            Arc::new(Allow),
        )
        .await
        .unwrap();
    assert_eq!(observed.requested_commit, merge);
    assert_eq!(observed.expected_old, base);
    assert!(observed.pack.starts_with("pack-"));
    assert_eq!(observed.bounds, bounds);
    // Exactly the two promised effects: the pack and the base ref.
    let pack_dir = request.repository.join(".git/objects/pack");
    assert!(pack_dir.join(format!("{}.pack", observed.pack)).is_file());
    assert!(pack_dir.join(format!("{}.idx", observed.pack)).is_file());
    assert!(
        !fs::read_dir(&pack_dir).unwrap().any(|e| e
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with("tmp_"))
    );
    assert_eq!(
        landing_checkout::resolve_local_ref(&request, "refs/heads/main").unwrap(),
        merge
    );
    assert_eq!(
        landing_checkout::head_branch(&request).unwrap(),
        "refs/heads/feature/work"
    );
    assert_eq!(
        fs::read_to_string(request.repository.join("file")).unwrap(),
        "tracked\nchanged\n"
    );
    let reflog = fs::read_to_string(request.repository.join(".git/logs/refs/heads/main")).unwrap();
    assert!(reflog.ends_with("\tpam guarded-land sync\n"));
    assert!(reflog.contains(&format!("{base} {merge} ")));
    assert_eq!(
        budget.usage().http_calls,
        0,
        "sync installation never opens a network transaction"
    );
    // The source repository can read the merge commit through its own Git.
    assert!(source_git_ok(
        &request,
        &["merge-base", "--is-ancestor", &base, &merge]
    ));
}

#[cfg(target_os = "macos")]
#[tokio::test]
async fn sync_refuses_a_checked_out_base_and_a_non_fast_forward() {
    let parent = tempfile::tempdir().unwrap();
    let parent = parent.path().canonicalize().unwrap();
    let (request, receipt, base, merge, pack) = sync_fixture(&parent);
    let bounds = crate::landing_pack::preflight_pack(&pack, sync_limits()).unwrap();
    let deadline = Instant::now() + std::time::Duration::from_secs(60);
    let budget = RequestBudget::new(deadline);
    let (_sender, mut cancel) = watch::channel(false);
    let config = GitTransport::resolve(&request, budget.clone(), &mut cancel, deadline)
        .await
        .unwrap();
    let target = GitTarget {
        request: request.clone(),
        receipt,
        branch: "main".into(),
        expected_old: Some(base.clone()),
    };

    // The frozen head is not an ancestor of the base: no fast-forward, no effect.
    let backwards = GitTarget {
        expected_old: Some(request.expected_commit.clone()),
        ..target.clone()
    };
    fs::write(
        request.repository.join(".git/refs/heads/main"),
        format!("{}\n", request.expected_commit),
    )
    .unwrap();
    let refused = config
        .sync_exact(
            &backwards,
            &merge,
            pack.clone(),
            bounds.clone(),
            budget.clone(),
            &mut cancel,
            deadline,
            Arc::new(Allow),
        )
        .await
        .unwrap_err();
    assert_eq!(refused.cause, "landing_sync_ancestry_unproven");
    assert!(
        !request.repository.join(".git/objects/pack").exists()
            || fs::read_dir(request.repository.join(".git/objects/pack"))
                .unwrap()
                .all(|e| !e.unwrap().file_name().to_string_lossy().ends_with(".idx"))
    );
    fs::write(
        request.repository.join(".git/refs/heads/main"),
        format!("{base}\n"),
    )
    .unwrap();

    // The base branch checked out: sync never writes the working tree.
    fs::write(
        request.repository.join(".git/HEAD"),
        "ref: refs/heads/main\n",
    )
    .unwrap();
    let refused = config
        .sync_exact(
            &target,
            &merge,
            pack,
            bounds,
            budget,
            &mut cancel,
            deadline,
            Arc::new(Allow),
        )
        .await
        .unwrap_err();
    assert_eq!(refused.cause, "landing_sync_base_checked_out");
    assert_eq!(
        landing_checkout::resolve_local_ref(&request, "refs/heads/main").unwrap(),
        base
    );
}

#[test]
fn a_journalled_sync_intent_reconciles_like_a_push_intent() {
    // The runtime journals the sync lease with snake_case state, the pack
    // bounds and later the pack name; the shared reconcile rule must read it.
    let intent = serde_json::json!({
        "ref_name": "refs/heads/main",
        "expected_old": "a".repeat(40),
        "requested_commit": "b".repeat(40),
        "state": "uncertain",
        "bounds": {"objects": 3, "deltas": 1, "compressed_bytes": 300, "decoded_bytes": 200, "expanded_bytes": 250},
        "pack": "pack-cafe",
    });
    let prepared: PushObservation = serde_json::from_value(intent).unwrap();
    assert_eq!(prepared.state, PushState::Uncertain);
    let observed = RemoteRef {
        ref_name: "refs/heads/main".into(),
        oid: Some("b".repeat(40)),
    };
    assert_eq!(
        reconcile(&observed, &prepared).unwrap(),
        Reconciliation::Matched
    );
}

#[test]
fn a_journalled_rejected_verdict_reads_back_and_reconciles_as_unchanged() {
    // The runtime journals the process verdict after `git push` returns;
    // a resume after a crash must read `rejected` back by its wire name.
    let intent = serde_json::json!({
        "ref_name": "refs/heads/feat/a",
        "expected_old": "a".repeat(40),
        "requested_commit": "b".repeat(40),
        "state": "rejected",
    });
    let prepared: PushObservation = serde_json::from_value(intent).unwrap();
    assert_eq!(prepared.state, PushState::Rejected);
    assert_eq!(
        serde_json::to_value(PushState::Rejected).unwrap(),
        serde_json::json!("rejected")
    );
    let observed = RemoteRef {
        ref_name: "refs/heads/feat/a".into(),
        oid: Some("a".repeat(40)),
    };
    assert_eq!(
        reconcile(&observed, &prepared).unwrap(),
        Reconciliation::Unchanged
    );
}
