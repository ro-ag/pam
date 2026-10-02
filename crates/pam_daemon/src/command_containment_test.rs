use std::path::PathBuf;

use crate::command_containment::{CommandContainment, profile};

struct Fixture {
    _temp: tempfile::TempDir,
    config: CommandContainment,
    program: PathBuf,
}

fn fixture() -> Fixture {
    let temp = tempfile::tempdir().unwrap();
    let base = temp.path().canonicalize().unwrap();
    let repository = base.join("repository");
    let protected_base = base.join("pam-private");
    let tools = base.join("tools");
    for path in [&repository, &protected_base, &tools] {
        std::fs::create_dir(path).unwrap();
    }
    let program = tools.join("workload");
    std::fs::write(&program, "not executed by profile tests").unwrap();
    Fixture {
        _temp: temp,
        config: CommandContainment {
            protected_base,
            repository,
            read_only_roots: vec![tools],
            allow_repository_writes: false,
            artifact_roots: Vec::new(),
        },
        program,
    }
}

#[test]
fn profile_has_no_unscoped_reads_network_or_host_services() {
    let fixture = fixture();
    let (text, program) = profile(
        &fixture.config,
        &fixture.program,
        &fixture.config.repository,
    )
    .unwrap();
    assert_eq!(program, fixture.program);
    assert!(text.contains("(deny default)"));
    assert!(!text.contains("(allow file-read*)"));
    assert!(!text.contains("(allow network"));
    assert!(!text.contains("(allow mach"));
    assert!(text.contains("(deny network*)"));
    assert!(text.contains("(deny mach-lookup)"));
    assert!(text.contains("^(/.*)?/Library/Keychains(/.*)?$"));
    assert!(text.contains("(deny file-link)"));
    assert!(text.contains("(allow signal (target self))"));
    assert!(!text.contains("(allow file-write*"));
    // The system TLS configuration is readable; the rest of /etc is not.
    assert!(text.contains("(allow file-read* file-map-executable (subpath \"/private/etc/ssl\"))"));
    assert!(!text.contains("(subpath \"/private/etc\")"));
    assert!(!text.contains("(subpath \"/etc\")"));
}

#[test]
fn repository_writes_require_explicit_effect_and_never_include_tools() {
    let mut fixture = fixture();
    fixture.config.allow_repository_writes = true;
    let (text, _) = profile(
        &fixture.config,
        &fixture.program,
        &fixture.config.repository,
    )
    .unwrap();
    let repo = serde_json::to_string(fixture.config.repository.to_str().unwrap()).unwrap();
    assert!(text.contains(&format!("(allow file-write* (subpath {repo}))")));
    assert_eq!(text.matches("(allow file-write*").count(), 1);
    let protected = serde_json::to_string(fixture.config.protected_base.to_str().unwrap()).unwrap();
    assert!(text.contains(&format!(
        "(deny file-read* file-write* file-map-executable (subpath {protected}))"
    )));
}

#[test]
fn overlapping_private_or_trusted_paths_fail_closed() {
    let fixture = fixture();
    let mut config = fixture.config.clone();
    config.repository = config.protected_base.clone();
    assert!(profile(&config, &fixture.program, &config.repository).is_err());
    let mut config = fixture.config.clone();
    config
        .read_only_roots
        .push(config.protected_base.parent().unwrap().to_path_buf());
    assert!(profile(&config, &fixture.program, &config.repository).is_err());
    let mut config = fixture.config.clone();
    config.allow_repository_writes = true;
    config.read_only_roots.push(config.repository.clone());
    assert!(profile(&config, &fixture.program, &config.repository).is_err());
}

#[test]
fn artifact_writes_cannot_overlap_source_private_data_or_toolchains() {
    let fixture = fixture();
    for forbidden in [
        &fixture.config.repository,
        &fixture.config.protected_base,
        &fixture.config.read_only_roots[0],
    ] {
        let mut config = fixture.config.clone();
        config.artifact_roots.push(forbidden.clone());
        assert!(profile(&config, &fixture.program, &config.repository).is_err());
    }
}

#[cfg(target_os = "macos")]
#[test]
fn actual_artifact_writes_leave_source_and_private_data_read_only() {
    use std::os::unix::fs::PermissionsExt;
    let mut fixture = fixture();
    let output = fixture
        .config
        .repository
        .parent()
        .unwrap()
        .join("artifacts");
    std::fs::create_dir(&output).unwrap();
    std::fs::set_permissions(&output, std::fs::Permissions::from_mode(0o700)).unwrap();
    fixture.config.artifact_roots.push(output.clone());
    fixture.config.read_only_roots.push(PathBuf::from("/bin"));
    let source = fixture.config.repository.join("tracked.txt");
    let secret = fixture.config.protected_base.join("secret");
    std::fs::write(&source, "original").unwrap();
    std::fs::write(&secret, "private").unwrap();
    let prepared = fixture
        .config
        .prepare(
            std::path::Path::new("/bin/sh"),
            &fixture.config.repository,
            &[],
        )
        .unwrap();
    let status = std::process::Command::new(prepared.program)
        .args(prepared.argv)
        .args([
            "-c",
            "printf built > \"$1/result\" && ! (printf changed > \"$2\") && ! /bin/cat \"$3\"",
            "check",
        ])
        .arg(&output)
        .arg(&source)
        .arg(&secret)
        .current_dir(&fixture.config.repository)
        .env_clear()
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .unwrap();
    assert!(status.success());
    assert_eq!(
        std::fs::read_to_string(output.join("result")).unwrap(),
        "built"
    );
    assert_eq!(std::fs::read_to_string(source).unwrap(), "original");
}

#[test]
fn missing_paths_unapproved_program_and_excess_roots_are_refused() {
    let fixture = fixture();
    assert!(
        profile(
            &fixture.config,
            &fixture.program,
            &fixture.config.protected_base
        )
        .is_err()
    );
    assert!(
        profile(
            &fixture.config,
            &fixture.program.with_extension("missing"),
            &fixture.config.repository
        )
        .is_err()
    );
    let mut config = fixture.config.clone();
    config.read_only_roots.clear();
    assert!(profile(&config, &fixture.program, &config.repository).is_err());
    config.read_only_roots = vec![fixture.config.read_only_roots[0].clone(); 17];
    assert!(profile(&config, &fixture.program, &config.repository).is_err());
}

#[cfg(unix)]
#[test]
fn symlinked_cwd_cannot_redirect_a_repo_command_into_private_state() {
    let fixture = fixture();
    let alias = fixture.config.repository.join("alias");
    std::os::unix::fs::symlink(&fixture.config.protected_base, &alias).unwrap();
    assert!(profile(&fixture.config, &fixture.program, &alias).is_err());
}

#[cfg(unix)]
#[test]
fn profile_paths_are_quoted_not_interpolated_as_policy() {
    let mut fixture = fixture();
    let repo = fixture
        .config
        .repository
        .join("quote\" ) (allow default) (\\");
    std::fs::create_dir(&repo).unwrap();
    fixture.config.repository = repo;
    let (text, _) = profile(
        &fixture.config,
        &fixture.program,
        &fixture.config.repository,
    )
    .unwrap();
    let quoted = serde_json::to_string(fixture.config.repository.to_str().unwrap()).unwrap();
    assert!(text.contains(&format!(
        "(allow file-read* file-map-executable (subpath {quoted}))"
    )));
    assert!(!text.lines().any(|line| line == "(allow default)"));
}

#[cfg(target_os = "macos")]
#[test]
fn caller_environment_is_applied_after_the_sandbox_launcher() {
    let fixture = fixture();
    let env = vec![(
        "DYLD_INSERT_LIBRARIES".to_owned(),
        "/private/payload.dylib".to_owned(),
    )];
    let prepared = fixture
        .config
        .prepare(&fixture.program, &fixture.config.repository, &env)
        .unwrap();
    assert!(
        fixture
            .config
            .prepare(
                &fixture.program,
                &fixture.config.repository,
                &[(
                    "CARGO_BIN_EXE_pam-test-helper".to_owned(),
                    "fixture".to_owned()
                )]
            )
            .is_ok()
    );
    assert_eq!(prepared.program, PathBuf::from("/usr/bin/sandbox-exec"));
    assert_eq!(prepared.argv[0], "-p");
    assert_eq!(prepared.argv[2], "/usr/bin/env");
    assert_eq!(prepared.argv[3], "-i");
    assert_eq!(prepared.argv[4], "--");
    assert_eq!(
        prepared.argv[5],
        "DYLD_INSERT_LIBRARIES=/private/payload.dylib"
    );
    assert!(
        fixture
            .config
            .prepare(
                &fixture.program,
                &fixture.config.repository,
                &[("BAD=NAME".to_owned(), "value".to_owned())]
            )
            .is_err()
    );
}

#[cfg(not(target_os = "macos"))]
#[test]
fn unsupported_platform_refuses_without_even_resolving_paths() {
    let config = CommandContainment {
        protected_base: "missing".into(),
        repository: "missing".into(),
        read_only_roots: vec![],
        allow_repository_writes: false,
        artifact_roots: Vec::new(),
    };
    let error = config
        .prepare(
            std::path::Path::new("missing"),
            std::path::Path::new("missing"),
            &[],
        )
        .unwrap_err();
    assert!(error.contains("only on macOS"));
}

/// A hand-made Git directory: enough layout for path rules, no Git process.
#[cfg(target_os = "macos")]
fn seed_git_dir(dir: &std::path::Path) {
    for sub in ["hooks", "objects", "refs/heads", "logs"] {
        std::fs::create_dir_all(dir.join(sub)).unwrap();
    }
    std::fs::write(dir.join("config"), "[core]\n\tbare = false\n").unwrap();
    std::fs::write(dir.join("HEAD"), "ref: refs/heads/main\n").unwrap();
}

/// Runs `script` under the stateful profile with the repository as `$0`'s cwd.
#[cfg(target_os = "macos")]
fn stateful_sh(fixture: &mut Fixture, script: &str) -> bool {
    fixture.config.allow_repository_writes = true;
    fixture.config.read_only_roots.push(PathBuf::from("/bin"));
    let prepared = fixture
        .config
        .prepare(
            std::path::Path::new("/bin/sh"),
            &fixture.config.repository,
            &[],
        )
        .unwrap();
    std::process::Command::new(prepared.program)
        .args(prepared.argv)
        .args(["-c", script])
        .current_dir(&fixture.config.repository)
        .env_clear()
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .unwrap()
        .success()
}

#[test]
fn git_control_surface_is_carved_out_of_repository_writes_only() {
    let mut fixture = fixture();
    let (read_only, _) = profile(
        &fixture.config,
        &fixture.program,
        &fixture.config.repository,
    )
    .unwrap();
    assert!(!read_only.contains("(deny file-write* (require-all"));
    fixture.config.allow_repository_writes = true;
    let (text, _) = profile(
        &fixture.config,
        &fixture.program,
        &fixture.config.repository,
    )
    .unwrap();
    let repo = serde_json::to_string(fixture.config.repository.to_str().unwrap()).unwrap();
    let allow = text
        .find(&format!("(allow file-write* (subpath {repo}))"))
        .unwrap();
    let denies: Vec<usize> = text
        .match_indices(&format!(
            "(deny file-write* (require-all (subpath {repo}) (regex #\""
        ))
        .map(|(at, _)| at)
        .collect();
    // SBPL applies the last matching rule, so every carve-out follows the allow.
    assert_eq!(denies.len(), 3);
    assert!(denies.iter().all(|at| *at > allow));
    for needle in [
        "[Hh][Oo][Oo][Kk][Ss]",
        "[Cc][Oo][Nn][Ff][Ii][Gg]",
        "[Cc][Oo][Mm][Mm][Oo][Nn][Dd][Ii][Rr]",
    ] {
        assert!(text.contains(needle), "{needle} missing from {text}");
    }
}

#[cfg(target_os = "macos")]
#[test]
fn stateful_writes_cannot_plant_hooks_or_rewrite_git_configuration() {
    let mut fixture = fixture();
    let repo = fixture.config.repository.clone();
    seed_git_dir(&repo.join(".git"));
    std::fs::create_dir_all(repo.join(".git/modules/vendor/lib")).unwrap();
    std::fs::create_dir(repo.join("nested")).unwrap();
    // Each attempt must fail on its own: `!` inverts, `&&` requires them all.
    let denied = [
        "printf x > .git/hooks/post-checkout",
        "printf x >> .git/config",
        "printf x > staged && mv staged .git/config",
        "printf x > .git/CONFIG",
        "printf x > .git/config.worktree",
        "printf ../evil > .git/commondir",
        "mkdir .git/modules/vendor/lib/hooks",
        "printf x > .git/modules/vendor/lib/config",
        "mv .git/hooks .git/hooks-moved",
        "mv .git .git-moved",
        "printf 'gitdir: ../evil' > nested/.git",
        "mkdir nested/.GIT",
    ];
    let script = denied
        .iter()
        .map(|attempt| format!("! ({attempt})"))
        .collect::<Vec<_>>()
        .join(" && ");
    assert!(stateful_sh(&mut fixture, &script), "{script}");
    assert_eq!(
        std::fs::read_dir(repo.join(".git/hooks")).unwrap().count(),
        0
    );
    assert_eq!(
        std::fs::read_to_string(repo.join(".git/config")).unwrap(),
        "[core]\n\tbare = false\n"
    );
    assert!(!repo.join(".git/commondir").exists());
    assert!(!repo.join("nested/.git").exists());
    assert!(repo.join(".git").is_dir());
}

#[cfg(target_os = "macos")]
#[test]
fn stateful_writes_still_reach_objects_index_refs_and_head() {
    let mut fixture = fixture();
    let repo = fixture.config.repository.clone();
    seed_git_dir(&repo.join(".git"));
    let script = "mkdir .git/objects/ab && printf blob > .git/objects/ab/cdef \
        && printf index > .git/index.lock && mv .git/index.lock .git/index \
        && printf 0000 > .git/refs/heads/main && printf 0000 > .git/refs/heads/hooks \
        && printf 0000 > .git/refs/heads/config && printf 'ref: refs/heads/hooks' > .git/HEAD \
        && printf log > .git/logs/HEAD && printf tracked > tracked.txt";
    assert!(stateful_sh(&mut fixture, script));
    assert_eq!(std::fs::read(repo.join(".git/index")).unwrap(), b"index");
    assert_eq!(
        std::fs::read(repo.join(".git/objects/ab/cdef")).unwrap(),
        b"blob"
    );
    assert_eq!(std::fs::read(repo.join("tracked.txt")).unwrap(), b"tracked");
}

/// Git as the flow tests resolve it: the real binary, not Apple's `xcrun` shim.
#[cfg(target_os = "macos")]
fn real_git() -> PathBuf {
    for installed in [
        "/Library/Developer/CommandLineTools/usr/bin/git",
        "/Applications/Xcode.app/Contents/Developer/usr/bin/git",
    ] {
        let path = PathBuf::from(installed);
        if path.is_file() {
            return path;
        }
    }
    crate::flow_exec::resolve_program("git", &[], &std::env::var_os("PATH").unwrap())
        .expect("git is installed wherever this workspace builds")
}

#[cfg(target_os = "macos")]
#[test]
fn a_real_commit_succeeds_while_git_itself_cannot_change_its_configuration() {
    let mut fixture = fixture();
    let repo = fixture.config.repository.clone();
    let git = real_git().canonicalize().unwrap();
    let host = |args: &[&str]| {
        assert!(
            std::process::Command::new(&git)
                .args(args)
                .current_dir(&repo)
                .env("GIT_CONFIG_GLOBAL", "/dev/null")
                .env("GIT_CONFIG_SYSTEM", "/dev/null")
                .output()
                .unwrap()
                .status
                .success(),
            "{args:?}"
        );
    };
    host(&["init", "-q", "."]);
    std::fs::write(repo.join("tracked.txt"), "one\n").unwrap();
    fixture.config.allow_repository_writes = true;
    fixture
        .config
        .read_only_roots
        .push(git.parent().unwrap().to_path_buf());
    for root in ["/Library/Developer", "/Applications/Xcode.app"] {
        if std::path::Path::new(root).is_dir() {
            fixture.config.read_only_roots.push(PathBuf::from(root));
        }
    }
    let env = vec![
        ("GIT_CONFIG_GLOBAL".to_owned(), "/dev/null".to_owned()),
        ("GIT_CONFIG_SYSTEM".to_owned(), "/dev/null".to_owned()),
    ];
    let contained = |args: &[&str]| {
        let prepared = fixture.config.prepare(&git, &repo, &env).unwrap();
        std::process::Command::new(prepared.program)
            .args(prepared.argv)
            .args(args)
            .current_dir(&repo)
            .env_clear()
            .output()
            .unwrap()
    };
    let identity = [
        "-c",
        "user.name=pam",
        "-c",
        "user.email=pam@example.invalid",
    ];
    assert!(contained(&["add", "tracked.txt"]).status.success());
    let commit = contained(&[&identity[..], &["commit", "-q", "-m", "first"]].concat());
    assert!(
        commit.status.success(),
        "{}",
        String::from_utf8_lossy(&commit.stderr)
    );
    // A branch whose name collides with a protected leaf is still a ref.
    assert!(contained(&["branch", "hooks"]).status.success());
    let before = std::fs::read(repo.join(".git/config")).unwrap();
    assert!(
        !contained(&["config", "core.hooksPath", "planted"])
            .status
            .success()
    );
    assert!(
        !contained(&["config", "core.fsmonitor", "./planted.sh"])
            .status
            .success()
    );
    assert_eq!(std::fs::read(repo.join(".git/config")).unwrap(), before);
    host(&["rev-parse", "--verify", "HEAD"]);
}

#[cfg(target_os = "macos")]
#[test]
fn a_gitfile_redirect_inside_the_repository_is_protected_at_its_target() {
    let mut fixture = fixture();
    let repo = fixture.config.repository.clone();
    seed_git_dir(&repo.join("meta"));
    std::fs::write(repo.join(".git"), "gitdir: meta\n").unwrap();
    let script = "! (printf x > meta/hooks/post-checkout) && ! (printf x >> meta/config) \
        && ! (printf 'gitdir: evil' > .git) && ! (mv meta meta-moved) \
        && mkdir meta/objects/ab && printf blob > meta/objects/ab/cdef \
        && printf index > meta/index";
    assert!(stateful_sh(&mut fixture, script));
    assert_eq!(
        std::fs::read_dir(repo.join("meta/hooks")).unwrap().count(),
        0
    );
    assert_eq!(std::fs::read(repo.join("meta/index")).unwrap(), b"index");
}

#[cfg(unix)]
#[test]
fn an_unresolvable_git_pointer_refuses_the_stateful_profile() {
    let mut fixture = fixture();
    fixture.config.allow_repository_writes = true;
    let dot_git = fixture.config.repository.join(".git");
    for pointer in ["gitdir: missing\n", "not a pointer\n", ""] {
        std::fs::write(&dot_git, pointer).unwrap();
        let error = profile(
            &fixture.config,
            &fixture.program,
            &fixture.config.repository,
        )
        .unwrap_err();
        assert!(
            error.contains("Git directory pointer"),
            "{pointer:?}: {error}"
        );
    }
    // A read-only step never gains repository writes, so nothing is resolved.
    fixture.config.allow_repository_writes = false;
    assert!(
        profile(
            &fixture.config,
            &fixture.program,
            &fixture.config.repository
        )
        .is_ok()
    );
    // A linked worktree: the common directory holds hooks and configuration.
    fixture.config.allow_repository_writes = true;
    let common = fixture.config.repository.join("common");
    let linked = common.join("worktrees/feature");
    std::fs::create_dir_all(&linked).unwrap();
    std::fs::write(linked.join("commondir"), "../..\n").unwrap();
    std::fs::write(&dot_git, "gitdir: common/worktrees/feature\n").unwrap();
    let (text, _) = profile(
        &fixture.config,
        &fixture.program,
        &fixture.config.repository,
    )
    .unwrap();
    for directory in [&linked, &common] {
        let quoted = serde_json::to_string(directory.to_str().unwrap()).unwrap();
        assert!(
            text.contains(&format!("(deny file-write* (literal {quoted})")),
            "{quoted} missing from {text}"
        );
    }
}
