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
