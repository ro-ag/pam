use std::ffi::OsStr;
#[cfg(unix)]
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::curator::{AgentCli, AgentId, CuratorError, detect, invoke, invoke_args};
#[cfg(unix)]
use crate::curator::{trusted_dirs, untrusted_reason};

/// Long enough that a script which answers immediately always makes it,
/// short enough that a hung one does not stall the suite.
const PROBE_DEADLINE: Duration = Duration::from_secs(10);

/// What a stand-in CLI does when it runs.
#[derive(Clone, Copy)]
enum Fake {
    /// Print a version line and exit 0.
    Version,
    /// Copy stdin to stdout.
    EchoStdin,
    /// Print the arguments it was given.
    EchoArgs,
    /// Outlive any deadline a test would set.
    Sleep,
    /// Complain on stderr and exit 3.
    Fail,
}

/// The file name a stand-in for `stem` needs to be found on this platform.
///
/// Windows has no executable bit; the extension is what makes a file
/// runnable, and `.cmd` is the one a script can be written in.
fn fake_name(stem: &str) -> String {
    if cfg!(windows) {
        format!("{stem}.cmd")
    } else {
        stem.to_owned()
    }
}

/// The script body for `fake`, in the shell this platform actually has.
fn script(fake: Fake) -> String {
    let body = if cfg!(windows) {
        match fake {
            Fake::Version => "@echo off\r\necho 1.2.3\r\necho trailing line\r\n",
            // `findstr` with a match-anything pattern and no file operand
            // copies stdin to stdout.
            Fake::EchoStdin => "@echo off\r\nfindstr /r \"^\"\r\n",
            Fake::EchoArgs => "@echo off\r\necho %*\r\n",
            // `timeout` needs a console; `ping` does not. Kept short: a
            // Windows child's pipe handles are read on a blocking thread,
            // and dropping them after a deadline waits for the read in
            // flight — which ends when the script does.
            Fake::Sleep => "@echo off\r\nping -n 6 127.0.0.1 > nul\r\n",
            Fake::Fail => "@echo off\r\necho boom from the fake cli 1>&2\r\nexit /b 3\r\n",
        }
    } else {
        match fake {
            Fake::Version => "#!/bin/sh\necho '1.2.3'\necho 'trailing line'\n",
            Fake::EchoStdin => "#!/bin/sh\ncat\n",
            Fake::EchoArgs => "#!/bin/sh\necho \"$@\"\n",
            Fake::Sleep => "#!/bin/sh\nsleep 5\n",
            Fake::Fail => "#!/bin/sh\necho 'boom from the fake cli' >&2\nexit 3\n",
        }
    };
    body.to_owned()
}

/// Write an executable stand-in for `stem` into `dir`.
fn write_fake(dir: &Path, stem: &str, fake: Fake) -> PathBuf {
    let path = dir.join(fake_name(stem));
    std::fs::write(&path, script(fake)).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    path
}

/// [`invoke`] against a stand-in that was written moments ago.
///
/// On Unix a script written by this thread can still be held open, for
/// a few microseconds, by a child another test thread forked but has not
/// exec'd yet (the write descriptor is `O_CLOEXEC`, so it dies at the
/// child's exec, not at the fork). Executing it in that window fails
/// with `ETXTBSY` ("Text file busy") — a race in the test harness, not
/// in the curator, so it is retried briefly here rather than widened
/// into a production retry the real agent CLIs never need.
async fn invoke_fresh(
    cli: &AgentCli,
    prompt: &str,
    deadline: Duration,
) -> Result<String, CuratorError> {
    for _ in 0..50 {
        match invoke(cli, prompt, deadline).await {
            Err(CuratorError::Io(err)) if err.kind() == std::io::ErrorKind::ExecutableFileBusy => {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            other => return other,
        }
    }
    invoke(cli, prompt, deadline).await
}

/// [`detect`] over `dirs` as the trusted set (an empty `PATH`), found CLIs only.
fn detect_in(dirs: &[&Path], deadline: Duration) -> Vec<AgentCli> {
    let trusted: Vec<PathBuf> = dirs.iter().map(|dir| dir.to_path_buf()).collect();
    detect(&trusted, OsStr::new(""), deadline).found
}

/// [`detect_in`] with the ETXTBSY harness race retried: a script this test
/// just wrote can still be held open by another test thread's
/// forked-but-not-yet-exec'd child, and `probe_version` reports that
/// spawn failure as `None`. Retry briefly until every version is known;
/// a real probe failure still surfaces after the bound.
fn detect_fresh(dirs: &[&Path], deadline: Duration) -> Vec<AgentCli> {
    for _ in 0..50 {
        let found = detect_in(dirs, deadline);
        if found.iter().all(|cli| cli.version.is_some()) {
            return found;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    detect_in(dirs, deadline)
}

/// A `PATH` value covering exactly `dirs`.
#[cfg(unix)]
fn path_env(dirs: &[&Path]) -> OsString {
    std::env::join_paths(dirs).unwrap()
}

/// An `AgentCli` pointing at a stand-in script.
fn cli_at(id: AgentId, path: &Path) -> AgentCli {
    AgentCli {
        id,
        path: path.to_path_buf(),
        version: None,
    }
}

#[test]
fn detect_finds_a_cli_and_keeps_the_first_version_line() {
    let dir = tempfile::tempdir().unwrap();
    let script = write_fake(dir.path(), "claude", Fake::Version);

    let found = detect_fresh(&[dir.path()], PROBE_DEADLINE);

    assert_eq!(found.len(), 1);
    assert_eq!(found[0].id, AgentId::Claude);
    assert_eq!(found[0].version.as_deref(), Some("1.2.3"));
    assert_eq!(found[0].path, script.canonicalize().unwrap());
}

#[test]
fn detect_finds_every_installed_agent_in_order() {
    let dir = tempfile::tempdir().unwrap();
    write_fake(dir.path(), "gemini", Fake::Version);
    write_fake(dir.path(), "claude", Fake::Version);
    write_fake(dir.path(), "copilot", Fake::Version);

    let found = detect_in(&[dir.path()], PROBE_DEADLINE);

    let ids: Vec<AgentId> = found.iter().map(|cli| cli.id).collect();
    assert_eq!(
        ids,
        vec![AgentId::Claude, AgentId::Copilot, AgentId::Gemini],
        "detection order follows AgentId::ALL, not the directory listing"
    );
}

#[test]
fn detect_skips_a_file_the_os_would_not_run() {
    let dir = tempfile::tempdir().unwrap();
    // No executable bit on Unix; no executable extension on Windows.
    std::fs::write(dir.path().join("claude"), "#!/bin/sh\necho 1.2.3\n").unwrap();

    assert!(detect_in(&[dir.path()], PROBE_DEADLINE).is_empty());
}

#[test]
fn detect_skips_a_directory_wearing_the_name() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir(dir.path().join(fake_name("codex"))).unwrap();

    assert!(detect_in(&[dir.path()], PROBE_DEADLINE).is_empty());
}

#[test]
fn detect_takes_the_first_match_in_trust_order() {
    let first = tempfile::tempdir().unwrap();
    let second = tempfile::tempdir().unwrap();
    let winner = write_fake(first.path(), "codex", Fake::Version);
    write_fake(second.path(), "codex", Fake::Version);

    let found = detect_in(&[first.path(), second.path()], PROBE_DEADLINE);

    assert_eq!(found.len(), 1);
    assert_eq!(found[0].path, winner.canonicalize().unwrap());
}

#[test]
fn detect_with_no_trusted_directories_finds_nothing() {
    assert!(detect_in(&[], PROBE_DEADLINE).is_empty());
}

#[test]
fn detect_reports_a_cli_that_will_not_say_its_version() {
    let dir = tempfile::tempdir().unwrap();
    write_fake(dir.path(), "copilot", Fake::Fail);

    let found = detect_in(&[dir.path()], PROBE_DEADLINE);

    assert_eq!(found.len(), 1);
    assert_eq!(found[0].id, AgentId::Copilot);
    assert_eq!(
        found[0].version, None,
        "a CLI that fails --version is still a CLI PAM can call"
    );
}

#[test]
fn detect_does_not_wait_forever_for_a_version() {
    let dir = tempfile::tempdir().unwrap();
    write_fake(dir.path(), "gemini", Fake::Sleep);

    let found = detect_in(&[dir.path()], Duration::from_millis(200));

    assert_eq!(found.len(), 1);
    assert_eq!(found[0].version, None);
}

#[tokio::test]
async fn invoke_returns_what_the_agent_said_on_stdin() {
    let dir = tempfile::tempdir().unwrap();
    let script = write_fake(dir.path(), "claude", Fake::EchoStdin);
    let cli = cli_at(AgentId::Claude, &script);

    let answer = invoke_fresh(&cli, "Reply with the single word OK.", PROBE_DEADLINE)
        .await
        .unwrap();

    assert_eq!(answer, "Reply with the single word OK.");
}

#[tokio::test]
async fn invoke_passes_the_prompt_as_an_argument_when_the_agent_wants_it() {
    let dir = tempfile::tempdir().unwrap();
    let script = write_fake(dir.path(), "gemini", Fake::EchoArgs);
    let cli = cli_at(AgentId::Gemini, &script);

    let answer = invoke_fresh(&cli, "Reply with the single word OK.", PROBE_DEADLINE)
        .await
        .unwrap();

    assert!(answer.contains("--prompt"), "got {answer:?}");
    assert!(
        answer.contains("Reply with the single word OK."),
        "got {answer:?}"
    );
}

#[tokio::test]
async fn invoke_times_out_and_kills_the_child() {
    let dir = tempfile::tempdir().unwrap();
    let script = write_fake(dir.path(), "codex", Fake::Sleep);
    let cli = cli_at(AgentId::Codex, &script);

    let deadline = Duration::from_millis(200);
    let failure = invoke_fresh(&cli, "anything", deadline).await.unwrap_err();

    match failure {
        CuratorError::Timeout(id, waited) => {
            assert_eq!(id, AgentId::Codex);
            assert_eq!(waited, deadline);
        }
        other => panic!("expected a timeout, got {other:?}"),
    }
}

#[tokio::test]
async fn invoke_reports_the_exit_code_and_the_complaint() {
    let dir = tempfile::tempdir().unwrap();
    let script = write_fake(dir.path(), "copilot", Fake::Fail);
    let cli = cli_at(AgentId::Copilot, &script);

    let failure = invoke_fresh(&cli, "anything", PROBE_DEADLINE)
        .await
        .unwrap_err();

    match failure {
        CuratorError::Failed(id, code, detail) => {
            assert_eq!(id, AgentId::Copilot);
            assert_eq!(code, 3);
            assert!(detail.contains("boom from the fake cli"), "got {detail:?}");
        }
        other => panic!("expected a failure, got {other:?}"),
    }
    assert_eq!(
        CuratorError::Failed(AgentId::Copilot, 3, "boom".to_owned()).to_string(),
        "copilot exited with 3: boom"
    );
}

#[tokio::test]
async fn invoke_on_a_binary_that_cannot_be_spawned_is_an_io_error() {
    let dir = tempfile::tempdir().unwrap();
    // Deliberately extension-less: Windows runs a `.cmd` through `cmd.exe`,
    // which spawns fine and then reports the missing script as its own
    // exit 1, so a `.cmd` path would prove nothing about the spawn error.
    let cli = cli_at(AgentId::Claude, &dir.path().join("no-such-agent"));

    let failure = invoke_fresh(&cli, "anything", PROBE_DEADLINE)
        .await
        .unwrap_err();

    assert!(matches!(failure, CuratorError::Io(_)), "got {failure:?}");
}

#[test]
fn invoke_args_are_non_interactive_and_tool_free() {
    let (claude, claude_stdin) = invoke_args(AgentId::Claude, "hello");
    assert_eq!(
        claude,
        vec![
            "--print",
            "--output-format",
            "text",
            "--no-session-persistence",
            "--permission-mode",
            "plan",
            "--tools",
            "",
        ]
    );
    assert!(claude_stdin);

    let (codex, codex_stdin) = invoke_args(AgentId::Codex, "hello");
    assert_eq!(
        codex,
        vec![
            "exec",
            "--skip-git-repo-check",
            "--ephemeral",
            "--sandbox",
            "read-only",
            "--color",
            "never",
        ]
    );
    assert!(codex_stdin);

    let (copilot, copilot_stdin) = invoke_args(AgentId::Copilot, "hello");
    assert_eq!(
        copilot,
        vec![
            "-p",
            "hello",
            "--silent",
            "--no-color",
            "--output-format",
            "text",
            "--available-tools=",
        ]
    );
    assert!(!copilot_stdin);

    let (gemini, gemini_stdin) = invoke_args(AgentId::Gemini, "hello");
    assert_eq!(gemini, vec!["--prompt", "hello"]);
    assert!(!gemini_stdin);
}

#[test]
fn invoke_args_carry_the_prompt_exactly_once() {
    for id in AgentId::ALL {
        let (args, on_stdin) = invoke_args(id, "PROMPT-MARKER");
        let occurrences = args.iter().filter(|a| a.contains("PROMPT-MARKER")).count();
        if on_stdin {
            assert_eq!(occurrences, 0, "{id} takes the prompt on stdin");
        } else {
            assert_eq!(occurrences, 1, "{id} takes the prompt as an argument");
        }
    }
}

#[test]
fn agent_id_names_round_trip() {
    for id in AgentId::ALL {
        assert_eq!(AgentId::parse(id.as_str()), Some(id));
        assert_eq!(id.binary_name(), id.as_str());
        assert_eq!(id.to_string(), id.as_str());
    }
    assert_eq!(AgentId::parse("Claude"), None);
    assert_eq!(AgentId::parse("cursor"), None);
    assert_eq!(AgentId::parse(""), None);
}

#[test]
fn agent_id_is_lowercase_on_the_wire() {
    let json = serde_json::to_string(&AgentId::ALL).unwrap();
    assert_eq!(json, r#"["claude","codex","copilot","gemini"]"#);
    assert_eq!(
        serde_json::from_str::<AgentId>("\"gemini\"").unwrap(),
        AgentId::Gemini
    );
}

#[test]
fn agent_cli_serializes_for_the_gui_list() {
    let cli = AgentCli {
        id: AgentId::Codex,
        path: PathBuf::from("/opt/bin/codex"),
        version: Some("codex-cli 0.151.0".to_owned()),
    };
    let json = serde_json::to_value(&cli).unwrap();
    assert_eq!(json["id"], "codex");
    assert_eq!(json["version"], "codex-cli 0.151.0");
    assert!(json["path"].is_string());
}

/// A stand-in that leaves a marker file when it runs, so a test can prove an
/// untrusted candidate was never executed (not even for `--version`).
#[cfg(unix)]
fn write_marking_fake(dir: &Path, stem: &str, marker: &Path) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let path = dir.join(stem);
    std::fs::write(
        &path,
        format!("#!/bin/sh\ntouch '{}'\necho 9.9.9\n", marker.display()),
    )
    .unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    path
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

/// The daemon may have been started by an agent: a `claude` that exists only in a
/// directory from the inherited `PATH` is neither offered nor run.
#[cfg(unix)]
#[test]
fn a_cli_found_only_on_the_inherited_path_is_reported_and_never_run() {
    let trusted = tempfile::tempdir().unwrap();
    let planted = tempfile::tempdir().unwrap();
    let marker = planted.path().join("ran");
    write_marking_fake(planted.path(), "claude", &marker);

    let detection = detect(
        &[trusted.path().to_path_buf()],
        &path_env(&[planted.path()]),
        PROBE_DEADLINE,
    );

    assert!(detection.found.is_empty(), "{detection:?}");
    assert_eq!(detection.untrusted.len(), 1);
    assert_eq!(detection.untrusted[0].id, AgentId::Claude);
    assert!(
        detection.untrusted[0]
            .reason
            .contains("outside the directories"),
        "{}",
        detection.untrusted[0].reason
    );
    assert!(
        !marker.exists(),
        "an untrusted candidate must never be executed"
    );
}

/// Being in the trusted list is not enough: a directory the agent's user could
/// let others write is refused with the reason, and nothing is executed.
#[cfg(unix)]
#[test]
fn a_trusted_listed_directory_that_others_can_write_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let marker = dir.path().join("ran");
    write_marking_fake(dir.path(), "codex", &marker);
    set_mode(dir.path(), 0o777);

    let detection = detect(&[dir.path().to_path_buf()], OsStr::new(""), PROBE_DEADLINE);

    assert!(detection.found.is_empty(), "{detection:?}");
    assert_eq!(detection.untrusted.len(), 1);
    assert!(
        detection.untrusted[0]
            .reason
            .contains("writable by group or others"),
        "{}",
        detection.untrusted[0].reason
    );
    assert!(!marker.exists());
    set_mode(dir.path(), 0o700);
}

#[cfg(unix)]
#[test]
fn a_group_writable_executable_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let marker = dir.path().join("ran");
    let script = write_marking_fake(dir.path(), "gemini", &marker);
    set_mode(&script, 0o775);

    let detection = detect(&[dir.path().to_path_buf()], OsStr::new(""), PROBE_DEADLINE);

    assert!(detection.found.is_empty());
    assert!(
        detection.untrusted[0]
            .reason
            .contains("writable by group or others")
    );
    assert!(!marker.exists());
}

/// Trust is checked again at use: a CLI that was fine at detection and then had its
/// directory opened up is refused by `invoke`.
#[cfg(unix)]
#[tokio::test]
async fn invoke_rechecks_trust_at_use() {
    let dir = tempfile::tempdir().unwrap();
    let marker = dir.path().join("ran");
    let script = write_marking_fake(dir.path(), "claude", &marker);
    let cli = cli_at(AgentId::Claude, &script);
    assert!(untrusted_reason(&script).is_none(), "trusted to begin with");

    set_mode(dir.path(), 0o777);
    let failure = invoke_fresh(&cli, "anything", PROBE_DEADLINE)
        .await
        .unwrap_err();

    assert!(
        matches!(failure, CuratorError::Untrusted(AgentId::Claude, _)),
        "{failure:?}"
    );
    assert!(!marker.exists());
    set_mode(dir.path(), 0o700);
}

/// The child sees the user's identity and a fixed few variables, not the daemon's
/// environment (this test process has plenty: `CARGO_*`, `RUST_*`, ...).
#[cfg(unix)]
#[tokio::test]
async fn the_child_gets_a_minimal_environment_and_nothing_inherited() {
    let dir = tempfile::tempdir().unwrap();
    let script = dir.path().join("claude");
    std::fs::write(&script, "#!/bin/sh\nenv\n").unwrap();
    set_mode(&script, 0o755);
    let cli = cli_at(AgentId::Claude, &script);
    assert!(
        std::env::vars().count() > 6,
        "the test process has a fuller environment than the allowlist"
    );

    let dump = invoke_fresh(&cli, "anything", PROBE_DEADLINE)
        .await
        .unwrap();

    let names: Vec<&str> = dump
        .lines()
        .filter_map(|line| line.split_once('=').map(|(name, _)| name))
        .collect();
    // `PWD`, `SHLVL`, `_` and `OLDPWD` are the shell's own.
    let allowed = [
        "HOME", "USER", "LOGNAME", "PATH", "TMPDIR", "LANG", "PWD", "SHLVL", "_", "OLDPWD",
    ];
    for name in &names {
        assert!(
            allowed.contains(name),
            "unexpected variable {name} in {names:?}"
        );
    }
    assert!(names.contains(&"PATH") && names.contains(&"TMPDIR") && names.contains(&"LANG"));
    let path_line = dump.lines().find(|line| line.starts_with("PATH=")).unwrap();
    assert!(
        path_line.contains("/usr/bin") && !path_line.contains("/tmp/agent"),
        "{path_line}"
    );
}

#[cfg(unix)]
#[test]
fn trusted_dirs_are_fixed_locations_plus_the_homes_install_dirs() {
    let home = Path::new("/home/dev");
    let with = trusted_dirs(Some(home));
    let without = trusted_dirs(None);
    assert!(with.contains(&home.join(".local/bin")));
    assert!(with.contains(&home.join(".cargo/bin")));
    assert!(!without.iter().any(|dir| dir.starts_with(home)));
    assert!(with.iter().chain(&without).all(|dir| dir.is_absolute()));
    assert_eq!(
        trusted_dirs(Some(Path::new("relative/home"))),
        without,
        "a relative home adds nothing"
    );
}
