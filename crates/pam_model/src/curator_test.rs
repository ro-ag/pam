use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::curator::{AgentCli, AgentId, CuratorError, detect, invoke, invoke_args};

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

/// A `PATH` value covering exactly `dirs`.
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

    let found = detect(&path_env(&[dir.path()]), PROBE_DEADLINE);

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

    let found = detect(&path_env(&[dir.path()]), PROBE_DEADLINE);

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

    assert!(detect(&path_env(&[dir.path()]), PROBE_DEADLINE).is_empty());
}

#[test]
fn detect_skips_a_directory_wearing_the_name() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir(dir.path().join(fake_name("codex"))).unwrap();

    assert!(detect(&path_env(&[dir.path()]), PROBE_DEADLINE).is_empty());
}

#[test]
fn detect_takes_the_first_match_on_path() {
    let first = tempfile::tempdir().unwrap();
    let second = tempfile::tempdir().unwrap();
    let winner = write_fake(first.path(), "codex", Fake::Version);
    write_fake(second.path(), "codex", Fake::Version);

    let found = detect(&path_env(&[first.path(), second.path()]), PROBE_DEADLINE);

    assert_eq!(found.len(), 1);
    assert_eq!(found[0].path, winner.canonicalize().unwrap());
}

#[test]
fn detect_on_an_empty_path_finds_nothing() {
    assert!(detect(OsStr::new(""), PROBE_DEADLINE).is_empty());
}

#[test]
fn detect_reports_a_cli_that_will_not_say_its_version() {
    let dir = tempfile::tempdir().unwrap();
    write_fake(dir.path(), "copilot", Fake::Fail);

    let found = detect(&path_env(&[dir.path()]), PROBE_DEADLINE);

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

    let found = detect(&path_env(&[dir.path()]), Duration::from_millis(200));

    assert_eq!(found.len(), 1);
    assert_eq!(found[0].version, None);
}

#[tokio::test]
async fn invoke_returns_what_the_agent_said_on_stdin() {
    let dir = tempfile::tempdir().unwrap();
    let script = write_fake(dir.path(), "claude", Fake::EchoStdin);
    let cli = cli_at(AgentId::Claude, &script);

    let answer = invoke(&cli, "Reply with the single word OK.", PROBE_DEADLINE)
        .await
        .unwrap();

    assert_eq!(answer, "Reply with the single word OK.");
}

#[tokio::test]
async fn invoke_passes_the_prompt_as_an_argument_when_the_agent_wants_it() {
    let dir = tempfile::tempdir().unwrap();
    let script = write_fake(dir.path(), "gemini", Fake::EchoArgs);
    let cli = cli_at(AgentId::Gemini, &script);

    let answer = invoke(&cli, "Reply with the single word OK.", PROBE_DEADLINE)
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
    let failure = invoke(&cli, "anything", deadline).await.unwrap_err();

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

    let failure = invoke(&cli, "anything", PROBE_DEADLINE).await.unwrap_err();

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

    let failure = invoke(&cli, "anything", PROBE_DEADLINE).await.unwrap_err();

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
