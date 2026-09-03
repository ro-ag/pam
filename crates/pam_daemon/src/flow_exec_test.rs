//! Unit tests for the mechanical half of a flow run.
//!
//! Nothing here starts a daemon: the verdict matrix, the summary
//! sentence, the environment scrub and program resolution are pure, and
//! the child-process tests drive `git` (present wherever this workspace
//! builds) and the crate's own `pam-flow-helper` binary.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::time::Duration;

use pam_flow::{Flow, parse};
use pam_proto::Outcome;
use tokio::sync::watch;

use crate::flow_exec::{
    CommandOutcome, CommandSpec, SECRET_ENV_FRAGMENTS, StepReport, StepStatus, is_secret_env_name,
    outcome_for, resolve_program, run_command, scrub_env, sleep_or_cancel, summary_for,
};

/// `git`, which every machine that builds this workspace has.
///
/// The three endings a purpose-built child is needed for — outliving a
/// timeout, flooding the output cap, being cancelled — are proved in
/// `tests/flows.rs` against `pam-flow-helper`: `CARGO_BIN_EXE_*` is set
/// for integration tests only, and `cargo test --lib` does not build the
/// package's binaries at all.
fn git() -> PathBuf {
    resolve_program(
        "git",
        &[],
        &std::env::var_os("PATH").expect("the test runner has a PATH"),
    )
    .expect("git is installed wherever this workspace builds")
}

/// A spec that runs `git` with `argv`.
fn git_spec(argv: &[&str]) -> CommandSpec {
    CommandSpec {
        program: git(),
        argv: argv.iter().map(|part| (*part).to_owned()).collect(),
        cwd: std::env::temp_dir(),
        env: Vec::new(),
        timeout: Duration::from_secs(30),
    }
}

/// A cancel channel that never fires, and the sender that keeps it open.
fn live_cancel() -> (watch::Sender<bool>, watch::Receiver<bool>) {
    watch::channel(false)
}

/// An empty file that [`resolve_program`] will accept as a program.
fn touch(dir: &Path, name: &str) -> PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, b"").expect("the fake program is written");
    path
}

/// A flow whose steps carry the effects and roles a verdict reads.
fn flow_with(steps: &str) -> Flow {
    parse(&format!(
        "schema: 1\nid: verdict\nname: Verdict\nsteps:\n{steps}"
    ))
    .expect("the fixture flow parses")
}

/// A report in a given status, with no error and no exit status.
fn report(id: &str, status: StepStatus) -> StepReport {
    StepReport::new(id, "command", status)
}

#[test]
fn outcome_is_solved_when_only_observation_ran() {
    let flow = flow_with("  - id: look\n    run: [git, status]\n");
    assert_eq!(
        outcome_for(&[report("look", StepStatus::Succeeded)], &flow),
        Outcome::Solved
    );
}

#[test]
fn outcome_is_verified_when_a_verify_step_succeeded() {
    let flow = flow_with("  - id: prove\n    run: [git, status]\n    role: verify\n");
    assert_eq!(
        outcome_for(&[report("prove", StepStatus::Succeeded)], &flow),
        Outcome::Verified
    );
}

#[test]
fn outcome_is_changed_when_a_stateful_step_succeeded() {
    let flow = flow_with(
        "  - id: prove\n    run: [git, status]\n    role: verify\n\
         \x20 - id: push\n    run: [git, push]\n    effect: stateful\n",
    );
    assert_eq!(
        outcome_for(
            &[
                report("prove", StepStatus::Succeeded),
                report("push", StepStatus::Succeeded),
            ],
            &flow
        ),
        Outcome::Changed
    );
}

#[test]
fn outcome_is_unresolved_when_a_step_failed() {
    let flow = flow_with(
        "  - id: prove\n    run: [git, status]\n    role: verify\n\
         \x20 - id: test\n    run: [cargo, test]\n",
    );
    assert_eq!(
        outcome_for(
            &[
                report("prove", StepStatus::Succeeded),
                report("test", StepStatus::Failed),
            ],
            &flow
        ),
        Outcome::Unresolved
    );
}

#[test]
fn a_blocked_step_outranks_a_failed_one() {
    let flow = flow_with(
        "  - id: test\n    run: [cargo, test]\n\
         \x20 - id: push\n    run: [git, push]\n    effect: stateful\n",
    );
    assert_eq!(
        outcome_for(
            &[
                report("test", StepStatus::Failed),
                report("push", StepStatus::Blocked),
            ],
            &flow
        ),
        Outcome::Blocked
    );
    assert_eq!(
        outcome_for(
            &[
                report("test", StepStatus::Failed),
                report("push", StepStatus::Cancelled),
            ],
            &flow
        ),
        Outcome::Blocked
    );
}

#[test]
fn a_skipped_stateful_step_does_not_make_the_run_changed() {
    let flow = flow_with(
        "  - id: prove\n    run: [git, status]\n    role: verify\n\
         \x20 - id: push\n    run: [git, push]\n    effect: stateful\n",
    );
    assert_eq!(
        outcome_for(
            &[
                report("prove", StepStatus::Succeeded),
                report("push", StepStatus::Skipped),
            ],
            &flow
        ),
        Outcome::Verified
    );
}

#[test]
fn the_summary_counts_every_status_and_names_the_first_culprit() {
    let mut failed = report("clippy", StepStatus::Failed);
    failed.exit_status = Some(101);
    let steps = vec![
        report("fmt", StepStatus::Succeeded),
        report("fetch", StepStatus::Succeeded),
        failed,
        report("docs", StepStatus::Skipped),
    ];
    assert_eq!(
        summary_for(&steps),
        "4 steps: 2 succeeded, 1 failed, 1 skipped (clippy, exit 101)"
    );
}

#[test]
fn the_summary_falls_back_to_the_cause_without_an_exit_status() {
    let mut blocked = report("deploy", StepStatus::Blocked);
    blocked.fail(
        StepStatus::Blocked,
        "approval_denied",
        "a human said no".to_owned(),
        "open Pam → Approvals".to_owned(),
    );
    assert_eq!(
        summary_for(&[blocked]),
        "1 step: 0 succeeded, 1 blocked (deploy, approval_denied)"
    );
}

#[test]
fn the_summary_appends_a_failing_step_summary_on_its_own_line() {
    let mut failed = report("test", StepStatus::Failed);
    failed.exit_status = Some(1);
    failed.summary = Some("two assertions in store::tests failed".to_owned());
    assert_eq!(
        summary_for(&[failed]),
        "1 step: 0 succeeded, 1 failed (test, exit 1)\n\
         two assertions in store::tests failed"
    );
}

#[test]
fn scrub_env_drops_secret_names_and_path_but_keeps_the_rest() {
    let vars = [
        ("HOME", "/Users/somebody"),
        ("PATH", "/usr/bin"),
        ("GITHUB_TOKEN", "ghp_never_reaches_a_child"),
        ("AWS_SECRET_ACCESS_KEY", "not this either"),
        ("npm_config_password", "nor this"),
        ("MY_PRIVATE_KEY", "nor this"),
        ("CARGO_TERM_COLOR", "never"),
    ]
    .into_iter()
    .map(|(name, value)| (OsString::from(name), OsString::from(value)));

    let kept = scrub_env(vars);
    let names: Vec<&str> = kept.iter().map(|(name, _)| name.as_str()).collect();
    assert_eq!(names, ["CARGO_TERM_COLOR", "HOME"]);
}

#[test]
fn every_secret_fragment_is_recognized_case_insensitively() {
    for fragment in SECRET_ENV_FRAGMENTS {
        let name = format!("SOME_{}_HERE", fragment.to_uppercase());
        assert!(is_secret_env_name(&name), "{name} should look secret");
    }
    assert!(!is_secret_env_name("HOME"));
}

#[test]
fn resolve_program_prefers_the_extra_path() {
    let extra = tempfile::tempdir().expect("tempdir");
    let inherited = tempfile::tempdir().expect("tempdir");
    let preferred = touch(extra.path(), "pam-fake-tool");
    let fallback = touch(inherited.path(), "pam-fake-tool");

    let path = OsString::from(inherited.path());
    let found = resolve_program("pam-fake-tool", &[extra.path().to_path_buf()], &path)
        .expect("the program resolves");
    assert_eq!(found, preferred);

    let found = resolve_program("pam-fake-tool", &[], &path).expect("the program resolves");
    assert_eq!(found, fallback);
}

#[test]
fn resolve_program_refuses_a_name_with_a_path_separator() {
    let dir = tempfile::tempdir().expect("tempdir");
    touch(dir.path(), "pam-fake-tool");
    let path = OsString::from(dir.path());
    assert!(resolve_program("../pam-fake-tool", &[], &path).is_none());
    assert!(resolve_program("", &[], &path).is_none());
    assert!(resolve_program("definitely-not-installed-xyz", &[], &path).is_none());
}

#[tokio::test]
async fn a_clean_exit_reports_its_output() {
    let (_alive, mut cancel) = live_cancel();
    let outcome = run_command(git_spec(&["--version"]), &mut cancel).await;
    match outcome {
        CommandOutcome::Exited { status, output } => {
            assert_eq!(status, 0);
            assert!(String::from_utf8_lossy(&output).contains("git version"));
        }
        other => panic!("expected a clean exit, got {other:?}"),
    }
}

#[tokio::test]
async fn a_non_zero_exit_arrives_with_the_stderr_it_wrote() {
    let (_alive, mut cancel) = live_cancel();
    let outcome = run_command(git_spec(&["pam-nonsense-subcommand"]), &mut cancel).await;
    match outcome {
        CommandOutcome::Exited { status, output } => {
            assert_ne!(status, 0, "a bad subcommand does not exit zero");
            // git writes its complaint to stderr; the buffer is one
            // stream, so it is here.
            assert!(
                !output.is_empty(),
                "stderr must land in the same buffer as stdout"
            );
        }
        other => panic!("expected a non-zero exit, got {other:?}"),
    }
}

#[tokio::test]
async fn the_environment_reaches_the_child_and_nothing_else_does() {
    let (_alive, mut cancel) = live_cancel();
    let mut spec = git_spec(&["config", "--get", "pam.marker"]);
    // `git config --get` reads the marker out of a config file named by
    // an environment variable, which proves the env we set is the env the
    // child saw — and that nothing was inherited implicitly.
    let dir = tempfile::tempdir().expect("tempdir");
    let config = dir.path().join("gitconfig");
    std::fs::write(
        &config,
        "[pam]
	marker = seen
",
    )
    .expect("the config is written");
    spec.env = vec![("GIT_CONFIG_GLOBAL".to_owned(), config.display().to_string())];
    spec.cwd = dir.path().to_path_buf();
    match run_command(spec, &mut cancel).await {
        CommandOutcome::Exited { status, output } => {
            assert_eq!(
                status,
                0,
                "git found no marker: {:?}",
                String::from_utf8_lossy(&output)
            );
            assert_eq!(String::from_utf8_lossy(&output).trim(), "seen");
        }
        other => panic!("expected a clean exit, got {other:?}"),
    }
}

#[tokio::test]
async fn a_program_that_cannot_be_started_says_so() {
    let (_alive, mut cancel) = live_cancel();
    let outcome = run_command(
        CommandSpec {
            program: Path::new("/definitely/not/here/pam-flow-helper").to_path_buf(),
            argv: Vec::new(),
            cwd: std::env::temp_dir(),
            env: Vec::new(),
            timeout: Duration::from_secs(5),
        },
        &mut cancel,
    )
    .await;
    assert!(
        matches!(outcome, CommandOutcome::SpawnFailed(_)),
        "expected a spawn failure, got {outcome:?}"
    );
}

#[tokio::test]
async fn sleep_or_cancel_returns_early_when_the_request_is_cancelled() {
    let (alive, mut cancel) = live_cancel();
    let _ = alive.send(true);
    assert!(sleep_or_cancel(Duration::from_mins(10), &mut cancel).await);

    let (_alive, mut cancel) = live_cancel();
    assert!(!sleep_or_cancel(Duration::from_millis(1), &mut cancel).await);
}
