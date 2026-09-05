//! CLI-flow integration tests: a real daemon ([`run_daemon`]) on a temp
//! base dir, driven through the library functions the `pam` binary
//! dispatches to — [`client::send_request`], [`client::follow_ticket`],
//! and the renderers. The binary itself stays a thin clap shell, so
//! driving the lib functions covers the surface.
//!
//! The `pam flow` suite is the exception: its subject *is* the shell —
//! argument parsing, the capability each subcommand sends, the process
//! exit code, and which stream the text lands on. Those tests execute
//! the compiled binary ([`run_pam`]) against the in-process daemon over
//! its real sockets, with `PAM_BASE_DIR` pointing at the same temp base.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use pam::client;
use pam::render;
use pam_daemon::daemon::{DaemonHandle, run_daemon};
use pam_daemon::flow_service::SETTING_ALLOWED_PROGRAMS;
use pam_daemon::policy::PROFILE_SETTING_KEY;
use pam_proto::{Event, Outcome, Response};
use pam_store::{RequestRow, RequestState, Store};
use tokio::sync::watch;
use tokio::time::timeout;

const DEADLINE: Duration = Duration::from_secs(20);

/// Bound on the event-follow calls; well under [`DEADLINE`] so a hang
/// fails legibly.
const FOLLOW_TIMEOUT: Duration = Duration::from_secs(10);

/// Temp dir with a short absolute path: macOS caps unix socket paths at
/// 104 bytes and the default temp root can get close.
fn short_tempdir() -> tempfile::TempDir {
    #[cfg(unix)]
    {
        tempfile::Builder::new()
            .prefix("pam")
            .tempdir_in("/tmp")
            .expect("tempdir under /tmp")
    }
    #[cfg(not(unix))]
    {
        tempfile::tempdir().expect("tempdir")
    }
}

struct TestDaemon {
    tmp: tempfile::TempDir,
    handle: DaemonHandle,
    shutdown: watch::Sender<bool>,
}

impl TestDaemon {
    async fn start() -> Self {
        Self::start_with_allowed_programs(&[]).await
    }

    /// A daemon whose flow steps may run exactly `programs` — the
    /// default allowlist is a whole toolchain, which a flow test must
    /// not inherit.
    async fn start_with_allowed_programs(programs: &[&str]) -> Self {
        let tmp = short_tempdir();
        seed_relaxed(&tmp).await;
        if !programs.is_empty() {
            seed_allowed_programs(&tmp, programs).await;
        }
        let (shutdown, shutdown_rx) = watch::channel(false);
        let handle = run_daemon(Some(base_of(&tmp)), shutdown_rx)
            .await
            .expect("daemon starts");
        Self {
            tmp,
            handle,
            shutdown,
        }
    }

    fn base(&self) -> PathBuf {
        base_of(&self.tmp)
    }

    async fn stop(self) {
        let _ = self.shutdown.send(true);
        self.handle.shutdown().await;
    }
}

/// The daemon base directory inside a test's temp dir.
fn base_of(tmp: &tempfile::TempDir) -> PathBuf {
    tmp.path().join("pam")
}

/// Persists the relaxed profile before the daemon (and thus the gate)
/// opens the store.
///
/// [`pam_daemon::policy::Profile::platform_default`] is `Relaxed` only on
/// macOS and `Standard` everywhere else, and only the relaxed profile
/// auto-grants a non-destructive capability on first use. These tests
/// drive `echo` without granting it, so without the seed they pass on
/// macOS and refuse with `not_granted` on Linux and Windows.
async fn seed_relaxed(tmp: &tempfile::TempDir) {
    let store = Store::open(&base_of(tmp).join("state.sqlite3"))
        .await
        .expect("store opens");
    store
        .set_setting(PROFILE_SETTING_KEY, "\"relaxed\"")
        .await
        .expect("relaxed profile persists");
}

/// Persists the programs a flow's command steps may run, before the
/// daemon opens the store.
async fn seed_allowed_programs(tmp: &tempfile::TempDir, programs: &[&str]) {
    let raw = serde_json::to_string(programs).expect("a string list always serializes");
    Store::open(&base_of(tmp).join("state.sqlite3"))
        .await
        .expect("store opens")
        .set_setting(SETTING_ALLOWED_PROGRAMS, &raw)
        .await
        .expect("the allowlist persists");
}

/// Polls the store until the request row satisfies `pred`.
async fn wait_for_row(store: &Store, id: &str, pred: impl Fn(&RequestRow) -> bool) -> RequestRow {
    loop {
        if let Some(row) = store.get_request(id).await.expect("get_request ok")
            && pred(&row)
        {
            return row;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

#[tokio::test]
async fn status_round_trips_and_maps_to_exit_zero() {
    timeout(DEADLINE, async {
        let daemon = TestDaemon::start().await;

        let response = client::send_request(
            &daemon.base(),
            "status",
            serde_json::json!({}),
            true,
            10_000,
            None,
        )
        .await
        .expect("request flows");

        let Response::Result { outcome, body, .. } = &response else {
            panic!("expected a result, got {response:?}");
        };
        assert_eq!(*outcome, Outcome::Verified);
        assert_eq!(body["daemon_version"], env!("CARGO_PKG_VERSION"));
        assert_eq!(render::exit_code(&response), 0);

        // The humane summary shows what the daemon reported.
        let summary = render::render_status(body);
        assert!(summary.contains(env!("CARGO_PKG_VERSION")), "{summary}");
        assert!(summary.contains("active requests"), "{summary}");

        daemon.stop().await;
    })
    .await
    .expect("test within deadline");
}

#[tokio::test]
async fn echo_solves_with_the_args_mirrored_back() {
    timeout(DEADLINE, async {
        let daemon = TestDaemon::start().await;

        let args = serde_json::json!({ "msg": "hello" });
        let response =
            client::send_request(&daemon.base(), "echo", args.clone(), true, 10_000, None)
                .await
                .expect("request flows");

        let Response::Result { outcome, body, .. } = &response else {
            panic!("expected a result, got {response:?}");
        };
        assert_eq!(*outcome, Outcome::Solved);
        assert_eq!(*body, serde_json::json!({ "echo": args }));
        assert_eq!(render::exit_code(&response), 0);

        daemon.stop().await;
    })
    .await
    .expect("test within deadline");
}

#[tokio::test]
async fn no_wait_returns_a_ticket_and_the_event_stream_ends_in_done() {
    timeout(DEADLINE, async {
        let daemon = TestDaemon::start().await;

        // Enough delay for the follow subscription to register before
        // the terminal event fires (zmq PUB has no replay).
        let args = serde_json::json!({ "delay_ms": 2_000 });
        let response = client::send_request(&daemon.base(), "echo", args, false, 10_000, None)
            .await
            .expect("request flows");

        let Response::Ticket { ticket, .. } = &response else {
            panic!("expected a ticket, got {response:?}");
        };
        assert_eq!(render::exit_code(&response), 0);
        let hint = render::render_ticket(ticket, 0);
        assert!(hint.contains(&format!("pam wait {ticket}")), "{hint}");

        // `pam wait` / `pam subscribe` share this one code path.
        let mut seen = Vec::new();
        let terminal = client::follow_ticket(&daemon.base(), ticket, FOLLOW_TIMEOUT, |event| {
            seen.push(event.clone());
        })
        .await
        .expect("follow reaches a terminal event");

        assert_eq!(terminal, Event::Done);
        assert_eq!(seen.last(), Some(&Event::Done));

        daemon.stop().await;
    })
    .await
    .expect("test within deadline");
}

#[tokio::test]
async fn a_follow_that_joins_after_the_terminal_event_still_terminates() {
    timeout(DEADLINE, async {
        let daemon = TestDaemon::start().await;

        let response = client::send_request(
            &daemon.base(),
            "echo",
            serde_json::json!({}),
            false,
            10_000,
            None,
        )
        .await
        .expect("request flows");
        let Response::Ticket { ticket, .. } = response else {
            panic!("expected a ticket, got a different response");
        };

        // Let the request finish before anybody subscribes: all its
        // events — the terminal one included — are published to nobody,
        // and zmq PUB has no replay (issue #1).
        let store = daemon.handle.store();
        wait_for_row(&store, &ticket, |row| row.state == RequestState::Done).await;

        // The follow still terminates, through the store reconcile.
        let terminal = client::follow_ticket(&daemon.base(), &ticket, FOLLOW_TIMEOUT, |_| {})
            .await
            .expect("follow reaches a terminal event");
        assert_eq!(terminal, Event::Done);

        daemon.stop().await;
    })
    .await
    .expect("test within deadline");
}

#[tokio::test]
async fn cancel_stops_a_delayed_echo() {
    timeout(DEADLINE, async {
        let daemon = TestDaemon::start().await;

        let args = serde_json::json!({ "delay_ms": 8_000 });
        let response = client::send_request(&daemon.base(), "echo", args, false, 10_000, None)
            .await
            .expect("request flows");
        let Response::Ticket { ticket, .. } = response else {
            panic!("expected a ticket, got {response:?}");
        };

        // Let the executor lease it so the cancel signals a runner.
        let store = daemon.handle.store();
        wait_for_row(&store, &ticket, |row| row.state == RequestState::Running).await;

        let response = client::send_request(
            &daemon.base(),
            "cancel",
            serde_json::json!({ "ticket": ticket }),
            true,
            10_000,
            None,
        )
        .await
        .expect("cancel flows");
        let Response::Result { outcome, body, .. } = &response else {
            panic!("expected a result, got {response:?}");
        };
        assert_eq!(*outcome, Outcome::Solved);
        assert_eq!(body["result"], "signalled_running");

        // The victim reaches its terminal state through its executor.
        let row = wait_for_row(&store, &ticket, |row| row.state == RequestState::Failed).await;
        assert_eq!(row.outcome.as_deref(), Some("cancelled"));

        daemon.stop().await;
    })
    .await
    .expect("test within deadline");
}

#[tokio::test]
async fn a_refusal_renders_cause_detail_and_recovery_and_exits_three() {
    timeout(DEADLINE, async {
        let daemon = TestDaemon::start().await;

        let response = client::send_request(
            &daemon.base(),
            "frobnicate",
            serde_json::json!({}),
            true,
            10_000,
            None,
        )
        .await
        .expect("request flows");

        let Response::Refusal {
            cause,
            detail,
            recovery,
            ..
        } = &response
        else {
            panic!("expected a refusal, got {response:?}");
        };
        assert_eq!(cause, "unknown_capability");
        assert_eq!(render::exit_code(&response), render::EXIT_REFUSED);

        let text = render::render_refusal(cause, detail, recovery);
        assert!(text.contains("refused (unknown_capability)"), "{text}");
        assert!(text.contains(detail.as_str()), "{text}");
        assert!(text.contains("GUI"), "{text}");

        daemon.stop().await;
    })
    .await
    .expect("test within deadline");
}

// --- pam flow, through the compiled binary --------------------------

/// Wall deadline for a flow test: a run spawns real `git` processes
/// through a real socket, so it needs more room than an `echo`.
const FLOW_DEADLINE: Duration = Duration::from_mins(1);

/// Exit code for a usage error (the crate docs' exit-code table).
const EXIT_USAGE: i32 = 2;

/// Every flow that ships in the binary.
const BUILTIN_FLOWS: [&str; 8] = [
    "after-merge-checks",
    "ci-failure-triage",
    "dependency-audit",
    "pam-pr-readiness",
    "pr-readiness",
    "release-readiness",
    "sonar-gate-check",
    "summarize-build-log",
];

/// A library flow that declares one input and runs one allowed program,
/// so a run proves the `key=value` argument reached the daemon.
const INPUT_ECHO_FLOW: &str = "\
schema: 1
id: input-echo
name: Input echo
description: Carries one declared input through a run.
inputs:
  label:
    description: A value the verdict body echoes back
    default: unset
steps:
  - id: version
    run: [git, --version]
";

/// What one execution of the compiled binary produced.
struct CliRun {
    code: i32,
    stdout: String,
    stderr: String,
}

/// Executes the freshly built binary once, outside any test deadline.
///
/// macOS assesses a new executable the first time it runs (once per
/// inode) and `cargo test` links a fresh inode every run, so without
/// this the first `pam flow` exec would spend seconds in `_dyld_start`
/// inside the test's own budget. See `live_subscribe.rs`, which pays the
/// same toll.
fn warm_binary() {
    let _ = Command::new(env!("CARGO_BIN_EXE_pam"))
        .arg("--version")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

/// Runs the compiled `pam` binary against the daemon on `base`, from
/// `cwd` — which is the repository the daemon attributes the request to.
async fn run_pam(base: &Path, cwd: &Path, args: &[&str]) -> CliRun {
    let base = base.to_path_buf();
    let cwd = cwd.to_path_buf();
    let args: Vec<String> = args.iter().map(|arg| (*arg).to_owned()).collect();
    // Off the runtime thread: the daemon serving this very request runs
    // in this process, and a blocking exec would sit on top of it.
    tokio::task::spawn_blocking(move || {
        let output = Command::new(env!("CARGO_BIN_EXE_pam"))
            .args(&args)
            .env("PAM_BASE_DIR", &base)
            .current_dir(&cwd)
            .stdin(Stdio::null())
            .output()
            .expect("the pam binary runs");
        CliRun {
            code: output.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        }
    })
    .await
    .expect("the pam exec joins")
}

/// A git repository with one commit and an `origin` remote pointing at
/// itself, so the builtin's `git fetch --prune` succeeds with no network.
fn temp_git_repo() -> tempfile::TempDir {
    let tmp = short_tempdir();
    let repo = tmp.path().to_path_buf();
    let git = |args: &[&str]| {
        let status = Command::new("git")
            .args(args)
            .current_dir(&repo)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .expect("git runs");
        assert!(status.success(), "git {args:?} exited {status}");
    };
    git(&["init", "--quiet", "."]);
    git(&["config", "user.email", "test@example.invalid"]);
    git(&["config", "user.name", "pam test"]);
    git(&["config", "commit.gpgsign", "false"]);
    std::fs::write(tmp.path().join("README.md"), "pam flow test\n").expect("the file is written");
    git(&["add", "README.md"]);
    git(&["commit", "--quiet", "--message", "first"]);
    git(&["remote", "add", "origin", &tmp.path().display().to_string()]);
    tmp
}

/// Writes one flow into the library a running daemon reads on demand.
fn seed_flow(tmp: &tempfile::TempDir, id: &str, yaml: &str) {
    let dir = base_of(tmp).join("flows");
    std::fs::create_dir_all(&dir).expect("the flow library directory is created");
    std::fs::write(dir.join(format!("{id}.yaml")), yaml).expect("the flow file is written");
}

#[tokio::test(flavor = "multi_thread")]
async fn flow_list_prints_every_builtin_and_exits_zero() {
    warm_binary();
    timeout(FLOW_DEADLINE, async {
        let daemon = TestDaemon::start_with_allowed_programs(&["git"]).await;

        let run = run_pam(&daemon.base(), daemon.tmp.path(), &["flow", "list"]).await;

        assert_eq!(run.code, 0, "stderr: {}", run.stderr);
        assert_eq!(
            run.stdout.lines().count(),
            BUILTIN_FLOWS.len(),
            "stdout: {}",
            run.stdout
        );
        for id in BUILTIN_FLOWS {
            assert!(run.stdout.contains(id), "stdout: {}", run.stdout);
        }
        assert!(run.stdout.contains("builtin"), "stdout: {}", run.stdout);

        daemon.stop().await;
    })
    .await
    .expect("test within deadline");
}

#[tokio::test(flavor = "multi_thread")]
async fn flow_show_prints_the_canonical_yaml_of_a_builtin() {
    warm_binary();
    timeout(FLOW_DEADLINE, async {
        let daemon = TestDaemon::start_with_allowed_programs(&["git"]).await;

        let run = run_pam(
            &daemon.base(),
            daemon.tmp.path(),
            &["flow", "show", "after-merge-checks"],
        )
        .await;

        assert_eq!(run.code, 0, "stderr: {}", run.stderr);
        assert!(
            run.stdout.starts_with("schema: 1"),
            "stdout: {}",
            run.stdout
        );
        assert!(
            run.stdout.contains("id: after-merge-checks"),
            "stdout: {}",
            run.stdout
        );

        daemon.stop().await;
    })
    .await
    .expect("test within deadline");
}

#[tokio::test(flavor = "multi_thread")]
async fn an_unknown_flow_id_is_refused_on_stderr_and_exits_three() {
    warm_binary();
    timeout(FLOW_DEADLINE, async {
        let daemon = TestDaemon::start_with_allowed_programs(&["git"]).await;

        let run = run_pam(
            &daemon.base(),
            daemon.tmp.path(),
            &["flow", "show", "no-such-flow"],
        )
        .await;

        assert_eq!(
            run.code,
            i32::from(render::EXIT_REFUSED),
            "stdout: {}",
            run.stdout
        );
        assert!(
            run.stderr.contains("refused (flow_not_found)"),
            "stderr: {}",
            run.stderr
        );
        assert!(
            run.stderr.contains("pam flow list"),
            "stderr: {}",
            run.stderr
        );
        assert!(run.stdout.is_empty(), "stdout: {}", run.stdout);

        daemon.stop().await;
    })
    .await
    .expect("test within deadline");
}

#[tokio::test(flavor = "multi_thread")]
async fn flow_run_verifies_after_merge_checks_inside_a_git_repo() {
    warm_binary();
    timeout(FLOW_DEADLINE, async {
        let daemon = TestDaemon::start_with_allowed_programs(&["git"]).await;
        let repo = temp_git_repo();

        let run = run_pam(
            &daemon.base(),
            repo.path(),
            &["flow", "run", "after-merge-checks"],
        )
        .await;

        assert_eq!(
            run.code, 0,
            "stdout: {}\nstderr: {}",
            run.stdout, run.stderr
        );
        assert!(
            run.stdout.contains("\u{2713} fetch  succeeded"),
            "stdout: {}",
            run.stdout
        );
        assert!(
            run.stdout.contains("3 steps: 3 succeeded"),
            "stdout: {}",
            run.stdout
        );

        // `--json` hands the agent the same verdict unrendered.
        let run = run_pam(
            &daemon.base(),
            repo.path(),
            &["flow", "run", "after-merge-checks", "--json"],
        )
        .await;

        assert_eq!(run.code, 0, "stderr: {}", run.stderr);
        let response: serde_json::Value =
            serde_json::from_str(&run.stdout).expect("the --json output is one JSON document");
        assert_eq!(response["outcome"], "verified", "response: {response}");
        assert_eq!(
            response["body"]["outcome"], "verified",
            "response: {response}"
        );
        assert_eq!(
            response["body"]["flow"]["id"], "after-merge-checks",
            "response: {response}"
        );

        daemon.stop().await;
    })
    .await
    .expect("test within deadline");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_key_value_input_reaches_the_daemon_and_comes_back_in_the_verdict() {
    warm_binary();
    timeout(FLOW_DEADLINE, async {
        let daemon = TestDaemon::start_with_allowed_programs(&["git"]).await;
        seed_flow(&daemon.tmp, "input-echo", INPUT_ECHO_FLOW);
        let repo = temp_git_repo();

        let run = run_pam(
            &daemon.base(),
            repo.path(),
            &["flow", "run", "input-echo", "label=carried", "--json"],
        )
        .await;

        assert_eq!(run.code, 0, "stderr: {}", run.stderr);
        let response: serde_json::Value =
            serde_json::from_str(&run.stdout).expect("the --json output is one JSON document");
        assert_eq!(
            response["body"]["inputs"]["label"], "carried",
            "response: {response}"
        );
        assert_eq!(
            response["body"]["flow"]["source"], "library",
            "response: {response}"
        );

        // With no argument the flow's declared default stands instead.
        let run = run_pam(
            &daemon.base(),
            repo.path(),
            &["flow", "run", "input-echo", "--json"],
        )
        .await;

        assert_eq!(run.code, 0, "stderr: {}", run.stderr);
        let response: serde_json::Value =
            serde_json::from_str(&run.stdout).expect("the --json output is one JSON document");
        assert_eq!(
            response["body"]["inputs"]["label"], "unset",
            "response: {response}"
        );

        daemon.stop().await;
    })
    .await
    .expect("test within deadline");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_positional_input_without_an_equals_sign_never_reaches_the_daemon() {
    warm_binary();
    // No daemon on purpose: the shell refuses before it opens a socket.
    let tmp = short_tempdir();

    let run = run_pam(
        &base_of(&tmp),
        tmp.path(),
        &["flow", "run", "after-merge-checks", "oops"],
    )
    .await;

    assert_eq!(run.code, EXIT_USAGE, "stderr: {}", run.stderr);
    assert_eq!(
        run.stderr.trim(),
        "pam flow run: input \"oops\" must be key=value"
    );
    assert!(run.stdout.is_empty(), "stdout: {}", run.stdout);
}

/// A repository in a specific dirty state, with config that would hide untracked files.
fn clean_tree_fixture(state: &str) -> tempfile::TempDir {
    let repo = temp_git_repo();
    // User configuration must not hide untracked changes from the assertion.
    assert!(
        Command::new("git")
            .args(["config", "status.showUntrackedFiles", "no"])
            .current_dir(repo.path())
            .status()
            .unwrap()
            .success()
    );
    match state {
        "staged" | "unstaged" => {
            std::fs::write(repo.path().join("README.md"), "changed\n").unwrap();
            if state == "staged" {
                assert!(
                    Command::new("git")
                        .args(["add", "README.md"])
                        .current_dir(repo.path())
                        .status()
                        .unwrap()
                        .success()
                );
            }
        }
        "untracked" => {
            std::fs::write(repo.path().join("dirty.txt"), "untracked\n").unwrap();
        }
        _ => {}
    }
    repo
}

#[tokio::test(flavor = "multi_thread")]
async fn clean_tree_assertion_reports_clean_staged_unstaged_and_untracked_via_cli() {
    warm_binary();
    timeout(FLOW_DEADLINE, async {
        let daemon = TestDaemon::start_with_allowed_programs(&["git"]).await;
        let store = Store::open(&daemon.base().join("state.sqlite3"))
            .await
            .unwrap();
        for state in ["clean", "staged", "unstaged", "untracked"] {
            let repo = clean_tree_fixture(state);
            let run = run_pam(
                &daemon.base(),
                repo.path(),
                &["flow", "run", "after-merge-checks", "--json"],
            )
            .await;
            let expected_code = if state == "clean" {
                0
            } else {
                i32::from(render::EXIT_UNRESOLVED)
            };
            assert_eq!(
                run.code, expected_code,
                "{state}: {} {}",
                run.stdout, run.stderr
            );
            let response: serde_json::Value = serde_json::from_str(&run.stdout).unwrap();
            let outcome = if state == "clean" {
                "verified"
            } else {
                "unresolved"
            };
            assert_eq!(response["outcome"], outcome, "{state}: {response}");
            let step = response["body"]["steps"]
                .as_array()
                .unwrap()
                .iter()
                .find(|step| step["id"] == "clean-tree")
                .unwrap();
            assert_eq!(
                step["exit_status"], 0,
                "git itself exits zero even when dirty"
            );
            assert_eq!(
                step["status"],
                if state == "clean" {
                    "succeeded"
                } else {
                    "failed"
                }
            );
            if state != "clean" {
                assert_eq!(step["error"]["cause"], "output_assertion");
                let mut retained = Vec::new();
                for id in step["evidence"].as_array().unwrap() {
                    let evidence = store
                        .get_evidence(id.as_str().unwrap())
                        .await
                        .unwrap()
                        .unwrap();
                    retained.extend(evidence.content);
                }
                let text = String::from_utf8_lossy(&retained);
                let path = if state == "untracked" {
                    "dirty.txt"
                } else {
                    "README.md"
                };
                assert!(
                    text.contains(path),
                    "{state} evidence lost dirty path: {text}"
                );
            }
        }
        daemon.stop().await;
    })
    .await
    .expect("clean-tree CLI cases complete within deadline");
}

async fn flow_admin(base: &Path, op: &str, args: serde_json::Value) -> serde_json::Value {
    match client::send_admin(base, op, args, 5000).await.unwrap() {
        Response::Result { body, .. } => body,
        other => panic!("admin operation failed: {other:?}"),
    }
}

#[tokio::test]
async fn admin_created_duplicated_and_renamed_flow_runs_from_the_actual_cli() {
    timeout(DEADLINE, async {
        let daemon = TestDaemon::start_with_allowed_programs(&["git"]).await;
        let base = daemon.base();
        let yaml = "schema: 1\nid: fresh\nname: Fresh flow\nsteps:\n  - id: inspect\n    run: [git, status, --porcelain=v1]\n";
        flow_admin(&base, "admin.flows.save", serde_json::json!({
            "id":"fresh", "yaml":yaml, "create_only":true,
        })).await;
        let copy = yaml.replace("id: fresh", "id: copied").replace("Fresh flow", "Copied flow");
        flow_admin(&base, "admin.flows.save", serde_json::json!({
            "id":"copied", "yaml":copy, "create_only":true,
        })).await;
        let renamed = copy.replace("Copied flow", "Renamed flow");
        flow_admin(&base, "admin.flows.save", serde_json::json!({
            "id":"copied", "yaml":renamed,
        })).await;
        let collision = client::send_admin(&base, "admin.flows.save", serde_json::json!({
            "id":"copied", "yaml":copy, "create_only":true,
        }), 5000).await.unwrap();
        assert!(matches!(collision, Response::Refusal { .. }));
        let got = flow_admin(&base, "admin.flows.get", serde_json::json!({"id":"copied"})).await;
        assert_eq!(got["flow"]["name"], "Renamed flow");
        assert_eq!(got["flow"]["id"], "copied");
        let repo = temp_git_repo();
        let run = run_pam(&base, repo.path(), &["flow", "run", "copied", "--json"]).await;
        assert_eq!(run.code, 0, "{}", run.stderr);
        let result: serde_json::Value = serde_json::from_str(&run.stdout).unwrap();
        assert_eq!(result["body"]["flow"]["source"], "library");
        let deleted = flow_admin(&base, "admin.flows.delete", serde_json::json!({"id":"copied"})).await;
        assert_eq!(deleted["revealed_builtin"], false);
        flow_admin(&base, "admin.flows.save", serde_json::json!({
            "id":"copied", "yaml":renamed, "create_only":true,
        })).await;
        let restored = flow_admin(&base, "admin.flows.get", serde_json::json!({"id":"copied"})).await;
        assert_eq!(restored["flow"]["name"], "Renamed flow");
        daemon.stop().await;
    }).await.expect("admin CRUD and actual CLI finish before deadline");
}
