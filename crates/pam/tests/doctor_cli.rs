//! `pam doctor` through the compiled binary: the exit code is the local
//! verdict, `--json` is one document, the daemon records the report (or,
//! with `--no-report`, stays never-checked), and `--profile` prints without
//! a daemon. The daemon runs in-process on a temp base
//! ([`pam_testkit::TestDaemon`], relaxed profile seeded); the binary finds
//! it through `PAM_BASE_DIR`, the same resolution every client command uses.
//!
//! An unsandboxed test process can reach everything under the base, so the
//! verdict here is always `not_established` (exit `6`); the `established`
//! path is the macOS acceptance suite's, under `sandbox-exec`.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use pam::doctor::profiles::Harness;
use pam_testkit::TestDaemon;
use tokio::time::timeout;

/// A whole doctor run: the probes (helpers included) plus the report, well
/// inside the engine's own 30 s bound.
const DEADLINE: Duration = Duration::from_secs(90);

struct CliRun {
    /// The exit code, or `-1` when a signal ended the process (named in
    /// `stderr` then).
    code: i32,
    stdout: String,
    stderr: String,
}

/// Runs the compiled `pam` binary with `PAM_BASE_DIR` set to `base`, off
/// the runtime thread (the daemon serving the request runs in this process).
async fn run_pam(base: &Path, args: &[&str]) -> CliRun {
    let base = base.to_path_buf();
    let args: Vec<String> = args.iter().map(|arg| (*arg).to_owned()).collect();
    tokio::task::spawn_blocking(move || run_pam_blocking(&base, &args))
        .await
        .expect("the pam exec joins")
}

/// Every exec runs a fresh clone of the binary (an APFS clone: cheap, a
/// new inode), never `target/debug/pam` itself.
///
/// The engine's `exe.write` probe opens the running executable for write
/// (it writes nothing), and macOS answers an open-for-write on a binary
/// that another process is mapped from by invalidating the kernel's code
/// signature for that inode: every later exec of it is `SIGKILL`ed until the
/// file is replaced (`doctor_poisons_nothing_it_runs_from` pins it). A test
/// run execs the binary many times, in parallel, so without a clone per
/// exec one doctor run kills the rest of the suite — and the `cli.rs` tests
/// that follow it.
fn run_pam_blocking(base: &Path, args: &[String]) -> CliRun {
    let scratch = tempfile::Builder::new()
        .prefix("pam-doctor-exe")
        .tempdir()
        .expect("tempdir");
    let exe = fresh_binary(scratch.path());
    exec(&exe, base, args)
}

/// A fresh clone of the built binary under `dir`, executable.
fn fresh_binary(dir: &Path) -> PathBuf {
    let exe = dir.join("pam");
    std::fs::copy(env!("CARGO_BIN_EXE_pam"), &exe).expect("the binary clones");
    exe
}

fn exec(exe: &Path, base: &Path, args: &[String]) -> CliRun {
    let output = Command::new(exe)
        .args(args)
        .env("PAM_BASE_DIR", base)
        .env_remove("PAM_SOCKET_DIR")
        .stdin(Stdio::null())
        .output()
        .expect("the pam binary runs");
    let mut stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    #[cfg(unix)]
    if let Some(signal) = std::os::unix::process::ExitStatusExt::signal(&output.status) {
        use std::fmt::Write as _;
        let _ = write!(stderr, "[the pam process was ended by signal {signal}]");
    }
    CliRun {
        code: output.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr,
    }
}

/// The one JSON document a `--json` run prints: anything else on stdout
/// fails the parse.
fn document(run: &CliRun) -> serde_json::Value {
    serde_json::from_str(&run.stdout)
        .unwrap_or_else(|error| panic!("stdout is one JSON document ({error}): {}", run.stdout))
}

/// The daemon's `boundary` status block, through `pam status --json`.
async fn boundary_block(base: &Path) -> serde_json::Value {
    let status = run_pam(base, &["status", "--json"]).await;
    assert_eq!(status.code, 0, "{}", status.stderr);
    let response = document(&status);
    assert_eq!(response["kind"], "result", "{response}");
    let block = response["body"]["boundary"].clone();
    assert!(
        block.is_object(),
        "status carries the boundary block: {response}"
    );
    block
}

/// A base nobody serves: the doctor must neither start a daemon under it
/// nor create anything there.
fn unserved_base() -> (tempfile::TempDir, PathBuf) {
    let tmp = tempfile::Builder::new()
        .prefix("pam-doctor")
        .tempdir()
        .expect("tempdir");
    let base = tmp.path().join("pam");
    (tmp, base)
}

#[cfg(target_os = "macos")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn doctor_json_is_one_document_exits_six_and_the_daemon_records_the_report() {
    timeout(DEADLINE, async {
        let daemon = TestDaemon::spawn().await;
        let base = daemon.base_dir();

        let run = run_pam(&base, &["doctor", "--json"]).await;
        assert_eq!(
            run.code, 6,
            "stdout: {}\nstderr: {}",
            run.stdout, run.stderr
        );
        assert!(run.stderr.is_empty(), "stderr: {}", run.stderr);
        let report = document(&run);
        assert_eq!(report["schema_version"], 1);
        assert_eq!(report["verdict"], "not_established");
        assert_eq!(report["platform"], "macos");
        assert_eq!(report["daemon"]["via"], "direct");
        assert_eq!(
            report["probes"][0],
            serde_json::json!({ "id": "public.reach", "class": "must_allow", "result": "allowed",
                                "elapsed_ms": report["probes"][0]["elapsed_ms"] })
        );
        assert!(
            report["failed"]
                .as_array()
                .is_some_and(|failed| failed.iter().any(|id| id == "admin.dir")),
            "an unsandboxed process reaches the admin directory: {report}"
        );
        assert_eq!(
            report["env"]["resolved_base"],
            base.to_string_lossy().as_ref()
        );
        // The daemon recorded it, and said how it saw the caller.
        assert_eq!(report["report"]["recorded"], true, "{report}");
        let request_id = report["report"]["request_id"]
            .as_str()
            .expect("the record names the request")
            .to_owned();
        assert!(request_id.starts_with("req_"), "{request_id}");
        assert_eq!(report["daemon_reply"]["accepted"], true, "{report}");
        assert_eq!(report["daemon_reply"]["verdict"], "not_established");
        assert_eq!(report["daemon_reply"]["request_id"], request_id);
        assert!(report["daemon_reply"]["peer"]["pid"].is_u64(), "{report}");

        let block = boundary_block(&base).await;
        assert_eq!(
            block["last_report"]["verdict"], "not_established",
            "{block}"
        );
        assert_eq!(block["last_report"]["request_id"], request_id, "{block}");
        assert_eq!(block["reports"]["not_established"], 1, "{block}");
        assert!(
            block["summary"]
                .as_str()
                .is_some_and(|summary| summary.starts_with("not_established ")),
            "{block}"
        );

        daemon.stop().await;
    })
    .await
    .expect("test within deadline");
}

#[cfg(target_os = "macos")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn doctor_no_report_keeps_the_verdict_and_leaves_the_daemon_never_checked() {
    timeout(DEADLINE, async {
        let daemon = TestDaemon::spawn().await;
        let base = daemon.base_dir();

        let run = run_pam(&base, &["doctor", "--json", "--no-report"]).await;
        assert_eq!(
            run.code, 6,
            "stdout: {}\nstderr: {}",
            run.stdout, run.stderr
        );
        assert!(run.stderr.is_empty(), "stderr: {}", run.stderr);
        let report = document(&run);
        assert_eq!(report["verdict"], "not_established");
        assert_eq!(
            report["report"],
            serde_json::json!({ "recorded": false, "reason": "--no-report" })
        );
        assert!(report.get("daemon_reply").is_none(), "{report}");

        let block = boundary_block(&base).await;
        assert!(block["last_report"].is_null(), "{block}");
        assert_eq!(block["reports"]["retained"], 0, "{block}");
        assert_eq!(
            block["summary"],
            "never checked — run pam doctor from the agent"
        );

        daemon.stop().await;
    })
    .await
    .expect("test within deadline");
}

#[cfg(target_os = "macos")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn doctor_human_output_names_the_verdict_the_record_and_the_daemons_view() {
    timeout(DEADLINE, async {
        let daemon = TestDaemon::spawn().await;
        let base = daemon.base_dir();

        let run = run_pam(&base, &["doctor"]).await;
        assert_eq!(
            run.code, 6,
            "stdout: {}\nstderr: {}",
            run.stdout, run.stderr
        );
        assert!(run.stderr.is_empty(), "stderr: {}", run.stderr);
        let stdout = &run.stdout;
        assert!(
            stdout.starts_with("boundary: not_established\n"),
            "{stdout}"
        );
        assert!(stdout.contains("  failed: "), "{stdout}");
        assert!(
            stdout.contains("profile: pam doctor --profile "),
            "{stdout}"
        );
        assert!(stdout.contains("report: recorded as req_"), "{stdout}");
        assert!(stdout.contains("the daemon saw you as: "), "{stdout}");
        assert!(stdout.contains("harness agrees: "), "{stdout}");

        // `pam status` now carries the verdict on its boundary line.
        let status = run_pam(&base, &["status"]).await;
        assert_eq!(status.code, 0, "{}", status.stderr);
        assert!(
            status
                .stdout
                .contains("  boundary:        not_established "),
            "{}",
            status.stdout
        );
        assert!(
            status.stdout.contains("    last report:   req_"),
            "{}",
            status.stdout
        );

        daemon.stop().await;
    })
    .await
    .expect("test within deadline");
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn doctor_without_a_daemon_is_cannot_probe_exit_one_and_starts_nothing() {
    timeout(DEADLINE, async {
        let (_tmp, base) = unserved_base();
        let run = run_pam(&base, &["doctor", "--json"]).await;
        assert_eq!(
            run.code, 1,
            "stdout: {}\nstderr: {}",
            run.stdout, run.stderr
        );
        let report = document(&run);
        assert_eq!(report["verdict"], "cannot_probe", "{report}");
        assert!(report["daemon"].is_null(), "{report}");
        assert_eq!(report["report"]["recorded"], false, "{report}");
        assert!(report.get("daemon_reply").is_none(), "{report}");
        // Unlike every other client command, the doctor never starts a daemon.
        assert!(
            !base.join("run").exists(),
            "nothing was started under {}",
            base.display()
        );
    })
    .await
    .expect("test within deadline");
}

#[cfg(unix)]
#[test]
fn doctor_profile_prints_every_harness_without_a_daemon_or_a_base() {
    let (_tmp, base) = unserved_base();
    let named = "/tmp/pam-doctor-profile-base-that-does-not-exist";
    for harness in Harness::ALL {
        let run = run_pam_blocking(
            &base,
            &["doctor", "--profile", harness.name(), "--base", named].map(str::to_owned),
        );
        assert_eq!(run.code, 0, "{harness}: {}", run.stderr);
        assert!(
            run.stdout.contains(named),
            "{harness} names the base: {}",
            run.stdout
        );
        assert!(
            run.stdout.contains("run/pam.sock"),
            "{harness} allows the public socket: {}",
            run.stdout
        );
    }
    assert!(
        !base.exists(),
        "a profile run creates nothing under the base"
    );

    // The JSON fragment parses and names the base; its guide is pointed at on stderr.
    let claude = run_pam_blocking(
        &base,
        &["doctor", "--profile", "claude-code", "--base", named].map(str::to_owned),
    );
    let fragment: serde_json::Value =
        serde_json::from_str(&claude.stdout).expect("the Claude fragment is JSON");
    assert!(fragment.is_object(), "{fragment}");
    assert!(
        claude.stderr.contains("docs/sandbox/macos/claude-code.md"),
        "{}",
        claude.stderr
    );
    // The Seatbelt fallback is pipeable: nothing on stderr.
    let seatbelt = run_pam_blocking(
        &base,
        &["doctor", "--profile", "sandbox-exec", "--base", named].map(str::to_owned),
    );
    assert!(seatbelt.stderr.is_empty(), "{}", seatbelt.stderr);
    assert!(
        seatbelt.stdout.contains("(version 1)"),
        "{}",
        seatbelt.stdout
    );

    // The managed variant exists for Claude only.
    let managed = run_pam_blocking(
        &base,
        &[
            "doctor",
            "--profile",
            "claude-code",
            "--base",
            named,
            "--managed",
        ]
        .map(str::to_owned),
    );
    assert_eq!(managed.code, 0, "{}", managed.stderr);
    let refused = run_pam_blocking(
        &base,
        &["doctor", "--profile", "codex", "--base", named, "--managed"].map(str::to_owned),
    );
    assert_eq!(refused.code, 2, "{}", refused.stdout);
    assert!(refused.stdout.is_empty(), "{}", refused.stdout);
    assert!(
        refused.stderr.contains("no managed variant"),
        "{}",
        refused.stderr
    );
}

#[test]
fn doctor_unknown_profile_is_a_usage_error_naming_the_choices() {
    let (_tmp, base) = unserved_base();
    let run = run_pam_blocking(&base, &["doctor", "--profile", "emacs"].map(str::to_owned));
    assert_eq!(run.code, 2, "{}", run.stderr);
    assert!(run.stdout.is_empty(), "{}", run.stdout);
    assert!(
        run.stderr.contains("unknown profile \"emacs\""),
        "{}",
        run.stderr
    );
    assert!(run.stderr.contains(&Harness::names()), "{}", run.stderr);
    assert!(
        !base.exists(),
        "a usage error creates nothing under the base"
    );
}

/// A doctor run must leave the binary it ran from runnable.
///
/// Pinned here because it is not: the `exe.write` probe opens the running
/// executable for write (no byte written), and when another process is
/// mapped from that inode — the daemon, in production — macOS invalidates
/// the kernel's code signature for it and `SIGKILL`s every later exec until
/// the file is replaced (`Killed: 9`; `codesign -vv` still says valid on
/// disk). Measured on macOS 26 (Darwin 27) on 2026-10-02: a daemon running
/// from a copy, one external `open(O_WRONLY)` + `close` on the copy, and
/// `copy --version` exits 137 from then on. The probe must ask the
/// permission question without opening the file (`/bin/test -w <exe>`,
/// `access(2)`, which Seatbelt honours: exit 1 under `(deny file-write*)`,
/// 0 outside); that is `crates/pam/src/doctor/probe_unix.rs`, the engine's
/// file, not this task's — see `scratchpad/doctor/cross-T3T5.md`. Ignored
/// until it lands; run it with `--ignored` to check.
#[cfg(target_os = "macos")]
#[ignore = "the exe.write probe opens the running binary for write and macOS then SIGKILLs every later exec of it; fix in doctor/probe_unix.rs (cross-T3T5.md)"]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn doctor_poisons_nothing_it_runs_from() {
    timeout(DEADLINE, async {
        // One clone, several execs: the daemon stays mapped from it while the
        // doctor probes, as on a real machine.
        let scratch = tempfile::Builder::new()
            .prefix("pam-doctor-exe")
            .tempdir()
            .expect("tempdir");
        let (_tmp, base) = unserved_base();
        let exe = fresh_binary(scratch.path());
        let before = exec(&exe, &base, &["--version".to_owned()]);
        assert_eq!(before.code, 0, "{}", before.stderr);
        let daemon = Command::new(&exe)
            .arg("daemon")
            .env("PAM_BASE_DIR", &base)
            .env_remove("PAM_SOCKET_DIR")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("the daemon spawns");
        let mut child = daemon;
        let ready = {
            let base = base.clone();
            let exe = exe.clone();
            tokio::task::spawn_blocking(move || {
                for _ in 0..200 {
                    if base.join("run").join("pam.sock").exists() {
                        return true;
                    }
                    std::thread::sleep(Duration::from_millis(50));
                }
                let _ = exe;
                false
            })
            .await
            .expect("joins")
        };
        assert!(ready, "the daemon binds its socket");

        let run = {
            let (exe, base) = (exe.clone(), base.clone());
            tokio::task::spawn_blocking(move || {
                exec(
                    &exe,
                    &base,
                    &["doctor".to_owned(), "--no-report".to_owned()],
                )
            })
            .await
            .expect("joins")
        };
        assert_eq!(run.code, 6, "{}\n{}", run.stdout, run.stderr);

        let after = {
            let (exe, base) = (exe.clone(), base.clone());
            tokio::task::spawn_blocking(move || exec(&exe, &base, &["--version".to_owned()]))
                .await
                .expect("joins")
        };
        // Stop the daemon through the library (a SIGTERM by pid), not through
        // the binary, which may be the very thing that no longer execs.
        let stopped = {
            let base = base.clone();
            tokio::task::spawn_blocking(move || {
                pam::client::stop_daemon(&base, Duration::from_secs(15))
            })
            .await
            .expect("joins")
        };
        let _ = child.wait();
        assert!(stopped.is_ok(), "{stopped:?}");
        assert_eq!(
            after.code, 0,
            "the binary no longer execs after a doctor run: {}",
            after.stderr
        );
    })
    .await
    .expect("test within deadline");
}
