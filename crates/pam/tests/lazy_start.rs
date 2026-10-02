//! The lazy daemon start, through the real `pam` binary: a client with no daemon behind it
//! spawns one, and that daemon is isolated from the command that started it.
//!
//! The daemon outlives the command and serves every later caller, so it must not inherit the
//! first caller's process group (a harness that kills the group would kill everyone's daemon) or
//! its environment (an agent-exported variable would reach every flow). Unix only: the
//! assertions read the process table through `ps`.

#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use pam::client::{self, DaemonStatus};

/// A variable only the calling shell has; it must never reach the daemon.
const MARKER_NAME: &str = "PAM_TEST_AGENT_SECRET_MARKER";
const MARKER_VALUE: &str = "leak-me-if-you-inherit-everything";

/// Bound on each wait for the daemon to come up or go away.
const WAIT: Duration = Duration::from_secs(30);

/// Short absolute temp path: macOS caps unix socket paths at 104 bytes.
fn short_tempdir() -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix("pam")
        .tempdir_in("/tmp")
        .expect("tempdir under /tmp")
}

fn pam(base: &Path, cwd: &Path, args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_pam"))
        .args(args)
        .env("PAM_BASE_DIR", base)
        .env(MARKER_NAME, MARKER_VALUE)
        .current_dir(cwd)
        .stdin(Stdio::null())
        .output()
        .expect("the pam binary runs")
}

/// Stops the lazily started daemon on the way out, panic included.
struct Cleanup {
    base: PathBuf,
    cwd: PathBuf,
}

impl Drop for Cleanup {
    fn drop(&mut self) {
        let _ = pam(&self.base, &self.cwd, &["daemon", "stop"]);
        let deadline = Instant::now() + WAIT;
        while Instant::now() < deadline {
            if matches!(
                client::probe_daemon(&self.base),
                Ok(DaemonStatus::NotRunning)
            ) {
                return;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }
}

fn ps(args: &[&str]) -> String {
    let output = Command::new("ps").args(args).output().expect("ps runs");
    String::from_utf8_lossy(&output.stdout).into_owned()
}

#[test]
fn a_lazily_started_daemon_leads_its_own_group_and_never_inherits_the_callers_environment() {
    let tmp = short_tempdir();
    let base = tmp.path().join("base");
    let _cleanup = Cleanup {
        base: base.clone(),
        cwd: tmp.path().to_path_buf(),
    };
    // macOS assesses a fresh binary on first exec; pay that outside the assertions.
    let _ = Command::new(env!("CARGO_BIN_EXE_pam"))
        .arg("--version")
        .output();

    let output = pam(&base, tmp.path(), &["status", "--json"]);
    assert!(
        output.status.success(),
        "a client with no daemon starts one and is answered: {} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("daemon_version"),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );

    let DaemonStatus::Running { pid: Some(pid) } =
        client::probe_daemon(&base).expect("the lock is probeable")
    else {
        panic!("the lazily started daemon holds the instance lock");
    };
    let pid = pid.to_string();

    let group = ps(&["-o", "pgid=", "-p", &pid]);
    assert_eq!(
        group.trim(),
        pid,
        "the daemon leads its own process group, not the caller's"
    );

    // `ps e` appends the process environment; only judge it when this host shows one.
    let environment = ps(&["eww", "-p", &pid]);
    if environment.contains("PAM_BASE_DIR=") {
        assert!(
            !environment.contains(MARKER_NAME) && !environment.contains(MARKER_VALUE),
            "the daemon must not inherit the caller's environment: {environment}"
        );
    } else {
        eprintln!("this host's `ps` shows no process environment; environment check skipped");
    }
}
