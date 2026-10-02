//! The lazy daemon start, through the real `pam` binary: a client with no daemon behind it
//! spawns one, and that daemon is isolated from the command that started it.
//!
//! The daemon outlives the command and serves every later caller, so it must not inherit the
//! first caller's process group (a harness that kills the group would kill everyone's daemon) or
//! its environment (an agent-exported variable would reach every flow). On unix the assertions
//! read the process table through `ps`. On Windows the one thing proved is that a caller
//! capturing the command's stdout through a pipe is not held up by the daemon the command
//! started.

#[cfg(unix)]
mod unix {

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
}

#[cfg(windows)]
mod windows {
    use std::collections::BTreeSet;
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    /// Bound on the captured call: a start takes a second or two; the hang this guards
    /// against lasts as long as the daemon lives.
    const CALL_BOUND: Duration = Duration::from_secs(30);

    /// The pids of every running `pam.exe`: the integration binary is `lazy_start-<hash>.exe`,
    /// so only daemons and clients of the binary under test show up.
    fn pam_pids() -> BTreeSet<u32> {
        let output = Command::new("tasklist")
            .args(["/FI", "IMAGENAME eq pam.exe", "/FO", "CSV", "/NH"])
            .output()
            .expect("tasklist runs");
        String::from_utf8_lossy(&output.stdout)
            .lines()
            .filter_map(|line| line.split("\",\"").nth(1)?.parse().ok())
            .collect()
    }

    /// Ends the daemon this test started (the pids `pam.exe` gained since `before`), panic
    /// included: Windows has no `pam daemon stop`.
    struct Cleanup {
        before: BTreeSet<u32>,
    }

    impl Cleanup {
        fn started(&self) -> BTreeSet<u32> {
            pam_pids().difference(&self.before).copied().collect()
        }
    }

    impl Drop for Cleanup {
        fn drop(&mut self) {
            for pid in self.started() {
                let _ = Command::new("taskkill")
                    .args(["/PID", &pid.to_string(), "/T", "/F"])
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status();
            }
        }
    }

    fn pam(base: &Path) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_pam"));
        command
            .args(["status", "--json"])
            .env("PAM_BASE_DIR", base)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        command
    }

    /// An agent harness captures the command's stdout through a pipe. The first command lazily
    /// starts the daemon, which outlives it: if the daemon held the pipe's write end the harness
    /// would wait for end-of-file until the daemon died.
    #[test]
    fn a_caller_capturing_stdout_through_a_pipe_is_not_held_by_the_daemon_it_started() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let base: PathBuf = tmp.path().join("base");
        let cleanup = Cleanup { before: pam_pids() };

        let started = Instant::now();
        let child = pam(&base).spawn().expect("the pam binary runs");
        let (done, answered) = mpsc::channel();
        let reader = std::thread::spawn(move || {
            let _ = done.send(child.wait_with_output());
        });
        let Ok(output) = answered.recv_timeout(CALL_BOUND) else {
            // The daemon is what keeps the pipe open; ending it frees the reader.
            drop(cleanup);
            let _ = reader.join();
            panic!(
                "the captured call did not return within {CALL_BOUND:?}: the daemon holds the pipe"
            );
        };
        let output = output.expect("the call finishes");
        let elapsed = started.elapsed();
        let _ = reader.join();
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success(),
            "{stdout} {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(stdout.contains("daemon_version"), "{stdout}");
        eprintln!("first captured call returned in {elapsed:?}");

        assert!(
            !cleanup.started().is_empty(),
            "the daemon keeps running after the command that started it returned"
        );
        let again = pam(&base).output().expect("the second call runs");
        assert!(
            again.status.success()
                && String::from_utf8_lossy(&again.stdout).contains("daemon_version"),
            "the daemon answers the next caller"
        );
    }
}
