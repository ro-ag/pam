//! Cross-process PUB/SUB regression test (issue #1): a REAL `pam
//! daemon` **process** — the compiled binary, spawned via
//! `CARGO_BIN_EXE_pam` on an isolated `PAM_BASE_DIR` — followed from
//! this test process over the real ipc sockets.
//!
//! The in-process suites (testkit, `cli.rs`) run daemon and subscriber
//! in one process; the live failure this guards against was only ever
//! observed between two OS processes: `pam echo --no-wait` returned a
//! ticket, and a later `pam subscribe` received nothing because the
//! terminal event had already been published before the subscription
//! joined (zmq `PUB` has no replay). Both follow scenarios are covered:
//! subscribing while the request still runs, and subscribing after it
//! finished.
//!
//! Every await is bounded; the spawned daemon receives `SIGTERM` (the
//! same signal `pam daemon stop` sends) and is reaped on the way out,
//! panic included, so no stray daemon outlives the test.

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use pam::client::{self, DaemonStatus};
use pam_daemon::policy::PROFILE_SETTING_KEY;
use pam_proto::{Event, Response};
use pam_store::Store;
use tokio::time::timeout;

/// Wall deadline for the whole test; generous for loaded runners.
const DEADLINE: Duration = Duration::from_mins(1);

/// Bound on each follow call, well under [`DEADLINE`].
const FOLLOW_TIMEOUT: Duration = Duration::from_secs(15);

/// Bound on daemon readiness and shutdown waits.
const LIFECYCLE_WAIT: Duration = Duration::from_secs(15);

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

/// The real `pam daemon` child process on its own base dir, killed and
/// reaped on drop so a panicking test leaves no stray daemon behind.
struct LiveDaemon {
    child: Child,
    base: PathBuf,
}

impl LiveDaemon {
    /// Spawns `pam daemon` (the compiled binary) with `PAM_BASE_DIR`
    /// pointing at `base` and waits until it holds the instance lock
    /// and serves the request socket.
    fn spawn(base: &Path) -> Self {
        let child = Command::new(env!("CARGO_BIN_EXE_pam"))
            .arg("daemon")
            .env("PAM_BASE_DIR", base)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("pam daemon spawns");
        let mut daemon = Self {
            child,
            base: base.to_path_buf(),
        };
        daemon.wait_ready();
        daemon
    }

    /// Polls (bounded) until the daemon is probe-ready: lock held and
    /// `pam.sock` bound. A child that exits early fails legibly.
    fn wait_ready(&mut self) {
        let deadline = Instant::now() + LIFECYCLE_WAIT;
        let socket = self.base.join("run").join("pam.sock");
        loop {
            if let Some(status) = self.child.try_wait().expect("try_wait ok") {
                panic!("pam daemon exited during startup: {status}");
            }
            let running = matches!(
                client::probe_daemon(&self.base),
                Ok(DaemonStatus::Running { .. })
            );
            if running && socket.exists() {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "pam daemon not ready within {LIFECYCLE_WAIT:?}"
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    /// Stops the daemon and asserts nothing of it outlives the test.
    ///
    /// On unix that is the graceful path `pam daemon stop` drives:
    /// SIGTERM, lock release, a clean exit status. Windows has no
    /// SIGTERM — `pam_client::client::stop_daemon` reports
    /// `StopError::Unsupported` there — so [`signal_term`] terminates
    /// the process instead, and a terminated process has no drain and no
    /// success status to assert; the lock release still is.
    ///
    /// Either way the pid is reaped, which is the authoritative
    /// no-stray-process check (pgrep would race against other pam
    /// daemons on the machine).
    fn stop(mut self) {
        signal_term(&self.child);
        #[cfg(unix)]
        {
            assert!(
                client::wait_for_daemon_exit(&self.base, LIFECYCLE_WAIT).expect("probe ok"),
                "daemon still holds the lock after SIGTERM + {LIFECYCLE_WAIT:?}"
            );
            let status = self.child.wait().expect("daemon reaps");
            assert!(status.success(), "daemon exited with {status}");
        }
        #[cfg(not(unix))]
        {
            let _ = self.child.wait().expect("daemon reaps");
            assert!(
                client::wait_for_daemon_exit(&self.base, LIFECYCLE_WAIT).expect("probe ok"),
                "daemon still holds the lock {LIFECYCLE_WAIT:?} after termination"
            );
        }
    }
}

impl Drop for LiveDaemon {
    fn drop(&mut self) {
        // Already reaped (the `stop` happy path): nothing to signal —
        // the pid may belong to someone else by now.
        if matches!(self.child.try_wait(), Ok(Some(_))) {
            return;
        }
        // Best effort on the panic path: SIGTERM, short bounded reap,
        // SIGKILL as the last resort.
        signal_term(&self.child);
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            match self.child.try_wait() {
                Ok(Some(_)) => return,
                Ok(None) => std::thread::sleep(Duration::from_millis(50)),
                Err(_) => break,
            }
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Asks the daemon process to stop, the way the platform allows.
///
/// Unix: SIGTERM through `/bin/kill`, exactly like `pam daemon stop`
/// (the workspace denies `unsafe`, which a direct `libc::kill` would
/// need), so the daemon runs its graceful drain.
///
/// Windows: there is no SIGTERM — the daemon only listens for ctrl-c,
/// which cannot be delivered to one child — and the `kill` that happens
/// to be on a Windows runner's PATH is MSYS's, which cannot see a Win32
/// pid at all (`kill: 8916: No such process`). `taskkill /T /F` is the
/// only stop available, so the daemon is terminated rather than drained.
fn signal_term(child: &Child) {
    #[cfg(unix)]
    let _ = Command::new("kill")
        .arg("-TERM")
        .arg(child.id().to_string())
        .status();
    #[cfg(not(unix))]
    let _ = Command::new("taskkill")
        .args(["/PID", &child.id().to_string(), "/T", "/F"])
        .status();
}

/// Persists the relaxed profile on `base` before the daemon process
/// opens it.
///
/// [`pam_daemon::policy::Profile::platform_default`] is `Relaxed` only on
/// macOS and `Standard` everywhere else, and only the relaxed profile
/// auto-grants a non-destructive capability on first use. This test
/// drives `echo` without granting it, so without the seed it passes on
/// macOS and refuses with `not_granted` on Linux and Windows.
async fn seed_relaxed(base: &Path) {
    let store = Store::open(&base.join("state.sqlite3"))
        .await
        .expect("store opens");
    store
        .set_setting(PROFILE_SETTING_KEY, "\"relaxed\"")
        .await
        .expect("relaxed profile persists");
}

/// Sends a no-wait `echo` and returns its ticket.
async fn ticket_for_delayed_echo(base: &Path, delay_ms: u64) -> String {
    let args = serde_json::json!({ "delay_ms": delay_ms });
    let response = client::send_request(base, "echo", args, false, 10_000, None)
        .await
        .expect("request flows");
    let Response::Ticket { ticket, .. } = response else {
        panic!("expected a ticket, got a different response");
    };
    ticket
}

#[tokio::test]
async fn a_separate_daemon_process_streams_events_to_a_live_follow() {
    timeout(DEADLINE, async {
        let tmp = short_tempdir();
        let base = tmp.path().join("pam");
        seed_relaxed(&base).await;
        let daemon = LiveDaemon::spawn(&base);

        // Scenario 1 — follow while the request runs: the terminal
        // event travels PUB → SUB across the process boundary.
        let ticket = ticket_for_delayed_echo(&base, 1_500).await;
        let mut seen = Vec::new();
        let terminal = client::follow_ticket(&base, &ticket, FOLLOW_TIMEOUT, |event| {
            seen.push(event.clone());
        })
        .await
        .expect("live follow reaches a terminal event");
        assert_eq!(terminal, Event::Done);
        assert_eq!(seen.last(), Some(&Event::Done));

        // Scenario 2 — the recorded live failure: subscribe only after
        // the request finished. Its events were published to nobody and
        // PUB has no replay; the follow must terminate through the
        // store reconcile all the same.
        let ticket = ticket_for_delayed_echo(&base, 100).await;
        tokio::time::sleep(Duration::from_millis(1_500)).await;
        let terminal = client::follow_ticket(&base, &ticket, FOLLOW_TIMEOUT, |_| {})
            .await
            .expect("late follow reaches a terminal event");
        assert_eq!(terminal, Event::Done);

        daemon.stop();
    })
    .await
    .expect("test within deadline");
}
