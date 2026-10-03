//! Cross-process follow regression test: spawns a REAL `pam daemon` process
//! (`CARGO_BIN_EXE_pam`, isolated `PAM_BASE_DIR`) and follows it over its real public socket.
//!
//! In-process suites run daemon and follower in one process; the failure this file was written
//! for only reproduced across two OS processes: a terminal event published before a later
//! `pam subscribe` joined was lost for good. A follow is now one connection that the daemon
//! attaches before it reads the store again and ends with the durable answer, so both joining
//! while the request runs and joining after it finished terminate, and each follow costs exactly
//! one `query` request row.
//!
//! Every await is bounded; the spawned daemon receives `SIGTERM` (same as `pam daemon stop`) and
//! is reaped on the way out, panic included, so no stray daemon outlives the test.

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use pam::client::{self, DaemonStatus};
use pam_client::transport::{self, Probe};
use pam_daemon::policy::PROFILE_SETTING_KEY;
use pam_daemon::runtime_dir::RuntimeDir;
use pam_proto::wire::Via;
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
            // Debug detail in the daemon's own log: it is only ever read
            // by `dump_daemon_log`, on the failure path.
            .env("PAM_LOG", "debug")
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

    /// Polls (bounded) until the daemon is ready the way a client means it:
    /// lock held and a hello acknowledged on the public endpoint. A child
    /// that exits early fails legibly.
    fn wait_ready(&mut self) {
        let deadline = Instant::now() + LIFECYCLE_WAIT;
        let dirs = RuntimeDir::paths_at_base(&self.base).expect("runtime paths resolve");
        let hello = pam_daemon::framed::client_hello(Via::Direct);
        loop {
            if let Some(status) = self.child.try_wait().expect("try_wait ok") {
                panic!("pam daemon exited during startup: {status}");
            }
            let running = matches!(
                client::probe_daemon(&self.base),
                Ok(DaemonStatus::Running { .. })
            );
            if running
                && matches!(
                    transport::probe(&dirs, &hello, Duration::from_secs(1)),
                    Probe::Ready(_)
                )
            {
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
        if std::thread::panicking() {
            dump_daemon_log(&self.base);
        }
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
    let _ = Command::new("/bin/kill")
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
/// macOS and refuses with `not_granted` on Windows.
async fn seed_relaxed(base: &Path) {
    let store = Store::open(&base.join("state.sqlite3"))
        .await
        .expect("store opens");
    store
        .set_setting(PROFILE_SETTING_KEY, "\"relaxed\"")
        .await
        .expect("relaxed profile persists");
    store.set_setting("flows.scope_policy", &serde_json::json!({
        "version": 1, "repositories": [{"root": pam::caller::detect_caller().repo, "connectors": []}]
    }).to_string()).await.expect("explicit follow repository scope");
}

/// Executes the freshly built binary once, outside any readiness clock.
///
/// macOS assesses a new executable the first time it runs (once per
/// inode): a 100 MB debug `pam` sits in `_dyld_start` for 5 s on a quiet
/// machine and past 30 s while other builds saturate the disk and CPU,
/// then every later launch starts in well under a second. `cargo test`
/// links a fresh inode every run, so without this the daemon's 15 s
/// readiness budget was paying for the assessment, not for the daemon.
/// A trivial `--version` exec absorbs the one-time cost before the test's
/// own deadline starts, so the daemon spawn measures only the daemon.
fn warm_binary() {
    let _ = Command::new(env!("CARGO_BIN_EXE_pam"))
        .arg("--version")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

/// Prints the daemon's own log to the test output on the failure path.
///
/// The daemon is a separate process with its stdio closed, so a failing
/// assertion in this file otherwise leaves no trace of what the daemon
/// was doing — the CI flake recorded as ptrack issue #2 (a follow that
/// times out although the daemon answered the ticket) has been unreadable
/// for exactly that reason. Best effort: a missing log prints nothing.
fn dump_daemon_log(base: &Path) {
    let Ok(entries) = std::fs::read_dir(base.join("log")) else {
        eprintln!("--- daemon log: no log directory under {}", base.display());
        return;
    };
    let mut files: Vec<PathBuf> = entries.filter_map(Result::ok).map(|e| e.path()).collect();
    files.sort();
    for file in files {
        eprintln!("--- daemon log {} ---", file.display());
        if let Ok(text) = std::fs::read_to_string(&file) {
            eprintln!("{text}");
        }
    }
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
    // Outside the deadline on purpose: the one-time cost is the host's,
    // not the daemon's (see `warm_binary`).
    warm_binary();
    timeout(DEADLINE, async {
        let tmp = short_tempdir();
        let base = tmp.path().join("pam");
        seed_relaxed(&base).await;
        let daemon = LiveDaemon::spawn(&base);

        // Scenario 1 — follow while the request runs: its events and its
        // ending cross the process boundary on the one follow connection.
        let ticket = ticket_for_delayed_echo(&base, 1_500).await;
        let mut seen = Vec::new();
        let terminal = client::follow_ticket(&base, &ticket, FOLLOW_TIMEOUT, |event| {
            seen.push(event.clone());
        })
        .await
        .expect("live follow reaches a terminal event");
        assert_eq!(terminal, Event::Done);
        assert_eq!(seen.last(), Some(&Event::Done));
        assert_eq!(
            seen.iter().filter(|event| **event == Event::Done).count(),
            1,
            "the ending is delivered once: {seen:?}"
        );

        // Scenario 2 — the recorded live failure: follow only after the
        // request finished. Its events were published to nobody; the
        // authorising query sees the durable ending and the daemon answers
        // `end` at once.
        let ticket = ticket_for_delayed_echo(&base, 100).await;
        tokio::time::sleep(Duration::from_millis(1_500)).await;
        let asked = Instant::now();
        let terminal = client::follow_ticket(&base, &ticket, FOLLOW_TIMEOUT, |_| {})
            .await
            .expect("late follow reaches a terminal event");
        assert_eq!(terminal, Event::Done);
        assert!(
            asked.elapsed() < Duration::from_secs(5),
            "a finished ticket is answered at once: {:?}",
            asked.elapsed()
        );

        daemon.stop();

        // The daemon process is gone, so its store can be read: two follows,
        // two `query` rows. Nothing was queried to reconcile either of them.
        let store = Store::open(&base.join("state.sqlite3"))
            .await
            .expect("store opens after the daemon exited");
        let queries = store
            .list_requests_filtered(Some(200), None, None, None, Some("query"), false)
            .await
            .expect("request rows list");
        assert_eq!(queries.len(), 2, "one query row per follow: {queries:?}");
    })
    .await
    .expect("test within deadline");
}
