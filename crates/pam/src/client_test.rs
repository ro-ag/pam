use std::fs::File;
use std::io;
use std::time::Duration;

use pam_daemon::lifecycle::{InstanceLock, acquire_instance_lock};
use pam_daemon::runtime_dir::RuntimeDir;

use crate::client::{ClientError, EnsureOutcome, ensure_daemon_with};

/// Short bounds so the not-ready path stays fast.
const WAIT: Duration = Duration::from_millis(120);
const POLL: Duration = Duration::from_millis(10);

/// A fake daemon: holds the instance lock and serves a (plain-file)
/// socket path, exactly the two facts the readiness probe checks.
struct FakeDaemon {
    _lock: InstanceLock,
}

fn start_fake_daemon(base: &std::path::Path) -> FakeDaemon {
    let dirs = RuntimeDir::at_base(base).expect("runtime dir");
    let lock = acquire_instance_lock(dirs.run_dir()).expect("lock acquired");
    File::create(dirs.router_socket()).expect("socket file");
    FakeDaemon { _lock: lock }
}

#[test]
fn a_running_daemon_means_no_spawn() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let _daemon = start_fake_daemon(tmp.path());

    let mut spawns = 0;
    let outcome = ensure_daemon_with(
        tmp.path(),
        &mut || {
            spawns += 1;
            Ok(())
        },
        WAIT,
        POLL,
    )
    .expect("ensure succeeds");

    assert_eq!(outcome, EnsureOutcome::AlreadyRunning);
    assert_eq!(spawns, 0, "no spawn when the lock is held");
}

#[test]
fn no_daemon_spawns_one_and_waits_for_readiness() {
    let tmp = tempfile::tempdir().expect("tempdir");
    // A stale socket file with no lock holder must read as "no daemon".
    let dirs = RuntimeDir::at_base(tmp.path()).expect("runtime dir");
    File::create(dirs.router_socket()).expect("stale socket file");

    let base = tmp.path().to_path_buf();
    // The fake daemons started by the spawner, kept alive (each holds
    // the lock) until the assertion.
    let mut fakes: Vec<FakeDaemon> = Vec::new();
    let outcome = ensure_daemon_with(
        &base,
        &mut || {
            fakes.push(start_fake_daemon(&base));
            Ok(())
        },
        WAIT,
        POLL,
    )
    .expect("ensure succeeds");

    assert_eq!(outcome, EnsureOutcome::Started);
    assert_eq!(fakes.len(), 1, "one spawn was enough");
}

#[test]
fn a_daemon_that_never_becomes_ready_is_retried_once_then_reported() {
    let tmp = tempfile::tempdir().expect("tempdir");

    let mut spawns = 0;
    let err = ensure_daemon_with(
        tmp.path(),
        &mut || {
            spawns += 1;
            Ok(())
        },
        WAIT,
        POLL,
    )
    .expect_err("never-ready daemon must fail");

    assert!(matches!(err, ClientError::NotReady { .. }), "got {err:?}");
    assert_eq!(spawns, 2, "spawned, retried once, gave up");
}

#[test]
fn a_failing_spawn_is_reported_as_a_spawn_error() {
    let tmp = tempfile::tempdir().expect("tempdir");

    let err = ensure_daemon_with(
        tmp.path(),
        &mut || Err(io::Error::other("no exe")),
        WAIT,
        POLL,
    )
    .expect_err("spawn failure surfaces");

    assert!(matches!(err, ClientError::Spawn { .. }), "got {err:?}");
}
