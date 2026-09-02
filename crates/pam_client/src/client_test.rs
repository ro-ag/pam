use std::fs::File;
use std::io;
use std::time::Duration;

use pam_daemon::daemon::CAUSE_DAEMON_OUTDATED;
use pam_daemon::lifecycle::{InstanceLock, acquire_instance_lock};
use pam_daemon::runtime_dir::RuntimeDir;
use pam_proto::{Outcome, Response};

use crate::client::{
    ClientError, DaemonStatus, EnsureOutcome, ensure_daemon_with, probe_daemon, should_retry,
    wait_for_daemon_exit,
};

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

#[test]
fn only_the_outdated_refusal_triggers_the_retry() {
    let outdated = Response::Refusal {
        id: "req_x".to_owned(),
        cause: CAUSE_DAEMON_OUTDATED.to_owned(),
        detail: "d".to_owned(),
        recovery: "r".to_owned(),
    };
    assert!(should_retry(&outdated));

    let other_refusal = Response::Refusal {
        id: "req_x".to_owned(),
        cause: "not_granted".to_owned(),
        detail: "d".to_owned(),
        recovery: "r".to_owned(),
    };
    assert!(!should_retry(&other_refusal));

    let result = Response::Result {
        id: "req_x".to_owned(),
        outcome: Outcome::Solved,
        body: serde_json::json!({}),
        evidence: Vec::new(),
    };
    assert!(!should_retry(&result));
}

#[test]
fn probe_reports_the_lock_holder_and_its_release() {
    let tmp = tempfile::tempdir().expect("tempdir");

    assert_eq!(
        probe_daemon(tmp.path()).expect("probe ok"),
        DaemonStatus::NotRunning
    );

    let daemon = start_fake_daemon(tmp.path());
    // `DaemonStatus::Running.pid` is an Option by contract — the holder's
    // pid "when the lock file was readable". Unix locks are advisory, so
    // the probe reads it back; Windows byte-range locks are mandatory and
    // any read through another handle fails with `ERROR_LOCK_VIOLATION`,
    // which is precisely the None the Option exists for. The fact under
    // test — the lock is seen as held — holds on both.
    assert_eq!(
        probe_daemon(tmp.path()).expect("probe ok"),
        DaemonStatus::Running {
            pid: if cfg!(unix) {
                Some(std::process::id())
            } else {
                None
            },
        }
    );

    // Held lock: the bounded wait times out without release.
    assert!(
        !wait_for_daemon_exit(tmp.path(), WAIT).expect("wait ok"),
        "lock is still held"
    );

    drop(daemon);
    assert!(
        wait_for_daemon_exit(tmp.path(), WAIT).expect("wait ok"),
        "lock released after drop"
    );
}

#[tokio::test]
async fn send_request_refuses_admin_capabilities_before_the_socket() {
    // No daemon exists under this base; the guard must fire before
    // ensure_daemon would try to spawn one.
    let tmp = tempfile::tempdir().expect("tempdir");

    let err = crate::client::send_request(
        tmp.path(),
        "admin.grants.add",
        serde_json::json!({ "capability": "deploy" }),
        true,
        1_000,
        None,
    )
    .await
    .expect_err("admin capabilities are refused");

    assert!(matches!(
        err,
        crate::client::RequestError::AdminOnly { ref capability }
            if capability == "admin.grants.add"
    ));
    let dirs = RuntimeDir::at_base(tmp.path()).expect("runtime dir");
    assert!(
        !dirs.router_socket().exists(),
        "the guard fired before anything touched the runtime dir"
    );
}

#[tokio::test]
async fn send_admin_rejects_non_admin_operations() {
    let tmp = tempfile::tempdir().expect("tempdir");

    let err = crate::client::send_admin(tmp.path(), "echo", serde_json::json!({}), 1_000)
        .await
        .expect_err("non-admin capabilities are refused");

    assert!(matches!(
        err,
        crate::client::RequestError::NotAdmin { ref capability } if capability == "echo"
    ));
}
