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

#[tokio::test]
async fn send_admin_requires_the_private_channel_even_when_public_daemon_is_ready() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let _daemon = start_fake_daemon(tmp.path());
    let error = crate::client::send_admin(
        tmp.path(),
        "admin.grants.add",
        serde_json::json!({"capability": "deploy"}),
        100,
    )
    .await
    .expect_err("public readiness does not authorize administration");
    assert!(matches!(
        error,
        crate::client::RequestError::AdminTransport { .. }
    ));
}

#[tokio::test]
async fn refused_follow_queries_once_and_never_subscribes_to_events() {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    use zeromq::{RouterSocket, Socket, SocketRecv, SocketSend, ZmqMessage};
    let tmp = tempfile::tempdir().unwrap();
    let dirs = RuntimeDir::at_base(tmp.path()).unwrap();
    let _lock = acquire_instance_lock(dirs.run_dir()).unwrap();
    let mut router = RouterSocket::new();
    router.bind(&dirs.router_endpoint()).await.unwrap();
    // Deliberately no events endpoint: an unauthorized follow must not connect.
    let calls = Arc::new(AtomicUsize::new(0));
    let observed = Arc::clone(&calls);
    let server = tokio::spawn(async move {
        loop {
            let frames = router.recv().await.unwrap().into_vec();
            observed.fetch_add(1, Ordering::SeqCst);
            let request: serde_json::Value =
                serde_json::from_slice(frames.last().unwrap()).unwrap();
            assert_eq!(request["capability"], "query");
            let reply = Response::Refusal {
                id: request["id"].as_str().unwrap().to_owned(),
                cause: "request_unavailable".to_owned(),
                detail: "Ticket is unavailable in this repository.".to_owned(),
                recovery: "Check repository access in the PAM GUI.".to_owned(),
            };
            let payload = serde_json::to_vec(&reply).unwrap();
            let mut message = ZmqMessage::from(payload);
            message.push_front(frames[0].clone());
            router.send(message).await.unwrap();
        }
    });
    let mut events = Vec::new();
    let result = crate::client::follow_ticket(
        tmp.path(),
        "original-ticket",
        Duration::from_secs(5),
        |event| events.push(event.clone()),
    )
    .await;
    assert!(
        matches!(&result, Err(crate::client::RequestError::FollowRefused { ticket, cause, .. }) if ticket == "original-ticket" && cause == "request_unavailable"),
        "{result:?}"
    );
    assert!(events.is_empty());
    assert_eq!(calls.load(Ordering::SeqCst), 1, "denial is never retried");
    server.abort();
    let _ = server.await;
}

#[test]
fn probe_and_exit_wait_leave_absent_runtime_directory_absent() {
    let tmp = tempfile::tempdir().unwrap();
    assert_eq!(probe_daemon(tmp.path()).unwrap(), DaemonStatus::NotRunning);
    assert!(wait_for_daemon_exit(tmp.path(), WAIT).unwrap());
    assert!(!tmp.path().join("run").exists());
}

#[test]
fn daemon_autostart_is_responsible_for_creating_runtime_files() {
    let tmp = tempfile::tempdir().unwrap();
    let mut daemon = None;
    let result = ensure_daemon_with(
        tmp.path(),
        &mut || {
            assert!(!tmp.path().join("run").exists());
            daemon = Some(start_fake_daemon(tmp.path()));
            Ok(())
        },
        WAIT,
        POLL,
    )
    .unwrap();
    assert_eq!(result, EnsureOutcome::Started);
    assert!(daemon.is_some());
}

#[test]
fn another_shared_probe_is_not_mistaken_for_the_exclusive_daemon_lock() {
    let tmp = tempfile::tempdir().unwrap();
    let dirs = RuntimeDir::at_base(tmp.path()).unwrap();
    let path = dirs.run_dir().join(pam_daemon::lifecycle::LOCK_FILE);
    std::fs::write(&path, "stale").unwrap();
    let reader = File::open(&path).unwrap();
    reader.try_lock_shared().unwrap();
    assert_eq!(probe_daemon(tmp.path()).unwrap(), DaemonStatus::NotRunning);
    reader.unlock().unwrap();
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "stale");
    // The probe released its lock before returning, so a daemon can acquire it.
    let _daemon = acquire_instance_lock(dirs.run_dir()).unwrap();
}

#[cfg(unix)]
#[test]
fn connecting_to_running_daemon_preserves_read_only_runtime_permissions() {
    use std::os::unix::fs::PermissionsExt;
    let tmp = tempfile::tempdir().unwrap();
    let _daemon = start_fake_daemon(tmp.path());
    let dirs = RuntimeDir::paths_at_base(tmp.path()).unwrap();
    let lock = dirs.run_dir().join(pam_daemon::lifecycle::LOCK_FILE);
    std::fs::set_permissions(&lock, std::fs::Permissions::from_mode(0o400)).unwrap();
    std::fs::set_permissions(dirs.run_dir(), std::fs::Permissions::from_mode(0o500)).unwrap();
    let mut spawn = || panic!("running daemon must not spawn another process");
    let ready = ensure_daemon_with(tmp.path(), &mut spawn, WAIT, POLL);
    let status = probe_daemon(tmp.path());
    let run_mode = std::fs::metadata(dirs.run_dir())
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    let lock_mode = std::fs::metadata(&lock).unwrap().permissions().mode() & 0o777;
    std::fs::set_permissions(dirs.run_dir(), std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::set_permissions(&lock, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(ready.unwrap(), EnsureOutcome::AlreadyRunning);
    assert!(matches!(status.unwrap(), DaemonStatus::Running { .. }));
    assert_eq!(run_mode, 0o500);
    assert_eq!(lock_mode, 0o400);
}
