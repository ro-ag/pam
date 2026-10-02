use std::fs::File;
use std::io;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use pam_daemon::daemon::CAUSE_DAEMON_OUTDATED;
use pam_daemon::lifecycle::{InstanceLock, acquire_instance_lock};
use pam_daemon::runtime_dir::RuntimeDir;
use pam_proto::{Outcome, Response};

#[cfg(unix)]
use crate::client::daemon_command;
use crate::client::{
    ClientError, DaemonStatus, EnsureOutcome, RequestError, RetryTimings, connect_dealer_within,
    daemon_env, ensure_daemon_off_thread, ensure_daemon_with, is_transient_cause, probe_daemon,
    send_envelope_with, should_retry, wait_for_daemon_exit,
};

/// Short bounds so the not-ready path stays fast.
const WAIT: Duration = Duration::from_millis(120);
const POLL: Duration = Duration::from_millis(10);

/// A fake daemon: holds the instance lock and listens on the socket path,
/// exactly the two facts the readiness probe checks (on unix the probe is
/// an actual connect, so the socket is a real listener).
struct FakeDaemon {
    _lock: InstanceLock,
    #[cfg(unix)]
    _listener: std::os::unix::net::UnixListener,
}

fn start_fake_daemon(base: &std::path::Path) -> FakeDaemon {
    let dirs = RuntimeDir::at_base(base).expect("runtime dir");
    let lock = acquire_instance_lock(dirs.run_dir()).expect("lock acquired");
    // A daemon removes the stale socket it finds under the lock, then binds.
    let _ = std::fs::remove_file(dirs.router_socket());
    #[cfg(unix)]
    let listener =
        std::os::unix::net::UnixListener::bind(dirs.router_socket()).expect("socket listener");
    #[cfg(not(unix))]
    File::create(dirs.router_socket()).expect("socket file");
    FakeDaemon {
        _lock: lock,
        #[cfg(unix)]
        _listener: listener,
    }
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

/// The readiness wait sleeps and polls synchronously; the async entry
/// point must keep that off the runtime's worker. On a single-threaded
/// runtime a blocked worker would stall this timer until the whole
/// not-ready wait (two attempts) had elapsed.
#[tokio::test(flavor = "current_thread")]
async fn the_async_readiness_wait_does_not_block_the_runtime_worker() {
    let tmp = tempfile::tempdir().unwrap();
    let base = tmp.path().to_path_buf();
    let started = std::time::Instant::now();
    let timer = tokio::spawn(async move {
        tokio::time::sleep(POLL).await;
        started.elapsed()
    });
    let never_ready = ensure_daemon_off_thread(&base, || Ok(()), WAIT, POLL).await;
    assert!(
        matches!(never_ready, Err(ClientError::NotReady { .. })),
        "{never_ready:?}"
    );
    let timer_done_after = timer.await.unwrap();
    assert!(
        timer_done_after < WAIT,
        "the timer task waited on the readiness probe: {timer_done_after:?}"
    );
}

#[test]
fn only_the_outdated_refusal_triggers_the_retry() {
    let outdated = Response::Refusal {
        retryable: false,
        id: "req_x".to_owned(),
        cause: CAUSE_DAEMON_OUTDATED.to_owned(),
        detail: "d".to_owned(),
        recovery: "r".to_owned(),
    };
    assert!(should_retry(&outdated));

    let other_refusal = Response::Refusal {
        retryable: false,
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

/// A fake daemon behind `pam.sock`: holds the instance lock, binds a zmq
/// `ROUTER` on the request endpoint (the two facts readiness checks) and
/// answers every envelope through `reply`. `None` swallows the request,
/// leaving the client to its own reply budget. No events endpoint exists.
struct FakeRouter {
    _lock: InstanceLock,
    calls: Arc<Mutex<Vec<serde_json::Value>>>,
    server: tokio::task::JoinHandle<()>,
}

impl FakeRouter {
    async fn start(
        base: &std::path::Path,
        reply: impl Fn(&serde_json::Value) -> Option<Response> + Send + 'static,
    ) -> Self {
        use zeromq::{RouterSocket, Socket, SocketRecv, SocketSend, ZmqMessage};
        let dirs = RuntimeDir::at_base(base).unwrap();
        let lock = acquire_instance_lock(dirs.run_dir()).unwrap();
        let mut router = RouterSocket::new();
        router.bind(&dirs.router_endpoint()).await.unwrap();
        let calls = Arc::new(Mutex::new(Vec::new()));
        let seen = Arc::clone(&calls);
        let server = tokio::spawn(async move {
            loop {
                let Ok(message) = router.recv().await else {
                    return;
                };
                let frames = message.into_vec();
                let request: serde_json::Value =
                    serde_json::from_slice(frames.last().unwrap()).unwrap();
                seen.lock().unwrap().push(request.clone());
                let Some(response) = reply(&request) else {
                    continue;
                };
                let mut message = ZmqMessage::from(serde_json::to_vec(&response).unwrap());
                message.push_front(frames[0].clone());
                // The peer may already have given up; that is its business.
                let _ = router.send(message).await;
            }
        });
        Self {
            _lock: lock,
            calls,
            server,
        }
    }

    /// Every envelope received so far, in arrival order.
    fn calls(&self) -> Vec<serde_json::Value> {
        self.calls.lock().unwrap().clone()
    }
}

impl Drop for FakeRouter {
    fn drop(&mut self) {
        self.server.abort();
    }
}

/// The version-handshake refusal, echoing the request's id.
fn outdated(request: &serde_json::Value) -> Response {
    Response::Refusal {
        retryable: false,
        id: request["id"].as_str().unwrap().to_owned(),
        cause: CAUSE_DAEMON_OUTDATED.to_owned(),
        detail: "a newer pam is on disk".to_owned(),
        recovery: "retry".to_owned(),
    }
}

#[tokio::test]
async fn refused_follow_queries_once_and_never_subscribes_to_events() {
    let tmp = tempfile::tempdir().unwrap();
    // Deliberately no events endpoint: an unauthorized follow must not connect.
    let router = FakeRouter::start(tmp.path(), |request| {
        assert_eq!(request["capability"], "query");
        Some(Response::Refusal {
            retryable: false,
            id: request["id"].as_str().unwrap().to_owned(),
            cause: "request_unavailable".to_owned(),
            detail: "Ticket is unavailable in this repository.".to_owned(),
            recovery: "Check repository access in the PAM GUI.".to_owned(),
        })
    })
    .await;
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
    assert_eq!(router.calls().len(), 1, "denial is never retried");
}

/// The reply budget is the envelope deadline plus the transport margin; a
/// daemon that takes the request and never answers is reported as a
/// timeout, not retried, and the daemon saw the envelope exactly once.
#[tokio::test]
async fn a_daemon_that_never_replies_times_out_after_the_deadline_plus_margin() {
    let tmp = tempfile::tempdir().unwrap();
    let router = FakeRouter::start(tmp.path(), |_| None).await;
    let started = std::time::Instant::now();
    let err = crate::client::send_request(
        tmp.path(),
        "echo",
        serde_json::json!({ "n": 1 }),
        true,
        1,
        None,
    )
    .await
    .expect_err("no reply must not hang");
    let elapsed = started.elapsed();
    let crate::client::RequestError::ReplyTimeout { waited } = err else {
        panic!("expected a reply timeout, got {err:?}");
    };
    // deadline_ms (1 ms) + the 5 s client margin, waited in full.
    assert_eq!(waited, Duration::from_millis(5_001));
    assert!(elapsed >= waited, "gave up early after {elapsed:?}");
    let calls = router.calls();
    assert_eq!(calls.len(), 1, "a timed-out exchange is not resent");
    assert_eq!(calls[0]["capability"], "echo");
    assert_eq!(calls[0]["deadline_ms"], 1);
}

/// `daemon_outdated` earns exactly one retry: two consecutive refusals end
/// the exchange with the second refusal, after two sends of the same
/// envelope with the retry pause between them.
#[tokio::test]
async fn two_outdated_refusals_stop_after_the_single_retry() {
    let tmp = tempfile::tempdir().unwrap();
    let router = FakeRouter::start(tmp.path(), |request| Some(outdated(request))).await;
    let started = std::time::Instant::now();
    // The fake never hands over (same lock, same pid for the whole test), so
    // the replacement wait is shortened to keep the test fast; it still
    // sits between the two sends, with the pause.
    let timings = RetryTimings {
        pause: Duration::from_millis(750),
        replacement_wait: Duration::from_millis(200),
    };
    let envelope = crate::request::build_envelope("echo", serde_json::json!({}), true, 1_000, None);
    let response = send_envelope_with(tmp.path(), &envelope, &timings, || async { Ok(()) })
        .await
        .expect("a refusal is an answer, not an error");
    let elapsed = started.elapsed();
    assert!(
        should_retry(&response),
        "the final answer is the refusal itself"
    );
    let calls = router.calls();
    assert_eq!(calls.len(), 2, "retried exactly once");
    assert_eq!(
        calls[0]["id"], calls[1]["id"],
        "the retry resends the same envelope"
    );
    assert_eq!(calls[1]["capability"], "echo");
    let Response::Refusal { id, .. } = &response else {
        panic!("expected the refusal, got {response:?}");
    };
    assert_eq!(*id, calls[0]["id"]);
    assert!(
        elapsed >= Duration::from_millis(750),
        "the retry waits for the old daemon to drain: {elapsed:?}"
    );
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

#[test]
fn the_session_override_redirects_dials_to_a_flat_socket_directory() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let session = tmp.path().join("session");

    let over = crate::client::dial_dirs_with(Some(&session), tmp.path()).expect("override dirs");
    assert_eq!(over.router_socket(), session.join("pam.sock"));
    assert_eq!(over.events_socket(), session.join("events.sock"));
    assert_eq!(over.run_dir(), session, "the relay dir has no run/ layout");

    let base = crate::client::dial_dirs_with(None, tmp.path()).expect("base dirs");
    assert_eq!(base.router_socket(), tmp.path().join("run/pam.sock"));
    assert_eq!(base.events_socket(), tmp.path().join("run/events.sock"));
}

#[tokio::test]
async fn the_session_override_never_spawns_a_daemon() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let session = tmp.path().join("session");
    let spawn = || panic!("an active session override must not spawn a daemon");
    crate::client::ensure_for_dial_off_thread(Some(&session), tmp.path(), spawn, WAIT, POLL)
        .await
        .expect("the override short-circuits the daemon probe");

    // Without the override, the same probe does spawn (and the fake
    // spawner marks the attempt) — here it must fail fast, not hang.
    let spawned = Arc::new(Mutex::new(0_u32));
    let counter = Arc::clone(&spawned);
    let spawn = move || {
        *counter.lock().expect("counter lock") += 1;
        Err(io::Error::other("no real daemon in this test"))
    };
    let result =
        crate::client::ensure_for_dial_off_thread(None, tmp.path(), spawn, WAIT, POLL).await;
    assert!(result.is_err(), "no daemon can become ready");
    assert!(
        *spawned.lock().expect("counter lock") > 0,
        "the probe tried to spawn"
    );
}

// --- readiness is an actual connect (finding 5) -----------------------------

/// A daemon that holds the lock but has not bound its socket yet (it binds
/// after crash recovery and warm-up) is *booting*: the client waits for it
/// and never spawns a second process, even when a stale `pam.sock` from the
/// previous run is still lying around.
#[cfg(unix)]
#[test]
fn a_booting_daemon_with_a_stale_socket_is_waited_for_not_raced() {
    let tmp = tempfile::tempdir().unwrap();
    let dirs = RuntimeDir::at_base(tmp.path()).unwrap();
    // The crashed predecessor's leftover: a socket file nobody listens on.
    drop(std::os::unix::net::UnixListener::bind(dirs.router_socket()).unwrap());
    assert!(dirs.router_socket().exists());
    let lock = acquire_instance_lock(dirs.run_dir()).unwrap();

    let socket = dirs.router_socket().to_path_buf();
    let binder = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(150));
        let _ = std::fs::remove_file(&socket);
        let listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
        std::thread::sleep(Duration::from_millis(600));
        drop(listener);
    });
    let mut spawn = || panic!("a booting daemon must not be raced with a second spawn");
    let outcome = ensure_daemon_with(tmp.path(), &mut spawn, Duration::from_secs(2), POLL)
        .expect("the daemon becomes ready once it binds");
    assert_eq!(outcome, EnsureOutcome::AlreadyRunning);
    binder.join().unwrap();
    drop(lock);
}

/// The first command after a crash: lock held by the booting daemon, socket
/// file stale. Ready must be false until a connect really succeeds.
#[cfg(unix)]
#[test]
fn a_stale_socket_file_is_never_ready_even_with_the_lock_held() {
    let tmp = tempfile::tempdir().unwrap();
    let dirs = RuntimeDir::at_base(tmp.path()).unwrap();
    drop(std::os::unix::net::UnixListener::bind(dirs.router_socket()).unwrap());
    let _lock = acquire_instance_lock(dirs.run_dir()).unwrap();
    let mut spawn = || panic!("the lock holder is alive; spawning would only lose the lock");
    let err = ensure_daemon_with(tmp.path(), &mut spawn, WAIT, POLL)
        .expect_err("a stale socket must not read as a ready daemon");
    assert!(matches!(err, ClientError::NotReady { .. }), "got {err:?}");
}

/// A stale socket with nobody holding the lock is no daemon at all: spawn.
#[cfg(unix)]
#[test]
fn a_dead_listener_without_the_lock_is_spawned_over() {
    let tmp = tempfile::tempdir().unwrap();
    let dirs = RuntimeDir::at_base(tmp.path()).unwrap();
    drop(std::os::unix::net::UnixListener::bind(dirs.router_socket()).unwrap());
    let base = tmp.path().to_path_buf();
    let mut fakes = Vec::new();
    let outcome = ensure_daemon_with(
        tmp.path(),
        &mut || {
            fakes.push(start_fake_daemon(&base));
            Ok(())
        },
        WAIT,
        POLL,
    )
    .unwrap();
    assert_eq!(outcome, EnsureOutcome::Started);
    assert_eq!(fakes.len(), 1);
}

/// A connect that fails because the daemon is mid-restart is retried (by
/// zeromq, inside the bound) instead of failing the first command, and a
/// socket nobody ever binds fails within the bound, not after zeromq's 30 s.
#[tokio::test]
async fn connect_waits_for_a_late_daemon_but_only_within_its_bound() {
    use zeromq::{RouterSocket, Socket};
    let tmp = tempfile::tempdir().unwrap();
    let dirs = RuntimeDir::at_base(tmp.path()).unwrap();
    let endpoint = dirs.router_endpoint();
    let binder = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(200)).await;
        let mut router = RouterSocket::new();
        router.bind(&endpoint).await.unwrap();
        // Keep the endpoint alive for the connecting side.
        tokio::time::sleep(Duration::from_secs(10)).await;
        drop(router);
    });
    connect_dealer_within(&dirs, Duration::from_secs(8))
        .await
        .expect("a daemon that binds within the bound is reached");
    binder.abort();

    let none = tempfile::tempdir().unwrap();
    let dirs = RuntimeDir::at_base(none.path()).unwrap();
    let started = std::time::Instant::now();
    let Err(error) = connect_dealer_within(&dirs, Duration::from_millis(600)).await else {
        panic!("nothing ever binds");
    };
    assert!(matches!(error, RequestError::Connect { .. }), "{error:?}");
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "bounded, not zeromq's 30 s default: {:?}",
        started.elapsed()
    );
}

// --- the spawned daemon is isolated from its caller (finding 6) --------------

fn vars(pairs: &[(&str, &str)]) -> Vec<(std::ffi::OsString, std::ffi::OsString)> {
    pairs
        .iter()
        .map(|(name, value)| ((*name).into(), (*value).into()))
        .collect()
}

#[test]
fn the_daemon_environment_is_an_allowlist_not_the_callers() {
    let kept = daemon_env(
        vars(&[
            ("HOME", "/home/me"),
            ("LANG", "en_US.UTF-8"),
            ("LC_ALL", "C"),
            ("PAM_LOG", "debug"),
            ("TMPDIR", "/tmp/x"),
            // Everything below belongs to the caller, not to the daemon.
            ("PAM_BASE_DIR", "/agent/chosen/base"),
            ("PAM_SOCKET_DIR", "/agent/relay"),
            ("AWS_SECRET_ACCESS_KEY", "s3cret"),
            ("CLAUDE_CODE_SESSION", "abc"),
            ("LD_PRELOAD", "/tmp/evil.so"),
            ("DYLD_INSERT_LIBRARIES", "/tmp/evil.dylib"),
            ("GIT_CONFIG_COUNT", "1"),
        ])
        .into_iter(),
    );
    let names: Vec<String> = kept
        .iter()
        .map(|(name, _)| name.to_string_lossy().into_owned())
        .collect();
    for wanted in ["HOME", "LANG", "LC_ALL", "PAM_LOG", "TMPDIR"] {
        assert!(
            names.iter().any(|name| name == wanted),
            "{wanted} kept: {names:?}"
        );
    }
    for dropped in [
        "PAM_BASE_DIR",
        "PAM_SOCKET_DIR",
        "AWS_SECRET_ACCESS_KEY",
        "CLAUDE_CODE_SESSION",
        "LD_PRELOAD",
        "DYLD_INSERT_LIBRARIES",
        "GIT_CONFIG_COUNT",
    ] {
        assert!(
            !names.iter().any(|name| name == dropped),
            "{dropped} dropped: {names:?}"
        );
    }
}

#[cfg(unix)]
#[test]
fn the_daemon_path_keeps_only_absolute_entries() {
    let path_of = |value: &str| {
        daemon_env(vars(&[("PATH", value)]).into_iter())
            .into_iter()
            .find(|(name, _)| name == "PATH")
            .map(|(_, value)| value.to_string_lossy().into_owned())
            .expect("a PATH is always given")
    };
    // Relative and empty entries resolve against whatever directory the
    // daemon runs in; they never survive.
    assert_eq!(path_of("/usr/bin::relative/bin:.:/bin"), "/usr/bin:/bin");
    assert_eq!(
        path_of(""),
        "/usr/local/bin:/usr/bin:/bin",
        "a usable default"
    );
    assert_eq!(path_of("bin:."), "/usr/local/bin:/usr/bin:/bin");
}

/// Runs the real [`daemon_command`] against a probe script that reports
/// what its environment, working directory and process group look like.
#[cfg(unix)]
#[test]
fn a_spawned_daemon_gets_its_own_process_group_cwd_and_environment() {
    use std::os::unix::fs::PermissionsExt;
    let tmp = tempfile::tempdir().unwrap();
    let probe = tmp.path().join("probe.sh");
    std::fs::write(
        &probe,
        "#!/bin/sh\nenv\necho \"CWD=$(pwd)\"\necho \"PID=$$\"\necho \"PGID=$(ps -o pgid= -p $$ | tr -d ' ')\"\n",
    )
    .unwrap();
    std::fs::set_permissions(&probe, std::fs::Permissions::from_mode(0o755)).unwrap();

    let mut command = daemon_command(
        &probe,
        std::path::Path::new("/some/base"),
        vars(&[
            ("HOME", "/home/me"),
            ("PATH", "/usr/bin:/bin"),
            ("SECRET_TOKEN", "hunter2"),
            ("PAM_BASE_DIR", "/agent/chosen/base"),
        ])
        .into_iter(),
    );
    command.stdout(std::process::Stdio::piped());
    // The freshly written script can briefly be "text file busy" while a
    // concurrent fork elsewhere in the test binary still holds the write fd.
    let output = (0..20)
        .find_map(|_| {
            command.output().map_or_else(
                |error| {
                    std::thread::sleep(Duration::from_millis(25));
                    let _ = error;
                    None
                },
                Some,
            )
        })
        .expect("the probe runs");
    let text = String::from_utf8_lossy(&output.stdout).into_owned();
    let line = |key: &str| {
        text.lines()
            .find_map(|line| line.strip_prefix(key))
            .map(str::to_owned)
    };
    assert_eq!(line("HOME=").as_deref(), Some("/home/me"), "{text}");
    assert_eq!(
        line("PAM_BASE_DIR=").as_deref(),
        Some("/some/base"),
        "the base is the client's resolved one, not the environment's: {text}"
    );
    assert!(!text.contains("SECRET_TOKEN"), "{text}");
    assert!(
        !text.contains("CARGO_"),
        "env_clear: nothing of this process's own environment leaks: {text}"
    );
    assert_eq!(line("CWD=").as_deref(), Some("/"), "{text}");
    let pid = line("PID=").expect("pid");
    assert_eq!(
        line("PGID=").as_deref(),
        Some(pid.as_str()),
        "the daemon leads its own process group: {text}"
    );
}

// --- ids, transient refusals and the follow loop (findings 4 and 12) ---------

fn result_for(request: &serde_json::Value, body: serde_json::Value) -> Response {
    Response::Result {
        id: request["id"].as_str().unwrap().to_owned(),
        outcome: Outcome::Solved,
        body,
        evidence: Vec::new(),
    }
}

fn refusal_for(request: &serde_json::Value, cause: &str) -> Response {
    Response::Refusal {
        retryable: false,
        id: request["id"].as_str().unwrap().to_owned(),
        cause: cause.to_owned(),
        detail: "the daemon is busy".to_owned(),
        recovery: "retry".to_owned(),
    }
}

#[tokio::test]
async fn the_request_id_on_the_wire_is_the_one_the_caller_chose() {
    let tmp = tempfile::tempdir().unwrap();
    let router = FakeRouter::start(tmp.path(), |request| {
        Some(result_for(request, serde_json::json!({})))
    })
    .await;
    crate::client::send_request_with_id(
        tmp.path(),
        "req_chosen_by_the_caller".to_owned(),
        "echo",
        serde_json::json!({}),
        true,
        1_000,
        None,
    )
    .await
    .unwrap();
    let calls = router.calls();
    assert_eq!(calls.len(), 1);
    assert_eq!(
        calls[0]["id"], "req_chosen_by_the_caller",
        "the id is known before sending, so a lost reply can still be named"
    );
}

#[test]
fn only_momentary_daemon_conditions_are_transient() {
    for cause in [
        "request_capacity_exhausted",
        "request_rate_exhausted",
        "daemon_shutting_down",
        CAUSE_DAEMON_OUTDATED,
        "deadline_exceeded",
        "internal_error",
    ] {
        assert!(is_transient_cause(cause), "{cause}");
    }
    for cause in [
        "not_granted",
        "scope_denied",
        "request_unavailable",
        "admin_denied",
    ] {
        assert!(!is_transient_cause(cause), "{cause} is a real answer");
    }
}

/// The follow rides out a saturated control pool: capacity and rate
/// refusals of the reconcile query are retried with backoff, and the ticket
/// that finished meanwhile is reported as finished, never as "refused".
#[tokio::test]
async fn a_follow_retries_capacity_refusals_instead_of_reporting_refused() {
    let tmp = tempfile::tempdir().unwrap();
    let count = Arc::new(Mutex::new(0_u32));
    let seen = Arc::clone(&count);
    let router = FakeRouter::start(tmp.path(), move |request| {
        assert_eq!(request["capability"], "query");
        let mut calls = seen.lock().unwrap();
        *calls += 1;
        Some(match *calls {
            1 => refusal_for(request, "request_capacity_exhausted"),
            2 => refusal_for(request, "request_rate_exhausted"),
            3 => refusal_for(request, "daemon_shutting_down"),
            _ => result_for(request, serde_json::json!({"state": "done"})),
        })
    })
    .await;
    let mut events = Vec::new();
    let event =
        crate::client::follow_ticket(tmp.path(), "req_busy", Duration::from_secs(30), |event| {
            events.push(event.clone());
        })
        .await
        .expect("transient refusals are retried to the terminal answer");
    assert_eq!(event, pam_proto::Event::Done);
    assert_eq!(
        router.calls().len(),
        4,
        "three busy answers, then the truth"
    );
}

/// A policy refusal is still final, even among transient ones.
#[tokio::test]
async fn a_policy_refusal_ends_the_follow_after_transient_ones() {
    let tmp = tempfile::tempdir().unwrap();
    let count = Arc::new(Mutex::new(0_u32));
    let seen = Arc::clone(&count);
    let router = FakeRouter::start(tmp.path(), move |request| {
        let mut calls = seen.lock().unwrap();
        *calls += 1;
        Some(if *calls == 1 {
            refusal_for(request, "request_capacity_exhausted")
        } else {
            refusal_for(request, "scope_denied")
        })
    })
    .await;
    let result =
        crate::client::follow_ticket(tmp.path(), "req_denied", Duration::from_secs(30), |_| {})
            .await;
    assert!(
        matches!(&result, Err(RequestError::FollowRefused { cause, .. }) if cause == "scope_denied"),
        "{result:?}"
    );
    assert_eq!(router.calls().len(), 2);
}

/// With no events endpoint at all (a daemon restarting, a relay that only
/// carries the request socket) the follow does not abort: events are only
/// hints, and the durable query keeps reconciling.
#[tokio::test]
async fn a_follow_survives_a_missing_event_stream_by_polling_the_store() {
    let tmp = tempfile::tempdir().unwrap();
    let count = Arc::new(Mutex::new(0_u32));
    let seen = Arc::clone(&count);
    let router = FakeRouter::start(tmp.path(), move |request| {
        let mut calls = seen.lock().unwrap();
        *calls += 1;
        Some(result_for(
            request,
            serde_json::json!({"state": if *calls >= 3 { "done" } else { "running" }}),
        ))
    })
    .await;
    let event =
        crate::client::follow_ticket(tmp.path(), "req_run", Duration::from_secs(30), |_| {})
            .await
            .expect("a missing PUB endpoint degrades to reconcile polling");
    assert_eq!(event, pam_proto::Event::Done);
    assert!(router.calls().len() >= 3);
}

/// An event kind this client does not know (a newer daemon) is skipped, not
/// fatal: the follow still ends on the durable answer.
#[tokio::test]
async fn a_follow_skips_unknown_event_kinds() {
    use zeromq::{PubSocket, Socket, SocketSend, ZmqMessage};
    let tmp = tempfile::tempdir().unwrap();
    let dirs = RuntimeDir::at_base(tmp.path()).unwrap();
    let mut publisher = PubSocket::new();
    publisher.bind(&dirs.events_endpoint()).await.unwrap();
    let count = Arc::new(Mutex::new(0_u32));
    let seen = Arc::clone(&count);
    let router = FakeRouter::start(tmp.path(), move |request| {
        let mut calls = seen.lock().unwrap();
        *calls += 1;
        Some(result_for(
            request,
            serde_json::json!({"state": if *calls >= 4 { "done" } else { "running" }}),
        ))
    })
    .await;
    let pump = tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_millis(100)).await;
            let mut message = ZmqMessage::from("req_future");
            message.push_back(br#"{"kind":"from_the_future","detail":1}"#.to_vec().into());
            let _ = publisher.send(message).await;
        }
    });
    let event =
        crate::client::follow_ticket(tmp.path(), "req_future", Duration::from_secs(30), |_| {})
            .await
            .expect("an unknown event kind must not abort the follow");
    pump.abort();
    assert_eq!(event, pam_proto::Event::Done);
    assert!(router.calls().len() >= 4);
}

// --- the version handshake waits for the replacement (finding 13) ------------

/// After a `daemon_outdated` refusal the old daemon drains and a new one
/// takes over: the single retry waits for that replacement and lands on it,
/// not on the draining daemon's `daemon_shutting_down`.
#[tokio::test]
async fn the_outdated_retry_lands_on_the_replacement_daemon() {
    let tmp = tempfile::tempdir().unwrap();
    let base = tmp.path().to_path_buf();
    let replacement_seen = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&replacement_seen);
    let handover_base = base.clone();
    let old = FakeRouter::start(tmp.path(), move |request| Some(outdated(request))).await;
    // The old daemon drains, exits, and a new binary binds a little later.
    let handover = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(250)).await;
        drop(old);
        tokio::time::sleep(Duration::from_millis(400)).await;
        let new = FakeRouter::start(&handover_base, move |request| {
            sink.lock().unwrap().push(request.clone());
            Some(result_for(request, serde_json::json!({"served_by": "new"})))
        })
        .await;
        // Hold the new daemon until the test is done with it.
        tokio::time::sleep(Duration::from_secs(10)).await;
        drop(new);
    });
    let timings = RetryTimings {
        pause: Duration::from_millis(50),
        replacement_wait: Duration::from_secs(8),
    };
    let envelope = crate::request::build_envelope("echo", serde_json::json!({}), true, 5_000, None);
    let ensure_base = base.clone();
    let response = send_envelope_with(&base, &envelope, &timings, || {
        let base = ensure_base.clone();
        async move {
            // A real ensure, with a spawner that must only ever be a no-op
            // here: the replacement is "started" by the handover task.
            ensure_daemon_off_thread(&base, || Ok(()), Duration::from_secs(5), POLL)
                .await
                .map(|_| ())
                .map_err(RequestError::from)
        }
    })
    .await
    .expect("the retry reaches the replacement daemon");
    handover.abort();
    let Response::Result { body, .. } = response else {
        panic!("expected the replacement's result, got {response:?}");
    };
    assert_eq!(body["served_by"], "new");
    let served = replacement_seen.lock().unwrap();
    assert_eq!(
        served.len(),
        1,
        "the retry went to the new daemon exactly once"
    );
    assert_eq!(served[0]["id"], envelope.id, "it resends the same envelope");
}
