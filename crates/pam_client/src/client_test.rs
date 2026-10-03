use std::fs::File;
use std::future::Future;
use std::io;
use std::path::Path;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use pam_daemon::daemon::CAUSE_DAEMON_OUTDATED;
use pam_daemon::lifecycle::acquire_instance_lock;
use pam_daemon::runtime_dir::RuntimeDir;
use pam_proto::wire::{Frame, Via, cause};
use pam_proto::{Event, Outcome, Response};

#[cfg(unix)]
use crate::client::daemon_command;
use crate::client::{
    ClientError, DaemonStatus, DialOptions, Ensure, EnsureOutcome, RequestError, StopError,
    daemon_env, ensure_daemon_off_thread, ensure_daemon_with, follow_with, is_transient_cause,
    probe_daemon, send_envelope_with, should_retry, wait_for_daemon_exit,
};
use crate::transport_test::{
    DaemonPeer, EPOCH, FakeDaemon, Seen, answering, envelope_id, legacy, short_tempdir,
};

/// Short bounds so the not-ready path stays fast.
const WAIT: Duration = Duration::from_millis(400);
const POLL: Duration = Duration::from_millis(10);

/// A fake daemon that holds the instance lock and acknowledges every hello: the two facts
/// readiness checks. It answers no request.
fn start_fake_daemon(base: &Path) -> FakeDaemon {
    FakeDaemon::start(base, greeter)
}

async fn greeter(mut peer: DaemonPeer) {
    peer.greet(EPOCH).await;
    peer.until_closed().await;
}

/// Dial options for a test: the production values, direct, with short waits.
fn options() -> DialOptions {
    DialOptions {
        pause: Duration::from_millis(50),
        replacement_wait: Duration::from_secs(8),
        backoff_min: Duration::from_millis(20),
        backoff_max: Duration::from_millis(80),
        ..DialOptions::new(None)
    }
}

/// An ensure step that does nothing: the test's fake is already there.
async fn no_ensure() -> Result<(), RequestError> {
    Ok(())
}

#[test]
fn a_running_daemon_means_no_spawn() {
    let tmp = short_tempdir();
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
    let tmp = short_tempdir();
    // A stale socket file with no lock holder must read as "no daemon".
    let dirs = RuntimeDir::at_base(tmp.path()).expect("runtime dir");
    File::create(dirs.public_socket()).expect("stale socket file");

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
    let tmp = short_tempdir();

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
    let tmp = short_tempdir();

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
    let tmp = short_tempdir();
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
    let tmp = short_tempdir();

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
    let tmp = short_tempdir();

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
    assert!(
        !tmp.path().join("run").exists(),
        "the guard fired before anything touched the runtime dir"
    );
}

#[tokio::test]
async fn send_admin_rejects_non_admin_operations() {
    let tmp = short_tempdir();

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
    let tmp = short_tempdir();
    let daemon = start_fake_daemon(tmp.path());
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
    assert!(
        daemon.connections() >= 1,
        "the daemon was ensured through the public hello first"
    );
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

/// A fake daemon scripted per follow: it greets, records the `follow` frame, and hands the
/// connection to `script` with the number of that follow (from 1). Hello-only connections (the
/// readiness probe) are greeted and not counted.
fn follow_daemon<H, F>(base: &Path, script: H) -> (FakeDaemon, Seen)
where
    H: Fn(usize, DaemonPeer, serde_json::Value) -> F + Send + Sync + 'static,
    F: Future<Output = ()> + Send + 'static,
{
    let seen: Seen = Arc::default();
    let record = Arc::clone(&seen);
    let script = Arc::new(script);
    let daemon = FakeDaemon::start(base, move |mut peer| {
        let record = Arc::clone(&record);
        let script = Arc::clone(&script);
        async move {
            let Some(frame) = peer.greet(EPOCH).await else {
                return;
            };
            let nth = {
                let mut seen = record.lock().unwrap();
                seen.push(frame.clone());
                seen.len()
            };
            script(nth, peer, frame).await;
        }
    });
    (daemon, seen)
}

/// A refused follow is one connection and one `end`: nothing is retried, nothing else is asked.
#[tokio::test]
async fn a_refused_follow_is_one_connection_and_one_end_and_is_never_retried() {
    let tmp = short_tempdir();
    let (_daemon, seen) = follow_daemon(tmp.path(), |_, mut peer, frame| async move {
        peer.end_refused(&envelope_id(&frame), "result_unavailable", false)
            .await;
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
        matches!(&result, Err(crate::client::RequestError::FollowRefused { ticket, cause, .. }) if ticket == "original-ticket" && cause == "result_unavailable"),
        "{result:?}"
    );
    assert!(events.is_empty());
    let seen = seen.lock().unwrap();
    assert_eq!(seen.len(), 1, "denial is never retried");
    assert_eq!(seen[0]["t"], "follow");
    assert_eq!(seen[0]["envelope"]["capability"], "query");
    assert_eq!(seen[0]["envelope"]["wait"], true);
    assert_eq!(seen[0]["envelope"]["args"]["ticket"], "original-ticket");
}

/// The reply budget is the envelope deadline plus the transport margin; a
/// daemon that takes the request and never answers is reported as a
/// timeout, not retried, and the daemon saw the envelope exactly once.
#[tokio::test]
async fn a_daemon_that_never_replies_times_out_after_the_deadline_plus_margin() {
    let tmp = short_tempdir();
    let (_daemon, seen) = answering(tmp.path(), |_| None);
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
    let calls = seen.lock().unwrap();
    assert_eq!(calls.len(), 1, "a timed-out exchange is not resent");
    assert_eq!(calls[0]["capability"], "echo");
    assert_eq!(calls[0]["deadline_ms"], 1);
}

/// `daemon_outdated` earns exactly one retry: two consecutive refusals end
/// the exchange with the second refusal, after two sends of the same
/// envelope with the retry pause between them.
#[tokio::test]
async fn two_outdated_refusals_stop_after_the_single_retry() {
    let tmp = short_tempdir();
    let (_daemon, seen) = answering(tmp.path(), |request| Some(outdated(request)));
    let started = std::time::Instant::now();
    // The fake never hands over (same lock, same pid for the whole test), so
    // the replacement wait is shortened to keep the test fast; it still
    // sits between the two sends, with the pause.
    let options = DialOptions {
        pause: Duration::from_millis(750),
        replacement_wait: Duration::from_millis(200),
        ..options()
    };
    let envelope = crate::request::build_envelope("echo", serde_json::json!({}), true, 1_000, None);
    let response = send_envelope_with(tmp.path(), &envelope, &options, no_ensure)
        .await
        .expect("a refusal is an answer, not an error");
    let elapsed = started.elapsed();
    assert!(
        should_retry(&response),
        "the final answer is the refusal itself"
    );
    let calls = seen.lock().unwrap();
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

/// A daemon that finds its binary replaced answers the hello itself with
/// `error daemon_outdated`. That is surfaced exactly like the refusal: one
/// retry, and the answer is a refusal naming the request, marked retryable.
#[tokio::test]
async fn an_outdated_error_at_the_hello_is_the_same_refusal_and_the_same_single_retry() {
    let tmp = short_tempdir();
    let daemon = FakeDaemon::start(tmp.path(), |mut peer| async move {
        peer.hello().await;
        peer.send(&Frame::error(
            cause::DAEMON_OUTDATED,
            "the pam binary was replaced while this daemon ran",
            "The daemon is restarting with the new binary; retry your command.",
        ))
        .await;
        peer.until_closed().await;
    });
    let options = DialOptions {
        replacement_wait: Duration::from_millis(100),
        ..options()
    };
    let envelope = crate::request::build_envelope("echo", serde_json::json!({}), true, 1_000, None);
    let response = send_envelope_with(tmp.path(), &envelope, &options, no_ensure)
        .await
        .expect("an error frame at the hello is an answer");
    let Response::Refusal {
        id,
        cause,
        retryable,
        recovery,
        ..
    } = response
    else {
        panic!("expected a refusal");
    };
    assert_eq!(
        id, envelope.id,
        "the refusal names the request that was not served"
    );
    assert_eq!(cause, CAUSE_DAEMON_OUTDATED);
    assert!(retryable);
    assert!(recovery.contains("retry"), "{recovery}");
    assert_eq!(daemon.connections(), 2, "sent, then retried exactly once");
}

/// Any other `error` frame at the hello is the refusal it is, sent once.
#[tokio::test]
async fn a_full_listener_is_a_retryable_refusal_not_a_transport_error() {
    let tmp = short_tempdir();
    let daemon = FakeDaemon::start(tmp.path(), |mut peer| async move {
        peer.send(&Frame::error(
            cause::CONNECTION_CAPACITY_EXHAUSTED,
            "the public listener is serving its maximum of 256 connections",
            "Retry shortly.",
        ))
        .await;
        peer.until_closed().await;
    });
    let envelope = crate::request::build_envelope("echo", serde_json::json!({}), true, 1_000, None);
    let response = send_envelope_with(tmp.path(), &envelope, &options(), no_ensure)
        .await
        .unwrap();
    assert!(
        matches!(&response, Response::Refusal { cause, retryable: true, id, .. }
            if cause == cause::CONNECTION_CAPACITY_EXHAUSTED && *id == envelope.id),
        "{response:?}"
    );
    assert_eq!(daemon.connections(), 1);
}

#[test]
fn probe_and_exit_wait_leave_absent_runtime_directory_absent() {
    let tmp = short_tempdir();
    assert_eq!(probe_daemon(tmp.path()).unwrap(), DaemonStatus::NotRunning);
    assert!(wait_for_daemon_exit(tmp.path(), WAIT).unwrap());
    assert!(!tmp.path().join("run").exists());
}

#[test]
fn daemon_autostart_is_responsible_for_creating_runtime_files() {
    let tmp = short_tempdir();
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
    let tmp = short_tempdir();
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
    let tmp = short_tempdir();
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
    let tmp = short_tempdir();
    let session = tmp.path().join("session");

    let over = crate::client::dial_dirs_with(Some(&session), tmp.path()).expect("override dirs");
    assert_eq!(
        over.public_socket().parent(),
        Some(session.as_path()),
        "the relay directory holds the socket directly"
    );
    assert_eq!(over.run_dir(), session, "the relay dir has no run/ layout");

    let base = crate::client::dial_dirs_with(None, tmp.path()).expect("base dirs");
    assert_eq!(
        base.public_socket().parent(),
        Some(tmp.path().join("run").as_path())
    );
    assert_eq!(
        over.public_socket().file_name(),
        base.public_socket().file_name(),
        "the same socket name on both paths"
    );
}

#[tokio::test]
async fn the_session_override_never_spawns_a_daemon() {
    let tmp = short_tempdir();
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

/// Through a session relay the hello says `relay`, the request goes to the
/// socket inside the session directory, and no lock under the base is needed.
#[tokio::test]
async fn a_dial_through_the_session_directory_says_relay_in_its_hello() {
    let tmp = short_tempdir();
    let session = tmp.path().join("s");
    std::fs::create_dir_all(&session).unwrap();
    let hellos = Arc::new(Mutex::new(Vec::new()));
    let record = Arc::clone(&hellos);
    let dirs = RuntimeDir::paths_at_dir(&session).unwrap();
    let relay = FakeDaemon::listen(&dirs, None, move |mut peer| {
        let record = Arc::clone(&record);
        async move {
            let Some(hello) = peer.hello().await else {
                return;
            };
            record.lock().unwrap().push(hello);
            peer.ack(EPOCH).await;
            let Some(frame) = peer.frame().await else {
                return;
            };
            peer.send(&Frame::Reply {
                response: result_for(&frame["envelope"], serde_json::json!({"via": "relay"})),
            })
            .await;
        }
    });
    let options = DialOptions {
        session_dir: Some(session.clone()),
        ..options()
    };
    let envelope = crate::request::build_envelope("echo", serde_json::json!({}), true, 1_000, None);
    let response = send_envelope_with(tmp.path(), &envelope, &options, no_ensure)
        .await
        .expect("the relay socket answers");
    assert!(matches!(response, Response::Result { .. }), "{response:?}");
    let said: Vec<Via> = hellos
        .lock()
        .unwrap()
        .iter()
        .map(|hello| hello.via)
        .collect();
    assert_eq!(said, [Via::Relay]);
    drop(relay);

    // Nothing listens in the session directory any more: the error names the relay, and the
    // way to start it, not an endpoint.
    let quick = DialOptions {
        connect_timeout: Duration::from_millis(200),
        ..options
    };
    let error = send_envelope_with(tmp.path(), &envelope, &quick, no_ensure)
        .await
        .expect_err("no relay");
    assert!(
        matches!(&error, RequestError::SessionUnreachable { dir, .. } if *dir == session),
        "{error:?}"
    );
    assert!(error.to_string().contains("pam listen"), "{error}");
    assert!(!error.is_transient());
}

// --- readiness is a successful hello ------------------------------------------

/// A daemon that holds the lock but has not bound its socket yet (it binds
/// after crash recovery and warm-up) is *booting*: the client waits for it
/// and never spawns a second process, even when a stale socket file from the
/// previous run is still lying around.
#[cfg(unix)]
#[test]
fn a_booting_daemon_with_a_stale_socket_is_waited_for_not_raced() {
    let tmp = short_tempdir();
    let dirs = RuntimeDir::at_base(tmp.path()).unwrap();
    // The crashed predecessor's leftover: a socket file nobody listens on.
    drop(std::os::unix::net::UnixListener::bind(dirs.public_socket()).unwrap());
    assert!(dirs.public_socket().exists());
    let lock = acquire_instance_lock(dirs.run_dir()).unwrap();

    let late = dirs.clone();
    let binder = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(150));
        let listener = FakeDaemon::listen(&late, None, greeter);
        std::thread::sleep(Duration::from_millis(900));
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
/// file stale. Ready must be false until a hello is really answered.
#[cfg(unix)]
#[test]
fn a_stale_socket_file_is_never_ready_even_with_the_lock_held() {
    let tmp = short_tempdir();
    let dirs = RuntimeDir::at_base(tmp.path()).unwrap();
    drop(std::os::unix::net::UnixListener::bind(dirs.public_socket()).unwrap());
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
    let tmp = short_tempdir();
    let dirs = RuntimeDir::at_base(tmp.path()).unwrap();
    drop(std::os::unix::net::UnixListener::bind(dirs.public_socket()).unwrap());
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

/// A spawned daemon that holds the lock and accepts connections is not ready
/// until it answers a hello: a listener that hangs up without a word (its
/// accept loop is up, its policy is not) is still booting.
#[test]
fn a_spawned_daemon_is_ready_only_once_it_acknowledges_a_hello() {
    let tmp = short_tempdir();
    let base = tmp.path().to_path_buf();
    let mut fakes = Vec::new();
    let outcome = ensure_daemon_with(
        tmp.path(),
        &mut || {
            fakes.push(FakeDaemon::start(&base, |mut peer| async move {
                if peer.connection >= 3 {
                    peer.greet(EPOCH).await;
                }
            }));
            Ok(())
        },
        Duration::from_secs(3),
        POLL,
    )
    .expect("ready once a hello is acknowledged");
    assert_eq!(outcome, EnsureOutcome::Started);
    assert_eq!(fakes.len(), 1, "one spawn; the wait was for the hello");
    assert!(
        fakes[0].connections() >= 4,
        "three unanswered hellos did not count as ready: {}",
        fakes[0].connections()
    );
}

/// A daemon whose binary was replaced answers hellos with `daemon_outdated`
/// while it drains. The client waits for it to hand over — it neither spawns
/// over the lock holder nor gives up at the boot wait — and then starts the
/// build on disk.
#[test]
fn an_outdated_daemon_is_waited_out_and_replaced() {
    let tmp = short_tempdir();
    let base = tmp.path().to_path_buf();
    let old = FakeDaemon::start(tmp.path(), |mut peer| async move {
        peer.hello().await;
        peer.send(&Frame::error(cause::DAEMON_OUTDATED, "replaced", "retry"))
            .await;
        peer.until_closed().await;
    });
    // Longer than the boot wait (two attempts of 400 ms), shorter than the
    // handover. The boot wait also bounds how long the replacement may take to
    // answer once it is spawned; 100 ms was too short on a loaded Windows runner.
    let drain = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(1_500));
        old.stop();
    });
    let mut fakes = Vec::new();
    let mut spawn = || {
        fakes.push(start_fake_daemon(&base));
        Ok(())
    };
    let mut signal = |_pid: u32| -> Result<(), StopError> {
        panic!("a restarting daemon of this protocol is never signalled")
    };
    let outcome = Ensure {
        spawn: &mut spawn,
        signal: &mut signal,
        client_version: env!("CARGO_PKG_VERSION"),
        wait: Duration::from_millis(400),
        poll: POLL,
        handover: Duration::from_secs(10),
        probe: Duration::from_millis(500),
    }
    .run(tmp.path())
    .expect("the replacement becomes ready");
    drain.join().unwrap();
    assert_eq!(outcome, EnsureOutcome::Started);
    assert_eq!(fakes.len(), 1);
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

// --- ids, transient refusals and the follow loop ------------------------------

fn result_for(request: &serde_json::Value, body: serde_json::Value) -> Response {
    Response::Result {
        id: request["id"].as_str().unwrap().to_owned(),
        outcome: Outcome::Solved,
        body,
        evidence: Vec::new(),
    }
}

#[tokio::test]
async fn the_request_id_on_the_wire_is_the_one_the_caller_chose() {
    let tmp = short_tempdir();
    let (_daemon, seen) = answering(tmp.path(), |request| {
        Some(result_for(request, serde_json::json!({})))
    });
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
    let calls = seen.lock().unwrap();
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
        // The store's queue bound: the daemon's disk is behind, nothing was
        // decided about the caller. The literal the daemon refuses with.
        pam_daemon::daemon::CAUSE_STORE_OVERLOADED,
        "store_overloaded",
        "daemon_shutting_down",
        CAUSE_DAEMON_OUTDATED,
        "deadline_exceeded",
        "internal_error",
        "follower_capacity_exhausted",
        "connection_capacity_exhausted",
        "handshake_timeout",
        "follow_expired",
    ] {
        assert!(is_transient_cause(cause), "{cause}");
    }
    for cause in [
        "not_granted",
        "scope_denied",
        "result_unavailable",
        "admin_denied",
        "client_version_mismatch",
        "protocol_mismatch",
        "bad_frame",
    ] {
        assert!(!is_transient_cause(cause), "{cause} is a real answer");
    }
}

/// The follow rides out a busy daemon: a refusal the daemon marks retryable,
/// one that is transient only by its cause, a full follower table, a drain's
/// `error` frame and a connection that is simply cut are all retried with
/// backoff, and the ticket that finished meanwhile is reported as finished,
/// never as "refused".
#[tokio::test]
async fn a_follow_retries_what_is_transient_instead_of_reporting_refused() {
    let tmp = short_tempdir();
    let (_daemon, seen) = follow_daemon(tmp.path(), |nth, mut peer, frame| async move {
        let id = envelope_id(&frame);
        match nth {
            // Marked by the daemon, under a cause this client does not list.
            1 => {
                peer.end_refused(&id, "a_cause_from_a_newer_daemon", true)
                    .await;
            }
            // Not marked: the cause list is the fallback.
            2 => peer.end_refused(&id, "request_rate_exhausted", false).await,
            3 => {
                peer.end_refused(&id, "follower_capacity_exhausted", true)
                    .await;
            }
            4 => {
                peer.following(EPOCH, 0).await;
                peer.send(&Frame::error(
                    cause::DAEMON_SHUTTING_DOWN,
                    "the daemon is draining",
                    "Reconnect shortly.",
                ))
                .await;
            }
            5 => peer.following(EPOCH, 0).await,
            _ => peer.end(&id, "done").await,
        }
    });
    let mut events = Vec::new();
    let end = follow_with(
        tmp.path(),
        "req_busy",
        Duration::from_secs(30),
        &options(),
        no_ensure,
        &mut |event| events.push(event.clone()),
    )
    .await
    .expect("transient failures are retried to the terminal answer");
    assert_eq!(end.event, Event::Done);
    assert_eq!(events, [Event::Done]);
    let seen = seen.lock().unwrap();
    assert_eq!(seen.len(), 6, "five busy answers, then the truth");
    let ids: std::collections::HashSet<&str> = seen
        .iter()
        .map(|frame| frame["envelope"]["id"].as_str().unwrap())
        .collect();
    assert_eq!(ids.len(), 6, "each connection is its own query request");
}

/// A policy refusal is still final, even among transient ones.
#[tokio::test]
async fn a_policy_refusal_ends_the_follow_after_transient_ones() {
    let tmp = short_tempdir();
    let (_daemon, seen) = follow_daemon(tmp.path(), |nth, mut peer, frame| async move {
        let id = envelope_id(&frame);
        if nth == 1 {
            peer.end_refused(&id, "request_capacity_exhausted", true)
                .await;
        } else {
            peer.end_refused(&id, "scope_denied", false).await;
        }
    });
    let result = follow_with(
        tmp.path(),
        "req_denied",
        Duration::from_secs(30),
        &options(),
        no_ensure,
        &mut |_| {},
    )
    .await;
    assert!(
        matches!(&result, Err(RequestError::FollowRefused { cause, .. }) if cause == "scope_denied"),
        "{result:?}"
    );
    assert_eq!(seen.lock().unwrap().len(), 2);
}

/// A follow that only ever meets a busy daemon ends as a timeout naming the
/// ticket, never as the last transient refusal.
#[tokio::test]
async fn a_follow_that_stays_busy_times_out_instead_of_reporting_refused() {
    let tmp = short_tempdir();
    let (_daemon, seen) = follow_daemon(tmp.path(), |_, mut peer, frame| async move {
        peer.end_refused(&envelope_id(&frame), "request_capacity_exhausted", true)
            .await;
    });
    let timeout = Duration::from_millis(400);
    let result = follow_with(
        tmp.path(),
        "req_still_busy",
        timeout,
        &options(),
        no_ensure,
        &mut |_| {},
    )
    .await;
    assert!(
        matches!(&result, Err(RequestError::FollowTimeout { ticket, waited }) if ticket == "req_still_busy" && *waited == timeout),
        "{result:?}"
    );
    assert!(seen.lock().unwrap().len() >= 2, "it kept asking");
}

/// A connection cut in the middle of a follow is reconnected, and the
/// reconnect resumes: it sends the last sequence number it delivered and the
/// epoch it saw it under, and nothing is delivered twice.
#[tokio::test]
async fn a_follow_resumes_after_a_cut_connection_without_repeating_events() {
    let tmp = short_tempdir();
    let (_daemon, seen) = follow_daemon(tmp.path(), |nth, mut peer, frame| async move {
        if nth == 1 {
            peer.following(EPOCH, 2).await;
            peer.event(1, Event::Queued).await;
            peer.event(2, Event::Started).await;
            // Cut: the relay died, the daemon was killed. No `end`.
            return;
        }
        peer.following(EPOCH, 3).await;
        // The ring still holds 2; a daemon that replays it anyway must not show twice.
        peer.event(2, Event::Started).await;
        peer.event(
            3,
            Event::Progress {
                pct: Some(80),
                note: "Task progress updated".to_owned(),
            },
        )
        .await;
        peer.end(&envelope_id(&frame), "done").await;
    });
    let mut events = Vec::new();
    let end = follow_with(
        tmp.path(),
        "req_cut",
        Duration::from_secs(30),
        &options(),
        no_ensure,
        &mut |event| events.push(event.clone()),
    )
    .await
    .expect("the follow survives the cut");
    assert_eq!(
        events,
        [
            Event::Queued,
            Event::Started,
            Event::Progress {
                pct: Some(80),
                note: "Task progress updated".to_owned()
            },
            Event::Done
        ]
    );
    assert_eq!(end.event, Event::Done);
    let Response::Result { body, .. } = &end.response else {
        panic!("the end carries the durable answer: {:?}", end.response);
    };
    assert_eq!(body["state"], "done");
    let seen = seen.lock().unwrap();
    assert_eq!(seen.len(), 2);
    assert_eq!(seen[0]["after_seq"], 0);
    assert_eq!(seen[0]["epoch"], serde_json::Value::Null);
    assert_eq!(
        seen[1]["after_seq"], 2,
        "the reconnect resumes after what it saw"
    );
    assert_eq!(seen[1]["epoch"], EPOCH);
}

/// A daemon that restarted between two connections has a new epoch: its
/// sequence numbers start again, so the client takes its replay from the
/// start instead of discarding it as already seen, and ends on what that
/// daemon's store says.
#[tokio::test]
async fn a_changed_epoch_is_a_restarted_daemon_and_its_replay_is_taken_whole() {
    const SECOND_EPOCH: &str = "01JSECONDDAEMONEPOCH000000";
    let tmp = short_tempdir();
    let seen: Seen = Arc::default();
    let record = Arc::clone(&seen);
    let _daemon = FakeDaemon::start(tmp.path(), move |mut peer| {
        let record = Arc::clone(&record);
        async move {
            if peer.hello().await.is_none() {
                return;
            }
            let first = record.lock().unwrap().is_empty();
            let epoch = if first { EPOCH } else { SECOND_EPOCH };
            peer.ack(epoch).await;
            let Some(frame) = peer.frame().await else {
                return;
            };
            record.lock().unwrap().push(frame.clone());
            if first {
                peer.following(epoch, 3).await;
                for seq in 1..=3 {
                    peer.event(seq, Event::Started).await;
                }
                return;
            }
            // The restarted daemon failed the ticket in crash recovery and
            // publishes under its own numbering.
            peer.following(epoch, 1).await;
            peer.event(1, Event::Queued).await;
            peer.end(&envelope_id(&frame), "failed").await;
        }
    });
    let mut events = Vec::new();
    let end = follow_with(
        tmp.path(),
        "req_restart",
        Duration::from_secs(30),
        &options(),
        no_ensure,
        &mut |event| events.push(event.clone()),
    )
    .await
    .expect("the follow ends on the restarted daemon's answer");
    assert_eq!(
        end.event,
        Event::Refused,
        "failed is what a subscriber sees as refused"
    );
    assert_eq!(
        events,
        [
            Event::Started,
            Event::Started,
            Event::Started,
            Event::Queued,
            Event::Refused
        ],
        "seq 1 of the new epoch is not mistaken for seq 1 of the old one"
    );
    let seen = seen.lock().unwrap();
    assert_eq!(seen[1]["after_seq"], 3);
    assert_eq!(
        seen[1]["epoch"], EPOCH,
        "the client reports the epoch it counted under; the daemon decides what that means"
    );
}

/// An answer that is neither a refusal nor a terminal state fails closed:
/// the follow never invents an ending.
#[tokio::test]
async fn an_end_without_a_terminal_state_fails_closed() {
    let tmp = short_tempdir();
    let (_daemon, _seen) = follow_daemon(tmp.path(), |_, mut peer, frame| async move {
        peer.end(&envelope_id(&frame), "running").await;
    });
    let mut events = Vec::new();
    let result = follow_with(
        tmp.path(),
        "req_odd",
        Duration::from_secs(5),
        &options(),
        no_ensure,
        &mut |event| events.push(event.clone()),
    )
    .await;
    assert!(
        matches!(&result, Err(RequestError::FollowRefused { cause, .. }) if cause == "result_unavailable"),
        "{result:?}"
    );
    assert!(events.is_empty(), "no terminal event was made up");
}

// --- the version handshake waits for the replacement (finding 13) ------------

/// After a `daemon_outdated` refusal the old daemon drains and a new one
/// takes over: the single retry waits for that replacement and lands on it,
/// not on the draining daemon's `daemon_shutting_down`.
#[tokio::test]
async fn the_outdated_retry_lands_on_the_replacement_daemon() {
    let tmp = short_tempdir();
    let base = tmp.path().to_path_buf();
    let (old, _) = answering(tmp.path(), |request| Some(outdated(request)));
    let (handed_over, replacement) = std::sync::mpsc::channel();
    // The old daemon drains, exits, and a new binary binds a little later.
    let handover_base = base.clone();
    let handover = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(250));
        old.stop();
        std::thread::sleep(Duration::from_millis(400));
        let new = answering(&handover_base, |request| {
            Some(result_for(request, serde_json::json!({"served_by": "new"})))
        });
        let _ = handed_over.send(new);
    });
    let envelope = crate::request::build_envelope("echo", serde_json::json!({}), true, 5_000, None);
    let ensure_base = base.clone();
    let response = send_envelope_with(&base, &envelope, &options(), || {
        let base = ensure_base.clone();
        async move {
            // A real ensure, with a spawner that must only ever be a no-op
            // here: the replacement is "started" by the handover thread.
            ensure_daemon_off_thread(&base, || Ok(()), Duration::from_secs(5), POLL)
                .await
                .map(|_| ())
                .map_err(RequestError::from)
        }
    })
    .await
    .expect("the retry reaches the replacement daemon");
    handover.join().unwrap();
    let (_new, served) = replacement.recv().unwrap();
    let Response::Result { body, .. } = response else {
        panic!("expected the replacement's result, got {response:?}");
    };
    assert_eq!(body["served_by"], "new");
    let served = served.lock().unwrap();
    assert_eq!(
        served.len(),
        1,
        "the retry went to the new daemon exactly once"
    );
    assert_eq!(served[0]["id"], envelope.id, "it resends the same envelope");
}

// --- a daemon of another build is refused, never stopped ----------------------

/// A real daemon on a temp base, for what only the real version rule can
/// answer.
struct RealDaemon {
    _tmp: tempfile::TempDir,
    base: std::path::PathBuf,
    handle: pam_daemon::daemon::DaemonHandle,
    shutdown: tokio::sync::watch::Sender<bool>,
}

impl RealDaemon {
    async fn start() -> Self {
        let tmp = short_tempdir();
        let base = tmp.path().join("pam");
        let (shutdown, receiver) = tokio::sync::watch::channel(false);
        let handle = pam_daemon::daemon::run_daemon(Some(base.clone()), receiver)
            .await
            .expect("the daemon starts");
        Self {
            _tmp: tmp,
            base,
            handle,
            shutdown,
        }
    }

    /// What both the CLI's sentence and the GUI's notice lift out of a
    /// `client_version_mismatch` detail: the daemon's version and executable.
    fn facts(&self) -> String {
        let path = self
            .handle
            .boot_image_path()
            .expect("the daemon recorded its executable");
        format!(
            "daemon version {} running from {}; ",
            pam_daemon::daemon::DAEMON_VERSION,
            path.display()
        )
    }

    /// Asserts nothing restarted or stopped, then stops the daemon.
    async fn stop_after_serving_its_own_build(self) {
        assert_eq!(
            *self.handle.lifecycle().borrow(),
            pam_daemon::lifecycle::LifecyclePhase::Serving
        );
        let envelope =
            crate::request::build_envelope("status", serde_json::json!({}), true, 5_000, None);
        let served = send_envelope_with(&self.base, &envelope, &options(), no_ensure)
            .await
            .expect("the daemon's own build is served");
        assert!(matches!(served, Response::Result { .. }), "{served:?}");
        let _ = self.shutdown.send(true);
        self.handle.shutdown().await;
    }
}

/// A real daemon, a hello that states another version, and a binary on disk
/// that has not changed: the request and the follow each come back as the
/// daemon's own `client_version_mismatch` refusal — the cause, a detail that
/// names the daemon's version and executable, and its recovery line.
/// Nothing restarts; the daemon serves the next client of its own build.
#[tokio::test(flavor = "multi_thread")]
async fn another_build_gets_the_daemons_refusal_on_a_request_and_on_a_follow() {
    let daemon = RealDaemon::start().await;
    let facts = daemon.facts();
    let other_build = DialOptions {
        client_version: "9.9.9".to_owned(),
        ..options()
    };

    let envelope =
        crate::request::build_envelope("status", serde_json::json!({}), true, 5_000, None);
    let refused = send_envelope_with(&daemon.base, &envelope, &other_build, no_ensure)
        .await
        .expect("a refused hello is the daemon's answer, not a transport error");
    let Response::Refusal {
        id,
        cause: refused_cause,
        detail,
        recovery,
        retryable,
    } = refused
    else {
        panic!("another build is not served");
    };
    assert_eq!(id, envelope.id);
    assert_eq!(refused_cause, cause::CLIENT_VERSION_MISMATCH);
    assert!(
        detail.starts_with("client version 9.9.9 does not match "),
        "{detail}"
    );
    assert!(detail.contains(&facts), "{detail}");
    assert!(!recovery.is_empty());
    assert!(!retryable, "asking again would only repeat");

    let followed = follow_with(
        &daemon.base,
        "req_any",
        Duration::from_secs(5),
        &other_build,
        no_ensure,
        &mut |_| {},
    )
    .await;
    let Err(RequestError::FollowRefused {
        cause: follow_cause,
        detail: follow_detail,
        recovery: follow_recovery,
        ..
    }) = &followed
    else {
        panic!("expected the refusal, got {followed:?}");
    };
    assert_eq!(follow_cause, cause::CLIENT_VERSION_MISMATCH);
    assert_eq!(*follow_detail, detail);
    assert_eq!(*follow_recovery, recovery);
    assert!(!followed.as_ref().unwrap_err().is_transient());

    daemon.stop_after_serving_its_own_build().await;
}

/// The lazy start meets the same refusal at its readiness hello and leaves
/// that daemon alone: it neither spawns over it nor signals it. The admin
/// operation that follows, as `send_admin` sends it, is answered by the
/// admin plane with the same refusal.
#[tokio::test(flavor = "multi_thread")]
async fn another_build_is_never_stopped_and_the_admin_plane_refuses_it_the_same_way() {
    let daemon = RealDaemon::start().await;
    let facts = daemon.facts();

    let probe_base = daemon.base.clone();
    let ensured = tokio::task::spawn_blocking(move || {
        let mut spawn = || panic!("a running daemon of another build is never spawned over");
        let mut signal = |_pid: u32| -> Result<(), StopError> {
            panic!("a daemon of another build is never stopped by a client")
        };
        Ensure {
            spawn: &mut spawn,
            signal: &mut signal,
            client_version: "9.9.9",
            wait: WAIT,
            poll: POLL,
            handover: Duration::from_secs(1),
            probe: Duration::from_secs(2),
        }
        .run(&probe_base)
    })
    .await
    .unwrap();
    assert_eq!(ensured.unwrap(), EnsureOutcome::AlreadyRunning);

    let mut admin = crate::request::build_envelope(
        "admin.activity.list",
        serde_json::json!({}),
        true,
        5_000,
        None,
    );
    admin.client_version = "9.9.9".to_owned();
    let answered = crate::client::exchange_admin(&daemon.base, &admin)
        .await
        .expect("the admin plane answers the hello it refuses");
    let Response::Refusal {
        id,
        cause: admin_cause,
        detail,
        recovery,
        ..
    } = answered
    else {
        panic!("another build is not served on the admin plane");
    };
    assert_eq!(id, admin.id);
    assert_eq!(admin_cause, cause::CLIENT_VERSION_MISMATCH);
    assert!(detail.contains(&facts), "{detail}");
    assert!(!recovery.is_empty());

    daemon.stop_after_serving_its_own_build().await;
}

/// `protocol_mismatch` at the hello is a refusal too, sent once and final.
#[tokio::test]
async fn a_protocol_mismatch_is_a_final_refusal_sent_once() {
    let tmp = short_tempdir();
    let daemon = FakeDaemon::start(tmp.path(), |mut peer| async move {
        peer.hello().await;
        peer.send(&Frame::error(
            cause::PROTOCOL_MISMATCH,
            "this daemon speaks pam wire protocol 3; the client sent 2",
            "Use the pam binary that matches the running daemon (0.9.0).",
        ))
        .await;
        peer.until_closed().await;
    });
    let envelope = crate::request::build_envelope("echo", serde_json::json!({}), true, 1_000, None);
    let response = send_envelope_with(tmp.path(), &envelope, &options(), no_ensure)
        .await
        .unwrap();
    assert!(
        matches!(&response, Response::Refusal { cause, retryable: false, id, .. }
            if cause == cause::PROTOCOL_MISMATCH && *id == envelope.id),
        "{response:?}"
    );
    assert_eq!(daemon.connections(), 1);
}

// --- a pre-migration daemon is superseded, once, by a client that may ---------

/// Ensure hooks for the takeover tests: a spawner that starts a framed fake
/// answering every request, and whatever signal the test injects.
struct Takeover {
    started: Arc<Mutex<Vec<(FakeDaemon, Seen)>>>,
    spawns: Arc<AtomicU32>,
    signals: Arc<Mutex<Vec<u32>>>,
}

impl Takeover {
    fn new() -> Self {
        Self {
            started: Arc::default(),
            spawns: Arc::default(),
            signals: Arc::default(),
        }
    }

    /// Runs the ensure logic on a blocking thread with this test's hooks.
    /// `signal` is what sending the stop signal does.
    async fn ensure(
        &self,
        base: &Path,
        handover: Duration,
        signal: impl Fn(u32) -> Result<(), StopError> + Send + 'static,
    ) -> Result<EnsureOutcome, ClientError> {
        let base = base.to_path_buf();
        let started = Arc::clone(&self.started);
        let spawns = Arc::clone(&self.spawns);
        let signals = Arc::clone(&self.signals);
        tokio::task::spawn_blocking(move || {
            let spawn_base = base.clone();
            let mut spawn = || {
                spawns.fetch_add(1, Ordering::SeqCst);
                started
                    .lock()
                    .unwrap()
                    .push(answering(&spawn_base, |request| {
                        Some(result_for(
                            request,
                            serde_json::json!({"served_by": "this build"}),
                        ))
                    }));
                Ok(())
            };
            let mut signal = |pid| {
                signals.lock().unwrap().push(pid);
                signal(pid)
            };
            Ensure {
                spawn: &mut spawn,
                signal: &mut signal,
                client_version: env!("CARGO_PKG_VERSION"),
                wait: Duration::from_secs(3),
                poll: POLL,
                handover,
                probe: Duration::from_millis(500),
            }
            .run(&base)
        })
        .await
        .unwrap()
    }

    fn spawns(&self) -> u32 {
        self.spawns.load(Ordering::SeqCst)
    }

    fn signals(&self) -> Vec<u32> {
        self.signals.lock().unwrap().clone()
    }
}

/// A fake pre-migration daemon as the spec's test plan describes it: it
/// holds the instance lock, names in it the pid of a child it owns, greets
/// in ZMTP on the socket the client dials, and releases the lock when that
/// child dies. The real stop signal can therefore be sent at it.
#[cfg(unix)]
struct OldDaemon {
    pid: u32,
    exited: std::sync::mpsc::Receiver<()>,
}

#[cfg(unix)]
impl OldDaemon {
    fn start(base: &Path) -> Self {
        let fake = legacy(base);
        let mut child = std::process::Command::new("/bin/sleep")
            .arg("600")
            .stdin(std::process::Stdio::null())
            .spawn()
            .expect("the stand-in process starts");
        let pid = child.id();
        let lock = RuntimeDir::paths_at_base(base)
            .unwrap()
            .run_dir()
            .join(pam_daemon::lifecycle::LOCK_FILE);
        std::fs::write(lock, pid.to_string()).expect("the lock names the child");
        let (gone, exited) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = child.wait();
            // The drain: unbind, then release the lock.
            fake.stop();
            let _ = gone.send(());
        });
        Self { pid, exited }
    }

    /// Whether the stand-in process is still alive.
    fn alive(&self) -> bool {
        std::process::Command::new("/bin/kill")
            .args(["-0", &self.pid.to_string()])
            .stderr(std::process::Stdio::null())
            .status()
            .is_ok_and(|status| status.success())
    }
}

#[cfg(unix)]
impl Drop for OldDaemon {
    fn drop(&mut self) {
        let _ = std::process::Command::new("/bin/kill")
            .args(["-KILL", &self.pid.to_string()])
            .stderr(std::process::Stdio::null())
            .status();
        let _ = self.exited.recv_timeout(Duration::from_secs(10));
    }
}

/// The whole takeover: the client meets a ZMTP greeting, reads the pid from
/// the instance lock, sends the real stop signal, waits for the lock, starts
/// its own build, and the request it was asked to send is answered by that
/// build. The old daemon never sees a request.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn a_pre_migration_daemon_is_stopped_and_the_request_lands_on_this_build() {
    let tmp = short_tempdir();
    let base = tmp.path().to_path_buf();
    let old = OldDaemon::start(&base);
    let takeover = Takeover::new();
    let envelope = crate::request::build_envelope("echo", serde_json::json!({}), true, 5_000, None);
    let response = send_envelope_with(&base, &envelope, &options(), || async {
        takeover
            .ensure(
                &base,
                Duration::from_secs(10),
                crate::client::signal_terminate,
            )
            .await
            .map(drop)
            .map_err(RequestError::from)
    })
    .await
    .expect("the request is served after the takeover");
    let Response::Result { body, .. } = response else {
        panic!("expected a result, got {response:?}");
    };
    assert_eq!(body["served_by"], "this build");
    assert_eq!(
        takeover.signals(),
        [old.pid],
        "the lock's pid was signalled, once"
    );
    assert_eq!(
        takeover.spawns(),
        1,
        "one lazy start after the lock was released"
    );
    assert!(!old.alive(), "the old daemon's process is gone");
    let started = takeover.started.lock().unwrap();
    let served = started[0].1.lock().unwrap();
    assert_eq!(served.len(), 1, "the request was sent once, to this build");
    assert_eq!(served[0]["id"], envelope.id);
}

/// A client that may not signal (the macOS broker profile denies signals)
/// fails with the instruction for the human, names the pid, starts nothing,
/// and the old daemon is untouched.
#[tokio::test(flavor = "multi_thread")]
async fn a_client_that_may_not_signal_reports_the_instruction_and_starts_nothing() {
    let tmp = short_tempdir();
    let base = tmp.path().to_path_buf();
    let old = legacy(&base);
    let takeover = Takeover::new();
    let envelope = crate::request::build_envelope("echo", serde_json::json!({}), true, 5_000, None);
    let failed = send_envelope_with(&base, &envelope, &options(), || async {
        takeover
            .ensure(&base, Duration::from_secs(10), |pid| {
                Err(StopError::Signal {
                    pid,
                    detail: "/bin/kill -TERM exited with exit status: 1".to_owned(),
                })
            })
            .await
            .map(drop)
            .map_err(RequestError::from)
    })
    .await
    .expect_err("the takeover is refused");
    let holder = if cfg!(unix) {
        Some(std::process::id())
    } else {
        None
    };
    assert!(
        matches!(&failed, RequestError::Ensure(ClientError::LegacyDaemon { pid, .. }) if *pid == holder),
        "{failed:?}"
    );
    let message = failed.to_string();
    assert!(message.contains("a pre-migration pam daemon"), "{message}");
    assert!(message.contains("may not stop it"), "{message}");
    if cfg!(unix) {
        assert!(
            message.contains(&format!("pid {}", std::process::id())),
            "{message}"
        );
        assert!(
            message.contains(
                "run `pam daemon stop` and then `pam status` outside the sandbox, then retry"
            ),
            "{message}"
        );
    }
    assert!(!failed.is_transient(), "retrying cannot change it");
    assert_eq!(
        takeover.spawns(),
        0,
        "nothing is started next to a daemon that still runs"
    );
    assert!(
        matches!(probe_daemon(&base).unwrap(), DaemonStatus::Running { .. }),
        "the old daemon still holds the lock"
    );
    drop(old);
}

/// The old daemon was signalled and is still draining when the wait ends:
/// the client says so, starts nothing, and the error is transient.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn a_daemon_still_draining_after_the_wait_is_reported_as_transient() {
    let tmp = short_tempdir();
    let base = tmp.path().to_path_buf();
    let old = legacy(&base);
    let takeover = Takeover::new();
    let handover = Duration::from_millis(300);
    // The signal is accepted and the fake keeps the lock: a long drain.
    let stuck = takeover.ensure(&base, handover, |_pid| Ok(())).await;
    assert!(
        matches!(&stuck, Err(ClientError::LegacyDraining { pid, waited }) if *pid == std::process::id() && *waited == handover),
        "{stuck:?}"
    );
    let error = RequestError::from(stuck.unwrap_err());
    assert!(error.to_string().contains("still draining"), "{error}");
    assert!(error.is_transient());
    assert_eq!(takeover.signals(), [std::process::id()]);
    assert_eq!(takeover.spawns(), 0);
    drop(old);
}

/// Two clients meet the old daemon at once. The one that comes second reads
/// the pid, greets once more, and finds a daemon that already answers its
/// hello: it signals nothing and starts nothing.
#[tokio::test(flavor = "multi_thread")]
async fn a_client_that_lost_the_race_does_not_signal_the_daemon_that_now_answers() {
    let tmp = short_tempdir();
    let base = tmp.path().to_path_buf();
    // The first dial meets the old daemon; by the second, another client has
    // superseded it and this build answers.
    let daemon = FakeDaemon::start(&base, |mut peer| async move {
        if peer.connection == 0 {
            peer.raw(&crate::transport_test::zmtp_greeting()).await;
            peer.until_closed().await;
        } else {
            greeter(peer).await;
        }
    });
    let takeover = Takeover::new();
    let outcome = takeover
        .ensure(&base, Duration::from_secs(10), |_pid| {
            panic!("a daemon that answers the hello is never signalled")
        })
        .await
        .expect("the daemon that answers is the one to use");
    assert_eq!(outcome, EnsureOutcome::AlreadyRunning);
    assert!(takeover.signals().is_empty());
    assert_eq!(takeover.spawns(), 0);
    assert_eq!(daemon.connections(), 2, "one greeting, one hello");
}

/// Through a session relay nothing is ever signalled: a ZMTP greeting from
/// behind it is an error that tells the human what to run, outside the
/// sandbox.
#[tokio::test(flavor = "multi_thread")]
async fn a_pre_migration_daemon_behind_the_relay_is_an_instruction_never_a_signal() {
    let tmp = short_tempdir();
    let base = tmp.path().join("base");
    let session = tmp.path().join("s");
    std::fs::create_dir_all(&session).unwrap();
    // The daemon the relay leads to, with its lock under the real base.
    let old = legacy(&base);
    // The relay's socket, a byte pipe as far as the client can tell.
    let relay = FakeDaemon::listen(
        &RuntimeDir::paths_at_dir(&session).unwrap(),
        None,
        |mut peer| async move {
            peer.raw(&crate::transport_test::zmtp_greeting()).await;
            peer.until_closed().await;
        },
    );
    let options = DialOptions {
        session_dir: Some(session.clone()),
        ..options()
    };
    let envelope = crate::request::build_envelope("echo", serde_json::json!({}), true, 5_000, None);
    let ensure_session = session.clone();
    let ensure_base = base.clone();
    let failed = send_envelope_with(&base, &envelope, &options, || {
        let session = ensure_session.clone();
        let base = ensure_base.clone();
        async move {
            // The production composition under the override: no probe, no spawn.
            let spawn = || panic!("a client behind a relay never starts a daemon");
            crate::client::ensure_for_dial_off_thread(Some(&session), &base, spawn, WAIT, POLL)
                .await
                .map_err(RequestError::from)
        }
    })
    .await
    .expect_err("the daemon behind the relay is too old");
    assert!(
        matches!(&failed, RequestError::Ensure(ClientError::LegacyBehindRelay { dir }) if *dir == session),
        "{failed:?}"
    );
    let message = failed.to_string();
    assert!(message.contains("$PAM_SOCKET_DIR"), "{message}");
    assert!(
        message.contains(
            "run `pam daemon stop` and then `pam status` outside the sandbox and try again"
        ),
        "{message}"
    );
    assert_eq!(relay.connections(), 1, "one dial; nothing was retried");
    assert_eq!(
        old.connections(),
        0,
        "the daemon's own socket was never dialled"
    );
    assert!(
        matches!(probe_daemon(&base).unwrap(), DaemonStatus::Running { .. }),
        "the old daemon was not stopped"
    );

    // The same on a follow.
    let followed = follow_with(
        &base,
        "req_any",
        Duration::from_secs(5),
        &options,
        no_ensure,
        &mut |_| {},
    )
    .await;
    assert!(
        matches!(
            &followed,
            Err(RequestError::Ensure(ClientError::LegacyBehindRelay { .. }))
        ),
        "{followed:?}"
    );
}

/// A greeting that comes back after the one takeover a call may attempt is
/// an error, not a loop.
#[tokio::test(flavor = "multi_thread")]
async fn a_daemon_that_still_greets_in_zmtp_after_the_takeover_ends_the_call() {
    let tmp = short_tempdir();
    let base = tmp.path().to_path_buf();
    let old = legacy(&base);
    let ensures = Arc::new(AtomicU32::new(0));
    let envelope = crate::request::build_envelope("echo", serde_json::json!({}), true, 5_000, None);
    let failed = send_envelope_with(&base, &envelope, &options(), || {
        ensures.fetch_add(1, Ordering::SeqCst);
        no_ensure()
    })
    .await
    .expect_err("the old daemon is still there");
    assert!(
        matches!(
            &failed,
            RequestError::Ensure(ClientError::LegacyDaemon { .. })
        ),
        "{failed:?}"
    );
    assert_eq!(
        ensures.load(Ordering::SeqCst),
        2,
        "the ensure step got exactly one more chance to supersede it"
    );
    assert_eq!(old.connections(), 2);
}

// --- the non-starting requests ---------------------------------------------------

/// With nobody holding the instance lock, a request that must not start the daemon sends
/// nothing and says so: `None`, and no runtime directory appears (the ensure step would have
/// created one and spawned a daemon).
#[tokio::test]
async fn a_request_that_must_not_start_the_daemon_finds_none_and_starts_none() {
    let tmp = short_tempdir();
    let sent = crate::client::send_request_if_running(
        tmp.path(),
        "status",
        serde_json::json!({}),
        true,
        1_000,
    )
    .await
    .expect("no daemon is an answer, not an error");
    assert!(sent.is_none());
    assert!(
        !tmp.path().join("run").exists(),
        "nothing touched the runtime directory"
    );

    let admin = crate::client::send_admin_if_running(
        tmp.path(),
        "admin.profile.get",
        serde_json::json!({}),
        1_000,
    )
    .await
    .expect("no daemon is an answer, not an error");
    assert!(admin.is_none());
    assert!(!tmp.path().join("run").exists());
}

/// The same entry points keep the structural guards of their starting twins.
#[tokio::test]
async fn the_non_starting_requests_keep_the_channel_guards() {
    let tmp = short_tempdir();
    let public = crate::client::send_request_if_running(
        tmp.path(),
        "admin.grants.add",
        serde_json::json!({}),
        true,
        1_000,
    )
    .await
    .expect_err("admin capabilities never go on the public socket");
    assert!(matches!(public, RequestError::AdminOnly { .. }));
    let admin =
        crate::client::send_admin_if_running(tmp.path(), "echo", serde_json::json!({}), 1_000)
            .await
            .expect_err("only admin operations go on the private channel");
    assert!(matches!(admin, RequestError::NotAdmin { .. }));
}

/// With a daemon holding the lock the request is exchanged as usual, and the ensure step is
/// never part of it: a request the daemon answers is `Some`, and the daemon saw one request.
#[tokio::test]
async fn a_running_daemon_answers_a_request_that_must_not_start_it() {
    let tmp = short_tempdir();
    let (_daemon, seen) = answering(tmp.path(), |request| {
        Some(result_for(request, serde_json::json!({"alive": true})))
    });
    let sent = crate::client::send_envelope_if_running(
        tmp.path(),
        &crate::request::build_envelope("status", serde_json::json!({}), true, 1_000, None),
        &options(),
    )
    .await
    .expect("the daemon answers")
    .expect("a daemon holds the lock");
    match sent {
        Response::Result { body, .. } => assert_eq!(body["alive"], true),
        other => panic!("expected a result, got {other:?}"),
    }
    assert_eq!(seen.lock().unwrap().len(), 1);
}
