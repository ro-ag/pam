//! Relay unit tests: the one socket forwards byte-for-byte and is the only entry the relay leaves
//! in the session directory, a live relay is never taken over, a stale socket file is replaced, a
//! directory or socket entry a neighbour could redirect is refused, and the startup probe tells a
//! pre-migration daemon from a current one and replaces it only through the stop and ensure steps.
//! Unix only — the relay's transport is unix domain sockets.

use std::collections::VecDeque;
use std::io;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use pam_daemon::runtime_dir::RuntimeDir;
use pam_proto::wire::{Frame, HelloAck, WIRE_PROTOCOL};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::watch;

use crate::client::{ClientError, EnsureOutcome, StopError, StopOutcome};
use crate::relay::{
    self, Accept, DaemonNote, Probe, RelayError, SupersedeOps, check_daemon, directory_refusal,
    probe,
};

fn tmp() -> tempfile::TempDir {
    tempfile::tempdir().expect("tempdir")
}

/// The daemon's public socket under `base`: the one path the relay forwards to.
fn daemon_socket(base: &Path) -> PathBuf {
    RuntimeDir::paths_at_base(base)
        .expect("runtime paths")
        .public_socket()
        .to_path_buf()
}

/// A daemon stand-in: binds `path` and echoes every byte back. The caller
/// must hold the returned listener for the echo to keep serving.
fn bind_echo_daemon(path: &Path) -> tokio::net::UnixListener {
    let _ = std::fs::remove_file(path);
    let listener = std::os::unix::net::UnixListener::bind(path).expect("echo daemon binds");
    listener.set_nonblocking(true).expect("nonblocking");
    // One fd for the accept loop, a duplicate for the caller to hold: the
    // echo dies with the test only when both are gone.
    let serving = listener.try_clone().expect("listener clone");
    serving.set_nonblocking(true).expect("nonblocking");
    let listener = tokio::net::UnixListener::from_std(listener).expect("async listener");
    let serving = tokio::net::UnixListener::from_std(serving).expect("async clone");
    tokio::spawn(async move {
        loop {
            match serving.accept().await {
                Ok((mut stream, _)) => {
                    tokio::spawn(async move {
                        let mut buffer = [0u8; 64];
                        loop {
                            match stream.read(&mut buffer).await {
                                Ok(0) | Err(_) => return,
                                Ok(read) => {
                                    if stream.write_all(&buffer[..read]).await.is_err() {
                                        return;
                                    }
                                }
                            }
                        }
                    });
                }
                Err(_) => return,
            }
        }
    });
    listener
}

/// A fake daemon under `<base>/base/run`, a prepared relay in
/// `<base>/session`, and the echo listener that keeps the fake alive.
struct Fixture {
    echo_keepalive: tokio::net::UnixListener,
    session: PathBuf,
    socket: PathBuf,
    shutdown_tx: watch::Sender<bool>,
    server: tokio::task::JoinHandle<Result<(), RelayError>>,
}

fn daemon_base(base: &Path) -> PathBuf {
    let daemon_base = base.join("base");
    std::fs::create_dir_all(daemon_base.join("run")).expect("daemon run dir");
    daemon_base
}

fn start_relay(base: &Path) -> Fixture {
    let daemon_base = daemon_base(base);
    let session = base.join("session");
    let echo_keepalive = bind_echo_daemon(&daemon_socket(&daemon_base));

    let bindings = relay::prepare(&session, &daemon_base).expect("relay prepares");
    let socket = bindings.socket().to_path_buf();
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let server = tokio::spawn(relay::serve(bindings, shutdown_rx));
    assert!(socket.exists(), "the relay binds its socket");
    Fixture {
        echo_keepalive,
        session,
        socket,
        shutdown_tx,
        server,
    }
}

impl Fixture {
    async fn stop(self) {
        // The echo listener goes last: the relay's socket is removed by
        // its own shutdown path, which the join below waits for.
        let Fixture {
            echo_keepalive,
            socket,
            shutdown_tx,
            server,
            ..
        } = self;
        let _ = shutdown_tx.send(true);
        server.await.expect("serve joins").expect("serve ok");
        assert!(
            !socket.exists(),
            "the relay socket is cleaned up on shutdown"
        );
        drop(echo_keepalive);
    }
}

fn entries(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .expect("read dir")
        .map(|entry| {
            entry
                .expect("entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    names.sort();
    names
}

fn mode_of(path: &Path) -> u32 {
    std::fs::metadata(path)
        .expect("metadata")
        .permissions()
        .mode()
        & 0o777
}

#[test]
fn the_relay_forwards_its_one_socket_byte_for_byte_and_is_the_only_entry() {
    let tmp = tmp();
    let runtime = tokio::runtime::Runtime::new().expect("runtime");
    runtime.block_on(async {
        let fixture = start_relay(tmp.path());
        let public = daemon_socket(&tmp.path().join("base"));
        assert_eq!(
            entries(&fixture.session),
            vec![
                public
                    .file_name()
                    .expect("socket name")
                    .to_string_lossy()
                    .into_owned()
            ],
            "the session directory holds exactly one socket"
        );
        assert_eq!(mode_of(&fixture.socket), 0o600, "the socket is owner-only");
        assert_eq!(
            mode_of(&fixture.session),
            0o700,
            "the directory is created 0700"
        );

        let mut client = tokio::net::UnixStream::connect(&fixture.socket)
            .await
            .expect("relay dials");
        client.write_all(b"envelope").await.expect("write");
        let mut buffer = [0u8; 8];
        client.read_exact(&mut buffer).await.expect("echo read");
        assert_eq!(&buffer, b"envelope");

        // A second, long-lived connection beside the first: a follow is just that.
        let mut follow = tokio::net::UnixStream::connect(&fixture.socket)
            .await
            .expect("relay dials again");
        follow.write_all(b"follow").await.expect("write");
        let mut buffer = [0u8; 6];
        follow.read_exact(&mut buffer).await.expect("echo read");
        assert_eq!(&buffer, b"follow");
        client.write_all(b"again").await.expect("write");
        let mut buffer = [0u8; 5];
        client.read_exact(&mut buffer).await.expect("echo read");
        assert_eq!(&buffer, b"again");

        fixture.stop().await;
    });
}

#[test]
fn a_live_relay_is_never_taken_over() {
    let tmp = tmp();
    let runtime = tokio::runtime::Runtime::new().expect("runtime");
    runtime.block_on(async {
        let daemon_base = daemon_base(tmp.path());
        let session = tmp.path().join("session");
        let _echo_keepalive = bind_echo_daemon(&daemon_socket(&daemon_base));

        let first = relay::prepare(&session, &daemon_base).expect("first relay prepares");
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let server = tokio::spawn(relay::serve(first, shutdown_rx));

        let error =
            relay::prepare(&session, &daemon_base).expect_err("a second prepare must refuse");
        assert!(
            matches!(error, RelayError::AlreadyListening { .. }),
            "the live relay must not be rebound: {error}"
        );

        let _ = shutdown_tx.send(true);
        server.await.expect("serve joins").expect("serve ok");
    });
}

#[test]
fn a_stale_socket_file_is_replaced() {
    let tmp = tmp();
    let runtime = tokio::runtime::Runtime::new().expect("runtime");
    runtime.block_on(async {
        let daemon_base = daemon_base(tmp.path());
        let session = tmp.path().join("session");
        let _echo_keepalive = bind_echo_daemon(&daemon_socket(&daemon_base));

        // A socket file nobody answers: bind, then drop the listener.
        let first = relay::prepare(&session, &daemon_base).expect("first prepare");
        let dead = first.socket().to_path_buf();
        drop(first);
        assert!(dead.exists(), "the abandoned socket file is still there");

        let bindings = relay::prepare(&session, &daemon_base)
            .expect("a stale socket file must be replaced, not refused");
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let server = tokio::spawn(relay::serve(bindings, shutdown_rx));
        let _ = shutdown_tx.send(true);
        server.await.expect("serve joins").expect("serve ok");
    });
}

/// An older relay also bound `events.sock`. Its dead socket is removed at startup so the
/// directory holds one socket; something else under that name is not the relay's to delete.
#[test]
fn a_stale_events_socket_from_an_older_relay_is_removed() {
    let tmp = tmp();
    let daemon_base = daemon_base(tmp.path());
    let session = tmp.path().join("session");
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&session)
        .expect("session dir");
    let stale = session.join("events.sock");
    drop(std::os::unix::net::UnixListener::bind(&stale).expect("bind"));
    assert!(stale.exists());

    let runtime = tokio::runtime::Runtime::new().expect("runtime");
    let _enter = runtime.enter();
    let bindings = relay::prepare(&session, &daemon_base).expect("prepares");
    assert!(!stale.exists(), "the stale events.sock is gone");
    assert_eq!(entries(&session).len(), 1, "one socket remains");
    drop(bindings);

    // A regular file called events.sock is left alone.
    let other = tmp.path().join("other");
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&other)
        .expect("dir");
    std::fs::write(other.join("events.sock"), b"mine").expect("write");
    let bindings = relay::prepare(&other, &daemon_base).expect("prepares");
    assert_eq!(
        std::fs::read(other.join("events.sock")).expect("kept"),
        b"mine",
        "only a socket is the relay's to remove"
    );
    drop(bindings);
}

#[test]
fn a_symlinked_session_directory_is_refused() {
    let tmp = tmp();
    let daemon_base = daemon_base(tmp.path());
    let real = tmp.path().join("real");
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&real)
        .expect("real dir");
    let link = tmp.path().join("link");
    symlink(&real, &link).expect("symlink");

    let runtime = tokio::runtime::Runtime::new().expect("runtime");
    let _enter = runtime.enter();
    for given in [link.clone(), PathBuf::from(format!("{}/", link.display()))] {
        let error = relay::prepare(&given, &daemon_base)
            .expect_err("a linked session directory must be refused");
        assert!(
            matches!(&error, RelayError::UnsafeDirectory { reason, .. } if reason.contains("symbolic link")),
            "{given:?}: {error}"
        );
        assert!(
            error.to_string().contains("0700"),
            "the refusal names the way out: {error}"
        );
    }
    assert!(
        entries(&real).is_empty(),
        "nothing was bound through the link"
    );
}

#[test]
fn a_symlinked_socket_entry_is_refused_and_its_target_is_left_alone() {
    let tmp = tmp();
    let daemon_base = daemon_base(tmp.path());
    let session = tmp.path().join("session");
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&session)
        .expect("session dir");
    let victim = tmp.path().join("victim");
    std::fs::write(&victim, b"precious").expect("victim");
    let name = daemon_socket(&daemon_base)
        .file_name()
        .expect("socket name")
        .to_owned();
    symlink(&victim, session.join(&name)).expect("symlink");

    let runtime = tokio::runtime::Runtime::new().expect("runtime");
    let _enter = runtime.enter();
    let error =
        relay::prepare(&session, &daemon_base).expect_err("a linked socket entry must be refused");
    assert!(
        matches!(&error, RelayError::UnsafeSocket { reason, .. } if reason.contains("symbolic link")),
        "{error}"
    );
    assert_eq!(std::fs::read(&victim).expect("victim kept"), b"precious");
    assert!(
        std::fs::symlink_metadata(session.join(&name))
            .expect("link kept")
            .file_type()
            .is_symlink(),
        "the relay does not remove what it refused"
    );
}

#[test]
fn a_file_that_is_not_a_socket_is_refused_not_deleted() {
    let tmp = tmp();
    let daemon_base = daemon_base(tmp.path());
    let session = tmp.path().join("session");
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&session)
        .expect("session dir");
    let name = daemon_socket(&daemon_base)
        .file_name()
        .expect("socket name")
        .to_owned();
    std::fs::write(session.join(&name), b"notes").expect("file");

    let runtime = tokio::runtime::Runtime::new().expect("runtime");
    let _enter = runtime.enter();
    let error = relay::prepare(&session, &daemon_base).expect_err("a regular file is refused");
    assert!(
        matches!(&error, RelayError::UnsafeSocket { reason, .. } if reason.contains("not a socket")),
        "{error}"
    );
    assert_eq!(std::fs::read(session.join(name)).expect("kept"), b"notes");
}

#[test]
fn a_directory_others_can_write_to_is_refused() {
    let tmp = tmp();
    let daemon_base = daemon_base(tmp.path());
    let session = tmp.path().join("session");
    std::fs::create_dir(&session).expect("session dir");
    for mode in [0o777, 0o770, 0o707] {
        std::fs::set_permissions(&session, std::fs::Permissions::from_mode(mode)).expect("chmod");
        let runtime = tokio::runtime::Runtime::new().expect("runtime");
        let _enter = runtime.enter();
        let error = relay::prepare(&session, &daemon_base)
            .expect_err("a group or world writable directory is refused");
        assert!(
            matches!(&error, RelayError::UnsafeDirectory { reason, .. } if reason.contains("writable")),
            "{mode:o}: {error}"
        );
        assert!(
            entries(&session).is_empty(),
            "{mode:o}: no socket was bound, and the mode was not 'repaired'"
        );
        assert_eq!(mode_of(&session), mode, "{mode:o}: left as found");
    }
}

#[test]
fn the_directory_verdict_covers_owner_and_mode() {
    assert_eq!(directory_refusal(501, 501, 0o700), None);
    assert_eq!(directory_refusal(501, 501, 0o755), None);
    assert_eq!(directory_refusal(501, 501, 0o750), None);
    assert!(
        directory_refusal(0, 501, 0o700)
            .expect("foreign owner")
            .contains("another user")
    );
    assert!(
        directory_refusal(502, 501, 0o700)
            .expect("foreign owner")
            .contains("uid 502")
    );
    assert!(
        directory_refusal(501, 501, 0o770)
            .expect("group write")
            .contains("770")
    );
    assert!(
        directory_refusal(501, 501, 0o702)
            .expect("world write")
            .contains("702")
    );
    // The owner is checked first: a foreign directory is never described as merely writable.
    assert!(
        directory_refusal(0, 501, 0o777)
            .expect("both wrong")
            .contains("another user")
    );
}

/// A missing directory is created owner-only; an existing one the user owns is tightened to
/// `0700` through the handle that was checked (not by name).
#[test]
fn a_missing_directory_is_created_0700_and_an_owned_one_is_tightened() {
    let tmp = tmp();
    let daemon_base = daemon_base(tmp.path());
    let runtime = tokio::runtime::Runtime::new().expect("runtime");
    let _enter = runtime.enter();

    let fresh = tmp.path().join("deep").join("fresh");
    let bindings = relay::prepare(&fresh, &daemon_base).expect("creates the directory");
    assert_eq!(mode_of(&fresh), 0o700);
    drop(bindings);

    let open = tmp.path().join("open");
    std::fs::create_dir(&open).expect("dir");
    std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o755)).expect("chmod");
    let bindings = relay::prepare(&open, &daemon_base).expect("owned 0755 is accepted");
    assert_eq!(mode_of(&open), 0o700, "tightened to owner-only");
    drop(bindings);
}

// --- the startup probe ----------------------------------------------------------------------

/// What the fake daemon says to the n-th connection.
#[derive(Clone, Copy)]
enum Greets {
    Zmtp,
    Framed,
}

/// A fake daemon socket: each accepted connection is answered per `script` (the last entry
/// repeats) and then held open until the peer closes. Returns the number of connections served.
fn fake_daemon(path: &Path, script: Vec<Greets>) -> Arc<AtomicUsize> {
    let _ = std::fs::remove_file(path);
    let listener = std::os::unix::net::UnixListener::bind(path).expect("fake daemon binds");
    listener.set_nonblocking(true).expect("nonblocking");
    let listener = tokio::net::UnixListener::from_std(listener).expect("async listener");
    let served = Arc::new(AtomicUsize::new(0));
    let count = Arc::clone(&served);
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let index = count.fetch_add(1, Ordering::SeqCst);
            let greets = script[index.min(script.len() - 1)];
            tokio::spawn(async move {
                match greets {
                    Greets::Zmtp => {
                        // The 64-byte ZMTP 3.0 greeting: 0xFF, eight length bytes, 0x7F, ...
                        let mut greeting = [0u8; 64];
                        greeting[0] = 0xFF;
                        greeting[9] = 0x7F;
                        let _ = stream.write_all(&greeting).await;
                    }
                    Greets::Framed => {
                        let ack = Frame::HelloAck(HelloAck {
                            proto: WIRE_PROTOCOL,
                            version: "9.9.9".to_owned(),
                            epoch: "01JB2M5T8Q0V7K3W9X4Y6Z1ABC".to_owned(),
                            pid: std::process::id(),
                        });
                        let _ = pam_daemon::framed::send(&mut stream, &ack, 4096).await;
                    }
                }
                let mut sink = [0u8; 256];
                while matches!(stream.read(&mut sink).await, Ok(read) if read > 0) {}
            });
        }
    });
    served
}

#[test]
fn the_probe_tells_a_zmtp_greeting_from_a_framed_answer_from_silence() {
    let tmp = tmp();
    let runtime = tokio::runtime::Runtime::new().expect("runtime");
    runtime.block_on(async {
        let base = daemon_base(tmp.path());
        let socket = daemon_socket(&base);

        assert_eq!(probe(&socket).await, Probe::Unreachable, "no socket file");

        let _legacy = fake_daemon(&socket, vec![Greets::Zmtp]);
        assert_eq!(probe(&socket).await, Probe::LegacyZmtp);

        let _framed = fake_daemon(&socket, vec![Greets::Framed]);
        assert_eq!(probe(&socket).await, Probe::Framed);

        // A socket file nobody answers is a stale leftover, not a daemon.
        let stale = tmp.path().join("stale.sock");
        drop(std::os::unix::net::UnixListener::bind(&stale).expect("bind"));
        assert_eq!(probe(&stale).await, Probe::Unreachable);
    });
}

/// Records the order of the two supersede steps and answers from a script.
#[derive(Default)]
struct FakeOps {
    calls: Mutex<Vec<&'static str>>,
    stop: Mutex<VecDeque<StopScript>>,
    ensure_fails: bool,
}

enum StopScript {
    Stopped,
    NotRunning,
    StillDraining,
    SignalDenied,
    NoPid,
}

impl FakeOps {
    fn scripted(stop: StopScript) -> Arc<Self> {
        Arc::new(Self {
            stop: Mutex::new(VecDeque::from([stop])),
            ..Self::default()
        })
    }

    fn calls(&self) -> Vec<&'static str> {
        self.calls.lock().expect("calls").clone()
    }
}

impl SupersedeOps for FakeOps {
    fn stop(&self, _base: &Path) -> Result<StopOutcome, StopError> {
        self.calls.lock().expect("calls").push("stop");
        match self.stop.lock().expect("script").pop_front() {
            Some(StopScript::Stopped) => Ok(StopOutcome::Stopped { pid: 4242 }),
            Some(StopScript::NotRunning) => Ok(StopOutcome::NotRunning),
            Some(StopScript::StillDraining) => Ok(StopOutcome::StillDraining { pid: 4242 }),
            Some(StopScript::SignalDenied) => Err(StopError::Signal {
                pid: 4242,
                detail: "kill: Operation not permitted".to_owned(),
            }),
            Some(StopScript::NoPid) => Err(StopError::NoPid),
            None => panic!("stop called more than scripted"),
        }
    }

    fn ensure(&self, _base: &Path) -> Result<EnsureOutcome, ClientError> {
        self.calls.lock().expect("calls").push("ensure");
        if self.ensure_fails {
            return Err(ClientError::NotReady {
                waited: Duration::from_secs(6),
            });
        }
        Ok(EnsureOutcome::Started)
    }
}

/// A pre-migration daemon is replaced the way `pam daemon stop` does it: signal and wait, then
/// start this binary's daemon. The relay never touches a daemon that answers the hello.
#[test]
fn a_zmtp_daemon_is_stopped_then_replaced_and_a_framed_one_is_left_alone() {
    let tmp = tmp();
    let runtime = tokio::runtime::Runtime::new().expect("runtime");
    runtime.block_on(async {
        let base = daemon_base(tmp.path());
        let socket = daemon_socket(&base);

        // Nothing there: no daemon yet, nothing to supersede.
        let ops = FakeOps::scripted(StopScript::Stopped);
        assert_eq!(
            check_daemon(&socket, &base, &ops).await.expect("no daemon"),
            DaemonNote::NotRunning
        );
        assert!(ops.calls().is_empty());

        // A current daemon: reachable, never signalled.
        let framed = fake_daemon(&socket, vec![Greets::Framed]);
        assert_eq!(
            check_daemon(&socket, &base, &ops)
                .await
                .expect("current daemon"),
            DaemonNote::Reachable
        );
        assert!(ops.calls().is_empty(), "a current daemon is never stopped");
        assert!(framed.load(Ordering::SeqCst) >= 1);

        // A pre-migration daemon: stop, then ensure, in that order.
        let _legacy = fake_daemon(&socket, vec![Greets::Zmtp]);
        let ops = FakeOps::scripted(StopScript::Stopped);
        assert_eq!(
            check_daemon(&socket, &base, &ops)
                .await
                .expect("superseded"),
            DaemonNote::Superseded
        );
        assert_eq!(ops.calls(), vec!["stop", "ensure"]);

        // The lock was free by the time the relay looked (the old daemon exited): still start one.
        let ops = FakeOps::scripted(StopScript::NotRunning);
        assert_eq!(
            check_daemon(&socket, &base, &ops).await.expect("started"),
            DaemonNote::Superseded
        );
        assert_eq!(ops.calls(), vec!["stop", "ensure"]);
    });
}

/// A second client (or relay) that already replaced the daemon wins: the second dial sees a hello
/// succeed and the relay skips the signal.
#[test]
fn a_daemon_replaced_between_the_two_dials_is_not_signalled() {
    let tmp = tmp();
    let runtime = tokio::runtime::Runtime::new().expect("runtime");
    runtime.block_on(async {
        let base = daemon_base(tmp.path());
        let socket = daemon_socket(&base);
        // First connection: ZMTP. Every later one: framed.
        let _daemon = fake_daemon(&socket, vec![Greets::Zmtp, Greets::Framed]);
        let ops = FakeOps::scripted(StopScript::Stopped);
        assert_eq!(
            check_daemon(&socket, &base, &ops).await.expect("raced"),
            DaemonNote::Reachable
        );
        assert!(
            ops.calls().is_empty(),
            "no signal for a daemon that already answers: {:?}",
            ops.calls()
        );
    });
}

/// What the relay cannot do it says, with the instruction, and it starts nothing.
#[test]
fn a_daemon_the_relay_may_not_stop_ends_the_start_with_the_instruction() {
    let tmp = tmp();
    let runtime = tokio::runtime::Runtime::new().expect("runtime");
    runtime.block_on(async {
        let base = daemon_base(tmp.path());
        let socket = daemon_socket(&base);
        let _legacy = fake_daemon(&socket, vec![Greets::Zmtp]);

        let ops = FakeOps::scripted(StopScript::SignalDenied);
        let error = check_daemon(&socket, &base, &ops)
            .await
            .expect_err("a daemon that cannot be signalled stops the relay");
        let text = error.to_string();
        assert!(
            matches!(
                error,
                RelayError::LegacyDaemon {
                    pid: Some(4242),
                    ..
                }
            ),
            "{text}"
        );
        assert!(text.contains("pre-migration"), "{text}");
        assert!(text.contains("4242"), "{text}");
        assert!(text.contains("Operation not permitted"), "{text}");
        assert!(
            text.contains("pam daemon stop"),
            "names the way out: {text}"
        );
        assert_eq!(ops.calls(), vec!["stop"], "no replacement is started");

        let ops = FakeOps::scripted(StopScript::NoPid);
        let error = check_daemon(&socket, &base, &ops)
            .await
            .expect_err("no pid, no signal");
        assert!(
            matches!(error, RelayError::LegacyDaemon { pid: None, .. }),
            "{error}"
        );
        assert_eq!(ops.calls(), vec!["stop"]);

        let ops = FakeOps::scripted(StopScript::StillDraining);
        let error = check_daemon(&socket, &base, &ops)
            .await
            .expect_err("still draining");
        let text = error.to_string();
        assert!(text.contains("still draining"), "{text}");
        assert!(text.contains("wait a few seconds"), "{text}");
        assert_eq!(ops.calls(), vec!["stop"]);

        let ops = Arc::new(FakeOps {
            stop: Mutex::new(VecDeque::from([StopScript::Stopped])),
            ensure_fails: true,
            ..FakeOps::default()
        });
        let error = check_daemon(&socket, &base, &ops)
            .await
            .expect_err("replacement does not start");
        let text = error.to_string();
        assert!(text.contains("replacement did not start"), "{text}");
        assert!(text.contains("pam daemon"), "{text}");
        assert_eq!(ops.calls(), vec!["stop", "ensure"]);
    });
}

/// A scripted source of client connections: yields its queue in order (an
/// `Err` is an accept failure), then never yields again.
struct Scripted {
    queue: Mutex<VecDeque<io::Result<tokio::net::UnixStream>>>,
}

impl Accept for Scripted {
    async fn accept_client(&self) -> io::Result<tokio::net::UnixStream> {
        let next = self.queue.lock().expect("script lock").pop_front();
        match next {
            Some(item) => item,
            None => std::future::pending().await,
        }
    }
}

/// A connected pair: the first end is what the "client" holds, the second is
/// what the relay "accepts".
fn pair() -> (tokio::net::UnixStream, tokio::net::UnixStream) {
    tokio::net::UnixStream::pair().expect("socket pair")
}

/// EMFILE or an aborted handshake says nothing about the listener: the relay
/// backs off and keeps accepting instead of exiting and tearing down its
/// socket.
#[test]
fn a_transient_accept_error_does_not_end_the_relay() {
    let tmp = tmp();
    let runtime = tokio::runtime::Runtime::new().expect("runtime");
    runtime.block_on(async {
        let echo = tmp.path().join("echo.sock");
        let _keepalive = bind_echo_daemon(&echo);
        let (mut client, accepted) = pair();
        let script = Scripted {
            queue: Mutex::new(VecDeque::from([
                Err(io::Error::from_raw_os_error(24)), // EMFILE
                Err(io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    "handshake aborted",
                )),
                Ok(accepted),
            ])),
        };
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let server = tokio::spawn(relay::forward_loop(script, echo, shutdown_rx, 8));

        client.write_all(b"still here").await.expect("write");
        let mut buffer = [0u8; 10];
        tokio::time::timeout(Duration::from_secs(5), client.read_exact(&mut buffer))
            .await
            .expect("the relay served the client after two accept errors")
            .expect("echo read");
        assert_eq!(&buffer, b"still here");
        assert!(!server.is_finished(), "the accept loop is still running");

        let _ = shutdown_tx.send(true);
        tokio::time::timeout(Duration::from_secs(5), server)
            .await
            .expect("shutdown still ends the loop")
            .expect("loop joins");
    });
}

/// One peer cannot exhaust the relay: past the cap, new connections are
/// closed at once while the ones in service keep working.
#[test]
fn concurrent_relayed_connections_are_capped() {
    let tmp = tmp();
    let runtime = tokio::runtime::Runtime::new().expect("runtime");
    runtime.block_on(async {
        let echo = tmp.path().join("echo.sock");
        let _keepalive = bind_echo_daemon(&echo);
        let (mut first, first_server) = pair();
        let (mut second, second_server) = pair();
        let (mut third, third_server) = pair();
        let script = Scripted {
            queue: Mutex::new(VecDeque::from([
                Ok(first_server),
                Ok(second_server),
                Ok(third_server),
            ])),
        };
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let server = tokio::spawn(relay::forward_loop(script, echo, shutdown_rx, 2));

        for (index, client) in [&mut first, &mut second].into_iter().enumerate() {
            client.write_all(b"ping").await.expect("write");
            let mut buffer = [0u8; 4];
            tokio::time::timeout(Duration::from_secs(5), client.read_exact(&mut buffer))
                .await
                .expect("within the cap, served")
                .expect("echo read");
            assert_eq!(&buffer, b"ping", "client {index}");
        }
        let mut buffer = [0u8; 1];
        let read = tokio::time::timeout(Duration::from_secs(5), third.read(&mut buffer))
            .await
            .expect("the over-cap client is closed promptly, not left hanging");
        assert!(
            matches!(read, Ok(0) | Err(_)),
            "the third connection is shed: {read:?}"
        );
        // The two in service are unaffected by the shed one.
        first.write_all(b"pong").await.expect("write");
        let mut buffer = [0u8; 4];
        first.read_exact(&mut buffer).await.expect("echo read");
        assert_eq!(&buffer, b"pong");

        let _ = shutdown_tx.send(true);
        tokio::time::timeout(Duration::from_secs(5), server)
            .await
            .expect("shutdown ends the loop")
            .expect("loop joins");
    });
}
