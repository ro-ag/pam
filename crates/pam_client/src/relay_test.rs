//! Relay unit tests: both sockets forward byte-for-byte, a live relay is
//! never taken over, and a stale socket file is replaced. Unix only — the
//! relay's transport is unix domain sockets.

use std::collections::VecDeque;
use std::io;
use std::sync::Mutex;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::watch;

use crate::relay::{self, Accept, RelayError};

fn tmp() -> tempfile::TempDir {
    tempfile::tempdir().expect("tempdir")
}

/// A daemon stand-in: binds `path` and echoes every byte back. The caller
/// must hold the returned listener for the echo to keep serving.
fn bind_echo_daemon(path: &std::path::Path) -> tokio::net::UnixListener {
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
/// `<base>/session`, and the echo listeners that keep the fake alive.
struct Fixture {
    echo_keepalive: [tokio::net::UnixListener; 2],
    session: std::path::PathBuf,
    shutdown_tx: watch::Sender<bool>,
    server: tokio::task::JoinHandle<Result<(), RelayError>>,
}

fn start_relay(base: &std::path::Path) -> Fixture {
    let daemon_base = base.join("base");
    let session = base.join("session");
    std::fs::create_dir_all(daemon_base.join("run")).expect("daemon run dir");

    let echo_keepalive = [
        bind_echo_daemon(&daemon_base.join("run/pam.sock")),
        bind_echo_daemon(&daemon_base.join("run/events.sock")),
    ];

    let bindings = relay::prepare(&session, &daemon_base).expect("relay prepares");
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let server = tokio::spawn(relay::serve(bindings, shutdown_rx));

    let router = session.join("pam.sock");
    for _ in 0..200 {
        if router.exists() && session.join("events.sock").exists() {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(router.exists(), "the relay binds pam.sock");
    Fixture {
        echo_keepalive,
        session,
        shutdown_tx,
        server,
    }
}

impl Fixture {
    async fn stop(self) {
        // The echo listeners go last: the relay's sockets are removed by
        // its own shutdown path, which the join below waits for.
        let Fixture {
            echo_keepalive,
            session,
            shutdown_tx,
            server,
        } = self;
        let _ = shutdown_tx.send(true);
        server.await.expect("serve joins").expect("serve ok");
        assert!(
            !session.join("pam.sock").exists(),
            "relay sockets are cleaned up on shutdown"
        );
        drop(echo_keepalive);
    }
}

#[test]
fn the_relay_forwards_both_sockets_byte_for_byte() {
    let tmp = tmp();
    let runtime = tokio::runtime::Runtime::new().expect("runtime");
    runtime.block_on(async {
        let fixture = start_relay(tmp.path());

        let mut client = tokio::net::UnixStream::connect(fixture.session.join("pam.sock"))
            .await
            .expect("router dials");
        client.write_all(b"envelope").await.expect("write");
        let mut buffer = [0u8; 8];
        client.read_exact(&mut buffer).await.expect("echo read");
        assert_eq!(&buffer, b"envelope");

        let mut events = tokio::net::UnixStream::connect(fixture.session.join("events.sock"))
            .await
            .expect("events dials");
        events.write_all(b"topic payload").await.expect("write");
        let mut buffer = [0u8; 13];
        events.read_exact(&mut buffer).await.expect("echo read");
        assert_eq!(&buffer, b"topic payload");

        fixture.stop().await;
    });
}

#[test]
fn a_live_relay_is_never_taken_over() {
    let tmp = tmp();
    let runtime = tokio::runtime::Runtime::new().expect("runtime");
    runtime.block_on(async {
        let daemon_base = tmp.path().join("base");
        let session = tmp.path().join("session");
        std::fs::create_dir_all(daemon_base.join("run")).expect("daemon run dir");
        let _echo_keepalive = [
            bind_echo_daemon(&daemon_base.join("run/pam.sock")),
            bind_echo_daemon(&daemon_base.join("run/events.sock")),
        ];

        let first = relay::prepare(&session, &daemon_base).expect("first relay prepares");
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let server = tokio::spawn(relay::serve(first, shutdown_rx));
        for _ in 0..200 {
            if session.join("pam.sock").exists() {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }

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
        let daemon_base = tmp.path().join("base");
        let session = tmp.path().join("session");
        std::fs::create_dir_all(daemon_base.join("run")).expect("daemon run dir");
        std::fs::create_dir_all(&session).expect("session dir");

        // A socket file nobody answers: bind, then drop the listener.
        let dead = session.join("pam.sock");
        let listener = std::os::unix::net::UnixListener::bind(&dead).expect("bind");
        drop(listener);

        let _echo_keepalive = [
            bind_echo_daemon(&daemon_base.join("run/pam.sock")),
            bind_echo_daemon(&daemon_base.join("run/events.sock")),
        ];
        let bindings = relay::prepare(&session, &daemon_base)
            .expect("a stale socket file must be replaced, not refused");
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let server = tokio::spawn(relay::serve(bindings, shutdown_rx));
        let _ = shutdown_tx.send(true);
        server.await.expect("serve joins").expect("serve ok");
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
/// backs off and keeps accepting instead of exiting and tearing down both
/// sockets.
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
