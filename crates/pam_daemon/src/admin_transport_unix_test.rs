//! The Unix adapter on its real socket: bind, modes, the kernel's word about
//! the peer, the scripted accept errors, and the client's single send.

use std::collections::VecDeque;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use pam_proto::wire::cause;
use pam_proto::{Event, Outcome, Response};
use tokio::io::AsyncReadExt;
use tokio::net::UnixStream;

use super::frame_test::{DEADLINE, admin_service, lifecycle, profile_get};
use super::platform::Listener;
use crate::event_hub::EventHub;
use crate::framed::{Accept, DialError};
use crate::framed_unix::UnixAcceptor;
use crate::ingress::PeerIdentity;

/// The real acceptor behind a script of accept errors: each `accept` returns
/// the next scripted error until the script is empty, then the real result.
struct Flaky {
    script: VecDeque<io::Error>,
    served: Arc<AtomicUsize>,
    inner: UnixAcceptor,
}

impl Accept for Flaky {
    type Stream = UnixStream;

    async fn accept(&mut self) -> io::Result<(UnixStream, PeerIdentity)> {
        if let Some(error) = self.script.pop_front() {
            self.served.fetch_add(1, Ordering::SeqCst);
            return Err(error);
        }
        self.inner.accept().await
    }

    fn reject(stream: UnixStream, frame: &[u8]) -> impl Future<Output = ()> + Send {
        UnixAcceptor::reject(stream, frame)
    }

    fn close(&mut self) {
        self.inner.close();
    }
}

/// A private base short enough for a unix socket path.
fn short_base() -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix("pam")
        .tempdir_in("/tmp")
        .expect("tempdir under /tmp")
}

/// The listener used to end on the first accept error, taking the whole
/// private plane with it while the daemon kept serving public traffic. It
/// now runs on the shared accept loop, which logs, backs off and accepts
/// again.
#[tokio::test]
async fn the_admin_listener_survives_accept_errors_and_keeps_serving() {
    tokio::time::timeout(DEADLINE, async {
        let tmp = short_base();
        let base = super::prepare_base(&tmp.path().join("pam")).unwrap();
        let served = Arc::new(AtomicUsize::new(0));
        let script: VecDeque<io::Error> = [
            // Descriptor exhaustion (EMFILE surfaces as an uncategorized
            // error), a peer that vanished mid-handshake, a signal, and
            // an error this code has never heard of.
            io::Error::from_raw_os_error(24),
            io::Error::other("too many open files"),
            io::Error::from(io::ErrorKind::ConnectionAborted),
            io::Error::from(io::ErrorKind::Interrupted),
            io::Error::from(io::ErrorKind::OutOfMemory),
            io::Error::other("something new"),
        ]
        .into();
        let scripted = script.len();
        let counter = Arc::clone(&served);
        let listener = Listener::bind_with(
            &base,
            admin_service().await,
            lifecycle(),
            EventHub::new(),
            |inner| Flaky {
                script,
                served: counter,
                inner,
            },
        )
        .unwrap();

        // Every scripted error has been returned and the loop is still
        // accepting: a real client is served, twice.
        for id in ["req_after_errors", "req_again"] {
            let response = super::exchange(&base, &profile_get(id)).await.unwrap();
            assert!(
                matches!(&response, Response::Result { id: got, outcome: Outcome::Verified, .. } if got == id),
                "{response:?}"
            );
        }
        assert_eq!(served.load(Ordering::SeqCst), scripted);
        listener.shutdown().await;
    })
    .await
    .expect("test within deadline");
}

/// The whole private path on the real socket: owner-only modes, a request,
/// the event stream, and a shutdown that ends the stream by name and leaves
/// no socket file behind.
#[tokio::test]
async fn the_private_socket_serves_requests_and_events_and_is_unlinked_at_shutdown() {
    tokio::time::timeout(DEADLINE, async {
        let tmp = short_base();
        let base = super::prepare_base(&tmp.path().join("pam")).unwrap();
        let hub = EventHub::new();
        let listener =
            Listener::bind(&base, admin_service().await, lifecycle(), Arc::clone(&hub)).unwrap();

        let socket = base.join("admin").join("control.sock");
        let mode = |path: &std::path::Path| path.metadata().unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&base.join("admin")), 0o700);
        assert_eq!(mode(&socket), 0o600);

        let response = super::exchange(&base, &profile_get("req_real_socket"))
            .await
            .unwrap();
        assert!(matches!(response, Response::Result { .. }), "{response:?}");

        // A version this daemon is not: refused at the hello, and the
        // refusal reaches the client as one for its request.
        let mut other_build = profile_get("req_other_build");
        other_build.client_version = "different-build".to_owned();
        let response = super::exchange(&base, &other_build).await.unwrap();
        assert!(
            matches!(&response, Response::Refusal { id, cause: named, retryable: false, .. }
                if id == "req_other_build" && named == cause::CLIENT_VERSION_MISMATCH),
            "{response:?}"
        );

        let mut events = super::events(&base).await.unwrap();
        assert_eq!(events.epoch(), hub.epoch());
        hub.publish("req_ticket", Event::Started).unwrap();
        let frame = events.next().await.unwrap();
        assert_eq!(
            (frame.ticket.as_deref(), &frame.event),
            (Some("req_ticket"), &Event::Started)
        );

        listener.shutdown().await;
        let ended = events.next().await;
        assert!(
            matches!(&ended, Err(DialError::Refused(error)) if error.cause == cause::DAEMON_SHUTTING_DOWN),
            "{ended:?}"
        );
        assert!(!socket.exists(), "the socket file is unlinked at shutdown");
        let gone = super::exchange(&base, &profile_get("req_gone")).await;
        assert_eq!(gone.unwrap_err().kind(), io::ErrorKind::NotFound);
        let gone = super::events(&base).await;
        assert!(
            matches!(&gone, Err(DialError::Io(error)) if error.kind() == io::ErrorKind::NotFound),
            "{gone:?}"
        );
    })
    .await
    .expect("test within deadline");
}

/// The client checks the endpoint before it sends anything: a socket that is
/// not owner-only is refused, and a socket left by an earlier daemon is
/// replaced only when it passes the same check.
#[tokio::test]
async fn an_endpoint_that_is_not_owner_only_is_refused_by_client_and_daemon() {
    tokio::time::timeout(DEADLINE, async {
        let tmp = short_base();
        let base = super::prepare_base(&tmp.path().join("pam")).unwrap();
        let listener =
            Listener::bind(&base, admin_service().await, lifecycle(), EventHub::new()).unwrap();
        let socket = base.join("admin").join("control.sock");
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o666)).unwrap();

        let refused = super::exchange(&base, &profile_get("req_loose_socket")).await;
        assert_eq!(refused.unwrap_err().kind(), io::ErrorKind::PermissionDenied);
        let refused = super::events(&base).await;
        assert!(
            matches!(&refused, Err(DialError::Io(error)) if error.kind() == io::ErrorKind::PermissionDenied),
            "{refused:?}"
        );
        // A second daemon does not take over a socket it cannot vouch for.
        let second = Listener::bind(&base, admin_service().await, lifecycle(), EventHub::new());
        assert_eq!(
            second.err().map(|error| error.kind()),
            Some(io::ErrorKind::PermissionDenied)
        );
        listener.shutdown().await;
    })
    .await
    .expect("test within deadline");
}

/// Administration is sent once. A daemon that takes the request and goes away
/// without a reply leaves an error, and the client does not dial again: the
/// effect is unknown and replaying it could apply it twice.
#[tokio::test]
async fn an_admin_operation_is_sent_once_and_never_replayed() {
    tokio::time::timeout(DEADLINE, async {
        let tmp = short_base();
        let base = super::prepare_base(&tmp.path().join("pam")).unwrap();
        // Bind and stop a real listener once so the private directory exists
        // with the modes the client insists on.
        Listener::bind(&base, admin_service().await, lifecycle(), EventHub::new())
            .unwrap()
            .shutdown()
            .await;
        let mut silent = UnixAcceptor::bind(&base.join("admin").join("control.sock")).unwrap();
        let connections = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&connections);
        let daemon = tokio::spawn(async move {
            let mut received = Vec::new();
            loop {
                let (mut stream, _) = silent.accept().await.unwrap();
                counter.fetch_add(1, Ordering::SeqCst);
                // Take everything the client sends, then vanish.
                let mut buffer = vec![0u8; 64 * 1024];
                let count = stream.read(&mut buffer).await.unwrap();
                received.push(buffer[..count].to_vec());
                drop(stream);
                if received.len() == 2 {
                    return received;
                }
            }
        });

        let request = profile_get("req_sent_once");
        let outcome = super::exchange(&base, &request).await;
        assert!(outcome.is_err(), "{outcome:?}");
        // Time for a retry to show up, if there were one.
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(connections.load(Ordering::SeqCst), 1);
        daemon.abort();
    })
    .await
    .expect("test within deadline");
}

/// Waits until the observer has written `count` observation rows.
async fn observations(
    store: &pam_store::Store,
    count: usize,
) -> Vec<pam_store::BoundaryObservationRow> {
    let waited = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let rows = store.list_boundary_observations(16).await.unwrap();
            if rows.len() >= count {
                return rows;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    if let Ok(rows) = waited {
        return rows;
    }
    panic!(
        "the observer recorded {:?}, expected {count} rows; census {:?}",
        store.list_boundary_observations(16).await.unwrap(),
        store.boundary_census().await.unwrap()
    )
}

/// A boundary observer for `base` whose trusted image is `image`.
async fn observe(
    base: &std::path::Path,
    image: Option<std::path::PathBuf>,
) -> (
    Arc<pam_store::Store>,
    Arc<crate::boundary::Boundary>,
    tokio::task::JoinHandle<()>,
) {
    let store = Arc::new(pam_store::Store::open_in_memory().await.unwrap());
    let boundary = crate::boundary::Boundary::new(
        Arc::clone(&store),
        image,
        Arc::new(crate::boundary::SystemResolver),
    );
    boundary.load().await;
    let (stop, shutdown) = tokio::sync::watch::channel(false);
    // The observer runs until the test aborts it; the sender is never dropped.
    std::mem::forget(stop);
    let (sink, task) = boundary.spawn_admin_observer(shutdown);
    crate::boundary::register_admin_sink(base, sink);
    (store, boundary, task)
}

fn same_file(a: &str, b: &std::path::Path) -> bool {
    std::path::Path::new(a).canonicalize().ok() == b.canonicalize().ok()
}

/// The doctor's `admin.endpoint` probe — connect, send nothing, drop — is
/// seen by the daemon as an admin contact with the kernel's pid and this
/// process's executable; a hello from the daemon's own image (the GUI,
/// here this very test binary) is an expected one.
#[tokio::test]
async fn an_accepted_connection_is_an_admin_contact_and_the_own_image_is_expected() {
    tokio::time::timeout(DEADLINE, async {
        let tmp = short_base();
        let base = super::prepare_base(&tmp.path().join("pam")).unwrap();
        let exe = std::env::current_exe().unwrap();
        let (store, boundary, observer) = observe(&base, Some(exe.clone())).await;
        let listener =
            Listener::bind(&base, admin_service().await, lifecycle(), EventHub::new()).unwrap();

        // The probe: the doctor holds its socket for a moment so the
        // kernel can still say who connected when the daemon accepts.
        let socket = base.join("admin").join("control.sock");
        let probe = UnixStream::connect(&socket).await.unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;
        drop(probe);
        let rows = observations(&store, 1).await;
        let probe = &rows[0];
        assert_eq!(probe.kind, pam_store::OBSERVATION_ADMIN_CONTACT);
        assert!(!probe.expected);
        assert_eq!(probe.peer.pid, Some(std::process::id()));
        assert_eq!(
            probe.detail.as_deref(),
            Some("accepted; the peer sent nothing")
        );
        assert!(
            probe
                .peer
                .exe
                .as_deref()
                .is_some_and(|got| same_file(got, &exe)),
            "{probe:?}"
        );
        assert!(probe.peer.harness.is_some());
        assert_eq!(probe.attributed, None);

        // The GUI: a real hello and request from the trusted image.
        let response = super::exchange(&base, &profile_get("req_gui"))
            .await
            .unwrap();
        assert!(matches!(response, Response::Result { .. }), "{response:?}");
        let rows = observations(&store, 2).await;
        let gui = rows
            .iter()
            .find(|row| row.expected)
            .unwrap_or_else(|| panic!("{rows:?}"));
        assert_eq!(
            gui.detail.as_deref(),
            Some("hello from the daemon's own image")
        );
        assert_eq!(gui.peer.pid, Some(std::process::id()));

        let block = boundary.status_block();
        assert_eq!(block["admin_contacts"]["unattributed"], 1);
        assert_eq!(block["admin_contacts"]["expected_total"], 1);
        assert_eq!(
            block["admin_contacts"]["last"]["peer_pid"],
            std::process::id()
        );
        listener.shutdown().await;
        observer.abort();
    })
    .await
    .expect("test within deadline");
}

/// A peer that connects and closes before the daemon accepts cannot be
/// identified (`getpeereid` fails on the closed socket and the acceptor
/// reports the connection aborted); it is still recorded as a contact,
/// with no pid and nothing to attribute it to.
#[tokio::test]
async fn a_connection_gone_before_its_credentials_are_read_is_a_vanished_contact() {
    tokio::time::timeout(DEADLINE, async {
        let tmp = short_base();
        let base = super::prepare_base(&tmp.path().join("pam")).unwrap();
        let (store, _boundary, observer) = observe(&base, None).await;
        let listener =
            Listener::bind(&base, admin_service().await, lifecycle(), EventHub::new()).unwrap();
        let socket = base.join("admin").join("control.sock");
        // Closed before the listener's task runs: not yet accepted.
        drop(UnixStream::connect(&socket).await.unwrap());
        let rows = observations(&store, 1).await;
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].kind, pam_store::OBSERVATION_ADMIN_CONTACT);
        assert_eq!(rows[0].peer.pid, None);
        assert_eq!(
            rows[0].detail.as_deref(),
            Some("accepted; gone before its credentials could be read")
        );
        assert!(!rows[0].expected);
        // The listener is still serving.
        let response = super::exchange(&base, &profile_get("req_after_vanish"))
            .await
            .unwrap();
        assert!(matches!(response, Response::Result { .. }), "{response:?}");
        listener.shutdown().await;
        observer.abort();
    })
    .await
    .expect("test within deadline");
}

/// A hello from an executable that is not the daemon's image is an
/// unexpected contact, whatever it asked for.
#[tokio::test]
async fn a_hello_from_another_executable_is_an_unexpected_admin_contact() {
    tokio::time::timeout(DEADLINE, async {
        let tmp = short_base();
        let base = super::prepare_base(&tmp.path().join("pam")).unwrap();
        let (store, boundary, observer) = observe(
            &base,
            Some(std::path::PathBuf::from(
                "/Applications/PAM.app/Contents/MacOS/pam",
            )),
        )
        .await;
        let listener =
            Listener::bind(&base, admin_service().await, lifecycle(), EventHub::new()).unwrap();
        let response = super::exchange(&base, &profile_get("req_foreign"))
            .await
            .unwrap();
        assert!(matches!(response, Response::Result { .. }), "{response:?}");
        let rows = observations(&store, 1).await;
        assert_eq!(rows.len(), 1);
        assert!(!rows[0].expected);
        assert_eq!(
            rows[0].detail.as_deref(),
            Some("hello from another executable")
        );
        assert_eq!(rows[0].peer.pid, Some(std::process::id()));
        assert_eq!(boundary.status_block()["admin_contacts"]["unattributed"], 1);
        listener.shutdown().await;
        observer.abort();
    })
    .await
    .expect("test within deadline");
}

/// A listener bound under a base nobody observes serves as before.
#[tokio::test]
async fn an_unobserved_listener_serves_without_a_sink() {
    tokio::time::timeout(DEADLINE, async {
        let tmp = short_base();
        let base = super::prepare_base(&tmp.path().join("pam")).unwrap();
        assert!(crate::boundary::admin_sink_for(&base).is_none());
        let listener =
            Listener::bind(&base, admin_service().await, lifecycle(), EventHub::new()).unwrap();
        let socket = base.join("admin").join("control.sock");
        drop(UnixStream::connect(&socket).await.unwrap());
        let response = super::exchange(&base, &profile_get("req_unobserved"))
            .await
            .unwrap();
        assert!(matches!(response, Response::Result { .. }), "{response:?}");
        listener.shutdown().await;
    })
    .await
    .expect("test within deadline");
}
