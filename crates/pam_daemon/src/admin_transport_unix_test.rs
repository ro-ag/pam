use std::collections::VecDeque;
use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use pam_proto::{Caller, Envelope, Outcome, PROTOCOL_VERSION, Response};
use pam_store::Store;
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::watch;

use super::frame::{AcceptBackoff, AdminLifecycle};
use super::platform::{Accept, Listener};
use crate::admin::{ADMIN_CALLER_AGENT, AdminService, OP_PROFILE_GET};
use crate::approval::ApprovalService;
use crate::connector_service::ConnectorService;
use crate::image::{BootImage, FsProbe, ImageProbe, ImageWatch};
use crate::lifecycle::LifecyclePhase;
use crate::log_service::LogService;
use crate::model_service::ModelService;
use crate::transport::EventPublisher;

const DEADLINE: Duration = Duration::from_secs(10);

/// A real listener behind a script of accept errors: each `accept` returns
/// the next scripted error until the script is empty, then the real result.
struct Flaky {
    script: VecDeque<io::Error>,
    served: Arc<AtomicUsize>,
    inner: UnixListener,
}

impl Accept for Flaky {
    async fn accept(&mut self) -> io::Result<UnixStream> {
        if let Some(error) = self.script.pop_front() {
            self.served.fetch_add(1, Ordering::SeqCst);
            return Err(error);
        }
        Accept::accept(&mut self.inner).await
    }
}

async fn admin_service() -> Arc<AdminService> {
    let store = Arc::new(Store::open_in_memory().await.unwrap());
    let (events, _rx) = EventPublisher::for_tests();
    let approvals = Arc::new(ApprovalService::new(
        Arc::clone(&store),
        events,
        Duration::from_mins(10),
    ));
    let models = ModelService::new(Arc::clone(&store)).await.unwrap();
    let logs = LogService::new(Arc::clone(&store), Arc::clone(&models));
    let connectors = Arc::new(ConnectorService::from_parts(Arc::clone(&store), None, None));
    let flows = crate::flow_service_test::flows_for_tests(
        std::path::Path::new("pam-tests-have-no-flow-library"),
        &store,
        &approvals,
        &connectors,
        &logs,
    )
    .await;
    Arc::new(AdminService::new(
        store,
        approvals,
        models,
        logs,
        connectors,
        flows,
        crate::flow_service_test::closed_submit(),
    ))
}

fn lifecycle() -> AdminLifecycle {
    let (phase, _) = watch::channel(LifecyclePhase::Serving);
    let probe: Arc<dyn ImageProbe> = Arc::new(FsProbe);
    AdminLifecycle {
        phase,
        image: ImageWatch::with_boot(BootImage::from_paths(Vec::new(), probe.as_ref()), probe),
    }
}

fn profile_get(id: &str) -> Envelope {
    Envelope {
        v: PROTOCOL_VERSION,
        id: id.to_owned(),
        capability: OP_PROFILE_GET.to_owned(),
        client_version: env!("CARGO_PKG_VERSION").to_owned(),
        caller: Caller {
            agent: ADMIN_CALLER_AGENT.to_owned(),
            repo: "/repo".to_owned(),
            pid: std::process::id(),
        },
        args: serde_json::json!({}),
        idempotency_key: None,
        deadline_ms: 5_000,
        wait: true,
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
/// now logs, backs off and accepts again.
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
            io::Error::other("too many open files"),
            io::Error::from(io::ErrorKind::ConnectionAborted),
            io::Error::from(io::ErrorKind::Interrupted),
            io::Error::from(io::ErrorKind::OutOfMemory),
            io::Error::other("something new"),
        ]
        .into();
        let scripted = script.len();
        let counter = Arc::clone(&served);
        let listener = Listener::bind_with(&base, admin_service().await, lifecycle(), |inner| {
            Flaky {
                script,
                served: counter,
                inner,
            }
        })
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

#[test]
fn accept_backoff_retries_gone_peers_at_once_and_paces_everything_else() {
    let mut backoff = AcceptBackoff::new();
    // A peer that vanished or a signal: nothing is wrong with the listener.
    assert_eq!(
        backoff.after(&io::Error::from(io::ErrorKind::ConnectionAborted)),
        Duration::ZERO
    );
    assert_eq!(
        backoff.after(&io::Error::from(io::ErrorKind::Interrupted)),
        Duration::ZERO
    );
    // Resource exhaustion and unknown errors: 10 ms, doubling, capped at 1 s.
    let mut pauses = Vec::new();
    for _ in 0..10 {
        pauses.push(backoff.after(&io::Error::other("too many open files")));
    }
    assert_eq!(pauses[0], AcceptBackoff::FIRST);
    assert_eq!(pauses[1], AcceptBackoff::FIRST * 2);
    assert_eq!(pauses[2], AcceptBackoff::FIRST * 4);
    assert!(pauses.windows(2).all(|pair| pair[0] <= pair[1]));
    assert_eq!(*pauses.last().unwrap(), AcceptBackoff::MAX);
    // One success and the next error starts over.
    backoff.reset();
    assert_eq!(
        backoff.after(&io::Error::other("too many open files")),
        AcceptBackoff::FIRST
    );
}
