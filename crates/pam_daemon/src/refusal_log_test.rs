//! The refusal log: coalescing under a burst, the memory bound, a reply path
//! that never waits for the store, retries, and the last write at shutdown.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use pam_store::{RefusalRow, RefusalWrite, RequestIngress, Store, StoreError};
use tokio::sync::watch;

use crate::boundary::{PeerResolver, ResolvedPeer};
use crate::ingress::PeerIdentity;
use crate::refusal_log::{
    Refusal, RefusalBackend, RefusalLimits, RefusalLog, Writing, of_handshake,
};

#[derive(Debug)]
struct Table;

impl PeerResolver for Table {
    fn resolve(&self, pid: u32) -> ResolvedPeer {
        ResolvedPeer {
            exe: (pid == 77).then(|| PathBuf::from("/opt/agent/bin/agent")),
            chain: Vec::new(),
        }
    }
}

/// A backend that waits before it writes: the slow disk.
#[derive(Debug)]
struct Slow {
    store: Arc<Store>,
    delay: Duration,
}

impl RefusalBackend for Slow {
    fn write(&self, writes: Vec<RefusalWrite>) -> Writing<'_> {
        Box::pin(async move {
            tokio::time::sleep(self.delay).await;
            self.store.write_refusals(writes).await
        })
    }
}

/// A backend that refuses its first `failures` writes.
#[derive(Debug)]
struct Flaky {
    store: Arc<Store>,
    failures: usize,
    calls: AtomicUsize,
}

impl RefusalBackend for Flaky {
    fn write(&self, writes: Vec<RefusalWrite>) -> Writing<'_> {
        Box::pin(async move {
            if self.calls.fetch_add(1, Ordering::SeqCst) < self.failures {
                return Err(StoreError::Overloaded { waiting: 64 });
            }
            self.store.write_refusals(writes).await
        })
    }
}

fn limits() -> RefusalLimits {
    RefusalLimits {
        window: Duration::from_secs(10),
        flush_delay: Duration::from_millis(10),
        max_runs: 256,
        retry_delay: Duration::from_millis(20),
        resolve_budget: Duration::from_secs(2),
    }
}

struct Harness {
    store: Arc<Store>,
    log: RefusalLog,
    stop: watch::Sender<bool>,
    task: tokio::task::JoinHandle<()>,
}

async fn harness_with(limits: RefusalLimits) -> Harness {
    let store = Arc::new(Store::open_in_memory().await.unwrap());
    let (stop, rx) = watch::channel(false);
    let (log, task) = RefusalLog::spawn(
        Arc::clone(&store) as Arc<dyn RefusalBackend>,
        Arc::new(Table),
        limits,
        rx,
    );
    Harness {
        store,
        log,
        stop,
        task,
    }
}

async fn harness() -> Harness {
    harness_with(limits()).await
}

fn peer(pid: u32) -> PeerIdentity {
    PeerIdentity::Unix {
        uid: 501,
        gid: 20,
        pid: Some(pid),
    }
}

fn refusal(cause: &str) -> Refusal<'_> {
    Refusal::new(RequestIngress::Public, cause, "the daemon said no").peer(peer(77))
}

async fn rows(store: &Store) -> Vec<RefusalRow> {
    store.list_refusals(500, None, None, None).await.unwrap()
}

#[tokio::test]
async fn a_burst_of_a_thousand_identical_refusals_is_one_row_with_the_count() {
    let h = harness().await;
    for _ in 0..1_000 {
        h.log.record(&refusal("request_rate_exhausted"));
    }
    h.log.flush().await;

    let rows = rows(&h.store).await;
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0].count, 1_000);
    assert_eq!(rows[0].cause, "request_rate_exhausted");
    assert_eq!(rows[0].peer_uid, Some(501));
    assert_eq!(rows[0].peer_pid, Some(77));
    // Resolved by the writer, off the reply path.
    assert_eq!(rows[0].peer_exe.as_deref(), Some("/opt/agent/bin/agent"));
    assert_eq!(h.log.recorded(), 1_000);
    assert_eq!(h.log.dropped(), 0);
}

#[tokio::test]
async fn a_burst_that_straddles_writes_still_adds_up() {
    let h = harness().await;
    for round in 0..5 {
        for _ in 0..200 {
            h.log.record(&refusal("request_capacity_exhausted"));
        }
        // Some rounds are written while the next one arrives, some after.
        if round % 2 == 0 {
            h.log.flush().await;
        }
    }
    h.log.flush().await;
    let rows = rows(&h.store).await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].count, 1_000);
}

#[tokio::test]
async fn refusals_that_differ_in_cause_peer_or_capability_are_separate_rows() {
    let h = harness().await;
    h.log.record(&refusal("bad_frame"));
    h.log.record(&refusal("handshake_timeout"));
    h.log
        .record(&Refusal::new(RequestIngress::Public, "bad_frame", "x").peer(peer(78)));
    let mut with_capability = refusal("bad_frame");
    with_capability.capability = Some("echo");
    h.log.record(&with_capability);
    let mut admin = refusal("bad_frame");
    admin.plane = RequestIngress::Admin;
    h.log.record(&admin);
    h.log.flush().await;
    assert_eq!(rows(&h.store).await.len(), 5);
}

#[tokio::test]
async fn a_run_is_over_after_its_window_and_the_next_attempt_gets_its_own_row() {
    let mut short = limits();
    short.window = Duration::from_millis(80);
    let h = harness_with(short).await;
    h.log.record(&refusal("bad_frame"));
    h.log.flush().await;
    tokio::time::sleep(Duration::from_millis(120)).await;
    h.log.record(&refusal("bad_frame"));
    h.log.flush().await;
    let rows = rows(&h.store).await;
    assert_eq!(rows.len(), 2, "{rows:?}");
    assert!(rows.iter().all(|row| row.count == 1));
}

#[tokio::test]
async fn memory_is_bounded_and_what_does_not_fit_is_counted_not_recorded() {
    let mut small = limits();
    small.max_runs = 8;
    small.window = Duration::from_millis(100);
    let h = harness_with(small).await;
    for n in 0..20 {
        h.log.record(&refusal(&format!("cause_{n}")));
    }
    assert_eq!(h.log.dropped(), 12);
    assert_eq!(h.log.recorded(), 8);
    h.log.flush().await;
    assert_eq!(rows(&h.store).await.len(), 8);
    let block = h.log.status_block();
    assert_eq!(block["dropped"], 12);
    assert_eq!(block["pending"], 0);

    // Once the runs are over and written they make room again.
    tokio::time::sleep(Duration::from_millis(150)).await;
    h.log.record(&refusal("late_cause"));
    assert_eq!(h.log.dropped(), 12);
    h.log.flush().await;
    assert_eq!(rows(&h.store).await.len(), 9);
}

#[tokio::test]
async fn recording_never_waits_for_the_store() {
    let store = Arc::new(Store::open_in_memory().await.unwrap());
    let (_stop, rx) = watch::channel(false);
    let backend = Arc::new(Slow {
        store: Arc::clone(&store),
        delay: Duration::from_secs(3),
    });
    let (log, _task) = RefusalLog::spawn(backend, Arc::new(Table), limits(), rx);

    let started = Instant::now();
    for n in 0..1_000 {
        log.record(&refusal("request_rate_exhausted"));
        log.record(&refusal(&format!("cause_{}", n % 50)));
    }
    let spent = started.elapsed();
    assert!(
        spent < Duration::from_millis(500),
        "2,000 refusals took {spent:?} against a store that takes three seconds"
    );
    // Nothing is durable yet, and the log says so.
    assert_eq!(rows(&store).await.len(), 0);
    assert_eq!(log.status_block()["pending"], 2_000);
}

#[tokio::test]
async fn a_store_that_refuses_keeps_the_attempts_and_the_writer_retries() {
    let store = Arc::new(Store::open_in_memory().await.unwrap());
    let (_stop, rx) = watch::channel(false);
    let backend = Arc::new(Flaky {
        store: Arc::clone(&store),
        failures: 2,
        calls: AtomicUsize::new(0),
    });
    let (log, _task) = RefusalLog::spawn(
        Arc::clone(&backend) as Arc<dyn RefusalBackend>,
        Arc::new(Table),
        limits(),
        rx,
    );
    for _ in 0..30 {
        log.record(&refusal("store_overloaded"));
    }
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let found = rows(&store).await;
        if found.first().is_some_and(|row| row.count == 30) {
            break;
        }
        assert!(Instant::now() < deadline, "never written: {found:?}");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(backend.calls.load(Ordering::SeqCst) >= 3);
    assert_eq!(log.status_block()["pending"], 0);
}

#[tokio::test]
async fn the_writer_writes_what_is_left_when_the_daemon_stops() {
    let mut slow = limits();
    slow.flush_delay = Duration::from_secs(30);
    let h = harness_with(slow).await;
    h.log.record(&refusal("daemon_shutting_down"));
    h.log.record(&refusal("daemon_shutting_down"));
    // The batching delay has not elapsed; the stop is what writes.
    h.stop.send(true).unwrap();
    tokio::time::timeout(Duration::from_secs(5), h.task)
        .await
        .expect("the writer ends on stop")
        .unwrap();
    let rows = rows(&h.store).await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].count, 2);
}

#[tokio::test]
async fn a_row_pruned_from_under_a_run_gets_the_rest_of_its_attempts_in_a_new_row() {
    let h = harness().await;
    h.log.record(&refusal("bad_frame"));
    h.log.flush().await;
    h.store.prune_refusals_before(i64::MAX).await.unwrap();
    assert_eq!(rows(&h.store).await.len(), 0);
    for _ in 0..4 {
        h.log.record(&refusal("bad_frame"));
    }
    // The bump finds no row; the next write inserts one for what is left.
    h.log.flush().await;
    let rows = rows(&h.store).await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].count, 4);
    assert_eq!(h.log.status_block()["pending"], 0);
}

#[tokio::test]
async fn what_a_client_claims_is_clipped_before_it_is_held() {
    let h = harness().await;
    let long = "x".repeat(100_000);
    let mut refused = refusal(&long);
    refused.agent = Some(&long);
    refused.repo = Some(&long);
    refused.request_id = Some(&long);
    refused.capability = Some(&long);
    refused.detail = &long;
    h.log.record(&refused);
    h.log.flush().await;
    let row = rows(&h.store).await.remove(0);
    assert_eq!(row.cause.len(), pam_store::MAX_CAUSE_BYTES);
    assert_eq!(row.detail.len(), pam_store::MAX_DETAIL_BYTES);
    assert_eq!(row.agent.unwrap().len(), pam_store::MAX_AGENT_BYTES);
    assert_eq!(
        row.capability.unwrap().len(),
        pam_store::MAX_CAPABILITY_BYTES
    );
}

#[tokio::test]
async fn a_peer_with_no_pid_is_recorded_without_one() {
    let h = harness().await;
    let mut windows = refusal("bad_frame");
    windows.peer = Some(PeerIdentity::OwnerNonce);
    h.log.record(&windows);
    h.log.flush().await;
    let row = rows(&h.store).await.remove(0);
    assert_eq!(
        (row.peer_uid, row.peer_pid, row.peer_exe),
        (None, None, None)
    );
}

#[tokio::test]
async fn a_disabled_log_records_nothing_and_reports_zero() {
    let log = RefusalLog::disabled();
    assert!(!log.is_enabled());
    log.record(&refusal("bad_frame"));
    log.flush().await;
    assert_eq!((log.recorded(), log.dropped()), (0, 0));
    assert_eq!(log.status_block()["pending"], 0);
}

#[test]
fn only_a_refused_handshake_is_a_refusal() {
    use crate::framed::HandshakeError;
    let cause = |error: &HandshakeError| of_handshake(error).map(|(cause, _)| cause);
    assert_eq!(cause(&HandshakeError::LegacyZmtp), Some("legacy_client"));
    assert_eq!(cause(&HandshakeError::Reserved(b'G')), Some("bad_frame"));
    assert_eq!(
        cause(&HandshakeError::Untyped(Vec::new())),
        Some("bad_frame")
    );
    assert_eq!(
        cause(&HandshakeError::BadFrame(
            "frame length 9 is outside 1..=4 bytes".into()
        )),
        Some("bad_frame")
    );
    assert_eq!(
        cause(&HandshakeError::ProtocolMismatch(9)),
        Some("protocol_mismatch")
    );
    assert_eq!(cause(&HandshakeError::Timeout), Some("handshake_timeout"));
    assert_eq!(
        cause(&HandshakeError::Io(
            std::io::ErrorKind::UnexpectedEof.into()
        )),
        None
    );
}
