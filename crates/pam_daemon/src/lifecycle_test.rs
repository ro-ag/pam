use std::{
    fs,
    future::Future,
    path::PathBuf,
    pin::Pin,
    sync::Arc,
    time::{Duration, Instant},
};

use pam_core::{CallerId, ContentDigest, EvidenceHandle, IdempotencyKey, ProjectId, RequestId};
use pam_platform::{ClientTransport, LocalEndpoint};
use pam_protocol::{
    BriefProvenance, BriefResult, CancellationDisposition, Event, EvidenceRedaction,
    EvidenceRetention, FailureCode, MAX_EVIDENCE_CHUNK_SIZE, MAX_FRAME_SIZE, OperationTruth,
    RequestEnvelope, ResultBody, ResultPayload, ServerMessage, SourceAvailability,
    decode_server_message, encode,
};
use pam_store::{
    EvidenceRedaction as StoreEvidenceRedaction, EvidenceRetention as StoreEvidenceRetention,
    PutEvidence, RequestState, Store, StoreError,
};
use tokio::sync::oneshot;

use super::lifecycle::{
    BriefProvider, DaemonConfig, Ownership, prepare_endpoint, serve_until_with_delay,
};
use crate::{DaemonError, request_exchange, request_status};

fn test_runtime(name: &str) -> PathBuf {
    let base = if cfg!(unix) {
        PathBuf::from("/tmp")
    } else {
        std::env::temp_dir()
    };
    base.join(format!("pam-test-{name}-{}", std::process::id()))
}

#[derive(Debug)]
struct PartialBriefProvider;

impl BriefProvider for PartialBriefProvider {
    fn brief<'a>(
        &'a self,
        _project_id: &'a ProjectId,
        _store: &'a Store,
    ) -> Pin<Box<dyn Future<Output = BriefResult> + Send + 'a>> {
        Box::pin(async {
            BriefResult {
                goal: None,
                decisions: Vec::new(),
                verified: Vec::new(),
                next: Vec::new(),
                provenance: vec![BriefProvenance {
                    source: "test-provider".to_owned(),
                    availability: SourceAvailability::Partial,
                    truth: OperationTruth::Unresolved,
                    evidence: None,
                    detail: Some("provider returned bounded partial context".to_owned()),
                }],
            }
        })
    }
}

#[derive(Debug)]
struct NeverBriefProvider;

impl BriefProvider for NeverBriefProvider {
    fn brief<'a>(
        &'a self,
        _project_id: &'a ProjectId,
        _store: &'a Store,
    ) -> Pin<Box<dyn Future<Output = BriefResult> + Send + 'a>> {
        Box::pin(std::future::pending())
    }
}

#[derive(Debug)]
struct OversizedBriefProvider;

impl BriefProvider for OversizedBriefProvider {
    fn brief<'a>(
        &'a self,
        _project_id: &'a ProjectId,
        _store: &'a Store,
    ) -> Pin<Box<dyn Future<Output = BriefResult> + Send + 'a>> {
        Box::pin(async {
            BriefResult {
                goal: None,
                decisions: Vec::new(),
                verified: Vec::new(),
                next: Vec::new(),
                provenance: vec![BriefProvenance {
                    source: "oversized-provider".to_owned(),
                    availability: SourceAvailability::Partial,
                    truth: OperationTruth::Unresolved,
                    evidence: None,
                    detail: Some("x".repeat(MAX_FRAME_SIZE)),
                }],
            }
        })
    }
}

#[test]
fn ownership_rejects_a_second_daemon() {
    let runtime = test_runtime("ownership");
    let _ = fs::remove_dir_all(&runtime);
    let endpoint = LocalEndpoint::ipc(runtime.clone());
    let first = Ownership::acquire(&endpoint).unwrap();

    assert!(matches!(
        Ownership::acquire(&endpoint),
        Err(DaemonError::AlreadyRunning)
    ));

    drop(first);
    let _ = fs::remove_dir_all(runtime);
}

#[test]
fn an_unlocked_persistent_lock_file_is_reclaimed_normally() {
    let runtime = test_runtime("persistent-lock");
    let _ = fs::remove_dir_all(&runtime);
    let endpoint = LocalEndpoint::ipc(runtime.clone());
    fs::create_dir_all(&runtime).unwrap();
    fs::write(endpoint.ownership_path(), b"stopped-daemon\n").unwrap();

    let ownership = Ownership::acquire(&endpoint).unwrap();
    assert_eq!(
        fs::read_to_string(endpoint.ownership_path()).unwrap(),
        format!("{}\n", std::process::id())
    );

    drop(ownership);
    let _ = fs::remove_dir_all(runtime);
}

#[test]
fn stale_socket_reports_recovery_command() {
    let runtime = test_runtime("stale");
    let _ = fs::remove_dir_all(&runtime);
    fs::create_dir_all(&runtime).unwrap();
    let endpoint = LocalEndpoint::ipc(runtime.clone());
    fs::write(endpoint.socket_path().unwrap(), b"stale").unwrap();

    let error = prepare_endpoint(&DaemonConfig {
        endpoint,
        recover: false,
        state_path: Some(runtime.join("state.sqlite3")),
        brief_provider: None,
    })
    .unwrap_err();
    assert!(matches!(error, DaemonError::StaleState(_)));
    assert_eq!(error.recovery_action(), Some("pam daemon --recover"));

    let _ = fs::remove_dir_all(runtime);
}

fn request(project: &str, suffix: &str) -> RequestEnvelope {
    RequestEnvelope::status(
        RequestId::new(format!("request-{suffix}")),
        CallerId::from("queue-test"),
        ProjectId::new(project),
        IdempotencyKey::new(format!("status-{suffix}")),
    )
}

async fn wait_until_ready(endpoint: &LocalEndpoint) {
    for _ in 0..50 {
        if endpoint.socket_path().is_some_and(std::path::Path::exists) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("daemon did not create its endpoint")
}

fn start_daemon(
    endpoint: LocalEndpoint,
    state_path: PathBuf,
    delay: Duration,
) -> (
    oneshot::Sender<()>,
    tokio::task::JoinHandle<Result<(), DaemonError>>,
) {
    start_daemon_with_provider(endpoint, state_path, delay, None)
}

fn start_daemon_with_provider(
    endpoint: LocalEndpoint,
    state_path: PathBuf,
    delay: Duration,
    brief_provider: Option<Arc<dyn BriefProvider>>,
) -> (
    oneshot::Sender<()>,
    tokio::task::JoinHandle<Result<(), DaemonError>>,
) {
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let daemon = tokio::spawn(serve_until_with_delay(
        DaemonConfig {
            endpoint,
            recover: false,
            state_path: Some(state_path),
            brief_provider,
        },
        async {
            let _ = shutdown_rx.await;
        },
        delay,
    ));
    (shutdown_tx, daemon)
}

async fn wait_for_state(store: &Store, request_id: &RequestId, expected: RequestState) {
    for _ in 0..100 {
        if store
            .snapshot(request_id.clone())
            .await
            .is_ok_and(|snapshot| snapshot.state == expected)
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("request {request_id} did not reach {expected:?}")
}

async fn request_once(endpoint: &LocalEndpoint, request: &RequestEnvelope) -> Vec<ServerMessage> {
    let mut client = ClientTransport::connect(endpoint, Duration::from_secs(1))
        .await
        .unwrap();
    client.send(encode(request).unwrap()).await.unwrap();
    let mut messages = Vec::new();
    loop {
        let message =
            decode_server_message(&client.receive(Duration::from_secs(2)).await.unwrap()).unwrap();
        let terminal = matches!(message, ServerMessage::Result(_));
        messages.push(message);
        if terminal {
            return messages;
        }
    }
}

async fn assert_status_healthy(endpoint: &LocalEndpoint, suffix: &str) {
    let exchange = request_status(
        endpoint,
        &request("health-project", suffix),
        Duration::from_secs(1),
    )
    .await
    .unwrap();
    assert!(matches!(exchange.result.body, ResultBody::Success { .. }));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn brief_baseline_is_honest_read_only_and_provider_neutral() {
    let runtime = test_runtime("brief-baseline");
    let _ = fs::remove_dir_all(&runtime);
    let endpoint = LocalEndpoint::ipc(runtime.clone());
    let state_path = runtime.join("state.sqlite3");
    let (shutdown, daemon) = start_daemon(endpoint.clone(), state_path.clone(), Duration::ZERO);
    wait_until_ready(&endpoint).await;
    let request = RequestEnvelope::brief(
        RequestId::from("brief-observer"),
        CallerId::from("brief-test"),
        ProjectId::from("brief-project"),
        IdempotencyKey::from("brief-read"),
    );

    let exchange = request_exchange(&endpoint, &request, Duration::from_secs(1))
        .await
        .unwrap();
    assert!(exchange.events.is_empty());
    let ResultBody::Success {
        truth,
        payload: ResultPayload::Brief(brief),
    } = exchange.result.body
    else {
        panic!("brief should return a typed success")
    };
    assert_eq!(truth, OperationTruth::Unresolved);
    assert_eq!(
        brief,
        BriefResult {
            goal: None,
            decisions: Vec::new(),
            verified: Vec::new(),
            next: Vec::new(),
            provenance: vec![BriefProvenance {
                source: "planning-context".to_owned(),
                availability: SourceAvailability::Unavailable,
                truth: OperationTruth::Unresolved,
                evidence: None,
                detail: Some("No planning-context provider is configured.".to_owned()),
            }],
        }
    );
    let observer = Store::open(&state_path).unwrap();
    assert!(matches!(
        observer.snapshot(request.request_id).await,
        Err(StoreError::RequestNotFound(_))
    ));
    observer.shutdown().await.unwrap();

    shutdown.send(()).unwrap();
    daemon.await.unwrap().unwrap();
    let _ = fs::remove_dir_all(runtime);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn brief_provider_can_report_partial_source_failure_explicitly() {
    let runtime = test_runtime("brief-partial");
    let _ = fs::remove_dir_all(&runtime);
    let endpoint = LocalEndpoint::ipc(runtime.clone());
    let (shutdown, daemon) = start_daemon_with_provider(
        endpoint.clone(),
        runtime.join("state.sqlite3"),
        Duration::ZERO,
        Some(Arc::new(PartialBriefProvider)),
    );
    wait_until_ready(&endpoint).await;
    let request = RequestEnvelope::brief(
        RequestId::from("partial-brief-observer"),
        CallerId::from("brief-test"),
        ProjectId::from("brief-project"),
        IdempotencyKey::from("partial-brief"),
    );

    let exchange = request_exchange(&endpoint, &request, Duration::from_secs(1))
        .await
        .unwrap();
    let ResultBody::Success {
        truth,
        payload: ResultPayload::Brief(brief),
    } = exchange.result.body
    else {
        panic!("brief should return provider context")
    };
    assert_eq!(brief.provenance.len(), 1);
    assert_eq!(
        brief.provenance[0].availability,
        SourceAvailability::Partial
    );
    assert_eq!(brief.provenance[0].truth, OperationTruth::Unresolved);
    assert!(brief.provenance[0].detail.is_some());
    assert_eq!(truth, OperationTruth::Unresolved);

    shutdown.send(()).unwrap();
    daemon.await.unwrap().unwrap();
    let _ = fs::remove_dir_all(runtime);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn client_deadline_is_not_reported_as_daemon_unavailable() {
    let runtime = test_runtime("client-deadline");
    let _ = fs::remove_dir_all(&runtime);
    let endpoint = LocalEndpoint::ipc(runtime.clone());
    let (shutdown, daemon) = start_daemon_with_provider(
        endpoint.clone(),
        runtime.join("state.sqlite3"),
        Duration::ZERO,
        Some(Arc::new(NeverBriefProvider)),
    );
    wait_until_ready(&endpoint).await;
    let request = RequestEnvelope::brief(
        RequestId::from("deadline-observer"),
        CallerId::from("brief-test"),
        ProjectId::from("brief-project"),
        IdempotencyKey::from("deadline-brief"),
    );

    let error = request_exchange(&endpoint, &request, Duration::from_millis(100))
        .await
        .unwrap_err();
    assert!(matches!(error, crate::ExchangeError::DeadlineExceeded));
    assert!(!error.is_unavailable());
    assert_eq!(error.recovery_action(), None);

    shutdown.send(()).unwrap();
    daemon.await.unwrap().unwrap();
    let _ = fs::remove_dir_all(runtime);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn oversized_brief_provider_result_isolated_and_daemon_stays_healthy() {
    let runtime = test_runtime("oversized-brief");
    let _ = fs::remove_dir_all(&runtime);
    let endpoint = LocalEndpoint::ipc(runtime.clone());
    let (shutdown, daemon) = start_daemon_with_provider(
        endpoint.clone(),
        runtime.join("state.sqlite3"),
        Duration::ZERO,
        Some(Arc::new(OversizedBriefProvider)),
    );
    wait_until_ready(&endpoint).await;
    let request = RequestEnvelope::brief(
        RequestId::from("oversized-brief-observer"),
        CallerId::from("brief-test"),
        ProjectId::from("brief-project"),
        IdempotencyKey::from("oversized-brief"),
    );

    let exchange = request_exchange(&endpoint, &request, Duration::from_secs(1))
        .await
        .unwrap();
    let ResultBody::Failure(failure) = exchange.result.body else {
        panic!("oversized provider output should fail")
    };
    assert_eq!(failure.code, FailureCode::FrameTooLarge);
    assert_status_healthy(&endpoint, "after-oversized-brief").await;

    shutdown.send(()).unwrap();
    daemon.await.unwrap().unwrap();
    let _ = fs::remove_dir_all(runtime);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn wait_resumes_live_and_terminal_work_with_split_correlation() {
    let runtime = test_runtime("wait-result");
    let _ = fs::remove_dir_all(&runtime);
    let endpoint = LocalEndpoint::ipc(runtime.clone());
    let state_path = runtime.join("state.sqlite3");
    let target = request("wait-project", "wait-target");
    let (shutdown, daemon) = start_daemon(
        endpoint.clone(),
        state_path.clone(),
        Duration::from_millis(400),
    );
    wait_until_ready(&endpoint).await;

    let target_observer = tokio::spawn({
        let endpoint = endpoint.clone();
        let target = target.clone();
        async move { request_status(&endpoint, &target, Duration::from_secs(2)).await }
    });
    let observer = Store::open(&state_path).unwrap();
    wait_for_state(&observer, &target.request_id, RequestState::Leased).await;

    let pending_request = RequestEnvelope::get_result(
        RequestId::from("pending-observer"),
        target.caller_id.clone(),
        target.project_id.clone(),
        IdempotencyKey::from("pending-result"),
        target.request_id.clone(),
    );
    let pending = request_exchange(&endpoint, &pending_request, Duration::from_secs(1))
        .await
        .unwrap();
    let ResultBody::Failure(pending_failure) = pending.result.body else {
        panic!("running target should be pending")
    };
    assert_eq!(pending_failure.code, FailureCode::Pending);

    let wait_request = RequestEnvelope::wait_for_result(
        RequestId::from("live-wait-observer"),
        target.caller_id.clone(),
        target.project_id.clone(),
        IdempotencyKey::from("live-wait"),
        target.request_id.clone(),
        1,
    );
    let live = request_exchange(&endpoint, &wait_request, Duration::from_secs(2))
        .await
        .unwrap();
    let target_exchange = target_observer.await.unwrap().unwrap();
    assert_eq!(
        live.events
            .iter()
            .map(|event| event.sequence)
            .collect::<Vec<_>>(),
        vec![2, 3]
    );
    assert!(
        live.events
            .iter()
            .all(|event| event.request_id == target.request_id)
    );
    assert_eq!(live.result.request_id, wait_request.request_id);
    assert_eq!(live.result.body, target_exchange.result.body);

    assert_terminal_reads(&endpoint, &target, &target_exchange.result.body).await;
    assert!(matches!(
        observer.snapshot(wait_request.request_id).await,
        Err(StoreError::RequestNotFound(_))
    ));

    observer.shutdown().await.unwrap();
    shutdown.send(()).unwrap();
    daemon.await.unwrap().unwrap();
    let _ = fs::remove_dir_all(runtime);
}

async fn assert_terminal_reads(
    endpoint: &LocalEndpoint,
    target: &RequestEnvelope,
    target_body: &ResultBody,
) {
    let resumed_request = RequestEnvelope::wait_for_result(
        RequestId::from("terminal-wait-observer"),
        target.caller_id.clone(),
        target.project_id.clone(),
        IdempotencyKey::from("terminal-wait"),
        target.request_id.clone(),
        2,
    );
    let resumed = request_exchange(endpoint, &resumed_request, Duration::from_secs(1))
        .await
        .unwrap();
    assert_eq!(resumed.events.len(), 1);
    assert_eq!(resumed.events[0].sequence, 3);
    assert_eq!(resumed.events[0].request_id, target.request_id);
    assert_eq!(resumed.result.request_id, resumed_request.request_id);
    assert_eq!(&resumed.result.body, target_body);

    let result_request = RequestEnvelope::get_result(
        RequestId::from("terminal-result-observer"),
        target.caller_id.clone(),
        target.project_id.clone(),
        IdempotencyKey::from("terminal-result"),
        target.request_id.clone(),
    );
    let terminal = request_exchange(endpoint, &result_request, Duration::from_secs(1))
        .await
        .unwrap();
    assert!(terminal.events.is_empty());
    assert_eq!(terminal.result.request_id, result_request.request_id);
    assert_eq!(&terminal.result.body, target_body);

    let wrong_project = RequestEnvelope::get_result(
        RequestId::from("wrong-project-observer"),
        target.caller_id.clone(),
        ProjectId::from("other-project"),
        IdempotencyKey::from("wrong-project-result"),
        target.request_id.clone(),
    );
    let hidden = request_exchange(endpoint, &wrong_project, Duration::from_secs(1))
        .await
        .unwrap();
    let ResultBody::Failure(hidden_failure) = hidden.result.body else {
        panic!("cross-project target should be hidden")
    };
    assert_eq!(hidden_failure.code, FailureCode::NotFound);

    let wrong_wait = RequestEnvelope::wait_for_result(
        RequestId::from("wrong-project-wait"),
        target.caller_id.clone(),
        ProjectId::from("other-project"),
        IdempotencyKey::from("wrong-project-wait"),
        target.request_id.clone(),
        0,
    );
    let hidden_wait = request_exchange(endpoint, &wrong_wait, Duration::from_secs(1))
        .await
        .unwrap();
    let ResultBody::Failure(hidden_wait_failure) = hidden_wait.result.body else {
        panic!("cross-project wait target should be hidden")
    };
    assert_eq!(hidden_wait_failure.code, FailureCode::NotFound);

    let missing = RequestEnvelope::get_result(
        RequestId::from("missing-observer"),
        target.caller_id.clone(),
        target.project_id.clone(),
        IdempotencyKey::from("missing-result"),
        RequestId::from("missing-target"),
    );
    let missing_exchange = request_exchange(endpoint, &missing, Duration::from_secs(1))
        .await
        .unwrap();
    let ResultBody::Failure(missing_failure) = missing_exchange.result.body else {
        panic!("missing target should fail")
    };
    assert_eq!(missing_failure.code, FailureCode::NotFound);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dropping_wait_observer_does_not_cancel_target_work() {
    let runtime = test_runtime("wait-disconnect");
    let _ = fs::remove_dir_all(&runtime);
    let endpoint = LocalEndpoint::ipc(runtime.clone());
    let state_path = runtime.join("state.sqlite3");
    let target = request("disconnect-project", "disconnect-target");
    let (shutdown, daemon) = start_daemon(
        endpoint.clone(),
        state_path.clone(),
        Duration::from_millis(250),
    );
    wait_until_ready(&endpoint).await;
    let target_observer = tokio::spawn({
        let endpoint = endpoint.clone();
        let target = target.clone();
        async move { request_status(&endpoint, &target, Duration::from_secs(2)).await }
    });
    let observer = Store::open(&state_path).unwrap();
    wait_for_state(&observer, &target.request_id, RequestState::Leased).await;
    let wait_request = RequestEnvelope::wait_for_result(
        RequestId::from("abandoned-wait"),
        target.caller_id.clone(),
        target.project_id.clone(),
        IdempotencyKey::from("abandoned-wait"),
        target.request_id.clone(),
        0,
    );
    let mut client = ClientTransport::connect(&endpoint, Duration::from_secs(1))
        .await
        .unwrap();
    client.send(encode(&wait_request).unwrap()).await.unwrap();
    drop(client);

    let completed = target_observer.await.unwrap().unwrap();
    assert!(matches!(completed.result.body, ResultBody::Success { .. }));
    wait_for_state(&observer, &target.request_id, RequestState::Succeeded).await;

    observer.shutdown().await.unwrap();
    shutdown.send(()).unwrap();
    daemon.await.unwrap().unwrap();
    let _ = fs::remove_dir_all(runtime);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn evidence_inspection_and_chunk_reads_are_bounded_and_project_scoped() {
    let runtime = test_runtime("evidence-read");
    let _ = fs::remove_dir_all(&runtime);
    let endpoint = LocalEndpoint::ipc(runtime.clone());
    let state_path = runtime.join("state.sqlite3");
    let project_id = ProjectId::from("evidence-project");
    let handle = EvidenceHandle::parse("evidence://ci/1842/failure").unwrap();
    let bytes = (0..(MAX_EVIDENCE_CHUNK_SIZE + 17))
        .map(|index| u8::try_from(index % 251).unwrap())
        .collect::<Vec<_>>();
    let seed = Store::open(&state_path).unwrap();
    let stored = seed
        .put_evidence(
            PutEvidence {
                handle: handle.clone(),
                project_id: project_id.clone(),
                media_type: "application/octet-stream".to_owned(),
                retention: StoreEvidenceRetention::Project,
                redaction: StoreEvidenceRedaction::Unredacted,
                bytes: bytes.clone(),
            },
            1,
        )
        .await
        .unwrap();
    seed.shutdown().await.unwrap();
    let (shutdown, daemon) = start_daemon(endpoint.clone(), state_path.clone(), Duration::ZERO);
    wait_until_ready(&endpoint).await;

    let inspect_id =
        assert_evidence_metadata(&endpoint, &project_id, &handle, &stored.digest, bytes.len())
            .await;
    assert_evidence_chunks(&endpoint, &project_id, &handle, &bytes).await;
    assert_evidence_failures(&endpoint, project_id, handle, bytes.len()).await;
    let observer = Store::open(&state_path).unwrap();
    assert!(matches!(
        observer.snapshot(inspect_id).await,
        Err(StoreError::RequestNotFound(_))
    ));
    observer.shutdown().await.unwrap();

    shutdown.send(()).unwrap();
    daemon.await.unwrap().unwrap();
    let _ = fs::remove_dir_all(runtime);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn oversized_evidence_observer_is_rejected_and_daemon_stays_healthy() {
    let runtime = test_runtime("oversized-evidence-observer");
    let _ = fs::remove_dir_all(&runtime);
    let endpoint = LocalEndpoint::ipc(runtime.clone());
    let state_path = runtime.join("state.sqlite3");
    let project_id = ProjectId::from("evidence-project");
    let handle = EvidenceHandle::parse("evidence://ci/oversized/observer").unwrap();
    let seed = Store::open(&state_path).unwrap();
    seed.put_evidence(
        PutEvidence {
            handle: handle.clone(),
            project_id: project_id.clone(),
            media_type: "application/octet-stream".to_owned(),
            retention: StoreEvidenceRetention::Project,
            redaction: StoreEvidenceRedaction::Unredacted,
            bytes: vec![7; MAX_EVIDENCE_CHUNK_SIZE],
        },
        1,
    )
    .await
    .unwrap();
    seed.shutdown().await.unwrap();
    let (shutdown, daemon) = start_daemon(endpoint.clone(), state_path, Duration::ZERO);
    wait_until_ready(&endpoint).await;
    let oversized = RequestEnvelope::read_evidence(
        RequestId::new("r".repeat(800 * 1024)),
        CallerId::from("evidence-test"),
        project_id,
        IdempotencyKey::from("oversized-observer"),
        handle,
        0,
        MAX_EVIDENCE_CHUNK_SIZE as u64,
    )
    .unwrap();

    let exchange = request_exchange(&endpoint, &oversized, Duration::from_secs(2))
        .await
        .unwrap();
    let ResultBody::Failure(failure) = exchange.result.body else {
        panic!("oversized observer identifier should fail")
    };
    assert_eq!(failure.code, FailureCode::InvalidRequest);
    assert_status_healthy(&endpoint, "after-oversized-evidence").await;

    shutdown.send(()).unwrap();
    daemon.await.unwrap().unwrap();
    let _ = fs::remove_dir_all(runtime);
}

async fn assert_evidence_metadata(
    endpoint: &LocalEndpoint,
    project_id: &ProjectId,
    handle: &EvidenceHandle,
    digest: &ContentDigest,
    size_bytes: usize,
) -> RequestId {
    let request = RequestEnvelope::inspect_evidence(
        RequestId::from("inspect-observer"),
        CallerId::from("evidence-test"),
        project_id.clone(),
        IdempotencyKey::from("inspect-evidence"),
        handle.clone(),
    );
    let inspected = request_exchange(endpoint, &request, Duration::from_secs(1))
        .await
        .unwrap();
    let ResultBody::Success {
        truth: OperationTruth::Observed,
        payload: ResultPayload::EvidenceMetadata(metadata),
    } = inspected.result.body
    else {
        panic!("inspect should return evidence metadata")
    };
    assert_eq!(&metadata.handle, handle);
    assert_eq!(&metadata.digest, digest);
    assert_eq!(metadata.size_bytes, size_bytes as u64);
    assert_eq!(metadata.retention, EvidenceRetention::Project);
    assert_eq!(metadata.redaction, EvidenceRedaction::Unredacted);
    request.request_id
}

async fn assert_evidence_chunks(
    endpoint: &LocalEndpoint,
    project_id: &ProjectId,
    handle: &EvidenceHandle,
    bytes: &[u8],
) {
    let first_read = RequestEnvelope::read_evidence(
        RequestId::from("read-first-observer"),
        CallerId::from("evidence-test"),
        project_id.clone(),
        IdempotencyKey::from("read-first"),
        handle.clone(),
        0,
        MAX_EVIDENCE_CHUNK_SIZE as u64,
    )
    .unwrap();
    let first = request_exchange(endpoint, &first_read, Duration::from_secs(1))
        .await
        .unwrap();
    let ResultBody::Success {
        payload: ResultPayload::EvidenceChunk(first_chunk),
        ..
    } = first.result.body
    else {
        panic!("read should return an evidence chunk")
    };
    assert_eq!(first_chunk.offset, 0);
    assert!(!first_chunk.eof);
    assert_eq!(first_chunk.bytes(), &bytes[..MAX_EVIDENCE_CHUNK_SIZE]);

    let final_read = RequestEnvelope::read_evidence(
        RequestId::from("read-final-observer"),
        CallerId::from("evidence-test"),
        project_id.clone(),
        IdempotencyKey::from("read-final"),
        handle.clone(),
        MAX_EVIDENCE_CHUNK_SIZE as u64,
        17,
    )
    .unwrap();
    let final_exchange = request_exchange(endpoint, &final_read, Duration::from_secs(1))
        .await
        .unwrap();
    let ResultBody::Success {
        payload: ResultPayload::EvidenceChunk(final_chunk),
        ..
    } = final_exchange.result.body
    else {
        panic!("final read should return an evidence chunk")
    };
    assert!(final_chunk.eof);
    assert_eq!(final_chunk.bytes(), &bytes[MAX_EVIDENCE_CHUNK_SIZE..]);
}

async fn assert_evidence_failures(
    endpoint: &LocalEndpoint,
    project_id: ProjectId,
    handle: EvidenceHandle,
    size_bytes: usize,
) {
    let wrong_project = RequestEnvelope::inspect_evidence(
        RequestId::from("inspect-wrong-project"),
        CallerId::from("evidence-test"),
        ProjectId::from("other-project"),
        IdempotencyKey::from("inspect-wrong-project"),
        handle.clone(),
    );
    let hidden = request_exchange(endpoint, &wrong_project, Duration::from_secs(1))
        .await
        .unwrap();
    let ResultBody::Failure(hidden_failure) = hidden.result.body else {
        panic!("wrong-project evidence should be hidden")
    };
    assert_eq!(hidden_failure.code, FailureCode::NotFound);

    let wrong_read = RequestEnvelope::read_evidence(
        RequestId::from("read-wrong-project"),
        CallerId::from("evidence-test"),
        ProjectId::from("other-project"),
        IdempotencyKey::from("read-wrong-project"),
        handle.clone(),
        0,
        1,
    )
    .unwrap();
    let hidden_read = request_exchange(endpoint, &wrong_read, Duration::from_secs(1))
        .await
        .unwrap();
    let ResultBody::Failure(hidden_read_failure) = hidden_read.result.body else {
        panic!("wrong-project evidence read should be hidden")
    };
    assert_eq!(hidden_read_failure.code, FailureCode::NotFound);

    let invalid_range = RequestEnvelope::read_evidence(
        RequestId::from("read-invalid-range"),
        CallerId::from("evidence-test"),
        project_id,
        IdempotencyKey::from("read-invalid-range"),
        handle,
        size_bytes as u64 + 1,
        1,
    )
    .unwrap();
    let invalid = request_exchange(endpoint, &invalid_range, Duration::from_secs(1))
        .await
        .unwrap();
    let ResultBody::Failure(range_failure) = invalid.result.body else {
        panic!("out-of-bounds evidence range should fail")
    };
    assert_eq!(range_failure.code, FailureCode::InvalidRequest);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn daemon_parallelizes_projects_but_serializes_each_project() {
    let runtime = test_runtime("concurrency");
    let _ = fs::remove_dir_all(&runtime);
    let endpoint = LocalEndpoint::ipc(runtime.clone());
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let delay = Duration::from_millis(300);
    let daemon = tokio::spawn(serve_until_with_delay(
        DaemonConfig {
            endpoint: endpoint.clone(),
            recover: false,
            state_path: Some(runtime.join("state.sqlite3")),
            brief_provider: None,
        },
        async {
            let _ = shutdown_rx.await;
        },
        delay,
    ));
    wait_until_ready(&endpoint).await;

    let different_a = request("project-a", "different-a");
    let different_b = request("project-b", "different-b");
    let different_started = Instant::now();
    let different = tokio::join!(
        request_status(&endpoint, &different_a, Duration::from_secs(3)),
        request_status(&endpoint, &different_b, Duration::from_secs(3))
    );
    assert!(different.0.is_ok());
    assert!(different.1.is_ok());
    let different_elapsed = different_started.elapsed();

    let same_a = request("project-c", "same-a");
    let same_b = request("project-c", "same-b");
    let same_started = Instant::now();
    let same = tokio::join!(
        request_status(&endpoint, &same_a, Duration::from_secs(3)),
        request_status(&endpoint, &same_b, Duration::from_secs(3))
    );
    let first_same_project = same.0.unwrap();
    let second_same_project = same.1.unwrap();
    let mut queue_depths = [
        status_queue_depth(&first_same_project),
        status_queue_depth(&second_same_project),
    ];
    queue_depths.sort_unstable();
    assert_eq!(queue_depths, [0, 1]);
    let same_elapsed = same_started.elapsed();

    assert!(
        same_elapsed >= different_elapsed + Duration::from_millis(150),
        "same-project elapsed {same_elapsed:?}, different-project elapsed {different_elapsed:?}"
    );

    let abandoned = request("project-abandoned", "abandoned");
    let mut abandoned_client = ClientTransport::connect(&endpoint, Duration::from_secs(1))
        .await
        .unwrap();
    abandoned_client
        .send(encode(&abandoned).unwrap())
        .await
        .unwrap();
    drop(abandoned_client);
    tokio::time::sleep(delay + Duration::from_millis(50)).await;
    assert!(
        request_status(
            &endpoint,
            &request("project-after-disconnect", "after-disconnect"),
            Duration::from_secs(2)
        )
        .await
        .is_ok()
    );

    shutdown_tx.send(()).unwrap();
    daemon.await.unwrap().unwrap();
    let _ = fs::remove_dir_all(runtime);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn accepted_work_survives_restart_and_replays_the_original_result() {
    let runtime = test_runtime("durable-restart");
    let _ = fs::remove_dir_all(&runtime);
    let endpoint = LocalEndpoint::ipc(runtime.clone());
    let state_path = runtime.join("state.sqlite3");
    let durable_request = request("project-durable", "durable");
    let (shutdown, daemon) =
        start_daemon(endpoint.clone(), state_path.clone(), Duration::from_secs(5));
    wait_until_ready(&endpoint).await;

    let pending = tokio::spawn({
        let endpoint = endpoint.clone();
        let request = durable_request.clone();
        async move { request_status(&endpoint, &request, Duration::from_secs(10)).await }
    });
    let observer = Store::open(&state_path).unwrap();
    wait_for_state(&observer, &durable_request.request_id, RequestState::Leased).await;
    shutdown.send(()).unwrap();
    daemon.await.unwrap().unwrap();
    pending.abort();
    let _ = pending.await;
    observer.shutdown().await.unwrap();

    let (second_shutdown, second_daemon) =
        start_daemon(endpoint.clone(), state_path, Duration::ZERO);
    wait_until_ready(&endpoint).await;
    let exchange = request_status(&endpoint, &durable_request, Duration::from_secs(2))
        .await
        .unwrap();
    assert_eq!(
        exchange
            .events
            .iter()
            .map(|event| event.event.clone())
            .collect::<Vec<_>>(),
        vec![
            Event::Accepted,
            Event::Started,
            Event::LeaseExpired,
            Event::Started,
            Event::Completed,
        ]
    );
    assert!(matches!(exchange.result.body, ResultBody::Success { .. }));

    second_shutdown.send(()).unwrap();
    second_daemon.await.unwrap().unwrap();
    let _ = fs::remove_dir_all(runtime);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cancelling_running_work_is_terminal_and_notifies_the_original_observer() {
    let runtime = test_runtime("durable-cancel");
    let _ = fs::remove_dir_all(&runtime);
    let endpoint = LocalEndpoint::ipc(runtime.clone());
    let state_path = runtime.join("state.sqlite3");
    let target = request("project-cancel", "target");
    let (shutdown, daemon) =
        start_daemon(endpoint.clone(), state_path.clone(), Duration::from_secs(5));
    wait_until_ready(&endpoint).await;

    let target_exchange = tokio::spawn({
        let endpoint = endpoint.clone();
        let target = target.clone();
        async move { request_status(&endpoint, &target, Duration::from_secs(3)).await }
    });
    let observer = Store::open(&state_path).unwrap();
    wait_for_state(&observer, &target.request_id, RequestState::Leased).await;
    let cancellation = RequestEnvelope::cancel(
        RequestId::from("cancel-observer"),
        target.caller_id.clone(),
        target.project_id.clone(),
        IdempotencyKey::from("cancel-target"),
        target.request_id.clone(),
    );
    let cancellation_messages = request_once(&endpoint, &cancellation).await;
    let ServerMessage::Result(cancellation_result) = cancellation_messages.last().unwrap() else {
        panic!("cancellation should return a result")
    };
    let ResultBody::Success {
        payload: ResultPayload::Cancellation(result),
        ..
    } = &cancellation_result.body
    else {
        panic!("cancellation should return a typed success")
    };
    assert_eq!(result.disposition, CancellationDisposition::Requested);

    let exchange = target_exchange.await.unwrap().unwrap();
    assert_eq!(
        exchange
            .events
            .iter()
            .map(|event| event.event.clone())
            .collect::<Vec<_>>(),
        vec![
            Event::Accepted,
            Event::Started,
            Event::CancellationRequested,
            Event::Cancelled,
        ]
    );
    let ResultBody::Failure(failure) = exchange.result.body else {
        panic!("cancelled target should return failure truth")
    };
    assert_eq!(failure.code, FailureCode::Cancelled);

    observer.shutdown().await.unwrap();
    shutdown.send(()).unwrap();
    daemon.await.unwrap().unwrap();
    let _ = fs::remove_dir_all(runtime);
}

fn status_queue_depth(exchange: &crate::StatusExchange) -> u64 {
    let ResultBody::Success {
        payload: ResultPayload::Status(status),
        ..
    } = &exchange.result.body
    else {
        panic!("status request should return a status result")
    };
    status.queue_depth
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn idempotent_retry_keeps_both_observers_correlated_without_duplicate_events() {
    let runtime = test_runtime("durable-observers");
    let _ = fs::remove_dir_all(&runtime);
    let endpoint = LocalEndpoint::ipc(runtime.clone());
    let state_path = runtime.join("state.sqlite3");
    let first = request("project-observers", "first");
    let mut retry = request("project-observers", "retry");
    retry.idempotency_key = first.idempotency_key.clone();
    let (shutdown, daemon) = start_daemon(
        endpoint.clone(),
        state_path.clone(),
        Duration::from_millis(300),
    );
    wait_until_ready(&endpoint).await;

    let first_observer = tokio::spawn({
        let endpoint = endpoint.clone();
        let first = first.clone();
        async move { request_status(&endpoint, &first, Duration::from_secs(2)).await }
    });
    let observer = Store::open(&state_path).unwrap();
    wait_for_state(&observer, &first.request_id, RequestState::Leased).await;
    let retry_observer = tokio::spawn({
        let endpoint = endpoint.clone();
        let retry = retry.clone();
        async move { request_status(&endpoint, &retry, Duration::from_secs(2)).await }
    });

    let first_exchange = first_observer.await.unwrap().unwrap();
    let retry_exchange = retry_observer.await.unwrap().unwrap();
    assert_eq!(first_exchange.result.request_id, first.request_id);
    assert_eq!(retry_exchange.result.request_id, retry.request_id);
    for exchange in [&first_exchange, &retry_exchange] {
        assert_eq!(
            exchange
                .events
                .iter()
                .map(|event| event.sequence)
                .collect::<Vec<_>>(),
            vec![1, 2, 3]
        );
    }

    observer.shutdown().await.unwrap();
    shutdown.send(()).unwrap();
    daemon.await.unwrap().unwrap();
    let _ = fs::remove_dir_all(runtime);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn invalid_replay_cursor_is_correlated_and_does_not_stop_the_daemon() {
    let runtime = test_runtime("invalid-replay");
    let _ = fs::remove_dir_all(&runtime);
    let endpoint = LocalEndpoint::ipc(runtime.clone());
    let (shutdown, daemon) = start_daemon(
        endpoint.clone(),
        runtime.join("state.sqlite3"),
        Duration::ZERO,
    );
    wait_until_ready(&endpoint).await;
    let status = request("project-replay", "status");
    let replay = RequestEnvelope::replay(
        RequestId::from("replay-observer"),
        status.caller_id.clone(),
        status.project_id.clone(),
        IdempotencyKey::from("invalid-replay"),
        status.request_id.clone(),
        u64::MAX,
    );

    let messages = request_once(&endpoint, &replay).await;
    let ServerMessage::Result(result) = messages.last().unwrap() else {
        panic!("invalid replay should return a result")
    };
    let ResultBody::Failure(failure) = &result.body else {
        panic!("invalid replay should return a typed failure")
    };
    assert_eq!(failure.code, FailureCode::InvalidRequest);
    let invalid_wait = RequestEnvelope::wait_for_result(
        RequestId::from("invalid-wait-observer"),
        status.caller_id.clone(),
        status.project_id.clone(),
        IdempotencyKey::from("invalid-wait"),
        status.request_id.clone(),
        u64::MAX,
    );
    let wait_messages = request_once(&endpoint, &invalid_wait).await;
    let ServerMessage::Result(wait_result) = wait_messages.last().unwrap() else {
        panic!("invalid wait should return a result")
    };
    let ResultBody::Failure(wait_failure) = &wait_result.body else {
        panic!("invalid wait should return a typed failure")
    };
    assert_eq!(wait_failure.code, FailureCode::InvalidRequest);
    assert!(
        request_status(&endpoint, &status, Duration::from_secs(1))
            .await
            .is_ok()
    );

    shutdown.send(()).unwrap();
    daemon.await.unwrap().unwrap();
    let _ = fs::remove_dir_all(runtime);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn long_running_work_renews_its_lease_without_duplicate_execution() {
    let runtime = test_runtime("lease-heartbeat");
    let _ = fs::remove_dir_all(&runtime);
    let endpoint = LocalEndpoint::ipc(runtime.clone());
    let (shutdown, daemon) = start_daemon(
        endpoint.clone(),
        runtime.join("state.sqlite3"),
        Duration::from_millis(3_500),
    );
    wait_until_ready(&endpoint).await;

    let exchange = request_status(
        &endpoint,
        &request("project-heartbeat", "long"),
        Duration::from_secs(5),
    )
    .await
    .unwrap();
    assert_eq!(
        exchange
            .events
            .iter()
            .map(|event| event.event.clone())
            .collect::<Vec<_>>(),
        vec![Event::Accepted, Event::Started, Event::Completed]
    );

    shutdown.send(()).unwrap();
    daemon.await.unwrap().unwrap();
    let _ = fs::remove_dir_all(runtime);
}
