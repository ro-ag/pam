use std::{
    fs,
    path::PathBuf,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use pam_core::{CallerId, IdempotencyKey, ProjectId, RequestId};
use pam_daemon::{DaemonConfig, request_exchange, request_status, serve_until};
use pam_platform::LocalEndpoint;
use pam_protocol::{
    Event, FailureCode, MAX_FRAME_SIZE, OperationTruth, PROTOCOL_VERSION, RequestEnvelope,
    ResultBody, ResultPayload, SourceAvailability,
};
use tokio::{sync::oneshot, task::JoinHandle};
use zeromq::{DealerSocket, Socket, SocketSend, ZmqMessage};

fn test_runtime(name: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let base = if cfg!(unix) {
        PathBuf::from("/tmp")
    } else {
        std::env::temp_dir()
    };
    base.join(format!(
        "pam-it-{name}-{}-{}",
        std::process::id(),
        nonce % 1_000_000
    ))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn brief_crosses_transport_with_explicit_unavailable_provenance() {
    let runtime = test_runtime("brief-round-trip");
    let endpoint = LocalEndpoint::ipc(runtime.clone());
    let (shutdown, daemon) = start_daemon(endpoint.clone());
    for _ in 0..40 {
        if endpoint.socket_path().is_some_and(std::path::Path::exists) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let request = RequestEnvelope::brief(
        RequestId::from("brief-round-trip"),
        CallerId::from("integration-test"),
        ProjectId::from("project-round-trip"),
        IdempotencyKey::from("brief-round-trip"),
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
        panic!("brief should return a typed result")
    };
    assert_eq!(brief.provenance.len(), 1);
    assert_eq!(
        brief.provenance[0].availability,
        SourceAvailability::Unavailable
    );
    assert_eq!(truth, OperationTruth::Unresolved);

    shutdown.send(()).unwrap();
    daemon.await.unwrap().unwrap();
    let _ = fs::remove_dir_all(runtime);
}

fn status_request() -> RequestEnvelope {
    RequestEnvelope::status(
        RequestId::from("request-round-trip"),
        CallerId::from("integration-test"),
        ProjectId::from("project-round-trip"),
        IdempotencyKey::from("status-round-trip"),
    )
}

fn start_daemon(
    endpoint: LocalEndpoint,
) -> (
    oneshot::Sender<()>,
    JoinHandle<Result<(), pam_daemon::DaemonError>>,
) {
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let state_path = endpoint.runtime_dir().join("state.sqlite3");
    let daemon = tokio::spawn(serve_until(
        DaemonConfig {
            endpoint,
            recover: false,
            state_path: Some(state_path),
            brief_provider: None,
        },
        async {
            let _ = shutdown_rx.await;
        },
    ));
    (shutdown_tx, daemon)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn status_crosses_transport_queue_events_and_result() {
    let runtime = test_runtime("round-trip");
    let endpoint = LocalEndpoint::ipc(runtime.clone());
    let (shutdown, daemon) = start_daemon(endpoint.clone());

    for _ in 0..40 {
        if endpoint.socket_path().is_some_and(std::path::Path::exists) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    let mut malformed_client = DealerSocket::new();
    malformed_client.connect(endpoint.address()).await.unwrap();
    let mut multipart = ZmqMessage::from(vec![1]);
    multipart.push_back(vec![2].into());
    malformed_client.send(multipart).await.unwrap();
    malformed_client
        .send(vec![0; MAX_FRAME_SIZE + 1].into())
        .await
        .unwrap();

    let request = status_request();
    let exchange = request_status(&endpoint, &request, Duration::from_secs(1))
        .await
        .unwrap();

    assert_eq!(exchange.result.request_id, request.request_id);
    assert_eq!(exchange.result.project_id, request.project_id);
    assert_eq!(
        exchange
            .events
            .iter()
            .map(|event| event.sequence)
            .collect::<Vec<_>>(),
        vec![1, 2, 3]
    );
    assert!(exchange.events.iter().all(|event| {
        event.request_id == request.request_id && event.project_id == request.project_id
    }));
    assert_eq!(
        exchange
            .events
            .iter()
            .map(|event| event.event.clone())
            .collect::<Vec<_>>(),
        vec![Event::Accepted, Event::Started, Event::Completed]
    );

    let ResultBody::Success { truth, payload } = exchange.result.body else {
        panic!("status should succeed")
    };
    assert_eq!(truth, OperationTruth::Observed);
    let ResultPayload::Status(status) = payload else {
        panic!("status should return a status payload")
    };
    assert!(status.ready);
    assert!(status.healthy);
    assert_eq!(status.queue_depth, 0);

    let mut future_request = status_request();
    future_request.protocol_version = PROTOCOL_VERSION + 1;
    let future_exchange = request_status(&endpoint, &future_request, Duration::from_secs(1))
        .await
        .unwrap();
    assert!(future_exchange.events.is_empty());
    let ResultBody::Failure(failure) = future_exchange.result.body else {
        panic!("future protocol request should receive a typed failure")
    };
    assert_eq!(failure.code, FailureCode::UnsupportedProtocolVersion);

    shutdown.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(2), daemon)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(endpoint.ownership_path().exists());
    assert!(endpoint.socket_path().is_none_or(|path| !path.exists()));

    let (second_shutdown, second_daemon) = start_daemon(endpoint.clone());
    for _ in 0..40 {
        if endpoint.socket_path().is_some_and(std::path::Path::exists) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    request_status(&endpoint, &status_request(), Duration::from_secs(1))
        .await
        .unwrap();
    second_shutdown.send(()).unwrap();
    second_daemon.await.unwrap().unwrap();
    let _ = fs::remove_dir_all(runtime);
}

#[tokio::test]
async fn unavailable_daemon_returns_recovery_without_auto_start() {
    let runtime = test_runtime("unavailable");
    let endpoint = LocalEndpoint::ipc(runtime.clone());

    let error = request_status(&endpoint, &status_request(), Duration::from_millis(50))
        .await
        .unwrap_err();

    assert!(error.is_unavailable());
    assert_eq!(error.recovery_action(), Some("pam daemon"));
    assert!(!endpoint.ownership_path().exists());
    assert!(!endpoint.socket_path().unwrap().exists());
    let _ = fs::remove_dir_all(runtime);
}
