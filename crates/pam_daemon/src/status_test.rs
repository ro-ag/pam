use std::{
    future::pending,
    sync::atomic::{AtomicU64, Ordering},
};

use pam_core::{CallerId, IdempotencyKey, ProjectId, RequestId};
use pam_platform::{LocalEndpoint, ServerTransport};
use pam_protocol::{
    Event, EventEnvelope, Failure, FailureCode, PROTOCOL_VERSION, RequestEnvelope, ResultBody,
    ResultEnvelope, ServerMessage, encode,
};
use tokio::time::{Duration, Instant};

use super::{ExchangeError, request_exchange_streaming, status::submit_maybe_sent};

static TEST_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[tokio::test]
async fn send_boundary_timeout_is_conservatively_marked_maybe_sent() {
    let mut may_have_been_sent = false;
    let result = submit_maybe_sent(
        &mut may_have_been_sent,
        Instant::now() + Duration::from_millis(10),
        pending::<Result<(), ExchangeError>>(),
    )
    .await;

    assert!(matches!(result, Err(ExchangeError::DeadlineExceeded)));
    assert!(may_have_been_sent);
}

#[tokio::test]
async fn correlation_failure_after_a_valid_event_retains_cursor_and_send_ambiguity() {
    let runtime = test_runtime("correlation");
    let _ = std::fs::remove_dir_all(&runtime);
    let endpoint = LocalEndpoint::ipc(runtime.clone());
    let mut server = ServerTransport::bind(&endpoint).await.unwrap();
    let request = status_request("correlated-status");
    let project_id = request.project_id.clone();
    let target_id = request.request_id.clone();
    let server_task = tokio::spawn(async move {
        let incoming = server.receive().await.unwrap();
        server
            .respond(
                &incoming,
                encode(&ServerMessage::Event(EventEnvelope {
                    protocol_version: PROTOCOL_VERSION,
                    request_id: target_id,
                    project_id: project_id.clone(),
                    sequence: 1,
                    event: Event::Accepted,
                }))
                .unwrap(),
            )
            .await
            .unwrap();
        server
            .respond(
                &incoming,
                encode(&ServerMessage::Result(ResultEnvelope {
                    protocol_version: PROTOCOL_VERSION,
                    request_id: RequestId::from("wrong-result-id"),
                    project_id,
                    body: ResultBody::Failure(Failure {
                        code: FailureCode::Internal,
                        message: "bounded failure".to_owned(),
                        recovery: None,
                        approval: None,
                    }),
                }))
                .unwrap(),
            )
            .await
            .unwrap();
        server.close().await.unwrap();
    });
    let mut delivered = Vec::new();
    let error = request_exchange_streaming(&endpoint, &request, Duration::from_secs(2), |event| {
        delivered.push(event.sequence);
    })
    .await
    .unwrap_err();

    assert!(matches!(error.error(), ExchangeError::Correlation(_)));
    assert!(error.request_may_have_been_sent());
    assert_eq!(error.last_sequence(), 1);
    assert_eq!(delivered, vec![1]);
    server_task.await.unwrap();
    let _ = std::fs::remove_dir_all(runtime);
}

#[tokio::test]
async fn disconnect_after_a_valid_event_retains_cursor_and_send_ambiguity() {
    let runtime = test_runtime("disconnect");
    let _ = std::fs::remove_dir_all(&runtime);
    let endpoint = LocalEndpoint::ipc(runtime.clone());
    let mut server = ServerTransport::bind(&endpoint).await.unwrap();
    let request = status_request("disconnected-status");
    let project_id = request.project_id.clone();
    let target_id = request.request_id.clone();
    let server_task = tokio::spawn(async move {
        let incoming = server.receive().await.unwrap();
        server
            .respond(
                &incoming,
                encode(&ServerMessage::Event(EventEnvelope {
                    protocol_version: PROTOCOL_VERSION,
                    request_id: target_id,
                    project_id,
                    sequence: 1,
                    event: Event::Accepted,
                }))
                .unwrap(),
            )
            .await
            .unwrap();
        server.close().await.unwrap();
    });
    let mut delivered = Vec::new();
    let error =
        request_exchange_streaming(&endpoint, &request, Duration::from_millis(250), |event| {
            delivered.push(event.sequence);
        })
        .await
        .unwrap_err();

    assert!(error.request_may_have_been_sent());
    assert_eq!(error.last_sequence(), 1);
    assert_eq!(delivered, vec![1]);
    server_task.await.unwrap();
    let _ = std::fs::remove_dir_all(runtime);
}

fn status_request(label: &str) -> RequestEnvelope {
    RequestEnvelope::status(
        RequestId::from(label),
        CallerId::from("streaming-test-caller"),
        ProjectId::from("streaming-test-project"),
        IdempotencyKey::from(format!("{label}-key")),
    )
}

fn test_runtime(label: &str) -> std::path::PathBuf {
    let sequence = TEST_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "pam-streaming-{label}-{}-{sequence}",
        std::process::id()
    ))
}
