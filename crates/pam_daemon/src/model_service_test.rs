use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use pam_model::{
    CancellationSignal, CancellationToken, RuntimeError, RuntimeFinishReason, RuntimeMessage,
    RuntimeMessageRole, RuntimeRequest, RuntimeResponse, RuntimeUsage,
};

use crate::model_service::{ModelGenerator, ModelService, ModelServiceError};

struct FakeGenerator {
    active: AtomicBool,
    calls: AtomicUsize,
    release: AtomicBool,
}

impl FakeGenerator {
    fn new(release: bool) -> Self {
        Self {
            active: AtomicBool::new(false),
            calls: AtomicUsize::new(0),
            release: AtomicBool::new(release),
        }
    }
}

impl ModelGenerator for FakeGenerator {
    fn generate(
        &self,
        _request: RuntimeRequest,
        cancellation: CancellationToken,
    ) -> Result<RuntimeResponse, RuntimeError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.active.store(true, Ordering::SeqCst);
        while !self.release.load(Ordering::SeqCst) {
            if cancellation.is_cancelled() {
                self.active.store(false, Ordering::SeqCst);
                return Err(RuntimeError::Cancelled);
            }
            thread::sleep(Duration::from_millis(1));
        }
        self.active.store(false, Ordering::SeqCst);
        Ok(RuntimeResponse {
            text: "ok".to_owned(),
            finish_reason: RuntimeFinishReason::Stop,
            usage: RuntimeUsage {
                input_tokens: 1,
                sampled_output_tokens: 1,
                emitted_output_tokens: 1,
            },
        })
    }
}

fn request() -> RuntimeRequest {
    RuntimeRequest::new(
        vec![RuntimeMessage::new(RuntimeMessageRole::User, "hello").unwrap()],
        16,
    )
    .unwrap()
}

async fn wait_until_active(runtime: &FakeGenerator) {
    tokio::time::timeout(Duration::from_secs(1), async {
        while !runtime.active.load(Ordering::SeqCst) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn worker_allows_one_active_and_one_queued_then_reports_busy() {
    let runtime = Arc::new(FakeGenerator::new(false));
    let (service, worker) = ModelService::start_generator(Arc::clone(&runtime));
    let first_service = service.clone();
    let first = tokio::spawn(async move {
        first_service
            .infer(request(), Instant::now() + Duration::from_secs(2))
            .await
    });
    wait_until_active(&runtime).await;

    let second_service = service.clone();
    let second = tokio::spawn(async move {
        second_service
            .infer(request(), Instant::now() + Duration::from_secs(2))
            .await
    });
    tokio::task::yield_now().await;

    let third = service
        .infer(request(), Instant::now() + Duration::from_secs(1))
        .await;
    assert!(matches!(third, Err(ModelServiceError::Busy)));

    runtime.release.store(true, Ordering::SeqCst);
    assert_eq!(first.await.unwrap().unwrap().text, "ok");
    assert_eq!(second.await.unwrap().unwrap().text, "ok");
    worker.shutdown().await;
}

#[tokio::test]
async fn deadline_cancels_generation_without_leaking_the_worker() {
    let runtime = Arc::new(FakeGenerator::new(false));
    let (service, worker) = ModelService::start_generator(Arc::clone(&runtime));
    let result = service
        .infer(request(), Instant::now() + Duration::from_millis(10))
        .await;
    assert!(matches!(result, Err(ModelServiceError::DeadlineExceeded)));

    tokio::time::timeout(Duration::from_secs(1), async {
        while runtime.active.load(Ordering::SeqCst) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    runtime.release.store(true, Ordering::SeqCst);
    assert_eq!(
        service
            .infer(request(), Instant::now() + Duration::from_secs(1))
            .await
            .unwrap()
            .text,
        "ok"
    );
    worker.shutdown().await;
}
