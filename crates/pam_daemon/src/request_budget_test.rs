use crate::request_budget::{Limits, RequestBudget};
use std::time::{Duration, Instant};

fn budget() -> std::sync::Arc<RequestBudget> {
    RequestBudget::with_limits(
        Instant::now() + Duration::from_secs(10),
        Limits {
            attempts: 2,
            http_calls: 2,
            http_bytes: 100,
            command_bytes: 100,
        },
    )
}

#[test]
fn retries_share_attempts_and_cancelled_reservations_stay_spent() {
    let original = budget();
    let retry = std::sync::Arc::clone(&original);
    original.attempt().unwrap();
    retry.attempt().unwrap();
    assert_eq!(retry.attempt().unwrap_err().resource, "attempts");
    drop(original.http(60).unwrap());
    assert_eq!(retry.http(41).unwrap_err().resource, "http_bytes");
    assert_eq!(original.usage().http_bytes, 60);
}

#[test]
fn exact_capture_refunds_unused_bytes_but_never_call_count() {
    let budget = budget();
    budget.http(100).unwrap().finish(10).unwrap();
    budget.http(90).unwrap().finish(20).unwrap();
    assert_eq!(budget.usage().http_bytes, 30);
    assert_eq!(budget.http(1).unwrap_err().resource, "http_calls");
    budget.command(100).unwrap().finish(99).unwrap();
    assert!(budget.command(2).is_err());
}

#[test]
fn expired_deadline_prevents_every_reservation() {
    let budget = RequestBudget::new(Instant::now());
    assert_eq!(
        budget.attempt().unwrap_err().cause,
        "request_deadline_exhausted"
    );
    assert!(budget.http(1).is_err());
    assert!(budget.command(1).is_err());
    assert_eq!(budget.usage().http_calls, 0);
}

#[test]
fn overlarge_capture_does_not_refund_or_overflow() {
    let budget = budget();
    assert!(budget.command(100).unwrap().finish(u64::MAX).is_err());
    assert_eq!(budget.usage().command_bytes, 100);
    assert!(budget.command(u64::MAX).is_err());
}

struct StalledTransport;
impl pam_connectors::HttpTransport for StalledTransport {
    fn send<'a>(
        &'a self,
        _request: pam_connectors::HttpRequest,
        _deadline: Instant,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = Result<pam_connectors::HttpResponse, pam_connectors::TransportError>,
                > + Send
                + 'a,
        >,
    > {
        Box::pin(std::future::pending())
    }
}

#[tokio::test]
async fn a_transport_that_ignores_its_deadline_is_stopped_and_keeps_its_reservation() {
    use pam_connectors::HttpTransport;
    let deadline = Instant::now() + Duration::from_millis(20);
    let budget = RequestBudget::new(deadline);
    let transport = crate::request_budget::BudgetTransport {
        inner: &StalledTransport,
        budget: std::sync::Arc::clone(&budget),
    };
    let request = pam_connectors::HttpRequest {
        method: pam_connectors::Method::Get,
        body: None,
        url: pam_connectors::validate_base_url(
            pam_flow::ConnectorId::Jenkins,
            "https://jenkins.example/",
        )
        .unwrap(),
        headers: Vec::new(),
        max_bytes: 1024,
        follow_one_https_redirect_without_auth: false,
    };
    let error = tokio::time::timeout(Duration::from_secs(2), transport.send(request, deadline))
        .await
        .unwrap()
        .unwrap_err();
    assert!(matches!(
        error,
        pam_connectors::TransportError::Policy {
            cause: "request_deadline_exhausted",
            ..
        }
    ));
    assert_eq!(budget.usage().http_calls, 1);
    assert_eq!(budget.usage().http_bytes, 1024);
}

async fn persistent() -> (
    std::sync::Arc<pam_store::Store>,
    std::sync::Arc<RequestBudget>,
) {
    let store = std::sync::Arc::new(pam_store::Store::open_in_memory().await.unwrap());
    store
        .insert_request("persistent", "flow.run", "/repo", "test", "{}", None)
        .await
        .unwrap();
    let budget = RequestBudget::load_persistent(
        std::sync::Arc::clone(&store),
        "persistent",
        Instant::now() + Duration::from_secs(30),
    )
    .await
    .unwrap();
    (store, budget)
}

#[tokio::test]
async fn durable_completed_capture_refunds_but_cancellation_stays_charged() {
    let (store, budget) = persistent().await;
    assert_eq!(
        budget.attempt().unwrap_err().cause,
        "request_budget_persistence_required"
    );
    assert!(budget.command(1).is_err());
    assert!(budget.http(1).is_err());
    budget.attempt_persisted().await.unwrap();
    budget
        .http_persisted(100)
        .await
        .unwrap()
        .finish_persisted(1)
        .await
        .unwrap();
    drop(budget.command_persisted(200).await.unwrap());
    let restored = RequestBudget::load_persistent(store, "persistent", budget.deadline())
        .await
        .unwrap();
    assert_eq!(restored.usage().attempts, 1);
    assert_eq!(restored.usage().http_bytes, 1);
    assert_eq!(restored.usage().command_bytes, 200);
}

#[tokio::test]
async fn independent_budget_handles_share_atomic_durable_ceiling() {
    let (store, a) = persistent().await;
    let b = RequestBudget::load_persistent(store, "persistent", a.deadline())
        .await
        .unwrap();
    let (x, y) = tokio::join!(a.http_persisted(100_000_000), b.http_persisted(100_000_000));
    assert_eq!(usize::from(x.is_ok()) + usize::from(y.is_ok()), 1);
}

#[tokio::test]
async fn missing_persistent_request_refuses_initialization() {
    let store = std::sync::Arc::new(pam_store::Store::open_in_memory().await.unwrap());
    assert_eq!(
        RequestBudget::load_persistent(store, "absent", Instant::now() + Duration::from_secs(10))
            .await
            .unwrap_err()
            .cause,
        "request_budget_store_unavailable"
    );
}

#[tokio::test]
async fn exhausted_persistent_transport_never_reaches_network() {
    use pam_connectors::HttpTransport;
    let (_, budget) = persistent().await;
    drop(budget.http_persisted(134_217_728).await.unwrap());
    let fake = pam_connectors::testing::FakeTransport::new();
    let transport = crate::request_budget::BudgetTransport {
        inner: &fake,
        budget: std::sync::Arc::clone(&budget),
    };
    let request = pam_connectors::HttpRequest {
        method: pam_connectors::Method::Get,
        body: None,
        url: pam_connectors::validate_base_url(
            pam_flow::ConnectorId::Jenkins,
            "https://jenkins.example/",
        )
        .unwrap(),
        headers: Vec::new(),
        max_bytes: 1,
        follow_one_https_redirect_without_auth: false,
    };
    assert!(matches!(
        transport.send(request, budget.deadline()).await,
        Err(pam_connectors::TransportError::Policy {
            cause: "request_budget_exhausted",
            ..
        })
    ));
    assert!(fake.requests().is_empty());
}

#[tokio::test]
async fn completed_tiny_commands_and_http_calls_can_run_past_two_large_reservations() {
    let (store, budget) = persistent().await;
    for _ in 0..4 {
        budget.attempt_persisted().await.unwrap();
        budget
            .command_persisted(64 * 1024 * 1024)
            .await
            .unwrap()
            .finish_persisted(10)
            .await
            .unwrap();
        budget
            .http_persisted(64 * 1024 * 1024)
            .await
            .unwrap()
            .finish_persisted(20)
            .await
            .unwrap();
    }
    let restored = RequestBudget::load_persistent(store, "persistent", budget.deadline())
        .await
        .unwrap();
    assert_eq!(restored.usage().attempts, 4);
    assert_eq!(restored.usage().http_calls, 4);
    assert_eq!(restored.usage().command_bytes, 40);
    assert_eq!(restored.usage().http_bytes, 80);
}
