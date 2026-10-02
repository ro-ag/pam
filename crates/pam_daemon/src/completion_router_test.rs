use std::time::Duration;

use pam_proto::{Outcome, Response};

use crate::completion_router::{
    CompletionRouter, FINISHED_TTL, MAX_FINISHED_BYTES, MAX_FINISHED_ENTRIES, Registration,
    approximate_size,
};

fn result(id: &str, body: serde_json::Value) -> Response {
    Response::Result {
        id: id.to_owned(),
        outcome: Outcome::Solved,
        body,
        evidence: Vec::new(),
    }
}

#[tokio::test]
async fn retained_responses_are_bounded_by_count_and_the_oldest_goes_first() {
    let router = CompletionRouter::new();
    let total = MAX_FINISHED_ENTRIES + 50;
    for index in 0..total {
        let id = format!("req_{index}");
        router
            .finish(&id, result(&id, serde_json::json!({ "n": index })))
            .await;
    }
    let usage = router.usage().await;
    assert_eq!(usage.finished, MAX_FINISHED_ENTRIES);

    // The first fifty were evicted: a late registrant is not handed a stale
    // answer, it waits (and the pipeline reads the durable row instead).
    assert!(matches!(
        router.register("req_0").await,
        Registration::Pending(_)
    ));
    assert!(matches!(
        router.register("req_49").await,
        Registration::Pending(_)
    ));
    // The newest are still there.
    let newest = format!("req_{}", total - 1);
    assert!(matches!(
        router.register(&newest).await,
        Registration::Ready(_)
    ));
    assert!(matches!(
        router.register("req_50").await,
        Registration::Ready(_)
    ));
}

#[tokio::test]
async fn retained_responses_are_bounded_by_bytes() {
    let router = CompletionRouter::new();
    // Twenty answers of about a megabyte each: 20 MiB offered, 8 MiB kept.
    let megabyte = "x".repeat(1024 * 1024);
    for index in 0..20 {
        let id = format!("big_{index}");
        router
            .finish(&id, result(&id, serde_json::json!({ "echo": megabyte })))
            .await;
    }
    let usage = router.usage().await;
    assert!(
        usage.finished_bytes <= MAX_FINISHED_BYTES,
        "retained {} bytes",
        usage.finished_bytes
    );
    assert!(usage.finished <= 8, "retained {} answers", usage.finished);
    assert!(usage.finished >= 6, "retained {} answers", usage.finished);
    // The newest survived; the oldest did not.
    assert!(matches!(
        router.register("big_19").await,
        Registration::Ready(_)
    ));
    assert!(matches!(
        router.register("big_0").await,
        Registration::Pending(_)
    ));
}

#[tokio::test]
async fn an_answer_larger_than_the_whole_budget_reaches_waiters_but_is_not_kept() {
    let router = CompletionRouter::new();
    let Registration::Pending(waiter) = router.register("huge").await else {
        panic!("nothing finished yet");
    };
    let body = serde_json::json!({ "echo": "y".repeat(MAX_FINISHED_BYTES + 1) });
    let response = result("huge", body);
    assert!(approximate_size(&response) > MAX_FINISHED_BYTES);
    router.finish("huge", response.clone()).await;

    assert_eq!(waiter.await.unwrap(), response);
    let usage = router.usage().await;
    assert_eq!((usage.finished, usage.finished_bytes), (0, 0));
}

#[tokio::test]
async fn refinishing_an_id_replaces_its_entry_instead_of_counting_twice() {
    let router = CompletionRouter::new();
    router
        .finish("req", result("req", serde_json::json!({ "v": 1 })))
        .await;
    let once = router.usage().await;
    router
        .finish("req", result("req", serde_json::json!({ "v": 2 })))
        .await;
    let twice = router.usage().await;
    assert_eq!(twice.finished, 1);
    assert_eq!(twice.finished_bytes, once.finished_bytes);
    let Registration::Ready(kept) = router.register("req").await else {
        panic!("req finished");
    };
    assert_eq!(*kept, result("req", serde_json::json!({ "v": 2 })));
}

#[tokio::test]
async fn waiters_that_gave_up_do_not_accumulate() {
    let router = CompletionRouter::new();
    // A request that is attached to and abandoned over and over — and never
    // finishes, which used to be the only thing that removed its entry.
    for _ in 0..500 {
        let registration = router.register("never_finishes").await;
        drop(registration);
    }
    for index in 0..100 {
        drop(router.register(&format!("abandoned_{index}")).await);
    }
    assert!(!router.has_waiters("never_finishes").await);
    router.prune().await;
    assert_eq!(router.usage().await.waiting, 0);

    // A live waiter is kept by the same sweep.
    let Registration::Pending(live) = router.register("live").await else {
        panic!("nothing finished yet");
    };
    router.prune().await;
    assert_eq!(router.usage().await.waiting, 1);
    router
        .finish("live", result("live", serde_json::json!({})))
        .await;
    assert!(live.await.is_ok());
}

#[tokio::test(start_paused = true)]
async fn retained_responses_expire_on_the_tick_without_another_finish() {
    let router = CompletionRouter::new();
    router
        .finish("req", result("req", serde_json::json!({})))
        .await;
    assert_eq!(router.usage().await.finished, 1);

    tokio::time::advance(FINISHED_TTL.saturating_sub(Duration::from_secs(1))).await;
    router.prune().await;
    assert_eq!(
        router.usage().await.finished,
        1,
        "still inside its lifetime"
    );

    tokio::time::advance(Duration::from_secs(2)).await;
    // No other request finishes: the reaper's tick is what frees it.
    router.prune().await;
    let usage = router.usage().await;
    assert_eq!((usage.finished, usage.finished_bytes), (0, 0));
    assert!(matches!(
        router.register("req").await,
        Registration::Pending(_)
    ));
}
