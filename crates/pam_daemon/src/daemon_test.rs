use std::time::Duration;

use pam_proto::{Outcome, Response};
use tokio::time::timeout;

use crate::daemon::{CompletionRouter, Registration};

const DEADLINE: Duration = Duration::from_secs(5);

fn result(id: &str) -> Response {
    Response::Result {
        id: id.to_owned(),
        outcome: Outcome::Solved,
        body: serde_json::json!({ "answer": 42 }),
        evidence: Vec::new(),
    }
}

#[tokio::test]
async fn finish_fans_out_to_every_registered_waiter() {
    timeout(DEADLINE, async {
        let router = CompletionRouter::new();
        let Registration::Pending(first) = router.register("req_1").await else {
            panic!("nothing finished yet");
        };
        let Registration::Pending(second) = router.register("req_1").await else {
            panic!("nothing finished yet");
        };

        router.finish("req_1", result("req_1")).await;

        assert_eq!(first.await.unwrap(), result("req_1"));
        assert_eq!(second.await.unwrap(), result("req_1"));
    })
    .await
    .expect("test within deadline");
}

#[tokio::test]
async fn registering_after_the_finish_gets_the_kept_response() {
    timeout(DEADLINE, async {
        let router = CompletionRouter::new();
        router.finish("req_1", result("req_1")).await;

        // The attach-after-finish race: a late registrant is answered
        // from the kept response instead of hanging to its deadline.
        let Registration::Ready(response) = router.register("req_1").await else {
            panic!("req_1 already finished");
        };
        assert_eq!(*response, result("req_1"));

        // Other requests are unaffected.
        assert!(matches!(
            router.register("req_2").await,
            Registration::Pending(_)
        ));
    })
    .await
    .expect("test within deadline");
}

#[tokio::test]
async fn a_dropped_waiter_does_not_block_the_finish() {
    timeout(DEADLINE, async {
        let router = CompletionRouter::new();
        let Registration::Pending(waiter) = router.register("req_1").await else {
            panic!("nothing finished yet");
        };
        // The waiting pipeline task gave up (deadline elapsed).
        drop(waiter);

        router.finish("req_1", result("req_1")).await;
        let Registration::Ready(response) = router.register("req_1").await else {
            panic!("req_1 already finished");
        };
        assert_eq!(*response, result("req_1"));
    })
    .await
    .expect("test within deadline");
}
