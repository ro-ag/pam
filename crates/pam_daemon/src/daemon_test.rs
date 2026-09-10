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

#[tokio::test(start_paused = true)]
async fn absolute_deadline_wait_does_not_restore_time_spent_before_registration() {
    use crate::daemon::await_registration_until;
    use tokio::time::{Instant, advance};

    let router = CompletionRouter::new();
    let admitted_deadline = Instant::now() + Duration::from_secs(10);
    // Gate/placement already consumed nine of the admitted ten seconds.
    advance(Duration::from_secs(9)).await;
    let original = router.register("absolute_deadline").await;
    let attached = router.register("absolute_deadline").await;
    let waiting_started = Instant::now();
    assert_eq!(
        await_registration_until(original, admitted_deadline).await,
        Err(true)
    );
    assert_eq!(Instant::now() - waiting_started, Duration::from_secs(1));
    // The wait primitive only observes: another observer retains its own wait,
    // and a timed-out receiver does not destroy the result channel for it.
    router
        .finish("absolute_deadline", result("absolute_deadline"))
        .await;
    assert_eq!(
        await_registration_until(attached, Instant::now() + Duration::from_secs(10))
            .await
            .unwrap(),
        result("absolute_deadline")
    );
}

#[tokio::test]
async fn deadline_expires_ticketed_approval_without_placing_or_executing_work() {
    use pam_store::RequestState;
    use pam_testkit::{TestDaemon, envelope, open_store, short_tempdir, with_deadline};

    with_deadline(async {
        let tmp = short_tempdir();
        let store = open_store(&tmp).await;
        store
            .set_setting(crate::policy::PROFILE_SETTING_KEY, "\"strict\"")
            .await
            .unwrap();
        store.insert_grant("echo").await.unwrap();
        drop(store);
        let daemon = TestDaemon::spawn_at_with(tmp, |config| {
            config.approval_timeout = Duration::from_secs(30);
        })
        .await;
        let mut client = daemon.client().await;
        let mut request = envelope(
            "ticketed_approval_deadline",
            "echo",
            serde_json::json!({"msg":"must not execute"}),
            false,
        );
        request.deadline_ms = 2_000;
        assert!(matches!(
            client.request(&request).await,
            Response::Ticket { .. }
        ));
        let row = daemon
            .wait_for_row(&request.id, |row| row.state.is_terminal())
            .await;
        assert_eq!(row.state, RequestState::Failed);
        assert_eq!(
            row.outcome.as_deref(),
            Some(crate::queue::CAUSE_LEASE_EXPIRED)
        );
        let approval = daemon
            .store()
            .approval_for_request(&request.id)
            .await
            .unwrap()
            .unwrap();
        assert!(
            approval.resolution.is_some(),
            "expired approval must not remain grantable"
        );
        let audit = daemon.store().audit_for_request(&request.id).await.unwrap();
        assert!(
            !audit
                .iter()
                .any(|row| row.action == crate::daemon::ACTION_EXECUTE)
        );
        assert_eq!(
            audit
                .iter()
                .filter(|row| row.action == crate::queue::ACTION_LEASE_REAPED)
                .count(),
            1
        );
        assert!(
            daemon
                .store()
                .list_evidence(&request.id)
                .await
                .unwrap()
                .is_empty()
        );
        daemon.assert_invariant_clean().await;
        daemon.stop().await;
    })
    .await;
}
