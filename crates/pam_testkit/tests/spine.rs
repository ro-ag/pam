//! Spine invariants, end to end through the shared harness: lane
//! serialization (same-repo requests never interleave; cross-repo
//! lanes run in parallel), dedupe attach, restart persistence, and the
//! audit sweep (every terminal state has exactly one audit row).
//!
//! # Timing sensitivity
//!
//! Ordering assertions use **logical event order** off the daemon's
//! `PUB` stream (one publisher loop, one connection — arrival order is
//! publish order), never wall durations, so runner load cannot flip
//! them. The only wall bound is the harness's generous
//! [`pam_testkit::TEST_DEADLINE`], which catches hangs.

use std::collections::HashSet;
use std::time::Duration;

use pam_daemon::lifecycle::CAUSE_DAEMON_RESTART;
use pam_daemon::queue::{ACTION_CANCEL, CAUSE_CANCELLED};
use pam_proto::{Event, Outcome, Response};
use pam_store::{RequestState, Store};
use pam_testkit::{TestDaemon, envelope, envelope_for_repo, open_store, with_deadline};

/// N same-lane background echoes: their `started`/`done` events must
/// form strictly non-overlapping pairs — request k+1 starts only after
/// request k is done — and all of them must complete.
#[tokio::test]
async fn same_repo_lane_requests_never_interleave() {
    with_deadline(async {
        let daemon = TestDaemon::spawn().await;
        let ids = ["req_lane_a", "req_lane_b", "req_lane_c"];
        let mut events = daemon.subscribe(&ids).await;
        let mut client = daemon.client().await;

        // Fire all three before reading any ticket, so they contend for
        // the lane at once. Distinct args (the `tag`) keep shape-dedupe
        // from attaching them to each other — this test wants three
        // separate executions on one lane.
        for id in ids {
            client
                .send(&envelope(
                    id,
                    "echo",
                    serde_json::json!({ "delay_ms": 200, "tag": id }),
                    false,
                ))
                .await;
        }
        for _ in ids {
            assert!(matches!(client.recv().await, Response::Ticket { .. }));
        }

        let stream = events.collect_until_terminals(3).await;
        let executions: Vec<(String, Event)> = stream
            .into_iter()
            .filter(|(_, event)| matches!(event, Event::Started | Event::Done))
            .collect();

        // Logical-order invariant: the execution stream is a sequence
        // of (started k, done k) pairs — no started event may land
        // between another request's started and done.
        assert_eq!(executions.len(), 2 * ids.len(), "stream: {executions:?}");
        let mut finished = HashSet::new();
        for pair in executions.chunks(2) {
            assert_eq!(pair[0].1, Event::Started, "stream: {executions:?}");
            assert_eq!(pair[1].1, Event::Done, "stream: {executions:?}");
            assert_eq!(
                pair[0].0, pair[1].0,
                "a request started before the previous one finished: {executions:?}"
            );
            finished.insert(pair[0].0.clone());
        }
        assert_eq!(finished.len(), ids.len(), "all requests completed");

        for id in ids {
            daemon.assert_row_state(id, RequestState::Done).await;
        }
        daemon.assert_invariant_clean().await;
        daemon.stop().await;
    })
    .await;
}

/// Two repos in parallel: both requests must be `started` before either
/// is `done` (observed overlap), unlike the same-lane case.
#[tokio::test]
async fn cross_repo_lanes_execute_in_parallel() {
    with_deadline(async {
        let daemon = TestDaemon::spawn().await;
        let ids = ["req_xrepo_a", "req_xrepo_b"];
        let mut events = daemon.subscribe(&ids).await;
        let mut client = daemon.client().await;

        // Long enough that the executor's next pass (100 ms tick, and
        // it leases every ready repo per pass) lands well inside the
        // first delay even on a loaded runner.
        let args = serde_json::json!({ "delay_ms": 1500 });
        client
            .send(&envelope_for_repo(
                "/repo/alpha",
                ids[0],
                "echo",
                args.clone(),
                false,
            ))
            .await;
        client
            .send(&envelope_for_repo(
                "/repo/beta",
                ids[1],
                "echo",
                args,
                false,
            ))
            .await;
        for _ in ids {
            assert!(matches!(client.recv().await, Response::Ticket { .. }));
        }

        let stream = events.collect_until_terminals(2).await;
        let executions: Vec<(String, Event)> = stream
            .into_iter()
            .filter(|(_, event)| matches!(event, Event::Started | Event::Done))
            .collect();
        assert_eq!(executions.len(), 4, "stream: {executions:?}");
        assert_eq!(
            (&executions[0].1, &executions[1].1),
            (&Event::Started, &Event::Started),
            "cross-repo lanes must overlap: the second started must \
             precede the first done: {executions:?}"
        );
        assert_ne!(
            executions[0].0, executions[1].0,
            "both repos started: {executions:?}"
        );

        for id in ids {
            daemon.assert_row_state(id, RequestState::Done).await;
        }
        daemon.assert_invariant_clean().await;
        daemon.stop().await;
    })
    .await;
}

/// Two identical waiting echoes with the same idempotency key: the
/// second attaches to the first — both callers get the same result id
/// and only one request row exists.
#[tokio::test]
async fn dedupe_attach_shares_one_result() {
    with_deadline(async {
        let daemon = TestDaemon::spawn().await;
        let mut first = daemon.client().await;
        let mut second = daemon.client().await;

        let args = serde_json::json!({ "delay_ms": 700, "tag": "dupe" });
        let mut original = envelope("req_dupe_a", "echo", args.clone(), true);
        original.idempotency_key = Some("dupe-key".to_owned());
        first.send(&original).await;
        // Deterministic attach point: wait until the original's row
        // exists (admitted) before sending the duplicate.
        daemon.wait_for_row("req_dupe_a", |_| true).await;

        let mut duplicate = envelope("req_dupe_b", "echo", args, true);
        duplicate.idempotency_key = Some("dupe-key".to_owned());
        second.send(&duplicate).await;

        let first_response = first.recv().await;
        let second_response = second.recv().await;
        assert_eq!(first_response, second_response);
        let Response::Result { id, outcome, .. } = second_response else {
            panic!("expected a result, got {second_response:?}");
        };
        assert_eq!(id, "req_dupe_a", "the attached caller shares the original");
        assert_eq!(outcome, Outcome::Solved);

        // The duplicate never got a row of its own.
        let store = daemon.store();
        assert!(store.get_request("req_dupe_b").await.unwrap().is_none());

        daemon.assert_invariant_clean().await;
        daemon.stop().await;
    })
    .await;
}

/// Seeds a `running` row the way a crashed daemon leaves one — no
/// graceful teardown wrote its terminal state.
async fn seed_crashed_running_row(store: &Store, id: &str) {
    store
        .insert_request(id, "echo", pam_testkit::TEST_REPO, "claude", "{}", None)
        .await
        .expect("insert");
    store
        .update_request_state(id, RequestState::Running, None)
        .await
        .expect("state set");
}

/// Restart persistence per the lifecycle spec: across a daemon restart
/// on the same base dir, in-flight work the drain had to cancel stays
/// legibly failed, `queued` rows survive and re-execute, and stuck rows
/// a crash left behind are failed `daemon_restart` on boot.
#[tokio::test]
async fn restart_persists_queued_work_and_fails_stuck_rows() {
    with_deadline(async {
        // A short drain bound forces the running request onto the
        // cancel path instead of waiting out its 8 s delay.
        let daemon =
            TestDaemon::spawn_with(|config| config.drain_timeout = Duration::from_millis(300))
                .await;
        let mut client = daemon.client().await;

        // Occupy the lane, then park a second request behind it.
        client
            .send(&envelope(
                "req_rst_running",
                "echo",
                serde_json::json!({ "delay_ms": 8000 }),
                false,
            ))
            .await;
        assert!(matches!(client.recv().await, Response::Ticket { .. }));
        daemon
            .wait_for_row("req_rst_running", |row| row.state == RequestState::Running)
            .await;
        client
            .send(&envelope(
                "req_rst_queued",
                "echo",
                serde_json::json!({ "msg": "later" }),
                false,
            ))
            .await;
        assert!(matches!(client.recv().await, Response::Ticket { .. }));
        daemon
            .wait_for_row("req_rst_queued", |row| row.state == RequestState::Queued)
            .await;

        // Graceful drain: the queued row is the restart-safe checkpoint
        // and stays put; the running lease is cancelled past the bound.
        let tmp = daemon.stop().await;

        // Between the two daemon lifetimes, plant what an *abrupt* death
        // leaves behind: a running row nobody will ever finish.
        {
            let store = open_store(&tmp).await;
            seed_crashed_running_row(&store, "req_rst_stuck").await;
        }

        let daemon = TestDaemon::spawn_at(tmp).await;
        let store = daemon.store();

        // The drained-and-cancelled request is terminal with its audit.
        let row = store.get_request("req_rst_running").await.unwrap().unwrap();
        assert_eq!(row.state, RequestState::Failed);
        assert_eq!(row.outcome.as_deref(), Some(CAUSE_CANCELLED));
        assert_eq!(
            daemon.terminal_audit_actions("req_rst_running").await,
            [ACTION_CANCEL]
        );

        // The stuck row was failed daemon_restart by crash recovery.
        let row = daemon
            .wait_for_row("req_rst_stuck", |row| row.state == RequestState::Failed)
            .await;
        assert_eq!(row.outcome.as_deref(), Some(CAUSE_DAEMON_RESTART));

        // The queued row was rebuilt into its lane and re-executed.
        let row = daemon
            .wait_for_row("req_rst_queued", |row| row.state == RequestState::Done)
            .await;
        assert_eq!(row.outcome.as_deref(), Some("solved"));

        for id in ["req_rst_running", "req_rst_stuck", "req_rst_queued"] {
            daemon.assert_single_terminal_audit(id).await;
        }
        daemon.assert_invariant_clean().await;
        daemon.stop().await;
    })
    .await;
}

/// Runs success, failure, refusal, cancel, and dedupe-attach scenarios
/// against one daemon, then sweeps: every terminal request carries
/// exactly one terminal audit row and the store-wide invariant query is
/// clean.
#[tokio::test]
async fn audit_invariant_sweep_across_terminal_paths() {
    with_deadline(async {
        let daemon = TestDaemon::spawn().await;
        let mut client = daemon.client().await;

        // Success.
        let response = client
            .request(&envelope(
                "req_swp_ok",
                "echo",
                serde_json::json!({ "msg": "hi" }),
                true,
            ))
            .await;
        assert!(matches!(response, Response::Result { .. }));

        // Execution failure.
        let response = client
            .request(&envelope(
                "req_swp_fail",
                "echo",
                serde_json::json!({ "fail": true }),
                true,
            ))
            .await;
        assert!(matches!(response, Response::Refusal { .. }));

        // Gate refusal (unknown capability).
        let response = client
            .request(&envelope(
                "req_swp_unknown",
                "frobnicate",
                serde_json::json!({}),
                true,
            ))
            .await;
        assert!(matches!(response, Response::Refusal { .. }));

        // Cancel of a running request.
        client
            .send(&envelope(
                "req_swp_victim",
                "echo",
                serde_json::json!({ "delay_ms": 8000 }),
                false,
            ))
            .await;
        assert!(matches!(client.recv().await, Response::Ticket { .. }));
        daemon
            .wait_for_row("req_swp_victim", |row| row.state == RequestState::Running)
            .await;
        let mut canceller = daemon.client().await;
        let response = canceller
            .request(&envelope(
                "req_swp_cancel",
                "cancel",
                serde_json::json!({ "ticket": "req_swp_victim" }),
                true,
            ))
            .await;
        assert!(matches!(response, Response::Result { .. }));
        daemon
            .wait_for_row("req_swp_victim", |row| row.state == RequestState::Failed)
            .await;

        // Dedupe attach (the duplicate must not add audit rows).
        let args = serde_json::json!({ "delay_ms": 700, "tag": "sweep" });
        let mut original = envelope("req_swp_dupe_a", "echo", args.clone(), true);
        original.idempotency_key = Some("sweep-dupe".to_owned());
        client.send(&original).await;
        daemon.wait_for_row("req_swp_dupe_a", |_| true).await;
        let mut duplicate = envelope("req_swp_dupe_b", "echo", args, true);
        duplicate.idempotency_key = Some("sweep-dupe".to_owned());
        let response = canceller.request(&duplicate).await;
        let Response::Result { id, .. } = response else {
            panic!("expected a result, got {response:?}");
        };
        assert_eq!(id, "req_swp_dupe_a");
        assert!(matches!(client.recv().await, Response::Result { .. }));

        // The sweep: exactly one terminal audit row per terminal path,
        // and no silent terminals store-wide (attached duplicates and
        // rowless refusals are skipped by the tracked-id sweep).
        for id in [
            "req_swp_ok",
            "req_swp_fail",
            "req_swp_unknown",
            "req_swp_victim",
            "req_swp_cancel",
            "req_swp_dupe_a",
        ] {
            daemon.assert_single_terminal_audit(id).await;
        }
        daemon.assert_invariant_clean().await;
        daemon.stop().await;
    })
    .await;
}
