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
    use crate::daemon::{Waited, wait_for_terminal};
    use tokio::time::{Instant, advance};

    let router = CompletionRouter::new();
    let admitted_deadline = Instant::now() + Duration::from_secs(10);
    // Gate/placement already consumed nine of the admitted ten seconds.
    advance(Duration::from_secs(9)).await;
    let original = router.register("absolute_deadline").await;
    let attached = router.register("absolute_deadline").await;
    let waiting_started = Instant::now();
    assert_eq!(
        wait_for_terminal(original, admitted_deadline, None).await,
        Waited::TimedOut
    );
    assert_eq!(Instant::now() - waiting_started, Duration::from_secs(1));
    // The wait primitive only observes: another observer retains its own wait,
    // and a timed-out receiver does not destroy the result channel for it.
    router
        .finish("absolute_deadline", result("absolute_deadline"))
        .await;
    assert_eq!(
        wait_for_terminal(attached, Instant::now() + Duration::from_secs(10), None).await,
        Waited::Answer(result("absolute_deadline"))
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

/// The store refusing on purpose is a cause of its own on the public plane,
/// retryable, with the store's sentence as the detail; any other store error
/// stays the internal error whose detail is only in the daemon log.
#[test]
fn a_store_refusal_is_named_to_a_public_caller_and_other_store_errors_are_not() {
    use crate::daemon::{
        CAUSE_DAEMON_SHUTTING_DOWN, CAUSE_INTERNAL_ERROR, CAUSE_STORE_OVERLOADED, queue_refusal,
        store_refusal,
    };
    use crate::queue::QueueError;
    use pam_store::StoreError;

    let parts = |response: Response| match response {
        Response::Refusal {
            id,
            cause,
            detail,
            recovery,
            retryable,
        } => {
            assert_eq!(id, "req_1");
            (cause, detail, recovery, retryable)
        }
        other => panic!("expected a refusal, got {other:?}"),
    };
    let overloaded = || StoreError::Overloaded { waiting: 1024 };

    for response in [
        store_refusal("req_1", &overloaded()),
        // Admission, where a flooded store is met first.
        queue_refusal("req_1".to_owned(), &QueueError::Store(overloaded())),
    ] {
        let (cause, detail, recovery, retryable) = parts(response);
        assert_eq!(cause, CAUSE_STORE_OVERLOADED);
        assert_eq!(detail, overloaded().to_string());
        assert!(
            detail.contains("1024 calls waiting for the database"),
            "{detail}"
        );
        assert_eq!(recovery, "Retry shortly.");
        assert!(retryable);
    }

    for response in [
        store_refusal("req_1", &StoreError::Closed),
        queue_refusal("req_1".to_owned(), &QueueError::Store(StoreError::Closed)),
    ] {
        let (cause, detail, recovery, retryable) = parts(response);
        assert_eq!(cause, CAUSE_DAEMON_SHUTTING_DOWN);
        assert_eq!(detail, StoreError::Closed.to_string());
        assert!(recovery.starts_with("Retry shortly"), "{recovery}");
        assert!(retryable);
    }

    let other = || StoreError::NotFound {
        table: "request",
        id: "secret_ticket".to_owned(),
    };
    let (cause, detail, _, retryable) = parts(store_refusal("req_1", &other()));
    assert_eq!(cause, CAUSE_INTERNAL_ERROR);
    assert!(!detail.contains("secret_ticket"), "{detail}");
    assert!(retryable);
    let (cause, _, _, retryable) = parts(queue_refusal(
        "req_1".to_owned(),
        &QueueError::Store(other()),
    ));
    assert_eq!(cause, CAUSE_INTERNAL_ERROR);
    assert!(retryable);
}

// ---------------------------------------------------------------------------
// A real daemon, driven through its ingress channel, with its internals in
// reach. `pam_testkit` links the non-test build of this crate, so its
// `TestDaemon` cannot hand back this build's `QueueManager` or router; these
// tests need to stall and inject, so they start the daemon themselves.
// ---------------------------------------------------------------------------

mod live {
    use std::sync::Arc;
    use std::time::Duration;

    use pam_proto::{Envelope, Outcome, Response};
    use pam_store::{RequestState, Store};
    use tokio::sync::{oneshot, watch};

    use crate::daemon::{
        ACTION_DEADLINE_REFUSAL, ACTION_EXECUTE, CANCEL_SLOTS, CAUSE_DAEMON_SHUTTING_DOWN,
        CAUSE_DEADLINE_EXCEEDED, CAUSE_INTERNAL_ERROR, CAUSE_REQUEST_CAPACITY,
        CAUSE_STORE_OVERLOADED, CONTROL_SLOTS, DaemonConfig, DaemonHandle, Registration,
        STATUS_SLOTS, WORK_SLOTS, run_daemon_with,
    };
    use crate::ingress::{Origin, PeerIdentity, PublicPeer};
    use crate::secrets::FakeSecretBackend;
    use crate::transport::IncomingRequest;

    const REPO: &str = "/repo/live";
    const PATIENCE: Duration = Duration::from_secs(10);

    struct Live {
        handle: DaemonHandle,
        shutdown: watch::Sender<bool>,
        /// The base: kept alive for the daemon's lifetime, and handed back
        /// by [`Self::stop_keeping_base`].
        tmp: tempfile::TempDir,
    }

    impl Live {
        /// A daemon on a fresh private base with `profile` seeded
        /// explicitly (the platform default differs off macOS), a fake
        /// keychain, and whatever `mutate` changes.
        async fn start(profile: &str, mutate: impl FnOnce(&mut DaemonConfig)) -> Self {
            let tmp = pam_testkit::short_tempdir();
            let store = pam_testkit::open_store(&tmp).await;
            store
                .set_setting(
                    crate::policy::PROFILE_SETTING_KEY,
                    &format!("\"{profile}\""),
                )
                .await
                .unwrap();
            drop(store);
            let mut config = DaemonConfig {
                base_dir: Some(pam_testkit::base_of(&tmp)),
                secret_backend: Some(Arc::new(FakeSecretBackend::default())),
                ..DaemonConfig::default()
            };
            mutate(&mut config);
            let (shutdown, shutdown_rx) = watch::channel(false);
            let handle = tokio::time::timeout(PATIENCE, run_daemon_with(config, shutdown_rx))
                .await
                .expect("the daemon starts in time")
                .expect("the daemon starts");
            Self {
                handle,
                shutdown,
                tmp,
            }
        }

        fn store(&self) -> Arc<Store> {
            self.handle.store()
        }

        /// Sends one public request straight into the dispatcher.
        async fn submit(&self, envelope: Envelope) -> oneshot::Receiver<Response> {
            self.submit_from(envelope, Origin::Public, None).await
        }

        /// Sends one request into the dispatcher as the given plane's
        /// listener would, with the peer that listener saw.
        async fn submit_from(
            &self,
            envelope: Envelope,
            origin: Origin,
            peer: Option<PublicPeer>,
        ) -> oneshot::Receiver<Response> {
            let (reply, answer) = oneshot::channel();
            self.handle
                .admin()
                .submit
                .send(IncomingRequest {
                    origin,
                    peer,
                    envelope,
                    reply,
                })
                .await
                .expect("the dispatcher is running");
            answer
        }

        async fn ask_from(
            &self,
            envelope: Envelope,
            origin: Origin,
            peer: Option<PublicPeer>,
        ) -> Response {
            let answer = self.submit_from(envelope, origin, peer).await;
            tokio::time::timeout(PATIENCE, answer)
                .await
                .expect("an answer within the test's patience")
                .expect("the daemon answers every admitted request")
        }

        async fn ask(&self, envelope: Envelope) -> Response {
            let answer = self.submit(envelope).await;
            tokio::time::timeout(PATIENCE, answer)
                .await
                .expect("an answer within the test's patience")
                .expect("the daemon answers every admitted request")
        }

        async fn stop(self) {
            self.stop_keeping_base().await;
        }

        /// Stops the daemon and hands back its base, to read what it left.
        async fn stop_keeping_base(self) -> tempfile::TempDir {
            let _ = self.shutdown.send(true);
            tokio::time::timeout(Duration::from_secs(30), self.handle.shutdown())
                .await
                .expect("the daemon drains");
            self.tmp
        }
    }

    fn request(id: &str, capability: &str, args: serde_json::Value, wait: bool) -> Envelope {
        pam_testkit::envelope_for_repo(REPO, id, capability, args, wait)
    }

    /// Polls `check` until it holds, panicking legibly when it never does.
    async fn eventually<F, Fut>(what: &str, mut check: F)
    where
        F: FnMut() -> Fut,
        Fut: Future<Output = bool>,
    {
        let deadline = tokio::time::Instant::now() + PATIENCE;
        while !check().await {
            assert!(
                tokio::time::Instant::now() < deadline,
                "never happened: {what}"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    async fn state_of(store: &Store, id: &str) -> Option<RequestState> {
        store.get_request(id).await.unwrap().map(|row| row.state)
    }

    fn refusal(response: &Response) -> (&str, bool) {
        match response {
            Response::Refusal {
                cause, retryable, ..
            } => (cause.as_str(), *retryable),
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    /// ptrack issue 35, the "never answered" path: only the execution was
    /// under the deadline, so a handler wedged in its own bookkeeping held
    /// its slot and its caller for as long as the wedge lasted.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_wedged_handler_is_cut_off_answered_and_still_gets_its_terminal_row() {
        let live = Live::start("relaxed", |config| {
            config.handler_grace = Duration::from_millis(300);
        })
        .await;
        let store = live.store();
        let queue = live.handle.queue();

        // The lane is busy with a long echo...
        let ticket = live
            .ask(request(
                "wedge_holder",
                "echo",
                serde_json::json!({ "delay_ms": 8_000 }),
                false,
            ))
            .await;
        assert!(matches!(ticket, Response::Ticket { .. }), "{ticket:?}");
        eventually("the holder is leased", || async {
            queue
                .leased_ids()
                .await
                .contains(&"wedge_holder".to_owned())
        })
        .await;

        // ...and a waiting request with a short deadline queues behind it.
        let mut waiting = request("wedged", "echo", serde_json::json!({ "n": 2 }), true);
        waiting.deadline_ms = 500;
        let answer = live.submit(waiting).await;
        eventually("the waiter is queued", || async {
            state_of(&store, "wedged").await == Some(RequestState::Queued)
        })
        .await;
        assert_eq!(live.handle.admission_available().work, WORK_SLOTS - 1);

        // The queue wedges. At its deadline the handler tries to expire
        // the request through the queue and blocks there.
        let stall = queue.stall().await;
        let response = tokio::time::timeout(Duration::from_secs(5), answer)
            .await
            .expect("the caller is answered although the handler is wedged")
            .unwrap();
        assert_eq!(refusal(&response), (CAUSE_DEADLINE_EXCEEDED, true));

        // The slot is free and the terminal row is written — both while
        // the queue is still wedged.
        eventually("the slot is released", || async {
            live.handle.admission_available().work == WORK_SLOTS
        })
        .await;
        eventually("the terminal row is written", || async {
            state_of(&store, "wedged").await == Some(RequestState::Failed)
        })
        .await;
        let row = store.get_request("wedged").await.unwrap().unwrap();
        assert_eq!(row.outcome.as_deref(), Some(CAUSE_DEADLINE_EXCEEDED));
        let audit = store.audit_for_request("wedged").await.unwrap();
        assert_eq!(audit.len(), 1, "{audit:?}");
        assert_eq!(audit[0].action, ACTION_DEADLINE_REFUSAL);

        drop(stall);
        let _ = queue.cancel("wedge_holder", pam_store::Actor::System).await;
        live.stop().await;
    }

    /// A handler that is only parked on someone else's result must not hold
    /// its slot for a caller that has gone away.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_parked_handler_frees_its_slot_when_its_caller_goes_away() {
        let live = Live::start("relaxed", |_| {}).await;
        let store = live.store();
        let args = serde_json::json!({ "delay_ms": 6_000, "tag": "shared" });

        let ticket = live
            .ask(request("gone_original", "echo", args.clone(), false))
            .await;
        assert!(matches!(ticket, Response::Ticket { .. }), "{ticket:?}");

        // An identical request attaches and waits for the original.
        let mut duplicate = request("gone_duplicate", "echo", args, true);
        duplicate.deadline_ms = 30_000;
        let answer = live.submit(duplicate).await;
        eventually("the duplicate is parked", || async {
            live.handle.admission_available().work == WORK_SLOTS - 1
        })
        .await;

        // Its caller disconnects.
        drop(answer);
        eventually("the parked handler lets go of its slot", || async {
            live.handle.admission_available().work == WORK_SLOTS
        })
        .await;
        // The original was left alone and is still in flight.
        let state = state_of(&store, "gone_original").await.unwrap();
        assert!(
            !state.is_terminal(),
            "the original was disturbed: {state:?}"
        );

        let _ = live
            .handle
            .queue()
            .cancel("gone_original", pam_store::Actor::System)
            .await;
        live.stop().await;
    }

    /// The peer the framed listener saw, as a test passes it.
    fn kernel_peer(pid: u32, relayed: bool) -> PublicPeer {
        PublicPeer {
            identity: PeerIdentity::Unix {
                uid: 501,
                gid: 20,
                pid: Some(pid),
            },
            relayed,
        }
    }

    /// Admission writes where a request entered the daemon onto its row:
    /// the plane, and for a framed public connection the kernel's uid and
    /// pid and the relay marker — whatever the envelope says about itself.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn admission_records_the_plane_and_the_peer_on_the_request_row() {
        use pam_store::{RequestIngress, RequestOrigin};

        let live = Live::start("relaxed", |_| {}).await;
        let store = live.store();

        // A laned request from a framed connection.
        let mut laned = request("origin_laned", "echo", serde_json::json!({ "n": 1 }), true);
        laned.caller.agent = "pam-gui".to_owned();
        laned.caller.pid = 1;
        let response = live
            .ask_from(laned, Origin::Public, Some(kernel_peer(7_001, false)))
            .await;
        assert!(matches!(response, Response::Result { .. }), "{response:?}");
        let row = store.get_request("origin_laned").await.unwrap().unwrap();
        assert_eq!(
            row.origin,
            RequestOrigin {
                ingress: RequestIngress::Public,
                peer_uid: Some(501),
                peer_pid: Some(7_001),
                relayed: false,
            }
        );
        // The label is stored as what it is: a label.
        assert_eq!(row.caller_agent, "pam-gui");

        // A control request through a relay: a bypass row, same columns.
        let query = request(
            "origin_query",
            "query",
            serde_json::json!({ "ticket": "origin_laned" }),
            true,
        );
        let _ = live
            .ask_from(query, Origin::Public, Some(kernel_peer(7_002, true)))
            .await;
        let row = store.get_request("origin_query").await.unwrap().unwrap();
        assert_eq!(row.origin.peer_pid, Some(7_002));
        assert!(row.origin.relayed);

        // A request refused before admission (unknown capability) is
        // recorded with its origin too.
        let unknown = request("origin_unknown", "frobnicate", serde_json::json!({}), true);
        let response = live
            .ask_from(unknown, Origin::Public, Some(kernel_peer(7_003, false)))
            .await;
        assert!(matches!(response, Response::Refusal { .. }), "{response:?}");
        let row = store.get_request("origin_unknown").await.unwrap().unwrap();
        assert_eq!(row.origin.peer_pid, Some(7_003));

        // A public request submitted with no peer records none.
        let _ = live
            .ask(request(
                "origin_legacy",
                "echo",
                serde_json::json!({ "n": 2 }),
                true,
            ))
            .await;
        let row = store.get_request("origin_legacy").await.unwrap().unwrap();
        assert_eq!(row.origin, RequestOrigin::PUBLIC);

        // What the private plane submits is recorded as such, with no peer
        // claimed for an in-process submission.
        let admin = request("origin_admin", "echo", serde_json::json!({ "n": 3 }), true);
        let response = live.ask_from(admin, Origin::Admin, None).await;
        assert!(matches!(response, Response::Result { .. }), "{response:?}");
        let row = store.get_request("origin_admin").await.unwrap().unwrap();
        assert_eq!(row.origin, RequestOrigin::ADMIN);

        live.stop().await;
    }

    /// The pipeline never judges a request by its envelope's version: the
    /// hello of the connection it came on went through the version rule on
    /// its listener, and what the administration plane submits in process
    /// came from a connection that did. The field is recorded, nothing more.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_request_is_never_judged_by_its_envelope_version() {
        let live = Live::start("relaxed", |_| {}).await;

        let mut public = request("ver_public", "echo", serde_json::json!({ "n": 1 }), true);
        public.client_version = "0.0.1".to_owned();
        let response = live
            .ask_from(public, Origin::Public, Some(kernel_peer(7_010, false)))
            .await;
        assert!(matches!(response, Response::Result { .. }), "{response:?}");

        let mut admin = request("ver_admin", "echo", serde_json::json!({ "n": 2 }), true);
        admin.client_version = "0.0.1".to_owned();
        let response = live.ask_from(admin, Origin::Admin, None).await;
        assert!(matches!(response, Response::Result { .. }), "{response:?}");

        // Neither moved the phase: a claimed version restarts nothing.
        assert_eq!(
            *live.handle.lifecycle().borrow(),
            crate::lifecycle::LifecyclePhase::Serving
        );
        live.stop().await;
    }

    /// A ticket whose lifecycle events are published is registered with the
    /// hub at admission, so the administration plane's stream can name it,
    /// and is gone from the hub once it ends. Control requests publish
    /// nothing and are never registered.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn tickets_are_registered_with_the_hub_at_admission_and_forgotten_at_the_end() {
        use pam_proto::Event;
        use pam_proto::wire::Ingress as WireIngress;

        use crate::event_hub::Subscribed;

        let live = Live::start("relaxed", |_| {}).await;
        let hub = live.handle.event_hub();
        let mut all = hub.subscribe_all().expect("a subscriber slot");
        let mut next = async || match tokio::time::timeout(PATIENCE, all.next()).await {
            Ok(Subscribed::Event(event)) => event,
            other => panic!("expected an event, got {other:?}"),
        };

        // A laned request: every event carries what admission knew.
        let response = live
            .ask(request(
                "hub_laned",
                "echo",
                serde_json::json!({ "n": 1 }),
                true,
            ))
            .await;
        assert!(matches!(response, Response::Result { .. }), "{response:?}");
        for expected in [Event::Queued, Event::Started, Event::Done] {
            let event = next().await;
            assert_eq!(
                (event.ticket.as_str(), &event.event),
                ("hub_laned", &expected)
            );
            let meta = event.meta.expect("registered at admission");
            assert_eq!(meta.capability, "echo");
            assert_eq!(meta.repo, REPO);
            assert_eq!(meta.agent, "claude");
            assert_eq!(meta.ingress, WireIngress::Public);
        }

        // The same request from the private plane is named as such.
        let admin = request("hub_admin", "echo", serde_json::json!({ "n": 2 }), true);
        let _ = live.ask_from(admin, Origin::Admin, None).await;
        for _ in 0..3 {
            let event = next().await;
            assert_eq!(event.ticket, "hub_admin");
            assert_eq!(
                event.meta.expect("registered at admission").ingress,
                WireIngress::Admin
            );
        }

        // A request refused before admission still names itself.
        let _ = live
            .ask(request(
                "hub_unknown",
                "frobnicate",
                serde_json::json!({}),
                true,
            ))
            .await;
        let event = next().await;
        assert_eq!(
            (event.ticket.as_str(), &event.event),
            ("hub_unknown", &Event::Refused)
        );
        assert_eq!(
            event
                .meta
                .expect("registered before the refusal")
                .capability,
            "frobnicate"
        );

        // A read-only bypass is registered and ends in its handler.
        let _ = live
            .ask(request(
                "hub_bypass",
                "flow.list",
                serde_json::json!({}),
                true,
            ))
            .await;
        let event = next().await;
        assert_eq!(
            (event.ticket.as_str(), &event.event),
            ("hub_bypass", &Event::Started)
        );
        assert_eq!(
            event.meta.expect("registered at admission").capability,
            "flow.list"
        );
        let event = next().await;
        assert_eq!(event.ticket, "hub_bypass");

        // Control requests publish nothing, so there is nothing to name.
        let _ = live
            .ask(request(
                "hub_query",
                "query",
                serde_json::json!({ "ticket": "hub_laned" }),
                true,
            ))
            .await;
        let _ = live
            .ask(request("hub_status", "status", serde_json::json!({}), true))
            .await;
        assert_eq!(all.queued(), 0, "a control request published an event");

        // Everything that ended is gone from the hub's table.
        eventually("the hub forgot every finished ticket", || async {
            hub.usage().entries == 0
        })
        .await;

        drop(all);
        live.stop().await;
    }

    /// A poll leaves nothing behind: it used to cost a request row, an
    /// audit row and a caller-registry write, 86k rows a day from one GUI.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn status_leaves_no_row_no_audit_and_no_caller_entry() {
        let live = Live::start("relaxed", |_| {}).await;
        let store = live.store();

        for index in 0..20 {
            let id = format!("poll_{index}");
            let mut envelope = request(&id, "status", serde_json::json!({}), index % 2 == 0);
            envelope.caller.agent = "poller".to_owned();
            let response = live.ask(envelope).await;
            let Response::Result { outcome, body, .. } = &response else {
                panic!("status answers a result whether or not asked to wait: {response:?}");
            };
            assert_eq!(*outcome, Outcome::Verified);
            assert_eq!(body["daemon_version"], env!("CARGO_PKG_VERSION"));
            assert!(body["snapshot"]["stale"].is_boolean(), "{body}");
            assert_eq!(
                body["active_requests"], 0,
                "a poll is not an active request"
            );
            assert!(
                store.get_request(&id).await.unwrap().is_none(),
                "status wrote a request row"
            );
            assert!(store.audit_for_request(&id).await.unwrap().is_empty());
        }
        assert!(
            !store
                .list_callers()
                .await
                .unwrap()
                .iter()
                .any(|caller| caller.agent == "poller"),
            "status wrote to the caller registry"
        );
        assert_eq!(store.count_inflight().await.unwrap(), 0);
        let free = live.handle.admission_available();
        assert_eq!((free.status, free.control), (STATUS_SLOTS, CONTROL_SLOTS));
        live.stop().await;
    }

    /// The other half of issue 35: with every control slot pinned by polls
    /// stuck behind slow bookkeeping, the daemon refused `status` and
    /// `cancel` — the remedy its own refusal text recommends.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn polls_stuck_behind_wedged_bookkeeping_cannot_starve_status_or_cancel() {
        let live = Live::start("relaxed", |_| {}).await;
        let queue = live.handle.queue();
        let stall = queue.stall().await;

        // Sixteen queries block in admission and hold every control slot.
        let mut stuck = Vec::new();
        for index in 0..CONTROL_SLOTS {
            stuck.push(
                live.submit(request(
                    &format!("stuck_{index}"),
                    "query",
                    serde_json::json!({ "ticket": "none" }),
                    true,
                ))
                .await,
            );
        }
        eventually("the control pool is exhausted", || async {
            live.handle.admission_available().control == 0
        })
        .await;

        // One more query is refused at once, and says it may be retried.
        let refused = live
            .ask(request(
                "one_too_many",
                "query",
                serde_json::json!({ "ticket": "none" }),
                true,
            ))
            .await;
        assert_eq!(refusal(&refused), (CAUSE_REQUEST_CAPACITY, true));

        // `status` still answers: it has its own slots and waits on nothing.
        let status = tokio::time::timeout(
            Duration::from_secs(4),
            live.submit(request("alive", "status", serde_json::json!({}), true))
                .await,
        )
        .await
        .expect("status answers while the queue is wedged")
        .unwrap();
        assert!(matches!(status, Response::Result { .. }), "{status:?}");

        // `cancel` is admitted from its own headroom instead of refused.
        let cancel = live
            .submit(request(
                "still_cancellable",
                "cancel",
                serde_json::json!({ "ticket": "none" }),
                true,
            ))
            .await;
        eventually("cancel took its reserved slot", || async {
            live.handle.admission_available().cancel == CANCEL_SLOTS - 1
        })
        .await;

        drop(stall);
        let cancelled = tokio::time::timeout(PATIENCE, cancel)
            .await
            .unwrap()
            .unwrap();
        assert!(
            matches!(cancelled, Response::Result { .. }),
            "{cancelled:?}"
        );
        for answer in stuck {
            // Each stuck poll is answered (the ticket does not exist).
            tokio::time::timeout(PATIENCE, answer)
                .await
                .unwrap()
                .unwrap();
        }
        eventually("every slot comes back", || async {
            let free = live.handle.admission_available();
            (free.control, free.cancel) == (CONTROL_SLOTS, CANCEL_SLOTS)
        })
        .await;
        live.stop().await;
    }

    /// A duplicate attached to a request that the gate then refuses used to
    /// wait out its whole deadline: only approval refusals went through the
    /// router.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_gate_refusal_releases_attached_duplicates_and_leaves_no_router_entry() {
        // Standard profile, nothing granted: `echo` is refused at the gate.
        let live = Live::start("standard", |_| {}).await;
        let router = live.handle.router();

        // An attached duplicate is a waiter registered on the original's id.
        let Registration::Pending(attached) = router.register("refused_original").await else {
            panic!("nothing has finished yet");
        };
        let response = live
            .ask(request(
                "refused_original",
                "echo",
                serde_json::json!({ "msg": "hi" }),
                true,
            ))
            .await;
        assert_eq!(
            refusal(&response),
            (crate::policy::CAUSE_NOT_GRANTED, false)
        );

        let forwarded = tokio::time::timeout(Duration::from_secs(3), attached)
            .await
            .expect("the attached duplicate is released with the refusal")
            .unwrap();
        assert_eq!(forwarded, response);
        assert_eq!(router.usage().await.waiting, 0);
        live.stop().await;
    }

    /// `let _ = store.finish_request(..)`: a bypass whose terminal write
    /// failed used to be answered as done, with no log line, leaving the
    /// row `running` until the next boot.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_bypass_whose_terminal_write_fails_is_not_reported_done_and_is_recorded_later() {
        let live = Live::start("relaxed", |_| {}).await;
        let store = live.store();
        let terminals = Arc::clone(&live.handle.admin().terminals);

        // The store refuses all three attempts of the next terminal write.
        terminals.fail_next(3);
        let response = live
            .ask(request(
                "unrecorded",
                "cancel",
                serde_json::json!({ "ticket": "no_such_ticket" }),
                true,
            ))
            .await;
        assert_eq!(refusal(&response), (CAUSE_INTERNAL_ERROR, true));
        assert_eq!(
            state_of(&store, "unrecorded").await,
            Some(RequestState::Running)
        );
        assert_eq!(terminals.parked_count(), 1);

        // The maintenance loop records the verdict once the store takes it.
        eventually("the parked verdict is recorded", || async {
            state_of(&store, "unrecorded").await == Some(RequestState::Done)
        })
        .await;
        assert_eq!(terminals.parked_count(), 0);
        let audit = store.audit_for_request("unrecorded").await.unwrap();
        assert_eq!(audit.len(), 1);
        assert_eq!(audit[0].action, ACTION_EXECUTE);
        live.stop().await;
    }

    /// The same bypass when the store turned the terminal write down at its
    /// queue bound: the caller is told the store is overloaded, in words,
    /// and to retry, instead of a bare "internal error".
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_bypass_whose_terminal_write_meets_the_store_queue_bound_says_store_overloaded() {
        let live = Live::start("relaxed", |_| {}).await;
        let store = live.store();
        let terminals = Arc::clone(&live.handle.admin().terminals);

        terminals.fail_next_overloaded(3);
        let response = live
            .ask(request(
                "overloaded",
                "cancel",
                serde_json::json!({ "ticket": "no_such_ticket" }),
                true,
            ))
            .await;
        assert_eq!(refusal(&response), (CAUSE_STORE_OVERLOADED, true));
        let Response::Refusal {
            detail, recovery, ..
        } = &response
        else {
            unreachable!()
        };
        assert!(
            detail.contains("calls waiting for the database"),
            "{detail}"
        );
        assert!(detail.contains("queued to be recorded"), "{detail}");
        assert_eq!(recovery, "Retry shortly.");
        assert_eq!(terminals.parked_count(), 1);

        // Nothing was lost: the verdict is recorded once the store keeps up.
        eventually("the parked verdict is recorded", || async {
            state_of(&store, "overloaded").await == Some(RequestState::Done)
        })
        .await;
        live.stop().await;
    }

    /// A store that is already closed answers every call with "the daemon
    /// is shutting down". A public request that reaches it used to be told
    /// "internal error"; it is told the truth, as a refusal to retry.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_public_request_that_meets_the_closed_store_is_told_the_daemon_is_shutting_down() {
        let live = Live::start("relaxed", |_| {}).await;
        // What the end of a shutdown does, while the dispatcher still runs.
        live.store().close().await.unwrap();

        for (id, capability, args) in [
            // Laned work, refused at admission.
            ("closed_echo", "echo", serde_json::json!({ "msg": "hi" })),
            // A control request, refused at admission too.
            (
                "closed_cancel",
                "cancel",
                serde_json::json!({ "ticket": "no_such_ticket" }),
            ),
            // No class: the row insert itself meets the closed store.
            (
                "closed_unknown",
                "no.such.capability",
                serde_json::json!({}),
            ),
        ] {
            let response = live.ask(request(id, capability, args, true)).await;
            assert_eq!(
                refusal(&response),
                (CAUSE_DAEMON_SHUTTING_DOWN, true),
                "{id}: {response:?}"
            );
            let Response::Refusal {
                detail, recovery, ..
            } = &response
            else {
                unreachable!()
            };
            assert!(detail.contains("the store is closed"), "{id}: {detail}");
            assert!(detail.contains("nothing was written"), "{id}: {detail}");
            assert!(recovery.starts_with("Retry shortly"), "{id}: {recovery}");
        }

        // The private plane keeps the store's own sentence too, under its
        // own cause.
        let mut admin = pam_testkit::envelope_for_repo(
            crate::admin::ADMIN_REPO,
            "closed_admin",
            crate::admin::OP_GRANTS_LIST,
            serde_json::json!({}),
            true,
        );
        crate::admin::ADMIN_CALLER_AGENT.clone_into(&mut admin.caller.agent);
        let response = live.handle.admin().handle(&admin).await;
        let Response::Refusal { cause, detail, .. } = &response else {
            panic!("expected a refusal, got {response:?}");
        };
        assert_eq!(cause, CAUSE_INTERNAL_ERROR);
        assert!(
            detail.contains("the store is closed: the pam daemon is shutting down"),
            "{detail}"
        );
        // Closing twice is harmless: the shutdown closes it again.
        live.stop().await;
    }

    /// An execution that outlives the drain finds the store closed when it
    /// ends. Its verdict cannot be recorded by this daemon, so it is not
    /// parked and its waiter is not told a result the next boot will not
    /// show: it is told the daemon is shutting down.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_leased_request_that_ends_on_a_closed_store_is_not_parked_and_not_reported_done() {
        let live = Live::start("relaxed", |_| {}).await;
        let store = live.store();
        let terminals = Arc::clone(&live.handle.admin().terminals);

        let mut slow = request(
            "outlived",
            "echo",
            serde_json::json!({ "delay_ms": 600 }),
            true,
        );
        slow.deadline_ms = 30_000;
        let answer = live.submit(slow).await;
        eventually("the echo is running", || async {
            state_of(&store, "outlived").await == Some(RequestState::Running)
        })
        .await;
        store.close().await.unwrap();

        let started = std::time::Instant::now();
        let response = tokio::time::timeout(PATIENCE, answer)
            .await
            .expect("an answer within the test's patience")
            .expect("the daemon answers every admitted request");
        assert_eq!(
            refusal(&response),
            (CAUSE_DAEMON_SHUTTING_DOWN, true),
            "{response:?}"
        );
        assert_eq!(terminals.parked_count(), 0);
        // The echo's own 600 ms, without two backoff pauses on top that a
        // closed store would have made pointless; generous for a loaded host.
        assert!(started.elapsed() < Duration::from_secs(5));
        live.stop().await;
    }

    /// A model verification still hashing when the daemon stops: the
    /// shutdown stops it and its follower records why before the store
    /// closes, so the row a reopened store shows is finished, not `running`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_model_job_running_at_shutdown_is_recorded_before_the_store_closes() {
        let live = Live::start("relaxed", |_| {}).await;
        let models = live.handle.models();
        let dir = tempfile::tempdir().unwrap();
        models.set_models_dir(dir.path()).await.unwrap();
        // Sparse: no disk, and still hashing long after the stop begins.
        let big = dir.path().join("qwen").join("big.gguf");
        std::fs::create_dir_all(big.parent().unwrap()).unwrap();
        std::fs::File::create(&big)
            .unwrap()
            .set_len(768 * 1024 * 1024)
            .unwrap();
        let entry = models.find("qwen/big").await.unwrap().unwrap();
        let job = models.start_verify(entry).await.unwrap();
        drop(models);

        let tmp = live.stop_keeping_base().await;

        // Reopening the file runs no recovery of model jobs (that is the
        // model service's, at the next daemon start): this is what the
        // stopped daemon itself wrote.
        let store = pam_testkit::open_store(&tmp).await;
        let rows = store.list_model_jobs(10).await.unwrap();
        let row = rows.iter().find(|row| row.id == job).expect("the job row");
        assert_eq!(row.state, crate::model_service::JOB_FAILED, "{row:?}");
        let detail = row.detail.as_deref().unwrap_or_default();
        assert!(
            detail.contains(crate::model_service::CAUSE_DAEMON_RESTART),
            "{detail}"
        );
        assert!(
            detail.contains("the daemon stopped while this job was running"),
            "{detail}"
        );
        store.close().await.unwrap();
    }

    /// The hub removes a ticket when its terminal event is published. A
    /// bypass whose verdict is parked for retry publishes none, and must not
    /// hold a slot of the hub's table until the table is full.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_bypass_that_ends_without_a_terminal_event_is_forgotten_by_the_hub() {
        let live = Live::start("relaxed", |_| {}).await;
        let store = live.store();
        let terminals = Arc::clone(&live.handle.admin().terminals);
        let hub = live.handle.event_hub();

        terminals.fail_next(3);
        let response = live
            .ask(request(
                "hub_parked",
                "flow.list",
                serde_json::json!({}),
                true,
            ))
            .await;
        assert_eq!(refusal(&response), (CAUSE_INTERNAL_ERROR, true));
        assert_eq!(terminals.parked_count(), 1);
        // `started` was published, `done` was not.
        assert_eq!(hub.usage().entries, 0);

        eventually("the parked verdict is recorded", || async {
            state_of(&store, "hub_parked").await == Some(RequestState::Done)
        })
        .await;
        live.stop().await;
    }

    /// A failed terminal write after a successful execution used to strand
    /// the lane until the lease deadline and turn the real result into
    /// `deadline_exceeded`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_leased_request_whose_terminal_write_fails_frees_its_lane_and_keeps_its_result() {
        let live = Live::start("relaxed", |_| {}).await;
        let store = live.store();

        // Every attempt to complete the first lease fails.
        live.handle.queue().fail_next_completes(3);
        let mut first = request(
            "unrecorded_lease",
            "echo",
            serde_json::json!({ "n": 1 }),
            true,
        );
        first.deadline_ms = 30_000;
        let response = live.ask(first).await;
        let Response::Result { body, .. } = &response else {
            panic!("the work ran; its waiter gets the result: {response:?}");
        };
        assert_eq!(body["echo"]["n"], 1);

        // The lane is free at once: a second request on the same repo runs
        // long before the first one's thirty-second lease would expire.
        let mut second = request("next_on_lane", "echo", serde_json::json!({ "n": 2 }), true);
        second.deadline_ms = 4_000;
        let response = live.ask(second).await;
        assert!(matches!(response, Response::Result { .. }), "{response:?}");

        // And the first row is recorded as what it was, not as an expiry.
        eventually("the parked verdict is recorded", || async {
            state_of(&store, "unrecorded_lease").await == Some(RequestState::Done)
        })
        .await;
        let audit = store.audit_for_request("unrecorded_lease").await.unwrap();
        assert!(
            audit.iter().any(|row| row.action == ACTION_EXECUTE),
            "{audit:?}"
        );
        live.stop().await;
    }
}

mod cancel_plane {
    //! Who may cancel what, and who the audit says did it.

    use std::sync::Arc;
    use std::time::Duration;

    use pam_proto::{Caller, Envelope, Outcome, PROTOCOL_VERSION, Response};
    use pam_store::{Actor, RequestState, Store};
    use tokio::sync::{oneshot, watch};

    use crate::admin::{ADMIN_CALLER_AGENT, OP_REQUESTS_CANCEL};
    use crate::daemon::{DAEMON_VERSION, DaemonConfig, DaemonHandle, run_daemon_with};
    use crate::ingress::Origin;
    use crate::queue::CAUSE_CANCELLED;
    use crate::secrets::FakeSecretBackend;
    use crate::transport::IncomingRequest;

    fn public(id: &str, repo: &str, capability: &str, args: serde_json::Value) -> Envelope {
        pam_testkit::envelope_for_repo(repo, id, capability, args, true)
    }

    /// Sends one public request into the dispatcher and awaits its answer.
    async fn ask(handle: &DaemonHandle, envelope: Envelope) -> Response {
        let (reply, answer) = oneshot::channel();
        handle
            .admin()
            .submit
            .send(IncomingRequest {
                origin: Origin::Public,
                peer: None,
                envelope,
                reply,
            })
            .await
            .unwrap();
        answer.await.unwrap()
    }

    /// The GUI's cancel, as it arrives on the private plane.
    fn human_cancel(ticket: &str) -> Envelope {
        Envelope {
            v: PROTOCOL_VERSION,
            id: "human_cancel".to_owned(),
            capability: OP_REQUESTS_CANCEL.to_owned(),
            client_version: DAEMON_VERSION.to_owned(),
            caller: Caller {
                agent: ADMIN_CALLER_AGENT.to_owned(),
                repo: "gui".to_owned(),
                pid: std::process::id(),
            },
            args: serde_json::json!({ "ticket": ticket }),
            idempotency_key: None,
            deadline_ms: 10_000,
            wait: true,
        }
    }

    async fn terminal_row(store: &Store, id: &str) -> pam_store::RequestRow {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        loop {
            let row = store.get_request(id).await.unwrap().unwrap();
            if row.state.is_terminal() {
                return row;
            }
            assert!(tokio::time::Instant::now() < deadline, "{id} never ended");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_public_cancel_is_bound_to_its_repository_and_the_admin_cancel_is_the_humans() {
        tokio::time::timeout(Duration::from_secs(30), async {
            let tmp = pam_testkit::short_tempdir();
            pam_testkit::seed_relaxed(&tmp).await;
            let (shutdown, shutdown_rx) = watch::channel(false);
            let handle = run_daemon_with(
                DaemonConfig {
                    base_dir: Some(pam_testkit::base_of(&tmp)),
                    secret_backend: Some(Arc::new(FakeSecretBackend::default())),
                    ..DaemonConfig::default()
                },
                shutdown_rx,
            )
            .await
            .unwrap();
            let store = handle.store();

            // The victim's long-running request, under its own repository.
            let mut victim = public(
                "victim_run",
                "/repo/victim",
                "echo",
                serde_json::json!({ "delay_ms": 20_000 }),
            );
            victim.wait = false;
            assert!(matches!(
                ask(&handle, victim).await,
                Response::Ticket { .. }
            ));

            // Another repository learns the id from the public event socket
            // and tries to cancel it, calling itself the GUI for good measure.
            let mut forged = public(
                "forged_cancel",
                "/repo/attacker",
                "cancel",
                serde_json::json!({ "ticket": "victim_run" }),
            );
            forged.caller.agent = ADMIN_CALLER_AGENT.to_owned();
            let Response::Result { outcome, body, .. } = ask(&handle, forged).await else {
                panic!("cancel answers a result");
            };
            assert_eq!(outcome, Outcome::Unresolved);
            assert_eq!(body["result"], "not_found");
            let row = store.get_request("victim_run").await.unwrap().unwrap();
            assert!(
                !row.state.is_terminal(),
                "a foreign cancel reached the ticket"
            );
            // The forged request is on record as a system-audited request
            // that changed nothing: the label made nobody a human.
            let forged_audit = store.audit_for_request("forged_cancel").await.unwrap();
            assert_eq!(forged_audit.len(), 1);
            assert_eq!(forged_audit[0].actor, Actor::System);

            // The human cancels it from the GUI, over the private plane.
            let response = handle.admin().handle(&human_cancel("victim_run")).await;
            let Response::Result { body, .. } = &response else {
                panic!("the admin cancel answers a result: {response:?}");
            };
            assert_eq!(body["ticket"], "victim_run");
            assert!(
                body["result"] == "signalled_running" || body["result"] == "cancelled_queued",
                "{body}"
            );

            // The ticket ends cancelled, and the admin op is the human's.
            let row = terminal_row(&store, "victim_run").await;
            assert_eq!(row.state, RequestState::Failed);
            assert_eq!(row.outcome.as_deref(), Some(CAUSE_CANCELLED));
            let human = store.audit_for_request("human_cancel").await.unwrap();
            assert_eq!(human.len(), 1);
            assert_eq!(human[0].actor, Actor::Human);

            let _ = shutdown.send(true);
            handle.shutdown().await;
        })
        .await
        .expect("test within deadline");
    }
}

mod reply_guard {
    use std::sync::Arc;

    use pam_proto::Response;
    use tokio::sync::{Semaphore, oneshot, watch};

    use crate::daemon::{CAUSE_DAEMON_SHUTTING_DOWN, CAUSE_INTERNAL_ERROR, ReplyGuard};
    use crate::lifecycle::LifecyclePhase;

    fn guard(
        slots: &Arc<Semaphore>,
        phase: LifecyclePhase,
    ) -> (ReplyGuard, oneshot::Receiver<Response>) {
        let (reply, answer) = oneshot::channel();
        let (phase, _) = watch::channel(phase);
        let permit = Arc::clone(slots).try_acquire_owned().unwrap();
        (
            ReplyGuard::new("req_guard".to_owned(), reply, phase.subscribe(), permit),
            answer,
        )
    }

    /// A handler that ends without answering — a panic, an abort, a bug —
    /// used to leave its caller waiting and, on the transport side, its
    /// permit held. The guard answers and releases on drop.
    #[test]
    fn dropping_an_unanswered_guard_answers_the_caller_and_frees_the_slot() {
        let slots = Arc::new(Semaphore::new(1));
        let (guard, mut answer) = guard(&slots, LifecyclePhase::Serving);
        assert_eq!(slots.available_permits(), 0);
        drop(guard);
        assert_eq!(slots.available_permits(), 1);
        let Response::Refusal {
            id,
            cause,
            retryable,
            ..
        } = answer.try_recv().expect("the caller is answered")
        else {
            panic!("a refusal");
        };
        assert_eq!(id, "req_guard");
        assert_eq!(cause, CAUSE_INTERNAL_ERROR);
        assert!(retryable);
    }

    #[test]
    fn a_guard_dropped_while_draining_says_the_daemon_is_shutting_down() {
        let slots = Arc::new(Semaphore::new(1));
        let (guard, mut answer) = guard(&slots, LifecyclePhase::Draining);
        drop(guard);
        let Response::Refusal { cause, .. } = answer.try_recv().unwrap() else {
            panic!("a refusal");
        };
        assert_eq!(cause, CAUSE_DAEMON_SHUTTING_DOWN);
        assert_eq!(slots.available_permits(), 1);
    }

    #[test]
    fn only_the_first_answer_is_sent_and_a_closed_caller_still_frees_the_slot() {
        let slots = Arc::new(Semaphore::new(2));
        let (mut answered, mut answer) = guard(&slots, LifecyclePhase::Serving);
        answered.send(Response::refusal("req_guard", "first", "d", "r"));
        answered.send(Response::refusal("req_guard", "second", "d", "r"));
        drop(answered);
        let Response::Refusal { cause, .. } = answer.try_recv().unwrap() else {
            panic!("a refusal");
        };
        assert_eq!(cause, "first");

        // The caller hung up before any answer: nothing to send, and the
        // slot is released all the same.
        let (unheard, answer) = guard(&slots, LifecyclePhase::Serving);
        drop(answer);
        drop(unheard);
        assert_eq!(slots.available_permits(), 2);
    }
}
