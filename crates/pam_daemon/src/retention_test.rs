use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::Duration;

use pam_store::{
    Actor, AuditEntry, Decision, RefusalRecord, RefusalWrite, RequestIngress, RequestState, Store,
    StoreError,
};

use crate::retention::{
    CAUSE_CLOCK_JUMP, CensusSource, GuardPolicy, KEEP_KIND, MAX_DAYS, PassCensus, PassOutcome,
    PruneReport, RECOVERY_CLOCK_JUMP, RetentionPatch, RetentionRefusal, RetentionService,
    RetentionSettings, SETTING_AUDIT_DAYS, SETTING_CLOCK_GUARD, SETTING_EVIDENCE_DAYS,
    SETTING_LAST_RUN, SETTING_WATERMARK, Trigger, validate,
};

const DAY: i64 = 86_400;

/// A retention service over a fresh in-memory store, plus the store
/// itself so a test can seed rows and read them back.
async fn service() -> (Arc<Store>, RetentionService) {
    let store = Arc::new(Store::open_in_memory().await.unwrap());
    (
        Arc::clone(&store),
        RetentionService::new(store, crate::managed_policy_service::PolicyHandle::none()),
    )
}

/// One request that has already finished, so a prune may touch it.
async fn finished_request(store: &Store, id: &str) {
    store
        .insert_request(id, "release", "ro-ag/pam", "claude", "{}", None)
        .await
        .unwrap();
    store
        .finish_request(
            id,
            RequestState::Done,
            None,
            AuditEntry {
                action: "execute",
                decision: Decision::Allow,
                actor: Actor::System,
                detail: None,
            },
        )
        .await
        .unwrap();
}

#[tokio::test]
async fn unset_keys_read_as_forever() {
    let (_store, service) = service().await;
    assert_eq!(
        service.settings().await.unwrap(),
        RetentionSettings::default()
    );
    assert_eq!(service.last_run().await.unwrap(), None);
}

#[tokio::test]
async fn set_persists_and_merges() {
    let (store, service) = service().await;
    let got = service
        .set_settings(RetentionPatch {
            audit_days: Some(Some(365)),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(
        got,
        RetentionSettings {
            evidence_days: None,
            audit_days: Some(365)
        }
    );

    let got = service
        .set_settings(RetentionPatch {
            evidence_days: Some(Some(90)),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(
        got,
        RetentionSettings {
            evidence_days: Some(90),
            audit_days: Some(365)
        }
    );
    assert_eq!(
        store
            .get_setting(SETTING_EVIDENCE_DAYS)
            .await
            .unwrap()
            .as_deref(),
        Some("90")
    );

    // `Some(None)` is the explicit "forever" a select sends back.
    let got = service
        .set_settings(RetentionPatch {
            evidence_days: Some(None),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(got.evidence_days, None);
}

#[tokio::test]
async fn evidence_longer_than_audit_refuses_and_writes_nothing() {
    let (_store, service) = service().await;
    service
        .set_settings(RetentionPatch {
            audit_days: Some(Some(90)),
            ..Default::default()
        })
        .await
        .unwrap();

    let err = service
        .set_settings(RetentionPatch {
            evidence_days: Some(Some(365)),
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert!(matches!(err, RetentionRefusal::Invalid { .. }));
    assert_eq!(service.settings().await.unwrap().evidence_days, None);

    // Forever evidence under a finite audit window is not that
    // violation: the record's own window takes its evidence with it.
    let got = service
        .set_settings(RetentionPatch {
            evidence_days: Some(None),
            audit_days: Some(Some(30)),
        })
        .await
        .unwrap();
    assert_eq!(
        got,
        RetentionSettings {
            evidence_days: None,
            audit_days: Some(30)
        }
    );
}

#[test]
fn validate_bounds_and_order() {
    assert!(
        validate(RetentionSettings {
            evidence_days: Some(0),
            audit_days: None
        })
        .is_err()
    );
    assert!(
        validate(RetentionSettings {
            evidence_days: None,
            audit_days: Some(MAX_DAYS + 1)
        })
        .is_err()
    );
    assert!(
        validate(RetentionSettings {
            evidence_days: Some(30),
            audit_days: Some(30)
        })
        .is_ok()
    );
    assert!(
        validate(RetentionSettings {
            evidence_days: Some(30),
            audit_days: None
        })
        .is_ok()
    );
    // Forever evidence never breaks the order: the audit window takes
    // the whole record, evidence included.
    assert!(
        validate(RetentionSettings {
            evidence_days: None,
            audit_days: Some(30)
        })
        .is_ok()
    );
    assert!(
        validate(RetentionSettings {
            evidence_days: Some(365),
            audit_days: Some(90)
        })
        .is_err()
    );
    assert!(validate(RetentionSettings::default()).is_ok());
}

#[tokio::test]
async fn prune_applies_both_windows_and_records_the_run() {
    let (store, service) = service().await;
    finished_request(&store, "r1").await;
    store
        .insert_evidence("ev1", "r1", "log.source", b"abcdef", None)
        .await
        .unwrap();
    store
        .insert_evidence("ev2", "r1", "flow.result", b"{}", None)
        .await
        .unwrap();
    let now = crate::retention::now_ts();

    // No windows: nothing goes, but the run is recorded.
    let report = service.prune(now).await.unwrap();
    assert_eq!(
        report,
        PruneReport {
            ts: now,
            evidence_rows: 0,
            evidence_bytes: 0,
            requests: 0,
            audit_rows: 0,
        }
    );
    assert_eq!(service.last_run().await.unwrap(), Some(report));

    // Evidence window only, seen from 40 days ahead: the source goes,
    // the verdict stays.
    service
        .set_settings(RetentionPatch {
            evidence_days: Some(Some(30)),
            ..Default::default()
        })
        .await
        .unwrap();
    let report = service.prune(now + 40 * DAY).await.unwrap();
    assert_eq!(
        (report.evidence_rows, report.evidence_bytes, report.requests),
        (1, 6, 0)
    );
    assert!(store.get_evidence("ev2").await.unwrap().is_some());

    // Audit window too, seen from 100 days ahead: the whole record goes.
    service
        .set_settings(RetentionPatch {
            audit_days: Some(Some(90)),
            ..Default::default()
        })
        .await
        .unwrap();
    let report = service.prune(now + 100 * DAY).await.unwrap();
    assert_eq!(
        (report.requests, report.audit_rows, report.evidence_rows),
        (1, 1, 1)
    );
    assert!(store.get_request("r1").await.unwrap().is_none());
}

#[tokio::test(start_paused = true)]
async fn scheduler_waits_out_the_first_delay_then_prunes_and_stops_on_shutdown() {
    let (store, service) = service().await;
    let (tx, rx) = tokio::sync::watch::channel(false);
    let first_delay = Duration::from_mins(2);
    let task = service
        .clone()
        .run_scheduler(first_delay, Duration::from_hours(1), rx);

    // Just short of the delay: nothing has run, so boot recovery and the
    // first requests have the store to themselves.
    tokio::time::sleep(Duration::from_secs(119)).await;
    for _ in 0..10 {
        tokio::task::yield_now().await;
    }
    assert!(
        service.last_run().await.unwrap().is_none(),
        "no prune before the first delay"
    );

    // Past it: the first scheduled pass runs.
    tokio::time::sleep(Duration::from_secs(2)).await;
    tokio::time::timeout(Duration::from_secs(5), async {
        while service.last_run().await.unwrap().is_none() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the first pass runs once the delay is over");

    tx.send(true).unwrap();
    tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .expect("stops on drain")
        .unwrap();
    drop(store);
}

/// The daemon's first prune waits, but not so long that a daemon running
/// for minutes never prunes.
#[test]
fn the_first_prune_delay_is_short_against_the_interval() {
    assert!(crate::retention::FIRST_PRUNE_DELAY > Duration::ZERO);
    assert!(crate::retention::FIRST_PRUNE_DELAY * 10 <= crate::retention::PRUNE_INTERVAL);
}

#[tokio::test]
async fn a_stored_window_out_of_range_reads_as_forever_and_prunes_nothing() {
    let (store, service) = service().await;
    finished_request(&store, "kept").await;
    // Not reachable through a save (validate refuses it): a hand-edited or
    // damaged setting. A zero window would make every finished record old.
    for raw in ["0", "999999"] {
        store.set_setting(SETTING_AUDIT_DAYS, raw).await.unwrap();
        store.set_setting(SETTING_EVIDENCE_DAYS, raw).await.unwrap();
        assert_eq!(
            service.settings().await.unwrap(),
            RetentionSettings::default(),
            "stored {raw}"
        );
        let report = service.prune(i64::MAX / 4).await.unwrap();
        assert_eq!(report.requests, 0, "stored {raw}");
        assert!(store.get_request("kept").await.unwrap().is_some());
    }
}

#[tokio::test]
async fn a_save_writes_both_windows_as_one_validated_pair() {
    let (store, service) = service().await;
    // A stale evidence window left behind by an earlier state: on its own
    // it would outlive the audit window this save sets.
    store
        .set_setting(SETTING_EVIDENCE_DAYS, "90")
        .await
        .unwrap();
    let refused = service
        .set_settings(RetentionPatch {
            audit_days: Some(Some(30)),
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert!(matches!(refused, RetentionRefusal::Invalid { .. }));
    assert_eq!(store.get_setting(SETTING_AUDIT_DAYS).await.unwrap(), None);

    // Naming one window stores the pair: the untouched one is written as
    // the value the validation saw, in the same transaction.
    let saved = service
        .set_settings(RetentionPatch {
            evidence_days: Some(Some(7)),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(saved.evidence_days, Some(7));
    assert_eq!(
        store
            .get_setting(SETTING_EVIDENCE_DAYS)
            .await
            .unwrap()
            .as_deref(),
        Some("7")
    );
    assert_eq!(
        store
            .get_setting(SETTING_AUDIT_DAYS)
            .await
            .unwrap()
            .as_deref(),
        Some("null")
    );
    assert_eq!(service.settings().await.unwrap(), saved);
}

// ---- the forward-clock-jump guard -------------------------------------

/// A census whose answer a test sets: what a pass "would remove".
#[derive(Debug)]
struct FakeCensus(Option<PassCensus>);

impl CensusSource for FakeCensus {
    fn census(
        &self,
        _settings: RetentionSettings,
        _now_ts: i64,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Option<PassCensus>, StoreError>> + Send + '_>,
    > {
        let answer = self.0;
        Box::pin(async move { Ok(answer) })
    }
}

/// `eligible` of `total` rows, as the census reports them.
fn census(eligible: u64, total: u64) -> Arc<FakeCensus> {
    Arc::new(FakeCensus(Some(PassCensus {
        eligible_rows: eligible,
        total_rows: total,
    })))
}

/// A service on a clock the test moves, over a store holding one finished
/// request that a 30-day window deletes as soon as the clock is 31 days on.
struct Guarded {
    store: Arc<Store>,
    service: RetentionService,
    clock: Arc<AtomicI64>,
    start: i64,
}

async fn guarded(census_source: Arc<FakeCensus>) -> Guarded {
    let (store, service) = service().await;
    finished_request(&store, "old").await;
    service
        .set_settings(RetentionPatch {
            evidence_days: Some(Some(30)),
            audit_days: Some(Some(30)),
        })
        .await
        .unwrap();
    let start = crate::retention::now_ts();
    let clock = Arc::new(AtomicI64::new(start));
    let reader = Arc::clone(&clock);
    let service = service
        .with_clock(Arc::new(move || reader.load(Ordering::SeqCst)))
        .with_census(census_source);
    Guarded {
        store,
        service,
        clock,
        start,
    }
}

impl Guarded {
    fn set_clock(&self, ts: i64) {
        self.clock.store(ts, Ordering::SeqCst);
    }

    async fn watermark(&self) -> Option<String> {
        self.store.get_setting(SETTING_WATERMARK).await.unwrap()
    }

    async fn kept(&self) -> bool {
        self.store.get_request("old").await.unwrap().is_some()
    }

    /// A scheduled hourly pass.
    async fn scheduled(&self) -> PassOutcome {
        self.service
            .run_pass(Trigger::Scheduled(Duration::from_hours(1)))
            .await
            .unwrap()
    }
}

fn skipped(outcome: PassOutcome) -> crate::retention::ClockGuardNotice {
    match outcome {
        PassOutcome::Skipped(notice) => notice,
        other @ PassOutcome::Ran { .. } => {
            panic!("expected the guard to hold the pass back, got {other:?}")
        }
    }
}

#[tokio::test]
async fn a_normal_pass_runs_and_moves_the_watermark() {
    let guarded = guarded(census(100, 100)).await;
    // The first pass has no watermark, so the guard has nothing to compare.
    assert!(matches!(
        guarded.scheduled().await,
        PassOutcome::Ran {
            overrode_guard: false,
            ..
        }
    ));
    assert_eq!(
        guarded.watermark().await.as_deref(),
        Some(guarded.start.to_string().as_str())
    );
    // An hour later is an ordinary tick, even though a census would say
    // every row is old.
    guarded.set_clock(guarded.start + 3600);
    assert!(matches!(
        guarded.scheduled().await,
        PassOutcome::Ran {
            overrode_guard: false,
            ..
        }
    ));
    assert_eq!(
        guarded.watermark().await.as_deref(),
        Some((guarded.start + 3600).to_string().as_str())
    );
    assert_eq!(guarded.service.clock_guard().await.unwrap(), None);
}

#[tokio::test]
async fn a_first_run_without_a_watermark_behaves_as_before_the_guard() {
    // No watermark and no recorded pass: the clock is 100 days on, the
    // census says everything is old, and the pass still runs.
    let guarded = guarded(census(100, 100)).await;
    assert_eq!(guarded.watermark().await, None);
    guarded.set_clock(guarded.start + 100 * DAY);
    assert!(matches!(guarded.scheduled().await, PassOutcome::Ran { .. }));
    assert!(!guarded.kept().await);
}

#[tokio::test]
async fn a_forward_jump_that_would_remove_most_rows_is_held_back() {
    let guarded = guarded(census(80, 100)).await;
    guarded.scheduled().await;
    let before = guarded.store.get_setting(SETTING_LAST_RUN).await.unwrap();

    // A VM resume (or a bad NTP answer) puts the clock 100 days on.
    guarded.set_clock(guarded.start + 100 * DAY);
    let notice = skipped(guarded.scheduled().await);
    assert_eq!(notice.ts, guarded.start + 100 * DAY);
    assert_eq!(notice.watermark_ts, guarded.start);
    assert_eq!(notice.jump_secs, 100 * DAY);
    assert_eq!(notice.threshold_secs, 24 * 3600);
    assert_eq!(
        (notice.eligible_rows, notice.total_rows),
        (Some(80), Some(100))
    );
    assert!(
        notice.detail().contains("80 of 100 rows"),
        "{}",
        notice.detail()
    );
    assert!(notice.detail().contains("nothing was deleted"));

    // Nothing was deleted, the watermark and the last run did not move, and
    // the notice is stored for the status reply.
    assert!(guarded.kept().await);
    assert_eq!(
        guarded.watermark().await.as_deref(),
        Some(guarded.start.to_string().as_str())
    );
    assert_eq!(
        guarded.store.get_setting(SETTING_LAST_RUN).await.unwrap(),
        before
    );
    assert_eq!(guarded.service.clock_guard().await.unwrap(), Some(notice));
    assert_eq!(CAUSE_CLOCK_JUMP, "retention_clock_jump");
    assert!(RECOVERY_CLOCK_JUMP.contains("Check the system clock"));

    // The next hourly tick is held back the same way: skipping never advances
    // the watermark, so the jump does not "age out".
    guarded.set_clock(guarded.start + 100 * DAY + 3600);
    skipped(guarded.scheduled().await);
    assert!(guarded.kept().await);
    // A settings save runs a pass too, and is held back like the scheduler.
    skipped(guarded.service.run_pass(Trigger::Settings).await.unwrap());
    assert!(guarded.kept().await);
}

#[tokio::test]
async fn a_late_pass_that_removes_little_is_not_held_back() {
    // The daemon was off for three days: past the threshold, but the pass
    // only takes 5 of 1000 rows, so nobody is asked to confirm anything.
    let guarded = guarded(census(5, 1000)).await;
    guarded.scheduled().await;
    guarded.set_clock(guarded.start + 3 * DAY);
    assert!(matches!(guarded.scheduled().await, PassOutcome::Ran { .. }));
    // Even a large share of a tiny store is not held back.
    let tiny = guarded_tiny().await;
    assert!(matches!(tiny.scheduled().await, PassOutcome::Ran { .. }));
}

async fn guarded_tiny() -> Guarded {
    let guarded = guarded(census(3, 4)).await;
    guarded.scheduled().await;
    guarded.set_clock(guarded.start + 100 * DAY);
    guarded
}

#[tokio::test]
async fn a_source_that_cannot_count_fails_closed() {
    let guarded = guarded(Arc::new(FakeCensus(None))).await;
    guarded.scheduled().await;
    guarded.set_clock(guarded.start + 100 * DAY);
    let notice = skipped(guarded.scheduled().await);
    assert_eq!((notice.eligible_rows, notice.total_rows), (None, None));
    assert!(notice.detail().contains("could not be counted"));
    assert!(guarded.kept().await);
}

/// The production source counts the store's own rows: a jump that would
/// take most of them is held back with the real figures in the notice, and
/// the human's confirmation then removes exactly what was counted.
#[tokio::test]
async fn the_store_census_holds_back_a_jump_that_would_remove_most_rows() {
    // Sixty finished requests under a 30-day audit window: 100 days on,
    // every one of them, and nothing else, would go.
    let (store, service) = service().await;
    for index in 0..60 {
        finished_request(&store, &format!("old_{index}")).await;
    }
    service
        .set_settings(RetentionPatch {
            evidence_days: None,
            audit_days: Some(Some(30)),
        })
        .await
        .unwrap();
    let start = crate::retention::now_ts();
    let clock = Arc::new(AtomicI64::new(start));
    let reader = Arc::clone(&clock);
    // No `with_census`: this is the source the daemon runs with.
    let service = service.with_clock(Arc::new(move || reader.load(Ordering::SeqCst)));
    service.run_pass(Trigger::Manual).await.unwrap();
    clock.store(start + 3600, Ordering::SeqCst);
    assert!(matches!(
        service.run_pass(Trigger::Settings).await.unwrap(),
        PassOutcome::Ran { .. }
    ));
    clock.store(start + 100 * DAY, Ordering::SeqCst);
    let notice = skipped(service.run_pass(Trigger::Settings).await.unwrap());
    assert_eq!(
        (notice.eligible_rows, notice.total_rows),
        (Some(60), Some(60)),
        "the notice carries the store's own count"
    );
    assert!(
        notice.detail().contains("60 of 60 rows"),
        "{}",
        notice.detail()
    );
    for index in 0..60 {
        let id = format!("old_{index}");
        assert!(store.get_request(&id).await.unwrap().is_some(), "{id}");
    }
    // Counting is not pruning: the pass is still held back on the next tick.
    skipped(
        service
            .run_pass(Trigger::Scheduled(Duration::from_hours(1)))
            .await
            .unwrap(),
    );
    // The human confirms; the pass removes exactly what was counted.
    let PassOutcome::Ran {
        report,
        overrode_guard,
    } = service.run_pass(Trigger::Manual).await.unwrap()
    else {
        panic!("a manual pass always runs");
    };
    assert!(overrode_guard);
    assert_eq!(report.requests, 60);
}

/// The same jump over a store it would barely touch runs without asking,
/// because the production source can now tell: sixty records with their
/// verdicts are kept by a forever audit window, and only five old source
/// blobs fall under the 30-day evidence window. Five rows is under the
/// guard's floor.
#[tokio::test]
async fn the_store_census_lets_a_late_pass_that_removes_little_run() {
    let (store, service) = service().await;
    for index in 0..60 {
        let id = format!("kept_{index}");
        finished_request(&store, &id).await;
        store
            .insert_evidence(&format!("verdict_{index}"), &id, KEEP_KIND, b"{}", None)
            .await
            .unwrap();
    }
    for index in 0..5 {
        store
            .insert_evidence(
                &format!("blob_{index}"),
                &format!("kept_{index}"),
                "log.source",
                b"source",
                None,
            )
            .await
            .unwrap();
    }
    service
        .set_settings(RetentionPatch {
            evidence_days: Some(Some(30)),
            audit_days: None,
        })
        .await
        .unwrap();
    let start = crate::retention::now_ts();
    let clock = Arc::new(AtomicI64::new(start));
    let reader = Arc::clone(&clock);
    let service = service.with_clock(Arc::new(move || reader.load(Ordering::SeqCst)));
    service.run_pass(Trigger::Manual).await.unwrap();
    clock.store(start + 100 * DAY, Ordering::SeqCst);
    let PassOutcome::Ran {
        report,
        overrode_guard,
    } = service.run_pass(Trigger::Settings).await.unwrap()
    else {
        panic!("a late pass that removes five rows of 125 is not held back");
    };
    assert!(!overrode_guard);
    assert_eq!((report.evidence_rows, report.requests), (5, 0));
    assert!(store.get_evidence("verdict_0").await.unwrap().is_some());
    assert!(store.get_evidence("blob_0").await.unwrap().is_none());
}

#[tokio::test]
async fn the_threshold_is_the_larger_of_a_day_and_two_intervals() {
    let policy = GuardPolicy::default();
    assert_eq!(policy.threshold_secs(Duration::from_hours(1)), 24 * 3600);
    assert_eq!(policy.threshold_secs(Duration::from_hours(30)), 60 * 3600);

    let guarded = guarded(census(100, 100)).await;
    guarded.scheduled().await;
    // 23 hours on: under the day, no matter what the census says.
    guarded.set_clock(guarded.start + 23 * 3600);
    assert!(matches!(guarded.scheduled().await, PassOutcome::Ran { .. }));
    let mark = guarded.start + 23 * 3600;
    // 25 hours after that: over it.
    guarded.set_clock(mark + 25 * 3600);
    skipped(guarded.scheduled().await);
    // The same gap is ordinary for a scheduler that ticks every 30 hours.
    assert!(matches!(
        guarded
            .service
            .run_pass(Trigger::Scheduled(Duration::from_hours(30)))
            .await
            .unwrap(),
        PassOutcome::Ran { .. }
    ));
}

#[tokio::test]
async fn a_manual_run_overrides_the_guard_and_clears_the_notice() {
    let guarded = guarded(census(80, 100)).await;
    guarded.scheduled().await;
    guarded.set_clock(guarded.start + 100 * DAY);
    skipped(guarded.scheduled().await);
    assert!(guarded.service.clock_guard().await.unwrap().is_some());

    let outcome = guarded.service.run_pass(Trigger::Manual).await.unwrap();
    let PassOutcome::Ran {
        report,
        overrode_guard,
    } = outcome
    else {
        panic!("a manual pass is never held back: {outcome:?}");
    };
    assert!(overrode_guard);
    assert_eq!(report.requests, 1);
    assert!(!guarded.kept().await);
    assert_eq!(guarded.service.clock_guard().await.unwrap(), None);
    assert_eq!(
        guarded
            .store
            .get_setting(SETTING_CLOCK_GUARD)
            .await
            .unwrap()
            .as_deref(),
        Some("null")
    );
    // The human vouched for this clock, so it is the new watermark and the
    // next ordinary tick is ordinary.
    assert_eq!(
        guarded.watermark().await.as_deref(),
        Some((guarded.start + 100 * DAY).to_string().as_str())
    );
    guarded.set_clock(guarded.start + 100 * DAY + 3600);
    assert!(matches!(
        guarded.scheduled().await,
        PassOutcome::Ran {
            overrode_guard: false,
            ..
        }
    ));
}

#[tokio::test]
async fn a_backward_jump_deletes_nothing_it_would_not_have_before() {
    let guarded = guarded(census(100, 100)).await;
    guarded.scheduled().await;

    // The clock falls 200 days behind. A pass still runs (it is harmless:
    // the cutoff only moved back), deletes nothing, and the watermark keeps
    // its high-water value.
    guarded.set_clock(guarded.start - 200 * DAY);
    let outcome = guarded.scheduled().await;
    let PassOutcome::Ran { report, .. } = outcome else {
        panic!("a backward jump is not held back: {outcome:?}");
    };
    assert_eq!((report.requests, report.evidence_rows), (0, 0));
    assert!(guarded.kept().await);
    assert_eq!(
        guarded.watermark().await.as_deref(),
        Some(guarded.start.to_string().as_str())
    );

    // Returning to the true time is not a forward jump from the watermark.
    guarded.set_clock(guarded.start + 3600);
    assert!(matches!(
        guarded.scheduled().await,
        PassOutcome::Ran {
            overrode_guard: false,
            ..
        }
    ));
    assert!(guarded.kept().await);
}

#[tokio::test]
async fn a_store_from_before_the_guard_uses_its_last_recorded_pass() {
    let guarded = guarded(census(100, 100)).await;
    // An install that predates the watermark only has `retention.last_run`.
    let old_pass = PruneReport {
        ts: guarded.start,
        evidence_rows: 0,
        evidence_bytes: 0,
        requests: 0,
        audit_rows: 0,
    };
    guarded
        .store
        .set_setting(SETTING_LAST_RUN, &serde_json::to_string(&old_pass).unwrap())
        .await
        .unwrap();
    guarded.set_clock(guarded.start + 100 * DAY);
    skipped(guarded.scheduled().await);
    assert!(guarded.kept().await);

    // An unreadable watermark falls back to it too, rather than to "no guard".
    guarded
        .store
        .set_setting(SETTING_WATERMARK, "not a number")
        .await
        .unwrap();
    skipped(guarded.scheduled().await);
    assert!(guarded.kept().await);
}

#[tokio::test]
async fn forever_windows_are_never_held_back() {
    let (store, service) = service().await;
    let start = crate::retention::now_ts();
    let clock = Arc::new(AtomicI64::new(start));
    let reader = Arc::clone(&clock);
    let service = service
        .with_clock(Arc::new(move || reader.load(Ordering::SeqCst)))
        .with_census(census(100, 100));
    service.run_pass(Trigger::Manual).await.unwrap();
    clock.store(start + 100 * DAY, Ordering::SeqCst);
    // Nothing can be removed with both windows forever, so there is nothing
    // to hold back, and the watermark follows the clock.
    assert!(matches!(
        service.run_pass(Trigger::Settings).await.unwrap(),
        PassOutcome::Ran { .. }
    ));
    assert_eq!(
        store.get_setting(SETTING_WATERMARK).await.unwrap(),
        Some((start + 100 * DAY).to_string())
    );
}

// ---- the managed policy -------------------------------------------------

/// A retention service over a fresh store whose policy handle read `policy`,
/// a trusted scripted file.
async fn managed_service(policy: &str) -> (Arc<Store>, RetentionService) {
    let store = Arc::new(Store::open_in_memory().await.unwrap());
    let handle = crate::managed_policy_service::PolicyHandle::load(
        Arc::clone(&store),
        Arc::new(crate::daemon_test::ScriptedPolicy::new(Some(policy))),
        std::path::Path::new("pam-tests-have-no-base"),
    )
    .await;
    assert!(
        matches!(handle.status().state.as_str(), "active" | "degraded"),
        "{:?}",
        handle.status()
    );
    (Arc::clone(&store), RetentionService::new(store, handle))
}

const CEILING: &str = r#"{
    "version": 1, "revision": "r9", "contact": "it@example.test",
    "retention": { "evidence_days": { "max": 30 }, "audit_days": { "max": 90 } }
}"#;

fn policy_refusal(error: RetentionRefusal) -> crate::managed_policy::WriteRefusal {
    match error {
        RetentionRefusal::Policy { refusal, .. } => refusal,
        other => panic!("expected the managed policy's refusal, got {other:?}"),
    }
}

#[tokio::test]
async fn a_ceiling_clamps_forever_and_every_reader_sees_the_clamped_pair() {
    let (store, service) = managed_service(CEILING).await;
    // Nothing stored at all, which reads as forever: the ceiling is the window.
    let want = RetentionSettings {
        evidence_days: Some(30),
        audit_days: Some(90),
    };
    assert_eq!(service.settings().await.unwrap(), want);
    // A stored "forever" is clamped too, and a stored longer window.
    store
        .set_setting(SETTING_EVIDENCE_DAYS, "null")
        .await
        .unwrap();
    store.set_setting(SETTING_AUDIT_DAYS, "400").await.unwrap();
    assert_eq!(service.settings().await.unwrap(), want);
    // The human's rows are never rewritten.
    assert_eq!(
        store
            .get_setting(SETTING_EVIDENCE_DAYS)
            .await
            .unwrap()
            .as_deref(),
        Some("null")
    );
    assert_eq!(
        store
            .get_setting(SETTING_AUDIT_DAYS)
            .await
            .unwrap()
            .as_deref(),
        Some("400")
    );
    let (_, entries) = service.effective().await.unwrap();
    for entry in &entries {
        assert_eq!(entry.source, crate::network_service::Source::Policy);
        assert!(entry.clamped);
        assert!(!entry.locked);
    }
    assert_eq!(
        entries[1].constraint,
        Some(serde_json::json!({ "max": 90 }))
    );

    // The pass reads the same pair: a record older than 90 days goes, with
    // the policy's window, although the human stored forever.
    store.set_setting(SETTING_AUDIT_DAYS, "null").await.unwrap();
    finished_request(&store, "old").await;
    let clock = Arc::new(AtomicI64::new(crate::retention::now_ts() + 100 * DAY));
    let reader = Arc::clone(&clock);
    let service = service.with_clock(Arc::new(move || reader.load(Ordering::SeqCst)));
    let PassOutcome::Ran { report, .. } = service.run_pass(Trigger::Manual).await.unwrap() else {
        panic!("a manual pass always runs");
    };
    // The old request, and the policy's own load request (also older than 90 days).
    assert!(report.requests >= 1, "{report:?}");
    assert!(store.get_request("old").await.unwrap().is_none());
}

#[tokio::test]
async fn a_floor_lengthens_a_shorter_window_and_leaves_forever_alone() {
    let (store, service) =
        managed_service(r#"{ "version": 1, "retention": { "audit_days": { "min": 365 } } }"#).await;
    store.set_setting(SETTING_AUDIT_DAYS, "30").await.unwrap();
    assert_eq!(service.settings().await.unwrap().audit_days, Some(365));
    store.set_setting(SETTING_AUDIT_DAYS, "null").await.unwrap();
    assert_eq!(service.settings().await.unwrap().audit_days, None);
}

#[tokio::test]
async fn a_locked_window_is_forced_and_a_default_applies_until_the_human_chooses() {
    let (store, service) = managed_service(
        r#"{ "version": 1, "retention": {
            "evidence_days": { "locked": 14, "reason": "SEC-9" },
            "audit_days": { "default": 120 } } }"#,
    )
    .await;
    store.set_setting(SETTING_EVIDENCE_DAYS, "7").await.unwrap();
    let (settings, entries) = service.effective().await.unwrap();
    assert_eq!(settings.evidence_days, Some(14));
    assert!(entries[0].locked);
    assert_eq!(entries[0].reason.as_deref(), Some("SEC-9"));
    // Unset: the default. Stored (even forever): the human's.
    assert_eq!(settings.audit_days, Some(120));
    assert_eq!(entries[1].source, crate::network_service::Source::Policy);
    assert!(!entries[1].locked);
    store.set_setting(SETTING_AUDIT_DAYS, "null").await.unwrap();
    assert_eq!(service.settings().await.unwrap().audit_days, None);
    store.set_setting(SETTING_AUDIT_DAYS, "200").await.unwrap();
    assert_eq!(service.settings().await.unwrap().audit_days, Some(200));
}

#[tokio::test]
async fn a_save_outside_the_bounds_refuses_and_writes_nothing() {
    let (store, service) = managed_service(CEILING).await;
    store.set_setting(SETTING_AUDIT_DAYS, "60").await.unwrap();

    // Forever is above any ceiling.
    let refusal = policy_refusal(
        service
            .set_settings(RetentionPatch {
                audit_days: Some(None),
                ..Default::default()
            })
            .await
            .unwrap_err(),
    );
    assert_eq!(
        refusal.cause,
        crate::managed_policy::CAUSE_POLICY_NOT_ALLOWED
    );
    assert!(
        refusal.detail.contains("retention.audit_days"),
        "{}",
        refusal.detail
    );
    assert!(refusal.detail.contains("forever"), "{}", refusal.detail);
    assert!(
        refusal.detail.contains("it@example.test"),
        "{}",
        refusal.detail
    );
    assert!(refusal.detail.contains("rev r9"), "{}", refusal.detail);
    assert_eq!(refusal.recovery, crate::managed_policy::RECOVERY_MANAGED);
    // So is a number above it.
    let refusal = policy_refusal(
        service
            .set_settings(RetentionPatch {
                evidence_days: Some(Some(31)),
                ..Default::default()
            })
            .await
            .unwrap_err(),
    );
    assert_eq!(
        refusal.key,
        crate::managed_policy::Key::RetentionEvidenceDays
    );
    assert_eq!(
        store
            .get_setting(SETTING_AUDIT_DAYS)
            .await
            .unwrap()
            .as_deref(),
        Some("60")
    );
    assert_eq!(
        store.get_setting(SETTING_EVIDENCE_DAYS).await.unwrap(),
        None
    );

    // Inside the bounds is saved, and answers the windows in force.
    let saved = service
        .set_settings(RetentionPatch {
            evidence_days: Some(Some(20)),
            audit_days: Some(Some(45)),
        })
        .await
        .unwrap();
    assert_eq!(
        saved,
        RetentionSettings {
            evidence_days: Some(20),
            audit_days: Some(45)
        }
    );
}

#[tokio::test]
async fn a_locked_window_refuses_setting_locked_and_a_held_one_policy_frozen() {
    let (store, service) =
        managed_service(r#"{ "version": 1, "retention": { "audit_days": { "locked": 365 } } }"#)
            .await;
    let refusal = policy_refusal(
        service
            .set_settings(RetentionPatch {
                audit_days: Some(Some(365)),
                ..Default::default()
            })
            .await
            .unwrap_err(),
    );
    assert_eq!(refusal.cause, crate::managed_policy::CAUSE_SETTING_LOCKED);
    assert_eq!(store.get_setting(SETTING_AUDIT_DAYS).await.unwrap(), None);
    // The other window is the human's.
    service
        .set_settings(RetentionPatch {
            evidence_days: Some(Some(30)),
            ..Default::default()
        })
        .await
        .unwrap();

    // A leaf the file got wrong, with no last-known-good copy, holds the key.
    let (_store, held) =
        managed_service(r#"{ "version": 1, "retention": { "audit_days": "ninety" } }"#).await;
    let refusal = policy_refusal(
        held.set_settings(RetentionPatch {
            audit_days: Some(Some(30)),
            ..Default::default()
        })
        .await
        .unwrap_err(),
    );
    assert_eq!(refusal.cause, crate::managed_policy::CAUSE_POLICY_FROZEN);
    // Reads show the human's value, unmanaged.
    assert_eq!(held.settings().await.unwrap(), RetentionSettings::default());
}

#[tokio::test]
async fn a_default_keeps_applying_to_a_window_the_human_never_set() {
    let (store, service) = managed_service(
        r#"{ "version": 1, "retention": {
            "evidence_days": { "default": 45 }, "audit_days": { "default": 120 } } }"#,
    )
    .await;
    service
        .set_settings(RetentionPatch {
            audit_days: Some(Some(200)),
            ..Default::default()
        })
        .await
        .unwrap();
    // The untouched window was not frozen into a stored "forever".
    assert_eq!(
        store.get_setting(SETTING_EVIDENCE_DAYS).await.unwrap(),
        None
    );
    assert_eq!(
        service.settings().await.unwrap(),
        RetentionSettings {
            evidence_days: Some(45),
            audit_days: Some(200)
        }
    );
}

#[tokio::test]
async fn removing_the_policy_restores_what_the_human_stored() {
    let (store, service) = managed_service(CEILING).await;
    store.set_setting(SETTING_AUDIT_DAYS, "400").await.unwrap();
    assert_eq!(service.settings().await.unwrap().audit_days, Some(90));
    let plain = RetentionService::new(store, crate::managed_policy_service::PolicyHandle::none());
    assert_eq!(plain.settings().await.unwrap().audit_days, Some(400));
}

#[tokio::test]
async fn the_clock_jump_guard_still_holds_back_a_policy_forced_window() {
    let (store, service) = managed_service(
        r#"{ "version": 1, "retention": {
            "evidence_days": { "locked": 30 }, "audit_days": { "locked": 30 } } }"#,
    )
    .await;
    finished_request(&store, "old").await;
    let start = crate::retention::now_ts();
    let clock = Arc::new(AtomicI64::new(start));
    let reader = Arc::clone(&clock);
    let service = service
        .with_clock(Arc::new(move || reader.load(Ordering::SeqCst)))
        .with_census(census(80, 100));
    let hourly = Trigger::Scheduled(Duration::from_hours(1));
    assert!(matches!(
        service.run_pass(hourly).await.unwrap(),
        PassOutcome::Ran { .. }
    ));
    clock.store(start + 100 * DAY, Ordering::SeqCst);
    let notice = skipped(service.run_pass(hourly).await.unwrap());
    assert_eq!(notice.jump_secs, 100 * DAY);
    assert!(
        store.get_request("old").await.unwrap().is_some(),
        "nothing was deleted"
    );
}

fn refusal_at(cause: &str, ts: i64) -> RefusalWrite {
    RefusalWrite::Insert(RefusalRecord {
        ts,
        last_ts: ts,
        ingress: RequestIngress::Public,
        cause: cause.to_owned(),
        detail: String::new(),
        count: 1,
        peer_uid: None,
        peer_pid: None,
        peer_exe: None,
        agent: None,
        repo: None,
        request_id: None,
        capability: None,
    })
}

/// The refusals decided before a request row existed are audit record: the
/// audit window removes them (by their latest attempt), the evidence window
/// and no window leave them alone.
#[tokio::test]
async fn refusals_leave_with_the_audit_window_and_only_with_it() {
    let (store, service) = service().await;
    let now = crate::retention::now_ts();
    store
        .write_refusals(vec![
            refusal_at("old", now - 60 * DAY),
            refusal_at("fresh", now - DAY),
        ])
        .await
        .unwrap();

    service.prune(now).await.unwrap();
    assert_eq!(store.refusal_rows().await.unwrap(), 2, "no window");

    service
        .set_settings(RetentionPatch {
            evidence_days: Some(Some(7)),
            ..Default::default()
        })
        .await
        .unwrap();
    service.prune(now).await.unwrap();
    assert_eq!(
        store.refusal_rows().await.unwrap(),
        2,
        "evidence window only"
    );

    service
        .set_settings(RetentionPatch {
            audit_days: Some(Some(30)),
            ..Default::default()
        })
        .await
        .unwrap();
    service.prune(now).await.unwrap();
    let kept = store.list_refusals(10, None, None, None).await.unwrap();
    assert_eq!(kept.len(), 1);
    assert_eq!(kept[0].cause, "fresh");
}
