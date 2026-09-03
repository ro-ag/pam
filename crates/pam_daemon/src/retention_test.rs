use std::sync::Arc;
use std::time::Duration;

use pam_store::{Actor, AuditEntry, Decision, RequestState, Store};

use crate::retention::{
    MAX_DAYS, PruneReport, RetentionPatch, RetentionRefusal, RetentionService, RetentionSettings,
    SETTING_EVIDENCE_DAYS, validate,
};

const DAY: i64 = 86_400;

/// A retention service over a fresh in-memory store, plus the store
/// itself so a test can seed rows and read them back.
async fn service() -> (Arc<Store>, RetentionService) {
    let store = Arc::new(Store::open_in_memory().await.unwrap());
    (Arc::clone(&store), RetentionService::new(store))
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

#[tokio::test]
async fn scheduler_prunes_on_its_first_tick_and_stops_on_shutdown() {
    let (store, service) = service().await;
    let (tx, rx) = tokio::sync::watch::channel(false);
    let task = service.clone().run_scheduler(Duration::from_hours(1), rx);

    tokio::time::timeout(Duration::from_secs(5), async {
        while service.last_run().await.unwrap().is_none() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the first tick prunes at once");

    tx.send(true).unwrap();
    tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .expect("stops on drain")
        .unwrap();
    drop(store);
}
