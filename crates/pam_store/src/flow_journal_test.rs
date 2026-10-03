use crate::{FlowJournalBegin, FlowJournalIdentity, FlowJournalState, Store};

fn identity(id: &str) -> FlowJournalIdentity {
    FlowJournalIdentity {
        request_id: id.to_owned(),
        flow_digest: "a".repeat(64),
        repository: "/repo".to_owned(),
        input_fingerprint: "b".repeat(64),
    }
}

async fn seed(store: &Store, id: &str) {
    store
        .insert_request(id, "flow.run", "/repo", "test", "{}", None)
        .await
        .unwrap();
    assert_eq!(
        store
            .begin_flow_journal(&identity(id), r#"{"next_step":0}"#)
            .await
            .unwrap(),
        FlowJournalBegin::Inserted
    );
}

#[tokio::test]
async fn identity_binding_and_completed_checkpoint_are_immutable() {
    let store = Store::open_in_memory().await.unwrap();
    seed(&store, "r").await;
    assert!(
        store
            .prepare_flow_attempt("r", 0, "read", 1, false)
            .await
            .unwrap()
    );
    assert!(
        store
            .settle_flow_attempt(
                "r",
                1,
                r#"{"next_step":1,"snapshot":"ev"}"#,
                &["ev".to_owned()],
                true
            )
            .await
            .unwrap()
    );
    assert_eq!(
        store
            .begin_flow_journal(&identity("r"), "{}")
            .await
            .unwrap(),
        FlowJournalBegin::Existing
    );
    let mut other = identity("r");
    other.flow_digest = "c".repeat(64);
    assert_eq!(
        store.begin_flow_journal(&other, "{}").await.unwrap(),
        FlowJournalBegin::Conflict
    );
    assert!(
        !store
            .prepare_flow_attempt("r", 2, "read", 2, false)
            .await
            .unwrap()
    );
    assert!(
        !store
            .settle_flow_attempt("r", 2, "{}", &[], false)
            .await
            .unwrap()
    );
    let row = store.read_flow_journal("r").await.unwrap().unwrap();
    assert_eq!(row.revision, 2);
    assert_eq!(row.state, FlowJournalState::Completed);
    assert_eq!(row.evidence_refs, ["ev"]);
    assert!(row.checkpoint_json.contains("snapshot"));
}

#[tokio::test]
async fn stale_and_concurrent_attempt_owners_cannot_advance_twice() {
    let store = Store::open_in_memory().await.unwrap();
    seed(&store, "r").await;
    let (a, b) = tokio::join!(
        store.prepare_flow_attempt("r", 0, "step", 1, false),
        store.prepare_flow_attempt("r", 0, "step", 1, false)
    );
    assert_ne!(a.unwrap(), b.unwrap());
    assert!(
        !store
            .settle_flow_attempt("r", 0, "{}", &[], false)
            .await
            .unwrap()
    );
    let (a, b) = tokio::join!(
        store.settle_flow_attempt("r", 1, "{}", &[], false),
        store.settle_flow_attempt("r", 1, "{}", &[], false)
    );
    assert_ne!(a.unwrap(), b.unwrap());
    assert_eq!(
        store
            .read_flow_journal("r")
            .await
            .unwrap()
            .unwrap()
            .revision,
        2
    );
}

#[tokio::test]
async fn interrupted_effect_is_never_abandoned_or_replayed() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.sqlite3");
    {
        let store = Store::open(&path).await.unwrap();
        seed(&store, "effect").await;
        assert!(
            store
                .prepare_flow_attempt("effect", 0, "write", 1, true)
                .await
                .unwrap()
        );
    }
    let store = Store::open(&path).await.unwrap();
    let row = store.read_flow_journal("effect").await.unwrap().unwrap();
    assert_eq!(row.state, FlowJournalState::Prepared);
    assert!(row.effectful);
    assert!(!store.abandon_read_attempt("effect", 1).await.unwrap());
    assert!(
        !store
            .prepare_flow_attempt("effect", 1, "write", 2, true)
            .await
            .unwrap()
    );
    assert!(store.mark_flow_uncertain("effect", 1).await.unwrap());
    assert!(
        !store
            .settle_flow_attempt("effect", 2, "{}", &[], true)
            .await
            .unwrap()
    );
    assert!(
        !store
            .prepare_flow_attempt("effect", 2, "write", 2, true)
            .await
            .unwrap()
    );
    assert_eq!(
        store
            .read_flow_journal("effect")
            .await
            .unwrap()
            .unwrap()
            .state,
        FlowJournalState::Uncertain
    );
}

#[tokio::test]
async fn interrupted_read_retains_prior_checkpoint_and_can_retry_with_new_ownership() {
    let store = Store::open_in_memory().await.unwrap();
    seed(&store, "read").await;
    assert!(
        store
            .prepare_flow_attempt("read", 0, "first", 1, false)
            .await
            .unwrap()
    );
    assert!(
        store
            .settle_flow_attempt(
                "read",
                1,
                r#"{"next_step":1,"budget_spent":10}"#,
                &["ev-first".to_owned()],
                false
            )
            .await
            .unwrap()
    );
    assert!(
        store
            .prepare_flow_attempt("read", 2, "second", 1, false)
            .await
            .unwrap()
    );
    assert!(!store.mark_flow_uncertain("read", 3).await.unwrap());
    assert!(store.abandon_read_attempt("read", 3).await.unwrap());
    let row = store.read_flow_journal("read").await.unwrap().unwrap();
    assert_eq!(row.checkpoint_json, r#"{"next_step":1,"budget_spent":10}"#);
    assert_eq!(row.evidence_refs, ["ev-first"]);
    assert!(
        store
            .prepare_flow_attempt("read", 4, "second", 2, false)
            .await
            .unwrap()
    );
    assert!(
        !store
            .settle_flow_attempt("read", 3, "{}", &[], false)
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn invalid_json_references_and_generations_fail_without_progress() {
    let store = Store::open_in_memory().await.unwrap();
    seed(&store, "r").await;
    for checkpoint in [
        "[]".to_owned(),
        "broken".to_owned(),
        format!("{{\"x\":\"{}\"}}", "x".repeat(131_072)),
    ] {
        assert!(
            store
                .begin_flow_journal(&identity("r"), &checkpoint)
                .await
                .is_err()
        );
    }
    assert!(
        store
            .prepare_flow_attempt("r", -1, "step", 1, false)
            .await
            .is_err()
    );
    assert!(
        store
            .prepare_flow_attempt("r", i64::MAX, "step", 1, false)
            .await
            .is_err()
    );
    assert!(
        store
            .prepare_flow_attempt("r", 0, "step", 0, false)
            .await
            .is_err()
    );
    assert!(
        store
            .prepare_flow_attempt("r", 0, "step", 257, false)
            .await
            .is_err()
    );
    assert!(
        store
            .prepare_flow_attempt("r", 0, &"x".repeat(257), 1, false)
            .await
            .is_err()
    );
    assert!(
        store
            .prepare_flow_attempt("r", 0, "step", 1, false)
            .await
            .unwrap()
    );
    for refs in [
        vec!["ev".to_owned(); 129],
        vec!["x".repeat(129)],
        vec!["\n".to_owned()],
    ] {
        assert!(
            store
                .settle_flow_attempt("r", 1, "{}", &refs, false)
                .await
                .is_err()
        );
    }
    assert_eq!(
        store
            .read_flow_journal("r")
            .await
            .unwrap()
            .unwrap()
            .revision,
        1
    );
}

#[tokio::test]
async fn request_foreign_key_and_checkpoint_origin_kind_size_are_enforced() {
    let store = Store::open_in_memory().await.unwrap();
    assert!(
        store
            .begin_flow_journal(&identity("missing"), "{}")
            .await
            .is_err()
    );
    assert!(store.read_flow_journal("missing").await.unwrap().is_none());
    seed(&store, "r").await;
    store
        .insert_request("other", "flow.run", "/other", "test", "{}", None)
        .await
        .unwrap();
    store
        .insert_evidence("valid", "r", "flow.checkpoint", b"{}", None)
        .await
        .unwrap();
    store
        .insert_evidence("wrong-kind", "r", "connector.result", b"{}", None)
        .await
        .unwrap();
    store
        .insert_evidence("other-origin", "other", "flow.checkpoint", b"{}", None)
        .await
        .unwrap();
    store
        .insert_evidence(
            "oversized",
            "r",
            "flow.checkpoint",
            &vec![b'x'; 1_048_577],
            None,
        )
        .await
        .unwrap();
    assert_eq!(
        store.read_flow_checkpoint("r", "valid").await.unwrap(),
        Some(b"{}".to_vec())
    );
    for id in ["wrong-kind", "other-origin", "missing"] {
        assert!(store.read_flow_checkpoint("r", id).await.unwrap().is_none());
    }
    assert!(store.read_flow_checkpoint("r", "oversized").await.is_err());
}

// --- Journal before checkpoint, in one transaction (store finding 13) ---

use crate::FlowCheckpoint;
use crate::store::CRASH_BETWEEN_JOURNAL_AND_CHECKPOINT;

/// Arms the injected crash for `request_id`'s next checkpointed write.
fn crash_next_checkpoint_of(request_id: &str) {
    *CRASH_BETWEEN_JOURNAL_AND_CHECKPOINT.lock().unwrap() = Some(request_id.to_owned());
}

async fn checkpoint_ids(store: &Store, request_id: &str) -> Vec<String> {
    store
        .list_evidence(request_id)
        .await
        .unwrap()
        .into_iter()
        .filter(|row| row.kind == crate::EVIDENCE_KIND_FLOW_CHECKPOINT)
        .map(|row| row.id)
        .collect()
}

async fn admitted(store: &Store, id: &str) {
    store
        .insert_request(id, "flow.run", "/repo", "test", "{}", None)
        .await
        .unwrap();
}

#[tokio::test]
async fn the_journal_and_its_first_checkpoint_are_written_together() {
    let store = Store::open_in_memory().await.unwrap();
    admitted(&store, "r").await;
    let begun = store
        .begin_flow_journal_with_checkpoint(
            &identity("r"),
            r#"{"evidence_id":"ev_first","next_step":0}"#,
            FlowCheckpoint {
                evidence_id: "ev_first",
                bytes: b"{\"snapshot\":0}",
            },
        )
        .await
        .unwrap();
    assert_eq!(begun, FlowJournalBegin::Inserted);
    assert!(store.read_flow_journal("r").await.unwrap().is_some());
    assert_eq!(
        store.read_flow_checkpoint("r", "ev_first").await.unwrap(),
        Some(b"{\"snapshot\":0}".to_vec())
    );
    // A second begin of the same identity files nothing more, and one with a
    // different identity files nothing at all.
    let again = store
        .begin_flow_journal_with_checkpoint(
            &identity("r"),
            r#"{"evidence_id":"ev_second","next_step":0}"#,
            FlowCheckpoint {
                evidence_id: "ev_second",
                bytes: b"{}",
            },
        )
        .await
        .unwrap();
    assert_eq!(again, FlowJournalBegin::Existing);
    let mut other = identity("r");
    other.flow_digest = "c".repeat(64);
    let conflict = store
        .begin_flow_journal_with_checkpoint(
            &other,
            r#"{"evidence_id":"ev_third","next_step":0}"#,
            FlowCheckpoint {
                evidence_id: "ev_third",
                bytes: b"{}",
            },
        )
        .await
        .unwrap();
    assert_eq!(conflict, FlowJournalBegin::Conflict);
    assert_eq!(
        checkpoint_ids(&store, "r").await,
        vec!["ev_first".to_owned()]
    );
}

#[tokio::test]
async fn a_crash_between_the_journal_and_its_first_checkpoint_leaves_neither() {
    let store = Store::open_in_memory().await.unwrap();
    admitted(&store, "crash-begin").await;
    crash_next_checkpoint_of("crash-begin");
    let error = store
        .begin_flow_journal_with_checkpoint(
            &identity("crash-begin"),
            r#"{"evidence_id":"ev_lost","next_step":0}"#,
            FlowCheckpoint {
                evidence_id: "ev_lost",
                bytes: b"{}",
            },
        )
        .await
        .unwrap_err();
    assert!(error.to_string().contains("injected crash"), "{error}");
    // Neither a journal naming a missing checkpoint (the old order's
    // "unrecoverable journal") nor a checkpoint without its journal.
    assert!(
        store
            .read_flow_journal("crash-begin")
            .await
            .unwrap()
            .is_none()
    );
    assert!(checkpoint_ids(&store, "crash-begin").await.is_empty());
    // The run can begin afresh.
    assert_eq!(
        store
            .begin_flow_journal_with_checkpoint(
                &identity("crash-begin"),
                r#"{"evidence_id":"ev_retry","next_step":0}"#,
                FlowCheckpoint {
                    evidence_id: "ev_retry",
                    bytes: b"{}",
                },
            )
            .await
            .unwrap(),
        FlowJournalBegin::Inserted
    );
}

#[tokio::test]
async fn a_settlement_files_its_checkpoint_only_when_it_applies() {
    let store = Store::open_in_memory().await.unwrap();
    seed(&store, "r").await;
    assert!(
        store
            .prepare_flow_attempt("r", 0, "read", 1, false)
            .await
            .unwrap()
    );
    // A stale revision: no settlement, no checkpoint.
    assert!(
        !store
            .settle_flow_attempt_with_checkpoint(
                "r",
                0,
                r#"{"evidence_id":"ev_stale","next_step":1}"#,
                &[],
                false,
                FlowCheckpoint {
                    evidence_id: "ev_stale",
                    bytes: b"{}",
                },
            )
            .await
            .unwrap()
    );
    assert!(checkpoint_ids(&store, "r").await.is_empty());
    assert!(
        store
            .settle_flow_attempt_with_checkpoint(
                "r",
                1,
                r#"{"evidence_id":"ev_one","next_step":1}"#,
                &[],
                false,
                FlowCheckpoint {
                    evidence_id: "ev_one",
                    bytes: b"{\"step\":1}",
                },
            )
            .await
            .unwrap()
    );
    let journal = store.read_flow_journal("r").await.unwrap().unwrap();
    assert_eq!(journal.revision, 2);
    assert_eq!(journal.state, FlowJournalState::Ready);
    assert!(journal.checkpoint_json.contains("ev_one"));
    assert_eq!(checkpoint_ids(&store, "r").await, vec!["ev_one".to_owned()]);
}

#[tokio::test]
async fn a_crash_between_a_settlement_and_its_checkpoint_leaves_the_attempt_prepared() {
    let store = Store::open_in_memory().await.unwrap();
    seed(&store, "crash-settle").await;
    assert!(
        store
            .prepare_flow_attempt("crash-settle", 0, "run", 1, true)
            .await
            .unwrap()
    );
    crash_next_checkpoint_of("crash-settle");
    assert!(
        store
            .settle_flow_attempt_with_checkpoint(
                "crash-settle",
                1,
                r#"{"evidence_id":"ev_lost","next_step":1}"#,
                &[],
                false,
                FlowCheckpoint {
                    evidence_id: "ev_lost",
                    bytes: b"{}",
                },
            )
            .await
            .is_err()
    );
    // The settlement rolled back with the checkpoint: the journal still says
    // the effectful attempt is prepared, which recovery reports as uncertain,
    // and no checkpoint row was left that nothing names.
    let journal = store
        .read_flow_journal("crash-settle")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(journal.revision, 1);
    assert_eq!(journal.state, FlowJournalState::Prepared);
    assert!(journal.effectful);
    assert!(!journal.checkpoint_json.contains("ev_lost"));
    assert!(checkpoint_ids(&store, "crash-settle").await.is_empty());
}

#[tokio::test]
async fn checkpoints_left_without_a_journal_are_closed_with_an_audit_row() {
    let store = Store::open_in_memory().await.unwrap();
    // What the old two-statement order could leave: a checkpoint filed for a
    // request that never got its journal.
    admitted(&store, "orphaned").await;
    store
        .insert_evidence(
            "ev_orphan",
            "orphaned",
            "flow.checkpoint",
            b"{\"x\":1}",
            None,
        )
        .await
        .unwrap();
    store
        .insert_evidence("ev_log", "orphaned", "log.source", b"kept", None)
        .await
        .unwrap();
    // A journaled run's checkpoints are not orphans.
    seed(&store, "journaled").await;
    store
        .insert_evidence("ev_kept", "journaled", "flow.checkpoint", b"{}", None)
        .await
        .unwrap();

    assert_eq!(store.close_orphan_flow_checkpoints().await.unwrap(), 1);
    assert!(checkpoint_ids(&store, "orphaned").await.is_empty());
    assert!(store.get_evidence("ev_log").await.unwrap().is_some());
    assert_eq!(
        checkpoint_ids(&store, "journaled").await,
        vec!["ev_kept".to_owned()]
    );
    let audit = store.audit_for_request("orphaned").await.unwrap();
    assert_eq!(audit.len(), 1);
    assert_eq!(audit[0].action, crate::ACTION_FLOW_CHECKPOINT_ORPHANED);
    assert_eq!(audit[0].actor, crate::Actor::System);
    let detail: serde_json::Value =
        serde_json::from_str(audit[0].detail.as_deref().unwrap()).unwrap();
    assert_eq!(detail["evidence_id"], "ev_orphan");
    assert_eq!(detail["bytes"], 7);
    assert_eq!(detail["cause"], "flow_checkpoint_without_journal");
    assert_eq!(detail["content_hash"].as_str().unwrap().len(), 64);
    // The row is not a terminal row: the request's own finish still lands.
    assert!(
        store
            .finish_request(
                "orphaned",
                crate::RequestState::Failed,
                Some("daemon_restart"),
                crate::AuditEntry {
                    action: "daemon_restart",
                    decision: crate::Decision::Timeout,
                    actor: crate::Actor::System,
                    detail: None,
                },
            )
            .await
            .unwrap()
    );
    // A second sweep finds nothing and writes nothing.
    assert_eq!(store.close_orphan_flow_checkpoints().await.unwrap(), 0);
    assert_eq!(store.audit_for_request("orphaned").await.unwrap().len(), 2);
}

#[tokio::test]
async fn the_orphan_sweep_works_through_more_than_one_batch() {
    let store = Store::open_in_memory().await.unwrap();
    admitted(&store, "many").await;
    for index in 0..150 {
        store
            .insert_evidence(
                &format!("ev_{index:03}"),
                "many",
                "flow.checkpoint",
                b"{}",
                None,
            )
            .await
            .unwrap();
    }
    assert_eq!(store.close_orphan_flow_checkpoints().await.unwrap(), 150);
    assert!(checkpoint_ids(&store, "many").await.is_empty());
    assert_eq!(store.audit_for_request("many").await.unwrap().len(), 150);
}
