//! The boundary record: bounded reports and observations, attribution,
//! lifetime counters, the census and the peer columns on the request row.

use crate::{
    Actor, AuditEntry, BoundaryObservationInsert, BoundaryPeer, BoundaryReportInsert, Decision,
    MAX_BOUNDARY_OBSERVATIONS, MAX_BOUNDARY_REPORTS, MAX_EXPECTED_OBSERVATIONS,
    OBSERVATION_ADMIN_CONTACT, OBSERVATION_ADMIN_HANDSHAKE_FAILED,
    OBSERVATION_PUBLIC_UNKNOWN_HARNESS, RequestIngress, RequestOrigin,
    SETTING_ADMIN_CONTACTS_TOTAL, Store,
};

fn peer(pid: u32) -> BoundaryPeer {
    BoundaryPeer {
        uid: Some(501),
        pid: Some(pid),
        exe: Some("/usr/local/bin/pam".to_owned()),
        harness: Some("claude".to_owned()),
    }
}

async fn request(store: &Store, id: &str) {
    let origin = RequestOrigin {
        ingress: RequestIngress::Public,
        peer_uid: Some(501),
        peer_pid: Some(4242),
        relayed: false,
    };
    store
        .insert_admitted_request_from(
            id,
            "doctor.report",
            "/repo",
            "claude",
            "{}",
            None,
            9_000_000_000_000,
            &origin,
        )
        .await
        .unwrap();
}

fn report<'a>(
    request_id: &'a str,
    verdict: &'a str,
    peer: &'a BoundaryPeer,
) -> BoundaryReportInsert<'a> {
    BoundaryReportInsert {
        request_id,
        report_ts: 1_759_400_000,
        verdict,
        failed_json: r#"["admin.endpoint"]"#,
        unverified_json: "[]",
        agent: "claude",
        repo: "/repo",
        peer,
        relayed: false,
        client_version: "0.5.0",
        report_json: r#"{"schema_version":1}"#,
    }
}

fn observation<'a>(
    peer: &'a BoundaryPeer,
    kind: &'static str,
    expected: bool,
) -> BoundaryObservationInsert<'a> {
    BoundaryObservationInsert {
        kind,
        expected,
        peer,
        detail: None,
        attributed: None,
    }
}

fn audit() -> AuditEntry<'static> {
    AuditEntry {
        action: "doctor.report",
        decision: Decision::Allow,
        actor: Actor::System,
        detail: Some(r#"{"verdict":"not_established"}"#),
    }
}

#[tokio::test]
async fn a_report_lands_with_its_audit_row_and_reads_back() {
    let store = Store::open_in_memory().await.unwrap();
    request(&store, "req_doc").await;
    let peer = peer(4242);
    let id = store
        .insert_boundary_report(report("req_doc", "not_established", &peer), audit())
        .await
        .unwrap();
    assert!(id >= 1);

    let rows = store.list_boundary_reports(10).await.unwrap();
    assert_eq!(rows.len(), 1);
    let row = &rows[0];
    assert_eq!(row.id, id);
    assert_eq!(row.request_id.as_deref(), Some("req_doc"));
    assert_eq!(row.verdict, "not_established");
    assert_eq!(row.failed, ["admin.endpoint"]);
    assert!(row.unverified.is_empty());
    assert_eq!(row.peer, peer);
    assert_eq!(row.report_ts, 1_759_400_000);
    assert!(row.ts > 0);
    assert!(!row.relayed);
    assert_eq!(row.client_version, "0.5.0");

    let audit = store.audit_for_request("req_doc").await.unwrap();
    assert_eq!(audit.len(), 1);
    assert_eq!(audit[0].action, "doctor.report");
    assert_eq!(audit[0].decision, Decision::Allow);
    assert_eq!(audit[0].actor, Actor::System);
}

#[tokio::test]
async fn a_report_is_refused_when_oversized_unrecordable_or_for_an_unknown_request() {
    let store = Store::open_in_memory().await.unwrap();
    request(&store, "req_doc").await;
    let peer = peer(1);
    let big = "x".repeat(16 * 1024 + 1);
    let mut oversized = report("req_doc", "established", &peer);
    oversized.report_json = &big;
    assert!(
        store
            .insert_boundary_report(oversized, audit())
            .await
            .is_err()
    );
    assert!(
        store
            .insert_boundary_report(report("req_doc", "cannot_probe", &peer), audit())
            .await
            .is_err()
    );
    assert!(
        store
            .insert_boundary_report(report("req_missing", "established", &peer), audit())
            .await
            .is_err()
    );
    // Nothing of a failed write lands: no report, no audit row.
    assert!(store.list_boundary_reports(10).await.unwrap().is_empty());
    assert!(store.audit_for_request("req_doc").await.unwrap().is_empty());
}

#[tokio::test]
async fn reports_are_pruned_to_the_newest_sixty_four() {
    let store = Store::open_in_memory().await.unwrap();
    let peer = peer(1);
    for n in 0..=MAX_BOUNDARY_REPORTS {
        let id = format!("req_{n}");
        request(&store, &id).await;
        let verdict = if n % 2 == 0 {
            "established"
        } else {
            "not_established"
        };
        store
            .insert_boundary_report(report(&id, verdict, &peer), audit())
            .await
            .unwrap();
    }
    let rows = store.list_boundary_reports(100).await.unwrap();
    assert_eq!(rows.len(), MAX_BOUNDARY_REPORTS as usize);
    // The oldest (req_0) is gone; the newest is first.
    assert!(
        rows.iter()
            .all(|row| row.request_id.as_deref() != Some("req_0"))
    );
    assert_eq!(rows[0].request_id.as_deref(), Some("req_64"));
    let census = store.boundary_census().await.unwrap();
    assert_eq!(census.reports_retained, MAX_BOUNDARY_REPORTS);
    assert_eq!(
        census.reports_established + census.reports_not_established,
        MAX_BOUNDARY_REPORTS
    );
    assert_eq!(
        census.last_report.unwrap().request_id.as_deref(),
        Some("req_64")
    );
}

#[tokio::test]
async fn observations_are_bounded_per_class_and_the_counters_outlive_the_rows() {
    let store = Store::open_in_memory().await.unwrap();
    let peer = peer(7);
    for _ in 0..(MAX_BOUNDARY_OBSERVATIONS + 3) {
        store
            .insert_boundary_observation(BoundaryObservationInsert {
                kind: OBSERVATION_ADMIN_CONTACT,
                expected: false,
                peer: &peer,
                detail: Some("accepted, no hello"),
                attributed: None,
            })
            .await
            .unwrap();
    }
    for _ in 0..(MAX_EXPECTED_OBSERVATIONS + 2) {
        store
            .insert_boundary_observation(BoundaryObservationInsert {
                kind: OBSERVATION_ADMIN_CONTACT,
                expected: true,
                peer: &peer,
                detail: None,
                attributed: None,
            })
            .await
            .unwrap();
    }
    // Two contacts seen but deduplicated: counted, not written.
    store
        .count_boundary_observation(OBSERVATION_ADMIN_CONTACT, false)
        .await
        .unwrap();
    store
        .count_boundary_observation(OBSERVATION_ADMIN_HANDSHAKE_FAILED, false)
        .await
        .unwrap();

    let rows = store.list_boundary_observations(1000).await.unwrap();
    let unexpected = rows.iter().filter(|row| !row.expected).count();
    let expected = rows.iter().filter(|row| row.expected).count();
    assert_eq!(unexpected, MAX_BOUNDARY_OBSERVATIONS as usize);
    assert_eq!(expected, MAX_EXPECTED_OBSERVATIONS as usize);

    let census = store.boundary_census().await.unwrap();
    assert_eq!(
        census.admin_total,
        u64::from(MAX_BOUNDARY_OBSERVATIONS) + 3 + 2
    );
    assert_eq!(
        census.admin_expected_total,
        u64::from(MAX_EXPECTED_OBSERVATIONS) + 2
    );
    assert_eq!(census.admin_unattributed, MAX_BOUNDARY_OBSERVATIONS);
    assert_eq!(census.admin_unattributed_24h, MAX_BOUNDARY_OBSERVATIONS);
    assert_eq!(census.public_unknown_total, 0);
    assert!(census.last_public_unknown.is_none());
    assert!(census.last_admin_contact.is_some_and(|row| !row.expected));
    assert!(
        census
            .last_expected_admin_contact
            .is_some_and(|row| row.expected)
    );
    // The counter is plain text in `setting`.
    assert_eq!(
        store
            .get_setting(SETTING_ADMIN_CONTACTS_TOTAL)
            .await
            .unwrap()
            .as_deref(),
        Some("261")
    );
}

#[tokio::test]
async fn attribution_touches_only_unexplained_unexpected_admin_contacts_of_that_pid_in_the_window()
{
    let store = Store::open_in_memory().await.unwrap();
    let this = peer(100);
    let other = peer(200);
    let contact = store
        .insert_boundary_observation(observation(&this, OBSERVATION_ADMIN_CONTACT, false))
        .await
        .unwrap();
    let handshake = store
        .insert_boundary_observation(observation(
            &this,
            OBSERVATION_ADMIN_HANDSHAKE_FAILED,
            false,
        ))
        .await
        .unwrap();
    let expected = store
        .insert_boundary_observation(observation(&this, OBSERVATION_ADMIN_CONTACT, true))
        .await
        .unwrap();
    let unknown = store
        .insert_boundary_observation(observation(
            &this,
            OBSERVATION_PUBLIC_UNKNOWN_HARNESS,
            false,
        ))
        .await
        .unwrap();
    let foreign = store
        .insert_boundary_observation(observation(&other, OBSERVATION_ADMIN_CONTACT, false))
        .await
        .unwrap();

    // Outside the window: nothing.
    let far_future = i64::MAX / 2;
    assert_eq!(
        store
            .attribute_boundary_observations(100, far_future, "req_doc")
            .await
            .unwrap(),
        0
    );
    let changed = store
        .attribute_boundary_observations(100, 0, "req_doc")
        .await
        .unwrap();
    assert_eq!(changed, 2);
    let rows = store.list_boundary_observations(100).await.unwrap();
    let attributed = |id: i64| {
        rows.iter()
            .find(|row| row.id == id)
            .unwrap()
            .attributed
            .clone()
    };
    assert_eq!(attributed(contact).as_deref(), Some("req_doc"));
    assert_eq!(attributed(handshake).as_deref(), Some("req_doc"));
    assert_eq!(attributed(expected), None);
    assert_eq!(attributed(unknown), None);
    assert_eq!(attributed(foreign), None);
    // Already explained: a second report does not take it over.
    assert_eq!(
        store
            .attribute_boundary_observations(100, 0, "req_other")
            .await
            .unwrap(),
        0
    );
    let census = store.boundary_census().await.unwrap();
    assert_eq!(census.admin_unattributed, 1);
    assert_eq!(census.public_unknown_total, 1);
    assert_eq!(
        census.last_public_unknown.unwrap().kind,
        OBSERVATION_PUBLIC_UNKNOWN_HARNESS
    );
}

#[tokio::test]
async fn an_observation_with_a_bad_kind_or_control_characters_is_refused() {
    let store = Store::open_in_memory().await.unwrap();
    let mut bad = peer(1);
    bad.exe = Some("/usr/bin/pam\n".to_owned());
    assert!(
        store
            .insert_boundary_observation(observation(&bad, OBSERVATION_ADMIN_CONTACT, false))
            .await
            .is_err()
    );
    assert!(
        store
            .insert_boundary_observation(observation(&peer(1), "something_else", false))
            .await
            .is_err()
    );
    assert!(
        store
            .count_boundary_observation(OBSERVATION_PUBLIC_UNKNOWN_HARNESS, true)
            .await
            .is_err()
    );
    assert!(
        store
            .list_boundary_observations(10)
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn the_request_row_carries_the_daemon_resolved_peer_facts() {
    let store = Store::open_in_memory().await.unwrap();
    request(&store, "req_a").await;
    assert_eq!(
        store.request_peer_facts("req_a").await.unwrap(),
        Some((None, None))
    );
    assert!(
        store
            .set_request_peer_facts("req_a", Some("/usr/local/bin/pam"), Some("claude"))
            .await
            .unwrap()
    );
    assert_eq!(
        store.request_peer_facts("req_a").await.unwrap(),
        Some((
            Some("/usr/local/bin/pam".to_owned()),
            Some("claude".to_owned())
        ))
    );
    assert!(
        !store
            .set_request_peer_facts("req_missing", None, None)
            .await
            .unwrap()
    );
    assert_eq!(store.request_peer_facts("req_missing").await.unwrap(), None);
    assert!(
        store
            .set_request_peer_facts("req_a", Some("bad\u{7f}"), None)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn an_empty_store_has_an_empty_census() {
    let store = Store::open_in_memory().await.unwrap();
    let census = store.boundary_census().await.unwrap();
    assert_eq!(census, crate::BoundaryCensus::default());
}
