//! Real IPC retrieval with fixture-owned immutable evidence, never native secrets.
use pam_proto::Response;
use pam_store::{EvidenceRangeOutcome, EvidenceRangeRequest, EvidenceViewInsert};
use pam_testkit::{
    TestClient, TestDaemon, envelope_for_repo, seed_relaxed, seed_repository_scope, short_tempdir,
};
use serde_json::{Value, json};

const ORIGINAL: &str = "evidence-origin";
const EVIDENCE: &str = "ev_fixture";
const VIEW: &str = "view_fixture";
const BYTES: &[u8] = b"A\xc3\xa9\0\xff\nZ";

struct Fixture {
    daemon: TestDaemon,
    client: TestClient,
    repo: String,
    _repo: tempfile::TempDir,
}

impl Fixture {
    async fn new() -> Self {
        let tmp = short_tempdir();
        let repo = short_tempdir();
        seed_relaxed(&tmp).await;
        seed_repository_scope(&tmp, repo.path(), &[]).await;
        let repository = repo
            .path()
            .canonicalize()
            .unwrap()
            .to_string_lossy()
            .into_owned();
        let daemon = TestDaemon::spawn_at(tmp).await;
        let mut client = daemon.client().await;
        result(
            client
                .request(&envelope_for_repo(
                    &repository,
                    ORIGINAL,
                    "echo",
                    json!({"source": ORIGINAL}),
                    true,
                ))
                .await,
        );
        let store = daemon.store();
        store
            .insert_evidence(EVIDENCE, ORIGINAL, "log_source", BYTES, None)
            .await
            .unwrap();
        assert!(
            store
                .insert_evidence_view(&EvidenceViewInsert {
                    evidence_id: EVIDENCE.into(),
                    request_id: ORIGINAL.into(),
                    repository: repository.clone(),
                    origin_json: json!({"targets": []}).to_string(),
                    identity_json: json!({"schema_version": 1, "source_kind": "fixture"})
                        .to_string(),
                    map_json: json!([{"view":{"start":0,"end":BYTES.len()},"parent":{"start":0,"end":BYTES.len()},"relation":"identity"}])
                        .to_string(),
                    view_id: VIEW.into(),
                    view_bytes: BYTES.to_vec(),
                })
                .await
                .unwrap()
        );
        Self {
            daemon,
            client,
            repo: repository,
            _repo: repo,
        }
    }

    async fn read(&mut self, id: &str, args: Value) -> Response {
        self.client
            .request(&envelope_for_repo(
                &self.repo,
                id,
                "evidence.read",
                args,
                true,
            ))
            .await
    }

    async fn stop(self) {
        self.daemon.assert_invariant_clean().await;
        self.daemon.stop().await;
    }
}

fn args() -> Value {
    json!({"request_id": ORIGINAL, "evidence_id": EVIDENCE, "length": 2})
}

fn result(response: Response) -> Value {
    match response {
        Response::Result { body, .. } => body,
        other => panic!("expected result, got {other:?}"),
    }
}

fn refusal(response: Response, expected: &str) {
    match response {
        Response::Refusal { cause, detail, .. } => {
            assert_eq!(cause, expected);
            assert!(!detail.contains("private original bytes"));
        }
        other => panic!("expected {expected}, got {other:?}"),
    }
}

#[tokio::test]
async fn exact_binary_pages_pin_the_view_and_charge_replays() {
    let mut fixture = Fixture::new().await;
    let first = result(fixture.read("page-one", args()).await);
    assert_eq!(first["data"], "41c3", "range may split a UTF-8 character");
    assert_eq!(first["encoding"], "hex");
    assert_eq!(first["returned_bytes"], 2);
    assert_eq!(first["total_bytes"], BYTES.len());
    assert_eq!(first["next_offset"], 2);
    assert_eq!(first["view_id"], VIEW);
    assert_eq!(first["request_id"], ORIGINAL);
    assert_eq!(first["evidence_id"], EVIDENCE);
    assert_eq!(
        first["view_sha256"],
        "72798e00ad8811b2ce24716f524a7027f381b40c41fa2585c46971888a958592"
    );
    let replay = result(fixture.read("page-replay", args()).await);
    assert_eq!(replay["data"], first["data"]);
    assert_eq!(
        replay["allowance"]["expires_at"],
        first["allowance"]["expires_at"]
    );
    assert_eq!(
        replay["allowance"]["remaining_bytes"].as_u64().unwrap() + 2,
        first["allowance"]["remaining_bytes"].as_u64().unwrap()
    );
    assert_eq!(
        replay["allowance"]["remaining_pages"].as_u64().unwrap() + 1,
        first["allowance"]["remaining_pages"].as_u64().unwrap()
    );
    let mut continuation = args();
    continuation["offset"] = json!(2);
    refusal(
        fixture
            .read("unbound-continuation", continuation.clone())
            .await,
        "invalid_evidence_range",
    );
    continuation["expected_view_id"] = json!(VIEW);
    continuation["expected_sha256"] = first["view_sha256"].clone();
    continuation["length"] = json!(65_536);
    let last = result(fixture.read("last-page", continuation.clone()).await);
    assert_eq!(last["data"], "a900ff0a5a");
    assert_eq!(last["next_offset"], Value::Null);
    assert_eq!(last["eof"], true);
    continuation["expected_sha256"] = json!("00".repeat(32));
    refusal(
        fixture.read("wrong-digest", continuation).await,
        "evidence_unavailable",
    );
    fixture.stop().await;
}

#[tokio::test]
async fn wrong_owner_repository_and_raw_only_evidence_are_unavailable() {
    let mut fixture = Fixture::new().await;
    result(
        fixture
            .client
            .request(&envelope_for_repo(
                &fixture.repo,
                "other-origin",
                "echo",
                json!({"source":"other-origin"}),
                true,
            ))
            .await,
    );
    let mut wrong = args();
    wrong["request_id"] = json!("other-origin");
    refusal(
        fixture.read("wrong-owner", wrong).await,
        "evidence_unavailable",
    );
    let other_repo = short_tempdir();
    let other = other_repo
        .path()
        .canonicalize()
        .unwrap()
        .to_string_lossy()
        .into_owned();
    let store = fixture.daemon.store();
    let mut scope: Value = serde_json::from_str(
        &store
            .get_setting("flows.scope_policy")
            .await
            .unwrap()
            .unwrap(),
    )
    .unwrap();
    scope["repositories"]
        .as_array_mut()
        .unwrap()
        .push(json!({"root": other, "connectors": []}));
    store
        .set_setting("flows.scope_policy", &scope.to_string())
        .await
        .unwrap();
    refusal(
        fixture
            .client
            .request(&envelope_for_repo(
                &other,
                "wrong-repository",
                "evidence.read",
                args(),
                true,
            ))
            .await,
        "evidence_unavailable",
    );
    store
        .insert_evidence(
            "ev_raw_only",
            ORIGINAL,
            "log_source",
            b"private original bytes",
            None,
        )
        .await
        .unwrap();
    let mut raw = args();
    raw["evidence_id"] = json!("ev_raw_only");
    refusal(fixture.read("raw-only", raw).await, "evidence_unavailable");
    fixture.stop().await;
}

#[tokio::test]
async fn revocation_invalidates_previous_evidence_authorization() {
    let mut fixture = Fixture::new().await;
    result(fixture.read("before-revocation", args()).await);
    let store = fixture.daemon.store();
    store.insert_grant("fixture.revoked").await.unwrap();
    store.revoke_grant("fixture.revoked").await.unwrap();
    refusal(
        fixture.read("after-revocation", args()).await,
        "evidence_unavailable",
    );
    fixture.stop().await;
}

#[tokio::test]
async fn retained_tombstones_report_expiry_only_to_the_authorized_owner() {
    let mut fixture = Fixture::new().await;
    fixture
        .daemon
        .store()
        .prune_evidence_before(i64::MAX, "verdict")
        .await
        .unwrap();
    refusal(
        fixture.read("retained-tombstone", args()).await,
        "evidence_expired",
    );
    let mut wrong = args();
    wrong["request_id"] = json!("unknown-origin");
    refusal(
        fixture.read("hidden-tombstone", wrong).await,
        "evidence_unavailable",
    );
    fixture.stop().await;
}

#[tokio::test]
async fn expired_first_read_allowance_is_not_renewed_by_the_daemon() {
    let mut fixture = Fixture::new().await;
    let store = fixture.daemon.store();
    let meta = store
        .evidence_view_meta(ORIGINAL, EVIDENCE, &fixture.repo)
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(
        store
            .read_evidence_view_range(&EvidenceRangeRequest {
                request_id: ORIGINAL.into(),
                evidence_id: EVIDENCE.into(),
                repository: fixture.repo.clone(),
                expected_view_id: VIEW.into(),
                expected_sha256: meta.view_sha256,
                offset: 0,
                length: 1,
                now: 0,
            })
            .await
            .unwrap(),
        EvidenceRangeOutcome::Range(_)
    ));
    refusal(
        fixture.read("expired-allowance", args()).await,
        "evidence_budget_exhausted",
    );
    fixture.stop().await;
}
