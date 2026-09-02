use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use pam_compact::MAX_SOURCE_BYTES;
use pam_proto::{Caller, Envelope, Outcome, PROTOCOL_VERSION, Response};
use pam_store::{EVIDENCE_KIND_LOG_COMPACT, RequestState, Store};
use serde_json::{Value, json};
use tokio::time::timeout;

use crate::admin::{
    ACTION_ADMIN, ADMIN_CALLER_AGENT, ADMIN_REPO, AdminService, CAUSE_ADMIN_DENIED,
    CAUSE_INVALID_ADMIN_ARGS,
};
use crate::admin_logs::{
    CAUSE_EVIDENCE_NOT_FOUND, CAUSE_SOURCE_TOO_LARGE, CAUSE_SOURCE_UNREADABLE, LOG_ADMIN_OPS,
    OP_EVIDENCE_GET, OP_EVIDENCE_LIST, OP_EVIDENCE_STATS, OP_LOG_COMPRESS, STATS_WINDOW_SECS,
};
use crate::approval::ApprovalService;
use crate::daemon::TERMINAL_ACTIONS;
use crate::log_service::{CAUSE_NO_DEFAULT, EVIDENCE_KIND_LOG_SOURCE, LogService};
use crate::model_service::ModelService;
use crate::transport::EventPublisher;

const DEADLINE: Duration = Duration::from_secs(20);

/// Approval timeout long enough never to fire here.
const LONG_TIMEOUT: Duration = Duration::from_mins(10);

// ---------------------------------------------------------------- fixture

/// An admin service over an in-memory store, with a temp directory to
/// write source logs into.
struct Fixture {
    store: Arc<Store>,
    admin: AdminService,
    dir: tempfile::TempDir,
    next: AtomicU32,
}

async fn fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = Arc::new(Store::open_in_memory().await.unwrap());
    let (events, _rx) = EventPublisher::for_tests();
    let approvals = Arc::new(ApprovalService::new(
        Arc::clone(&store),
        events,
        LONG_TIMEOUT,
    ));
    let models = ModelService::new(Arc::clone(&store)).await.unwrap();
    let logs = LogService::new(Arc::clone(&store), Arc::clone(&models));
    let admin = AdminService::new(Arc::clone(&store), approvals, models, logs);
    Fixture {
        store,
        admin,
        dir,
        next: AtomicU32::new(0),
    }
}

impl Fixture {
    /// Runs one admin op through the whole service (row, tripwire,
    /// deadline, audit) and returns the response with the request id it
    /// ran under — evidence rows hang off that id.
    async fn run(&self, op: &str, args: Value) -> (String, Response) {
        self.run_as(ADMIN_CALLER_AGENT, op, args).await
    }

    async fn run_as(&self, agent: &str, op: &str, args: Value) -> (String, Response) {
        let index = self.next.fetch_add(1, Ordering::Relaxed);
        let id = format!("req_log_{index:03}");
        let envelope = Envelope {
            v: PROTOCOL_VERSION,
            id: id.clone(),
            capability: op.to_owned(),
            client_version: env!("CARGO_PKG_VERSION").to_owned(),
            caller: Caller {
                agent: agent.to_owned(),
                repo: "/repo/anywhere".to_owned(),
                pid: 4242,
            },
            args,
            idempotency_key: None,
            deadline_ms: 15_000,
            wait: true,
        };
        let response = self.admin.handle(&envelope).await;
        self.assert_single_terminal_audit(&id, &response).await;
        (id, response)
    }

    /// The op's request row is terminal, belongs to the gui repo, and
    /// carries exactly one terminal audit row.
    async fn assert_single_terminal_audit(&self, id: &str, response: &Response) {
        let row = self
            .store
            .get_request(id)
            .await
            .unwrap()
            .unwrap_or_else(|| panic!("admin request {id} has a row"));
        assert_eq!(row.repo, ADMIN_REPO, "admin rows belong to the gui repo");
        let expected = match response {
            Response::Result { .. } => RequestState::Done,
            _ => RequestState::Refused,
        };
        assert_eq!(row.state, expected, "terminal state of {id}");
        let terminal: Vec<String> = self
            .store
            .audit_for_request(id)
            .await
            .unwrap()
            .into_iter()
            .filter(|audit| TERMINAL_ACTIONS.contains(&audit.action.as_str()))
            .map(|audit| audit.action)
            .collect();
        assert_eq!(
            terminal.len(),
            1,
            "request {id} should have exactly one terminal audit row, got {terminal:?}"
        );
    }

    /// The parsed detail of the request's `admin` audit row.
    async fn audit_detail(&self, id: &str) -> Value {
        let rows = self.store.audit_for_request(id).await.unwrap();
        let row = rows
            .into_iter()
            .find(|row| row.action == ACTION_ADMIN)
            .unwrap_or_else(|| panic!("request {id} has an {ACTION_ADMIN} audit row"));
        serde_json::from_str(&row.detail.expect("the audit row carries a detail")).unwrap()
    }

    /// Writes a log file into the fixture's directory and returns its
    /// absolute path.
    fn write_log(&self, name: &str, lines: usize) -> PathBuf {
        let mut text = String::new();
        for index in 0..lines {
            writeln!(text, "compiling unit {index}").unwrap();
        }
        text.push_str("error: boom\n");
        let path = self.dir.path().join(name);
        std::fs::write(&path, text).unwrap();
        path
    }

    /// Compresses one log and hands back the request id and the body.
    async fn compress(&self, path: &Path) -> (String, Value) {
        let (id, response) = self
            .run(
                OP_LOG_COMPRESS,
                json!({ "path": path.display().to_string(), "exit_status": 1 }),
            )
            .await;
        (id, expect_result(response, Outcome::Solved))
    }
}

/// Unwraps a result body, asserting the outcome.
fn expect_result(response: Response, outcome: Outcome) -> Value {
    match response {
        Response::Result {
            outcome: got, body, ..
        } => {
            assert_eq!(got, outcome, "result outcome");
            body
        }
        other => panic!("expected a result, got {other:?}"),
    }
}

/// Unwraps a refusal, asserting the cause and that a recovery came with
/// it — a cause with no way forward is not a legible refusal.
fn expect_refusal(response: Response, cause: &str) -> String {
    match response {
        Response::Refusal {
            cause: got,
            detail,
            recovery,
            ..
        } => {
            assert_eq!(got, cause, "refusal cause");
            assert!(!recovery.is_empty(), "a refusal carries a recovery line");
            detail
        }
        other => panic!("expected a refusal, got {other:?}"),
    }
}

fn now_ts() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    )
    .unwrap()
}

// ------------------------------------------------------------------ tests

#[tokio::test]
async fn compress_reads_the_file_and_answers_the_report() {
    timeout(DEADLINE, async {
        let fixture = fixture().await;
        let path = fixture.write_log("build.log", 50);
        let expected_bytes = std::fs::metadata(&path).unwrap().len();

        let (id, body) = fixture.compress(&path).await;

        assert_eq!(body["stats"]["source_bytes"], expected_bytes);
        assert_eq!(body["model_skipped"]["cause"], CAUSE_NO_DEFAULT);
        assert!(body["summary"].is_null(), "no model, no summary");
        assert!(
            body["source"]["id"]
                .as_str()
                .is_some_and(|id| id.starts_with("ev_")),
            "{}",
            body["source"]
        );
        assert!(
            body["compact_text"]
                .as_str()
                .is_some_and(|text| text.contains("error: boom")),
            "the failing line is retained"
        );

        let detail = fixture.audit_detail(&id).await;
        assert_eq!(detail["op"], OP_LOG_COMPRESS);
        assert_eq!(detail["name"], "build.log");
        assert_eq!(detail["source_bytes"], expected_bytes);
        assert_eq!(detail["compact_bytes"], body["stats"]["compact_bytes"]);
        assert_eq!(
            detail["tokens_avoided_est"],
            body["stats"]["tokens_avoided_est"]
        );
        assert_eq!(detail["summarized"], false);
        assert_eq!(detail["model_skipped"], CAUSE_NO_DEFAULT);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn compress_refuses_a_relative_path_and_a_missing_file() {
    timeout(DEADLINE, async {
        let fixture = fixture().await;

        let (_, response) = fixture
            .run(OP_LOG_COMPRESS, json!({ "path": "build.log" }))
            .await;
        expect_refusal(response, CAUSE_INVALID_ADMIN_ARGS);

        let missing = fixture.dir.path().join("definitely-missing.log");
        let (id, response) = fixture
            .run(
                OP_LOG_COMPRESS,
                json!({ "path": missing.display().to_string() }),
            )
            .await;
        let detail = expect_refusal(response, CAUSE_SOURCE_UNREADABLE);
        assert!(
            detail.contains(&missing.display().to_string()),
            "the detail names the path: {detail}"
        );
        assert!(
            fixture.store.list_evidence(&id).await.unwrap().is_empty(),
            "a refused compress leaves no evidence"
        );
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn compress_refuses_an_oversized_file_from_its_metadata() {
    timeout(DEADLINE, async {
        let fixture = fixture().await;
        let path = fixture.dir.path().join("huge.log");
        let file = std::fs::File::create(&path).unwrap();
        // Sparse: the bytes are never written, only the length claimed.
        file.set_len(u64::try_from(MAX_SOURCE_BYTES).unwrap() + 1)
            .unwrap();
        drop(file);

        let (id, response) = fixture
            .run(
                OP_LOG_COMPRESS,
                json!({ "path": path.display().to_string() }),
            )
            .await;

        expect_refusal(response, CAUSE_SOURCE_TOO_LARGE);
        assert!(
            fixture.store.list_evidence(&id).await.unwrap().is_empty(),
            "nothing was read, so nothing was stored"
        );
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn evidence_list_and_get_round_trip_through_the_ops() {
    timeout(DEADLINE, async {
        let fixture = fixture().await;
        let path = fixture.write_log("test.log", 60);
        let (request_id, report) = fixture.compress(&path).await;

        let (_, response) = fixture
            .run(OP_EVIDENCE_LIST, json!({ "request_id": request_id }))
            .await;
        let body = expect_result(response, Outcome::Verified);
        let listed = body["evidence"].as_array().expect("an evidence array");
        assert_eq!(listed.len(), 2);
        assert_eq!(listed[0]["kind"], EVIDENCE_KIND_LOG_SOURCE);
        assert_eq!(listed[1]["kind"], EVIDENCE_KIND_LOG_COMPACT);
        assert_eq!(listed[0]["request_id"], request_id);
        assert_eq!(listed[0]["bytes"], report["stats"]["source_bytes"]);
        assert!(
            listed[0]["sha256"]
                .as_str()
                .is_some_and(|hash| hash.len() == 64),
            "a hex sha256"
        );
        assert!(
            listed[1]["meta"].is_object(),
            "meta is parsed JSON, not a string: {}",
            listed[1]["meta"]
        );
        assert_eq!(listed[1]["meta"]["name"], "test.log");

        // The compact row reads back as its rendered text, not its JSON —
        // but `bytes` still reports the blob, the same figure the listing
        // gave for the same handle, so one id never shows two sizes.
        let compact_id = report["compact"]["id"].as_str().unwrap();
        let listed_compact_bytes = listed[1]["bytes"].clone();
        let (_, response) = fixture
            .run(OP_EVIDENCE_GET, json!({ "id": compact_id }))
            .await;
        let body = expect_result(response, Outcome::Verified);
        assert_eq!(body["kind"], EVIDENCE_KIND_LOG_COMPACT);
        assert_eq!(body["id"], compact_id);
        assert_eq!(body["text"], report["compact_text"]);
        assert_eq!(
            body["bytes"], listed_compact_bytes,
            "get and list agree on the blob length"
        );
        assert_eq!(
            body["text_bytes"].as_u64(),
            Some(report["compact_text"].as_str().unwrap().len() as u64),
            "text_bytes is the rendered text's length"
        );
        assert_ne!(
            body["bytes"], body["text_bytes"],
            "the JSON report really is bigger than the text it renders"
        );
        assert_eq!(body["truncated"], false);

        // A budget smaller than the text truncates and says so; for a
        // source row the blob and the text are the same bytes.
        let source_id = report["source"]["id"].as_str().unwrap();
        let file_len = std::fs::metadata(&path).unwrap().len();
        let (_, response) = fixture
            .run(OP_EVIDENCE_GET, json!({ "id": source_id, "max_bytes": 10 }))
            .await;
        let body = expect_result(response, Outcome::Verified);
        assert!(
            body["text"].as_str().expect("text").len() <= 10,
            "{}",
            body["text"]
        );
        assert_eq!(body["bytes"].as_u64(), Some(file_len));
        assert_eq!(body["text_bytes"].as_u64(), Some(file_len));
        assert_eq!(body["truncated"], true);

        let (_, response) = fixture
            .run(OP_EVIDENCE_GET, json!({ "id": "ev_nope" }))
            .await;
        expect_refusal(response, CAUSE_EVIDENCE_NOT_FOUND);

        // A request with no evidence is an empty list, not a refusal.
        let (_, response) = fixture
            .run(OP_EVIDENCE_LIST, json!({ "request_id": "req_nothing" }))
            .await;
        let body = expect_result(response, Outcome::Verified);
        assert_eq!(body["evidence"].as_array().unwrap().len(), 0);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn evidence_stats_reports_the_window() {
    timeout(DEADLINE, async {
        let fixture = fixture().await;
        let before = now_ts();
        let first = fixture.write_log("one.log", 40);
        let second = fixture.write_log("two.log", 90);
        let (_, one) = fixture.compress(&first).await;
        let (_, two) = fixture.compress(&second).await;
        let expected = one["stats"]["tokens_avoided_est"].as_u64().unwrap()
            + two["stats"]["tokens_avoided_est"].as_u64().unwrap();

        let (_, response) = fixture.run(OP_EVIDENCE_STATS, json!({})).await;
        let body = expect_result(response, Outcome::Verified);
        assert_eq!(body["compressions"], 2);
        assert_eq!(body["tokens_avoided_est"], expected);
        let since = body["since_ts"].as_i64().expect("since_ts");
        assert!(
            (before - STATS_WINDOW_SECS - 5..=now_ts() - STATS_WINDOW_SECS).contains(&since),
            "the default window is seven days back, got {since}"
        );

        let (_, response) = fixture
            .run(OP_EVIDENCE_STATS, json!({ "since_ts": now_ts() + 60 }))
            .await;
        let body = expect_result(response, Outcome::Verified);
        assert_eq!(body["compressions"], 0);
        assert_eq!(body["tokens_avoided_est"], 0);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn log_ops_are_gui_only() {
    timeout(DEADLINE, async {
        let fixture = fixture().await;
        let missing = fixture.dir.path().join("never-read.log");

        let (_, response) = fixture
            .run_as(
                "claude",
                OP_LOG_COMPRESS,
                json!({ "path": missing.display().to_string() }),
            )
            .await;

        // The tripwire fires before dispatch: the missing file is never
        // even measured, so this is `admin_denied`, not `source_unreadable`.
        expect_refusal(response, CAUSE_ADMIN_DENIED);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn every_log_op_is_answered_by_the_log_dispatcher() {
    timeout(DEADLINE, async {
        let fixture = fixture().await;
        for op in LOG_ADMIN_OPS {
            let (_, response) = fixture.run(op, json!({})).await;
            // Each is missing its required argument, which proves the op
            // name reached its handler rather than falling through to
            // `unknown_admin_op`.
            let cause = match op {
                &OP_EVIDENCE_STATS => continue,
                _ => CAUSE_INVALID_ADMIN_ARGS,
            };
            expect_refusal(response, cause);
        }
    })
    .await
    .unwrap();
}
