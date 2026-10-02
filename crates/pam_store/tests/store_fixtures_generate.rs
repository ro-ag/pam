//! Writes the database fixtures under `tests/fixtures/turso-0.7`: files
//! produced by the turso 0.7 engine, with what that same engine reads back
//! from them recorded next to each one (`expected.json`).
//!
//! Runs only on request, and rewrites the committed files:
//!
//! ```text
//! PAM_REGENERATE_STORE_FIXTURES=1 cargo test -p pam_store --test store_fixtures_generate
//! ```
//!
//! This file lives and dies with the turso engine. It names `turso` types and
//! includes `src/migrations.rs` by path, so it stops compiling the moment the
//! store moves to another engine; it is deleted then, and the fixtures are
//! never regenerated. `tests/store_fixtures.rs` is the part that stays.
//!
//! What writes what:
//!
//! - `v13-full` and `v13-wal`: every row goes through the public
//!   [`pam_store::Store`] API. The only statement outside it is the engine's
//!   own `PRAGMA wal_checkpoint(TRUNCATE)` on a raw connection, because the
//!   store has no close or checkpoint call and never moves its write-ahead log
//!   into the main file on drop.
//! - `v11`: the schema of release 0.4.3. The current store cannot produce it
//!   (opening migrates to the latest version, and its INSERTs name columns
//!   schema 11 lacks), so the file is built on a raw turso connection: the
//!   first eleven migrations verbatim from `src/migrations.rs`, then rows
//!   written with the statements release 0.4.3's store used.

// The seeds are lists of rows whose order is part of the fixture (admissions
// are numbered against the revocations before them); cutting a list to fit a
// line budget would hide that order, not make it clearer.
#![allow(clippy::too_many_lines)]

mod fixture_support;

// The store's own error type and migration texts, compiled into this test so
// schema 11 is rebuilt from the real migrations rather than from a copy.
#[allow(dead_code)]
#[path = "../src/error.rs"]
mod error;
#[allow(dead_code)]
#[path = "../src/migrations.rs"]
mod migrations;

use std::path::{Path, PathBuf};

use fixture_support::{
    AS_WRITTEN, DATABASE, FIXTURE_SET, MAIN_ONLY, copy_database, file_inventory, first_difference,
    fixture_dir, public_dump, row_digest, sha256_hex,
};
use pam_store::{
    Actor, ApprovalResolution, AuditEntry, ConnectorPatch, CorrelationBind, Decision,
    EvidencePrune, EvidenceRangeOutcome, EvidenceRangeRequest, EvidenceViewInsert,
    FlowJournalBegin, FlowJournalIdentity, GrantChange, GrantChangeOutcome, OUTCOME_ADMIN_DENIED,
    RequestBudgetCharge, RequestIngress, RequestOrigin, RequestPrune, RequestState, Store,
};
use serde_json::{Map, Value, json};
use turso::{Builder, Connection, Database, params};

/// Set to `1` to rewrite the committed fixtures.
const REGENERATE_ENV: &str = "PAM_REGENERATE_STORE_FIXTURES";

const REPO: &str = "/Users/ünï/pam-répo";
const REPO_QUOTED: &str = "/tmp/it's a \"repo\"";
const REPO_OTHER: &str = "/other/repo";
const AGENT: &str = "claude-code";
const AGENT_UNICODE: &str = "agënt ✓ 'q' \"d\"";
const UNICODE_TEXT: &str = "välue 'single' \"double\" \\ back\nnewline\ttab ✓ 日本語";
const ORIGIN: &str =
    r#"{"connector":"github","base_url":"https://api.github.com/","targets":["org/répo"]}"#;
const BINDING: &str = r#"{"schema_version":1,"decision":{"status":"matched"},"origin":{"connector":"github","call":"run","base_url":"https://api.github.com/"},"identity":{"repository":"org/repo","run_id":123456789,"run_attempt":1}}"#;
const KEEP_KIND: &str = "log.summary";
/// No admission in the fixtures outlives this deadline.
const FAR_MS: i64 = i64::MAX;
/// An evidence read allowance started here expired long ago.
const RANGE_NOW_PAST: i64 = 1_700_000_000;
/// An evidence read allowance started here never expires in practice.
const RANGE_NOW_FAR: i64 = i64::MAX - 7200;
/// The clock of every row in the schema-11 fixture.
const V11_TS: i64 = 1_750_000_000;

/// Stack for the generating thread. A debug build of the engine translates
/// an expression with one large frame per nesting level, and the per-row
/// rendering in [`raw_snapshot`] nests one level per column: far past the
/// 2 MiB a test thread gets.
const STACK_BYTES: usize = 256 * 1024 * 1024;

#[test]
fn regenerate_store_fixtures() {
    if std::env::var(REGENERATE_ENV).as_deref() != Ok("1") {
        eprintln!("skipped: set {REGENERATE_ENV}=1 to rewrite tests/fixtures/{FIXTURE_SET}");
        return;
    }
    let generator = std::thread::Builder::new()
        .stack_size(STACK_BYTES)
        .spawn(|| {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(regenerate());
        })
        .unwrap();
    generator.join().expect("the generator panicked");
}

async fn regenerate() {
    let scratch = tempfile::tempdir().unwrap();

    let full = scratch.path().join("v13-full");
    Box::pin(build_latest_full(&full)).await;
    Box::pin(publish(
        "v13-full",
        &full,
        &latest_probes(),
        "turso 0.7 through pam_store::Store at schema 13; write-ahead log moved into the \
         main file by the engine's own TRUNCATE checkpoint",
        scratch.path(),
    ))
    .await;

    let wal = scratch.path().join("v13-wal");
    Box::pin(build_latest_wal(&wal)).await;
    Box::pin(publish(
        "v13-wal",
        &wal,
        &latest_probes(),
        "turso 0.7 through pam_store::Store at schema 13; the three files copied while the \
         store was open and idle, the last commits only in the write-ahead log",
        scratch.path(),
    ))
    .await;

    let v11 = scratch.path().join("v11");
    build_v11(&v11).await;
    Box::pin(publish(
        "v11",
        &v11,
        &v11_probes(),
        "turso 0.7 on a raw connection: migrations 1 to 11 from src/migrations.rs, rows \
         written with release 0.4.3's statements, the last commits only in the write-ahead log",
        scratch.path(),
    ))
    .await;
}

// ---------------------------------------------------------------------------
// Raw engine access: the checkpoint, the per-table record of what the engine
// reads, and the schema-11 build.
// ---------------------------------------------------------------------------

async fn raw_open(path: &Path) -> (Database, Connection) {
    let db = Builder::new_local(path.to_str().unwrap())
        .build()
        .await
        .unwrap();
    let conn = db.connect().unwrap();
    (db, conn)
}

/// The first column of every row, as text.
async fn raw_lines(conn: &Connection, sql: &str) -> Vec<String> {
    let mut rows = conn
        .query(sql, ())
        .await
        .unwrap_or_else(|error| panic!("{sql}: {error}"));
    let mut out = Vec::new();
    while let Some(row) = rows.next().await.unwrap() {
        out.push(match row.get_value(0).unwrap() {
            turso::Value::Text(text) => text,
            turso::Value::Integer(number) => number.to_string(),
            turso::Value::Null => String::new(),
            other => panic!("{sql}: unexpected {other:?}"),
        });
    }
    out
}

/// One integer pragma, or `null` where the engine does not answer it.
async fn raw_pragma(conn: &Connection, name: &str) -> Value {
    let Ok(mut rows) = conn.query(&format!("PRAGMA {name}"), ()).await else {
        return Value::Null;
    };
    match rows.next().await {
        Ok(Some(row)) => row.get::<i64>(0).map_or(Value::Null, Value::from),
        _ => Value::Null,
    }
}

/// Moves the write-ahead log into the main file and empties it, with the
/// engine that wrote it.
async fn checkpoint(path: &Path) {
    let (db, conn) = raw_open(path).await;
    raw_lines(&conn, "PRAGMA wal_checkpoint(TRUNCATE)").await;
    drop((conn, db));
    let wal = path.with_file_name(format!("{DATABASE}-wal"));
    assert_eq!(
        std::fs::metadata(&wal).map_or(0, |meta| meta.len()),
        0,
        "the checkpoint left frames in the write-ahead log"
    );
}

/// What the engine itself reads from the database at `path`: the schema
/// version, the schema objects, and for every table its row count and one
/// short digest per row, in rowid order.
///
/// Each row is rendered inside the engine as `hex(quote(c1)||'|'||...)`, so
/// the same statement run by another engine on the same file yields the same
/// lines exactly when both read the same values of the same types. The
/// statement is recorded with the digests so the comparison needs no schema
/// knowledge.
async fn raw_snapshot(path: &Path) -> Value {
    let (db, conn) = raw_open(path).await;
    let tables = raw_lines(
        &conn,
        "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' \
         ORDER BY name",
    )
    .await;
    let mut out = Map::new();
    for table in tables {
        let mut columns = Vec::new();
        let mut info = conn
            .query(&format!("PRAGMA table_info(\"{table}\")"), ())
            .await
            .unwrap();
        while let Some(row) = info.next().await.unwrap() {
            columns.push(row.get::<String>(1).unwrap());
        }
        drop(info);
        assert!(!columns.is_empty(), "no columns reported for {table}");
        let rendered: Vec<String> = columns
            .iter()
            .map(|column| format!("quote(\"{column}\")"))
            .collect();
        let rows_sql = format!(
            "SELECT hex({}) FROM \"{table}\" ORDER BY rowid",
            rendered.join("||'|'||")
        );
        let lines = raw_lines(&conn, &rows_sql).await;
        let count = raw_lines(&conn, &format!("SELECT count(*) FROM \"{table}\"")).await;
        assert_eq!(count, [lines.len().to_string()]);
        out.insert(
            table,
            json!({
                "count": lines.len(),
                "rows_sql": rows_sql,
                "row_digests": lines.iter().map(|line| row_digest(line)).collect::<Vec<_>>(),
            }),
        );
    }
    let user_version: i64 = raw_lines(&conn, "PRAGMA user_version").await[0]
        .parse()
        .unwrap();
    let schema_objects = raw_lines(
        &conn,
        "SELECT type || ':' || name FROM sqlite_master ORDER BY 1",
    )
    .await;
    let page_count = raw_pragma(&conn, "page_count").await;
    let freelist_count = raw_pragma(&conn, "freelist_count").await;
    drop((conn, db));
    json!({
        "user_version": user_version,
        "page_count": page_count,
        "freelist_count": freelist_count,
        "schema_objects": schema_objects,
        "tables": out,
    })
}

// ---------------------------------------------------------------------------
// Recording: the expectation file of one fixture.
// ---------------------------------------------------------------------------

/// What the store's public reads return for a fresh copy of the database in
/// `captured`.
async fn read_through_store(captured: &Path, with_wal: bool, probes: &Value, to: &Path) -> Value {
    let path = copy_database(captured, to, with_wal);
    let store = Store::open(&path).await.unwrap();
    store.check_integrity().await.unwrap();
    let dump = Box::pin(public_dump(&store, probes)).await;
    drop(store);
    dump
}

async fn variant(captured: &Path, with_wal: bool, probes: &Value, scratch: &Path) -> Value {
    let tag = if with_wal { "wal" } else { "main" };
    let name = captured.file_name().unwrap().to_string_lossy().into_owned();
    let work = |step: &str| scratch.join(format!("{name}-{tag}-{step}"));
    let raw = raw_snapshot(&copy_database(captured, &work("raw"), with_wal)).await;
    let public = read_through_store(captured, with_wal, probes, &work("read")).await;
    // The oracle must not depend on when or how often it is taken.
    let again = read_through_store(captured, with_wal, probes, &work("again")).await;
    if let Some(difference) = first_difference(&again, &public, "") {
        panic!("{name} ({tag}): two reads of the same files differ at {difference}");
    }
    json!({ "raw": raw, "public": public })
}

/// The two triggers of schema 12 refuse a forbidden update under the engine
/// that wrote the file. No public store call attempts one, so this is the
/// only place the refusal is exercised; it runs on a scratch copy.
async fn assert_triggers_refuse(captured: &Path, scratch: &Path) {
    let name = captured.file_name().unwrap().to_string_lossy().into_owned();
    let path = copy_database(captured, &scratch.join(format!("{name}-triggers")), true);
    let (db, conn) = raw_open(&path).await;
    for (update, refusal) in [
        (
            "UPDATE audit SET detail = 'tampered'",
            "audit rows are append-only",
        ),
        (
            "UPDATE evidence_view SET view_sha256 = 'tampered'",
            "evidence views are immutable",
        ),
    ] {
        let error = conn
            .execute(update, ())
            .await
            .expect_err("the trigger let a forbidden update through");
        assert!(error.to_string().contains(refusal), "{update}: {error}");
    }
    drop((conn, db));
}

/// Records what the engine and the store read from `captured`, then replaces
/// the committed fixture `name` with the files and the record.
async fn publish(name: &str, captured: &Path, probes: &Value, written_by: &str, scratch: &Path) {
    let wal_bytes =
        std::fs::metadata(captured.join(format!("{DATABASE}-wal"))).map_or(0, |meta| meta.len());
    if name.starts_with("v13") {
        assert_triggers_refuse(captured, scratch).await;
    }
    let mut variants = Map::new();
    variants.insert(
        AS_WRITTEN.to_owned(),
        Box::pin(variant(captured, true, probes, scratch)).await,
    );
    if wal_bytes > 0 {
        let main_only = Box::pin(variant(captured, false, probes, scratch)).await;
        assert!(
            first_difference(&main_only["public"], &variants[AS_WRITTEN]["public"], "").is_some(),
            "{name}: the write-ahead log carries nothing the main file lacks"
        );
        variants.insert(MAIN_ONLY.to_owned(), main_only);
    }
    let expected = json!({
        "format": 1,
        "fixture": name,
        "written_by": written_by,
        "files": file_inventory(captured),
        "probes": probes,
        "variants": variants,
    });
    let target = fixture_dir(name);
    if target.exists() {
        std::fs::remove_dir_all(&target).unwrap();
    }
    copy_database(captured, &target, true);
    let mut text = String::new();
    render(&expected, 0, &mut text);
    text.push('\n');
    std::fs::write(target.join("expected.json"), text).unwrap();
    println!("{name}: {}", file_inventory(&target));
}

/// Writes `value` indented down to the level of a table's rows and compact
/// below it, so a row, a digest list or a statement is one line of the file.
fn render(value: &Value, depth: usize, out: &mut String) {
    const EXPANDED_LEVELS: usize = 6;
    let scalar = |value: &Value| !matches!(value, Value::Object(_) | Value::Array(_));
    let line = |out: &mut String, depth: usize| {
        out.push('\n');
        out.push_str(&" ".repeat(depth));
    };
    match value {
        Value::Object(fields) if depth < EXPANDED_LEVELS && !fields.is_empty() => {
            out.push('{');
            for (index, (key, field)) in fields.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                line(out, depth + 1);
                out.push_str(&Value::from(key.as_str()).to_string());
                out.push_str(": ");
                render(field, depth + 1, out);
            }
            line(out, depth);
            out.push('}');
        }
        Value::Array(items)
            if depth < EXPANDED_LEVELS && !items.is_empty() && !items.iter().all(scalar) =>
        {
            out.push('[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                line(out, depth + 1);
                render(item, depth + 1, out);
            }
            line(out, depth);
            out.push(']');
        }
        compact => out.push_str(&compact.to_string()),
    }
}

// ---------------------------------------------------------------------------
// Schema 13, through the public store API.
// ---------------------------------------------------------------------------

async fn build_latest_full(dir: &Path) {
    std::fs::create_dir_all(dir).unwrap();
    let path = dir.join(DATABASE);
    let store = Store::open(&path).await.unwrap();
    Box::pin(seed_latest(&store, true)).await;
    drop(store);
    checkpoint(&path).await;
}

/// The same kind of database, left the way a daemon that was killed leaves
/// it: the main file as of its last checkpoint, later commits in the log.
async fn build_latest_wal(dir: &Path) {
    let live = dir.join("live");
    std::fs::create_dir_all(&live).unwrap();
    let path = live.join(DATABASE);
    let store = Store::open(&path).await.unwrap();
    Box::pin(seed_latest(&store, false)).await;
    drop(store);
    checkpoint(&path).await;
    let checkpointed = sha256_hex(&std::fs::read(&path).unwrap());

    let store = Store::open(&path).await.unwrap();
    Box::pin(seed_latest_delta(&store)).await;
    // Every call above has returned, so nothing is in flight: the files are
    // copied as they stand, with the store still open.
    copy_database(&live, dir, true);
    drop(store);

    // Dropping the store changed nothing, so the copy is what a crash at that
    // moment leaves; and the main file is still the checkpointed one, so the
    // commits since then are in the log alone.
    assert_eq!(
        file_inventory(dir),
        file_inventory(&live),
        "the files changed between the copy and the store's drop"
    );
    assert_eq!(sha256_hex(&std::fs::read(&path).unwrap()), checkpointed);
    assert!(
        std::fs::metadata(dir.join(format!("{DATABASE}-wal")))
            .unwrap()
            .len()
            > 0
    );
    std::fs::remove_dir_all(&live).unwrap();
}

fn latest_probes() -> Value {
    json!({
        "setting_keys": [
            "policy.profile", "retention.evidence_days", "retention.audit_days",
            "retention.watermark_ts", "retention.last_run", "retention.clock_guard",
            "flows.scope_policy", "setting.empty", "setting.large", "setting.overwritten",
            "kéy 'q' \"d\" ✓", "wal.only", "missing.key",
        ],
        "repositories": [REPO, REPO_QUOTED, REPO_OTHER],
        "views": [
            ["req_00_pruned", "ev_00_source", REPO],
            ["req_01_tombstone", "ev_01_source", REPO],
            ["req_01_tombstone", "ev_01_summary", REPO],
            ["req_03_flow_voided", "ev_03_result", REPO_QUOTED],
            ["req_30_evidence", "ev_30_empty", REPO],
            ["req_30_evidence", "ev_30_small", REPO],
            ["req_30_evidence", "ev_30_small", REPO_OTHER],
            ["req_30_evidence", "ev_30_large", REPO],
            ["req_31_foreign", "ev_31_source", REPO_OTHER],
            ["req_32_ready", "ev_32_result", REPO],
            ["req_40_watch", "ev_40_watch", REPO],
            ["req_50_late_prune", "ev_50_source", REPO],
            ["missing", "missing", REPO],
        ],
        "now_ms": [0, 1_850_000_000_000_i64, i64::MAX],
        "terminal_actions": [
            "execute", "admin.grants.revoke", "admin.grants.add", "admin.tripwire", "approval",
        ],
        "keep_kind": KEEP_KIND,
    })
}

/// Deterministic bytes with no NUL among them.
fn noise(len: usize, seed: u32) -> Vec<u8> {
    let mut state = seed;
    (0..len)
        .map(|_| {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            state.to_be_bytes()[0].max(1)
        })
        .collect()
}

fn digest(fill: char) -> String {
    fill.to_string().repeat(64)
}

fn entry<'a>(
    action: &'a str,
    decision: Decision,
    actor: Actor,
    detail: Option<&'a str>,
) -> AuditEntry<'a> {
    AuditEntry {
        action,
        decision,
        actor,
        detail,
    }
}

fn identity(id: &str, repository: &str) -> FlowJournalIdentity {
    FlowJournalIdentity {
        request_id: id.to_owned(),
        flow_digest: digest('a'),
        repository: repository.to_owned(),
        input_fingerprint: digest('b'),
    }
}

fn landing_document(repository: &str, step: &str, operation: &str) -> String {
    json!({
        "version": 1,
        "flow_digest": digest('a'),
        "repository": repository,
        "intent": { "step_id": step, "state": "prepared", "operation": operation },
        "note": UNICODE_TEXT,
    })
    .to_string()
}

/// A redacted view of `evidence_id` with a provenance map of `segments`
/// entries; more than one segment is recorded as a coarsened map.
fn view(
    request_id: &str,
    evidence_id: &str,
    repository: &str,
    bytes: Vec<u8>,
    segments: u64,
) -> EvidenceViewInsert {
    let map: Vec<Value> = (0..segments)
        .map(|index| {
            json!({
                "view": { "start": index * 16, "end": index * 16 + 16 },
                "parent": { "start": index * 64, "end": index * 64 + 48 },
                "relation": if segments > 1 { "coarse" } else { "identity" },
            })
        })
        .collect();
    let mut identity = json!({
        "schema_version": 1, "evidence_id": evidence_id, "request_id": request_id,
        "captured_at": 1_700_000_000, "offset_basis": "view_bytes",
        "redaction": { "policy": "detectors ü1", "replacements": 2 },
        "completeness": "not_asserted",
    });
    if segments > 1 {
        identity["provenance_map"] = json!({
            "resolution": "coarsened", "segments": segments,
            "source_segments": segments * 4, "merged_segments": segments * 3,
        });
    }
    EvidenceViewInsert {
        evidence_id: evidence_id.to_owned(),
        request_id: request_id.to_owned(),
        repository: repository.to_owned(),
        origin_json: ORIGIN.to_owned(),
        identity_json: identity.to_string(),
        map_json: Value::Array(map).to_string(),
        view_id: format!("view_{evidence_id}"),
        view_bytes: bytes,
    }
}

async fn add_view(store: &Store, view: &EvidenceViewInsert) {
    assert!(
        store.insert_evidence_view(view).await.unwrap(),
        "no evidence row for view {}",
        view.view_id
    );
}

/// One charged range read of a stored view; `now` starts the request's
/// allowance when it has none.
async fn read_range(store: &Store, view: &EvidenceViewInsert, offset: u64, length: u32, now: i64) {
    let outcome = store
        .read_evidence_view_range(&EvidenceRangeRequest {
            request_id: view.request_id.clone(),
            evidence_id: view.evidence_id.clone(),
            repository: view.repository.clone(),
            expected_view_id: view.view_id.clone(),
            expected_sha256: sha256_hex(&view.view_bytes),
            offset,
            length,
            now,
        })
        .await
        .unwrap();
    assert!(
        matches!(outcome, EvidenceRangeOutcome::Range(_)),
        "{}: {outcome:?}",
        view.view_id
    );
}

async fn admit(store: &Store, id: &str, capability: &str, repo: &str) {
    store
        .insert_admitted_request(id, capability, repo, AGENT, "{}", None, FAR_MS)
        .await
        .unwrap();
}

/// A flow ticket the way the daemon leaves it once dispatched: admitted,
/// authorized for the queue, and started.
async fn admit_flow(store: &Store, id: &str, repo: &str) {
    admit(store, id, "flow.run", repo).await;
    assert!(store.authorize_queued_request(id, repo, 0).await.unwrap());
    assert!(store.start_queued_request(id, 0).await.unwrap());
}

async fn begin_journal(store: &Store, id: &str, repo: &str, checkpoint: &str) {
    assert_eq!(
        store
            .begin_flow_journal(&identity(id, repo), checkpoint)
            .await
            .unwrap(),
        FlowJournalBegin::Inserted
    );
}

async fn finish(
    store: &Store,
    id: &str,
    state: RequestState,
    outcome: Option<&str>,
    audit: AuditEntry<'_>,
) {
    assert!(
        store
            .finish_request(id, state, outcome, audit)
            .await
            .unwrap(),
        "{id} was already terminal"
    );
}

/// Every table and row kind the public API can write. `large` picks the
/// sizes of the two biggest blobs.
async fn seed_latest(store: &Store, large: bool) {
    seed_settings(store).await;
    Box::pin(seed_pruned_record(store)).await;
    seed_tombstone(store).await;
    Box::pin(seed_grants(store)).await;
    Box::pin(seed_grant_changes(store)).await;
    Box::pin(seed_states(store)).await;
    Box::pin(seed_terminal_states(store)).await;
    Box::pin(seed_edge_rows(store)).await;
    Box::pin(seed_approvals(store)).await;
    Box::pin(seed_evidence(store, large)).await;
    Box::pin(seed_flows(store)).await;
    Box::pin(seed_flow_lifecycles(store)).await;
    Box::pin(seed_flow_effects(store)).await;
    seed_connectors(store).await;
    seed_model_jobs(store).await;
    seed_late_prune(store, large).await;
    for (agent, repo) in [
        (AGENT, REPO),
        (AGENT_UNICODE, REPO_QUOTED),
        (AGENT, REPO),
        ("", ""),
    ] {
        store.upsert_caller(agent, repo).await.unwrap();
    }
}

async fn seed_settings(store: &Store) {
    store
        .set_setting("policy.profile", "\"relaxed\"")
        .await
        .unwrap();
    store
        .set_settings(&[
            ("retention.evidence_days", "30"),
            ("retention.audit_days", "365"),
        ])
        .await
        .unwrap();
    store
        .set_setting("retention.watermark_ts", "1700000000")
        .await
        .unwrap();
    store
        .set_setting(
            "retention.last_run",
            r#"{"ts":1700000000,"evidence_rows":3,"requests":1}"#,
        )
        .await
        .unwrap();
    store
        .set_setting("retention.clock_guard", "1700000000")
        .await
        .unwrap();
    let first = json!({ "version": 1, "repositories": [{ "root": REPO }] }).to_string();
    let second = json!({
        "version": 1,
        "repositories": [{ "root": REPO, "note": UNICODE_TEXT }, { "root": REPO_QUOTED }],
    })
    .to_string();
    let key = "flows.scope_policy";
    assert!(
        store
            .compare_exchange_setting(key, None, &first)
            .await
            .unwrap()
    );
    assert!(
        !store
            .compare_exchange_setting(key, Some("stale"), &second)
            .await
            .unwrap()
    );
    assert!(
        store
            .compare_exchange_setting(key, Some(&first), &second)
            .await
            .unwrap()
    );
    store.set_setting("setting.empty", "").await.unwrap();
    // Exactly the 32 KiB a bounded read accepts, in two-byte characters.
    store
        .set_setting("setting.large", &"é".repeat(16_384))
        .await
        .unwrap();
    store
        .set_setting("kéy 'q' \"d\" ✓", UNICODE_TEXT)
        .await
        .unwrap();
    store.set_setting("setting.overwritten", "1").await.unwrap();
    store.set_setting("setting.overwritten", "2").await.unwrap();
}

/// A whole record, with a row in every table that hangs off a request, which
/// the audit window then removes: the file keeps the pages those rows freed.
async fn seed_pruned_record(store: &Store) {
    let id = "req_00_pruned";
    admit_flow(store, id, REPO).await;
    store
        .append_audit(id, "enqueue", Decision::Allow, Actor::Policy, None)
        .await
        .unwrap();
    store.load_request_budget(id).await.unwrap();
    store
        .reserve_request_budget(id, RequestBudgetCharge::Attempt)
        .await
        .unwrap()
        .unwrap();
    begin_journal(store, id, REPO, "{}").await;
    let document = landing_document(REPO, "push", "push");
    assert!(
        store
            .save_landing_session(id, None, &document, 0)
            .await
            .unwrap()
    );
    store.bind_correlation_target(id, "{}").await.unwrap();
    store
        .bind_correlation_step(id, "run", BINDING)
        .await
        .unwrap();
    store
        .append_correlation_membership(id, "run", BINDING, &[1, 2])
        .await
        .unwrap()
        .unwrap();
    let content = b"bytes the audit window removes";
    store
        .insert_evidence("ev_00_source", id, "log.source", content, None)
        .await
        .unwrap();
    let pruned_view = view(id, "ev_00_source", REPO, b"redacted".to_vec(), 1);
    add_view(store, &pruned_view).await;
    read_range(store, &pruned_view, 0, 4, RANGE_NOW_PAST).await;
    store
        .insert_approval(id, "flow.step:github.run")
        .await
        .unwrap();
    store
        .resolve_approval(id, ApprovalResolution::Approved, None)
        .await
        .unwrap();
    let done = entry("execute", Decision::Allow, Actor::System, None);
    finish(store, id, RequestState::Done, Some("ok"), done).await;
    assert_eq!(
        store.prune_requests_before(i64::MAX).await.unwrap(),
        RequestPrune {
            requests: 1,
            audit_rows: 2,
            approvals: 1,
            evidence_rows: 1,
            evidence_bytes: 30,
        }
    );
}

/// A finished request whose source evidence the evidence window removed: the
/// view stays as a tombstone (blob NULL, `expired_at` set) and the kept kind
/// stays whole.
async fn seed_tombstone(store: &Store) {
    let id = "req_01_tombstone";
    store
        .insert_request(
            id,
            "log.compress",
            REPO,
            AGENT,
            r#"{"path":"build.log"}"#,
            None,
        )
        .await
        .unwrap();
    store
        .insert_evidence("ev_01_source", id, "log.source", &noise(6000, 1), None)
        .await
        .unwrap();
    store
        .insert_evidence(
            "ev_01_summary",
            id,
            KEEP_KIND,
            "résumé: 3 errors — 'quoted' \"double\" ✓ 日本語".as_bytes(),
            Some(r#"{"model":"qwen ü"}"#),
        )
        .await
        .unwrap();
    add_view(store, &view(id, "ev_01_source", REPO, noise(1500, 2), 1)).await;
    add_view(store, &view(id, "ev_01_summary", REPO, noise(300, 3), 1)).await;
    let done = entry("execute", Decision::Allow, Actor::System, None);
    finish(store, id, RequestState::Done, Some("compressed"), done).await;
    assert_eq!(
        store
            .prune_evidence_before(i64::MAX, KEEP_KIND)
            .await
            .unwrap(),
        EvidencePrune {
            rows: 1,
            bytes: 6000
        }
    );
}

/// Plain grants, two requests admitted under them, and the first of three
/// numbered revocations with its re-grant. [`seed_grant_changes`] revokes
/// the grants those two admissions depend on, which voids both.
async fn seed_grants(store: &Store) {
    for capability in [
        "echo",
        "log.compress",
        "flow.run",
        "flow.step:github.run",
        "ünï 'q' \"d\"",
    ] {
        store.insert_grant(capability).await.unwrap();
    }
    // Admitted before the revocations below: both end up voided.
    admit(store, "req_02_voided", "log.compress", REPO).await;
    store
        .insert_admitted_request(
            "req_03_flow_voided",
            "flow.run",
            REPO_QUOTED,
            AGENT_UNICODE,
            "{}",
            None,
            FAR_MS,
        )
        .await
        .unwrap();
    store
        .insert_evidence(
            "ev_03_result",
            "req_03_flow_voided",
            "flow.result",
            b"{}",
            Some(r#"{"agent_result":{"status":"passed"}}"#),
        )
        .await
        .unwrap();
    let voided_view = view(
        "req_03_flow_voided",
        "ev_03_result",
        REPO_QUOTED,
        b"ok".to_vec(),
        1,
    );
    add_view(store, &voided_view).await;

    store.revoke_grant("echo").await.unwrap();
    store.insert_grant("echo").await.unwrap();
}

/// The audited ways to change a grant: the administration plane's grant and
/// revoke, which finish their request in the same transaction, and the
/// relaxed profile's grant in the middle of a request.
async fn seed_grant_changes(store: &Store) {
    let admin = |id: &'static str, capability: &'static str| async move {
        store
            .insert_running_request_from(
                id,
                capability,
                "",
                "gui",
                r#"{"capability":"…"}"#,
                None,
                &RequestOrigin::ADMIN,
            )
            .await
            .unwrap();
    };
    admin("req_04_admin_revoke", "admin.grants.revoke").await;
    let revoked = entry(
        "admin.grants.revoke",
        Decision::Allow,
        Actor::Human,
        Some(r#"{"capability":"log.compress"}"#),
    );
    assert_eq!(
        store
            .finish_request_with_grant_change(
                "req_04_admin_revoke",
                GrantChange::Revoke("log.compress"),
                Some("revoked"),
                revoked,
            )
            .await
            .unwrap(),
        GrantChangeOutcome::Applied
    );
    admin("req_05_admin_grant", "admin.grants.add").await;
    admin("req_06_admin_noop", "admin.grants.add").await;
    let granted = entry("admin.grants.add", Decision::Allow, Actor::Human, None);
    for (id, outcome) in [
        ("req_05_admin_grant", GrantChangeOutcome::Applied),
        ("req_06_admin_noop", GrantChangeOutcome::Unchanged),
    ] {
        assert_eq!(
            store
                .finish_request_with_grant_change(
                    id,
                    GrantChange::Add("git.push"),
                    Some("granted"),
                    granted,
                )
                .await
                .unwrap(),
            outcome
        );
    }
    let noop = entry("admin.grants.add", Decision::Refuse, Actor::Policy, None);
    let state = RequestState::Refused;
    finish(
        store,
        "req_06_admin_noop",
        state,
        Some("already_granted"),
        noop,
    )
    .await;

    store.revoke_grant("flow.step:github.run").await.unwrap();
    store.insert_grant("flow.step:github.run").await.unwrap();

    store
        .insert_admitted_request(
            "req_07_autogrant",
            "git.fetch",
            REPO,
            AGENT,
            "{}",
            Some("key-7"),
            FAR_MS,
        )
        .await
        .unwrap();
    let auto = entry(
        "auto_grant",
        Decision::Allow,
        Actor::Policy,
        Some(r#"{"profile":"relaxed"}"#),
    );
    for (change, outcome) in [
        (GrantChange::Add("git.fetch"), GrantChangeOutcome::Applied),
        (GrantChange::Add("git.fetch"), GrantChangeOutcome::Unchanged),
        (
            GrantChange::Revoke("never.granted"),
            GrantChangeOutcome::Unchanged,
        ),
    ] {
        assert_eq!(
            store
                .apply_grant_change_audited("req_07_autogrant", change, auto)
                .await
                .unwrap(),
            outcome
        );
    }
    assert_eq!(store.grant_revocation_revision().await.unwrap(), 3);
}

/// A request in each in-flight state, with each kind of origin and key.
async fn seed_states(store: &Store) {
    store
        .insert_request(
            "req_10_queued",
            "echo",
            REPO,
            AGENT,
            r#"{"text":"hi"}"#,
            None,
        )
        .await
        .unwrap();
    store
        .insert_running_request("req_11_status_probe", "status", "", AGENT, "{}", None)
        .await
        .unwrap();
    let relayed = RequestOrigin {
        ingress: RequestIngress::Public,
        peer_uid: Some(501),
        peer_pid: Some(4242),
        relayed: true,
    };
    let args = json!({ "text": UNICODE_TEXT }).to_string();
    store
        .insert_admitted_request_from(
            "req_12_admitted",
            "echo",
            REPO,
            AGENT_UNICODE,
            &args,
            Some("idem-'12'"),
            FAR_MS,
            &relayed,
        )
        .await
        .unwrap();
    admit(store, "req_13_authorized", "echo", REPO).await;
    assert!(
        store
            .authorize_queued_request("req_13_authorized", REPO, 0)
            .await
            .unwrap()
    );
    admit(store, "req_14_started", "echo", REPO).await;
    assert!(
        store
            .authorize_queued_request("req_14_started", REPO, 0)
            .await
            .unwrap()
    );
    assert!(
        store
            .start_queued_request("req_14_started", 0)
            .await
            .unwrap()
    );
}

/// A request in each terminal state: with and without an outcome, a refused
/// administration attempt, and one failed by its deadline.
async fn seed_terminal_states(store: &Store) {
    store
        .insert_request("req_20_done", "echo", REPO, AGENT, "{}", Some(""))
        .await
        .unwrap();
    let done = entry(
        "execute",
        Decision::Allow,
        Actor::System,
        Some(UNICODE_TEXT),
    );
    let outcome = Some(r#"{"ok":true}"#);
    finish(store, "req_20_done", RequestState::Done, outcome, done).await;

    let extreme = RequestOrigin {
        ingress: RequestIngress::Public,
        peer_uid: Some(u32::MAX),
        peer_pid: Some(0),
        relayed: false,
    };
    store
        .insert_running_request_from(
            "req_21_admin_denied",
            "admin.grants.add",
            REPO,
            "intruder",
            "{}",
            None,
            &extreme,
        )
        .await
        .unwrap();
    let tripwire = entry(
        "admin.tripwire",
        Decision::Refuse,
        Actor::Policy,
        Some("{}"),
    );
    let denied = Some(OUTCOME_ADMIN_DENIED);
    let state = RequestState::Refused;
    finish(store, "req_21_admin_denied", state, denied, tripwire).await;

    store
        .insert_request("req_22_failed", "echo", REPO, AGENT, "{}", None)
        .await
        .unwrap();
    let failed = entry("execute", Decision::Refuse, Actor::System, None);
    finish(store, "req_22_failed", RequestState::Failed, None, failed).await;

    // The smallest deadline there is; only this row is behind `now_ms = -1`.
    store
        .insert_admitted_request("req_23_expired", "echo", REPO, AGENT, "{}", None, i64::MIN)
        .await
        .unwrap();
    let reaped = entry("reap", Decision::Timeout, Actor::System, None);
    assert_eq!(
        store
            .fail_expired_requests(-1, 64, "deadline_exceeded", reaped)
            .await
            .unwrap(),
        ["req_23_expired"]
    );
}

/// Rows at the edges: an outcome on a request still in flight, empty and
/// non-ASCII text in every column, arguments long enough to overflow a
/// page, and the administration plane's own traffic.
async fn seed_edge_rows(store: &Store) {
    store
        .insert_request("req_24_resumed", "echo", REPO, AGENT, "{}", None)
        .await
        .unwrap();
    store
        .update_request_state("req_24_resumed", RequestState::Running, Some("resumed ✓"))
        .await
        .unwrap();
    store
        .insert_running_request_from(
            "req_25_admin_compress",
            "admin.log.compress",
            REPO,
            "gui",
            "{}",
            None,
            &RequestOrigin::ADMIN,
        )
        .await
        .unwrap();
    store
        .insert_request("req_26_ünï 'q' \"d\"", "", "", "", "", Some(""))
        .await
        .unwrap();
    let big = json!({ "text": "ünï-✓ ".repeat(2000) }).to_string();
    let wide = RequestOrigin {
        ingress: RequestIngress::Public,
        peer_uid: Some(0),
        peer_pid: Some(u32::MAX),
        relayed: false,
    };
    store
        .insert_admitted_request_from(
            "req_27_big_args",
            "echo",
            REPO_QUOTED,
            AGENT,
            &big,
            Some("idem-27"),
            2_000_000_000_000,
            &wide,
        )
        .await
        .unwrap();
    store
        .insert_running_request_from(
            "req_28_admin_probe",
            "admin.status",
            "",
            "gui",
            "{}",
            None,
            &RequestOrigin::ADMIN,
        )
        .await
        .unwrap();
}

/// An approval in each resolution, one still pending, and one request with
/// two approval rows.
async fn seed_approvals(store: &Store) {
    let capability = "deploy";
    admit(store, "req_15_waiting", capability, REPO).await;
    store
        .insert_approval_waiting("req_15_waiting", capability)
        .await
        .unwrap();

    admit(store, "req_16_approved", capability, REPO).await;
    store
        .insert_approval_waiting("req_16_approved", capability)
        .await
        .unwrap();
    let approved = entry("approval", Decision::Approve, Actor::Human, Some("{}"));
    let remembered = entry("grant", Decision::Allow, Actor::Human, None);
    assert!(
        store
            .resolve_approval_audited(
                "req_16_approved",
                ApprovalResolution::Approved,
                Some("lgtm ✓ — 'ok'"),
                approved,
                Some((capability, remembered)),
            )
            .await
            .unwrap(),
        "the approval should have written a new grant"
    );
    store
        .update_request_state("req_16_approved", RequestState::Running, None)
        .await
        .unwrap();
    let done = entry("execute", Decision::Allow, Actor::System, None);
    let state = RequestState::Done;
    finish(store, "req_16_approved", state, Some("deployed"), done).await;

    store
        .insert_request("req_17_denied", capability, REPO, AGENT, "{}", None)
        .await
        .unwrap();
    store
        .insert_approval("req_17_denied", capability)
        .await
        .unwrap();
    let note = Some("no; \"prod\" freeze");
    store
        .resolve_approval("req_17_denied", ApprovalResolution::Denied, note)
        .await
        .unwrap();
    let denied = entry("approval", Decision::Deny, Actor::Human, None);
    let state = RequestState::Refused;
    finish(store, "req_17_denied", state, Some("denied"), denied).await;

    admit(store, "req_18_timeout", capability, REPO).await;
    store
        .insert_approval_waiting("req_18_timeout", capability)
        .await
        .unwrap();
    let timeout = entry("approval", Decision::Timeout, Actor::System, None);
    assert!(
        !store
            .resolve_approval_audited(
                "req_18_timeout",
                ApprovalResolution::Timeout,
                None,
                timeout,
                None,
            )
            .await
            .unwrap()
    );
    let state = RequestState::Failed;
    let outcome = Some("approval_timeout");
    finish(store, "req_18_timeout", state, outcome, timeout).await;

    // Two approval rows: the public read returns the newer, unresolved one.
    store
        .insert_request("req_19_two_approvals", capability, REPO, AGENT, "{}", None)
        .await
        .unwrap();
    store
        .insert_approval("req_19_two_approvals", capability)
        .await
        .unwrap();
    store
        .resolve_approval("req_19_two_approvals", ApprovalResolution::Approved, None)
        .await
        .unwrap();
    store
        .insert_approval("req_19_two_approvals", "deploy again")
        .await
        .unwrap();
}

/// Evidence blobs of each size (empty, a few bytes, several pages, a long
/// overflow chain), views over them, and both kinds of read allowance.
async fn seed_evidence(store: &Store, large: bool) {
    let id = "req_30_evidence";
    store
        .insert_running_request(id, "log.compress", REPO, AGENT, "{}", None)
        .await
        .unwrap();
    let small: Vec<u8> = (1..=255).collect();
    let large_blob = noise(if large { 100_000 } else { 20_000 }, 7);
    let compact = r#"{"source_bytes":200000,"compact_bytes":10000,"tokens_avoided_est":47500}"#;
    for (evidence_id, kind, content, meta) in [
        ("ev_30_empty", "log.source", Vec::new(), None),
        ("ev_30_small", "log.source", small, Some(r#"{"lines":3}"#)),
        (
            "ev_30_pages",
            "log.compact",
            noise(10_000, 5),
            Some(compact),
        ),
        ("ev_30_large", "log.source", large_blob, None),
        (
            "ev_30_bad_meta",
            "log.compact",
            b"x".to_vec(),
            Some("not json"),
        ),
        ("ev_30_no_meta", "log.compact", b"y".to_vec(), None),
    ] {
        store
            .insert_evidence(evidence_id, id, kind, &content, meta)
            .await
            .unwrap();
    }
    let small_view = view(id, "ev_30_small", REPO, UNICODE_TEXT.as_bytes().to_vec(), 1);
    let large_view = view(
        id,
        "ev_30_large",
        REPO,
        noise(if large { 80_000 } else { 66_000 }, 9),
        if large { 512 } else { 64 },
    );
    add_view(store, &small_view).await;
    add_view(store, &large_view).await;
    add_view(store, &view(id, "ev_30_empty", REPO, Vec::new(), 0)).await;
    // The first read starts the allowance: an hour from a clock long past.
    read_range(store, &small_view, 0, 16, RANGE_NOW_PAST).await;
    read_range(store, &large_view, 65_536, 4096, RANGE_NOW_PAST).await;

    let foreign = "req_31_foreign";
    store
        .insert_running_request(foreign, "log.compress", REPO, AGENT, "{}", None)
        .await
        .unwrap();
    store
        .insert_evidence("ev_31_source", foreign, "log.source", b"foreign", None)
        .await
        .unwrap();
    let foreign_view = view(foreign, "ev_31_source", REPO_OTHER, b"foreign".to_vec(), 1);
    add_view(store, &foreign_view).await;
    read_range(store, &foreign_view, 0, 7, RANGE_NOW_PAST).await;

    let ready = "req_32_ready";
    admit(store, ready, "flow.run", REPO).await;
    store
        .insert_evidence(
            "ev_32_result",
            ready,
            "flow.result",
            b"{}",
            Some(r#"{"agent_result":{"status":"passed","summary":"ünï 'q'"}}"#),
        )
        .await
        .unwrap();
    store
        .insert_evidence(
            "ev_32_checkpoint",
            ready,
            "flow.checkpoint",
            br#"{"private":"checkpoint"}"#,
            None,
        )
        .await
        .unwrap();
    let result_view = view(ready, "ev_32_result", REPO, b"passed".to_vec(), 1);
    add_view(store, &result_view).await;
    // An allowance whose hour ends at the far end of the clock.
    read_range(store, &result_view, 0, 3, RANGE_NOW_FAR).await;
}

/// A parked watch: a journal with a published observation, a budget charged
/// to its HTTP byte ceiling, and a correlation target, steps and membership.
async fn seed_flows(store: &Store) {
    let id = "req_40_watch";
    admit_flow(store, id, REPO).await;
    begin_journal(store, id, REPO, r#"{"next_step":0}"#).await;
    assert_eq!(
        store
            .begin_flow_journal(&identity(id, REPO), "{}")
            .await
            .unwrap(),
        FlowJournalBegin::Existing
    );
    let progress = json!({ "watch_progress": {
        "step": "wait-ci", "connector": "github", "status": "in_progress",
        "watch_state": "pending", "evidence_id": "ev_40_watch", "polls": 2, "omissions": 0,
        "next_poll_at": null,
    }})
    .to_string();
    store
        .insert_evidence(
            "ev_40_watch",
            id,
            "flow.watch",
            b"observation",
            Some(&progress),
        )
        .await
        .unwrap();
    add_view(
        store,
        &view(id, "ev_40_watch", REPO, b"observation".to_vec(), 1),
    )
    .await;
    assert!(
        store
            .prepare_flow_attempt(id, 0, "wait-ci", 1, false)
            .await
            .unwrap()
    );
    let checkpoint = r#"{"next_step":0,"watch":{"polls":3,"next_poll_ms":1900000000000,"last_evidence":"ev_40_watch"}}"#;
    assert!(
        store
            .settle_flow_attempt(id, 1, checkpoint, &["ev_40_watch".to_owned()], false)
            .await
            .unwrap()
    );

    store.load_request_budget(id).await.unwrap();
    for charge in [
        RequestBudgetCharge::Attempt,
        RequestBudgetCharge::Attempt,
        RequestBudgetCharge::Http(134_217_728),
        RequestBudgetCharge::Command(4096),
    ] {
        store
            .reserve_request_budget(id, charge)
            .await
            .unwrap()
            .unwrap();
    }
    store
        .refund_request_budget(id, RequestBudgetCharge::Http(1000))
        .await
        .unwrap();
    assert!(
        store
            .reserve_request_budget(id, RequestBudgetCharge::Http(1001))
            .await
            .unwrap()
            .is_none(),
        "the HTTP byte ceiling should refuse this"
    );

    let target = json!({ "kind": "pull_request", "title": UNICODE_TEXT }).to_string();
    assert_eq!(
        store.bind_correlation_target(id, &target).await.unwrap(),
        CorrelationBind::Inserted
    );
    for (step, binding) in [("wait-ci", BINDING), ("other 'step'", r#"{"free":"form"}"#)] {
        assert_eq!(
            store
                .bind_correlation_step(id, step, binding)
                .await
                .unwrap(),
            CorrelationBind::Inserted
        );
    }
    for (observed, merged) in [(&[3, 1, 2][..], &[1, 2, 3][..]), (&[5, 2], &[1, 2, 3, 5])] {
        assert_eq!(
            store
                .append_correlation_membership(id, "wait-ci", BINDING, observed)
                .await
                .unwrap()
                .as_deref(),
            Some(merged)
        );
    }
    assert!(
        store
            .park_flow_request(id, 1_900_000_000_000, 1_800_000_000_000)
            .await
            .unwrap()
    );
}

/// Journals that ran their course: parked and woken, completed at the
/// attempt ceiling, and a read abandoned after a crash.
async fn seed_flow_lifecycles(store: &Store) {
    let woken = "req_47_woken";
    admit_flow(store, woken, REPO).await;
    begin_journal(store, woken, REPO, "{}").await;
    assert!(store.park_flow_request(woken, 1000, 0).await.unwrap());
    assert!(store.wake_parked_flow_request(woken, 2000).await.unwrap());

    let completed = "req_44_completed";
    admit_flow(store, completed, REPO).await;
    begin_journal(store, completed, REPO, "{}").await;
    // The attempt ceiling: 256 reservations pass, the next is refused.
    store.load_request_budget(completed).await.unwrap();
    for _ in 0..256 {
        store
            .reserve_request_budget(completed, RequestBudgetCharge::Attempt)
            .await
            .unwrap()
            .unwrap();
    }
    assert!(
        store
            .reserve_request_budget(completed, RequestBudgetCharge::Attempt)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .prepare_flow_attempt(completed, 0, "final", 1, false)
            .await
            .unwrap()
    );
    let checkpoint = json!({ "next_step": 9, "notes": "ünï ✓ ".repeat(900) }).to_string();
    let refs = ["ev_44_a".to_owned(), "ev_44_b".to_owned()];
    assert!(
        store
            .settle_flow_attempt(completed, 1, &checkpoint, &refs, true)
            .await
            .unwrap()
    );
    let done = entry("execute", Decision::Allow, Actor::System, None);
    finish(store, completed, RequestState::Done, Some("ok"), done).await;

    let abandoned = "req_45_abandoned";
    admit_flow(store, abandoned, REPO_QUOTED).await;
    begin_journal(store, abandoned, REPO_QUOTED, "{}").await;
    assert!(
        store
            .prepare_flow_attempt(abandoned, 0, "read-logs", 2, false)
            .await
            .unwrap()
    );
    assert!(store.abandon_read_attempt(abandoned, 1).await.unwrap());
}

/// Effectful flows: a prepared intent with its landing session, one handed
/// to reconciliation and requeued, and one sealed as uncertain.
async fn seed_flow_effects(store: &Store) {
    let prepared = "req_41_prepared";
    admit_flow(store, prepared, REPO).await;
    begin_journal(store, prepared, REPO, "{}").await;
    assert!(
        store
            .prepare_flow_attempt(prepared, 0, "push", 1, true)
            .await
            .unwrap()
    );
    let idle = json!({ "version": 1, "manifest": [] }).to_string();
    assert!(
        store
            .save_landing_session(prepared, None, &idle, 0)
            .await
            .unwrap()
    );
    let intent = landing_document(REPO, "push", "push");
    assert!(
        store
            .save_landing_session(prepared, Some(0), &intent, 0)
            .await
            .unwrap()
    );

    let recovered = "req_42_recovered";
    admit_flow(store, recovered, REPO).await;
    begin_journal(store, recovered, REPO, "{}").await;
    assert!(
        store
            .prepare_flow_attempt(recovered, 0, "merge", 1, true)
            .await
            .unwrap()
    );
    let intent = landing_document(REPO, "merge", "merge");
    assert!(
        store
            .save_landing_session(recovered, None, &intent, 0)
            .await
            .unwrap()
    );
    assert!(
        store
            .recover_landing_reconciliation(recovered, 1, 0)
            .await
            .unwrap()
    );
    assert!(store.requeue_journaled_flow(recovered, 0).await.unwrap());

    let uncertain = "req_43_uncertain";
    admit_flow(store, uncertain, REPO).await;
    begin_journal(store, uncertain, REPO, "{}").await;
    assert!(
        store
            .prepare_flow_attempt(uncertain, 0, "ensure-pr", 256, true)
            .await
            .unwrap()
    );
    assert!(store.mark_flow_uncertain(uncertain, 1).await.unwrap());
    // Asked to finish as done; the store seals it as failed instead.
    let claimed = entry(
        "execute",
        Decision::Allow,
        Actor::System,
        Some("claimed success"),
    );
    finish(store, uncertain, RequestState::Done, Some("ok"), claimed).await;
}

/// The last write of the seed: a finished request loses a multi-page blob to
/// the evidence window, so the file ends with free pages nothing has reused.
async fn seed_late_prune(store: &Store, large: bool) {
    let bytes: u32 = if large { 40_000 } else { 12_000 };
    let id = "req_50_late_prune";
    store
        .insert_request(id, "log.compress", REPO, AGENT, "{}", None)
        .await
        .unwrap();
    store
        .insert_evidence(
            "ev_50_source",
            id,
            "log.source",
            &noise(bytes as usize, 13),
            None,
        )
        .await
        .unwrap();
    add_view(store, &view(id, "ev_50_source", REPO, noise(9000, 14), 1)).await;
    let done = entry("execute", Decision::Allow, Actor::System, None);
    finish(store, id, RequestState::Done, Some("compressed"), done).await;
    assert_eq!(
        store
            .prune_evidence_before(i64::MAX, KEEP_KIND)
            .await
            .unwrap(),
        EvidencePrune {
            rows: 1,
            bytes: u64::from(bytes)
        }
    );
}

async fn seed_connectors(store: &Store) {
    let github = ConnectorPatch {
        enabled: Some(true),
        base_url: Some(Some("https://api.github.com/")),
        ..ConnectorPatch::default()
    };
    store.upsert_connector("github", github).await.unwrap();
    store
        .record_connector_test("github", true, "ok ✓")
        .await
        .unwrap();
    let jenkins = ConnectorPatch {
        enabled: Some(false),
        base_url: Some(Some("https://jenkins.example/ünï")),
        username: Some(Some("o'brien")),
        ..ConnectorPatch::default()
    };
    store.upsert_connector("jenkins", jenkins).await.unwrap();
    store
        .record_connector_test("jenkins", false, "401 \"unauthorized\"")
        .await
        .unwrap();
    // Clearing the username invalidates the verdict just recorded.
    let cleared = ConnectorPatch {
        username: Some(None),
        ..ConnectorPatch::default()
    };
    store.upsert_connector("jenkins", cleared).await.unwrap();
    store
        .record_connector_test("sonar", false, "")
        .await
        .unwrap();
    store
        .upsert_connector("never-configured", ConnectorPatch::default())
        .await
        .unwrap();
}

async fn seed_model_jobs(store: &Store) {
    let source = Some("https://example.invalid/models/ünï.gguf");
    store
        .insert_model_job(
            "job_01_done",
            "download",
            "qwen/tiny",
            source,
            Some(i64::MAX),
        )
        .await
        .unwrap();
    store
        .update_model_job_progress("job_01_done", i64::MAX - 1, Some(i64::MAX))
        .await
        .unwrap();
    store
        .finish_model_job("job_01_done", "done", Some(r#"{"sha256":"ab"}"#))
        .await
        .unwrap();
    store
        .insert_model_job("job_02_failed", "verify", "qwen/tiny", None, None)
        .await
        .unwrap();
    let detail = Some(r#"{"cause":"digest_mismatch","detail":"ünï 'q'"}"#);
    store
        .finish_model_job("job_02_failed", "failed", detail)
        .await
        .unwrap();
    store
        .insert_model_job(
            "job_03_cancelled",
            "download",
            "vendor/other",
            source,
            Some(0),
        )
        .await
        .unwrap();
    store
        .finish_model_job("job_03_cancelled", "cancelled", None)
        .await
        .unwrap();
    store
        .insert_model_job("job_04_restart", "download", "qwen/tiny", source, None)
        .await
        .unwrap();
    let restart = r#"{"cause":"daemon_restart"}"#;
    assert_eq!(store.fail_running_model_jobs(restart).await.unwrap(), 1);
    store
        .insert_model_job("job_05_running", "verify", "qwen/tiny", None, None)
        .await
        .unwrap();
}

/// The commits of `v13-wal` that never reach the main file: six new requests
/// and a change to each kind of older row.
async fn seed_latest_delta(store: &Store) {
    for index in 0..6 {
        let id = format!("req_9{index}_wal");
        if index % 2 == 0 {
            store
                .insert_request(&id, "echo", REPO, AGENT, r#"{"wal":true}"#, None)
                .await
                .unwrap();
        } else {
            let origin = RequestOrigin {
                ingress: RequestIngress::Public,
                peer_uid: Some(501),
                peer_pid: Some(9000 + index),
                relayed: index == 3,
            };
            store
                .insert_admitted_request_from(
                    &id,
                    "echo",
                    REPO,
                    "wal-agent",
                    "{}",
                    None,
                    FAR_MS,
                    &origin,
                )
                .await
                .unwrap();
        }
    }
    let done = entry(
        "execute",
        Decision::Allow,
        Actor::System,
        Some("wal only ✓"),
    );
    let state = RequestState::Done;
    finish(
        store,
        "req_10_queued",
        state,
        Some("finished in the wal"),
        done,
    )
    .await;
    store
        .append_audit(
            "req_91_wal",
            "enqueue",
            Decision::Allow,
            Actor::Policy,
            None,
        )
        .await
        .unwrap();
    let denied = entry("approval", Decision::Deny, Actor::Human, None);
    assert!(
        !store
            .resolve_approval_audited(
                "req_15_waiting",
                ApprovalResolution::Denied,
                Some("denied in the wal"),
                denied,
                None,
            )
            .await
            .unwrap()
    );
    let state = RequestState::Refused;
    finish(store, "req_15_waiting", state, Some("denied"), denied).await;
    store.revoke_grant("git.push").await.unwrap();
    store
        .insert_evidence(
            "ev_91_wal",
            "req_91_wal",
            "log.source",
            &noise(5000, 11),
            None,
        )
        .await
        .unwrap();
    store
        .set_settings(&[
            ("retention.watermark_ts", "1800000000"),
            ("wal.only", "true"),
        ])
        .await
        .unwrap();
    store.upsert_caller("wal-agent", REPO).await.unwrap();
    store
        .insert_model_job("job_90_wal", "verify", "qwen/tiny", None, Some(1))
        .await
        .unwrap();
    store
        .record_connector_test("github", false, "wal: 401")
        .await
        .unwrap();
}

// ---------------------------------------------------------------------------
// Schema 11 (release 0.4.3), on a raw connection.
// ---------------------------------------------------------------------------

/// Release 0.4.3's request INSERT: no origin columns yet.
const V11_INSERT_REQUEST: &str = "INSERT INTO request
        (id, capability, repo, caller_agent, args_json,
         idempotency_key, state, outcome, created_ts, updated_ts, expires_at_ms,
         authorization_revision)
    VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, NULL, ?8, ?8, ?9,
         CASE WHEN ?9 IS NOT NULL THEN
           (SELECT COUNT(*) FROM \"grant\" WHERE revoked_ts IS NOT NULL)
         ELSE NULL END)";

fn v11_probes() -> Value {
    json!({
        "setting_keys": [
            "policy.profile", "retention.evidence_days", "retention.audit_days",
            "retention.watermark_ts", "setting.large", "kéy 'q' \"d\" ✓", "wal.only",
            "missing.key",
        ],
        "repositories": [REPO, REPO_QUOTED, REPO_OTHER],
        "views": [
            ["v11_compress_between", "ev_v11_source", REPO],
            ["v11_compress_between", "ev_v11_summary", REPO],
            ["v11_compress_between", "ev_v11_summary", REPO_OTHER],
            ["v11_flow_before", "ev_v11_watch", REPO],
            ["missing", "missing", REPO],
        ],
        "now_ms": [0, 1_850_000_000_000_i64, i64::MAX],
        "terminal_actions": ["execute", "admin.tripwire", "approval"],
        "keep_kind": KEEP_KIND,
    })
}

async fn run(conn: &Connection, sql: &str, params: impl turso::IntoParams) -> u64 {
    conn.execute(sql, params)
        .await
        .unwrap_or_else(|error| panic!("{sql}: {error}"))
}

/// One schema-11 request row, written the way release 0.4.3 wrote it and
/// then moved to `state`.
#[allow(clippy::too_many_arguments)] // one row = one INSERT
async fn v11_request(
    conn: &Connection,
    id: &str,
    capability: &str,
    repo: &str,
    args: &str,
    key: Option<&str>,
    state: &str,
    expires_at_ms: Option<i64>,
    ts: i64,
) {
    let initial = if expires_at_ms.is_some() {
        "running"
    } else {
        "queued"
    };
    run(
        conn,
        V11_INSERT_REQUEST,
        params![
            id,
            capability,
            repo,
            AGENT,
            args,
            key,
            initial,
            ts,
            expires_at_ms
        ],
    )
    .await;
    if state != initial {
        run(
            conn,
            "UPDATE request SET state = ?2, updated_ts = ?3 WHERE id = ?1",
            params![id, state, ts + 1],
        )
        .await;
    }
}

/// Release 0.4.3's terminal write: the state and its audit row together.
async fn v11_finish(
    conn: &Connection,
    id: &str,
    state: &str,
    outcome: Option<&str>,
    audit: [Option<&str>; 4],
    ts: i64,
) {
    let [action, decision, actor, detail] = audit;
    run(conn, "BEGIN", ()).await;
    run(
        conn,
        "UPDATE request SET state = ?2, outcome = ?3, updated_ts = ?4
         WHERE id = ?1 AND state IN ('queued','running','waiting_approval')",
        params![id, state, outcome, ts],
    )
    .await;
    run(
        conn,
        "INSERT INTO audit (request_id, action, decision, actor, detail, ts)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![id, action, decision, actor, detail, ts],
    )
    .await;
    run(conn, "COMMIT", ()).await;
}

async fn v11_grant(conn: &Connection, capability: &str, ts: i64) {
    run(
        conn,
        "INSERT INTO \"grant\" (capability, scope, granted_ts) VALUES (?1, 'global', ?2)",
        params![capability, ts],
    )
    .await;
}

/// Release 0.4.3's revocation: `revoked_ts` only, no sequence number.
async fn v11_revoke(conn: &Connection, capability: &str, ts: i64) {
    let changed = run(
        conn,
        "UPDATE \"grant\" SET revoked_ts = ?2 WHERE capability = ?1 AND revoked_ts IS NULL",
        params![capability, ts],
    )
    .await;
    assert_eq!(changed, 1, "no active grant for {capability}");
}

async fn v11_evidence(
    conn: &Connection,
    id: &str,
    request_id: &str,
    kind: &str,
    content: &[u8],
    meta: Option<&str>,
    ts: i64,
) {
    run(
        conn,
        "INSERT INTO evidence (id, request_id, kind, content, path, content_hash, meta_json, ts)
         VALUES (?1, ?2, ?3, ?4, NULL, ?5, ?6, ?7)",
        params![
            id,
            request_id,
            kind,
            content.to_vec(),
            sha256_hex(content),
            meta,
            ts
        ],
    )
    .await;
}

async fn v11_view(conn: &Connection, view: &EvidenceViewInsert) {
    run(
        conn,
        "INSERT INTO evidence_view (evidence_id,request_id,repository,origin_json,identity_json,
            map_json,view_id,view_sha256,view_bytes,view_blob)
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
        params![
            view.evidence_id.clone(),
            view.request_id.clone(),
            view.repository.clone(),
            view.origin_json.clone(),
            view.identity_json.clone(),
            view.map_json.clone(),
            view.view_id.clone(),
            sha256_hex(&view.view_bytes),
            i64::try_from(view.view_bytes.len()).unwrap(),
            view.view_bytes.clone()
        ],
    )
    .await;
}

async fn v11_journal(
    conn: &Connection,
    id: &str,
    repo: &str,
    state: &str,
    step: Option<&str>,
    effectful: bool,
    checkpoint: &str,
) {
    run(
        conn,
        "INSERT INTO flow_journal(request_id,schema_version,flow_digest,repository,
            input_fingerprint,revision,state,step_id,attempt,effectful,checkpoint_json,
            evidence_refs_json)
         VALUES (?1,1,?2,?3,?4,?5,?6,?7,?8,?9,?10,'[]')",
        params![
            id,
            digest('a'),
            repo,
            digest('b'),
            i64::from(step.is_some()),
            state,
            step,
            i64::from(step.is_some()),
            i64::from(effectful),
            checkpoint
        ],
    )
    .await;
}

async fn build_v11(dir: &Path) {
    std::fs::create_dir_all(dir).unwrap();
    let path: PathBuf = dir.join(DATABASE);
    let (db, conn) = raw_open(&path).await;
    run(&conn, "PRAGMA foreign_keys = ON", ()).await;
    // The runner's own shape: one transaction per migration, stamped inside.
    for migration in &migrations::MIGRATIONS[..11] {
        run(&conn, "BEGIN", ()).await;
        conn.execute_batch(migration.sql).await.unwrap();
        let version = migration.version;
        run(&conn, &format!("PRAGMA user_version = {version}"), ()).await;
        run(&conn, "COMMIT", ()).await;
    }
    assert_eq!(migrations::MIGRATIONS[10].version, 11);
    v11_grants_and_admissions(&conn).await;
    v11_records(&conn).await;
    v11_flow_rows(&conn).await;
    v11_plain_tables(&conn).await;
    v11_delete_record(&conn).await;
    drop((conn, db));
    checkpoint(&path).await;
    let checkpointed = sha256_hex(&std::fs::read(&path).unwrap());

    let (db, conn) = raw_open(&path).await;
    run(&conn, "PRAGMA foreign_keys = ON", ()).await;
    v11_delta(&conn).await;
    drop((conn, db));
    assert_eq!(sha256_hex(&std::fs::read(&path).unwrap()), checkpointed);
}

/// Six grants, four of them revoked (two inside one second), with a request
/// admitted between each pair of revocations. Migration 12 has to number
/// these revocations from `revoked_ts` alone.
async fn v11_grants_and_admissions(conn: &Connection) {
    let ts = V11_TS;
    for capability in [
        "echo",
        "log.compress",
        "flow.step:github.run",
        "flow.run",
        "deploy",
        "git.push",
    ] {
        v11_grant(conn, capability, ts + 100).await;
    }
    let admitted = Some(FAR_MS);
    v11_request(
        conn,
        "v11_echo_before",
        "echo",
        REPO,
        "{}",
        None,
        "running",
        admitted,
        ts + 110,
    )
    .await;
    v11_request(
        conn,
        "v11_legacy_queued",
        "echo",
        REPO,
        r#"{"text":"hi"}"#,
        Some("k-legacy"),
        "queued",
        None,
        ts + 120,
    )
    .await;
    v11_revoke(conn, "echo", ts + 200).await;
    v11_grant(conn, "echo", ts + 201).await;
    v11_request(
        conn,
        "v11_echo_after",
        "echo",
        REPO,
        "{}",
        None,
        "queued",
        admitted,
        ts + 210,
    )
    .await;
    run(
        conn,
        "UPDATE request SET queue_authorized = 1 WHERE id = 'v11_echo_after'",
        (),
    )
    .await;
    v11_revoke(conn, "deploy", ts + 250).await;
    v11_request(
        conn,
        "v11_flow_before",
        "flow.run",
        REPO,
        "{}",
        None,
        "running",
        admitted,
        ts + 260,
    )
    .await;
    v11_revoke(conn, "flow.step:github.run", ts + 300).await;
    v11_request(
        conn,
        "v11_compress_between",
        "log.compress",
        REPO,
        "{}",
        None,
        "running",
        admitted,
        ts + 300,
    )
    .await;
    v11_revoke(conn, "log.compress", ts + 300).await;
    v11_request(
        conn,
        "v11_flow_after",
        "flow.run",
        REPO,
        "{}",
        None,
        "running",
        admitted,
        ts + 310,
    )
    .await;
    v11_request(
        conn,
        "v11_parked",
        "flow.run",
        REPO_QUOTED,
        "{}",
        None,
        "queued",
        admitted,
        ts + 320,
    )
    .await;
    run(
        conn,
        "UPDATE request SET queue_authorized = 1 WHERE capability = 'flow.run'",
        (),
    )
    .await;
    run(
        conn,
        "UPDATE request SET resume_at_ms = 1900000000000 WHERE id = 'v11_parked'",
        (),
    )
    .await;
}

/// Finished and waiting requests with their audit, approval and evidence
/// rows.
async fn v11_records(conn: &Connection) {
    let ts = V11_TS + 400;
    let big = json!({ "text": "ünï-✓ ".repeat(1200) }).to_string();
    for (id, capability, args, key) in [
        ("v11_done", "echo", big.as_str(), Some("")),
        ("v11_refused", "admin.grants.add", "{}", None),
        ("v11_failed", "echo", "{}", None),
        ("v11_approved", "deploy", "{}", None),
        ("v11_denied", "deploy", "{}", None),
        ("v11_timeout", "deploy", "{}", None),
        ("v11_deleted", "echo", "{}", None),
        ("v11_ünï 'q' \"d\"", "", "", Some("")),
    ] {
        let repo = if capability.is_empty() { "" } else { REPO };
        v11_request(conn, id, capability, repo, args, key, "queued", None, ts).await;
    }
    v11_request(
        conn,
        "v11_waiting",
        "deploy",
        REPO,
        "{}",
        None,
        "waiting_approval",
        Some(FAR_MS),
        ts,
    )
    .await;
    for (id, resolution, note) in [
        ("v11_waiting", None, None),
        ("v11_approved", Some("approved"), Some("lgtm ✓ — 'ok'")),
        ("v11_denied", Some("denied"), Some("no; \"prod\" freeze")),
        ("v11_timeout", Some("timeout"), None),
        ("v11_deleted", Some("approved"), None),
    ] {
        run(
            conn,
            "INSERT INTO approval (request_id, capability, requested_ts) VALUES (?1, 'deploy', ?2)",
            params![id, ts + 1],
        )
        .await;
        if resolution.is_some() {
            run(
                conn,
                "UPDATE approval SET resolved_ts = ?2, resolution = ?3, note = ?4
                 WHERE request_id = ?1 AND resolved_ts IS NULL",
                params![id, ts + 2, resolution, note],
            )
            .await;
        }
    }
    let system = Some("system");
    for (id, state, outcome, audit) in [
        (
            "v11_done",
            "done",
            Some(r#"{"ok":true}"#),
            [Some("execute"), Some("allow"), system, Some(UNICODE_TEXT)],
        ),
        (
            "v11_refused",
            "refused",
            Some("admin_denied"),
            [
                Some("admin.tripwire"),
                Some("refuse"),
                Some("policy"),
                Some("{}"),
            ],
        ),
        (
            "v11_failed",
            "failed",
            None,
            [Some("reap"), Some("timeout"), system, None],
        ),
        (
            "v11_approved",
            "done",
            Some("deployed"),
            [Some("approval"), Some("approve"), Some("human"), None],
        ),
        (
            "v11_denied",
            "refused",
            Some("denied"),
            [Some("approval"), Some("deny"), Some("human"), None],
        ),
        (
            "v11_timeout",
            "failed",
            Some("approval_timeout"),
            [Some("approval"), Some("timeout"), system, None],
        ),
        (
            "v11_deleted",
            "done",
            Some("ok"),
            [Some("execute"), Some("allow"), system, None],
        ),
        (
            "v11_compress_between",
            "done",
            Some("compressed"),
            [Some("execute"), Some("allow"), system, None],
        ),
    ] {
        v11_finish(conn, id, state, outcome, audit, ts + 3).await;
    }
    run(
        conn,
        "INSERT INTO audit (request_id, action, decision, actor, detail, ts)
         VALUES ('v11_echo_before', 'enqueue', 'allow', 'policy', NULL, ?1)",
        params![ts],
    )
    .await;

    let request = "v11_compress_between";
    let compact = Some(r#"{"source_bytes":30000,"compact_bytes":9000,"tokens_avoided_est":5250}"#);
    for (id, kind, content, meta) in [
        ("ev_v11_empty", "log.source", Vec::new(), None),
        ("ev_v11_source", "log.source", noise(30_000, 21), None),
        ("ev_v11_compact", "log.compact", noise(9000, 22), compact),
        (
            "ev_v11_summary",
            KEEP_KIND,
            "résumé ✓ 'q' \"d\"".as_bytes().to_vec(),
            Some(r#"{"model":"qwen ü"}"#),
        ),
        ("ev_v11_small", "log.source", (1..=255).collect(), None),
    ] {
        v11_evidence(conn, id, request, kind, &content, meta, ts + 4).await;
    }
    v11_view(
        conn,
        &view(request, "ev_v11_source", REPO, noise(3000, 23), 1),
    )
    .await;
    v11_view(
        conn,
        &view(request, "ev_v11_summary", REPO, noise(20_000, 24), 100),
    )
    .await;
    run(
        conn,
        "INSERT OR IGNORE INTO evidence_read_allowance
            (request_id,repository,started_at,expires_at,remaining_bytes,remaining_pages)
         VALUES (?1,?2,?3,?4,67108864,4096)",
        params![request, REPO, ts + 5, ts + 3605],
    )
    .await;
    run(
        conn,
        "UPDATE evidence_read_allowance SET remaining_bytes=remaining_bytes-?3,
            remaining_pages=remaining_pages-1 WHERE request_id=?1 AND repository=?2",
        params![request, REPO, 65_536],
    )
    .await;
    // Release 0.4.3's evidence prune: tombstone the view, delete the row.
    run(
        conn,
        "UPDATE evidence_view SET view_blob = NULL, expired_at = ?2 WHERE evidence_id = ?1",
        params!["ev_v11_source", ts + 6],
    )
    .await;
    run(conn, "DELETE FROM evidence WHERE id = 'ev_v11_source'", ()).await;

    v11_evidence(
        conn,
        "ev_v11_deleted",
        "v11_deleted",
        "log.source",
        &noise(12_000, 25),
        None,
        ts,
    )
    .await;
}

/// The last write before the checkpoint: a record removed whole, as the
/// audit window does it (children first), so the main file ends with free
/// pages.
async fn v11_delete_record(conn: &Connection) {
    for table in ["evidence", "approval", "audit"] {
        run(
            conn,
            &format!("DELETE FROM {table} WHERE request_id = 'v11_deleted'"),
            (),
        )
        .await;
    }
    run(conn, "DELETE FROM request WHERE id = 'v11_deleted'", ()).await;
}

/// Journals in each state, a landing session, budgets, correlation.
async fn v11_flow_rows(conn: &Connection) {
    let ts = V11_TS + 500;
    let watch = r#"{"next_step":0,"watch":{"polls":3,"next_poll_ms":1900000000000,"last_evidence":"ev_v11_watch"}}"#;
    v11_journal(conn, "v11_flow_before", REPO, "ready", None, false, watch).await;
    v11_journal(
        conn,
        "v11_flow_after",
        REPO,
        "prepared",
        Some("push"),
        true,
        "{}",
    )
    .await;
    v11_journal(conn, "v11_parked", REPO_QUOTED, "ready", None, false, "{}").await;
    v11_journal(
        conn,
        "v11_done",
        REPO,
        "completed",
        Some("final"),
        false,
        &json!({ "notes": "ünï ✓ ".repeat(500) }).to_string(),
    )
    .await;
    v11_journal(
        conn,
        "v11_failed",
        REPO,
        "uncertain",
        Some("merge"),
        true,
        "{}",
    )
    .await;
    run(
        conn,
        "INSERT INTO landing_session(request_id,revision,document) VALUES (?1,?2,?3)",
        params!["v11_flow_after", 1, landing_document(REPO, "push", "push")],
    )
    .await;
    let progress = json!({ "watch_progress": {
        "step": "wait-ci", "connector": "github", "status": "in_progress",
        "watch_state": "pending", "evidence_id": "ev_v11_watch", "polls": 2, "omissions": 0,
        "next_poll_at": null,
    }})
    .to_string();
    v11_evidence(
        conn,
        "ev_v11_watch",
        "v11_flow_before",
        "flow.watch",
        b"observation",
        Some(&progress),
        ts,
    )
    .await;
    v11_view(
        conn,
        &view(
            "v11_flow_before",
            "ev_v11_watch",
            REPO,
            b"observation".to_vec(),
            1,
        ),
    )
    .await;
    v11_evidence(
        conn,
        "ev_v11_checkpoint",
        "v11_flow_before",
        "flow.checkpoint",
        br#"{"private":"checkpoint"}"#,
        None,
        ts,
    )
    .await;

    for (id, attempts, calls, http, command) in [
        (
            "v11_flow_before",
            256,
            128,
            134_217_728_i64,
            134_217_728_i64,
        ),
        ("v11_flow_after", 1, 0, 0, 0),
        ("v11_done", 3, 2, 4096, 1),
    ] {
        run(
            conn,
            "INSERT INTO request_budget(request_id) SELECT id FROM request WHERE id=?1
             ON CONFLICT(request_id) DO NOTHING",
            params![id],
        )
        .await;
        run(
            conn,
            "UPDATE request_budget SET attempts=attempts+?2,http_calls=http_calls+?3,
                http_bytes=http_bytes+?4,command_bytes=command_bytes+?5 WHERE request_id=?1",
            params![id, attempts, calls, http, command],
        )
        .await;
    }
    let target = json!({ "kind": "pull_request", "title": UNICODE_TEXT }).to_string();
    run(
        conn,
        "INSERT INTO correlation_target(request_id,canonical_json) VALUES (?1,?2)",
        params!["v11_flow_before", target],
    )
    .await;
    for (step, binding) in [("wait-ci", BINDING), ("other 'step'", r#"{"free":"form"}"#)] {
        run(
            conn,
            "INSERT INTO correlation_step(request_id,step_id,canonical_json) VALUES (?1,?2,?3)",
            params!["v11_flow_before", step, binding],
        )
        .await;
    }
    for members in ["[1,2,3]", "[1,2,3,5]"] {
        run(
            conn,
            "INSERT INTO correlation_membership(request_id,step_id,members_json) VALUES(?1,?2,?3)
             ON CONFLICT(request_id,step_id) DO UPDATE SET members_json=excluded.members_json",
            params!["v11_flow_before", "wait-ci", members],
        )
        .await;
    }
}

/// The tables that hang off nothing: callers, settings, model jobs,
/// connectors.
async fn v11_plain_tables(conn: &Connection) {
    let ts = V11_TS + 600;
    for (agent, repo, seen) in [
        (AGENT, REPO, ts),
        (AGENT_UNICODE, REPO_QUOTED, ts + 1),
        (AGENT, REPO, ts + 2),
        ("", "", ts + 3),
    ] {
        run(
            conn,
            "INSERT INTO caller (agent, repo, first_seen, last_seen) VALUES (?1, ?2, ?3, ?3)
             ON CONFLICT (agent, repo) DO UPDATE SET last_seen = excluded.last_seen",
            params![agent, repo, seen],
        )
        .await;
    }
    let large = "é".repeat(4096);
    for (key, value) in [
        ("policy.profile", "\"standard\""),
        ("retention.evidence_days", "30"),
        ("retention.audit_days", "365"),
        ("retention.watermark_ts", "1750000000"),
        ("setting.large", large.as_str()),
        ("kéy 'q' \"d\" ✓", UNICODE_TEXT),
        ("retention.evidence_days", "14"),
    ] {
        run(
            conn,
            "INSERT INTO setting (key, value) VALUES (?1, ?2)
             ON CONFLICT (key) DO UPDATE SET value = excluded.value",
            params![key, value],
        )
        .await;
    }
    let source = Some("https://example.invalid/models/ünï.gguf");
    for (id, kind, source, state, done, total, detail) in [
        (
            "job_v11_done",
            "download",
            source,
            "done",
            i64::MAX - 1,
            Some(i64::MAX),
            Some(r#"{"sha256":"ab"}"#),
        ),
        (
            "job_v11_failed",
            "verify",
            None,
            "failed",
            0,
            None,
            Some(r#"{"cause":"ünï 'q'"}"#),
        ),
        (
            "job_v11_cancelled",
            "download",
            source,
            "cancelled",
            5,
            Some(0),
            None,
        ),
        ("job_v11_running", "verify", None, "running", 0, None, None),
    ] {
        run(
            conn,
            "INSERT INTO model_job (id, kind, model_id, source, state, bytes_done, bytes_total,
                detail, created_ts, updated_ts)
             VALUES (?1, ?2, 'qwen/tiny', ?3, ?4, ?5, ?6, ?7, ?8, ?8)",
            params![id, kind, source, state, done, total, detail, ts],
        )
        .await;
    }
    for (id, enabled, base_url, username, status, detail, tested) in [
        (
            "github",
            1,
            Some("https://api.github.com/"),
            None,
            Some("passed"),
            Some("ok ✓"),
            Some(ts),
        ),
        (
            "jenkins",
            0,
            Some("https://jenkins.example/ünï"),
            Some("o'brien"),
            Some("failed"),
            Some("401 \"unauthorized\""),
            Some(ts),
        ),
        ("never-configured", 0, None, None, None, None, None),
    ] {
        run(
            conn,
            "INSERT INTO connector (id, enabled, base_url, username, last_test_status,
                last_test_detail, last_test_ts, updated_ts)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![id, enabled, base_url, username, status, detail, tested, ts],
        )
        .await;
    }
}

/// The commits of `v11` that never reach the main file: six requests, a
/// fifth revocation, and a change to each kind of older row.
async fn v11_delta(conn: &Connection) {
    let ts = V11_TS + 700;
    for index in 0..6 {
        let id = format!("v11_wal_{index}");
        let expires = (index % 2 == 1).then_some(FAR_MS);
        let state = if expires.is_some() {
            "running"
        } else {
            "queued"
        };
        v11_request(
            conn,
            &id,
            "echo",
            REPO,
            r#"{"wal":true}"#,
            None,
            state,
            expires,
            ts + index,
        )
        .await;
    }
    let audit = [
        Some("execute"),
        Some("allow"),
        Some("system"),
        Some("wal only ✓"),
    ];
    v11_finish(
        conn,
        "v11_legacy_queued",
        "done",
        Some("finished in the wal"),
        audit,
        ts + 10,
    )
    .await;
    v11_revoke(conn, "git.push", ts + 20).await;
    v11_evidence(
        conn,
        "ev_v11_wal",
        "v11_wal_1",
        "log.source",
        &noise(5000, 31),
        None,
        ts + 30,
    )
    .await;
    for (key, value) in [
        ("retention.watermark_ts", "1800000000"),
        ("wal.only", "true"),
    ] {
        run(
            conn,
            "INSERT INTO setting (key, value) VALUES (?1, ?2)
             ON CONFLICT (key) DO UPDATE SET value = excluded.value",
            params![key, value],
        )
        .await;
    }
    run(
        conn,
        "INSERT INTO caller (agent, repo, first_seen, last_seen) VALUES ('wal-agent', ?1, ?2, ?2)",
        params![REPO, ts + 40],
    )
    .await;
    run(
        conn,
        "UPDATE model_job SET state = 'failed', detail = ?1, updated_ts = ?2
         WHERE state = 'running'",
        params![r#"{"cause":"daemon_restart"}"#, ts + 50],
    )
    .await;
}
