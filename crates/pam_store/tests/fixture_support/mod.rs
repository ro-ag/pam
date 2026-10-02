//! Shared by the store fixture tests: where the committed database files
//! live, how a test gets a private copy of one, and the oracle dump — every
//! row the store hands back through its public read API, as JSON.
//!
//! Nothing here names the database engine. The dump was recorded once with
//! the engine that wrote the fixtures (`expected.json`, next to each
//! database) and is replayed against whatever engine the store runs on, so a
//! difference between the two is a difference in how the same file is read.
#![allow(dead_code)] // the oracle test and the generator each use a part

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use pam_store::{
    EvidenceOrigins, EvidenceRangeOutcome, EvidenceRangeRequest, FlowJournalState, MAX_LIST_LIMIT,
    RequestRow, RequestState, Store, StoreError,
};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

/// Directory under `tests/fixtures` naming the engine that wrote the files.
pub(crate) const FIXTURE_SET: &str = "turso-0.7";

/// Every committed fixture, by directory name.
pub(crate) const FIXTURES: [&str; 3] = ["v13-full", "v13-wal", "v11"];

/// The database file inside a fixture directory; the engine's `-wal` and
/// `-shm` companions sit beside it under the same name plus a suffix.
pub(crate) const DATABASE: &str = "state.sqlite3";

/// Suffixes of the files that together are one database.
pub(crate) const DATABASE_SUFFIXES: [&str; 3] = ["", "-wal", "-shm"];

/// The variant read from the files exactly as they were captured.
pub(crate) const AS_WRITTEN: &str = "as_written";

/// The variant read from the main file alone, its write-ahead log left
/// behind: what a backup that copies only `state.sqlite3` restores.
pub(crate) const MAIN_ONLY: &str = "main_only";

/// The six request states, in schema order.
const STATES: [RequestState; 6] = [
    RequestState::Queued,
    RequestState::Running,
    RequestState::WaitingApproval,
    RequestState::Done,
    RequestState::Refused,
    RequestState::Failed,
];

/// Texts longer than this are recorded as length, digest and head rather
/// than whole, so the expectation files stay small.
const INLINE_TEXT_BYTES: usize = 512;

/// Blobs up to this size are recorded as hex next to their digest.
const INLINE_BLOB_BYTES: usize = 64;

/// The clock a view read is given when its request has no allowance yet.
const RANGE_PROBE_NOW: i64 = 1_700_000_000;

/// Largest range one view read may ask for (the store's own page limit).
const RANGE_PAGE: u32 = 64 * 1024;

pub(crate) fn fixtures_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(FIXTURE_SET)
}

pub(crate) fn fixture_dir(name: &str) -> PathBuf {
    fixtures_root().join(name)
}

/// Copies one database out of `from` into `to` and returns the path of the
/// copy's main file. With `with_wal` false only the main file is copied.
/// Tests always work on such a copy: a committed fixture is never opened.
pub(crate) fn copy_database(from: &Path, to: &Path, with_wal: bool) -> PathBuf {
    std::fs::create_dir_all(to).unwrap();
    for suffix in DATABASE_SUFFIXES {
        if !with_wal && !suffix.is_empty() {
            continue;
        }
        let name = format!("{DATABASE}{suffix}");
        let source = from.join(&name);
        if source.exists() {
            std::fs::copy(&source, to.join(&name)).unwrap();
        }
    }
    to.join(DATABASE)
}

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// Short digest of one rendered row. The generator renders every row of
/// every table inside the engine as one line of hex and records these; the
/// `sqlite3` cross-check renders the same rows with the same statement.
pub(crate) fn row_digest(line: &str) -> String {
    sha256_hex(line.as_bytes())[..16].to_owned()
}

/// Name, size and digest of each database file present in `dir`.
pub(crate) fn file_inventory(dir: &Path) -> Value {
    let mut files = Map::new();
    for suffix in DATABASE_SUFFIXES {
        let name = format!("{DATABASE}{suffix}");
        if let Ok(bytes) = std::fs::read(dir.join(&name)) {
            files.insert(
                name,
                json!({ "bytes": bytes.len(), "sha256": sha256_hex(&bytes) }),
            );
        }
    }
    Value::Object(files)
}

pub(crate) fn load_expected(name: &str) -> Value {
    let path = fixture_dir(name).join("expected.json");
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()));
    serde_json::from_str(&raw)
        .unwrap_or_else(|error| panic!("{} is not valid JSON: {error}", path.display()))
}

/// Where `actual` first departs from `expected`, as a JSON pointer with both
/// values; `None` when they are equal.
pub(crate) fn first_difference(actual: &Value, expected: &Value, at: &str) -> Option<String> {
    match (actual, expected) {
        (Value::Object(a), Value::Object(e)) => {
            let keys: BTreeSet<&String> = a.keys().chain(e.keys()).collect();
            keys.into_iter().find_map(|key| {
                let here = format!("{at}/{key}");
                match (a.get(key), e.get(key)) {
                    (Some(a), Some(e)) => first_difference(a, e, &here),
                    (Some(_), None) => Some(format!("{here}: not in the expectation")),
                    (None, _) => Some(format!("{here}: missing from the store's answer")),
                }
            })
        }
        (Value::Array(a), Value::Array(e)) => {
            if a.len() != e.len() {
                return Some(format!(
                    "{at}: {} entries, the expectation has {}",
                    a.len(),
                    e.len()
                ));
            }
            a.iter()
                .zip(e)
                .enumerate()
                .find_map(|(index, (a, e))| first_difference(a, e, &format!("{at}/{index}")))
        }
        (a, e) if a == e => None,
        (a, e) => Some(format!(
            "{at}: the store answers {a}, the expectation is {e}"
        )),
    }
}

/// A text column: whole when short, otherwise its length, digest and head.
fn text(value: &str) -> Value {
    if value.len() <= INLINE_TEXT_BYTES {
        return json!(value);
    }
    let head: String = value.chars().take(48).collect();
    json!({ "bytes": value.len(), "sha256": sha256_hex(value.as_bytes()), "head": head })
}

fn opt_text(value: Option<&str>) -> Value {
    value.map_or(Value::Null, text)
}

/// A blob: its length and digest, and the bytes themselves when few.
fn blob(bytes: &[u8]) -> Value {
    let mut out = json!({ "bytes": bytes.len(), "sha256": sha256_hex(bytes) });
    if bytes.len() <= INLINE_BLOB_BYTES {
        out["hex"] = json!(hex::encode(bytes));
    }
    out
}

/// A refusal, by kind. The engine's own wording is left out on purpose: it
/// is the one part of an error that may differ between engines.
fn refusal(error: &StoreError) -> Value {
    let kind = match error {
        StoreError::NotFound { table, .. } => format!("not_found:{table}"),
        StoreError::UnexpectedValue { column, .. } => format!("unexpected_value:{column}"),
        StoreError::AlreadyTerminal { .. } => "already_terminal".to_owned(),
        _ => "error".to_owned(),
    };
    json!({ "refused": kind })
}

fn answer<T>(result: Result<T, StoreError>, show: impl FnOnce(T) -> Value) -> Value {
    match result {
        Ok(value) => show(value),
        Err(error) => refusal(&error),
    }
}

fn strings(value: &Value) -> Vec<String> {
    value
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

fn ids(rows: &[RequestRow]) -> Vec<&str> {
    rows.iter().map(|row| row.id.as_str()).collect()
}

fn request_row(row: &RequestRow) -> Value {
    json!({
        "id": row.id,
        "capability": row.capability,
        "repo": row.repo,
        "caller_agent": row.caller_agent,
        "args_json": text(&row.args_json),
        "idempotency_key": row.idempotency_key,
        "state": row.state.as_str(),
        "outcome": row.outcome,
        "created_ts": row.created_ts,
        "updated_ts": row.updated_ts,
        "expires_at_ms": row.expires_at_ms,
        "queue_authorized": row.queue_authorized,
        "authorization_revision": row.authorization_revision,
        "resume_at_ms": row.resume_at_ms,
        "ingress": row.origin.ingress.as_str(),
        "peer_uid": row.origin.peer_uid,
        "peer_pid": row.origin.peer_pid,
        "relayed": row.origin.relayed,
    })
}

/// What the dump is told to look for: the keys and tuples the store has no
/// way to enumerate, and the clocks the time-dependent reads are given.
struct Probes {
    setting_keys: Vec<String>,
    repositories: Vec<String>,
    /// `(request id, evidence id, repository)` of every view to look up.
    views: Vec<(String, String, String)>,
    now_ms: Vec<i64>,
    terminal_actions: Vec<String>,
    keep_kind: String,
}

impl Probes {
    fn parse(probes: &Value) -> Self {
        let views = probes["views"]
            .as_array()
            .map(|views| {
                views
                    .iter()
                    .map(|view| {
                        let part = |index: usize| view[index].as_str().unwrap().to_owned();
                        (part(0), part(1), part(2))
                    })
                    .collect()
            })
            .unwrap_or_default();
        Self {
            setting_keys: strings(&probes["setting_keys"]),
            repositories: strings(&probes["repositories"]),
            views,
            now_ms: probes["now_ms"]
                .as_array()
                .map(|values| values.iter().filter_map(Value::as_i64).collect())
                .unwrap_or_default(),
            terminal_actions: strings(&probes["terminal_actions"]),
            keep_kind: probes["keep_kind"].as_str().unwrap_or_default().to_owned(),
        }
    }

    /// The repositories one request is probed under: its own, then the
    /// fixture-wide ones.
    fn repositories_for(&self, row: &RequestRow) -> BTreeSet<String> {
        let mut out: BTreeSet<String> = self.repositories.iter().cloned().collect();
        out.insert(row.repo.clone());
        out
    }
}

/// Everything the store's public read API returns for the database behind
/// `store`, table by table. `probes` is the `probes` object of the fixture's
/// `expected.json`.
///
/// The reads run in a fixed order and the last section charges evidence read
/// allowances, so the dump is only repeatable on a fresh copy of a fixture.
pub(crate) async fn public_dump(store: &Store, probes: &Value) -> Value {
    let probes = Probes::parse(probes);
    let (rows, request) = requests(store).await;
    let mut by_id: Vec<&RequestRow> = rows.iter().collect();
    by_id.sort_by(|a, b| a.id.cmp(&b.id));
    json!({
        "request": request,
        "request_queries": request_queries(store, &by_id, &probes).await,
        "request_lists": request_lists(store, &by_id, &probes).await,
        "audit": audit(store, &by_id).await,
        "grant": grants(store, &by_id).await,
        "approval": approvals(store, &by_id).await,
        "caller": callers(store).await,
        "setting": settings(store, &probes).await,
        "connector": connectors(store).await,
        "model_job": model_jobs(store).await,
        "evidence": evidence(store, &by_id, &probes).await,
        "evidence_view": evidence_views(store, &probes).await,
        "correlation": correlation(store, &by_id).await,
        "request_budget": budgets(store, &by_id).await,
        "flow_journal": flow_journals(store, &by_id, &probes).await,
        "landing_session": landing_sessions(store, &by_id).await,
        // Last: these reads are charged, which writes.
        "evidence_view_reads": view_reads(store, &probes).await,
    })
}

async fn requests(store: &Store) -> (Vec<RequestRow>, Value) {
    let rows = store
        .list_requests_filtered(Some(MAX_LIST_LIMIT), None, None, None, None, false)
        .await
        .unwrap();
    assert!(
        u64::try_from(rows.len()).unwrap() < MAX_LIST_LIMIT,
        "the fixture holds more requests than one list call returns"
    );
    for row in &rows {
        let again = store.get_request(&row.id).await.unwrap();
        assert_eq!(
            again.as_ref(),
            Some(row),
            "get_request disagrees with the list"
        );
    }
    let dump = json!({
        "count": rows.len(),
        "read_via": "list_requests_filtered, newest first; each row re-read with get_request",
        "rows": rows.iter().map(request_row).collect::<Vec<_>>(),
    });
    (rows, dump)
}

/// Per-request reads that are not the row itself: bounded status metadata,
/// whether the admission still stands, dedupe by shape, and the watch
/// schedule checks at each probe clock (in `probes.now_ms` order).
async fn request_queries(store: &Store, rows: &[&RequestRow], probes: &Probes) -> Value {
    let mut out = Map::new();
    for row in rows {
        let status = answer(store.request_status_meta(&row.id).await, |meta| {
            let Some(meta) = meta else {
                return Value::Null;
            };
            let found = json!({
                "capability": meta.capability,
                "repository": meta.repository,
                "state": meta.state.as_str(),
                "outcome": meta.outcome,
                "authorization_revision": meta.authorization_revision,
            });
            let of_row = json!({
                "capability": row.capability,
                "repository": row.repo,
                "state": row.state.as_str(),
                "outcome": row.outcome,
                "authorization_revision": row.authorization_revision,
            });
            // The row's own columns are already in `request`; only a
            // departure from them is worth spelling out.
            let columns = if found == of_row {
                json!("as_row")
            } else {
                found
            };
            json!({ "columns": columns, "authorization_current": meta.authorization_current })
        });
        let shape = store
            .find_admitted_by_shape(
                &row.capability,
                &row.repo,
                &row.args_json,
                row.idempotency_key.as_deref(),
                0,
            )
            .await;
        let mut parked = Vec::new();
        let mut expired = Vec::new();
        for now in &probes.now_ms {
            parked.push(answer(
                store.validate_parked_flow_request(&row.id, *now).await,
                Value::Bool,
            ));
            expired.push(answer(
                store.request_admission_expired(&row.id, *now).await,
                Value::Bool,
            ));
        }
        out.insert(
            row.id.clone(),
            json!({
                "status_meta": status,
                "authorization_current": answer(
                    store.request_authorization_current(&row.id).await,
                    Value::Bool,
                ),
                "admitted_by_shape": answer(shape, |found| json!(found.map(|found| found.id))),
                "parked_schedule_valid": parked,
                "admission_expired": expired,
            }),
        );
    }
    Value::Object(out)
}

/// Reads one recovery subset to its end, page by page; `null` when the store
/// refuses a page.
async fn recovery(store: &Store, queued: bool, maximum_bytes: u64) -> Value {
    let mut out: Vec<String> = Vec::new();
    let mut after: Option<(i64, String)> = None;
    loop {
        let cursor = after.as_ref().map(|(ts, id)| (*ts, id.as_str()));
        let page = if queued {
            store.queued_recovery_page(cursor, maximum_bytes).await
        } else {
            store.stuck_recovery_page(cursor, maximum_bytes).await
        };
        let Some(page) = page.unwrap() else {
            return Value::Null;
        };
        let Some(last) = page.last() else {
            return json!(out);
        };
        after = Some((last.created_ts, last.id.clone()));
        out.extend(page.iter().map(|row| row.id.clone()));
    }
}

/// Ids of the requests one filtered list call returns, newest first.
async fn listed(
    store: &Store,
    repo: Option<&str>,
    agent: Option<&str>,
    state: Option<RequestState>,
    capability: Option<&str>,
    hide_probes: bool,
) -> Value {
    let found = store
        .list_requests_filtered(
            Some(MAX_LIST_LIMIT),
            repo,
            agent,
            state,
            capability,
            hide_probes,
        )
        .await
        .unwrap();
    json!(ids(&found))
}

/// The filtered lists over `request`, one per distinct value of each filter.
async fn request_filters(store: &Store, rows: &[&RequestRow]) -> Value {
    let distinct = |field: fn(&RequestRow) -> &str| -> BTreeSet<&str> {
        rows.iter().map(|row| field(row)).collect()
    };
    let mut by_state = Map::new();
    for state in STATES {
        by_state.insert(
            state.as_str().to_owned(),
            listed(store, None, None, Some(state), None, false).await,
        );
    }
    let mut by_repo = Map::new();
    for repo in distinct(|row| row.repo.as_str()) {
        by_repo.insert(
            repo.to_owned(),
            listed(store, Some(repo), None, None, None, false).await,
        );
    }
    let mut by_agent = Map::new();
    for agent in distinct(|row| row.caller_agent.as_str()) {
        by_agent.insert(
            agent.to_owned(),
            listed(store, None, Some(agent), None, None, false).await,
        );
    }
    let mut by_capability = Map::new();
    for capability in distinct(|row| row.capability.as_str()) {
        by_capability.insert(
            capability.to_owned(),
            listed(store, None, None, None, Some(capability), true).await,
        );
    }
    json!({
        "hide_probes": listed(store, None, None, None, None, true).await,
        "by_state": by_state,
        "by_repo": by_repo,
        "by_agent": by_agent,
        "by_capability_hiding_probes": by_capability,
    })
}

/// The list and aggregate reads over `request`.
async fn request_lists(store: &Store, rows: &[&RequestRow], probes: &Probes) -> Value {
    let mut usage_at = Map::new();
    for now in &probes.now_ms {
        let (count, bytes) = store.admission_usage_at(*now).await.unwrap();
        usage_at.insert(now.to_string(), json!({ "count": count, "bytes": bytes }));
    }
    let (count, bytes) = store.admission_usage().await.unwrap();
    let actions: Vec<&str> = probes.terminal_actions.iter().map(String::as_str).collect();
    let queued = store.list_queued_ordered().await.unwrap();
    json!({
        "filtered": request_filters(store, rows).await,
        "count_inflight": store.count_inflight().await.unwrap(),
        "admission_usage": { "count": count, "bytes": bytes },
        "admission_usage_at_ms": usage_at,
        "queued_ordered": ids(&queued),
        "queued_recovery": recovery(store, true, 8 * 1024 * 1024).await,
        "stuck_recovery": recovery(store, false, 8 * 1024 * 1024).await,
        "queued_recovery_within_64_bytes": recovery(store, true, 64).await,
        "stuck_recovery_within_64_bytes": recovery(store, false, 64).await,
        "terminal_missing_audit": store.terminal_requests_missing_audit(&actions).await.unwrap(),
        "terminal_missing_audit_no_actions":
            store.terminal_requests_missing_audit(&[]).await.unwrap(),
    })
}

async fn audit(store: &Store, rows: &[&RequestRow]) -> Value {
    let mut out = Vec::new();
    for row in rows {
        for entry in store.audit_for_request(&row.id).await.unwrap() {
            out.push(json!({
                "id": entry.id,
                "request_id": entry.request_id,
                "action": entry.action,
                "decision": entry.decision.as_str(),
                "actor": entry.actor.as_str(),
                "detail": opt_text(entry.detail.as_deref()),
                "ts": entry.ts,
            }));
        }
    }
    json!({
        "count": out.len(),
        "read_via": "audit_for_request per request (request id ascending, then audit id)",
        "rows": out,
    })
}

async fn grants(store: &Store, rows: &[&RequestRow]) -> Value {
    let grants = store.list_grants().await.unwrap();
    let mut capabilities: BTreeSet<&str> = grants.iter().map(|g| g.capability.as_str()).collect();
    capabilities.extend(rows.iter().map(|row| row.capability.as_str()));
    let mut per_capability = Map::new();
    for capability in capabilities {
        per_capability.insert(
            capability.to_owned(),
            json!({
                "active": store.active_grant(capability).await.unwrap(),
                "revocation_revision":
                    store.grant_revocation_revision_for(capability).await.unwrap(),
            }),
        );
    }
    json!({
        "count": grants.len(),
        "read_via": "list_grants, newest first",
        "not_readable": "revoked_seq has no public read; it shows through \
            request_queries/*/authorization_current and per_capability/*/revocation_revision",
        "rows": grants.iter().map(|grant| json!({
            "id": grant.id,
            "capability": grant.capability,
            "scope": grant.scope,
            "granted_ts": grant.granted_ts,
            "revoked_ts": grant.revoked_ts,
        })).collect::<Vec<_>>(),
        "revocation_revision": store.grant_revocation_revision().await.unwrap(),
        "per_capability": per_capability,
    })
}

async fn approvals(store: &Store, rows: &[&RequestRow]) -> Value {
    let mut out = Vec::new();
    for row in rows {
        if let Some(approval) = store.approval_for_request(&row.id).await.unwrap() {
            out.push(json!({
                "id": approval.id,
                "request_id": approval.request_id,
                "capability": approval.capability,
                "requested_ts": approval.requested_ts,
                "resolved_ts": approval.resolved_ts,
                "resolution": approval.resolution.map(pam_store::ApprovalResolution::as_str),
                "note": approval.note,
            }));
        }
    }
    let pending = store.list_pending_approvals().await.unwrap();
    json!({
        "count": out.len(),
        "read_via": "approval_for_request per request: the newest approval of each",
        "not_readable": "an older approval row of a request that has a newer one",
        "rows": out,
        "pending": pending.iter().map(|approval| json!({
            "request_id": approval.request_id,
            "capability": approval.capability,
            "repo": approval.repo,
            "caller_agent": approval.caller_agent,
            "requested_ts": approval.requested_ts,
            "request_capability": approval.request_capability,
            "args_json": text(&approval.args_json),
        })).collect::<Vec<_>>(),
    })
}

async fn callers(store: &Store) -> Value {
    let callers = store.list_callers().await.unwrap();
    json!({
        "count": callers.len(),
        "read_via": "list_callers, most recently seen first",
        "rows": callers.iter().map(|caller| json!({
            "agent": caller.agent,
            "repo": caller.repo,
            "first_seen": caller.first_seen,
            "last_seen": caller.last_seen,
        })).collect::<Vec<_>>(),
    })
}

async fn settings(store: &Store, probes: &Probes) -> Value {
    let mut out = Vec::new();
    for key in &probes.setting_keys {
        let value = store.get_setting(key).await.unwrap();
        out.push(json!({
            "key": key,
            "value": opt_text(value.as_deref()),
            "bounded_to_64_bytes": answer(
                store.get_setting_bounded(key, 64).await,
                |value| opt_text(value.as_deref()),
            ),
            "bounded_to_32_kib": answer(
                store.get_setting_bounded(key, 32 * 1024).await,
                |value| opt_text(value.as_deref()),
            ),
        }));
    }
    json!({
        "count": out.iter().filter(|row| !row["value"].is_null()).count(),
        "read_via": "get_setting and get_setting_bounded for each key in probes.setting_keys",
        "not_readable": "the store cannot list settings; a key outside the probes is not seen",
        "rows": out,
    })
}

async fn connectors(store: &Store) -> Value {
    let connectors = store.list_connectors().await.unwrap();
    for connector in &connectors {
        let again = store.get_connector(&connector.id).await.unwrap();
        assert_eq!(again.as_ref(), Some(connector));
    }
    json!({
        "count": connectors.len(),
        "read_via": "list_connectors by id; each row re-read with get_connector",
        "rows": connectors.iter().map(|connector| json!({
            "id": connector.id,
            "enabled": connector.enabled,
            "base_url": connector.base_url,
            "username": connector.username,
            "last_test_status": connector.last_test_status,
            "last_test_detail": connector.last_test_detail,
            "last_test_ts": connector.last_test_ts,
            "updated_ts": connector.updated_ts,
        })).collect::<Vec<_>>(),
    })
}

async fn model_jobs(store: &Store) -> Value {
    let jobs = store.list_model_jobs(MAX_LIST_LIMIT).await.unwrap();
    json!({
        "count": jobs.len(),
        "read_via": "list_model_jobs, newest first",
        "rows": jobs.iter().map(|job| json!({
            "id": job.id,
            "kind": job.kind,
            "model_id": job.model_id,
            "source": job.source,
            "state": job.state,
            "bytes_done": job.bytes_done,
            "bytes_total": job.bytes_total,
            "detail": job.detail,
            "created_ts": job.created_ts,
            "updated_ts": job.updated_ts,
        })).collect::<Vec<_>>(),
    })
}

async fn evidence(store: &Store, rows: &[&RequestRow], probes: &Probes) -> Value {
    let mut out = Vec::new();
    for row in rows {
        for meta in store.list_evidence(&row.id).await.unwrap() {
            let full = store.get_evidence(&meta.id).await.unwrap().unwrap();
            assert_eq!(u64::try_from(full.content.len()).unwrap(), meta.bytes);
            assert_eq!(
                (
                    &full.request_id,
                    &full.kind,
                    &full.content_hash,
                    &full.meta_json,
                    full.ts
                ),
                (
                    &meta.request_id,
                    &meta.kind,
                    &meta.content_hash,
                    &meta.meta_json,
                    meta.ts
                ),
                "get_evidence disagrees with list_evidence"
            );
            out.push(json!({
                "id": meta.id,
                "request_id": meta.request_id,
                "kind": meta.kind,
                "content": blob(&full.content),
                "content_hash": meta.content_hash,
                "meta_json": opt_text(meta.meta_json.as_deref()),
                "ts": meta.ts,
                "as_flow_checkpoint": answer(
                    store.read_flow_checkpoint(&row.id, &meta.id).await,
                    |bytes| bytes.as_deref().map_or(Value::Null, blob),
                ),
            }));
        }
    }
    let stats = |stats: pam_store::CompressionStats| {
        json!({
            "compressions": stats.compressions,
            "source_bytes": stats.source_bytes,
            "compact_bytes": stats.compact_bytes,
            "tokens_avoided_est": stats.tokens_avoided_est,
        })
    };
    let mut census = Map::new();
    for (name, evidence_cutoff, request_cutoff) in [
        ("no_window", None, None),
        ("all_evidence", Some(i64::MAX), None),
        ("all_requests", None, Some(i64::MAX)),
        ("both", Some(i64::MAX), Some(i64::MAX)),
        ("nothing_old_enough", Some(i64::MIN), Some(i64::MIN)),
    ] {
        let found = store
            .retention_census(evidence_cutoff, &probes.keep_kind, request_cutoff)
            .await
            .unwrap();
        census.insert(
            name.to_owned(),
            json!({ "eligible_rows": found.eligible_rows, "total_rows": found.total_rows }),
        );
    }
    json!({
        "count": out.len(),
        "read_via": "list_evidence per request (oldest first), each blob read with get_evidence",
        "not_readable": "path (always NULL: evidence is blob-backed)",
        "rows": out,
        "compression_stats_since_ever": stats(store.compression_stats(i64::MIN).await.unwrap()),
        "compression_stats_since_never": stats(store.compression_stats(i64::MAX).await.unwrap()),
        "retention_census": census,
    })
}

async fn evidence_views(store: &Store, probes: &Probes) -> Value {
    let mut out = Vec::new();
    for (request_id, evidence_id, repository) in &probes.views {
        let meta = store
            .evidence_view_meta(request_id, evidence_id, repository)
            .await;
        out.push(json!({
            "request_id": request_id,
            "evidence_id": evidence_id,
            "repository": repository,
            "meta": answer(meta, |meta| meta.map_or(Value::Null, |meta| json!({
                "authorization_revision": meta.authorization_revision,
                "authorization_current": meta.authorization_current,
                "identity_json": text(&meta.identity_json),
                "origin_json": text(&meta.origin_json),
                "map_json": text(&meta.map_json),
                "view_id": meta.view_id,
                "view_sha256": meta.view_sha256,
                "view_bytes": meta.view_bytes,
                "expired_at": meta.expired_at,
            }))),
        }));
    }
    json!({
        "count": out.iter().filter(|row| !row["meta"].is_null()).count(),
        "read_via": "evidence_view_meta for each tuple in probes.views; the bytes are read \
            in evidence_view_reads",
        "not_readable": "the store cannot list views; a tuple outside the probes is not seen",
        "rows": out,
    })
}

async fn correlation(store: &Store, rows: &[&RequestRow]) -> Value {
    let mut targets = Vec::new();
    let mut steps = Vec::new();
    let mut memberships = Vec::new();
    for row in rows {
        match store.read_correlation_target(&row.id).await {
            Ok(None) => {}
            Ok(Some(target)) => {
                targets.push(json!({ "request_id": row.id, "canonical_json": text(&target) }));
            }
            Err(error) => targets.push(json!({ "request_id": row.id, "read": refusal(&error) })),
        }
        let found = match store.read_correlation_steps(&row.id).await {
            Ok(found) => found,
            Err(error) => {
                steps.push(json!({ "request_id": row.id, "read": refusal(&error) }));
                continue;
            }
        };
        for step in found {
            steps.push(json!({
                "request_id": row.id,
                "step_id": step.step_id,
                "canonical_json": text(&step.canonical_json),
            }));
            let members = store
                .read_correlation_membership(&row.id, &step.step_id, &step.canonical_json)
                .await;
            memberships.push(json!({
                "request_id": row.id,
                "step_id": step.step_id,
                "members": answer(members, |members| json!(members)),
            }));
        }
    }
    json!({
        "correlation_target": {
            "count": targets.len(),
            "read_via": "read_correlation_target per request",
            "rows": targets,
        },
        "correlation_step": {
            "count": steps.len(),
            "read_via": "read_correlation_steps per request, by step id",
            "rows": steps,
        },
        "correlation_membership": {
            "read_via": "read_correlation_membership per step, under the step's own binding",
            "not_readable": "a step with no membership row and one with an empty list both \
                answer []; a step whose binding is not a GitHub run is refused before any read",
            "rows": memberships,
        },
    })
}

async fn budgets(store: &Store, rows: &[&RequestRow]) -> Value {
    let mut out = Vec::new();
    let mut budgets = 0_usize;
    for row in rows {
        // `load_request_budget` would create the row; the report only reads.
        let report = match store.request_budget_report(&row.id, &row.repo).await {
            Ok(report) => report.expect("a request is reported under its own repository"),
            Err(error) => {
                out.push(json!({ "request_id": row.id, "read": refusal(&error) }));
                continue;
            }
        };
        let work = &report["work"];
        let reads = &report["evidence_reads"];
        if work.is_null() && reads["state"] == "not_initialized" {
            continue;
        }
        budgets += usize::from(!work.is_null());
        let figures = |suffix: &str| {
            if work.is_null() {
                return Value::Null;
            }
            json!({
                "attempts": work[format!("attempt_slots_{suffix}")],
                "http_calls": work[format!("http_call_slots_{suffix}")],
                "http_bytes": work[format!("http_bytes_{suffix}")],
                "command_bytes": work[format!("command_bytes_{suffix}")],
            })
        };
        out.push(json!({
            "request_id": row.id,
            "execution_expires_at_ms": report["execution_expires_at_ms"],
            "charged": figures("charged"),
            "remaining": figures("remaining"),
            "evidence_reads": {
                "state": reads["state"],
                "expires_at": reads["expires_at"],
                "remaining_bytes": reads["remaining_bytes"],
                "remaining_pages": reads["remaining_pages"],
            },
        }));
    }
    json!({
        "count": budgets,
        "read_via": "request_budget_report per request under its own repository: `charged` \
            and `remaining` are the request_budget row, `evidence_reads` the \
            evidence_read_allowance row; a request with neither is left out",
        "not_readable": "evidence_read_allowance.started_at, and an allowance under a \
            repository other than the request's own (see evidence_view_reads for those)",
        "rows": out,
    })
}

fn journal_state(state: FlowJournalState) -> &'static str {
    match state {
        FlowJournalState::Ready => "ready",
        FlowJournalState::Prepared => "prepared",
        FlowJournalState::Completed => "completed",
        FlowJournalState::Uncertain => "uncertain",
    }
}

async fn flow_journals(store: &Store, rows: &[&RequestRow], probes: &Probes) -> Value {
    let mut journals = Vec::new();
    let mut projections = Vec::new();
    let nothing_published = json!({
        "evidence_origins": { "ready": [] },
        "flow_result": null,
        "watch_progress": null,
    });
    for row in rows {
        match store.read_flow_journal(&row.id).await {
            Ok(None) => {}
            Ok(Some(journal)) => journals.push(json!({
                "request_id": journal.identity.request_id,
                "flow_digest": journal.identity.flow_digest,
                "repository": journal.identity.repository,
                "input_fingerprint": journal.identity.input_fingerprint,
                "revision": journal.revision,
                "state": journal_state(journal.state),
                "step_id": journal.step_id,
                "attempt": journal.attempt,
                "effectful": journal.effectful,
                "checkpoint_json": text(&journal.checkpoint_json),
                "evidence_refs": journal.evidence_refs,
            })),
            Err(error) => journals.push(json!({ "request_id": row.id, "read": refusal(&error) })),
        }
        for repository in probes.repositories_for(row) {
            let origins = store
                .request_evidence_origins_state(&row.id, &repository)
                .await;
            let result = store.flow_result_meta(&row.id, &repository).await;
            let progress = store.flow_watch_progress(&row.id, &repository).await;
            let projection = json!({
                "evidence_origins": answer(origins, |origins| match origins {
                    EvidenceOrigins::Ready(origins) => json!({ "ready": origins }),
                    EvidenceOrigins::Incomplete => json!("incomplete"),
                    EvidenceOrigins::Foreign => json!("foreign"),
                }),
                "flow_result": answer(result, |meta| meta.map_or(Value::Null, |meta| json!({
                    "origin_json": text(&meta.origin_json),
                    "metadata_json": text(&meta.metadata_json),
                }))),
                "watch_progress": answer(progress, |progress| json!(progress)),
            });
            // Nothing captured, nothing published: the answer for most
            // request and repository pairs, and not worth a line each.
            if projection != nothing_published {
                projections.push(json!({
                    "request_id": row.id,
                    "repository": repository,
                    "projection": projection,
                }));
            }
        }
    }
    json!({
        "count": journals.len(),
        "read_via": "read_flow_journal per request",
        "rows": journals,
        "projections_read_via": "request_evidence_origins_state, flow_result_meta and \
            flow_watch_progress per request under its own and each probe repository; a pair \
            with no evidence, result or progress is left out",
        "projections": projections,
    })
}

async fn landing_sessions(store: &Store, rows: &[&RequestRow]) -> Value {
    let mut out = Vec::new();
    for row in rows {
        match store.read_landing_session(&row.id).await {
            Ok(None) => {}
            Ok(Some(session)) => out.push(json!({
                "request_id": row.id,
                "revision": session.revision,
                "document": text(&session.document),
            })),
            Err(error) => out.push(json!({ "request_id": row.id, "read": refusal(&error) })),
        }
    }
    let live = store.live_landing_session_documents().await;
    json!({
        "count": out.len(),
        "read_via": "read_landing_session per request",
        "rows": out,
        "live_documents": answer(live, |documents| {
            json!(documents.iter().map(|document| text(document)).collect::<Vec<_>>())
        }),
    })
}

/// Reads every probed view to its end through the public range read, which
/// charges the request's allowance, and records what came back.
///
/// The first read of each view asks for the end of it, which the store
/// answers without charging and with the allowance as it stands; the pages
/// that follow use the clock that allowance was started with, so an
/// allowance persisted in the fixture is still open however much later the
/// test runs.
async fn view_reads(store: &Store, probes: &Probes) -> Value {
    let mut out = Vec::new();
    for (request_id, evidence_id, repository) in &probes.views {
        let Ok(Some(meta)) = store
            .evidence_view_meta(request_id, evidence_id, repository)
            .await
        else {
            continue;
        };
        let read = |offset: u64, length: u32, now: i64, sha256: &str| EvidenceRangeRequest {
            request_id: request_id.clone(),
            evidence_id: evidence_id.clone(),
            repository: repository.clone(),
            expected_view_id: meta.view_id.clone(),
            expected_sha256: sha256.to_owned(),
            offset,
            length,
            now,
        };
        let mut entry = json!({
            "request_id": request_id,
            "evidence_id": evidence_id,
            "repository": repository,
        });
        let wrong = "0".repeat(64);
        entry["under_another_digest"] = range_outcome(
            store
                .read_evidence_view_range(&read(0, 1, RANGE_PROBE_NOW, &wrong))
                .await,
        );
        let end = store
            .read_evidence_view_range(&read(
                meta.view_bytes,
                1,
                RANGE_PROBE_NOW,
                &meta.view_sha256,
            ))
            .await;
        let Ok(EvidenceRangeOutcome::Range(end)) = end else {
            entry["end_of_view"] = range_outcome(end);
            out.push(entry);
            continue;
        };
        entry["allowance_before"] = json!({
            "expires_at": end.allowance_expires_at,
            "remaining_bytes": end.remaining_bytes,
            "remaining_pages": end.remaining_pages,
        });
        let now = end.allowance_expires_at - 3600;
        let mut bytes: Vec<u8> = Vec::new();
        let mut pages = Vec::new();
        let mut offset = Some(0_u64);
        while let Some(at) = offset.take() {
            if at >= meta.view_bytes {
                break;
            }
            let page = store
                .read_evidence_view_range(&read(at, RANGE_PAGE, now, &meta.view_sha256))
                .await;
            if let Ok(EvidenceRangeOutcome::Range(range)) = &page {
                bytes.extend_from_slice(&range.bytes);
                offset = range.next_offset;
            }
            pages.push(range_outcome(page));
        }
        assert_eq!(
            sha256_hex(&bytes) == meta.view_sha256,
            u64::try_from(bytes.len()).unwrap() == meta.view_bytes,
            "a view read whole must hash to its recorded digest"
        );
        entry["pages"] = json!(pages);
        entry["content"] = blob(&bytes);
        out.push(entry);
    }
    json!({
        "read_via": "read_evidence_view_range, 64 KiB pages; each page is charged to the \
            request's allowance (a write), which is why this runs last",
        "rows": out,
    })
}

fn range_outcome(outcome: Result<EvidenceRangeOutcome, StoreError>) -> Value {
    answer(outcome, |outcome| match outcome {
        EvidenceRangeOutcome::Unavailable => json!({ "outcome": "unavailable" }),
        EvidenceRangeOutcome::Expired => json!({ "outcome": "expired" }),
        EvidenceRangeOutcome::InvalidRange => json!({ "outcome": "invalid_range" }),
        EvidenceRangeOutcome::BudgetExhausted => json!({ "outcome": "budget_exhausted" }),
        EvidenceRangeOutcome::Range(range) => json!({
            "outcome": "range",
            "view_id": range.view_id,
            "offset": range.offset,
            "bytes": range.bytes.len(),
            "total_bytes": range.total_bytes,
            "next_offset": range.next_offset,
            "allowance_expires_at": range.allowance_expires_at,
            "remaining_bytes": range.remaining_bytes,
            "remaining_pages": range.remaining_pages,
        }),
    })
}
