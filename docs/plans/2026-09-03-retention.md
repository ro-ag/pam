# Retention — implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Evidence and audit rows are pruned by age from two Settings selects; the daemon prunes at boot, hourly, after a save, and on "Prune now", and reports what it removed.

**Architecture:** `pam_store` gains two transactional prune methods. `pam_daemon::retention` owns the two settings (`setting` table, JSON), their validation (evidence window ≤ audit window), the prune pass (evidence first, then whole request records) and an hourly scheduler task. `pam_daemon::admin_retention` exposes `admin.retention.get/set/prune` as GUI-only admin ops spliced into the `pam_gui` bridge whitelist. The frontend `RetentionPanel` binds its two selects to those ops and adds a Prune now button and a last-run line.

**Tech Stack:** Rust (turso store, tokio), React 19 + TypeScript, TanStack Query, Tailwind v4 tokens, vitest + testing-library.

Spec: `docs/specs/2026-09-03-retention-design.md` (approved 2026-09-03).

## Global constraints

- Branch first, PR + squash merge, no AI attribution in commits or PRs. Never commit to `main`.
- Rust tests live in sibling `*_test.rs` files wired with `#[cfg(test)] mod x_test;` — never `mod tests` inside a source file.
- No new dependencies, Rust or npm. No new CI workflows.
- Every store method takes `conn_lock` at the top; a transaction holds it across `BEGIN..COMMIT` (turso forbids concurrent statements on one connection).
- ESLint bans Tailwind arbitrary values; colors only via `@theme` tokens; copy in pam's first-person voice for the italic notes, data voice (`font-data`) for figures.
- Test harnesses seed nothing platform-specific here; in-memory stores only.
- Local gate before every PR: `tools/check.sh` (fmt, clippy -D warnings, cargo test, eslint, tsc + vite build, vitest). Foreground only — no background waits.

## File structure

Branch A (`feat/retention-daemon`):
- Modify `crates/pam_store/src/store.rs` — `EvidencePrune`, `RequestPrune`, `prune_evidence_before`, `prune_requests_before`; `crates/pam_store/src/lib.rs` re-exports; tests in `crates/pam_store/src/store_test.rs`.
- Create `crates/pam_daemon/src/retention.rs` + `retention_test.rs` — settings, validation, prune pass, scheduler.
- Create `crates/pam_daemon/src/admin_retention.rs` + `admin_retention_test.rs` — the three ops.
- Modify `crates/pam_daemon/src/lib.rs` (modules), `crates/pam_daemon/src/admin.rs` (dispatch chain), `crates/pam_daemon/src/daemon.rs` (scheduler spawn).
- Modify `crates/pam_gui/src/bridge.rs` (splice) + `bridge_test.rs` (count + list test).

Branch B (`feat/retention-gui`):
- Modify `frontend/src/lib/ipc.ts` — types, three wrappers, `AdminOp` union.
- Modify `frontend/src/screens/Settings.tsx` — `RetentionPanel`.
- Modify `frontend/src/screens/Settings.test.tsx` — retention block + mocks.

---

### Task 1: `pam_store` prune methods

**Files:**
- Modify: `crates/pam_store/src/store.rs` (types near `CompressionStats`, methods after `compression_stats`)
- Modify: `crates/pam_store/src/lib.rs` (re-export `EvidencePrune`, `RequestPrune`)
- Test: `crates/pam_store/src/store_test.rs`

**Interfaces — produces:**

```rust
/// What one evidence prune pass removed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct EvidencePrune { pub rows: u64, pub bytes: u64 }

/// What one request prune pass removed, table by table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RequestPrune {
    pub requests: u64, pub audit_rows: u64, pub approvals: u64,
    pub evidence_rows: u64, pub evidence_bytes: u64,
}

impl Store {
    pub async fn prune_evidence_before(&self, cutoff_ts: i64, keep_kind: &str) -> Result<EvidencePrune, StoreError>;
    pub async fn prune_requests_before(&self, cutoff_ts: i64) -> Result<RequestPrune, StoreError>;
}
```

- [ ] **Step 1: Failing tests** (append to `store_test.rs`; `ts` columns are set with raw SQL through `store.conn`, which is `pub(crate)`)

```rust
/// Backdates every timestamp column of one request record so a prune
/// with cutoff `now` sees it as old.
async fn age_request(store: &Store, id: &str, ts: i64) {
    for sql in [
        "UPDATE request SET created_ts = ?2, updated_ts = ?2 WHERE id = ?1",
        "UPDATE audit SET ts = ?2 WHERE request_id = ?1",
        "UPDATE evidence SET ts = ?2 WHERE request_id = ?1",
    ] {
        store.conn.execute(sql, turso::params![id, ts]).await.unwrap();
    }
}

async fn count(store: &Store, sql: &str) -> i64 {
    let mut rows = store.conn.query(sql, ()).await.unwrap();
    rows.next().await.unwrap().unwrap().get(0).unwrap()
}

#[tokio::test]
async fn prune_evidence_skips_the_kept_kind_and_inflight_requests() {
    let store = Store::open_in_memory().await.unwrap();
    insert_demo_request(&store, "old_done").await;
    store.finish_request("old_done", RequestState::Done, None, entry("execute")).await.unwrap();
    store.insert_evidence("ev_a", "old_done", "log.source", b"0123456789", None).await.unwrap();
    store.insert_evidence("ev_b", "old_done", "flow.result", b"{}", None).await.unwrap();
    insert_demo_request(&store, "old_running").await;
    store.update_request_state("old_running", RequestState::Running, None).await.unwrap();
    store.insert_evidence("ev_c", "old_running", "log.source", b"xyz", None).await.unwrap();
    age_request(&store, "old_done", 1_000).await;
    age_request(&store, "old_running", 1_000).await;

    let pruned = store.prune_evidence_before(2_000, "flow.result").await.unwrap();
    assert_eq!(pruned, EvidencePrune { rows: 1, bytes: 10 });
    assert!(store.get_evidence("ev_a").await.unwrap().is_none());
    assert!(store.get_evidence("ev_b").await.unwrap().is_some());
    assert!(store.get_evidence("ev_c").await.unwrap().is_some());
    // A second pass has nothing left to do.
    assert_eq!(store.prune_evidence_before(2_000, "flow.result").await.unwrap(), EvidencePrune::default());
}

#[tokio::test]
async fn prune_evidence_leaves_rows_at_or_after_the_cutoff() {
    let store = Store::open_in_memory().await.unwrap();
    insert_demo_request(&store, "fresh").await;
    store.finish_request("fresh", RequestState::Done, None, entry("execute")).await.unwrap();
    store.insert_evidence("ev_new", "fresh", "log.source", b"new", None).await.unwrap();
    // Inserted "now"; a cutoff far in the past keeps it.
    assert_eq!(store.prune_evidence_before(1_000, "flow.result").await.unwrap(), EvidencePrune::default());
    assert!(store.get_evidence("ev_new").await.unwrap().is_some());
}

#[tokio::test]
async fn prune_requests_removes_the_whole_terminal_record_only() {
    let store = Store::open_in_memory().await.unwrap();
    // Old and terminal: goes, with everything hanging off it.
    insert_demo_request(&store, "old").await;
    store.insert_approval("old", "release").await.unwrap();
    store.finish_request("old", RequestState::Refused, Some("denied"), entry("gate_refusal")).await.unwrap();
    store.insert_evidence("ev_old", "old", "flow.result", b"verdict", None).await.unwrap();
    // Old but in flight: stays.
    insert_demo_request(&store, "stuck").await;
    store.update_request_state("stuck", RequestState::Running, None).await.unwrap();
    // Terminal but fresh: stays.
    insert_demo_request(&store, "fresh").await;
    store.finish_request("fresh", RequestState::Done, None, entry("execute")).await.unwrap();
    age_request(&store, "old", 1_000).await;
    age_request(&store, "stuck", 1_000).await;

    let pruned = store.prune_requests_before(2_000).await.unwrap();
    assert_eq!(pruned, RequestPrune { requests: 1, audit_rows: 1, approvals: 1, evidence_rows: 1, evidence_bytes: 7 });
    assert!(store.get_request("old").await.unwrap().is_none());
    assert!(store.get_request("stuck").await.unwrap().is_some());
    assert!(store.get_request("fresh").await.unwrap().is_some());
    assert_eq!(count(&store, "SELECT COUNT(*) FROM audit WHERE request_id = 'old'").await, 0);
    assert_eq!(count(&store, "SELECT COUNT(*) FROM approval WHERE request_id = 'old'").await, 0);
    assert!(store.get_evidence("ev_old").await.unwrap().is_none());
    assert_eq!(count(&store, "SELECT COUNT(*) FROM audit WHERE request_id = 'fresh'").await, 1);
    // Nothing dangles: every audit row still has its request.
    assert_eq!(count(&store, "SELECT COUNT(*) FROM audit WHERE request_id NOT IN (SELECT id FROM request)").await, 0);
}
```

Imports to add at the top of `store_test.rs`: `EvidencePrune, RequestPrune` from `crate`.

- [ ] **Step 2: Run** `cargo test -p pam_store prune` — expect compile failure (types missing).

- [ ] **Step 3: Implement** in `store.rs`. Both methods: take `conn_lock`, `BEGIN`, measure, delete, `COMMIT` (`ROLLBACK` on error, same shape as `finish_request`). Age filter for evidence is `evidence.ts < ?1`; for requests it is `request.updated_ts < ?1`.

```rust
/// Deletes evidence rows older than `cutoff_ts` whose kind is not
/// `keep_kind` and whose request is already terminal ...
pub async fn prune_evidence_before(&self, cutoff_ts: i64, keep_kind: &str) -> Result<EvidencePrune, StoreError> {
    let _guard = self.conn_lock.lock().await;
    self.conn.execute("BEGIN", ()).await?;
    let result = self.prune_evidence_in_txn(cutoff_ts, keep_kind).await;
    self.end_txn(result).await
}

const EVIDENCE_PRUNE_FILTER: &str = "ts < ?1 AND kind <> ?2 AND request_id IN \
    (SELECT id FROM request WHERE state IN ('done','refused','failed'))";

async fn prune_evidence_in_txn(&self, cutoff_ts: i64, keep_kind: &str) -> Result<EvidencePrune, StoreError> {
    let (rows, bytes) = self.measure(&format!("SELECT COUNT(*), COALESCE(SUM(LENGTH(content)), 0) FROM evidence WHERE {EVIDENCE_PRUNE_FILTER}"), params![cutoff_ts, keep_kind]).await?;
    if rows > 0 {
        self.conn.execute(&format!("DELETE FROM evidence WHERE {EVIDENCE_PRUNE_FILTER}"), params![cutoff_ts, keep_kind]).await?;
    }
    Ok(EvidencePrune { rows, bytes })
}
```

`prune_requests_in_txn` measures four counts with the request filter `request_id IN (SELECT id FROM request WHERE state IN ('done','refused','failed') AND updated_ts < ?1)` (evidence count+bytes, audit count, approval count) plus the request count, then deletes evidence, approval, audit, request in that order. A shared helper `end_txn(result)` commits on `Ok` and rolls back on `Err`; `measure` runs one query and reads `(u64, u64)` from columns 0 and 1 via `i64` → `u64::try_from(..).unwrap_or(0)`. No `unwrap` outside tests.

- [ ] **Step 4: Run** `cargo test -p pam_store` — all pass. `cargo clippy -p pam_store --all-targets -- -D warnings` clean.

- [ ] **Step 5: Commit** `feat(store): age-based prune of evidence and request records (#60)`.

### Task 2: `pam_daemon::retention`

**Files:**
- Create: `crates/pam_daemon/src/retention.rs`, `crates/pam_daemon/src/retention_test.rs`
- Modify: `crates/pam_daemon/src/lib.rs` (`pub mod retention;` + `#[cfg(test)] mod retention_test;`)

**Interfaces — produces:**

```rust
pub const SETTING_EVIDENCE_DAYS: &str = "retention.evidence_days";
pub const SETTING_AUDIT_DAYS: &str = "retention.audit_days";
pub const SETTING_LAST_RUN: &str = "retention.last_run";
pub const MAX_DAYS: u32 = 3650;
pub const PRUNE_INTERVAL: Duration = Duration::from_secs(60 * 60);
pub const CAUSE_RETENTION_INVALID: &str = "retention_invalid";
pub const RECOVERY_RETENTION_INVALID: &str = "Keep evidence no longer than audit rows: shorten the evidence window or lengthen the audit one.";
pub const KEEP_KIND: &str = crate::flow_service::EVIDENCE_KIND_FLOW_RESULT;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct RetentionSettings { pub evidence_days: Option<u32>, pub audit_days: Option<u32> }

/// An absent field leaves the setting alone; `Some(None)` sets forever.
#[derive(Debug, Clone, Copy, Default)]
pub struct RetentionPatch { pub evidence_days: Option<Option<u32>>, pub audit_days: Option<Option<u32>> }

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PruneReport { pub ts: i64, pub evidence_rows: u64, pub evidence_bytes: u64, pub requests: u64, pub audit_rows: u64 }

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RetentionRefusal { Invalid { detail: String }, Store(String) }

#[derive(Debug, Clone)]
pub struct RetentionService { store: Arc<Store> }
impl RetentionService {
    pub fn new(store: Arc<Store>) -> Self;
    pub async fn settings(&self) -> Result<RetentionSettings, StoreError>;
    pub async fn set_settings(&self, patch: RetentionPatch) -> Result<RetentionSettings, RetentionRefusal>;
    pub async fn prune(&self, now_ts: i64) -> Result<PruneReport, StoreError>;
    pub async fn last_run(&self) -> Result<Option<PruneReport>, StoreError>;
    pub fn run_scheduler(self, interval: Duration, shutdown: watch::Receiver<bool>) -> JoinHandle<()>;
}
pub fn validate(settings: RetentionSettings) -> Result<(), String>;  // pure, the rule in one place
pub fn now_ts() -> i64;
```

- [ ] **Step 1: Failing tests** (`retention_test.rs`)

```rust
use std::sync::Arc;
use std::time::Duration;
use pam_store::{Actor, AuditEntry, Decision, RequestState, Store};
use crate::retention::{
    MAX_DAYS, PruneReport, RetentionPatch, RetentionRefusal, RetentionService, RetentionSettings,
    SETTING_EVIDENCE_DAYS, validate,
};

const DAY: i64 = 86_400;

async fn service() -> (Arc<Store>, RetentionService) {
    let store = Arc::new(Store::open_in_memory().await.unwrap());
    (Arc::clone(&store), RetentionService::new(store))
}

async fn finished_request(store: &Store, id: &str) {
    store.insert_request(id, "release", "ro-ag/pam", "claude", "{}", None).await.unwrap();
    store.finish_request(id, RequestState::Done, None, AuditEntry { action: "execute", decision: Decision::Allow, actor: Actor::System, detail: None }).await.unwrap();
}

#[tokio::test]
async fn unset_keys_read_as_forever() {
    let (_store, service) = service().await;
    assert_eq!(service.settings().await.unwrap(), RetentionSettings::default());
    assert_eq!(service.last_run().await.unwrap(), None);
}

#[tokio::test]
async fn set_persists_and_merges() {
    let (store, service) = service().await;
    let got = service.set_settings(RetentionPatch { audit_days: Some(Some(365)), ..Default::default() }).await.unwrap();
    assert_eq!(got, RetentionSettings { evidence_days: None, audit_days: Some(365) });
    let got = service.set_settings(RetentionPatch { evidence_days: Some(Some(90)), ..Default::default() }).await.unwrap();
    assert_eq!(got, RetentionSettings { evidence_days: Some(90), audit_days: Some(365) });
    assert_eq!(store.get_setting(SETTING_EVIDENCE_DAYS).await.unwrap().as_deref(), Some("90"));
    let got = service.set_settings(RetentionPatch { evidence_days: Some(None), ..Default::default() }).await.unwrap();
    assert_eq!(got.evidence_days, None);
}

#[tokio::test]
async fn evidence_longer_than_audit_refuses_and_writes_nothing() {
    let (_store, service) = service().await;
    service.set_settings(RetentionPatch { audit_days: Some(Some(90)), ..Default::default() }).await.unwrap();
    let err = service.set_settings(RetentionPatch { evidence_days: Some(Some(365)), ..Default::default() }).await.unwrap_err();
    assert!(matches!(err, RetentionRefusal::Invalid { .. }));
    assert_eq!(service.settings().await.unwrap().evidence_days, None);
    // Forever evidence under a finite audit window is the same violation.
    let err = service.set_settings(RetentionPatch { evidence_days: Some(None), audit_days: Some(Some(30)) }).await.unwrap_err();
    assert!(matches!(err, RetentionRefusal::Invalid { .. }));
}

#[test]
fn validate_bounds_and_order() {
    assert!(validate(RetentionSettings { evidence_days: Some(0), audit_days: None }).is_err());
    assert!(validate(RetentionSettings { evidence_days: None, audit_days: Some(MAX_DAYS + 1) }).is_err());
    assert!(validate(RetentionSettings { evidence_days: Some(30), audit_days: Some(30) }).is_ok());
    assert!(validate(RetentionSettings { evidence_days: Some(30), audit_days: None }).is_ok());
    assert!(validate(RetentionSettings::default()).is_ok());
}

#[tokio::test]
async fn prune_applies_both_windows_and_records_the_run() {
    let (store, service) = service().await;
    finished_request(&store, "r1").await;
    store.insert_evidence("ev1", "r1", "log.source", b"abcdef", None).await.unwrap();
    store.insert_evidence("ev2", "r1", "flow.result", b"{}", None).await.unwrap();
    let now = crate::retention::now_ts();
    // No windows: nothing goes, but the run is recorded.
    let report = service.prune(now).await.unwrap();
    assert_eq!(report, PruneReport { ts: now, evidence_rows: 0, evidence_bytes: 0, requests: 0, audit_rows: 0 });
    assert_eq!(service.last_run().await.unwrap(), Some(report));
    // Evidence window only, seen from 40 days ahead: the source goes, the verdict stays.
    service.set_settings(RetentionPatch { evidence_days: Some(Some(30)), ..Default::default() }).await.unwrap();
    let report = service.prune(now + 40 * DAY).await.unwrap();
    assert_eq!((report.evidence_rows, report.evidence_bytes, report.requests), (1, 6, 0));
    assert!(store.get_evidence("ev2").await.unwrap().is_some());
    // Audit window too, seen from 100 days ahead: the whole record goes.
    service.set_settings(RetentionPatch { audit_days: Some(Some(90)), ..Default::default() }).await.unwrap();
    let report = service.prune(now + 100 * DAY).await.unwrap();
    assert_eq!((report.requests, report.audit_rows, report.evidence_rows), (1, 1, 1));
    assert!(store.get_request("r1").await.unwrap().is_none());
}

#[tokio::test]
async fn scheduler_prunes_on_its_first_tick_and_stops_on_shutdown() {
    let (store, service) = service().await;
    let (tx, rx) = tokio::sync::watch::channel(false);
    let task = service.clone().run_scheduler(Duration::from_secs(3600), rx);
    tokio::time::timeout(Duration::from_secs(5), async {
        while service.last_run().await.unwrap().is_none() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }).await.expect("the first tick prunes at once");
    tx.send(true).unwrap();
    tokio::time::timeout(Duration::from_secs(5), task).await.expect("stops on drain").unwrap();
    drop(store);
}
```

- [ ] **Step 2: Run** `cargo test -p pam_daemon retention` — compile failure.

- [ ] **Step 3: Implement** `retention.rs` with a module doc in the crate's voice (why: the spine spec's "evidence first, audit last"; owner decisions; the one-connection rule). Details:
  - `settings()`: for each key, `store.get_setting(key)` → `serde_json::from_str::<Option<u32>>(&raw)`; a parse error logs `tracing::warn!(setting = key, "the stored retention window is unreadable; treating it as forever")` and yields `None`.
  - `set_settings`: `let current = self.settings().await.map_err(store_refusal)?; let merged = RetentionSettings { evidence_days: patch.evidence_days.unwrap_or(current.evidence_days), audit_days: patch.audit_days.unwrap_or(current.audit_days) }; validate(merged).map_err(|detail| RetentionRefusal::Invalid { detail })?;` then write only the patched keys as `serde_json::to_string(&Option<u32>)` (`"90"` / `"null"`), return `merged`.
  - `validate`: each `Some(d)` must satisfy `1..=MAX_DAYS` ("evidence window must be 1..=3650 days"); if `evidence_days > audit_days` (treating `None` as infinite: `Some(e), Some(a) if e > a` or `(None, Some(_))`) → `Err(format!("evidence window ({}) exceeds audit window ({})", describe(e), describe(a)))` where `describe(None) = "forever"`, `describe(Some(d)) = "{d} days"`.
  - `prune(now_ts)`: read settings; `evidence = match evidence_days { Some(d) => store.prune_evidence_before(now_ts - i64::from(d) * 86_400, KEEP_KIND).await?, None => EvidencePrune::default() }`; same for requests; build `PruneReport { ts: now_ts, evidence_rows: evidence.rows + requests.evidence_rows, evidence_bytes: evidence.bytes + requests.evidence_bytes, requests: requests.requests, audit_rows: requests.audit_rows }`; `store.set_setting(SETTING_LAST_RUN, &serde_json::to_string(&report)?)` — map the serde error into `StoreError` via the existing variant used elsewhere in the crate, or `tracing::warn!` and continue if none fits (check `StoreError` variants; prefer a store-level error over a panic). Log `tracing::info!` when any count is nonzero, `tracing::debug!` otherwise.
  - `run_scheduler`: same shape as `QueueManager::run_reaper` (`tokio::time::interval`, `MissedTickBehavior::Delay`, `select!` on `shutdown.changed()`); each tick calls `self.prune(now_ts())` and logs `tracing::warn!(%error, "retention prune failed")` on error.
  - `now_ts()`: same as the store's private helper (`SystemTime::now()` secs, `i64::try_from(..).unwrap_or(i64::MAX)`).

- [ ] **Step 4: Run** `cargo test -p pam_daemon retention` — pass; clippy clean.

- [ ] **Step 5: Commit** `feat(daemon): retention service — windows, validation, prune pass, hourly scheduler (#60)`.

### Task 3: `admin.retention.*` ops + bridge splice + scheduler wiring

**Files:**
- Create: `crates/pam_daemon/src/admin_retention.rs`, `crates/pam_daemon/src/admin_retention_test.rs`
- Modify: `crates/pam_daemon/src/lib.rs`, `crates/pam_daemon/src/admin.rs` (`dispatch`: add `dispatch_retention` after `dispatch_connectors`, module docs list), `crates/pam_daemon/src/daemon.rs` (spawn scheduler), `crates/pam_gui/src/bridge.rs`, `crates/pam_gui/src/bridge_test.rs`

**Interfaces — produces:**

```rust
pub const OP_RETENTION_GET: &str = "admin.retention.get";
pub const OP_RETENTION_SET: &str = "admin.retention.set";
pub const OP_RETENTION_PRUNE: &str = "admin.retention.prune";
pub const RETENTION_ADMIN_OPS: &[&str] = &[OP_RETENTION_GET, OP_RETENTION_SET, OP_RETENTION_PRUNE];
impl AdminService {
    pub(crate) async fn dispatch_retention(&self, op: &str, args: &Value) -> Option<Result<AdminOk, AdminRefusal>>;
}
```

Bodies: `get`/`set` answer `{ "evidence_days": <u32|null>, "audit_days": <u32|null>, "last_run": <PruneReport|null> }`; `prune` answers the `PruneReport` as JSON (`serde_json::to_value`). `set` parses each of `evidence_days` / `audit_days`: absent → `None`; JSON `null` → `Some(None)`; a non-negative integer that fits `u32` → `Some(Some(n))`; anything else → `AdminRefusal { cause: CAUSE_INVALID_ADMIN_ARGS, detail: "admin.retention.set: evidence_days must be a whole number of days or null", recovery: RECOVERY_FIX_ARGS }`. After a successful set it calls `prune(now_ts())` and answers with the settings and the fresh `last_run`. `RetentionRefusal::Invalid { detail }` → `AdminRefusal { cause: CAUSE_RETENTION_INVALID, detail, recovery: RECOVERY_RETENTION_INVALID }`; `RetentionRefusal::Store(detail)` → `CAUSE_INTERNAL_ERROR` + `RECOVERY_INTERNAL`. Outcomes: get `Verified`, set `Changed`, prune `Changed` when any count is nonzero else `Verified`. Audit details: `{ "op": ..., "evidence_days": ..., "audit_days": ... }` for get/set, the counts for prune.

- [ ] **Step 1: Failing tests** (`admin_retention_test.rs`; copy the fixture shape of `admin_logs_test.rs` — `fixture()` building `AdminService` over an in-memory store, `envelope(op, args)` with the GUI tripwire caller, `body_of`, `cause_of`)

```rust
#[test]
fn the_bridge_whitelist_names_every_op_once() {
    let mut sorted = RETENTION_ADMIN_OPS.to_vec();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(sorted.len(), RETENTION_ADMIN_OPS.len());
    assert_eq!(RETENTION_ADMIN_OPS.len(), 3);
    for op in RETENTION_ADMIN_OPS { assert!(op.starts_with("admin.retention."), "{op} is misnamed"); }
}

#[tokio::test]
async fn get_on_a_fresh_store_is_forever_and_never_pruned() {
    let f = fixture().await;
    let body = body_of(f.admin.handle(&f.envelope(OP_RETENTION_GET, json!({}))).await, Outcome::Verified);
    assert_eq!(body, json!({ "evidence_days": null, "audit_days": null, "last_run": null }));
}

#[tokio::test]
async fn set_persists_prunes_at_once_and_round_trips() {
    let f = fixture().await;
    let body = body_of(f.admin.handle(&f.envelope(OP_RETENTION_SET, json!({ "audit_days": 365, "evidence_days": 90 }))).await, Outcome::Changed);
    assert_eq!(body["evidence_days"], 90);
    assert_eq!(body["audit_days"], 365);
    assert!(body["last_run"]["ts"].is_i64(), "a save prunes at once");
    let body = body_of(f.admin.handle(&f.envelope(OP_RETENTION_GET, json!({}))).await, Outcome::Verified);
    assert_eq!(body["evidence_days"], 90);
    // null clears one window; the other is untouched.
    let body = body_of(f.admin.handle(&f.envelope(OP_RETENTION_SET, json!({ "evidence_days": null }))).await, Outcome::Changed);
    assert_eq!(body, json!({ "evidence_days": null, "audit_days": 365, "last_run": body["last_run"] }));
}

#[tokio::test]
async fn set_refuses_the_order_violation_and_bad_args() {
    let f = fixture().await;
    f.admin.handle(&f.envelope(OP_RETENTION_SET, json!({ "audit_days": 90 }))).await;
    assert_eq!(cause_of(f.admin.handle(&f.envelope(OP_RETENTION_SET, json!({ "evidence_days": 365 }))).await), CAUSE_RETENTION_INVALID);
    assert_eq!(cause_of(f.admin.handle(&f.envelope(OP_RETENTION_SET, json!({ "evidence_days": "soon" }))).await), CAUSE_INVALID_ADMIN_ARGS);
    assert_eq!(cause_of(f.admin.handle(&f.envelope(OP_RETENTION_SET, json!({ "evidence_days": -1 }))).await), CAUSE_INVALID_ADMIN_ARGS);
}

#[tokio::test]
async fn prune_answers_a_report_and_every_op_leaves_one_audit_row() {
    let f = fixture().await;
    let body = body_of(f.admin.handle(&f.envelope(OP_RETENTION_PRUNE, json!({}))).await, Outcome::Verified);
    assert_eq!(body["requests"], 0);
    assert!(body["ts"].is_i64());
    assert!(f.store.terminal_requests_missing_audit(TERMINAL_ACTIONS).await.unwrap().is_empty());
}
```

- [ ] **Step 2: Run** `cargo test -p pam_daemon admin_retention` — compile failure.

- [ ] **Step 3: Implement** `admin_retention.rs` (module doc: why GUI-only — deleting the audit trail is the most human act the daemon has; same security model as the other admin modules). Wire `dispatch_retention` into `AdminService::dispatch` in `admin.rs` right after the connectors branch (`.map_err(OwnedRefusal::from)`), add the module to `admin.rs`'s module-doc list of surfaces, and add `pub mod admin_retention;` + `#[cfg(test)] mod admin_retention_test;` to `lib.rs`. The ops build `RetentionService::new(Arc::clone(&self.store))` on demand.

- [ ] **Step 4: Wire the scheduler** in `daemon.rs::run_daemon_with`: after the reaper entry in `tasks`, `RetentionService::new(Arc::clone(&store)).run_scheduler(PRUNE_INTERVAL, drain_rx.clone())`. Add the task to the module docs' task list.

- [ ] **Step 5: Bridge splice** in `pam_gui/src/bridge.rs`: import `pam_daemon::admin_retention::RETENTION_ADMIN_OPS`, add it to `ADMIN_OPS_LEN` and `compose_admin_ops` (a sixth while-loop after connectors), extend the doc comment. In `bridge_test.rs` add `+ pam_daemon::admin_retention::RETENTION_ADMIN_OPS.len()` to the count and a `every_retention_admin_op_is_whitelisted` test mirroring the connector one. If `deadline_for` special-cases ops, retention ops take the default 30 s.

- [ ] **Step 6: Run** `cargo test -p pam_daemon -p pam_gui` — pass; `cargo clippy --workspace --all-targets -- -D warnings`; `cargo fmt --all --check`.

- [ ] **Step 7: Commit** `feat(daemon): admin.retention.get/set/prune, hourly prune task, GUI bridge splice (#60)`.

- [ ] **Step 8: Gate + PR.** `tools/check.sh` green in the foreground. Push `feat/retention-daemon`, open a PR titled `feat(daemon): age-based retention — prune evidence and audit records (#60)` whose body summarizes the three ops, the schedule, and the two store methods. No attribution lines.

### Task 4: GUI — `RetentionPanel` wakes up

**Files:**
- Modify: `frontend/src/lib/ipc.ts` (`AdminOp` union; new section after `flowsSettingsSet`)
- Modify: `frontend/src/screens/Settings.tsx` (`RetentionPanel`, lines ~508–555; imports)
- Modify: `frontend/src/screens/Settings.test.tsx` (mocks + `describe("retention")`)

**Interfaces — consumes** the op bodies from Task 3 exactly. **Produces:**

```ts
export interface RetentionSettings { evidence_days: number | null; audit_days: number | null }
export interface PruneReport { ts: number; evidence_rows: number; evidence_bytes: number; requests: number; audit_rows: number }
export interface RetentionState extends RetentionSettings { last_run: PruneReport | null }
export function retentionGet(): Promise<RetentionState>
export function retentionSet(patch: Partial<RetentionSettings>): Promise<RetentionState>
export function retentionPrune(): Promise<PruneReport>
// Settings.tsx
export const EVIDENCE_CHOICES: ReadonlyArray<number | null> = [30, 90, 365, null];
export const AUDIT_CHOICES: ReadonlyArray<number | null> = [90, 365, null];
export function windowLabel(days: number | null): string; // "30 days" | "90 days" | "1 year" | "forever"
export function pruneLine(report: PruneReport, nowMs?: number): string; // "last pruned 12m ago · 41 evidence rows (2.1 MB) · 3 requests"
```

- [ ] **Step 1: Failing tests.** Add `retentionGet`, `retentionSet`, `retentionPrune` to `mocks` and to the `vi.mock` spread (already spreads `mocks`). In `beforeEach`: `mocks.retentionGet.mockResolvedValue({ evidence_days: 90, audit_days: 365, last_run: { ts: nowSec - 720, evidence_rows: 41, evidence_bytes: 2_100_000, requests: 3, audit_rows: 5 } }); mocks.retentionSet.mockImplementation(async (patch) => ({ evidence_days: 90, audit_days: 365, last_run: null, ...patch })); mocks.retentionPrune.mockResolvedValue({ ts: nowSec, evidence_rows: 2, evidence_bytes: 512, requests: 0, audit_rows: 0 });`. Replace the retention describe:

```ts
describe("retention", () => {
  it("renders the stored windows and the last run", async () => {
    renderSettings();
    const evidence = (await screen.findByLabelText("evidence age")) as HTMLSelectElement;
    await waitFor(() => expect(evidence.value).toBe("90"));
    expect((screen.getByLabelText("audit age") as HTMLSelectElement).value).toBe("365");
    expect(screen.getByText(/last pruned 12m ago · 41 evidence rows \(2\.1 MB\) · 3 requests/)).toBeInTheDocument();
    expect(screen.queryByText("arrives with retention")).not.toBeInTheDocument();
    expect(EVIDENCE_CHOICES).toEqual([30, 90, 365, null]);
    expect(AUDIT_CHOICES).toEqual([90, 365, null]);
  });

  it("saves a changed window through the daemon", async () => {
    renderSettings();
    const evidence = await screen.findByLabelText("evidence age");
    await waitFor(() => expect((evidence as HTMLSelectElement).value).toBe("90"));
    fireEvent.change(evidence, { target: { value: "forever" } });
    await waitFor(() => expect(mocks.retentionSet).toHaveBeenCalledWith({ evidence_days: null }));
    fireEvent.change(screen.getByLabelText("audit age"), { target: { value: "90" } });
    await waitFor(() => expect(mocks.retentionSet).toHaveBeenCalledWith({ audit_days: 90 }));
  });

  it("shows the daemon's refusal and snaps the select back", async () => {
    mocks.retentionSet.mockRejectedValue({ cause: "retention_invalid", detail: "evidence window (1 year) exceeds audit window (90 days)", recovery: "Keep evidence no longer than audit rows: shorten the evidence window or lengthen the audit one." });
    renderSettings();
    const evidence = (await screen.findByLabelText("evidence age")) as HTMLSelectElement;
    await waitFor(() => expect(evidence.value).toBe("90"));
    fireEvent.change(evidence, { target: { value: "365" } });
    expect(await screen.findByText(/exceeds audit window/)).toBeInTheDocument();
    await waitFor(() => expect(evidence.value).toBe("90"));
  });

  it("prunes on demand and reports the counts", async () => {
    renderSettings();
    const prune = await screen.findByRole("button", { name: "Prune now" });
    fireEvent.click(prune);
    await waitFor(() => expect(mocks.retentionPrune).toHaveBeenCalledTimes(1));
    expect(await screen.findByText(/2 evidence rows \(512 B\) · 0 requests/)).toBeInTheDocument();
  });

  it("never pruned yet reads honestly", async () => {
    mocks.retentionGet.mockResolvedValue({ evidence_days: null, audit_days: null, last_run: null });
    renderSettings();
    expect(await screen.findByText("never pruned yet")).toBeInTheDocument();
    expect(((await screen.findByLabelText("evidence age")) as HTMLSelectElement).value).toBe("forever");
  });
});
```

Also update the file's header comment ("the honestly-disabled retention section" → "the retention windows and prune button") and import `AUDIT_CHOICES, EVIDENCE_CHOICES` from `./Settings`.

- [ ] **Step 2: Run** `npm --prefix frontend run test -- Settings.test` — the retention tests fail.

- [ ] **Step 3: Implement.** `ipc.ts`: add the three op names to `AdminOp`, the types and wrappers in a `// --- retention ---` section (doc comment: why GUI-only, what `null` means). `Settings.tsx` `RetentionPanel`:
  - `const state = useQuery({ queryKey: ["retention"], queryFn: retentionGet });`
  - `save = useMutation({ mutationFn: retentionSet, onMutate: () => setFailure(null), onSuccess: (next) => queryClient.setQueryData(["retention"], next), onError: (e) => setFailure(toBridgeFailure(e)), onSettled: () => invalidate ["retention"] })` — the select is controlled from `state.data`, so a refusal snaps back on its own.
  - `prune = useMutation({ mutationFn: retentionPrune, onSuccess: (report) => { setReport(report); invalidate ["retention"]; }, onError: ... })`.
  - Select value: `days === null ? "forever" : String(days)`; `onChange`: `value === "forever" ? null : Number(value)`; `disabled={state.isPending || save.isPending}`. Keep the two `aria-label`s and `selectClasses`. Options rendered from `EVIDENCE_CHOICES` / `AUDIT_CHOICES` with `windowLabel`.
  - Header row: eyebrow `storage pruning` left; right a `Button size="sm" variant="ghost"` labelled `Prune now` (`disabled={prune.isPending}`).
  - Line under the selects in `font-data text-xs text-ink-muted`: `report ? pruneLine(report) : state.data?.last_run ? pruneLine(state.data.last_run) : "never pruned yet"`. `pruneLine` uses `relativeTime(report.ts, nowMs)` and `formatBytes(report.evidence_bytes)` (import from `../lib/bytes`): `` `last pruned ${relativeTime(ts)} · ${evidence_rows} evidence rows (${formatBytes(evidence_bytes)}) · ${requests} requests` ``. (After a manual prune the report's `ts` is "now", so the line reads `last pruned now · 2 evidence rows (512 B) · 0 requests`.)
  - `FailureNote` for the query error (`label="retention"`) and for the mutation failure.
  - Closing italic copy: "I prune when I start, every hour after that, and whenever you change these. Evidence goes first; a request's verdict stays until its audit rows go, then the whole record leaves together."
  - Update the `RetentionPanel` doc comment and the file header line that says "the one thing the daemon cannot do yet (retention pruning)".

- [ ] **Step 4: Run** `npm --prefix frontend run test`, `npm --prefix frontend run lint`, `npm --prefix frontend run build` — green.

- [ ] **Step 5: Commit** `feat(gui): retention panel — windows, prune now, last run (#61)`.

- [ ] **Step 6: Gate + PR.** `tools/check.sh` green in the foreground. Push `feat/retention-gui`, PR titled `feat(gui): Settings › Retention wakes up (#61)`. No attribution lines.

## Self-review

- Spec coverage: defaults forever (Task 2 `settings()`), order invariant (Task 2 `validate` + Task 3 refusal), whole-record audit prune and `flow.result` keep (Task 1), schedule boot/hourly/save/now (Tasks 2, 3, 4), last-run figures (Tasks 2, 4), bridge splice (Task 3), GUI copy and tests (Task 4).
- Type names match across tasks: `RetentionSettings`, `RetentionPatch`, `PruneReport`, `RetentionRefusal`, `EvidencePrune`, `RequestPrune`, `RETENTION_ADMIN_OPS`, `CAUSE_RETENTION_INVALID`.
