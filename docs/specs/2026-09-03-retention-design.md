# Retention — design

Status: approved by owner (brainstorming session, 2026-09-03)
Umbrella vision: `docs/vision.md` GUI principle 7 ("Settings are
complete, day one — logs (retention, ...)"). Spine spec
(`docs/specs/2026-09-01-spine-design.md`, "Retention: pruning by age
policy from Settings — evidence first, audit last"). Log-compression
spec deferred the pruning half here.

## Scope and owner decisions (2026-09-03)

- **Two windows, both age-based, both from Settings.** "Keep evidence
  for" (30 days / 90 days / 1 year / forever) and "keep audit rows for"
  (90 days / 1 year / forever). The existing disabled `RetentionPanel`
  wakes up with exactly these choices.
- **Defaults are forever.** A store that has never been told a window
  loses nothing on upgrade. The GUI shows `forever` until a human picks
  otherwise.
- **Audit-age pruning removes the whole request record** (owner
  decision): the `request` row, its `audit` rows, its `approval` row,
  and whatever `evidence` it still holds, `flow.result` included.
  Activity history shrinks to the window. `grant`, `caller`,
  `model_job`, `connector`, and `setting` rows are never pruned.
- **Evidence-age pruning removes evidence only**, and never a request's
  `flow.result` row — the verdict lives exactly as long as its audit
  rows (plan note from #5). Evidence of a non-terminal request is never
  touched, whatever its age.
- **Order invariant:** the evidence window may not exceed the audit
  window (`forever` counts as infinite). The daemon refuses such a
  save; the GUI does not pre-filter, the human learns the rule from pam
  (same posture as Settings › Flows).
- **Schedule** (owner decision): the daemon prunes at boot (after crash
  recovery), every hour after that, right after a settings save, and on
  demand from a "Prune now" button. The last run's figures are stored
  and shown.
- **No VACUUM.** Freed pages are reused by the engine; the panel reports
  rows and blob bytes removed, not file size.

Out of scope: pruning the daemon's own `daemon.log` (tracing rotates it
daily already), per-kind evidence windows, size-based caps, pruning
`model_job` history, an "undo".

## Daemon

### `pam_store` — two prune methods

```rust
/// What one prune pass removed.
pub struct EvidencePrune { pub rows: u64, pub bytes: u64 }
pub struct RequestPrune { pub requests: u64, pub audit_rows: u64, pub approvals: u64, pub evidence_rows: u64, pub evidence_bytes: u64 }

impl Store {
    /// Deletes evidence rows with `ts < cutoff_ts` whose kind is not
    /// `keep_kind` and whose request is terminal. One transaction under
    /// `conn_lock`; counts and blob bytes are measured before the delete.
    pub async fn prune_evidence_before(&self, cutoff_ts: i64, keep_kind: &str) -> Result<EvidencePrune, StoreError>;

    /// Deletes terminal requests (`done|refused|failed`) with
    /// `updated_ts < cutoff_ts` together with their audit, approval and
    /// evidence rows — children first, one transaction under `conn_lock`.
    pub async fn prune_requests_before(&self, cutoff_ts: i64) -> Result<RequestPrune, StoreError>;
}
```

Both hold `conn_lock` across `BEGIN..COMMIT` (memento law: one turso
connection, one statement at a time). Counts come from `SELECT
COUNT(*), COALESCE(SUM(LENGTH(content)),0)` before each `DELETE` so the
report is exact whatever the engine's `changes()` says about
multi-table deletes.

### `pam_daemon::retention` — settings, validation, prune, scheduler

```rust
pub const SETTING_EVIDENCE_DAYS: &str = "retention.evidence_days"; // JSON u32 or null
pub const SETTING_AUDIT_DAYS: &str = "retention.audit_days";       // JSON u32 or null
pub const SETTING_LAST_RUN: &str = "retention.last_run";           // JSON PruneReport
pub const MAX_DAYS: u32 = 3650;
pub const PRUNE_INTERVAL: Duration = Duration::from_hours(1);
pub const CAUSE_RETENTION_INVALID: &str = "retention_invalid";

#[derive(Serialize, Deserialize)]
pub struct RetentionSettings { pub evidence_days: Option<u32>, pub audit_days: Option<u32> }
pub struct RetentionPatch { pub evidence_days: Option<Option<u32>>, pub audit_days: Option<Option<u32>> }

#[derive(Serialize, Deserialize)]
pub struct PruneReport { pub ts: i64, pub evidence_rows: u64, pub evidence_bytes: u64, pub requests: u64, pub audit_rows: u64 }

pub struct RetentionService { store: Arc<Store> }
impl RetentionService {
    pub fn new(store: Arc<Store>) -> Self;
    pub async fn settings(&self) -> Result<RetentionSettings, StoreError>;   // unset key = None
    pub async fn set_settings(&self, patch: RetentionPatch) -> Result<RetentionSettings, RetentionRefusal>;
    pub async fn prune(&self, now_ts: i64) -> Result<PruneReport, StoreError>;  // stores SETTING_LAST_RUN
    pub async fn last_run(&self) -> Result<Option<PruneReport>, StoreError>;
    pub fn run_scheduler(self, interval: Duration, shutdown: watch::Receiver<bool>) -> JoinHandle<()>;
}
```

- `settings()` reads both keys; an unreadable stored value logs a warn
  and reads as `None` (forever), never as a window.
- `set_settings` validates the merged result: each window is `None` or
  `1..=MAX_DAYS`; `evidence_days` must be `<=` `audit_days` when both
  are set, and `Some` evidence with `None` audit is fine (evidence
  shorter than forever). A violation refuses with
  `CAUSE_RETENTION_INVALID`, detail naming the two values, recovery
  "Keep evidence no longer than audit rows: shorten the evidence window
  or lengthen the audit one." Nothing is written on refusal.
- `prune(now)`: evidence pass when `evidence_days` is set
  (`cutoff = now - days*86400`, keep kind `flow.result`), then request
  pass when `audit_days` is set. A pass that removed nothing is still a
  run: `last_run` is written every time with `ts = now`. Errors
  propagate; the scheduler logs them and keeps ticking.
- `run_scheduler`: `tokio::time::interval` (first tick immediate, so
  boot prunes) with `MissedTickBehavior::Delay`, `select!` against the
  drain watch like `QueueManager::run_reaper`. Logs at info when a pass
  removed anything, at debug otherwise.

### `pam_daemon::admin_retention` — three GUI-only ops

| op | args | answer |
| --- | --- | --- |
| `admin.retention.get` | — | `{ evidence_days, audit_days, last_run }` (`last_run` = `PruneReport` or `null`) |
| `admin.retention.set` | `{ evidence_days?, audit_days? }` — each a number or `null`; absent = unchanged | same shape as `get`, after an immediate prune |
| `admin.retention.prune` | — | `PruneReport` |

`RETENTION_ADMIN_OPS` is spliced into `pam_gui::bridge::ADMIN_OPS`
like the other four lists; the bridge test's core count (`9 + ...`)
gains `+ RETENTION_ADMIN_OPS.len()`. Ordinary admin ops in every other
way: tripwire, request row, one terminal audit row (audit detail
carries the settings or the counts, never a body), 30 s deadline. The
ops build a `RetentionService` over `self.store` on demand — no new
`AdminService` field, no constructor change.

### Wiring

`run_daemon_with` spawns `RetentionService::new(store).run_scheduler(PRUNE_INTERVAL, drain_rx)`
next to the reaper. Nothing else in the daemon changes.

## GUI

### `ipc.ts`

```ts
export interface RetentionSettings { evidence_days: number | null; audit_days: number | null }
export interface PruneReport { ts: number; evidence_rows: number; evidence_bytes: number; requests: number; audit_rows: number }
export interface RetentionState extends RetentionSettings { last_run: PruneReport | null }
export function retentionGet(): Promise<RetentionState>
export function retentionSet(patch: Partial<RetentionSettings>): Promise<RetentionState>
export function retentionPrune(): Promise<PruneReport>
```

`AdminOp` gains the three names.

### `RetentionPanel` (Settings.tsx)

- Query `["retention"]` → `retentionGet`. Two enabled `<select>`s with
  the same labels as today (`evidence age`, `audit age`); value is the
  day count or `"forever"`. Choices: `EVIDENCE_CHOICES = [30, 90, 365, null]`,
  `AUDIT_CHOICES = [90, 365, null]` (exported for the test). Changing
  one fires `retentionSet({ <key>: value })`; success replaces the query
  data; a refusal renders as `FailureNote` (label `retention`) and the
  select snaps back to the stored value.
- Header row: eyebrow `storage pruning`, the `arrives with retention`
  badge is gone; right side is a `Prune now` ghost button (disabled
  while pending) that calls `retentionPrune` and then invalidates the
  query.
- Status line in the data voice: `last pruned 12m ago · 41 evidence rows
  (2.1 MB) · 3 requests` from `last_run`, or `never pruned yet`. After a
  manual prune the same line shows the fresh report.
- Closing italic copy, first person: "I prune when I start, every hour
  after that, and whenever you change these. Evidence goes first; a
  request's verdict stays until its audit rows go, then the whole record
  leaves together."
- Tests (`Settings.test.tsx` retention block): renders stored values and
  the last-run line; picking `90 days` for evidence calls
  `retentionSet({ evidence_days: 90 })`; a `retention_invalid` refusal
  shows the FailureNote; `Prune now` calls `retentionPrune` and shows
  the counts. The heading list assertions elsewhere stay as they are.

## Testing

- `pam_store/src/store_test.rs`: evidence prune skips `flow.result`,
  skips non-terminal requests, reports rows + bytes; request prune
  removes request + audit + approval + evidence for terminal rows older
  than the cutoff only, leaves newer and in-flight rows, and the
  foreign-key pragma stays satisfied afterwards.
- `pam_daemon/src/retention_test.rs`: unset keys read as forever; set
  persists and answers the merged settings; the order violation refuses
  and writes nothing; `prune` writes `last_run` even when nothing went;
  ages are computed from `now_ts`.
- `pam_daemon/src/admin_retention_test.rs`: whitelist names three ops
  once; `get` on a fresh store; `set` then `get` round-trip; refusal
  cause; `prune` answers a report and leaves one audit row per op.
- `pam_gui/src/bridge_test.rs`: every retention op is whitelisted; the
  total count includes the new list.
- Frontend vitest as above. Local gate `tools/check.sh` before every PR.

## Landing

Two branches from `main`, disjoint files:

- **A, Rust** (`feat/retention-daemon`): `pam_store` prune methods,
  `pam_daemon::retention`, `pam_daemon::admin_retention`, scheduler
  wiring, `pam_gui` bridge splice + tests.
- **B, GUI** (`feat/retention-gui`): `ipc.ts`, `Settings.tsx`,
  `Settings.test.tsx`.

B merges after A. Eyeball through the fixture proxy against a live
daemon (settings round trip, refusal, Prune now) in both theme
families; prove the production bundle carries the op names
(`admin.retention.prune` in `dist/assets/*.js` and in the gui-embed
binary).
