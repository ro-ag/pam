# Log compression — design

Status: approved by owner (brainstorming session, 2026-09-02)
Umbrella vision: `docs/vision.md` §4 "Log compression"
Depends on: spine spec (evidence table, admin surface) and model-layer spec
(`ModelService::generate`, tiers).

## Scope

Deterministic reduction of build/test logs first, local-model summary
second, with the original always addressable by an evidence handle. The
success metric is input tokens avoided per diagnosis, and the GUI shows it.

**Owner decisions (2026-09-02):**

- Log compression is **daemon-internal**. No `pam` subcommand and no
  agent-facing capability: agents get compact verdicts through flows
  (plan #5) and connector diagnoses (plan #8), which call the service
  directly. Nothing here widens the CLI surface.
- The one caller today is a **GUI-only admin op** so a human can drive a
  log through the pipeline and inspect every evidence row it leaves. This
  is the observatory, not a product feature for agents.
- The vision's **"tokens avoided" odometer** ships now, fed by an
  aggregate over the compact evidence rows (migration 4 adds
  `evidence.meta_json`).
- Issue #3 (Windows `RemoveStale` `PermissionDenied` on a fresh temp
  dir) is investigated in this plan: `remove_stale` tolerates the
  transient handle race instead of failing the daemon boot.

Out of scope: evidence pruning/retention (its Settings panel stays
disabled with corrected copy), stage boundaries and boilerplate rules
from pam-old's policy (no caller yet), streaming progress events (the
op is synchronous under the envelope deadline), path-backed evidence
(`evidence.path` stays NULL; every row is a BLOB).

## Crate: `pam_compact`

Pure Rust library (`serde`, `serde_json`, `sha2`, `hex`, `thiserror`),
no daemon knowledge. A port of pam-old's `pam-log-compact-v1` structural
compactor, kept byte-exact so the algorithm version name still means
the same thing.

```rust
pub const ALGORITHM_VERSION: &str = "pam-log-compact-v1";
pub const MAX_SOURCE_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_SOURCE_RECORDS: usize = 100_000;
pub const MAX_FAILURE_CONTEXT_RECORDS: usize = 64;
pub const DEFAULT_BOUNDARY_RECORDS: usize = 20;
pub const DEFAULT_FAILURE_CONTEXT_RECORDS: usize = 3;

pub struct Policy { pub boundary_records: usize, pub failure_context_records: usize }
impl Default for Policy { /* 20 / 3 */ }

pub fn compact(bytes: &[u8], exit_status: Option<i32>, policy: &Policy)
    -> Result<Compacted, CompactError>;
pub fn estimate_tokens(bytes: u64) -> u64;   // bytes.div_ceil(4)
pub fn sha256_hex(bytes: &[u8]) -> String;

pub struct Compacted {
    pub algorithm_version: String,
    pub source_sha256: String,
    pub exit_status: Option<i32>,
    pub source_bytes: u64, pub retained_bytes: u64,
    pub source_records: u64, pub retained_records: u64,
    pub rendered_text: String,
    pub fragments: Vec<Fragment>,
}
pub struct Fragment { pub offset: u64, pub length: u64, pub kind: FragmentKind, pub rendered: String }
pub enum FragmentKind {
    Retained { reasons: Vec<RetentionReason> },
    Omitted { reason: OmissionReason, record_count: u64 },
}
pub enum RetentionReason { FirstBoundary, LastBoundary, FailureNeighborhood { keyword: FailureKeyword } }
pub enum OmissionReason { OutsideRetentionWindow, Repeated, SupersededProgress }
pub enum FailureKeyword { Error, Fatal, Panic, Failed }
pub enum CompactError { SourceTooLarge { actual_bytes, maximum_bytes }, TooManyRecords { maximum_records }, InvalidPolicy { field: &'static str } }
impl CompactError { pub fn cause(&self) -> &'static str } // source_too_large | too_many_records | invalid_policy
```

Algorithm (all byte-based, locale-independent, deterministic):

1. **Records.** Split on `\r\n` (line), `\n` (line), bare `\r` (progress
   frame). A trailing unterminated tail is a line. More than
   `MAX_SOURCE_RECORDS` → `TooManyRecords`.
2. **Display form.** Strip ANSI CSI/OSC escapes, lossy UTF-8, control
   characters rendered as `\t`, `\xNN`, `\u{...}`.
3. **Omissions (pre-pass).** Progress frames: a bare-`\r` frame is
   `SupersededProgress` when any record follows it (the next record
   overwrites it on a terminal); only a trailing frame at the end of the
   input survives. Then adjacent records with an identical display form
   collapse: the second and later are `Repeated` (an omitted record
   resets the comparison).
4. **Retention.** Over the surviving ("active") records: the first
   `boundary_records` get `FirstBoundary`, the last `boundary_records`
   `LastBoundary`; each active record whose display contains `error`,
   `fatal`, `panic`, or `failed` (ASCII case-insensitive) keeps itself and
   `failure_context_records` active neighbors on each side with
   `FailureNeighborhood { keyword }`. Reasons are deduplicated per record.
5. **Fragments.** Retained records render as `display\n`. Consecutive
   omitted records with the same reason merge into one fragment rendered
   as `[... N records outside retention windows ...]`,
   `[... N repeated records collapsed ...]`,
   `[... N progress frames superseded ...]`. Every source byte belongs
   to exactly one fragment (`offset`, `length`), fragments are
   contiguous and ordered — the original is rebuilt by reading the
   ranges from the source handle in order.
6. **Footer.** Empty input renders `[no log output]\n`. Always ends with
   `[exit status: N]\n` or `[exit status: unknown]\n`.

Bounds are checked before any work: `SourceTooLarge` over 64 MiB,
`InvalidPolicy` when `failure_context_records > 64` or
`boundary_records > MAX_SOURCE_RECORDS`.

## Store (`pam_store`)

Migration 4: `ALTER TABLE evidence ADD COLUMN meta_json TEXT;` — small
kind-specific metadata (stats for compacts, model figures for
summaries) so the GUI lists evidence without reading blobs and the
odometer aggregates without parsing reports.

```rust
pub struct EvidenceRow  { id, request_id, kind, content: Vec<u8>, content_hash, meta_json: Option<String>, ts }
pub struct EvidenceMeta { id, request_id, kind, bytes: u64, content_hash, meta_json: Option<String>, ts }
pub struct CompressionStats { compressions: u64, source_bytes: u64, compact_bytes: u64, tokens_avoided_est: u64 }

impl Store {
    pub async fn insert_evidence(&self, id: &str, request_id: &str, kind: &str, content: &[u8], meta_json: Option<&str>) -> Result<(), StoreError>; // sha256 hex into content_hash, ts = now
    pub async fn get_evidence(&self, id: &str) -> Result<Option<EvidenceRow>, StoreError>;
    pub async fn list_evidence(&self, request_id: &str) -> Result<Vec<EvidenceMeta>, StoreError>; // LENGTH(content), no blob, ordered by ts, id
    pub async fn compression_stats(&self, since_ts: i64) -> Result<CompressionStats, StoreError>; // kind = 'log.compact' AND ts >= since; sums read from meta_json in Rust (no SQL JSON functions); rows with unreadable meta count as a compression with zero figures and a warn
}
```

Evidence ids are `ev_<ulid>`, minted by the daemon. Every statement runs
behind the existing `conn_lock` (turso concurrency rule).

## Daemon (`pam_daemon`)

### `LogService`

```rust
pub struct LogService { store: Arc<Store>, models: Arc<ModelService> }
pub struct CompressInput { pub name: String, pub bytes: Vec<u8>, pub exit_status: Option<i32>, pub use_model: bool }
pub struct EvidenceRef { pub id: String, pub bytes: u64 }
pub struct CompressStats { source_bytes, compact_bytes, source_records, retained_records, tokens_source_est, tokens_compact_est, tokens_avoided_est }
pub struct ModelUse { pub id: String, pub tier: &'static str, pub prompt_tokens, pub completion_tokens, pub tokens_per_sec }
pub struct ModelSkipped { pub cause: String, pub detail: String }
pub struct CompressReport {
    pub source: EvidenceRef, pub compact: EvidenceRef, pub summary: Option<EvidenceRef>,
    pub compact_text: String, pub summary_text: Option<String>,
    pub stats: CompressStats, pub model: Option<ModelUse>, pub model_skipped: Option<ModelSkipped>,
}
pub enum LogError { SourceTooLarge { actual_bytes, maximum_bytes }, Compact(CompactError), Store(StoreError) }
impl LogService { pub async fn compress(&self, request_id: &str, input: CompressInput) -> Result<CompressReport, LogError>; }
```

Pipeline, in order, under the caller's request id (evidence rows
reference `request(id)`, so the caller owns a request row — the admin
op today, a flow step later):

1. Bound: `bytes.len() > MAX_SOURCE_BYTES` → `SourceTooLarge`.
2. `spawn_blocking`: `pam_compact::compact(&bytes, exit_status, &Policy::default())` (CPU work off the runtime).
3. Evidence `log.source`: content = the exact bytes, meta
   `{ "name", "exit_status" }`.
4. Evidence `log.compact`: content = the `Compacted` report as JSON
   (fragments included — this is the provenance map), meta = the
   `CompressStats` plus `{ "name", "algorithm_version", "exit_status",
   "source_evidence": <id> }`. `tokens_*_est = estimate_tokens(bytes)`,
   `tokens_avoided_est = source − compact` (saturating).
5. Model summary when `use_model`: prompt = `rendered_text` fitted to
   `PROMPT_BUDGET_BYTES = 24_000` (≈6k tokens under the 8192 context
   with the system turn and a 400-token answer): longer texts keep the
   first 16 000 and last 8 000 bytes cut at line boundaries around a
   `[... N bytes elided for the model prompt ...]` marker. Request:
   `system = SUMMARY_SYSTEM`, `max_tokens = 400`, `temperature = 0`,
   `stop = []`, via `ModelService::generate(Tier::Heavy, …)` (heavy →
   light → none). Ok → evidence `log.summary`, content = the text, meta
   `{ "model_id", "tier", "prompt_tokens", "completion_tokens",
   "tokens_per_sec", "source_evidence", "compact_evidence" }`. Err →
   `model_skipped { cause, detail }` with cause `no_default`,
   `model_missing`, or the runtime cause (`prompt_too_long`, `busy`,
   `load_failed`, `generation_failed`, `crashed`, …). **A model failure
   never fails the compress**: the deterministic result stands.
6. Return the report; the caller's audit row records the figures.

`SUMMARY_SYSTEM`: "You are PAM's log summarizer. You receive a build or
test log that was already reduced deterministically; bracketed markers
say how many records were omitted and why. Answer in plain text, at most
eight lines: the outcome first (pass, fail, or unknown), then the failing
step and the exact error lines that explain it, quoted verbatim, then
what a developer must fix. Never invent lines that are not in the log."

### Admin ops (`admin_logs.rs`, GUI-only, same intercept and audit choke point)

| op | args | answer |
| --- | --- | --- |
| `admin.log.compress` | `{ path: absolute string, exit_status?: i32, model?: bool = true }` | `CompressReport`; outcome `solved` |
| `admin.evidence.list` | `{ request_id }` | `{ evidence: [ { id, request_id, kind, bytes, sha256, meta, ts } ] }` |
| `admin.evidence.get` | `{ id, max_bytes? = 262 144 (clamped to 4 MiB) }` | `{ id, request_id, kind, bytes, sha256, meta, ts, text, text_bytes, truncated }` — `text` is lossy UTF-8 of the first `max_bytes`; for `log.compact` it is the report's `rendered_text` (the JSON is the storage form, the text is what a reader wants). `bytes` is always the blob length; `text_bytes` is the length of the text `text` is a prefix of (the rendered text for `log.compact`), and `truncated = text_bytes > max_bytes` |
| `admin.evidence.stats` | `{ since_ts? = now − 7 days }` | `{ since_ts, compressions, source_bytes, compact_bytes, tokens_avoided_est }` |

Refusals (`cause` / recovery): `bad_args` (missing or relative `path`,
non-integer `exit_status`), `source_unreadable` (metadata or read
failed; detail names the path and the OS error; recovery "Check the
path and that the daemon's user can read it"), `source_too_large`
(size checked from metadata before reading), `not_found` (unknown
evidence id or request id with no rows is an empty list, not a
refusal). The file is read by the daemon's own user through
`tokio::fs`; the human names the path in the GUI. Audit detail for
compress: `{ op, name, source_bytes, compact_bytes, tokens_avoided_est,
summarized, model_skipped }`.

`AdminService` gains `logs: Arc<LogService>`; `dispatch_logs` answers
first for its ops like `dispatch_models` does; `LOG_ADMIN_OPS` is the
list the bridge splices in. The GUI bridge deadline for
`admin.log.compress` is 120 s (a heavy-tier generation on a 30B MoE
plus a 64 MiB compaction).

### `remove_stale` (issue #3)

`runtime_dir::remove_stale(path)` becomes a bounded retry:
`NotFound` → Ok; `PermissionDenied` → Ok when the file is gone after
the error, otherwise retry up to 5 attempts 25 ms apart, then the error;
any other error → the error immediately. The loop is written over an
injected remover (`remove_stale_with(path, remover, attempts, backoff)`)
so the retry policy is unit-tested without a platform race. The
transport still reports `RemoveStale` when the attempts run out, with
the same legible message.

## GUI (`pam_gui` + frontend)

- Bridge: `ADMIN_OPS` composed from core + model + log lists (three
  daemon-owned lists, nothing retyped); `deadline_for` gives
  `admin.log.compress` 120 s.
- `ipc.ts`: `AdminOp` union extended; typed wrappers `logCompress`,
  `evidenceList`, `evidenceGet`, `evidenceStats` and their reply types.
- **Activity screen** (the tide):
  - An evidence band under the header: the **odometer tile** — big
    `font-display` digits for tokens avoided over the last 7 days, digits
    rolling from the previous value with `motion` (instant under
    `prefers-reduced-motion`), with the count of compressions and
    "88 KB → 4 KB" in `font-data`; and the **compress box** — path input,
    optional exit status, "use model" toggle (on), a Compress button.
    Success invalidates activity, stats, and expands the new request's
    row; a refusal renders as a `FailureNote`.
  - **Row detail**: an evidence strip fetched on expand — one mono chip
    per row (`kind · size`, the `ev_` id as title). Clicking a chip loads
    it into a viewer under the strip: `log.summary` in the serif voice,
    everything else in a Plex Mono `<pre>`; `log.compact` shows its stats
    line first ("1,204 → 61 records · 88 KB → 4 KB · ~21k tokens
    avoided"); a truncated body says "showing the first 256 KB of N".
    Rows without evidence show nothing new.
- Settings › Retention copy: evidence rows exist now (sources, compacts,
  summaries); pruning still arrives with the retention plan.
- Frontend tests (vitest) mock `ipc` for the tile, the compress box, the
  strip and viewer, and the truncated state; the bridge whitelist test
  asserts every log op is forwarded and unknown ops refused.

## Testing

- `pam_compact`: sibling tests port pam-old's behaviours — CRLF/LF/CR
  parsing, ANSI stripping, control rendering, progress supersession,
  repeat collapse with reset, boundary windows, failure neighborhoods
  (case-insensitive, clamped at the ends, overlapping reasons
  deduplicated), every byte covered exactly once by ordered fragments,
  empty input, exit footer, determinism (same input, same output),
  `SourceTooLarge`, `TooManyRecords`, `InvalidPolicy`, `estimate_tokens`.
- `pam_store`: insert/get round-trips bytes and the sha256; list
  returns metadata without blobs; stats sum only `log.compact` rows
  newer than `since_ts`; migration 4 applies on a v3 database.
- `pam_daemon`: `LogService` with no tier default → three-step report
  with `model_skipped.cause == "no_default"`, two evidence rows, stats
  aggregate matches; opt-in `PAM_BENCH_MODEL` test seeds
  `model.models_dir` and `model.default.heavy` **directly in the settings
  table** (the floor is enforced by `admin.models.defaults.set`, not by
  `resolve`; a wiring model may serve a test) and asserts a `log.summary`
  row with non-empty text. Admin ops through the testkit daemon:
  compress a temp file (request row `done`, evidence rows, audit detail
  figures, `admin.evidence.list/get/stats` agree), refusals for a
  relative path, a missing file, and a file over the bound (the bound
  test writes a sparse 64 MiB + 1 file), `evidence.get` truncation, and
  the tripwire (a non-GUI caller is refused before dispatch).
  `remove_stale_with` retry policy over a counting remover.
- Gate: `tools/check.sh` green on the settled tree before every PR; CI
  green on all five targets after every merge.

## Waves

| Wave | Tasks | Disjoint file sets |
| --- | --- | --- |
| 1 | #39 `pam_compact` · #40 store evidence · #43 `remove_stale` | `crates/pam_compact/**` + `Cargo.toml` members · `crates/pam_store/**` · `crates/pam_daemon/src/runtime_dir*.rs` |
| 2 | #41 `LogService` + admin ops | `crates/pam_daemon/**` (minus runtime_dir), `crates/pam_testkit/**` if a helper is needed |
| 3 | #42 GUI | `crates/pam_gui/**`, `frontend/**` |
| 4 | #17 integrate and verify | — |
