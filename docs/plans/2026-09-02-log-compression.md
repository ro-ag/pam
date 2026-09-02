# Log Compression Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give the daemon a deterministic log reducer plus a local-model summarizer that leave reversible evidence rows, exposed to humans through GUI-only admin ops with an evidence viewer and a tokens-avoided odometer — and harden `remove_stale` against the Windows handle race (issue #3).

**Architecture:** New pure library crate `pam_compact` (port of pam-old `pam-log-compact-v1`); `pam_store` gains migration 4 (`evidence.meta_json`) and an evidence API; `pam_daemon` gains `LogService` (compress → evidence rows → heavy-tier summary) and `admin_logs.rs` (`admin.log.compress`, `admin.evidence.*`) through the existing `AdminService` intercept; `pam_gui` splices the new op list into the bridge whitelist and the Activity screen grows an evidence band (odometer + compress box) and a per-row evidence strip/viewer. Spec: `docs/specs/2026-09-02-log-compression-design.md` — every requirement traces to it.

**Tech Stack:** Rust 1.97 (edition 2024), tokio, turso store, sha2/hex, ulid, Tauri 2, React 19 + TanStack Query, `motion`, Tailwind v4 tokens, vitest.

## Global Constraints

- **No CLI, no agent capability**: nothing in `crates/pam/`, `pam_client`, `policy::classify`, or `executor::BuiltinCapability` changes. Every new op is `admin.*` (GUI-only).
- **C-free dependency tree**: no new crates that run `cc`/`cmake`. Verify with `cargo tree -e normal,build | grep -E '^(cc|cmake|onig_sys|esaxx-rs) '` — must print nothing.
- **Sibling tests**: unit tests in `module_test.rs`, declared `#[cfg(test)] mod module_test;` from the parent. Never `#[cfg(test)] mod tests` inline.
- **turso concurrency rule**: every `Store` method takes `conn_lock` first; a transaction holds it across `BEGIN..COMMIT`.
- **Frontend**: Tailwind v4 semantic tokens only (ESLint bans arbitrary values), CVA variants, existing `Panel`/`Badge`/`Button`/`FailureNote`/`Section` furniture; `font-voice` serif for Pam sentences, `font-data` mono for facts and ids, `font-display` for the big number.
- **Refusal legibility**: every failure = `{ cause, detail, recovery }`; recovery names the GUI screen or the concrete fix.
- **Gates**: `tools/check.sh` (fmt, clippy `-D warnings` pedantic, tests, eslint, tsc+vite build, vitest) green on the settled tree before every PR; no `#[allow]` sprinkles — fix the code. Foreground gates only; never background a check.
- **Commits**: conventional prefix, `#<task-id>` in the subject, **no AI attribution trailers of any kind**. PR title carries `#<task-id>`. Branch per task, PR to `main`, squash merge, branch deleted.
- **Bounds copied from the spec**: `MAX_SOURCE_BYTES = 64 * 1024 * 1024`, `MAX_SOURCE_RECORDS = 100_000`, `MAX_FAILURE_CONTEXT_RECORDS = 64`, `DEFAULT_BOUNDARY_RECORDS = 20`, `DEFAULT_FAILURE_CONTEXT_RECORDS = 3`, `PROMPT_BUDGET_BYTES = 24_000` (head 16 000 / tail 8 000), summary `max_tokens = 400`, `temperature = 0.0`, `admin.evidence.get` default `max_bytes = 262_144` clamped to `4 * 1024 * 1024`, stats window 7 days, bridge deadline for `admin.log.compress` 120 000 ms, `remove_stale` 5 attempts × 25 ms.

---

## Wave map (parallelism)

| Wave | Tasks (ptrack ids) | Disjoint file sets |
| --- | --- | --- |
| 1 | #39 `pam_compact` · #40 store evidence · #43 `remove_stale` | `crates/pam_compact/**` + root `Cargo.toml` · `crates/pam_store/**` · `crates/pam_daemon/src/runtime_dir.rs`, `runtime_dir_test.rs` |
| 2 | #41 `LogService` + admin ops | `crates/pam_daemon/**` (not runtime_dir), `crates/pam_gui/src/bridge.rs` whitelist splice only if needed to keep the workspace compiling (it is not: the bridge reads lists it already imports) |
| 3 | #42 GUI | `crates/pam_gui/**`, `frontend/**` |
| 4 | #17 integrate and verify (coordinator) | — |

---

### Task 1 (ptrack #39): `pam_compact` crate

**Files:**
- Modify: `Cargo.toml` (workspace `members` += `"crates/pam_compact"`; `[workspace.dependencies]` += `pam_compact = { path = "crates/pam_compact" }`)
- Create: `crates/pam_compact/Cargo.toml`, `crates/pam_compact/src/lib.rs`, `crates/pam_compact/src/compact.rs`, `crates/pam_compact/src/compact_test.rs`

**Interfaces (Produces):**

```rust
// lib.rs
#![forbid(unsafe_code)]
pub mod compact;
pub use compact::{
    ALGORITHM_VERSION, DEFAULT_BOUNDARY_RECORDS, DEFAULT_FAILURE_CONTEXT_RECORDS,
    MAX_FAILURE_CONTEXT_RECORDS, MAX_SOURCE_BYTES, MAX_SOURCE_RECORDS,
    CompactError, Compacted, FailureKeyword, Fragment, FragmentKind, OmissionReason, Policy,
    RetentionReason, compact, estimate_tokens, sha256_hex,
};

// compact.rs
pub const ALGORITHM_VERSION: &str = "pam-log-compact-v1";
pub const MAX_SOURCE_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_SOURCE_RECORDS: usize = 100_000;
pub const MAX_FAILURE_CONTEXT_RECORDS: usize = 64;
pub const DEFAULT_BOUNDARY_RECORDS: usize = 20;
pub const DEFAULT_FAILURE_CONTEXT_RECORDS: usize = 3;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Policy { pub boundary_records: usize, pub failure_context_records: usize }
impl Default for Policy { fn default() -> Self { Self { boundary_records: 20, failure_context_records: 3 } } }

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureKeyword { Error, Fatal, Panic, Failed }
impl FailureKeyword { pub const ALL: [Self; 4]; pub fn as_str(self) -> &'static str }

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RetentionReason { FirstBoundary, LastBoundary, FailureNeighborhood { keyword: FailureKeyword } }

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OmissionReason { OutsideRetentionWindow, Repeated, SupersededProgress }

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum FragmentKind {
    Retained { reasons: Vec<RetentionReason> },
    Omitted { reason: OmissionReason, record_count: u64 },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Fragment { pub offset: u64, pub length: u64, #[serde(flatten)] pub kind: FragmentKind, pub rendered: String }
// NOTE: `#[serde(flatten)]` on an internally tagged enum serializes as {"offset","length","kind":"retained","reasons":[...],"rendered"}; if serde rejects flatten+tag at compile time, drop `flatten` and keep `kind` as a nested object — either is fine, the GUI never reads fragments.

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Compacted {
    pub algorithm_version: String,
    pub source_sha256: String,
    pub exit_status: Option<i32>,
    pub source_bytes: u64,
    pub retained_bytes: u64,
    pub source_records: u64,
    pub retained_records: u64,
    pub rendered_text: String,
    pub fragments: Vec<Fragment>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CompactError {
    #[error("log source is {actual_bytes} bytes; the maximum is {maximum_bytes}")]
    SourceTooLarge { actual_bytes: u64, maximum_bytes: u64 },
    #[error("log exceeds {maximum_records} source records")]
    TooManyRecords { maximum_records: u64 },
    #[error("invalid compaction policy: {field} is out of bounds")]
    InvalidPolicy { field: &'static str },
}
impl CompactError { #[must_use] pub fn cause(&self) -> &'static str /* source_too_large | too_many_records | invalid_policy */ }

pub fn compact(bytes: &[u8], exit_status: Option<i32>, policy: &Policy) -> Result<Compacted, CompactError>;
#[must_use] pub fn estimate_tokens(bytes: u64) -> u64;   // bytes.div_ceil(4)
#[must_use] pub fn sha256_hex(bytes: &[u8]) -> String;   // lowercase hex
```

- [ ] Create `crates/pam_compact/Cargo.toml`: `[package] name = "pam_compact"`, description "Deterministic, provenance-preserving log reduction.", workspace version/edition/license/repository; deps `serde.workspace`, `serde_json.workspace`, `thiserror.workspace`, `sha2.workspace`, `hex.workspace`; `[lints] workspace = true`. Add the member and workspace dep in the root `Cargo.toml`.
- [ ] Write `compact_test.rs` first (helper `fn run(input: &[u8]) -> Compacted { compact(input, Some(0), &Policy::default()).unwrap() }`; tests are named as sentences):
  - `lf_crlf_and_bare_cr_frame_records`: `b"a\nb\r\nc\rd\re\n"` → 5 records; the two `c\r`, `d\r` are progress frames: `c` omitted `SupersededProgress` (count 1), `d`, `a`, `b`, `e` retained.
  - `ansi_and_control_bytes_render_in_display_form`: `b"\x1b[31mred\x1b[0m\ttab\x01\n"` renders `red\ttab\x01` (`\t` as the two characters backslash-t, `\x01` as `\x01` text) and the fragment length still counts the raw bytes.
  - `adjacent_repeats_collapse_and_reset_after_an_omission`: `"x\nx\nx\ny\n"` → `x` retained, 2 `Repeated` merged into one fragment with `record_count: 2`, `y` retained.
  - `progress_runs_keep_only_the_last_frame`: `"10%\r20%\r30%\rdone\n"` → one `SupersededProgress` fragment `record_count 2`, then `30%` and `done` retained.
  - `boundaries_keep_the_first_and_last_windows`: 100 distinct lines with `Policy { boundary_records: 3, failure_context_records: 0 }` → records 0..3 `FirstBoundary`, 97..100 `LastBoundary`, one `OutsideRetentionWindow` fragment with `record_count 94` rendered `[... 94 records outside retention windows ...]\n`.
  - `failure_lines_keep_their_neighbourhood_case_insensitively`: 30 lines, line 15 = `"Build FAILED: link error"` with `boundary_records: 0, failure_context_records: 2` → records 13..=17 retained, reasons contain `FailureNeighborhood { keyword: Failed }` and `{ keyword: Error }` (deduplicated, no duplicates in the vec), the rest omitted.
  - `failure_windows_clamp_at_both_ends`: 3 lines, `"error"` on line 0, context 5 → all three retained, no panic.
  - `every_byte_belongs_to_exactly_one_ordered_fragment`: for a mixed input (progress, repeats, ANSI, a failure, 60 lines), assert fragments are contiguous: first `offset == 0`, each `offset == previous.offset + previous.length`, last ends at `source_bytes`; `retained_bytes` equals the sum of retained fragment lengths; `retained_records` equals the count of retained fragments.
  - `empty_input_renders_the_no_output_line_and_exit_status`: `b""` → `rendered_text == "[no log output]\n[exit status: 0]\n"`, no fragments, `source_records == 0`.
  - `unknown_exit_status_renders_unknown`: `compact(b"ok\n", None, ..)` ends with `[exit status: unknown]\n`.
  - `same_input_same_output`: two runs equal; `source_sha256 == sha256_hex(input)`.
  - `too_large_and_too_many_records_are_refused_before_work`: `vec![b'\n'; MAX_SOURCE_RECORDS + 1]` → `TooManyRecords { maximum_records: 100_000 }`; a `Vec` of `MAX_SOURCE_BYTES + 1` zero bytes → `SourceTooLarge`, and `cause()` strings are `too_many_records` / `source_too_large`.
  - `policy_bounds_are_validated`: `failure_context_records: 65` → `InvalidPolicy { field: "failure_context_records" }`; `boundary_records: MAX_SOURCE_RECORDS + 1` → `InvalidPolicy { field: "boundary_records" }`.
  - `estimate_tokens_rounds_up`: `estimate_tokens(0) == 0`, `(1) == 1`, `(4) == 1`, `(5) == 2`.
  - `report_serializes_to_json_and_back`: `serde_json` round-trip of a `Compacted` equals itself.
- [ ] Run `cargo test -p pam_compact` — expected: compile failure (nothing implemented).
- [ ] Implement `compact.rs` as a faithful port of pam-old `crates/pam_compact/src/lib.rs` (at `~/dev/rs/pam-old`) minus boilerplate rules and stage boundaries: `parse_records` (CRLF/LF line, bare CR progress, trailing tail), `normalize_display` + `strip_terminal_sequences` (`consume_csi`/`consume_osc`), `progress_omissions`, `apply_repeat_omissions`, `retain_boundaries`, `retain_failure_neighborhoods` (`contains_ascii_case_insensitive`), `build_fragments` (merge consecutive omissions with the same reason), `render_omission`, `render_exit_status`, `[no log output]`. Validation order: size → policy → records. Private `struct Record { start, end, display, frame_kind }`, `enum FrameKind { Line, Progress }`, `enum Disposition { Retained(Vec<RetentionReason>), Omitted(OmissionReason) }`. No `unwrap` outside tests; `usize`→`u64` via `u64::try_from(..).unwrap_or(u64::MAX)` helper is acceptable and documented.
- [ ] Run `cargo test -p pam_compact` — expected: all green. Then `cargo clippy -p pam_compact --all-targets -- -D warnings` clean.
- [ ] Prove C-free: `cargo tree -p pam_compact -e normal,build | grep -E '^(cc|cmake|onig_sys|esaxx-rs) '` prints nothing; paste in the PR body.
- [ ] Gate `tools/check.sh`. Commit `feat(compact): pam_compact crate — deterministic log reduction (#39)`. PR title `feat(compact): pam_compact crate (#39)`.

---

### Task 2 (ptrack #40): store evidence API + migration 4

**Files:**
- Modify: `crates/pam_store/Cargo.toml` (deps += `sha2.workspace = true`, `hex.workspace = true`, `serde_json.workspace = true`, `tracing.workspace = true`)
- Modify: `crates/pam_store/src/migrations.rs` (`SCHEMA_V4`, `MIGRATIONS` += version 4)
- Modify: `crates/pam_store/src/migrations_test.rs` (v3 → v4 upgrade)
- Modify: `crates/pam_store/src/store.rs` (types + four methods)
- Modify: `crates/pam_store/src/store_test.rs`
- Modify: `crates/pam_store/src/lib.rs` (re-exports)

**Interfaces (Produces):**

```rust
// migrations.rs
/// Migration 4: `evidence.meta_json` — small kind-specific metadata so the
/// GUI lists evidence and the odometer aggregates without reading blobs.
const SCHEMA_V4: &str = "ALTER TABLE evidence ADD COLUMN meta_json TEXT;";

// store.rs
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceRow { pub id: String, pub request_id: String, pub kind: String, pub content: Vec<u8>, pub content_hash: String, pub meta_json: Option<String>, pub ts: i64 }
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceMeta { pub id: String, pub request_id: String, pub kind: String, pub bytes: u64, pub content_hash: String, pub meta_json: Option<String>, pub ts: i64 }
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CompressionStats { pub compressions: u64, pub source_bytes: u64, pub compact_bytes: u64, pub tokens_avoided_est: u64 }
/// Evidence kind whose `meta_json` carries the compression figures.
pub const EVIDENCE_KIND_LOG_COMPACT: &str = "log.compact";

impl Store {
    pub async fn insert_evidence(&self, id: &str, request_id: &str, kind: &str, content: &[u8], meta_json: Option<&str>) -> Result<(), StoreError>;
    pub async fn get_evidence(&self, id: &str) -> Result<Option<EvidenceRow>, StoreError>;
    pub async fn list_evidence(&self, request_id: &str) -> Result<Vec<EvidenceMeta>, StoreError>;
    pub async fn compression_stats(&self, since_ts: i64) -> Result<CompressionStats, StoreError>;
}
```

- [ ] Write `migrations_test.rs` addition `v3_database_gains_meta_json`: open a fresh in-memory store (`Store::open_in_memory()`), assert `schema_version() == 4`, then `PRAGMA table_info(evidence)` (via the existing test helper pattern in that file, or a raw `conn.query`) lists a `meta_json` column. If the file already has a "fresh db reaches latest" test, extend its expected version to 4 and add only the column assertion.
- [ ] Write `store_test.rs` additions:
  - `evidence_round_trips_bytes_hash_and_meta`: insert a request row (existing helper), `insert_evidence("ev_1", req, "log.source", b"\x00\xff\nraw", Some(r#"{"name":"build.log"}"#))`, `get_evidence("ev_1")` → same bytes, `content_hash == hex(sha256(bytes))` (compute with `sha2` in the test), `meta_json` preserved, `kind` preserved; `get_evidence("ev_missing") == None`.
  - `list_evidence_returns_metadata_without_blobs_in_insertion_order`: three rows on one request, one on another; `list_evidence(req)` → three `EvidenceMeta` ordered by `(ts, id)` with `bytes == content.len()`; no `content` field exists on the type (compile-time).
  - `compression_stats_sums_only_compact_rows_in_the_window`: insert `log.compact` rows with `meta_json` `{"source_bytes":1000,"compact_bytes":100,"tokens_avoided_est":225}` ×2, one `log.source` row with the same meta (must be ignored), one `log.compact` row with `meta_json = Some("not json")` (counts as a compression, adds nothing). `compression_stats(0)` → `compressions 3, source_bytes 2000, compact_bytes 200, tokens_avoided_est 450`; `compression_stats(now + 10)` → all zeros. (Insert rows via `insert_evidence`, then `UPDATE evidence SET ts = ?` through a test-only raw statement if needed to place one row before the window — or simply assert the future-window case.)
  - `evidence_insert_refuses_an_unknown_request`: the FK `REFERENCES request(id)` — assert the insert on a request id that does not exist errors (turso enforces FKs only with `PRAGMA foreign_keys = ON`; if the store does not enable it, drop this test and note it in the PR body rather than enabling the pragma — out of scope).
- [ ] Run `cargo test -p pam_store` — expected: failures on the missing methods.
- [ ] Implement: `insert_evidence` — `let _guard = self.conn_lock.lock().await;` then `INSERT INTO evidence (id, request_id, kind, content, path, content_hash, meta_json, ts) VALUES (?1, ?2, ?3, ?4, NULL, ?5, ?6, ?7)` with `content.to_vec()` bound as a blob (turso `Value::Blob`), hash = `hex::encode(sha2::Sha256::digest(content))`, `ts = now_ts()`. `get_evidence` — `SELECT id, request_id, kind, content, content_hash, meta_json, ts FROM evidence WHERE id = ?1`; blob column read as `Vec<u8>` (`row.get_value(3)` → `Value::Blob`; a NULL content is an empty vec). `list_evidence` — `SELECT id, request_id, kind, LENGTH(content), content_hash, meta_json, ts FROM evidence WHERE request_id = ?1 ORDER BY ts ASC, id ASC`; `LENGTH` on NULL yields NULL → 0. `compression_stats` — `SELECT meta_json FROM evidence WHERE kind = ?1 AND ts >= ?2`, then in Rust: for each row `compressions += 1`; parse `meta_json` with `serde_json::from_str::<serde_json::Value>`; add `source_bytes`, `compact_bytes`, `tokens_avoided_est` when they are `u64`; on parse failure `tracing::warn!(evidence_kind, "unreadable compression meta")` and continue.
- [ ] Re-export from `lib.rs`: `pub use store::{CompressionStats, EVIDENCE_KIND_LOG_COMPACT, EvidenceMeta, EvidenceRow};` (match the file's existing re-export style).
- [ ] Run `cargo test -p pam_store` green; `cargo clippy -p pam_store --all-targets -- -D warnings` clean.
- [ ] Gate `tools/check.sh`. Commit `feat(store): evidence rows with meta_json and compression stats (#40)`. PR title `feat(store): evidence API + migration 4 (#40)`.

---

### Task 3 (ptrack #43): `remove_stale` hardening (issue #3)

**Files:**
- Modify: `crates/pam_daemon/src/runtime_dir.rs` (`remove_stale`, new `remove_stale_with`)
- Modify: `crates/pam_daemon/src/runtime_dir_test.rs`

**Interfaces (Produces):**

```rust
/// Attempts before a persistent `PermissionDenied` is reported.
pub const STALE_REMOVE_ATTEMPTS: u32 = 5;
/// Pause between attempts.
pub const STALE_REMOVE_BACKOFF: Duration = Duration::from_millis(25);

/// Removes a stale socket file left by a previous daemon. A missing file
/// is fine. `PermissionDenied` is retried briefly (Windows: Defender or
/// the indexer holding a handle on the file between our `remove` calls —
/// issue #3) and is also fine when the file is gone after the error.
pub fn remove_stale(path: &Path) -> io::Result<()> {
    remove_stale_with(path, std::fs::remove_file, STALE_REMOVE_ATTEMPTS, STALE_REMOVE_BACKOFF)
}

/// The retry policy over an injected remover, so tests drive it without a
/// platform race.
pub fn remove_stale_with(
    path: &Path,
    mut remove: impl FnMut(&Path) -> io::Result<()>,
    attempts: u32,
    backoff: Duration,
) -> io::Result<()>;
```

- [ ] Write tests in `runtime_dir_test.rs` (keep the existing `remove_stale_deletes_file_and_tolerates_absence`):
  - `not_found_is_success_on_the_first_call`: remover returns `NotFound`; result `Ok`; call count 1.
  - `permission_denied_retries_then_succeeds`: on a temp file that exists, remover fails `PermissionDenied` twice then deletes the file and returns `Ok`; result `Ok`; count 3.
  - `permission_denied_on_a_file_that_vanished_is_success`: remover returns `PermissionDenied` but has already deleted the file (do `std::fs::remove_file` inside the closure before returning the error); result `Ok`; count 1.
  - `persistent_permission_denied_reports_after_the_attempts`: file exists, remover always `PermissionDenied`; `remove_stale_with(.., 5, Duration::ZERO)` → `Err` with kind `PermissionDenied`; count 5.
  - `other_errors_are_not_retried`: remover returns `io::ErrorKind::Other` once; `Err(Other)`; count 1.
- [ ] Run `cargo test -p pam_daemon runtime_dir` — expected: compile failure on `remove_stale_with`.
- [ ] Implement `remove_stale_with`: loop `attempt in 1..=attempts`: `match remove(path) { Ok(()) => return Ok(()), Err(e) if e.kind() == NotFound => return Ok(()), Err(e) if e.kind() == PermissionDenied => { if !path.exists() { return Ok(()); } if attempt == attempts { return Err(e); } std::thread::sleep(backoff); } Err(e) => return Err(e) }`. `attempts == 0` behaves as 1 (`attempts.max(1)`). Update the doc comment; keep the `TransportError::RemoveStale` message unchanged.
- [ ] Run `cargo test -p pam_daemon runtime_dir` green; `cargo clippy -p pam_daemon --all-targets -- -D warnings`.
- [ ] Gate `tools/check.sh`. Commit `fix(daemon): retry stale socket removal on PermissionDenied (#43)`. PR title `fix(daemon): remove_stale tolerates the Windows handle race (#43)`. Mention issue #3 and the run id `33605369180` in the PR body.

---

### Task 4 (ptrack #41): `LogService` + admin ops

**Files:**
- Modify: `crates/pam_daemon/Cargo.toml` (deps += `pam_compact.workspace = true`)
- Create: `crates/pam_daemon/src/log_service.rs`, `log_service_test.rs`, `admin_logs.rs`, `admin_logs_test.rs`
- Modify: `crates/pam_daemon/src/lib.rs` (`pub mod admin_logs; pub mod log_service;` + test mods)
- Modify: `crates/pam_daemon/src/admin.rs` (`AdminService` gains `logs: Arc<LogService>`; `new` takes it; `dispatch` asks `dispatch_logs` after `dispatch_models`)
- Modify: `crates/pam_daemon/src/daemon.rs` (build `LogService::new(store, models)` and pass it to `AdminService::new`; expose `DaemonHandle::logs()` only if a test needs it — otherwise not)
- Modify: `crates/pam_daemon/src/admin_test.rs` and `admin_models_test.rs` helper constructors (one extra argument)

**Interfaces (Consumes):** Task 1 `pam_compact::{compact, estimate_tokens, Policy, Compacted, CompactError, MAX_SOURCE_BYTES}`; Task 2 `Store::{insert_evidence, get_evidence, list_evidence, compression_stats}`, `EVIDENCE_KIND_LOG_COMPACT`; existing `ModelService::generate(Tier::Heavy, GenerateRequest)`, `ModelUnavailable`, `pam_model::RuntimeError::cause()`.

**Interfaces (Produces):**

```rust
// log_service.rs
pub const EVIDENCE_KIND_LOG_SOURCE: &str = "log.source";
pub const EVIDENCE_KIND_LOG_SUMMARY: &str = "log.summary";
pub const PROMPT_BUDGET_BYTES: usize = 24_000;
pub const PROMPT_HEAD_BYTES: usize = 16_000;
pub const PROMPT_TAIL_BYTES: usize = 8_000;
pub const SUMMARY_MAX_TOKENS: usize = 400;
pub const SUMMARY_TEMPERATURE: f64 = 0.0;
pub const SUMMARY_SYSTEM: &str = "You are PAM's log summarizer. You receive a build or test log that was already reduced deterministically; bracketed markers say how many records were omitted and why. Answer in plain text, at most eight lines: the outcome first (pass, fail, or unknown), then the failing step and the exact error lines that explain it, quoted verbatim, then what a developer must fix. Never invent lines that are not in the log.";

pub struct LogService { store: Arc<Store>, models: Arc<ModelService> }
#[derive(Debug, Clone)]
pub struct CompressInput { pub name: String, pub bytes: Vec<u8>, pub exit_status: Option<i32>, pub use_model: bool }
#[derive(Debug, Clone, PartialEq, Eq, Serialize)] pub struct EvidenceRef { pub id: String, pub bytes: u64 }
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompressStats { pub source_bytes: u64, pub compact_bytes: u64, pub source_records: u64, pub retained_records: u64, pub tokens_source_est: u64, pub tokens_compact_est: u64, pub tokens_avoided_est: u64 }
#[derive(Debug, Clone, PartialEq, Serialize)] pub struct ModelUse { pub id: String, pub tier: &'static str, pub prompt_tokens: usize, pub completion_tokens: usize, pub tokens_per_sec: f64 }
#[derive(Debug, Clone, PartialEq, Eq, Serialize)] pub struct ModelSkipped { pub cause: String, pub detail: String }
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct CompressReport { pub source: EvidenceRef, pub compact: EvidenceRef, pub summary: Option<EvidenceRef>, pub compact_text: String, pub summary_text: Option<String>, pub stats: CompressStats, pub model: Option<ModelUse>, pub model_skipped: Option<ModelSkipped> }
#[derive(Debug, thiserror::Error)]
pub enum LogError {
    #[error("log source is {actual_bytes} bytes; the maximum is {maximum_bytes}")] SourceTooLarge { actual_bytes: u64, maximum_bytes: u64 },
    #[error(transparent)] Compact(#[from] CompactError),
    #[error(transparent)] Store(#[from] StoreError),
    #[error("the compaction task did not finish: {0}")] Join(String),
}
impl LogError { pub fn cause(&self) -> &'static str /* source_too_large | <CompactError::cause> | store_error | internal_error */ }
impl LogService {
    pub fn new(store: Arc<Store>, models: Arc<ModelService>) -> Arc<Self>;
    pub async fn compress(&self, request_id: &str, input: CompressInput) -> Result<CompressReport, LogError>;
}
/// Fits `text` to the prompt budget: unchanged when it fits, else head + marker + tail cut at line boundaries.
pub fn fit_prompt(text: &str) -> String;
pub fn new_evidence_id() -> String; // "ev_" + ulid lowercase, same style as request ids

// admin_logs.rs
pub const OP_LOG_COMPRESS: &str = "admin.log.compress";
pub const OP_EVIDENCE_LIST: &str = "admin.evidence.list";
pub const OP_EVIDENCE_GET: &str = "admin.evidence.get";
pub const OP_EVIDENCE_STATS: &str = "admin.evidence.stats";
pub const LOG_ADMIN_OPS: &[&str] = &[OP_LOG_COMPRESS, OP_EVIDENCE_LIST, OP_EVIDENCE_GET, OP_EVIDENCE_STATS];
pub const CAUSE_SOURCE_UNREADABLE: &str = "source_unreadable";
pub const CAUSE_SOURCE_TOO_LARGE: &str = "source_too_large";
pub const CAUSE_EVIDENCE_NOT_FOUND: &str = "not_found";
pub const EVIDENCE_GET_DEFAULT_MAX_BYTES: u64 = 262_144;
pub const EVIDENCE_GET_MAX_BYTES: u64 = 4 * 1024 * 1024;
pub const STATS_WINDOW_SECS: i64 = 7 * 24 * 60 * 60;
impl AdminService { pub(crate) async fn dispatch_logs(&self, op: &str, args: &Value) -> Option<Result<AdminOk, AdminRefusal>>; }
```

- [ ] Write `log_service_test.rs` (helpers: in-memory store, `ModelService::new(store)`, a request row inserted with the existing `insert_request` so the FK target exists):
  - `compress_without_a_model_stores_source_and_compact_and_skips_the_summary`: input 400 lines with one `error:` line, `use_model: true`, no defaults → report has `summary == None`, `model == None`, `model_skipped == Some { cause: "no_default", .. }`; `list_evidence(req)` has exactly two rows, kinds `log.source` then `log.compact`; `get_evidence(source.id).content == input bytes`; the compact row's content parses as `pam_compact::Compacted` with `rendered_text == report.compact_text`; its `meta_json` parses and carries `source_bytes`, `compact_bytes`, `tokens_avoided_est == tokens_source_est - tokens_compact_est`, `source_evidence == source.id`, `name`; `compression_stats(0).compressions == 1`.
  - `use_model_false_never_touches_the_model_layer`: `model_skipped == None`, `summary == None`, two rows.
  - `oversized_input_is_refused_before_any_row_exists`: `vec![0u8; MAX_SOURCE_BYTES + 1]` → `Err(LogError::SourceTooLarge {..})`, `list_evidence(req)` empty.
  - `fit_prompt_keeps_short_text_and_trims_long_text_at_line_boundaries`: 1 000-byte text unchanged; 60 000 bytes of `line N\n` → result length ≤ `PROMPT_BUDGET_BYTES + 80`, starts with `line 0\n`, ends with the last line, contains `[... ` and ` bytes elided for the model prompt ...]`, and the marker sits between two `\n`.
  - `new_evidence_id_has_the_ev_prefix_and_ulid_length`: `id.starts_with("ev_") && id.len() == 3 + 26`.
  - `bench_model_writes_a_summary_row` — opt-in via `PAM_BENCH_MODEL` exactly like `crates/pam_model/tests/bench.rs` (read the env var; unset → `eprintln!` how to run and return). Seed `model.models_dir` to the models dir derived from the path and `model.default.heavy` to the model id **directly with `store.set_setting`** (the floor lives in `admin.models.defaults.set`, not in `resolve`), compress a 200-line log with `Build FAILED: undefined reference to foo`, assert `summary.is_some()`, `summary_text` non-empty, a `log.summary` row whose `meta_json` names `model_id` and `tier == "heavy"`, `model.completion_tokens > 0`.
- [ ] Write `admin_logs_test.rs` (mirror `admin_test.rs`'s `service()` helper and envelope construction with `ADMIN_CALLER_AGENT`; use `tempfile` for source files):
  - `compress_reads_the_file_and_answers_the_report`: write 50 lines + `error: boom`; op `{ "path": abs, "exit_status": 1 }` → `Response::Result { outcome: Solved, body }` where `body.stats.source_bytes == file len`, `body.model_skipped.cause == "no_default"`, `body.source.id` starts `ev_`; request row `done`; audit detail (from `audit_for_request`) parses to JSON with `op`, `name` (file name), `source_bytes`, `compact_bytes`, `tokens_avoided_est`, `summarized == false`, `model_skipped == "no_default"`.
  - `compress_refuses_a_relative_path_and_a_missing_file`: `{ "path": "build.log" }` → refusal `invalid_admin_args`; `{ "path": "/definitely/missing/build.log" }` → `source_unreadable` whose detail contains the path; both rows `refused` with one audit row.
  - `compress_refuses_an_oversized_file_from_its_metadata`: create a file, `set_len(MAX_SOURCE_BYTES as u64 + 1)` (sparse), → `source_too_large`; assert no evidence rows exist for that request.
  - `evidence_list_and_get_round_trip_through_the_ops`: after a successful compress, `admin.evidence.list { request_id }` → two entries with `bytes`, `sha256`, `kind`, `meta` (object, not string); `admin.evidence.get { id: compact }` → `text == report.compact_text`, `truncated == false`, `kind == "log.compact"`; `get { id: source, max_bytes: 10 }` → `text.len() <= 10` (lossy cut on a char boundary), `truncated == true`, `bytes == full len`; `get { id: "ev_nope" }` → `not_found`.
  - `evidence_stats_reports_the_window`: after two compresses, `admin.evidence.stats {}` → `compressions == 2`, `tokens_avoided_est` equals the sum of the two reports, `since_ts` ≈ now − 7 days; `{ "since_ts": now + 60 }` → zeros.
  - `log_ops_are_gui_only`: an envelope with caller agent `"claude"` → `admin_denied` before any file is read (use a missing path; the refusal must be the tripwire cause, not `source_unreadable`).
- [ ] Run `cargo test -p pam_daemon log_service admin_logs` — expected: compile failures.
- [ ] Implement `log_service.rs`: `compress` = bound check → `tokio::task::spawn_blocking(move || pam_compact::compact(&bytes, exit_status, &Policy::default()))` (map join error to `LogError::Join`) → `insert_evidence(source_id, request_id, "log.source", &bytes, Some(json!({"name", "exit_status"})))` → `serde_json::to_vec(&compacted)` as `log.compact` content with meta = `CompressStats` fields + `name`, `algorithm_version`, `exit_status`, `source_evidence` → if `use_model`: `self.models.generate(Tier::Heavy, GenerateRequest { system: Some(SUMMARY_SYSTEM.to_owned()), prompt: fit_prompt(&compacted.rendered_text), max_tokens: SUMMARY_MAX_TOKENS, temperature: SUMMARY_TEMPERATURE, stop: Vec::new() })`; on `Ok(result)` resolve the model id via `self.models.resolve(Tier::Heavy).await.map(|e| e.id)` **before** generating (one resolve, reuse it) and insert `log.summary` with meta `{model_id, tier: "heavy", prompt_tokens, completion_tokens, tokens_per_sec, source_evidence, compact_evidence}`; on `Err(ModelUnavailable::NoDefault(_))` → cause `no_default`, `Missing(id)` → `model_missing`, `Runtime(err)` → `err.cause()`, store errors from the summary insert → treat as skipped with cause `store_error` and a `tracing::warn!` (the compact result stands). `tracing::info!` one line per compress with the figures. `fit_prompt`: if `text.len() <= PROMPT_BUDGET_BYTES` return owned; else `head = &text[..floor_char_boundary(PROMPT_HEAD_BYTES)]` trimmed back to the last `\n`, `tail` = from `text.len() - PROMPT_TAIL_BYTES` forward to the next `\n`+1; elided = `text.len() - head.len() - tail.len()`; `format!("{head}[... {elided} bytes elided for the model prompt ...]\n{tail}")`.
- [ ] Implement `admin_logs.rs`: `dispatch_logs` matches the four ops. `log_compress`: `required_str(args, "path", OP_LOG_COMPRESS)`, refuse non-absolute with `CAUSE_INVALID_ADMIN_ARGS` + `RECOVERY_FIX_ARGS`; `exit_status` optional `i64` → `i32` (out of range → invalid args); `model` optional bool default true; `tokio::fs::metadata(path)` → `source_unreadable` (detail `"cannot read {path}: {err}"`, recovery `"Check the path and that the daemon's user can read it."`), `len > MAX_SOURCE_BYTES` → `source_too_large` (recovery `"Split the log or trim it below 64 MiB before compressing."`); `tokio::fs::read` → `source_unreadable`; `name` = file name lossy; `self.logs.compress(request_id, CompressInput {..})` — the request id is the envelope id (thread it through `dispatch_logs(&self, envelope_id: &str, op, args)` or pass the envelope; pick one and keep `dispatch_models` untouched) — `LogError` → refusal with `err.cause()` and `RECOVERY_INTERNAL`; `AdminOk { outcome: Solved, body: to_value(report), audit: json!({"op", "name", "source_bytes", "compact_bytes", "tokens_avoided_est", "summarized": report.summary.is_some(), "model_skipped": report.model_skipped.as_ref().map(|s| &s.cause)}) }`. `evidence_list`: `required_str("request_id")` → `list_evidence` → `{ "evidence": [ { id, request_id, kind, bytes, sha256: content_hash, meta: parsed-or-null, ts } ] }`, audit `{op, request_id, count}`. `evidence_get`: `required_str("id")`, `max_bytes` clamp `1..=EVIDENCE_GET_MAX_BYTES` default `EVIDENCE_GET_DEFAULT_MAX_BYTES`; `get_evidence` None → `not_found` (recovery `"Pick an evidence handle from the request's row in Activity."`); text source = for `log.compact` the `rendered_text` of the parsed `Compacted` (parse failure → fall back to the raw bytes), else the raw bytes; `text = String::from_utf8_lossy(&bytes[..cut])` with `cut` floored to a char boundary of the lossy string (simplest: take `max_bytes` raw bytes, lossy-convert, done — the cut may replace one partial char with U+FFFD, acceptable); `truncated = source_len > max_bytes`; body `{ id, request_id, kind, bytes, sha256, meta, ts, text, truncated }`; audit `{op, id, kind, truncated}`. `evidence_stats`: `since_ts` optional `i64` default `now - STATS_WINDOW_SECS` → `{ since_ts, compressions, source_bytes, compact_bytes, tokens_avoided_est }`, audit `{op, since_ts}`. All ops `Outcome::Verified` except compress (`Solved`).
- [ ] Wire `AdminService`: field `pub(crate) logs: Arc<LogService>`, `new(store, approvals, models, logs)`; `dispatch`: after `dispatch_models`, `if let Some(answer) = self.dispatch_logs(...)`. Update `daemon.rs` construction and both test helpers. Add `pub mod log_service; pub mod admin_logs;` and the `#[cfg(test)] mod` lines in `lib.rs`.
- [ ] Run `cargo test -p pam_daemon` green (the bench test prints its skip line); `cargo clippy -p pam_daemon --all-targets -- -D warnings` clean.
- [ ] Optional but worth the minute: run the opt-in test once against the wiring model if `~/llm/qwen/Qwen3-0.6B-Q8_0.gguf` exists: `PAM_BENCH_MODEL=~/llm/qwen/Qwen3-0.6B-Q8_0.gguf cargo test -p pam_daemon bench_model_writes_a_summary_row -- --nocapture`; paste the summary text in the PR body.
- [ ] Gate `tools/check.sh` (the workspace must still build: `pam_gui`'s bridge test asserts `ADMIN_OPS.len() == 9 + MODEL_ADMIN_OPS.len()` and stays true until Task 5 splices the log list — do not touch `pam_gui` here). Commit `feat(daemon): log compression service and admin.log/evidence ops (#41)`. PR title `feat(daemon): LogService + admin.log.compress / admin.evidence.* (#41)`.

---

### Task 5 (ptrack #42): GUI — bridge, ipc, Activity evidence band, viewer, retention copy

**Files:**
- Modify: `crates/pam_gui/src/bridge.rs` (`LOG_ADMIN_OPS` spliced into `ADMIN_OPS`; `deadline_for(OP_LOG_COMPRESS) == 120_000`)
- Modify: `crates/pam_gui/src/bridge_test.rs` (count `9 + MODEL + LOG`; every log op forwarded; only `admin.models.try` and `admin.log.compress` get 120 s)
- Modify: `frontend/src/lib/ipc.ts` (`AdminOp` += four ops; types + wrappers), `frontend/src/lib/ipc.test.ts`
- Create: `frontend/src/screens/EvidenceBand.tsx` (odometer tile + compress box), `frontend/src/screens/EvidenceBand.test.tsx`, `frontend/src/screens/EvidenceStrip.tsx` (chips + viewer for one request), `frontend/src/screens/EvidenceStrip.test.tsx`
- Modify: `frontend/src/screens/Activity.tsx` (mount the band under the header; mount the strip inside the expanded `TideRow`), `frontend/src/screens/Activity.test.tsx` (mocks gain `evidenceStats`, `evidenceList`, `evidenceGet`, `logCompress`)
- Modify: `frontend/src/screens/Settings.tsx` (`RetentionPanel` copy), `frontend/src/screens/Settings.test.tsx` if it asserts the old sentence
- Modify: `frontend/src/lib/bytes.ts` only if a needed formatter is missing (it already formats byte sizes — reuse it)

**Interfaces (Consumes):** Task 4 op names and reply shapes (`CompressReport`, `evidence.list/get/stats` bodies).

**Interfaces (Produces, ipc.ts):**

```ts
export type AdminOp = ... | "admin.log.compress" | "admin.evidence.list" | "admin.evidence.get" | "admin.evidence.stats";
export interface EvidenceRef { id: string; bytes: number }
export interface CompressStats { source_bytes: number; compact_bytes: number; source_records: number; retained_records: number; tokens_source_est: number; tokens_compact_est: number; tokens_avoided_est: number }
export interface ModelUse { id: string; tier: string; prompt_tokens: number; completion_tokens: number; tokens_per_sec: number }
export interface CompressReport { source: EvidenceRef; compact: EvidenceRef; summary: EvidenceRef | null; compact_text: string; summary_text: string | null; stats: CompressStats; model: ModelUse | null; model_skipped: { cause: string; detail: string } | null }
export interface EvidenceMeta { id: string; request_id: string; kind: string; bytes: number; sha256: string; meta: Record<string, unknown> | null; ts: number }
export interface EvidenceContent extends EvidenceMeta { text: string; truncated: boolean }
export interface EvidenceStats { since_ts: number; compressions: number; source_bytes: number; compact_bytes: number; tokens_avoided_est: number }
export function logCompress(args: { path: string; exit_status?: number; model?: boolean }): Promise<CompressReport>;
export function evidenceList(requestId: string): Promise<{ evidence: EvidenceMeta[] }>;
export function evidenceGet(id: string, maxBytes?: number): Promise<EvidenceContent>;
export function evidenceStats(sinceTs?: number): Promise<EvidenceStats>;
```

- [ ] Bridge: import `pam_daemon::admin_logs::{LOG_ADMIN_OPS, OP_LOG_COMPRESS}`; `ADMIN_OPS_LEN = CORE + MODEL + LOG`; extend `compose_admin_ops` with a third splice loop; `deadline_for`: `OP_MODELS_TRY | OP_LOG_COMPRESS => TRY_DEADLINE_MS` (rename the const to `LONG_DEADLINE_MS` if that reads better — keep the doc honest: "a generation or a 64 MiB compaction plus a generation"). Tests: `every_daemon_admin_op_is_whitelisted` count becomes `9 + MODEL_ADMIN_OPS.len() + LOG_ADMIN_OPS.len()`; add `every_log_admin_op_is_whitelisted`; extend the deadline test to both long ops. `cargo test -p pam_gui`.
- [ ] `ipc.ts` wrappers + `ipc.test.ts` cases asserting each wrapper calls `invoke("admin_call", { op, args })` with the exact op and args (`evidenceGet("ev_1", 10)` → `{ id: "ev_1", max_bytes: 10 }`; `evidenceStats()` → `{}`; `logCompress({ path, model: false })` → `{ path, model: false }`), matching the file's existing test style.
- [ ] `EvidenceBand.tsx`: `useQuery({ queryKey: ["evidence-stats"], queryFn: () => evidenceStats() })`. Tile: eyebrow `tokens avoided · 7 days` (`font-data text-xs uppercase tracking-widest text-ink-faint`), the number in `font-display text-display tabular-nums text-ink` (use the largest display size token that exists in `styles/tokens.css`), sub-line `font-data text-xs text-ink-muted`: `{compressions} compressions · {formatBytes(source_bytes)} → {formatBytes(compact_bytes)}` (reuse the formatter in `lib/bytes.ts`). Rolling digits: `useMotionValue(previous)` + `animate(value, next, { duration: 0.8, ease: "easeOut" })` on change, rendered through `useTransform(v => Math.round(v).toLocaleString())`; under `useReducedMotion()` set the value directly. While loading show `—`; on failure show the `FailureNote` inline (label "evidence stats"). Compress box (right of the tile on `md`, stacked below on narrow): `<input aria-label="log path">` (`font-data`, placeholder `/absolute/path/to/build.log`), `<input aria-label="exit status" type="number">` (optional), `<label><input type="checkbox" aria-label="use model" defaultChecked/> summarize with the heavy model</label>`, `<Button>Compress</Button>` disabled while pending or when the path is not absolute (starts with `/` or matches `/^[A-Za-z]:[\\/]/`). On success: `queryClient.invalidateQueries(["activity"])`, `(["evidence-stats"])`, and call `onCompressed(requestId)` — the report does not carry the request id, so the band calls `activityList({ limit: 1, repo: "pam-gui" })`? No: `admin.activity.list` rows for admin ops carry `repo == "pam-gui"` (`ADMIN_REPO`); the simplest reliable path is: after success, invalidate, then the parent expands the newest row whose `capability === "admin.log.compress"` once the refetch lands. Implement `onCompressed()` with no args and let `ActivityScreen` expand the first such row on the next data change (a `useEffect` keyed on a `pendingExpand` flag). A refusal renders `FailureNote` (label "compress").
- [ ] `EvidenceBand.test.tsx`: renders the stats (`21,450` from `tokens_avoided_est: 21450`, "3 compressions"); button disabled for a relative path; enabled and calls `logCompress` with `{ path: "/tmp/build.log", exit_status: 1, model: true }` after typing; on rejection with `{cause:"source_unreadable",...}` shows the detail; stats failure shows the `FailureNote`. Mock `motion/react`'s `useReducedMotion` to `true` in tests so numbers render synchronously.
- [ ] `EvidenceStrip.tsx` (`{ requestId }`): `useQuery(["evidence", requestId], () => evidenceList(requestId))`; nothing rendered while loading or when `evidence.length === 0` (tests assert absence); chips: `<button>` per row, `font-data text-xs`, content `{kind} · {formatBytes(bytes)}`, `title={id}`, `aria-pressed` when selected; on select `useQuery(["evidence", id], () => evidenceGet(id))` and render the viewer: for `kind === "log.compact"` a stats line from `meta` (`{source_records} → {retained_records} records · {formatBytes(source_bytes)} → {formatBytes(compact_bytes)} · ~{tokens_avoided_est.toLocaleString()} tokens avoided`) above a `<pre className="… font-data text-xs …">`; for `log.summary` a `<p className="font-voice text-base text-ink italic whitespace-pre-line">`; for anything else the `<pre>`; when `truncated`, a `font-data text-xs text-ink-faint` line `showing the first {formatBytes(text.length)} of {formatBytes(bytes)}`. Failures → `FailureNote`.
- [ ] `EvidenceStrip.test.tsx`: empty list renders nothing; two chips render with sizes; clicking the compact chip calls `evidenceGet("ev_c", undefined)` and shows the stats line + pre text; clicking the summary chip shows the serif paragraph; truncated content shows the "showing the first" line.
- [ ] `Activity.tsx`: render `<EvidenceBand onCompressed=… />` between the header and the failure/tide section (inside the same padded column); inside `TideRow`'s expanded block add `<EvidenceStrip requestId={row.id} />` after the args `<pre>`. Update `Activity.test.tsx` mocks (`evidenceStats` resolves zeros, `evidenceList` resolves `{ evidence: [] }`) so existing tests keep passing; add one test: expanding a row calls `evidenceList(row.id)`.
- [ ] `Settings.tsx` `RetentionPanel`: replace the italic sentence with "Evidence rows exist now — log sources, compacts, summaries — but nothing prunes them yet. These knobs wake up with the retention plan." Keep the badge text `arrives with retention`. Fix any Settings test asserting the old sentence.
- [ ] `npm --prefix frontend run lint && npm --prefix frontend run build && npm --prefix frontend run test` green. Then `tools/check.sh`.
- [ ] Eyeball in the Browser pane: run the Vite dev server (`.claude/launch.json` entry or `npm --prefix frontend run dev`) — without a bridge the screen shows the `bridge_unavailable` failure notes, so for a populated view temporarily stub the four wrappers in a scratch copy of `ipc.ts`? No — do not edit source for screenshots. Instead build the production GUI (`npm run --prefix frontend tauri -- build --no-bundle` is not wired here; use `cargo build --release -p pam --features gui-embed` after `npm --prefix frontend run build`) and drive `pam gui` against the real daemon with a real log file, in both themes × both modes (Settings › Appearance), capturing: the band with a non-zero odometer, an expanded compress row with the strip, the compact viewer, the summary viewer (when a heavy default exists) or the `model_skipped` state. Attach the screenshots to the PR.
- [ ] Commit `feat(gui): evidence band, odometer, compress box, evidence viewer (#42)`. PR title `feat(gui): log compression observatory in Activity (#42)`.

---

### Task 6 (ptrack #17): integrate and verify (coordinator)

- [ ] On the settled `main`: `tools/check.sh` green; `gh run list --branch main --limit 1` green on all five targets.
- [ ] Production binary: `npm --prefix frontend run build && cargo build --release -p pam --features gui-embed`; `strings target/release/pam | grep -c 'tokens avoided'` ≥ 1 (embedded dist carries the band); launch `pam gui` without Vite running — window renders.
- [ ] Drive the real thing: compress a real build log (e.g. `cargo build 2>&1 | tee /tmp/build.log` with an induced error) through the GUI; the tide shows the `admin.log.compress` row, the strip lists `log.source` and `log.compact`, the odometer moves; with the owner's heavy default configured (or `PAM_BENCH_MODEL` seeded through the settings for a wiring run) a `log.summary` appears in the serif voice.
- [ ] `ptrack task done` each task with a summary that answers "what calls this now?" (the GUI admin op; flows and connectors later through `LogService::compress`), close issue #3 with the fix reference, `ptrack plan done 4`, act on the checkpoint block, `ptrack summary set`.
