# `pam_store` on SQLite (rusqlite, bundled) — design and implementation plan

Status: implemented (T0–T5, T7); T6 pending a Windows run. Built on
`feat/sqlite-store`, 2026-10-02. Nothing here has been compiled or run on
Windows yet, and T8's one real upgrade of an owner database is still to do.
What was built, where it departs from the design below, is in
[As built](#as-built-2026-10-02); corrections from the T1 port are under
[Findings from T1](#findings-from-t1-2026-10-02). Implements the owner decision of
2026-10-02 on ptrack issue 38 (design review, owner decision 1): the store that
holds grants, approvals, the request ledger and the audit trail runs on real
SQLite, and SQLite becomes a named exception to the no-C rule.
Review record: [design review, 2026-10-02](../reviews/design-review-2026-10-02.md),
store findings 7 and 11.

Line references were read on `feat/framed-public-transport` at `7a6bf46`.
While this was being written, plan 49 began editing `crates/pam_store`
(`store.rs`, `migrations.rs`, `lib.rs` and two test files, uncommitted): it adds
migration 13, four attribution columns on `request`. Re-anchor line numbers
before implementing, and read "12" below as "the last turso-era schema" where
plan 49 has landed. The decision itself is not reopened here. This document
settles how.

Release targets are exactly three: macOS arm64, Windows amd64, Windows arm64.
Linux is not a target and nothing here is designed or tested for it.

## What was verified and what was not

Verified while writing this, on this host, without building anything:

- The SQL in `crates/pam_store/src` prepares under real SQLite with
  double-quoted string literals disabled: 107 statements extracted mechanically,
  and the 25 built from templates through a hand-expanded representative of
  each template (not every table of the prune loop individually). All twelve migrations apply to an empty
  file. Triggers, foreign keys, CHECK constraints, upserts and blob functions
  behave as the code expects. Tool: the system `sqlite3` CLI, SQLite 3.54.0
  (Apple build). The bundled engine will be 3.53.2, so T1 repeats this with the
  real binary.
- A copy of the owner's `~/.pam/state.sqlite3` (+ `-wal`, `-shm`), written by
  turso 0.7.2, opens in real SQLite, passes `integrity_check`, and accepts
  migration 12. Details in [Existing database files](#existing-database-files).
  The copies were deleted afterwards; the originals were never opened.
- rusqlite 0.40.1 and libsqlite3-sys 0.38.1 sources (this machine's cargo
  registry cache): feature lists, the bundled build's compile flags, the
  bundled SQLite version, and that `Connection` is `Send` and not `Sync`.
- tokio 1.53.1 source: paused-clock auto-advance is inhibited for
  `spawn_blocking` and for nothing else.

Not verified, and assigned to a task below:

- That turso and SQLite read the same rows from the same file. Row counts from
  SQLite are plausible and the file is structurally sound, but turso was not run
  (no builds allowed). T0 records turso's own reading of the fixtures; T1
  compares.
- What a turso-based binary does with a file SQLite has written (T2, one manual
  check).
- That rusqlite 0.40.1 is the newest release on crates.io (it is the newest in
  the local cache).
- The MSVC C toolchain in the Parallels VM, and the Windows build as a whole.

## Current state

`pam_store` is 2,976 lines of `store.rs` plus nine submodules, 94 public async
methods, 148 unit tests in fourteen sibling files and one integration test
file (`tests/vector_math.rs`, five tests).

- One connection, owned by an async mutex (`conn_gate.rs:33-35`). Every method
  takes `Store::lock()` (`store.rs:679-681`). `ConnGate::lock` asks
  `is_autocommit()` on acquisition and rolls back a transaction a dropped caller
  left open (`conn_gate.rs:57-80`).
- Ten transactions go through the `transact!` macro (`store.rs:52-58`; sites at
  `store.rs:975, 1400, 1666, 1771, 1802, 2001, 2046, 2257, 2585, 2649`), and the
  migration runner writes its own `BEGIN`..`COMMIT` (`migrations.rs:156-182`).
- Open sets two pragmas, runs `quick_check` on files up to 256 MiB, then
  migrates (`store.rs:659-675`, `2914-2933`).
- The engine leaks into the public API in one place:
  `StoreError::Database(#[source] turso::Error)` (`error.rs:107-108`). No crate
  outside `pam_store` names a `turso::` type (grep over `crates/`, `tools/`,
  `.github/`: the only hits are `crates/pam_store/Cargo.toml:10` and
  `crates/pam_store/tests/vector_math.rs`).
- The workspace carries `turso = "0.7"` (`Cargo.toml:44`), two
  `[patch.crates-io]` entries and two `exclude` entries for `vendor/turso_core`
  and `vendor/aegis` (`Cargo.toml:2, 105-106`), 441 tracked vendor files, and a
  Windows linker flag that exists only because turso's WAL replay overflowed the
  1 MiB main-thread stack (`.cargo/config.toml:14-23`, issue 23).
- 85 of the 589 packages in `Cargo.lock` are reachable only through `turso`,
  among them `bindgen`, `clang-sys`, `prost`, `loom`, `shuttle`, `aes-gcm`, and
  `generator`, which already depends on `cc`.

## Concurrency model

rusqlite is synchronous. `rusqlite::Connection` is `Send` and not `Sync`
(`rusqlite-0.40.1/src/lib.rs:364`), and `Statement`, `Rows` and `Transaction`
borrow it, so none of them can be held across an `.await`.

### Options compared

**(a) A dedicated store thread.** The thread owns the connection and reads
boxed closures from a bounded channel; each async method sends a closure and
awaits a oneshot reply. A closure runs to completion once started.

**(b) `spawn_blocking` around a `std::sync::Mutex<Connection>`.** Each call
spawns a blocking task that locks the mutex inside the blocking thread.

**(c) An async gate, then one blocking task.** The connection lives in
`Arc<tokio::sync::Mutex<Connection>>`. A call awaits `lock_owned()`, moves the
owned guard and its closure into `spawn_blocking`, and awaits the join handle.

| Property | (a) store thread | (b) blocking + std mutex | (c) async gate + blocking |
| --- | --- | --- | --- |
| A started unit runs to completion when its caller is dropped | yes | yes | yes |
| Order of waiting callers | FIFO (channel) | unfair (std mutex) | FIFO (tokio mutex is fair) |
| Cost of a waiting caller | a queued closure, or a suspended sender when full | one parked pool thread each | a suspended future, as today |
| Backpressure | explicit queue bound | none (the blocking pool queue is unbounded) | none added; bounded by the daemon's own concurrency |
| Panic in a unit | `catch_unwind` in the loop | poisons the mutex | `catch_unwind` in the closure; tokio's mutex does not poison |
| tokio features in `pam_store` | `sync` (today's) | `sync`, `rt` | `sync`, `rt` |
| Shutdown | explicit drain and join | runtime-dependent | explicit `close()`; started work finishes before the runtime drops |
| Paused-clock tests (`start_paused = true`) | broken, see below | transparent | transparent |

The last row decides it. tokio's test clock auto-advances to the next timer
whenever the runtime has nothing to do. It suppresses that only while a
`spawn_blocking` task is outstanding on a current-thread runtime
(`tokio-1.53.1/src/runtime/blocking/schedule.rs:19-28, 44-50`); the hook is
`pub(crate)`, so a foreign thread cannot use it. With (a), a test that awaits a
store call under a paused clock leaves the runtime idle while the store thread
works, the clock jumps to the nearest timer, and the surrounding
`timeout(DEADLINE, ..)` fires at once, or fires sometimes, depending on which
thread wins. `pam_daemon` has eighteen `start_paused` tests; ten are in files
that drive the store (`queue_test.rs:402, 457, 734, 1251`, `approval_test.rs:180`,
`daemon_test.rs:82`, `model_service_test.rs:376, 394`,
`status_cache_test.rs:86, 171`). They pass today because turso's futures
complete inside `poll` without waiting on another thread (an inference from the
tests passing, not something read in turso's source). Under (a) each of them,
and every such test written later, would have to move to real time.

### Recommendation: (c)

(c) keeps the property (a) was proposed for: once the blocking closure starts
it cannot be abandoned, so a transaction is never left open by a dropped
caller. It keeps today's waiting behaviour (suspended futures, FIFO), uses one
pool thread at a time, and leaves every existing paused-clock test alone. Its
costs are the `rt` feature in `pam_store` (the note at
`crates/pam_store/Cargo.toml:18-20`, "No runtime features", is rewritten) and
that the connection moves between pool threads, which SQLite permits for a
connection used by one thread at a time.

If the owner prefers (a) regardless, the price is rewriting the ten tests above
and a standing rule that no paused-clock test may touch the store. Nothing else
in this document changes.

### Shape

`conn_gate.rs` stays as the one owner of the connection and is rewritten:

```rust
pub(crate) struct ConnGate { conn: Arc<tokio::sync::Mutex<Option<rusqlite::Connection>>>, poisoned: AtomicBool }

impl ConnGate {
    /// Runs `job` on the connection, off the async threads, to completion.
    pub(crate) async fn run<T, F>(&self, job: F) -> Result<T, StoreError>
    where
        F: FnOnce(&mut rusqlite::Connection) -> Result<T, StoreError> + Send + 'static,
        T: Send + 'static;
}
```

- **Arguments are owned.** A job is `'static`, so each public method copies its
  borrowed arguments before calling `run` (`insert_evidence` already does,
  `store.rs:2399-2403`). `AuditEntry<'_>`, `GrantChange<'_>` and
  `ConnectorPatch<'_>` get private owned twins. No public signature changes.
- **Dropped before start.** The call holds an abort-on-drop guard for its
  blocking task. tokio can cancel a blocking task only before it starts, and may
  not manage even that; either way the job runs whole or not at all. This is
  today's behaviour for a caller dropped while waiting for the lock.
- **Dropped after start.** The job finishes and commits. This is the one
  semantic change callers can observe: today a caller dropped inside
  `BEGIN`..`COMMIT` causes a rollback at the next acquisition; afterwards a
  caller that times out must assume the write may have landed. `finish_request`
  is idempotent by design (`store.rs:1378-1384`). `insert_request` is not: a
  retry after a landed insert fails on the primary key. T5 audits the daemon's
  30 `timeout(`/`timeout_at(` sites for a store write inside.
- **Transactions.** The `transact!` macro becomes a function,
  `in_txn(conn, |tx| ..)`, over
  `conn.transaction_with_behavior(TransactionBehavior::Immediate)`: commit on
  `Ok`, drop on `Err`. Dropping a `rusqlite::Transaction` rolls back, and a
  failed `COMMIT` is followed by that rollback, which is the contract of
  `ConnGuard::end` (`conn_gate.rs:104-123`) including "the statements' own error
  is the one returned". The `*_in_txn(conn, ..)` helpers become synchronous
  functions over `&rusqlite::Connection`.
- **Transaction boundaries do not move.** Methods that autocommit each statement
  today keep doing so. `read_evidence_view_range` depends on it: the allowance
  charge must survive a failure of the read that follows
  (`evidence_views.rs:225-229`).
- **Panic containment.** `run` wraps the job in `catch_unwind`. A panic unwinds
  through any `Transaction` (rollback), the statement cache is flushed, the
  caller gets `StoreError::Unavailable`, and the next call proceeds.
- **Invariant after every job.** `run` checks `is_autocommit()` before releasing
  the guard. A transaction still open is rolled back and logged; if the rollback
  fails the gate is poisoned and every later call answers
  `StoreError::AbandonedTransaction`, whose text already says to restart the
  daemon (`error.rs:89-93`). This is what remains of rollback-at-next-acquire,
  and it should be unreachable.
- **Queue bound and backpressure.** There is no queue. Waiters are futures
  suspended on the gate, as today. Their number is bounded by what the daemon
  already bounds: the admission cap, the 32 admin connections, and a fixed set
  of service loops. A hard cap that refuses calls is not added: turning load
  into failed audit writes is worse than waiting, and callers carry deadlines.
- **Shutdown.** New `Store::close(&self)`: takes the gate (so a running job
  finishes), runs `PRAGMA wal_checkpoint(TRUNCATE)`, closes the connection, and
  leaves `None` behind so later calls answer `Unavailable`. The daemon calls it
  at the end of graceful shutdown (the spine's "flush audit, close store",
  `2026-09-01-spine-design.md:169-170`). A daemon that is killed leaves the WAL;
  the next open recovers it. Without `close`, the connection is closed when the
  last `Arc` drops, which a still-running orphan job delays; tests that delete
  their directory on Windows after dropping a call mid-flight call `close` first.
- **Open.** `Store::open` runs its file copy, checks and migrations inside one
  blocking task.

### A second, read-only connection

WAL lets one writer and any number of readers proceed together. A read-only
connection (`SQLITE_OPEN_READ_ONLY`, `PRAGMA query_only = ON`) behind its own
gate would take the list queries and the on-demand integrity check off the
write path. A read that starts after a write's reply sees that write, because
the reply is sent after `COMMIT`.

Measured on the migrated copy of the owner's database (132,421 requests): the
Activity list with `hide_probes` walks `request_created_idx` and, because only
31 rows are not GUI probes, never reaches its `LIMIT`; it takes 32 ms.
`quick_check` takes 0.22 s and `integrity_check` 0.39 s on that copy (60 MB
after migration 12 added its indexes).

It is worth doing, later and narrowly:

- Not in the engine swap. The swap must be provably equivalent to one serialized
  connection.
- File-backed stores only. Two connections to `:memory:` need shared-cache mode,
  which has table locks instead of WAL. The in-memory stores that 48 test files
  use would keep one connection, so the two-connection path needs its own
  file-backed tests.
- An allowlist of pure reads: `list_requests_filtered`, `list_model_jobs`,
  `list_grants`, `list_callers`, `list_evidence`, `audit_for_request`,
  `compression_stats`, `get_evidence`, `check_integrity`. Anything that reads
  and then writes stays on the writer.

T1 routes every method through `ConnGate::run`; T7 adds the reader. Store
finding 7 stays "partly fixed" until T7.

## SQL and feature inventory

No statement needs rewriting. The differences are in the client API and in
defaults.

| Construct | Where | Under SQLite |
| --- | --- | --- |
| `PRAGMA foreign_keys = ON` | `store.rs:661` | Same. On today, per connection, and the schema depends on it: `ON DELETE CASCADE` (`migrations.rs:117, 368, 375, 397`), a missing request failing the audit row's foreign key (`store.rs:1762-1763`), children deleted before parents in prune (`store.rs:2699-2713`). Keep setting it and read it back; refuse to open if it does not read 1. The bundled build also defaults it on. |
| `PRAGMA busy_timeout = 5000` | `store.rs:662` | The pragma returns a row, which rusqlite's `execute` rejects. Use `Connection::busy_timeout`. |
| WAL | "native", never switched on (`lib.rs:10`) | SQLite's default for a new file is a rollback journal. Set `PRAGMA journal_mode = WAL` at open and require the answer `wal` for a file. Existing turso files are already WAL. `:memory:` answers `memory`. |
| `synchronous` | unset | Set `FULL`: a terminal write and its audit row must survive power loss once acknowledged. The cost is one fsync per commit. |
| `is_autocommit()` | `conn_gate.rs:59, 75` | `Connection::is_autocommit() -> bool`. |
| `PRAGMA quick_check` | `store.rs:2915` | Same. Rows other than `ok` are the findings. |
| `PRAGMA user_version` (read; write inside a transaction) | `migrations.rs:126, 161` | Same, and transactional: a rolled-back migration leaves the old version (checked). |
| Nested `BEGIN` refused | `conn_gate_test.rs:58-72` | Same message, "cannot start a transaction within a transaction" (checked). |
| Triggers: `audit_append_only`, `evidence_view_immutable` with `RAISE(ABORT, ..)` | `migrations.rs:97-114` | Same. The update is refused with the trigger's text; retention's tombstone (`store.rs:2619`) passes (checked). Tests assert the text (`store_integrity_test.rs:412`, `evidence_views_test.rs:452`), so the engine error must keep its message. |
| `LENGTH(CAST(x AS BLOB))` byte lengths, in CHECKs and queries | `migrations.rs:117, 356-397`, `store.rs:929-934, 1226-1248`, submodules | Same: bytes, not characters, and not cut at a NUL (`'hé'` gives 3; a 131,073-byte document is refused by the CHECK). |
| `LENGTH(blob)`, `substr(blob, ?, ?)` | `store.rs:2453, 2610`, `evidence_views.rs:167, 264` | Same: bytes for a BLOB. |
| Upserts: `ON CONFLICT .. DO UPDATE SET .. = excluded..`, `DO NOTHING`, `IS NOT excluded.x` | `store.rs:1939, 2235, 2244, 2851, 2896`, `flow_journal.rs:115`, `correlation_membership.rs:82-83` | Same. |
| `INSERT .. SELECT .. ON CONFLICT` | `request_budget.rs:76`, `landing_session.rs:176` | SQLite needs a `WHERE` on the `SELECT` to parse this. Both have one. |
| `INSERT OR IGNORE` | `evidence_views.rs:259` | Same. |
| Unary plus to keep an index out of the plan (`+state`) | `store.rs:1882-1891` | A SQLite idiom; the plan uses `request_created_idx` (checked). |
| `IN (SELECT .. ORDER BY .. LIMIT n)` in `DELETE`/`UPDATE` | `store.rs:2528-2553, 2606-2713` | Same; the prune batch uses `request_updated_idx` (checked). |
| `CREATE INDEX .. (created_ts DESC, id DESC)` | `migrations.rs:87` | Honoured: existing files have schema format 4. |
| `LIKE 'admin.%'`, `LIKE 'flow.step:%'` | `store.rs:93, 890, 1907` | SQLite's `LIKE` ignores ASCII case. turso is expected to match; T1 pins it with a test. Over-matching here only invalidates more. |
| `"grant"` as a quoted identifier | everywhere | Unaffected by disabling double-quoted string literals. |
| Dynamic argument lists (`Vec<String>`) | `store.rs:1536, 1922` | `rusqlite::params_from_iter`. |
| `execute` returning `u64` | throughout | rusqlite returns `usize`. |
| `row.get_value` matched on `turso::Value` | `store.rs:2918-2921, 2936-2959` | `row.get_ref` matched on `ValueRef`, keeping the same tolerance (text accepted where a blob is expected, NULL as empty). |
| `RETURNING` | none | Not used. |
| SQL JSON functions | none | Not used; `compression_stats` parses in Rust on purpose (`store.rs:2476-2478`). |
| Vector functions | `crates/pam_store/tests/vector_math.rs` only | No store statement uses them. The file tests the vendored kernel and is deleted with it. |
| Page size | 4096 in existing files | SQLite's default. No change. |

Stricter in rusqlite, to be caught by the suite rather than assumed:

- The number of bound values must equal the statement's parameter count.
- `execute` fails on a statement that returns rows.
- `row.get::<T>` fails on a type mismatch, NULL into a non-`Option` included.

Comments about the engine's stack use (`store.rs:45-51, 923-925, 1220-1225`)
become history. The SQL they explain stays as it is: a port is not the place to
change working statements.

### Connection settings

Set at open, in this order, each read back where it can be:

1. Open flags `READ_WRITE | CREATE | NO_MUTEX`, without `URI`, so a path is
   never parsed as a URI. (T1: not sufficient on its own; see the `file:`
   guard in the findings below.)
2. `busy_timeout` 5 s (today's value).
3. `SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE` on, until the integrity check has passed.
4. `SQLITE_DBCONFIG_DEFENSIVE` on, `TRUSTED_SCHEMA` off, `DQS_DML` and `DQS_DDL`
   off, `ENABLE_FKEY` on.
5. `journal_mode = WAL`, `synchronous = FULL`, `secure_delete = ON`,
   `journal_size_limit = 16 MiB`.
6. Limits (`limits` feature): `SQLITE_LIMIT_ATTACHED = 0`,
   `SQLITE_LIMIT_LENGTH = 128 MiB` (evidence blobs run to 64 MiB,
   `store.rs:2555`).

`secure_delete` is an addition, not parity: turso leaves pruned bytes in free
pages. It makes retention's deletions real inside the file. It does not scrub
WAL frames already written or the filesystem.

## Existing database files

### What the owner's database showed

`~/.pam/state.sqlite3` (48,353,280 bytes), `-wal` (395,552 bytes) and `-shm`
(32,768 bytes, dated 2026-09-01) were copied to a scratch directory. Only the
copies were opened. No daemon was running.

Header of the main file (`xxd -l 100`):

| Offset | Field | Value |
| --- | --- | --- |
| 0 | magic | `SQLite format 3\0` |
| 16 | page size | 4096 |
| 18, 19 | write, read version | 2, 2 (WAL) |
| 20 | reserved bytes per page | 0 |
| 24 | file change counter | 1 |
| 28 | size in pages | 11,805 (matches the file size) |
| 32, 36 | freelist trunk, count | page 11,805, 1 |
| 40 | schema cookie | 29 |
| 44 | schema format | 4 |
| 48 | default cache size | −2000 |
| 56 | text encoding | 1 (UTF-8) |
| 60 | `user_version` | 11 |
| 68 | application id | 0 |
| 92 | version-valid-for | 3,047,000 |
| 96 | SQLite version number | 3,047,000 |

The only turso-specific trait is the pair at 92 and 96. turso stamps 3.47.0 in
both and leaves the change counter at 1. Real SQLite stores the change counter
at 92, and when the two disagree it ignores the in-header size and uses the
file's. That is harmless here. There are no other non-standard header fields
and no extra files.

The WAL has magic `0x377f0682`, format 3,007,000, page size 4096, checkpoint
sequence 1340. A separate script recomputed SQLite's frame checksums: all 96
frames are valid, 19 are commit frames, the last commit sets the database to
11,806 pages, and page 1 is among the frames. The `-shm` file is a stale
wal-index (`mxFrame` 0); it is not known what wrote it.

System `sqlite3` 3.54.0 on the copy:

- `PRAGMA integrity_check`: `ok`. `PRAGMA quick_check`: `ok`.
  `PRAGMA foreign_key_check`: no rows.
- `journal_mode` `wal`, `user_version` 11, `page_size` 4096, `page_count`
  11,806, `freelist_count` 0, `encoding` UTF-8, `schema_version` 29,
  `auto_vacuum` 0.
- `.schema`: 17 tables and 21 indexes (6 named, 15 `sqlite_autoindex_*`), no
  triggers. turso stores normalized `CREATE` text: `"action"` and `"key"` are
  quoted, and `evidence`'s foreign key became a table constraint after its
  `ALTER TABLE`. SQLite parses it, also with double-quoted literals disabled.
  A file created by SQLite will carry the migration text verbatim, so no test
  may compare `sqlite_master.sql`; the current ones count names only
  (`migrations_test.rs:34, 187, 377`).
- Rows: `request` 132,421, `audit` 132,423, `request_budget` 31,469, `caller`
  6, `setting` 5, `model_job` 4, `grant` 2, the other ten tables 0.

Three variants of the copy:

| Variant | request | audit | request_budget | integrity |
| --- | --- | --- | --- | --- |
| main + WAL + stale `-shm` | 132,421 | 132,423 | 31,469 | ok |
| main + WAL, no `-shm` | 132,421 | 132,423 | 31,469 | ok |
| main only | 132,415 | 132,412 | 31,468 | ok |

So SQLite replays a turso-written WAL, a stale `-shm` does no harm (SQLite
rebuilds it), and a main file without its WAL is a consistent but older
database. A backup that copies only the main file loses the newest commits
without any error.

Migration 12, run by SQLite on the copy inside `BEGIN`..`COMMIT`, succeeded:
`user_version` 12, both triggers present, `integrity_check` ok,
`foreign_key_check` clean, 14,672 pages. After a checkpoint the header reads
change counter 2, version-valid-for 2, version 3,054,000: the first write by
SQLite removes turso's stamp.

Schema 12 is not in a release (`c24f5a7` is after tag `v0.4.3`). Files in the
field are at 11 or lower; 12, and plan 49's 13, exist only on development
builds.

### Open path for an upgraded install

The boundary is a schema version, called E below: the first migration that only
the SQLite-based binary knows. E is the next free number when T2 is written.
Today that is 14, because plan 49's migration 13 is being added on the turso
engine. Every turso-era file has a header `user_version` below E.

1. The daemon already holds its instance lock before opening the store
   (`daemon.rs:555-556`). Nothing changes there.
2. No file: create it, apply the settings, run all migrations, checkpoint. No
   backup.
3. A file exists: read exactly its first 100 bytes with plain file I/O. A wrong
   magic is `StoreError::Corrupt`. If the header `user_version` is below E the
   file needs the one-time backup. The header can lag the WAL; that only causes
   a backup attempt that finds one already there. A turso-era file can never be
   mistaken for an upgraded one.
4. Backup: copy `state.sqlite3`, `-wal` and `-shm`, those that exist, into
   `<base>/backup/pre-sqlite-engine/`, by way of a `.partial` directory that is
   synced and renamed, files mode 0600. An existing backup is never
   overwritten: the first one is the pre-upgrade state. If the copy fails (disk
   full, permissions) the open is refused with a new
   `StoreError::UpgradeBackup { path, source }` that names the directory and the
   space needed. There is no override. An operator who wants to proceed without
   history moves the state file away.
5. Open with the settings above. SQLite recovers the WAL; this rewrites `-shm`
   only.
6. Check before any write. For a file below E: full `PRAGMA integrity_check`
   and `PRAGMA foreign_key_check`, whatever the size. This is the one moment a
   turso-written b-tree meets SQLite's checker, and it costs about 7 s per GiB
   by the figure above (0.39 s for 60 MB on this host). Later boots keep today's rule, `quick_check` up to
   256 MiB (`store.rs:74-77`).
7. If the check fails, or the engine answers `SQLITE_CORRUPT` or
   `SQLITE_NOTADB`: close without checkpointing (step 3 of the settings exists
   for this) and return `StoreError::Corrupt`, with the backup path in the
   detail. The daemon does not start. Nothing is deleted, renamed or recreated.
   Recovery, to be written into the daemon's refusal text and the docs: the
   untouched copy is in `backup/pre-sqlite-engine/`; run the previous release
   against it, or salvage with `sqlite3 <copy> .recover`, or move the state file
   aside and start empty.
8. Migrate with the existing runner. Migration E sets
   `PRAGMA application_id = 1346456881` (`PAM1`) and stamps version E.
9. `PRAGMA wal_checkpoint(TRUNCATE)`, so the main file carries version E in its
   header, then clear `NO_CKPT_ON_CLOSE`.

Downgrade. An older turso-based binary that meets a version-E file refuses it
with the existing `StoreError::VersionTooNew` (`migrations.rs:139-147`, tested at
`migrations_test.rs:60`): "upgrade pam instead of downgrading the database".
That is the intended answer. To go back, stop the daemon, restore the three
files from `backup/pre-sqlite-engine/` and accept losing what was written
since. One thing is unverified: to read the version, turso opens the file and
replays any WAL SQLite left behind. T2 runs the released `v0.4.3` binary once
against an upgraded copy, with and without a WAL, and records what it does.

## Migrations

- Versioning is `PRAGMA user_version` and stays. The runner's logic stays: read
  the version, refuse a newer one, apply each newer migration in its own
  transaction, stamp, commit (`migrations.rs:125-182`). Only the client calls
  change: `execute_batch` for the SQL, one `Transaction` per migration.
- No migration is turso-only. `SCHEMA_V1`..`SCHEMA_V12` were applied verbatim
  to an empty file by SQLite, in a rollback journal and again in WAL with
  double-quoted literals disabled; both end at version 12 with `integrity_check`
  ok, 17 tables, 26 indexes and 2 triggers.
- Plan 49's `SCHEMA_V13` (four `ALTER TABLE request ADD COLUMN`, two with
  `NOT NULL DEFAULT` and a CHECK) was run on SQLite separately and is accepted.
- The existing constants are not edited. Migration E is added.
- `migrations_test.rs` builds its old databases by replaying a prefix of
  `MIGRATIONS` through `turso::Builder` (lines 65, 93, 128, 168, 258, 278). The
  ten tests are ported to open with rusqlite; their assertions do not change.
  They prove the migration logic on SQLite-written files.
- The turso-written fixtures prove the hand-over between engines; see the test
  strategy. Both kinds are kept.

## Error type

`StoreError` becomes engine-agnostic. No rusqlite type appears in a public
variant, field or `source`.

| Variant | Change |
| --- | --- |
| `Database(#[source] turso::Error)` | `Database(#[source] EngineError)`. `EngineError` is defined in `pam_store`: opaque, holding SQLite's extended result code and the message, with `Display`, `Error`, and `code()`, `is_constraint()`, `is_busy()`. The outer text stays `database error: {0}`. |
| `Corrupt { detail }` | Same shape. Produced from `SQLITE_CORRUPT` and `SQLITE_NOTADB` (were `turso::Error::Corrupt` and `NotAdb`, `error.rs:116-123`), from check output, and from a bad header magic. |
| `AbandonedTransaction` | Kept. It now means the gate found a transaction it could not roll back after a job. The doc comment changes, the text does not. |
| `NonUtf8Path` | Kept, with the up-front check at `store.rs:648-650`, so behaviour is the same on every target. |
| `Unavailable { detail }` | New: the job panicked, the runtime is shutting down, or the store was closed. |
| `UpgradeBackup { path, source: io::Error }` | New: the pre-upgrade copy could not be made. |
| all others | Unchanged. |

Sites outside `pam_store` that name a variant, complete by grep:

- `NotFound`: `terminal.rs:149, 220`, `admin_flows.rs:418`, `lifecycle.rs:243, 266`.
- `AlreadyTerminal`: `admin.rs:564` (with an `other =>` arm),
  `policy_test.rs:159`, `approval_test.rs:553`.
- `AbandonedTransaction`, constructed as a stand-in failure under `#[cfg(test)]`:
  `terminal.rs:125`, `queue.rs:653`.

None of them changes. No site matches `Database`, `Corrupt`, `NonUtf8Path`,
`CreateDir` or `VersionTooNew`, and no `match` over `StoreError` outside the
crate is exhaustive, so the two new variants break nothing. The `#[from]`
wrappers (`policy.rs:230`, `queue.rs:177`, `scope_policy.rs:93`, `daemon.rs:321`,
`lifecycle.rs:74`, `connector_service.rs:223`, `model_service.rs:179, 195`,
`log_service.rs:233`) and the sites that format the error (`admin.rs:216-262`,
`flow_service.rs:1668-1685`, `retention.rs:371-375`) compile as they are.

## Build and packaging

### Dependency

Root `Cargo.toml`, replacing lines 40-44:

```toml
# Real SQLite: the amalgamation shipped inside libsqlite3-sys, compiled by `cc`
# and linked statically. A named exception to the no-C rule (owner decision
# 2026-10-02, issue 38), like the Tauri/objc2 shims. Never the system library,
# so every target runs the same engine.
rusqlite = { version = "0.40.1", default-features = false, features = ["bundled", "cache", "limits"] }
```

(As landed in root `Cargo.toml`, the comment reads "Real SQLite for the store"
and names the exception and the owner decision; the version is 0.40.1, see the
findings below.)

`crates/pam_store/Cargo.toml`: `rusqlite.workspace = true` in place of
`turso.workspace = true`; tokio becomes `features = ["sync", "rt"]`.

- `bundled`: yes. SQLite 3.53.2 in libsqlite3-sys 0.38.1; the source is in the
  crate, nothing is fetched at build time, and bindings are pre-generated (no
  `bindgen`).
- `cache`: yes, for `prepare_cached`.
- `limits`: yes, for the two limits above.
- `backup`: no. The pre-upgrade backup must happen before the new engine reads
  the file, so it is a file copy. A live export can use `VACUUM INTO` when
  someone specifies it.
- `hooks`: no. Nothing uses update or commit hooks.
- `load_extension`: no. Without it rusqlite has no way to enable loading.

### Compile flags

None are set. `libsqlite3-sys` takes extra flags only from the
`LIBSQLITE3_FLAGS` environment variable (`build.rs:294-305`), which a build
outside this workspace's `.cargo/config.toml` would not see. Security must not
depend on it; every item has a runtime equivalent that a test reads back.

| Flag | Decision |
| --- | --- |
| `SQLITE_DQS=0` | Runtime: `DQS_DML` and `DQS_DDL` off per connection. |
| `SQLITE_DEFAULT_WAL_SYNCHRONOUS` | Runtime: `PRAGMA synchronous = FULL`. |
| `SQLITE_THREADSAFE` | The bundled build sets 1 (`build.rs:139`). The connection is opened `NO_MUTEX` and serialized by the gate. |
| `SQLITE_OMIT_LOAD_EXTENSION` | Not set. The bundled build compiles the loader in (`build.rs:134`), SQLite leaves it disabled per connection, and without the `load_extension` feature nothing can enable it. A test asserts `SELECT load_extension('x')` fails. Omitting it at compile time is an untested combination with rusqlite's bindings. |
| `SQLITE_SECURE_DELETE` | Runtime: `PRAGMA secure_delete = ON`. |

The bundled build also compiles FTS3/5, R-Tree, JSON1 and DBSTAT
(`build.rs:129-138`). They are reachable only through SQL text, and the store
never executes caller-supplied SQL (`store.rs:95`).

### Targets and bundle

| Target | Effect |
| --- | --- |
| macOS arm64 | `cc` uses the Xcode toolchain already needed for the objc2 helper. One more static object in `pam`. No new dylib, so signing, hardened runtime and the dmg are unaffected. |
| Windows amd64 | `cc` uses `cl.exe` from the MSVC build tools that Rust's MSVC target already requires for linking. Covered by the `windows-2025` CI runner on the PR. |
| Windows arm64 | Same with the ARM64 toolset. Native in the Parallels VM. The VM needs the C++ workload; T1 checks it before anything else. |

`cc` is already in `Cargo.lock` (1.4.4), through `objc2-exception-helper`,
`embed-resource` and turso's own `generator`. Removing turso drops 85 lock
entries, `bindgen` and `clang-sys` among them. rusqlite adds about five
(`rusqlite`, `libsqlite3-sys`, `hashlink`, `fallible-streaming-iterator`,
`vcpkg`; `pkg-config` is already present). `vcpkg` and `pkg-config` are build
dependencies of `libsqlite3-sys`'s default feature and are not used by a
bundled build.

The Tauri bundle contains the same single `pam` binary with SQLite linked in.
No resource, sidecar or installer change. `cargo install` from source now needs
a C compiler.

### The Windows `/STACK` workaround

`.cargo/config.toml:14-23` lifts the main thread to 16 MiB because store open
replayed the WAL through turso and overflowed 1 MiB. SQLite's WAL recovery is
iterative and, under this design, runs on a blocking-pool thread, not the main
thread. T1 measured the store at under 64 KiB of stack (findings below). The flag should
go, on evidence: T6 removes it and runs the workspace
suite and a daemon boot over a multi-megabyte WAL in the VM, debug build. If
something else on the main thread overflows, the flag stays and its comment is
rewritten to name the real cause. `target-feature=+fp16` on
`aarch64-pc-windows-msvc` is unrelated and stays.

### Removal

- `Cargo.toml:44` (`turso`), `:105-106` (the `turso_core` and `aegis` patches),
  `:2` (their `exclude` entries; `vendor/zeromq` is plan 49's).
- `vendor/turso_core/`, `vendor/aegis/` (441 tracked files).
- `crates/pam_store/tests/vector_math.rs` (five tests of the vendored kernel).
- `Cargo.lock` regenerated.

### Documents to update

| Where | Now | Becomes |
| --- | --- | --- |
| `Cargo.toml:40-43` | "the point of turso is a pure-Rust engine … Same-version patches below remove mandatory SimSIMD C compilation" | The comment in the dependency block above. |
| `Cargo.toml:74-75` | "This conflicts with the no-C-compiler constraint; see ptrack issue 16/task 142." | Add: "an accepted exception, as SQLite is". |
| `crates/pam_store/src/lib.rs:6-16` | "Engine: Turso … a pure-Rust SQLite rewrite … WAL is native … a `BEGIN`..`COMMIT` window that a dropped caller abandons is rolled back before the next statement" | Engine: SQLite through rusqlite, bundled; WAL set at open; a call runs to completion off the async threads once started (see `conn_gate`). |
| `crates/pam_store/src/conn_gate.rs:1-23`, `store.rs:606-622` | turso's concurrent-use and nested-`BEGIN` rules | The gate as described here. |
| `crates/pam_store/Cargo.toml:18-20` | "No runtime features — the daemon owns task placement." | The store places its own blocking work; `rt` is for `spawn_blocking`. |
| `docs/native-build-dependencies.md:3` | "PAM requires Rust dependencies that do not compile C/C++ sources." | "… with two named exceptions: the platform shims Tauri and objc2 compile, and SQLite, compiled from the amalgamation bundled in `libsqlite3-sys` (owner decision 2026-10-02, issue 38)." |
| `docs/native-build-dependencies.md:8-34` | "Database repair (task #142)": the turso and aegis patches and the `CC=/usr/bin/false … cargo test -p pam_store` proof | Replaced by a short "Database" section: what is compiled, from where, which version, how to read it back (`PRAGMA compile_options`, `sqlite_version()`). The compiler-denied proof no longer applies to `pam_store`. |
| `docs/enterprise-evidence-checkpoint.md:37-42` | "no C libraries, no cmake, no vendored C code (turso rather than rusqlite, the zeromq crate rather than libzmq) — while the platform binding shims … are an accepted exception" | "no C libraries of PAM's own choosing except SQLite (rusqlite, bundled; decided 2026-10-02 for the audit spine), no cmake, …"; drop "turso rather than rusqlite". |
| `docs/agent-companion-roadmap.md:31` | "Pure-Rust dependency constraint remains." | "… remains, with SQLite as a named exception." |
| `docs/specs/2026-09-09-local-model-triage.md:34` | "Retain one binary and the Rust-only Candle/turso design." | Drop "/turso"; add a dated note. |
| `docs/specs/2026-09-13-llama-cpp-engine.md:20` | "keeps the no-C rule for PAM's own dependency graph" | Dated note that the rule now has the SQLite exception; the argument about llama.cpp is unchanged. |
| `docs/specs/2026-09-03-retention-design.md:65-67` | "memento law: one turso connection, one statement at a time … `ConnGate`" | The gate as described here. |
| `docs/specs/2026-09-02-log-compression-design.md:135` | "turso concurrency rule" | Same replacement. |
| `docs/specs/2026-09-01-spine-design.md:134-136` | "Store (SQLite) … WAL" | Add the engine, the settings and a link to this spec. |
| `docs/reviews/design-review-2026-10-02.md:93, 149-154, 226` | finding 11 "partly fixed"; owner decision 1 "Still open"; reader connection deferred | Record the decision, this spec, and T7. |
| `CLAUDE.md:114`, `AGENTS.md:112`, `MEMENTO.md:23-26` | the `turso-connection-concurrent-use` rule | Replaced through the memento tool, not by hand: the store's connection is used only inside `ConnGate::run`; no rusqlite value is held across an await; no second write connection. |
| `CHANGELOG.md` | — | Engine change, one-time backup and its location, the downgrade refusal. |

`docs/plans/*` name turso as history and are left alone. The owner's agent
memory note "PAM C-dependency-free rule" lives outside the repository and needs
the same exception.

## Test strategy

### Must pass unmodified

- The seven test files that use only the public API, 32 tests:
  `correlation_membership_test`, `flow_journal_test`, `flow_results_test`,
  `landing_session_test`, `terminal_uncertainty_test`, `watch_progress_test`,
  `watch_schedule_test`.
- Every test outside `pam_store`: `pam_daemon`, `pam_testkit`, `pam`. They reach
  the store through `Store::open` and `open_in_memory` and the public methods.
  The ten paused-clock tests named above are part of this.

### Same assertions, new test seam

`store_test` (56), `store_integrity_test` (19), `evidence_views_test` (12),
`request_budget_test` (6), `correlation_test` (5) and `migrations_test` (10)
are engine-agnostic in what they assert, but 30 call sites seed or inspect rows
through `store.lock()` with turso's client API. They move to a `#[cfg(test)]`
seam, `Store::raw(|conn| ..)`, over `ConnGate::run`. A reviewer's diff of these
files should show helper calls changing and no assertion changing. Three to
watch:

- `a_structurally_damaged_database_is_refused_legibly_at_open`
  (`store_integrity_test.rs:1011-1046`) overwrites everything past the first
  4096 bytes of the main file and the WAL. SQLite must still answer `Corrupt`,
  which exercises the `SQLITE_CORRUPT` mapping.
- The two tests that assert trigger text.
- `boot_recovery_and_the_hot_statements_fit_well_inside_a_thread_stack`
  (`store_integrity_test.rs:1053-1110`) passes trivially, since the statements
  no longer run on the measured thread. It is kept as a smoke test and its
  comment rewritten.

### Replaced: `conn_gate_test.rs` (8 tests)

| Today | Becomes |
| --- | --- |
| the engine refuses a `BEGIN` inside an open transaction | Kept through the seam; same message. |
| a deadline inside a transaction is rolled back before the next call | Two tests. A caller dropped after its job started: the job commits whole, state and audit row together, and the next call works. A caller dropped while another job holds the gate: its job never runs. |
| a connection left inside a raw transaction is recovered by the next lock | A job that returns with `BEGIN` open (through the seam) is rolled back by the gate; its write is not visible; the next call works. |
| an aborted task inside a transaction does not wedge the store | Same name, new expectation: all or nothing, never half, and the store is usable. |
| a panic inside a transaction does not wedge the store | The panicking job is rolled back, the caller gets `Unavailable`, the next call works. |
| an error inside a transaction rolls back and returns that error | Kept. |
| writes after an abandoned transaction are durable and its own are not | Kept, with a panicking job, checked by reopening the file. |
| `finish_request` dropped at any poll leaves state and audit consistent | Kept as written: for every poll count, both rows or neither. |

### New

- **Kill during a transaction, real file.** The test binary re-executes itself
  as a child that opens a store at a path, commits some rows, opens a
  transaction, writes, reports readiness on stdout and blocks. The parent calls
  `Child::kill`, which is `SIGKILL` on Unix and `TerminateProcess` on Windows,
  with no signal-specific assertions (memento `pam-tests-never-ran-off-macos`).
  It then reopens: check passes, committed rows present, the open transaction's
  rows absent. A second case kills inside a prune batch.
- **Concurrent callers.** A multi-thread runtime, many tasks, mixed reads and
  writes on a file-backed store: no error, counts add up, one caller's calls
  apply in order.
- **Close.** Calls in flight at `close` finish; calls after it answer
  `Unavailable`; the WAL is empty; the file reopens.
- **Settings read-back.** `foreign_keys` 1, `journal_mode` `wal`, `synchronous`
  2, `secure_delete` 1, a double-quoted literal is an error, `load_extension`
  fails, `ATTACH` is refused, `sqlite_version()` is the bundled one.
- **`LIKE` case** pinned for the two patterns.
- **Error mapping.** Corruption codes, a constraint failure with its message, a
  busy answer.

### turso-written fixtures

Committed under `crates/pam_store/tests/fixtures/`:

- `turso-0.7.2-v11/` and `turso-0.7.2-latest/` (schema 12, or 13 if plan 49 has
  landed when T0 runs), each with `state.sqlite3`,
  `state.sqlite3-wal` holding commits that are not in the main file, and
  `expected.json`: per-table counts and a handful of rows, written by turso's
  own reads when the fixture is generated. Version 11 is the released shape and
  must include revoked grants, so the `revoked_seq` backfill of migration 12
  runs under SQLite on turso-written rows; the latest one covers development
  builds.
- Synthetic rows only. Under 200 KB each. `.gitattributes` marks them binary so
  no checkout rewrites a byte.
- `README.md`: the commit they were generated at and the generator's source.
  After T3 the generator can no longer run, so the files are regenerated never
  and trusted forever.

Tests copy a fixture to a temporary directory and never open it in place:

- Open succeeds; the version is the latest; counts and rows equal
  `expected.json`, including the rows that exist only in the WAL.
- `backup/pre-sqlite-engine/` holds files byte-identical to the fixture.
- A second open makes no second backup and changes nothing.
- A fixture with a stale `-shm` added, and one with the WAL removed, both open;
  the second shows the older counts.
- A fixture with a damaged b-tree page is refused with `Corrupt`; the main file
  and WAL are byte-identical afterwards and the backup exists.
- A fixture in a directory where the backup cannot be written is refused with
  `UpgradeBackup` and is not opened.

## Implementation plan

Branch `feat/sqlite-store`, from `main` after plan 49 lands or rebased over it;
plan 49 is editing `crates/pam_daemon/src/daemon.rs`, which T5 also touches.
Two agents: A owns the store, B owns everything else. Each task references its
ptrack id in commits.

**T0. turso fixtures (B).** Before any other task, at the pre-port commit, in
its own worktree with its own `CARGO_TARGET_DIR`.
Owns: `crates/pam_store/tests/fixtures/**`, `.gitattributes`.
Does: generate the two fixture sets with the current turso-based code, leaving
uncheckpointed WAL frames; record turso's reads in `expected.json`.
Accept: each fixture passes `PRAGMA integrity_check` in the `sqlite3` CLI; the
CLI's counts equal `expected.json`; the README names the commit.

**T1. Spike: port the store's internals (A).** Go/no-go.
Owns: `crates/pam_store/**` except `tests/fixtures`; the `rusqlite` line in
root `Cargo.toml`; `Cargo.lock`. turso's workspace entries and vendor
directories stay for now (cargo warns about unused patches; that is expected).
Does: confirm the rusqlite version against crates.io and the C toolchain in the
VM; rewrite `conn_gate.rs`, `error.rs`, `migrations.rs`, `store.rs` and the nine
submodules onto `ConnGate::run`; apply the connection settings; port the tests
as classified above; delete `tests/vector_math.rs`. No upgrade path yet beyond
opening an existing file.
Go when all of these hold:

1. `cargo clippy -p pam_store --all-targets -- -D warnings` is clean and
   `cargo test -p pam_store` is green, with no assertion edited.
2. `cargo test --workspace` is green on macOS with no file changed outside
   `crates/pam_store`, root `Cargo.toml` and `Cargo.lock`. This is "no caller
   API change", and it includes the paused-clock tests.
3. A fresh copy of the owner's database (made as in this document, deleted
   after) and both fixtures open through `Store::open`, pass `integrity_check`
   and `foreign_key_check`, migrate to the last turso-era version, and the
   fixtures' rows equal
   `expected.json`.
4. `cargo test -p pam_store` is green in the Windows VM.

No-go if 3 fails in a way that is not a bug in the port, or if 2 can only be
met by editing callers.

**T2. Upgrade path and durability tests (A).** After go.
Owns: `crates/pam_store/**`.
Does: header read, one-time backup, the full check for files below E,
no-checkpoint-on-failure, migration E, `Store::close`, the two new error
variants; the fixture, kill, concurrency, close and read-back tests; the one
manual downgrade check with the `v0.4.3` binary, recorded in the PR.
Accept: every test in "New" and "turso-written fixtures" is green on macOS and
in the VM.

**T3. Remove turso (B).** After T1 lands on the branch; parallel with T2.
Owns: root `Cargo.toml` (from here on), `Cargo.lock`, `vendor/turso_core/**`,
`vendor/aegis/**`.
Accept: `cargo metadata` shows no `turso*`, `aegis`, `bindgen` or `clang-sys`;
no unused-patch warning; `cargo build --workspace` is clean.

**T4. Documents (B).** Parallel with T2.
Owns: `docs/**`, `CHANGELOG.md`, and the memento rule through the memento tool
(which regenerates the lines in `CLAUDE.md` and `AGENTS.md`). Comments inside
`crates/pam_store` belong to A.
Accept: every row of "Documents to update" is done; `grep -ri turso` over the
repository outside `docs/plans` and the fixtures finds only history.

**T5. Daemon touch points (B).** After T2's `close` exists and plan 49 has
landed.
Owns: `crates/pam_daemon/src/daemon.rs` (the shutdown path) and any file the
audit finds.
Does: call `store.close()` at the end of graceful shutdown; put the backup path
and recovery sentence into the refusal a corrupt store produces at boot; audit
the timeout sites for writes that are not safe to repeat after "may have
landed", and fix or record each.
Accept: a daemon test shows an empty WAL after graceful shutdown; the audit is
a table in the PR.

**T6. Windows stack flag (B).** After T3.
Owns: `.cargo/config.toml`.
Accept: with both `/STACK` arguments removed, `cargo test --workspace` and a
daemon boot over a multi-megabyte WAL pass in the VM, debug build. Otherwise
the flag stays and the comment names the real cause.

**T7. Read connection (A).** After T2. Not part of the swap's acceptance.
Owns: `crates/pam_store/**`.
Accept: file-backed tests show a list query completing while a write
transaction is held open through the seam, and a read after a write seeing it;
in-memory stores unchanged.

**T8. Integrate and verify.**
`cargo clippy --all-targets -- -D warnings` on `pam_store` first (memento
`clippy-before-full-gate`), then `bash tools/check.sh` on macOS, then
`cargo test --workspace` in the Parallels Windows 11 VM (arm64, native). Windows
amd64 is covered by the PR's CI run; wait for it before merging. One real
upgrade: start the built daemon against a copy of a turso-era `~/.pam`, confirm
the backup, version E, and a working GUI.

## Risks and what would make this a no-go

No-go:

- **SQLite reads a turso-written file differently from turso.** Not seen: the
  owner's file is structurally sound and its WAL replays. If T1 finds a
  mismatch against `expected.json`, a file copy is not a safe hand-over and the
  alternative is a bridge release that still links turso to export. That
  defeats the purpose and goes back to the owner.
- **Callers must change to keep their tests passing.** Then the abstraction is
  wrong, most likely the concurrency model, and this section is revisited
  before any caller is edited.
- **The bundled build fails on a Windows target** for a reason that is not a
  missing toolchain.

Risks carried:

- **A caller that times out can no longer assume its write was rolled back.**
  T5's audit. Terminal writes are idempotent; inserts are not.
- **A running job cannot be cancelled.** A slow statement holds the connection
  until it ends. Bounded today by batch sizes and list limits;
  `check_integrity` on a large file is the exception until T7.
- **The first boot after upgrade is slower**: a file copy plus a full check,
  roughly 10 s per GiB.
- **The backup doubles the state file's disk use** until the operator deletes
  it. It is never deleted automatically. It holds audit data and is written
  0600 inside `~/.pam`.
- **`synchronous = FULL` adds an fsync per commit.** The write rate is low now
  that `status` writes no rows; measure in T2 before trusting that.
- **`secure_delete` makes prune write more.**
- **An outside process holding the file** (an operator's `sqlite3`, antivirus
  on Windows) stalls the store for up to the 5 s busy timeout. The same exposure
  exists today.
- **In-memory stores are not WAL.** Tests on `:memory:` do not exercise WAL
  paths; the file-backed tests above do.
- **Fixtures cannot be regenerated** once turso is gone. T0 must be right, and
  is cheap to check before T3.
- **The store now uses the daemon's blocking pool**, shared with keychain and
  hashing jobs. It takes one thread at a time, two with T7.
- **turso's behaviour on a file SQLite wrote** is unverified until T2's manual
  check. The supported downgrade is restoring the backup, which does not depend
  on it.

## Open points for the owner

1. Concurrency model (c) instead of the dedicated thread (a), for the
   paused-clock reason above.
2. A boundary migration (E) whose only job is to make older binaries refuse the
   file.
3. `synchronous = FULL` and `secure_delete = ON`.
4. No override for a failed pre-upgrade backup.

## Findings from T1 (2026-10-02)

The port is on `feat/sqlite-store` (`e963f51`). What it found that corrects or
completes the sections above; the full spike report is the T1 record.

- **rusqlite version.** The lock and this spec use rusqlite 0.40.1 with
  `libsqlite3-sys` 0.38.1 (SQLite 3.53.2, read back by a test). crates.io's
  newest at the time was 0.40.2 (`libsqlite3-sys` 0.38.2); 0.40.1 was what the
  local registry cache held and the port was built offline. Whoever bumps it
  must first read which SQLite 0.38.2 bundles. "0.40.1 is the newest release"
  in the unverified list above is therefore false: it is the one in use, not the
  newest.
- **`file:` URI guard.** Opening without `OpenFlags::URI` is not enough: the
  bundled build compiles `SQLITE_USE_URI`, so SQLite parses a name that starts
  with `file:` as a URI whatever the flags say. `open.rs` opens such a path as
  `./file:...`, and a test pins it. The "a path is a path" requirement stands;
  the guard is how it is met.
- **Check before the journal switch.** The boot `quick_check` runs before
  `PRAGMA journal_mode = WAL`, not after: switching a rollback-journal file to
  WAL writes the header, and a file that fails the check must be left
  byte-identical (tested: a refused open leaves the main file and `-wal`
  unchanged).
- **Stack.** The fixture read-back (open, WAL recovery, migrations 11 to 13,
  `quick_check`, every public read) passes with the driving thread and the
  blocking threads both at 1 MiB, 512, 256, 192, 128, 96 and 64 KiB, and
  overflows at 48 KiB. turso needed more than 1 MiB for the same reads. Store
  statements, open included, no longer run on the main thread at all. The unit
  test that guards this runs the boot and hot statements on 512 KiB threads
  (was 1.5 MiB). T6 still has to prove nothing else on the main thread needs
  the Windows 16 MiB `/STACK` flag: the daemon's startup poll chain runs inline
  on the main thread (`runtime.block_on(serve(base))`), and deep async fixture
  futures in the daemon tests are the other known consumer.
- **Timing.** `pam_store` unit suite 1.65 to 1.90 s on turso, 1.19 to 1.27 s on
  SQLite; `store_fixtures` 5 times faster; the `pam_daemon` unit suite (808
  tests) 15.1 to 15.6 s on turso against 16.7 to 16.9 s on SQLite, **9 %
  slower**, not attributed (candidates: the thread hop per call and one fsync
  per commit with `synchronous = FULL`). The file-backed integration suites did
  not move. Windows will be slower per commit than macOS; time it in the VM.
- **Paused-clock tests.** There are 21 `start_paused` tests today (the text above counts
  eighteen, ten of them driving the store); all pass under concurrency model (c).
- **A race the port exposed in `pam_daemon`.** Under turso a store future never
  returned `Pending`, so tasks never interleaved inside one. Under (c) every
  store call suspends. `model_service::maybe_idle_unload` held the
  `operation` try-lock across its settings read while `generate_diagnostic`
  answers `Busy` if that lock is held, so the test
  `diagnostic_requires_installed_id_and_does_not_resolve_or_load_a_default`
  failed in about one run in four (16 of 60 alone). The same window existed in
  production on the multi-thread runtime, once per 30 s idle tick. Proof it was
  the cause: the same binary with the job run inline in the poll passed 60 of
  60. Resolution: the setting is read before the lock is taken, so the lock is
  never held across a store await (a three-line caller change, the first of the
  three options the T1 report offered, landed with the port). General rule: a
  store call suspends; do not hold a `try_lock`-style guard across one if another
  task treats "held" as busy. A caller dropped after its job started must assume
  the write landed (T5's audit).
- **Other deviations.** `ConnGate` holds a `Connection`, not an
  `Option<Connection>` (no `Store::close` until T2). A thin `db.rs` layer
  (`Db`, `Stmt`, `Rows`, `Row`) returns `StoreError` instead of an
  `impl From<rusqlite::Error>`, so no rusqlite type reaches the public
  interface. `EngineError::message()` is an extra accessor. `pkg-config` is new
  in the lock (the spec assumed it present), so 112 packages left the lock, not
  85. `PRAGMA fullfsync` is not set: `synchronous = FULL` on macOS is `fsync`,
  which does not flush the drive's cache; the owner decides whether real
  power-loss durability there is worth the cost per commit.
- **Removal (T3), done.** Root `Cargo.toml` lost the `turso` workspace
  dependency, the `exclude` entries and the whole `[patch.crates-io]` table;
  `vendor/` (441 tracked files) is gone; `Cargo.lock` lost its two
  `[[patch.unused]]` entries. `cargo tree -i turso`, `-i turso_core` and
  `-i aegis` match no package and cargo prints no unused-patch warning.

## As built (2026-10-02)

T2 (upgrade path, durability), T5 (shutdown close, timeout audit) and T7 (read
connection) as they landed. Where this section and the design above disagree,
this section is what the code does. The design text it supersedes:

| Design above says | Built |
| --- | --- |
| Calls after `close` answer `Unavailable` | `StoreError::Closed`. `Unavailable` says "retry it", which is wrong for a closed store |
| "There is no queue … a hard cap that refuses calls is not added" | 1,024 calls per connection, then `StoreError::Overloaded` |
| `NO_CKPT_ON_CLOSE` on until the integrity check has passed, then cleared | On for the connection's whole life. Only `Store::close` folds the log |
| Without `close`, the connection is checkpointed when the last `Arc` drops | A dropped store never checkpoints and writes nothing |
| Backup in `backup/pre-sqlite-engine/` | `backup/state-<UTC time>-pre-sqlite/` |
| Two new error variants | Four: `UpgradeBackup { path, needed_bytes, source }`, `NotPamDatabase`, `Closed`, `Overloaded` |
| The read connection as a later, narrow task | Built; routing table below (`list_grants` stayed on the writer) |
| One batch of migrations | Still one transaction per migration; a failed later one leaves the earlier ones applied, with the pre-batch backup to go back to |
| T5 owned by B, `fullfsync` an open question | T5 done with T2; `fullfsync` measured and left off |

### Open path

`Store::open(path)` for a file, in order. A refusal at any step leaves every
database file as it was found.

1. **Look, without the engine** (`header.rs`: the first 100 bytes as plain
   bytes).

   | At the path | Result |
   | --- | --- |
   | nothing, no log | new database |
   | nothing, or a zero-length file, with a non-empty `-wal` beside it | refused (`Corrupt`): a log without its main file. SQLite, opening that pair, deletes the log |
   | zero-length file, no log, in a directory with no sign of an earlier PAM | new database |
   | zero-length file, no log, where PAM has run before (`backup/`, a non-empty `log/`, `run/daemon.lock`, `flows/` or `model-trust/` beside it) | refused (`Corrupt`): an empty file is not a database PAM wrote. The refusal names the newest backup to restore, or says to move the empty file aside to start fresh |
   | shorter than a header, or no `SQLite format 3` magic | refused (`Corrupt`) before any copy; the engine never opens it |
   | a database | header `user_version`, `application_id`, and whether it carries the previous engine's stamp |
   | unreadable | refused, naming the file |

2. **Back up before anything can change.** A header version below the newest
   this binary knows means an upgrade is pending: below 14 the copy is
   `pre-sqlite`, otherwise `pre-v<latest>`. The header can lag the log and
   never runs ahead of it, so this errs toward a copy too many. A copy that
   cannot be written refuses the open (`UpgradeBackup`), the partial copy is
   removed, and the engine never opens the file. No override.
3. **Open and harden** (the connection settings above).
4. **Read the real version, through the log.** Newer than this binary:
   refused (`VersionTooNew`). Version 14 or later without PAM's
   `application_id`: refused (`NotPamDatabase`), before any write. A header
   that had only lagged: the copy just made is removed, or renamed to what it
   really precedes.
5. **Check before any write.** Below 14 (the first open by SQLite): full
   `integrity_check`, then `foreign_key_check`, whatever the size. Otherwise
   `quick_check` up to 256 MiB. A failure is `Corrupt`, naming the backup and
   three ways on (the old release against the copy, `sqlite3 .recover`, move
   the files aside).
6. WAL asserted, `synchronous = FULL`, `journal_size_limit`, the macOS sync
   settings; for a file below 14, a `wal_checkpoint(TRUNCATE)` so the previous
   engine's log is in the main file before SQLite appends.
7. **Migrate**, one transaction each. Migration 14 changes no table: it
   stamps `user_version = 14` and `application_id = 0x50414D31` (`PAM1`)
   together.
8. **Checkpoint** whenever the header does not already show the latest
   version, so the next open decides on a current header.
9. Retention of `pre-v*` backups; the read-only connection.

A second open of an upgraded file copies nothing and leaves the main file
byte-identical after open and close.

### Backups

```
<base>/backup/                              0700
  state-20261002T201010Z-pre-sqlite/        0700   never deleted by pam
    state.sqlite3                           0600
    state.sqlite3-wal                       0600   (each file that existed)
    state.sqlite3-shm
  state-20270114T093000Z-pre-v15/                  newest 3 kept
  .partial-state-…/                                a copy in progress
```

Plain copies of the main file, `-wal`, `-shm` and, for a database not in WAL
mode, `-journal`. Each file is synced, then the directory, then the directory
is renamed from `.partial-…`: a final name is always a complete copy. Never
overwritten; a second backup in the same second gets `-2`, `-3`. An existing
backup of the same kind whose content files equal the current ones byte for
byte is reused, so a restart loop against a refused database does not fill the
disk. `pre-v*` copies are pruned to the newest three after a successful
migration; `pre-sqlite` is never pruned. Restore: stop the daemon, copy the
directory's files over the ones beside `backup/` (removing a `-wal` or `-shm`
the backup lacks), start the PAM that wrote them. The copy is consistent when
nothing else is writing the database; the daemon holds its instance lock
first, but an operator's `sqlite3` shell is not excluded.

### Durability

`synchronous = FULL`, and on macOS `checkpoint_fullfsync = ON`. `fullfsync`
per commit was measured and left off:

| 2,000 commits, internal SSD, debug build | per commit |
| --- | --- |
| `fsync` (as built) | 0.201, 0.177, 0.179 ms |
| `F_FULLFSYNC` (`PRAGMA fullfsync = ON`) | 4.988, 5.217, 4.936 ms |

5 ms is two and a half times the 2 ms bar, and a request is at least three
commits. What that leaves: a process crash or `kill -9` loses nothing
(tested, with `Child::kill`). An operating-system crash or power cut can lose
the last commits the drive had accepted and not yet written; they disappear
whole and newest first, the database stays consistent, and boot recovery
closes a request left in its earlier state. Integrity does not depend on the
drive's cache, because checkpoints use `F_FULLFSYNC`. On Windows
`synchronous = FULL` is `FlushFileBuffers`, which does ask the drive to flush.
The power-loss case cannot be tested from user space.

### Close, drop, shutdown

`Store::close` closes the reader, waits for the writer's running job, runs
`wal_checkpoint(TRUNCATE)`, and closes: the main file is then the whole
database. Later calls answer `Closed`. Idempotent. If another connection is
mid-read the log stays, a warning is logged, nothing is lost. Dropping a
store checkpoints nothing and writes nothing; nothing relies on it doing so
(tests that read a store after dropping it reopen it through `Store::open`).

`DaemonHandle::shutdown`: join the daemon's tasks, shut both listeners,
`ModelService::shutdown` (cancel running downloads and verifications, wait up
to five seconds for their followers to record the job rows, stop the
idle-unload ticker; a follower that does not stop in time is logged and
left), then `Store::close`. A terminal write that meets the closed store is
not retried and not parked.

The timeout audit (32 sites in `pam_daemon`) found no write that is unsafe to
have landed after its caller gave up; no daemon code needed changing for it.
The site-by-site table is T5's deliverable and goes in the pull request.

### Queue bound

1,024 calls per connection, waiting plus running; the next one is refused
before it queues and writes nothing. The daemon admits at most 200 requests
at once and runs about a dozen service loops, so about 200 waiters is the
healthy maximum; five times that is reached only against a disk that is not
answering. `close` takes no slot. On the public plane the refusal is
`store_overloaded` (retryable, the store's sentence as detail, "Retry
shortly."); a call that meets the closed store is `daemon_shutting_down`
(retryable). The admin plane passes the store's sentence through in the
refusal's detail. Capabilities that already give a store failure a cause of
their own (`evidence_store_unavailable`, the `query` non-disclosure answer,
`execution_failed` from `cancel`, the request budget's persistence error)
keep it.

### Read connection

File-backed stores open a second connection: read-only, `query_only = ON`,
the same hardening, its own gate and queue bound. In-memory stores keep one.
`Store::read` runs its job as one deferred read transaction, which sees every
write whose call had returned.

| Read | Connection | Why |
| --- | --- | --- |
| `list_requests_filtered` (Activity) | reader | the review's head-of-line query |
| `audit_for_request` | reader | list |
| `read_evidence_view_range`, the page bytes | reader | reads the one or two 64 KiB chunks the page covers and checks their digests (schema 20; before it, SQLite loaded the whole view, up to 64 MiB, to cut one page) |
| `read_evidence_view_range`, the charge | writer | it is a write, and must survive the read failing |
| `retention_census` | reader | five counts over two tables, one snapshot |
| `check_integrity` | reader | reads every page |
| `get_evidence`, `list_evidence` | reader | blobs up to 64 MiB; list |
| `compression_stats` | reader | scan plus JSON parsing in Rust |
| `list_model_jobs`, `list_callers` | reader | lists |
| `list_grants`, `active_grant`, `request_authorization_current`, `evidence_view_meta`, `get_request`, settings, recovery pages, everything else | writer | authorization reads, cheap point reads, or reads whose job also writes |

### Schemas 19 and 20: the review's store leftovers

ptrack task 228 closed what the 2026-10 design review left of store findings
7, 9 and 13 (`docs/reviews/design-review-2026-10-02.md`).

**One terminal audit row per request (19).** `audit.terminal` is 1 on the
row the terminal writer (`finish_request_in_txn`, under `finish_request`,
`fail_expired_requests` and `finish_request_with_grant_change`) writes with
the terminal state, 0 on every other row, and the partial unique index
`audit_terminal_once ON audit (request_id) WHERE terminal = 1` admits one per
request. The flag is not derived from the action: `admin` and `policy.load`
are a terminal row on one request and ordinary rows on another (the managed
policy's daemon-owned request carries several `policy.*` rows before its
finish), and the daemon's `TERMINAL_ACTIONS` list stays the invariant
query's business. The insert is `ON CONFLICT (request_id) WHERE terminal = 1
DO NOTHING`: a request that somehow already has its terminal row (moved back
out of a terminal state by hand) keeps it, the write still finishes the
request, and a warning is logged. Rows from before 19 read 0; a request that
was terminal then can never be finished again, so the index covers every
terminal write from 19 on.

**Views reference their evidence; bytes in chunks (20).** `evidence_view` is
rebuilt with `source_id TEXT REFERENCES evidence(id) ON DELETE SET NULL`,
which is `evidence_id` while the evidence row exists and NULL after, and the
CHECK `source_id IS NOT NULL OR expired_at IS NOT NULL`: a live view without
its evidence cannot be represented, so a deletion of evidence whose view was
not tombstoned first fails instead of leaving a dangling view. `view_blob` is
gone; the bytes live in `evidence_view_chunk (evidence_id, seq, sha256,
bytes)`, 64 KiB per chunk (the view records its `chunk_bytes`), each with the
SHA-256 of its bytes. Triggers: chunks are never updated; a live view's
chunks are never deleted (a request prune deletes the view row, and the
chunks go by cascade); a chunk is inserted only for a live view; tombstoning
a view (`expired_at` set) deletes its chunks; a tombstone is final;
`source_id` only ever changes to NULL. Retention's evidence pass is therefore
`UPDATE ... SET expired_at` (the trigger drops the chunks) and then the
`DELETE` of the evidence, in that order, in one batch transaction.

The chunk size is the largest page, so a page touches at most two chunks
and the default 16 KiB page touches one. A read loads only those, checks
each chunk's length and digest, and answers `EvidenceRangeOutcome::Corrupt`
when one is missing, short, or does not hash to its digest; the daemon
refuses it as `evidence_corrupt` (recovery: re-run the flow, restore the
newest backup if more views fail). The whole-view `view_sha256`, the offset
basis and every other part of the retrieval contract are unchanged. 64 KiB
rather than 256 KiB: a 256 KiB chunk would load and hash 16 times the bytes
of a default page.

The migration's Rust half (`view_chunks::migrate_v20`, a new optional
`code` step of a migration, run after its SQL in the same transaction):
every view still live gets its chunks from its old blob when the blob has
the recorded length and hashes to `view_sha256`. A live view whose evidence
row was missing is tombstoned and reported in an `evidence.view_orphaned`
audit row; a live view whose bytes do not match keeps its row, gets no
chunks (its reads refuse as corrupt) and is reported as
`evidence.view_corrupt`. No view row is dropped. None of the three turso
fixtures has either kind; their recorded reads are unchanged.

Measured, a 64 KiB page of a 32 MiB view on a file-backed store, median of
20 reads at offsets 0, 16 MiB and 32 MiB − 64 KiB (`tests/view_page_read.rs`,
`--ignored`), including the charge on the writer:

| Build | Before (one blob) | After (chunks) |
| --- | --- | --- |
| release | 3.77, 3.77, 3.84 ms | 0.18, 0.17, 0.16 ms |
| debug | 3.80, 4.27, 4.58 ms | 2.72, 2.34, 2.38 ms (unoptimised SHA-256 of the chunk dominates) |

Inserting the 32 MiB view went from 0.18 s to 0.27 s (release), the cost of
hashing each chunk as well as the whole view, done before the connection is
taken.

**Journal before checkpoint (store 13).** The daemon files a protected
checkpoint (`flow.checkpoint` evidence) only in the transaction that writes
the journal row naming it: `begin_flow_journal_with_checkpoint` (insert the
journal, then the first checkpoint, only when the row was inserted) and
`settle_flow_attempt_with_checkpoint` (settle the prepared attempt, then the
checkpoint, only when the settlement applied). The old order could leave a
journal naming a checkpoint that was never filed (an unrecoverable journal)
or, at a settlement, a checkpoint no journal names. A test-only fault
(`CRASH_BETWEEN_JOURNAL_AND_CHECKPOINT`) fails the transaction between the
two statements and shows that neither is left. Boot recovery
(`recover_stuck_rows`) first runs `Store::close_orphan_flow_checkpoints`:
each `flow.checkpoint` row whose request has no journal (no reader can reach
it) is deleted with a `flow.checkpoint_orphaned` audit row on its request
(evidence id, size, digest, when it was filed), in batches of 64, oldest
first; a second boot finds nothing. A legacy settlement crash's checkpoint
(the request has a journal) cannot be told apart from a superseded one and
is left to retention, as superseded checkpoints are; the journal it belongs
to is `prepared`, which recovery already reports or redoes.

Upgrade tests: `migrations_test::v18_database_moves_views_into_chunks_and_reports_what_it_cannot_move`
(a schema-18 file with a live, an orphaned, a tombstoned, a mismatched and
an empty view, and audit rows from before the flag). The on-demand-check
test in `tests/store_upgrade.rs` now finds the page it damages in the
upgraded file (the last page in the middle of an overflow chain), because
migration 20 rewrote the page it used to name.

### Deviations and what is open

- A foreign database at version 0 is still migrated, as before; only version
  14 or later without PAM's `application_id` is refused.
- The future-migration backup (`pre-v<N>`) is tested with a stand-in later
  binary, since no migration 15 exists.
- Not verified: anything on Windows (T6, and the `cfg(not(unix))` branches of
  the backup and open code, which were read and not built); the released
  0.4.3 binary against an upgraded file (the downgrade refusal is tested with
  the same migration runner handed a shorter list); a real `~/.pam` (T8).
- One window rests on an assumption: a daemon killed between migration 14's
  commit and the checkpoint leaves header 13 with 14 only in a SQLite-written
  log, which an old binary refuses only if it replays that log.
- The memento rule `turso-connection-concurrent-use` is still to be replaced
  through the ledger.
