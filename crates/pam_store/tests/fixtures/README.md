# Store database fixtures

Database files written by one engine and kept so another can be shown to read
them the same way. Tests copy a fixture to a temporary directory before
opening it; nothing opens these files in place.

## `turso-0.7/`

Written once by turso 0.7.2 (the `turso_core` the workspace vendored at the
time), with `crates/pam_store/src` as of commit
`ac1859fed63bdde3d411566b0ab56fa13fcd75ad` (schema 13). The generator that
wrote them, a test file named `store_fixtures_generate.rs`, named turso's
types; it was deleted when the store moved to SQLite and the engine left the
workspace, so it is not in the tree and cannot be run. These files are
therefore history: the record of what turso wrote and of what turso read back
from it. They are never regenerated and never edited. The `.gitattributes`
in this directory marks them binary so no checkout rewrites a byte, and each
`expected.json` carries the size and SHA-256 of its database files, which the
oracle test checks before it opens anything.

| Directory | Schema | Written through | Files |
| --- | --- | --- | --- |
| `v13-full` | 13 | the public `Store` API | main file after the engine's own `wal_checkpoint(TRUNCATE)`; the log is empty |
| `v13-wal` | 13 | the public `Store` API | main file as of a checkpoint, plus a log holding later commits (six requests and a change to each older kind of row), copied while the store was open and idle |
| `v11` | 11 (release 0.4.3) | a raw turso connection: migrations 1 to 11 from `src/migrations.rs`, rows with release 0.4.3's statements | main file as of a checkpoint, plus a log holding later commits |

turso writes no `-shm` file, so there is none.

Each directory has an `expected.json`:

- `files`: size and SHA-256 of each database file. A test fails if a committed
  file is not the one the record was made from.
- `probes`: the keys the store cannot enumerate (settings, evidence views) and
  the clocks its time-dependent reads are given.
- `variants.as_written`: the files as captured. `variants.main_only`: the main
  file without its log, which is an older, consistent database.
- `variants.*.public`: every row the store's public read API returned, table
  by table, read by turso when the fixture was generated. Each table says how
  it was read (`read_via`) and what the API cannot show (`not_readable`).
- `variants.*.raw`: what the engine itself read: schema version, page and
  free-page counts, schema objects, and per table the row count and one short
  digest per row. `rows_sql` is the statement that renders the rows, so any
  engine can be asked the same question of the same file.

Timestamps the store stamps itself (`created_ts`, `ts`, `granted_ts`, ...) are
the wall clock of the generating run in the two schema-13 fixtures; the store
has no clock to inject. Everything else is fixed, and `v11` is fixed
throughout.

## Tests

Every test copies a fixture to a temporary directory and opens the copy.

`crates/pam_store/tests/store_fixtures.rs` is the oracle test, public `Store`
API only. The store that opens the copy now runs on SQLite, and the record it
is held to was written by turso, so agreement is the proof that the two
engines read the same rows from the same files:

- every fixture is opened as written (`as_written`) and, where it has a log,
  without it (`main_only`); the open upgrades the copy to the current schema,
  and every public read must then equal that variant's `public`, row for row,
  including the rows that exist only in the log;
- every table of every fixture must have a recorded digest in `raw`, so a
  table cannot be left out of the comparison unnoticed;
- with `PAM_STORE_FIXTURES_SQLITE3=1` (or the path of a `sqlite3` binary), the
  SQLite shell reads a copy of every fixture and must agree with `raw`, then
  checks a copy the store has opened and migrated.

`crates/pam_store/tests/store_upgrade.rs` uses the same files for the first
open after the engine change: the backup, the full check, the schema stamp,
and each way that open is refused. `crates/pam_daemon/tests/store_lifecycle.rs`
boots a daemon on `v11`.

## Not regenerated

There is no command that rewrites these files. A new fixture for a later
schema is written by the store as it is then, into a directory of its own
beside `turso-0.7/`, with its own record; these stay as they are.
