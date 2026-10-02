# Store database fixtures

Database files written by one engine and kept so another can be shown to read
them the same way. Tests copy a fixture to a temporary directory before
opening it; nothing opens these files in place.

## `turso-0.7/`

Written by turso 0.7.2 (the workspace's vendored `turso_core`), with
`crates/pam_store/src` as of commit `ac1859fed63bdde3d411566b0ab56fa13fcd75ad`
(schema 13), by `crates/pam_store/tests/store_fixtures_generate.rs`.

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

`crates/pam_store/tests/store_fixtures.rs`, public `Store` API only:

- by default, every fixture and variant is opened with the store and its
  public reads must equal `public`;
- with `PAM_STORE_FIXTURES_SQLITE3=1` (or the path of a `sqlite3` binary), the
  SQLite shell reads a copy of every fixture and must agree with `raw`, then
  checks a copy the store has opened and migrated.

## Regenerating

```
PAM_REGENERATE_STORE_FIXTURES=1 cargo test -p pam_store --test store_fixtures_generate
```

This rewrites the files above. It is possible only while the store runs on
turso: the generator names turso types and is deleted with the engine. From
then on these files are the record of what turso wrote and are not
regenerated.
