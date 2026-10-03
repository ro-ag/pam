//! The open path's decisions about a database that is not at this binary's
//! schema version: which backup it makes, what a header that lags the log
//! changes, what an older binary and a later one do with the same file.
//!
//! A "later binary" is this one handed a longer migration list; an "older
//! binary" is this one handed a shorter one. The fixtures written by the
//! previous engine are exercised in `tests/store_upgrade.rs`.

use std::path::{Path, PathBuf};

use rusqlite::Connection;
use rusqlite::config::DbConfig;

use crate::migrations::{self, MIGRATIONS, Migration};
use crate::open::{self, Opened, Target};
use crate::{Store, StoreError};

/// The migrations of a binary `extra` schema versions past this one. Each
/// added migration creates one table, so its having run can be seen.
fn later_binary(extra: i64) -> Vec<Migration> {
    const LATER: [&str; 5] = [
        "CREATE TABLE later_1 (x INTEGER);",
        "CREATE TABLE later_2 (x INTEGER);",
        "CREATE TABLE later_3 (x INTEGER);",
        "CREATE TABLE later_4 (x INTEGER);",
        "CREATE TABLE later_5 (x INTEGER);",
    ];
    let latest = migrations::latest_version();
    let mut known: Vec<Migration> = MIGRATIONS
        .iter()
        .map(|migration| Migration {
            version: migration.version,
            sql: migration.sql,
        })
        .collect();
    for (step, sql) in (1..=extra).zip(LATER) {
        known.push(Migration {
            version: latest + step,
            sql,
        });
    }
    known
}

fn target(path: &Path) -> Target {
    Target::File {
        path: path.to_str().unwrap().to_owned(),
        check: true,
    }
}

/// Opens as `known` would and closes in good order.
fn open_and_close(path: &Path, known: &[Migration]) -> Result<i64, StoreError> {
    let Opened { writer, reader } = open::open_with(&target(path), known)?;
    let version = migrations::current_version(&writer)?;
    if let Some(reader) = reader {
        open::shut(reader, false)?;
    }
    open::shut(writer, true)?;
    Ok(version)
}

/// The `user_version` field of the main file's header, read as bytes.
fn header_version(path: &Path) -> i64 {
    let bytes = std::fs::read(path).unwrap();
    i64::from(i32::from_be_bytes(bytes[60..64].try_into().unwrap()))
}

fn backups(path: &Path) -> Vec<String> {
    let root = path.parent().unwrap().join("backup");
    let Ok(entries) = std::fs::read_dir(root) else {
        return Vec::new();
    };
    let mut names: Vec<String> = entries
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    names
}

fn backup_dir(path: &Path, name: &str) -> PathBuf {
    path.parent().unwrap().join("backup").join(name)
}

/// The label after the timestamp: `pre-sqlite`, `pre-v17`, ...
fn labels(path: &Path) -> Vec<String> {
    backups(path)
        .iter()
        .map(|name| name["state-20261002T120000Z-".len()..].to_owned())
        .collect()
}

/// A database as a pre-boundary pam left it: the first `upto` migrations,
/// stamped, with one row, in WAL mode and fully checkpointed.
fn build_pre_boundary(path: &Path, upto: usize) {
    let conn = Connection::open(path).unwrap();
    conn.pragma_update(None, "journal_mode", "WAL").unwrap();
    for migration in &MIGRATIONS[..upto] {
        conn.execute_batch(migration.sql).unwrap();
    }
    conn.execute_batch(&format!("PRAGMA user_version = {upto}"))
        .unwrap();
    conn.execute(
        "INSERT INTO setting (key, value) VALUES ('kept', 'yes')",
        (),
    )
    .unwrap();
}

#[test]
fn a_new_database_is_stamped_in_its_header_and_needs_no_backup() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.sqlite3");
    let opened = open::open(&target(&path)).unwrap();
    // Readable from the file itself while the store is still open: the
    // open folded its own migrations into the main file.
    assert_eq!(header_version(&path), migrations::latest_version());
    let bytes = std::fs::read(&path).unwrap();
    assert_eq!(&bytes[68..72], b"PAM1");
    assert_eq!(
        migrations::application_id(&opened.writer).unwrap(),
        migrations::APPLICATION_ID
    );
    assert!(backups(&path).is_empty());
    drop(opened);

    // Nor does any later open of it.
    assert_eq!(
        open_and_close(&path, MIGRATIONS).unwrap(),
        migrations::latest_version()
    );
    assert!(backups(&path).is_empty());
}

#[test]
fn the_boundary_is_above_every_schema_the_previous_engine_wrote() {
    // Release 0.4.3 knows schema 11; the last development build on the
    // previous engine knew 13. The boundary migration is the next one, and
    // it is the newest this binary has: nothing sits between the engines.
    assert_eq!(migrations::ENGINE_BOUNDARY, 14);
    assert!(
        MIGRATIONS
            .iter()
            .any(|migration| migration.version == migrations::ENGINE_BOUNDARY)
    );
    assert_eq!(migrations::APPLICATION_ID.to_be_bytes()[4..], *b"PAM1");
}

#[test]
fn a_pre_boundary_database_gets_the_one_time_backup_and_a_later_migration_its_own() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.sqlite3");
    build_pre_boundary(&path, 13);
    let as_found = std::fs::read(&path).unwrap();

    // This binary: across the engine boundary to its latest version, with
    // the one pre-engine copy.
    assert_eq!(open_and_close(&path, MIGRATIONS).unwrap(), 16);
    assert_eq!(labels(&path), ["pre-sqlite"]);
    assert_eq!(
        std::fs::read(backup_dir(&path, &backups(&path)[0]).join("state.sqlite3")).unwrap(),
        as_found
    );
    assert_eq!(header_version(&path), 16);

    // A later binary with one more migration: a migration backup of the
    // database as this binary left it.
    let before_17 = std::fs::read(&path).unwrap();
    assert_eq!(open_and_close(&path, &later_binary(1)).unwrap(), 17);
    assert_eq!(labels(&path), ["pre-sqlite", "pre-v17"]);
    let migration_backup = backup_dir(&path, &backups(&path)[1]);
    assert_eq!(
        std::fs::read(migration_backup.join("state.sqlite3")).unwrap(),
        before_17
    );
    assert_eq!(header_version(&path), 17);

    // The same binary again: nothing pending, nothing copied.
    assert_eq!(open_and_close(&path, &later_binary(1)).unwrap(), 17);
    assert_eq!(labels(&path), ["pre-sqlite", "pre-v17"]);

    // The row survived both upgrades.
    let conn = Connection::open(&path).unwrap();
    let kept: String = conn
        .query_row("SELECT value FROM setting WHERE key = 'kept'", (), |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(kept, "yes");
}

#[test]
fn migration_backups_are_bounded_and_the_pre_engine_one_is_kept() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.sqlite3");
    build_pre_boundary(&path, 11);
    open_and_close(&path, MIGRATIONS).unwrap();
    // Five later binaries, one schema version apart.
    for extra in 1..=5 {
        assert_eq!(
            open_and_close(&path, &later_binary(extra)).unwrap(),
            16 + extra
        );
    }
    assert_eq!(
        labels(&path),
        ["pre-sqlite", "pre-v19", "pre-v20", "pre-v21"]
    );
}

#[test]
fn an_older_binary_refuses_a_later_database_and_touches_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.sqlite3");
    open_and_close(&path, &later_binary(2)).unwrap();
    let main = std::fs::read(&path).unwrap();

    // This binary, then two stand-ins for binaries on the previous engine's
    // schema versions: each knows less than the file records.
    for known in [MIGRATIONS, &MIGRATIONS[..13], &MIGRATIONS[..11]] {
        let supported = known.last().unwrap().version;
        let error = open_and_close(&path, known).unwrap_err();
        assert!(
            matches!(error, StoreError::VersionTooNew { found: 18, supported: s } if s == supported),
            "{error:?}"
        );
        let text = error.to_string();
        assert!(text.contains("newer than this binary supports"), "{text}");
        assert!(
            text.contains("upgrade pam instead of downgrading the database"),
            "{text}"
        );
        assert_eq!(std::fs::read(&path).unwrap(), main);
        assert!(backups(&path).is_empty(), "{:?}", backups(&path));
    }
}

/// A database whose newest version was committed and never checkpointed:
/// the main file's header still shows the old one.
fn leave_the_stamp_in_the_log(path: &Path, sql: &str, version: i64) {
    let conn = Connection::open(path).unwrap();
    conn.set_db_config(DbConfig::SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE, true)
        .unwrap();
    conn.execute_batch(&format!(
        "BEGIN; {sql} PRAGMA user_version = {version}; COMMIT;"
    ))
    .unwrap();
}

#[test]
fn a_header_that_lags_the_log_leaves_no_mislabelled_backup() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.sqlite3");
    // Schema 13 in the main file; the boundary migration and the two after
    // it only in the log, as a daemon killed between their commit and the
    // checkpoint leaves it.
    build_pre_boundary(&path, 13);
    let past_the_boundary = format!(
        "{}{}{}",
        MIGRATIONS[13].sql, MIGRATIONS[14].sql, MIGRATIONS[15].sql
    );
    leave_the_stamp_in_the_log(&path, &past_the_boundary, 16);
    assert_eq!(header_version(&path), 13);

    // The header says "pre-engine", the log says "already upgraded": the
    // copy made on the header's word is not a pre-engine database and does
    // not stay under that name.
    assert_eq!(open_and_close(&path, MIGRATIONS).unwrap(), 16);
    assert!(backups(&path).is_empty(), "{:?}", backups(&path));
    // And the header has caught up, so the next open does not even copy.
    assert_eq!(header_version(&path), 16);

    // The same one migration later: header 16, log 17.
    leave_the_stamp_in_the_log(&path, "CREATE TABLE later_1 (x INTEGER);", 17);
    assert_eq!(header_version(&path), 16);
    assert_eq!(open_and_close(&path, &later_binary(1)).unwrap(), 17);
    assert!(backups(&path).is_empty(), "{:?}", backups(&path));
    assert_eq!(header_version(&path), 17);

    // A header that lags a log which is itself behind: 17 on disk says the
    // header, 18 says the log, and the binary knows 19. One migration is
    // really pending, and its backup carries the right label.
    leave_the_stamp_in_the_log(&path, "CREATE TABLE later_2 (x INTEGER);", 18);
    assert_eq!(open_and_close(&path, &later_binary(3)).unwrap(), 19);
    assert_eq!(labels(&path), ["pre-v19"]);
}

#[test]
fn a_failed_migration_leaves_the_database_at_its_version_and_keeps_the_backup() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.sqlite3");
    open_and_close(&path, MIGRATIONS).unwrap();
    let before = std::fs::read(&path).unwrap();

    let mut broken = later_binary(1);
    // A migration that cannot apply: the table exists.
    broken.push(Migration {
        version: 18,
        sql: "CREATE TABLE later_1 (y INTEGER);",
    });
    let error = open_and_close(&path, &broken).unwrap_err();
    assert!(error.to_string().contains("already exists"), "{error}");

    // Migration 17 committed, 18 did not, and the copy from before both is
    // there to go back to.
    let conn = Connection::open(&path).unwrap();
    let version: i64 = conn
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .unwrap();
    assert_eq!(version, 17);
    drop(conn);
    assert_eq!(labels(&path), ["pre-v18"]);
    assert_eq!(
        std::fs::read(backup_dir(&path, &backups(&path)[0]).join("state.sqlite3")).unwrap(),
        before
    );
}

#[tokio::test]
async fn a_database_from_pams_version_range_without_pams_mark_is_refused_unchanged() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.sqlite3");
    {
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch(
            "CREATE TABLE theirs (note TEXT); INSERT INTO theirs VALUES ('x');
             PRAGMA user_version = 14;",
        )
        .unwrap();
    }
    let before = std::fs::read(&path).unwrap();

    let error = Store::open(&path).await.unwrap_err();
    assert!(
        matches!(
            error,
            StoreError::NotPamDatabase {
                found: 0,
                expected: migrations::APPLICATION_ID
            }
        ),
        "{error:?}"
    );
    let text = error.to_string();
    assert!(text.contains("pam did not write"), "{text}");
    assert!(text.contains("not changed"), "{text}");
    assert_eq!(std::fs::read(&path).unwrap(), before);
    assert!(backups(&path).is_empty());
}

#[tokio::test]
async fn a_file_shorter_than_a_header_is_refused_unchanged() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.sqlite3");
    std::fs::write(&path, b"SQLite format 3\0 and then nothing").unwrap();

    match Store::open(&path).await {
        Err(StoreError::Corrupt { detail }) => {
            assert!(
                detail.contains("shorter than a database header"),
                "{detail}"
            );
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(
        std::fs::read(&path).unwrap(),
        b"SQLite format 3\0 and then nothing"
    );
    assert!(!dir.path().join("state.sqlite3-shm").exists());
}
