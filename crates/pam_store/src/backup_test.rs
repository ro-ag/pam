//! The backup directory: what a copy holds, when one is reused, what
//! retention removes, and what is never touched.

use std::path::{Path, PathBuf};
use std::time::{Duration, UNIX_EPOCH};

use crate::StoreError;
use crate::backup::{self, Kind};

/// A stand-in database: a main file and a log with the given bytes.
fn write_database(dir: &Path, main: &[u8], log: Option<&[u8]>) -> PathBuf {
    let state = dir.join("state.sqlite3");
    std::fs::write(&state, main).unwrap();
    let log_path = dir.join("state.sqlite3-wal");
    match log {
        Some(bytes) => std::fs::write(&log_path, bytes).unwrap(),
        None => {
            let _ = std::fs::remove_file(&log_path);
        }
    }
    state
}

fn entries(root: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(root)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    names
}

#[test]
fn the_stamp_is_utc_calendar_time() {
    let at = |seconds: u64| backup::utc_stamp(UNIX_EPOCH + Duration::from_secs(seconds));
    assert_eq!(at(0), "19700101T000000Z");
    // The last second of a leap day, and the first of the day after.
    assert_eq!(at(951_868_799), "20000229T235959Z");
    assert_eq!(at(951_868_800), "20000301T000000Z");
    assert_eq!(at(1_790_944_201), "20261002T123001Z");
    // A century year that is not a leap year.
    assert_eq!(at(4_107_542_400), "21000301T000000Z");
}

#[test]
fn a_backup_holds_every_database_file_and_only_those() {
    let dir = tempfile::tempdir().unwrap();
    let state = write_database(dir.path(), b"main", Some(b"log"));
    std::fs::write(dir.path().join("state.sqlite3-shm"), b"index").unwrap();
    std::fs::write(dir.path().join("state.sqlite3-journal"), b"journal").unwrap();
    std::fs::write(dir.path().join("unrelated.txt"), b"not ours").unwrap();

    let made = backup::take(&state, Kind::PreSqlite).unwrap();
    assert!(made.created);
    assert_eq!(made.dir.parent().unwrap(), dir.path().join("backup"));
    assert_eq!(
        entries(&made.dir),
        [
            "state.sqlite3",
            "state.sqlite3-journal",
            "state.sqlite3-shm",
            "state.sqlite3-wal"
        ]
    );
    for (name, bytes) in [
        ("state.sqlite3", &b"main"[..]),
        ("state.sqlite3-wal", b"log"),
        ("state.sqlite3-shm", b"index"),
        ("state.sqlite3-journal", b"journal"),
    ] {
        assert_eq!(std::fs::read(made.dir.join(name)).unwrap(), bytes);
    }
    // Nothing unfinished is left beside it.
    assert_eq!(entries(&dir.path().join("backup")).len(), 1);
}

#[test]
fn an_identical_backup_is_reused_and_a_changed_database_gets_its_own() {
    let dir = tempfile::tempdir().unwrap();
    let state = write_database(dir.path(), b"main", Some(b"log"));
    let first = backup::take(&state, Kind::PreSqlite).unwrap();

    // The same files again, with a rebuilt index beside them: the index is
    // not content.
    std::fs::write(dir.path().join("state.sqlite3-shm"), b"rebuilt").unwrap();
    let again = backup::take(&state, Kind::PreSqlite).unwrap();
    assert!(!again.created);
    assert_eq!(again.dir, first.dir);
    assert_eq!(entries(&dir.path().join("backup")).len(), 1);

    // A different kind is a different backup, even of the same bytes.
    let migration = backup::take(&state, Kind::PreSchema(15)).unwrap();
    assert!(migration.created);
    assert_ne!(migration.dir, first.dir);

    // Changed content, in the main file or only in the log, is copied anew
    // and the earlier copies are left exactly as they were.
    write_database(dir.path(), b"main", Some(b"log, longer"));
    let changed_log = backup::take(&state, Kind::PreSqlite).unwrap();
    assert!(changed_log.created);
    write_database(dir.path(), b"MAIN", Some(b"log, longer"));
    let changed_main = backup::take(&state, Kind::PreSqlite).unwrap();
    assert!(changed_main.created);
    // A log that is gone is a change too.
    write_database(dir.path(), b"MAIN", None);
    let no_log = backup::take(&state, Kind::PreSqlite).unwrap();
    assert!(no_log.created);
    assert!(!no_log.dir.join("state.sqlite3-wal").exists());

    assert_eq!(entries(&dir.path().join("backup")).len(), 5);
    assert_eq!(
        std::fs::read(first.dir.join("state.sqlite3")).unwrap(),
        b"main"
    );
    assert_eq!(
        std::fs::read(first.dir.join("state.sqlite3-wal")).unwrap(),
        b"log"
    );
    // Made within the same second, so the names differ by their serial and
    // none replaced another.
    let dirs = [
        first.dir,
        migration.dir,
        changed_log.dir,
        changed_main.dir,
        no_log.dir,
    ];
    for (index, dir) in dirs.iter().enumerate() {
        assert!(!dirs[..index].contains(dir));
    }
}

#[test]
fn retention_keeps_the_newest_migration_backups_and_every_pre_engine_one() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("backup");
    std::fs::create_dir(&root).unwrap();
    let made = |name: &str| {
        std::fs::create_dir(root.join(name)).unwrap();
        std::fs::write(root.join(name).join("state.sqlite3"), name).unwrap();
    };
    for name in [
        "state-20260101T000000Z-pre-sqlite",
        "state-20260102T000000Z-pre-sqlite",
        "state-20260201T000000Z-pre-v15",
        "state-20260301T000000Z-pre-v16",
        "state-20260301T000000Z-pre-v16-2",
        "state-20260401T000000Z-pre-v17",
        "state-20260501T000000Z-pre-v18",
        // Not names this module writes: never listed, never removed.
        "state-20260101T000000Z-by-hand",
        "state-2026-pre-v15",
        "notes",
    ] {
        made(name);
    }
    std::fs::write(root.join("state-20260101T000000Z-pre-v15"), b"a file").unwrap();

    backup::prune_migration_backups(&root);

    assert_eq!(backup::KEEP_MIGRATION_BACKUPS, 3);
    assert_eq!(
        entries(&root),
        [
            "notes",
            "state-2026-pre-v15",
            "state-20260101T000000Z-by-hand",
            "state-20260101T000000Z-pre-sqlite",
            "state-20260101T000000Z-pre-v15",
            "state-20260102T000000Z-pre-sqlite",
            "state-20260301T000000Z-pre-v16-2",
            "state-20260401T000000Z-pre-v17",
            "state-20260501T000000Z-pre-v18",
        ]
    );
    assert_eq!(
        backup::newest(&root).unwrap(),
        root.join("state-20260501T000000Z-pre-v18")
    );
}

#[test]
fn an_unfinished_copy_is_never_a_backup_and_is_cleared_by_the_next_one() {
    let dir = tempfile::tempdir().unwrap();
    let state = write_database(dir.path(), b"main", Some(b"log"));
    let root = dir.path().join("backup");
    // What a process killed half-way through a copy leaves.
    let partial = root.join(".partial-state-20260101T000000Z-pre-sqlite");
    std::fs::create_dir_all(&partial).unwrap();
    std::fs::write(partial.join("state.sqlite3"), b"ma").unwrap();
    assert_eq!(backup::newest(&root), None);

    let made = backup::take(&state, Kind::PreSqlite).unwrap();
    assert!(made.created);
    assert!(!partial.exists());
    assert_eq!(
        std::fs::read(made.dir.join("state.sqlite3")).unwrap(),
        b"main"
    );
}

#[test]
fn a_failed_copy_leaves_no_backup_and_names_the_space_it_needs() {
    let dir = tempfile::tempdir().unwrap();
    let state = write_database(dir.path(), b"main", Some(b"log"));
    let root = dir.path().join("backup");
    std::fs::write(&root, b"a file where the directory goes").unwrap();

    match backup::take(&state, Kind::PreSqlite) {
        Err(StoreError::UpgradeBackup {
            path, needed_bytes, ..
        }) => {
            assert_eq!(path, root);
            assert_eq!(needed_bytes, 7);
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(
        std::fs::read(&root).unwrap(),
        b"a file where the directory goes"
    );
    assert_eq!(std::fs::read(&state).unwrap(), b"main");
}

#[test]
fn discard_and_relabel_only_touch_a_backup_this_open_made() {
    let dir = tempfile::tempdir().unwrap();
    let state = write_database(dir.path(), b"main", None);
    let made = backup::take(&state, Kind::PreSqlite).unwrap();
    let found = backup::take(&state, Kind::PreSqlite).unwrap();
    assert!(!found.created);

    // Found, not made: stays, under its name.
    backup::discard(&found);
    assert!(found.dir.exists());
    let kept = backup::relabel(found.clone(), Kind::PreSchema(15));
    assert_eq!(kept, found);

    // Made: renamed to what it turned out to precede, then removable.
    let relabelled = backup::relabel(made.clone(), Kind::PreSchema(15));
    assert_eq!(relabelled.kind, Kind::PreSchema(15));
    assert!(!made.dir.exists());
    assert!(
        relabelled
            .dir
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .ends_with("-pre-v15")
    );
    assert_eq!(
        std::fs::read(relabelled.dir.join("state.sqlite3")).unwrap(),
        b"main"
    );
    backup::discard(&relabelled);
    assert!(!relabelled.dir.exists());
}

#[cfg(unix)]
#[test]
fn a_backup_is_readable_by_its_owner_only() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let state = write_database(dir.path(), b"main", Some(b"log"));
    // Whatever the source's mode, and whatever the process umask.
    std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o644)).unwrap();
    let copy = backup::take(&state, Kind::PreSqlite).unwrap();
    let mode = |path: &Path| std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(&dir.path().join("backup")), 0o700);
    assert_eq!(mode(&copy.dir), 0o700);
    assert_eq!(mode(&copy.dir.join("state.sqlite3")), 0o600);
    assert_eq!(mode(&copy.dir.join("state.sqlite3-wal")), 0o600);
}
