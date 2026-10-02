//! The first open of a database written by the previous engine, on the
//! committed fixtures: the backup, the checks, the boundary stamp, and every
//! way that open is refused.
//!
//! Real files in temporary directories, the public `Store` API, and plain
//! reads of the bytes on disk. Nothing here names the engine.

mod fixture_support;

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use fixture_support::{
    AS_WRITTEN, DATABASE, FIXTURES, MAIN_ONLY, copy_database, fixture_dir, load_expected,
};
use pam_store::{MAX_LIST_LIMIT, Store, StoreError};

/// `PAM1`: the application id the boundary migration stamps.
const APPLICATION_ID: u32 = 0x5041_4D31;

/// The schema version a database has once this binary has opened it.
async fn latest_schema() -> i64 {
    Store::open_in_memory()
        .await
        .unwrap()
        .schema_version()
        .await
        .unwrap()
}

/// A big-endian field of the database header, read from the file itself.
fn header_field(database: &Path, offset: usize) -> u32 {
    let bytes = std::fs::read(database).unwrap();
    u32::from_be_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

/// The backup directories beside `database`, by name.
fn backups(database: &Path) -> Vec<PathBuf> {
    let root = database.parent().unwrap().join("backup");
    let Ok(entries) = std::fs::read_dir(root) else {
        return Vec::new();
    };
    let mut found: Vec<PathBuf> = entries.map(|entry| entry.unwrap().path()).collect();
    found.sort();
    found
}

/// File names in `dir`, sorted.
fn names(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    names
}

/// Every database file of `dir` that exists, with its bytes.
fn database_files(dir: &Path) -> Vec<(String, Vec<u8>)> {
    ["", "-wal", "-shm"]
        .iter()
        .filter_map(|suffix| {
            let name = format!("{DATABASE}{suffix}");
            std::fs::read(dir.join(&name))
                .ok()
                .map(|bytes| (name, bytes))
        })
        .collect()
}

fn request_ids(expected: &serde_json::Value, variant: &str) -> BTreeSet<String> {
    expected["variants"][variant]["public"]["request"]["rows"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| row["id"].as_str().unwrap().to_owned())
        .collect()
}

async fn listed_ids(store: &Store) -> BTreeSet<String> {
    store
        .list_requests_filtered(Some(MAX_LIST_LIMIT), None, None, None, None, false)
        .await
        .unwrap()
        .into_iter()
        .map(|row| row.id)
        .collect()
}

/// `state-<YYYYMMDD>T<HHMMSS>Z-pre-sqlite`.
fn is_pre_engine_backup(dir: &Path) -> bool {
    let name = dir.file_name().unwrap().to_str().unwrap();
    let Some(rest) = name.strip_prefix("state-") else {
        return false;
    };
    rest.len() == "20261002T120000Z-pre-sqlite".len()
        && rest.ends_with("Z-pre-sqlite")
        && rest.as_bytes()[8] == b'T'
        && rest[..8].bytes().all(|byte| byte.is_ascii_digit())
        && rest[9..15].bytes().all(|byte| byte.is_ascii_digit())
}

fn corrupt_detail(result: Result<Store, StoreError>) -> String {
    match result {
        Err(StoreError::Corrupt { detail }) => detail,
        Err(other) => panic!("expected a corruption refusal, got: {other}"),
        Ok(_) => panic!("a damaged database was opened"),
    }
}

#[tokio::test]
async fn the_first_open_backs_up_every_file_checks_stamps_and_never_repeats() {
    let latest = latest_schema().await;
    for name in FIXTURES {
        let expected = load_expected(name);
        let original = database_files(&fixture_dir(name));
        let dir = tempfile::tempdir().unwrap();
        let path = copy_database(&fixture_dir(name), dir.path(), true);

        let store = Store::open(&path).await.unwrap();

        // One backup, holding every file exactly as the fixture has it.
        let made = backups(&path);
        assert_eq!(made.len(), 1, "{name}: {made:?}");
        assert!(is_pre_engine_backup(&made[0]), "{name}: {:?}", made[0]);
        assert_eq!(database_files(&made[0]), original, "{name}");
        assert_eq!(
            names(&made[0]),
            original
                .iter()
                .map(|(file, _)| file.clone())
                .collect::<Vec<_>>(),
            "{name}: the backup holds something else too"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let bits = |path: &Path| std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
            assert_eq!(bits(&made[0]), 0o700, "{name}");
            assert_eq!(bits(made[0].parent().unwrap()), 0o700, "{name}");
            for file in names(&made[0]) {
                assert_eq!(bits(&made[0].join(file)), 0o600, "{name}");
            }
        }

        // Upgraded, and every request is there: the ones only the log held
        // included.
        assert_eq!(store.schema_version().await.unwrap(), latest, "{name}");
        store.check_integrity().await.unwrap();
        assert_eq!(
            listed_ids(&store).await,
            request_ids(&expected, AS_WRITTEN),
            "{name}"
        );
        if expected["variants"].get(MAIN_ONLY).is_some() {
            let only_in_the_log: Vec<String> = request_ids(&expected, AS_WRITTEN)
                .difference(&request_ids(&expected, MAIN_ONLY))
                .cloned()
                .collect();
            assert_eq!(only_in_the_log.len(), 6, "{name}");
            for id in only_in_the_log {
                assert!(
                    store.get_request(&id).await.unwrap().is_some(),
                    "{name}: {id}"
                );
            }
        }

        // Closed: the main file alone is the database, stamped.
        store.close().await.unwrap();
        let log = dir.path().join(format!("{DATABASE}-wal"));
        assert_eq!(
            std::fs::metadata(&log).map_or(0, |meta| meta.len()),
            0,
            "{name}"
        );
        assert_eq!(i64::from(header_field(&path, 60)), latest, "{name}");
        assert_eq!(header_field(&path, 68), APPLICATION_ID, "{name}");

        // A second open has nothing to back up and changes no request.
        let main_before = std::fs::read(&path).unwrap();
        let store = Store::open(&path).await.unwrap();
        assert_eq!(
            backups(&path),
            made,
            "{name}: the second open made a backup"
        );
        assert_eq!(
            listed_ids(&store).await,
            request_ids(&expected, AS_WRITTEN),
            "{name}"
        );
        store.close().await.unwrap();
        assert_eq!(
            std::fs::read(&path).unwrap(),
            main_before,
            "{name}: an open and close with nothing to do rewrote the main file"
        );
    }
}

#[tokio::test]
async fn a_main_file_without_its_log_upgrades_to_the_older_database() {
    for name in ["v13-wal", "v11"] {
        let expected = load_expected(name);
        let dir = tempfile::tempdir().unwrap();
        let path = copy_database(&fixture_dir(name), dir.path(), false);
        let main = std::fs::read(&path).unwrap();

        let store = Store::open(&path).await.unwrap();
        assert_eq!(
            listed_ids(&store).await,
            request_ids(&expected, MAIN_ONLY),
            "{name}"
        );
        let made = backups(&path);
        assert_eq!(made.len(), 1, "{name}");
        assert_eq!(
            database_files(&made[0]),
            vec![(DATABASE.to_owned(), main)],
            "{name}"
        );
        store.close().await.unwrap();
    }
}

#[tokio::test]
async fn a_stale_log_index_is_backed_up_as_found_and_does_no_harm() {
    for name in ["v13-wal", "v11"] {
        let expected = load_expected(name);
        let dir = tempfile::tempdir().unwrap();
        let path = copy_database(&fixture_dir(name), dir.path(), true);
        // An index left by some earlier process, describing nothing.
        let stale = vec![0u8; 32 * 1024];
        std::fs::write(dir.path().join(format!("{DATABASE}-shm")), &stale).unwrap();
        let found = database_files(dir.path());
        assert_eq!(found.len(), 3);

        let store = Store::open(&path).await.unwrap();
        assert_eq!(
            listed_ids(&store).await,
            request_ids(&expected, AS_WRITTEN),
            "{name}"
        );
        let made = backups(&path);
        assert_eq!(made.len(), 1, "{name}");
        assert_eq!(database_files(&made[0]), found, "{name}");
        store.close().await.unwrap();
    }
}

/// Opens the damaged database at `path` twice and requires the same refusal
/// both times, the files untouched, and one backup holding them as found.
async fn refused_with_one_backup(name: &str, path: &Path) -> String {
    let dir = path.parent().unwrap();
    let log = dir.join(format!("{DATABASE}-wal"));
    let main_before = std::fs::read(path).unwrap();
    let log_before = std::fs::read(&log).ok();

    let detail = corrupt_detail(Store::open(path).await);
    let made = backups(path);
    assert_eq!(made.len(), 1, "{name}: {made:?}");
    assert!(is_pre_engine_backup(&made[0]), "{name}");
    // The refusal names the copy and says what to do with it.
    assert!(
        detail.contains(made[0].to_str().unwrap()),
        "{name}: {detail}"
    );
    for step in ["stop the daemon", "go back", "start empty", ".recover"] {
        assert!(detail.contains(step), "{name}: no {step:?} in: {detail}");
    }
    // Nothing of the database changed, and the copy is of what was found.
    assert_eq!(std::fs::read(path).unwrap(), main_before, "{name}");
    assert_eq!(std::fs::read(&log).ok(), log_before, "{name}");
    assert_eq!(
        std::fs::read(made[0].join(DATABASE)).unwrap(),
        main_before,
        "{name}"
    );
    assert_eq!(
        std::fs::read(made[0].join(format!("{DATABASE}-wal"))).ok(),
        log_before,
        "{name}"
    );

    // A service manager that restarts the daemon gets the same answer and
    // does not fill the disk with copies.
    let again = corrupt_detail(Store::open(path).await);
    assert_eq!(again, detail, "{name}");
    assert_eq!(backups(path), made, "{name}: a second copy was made");
    assert_eq!(std::fs::read(path).unwrap(), main_before, "{name}");
    assert_eq!(std::fs::read(&log).ok(), log_before, "{name}");
    detail
}

#[tokio::test]
async fn a_database_with_flipped_table_pages_is_refused_and_kept() {
    for name in FIXTURES {
        let dir = tempfile::tempdir().unwrap();
        let path = copy_database(&fixture_dir(name), dir.path(), true);
        // Every bit of every page after the first is flipped: the header
        // still names a database, the tables behind it are noise.
        let mut bytes = std::fs::read(&path).unwrap();
        for byte in &mut bytes[4096..] {
            *byte = !*byte;
        }
        std::fs::write(&path, &bytes).unwrap();

        let detail = refused_with_one_backup(name, &path).await;
        assert!(detail.contains("first open"), "{name}: {detail}");
    }
}

/// Flips every bit of one 4096-byte page of the database at `path`, in
/// place: the file is not truncated or replaced, so this also works on a
/// database a store has open.
fn flip_page(path: &Path, page: u64) {
    use std::io::{Read, Seek, SeekFrom, Write};

    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .unwrap();
    let start = SeekFrom::Start((page - 1) * 4096);
    let mut bytes = [0u8; 4096];
    file.seek(start).unwrap();
    file.read_exact(&mut bytes).unwrap();
    for byte in &mut bytes {
        *byte = !*byte;
    }
    file.seek(start).unwrap();
    file.write_all(&bytes).unwrap();
    file.sync_all().unwrap();
}

/// A page of the `v13-full` fixture that belongs to a table: with it damaged
/// the schema still loads, so the damage is found by the integrity check
/// itself rather than by the engine failing to read the file at all.
const A_TABLE_PAGE_OF_V13_FULL: u64 = 120;

#[tokio::test]
async fn one_damaged_table_page_is_found_by_the_first_open_integrity_check() {
    let dir = tempfile::tempdir().unwrap();
    let path = copy_database(&fixture_dir("v13-full"), dir.path(), true);
    flip_page(&path, A_TABLE_PAGE_OF_V13_FULL);

    let detail = refused_with_one_backup("v13-full", &path).await;
    // The checker's own finding, naming the tree and the page.
    assert!(detail.contains("Tree"), "{detail}");
    assert!(detail.contains("page"), "{detail}");
}

/// The branch nothing could reach before: a database that opened sound and
/// is found damaged afterwards, by the on-demand check.
#[tokio::test]
async fn damage_after_a_successful_open_is_found_by_the_on_demand_check() {
    let dir = tempfile::tempdir().unwrap();
    let path = copy_database(&fixture_dir("v13-full"), dir.path(), true);
    // Upgrade it and close, so every page is in the main file.
    Store::open(&path).await.unwrap().close().await.unwrap();

    // The open ran its own check and passed it.
    let store = Store::open(&path).await.unwrap();
    flip_page(&path, A_TABLE_PAGE_OF_V13_FULL);

    match store.check_integrity().await {
        Err(StoreError::Corrupt { detail }) => {
            assert!(detail.contains("page"), "{detail}");
        }
        other => panic!("the damaged page went unnoticed: {other:?}"),
    }
    // The verdict is repeatable and the store still answers.
    assert!(matches!(
        store.check_integrity().await,
        Err(StoreError::Corrupt { .. })
    ));
    assert_eq!(store.schema_version().await.unwrap(), latest_schema().await);
    drop(store);

    // And the next open refuses it, as an ordinary open does: no new copy
    // is made of a database that needs no upgrade, and the refusal points
    // at the one that exists.
    let detail = corrupt_detail(Store::open(&path).await);
    let made = backups(&path);
    assert_eq!(made.len(), 1);
    assert!(detail.contains(made[0].to_str().unwrap()), "{detail}");
}

#[tokio::test]
async fn a_truncated_database_is_refused_and_kept() {
    for name in FIXTURES {
        let dir = tempfile::tempdir().unwrap();
        let path = copy_database(&fixture_dir(name), dir.path(), true);
        let bytes = std::fs::read(&path).unwrap();
        // Cut inside a page, a third of the way in.
        std::fs::write(&path, &bytes[..bytes.len() / 3 + 100]).unwrap();

        refused_with_one_backup(name, &path).await;
    }
}

#[tokio::test]
async fn a_file_that_is_not_a_database_is_refused_before_any_copy() {
    let dir = tempfile::tempdir().unwrap();
    let path = copy_database(&fixture_dir("v13-wal"), dir.path(), true);
    let log = dir.path().join(format!("{DATABASE}-wal"));
    let log_before = std::fs::read(&log).unwrap();
    let garbage = b"not a database, just bytes somebody left here\n".repeat(500);
    std::fs::write(&path, &garbage).unwrap();

    let detail = corrupt_detail(Store::open(&path).await);
    assert!(detail.contains("not a database"), "{detail}");
    assert_eq!(std::fs::read(&path).unwrap(), garbage);
    assert_eq!(std::fs::read(&log).unwrap(), log_before);
    // The engine never opened it: no index file, and nothing to back up.
    assert!(!dir.path().join(format!("{DATABASE}-shm")).exists());
    assert!(backups(&path).is_empty());
}

#[tokio::test]
async fn a_log_without_its_main_file_is_refused() {
    for name in ["v13-wal", "v11"] {
        let dir = tempfile::tempdir().unwrap();
        let path = copy_database(&fixture_dir(name), dir.path(), true);
        let log = dir.path().join(format!("{DATABASE}-wal"));
        let log_before = std::fs::read(&log).unwrap();
        std::fs::write(&path, b"").unwrap();

        let detail = corrupt_detail(Store::open(&path).await);
        assert!(detail.contains("is empty"), "{name}: {detail}");
        assert!(detail.contains("write-ahead log"), "{name}: {detail}");
        assert_eq!(std::fs::metadata(&path).unwrap().len(), 0, "{name}");
        assert_eq!(std::fs::read(&log).unwrap(), log_before, "{name}");
        assert!(!dir.path().join(format!("{DATABASE}-shm")).exists());
        assert!(backups(&path).is_empty(), "{name}");

        // The same with the main file moved away and its log left behind:
        // opening that pair would create an empty database and throw the
        // log, with the moved database's newest commits, away.
        std::fs::remove_file(&path).unwrap();
        let detail = corrupt_detail(Store::open(&path).await);
        assert!(detail.contains("is missing"), "{name}: {detail}");
        assert!(!path.exists(), "{name}: a state file was created");
        assert_eq!(std::fs::read(&log).unwrap(), log_before, "{name}");

        // With the log moved away too, the directory starts empty.
        std::fs::remove_file(&log).unwrap();
        let store = Store::open(&path).await.unwrap();
        assert!(listed_ids(&store).await.is_empty(), "{name}");
        store.close().await.unwrap();
    }
}

/// A zero-length state file with no log, in a directory that holds nothing
/// else of pam's, has nothing to lose: it is opened as a new database. An
/// empty `log` directory is not a sign of an earlier pam either.
#[tokio::test]
async fn an_empty_file_in_a_directory_pam_never_used_is_a_new_database() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(DATABASE);
    std::fs::write(&path, b"").unwrap();
    std::fs::create_dir(dir.path().join("log")).unwrap();

    let store = Store::open(&path).await.unwrap();
    assert_eq!(store.schema_version().await.unwrap(), latest_schema().await);
    assert!(listed_ids(&store).await.is_empty());
    assert!(backups(&path).is_empty());
    store.close().await.unwrap();
}

/// Puts one thing a pam daemon leaves in its base directory into `base`.
fn leave_sign(base: &Path, sign: &str) {
    match sign {
        "log" => {
            std::fs::create_dir(base.join("log")).unwrap();
            std::fs::write(base.join("log/daemon.log"), b"a line\n").unwrap();
        }
        "run/daemon.lock" => {
            std::fs::create_dir(base.join("run")).unwrap();
            std::fs::write(base.join("run/daemon.lock"), b"4242\n").unwrap();
        }
        directory => std::fs::create_dir(base.join(directory)).unwrap(),
    }
}

const INSTALL_SIGNS: [&str; 5] = ["backup", "log", "run/daemon.lock", "flows", "model-trust"];

/// The same empty file where pam has run before is not a database pam
/// wrote: opening it as a new one would start the grants and the audit
/// history over without a word. Refused, with the way out, and untouched.
#[tokio::test]
async fn an_empty_state_file_where_pam_has_run_before_is_refused() {
    for sign in INSTALL_SIGNS {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(DATABASE);
        std::fs::write(&path, b"").unwrap();
        leave_sign(dir.path(), sign);
        let before = names(dir.path());

        let detail = corrupt_detail(Store::open(&path).await);
        for part in [
            "is empty",
            "used by pam before",
            "Nothing was changed",
            "stop the daemon",
            "move the empty file aside to start fresh",
        ] {
            assert!(detail.contains(part), "{sign}: no {part:?} in: {detail}");
        }
        let named = dir.path().join(sign);
        assert!(
            detail.contains(&named.display().to_string()),
            "{sign}: {detail}"
        );
        // No backup to point at, and the refusal says so instead of naming one.
        assert!(detail.contains("There is no backup"), "{sign}: {detail}");
        // The engine never opened it: nothing was created beside it.
        assert_eq!(std::fs::metadata(&path).unwrap().len(), 0, "{sign}");
        assert_eq!(names(dir.path()), before, "{sign}");

        // Refused again, the same way: a restart loop changes nothing.
        assert_eq!(corrupt_detail(Store::open(&path).await), detail, "{sign}");

        // The second way out: with the empty file moved aside, pam starts
        // fresh.
        std::fs::rename(&path, dir.path().join("state.sqlite3.empty")).unwrap();
        let store = Store::open(&path).await.unwrap();
        assert!(listed_ids(&store).await.is_empty(), "{sign}");
        store.close().await.unwrap();
    }
}

/// An install that was upgraded has a backup; when its state file is later
/// found empty the refusal names that backup, and restoring it works.
#[tokio::test]
async fn an_emptied_state_file_is_refused_with_the_backup_to_restore() {
    let dir = tempfile::tempdir().unwrap();
    let path = copy_database(&fixture_dir("v11"), dir.path(), true);
    let store = Store::open(&path).await.unwrap();
    let ids = listed_ids(&store).await;
    assert!(!ids.is_empty());
    store.close().await.unwrap();
    let made = backups(&path);
    assert_eq!(made.len(), 1);

    // Something truncated the state file while pam was stopped.
    std::fs::write(&path, b"").unwrap();
    let detail = corrupt_detail(Store::open(&path).await);
    assert!(detail.contains("is empty"), "{detail}");
    assert!(
        detail.contains(&format!(
            "restore the newest backup from {}",
            made[0].display()
        )),
        "{detail}"
    );
    assert!(detail.contains("move the empty file aside"), "{detail}");
    assert_eq!(std::fs::metadata(&path).unwrap().len(), 0);
    assert_eq!(
        backups(&path),
        made,
        "the refusal made no backup of nothing"
    );

    // The first way out, as the refusal words it: the backup's files over
    // the state file and beside it.
    for (name, bytes) in database_files(&made[0]) {
        std::fs::write(dir.path().join(name), bytes).unwrap();
    }
    let store = Store::open(&path).await.unwrap();
    assert_eq!(listed_ids(&store).await, ids);
    store.close().await.unwrap();
}

/// A state file that does not exist is a database about to be created,
/// whatever else is in the directory: the daemon has taken its lock and
/// started its log by the time it opens the store for the first time.
#[tokio::test]
async fn a_missing_state_file_is_a_new_database_where_the_daemon_has_prepared_its_base() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(DATABASE);
    for sign in INSTALL_SIGNS {
        leave_sign(dir.path(), sign);
    }

    let store = Store::open(&path).await.unwrap();
    assert_eq!(store.schema_version().await.unwrap(), latest_schema().await);
    assert!(listed_ids(&store).await.is_empty());
    assert!(backups(&path).is_empty());
    store.close().await.unwrap();
}

#[tokio::test]
async fn a_backup_that_cannot_be_written_refuses_the_open_untouched() {
    for name in ["v13-wal", "v11"] {
        let dir = tempfile::tempdir().unwrap();
        let path = copy_database(&fixture_dir(name), dir.path(), true);
        let before = database_files(dir.path());
        // Something that is not a directory sits where the backups go.
        let blocker = dir.path().join("backup");
        std::fs::write(&blocker, b"in the way").unwrap();

        match Store::open(&path).await {
            Err(StoreError::UpgradeBackup {
                path: refused,
                needed_bytes,
                ..
            }) => {
                assert_eq!(refused, blocker, "{name}");
                let size: usize = before.iter().map(|(_, bytes)| bytes.len()).sum();
                assert_eq!(needed_bytes, u64::try_from(size).unwrap(), "{name}");
            }
            Err(other) => panic!("{name}: expected a backup refusal, got: {other}"),
            Ok(_) => panic!("{name}: opened without a backup"),
        }
        // Not opened: the files are as they were and no index was created.
        assert_eq!(database_files(dir.path()), before, "{name}");
        assert_eq!(std::fs::read(&blocker).unwrap(), b"in the way");

        // The refusal says what happened and what to do, in words.
        let message = Store::open(&path).await.unwrap_err().to_string();
        for part in ["not opened", "unchanged", "bytes", "no override"] {
            assert!(message.contains(part), "{name}: no {part:?} in: {message}");
        }

        // Once the way is clear the same files upgrade.
        std::fs::remove_file(&blocker).unwrap();
        let store = Store::open(&path).await.unwrap();
        assert_eq!(backups(&path).len(), 1, "{name}");
        store.close().await.unwrap();
    }
}

#[cfg(unix)]
#[tokio::test]
async fn a_read_only_backup_directory_refuses_the_open_untouched() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let path = copy_database(&fixture_dir("v11"), dir.path(), true);
    let before = database_files(dir.path());
    let root = dir.path().join("backup");
    std::fs::create_dir(&root).unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o500)).unwrap();
    if std::fs::write(root.join("probe"), b"").is_ok() {
        // Running as a user the permission bits do not bind (root).
        return;
    }

    let error = Store::open(&path).await.unwrap_err();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert!(
        matches!(&error, StoreError::UpgradeBackup { path, .. } if *path == root),
        "{error}"
    );
    assert_eq!(database_files(dir.path()), before);
    assert!(names(&root).is_empty(), "{:?}", names(&root));
}
