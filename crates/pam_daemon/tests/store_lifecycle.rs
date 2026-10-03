//! The daemon and the state file across its lifetimes: what a graceful stop
//! leaves on disk, what a store handle answers afterwards, and what boot
//! does with a database written by the previous engine — sound or damaged.
//!
//! Real files in temporary base directories; the previous-engine databases
//! are the fixtures committed under `crates/pam_store/tests/fixtures`.

use std::path::{Path, PathBuf};

use pam_daemon::daemon::{DaemonConfig, DaemonError, run_daemon_with};
use pam_proto::Response;
use pam_store::{RequestState, Store, StoreError};
use pam_testkit::{TestDaemon, base_of, envelope, short_tempdir, with_deadline};
use tokio::sync::watch;

const DATABASE: &str = "state.sqlite3";

/// A database as release 0.4.3 leaves it after a kill: schema 11, with its
/// newest commits only in the write-ahead log.
fn previous_engine_fixture() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../pam_store/tests/fixtures/turso-0.7/v11")
}

/// A request the fixture's main file does not hold: it is only in the log.
const ONLY_IN_THE_LOG: &str = "v11_wal_5";

/// Puts the fixture's files where a daemon on `tmp` keeps its state.
fn install_fixture(tmp: &tempfile::TempDir) -> PathBuf {
    let base = base_of(tmp);
    std::fs::create_dir_all(&base).unwrap();
    for suffix in ["", "-wal"] {
        let name = format!("{DATABASE}{suffix}");
        std::fs::copy(previous_engine_fixture().join(&name), base.join(&name)).unwrap();
    }
    base.join(DATABASE)
}

fn backups(base: &Path) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(base.join("backup")) else {
        return Vec::new();
    };
    entries.map(|entry| entry.unwrap().path()).collect()
}

fn len(path: &Path) -> u64 {
    std::fs::metadata(path).map_or(0, |meta| meta.len())
}

async fn boot(base: &Path) -> Result<(), DaemonError> {
    let (_keep, shutdown) = watch::channel(false);
    let config = DaemonConfig {
        base_dir: Some(base.to_owned()),
        policy_source: Some(pam_testkit::ScriptedPolicy::absent()),
        ..DaemonConfig::default()
    };
    run_daemon_with(config, shutdown).await.map(|_| ())
}

#[tokio::test]
async fn a_stopped_daemon_leaves_one_complete_file_and_a_store_that_says_it_is_closed() {
    with_deadline(Box::pin(async {
        let daemon = TestDaemon::spawn().await;
        let mut client = daemon.client().await;
        let done = client
            .request(&envelope("life_done", "echo", serde_json::json!({}), true))
            .await;
        assert!(matches!(done, Response::Result { .. }), "{done:?}");
        // One more, still running when the stop begins: its terminal write
        // is the last thing the drain produces.
        client
            .send(&envelope(
                "life_draining",
                "echo",
                serde_json::json!({ "delay_ms": 500 }),
                false,
            ))
            .await;
        assert!(matches!(client.recv().await, Response::Ticket { .. }));
        daemon
            .wait_for_row("life_draining", |row| row.state == RequestState::Running)
            .await;

        let store = daemon.store();
        let base = daemon.base_dir();
        let tmp = daemon.stop().await;

        // The handle an embedding host kept answers at once, with the
        // reason, on the writing and on the reading connection: no panic,
        // no hang, nothing written.
        let refusals = [
            store.count_inflight().await.unwrap_err(),
            store
                .insert_request("life_late", "echo", "/repo", "agent", "{}", None)
                .await
                .unwrap_err(),
            store
                .list_requests_filtered(None, None, None, None, None, false)
                .await
                .unwrap_err(),
            store.audit_for_request("life_done").await.unwrap_err(),
        ];
        for refusal in refusals {
            assert!(matches!(refusal, StoreError::Closed), "{refusal:?}");
            let text = refusal.to_string();
            assert!(text.contains("the store is closed"), "{text}");
            assert!(text.contains("shutting down"), "{text}");
        }

        // Nothing is left in a log: the main file is the whole database.
        assert_eq!(len(&base.join(format!("{DATABASE}-wal"))), 0);
        assert!(!base.join(format!("{DATABASE}-shm")).exists());
        let elsewhere = tempfile::tempdir().unwrap();
        let copy = elsewhere.path().join(DATABASE);
        std::fs::copy(base.join(DATABASE), &copy).unwrap();
        let restored = Store::open(&copy).await.unwrap();
        restored.check_integrity().await.unwrap();
        for id in ["life_done", "life_draining"] {
            let row = restored.get_request(id).await.unwrap().unwrap();
            assert_eq!(row.state, RequestState::Done, "{id}");
            assert!(
                !restored.audit_for_request(id).await.unwrap().is_empty(),
                "{id} has no audit row in the copied file"
            );
        }
        assert!(restored.get_request("life_late").await.unwrap().is_none());
        restored.close().await.unwrap();

        // And the next daemon on the same base starts from it.
        let daemon = TestDaemon::spawn_at(tmp).await;
        daemon
            .assert_row_state("life_draining", RequestState::Done)
            .await;
        daemon.stop().await;
    }))
    .await;
}

/// Over the real public socket: a request that reaches a store already
/// closed is told the daemon is shutting down, as a refusal to retry, with
/// the store's own sentence. It used to be `internal_error`.
#[tokio::test]
async fn a_request_that_meets_the_closed_store_is_refused_as_shutting_down_on_the_wire() {
    with_deadline(Box::pin(async {
        let daemon = TestDaemon::spawn().await;
        let mut client = daemon.client().await;
        // What the last step of a shutdown does, while the listener is
        // still up (the handle is the daemon's own store).
        daemon.store().close().await.unwrap();

        let refused = client
            .request(&envelope(
                "life_closed",
                "echo",
                serde_json::json!({}),
                true,
            ))
            .await;
        let Response::Refusal {
            cause,
            detail,
            recovery,
            retryable,
            ..
        } = &refused
        else {
            panic!("expected a refusal, got {refused:?}");
        };
        assert_eq!(cause, pam_daemon::daemon::CAUSE_DAEMON_SHUTTING_DOWN);
        assert!(*retryable, "{refused:?}");
        assert!(detail.contains("the store is closed"), "{detail}");
        assert!(detail.contains("nothing was written"), "{detail}");
        assert!(recovery.starts_with("Retry shortly"), "{recovery}");

        // The shutdown closes the store again, which is harmless, and the
        // next daemon on the base starts: nothing was half-written.
        let tmp = daemon.stop().await;
        let daemon = TestDaemon::spawn_at(tmp).await;
        assert!(
            daemon
                .store()
                .get_request("life_closed")
                .await
                .unwrap()
                .is_none()
        );
        daemon.stop().await;
    }))
    .await;
}

/// A state file found empty in a base the daemon has used is not started
/// on as a new database: the daemon refuses to boot, says so, and leaves
/// the file alone. Moving the empty file aside is the way to start fresh.
#[tokio::test]
async fn boot_refuses_an_emptied_state_file_in_a_base_the_daemon_has_used() {
    with_deadline(Box::pin(async {
        let daemon = TestDaemon::spawn().await;
        let base = daemon.base_dir();
        let tmp = daemon.stop().await;
        let state = base.join(DATABASE);
        // Something emptied the file while the daemon was stopped.
        std::fs::write(&state, b"").unwrap();

        for attempt in 0..2 {
            let refused = boot(&base).await.unwrap_err();
            let text = refused.to_string();
            assert!(
                matches!(&refused, DaemonError::Store(StoreError::Corrupt { .. })),
                "attempt {attempt}: {text}"
            );
            assert!(text.contains("is empty"), "{text}");
            assert!(text.contains("used by pam before"), "{text}");
            assert!(
                text.contains("move the empty file aside to start fresh"),
                "{text}"
            );
            assert_eq!(len(&state), 0, "attempt {attempt}");
            assert!(backups(&base).is_empty(), "attempt {attempt}");
        }

        // The way out the refusal names.
        std::fs::rename(&state, base.join("state.sqlite3.empty")).unwrap();
        let daemon = TestDaemon::spawn_at(tmp).await;
        daemon.stop().await;
    }))
    .await;
}

#[tokio::test]
async fn boot_takes_over_a_previous_engine_database_backs_it_up_and_serves() {
    with_deadline(Box::pin(async {
        let tmp = short_tempdir();
        let database = install_fixture(&tmp);
        let base = base_of(&tmp);
        let main_as_found = std::fs::read(&database).unwrap();
        let log_as_found = std::fs::read(base.join(format!("{DATABASE}-wal"))).unwrap();

        let daemon = TestDaemon::spawn_at(tmp).await;

        // The files as they were found are kept, whole.
        let made = backups(&base);
        assert_eq!(made.len(), 1, "{made:?}");
        assert!(
            made[0].to_str().unwrap().ends_with("-pre-sqlite"),
            "{:?}",
            made[0]
        );
        assert_eq!(
            std::fs::read(made[0].join(DATABASE)).unwrap(),
            main_as_found
        );
        assert_eq!(
            std::fs::read(made[0].join(format!("{DATABASE}-wal"))).unwrap(),
            log_as_found
        );

        // The daemon serves, on the upgraded schema, with the rows the old
        // engine had only in its log.
        let mut client = daemon.client().await;
        let status = client
            .request(&envelope(
                "life_status",
                "status",
                serde_json::json!({}),
                true,
            ))
            .await;
        assert!(matches!(status, Response::Result { .. }), "{status:?}");
        let store = daemon.store();
        assert!(store.schema_version().await.unwrap() >= 14);
        assert!(store.get_request(ONLY_IN_THE_LOG).await.unwrap().is_some());
        store.check_integrity().await.unwrap();

        // A second lifetime on the same base has nothing to back up.
        let tmp = daemon.stop().await;
        assert_eq!(len(&base.join(format!("{DATABASE}-wal"))), 0);
        let daemon = TestDaemon::spawn_at(tmp).await;
        assert_eq!(backups(&base), made);
        assert!(
            daemon
                .store()
                .get_request(ONLY_IN_THE_LOG)
                .await
                .unwrap()
                .is_some()
        );
        daemon.stop().await;
    }))
    .await;
}

#[tokio::test]
async fn boot_refuses_a_damaged_previous_engine_database_and_says_where_the_copy_is() {
    with_deadline(Box::pin(async {
        let tmp = short_tempdir();
        let database = install_fixture(&tmp);
        let base = base_of(&tmp);
        // Every page after the first is noise.
        let mut bytes = std::fs::read(&database).unwrap();
        for byte in &mut bytes[4096..] {
            *byte = !*byte;
        }
        std::fs::write(&database, &bytes).unwrap();
        let log_as_found = std::fs::read(base.join(format!("{DATABASE}-wal"))).unwrap();

        // Twice: a service manager restarts a daemon that exits.
        for attempt in 0..2 {
            let error = with_deadline(boot(&base)).await.unwrap_err();
            // The store's refusal, not "already running": the instance lock
            // of the failed boot was released.
            let DaemonError::Store(StoreError::Corrupt { detail }) = &error else {
                panic!("attempt {attempt}: {error}");
            };
            let made = backups(&base);
            assert_eq!(made.len(), 1, "attempt {attempt}: {made:?}");
            // The daemon names its base by its canonical spelling, which on
            // Windows is the `\\?\` form.
            let named = std::fs::canonicalize(&made[0]).unwrap();
            assert!(detail.contains(named.to_str().unwrap()), "{detail}");
            // What the human reads on the daemon's standard error.
            let shown = error.to_string();
            for part in [
                "database integrity check failed",
                "stop the daemon",
                "go back",
                "start empty",
            ] {
                assert!(
                    shown.contains(part),
                    "attempt {attempt}: no {part:?} in: {shown}"
                );
            }
            assert_eq!(
                std::fs::read(&database).unwrap(),
                bytes,
                "attempt {attempt}"
            );
            assert_eq!(
                std::fs::read(base.join(format!("{DATABASE}-wal"))).unwrap(),
                log_as_found,
                "attempt {attempt}"
            );
            assert_eq!(std::fs::read(made[0].join(DATABASE)).unwrap(), bytes);
        }
    }))
    .await;
}

#[tokio::test]
async fn boot_refuses_to_upgrade_when_the_backup_cannot_be_written() {
    with_deadline(Box::pin(async {
        let tmp = short_tempdir();
        let database = install_fixture(&tmp);
        let base = base_of(&tmp);
        let main_as_found = std::fs::read(&database).unwrap();
        let log_as_found = std::fs::read(base.join(format!("{DATABASE}-wal"))).unwrap();
        std::fs::write(base.join("backup"), b"in the way").unwrap();

        let error = with_deadline(boot(&base)).await.unwrap_err();
        assert!(
            matches!(&error, DaemonError::Store(StoreError::UpgradeBackup { .. })),
            "{error}"
        );
        let shown = error.to_string();
        assert!(shown.contains("was not opened"), "{shown}");
        assert!(shown.contains("unchanged"), "{shown}");
        assert_eq!(std::fs::read(&database).unwrap(), main_as_found);
        assert_eq!(
            std::fs::read(base.join(format!("{DATABASE}-wal"))).unwrap(),
            log_as_found
        );
        assert!(!base.join(format!("{DATABASE}-shm")).exists());

        // With the way cleared, the same files boot.
        std::fs::remove_file(base.join("backup")).unwrap();
        let daemon = TestDaemon::spawn_at(tmp).await;
        assert_eq!(backups(&base).len(), 1);
        assert!(
            daemon
                .store()
                .get_request(ONLY_IN_THE_LOG)
                .await
                .unwrap()
                .is_some()
        );
        daemon.stop().await;
    }))
    .await;
}
