use std::{fs, sync::mpsc, time::Duration};

use pam_core::{ContentDigest, EvidenceHandle, ProjectId};
use rusqlite::Connection;
use sha2::{Digest as _, Sha256};

use super::{
    EvidenceRedaction, EvidenceRetention, MAX_EVIDENCE_BYTES, MAX_EVIDENCE_PRUNE_BATCH_SIZE,
    MAX_EVIDENCE_RANGE_BYTES, PutEvidence, Store, StoreError,
};
use crate::{
    evidence::{
        EvidenceFiles, content_digest, evidence_blob_path, evidence_temporary_path, inspect,
        install_blob_with_namespace_swap, prune, put_with_install_hook, validate_size,
    },
    store::{database_path, open_connection},
};

fn evidence(handle: &str, project: &str, bytes: &[u8]) -> PutEvidence {
    PutEvidence {
        handle: EvidenceHandle::parse(handle).unwrap(),
        project_id: ProjectId::from(project),
        media_type: "application/octet-stream".to_owned(),
        retention: EvidenceRetention::Project,
        redaction: EvidenceRedaction::Unredacted,
        bytes: bytes.to_vec(),
    }
}

fn retained_evidence(
    handle: &str,
    project: &str,
    retention: EvidenceRetention,
    bytes: &[u8],
) -> PutEvidence {
    PutEvidence {
        retention,
        ..evidence(handle, project, bytes)
    }
}

fn insert_install_intent(
    connection: &Connection,
    attempt_id: &str,
    digest: &ContentDigest,
    temporary_name: &str,
    size_bytes: usize,
    started_at_ms: i64,
) {
    connection
        .execute(
            "INSERT INTO evidence_install_intents(
                 attempt_id, digest, temporary_name, size_bytes, started_at_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![
                attempt_id,
                digest.as_str(),
                temporary_name,
                i64::try_from(size_bytes).unwrap(),
                started_at_ms
            ],
        )
        .unwrap();
}

fn write_crash_temporary(path: &std::path::Path, temporary_name: &str, bytes: &[u8]) {
    let temporary = evidence_temporary_path(path, temporary_name);
    fs::create_dir_all(temporary.parent().unwrap()).unwrap();
    fs::write(temporary, bytes).unwrap();
}

async fn put_retention_scope_fixtures(store: &Store) {
    for (request, created_at_ms) in [
        (
            retained_evidence(
                "evidence://retention/old",
                "project-a",
                EvidenceRetention::Project,
                b"old",
            ),
            10,
        ),
        (
            retained_evidence(
                "evidence://retention/boundary",
                "project-a",
                EvidenceRetention::Project,
                b"boundary",
            ),
            20,
        ),
        (
            retained_evidence(
                "evidence://retention/new",
                "project-a",
                EvidenceRetention::Project,
                b"new",
            ),
            21,
        ),
        (
            retained_evidence(
                "evidence://retention/session",
                "project-a",
                EvidenceRetention::Session,
                b"session",
            ),
            1,
        ),
        (
            retained_evidence(
                "evidence://retention/persistent",
                "project-a",
                EvidenceRetention::Persistent,
                b"persistent",
            ),
            1,
        ),
        (
            retained_evidence(
                "evidence://retention/other-project",
                "project-b",
                EvidenceRetention::Project,
                b"other",
            ),
            1,
        ),
    ] {
        store.put_evidence(request, created_at_ms).await.unwrap();
    }
}

async fn close(store: Store, directory: &std::path::Path) {
    store.shutdown().await.unwrap();
    fs::remove_dir_all(directory).unwrap();
}

#[tokio::test]
async fn exact_arbitrary_bytes_survive_restart_and_bounded_range_reads() {
    let (directory, path) = database_path("evidence-exact");
    let bytes = b"\xff\0first\r\nprogress\rnext\n\xfe";
    let store = Store::open(&path).unwrap();
    let stored = store
        .put_evidence(
            evidence("evidence://ci/1842/failure", "project-a", bytes),
            123,
        )
        .await
        .unwrap();

    assert_eq!(stored.handle.as_str(), "evidence://ci/1842/failure");
    assert_eq!(stored.project_id, ProjectId::from("project-a"));
    assert_eq!(stored.size_bytes, u64::try_from(bytes.len()).unwrap());
    assert_eq!(stored.media_type, "application/octet-stream");
    assert_eq!(stored.retention, EvidenceRetention::Project);
    assert_eq!(stored.redaction, EvidenceRedaction::Unredacted);
    assert_eq!(stored.created_at_ms, 123);
    assert_eq!(
        stored.digest,
        ContentDigest::from_sha256(Sha256::digest(bytes).into())
    );
    assert_eq!(
        store
            .inspect_evidence(
                ProjectId::from("project-a"),
                EvidenceHandle::parse("evidence://ci/1842/failure").unwrap(),
            )
            .await
            .unwrap(),
        stored
    );
    assert_eq!(
        store
            .read_evidence_range(ProjectId::from("project-a"), stored.handle.clone(), 1, 7,)
            .await
            .unwrap(),
        &bytes[1..8]
    );
    assert_eq!(
        store
            .read_evidence_range(
                ProjectId::from("project-a"),
                stored.handle.clone(),
                stored.size_bytes - 2,
                100,
            )
            .await
            .unwrap(),
        &bytes[bytes.len() - 2..]
    );
    assert!(matches!(
        store
            .read_evidence_range(
                ProjectId::from("project-a"),
                stored.handle.clone(),
                stored.size_bytes + 1,
                1,
            )
            .await,
        Err(StoreError::EvidenceRangeOutOfBounds { .. })
    ));
    assert!(matches!(
        store
            .read_evidence_range(
                ProjectId::from("project-a"),
                stored.handle.clone(),
                0,
                MAX_EVIDENCE_RANGE_BYTES + 1,
            )
            .await,
        Err(StoreError::EvidenceRangeTooLarge { .. })
    ));
    store.shutdown().await.unwrap();

    let reopened = Store::open(&path).unwrap();
    assert_eq!(
        reopened
            .read_evidence_range(
                ProjectId::from("project-a"),
                stored.handle,
                0,
                stored.size_bytes,
            )
            .await
            .unwrap(),
        bytes
    );
    close(reopened, &directory).await;
}

#[tokio::test]
async fn blobs_deduplicate_globally_while_handles_remain_project_scoped() {
    let (directory, path) = database_path("evidence-dedupe");
    let store = Store::open(&path).unwrap();
    let first = store
        .put_evidence(
            evidence("evidence://ci/1842/failure", "project-a", b"same"),
            10,
        )
        .await
        .unwrap();
    let second = store
        .put_evidence(evidence("evidence://logs/build", "project-b", b"same"), 11)
        .await
        .unwrap();

    assert_eq!(first.digest, second.digest);
    assert!(matches!(
        store
            .inspect_evidence(ProjectId::from("project-b"), first.handle.clone())
            .await,
        Err(StoreError::EvidenceNotFound { .. })
    ));
    store.shutdown().await.unwrap();

    let connection = Connection::open(&path).unwrap();
    let blob_count: u32 = connection
        .query_row("SELECT COUNT(*) FROM evidence_blobs", [], |row| row.get(0))
        .unwrap();
    let handle_count: u32 = connection
        .query_row("SELECT COUNT(*) FROM evidence_handles", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(blob_count, 1);
    assert_eq!(handle_count, 2);
    assert!(evidence_blob_path(&path, &first.digest).is_file());
    drop(connection);
    fs::remove_dir_all(directory).unwrap();
}

#[tokio::test]
async fn semantic_handle_puts_are_idempotent_but_immutable() {
    let (directory, path) = database_path("evidence-immutable");
    let store = Store::open(&path).unwrap();
    let request = evidence("evidence://git/7ac19f", "project", b"original");
    let first = store.put_evidence(request.clone(), 10).await.unwrap();
    let repeated = store.put_evidence(request, 99).await.unwrap();

    assert_eq!(repeated, first);
    assert_eq!(repeated.created_at_ms, 10);
    assert!(matches!(
        store
            .put_evidence(evidence("evidence://git/7ac19f", "project", b"changed"), 11,)
            .await,
        Err(StoreError::EvidenceHandleConflict { .. })
    ));

    close(store, &directory).await;
}

#[tokio::test]
async fn concurrent_store_workers_share_one_blob_and_one_idempotent_mapping() {
    let (directory, path) = database_path("evidence-concurrent");
    let first_store = Store::open(&path).unwrap();
    let second_store = Store::open(&path).unwrap();
    let first_request = evidence("evidence://ci/concurrent/output", "project", b"same");
    let second_request = first_request.clone();

    let (first, second) = tokio::join!(
        first_store.put_evidence(first_request, 10),
        second_store.put_evidence(second_request, 11),
    );
    let first = first.unwrap();
    let second = second.unwrap();
    assert_eq!(first.digest, second.digest);
    assert_eq!(first.created_at_ms, second.created_at_ms);
    first_store.shutdown().await.unwrap();
    second_store.shutdown().await.unwrap();

    let connection = Connection::open(&path).unwrap();
    assert_eq!(
        connection
            .query_row("SELECT COUNT(*) FROM evidence_blobs", [], |row| {
                row.get::<_, u32>(0)
            })
            .unwrap(),
        1
    );
    assert_eq!(
        connection
            .query_row("SELECT COUNT(*) FROM evidence_handles", [], |row| {
                row.get::<_, u32>(0)
            })
            .unwrap(),
        1
    );
    drop(connection);
    fs::remove_dir_all(directory).unwrap();
}

#[tokio::test]
async fn lease_renewal_remains_responsive_while_evidence_worker_is_blocked() {
    let (directory, path) = database_path("evidence-worker-isolation");
    let store = Store::open(&path).unwrap();
    store
        .accept(
            crate::AcceptRequest {
                request_id: pam_core::RequestId::from("request"),
                caller_id: pam_core::CallerId::from("caller"),
                project_id: ProjectId::from("project"),
                idempotency_key: pam_core::IdempotencyKey::from("key"),
                operation_kind: "test.operation".to_owned(),
                operation: Vec::new(),
            },
            10,
        )
        .await
        .unwrap();
    let leased = store.claim("worker", 20, 10_000).await.unwrap().unwrap();
    let (entered_tx, entered_rx) = mpsc::sync_channel(1);
    let (release_tx, release_rx) = mpsc::sync_channel(1);
    store
        .hold_evidence_worker(entered_tx, release_rx)
        .await
        .unwrap();
    entered_rx.recv_timeout(Duration::from_secs(2)).unwrap();

    let renewal = tokio::time::timeout(
        Duration::from_secs(2),
        store.renew(leased.lease, 21, 10_000),
    )
    .await;
    release_tx.send(()).unwrap();
    let renewed = renewal
        .expect("scheduler must not wait for evidence I/O")
        .unwrap();
    assert_eq!(renewed.expires_at_ms, 10_021);

    close(store, &directory).await;
}

#[tokio::test]
async fn missing_and_corrupt_blobs_are_never_returned() {
    let (directory, path) = database_path("evidence-corruption");
    let store = Store::open(&path).unwrap();
    let metadata = store
        .put_evidence(
            evidence("evidence://ci/corrupt/output", "project", b"original"),
            10,
        )
        .await
        .unwrap();
    store.shutdown().await.unwrap();
    let blob = evidence_blob_path(&path, &metadata.digest);
    fs::write(&blob, b"modified").unwrap();

    let reopened = Store::open(&path).unwrap();
    assert!(matches!(
        reopened
            .put_evidence(
                evidence("evidence://ci/corrupt/output", "project", b"original"),
                11,
            )
            .await,
        Err(StoreError::EvidenceBlobCorrupt(digest)) if digest == metadata.digest
    ));
    assert!(matches!(
        reopened
            .inspect_evidence(ProjectId::from("project"), metadata.handle.clone())
            .await,
        Err(StoreError::EvidenceBlobCorrupt(digest)) if digest == metadata.digest
    ));
    reopened.shutdown().await.unwrap();
    fs::remove_file(&blob).unwrap();

    let reopened = Store::open(&path).unwrap();
    assert!(matches!(
        reopened
            .read_evidence_range(ProjectId::from("project"), metadata.handle, 0, 8)
            .await,
        Err(StoreError::EvidenceBlobMissing(digest)) if digest == metadata.digest
    ));
    close(reopened, &directory).await;
}

#[cfg(unix)]
#[tokio::test]
async fn symlinked_evidence_directory_is_rejected_before_put() {
    use std::os::unix::fs::symlink;

    let (directory, path) = database_path("evidence-directory-symlink");
    fs::create_dir_all(&directory).unwrap();
    let outside = directory.join("outside");
    fs::create_dir(&outside).unwrap();
    symlink(&outside, directory.join("evidence")).unwrap();
    let store = Store::open(&path).unwrap();

    assert!(matches!(
        store
            .put_evidence(
                evidence("evidence://ci/symlink/directory", "project", b"bytes"),
                10,
            )
            .await,
        Err(StoreError::UnsafeEvidencePath)
    ));
    close(store, &directory).await;
}

#[cfg(unix)]
#[tokio::test]
async fn symlinked_blob_is_rejected_even_when_target_bytes_match() {
    use std::os::unix::fs::symlink;

    let (directory, path) = database_path("evidence-symlink");
    let store = Store::open(&path).unwrap();
    let metadata = store
        .put_evidence(
            evidence("evidence://ci/symlink/output", "project", b"original"),
            10,
        )
        .await
        .unwrap();
    store.shutdown().await.unwrap();
    let blob = evidence_blob_path(&path, &metadata.digest);
    let target = directory.join("outside");
    fs::write(&target, b"original").unwrap();
    fs::remove_file(&blob).unwrap();
    symlink(&target, &blob).unwrap();

    let reopened = Store::open(&path).unwrap();
    assert!(matches!(
        reopened
            .inspect_evidence(ProjectId::from("project"), metadata.handle)
            .await,
        Err(StoreError::UnsafeEvidencePath)
    ));
    close(reopened, &directory).await;
}

#[cfg(unix)]
#[tokio::test]
async fn fifo_blob_is_rejected_without_blocking_evidence_requests_or_shutdown() {
    use nix::{sys::stat::Mode, unistd::mkfifo};

    let (directory, path) = database_path("evidence-fifo");
    let store = Store::open(&path).unwrap();
    let metadata = store
        .put_evidence(
            evidence("evidence://ci/fifo/output", "project", b"original"),
            10,
        )
        .await
        .unwrap();
    store.shutdown().await.unwrap();

    let blob = evidence_blob_path(&path, &metadata.digest);
    fs::remove_file(&blob).unwrap();
    mkfifo(&blob, Mode::S_IRUSR | Mode::S_IWUSR).unwrap();

    let reopened = Store::open(&path).unwrap();
    let inspect = tokio::time::timeout(
        Duration::from_secs(2),
        reopened.inspect_evidence(ProjectId::from("project"), metadata.handle.clone()),
    )
    .await
    .expect("inspecting a FIFO must not block");
    assert!(matches!(
        inspect,
        Err(StoreError::EvidenceBlobCorrupt(digest)) if digest == metadata.digest
    ));

    let read = tokio::time::timeout(
        Duration::from_secs(2),
        reopened.read_evidence_range(
            ProjectId::from("project"),
            metadata.handle,
            0,
            metadata.size_bytes,
        ),
    )
    .await
    .expect("reading a FIFO must not block");
    assert!(matches!(
        read,
        Err(StoreError::EvidenceBlobCorrupt(digest)) if digest == metadata.digest
    ));

    tokio::time::timeout(Duration::from_secs(2), reopened.shutdown())
        .await
        .expect("shutdown after rejecting a FIFO must not block")
        .unwrap();
    fs::remove_file(blob).unwrap();
    fs::remove_dir_all(directory).unwrap();
}

#[tokio::test]
async fn shutdown_releases_database_and_evidence_directory_handles_before_returning() {
    let (directory, path) = database_path("evidence-shutdown-handles");
    let renamed = directory.with_file_name(format!(
        "{}-renamed",
        directory.file_name().unwrap().to_string_lossy()
    ));
    let store = Store::open(&path).unwrap();
    store
        .put_evidence(
            evidence("evidence://ci/shutdown/output", "project", b"original"),
            10,
        )
        .await
        .unwrap();

    store.shutdown().await.unwrap();
    fs::rename(&directory, &renamed).unwrap();
    fs::remove_dir_all(renamed).unwrap();
}

#[tokio::test]
async fn evidence_size_and_media_type_are_bounded_before_file_io() {
    assert!(matches!(
        validate_size(MAX_EVIDENCE_BYTES + 1),
        Err(StoreError::EvidenceTooLarge { .. })
    ));

    let (directory, path) = database_path("evidence-validation");
    let store = Store::open(&path).unwrap();
    let mut invalid = evidence("evidence://ci/invalid/type", "project", b"bytes");
    invalid.media_type = "invalid\0type".to_owned();
    assert!(matches!(
        store.put_evidence(invalid, 10).await,
        Err(StoreError::InvalidEvidenceMediaType)
    ));
    assert!(!directory.join("evidence").exists());
    close(store, &directory).await;
}

#[tokio::test]
async fn invalid_timestamp_leaves_no_blob_or_evidence_metadata() {
    let (directory, path) = database_path("evidence-timestamp-validation");
    let store = Store::open(&path).unwrap();

    assert!(matches!(
        store
            .put_evidence(
                evidence("evidence://ci/invalid/timestamp", "project", b"bytes"),
                u64::MAX,
            )
            .await,
        Err(StoreError::TimestampOutOfRange(value)) if value == u64::MAX
    ));
    assert!(!directory.join("evidence").exists());
    store.shutdown().await.unwrap();
    let connection = Connection::open(&path).unwrap();
    let handle_count: u32 = connection
        .query_row("SELECT COUNT(*) FROM evidence_handles", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(handle_count, 0);
    drop(connection);
    fs::remove_dir_all(directory).unwrap();
}

#[cfg(unix)]
#[test]
fn held_directory_handles_prevent_namespace_swap_from_redirecting_publication() {
    use std::os::unix::fs::symlink;

    let (directory, path) = database_path("evidence-namespace-swap");
    fs::create_dir_all(&directory).unwrap();
    let files = EvidenceFiles::open(&path).unwrap();
    let digest = content_digest(b"exact bytes");
    let live_root = directory.join("evidence");
    let held_root = directory.join("evidence-held");
    let outside = directory.join("outside");
    fs::create_dir(&outside).unwrap();

    let result = install_blob_with_namespace_swap(&files, &digest, b"exact bytes", || {
        fs::rename(&live_root, &held_root).unwrap();
        symlink(&outside, &live_root).unwrap();
    });

    assert!(matches!(result, Err(StoreError::UnsafeEvidencePath)));
    assert_eq!(fs::read_dir(&outside).unwrap().count(), 0);
    assert_eq!(
        fs::read(
            held_root
                .join("blobs")
                .join("sha256")
                .join(&digest.sha256_hex()[..2])
                .join(digest.sha256_hex())
        )
        .unwrap(),
        b"exact bytes"
    );
    fs::remove_file(live_root).unwrap();
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn content_digest_helper_preserves_sha256_identity() {
    assert_eq!(
        content_digest(b"abc").as_str(),
        "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}

#[tokio::test]
async fn retention_prune_is_bounded_inclusive_and_strictly_scoped() {
    let (directory, path) = database_path("evidence-retention-scope");
    let store = Store::open(&path).unwrap();
    put_retention_scope_fixtures(&store).await;
    store.shutdown().await.unwrap();

    let mut connection = open_connection(&path).unwrap();
    let files = EvidenceFiles::open(&path).unwrap();
    let first = prune(
        &mut connection,
        &files,
        &ProjectId::from("project-a"),
        EvidenceRetention::Project,
        20,
        1,
    )
    .unwrap();
    assert_eq!(first.handles_deleted, 1);
    assert_eq!(first.blobs_deleted, 1);
    assert_eq!(first.blobs_pending, 0);
    assert!(first.has_more);
    assert_eq!(
        connection
            .query_row(
                "SELECT COUNT(*) FROM evidence_handles
                 WHERE project_id = 'project-a' AND handle = 'evidence://retention/old'",
                [],
                |row| row.get::<_, u32>(0),
            )
            .unwrap(),
        0
    );

    let second = prune(
        &mut connection,
        &files,
        &ProjectId::from("project-a"),
        EvidenceRetention::Project,
        20,
        1,
    )
    .unwrap();
    assert_eq!(second.handles_deleted, 1);
    assert_eq!(second.blobs_deleted, 1);
    assert_eq!(second.blobs_pending, 0);
    assert!(!second.has_more);

    let remaining: Vec<String> = connection
        .prepare("SELECT handle FROM evidence_handles ORDER BY handle")
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(
        remaining,
        vec![
            "evidence://retention/new",
            "evidence://retention/other-project",
            "evidence://retention/persistent",
            "evidence://retention/session",
        ]
    );

    assert_eq!(
        prune(
            &mut connection,
            &files,
            &ProjectId::from("project-a"),
            EvidenceRetention::Project,
            20,
            1,
        )
        .unwrap(),
        crate::evidence::PruneOutcome {
            handles_deleted: 0,
            blobs_deleted: 0,
            blobs_pending: 0,
            cleanup_unresolved: false,
            has_more: false,
        }
    );
    drop(connection);
    drop(files);
    fs::remove_dir_all(directory).unwrap();
}

#[tokio::test]
async fn shared_blob_is_removed_only_after_its_last_handle() {
    let (directory, path) = database_path("evidence-retention-shared");
    let store = Store::open(&path).unwrap();
    let first = store
        .put_evidence(
            evidence("evidence://retention/shared-a", "project-a", b"shared"),
            10,
        )
        .await
        .unwrap();
    store
        .put_evidence(
            evidence("evidence://retention/shared-b", "project-b", b"shared"),
            10,
        )
        .await
        .unwrap();
    store.shutdown().await.unwrap();

    let blob_path = evidence_blob_path(&path, &first.digest);
    let mut connection = open_connection(&path).unwrap();
    let files = EvidenceFiles::open(&path).unwrap();
    let first_prune = prune(
        &mut connection,
        &files,
        &ProjectId::from("project-a"),
        EvidenceRetention::Project,
        10,
        10,
    )
    .unwrap();
    assert_eq!(first_prune.handles_deleted, 1);
    assert_eq!(first_prune.blobs_deleted, 0);
    assert_eq!(first_prune.blobs_pending, 0);
    assert!(blob_path.is_file());

    let last_prune = prune(
        &mut connection,
        &files,
        &ProjectId::from("project-b"),
        EvidenceRetention::Project,
        10,
        10,
    )
    .unwrap();
    assert_eq!(last_prune.handles_deleted, 1);
    assert_eq!(last_prune.blobs_deleted, 1);
    assert_eq!(last_prune.blobs_pending, 0);
    assert!(!blob_path.exists());
    assert_eq!(
        connection
            .query_row("SELECT COUNT(*) FROM evidence_blobs", [], |row| {
                row.get::<_, u32>(0)
            })
            .unwrap(),
        0
    );
    assert_eq!(
        prune(
            &mut connection,
            &files,
            &ProjectId::from("project-b"),
            EvidenceRetention::Project,
            10,
            10,
        )
        .unwrap()
        .handles_deleted,
        0
    );
    drop(connection);
    drop(files);
    fs::remove_dir_all(directory).unwrap();
}

#[cfg(unix)]
#[tokio::test]
async fn retention_prune_reports_symlinked_blob_cleanup_pending_without_following_target() {
    use std::os::unix::fs::symlink;

    let (directory, path) = database_path("evidence-retention-symlink");
    let store = Store::open(&path).unwrap();
    let stored = store
        .put_evidence(
            evidence(
                "evidence://retention/symlinked-blob",
                "project",
                b"original",
            ),
            10,
        )
        .await
        .unwrap();
    store.shutdown().await.unwrap();
    let outside = directory.join("outside");
    fs::write(&outside, b"outside").unwrap();
    let blob = evidence_blob_path(&path, &stored.digest);
    fs::remove_file(&blob).unwrap();
    symlink(&outside, &blob).unwrap();

    let mut connection = open_connection(&path).unwrap();
    let files = EvidenceFiles::open(&path).unwrap();
    let outcome = prune(
        &mut connection,
        &files,
        &ProjectId::from("project"),
        EvidenceRetention::Project,
        10,
        10,
    )
    .unwrap();
    assert_eq!(outcome.handles_deleted, 1);
    assert_eq!(outcome.blobs_deleted, 0);
    assert_eq!(outcome.blobs_pending, 1);
    assert!(outcome.has_more);
    assert_eq!(fs::read(&outside).unwrap(), b"outside");
    assert_eq!(
        connection
            .query_row("SELECT COUNT(*) FROM evidence_handles", [], |row| {
                row.get::<_, u32>(0)
            })
            .unwrap(),
        0
    );
    let retry = prune(
        &mut connection,
        &files,
        &ProjectId::from("project"),
        EvidenceRetention::Project,
        10,
        10,
    )
    .unwrap();
    assert_eq!(retry.handles_deleted, 0);
    assert_eq!(retry.blobs_pending, 1);
    assert!(retry.has_more);
    drop(connection);
    drop(files);
    fs::remove_dir_all(directory).unwrap();
}

#[tokio::test]
async fn retention_prune_recovers_a_crash_orphan_tracked_by_an_install_intent() {
    let (directory, path) = database_path("evidence-retention-install-intent");
    let store = Store::open(&path).unwrap();
    store.shutdown().await.unwrap();
    let mut connection = open_connection(&path).unwrap();
    let files = EvidenceFiles::open(&path).unwrap();
    let bytes = b"installed before metadata commit";
    let digest = content_digest(bytes);
    install_blob_with_namespace_swap(&files, &digest, bytes, || {}).unwrap();
    connection
        .execute(
            "INSERT INTO evidence_install_intents(
                 attempt_id, digest, temporary_name, size_bytes, started_at_ms
             ) VALUES (?1, ?2, ?3, ?4, 0)",
            rusqlite::params![
                "10000000-0000-4000-8000-000000000001",
                digest.as_str(),
                "20000000-0000-4000-8000-000000000001",
                i64::try_from(bytes.len()).unwrap()
            ],
        )
        .unwrap();
    let blob = evidence_blob_path(&path, &digest);
    assert!(blob.is_file());

    let outcome = prune(
        &mut connection,
        &files,
        &ProjectId::from("project"),
        EvidenceRetention::Project,
        0,
        10,
    )
    .unwrap();
    assert_eq!(outcome.handles_deleted, 0);
    assert_eq!(outcome.blobs_deleted, 1);
    assert_eq!(outcome.blobs_pending, 0);
    assert!(!outcome.cleanup_unresolved);
    assert!(!blob.exists());
    assert_eq!(
        connection
            .query_row("SELECT COUNT(*) FROM evidence_install_intents", [], |row| {
                row.get::<_, u32>(0)
            })
            .unwrap(),
        0
    );
    drop(connection);
    drop(files);
    fs::remove_dir_all(directory).unwrap();
}

#[tokio::test]
async fn stale_intent_removes_its_exact_crash_temp_before_hardlink_idempotently() {
    let (directory, path) = database_path("evidence-retention-crash-temp");
    let store = Store::open(&path).unwrap();
    store.shutdown().await.unwrap();
    let mut connection = open_connection(&path).unwrap();
    let files = EvidenceFiles::open(&path).unwrap();
    let bytes = b"crash before hardlink";
    let digest = content_digest(bytes);
    let attempt_id = "10000000-0000-4000-8000-000000000002";
    let temporary_name = "20000000-0000-4000-8000-000000000002";

    insert_install_intent(
        &connection,
        attempt_id,
        &digest,
        temporary_name,
        bytes.len(),
        0,
    );
    write_crash_temporary(&path, temporary_name, bytes);
    let temporary = evidence_temporary_path(&path, temporary_name);
    assert!(temporary.is_file());
    assert!(!evidence_blob_path(&path, &digest).exists());

    let first = prune(
        &mut connection,
        &files,
        &ProjectId::from("project"),
        EvidenceRetention::Project,
        0,
        10,
    )
    .unwrap();
    assert_eq!(first.blobs_deleted, 0);
    assert_eq!(first.blobs_pending, 0);
    assert!(!first.cleanup_unresolved);
    assert!(!temporary.exists());
    assert_eq!(
        connection
            .query_row("SELECT COUNT(*) FROM evidence_install_intents", [], |row| {
                row.get::<_, u32>(0)
            })
            .unwrap(),
        0
    );

    let repeated = prune(
        &mut connection,
        &files,
        &ProjectId::from("project"),
        EvidenceRetention::Project,
        0,
        10,
    )
    .unwrap();
    assert_eq!(repeated.blobs_deleted, 0);
    assert_eq!(repeated.blobs_pending, 0);
    assert!(!repeated.cleanup_unresolved);
    drop(connection);
    drop(files);
    fs::remove_dir_all(directory).unwrap();
}

#[tokio::test]
async fn stale_same_digest_attempt_cannot_clear_or_delete_a_non_stale_attempt() {
    let (directory, path) = database_path("evidence-retention-concurrent-intents");
    let store = Store::open(&path).unwrap();
    store.shutdown().await.unwrap();
    let mut connection = open_connection(&path).unwrap();
    let files = EvidenceFiles::open(&path).unwrap();
    let bytes = b"same digest concurrent attempts";
    let digest = content_digest(bytes);
    install_blob_with_namespace_swap(&files, &digest, bytes, || {}).unwrap();
    let blob = evidence_blob_path(&path, &digest);
    let stale_attempt = "10000000-0000-4000-8000-000000000003";
    let stale_temporary = "20000000-0000-4000-8000-000000000003";
    let active_attempt = "10000000-0000-4000-8000-000000000004";
    let active_temporary = "20000000-0000-4000-8000-000000000004";
    insert_install_intent(
        &connection,
        stale_attempt,
        &digest,
        stale_temporary,
        bytes.len(),
        0,
    );
    insert_install_intent(
        &connection,
        active_attempt,
        &digest,
        active_temporary,
        bytes.len(),
        i64::MAX,
    );
    write_crash_temporary(&path, stale_temporary, bytes);
    write_crash_temporary(&path, active_temporary, bytes);

    let first = prune(
        &mut connection,
        &files,
        &ProjectId::from("project"),
        EvidenceRetention::Project,
        0,
        10,
    )
    .unwrap();
    assert_eq!(first.blobs_deleted, 0);
    assert_eq!(first.blobs_pending, 0);
    assert!(!first.cleanup_unresolved);
    assert!(!evidence_temporary_path(&path, stale_temporary).exists());
    assert!(evidence_temporary_path(&path, active_temporary).is_file());
    assert!(blob.is_file());
    assert_eq!(
        connection
            .query_row(
                "SELECT attempt_id FROM evidence_install_intents",
                [],
                |row| row.get::<_, String>(0),
            )
            .unwrap(),
        active_attempt
    );

    connection
        .execute(
            "UPDATE evidence_install_intents SET started_at_ms = 0 WHERE attempt_id = ?1",
            [active_attempt],
        )
        .unwrap();
    let final_cleanup = prune(
        &mut connection,
        &files,
        &ProjectId::from("project"),
        EvidenceRetention::Project,
        0,
        10,
    )
    .unwrap();
    assert_eq!(final_cleanup.blobs_deleted, 1);
    assert_eq!(final_cleanup.blobs_pending, 0);
    assert!(!final_cleanup.cleanup_unresolved);
    assert!(!evidence_temporary_path(&path, active_temporary).exists());
    assert!(!blob.exists());
    assert_eq!(
        connection
            .query_row("SELECT COUNT(*) FROM evidence_install_intents", [], |row| {
                row.get::<_, u32>(0)
            })
            .unwrap(),
        0
    );
    drop(connection);
    drop(files);
    fs::remove_dir_all(directory).unwrap();
}

#[cfg(unix)]
#[tokio::test]
async fn pending_blob_cleanup_does_not_starve_later_unreferenced_blobs() {
    use std::os::unix::fs::symlink;

    let (directory, path) = database_path("evidence-retention-pending-fairness");
    let store = Store::open(&path).unwrap();
    let first = store
        .put_evidence(
            evidence("evidence://retention/fair-a", "project", b"first"),
            1,
        )
        .await
        .unwrap();
    let second = store
        .put_evidence(
            evidence("evidence://retention/fair-b", "project", b"second"),
            2,
        )
        .await
        .unwrap();
    store.shutdown().await.unwrap();
    let (pending_digest, removable_digest) = if first.digest.as_str() < second.digest.as_str() {
        (first.digest, second.digest)
    } else {
        (second.digest, first.digest)
    };
    let outside = directory.join("outside");
    fs::write(&outside, b"outside").unwrap();
    let pending_blob = evidence_blob_path(&path, &pending_digest);
    fs::remove_file(&pending_blob).unwrap();
    symlink(&outside, &pending_blob).unwrap();
    let removable_blob = evidence_blob_path(&path, &removable_digest);

    let mut connection = open_connection(&path).unwrap();
    connection
        .execute("DELETE FROM evidence_handles", [])
        .unwrap();
    let files = EvidenceFiles::open(&path).unwrap();
    let first_pass = prune(
        &mut connection,
        &files,
        &ProjectId::from("project"),
        EvidenceRetention::Project,
        2,
        1,
    )
    .unwrap();
    assert_eq!(first_pass.blobs_pending, 1);
    assert!(removable_blob.is_file());

    let second_pass = prune(
        &mut connection,
        &files,
        &ProjectId::from("project"),
        EvidenceRetention::Project,
        2,
        1,
    )
    .unwrap();
    assert_eq!(second_pass.blobs_deleted, 1);
    assert!(!removable_blob.exists());
    assert_eq!(fs::read(outside).unwrap(), b"outside");
    drop(connection);
    drop(files);
    fs::remove_dir_all(directory).unwrap();
}

#[tokio::test]
async fn cleanup_reports_committed_removals_when_a_later_database_step_fails() {
    let (directory, path) = database_path("evidence-retention-partial-cleanup");
    let store = Store::open(&path).unwrap();
    let first = store
        .put_evidence(
            evidence("evidence://retention/partial-a", "project", b"first"),
            1,
        )
        .await
        .unwrap();
    let second = store
        .put_evidence(
            evidence("evidence://retention/partial-b", "project", b"second"),
            2,
        )
        .await
        .unwrap();
    store.shutdown().await.unwrap();
    let (first_digest, later_digest) = if first.digest.as_str() < second.digest.as_str() {
        (first.digest, second.digest)
    } else {
        (second.digest, first.digest)
    };

    let mut connection = open_connection(&path).unwrap();
    connection
        .execute("DELETE FROM evidence_handles", [])
        .unwrap();
    connection
        .execute_batch(&format!(
            "CREATE TRIGGER fail_later_blob_delete
             BEFORE DELETE ON evidence_blobs
             WHEN OLD.digest = '{}'
             BEGIN SELECT RAISE(ABORT, 'injected cleanup failure'); END;",
            later_digest.as_str()
        ))
        .unwrap();
    let files = EvidenceFiles::open(&path).unwrap();

    let outcome = prune(
        &mut connection,
        &files,
        &ProjectId::from("project"),
        EvidenceRetention::Project,
        2,
        10,
    )
    .unwrap();
    assert_eq!(outcome.handles_deleted, 0);
    assert_eq!(outcome.blobs_deleted, 2);
    assert_eq!(outcome.blobs_pending, 1);
    assert!(outcome.cleanup_unresolved);
    assert!(outcome.has_more);
    assert!(!evidence_blob_path(&path, &first_digest).exists());
    assert!(!evidence_blob_path(&path, &later_digest).exists());
    assert_eq!(
        connection
            .query_row("SELECT COUNT(*) FROM evidence_blobs", [], |row| {
                row.get::<_, u32>(0)
            })
            .unwrap(),
        1
    );

    connection
        .execute("DROP TRIGGER fail_later_blob_delete", [])
        .unwrap();
    let retry = prune(
        &mut connection,
        &files,
        &ProjectId::from("project"),
        EvidenceRetention::Project,
        2,
        10,
    )
    .unwrap();
    assert_eq!(retry.blobs_deleted, 0);
    assert_eq!(retry.blobs_pending, 0);
    assert!(!retry.cleanup_unresolved);
    assert_eq!(
        connection
            .query_row("SELECT COUNT(*) FROM evidence_blobs", [], |row| {
                row.get::<_, u32>(0)
            })
            .unwrap(),
        0
    );
    drop(connection);
    drop(files);
    fs::remove_dir_all(directory).unwrap();
}

#[tokio::test]
async fn retention_prune_rejects_persistent_unbounded_and_invalid_cutoffs() {
    let (directory, path) = database_path("evidence-retention-validation");
    let store = Store::open(&path).unwrap();
    store.shutdown().await.unwrap();
    let mut connection = open_connection(&path).unwrap();
    let files = EvidenceFiles::open(&path).unwrap();

    assert!(matches!(
        prune(
            &mut connection,
            &files,
            &ProjectId::from("project"),
            EvidenceRetention::Persistent,
            10,
            1,
        ),
        Err(StoreError::InvalidEvidencePruneRetention)
    ));
    for limit in [0, MAX_EVIDENCE_PRUNE_BATCH_SIZE + 1] {
        assert!(matches!(
            prune(
                &mut connection,
                &files,
                &ProjectId::from("project"),
                EvidenceRetention::Project,
                10,
                limit,
            ),
            Err(StoreError::InvalidEvidencePruneLimit { limit: actual, maximum })
                if actual == limit && maximum == MAX_EVIDENCE_PRUNE_BATCH_SIZE
        ));
    }
    assert!(matches!(
        prune(
            &mut connection,
            &files,
            &ProjectId::from("project"),
            EvidenceRetention::Project,
            u64::MAX,
            1,
        ),
        Err(StoreError::TimestampOutOfRange(value)) if value == u64::MAX
    ));

    drop(connection);
    drop(files);
    fs::remove_dir_all(directory).unwrap();
}

#[tokio::test]
async fn put_recovers_when_prune_removes_optimistic_install_before_handle_publish() {
    let (directory, path) = database_path("evidence-put-prune-exclusion");
    let store = Store::open(&path).unwrap();
    store.shutdown().await.unwrap();
    let (installed_tx, installed_rx) = mpsc::sync_channel(1);
    let (release_tx, release_rx) = mpsc::sync_channel(1);
    let put_path = path.clone();
    let put_thread = std::thread::spawn(move || {
        let mut connection = open_connection(&put_path).unwrap();
        let files = EvidenceFiles::open(&put_path).unwrap();
        put_with_install_hook(
            &mut connection,
            &files,
            evidence("evidence://retention/concurrent-put", "project", b"new"),
            100,
            || {
                installed_tx.send(()).unwrap();
                release_rx.recv().unwrap();
            },
        )
        .unwrap();
    });
    installed_rx.recv_timeout(Duration::from_secs(2)).unwrap();

    let prune_path = path.clone();
    let (attempting_tx, attempting_rx) = mpsc::sync_channel(1);
    let (pruned_tx, pruned_rx) = mpsc::sync_channel(1);
    let prune_thread = std::thread::spawn(move || {
        let mut connection = open_connection(&prune_path).unwrap();
        let files = EvidenceFiles::open(&prune_path).unwrap();
        attempting_tx.send(()).unwrap();
        let outcome = prune(
            &mut connection,
            &files,
            &ProjectId::from("project"),
            EvidenceRetention::Project,
            99,
            10,
        )
        .unwrap();
        pruned_tx.send(outcome).unwrap();
    });
    attempting_rx.recv_timeout(Duration::from_secs(2)).unwrap();
    let outcome = pruned_rx.recv_timeout(Duration::from_secs(2)).unwrap();
    assert_eq!(outcome.handles_deleted, 0);
    assert_eq!(outcome.blobs_deleted, 0);
    assert_eq!(outcome.blobs_pending, 0);
    assert!(!outcome.cleanup_unresolved);
    prune_thread.join().unwrap();
    release_tx.send(()).unwrap();
    put_thread.join().unwrap();

    let connection = open_connection(&path).unwrap();
    assert_eq!(
        connection
            .query_row(
                "SELECT COUNT(*) FROM evidence_handles
                 WHERE project_id = 'project'
                   AND handle = 'evidence://retention/concurrent-put'",
                [],
                |row| row.get::<_, u32>(0),
            )
            .unwrap(),
        1
    );
    let files = EvidenceFiles::open(&path).unwrap();
    assert!(
        inspect(
            &connection,
            &files,
            &ProjectId::from("project"),
            &EvidenceHandle::parse("evidence://retention/concurrent-put").unwrap(),
        )
        .is_ok()
    );
    drop(connection);
    drop(files);
    fs::remove_dir_all(directory).unwrap();
}
