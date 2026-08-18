use std::{fs, sync::mpsc, time::Duration};

use pam_core::{ContentDigest, EvidenceHandle, ProjectId};
use rusqlite::Connection;
use sha2::{Digest as _, Sha256};

use super::{
    EvidenceRedaction, EvidenceRetention, MAX_EVIDENCE_BYTES, MAX_EVIDENCE_RANGE_BYTES,
    PutEvidence, Store, StoreError,
};
use crate::{
    evidence::{
        EvidenceFiles, content_digest, evidence_blob_path, install_blob_with_namespace_swap,
        validate_size,
    },
    store::database_path,
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
