use std::{
    io::{ErrorKind, Read, Write},
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

use cap_fs_ext::{
    DirExt as _, FollowSymlinks, MetadataExt as _, OpenOptionsFollowExt as _,
    OpenOptionsSyncExt as _, ambient_authority,
};
use cap_std::fs::{Dir, File, OpenOptions};
use pam_core::{ContentDigest, EvidenceHandle, ProjectId};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

use crate::store::{sql_integer, unsigned_integer};
use crate::{
    EvidenceMetadata, EvidenceRedaction, EvidenceRetention, MAX_EVIDENCE_BYTES,
    MAX_EVIDENCE_MEDIA_TYPE_BYTES, MAX_EVIDENCE_PRUNE_BATCH_SIZE, MAX_EVIDENCE_RANGE_BYTES,
    PutEvidence, StoreError,
};

const EVIDENCE_DIRECTORY: &str = "evidence";
const INSTALL_INTENT_GRACE_MS: u64 = 10 * 60 * 1_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct PruneOutcome {
    pub(super) handles_deleted: u32,
    pub(super) blobs_deleted: u32,
    pub(super) blobs_pending: u32,
    pub(super) cleanup_unresolved: bool,
    pub(super) has_more: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct InstallIntent {
    attempt_id: String,
    temporary_name: String,
}

impl InstallIntent {
    fn new() -> Self {
        Self {
            attempt_id: Uuid::new_v4().hyphenated().to_string(),
            temporary_name: Uuid::new_v4().hyphenated().to_string(),
        }
    }
}

pub(super) struct EvidenceFiles {
    base: Dir,
}

impl EvidenceFiles {
    pub(super) fn open(database_path: &Path) -> Result<Self, StoreError> {
        let parent = database_path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        Ok(Self {
            base: Dir::open_ambient_dir(parent, ambient_authority())?,
        })
    }
}

pub(super) fn put(
    connection: &mut Connection,
    files: &EvidenceFiles,
    evidence: PutEvidence,
    now_ms: u64,
) -> Result<EvidenceMetadata, StoreError> {
    put_after_blob_installed(connection, files, evidence, now_ms, || {})
}

fn put_after_blob_installed<F>(
    connection: &mut Connection,
    files: &EvidenceFiles,
    evidence: PutEvidence,
    now_ms: u64,
    after_blob_installed: F,
) -> Result<EvidenceMetadata, StoreError>
where
    F: FnOnce(),
{
    validate_media_type(&evidence.media_type)?;
    let size_bytes =
        u64::try_from(evidence.bytes.len()).map_err(|_| StoreError::EvidenceTooLarge {
            size_bytes: u64::MAX,
            maximum_bytes: MAX_EVIDENCE_BYTES,
        })?;
    validate_size(size_bytes)?;
    let now = sql_integer(now_ms)?;
    let size = sql_integer(size_bytes)?;
    let digest = content_digest(&evidence.bytes);
    if let Some(existing) = find_metadata(connection, &evidence.project_id, &evidence.handle)? {
        ensure_same_mapping(&existing, &evidence, &digest)?;
        verify_blob(files, &existing.digest, existing.size_bytes)?;
        return Ok(existing);
    }

    let intent = InstallIntent::new();
    record_install_intent(
        connection,
        &intent,
        &digest,
        size,
        sql_integer(system_now_ms())?,
    )?;
    // Expensive write, sync, and full-content verification happen without a
    // SQLite writer lock. A stale intent makes a crash orphan discoverable.
    install_blob(files, &digest, &evidence.bytes, &intent.temporary_name)?;
    after_blob_installed();
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;

    if let Some(existing) = find_metadata_tx(&transaction, &evidence.project_id, &evidence.handle)?
    {
        ensure_same_mapping(&existing, &evidence, &digest)?;
        ensure_blob_entry(
            files,
            &digest,
            size_bytes,
            &evidence.bytes,
            &intent.temporary_name,
        )?;
        transaction.commit()?;
        clear_install_intent(connection, &intent.attempt_id);
        return Ok(existing);
    }

    // Pruning uses the same writer exclusion window. If it removed the
    // optimistic install before this transaction began, reinstall now; otherwise
    // only bounded metadata is checked while the global writer is held.
    ensure_blob_entry(
        files,
        &digest,
        size_bytes,
        &evidence.bytes,
        &intent.temporary_name,
    )?;
    transaction.execute(
        "INSERT OR IGNORE INTO projects(project_id) VALUES (?1)",
        [evidence.project_id.as_str()],
    )?;
    transaction.execute(
        "INSERT OR IGNORE INTO evidence_blobs(digest, size_bytes) VALUES (?1, ?2)",
        params![digest.as_str(), size],
    )?;
    let stored_size: i64 = transaction.query_row(
        "SELECT size_bytes FROM evidence_blobs WHERE digest = ?1",
        [digest.as_str()],
        |row| row.get(0),
    )?;
    if stored_size != size {
        return Err(StoreError::InvalidState(
            "content digest has conflicting stored size".to_owned(),
        ));
    }

    if let Some(existing) = find_metadata_tx(&transaction, &evidence.project_id, &evidence.handle)?
    {
        ensure_same_mapping(&existing, &evidence, &digest)?;
        transaction.commit()?;
        clear_install_intent(connection, &intent.attempt_id);
        return Ok(existing);
    }

    transaction.execute(
        "INSERT INTO evidence_handles(
            project_id, handle, digest, media_type, retention, redaction, created_at_ms
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            evidence.project_id.as_str(),
            evidence.handle.as_str(),
            digest.as_str(),
            evidence.media_type,
            evidence.retention.as_str(),
            evidence.redaction.as_str(),
            now
        ],
    )?;
    transaction.commit()?;
    clear_install_intent(connection, &intent.attempt_id);

    Ok(EvidenceMetadata {
        handle: evidence.handle,
        digest,
        size_bytes,
        media_type: evidence.media_type,
        project_id: evidence.project_id,
        retention: evidence.retention,
        redaction: evidence.redaction,
        created_at_ms: now_ms,
    })
}

fn record_install_intent(
    connection: &Connection,
    intent: &InstallIntent,
    digest: &ContentDigest,
    size_bytes: i64,
    started_at_ms: i64,
) -> Result<(), StoreError> {
    connection.execute(
        "INSERT INTO evidence_install_intents(
             attempt_id, digest, temporary_name, size_bytes, started_at_ms
        ) VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            intent.attempt_id.as_str(),
            digest.as_str(),
            intent.temporary_name.as_str(),
            size_bytes,
            started_at_ms
        ],
    )?;
    Ok(())
}

fn clear_install_intent(connection: &Connection, attempt_id: &str) {
    drop(connection.execute(
        "DELETE FROM evidence_install_intents WHERE attempt_id = ?1",
        [attempt_id],
    ));
}

/// Deletes one deterministic, bounded page of non-persistent evidence handles.
///
/// The inclusive cutoff and retention class are explicit because `session` does
/// not identify a lifecycle by itself. Filesystem unlink and `SQLite` commit are
/// deliberately not claimed to be atomic; writer exclusion only prevents a
/// concurrent put from publishing a handle for a blob while it is being pruned.
pub(super) fn prune(
    connection: &mut Connection,
    files: &EvidenceFiles,
    project_id: &ProjectId,
    retention: EvidenceRetention,
    created_before_unix_ms: u64,
    limit: u32,
) -> Result<PruneOutcome, StoreError> {
    if retention == EvidenceRetention::Persistent {
        return Err(StoreError::InvalidEvidencePruneRetention);
    }
    if !(1..=MAX_EVIDENCE_PRUNE_BATCH_SIZE).contains(&limit) {
        return Err(StoreError::InvalidEvidencePruneLimit {
            limit,
            maximum: MAX_EVIDENCE_PRUNE_BATCH_SIZE,
        });
    }
    let cutoff = sql_integer(created_before_unix_ms)?;
    let query_limit = i64::from(limit) + 1;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let mut candidates = {
        let mut statement = transaction.prepare(
            "SELECT handle, digest
             FROM evidence_handles
             WHERE project_id = ?1 AND retention = ?2 AND created_at_ms <= ?3
             ORDER BY created_at_ms, handle
             LIMIT ?4",
        )?;
        statement
            .query_map(
                params![project_id.as_str(), retention.as_str(), cutoff, query_limit],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )?
            .collect::<Result<Vec<_>, _>>()?
    };
    let has_more = candidates.len()
        > usize::try_from(limit)
            .map_err(|_| StoreError::InvalidState("evidence prune limit overflow".to_owned()))?;
    if has_more {
        candidates.pop();
    }

    for (handle, _) in &candidates {
        let deleted = transaction.execute(
            "DELETE FROM evidence_handles
             WHERE project_id = ?1 AND handle = ?2 AND retention = ?3
               AND created_at_ms <= ?4",
            params![project_id.as_str(), handle, retention.as_str(), cutoff],
        )?;
        if deleted != 1 {
            return Err(StoreError::InvalidState(
                "selected evidence handle changed during prune".to_owned(),
            ));
        }
    }
    transaction.commit()?;

    // Filesystem cleanup is a recoverable phase after logical handle deletion.
    // Each blob is rechecked under its own writer exclusion window, so a new put
    // cannot publish a reference between the zero-reference check and unlink.
    let cleanup_now_ms = system_now_ms();
    let intent_cleanup = cleanup_stale_install_intents(connection, files, cleanup_now_ms, limit);
    let blob_cleanup = cleanup_unreferenced_blobs(connection, files, cleanup_now_ms, limit);
    Ok(PruneOutcome {
        handles_deleted: u32::try_from(candidates.len())
            .map_err(|_| StoreError::InvalidState("evidence prune count overflow".to_owned()))?,
        blobs_deleted: intent_cleanup.deleted.saturating_add(blob_cleanup.deleted),
        blobs_pending: intent_cleanup.pending.saturating_add(blob_cleanup.pending),
        cleanup_unresolved: intent_cleanup.unresolved || blob_cleanup.unresolved,
        has_more: has_more || intent_cleanup.has_more || blob_cleanup.has_more,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct BlobCleanupOutcome {
    deleted: u32,
    pending: u32,
    unresolved: bool,
    has_more: bool,
}

impl BlobCleanupOutcome {
    fn unresolved() -> Self {
        Self {
            deleted: 0,
            pending: 0,
            unresolved: true,
            has_more: true,
        }
    }

    fn record(&mut self, attempt: CleanupAttempt, digest: &str, connection: &Connection, now: u64) {
        if attempt.blob_removed {
            self.deleted += 1;
        }
        if !attempt.resolved {
            self.pending += 1;
            self.unresolved = true;
            self.has_more = true;
            drop(record_gc_attempt(connection, digest, now));
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CleanupAttempt {
    blob_removed: bool,
    resolved: bool,
}

fn cleanup_unreferenced_blobs(
    connection: &mut Connection,
    files: &EvidenceFiles,
    now_ms: u64,
    limit: u32,
) -> BlobCleanupOutcome {
    let query_limit = i64::from(limit) + 1;
    let selected = (|| -> Result<Vec<String>, StoreError> {
        let mut statement = connection.prepare(
            "SELECT evidence_blobs.digest FROM evidence_blobs
             LEFT JOIN evidence_gc_attempts
               ON evidence_gc_attempts.digest = evidence_blobs.digest
             WHERE NOT EXISTS(
                 SELECT 1 FROM evidence_handles WHERE evidence_handles.digest = evidence_blobs.digest
             )
             ORDER BY COALESCE(evidence_gc_attempts.last_attempt_ms, 0), evidence_blobs.digest
             LIMIT ?1",
        )?;
        Ok(statement
            .query_map([query_limit], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?)
    })();
    let Ok(mut digests) = selected else {
        return BlobCleanupOutcome::unresolved();
    };
    let has_more = digests.len() > usize::try_from(limit).unwrap_or(usize::MAX);
    if has_more {
        digests.pop();
    }

    let mut outcome = BlobCleanupOutcome {
        deleted: 0,
        pending: 0,
        unresolved: false,
        has_more,
    };
    for stored_digest in digests {
        let attempt = cleanup_unreferenced_blob(connection, files, &stored_digest);
        outcome.record(attempt, &stored_digest, connection, now_ms);
    }
    outcome.has_more |= outcome.pending > 0;
    outcome
}

fn cleanup_unreferenced_blob(
    connection: &mut Connection,
    files: &EvidenceFiles,
    stored_digest: &str,
) -> CleanupAttempt {
    let mut blob_removed = false;
    let result = (|| -> Result<(), StoreError> {
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let referenced: bool = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM evidence_handles WHERE digest = ?1)",
            [stored_digest],
            |row| row.get(0),
        )?;
        if referenced {
            transaction.commit()?;
            return Ok(());
        }
        let digest = ContentDigest::parse(stored_digest.to_owned())
            .map_err(|error| StoreError::InvalidState(error.to_string()))?;
        blob_removed = remove_blob(files, &digest)? == BlobRemoval::Removed;
        let row_count = transaction.execute(
            "DELETE FROM evidence_blobs
             WHERE digest = ?1
               AND NOT EXISTS(SELECT 1 FROM evidence_handles WHERE digest = ?1)",
            [stored_digest],
        )?;
        if row_count != 1 {
            return Err(StoreError::InvalidState(
                "unreferenced evidence blob changed during prune".to_owned(),
            ));
        }
        transaction.execute(
            "DELETE FROM evidence_gc_attempts WHERE digest = ?1",
            [stored_digest],
        )?;
        transaction.commit()?;
        Ok(())
    })();
    CleanupAttempt {
        blob_removed,
        resolved: result.is_ok(),
    }
}

type StoredInstallIntent = (String, String, String);

fn cleanup_stale_install_intents(
    connection: &mut Connection,
    files: &EvidenceFiles,
    now_ms: u64,
    limit: u32,
) -> BlobCleanupOutcome {
    let Ok(stale_before) = sql_integer(now_ms.saturating_sub(INSTALL_INTENT_GRACE_MS)) else {
        return BlobCleanupOutcome::unresolved();
    };
    let query_limit = i64::from(limit) + 1;
    let selected = (|| -> Result<Vec<StoredInstallIntent>, StoreError> {
        let mut statement = connection.prepare(
            "SELECT evidence_install_intents.attempt_id,
                    evidence_install_intents.digest,
                    evidence_install_intents.temporary_name
             FROM evidence_install_intents
             LEFT JOIN evidence_gc_attempts
               ON evidence_gc_attempts.digest = evidence_install_intents.digest
             WHERE evidence_install_intents.started_at_ms <= ?1
             ORDER BY COALESCE(evidence_gc_attempts.last_attempt_ms, 0),
                      evidence_install_intents.started_at_ms,
                      evidence_install_intents.attempt_id
             LIMIT ?2",
        )?;
        Ok(statement
            .query_map(params![stale_before, query_limit], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?))
            })?
            .collect::<Result<Vec<_>, _>>()?)
    })();
    let Ok(mut intents) = selected else {
        return BlobCleanupOutcome::unresolved();
    };
    let has_more = intents.len() > usize::try_from(limit).unwrap_or(usize::MAX);
    if has_more {
        intents.pop();
    }

    let mut outcome = BlobCleanupOutcome {
        deleted: 0,
        pending: 0,
        unresolved: false,
        has_more,
    };
    for (attempt_id, stored_digest, temporary_name) in intents {
        let attempt = cleanup_stale_install_intent(
            connection,
            files,
            &attempt_id,
            &stored_digest,
            &temporary_name,
            stale_before,
        );
        outcome.record(attempt, &stored_digest, connection, now_ms);
    }
    outcome.has_more |= outcome.pending > 0;
    outcome
}

fn cleanup_stale_install_intent(
    connection: &mut Connection,
    files: &EvidenceFiles,
    attempt_id: &str,
    selected_digest: &str,
    selected_temporary_name: &str,
    stale_before: i64,
) -> CleanupAttempt {
    let mut blob_removed = false;
    let result = (|| -> Result<(), StoreError> {
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let stored = transaction
            .query_row(
                "SELECT digest, temporary_name
                 FROM evidence_install_intents
                 WHERE attempt_id = ?1 AND started_at_ms <= ?2",
                params![attempt_id, stale_before],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()?;
        let Some((stored_digest, temporary_name)) = stored else {
            transaction.commit()?;
            return Ok(());
        };
        if stored_digest != selected_digest || temporary_name != selected_temporary_name {
            return Err(StoreError::InvalidState(
                "evidence install intent changed during cleanup".to_owned(),
            ));
        }

        remove_temporary(files, &temporary_name)?;
        let tracked: bool = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM evidence_blobs WHERE digest = ?1)",
            [&stored_digest],
            |row| row.get(0),
        )?;
        let another_attempt: bool = transaction.query_row(
            "SELECT EXISTS(
                 SELECT 1 FROM evidence_install_intents
                 WHERE digest = ?1 AND attempt_id <> ?2
             )",
            params![stored_digest, attempt_id],
            |row| row.get(0),
        )?;
        if !tracked && !another_attempt {
            let digest = ContentDigest::parse(stored_digest.clone())
                .map_err(|error| StoreError::InvalidState(error.to_string()))?;
            blob_removed = remove_blob(files, &digest)? == BlobRemoval::Removed;
        }
        let deleted = transaction.execute(
            "DELETE FROM evidence_install_intents
             WHERE attempt_id = ?1 AND started_at_ms <= ?2",
            params![attempt_id, stale_before],
        )?;
        if deleted != 1 {
            return Err(StoreError::InvalidState(
                "evidence install intent changed during cleanup".to_owned(),
            ));
        }
        transaction.execute(
            "DELETE FROM evidence_gc_attempts
             WHERE digest = ?1
               AND NOT EXISTS(
                   SELECT 1 FROM evidence_install_intents WHERE digest = ?1
               )",
            [&stored_digest],
        )?;
        transaction.commit()?;
        Ok(())
    })();
    CleanupAttempt {
        blob_removed,
        resolved: result.is_ok(),
    }
}

fn record_gc_attempt(connection: &Connection, digest: &str, now_ms: u64) -> Result<(), StoreError> {
    connection.execute(
        "INSERT INTO evidence_gc_attempts(digest, last_attempt_ms) VALUES (?1, ?2)
         ON CONFLICT(digest) DO UPDATE SET last_attempt_ms = excluded.last_attempt_ms",
        params![digest, sql_integer(now_ms)?],
    )?;
    Ok(())
}

fn system_now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

pub(super) fn inspect(
    connection: &Connection,
    files: &EvidenceFiles,
    project_id: &ProjectId,
    handle: &EvidenceHandle,
) -> Result<EvidenceMetadata, StoreError> {
    let metadata = find_metadata(connection, project_id, handle)?.ok_or_else(|| {
        StoreError::EvidenceNotFound {
            project_id: project_id.clone(),
            handle: handle.clone(),
        }
    })?;
    verify_blob(files, &metadata.digest, metadata.size_bytes)?;
    Ok(metadata)
}

pub(super) fn read_range(
    connection: &Connection,
    files: &EvidenceFiles,
    project_id: &ProjectId,
    handle: &EvidenceHandle,
    offset: u64,
    length: u64,
) -> Result<Vec<u8>, StoreError> {
    if length > MAX_EVIDENCE_RANGE_BYTES {
        return Err(StoreError::EvidenceRangeTooLarge {
            length,
            maximum_bytes: MAX_EVIDENCE_RANGE_BYTES,
        });
    }
    let metadata = find_metadata(connection, project_id, handle)?.ok_or_else(|| {
        StoreError::EvidenceNotFound {
            project_id: project_id.clone(),
            handle: handle.clone(),
        }
    })?;
    if offset > metadata.size_bytes {
        return Err(StoreError::EvidenceRangeOutOfBounds {
            offset,
            size_bytes: metadata.size_bytes,
        });
    }
    let bytes = verified_blob(files, &metadata.digest, metadata.size_bytes)?;
    let end = offset.saturating_add(length).min(metadata.size_bytes);
    let start = usize::try_from(offset)
        .map_err(|_| StoreError::InvalidState("evidence offset overflow".to_owned()))?;
    let end = usize::try_from(end)
        .map_err(|_| StoreError::InvalidState("evidence range overflow".to_owned()))?;
    Ok(bytes[start..end].to_vec())
}

fn ensure_same_mapping(
    existing: &EvidenceMetadata,
    requested: &PutEvidence,
    digest: &ContentDigest,
) -> Result<(), StoreError> {
    if existing.digest == *digest
        && existing.media_type == requested.media_type
        && existing.retention == requested.retention
        && existing.redaction == requested.redaction
    {
        Ok(())
    } else {
        Err(StoreError::EvidenceHandleConflict {
            project_id: requested.project_id.clone(),
            handle: requested.handle.clone(),
        })
    }
}

fn validate_media_type(media_type: &str) -> Result<(), StoreError> {
    if media_type.is_empty()
        || media_type.len() > MAX_EVIDENCE_MEDIA_TYPE_BYTES
        || media_type.trim() != media_type
        || !media_type.contains('/')
        || !media_type
            .as_bytes()
            .iter()
            .all(|byte| matches!(byte, 0x20..=0x7e))
    {
        Err(StoreError::InvalidEvidenceMediaType)
    } else {
        Ok(())
    }
}

type StoredMetadata = (String, String, i64, String, String, String, i64);

fn find_metadata(
    connection: &Connection,
    project_id: &ProjectId,
    handle: &EvidenceHandle,
) -> Result<Option<EvidenceMetadata>, StoreError> {
    let stored = connection
        .query_row(
            "SELECT handle, digest, size_bytes, media_type, retention, redaction, created_at_ms
             FROM evidence_handles
             JOIN evidence_blobs USING (digest)
             WHERE project_id = ?1 AND handle = ?2",
            params![project_id.as_str(), handle.as_str()],
            metadata_row,
        )
        .optional()?;
    stored
        .map(|row| metadata_from_row(project_id.clone(), row))
        .transpose()
}

fn find_metadata_tx(
    transaction: &Transaction<'_>,
    project_id: &ProjectId,
    handle: &EvidenceHandle,
) -> Result<Option<EvidenceMetadata>, StoreError> {
    let stored = transaction
        .query_row(
            "SELECT handle, digest, size_bytes, media_type, retention, redaction, created_at_ms
             FROM evidence_handles
             JOIN evidence_blobs USING (digest)
             WHERE project_id = ?1 AND handle = ?2",
            params![project_id.as_str(), handle.as_str()],
            metadata_row,
        )
        .optional()?;
    stored
        .map(|row| metadata_from_row(project_id.clone(), row))
        .transpose()
}

fn metadata_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<StoredMetadata> {
    Ok((
        row.get(0)?,
        row.get(1)?,
        row.get(2)?,
        row.get(3)?,
        row.get(4)?,
        row.get(5)?,
        row.get(6)?,
    ))
}

fn metadata_from_row(
    project_id: ProjectId,
    stored: StoredMetadata,
) -> Result<EvidenceMetadata, StoreError> {
    validate_media_type(&stored.3)?;
    Ok(EvidenceMetadata {
        handle: EvidenceHandle::parse(stored.0)
            .map_err(|error| StoreError::InvalidState(error.to_string()))?,
        digest: ContentDigest::parse(stored.1)
            .map_err(|error| StoreError::InvalidState(error.to_string()))?,
        size_bytes: unsigned_integer(stored.2)?,
        media_type: stored.3,
        project_id,
        retention: parse_retention(&stored.4)?,
        redaction: parse_redaction(&stored.5)?,
        created_at_ms: unsigned_integer(stored.6)?,
    })
}

fn parse_retention(value: &str) -> Result<EvidenceRetention, StoreError> {
    match value {
        "session" => Ok(EvidenceRetention::Session),
        "project" => Ok(EvidenceRetention::Project),
        "persistent" => Ok(EvidenceRetention::Persistent),
        _ => Err(StoreError::InvalidState(format!(
            "invalid evidence retention {value}"
        ))),
    }
}

fn parse_redaction(value: &str) -> Result<EvidenceRedaction, StoreError> {
    match value {
        "unredacted" => Ok(EvidenceRedaction::Unredacted),
        "redacted" => Ok(EvidenceRedaction::Redacted),
        _ => Err(StoreError::InvalidState(format!(
            "invalid evidence redaction {value}"
        ))),
    }
}

pub(super) fn content_digest(bytes: &[u8]) -> ContentDigest {
    ContentDigest::from_sha256(Sha256::digest(bytes).into())
}

pub(super) fn validate_size(size_bytes: u64) -> Result<(), StoreError> {
    if size_bytes > MAX_EVIDENCE_BYTES {
        Err(StoreError::EvidenceTooLarge {
            size_bytes,
            maximum_bytes: MAX_EVIDENCE_BYTES,
        })
    } else {
        Ok(())
    }
}

fn install_blob(
    files: &EvidenceFiles,
    digest: &ContentDigest,
    bytes: &[u8],
    temporary_name: &str,
) -> Result<(), StoreError> {
    install_blob_after_directories_opened(files, digest, bytes, temporary_name, || {})
}

fn ensure_blob_entry(
    files: &EvidenceFiles,
    digest: &ContentDigest,
    size_bytes: u64,
    bytes: &[u8],
    temporary_name: &str,
) -> Result<(), StoreError> {
    let directories = match BlobDirectories::open(files, digest, false) {
        Ok(directories) => directories,
        Err(StoreError::Io(error)) if error.kind() == ErrorKind::NotFound => {
            return install_blob(files, digest, bytes, temporary_name);
        }
        Err(error) => return Err(error),
    };
    directories.ensure_current(files)?;
    match directories.shard.symlink_metadata(digest.sha256_hex()) {
        Ok(metadata) if metadata.is_file() && metadata.len() == size_bytes => Ok(()),
        Ok(metadata) if metadata.file_type().is_symlink() => Err(StoreError::UnsafeEvidencePath),
        Ok(_) => Err(StoreError::EvidenceBlobCorrupt(digest.clone())),
        Err(error) if error.kind() == ErrorKind::NotFound => {
            install_blob(files, digest, bytes, temporary_name)
        }
        Err(error) => Err(error.into()),
    }
}

fn install_blob_after_directories_opened<F>(
    files: &EvidenceFiles,
    digest: &ContentDigest,
    bytes: &[u8],
    temporary_name: &str,
    after_directories_opened: F,
) -> Result<(), StoreError>
where
    F: FnOnce(),
{
    let directories = WriteDirectories::open(files, digest)?;
    after_directories_opened();
    let size_bytes = u64::try_from(bytes.len()).expect("evidence length fits u64");
    match verified_blob_from_shard(&directories.blob.shard, digest, size_bytes) {
        Ok(_) => {
            directories.blob.ensure_current(files)?;
            return Ok(());
        }
        Err(StoreError::EvidenceBlobMissing(_)) => {}
        Err(error) => return Err(error),
    }

    validate_temporary_name(temporary_name)?;
    let temporary = TemporaryFile::new(&directories.tmp, temporary_name);
    let mut options = OpenOptions::new();
    options
        .write(true)
        .create_new(true)
        .follow(FollowSymlinks::No);
    let mut file = directories.tmp.open_with(temporary_name, &options)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(StoreError::UnsafeEvidencePath);
    }
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);

    match directories
        .tmp
        .hard_link(temporary_name, &directories.blob.shard, digest.sha256_hex())
    {
        Ok(()) => sync_directory(&directories.blob.shard)?,
        Err(error) if error.kind() == ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error.into()),
    }
    verified_blob_from_shard(&directories.blob.shard, digest, size_bytes)?;
    directories.blob.ensure_current(files)?;
    drop(temporary);
    Ok(())
}

fn validate_temporary_name(temporary_name: &str) -> Result<(), StoreError> {
    let parsed = Uuid::parse_str(temporary_name)
        .map_err(|_| StoreError::InvalidState("invalid evidence temporary name".to_owned()))?;
    if parsed.hyphenated().to_string() == temporary_name {
        Ok(())
    } else {
        Err(StoreError::InvalidState(
            "invalid evidence temporary name".to_owned(),
        ))
    }
}

struct TemporaryFile<'a> {
    directory: &'a Dir,
    name: &'a str,
}

impl<'a> TemporaryFile<'a> {
    fn new(directory: &'a Dir, name: &'a str) -> Self {
        Self { directory, name }
    }
}

impl Drop for TemporaryFile<'_> {
    fn drop(&mut self) {
        let _ = self.directory.remove_file(self.name);
    }
}

fn verify_blob(
    files: &EvidenceFiles,
    digest: &ContentDigest,
    size_bytes: u64,
) -> Result<(), StoreError> {
    verified_blob(files, digest, size_bytes).map(|_| ())
}

fn verified_blob(
    files: &EvidenceFiles,
    digest: &ContentDigest,
    size_bytes: u64,
) -> Result<Vec<u8>, StoreError> {
    if size_bytes > MAX_EVIDENCE_BYTES {
        return Err(StoreError::EvidenceBlobCorrupt(digest.clone()));
    }
    let directories = match BlobDirectories::open(files, digest, false) {
        Ok(directories) => directories,
        Err(StoreError::Io(error)) if error.kind() == ErrorKind::NotFound => {
            return Err(StoreError::EvidenceBlobMissing(digest.clone()));
        }
        Err(error) => return Err(error),
    };
    let bytes = verified_blob_from_shard(&directories.shard, digest, size_bytes)?;
    directories.ensure_current(files)?;
    Ok(bytes)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BlobRemoval {
    Removed,
    AlreadyAbsent,
}

fn remove_temporary(
    files: &EvidenceFiles,
    temporary_name: &str,
) -> Result<BlobRemoval, StoreError> {
    validate_temporary_name(temporary_name)?;
    let directories = match TemporaryDirectories::open(files, false) {
        Ok(directories) => directories,
        Err(StoreError::Io(error)) if error.kind() == ErrorKind::NotFound => {
            return Ok(BlobRemoval::AlreadyAbsent);
        }
        Err(error) => return Err(error),
    };
    directories.ensure_current(files)?;
    match directories.tmp.symlink_metadata(temporary_name) {
        Ok(metadata) if metadata.is_file() => {}
        Ok(_) => return Err(StoreError::UnsafeEvidencePath),
        Err(error) if error.kind() == ErrorKind::NotFound => {
            return Ok(BlobRemoval::AlreadyAbsent);
        }
        Err(error) => return Err(error.into()),
    }
    directories.tmp.remove_file(temporary_name)?;
    sync_directory(&directories.tmp)?;
    directories.ensure_current(files)?;
    Ok(BlobRemoval::Removed)
}

fn remove_blob(files: &EvidenceFiles, digest: &ContentDigest) -> Result<BlobRemoval, StoreError> {
    let directories = match BlobDirectories::open(files, digest, false) {
        Ok(directories) => directories,
        Err(StoreError::Io(error)) if error.kind() == ErrorKind::NotFound => {
            return Ok(BlobRemoval::AlreadyAbsent);
        }
        Err(error) => return Err(error),
    };
    directories.ensure_current(files)?;
    let name = digest.sha256_hex();
    match directories.shard.symlink_metadata(name) {
        Ok(metadata) if metadata.is_file() => {}
        Ok(metadata) if metadata.file_type().is_symlink() => {
            return Err(StoreError::UnsafeEvidencePath);
        }
        Ok(_) => return Err(StoreError::EvidenceBlobCorrupt(digest.clone())),
        Err(error) if error.kind() == ErrorKind::NotFound => {
            return Ok(BlobRemoval::AlreadyAbsent);
        }
        Err(error) => return Err(error.into()),
    }
    directories.shard.remove_file(name)?;
    sync_directory(&directories.shard)?;
    directories.ensure_current(files)?;
    Ok(BlobRemoval::Removed)
}

fn verified_blob_from_shard(
    shard: &Dir,
    digest: &ContentDigest,
    size_bytes: u64,
) -> Result<Vec<u8>, StoreError> {
    let mut options = OpenOptions::new();
    options.read(true).follow(FollowSymlinks::No).nonblock(true);
    let file = match shard.open_with(digest.sha256_hex(), &options) {
        Ok(file) => file,
        Err(error) if error.kind() == ErrorKind::NotFound => {
            return Err(StoreError::EvidenceBlobMissing(digest.clone()));
        }
        Err(error) => return classify_blob_open_error(shard, digest, error),
    };
    verified_open_file(file, digest, size_bytes)
}

fn classify_blob_open_error(
    shard: &Dir,
    digest: &ContentDigest,
    error: std::io::Error,
) -> Result<Vec<u8>, StoreError> {
    match shard.symlink_metadata(digest.sha256_hex()) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(StoreError::UnsafeEvidencePath),
        Ok(_) => Err(StoreError::EvidenceBlobCorrupt(digest.clone())),
        Err(classification_error) if classification_error.kind() == ErrorKind::NotFound => {
            Err(StoreError::EvidenceBlobMissing(digest.clone()))
        }
        Err(_) => Err(error.into()),
    }
}

fn verified_open_file(
    file: File,
    digest: &ContentDigest,
    size_bytes: u64,
) -> Result<Vec<u8>, StoreError> {
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() != size_bytes {
        return Err(StoreError::EvidenceBlobCorrupt(digest.clone()));
    }
    let mut bytes = Vec::with_capacity(
        usize::try_from(size_bytes).map_err(|_| StoreError::EvidenceBlobCorrupt(digest.clone()))?,
    );
    file.take(size_bytes.saturating_add(1))
        .read_to_end(&mut bytes)?;
    if u64::try_from(bytes.len()).ok() != Some(size_bytes) || content_digest(&bytes) != *digest {
        return Err(StoreError::EvidenceBlobCorrupt(digest.clone()));
    }
    Ok(bytes)
}

struct BlobDirectories {
    root: Dir,
    blobs: Dir,
    sha256: Dir,
    shard_name: String,
    shard: Dir,
}

impl BlobDirectories {
    fn open(
        files: &EvidenceFiles,
        digest: &ContentDigest,
        create: bool,
    ) -> Result<Self, StoreError> {
        let root = open_directory(&files.base, EVIDENCE_DIRECTORY, create)?;
        let blobs = open_directory(&root, "blobs", create)?;
        let sha256 = open_directory(&blobs, "sha256", create)?;
        let shard_name = digest.sha256_hex()[..2].to_owned();
        let shard = open_directory(&sha256, &shard_name, create)?;
        Ok(Self {
            root,
            blobs,
            sha256,
            shard_name,
            shard,
        })
    }

    fn ensure_current(&self, files: &EvidenceFiles) -> Result<(), StoreError> {
        ensure_same_directory(&files.base, EVIDENCE_DIRECTORY, &self.root)?;
        ensure_same_directory(&self.root, "blobs", &self.blobs)?;
        ensure_same_directory(&self.blobs, "sha256", &self.sha256)?;
        ensure_same_directory(&self.sha256, &self.shard_name, &self.shard)
    }
}

struct WriteDirectories {
    blob: BlobDirectories,
    tmp: Dir,
}

struct TemporaryDirectories {
    root: Dir,
    tmp: Dir,
}

impl TemporaryDirectories {
    fn open(files: &EvidenceFiles, create: bool) -> Result<Self, StoreError> {
        let root = open_directory(&files.base, EVIDENCE_DIRECTORY, create)?;
        let tmp = open_directory(&root, "tmp", create)?;
        Ok(Self { root, tmp })
    }

    fn ensure_current(&self, files: &EvidenceFiles) -> Result<(), StoreError> {
        ensure_same_directory(&files.base, EVIDENCE_DIRECTORY, &self.root)?;
        ensure_same_directory(&self.root, "tmp", &self.tmp)
    }
}

impl WriteDirectories {
    fn open(files: &EvidenceFiles, digest: &ContentDigest) -> Result<Self, StoreError> {
        let blob = BlobDirectories::open(files, digest, true)?;
        let tmp = open_directory(&blob.root, "tmp", true)?;
        Ok(Self { blob, tmp })
    }
}

fn open_directory(parent: &Dir, name: &str, create: bool) -> Result<Dir, StoreError> {
    match parent.open_dir_nofollow(name) {
        Ok(directory) => verify_open_directory(directory),
        Err(error) if create && error.kind() == ErrorKind::NotFound => {
            match parent.create_dir(name) {
                Ok(()) => sync_directory(parent)?,
                Err(error) if error.kind() == ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
            parent
                .open_dir_nofollow(name)
                .and_then(verify_directory_io)
                .map_err(|error| classify_directory_open_error(parent, name, error))
        }
        Err(error) => Err(classify_directory_open_error(parent, name, error)),
    }
}

fn verify_open_directory(directory: Dir) -> Result<Dir, StoreError> {
    verify_directory_io(directory).map_err(StoreError::Io)
}

fn verify_directory_io(directory: Dir) -> std::io::Result<Dir> {
    if directory.dir_metadata()?.is_dir() {
        Ok(directory)
    } else {
        Err(std::io::Error::other(
            "opened evidence path is not a directory",
        ))
    }
}

fn classify_directory_open_error(parent: &Dir, name: &str, error: std::io::Error) -> StoreError {
    match parent.symlink_metadata(name) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            StoreError::UnsafeEvidencePath
        }
        _ => StoreError::Io(error),
    }
}

fn ensure_same_directory(
    parent: &Dir,
    name: impl AsRef<Path>,
    expected: &Dir,
) -> Result<(), StoreError> {
    let current = parent
        .open_dir_nofollow(name)
        .map_err(|_| StoreError::UnsafeEvidencePath)?;
    if same_directory(&current, expected)? {
        Ok(())
    } else {
        Err(StoreError::UnsafeEvidencePath)
    }
}

fn same_directory(left: &Dir, right: &Dir) -> Result<bool, StoreError> {
    let left = left.dir_metadata()?;
    let right = right.dir_metadata()?;
    Ok(left.dev() == right.dev() && left.ino() == right.ino())
}

#[cfg(unix)]
fn sync_directory(directory: &Dir) -> Result<(), StoreError> {
    // `cap_std::Dir` may hold an `O_PATH` descriptor on Linux. Reopen `.` with
    // read access so `fsync` receives a syncable directory descriptor.
    directory.open(".")?.sync_all()?;
    Ok(())
}

#[cfg(not(unix))]
fn sync_directory(_directory: &Dir) -> Result<(), StoreError> {
    Ok(())
}

#[cfg(test)]
pub(super) fn evidence_blob_path(
    database_path: &Path,
    digest: &ContentDigest,
) -> std::path::PathBuf {
    database_path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
        .join(EVIDENCE_DIRECTORY)
        .join("blobs")
        .join("sha256")
        .join(&digest.sha256_hex()[..2])
        .join(digest.sha256_hex())
}

#[cfg(test)]
pub(super) fn evidence_temporary_path(
    database_path: &Path,
    temporary_name: &str,
) -> std::path::PathBuf {
    database_path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
        .join(EVIDENCE_DIRECTORY)
        .join("tmp")
        .join(temporary_name)
}

#[cfg(test)]
pub(super) fn install_blob_with_namespace_swap<F>(
    files: &EvidenceFiles,
    digest: &ContentDigest,
    bytes: &[u8],
    swap: F,
) -> Result<(), StoreError>
where
    F: FnOnce(),
{
    let temporary_name = Uuid::new_v4().hyphenated().to_string();
    install_blob_after_directories_opened(files, digest, bytes, &temporary_name, swap)
}

#[cfg(test)]
pub(super) fn put_with_install_hook<F>(
    connection: &mut Connection,
    files: &EvidenceFiles,
    evidence: PutEvidence,
    now_ms: u64,
    after_blob_installed: F,
) -> Result<EvidenceMetadata, StoreError>
where
    F: FnOnce(),
{
    put_after_blob_installed(connection, files, evidence, now_ms, after_blob_installed)
}
