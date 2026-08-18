use std::{
    io::{ErrorKind, Read, Write},
    path::Path,
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
    MAX_EVIDENCE_MEDIA_TYPE_BYTES, MAX_EVIDENCE_RANGE_BYTES, PutEvidence, StoreError,
};

const EVIDENCE_DIRECTORY: &str = "evidence";

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

    install_blob(files, &digest, &evidence.bytes)?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
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
) -> Result<(), StoreError> {
    install_blob_after_directories_opened(files, digest, bytes, || {})
}

fn install_blob_after_directories_opened<F>(
    files: &EvidenceFiles,
    digest: &ContentDigest,
    bytes: &[u8],
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

    let temporary_name = Uuid::new_v4().hyphenated().to_string();
    let temporary = TemporaryFile::new(&directories.tmp, &temporary_name);
    let mut options = OpenOptions::new();
    options
        .write(true)
        .create_new(true)
        .follow(FollowSymlinks::No);
    let mut file = directories.tmp.open_with(&temporary_name, &options)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(StoreError::UnsafeEvidencePath);
    }
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);

    match directories.tmp.hard_link(
        &temporary_name,
        &directories.blob.shard,
        digest.sha256_hex(),
    ) {
        Ok(()) => sync_directory(&directories.blob.shard)?,
        Err(error) if error.kind() == ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error.into()),
    }
    verified_blob_from_shard(&directories.blob.shard, digest, size_bytes)?;
    directories.blob.ensure_current(files)?;
    drop(temporary);
    Ok(())
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
pub(super) fn install_blob_with_namespace_swap<F>(
    files: &EvidenceFiles,
    digest: &ContentDigest,
    bytes: &[u8],
    swap: F,
) -> Result<(), StoreError>
where
    F: FnOnce(),
{
    install_blob_after_directories_opened(files, digest, bytes, swap)
}
