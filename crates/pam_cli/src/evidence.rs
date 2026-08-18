use std::{
    error::Error,
    ffi::OsString,
    fmt, fs,
    fs::{File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use pam_core::{ContentDigest, EvidenceHandle};
use pam_daemon::StatusError;
use pam_platform::LocalEndpoint;
use pam_protocol::{
    EvidenceChunk, EvidenceMetadata, Failure, MAX_EVIDENCE_CHUNK_SIZE, OperationTruth,
    ProtocolContractError, ResultBody, ResultPayload,
};
use sha2::{Digest, Sha256};

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt as _;

use crate::request::RequestContext;

const MAX_BUFFERED_EVIDENCE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_TEMPORARY_FILE_ATTEMPTS: u64 = 32;
static NEXT_TEMPORARY_FILE: AtomicU64 = AtomicU64::new(1);

pub(crate) struct EvidenceDownload {
    pub(crate) metadata: EvidenceMetadata,
    pub(crate) bytes: Vec<u8>,
    pub(crate) truth: OperationTruth,
}

#[derive(Debug)]
pub(crate) enum EvidenceError {
    Exchange(StatusError),
    Protocol(ProtocolContractError),
    Remote(Failure),
    UnexpectedEvents,
    UnexpectedResult,
    HandleMismatch,
    OffsetMismatch {
        expected: u64,
        actual: u64,
    },
    EmptyChunk,
    PrematureEof,
    MissingEof,
    SizeMismatch {
        expected: u64,
        actual: u64,
    },
    TooLarge {
        actual: u64,
        maximum: u64,
    },
    DigestMismatch {
        expected: ContentDigest,
        actual: ContentDigest,
    },
    NonPublishableTruth {
        stage: &'static str,
        truth: OperationTruth,
    },
    TruthMismatch {
        expected: OperationTruth,
        actual: OperationTruth,
    },
    BufferAllocation,
}

impl EvidenceError {
    pub(crate) fn recovery_action(&self) -> Option<&str> {
        match self {
            Self::Exchange(error) => error.recovery_action(),
            Self::Remote(failure) => failure.recovery.as_deref(),
            Self::Protocol(_)
            | Self::UnexpectedEvents
            | Self::UnexpectedResult
            | Self::HandleMismatch
            | Self::OffsetMismatch { .. }
            | Self::EmptyChunk
            | Self::PrematureEof
            | Self::MissingEof
            | Self::SizeMismatch { .. }
            | Self::TooLarge { .. }
            | Self::DigestMismatch { .. }
            | Self::NonPublishableTruth { .. }
            | Self::TruthMismatch { .. }
            | Self::BufferAllocation => None,
        }
    }
}

impl fmt::Display for EvidenceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Exchange(error) => error.fmt(formatter),
            Self::Protocol(error) => error.fmt(formatter),
            Self::Remote(failure) => write!(formatter, "{}", failure.message),
            Self::UnexpectedEvents => {
                formatter.write_str("evidence inspection returned unexpected events")
            }
            Self::UnexpectedResult => {
                formatter.write_str("evidence inspection returned an unexpected result")
            }
            Self::HandleMismatch => {
                formatter.write_str("evidence response did not match the requested handle")
            }
            Self::OffsetMismatch { expected, actual } => write!(
                formatter,
                "evidence chunk offset was {actual}; expected {expected}"
            ),
            Self::EmptyChunk => {
                formatter.write_str("evidence response contained an empty non-terminal chunk")
            }
            Self::PrematureEof => {
                formatter.write_str("evidence response ended before its declared size")
            }
            Self::MissingEof => {
                formatter.write_str("evidence response reached its declared size without EOF")
            }
            Self::SizeMismatch { expected, actual } => write!(
                formatter,
                "evidence size was {actual} bytes; metadata declared {expected}"
            ),
            Self::TooLarge { actual, maximum } => write!(
                formatter,
                "evidence is {actual} bytes; CLI verification limit is {maximum} bytes"
            ),
            Self::DigestMismatch { expected, actual } => write!(
                formatter,
                "evidence digest was {actual}; metadata declared {expected}"
            ),
            Self::NonPublishableTruth { stage, truth } => write!(
                formatter,
                "evidence {stage} reported {} truth; refusing to publish evidence",
                truth_label(truth)
            ),
            Self::TruthMismatch { expected, actual } => write!(
                formatter,
                "evidence chunk truth was {}; metadata truth was {}",
                truth_label(actual),
                truth_label(expected)
            ),
            Self::BufferAllocation => {
                formatter.write_str("PAM could not allocate the bounded evidence buffer")
            }
        }
    }
}

impl Error for EvidenceError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Exchange(error) => Some(error),
            Self::Protocol(error) => Some(error),
            Self::Remote(_)
            | Self::UnexpectedEvents
            | Self::UnexpectedResult
            | Self::HandleMismatch
            | Self::OffsetMismatch { .. }
            | Self::EmptyChunk
            | Self::PrematureEof
            | Self::MissingEof
            | Self::SizeMismatch { .. }
            | Self::TooLarge { .. }
            | Self::DigestMismatch { .. }
            | Self::NonPublishableTruth { .. }
            | Self::TruthMismatch { .. }
            | Self::BufferAllocation => None,
        }
    }
}

impl From<StatusError> for EvidenceError {
    fn from(error: StatusError) -> Self {
        Self::Exchange(error)
    }
}

impl From<ProtocolContractError> for EvidenceError {
    fn from(error: ProtocolContractError) -> Self {
        Self::Protocol(error)
    }
}

pub(crate) async fn download_evidence(
    endpoint: &LocalEndpoint,
    context: &RequestContext,
    handle: EvidenceHandle,
    request_timeout: Duration,
) -> Result<EvidenceDownload, EvidenceError> {
    let inspect = pam_daemon::request_exchange(
        endpoint,
        &context.inspect_evidence(handle.clone()),
        request_timeout,
    )
    .await?;
    if !inspect.events.is_empty() {
        return Err(EvidenceError::UnexpectedEvents);
    }
    let (metadata, truth) = match inspect.result.body {
        ResultBody::Success {
            truth,
            payload: ResultPayload::EvidenceMetadata(metadata),
            ..
        } => (metadata, truth),
        ResultBody::Failure(failure) => return Err(EvidenceError::Remote(failure)),
        ResultBody::Success { .. } => return Err(EvidenceError::UnexpectedResult),
    };
    let mut assembler = EvidenceAssembler::new(handle.clone(), metadata, truth)?;

    while !assembler.complete() {
        let offset = assembler.offset();
        let remaining = assembler.metadata.size_bytes - offset;
        let length = remaining.clamp(1, MAX_EVIDENCE_CHUNK_SIZE as u64);
        let request = context.read_evidence(handle.clone(), offset, length)?;
        let exchange = pam_daemon::request_exchange(endpoint, &request, request_timeout).await?;
        if !exchange.events.is_empty() {
            return Err(EvidenceError::UnexpectedEvents);
        }
        let (chunk, truth) = match exchange.result.body {
            ResultBody::Success {
                truth,
                payload: ResultPayload::EvidenceChunk(chunk),
                ..
            } => (chunk, truth),
            ResultBody::Failure(failure) => return Err(EvidenceError::Remote(failure)),
            ResultBody::Success { .. } => return Err(EvidenceError::UnexpectedResult),
        };
        assembler.push(&chunk, truth)?;
    }

    assembler.finish()
}

pub(crate) struct EvidenceAssembler {
    requested_handle: EvidenceHandle,
    metadata: EvidenceMetadata,
    bytes: Vec<u8>,
    saw_eof: bool,
    truth: OperationTruth,
}

impl EvidenceAssembler {
    pub(crate) fn new(
        requested_handle: EvidenceHandle,
        metadata: EvidenceMetadata,
        truth: OperationTruth,
    ) -> Result<Self, EvidenceError> {
        ensure_publishable_truth("metadata", &truth)?;
        if metadata.handle != requested_handle {
            return Err(EvidenceError::HandleMismatch);
        }
        if metadata.size_bytes > MAX_BUFFERED_EVIDENCE_BYTES {
            return Err(EvidenceError::TooLarge {
                actual: metadata.size_bytes,
                maximum: MAX_BUFFERED_EVIDENCE_BYTES,
            });
        }
        let capacity =
            usize::try_from(metadata.size_bytes).map_err(|_| EvidenceError::TooLarge {
                actual: metadata.size_bytes,
                maximum: MAX_BUFFERED_EVIDENCE_BYTES,
            })?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(capacity)
            .map_err(|_| EvidenceError::BufferAllocation)?;
        Ok(Self {
            requested_handle,
            metadata,
            bytes,
            saw_eof: false,
            truth,
        })
    }

    pub(crate) fn offset(&self) -> u64 {
        self.bytes.len() as u64
    }

    pub(crate) fn complete(&self) -> bool {
        self.saw_eof
    }

    pub(crate) fn push(
        &mut self,
        chunk: &EvidenceChunk,
        truth: OperationTruth,
    ) -> Result<(), EvidenceError> {
        ensure_publishable_truth("chunk", &truth)?;
        if truth != self.truth {
            return Err(EvidenceError::TruthMismatch {
                expected: self.truth.clone(),
                actual: truth,
            });
        }
        if chunk.handle != self.requested_handle {
            return Err(EvidenceError::HandleMismatch);
        }
        let expected_offset = self.offset();
        if chunk.offset != expected_offset {
            return Err(EvidenceError::OffsetMismatch {
                expected: expected_offset,
                actual: chunk.offset,
            });
        }
        if chunk.bytes().is_empty() && !chunk.eof {
            return Err(EvidenceError::EmptyChunk);
        }
        let chunk_length =
            u64::try_from(chunk.bytes().len()).map_err(|_| EvidenceError::SizeMismatch {
                expected: self.metadata.size_bytes,
                actual: u64::MAX,
            })?;
        let new_size =
            expected_offset
                .checked_add(chunk_length)
                .ok_or(EvidenceError::SizeMismatch {
                    expected: self.metadata.size_bytes,
                    actual: u64::MAX,
                })?;
        if new_size > self.metadata.size_bytes {
            return Err(EvidenceError::SizeMismatch {
                expected: self.metadata.size_bytes,
                actual: new_size,
            });
        }
        self.bytes.extend_from_slice(chunk.bytes());
        if chunk.eof {
            if new_size != self.metadata.size_bytes {
                return Err(EvidenceError::PrematureEof);
            }
            self.saw_eof = true;
        } else if new_size == self.metadata.size_bytes {
            return Err(EvidenceError::MissingEof);
        }
        Ok(())
    }

    pub(crate) fn finish(self) -> Result<EvidenceDownload, EvidenceError> {
        let actual_size = self.bytes.len() as u64;
        if actual_size != self.metadata.size_bytes {
            return Err(EvidenceError::SizeMismatch {
                expected: self.metadata.size_bytes,
                actual: actual_size,
            });
        }
        if actual_size > 0 && !self.saw_eof {
            return Err(EvidenceError::MissingEof);
        }
        let actual_digest = sha256_digest(&self.bytes);
        if actual_digest != self.metadata.digest {
            return Err(EvidenceError::DigestMismatch {
                expected: self.metadata.digest,
                actual: actual_digest,
            });
        }
        Ok(EvidenceDownload {
            metadata: self.metadata,
            bytes: self.bytes,
            truth: self.truth,
        })
    }
}

fn ensure_publishable_truth(
    stage: &'static str,
    truth: &OperationTruth,
) -> Result<(), EvidenceError> {
    match truth {
        OperationTruth::Observed | OperationTruth::Changed | OperationTruth::Verified => Ok(()),
        OperationTruth::Unresolved | OperationTruth::Blocked => {
            Err(EvidenceError::NonPublishableTruth {
                stage,
                truth: truth.clone(),
            })
        }
    }
}

fn truth_label(truth: &OperationTruth) -> &'static str {
    match truth {
        OperationTruth::Observed => "observed",
        OperationTruth::Changed => "changed",
        OperationTruth::Verified => "verified",
        OperationTruth::Unresolved => "unresolved",
        OperationTruth::Blocked => "blocked",
    }
}

fn sha256_digest(bytes: &[u8]) -> ContentDigest {
    let digest: [u8; 32] = Sha256::digest(bytes).into();
    ContentDigest::from_sha256(digest)
}

#[derive(Debug)]
pub(crate) enum OutputError {
    InvalidTarget,
    AlreadyExists(PathBuf),
    Published {
        path: PathBuf,
        stage: OutputFinalizationStage,
        source: std::io::Error,
    },
    Io(std::io::Error),
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum OutputFinalizationStage {
    TemporaryCleanup,
    DirectorySync,
}

impl fmt::Display for OutputError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidTarget => formatter.write_str("evidence output target must name a file"),
            Self::AlreadyExists(path) => write!(
                formatter,
                "evidence output target already exists: {}",
                path.display()
            ),
            Self::Published { path, stage, .. } => write!(
                formatter,
                "evidence was written to {}, but PAM could not {}",
                path.display(),
                match stage {
                    OutputFinalizationStage::TemporaryCleanup => {
                        "confirm temporary-file cleanup"
                    }
                    OutputFinalizationStage::DirectorySync => {
                        "confirm directory durability"
                    }
                }
            ),
            Self::Io(_) => formatter.write_str("PAM could not safely write the evidence output"),
        }
    }
}

impl Error for OutputError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Published { source, .. } | Self::Io(source) => Some(source),
            Self::InvalidTarget | Self::AlreadyExists(_) => None,
        }
    }
}

impl From<std::io::Error> for OutputError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

/// Persists verified evidence atomically without replacing an existing target.
pub(crate) fn write_new_output(path: &Path, bytes: &[u8]) -> Result<(), OutputError> {
    let Some(file_name) = path.file_name() else {
        return Err(OutputError::InvalidTarget);
    };
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let (mut file, mut temporary) = create_temporary_file(parent, file_name)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);

    match fs::hard_link(temporary.path(), path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            return Err(OutputError::AlreadyExists(path.to_path_buf()));
        }
        Err(error) => return Err(OutputError::Io(error)),
    }
    temporary.remove().map_err(|error| OutputError::Published {
        path: path.to_path_buf(),
        stage: OutputFinalizationStage::TemporaryCleanup,
        source: into_io_error(error),
    })?;
    sync_directory(parent).map_err(|error| OutputError::Published {
        path: path.to_path_buf(),
        stage: OutputFinalizationStage::DirectorySync,
        source: into_io_error(error),
    })?;
    Ok(())
}

fn into_io_error(error: OutputError) -> std::io::Error {
    match error {
        OutputError::Io(error) => error,
        _ => std::io::Error::other(error.to_string()),
    }
}

fn create_temporary_file(
    parent: &Path,
    file_name: &std::ffi::OsStr,
) -> Result<(File, TemporaryOutput), OutputError> {
    for _ in 0..MAX_TEMPORARY_FILE_ATTEMPTS {
        let sequence = NEXT_TEMPORARY_FILE.fetch_add(1, Ordering::Relaxed);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let mut temporary_name = OsString::from(file_name);
        temporary_name.push(format!(".pam-tmp-{}-{now}-{sequence}", std::process::id()));
        let path = parent.join(temporary_name);
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        options.mode(0o600);
        match options.open(&path) {
            Ok(file) => return Ok((file, TemporaryOutput { path: Some(path) })),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(OutputError::Io(error)),
        }
    }
    Err(OutputError::Io(std::io::Error::new(
        std::io::ErrorKind::AlreadyExists,
        "could not reserve a unique temporary output file",
    )))
}

fn sync_directory(path: &Path) -> Result<(), OutputError> {
    #[cfg(unix)]
    File::open(path)?.sync_all()?;
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

pub(crate) struct TemporaryOutput {
    path: Option<PathBuf>,
}

impl TemporaryOutput {
    fn path(&self) -> &Path {
        self.path
            .as_deref()
            .expect("temporary output path is present until removal")
    }

    pub(crate) fn remove(&mut self) -> Result<(), OutputError> {
        if let Some(path) = self.path.as_deref() {
            fs::remove_file(path)?;
            self.path = None;
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn for_test(path: PathBuf) -> Self {
        Self { path: Some(path) }
    }

    #[cfg(test)]
    pub(crate) fn retains_path(&self) -> bool {
        self.path.is_some()
    }
}

impl Drop for TemporaryOutput {
    fn drop(&mut self) {
        if let Some(path) = self.path.take() {
            drop(fs::remove_file(path));
        }
    }
}
