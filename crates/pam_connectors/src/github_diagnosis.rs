//! Deterministic, evidence-backed diagnosis of collected GitHub Actions logs.

use std::{collections::BTreeSet, error::Error, fmt};

use pam_compact::{
    CompactError, CompactedLog, CompactionPolicy, LogMetadata, SourceEvidence, compact_log,
};
use pam_core::{ContentDigest, EvidenceHandle, EvidenceReference};
use serde::Serialize;
use sha2::{Digest as _, Sha256};

use crate::{
    BoundedSummary, ConnectorOutput, ExactArtifact,
    github::{
        CollectRunLogsResponse, MAX_COLLECTED_JOBS, MAX_LOG_BYTES_PER_JOB, MAX_TOTAL_LOG_BYTES,
    },
};

pub const MAX_DIAGNOSIS_LOGS: usize = MAX_COLLECTED_JOBS;
pub const MAX_DIAGNOSIS_FINDINGS: usize = 64;
pub const MAX_DIAGNOSIS_MANIFEST_BYTES: usize = 256 * 1024;
pub const DIAGNOSIS_SCHEMA_VERSION: &str = "pam-github-diagnosis-v1";

const COMPILATION_PATTERNS: &[&[u8]] = &[
    b"could not compile",
    b"compilation failed",
    b"compiler error",
    b"error[e",
    b"undefined reference",
];
const TEST_PATTERNS: &[&[u8]] = &[
    b"test result: failed",
    b"tests failed",
    b"assertion failed",
    b"failures:",
];
const SIGNING_PATTERNS: &[&[u8]] = &[
    b"code signing",
    b"codesign",
    b"notarization failed",
    b"packaging failed",
    b"package build failed",
];
const TIMEOUT_PATTERNS: &[&[u8]] = &[b"timed out", b"timeout", b"deadline exceeded"];
const AUTHORIZATION_PATTERNS: &[&[u8]] = &[
    b"permission denied",
    b"unauthorized",
    b"forbidden",
    b"authentication failed",
    b"access denied",
];
const REMOTE_OR_UNKNOWN_PATTERNS: &[&[u8]] = &[
    b"##[error]",
    b"error:",
    b"fatal:",
    b"process completed with exit code",
    b"service unavailable",
    b"connection reset",
];
const GITHUB_LOG_EVIDENCE_PREFIX: &str = "evidence://github-actions/log";

/// Exact bytes for one collected job log.
#[derive(Clone, Eq, PartialEq)]
pub struct ExactJobLog {
    job_id: u64,
    bytes: Vec<u8>,
}

impl ExactJobLog {
    /// Creates a bounded exact job log.
    ///
    /// # Errors
    ///
    /// Returns an error for a zero job identifier or a payload over the per-job collection bound.
    pub fn new(job_id: u64, bytes: Vec<u8>) -> Result<Self, DiagnosisError> {
        if job_id == 0 {
            return Err(DiagnosisError::InvalidJobId);
        }
        if bytes.len() > MAX_LOG_BYTES_PER_JOB {
            return Err(DiagnosisError::LogTooLarge { job_id });
        }
        Ok(Self { job_id, bytes })
    }

    #[must_use]
    pub const fn job_id(&self) -> u64 {
        self.job_id
    }

    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

fn canonical_source(bytes: &[u8]) -> SourceEvidence {
    let digest = ContentDigest::from_sha256(Sha256::digest(bytes).into());
    let handle = EvidenceHandle::parse(format!(
        "{GITHUB_LOG_EVIDENCE_PREFIX}/{}",
        digest.sha256_hex()
    ))
    .expect("a lowercase SHA-256 digest is a canonical evidence segment");
    SourceEvidence { handle, digest }
}

impl fmt::Debug for ExactJobLog {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExactJobLog")
            .field("job_id", &self.job_id)
            .field("byte_len", &self.bytes.len())
            .finish()
    }
}

/// A deliberately coarse deterministic failure class.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingCategory {
    Compilation,
    Tests,
    SigningOrPackaging,
    Timeout,
    Authorization,
    RemoteOrUnknown,
}

impl FindingCategory {
    const fn summary(self) -> &'static str {
        match self {
            Self::Compilation => "log contains a compilation failure signature",
            Self::Tests => "log contains a test failure signature",
            Self::SigningOrPackaging => "log contains a signing or packaging failure signature",
            Self::Timeout => "log contains a timeout signature",
            Self::Authorization => "log contains an authorization failure signature",
            Self::RemoteOrUnknown => "log contains an unclassified failure signature",
        }
    }
}

/// One lexical inference anchored to an exact source byte range.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct DiagnosisFinding {
    job_id: u64,
    category: FindingCategory,
    evidence: EvidenceReference,
    inference: bool,
    summary: &'static str,
}

impl DiagnosisFinding {
    #[must_use]
    pub const fn job_id(&self) -> u64 {
        self.job_id
    }

    #[must_use]
    pub const fn category(&self) -> FindingCategory {
        self.category
    }

    #[must_use]
    pub const fn evidence(&self) -> &EvidenceReference {
        &self.evidence
    }

    #[must_use]
    pub const fn is_inference(&self) -> bool {
        self.inference
    }

    #[must_use]
    pub const fn summary(&self) -> &'static str {
        self.summary
    }
}

/// Compacted display text with complete source-range provenance for one job.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiagnosedLog {
    job_id: u64,
    artifact_name: String,
    compacted: CompactedLog,
}

impl DiagnosedLog {
    #[must_use]
    pub const fn job_id(&self) -> u64 {
        self.job_id
    }

    #[must_use]
    pub fn artifact_name(&self) -> &str {
        &self.artifact_name
    }

    #[must_use]
    pub const fn compacted(&self) -> &CompactedLog {
        &self.compacted
    }
}

/// Completeness-aware outcome. `Partial` is never promoted to a solved or verified claim.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosisStatus {
    Diagnosed,
    Unresolved,
    Partial,
}

/// Pure diagnosis output and its canonical deterministic manifest artifact.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RunDiagnosis {
    status: DiagnosisStatus,
    summary: BoundedSummary,
    logs: Vec<DiagnosedLog>,
    findings: Vec<DiagnosisFinding>,
    manifest: ExactArtifact,
}

impl RunDiagnosis {
    #[must_use]
    pub const fn status(&self) -> DiagnosisStatus {
        self.status
    }

    #[must_use]
    pub const fn summary(&self) -> &BoundedSummary {
        &self.summary
    }

    #[must_use]
    pub fn logs(&self) -> &[DiagnosedLog] {
        &self.logs
    }

    #[must_use]
    pub fn findings(&self) -> &[DiagnosisFinding] {
        &self.findings
    }

    #[must_use]
    pub const fn manifest(&self) -> &ExactArtifact {
        &self.manifest
    }
}

/// Validates, compacts, and lexically classifies exact collected logs without model calls.
///
/// # Errors
///
/// Returns an error for inconsistent jobs/artifacts/evidence, exceeded bounds, compaction failure,
/// or a manifest that cannot fit its fixed byte budget.
pub fn diagnose_run(
    collection: &ConnectorOutput<CollectRunLogsResponse>,
    exact_logs: Vec<ExactJobLog>,
) -> Result<RunDiagnosis, DiagnosisError> {
    let response = collection.value();
    let input_complete = collection.truth().is_complete();
    validate_response_bounds(collection, &exact_logs)?;

    let mut exact_logs = exact_logs;
    exact_logs.sort_by_key(ExactJobLog::job_id);
    let mut diagnosed_logs = Vec::with_capacity(exact_logs.len());
    let mut findings = Vec::new();
    let mut seen_findings = BTreeSet::new();

    for exact in exact_logs {
        let Some(collected) = response
            .logs()
            .iter()
            .find(|log| log.job_id() == exact.job_id)
        else {
            return Err(DiagnosisError::EvidenceWithoutArtifact {
                job_id: exact.job_id,
            });
        };
        let artifact = collection
            .artifacts()
            .iter()
            .find(|artifact| artifact.name() == collected.artifact_name())
            .ok_or(DiagnosisError::ArtifactPayloadCountMismatch)?;
        let source = canonical_source(artifact.bytes());
        let compacted = compact_log(
            &source,
            &exact.bytes,
            &LogMetadata::default(),
            &CompactionPolicy::default(),
        )
        .map_err(|source| DiagnosisError::Compaction {
            job_id: exact.job_id,
            source,
        })?;
        classify_log(
            exact.job_id,
            &source,
            &exact.bytes,
            &mut seen_findings,
            &mut findings,
        );
        diagnosed_logs.push(DiagnosedLog {
            job_id: exact.job_id,
            artifact_name: collected.artifact_name().to_owned(),
            compacted,
        });
    }

    findings.sort_by_key(|finding| (finding.job_id, finding.category, finding.evidence.offset));
    let findings_truncated = findings.len() > MAX_DIAGNOSIS_FINDINGS;
    findings.truncate(MAX_DIAGNOSIS_FINDINGS);

    let status = if !input_complete || findings_truncated {
        DiagnosisStatus::Partial
    } else if findings.is_empty() {
        DiagnosisStatus::Unresolved
    } else {
        DiagnosisStatus::Diagnosed
    };
    let summary = diagnosis_summary(status, diagnosed_logs.len(), findings.len())?;
    let manifest_bytes = manifest_bytes(
        response,
        input_complete,
        findings_truncated,
        status,
        &summary,
        &diagnosed_logs,
        &findings,
    )?;
    let manifest_name = format!("github-run-{}-diagnosis.json", response.run().id().get());
    let manifest = ExactArtifact::new(manifest_name, manifest_bytes)
        .map_err(|_| DiagnosisError::ManifestTooLarge)?;

    Ok(RunDiagnosis {
        status,
        summary,
        logs: diagnosed_logs,
        findings,
        manifest,
    })
}

fn validate_response_bounds(
    collection: &ConnectorOutput<CollectRunLogsResponse>,
    exact_logs: &[ExactJobLog],
) -> Result<(), DiagnosisError> {
    let response = collection.value();
    let input_complete = collection.truth().is_complete();
    if response.jobs().len() > MAX_COLLECTED_JOBS
        || response.logs().len() > MAX_DIAGNOSIS_LOGS
        || exact_logs.len() > MAX_DIAGNOSIS_LOGS
    {
        return Err(DiagnosisError::TooManyLogs);
    }
    if input_complete && response.total_jobs() != response.jobs().len() as u64 {
        return Err(DiagnosisError::ContradictoryCompleteness);
    }

    let mut job_ids = BTreeSet::new();
    for job in response.jobs() {
        if job.id() == 0 {
            return Err(DiagnosisError::InvalidJobId);
        }
        if !job_ids.insert(job.id()) {
            return Err(DiagnosisError::DuplicateJob { job_id: job.id() });
        }
    }

    let mut collected_ids = BTreeSet::new();
    for log in response.logs() {
        if !collected_ids.insert(log.job_id()) {
            return Err(DiagnosisError::DuplicateArtifact {
                job_id: log.job_id(),
            });
        }
        if !job_ids.contains(&log.job_id()) {
            return Err(DiagnosisError::ArtifactWithoutJob {
                job_id: log.job_id(),
            });
        }
        let expected_name = format!(
            "github-run-{}-job-{}.log",
            response.run().id().get(),
            log.job_id()
        );
        if log.artifact_name() != expected_name {
            return Err(DiagnosisError::ArtifactNameMismatch {
                job_id: log.job_id(),
            });
        }
        if log.byte_len() > MAX_LOG_BYTES_PER_JOB {
            return Err(DiagnosisError::LogTooLarge {
                job_id: log.job_id(),
            });
        }
    }
    if input_complete
        && response
            .jobs()
            .iter()
            .filter(|job| job.conclusion() == Some("failure"))
            .any(|job| !collected_ids.contains(&job.id()))
    {
        return Err(DiagnosisError::ContradictoryCompleteness);
    }

    validate_artifact_payloads(collection, response)?;
    validate_exact_evidence(collection, response, exact_logs, &collected_ids)
}

fn validate_artifact_payloads(
    collection: &ConnectorOutput<CollectRunLogsResponse>,
    response: &CollectRunLogsResponse,
) -> Result<(), DiagnosisError> {
    if collection.artifacts().len() != response.logs().len() {
        return Err(DiagnosisError::ArtifactPayloadCountMismatch);
    }
    let mut artifact_names = BTreeSet::new();
    for artifact in collection.artifacts() {
        if !artifact_names.insert(artifact.name()) {
            return Err(DiagnosisError::DuplicateArtifactPayload);
        }
        let Some(log) = response
            .logs()
            .iter()
            .find(|log| log.artifact_name() == artifact.name())
        else {
            return Err(DiagnosisError::UnexpectedArtifactPayload);
        };
        if log.byte_len() != artifact.bytes().len() {
            return Err(DiagnosisError::ArtifactPayloadMismatch {
                job_id: log.job_id(),
            });
        }
    }
    Ok(())
}

fn validate_exact_evidence(
    collection: &ConnectorOutput<CollectRunLogsResponse>,
    response: &CollectRunLogsResponse,
    exact_logs: &[ExactJobLog],
    collected_ids: &BTreeSet<u64>,
) -> Result<(), DiagnosisError> {
    let mut exact_ids = BTreeSet::new();
    let mut total_bytes = 0_usize;
    for exact in exact_logs {
        if !exact_ids.insert(exact.job_id) {
            return Err(DiagnosisError::DuplicateEvidence {
                job_id: exact.job_id,
            });
        }
        let Some(log) = response
            .logs()
            .iter()
            .find(|log| log.job_id() == exact.job_id)
        else {
            return Err(DiagnosisError::EvidenceWithoutArtifact {
                job_id: exact.job_id,
            });
        };
        if log.byte_len() != exact.bytes.len() {
            return Err(DiagnosisError::ByteLengthMismatch {
                job_id: exact.job_id,
            });
        }
        let artifact = collection
            .artifacts()
            .iter()
            .find(|artifact| artifact.name() == log.artifact_name())
            .ok_or(DiagnosisError::ArtifactPayloadCountMismatch)?;
        if artifact.bytes() != exact.bytes {
            return Err(DiagnosisError::ArtifactPayloadMismatch {
                job_id: exact.job_id,
            });
        }
        total_bytes = total_bytes
            .checked_add(exact.bytes.len())
            .ok_or(DiagnosisError::TotalLogBytesTooLarge)?;
    }
    if &exact_ids != collected_ids {
        let missing = collected_ids
            .difference(&exact_ids)
            .next()
            .copied()
            .unwrap_or(0);
        return Err(DiagnosisError::MissingEvidence { job_id: missing });
    }
    if total_bytes > MAX_TOTAL_LOG_BYTES {
        return Err(DiagnosisError::TotalLogBytesTooLarge);
    }
    Ok(())
}

fn classify_log(
    job_id: u64,
    source: &SourceEvidence,
    bytes: &[u8],
    seen: &mut BTreeSet<(u64, FindingCategory)>,
    findings: &mut Vec<DiagnosisFinding>,
) {
    let mut offset = 0_usize;
    while offset < bytes.len() {
        let relative_end = bytes[offset..].iter().position(|byte| *byte == b'\n');
        let end = relative_end.map_or(bytes.len(), |index| offset + index + 1);
        let line = &bytes[offset..end];
        if let Some(category) = classify_line(line)
            && seen.insert((job_id, category))
        {
            findings.push(DiagnosisFinding {
                job_id,
                category,
                evidence: EvidenceReference {
                    handle: source.handle.clone(),
                    offset: u64::try_from(offset).expect("usize fits in u64"),
                    length: u64::try_from(end - offset).expect("usize fits in u64"),
                },
                inference: true,
                summary: category.summary(),
            });
        }
        offset = end;
    }
}

fn classify_line(line: &[u8]) -> Option<FindingCategory> {
    if contains_any(line, AUTHORIZATION_PATTERNS) {
        Some(FindingCategory::Authorization)
    } else if contains_any(line, TIMEOUT_PATTERNS) {
        Some(FindingCategory::Timeout)
    } else if contains_any(line, SIGNING_PATTERNS) {
        Some(FindingCategory::SigningOrPackaging)
    } else if contains_any(line, TEST_PATTERNS) {
        Some(FindingCategory::Tests)
    } else if contains_any(line, COMPILATION_PATTERNS) {
        Some(FindingCategory::Compilation)
    } else if contains_any(line, REMOTE_OR_UNKNOWN_PATTERNS) {
        Some(FindingCategory::RemoteOrUnknown)
    } else {
        None
    }
}

fn contains_any(line: &[u8], patterns: &[&[u8]]) -> bool {
    patterns.iter().any(|pattern| {
        line.windows(pattern.len())
            .any(|window| window.eq_ignore_ascii_case(pattern))
    })
}

fn diagnosis_summary(
    status: DiagnosisStatus,
    log_count: usize,
    finding_count: usize,
) -> Result<BoundedSummary, DiagnosisError> {
    let text = match status {
        DiagnosisStatus::Diagnosed => format!(
            "found {finding_count} deterministic failure signature(s) across {log_count} complete GitHub Actions job log(s)"
        ),
        DiagnosisStatus::Unresolved => format!(
            "no supported lexical failure signature was found in {log_count} complete GitHub Actions job log(s)"
        ),
        DiagnosisStatus::Partial => format!(
            "partial GitHub Actions diagnosis retained {finding_count} deterministic failure signature(s) across {log_count} job log(s)"
        ),
    };
    BoundedSummary::new(text).map_err(|_| DiagnosisError::SummaryTooLarge)
}

#[derive(Serialize)]
struct Manifest<'a> {
    schema_version: &'static str,
    run_id: u64,
    input_complete: bool,
    findings_truncated: bool,
    status: DiagnosisStatus,
    summary: &'a str,
    logs: Vec<ManifestLog<'a>>,
    findings: &'a [DiagnosisFinding],
}

#[derive(Serialize)]
struct ManifestLog<'a> {
    job_id: u64,
    artifact_name: &'a str,
    source: &'a SourceEvidence,
    algorithm_version: &'a str,
    policy_version: &'a str,
    policy_digest: &'a ContentDigest,
    source_byte_count: u64,
    retained_byte_count: u64,
    source_record_count: u64,
    retained_record_count: u64,
}

fn manifest_bytes(
    response: &CollectRunLogsResponse,
    input_complete: bool,
    findings_truncated: bool,
    status: DiagnosisStatus,
    summary: &BoundedSummary,
    logs: &[DiagnosedLog],
    findings: &[DiagnosisFinding],
) -> Result<Vec<u8>, DiagnosisError> {
    let logs = logs
        .iter()
        .map(|log| ManifestLog {
            job_id: log.job_id,
            artifact_name: &log.artifact_name,
            source: &log.compacted.source,
            algorithm_version: &log.compacted.algorithm_version,
            policy_version: &log.compacted.policy_version,
            policy_digest: &log.compacted.policy_digest,
            source_byte_count: log.compacted.source_byte_count,
            retained_byte_count: log.compacted.retained_byte_count,
            source_record_count: log.compacted.source_record_count,
            retained_record_count: log.compacted.retained_record_count,
        })
        .collect();
    let manifest = Manifest {
        schema_version: DIAGNOSIS_SCHEMA_VERSION,
        run_id: response.run().id().get(),
        input_complete,
        findings_truncated,
        status,
        summary: summary.as_str(),
        logs,
        findings,
    };
    let bytes = serde_json::to_vec(&manifest).map_err(|_| DiagnosisError::ManifestEncoding)?;
    if bytes.len() > MAX_DIAGNOSIS_MANIFEST_BYTES {
        return Err(DiagnosisError::ManifestTooLarge);
    }
    Ok(bytes)
}

#[derive(Debug)]
pub enum DiagnosisError {
    InvalidJobId,
    TooManyLogs,
    LogTooLarge { job_id: u64 },
    TotalLogBytesTooLarge,
    ContradictoryCompleteness,
    DuplicateJob { job_id: u64 },
    DuplicateArtifact { job_id: u64 },
    DuplicateEvidence { job_id: u64 },
    ArtifactWithoutJob { job_id: u64 },
    ArtifactNameMismatch { job_id: u64 },
    ArtifactPayloadCountMismatch,
    DuplicateArtifactPayload,
    UnexpectedArtifactPayload,
    ArtifactPayloadMismatch { job_id: u64 },
    EvidenceWithoutArtifact { job_id: u64 },
    MissingEvidence { job_id: u64 },
    ByteLengthMismatch { job_id: u64 },
    Compaction { job_id: u64, source: CompactError },
    SummaryTooLarge,
    ManifestEncoding,
    ManifestTooLarge,
}

impl fmt::Display for DiagnosisError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidJobId => formatter.write_str("diagnosis job identifier must be nonzero"),
            Self::TooManyLogs => formatter.write_str("diagnosis log count exceeds its bound"),
            Self::LogTooLarge { job_id } => {
                write!(formatter, "job {job_id} log exceeds its byte bound")
            }
            Self::TotalLogBytesTooLarge => {
                formatter.write_str("diagnosis log bytes exceed the aggregate bound")
            }
            Self::ContradictoryCompleteness => {
                formatter.write_str("complete input omits jobs reported by GitHub")
            }
            Self::DuplicateJob { job_id } => write!(formatter, "job {job_id} is duplicated"),
            Self::DuplicateArtifact { job_id } => {
                write!(formatter, "job {job_id} artifact is duplicated")
            }
            Self::DuplicateEvidence { job_id } => {
                write!(formatter, "job {job_id} evidence is duplicated")
            }
            Self::ArtifactWithoutJob { job_id } => {
                write!(formatter, "job {job_id} artifact has no job record")
            }
            Self::ArtifactNameMismatch { job_id } => {
                write!(formatter, "job {job_id} artifact name is not canonical")
            }
            Self::ArtifactPayloadCountMismatch => {
                formatter.write_str("collected log metadata and artifact payload counts differ")
            }
            Self::DuplicateArtifactPayload => {
                formatter.write_str("collected artifact payload name is duplicated")
            }
            Self::UnexpectedArtifactPayload => {
                formatter.write_str("collected artifact payload has no log metadata")
            }
            Self::ArtifactPayloadMismatch { job_id } => {
                write!(
                    formatter,
                    "job {job_id} exact evidence differs from its collected artifact payload"
                )
            }
            Self::EvidenceWithoutArtifact { job_id } => {
                write!(formatter, "job {job_id} evidence has no collected artifact")
            }
            Self::MissingEvidence { job_id } => {
                write!(
                    formatter,
                    "job {job_id} collected artifact has no exact evidence"
                )
            }
            Self::ByteLengthMismatch { job_id } => {
                write!(
                    formatter,
                    "job {job_id} evidence length differs from its artifact"
                )
            }
            Self::Compaction { job_id, source } => {
                write!(formatter, "job {job_id} log compaction failed: {source}")
            }
            Self::SummaryTooLarge => formatter.write_str("diagnosis summary exceeds its bound"),
            Self::ManifestEncoding => formatter.write_str("diagnosis manifest encoding failed"),
            Self::ManifestTooLarge => formatter.write_str("diagnosis manifest exceeds its bound"),
        }
    }
}

impl Error for DiagnosisError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Compaction { source, .. } => Some(source),
            _ => None,
        }
    }
}
