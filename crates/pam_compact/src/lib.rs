#![forbid(unsafe_code)]

use std::{cmp, collections::BTreeMap, error::Error, fmt};

use pam_core::{ContentDigest, EvidenceHandle, EvidenceReference};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

pub const ALGORITHM_VERSION: &str = "pam-log-compact-v1";
pub const DEFAULT_POLICY_VERSION: &str = "pam-log-policy-v1";
pub const MAX_SOURCE_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_SOURCE_RECORDS: usize = 100_000;
pub const MAX_POLICY_VERSION_BYTES: usize = 64;
pub const MAX_BOUNDARY_RECORDS: usize = MAX_SOURCE_RECORDS;
pub const MAX_FAILURE_CONTEXT_RECORDS: usize = 64;
pub const MAX_BOILERPLATE_RULES: usize = 128;
pub const MAX_BOILERPLATE_ID_BYTES: usize = 64;
pub const MAX_BOILERPLATE_TEXT_BYTES: usize = 4 * 1024;
pub const MAX_STAGE_BOUNDARIES: usize = 256;
pub const MAX_STAGE_LABEL_BYTES: usize = 128;

const FAILURE_KEYWORDS: [FailureKeyword; 4] = [
    FailureKeyword::Error,
    FailureKeyword::Fatal,
    FailureKeyword::Panic,
    FailureKeyword::Failed,
];

/// The immutable evidence object compacted by [`compact_log`].
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SourceEvidence {
    pub handle: EvidenceHandle,
    pub digest: ContentDigest,
}

/// Metadata captured independently from a log's byte stream.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct LogMetadata {
    pub exit_status: Option<i32>,
    pub stage_boundaries: Vec<StageBoundary>,
}

/// A named pipeline boundary at an exact source byte offset.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct StageBoundary {
    pub label: String,
    pub byte_offset: u64,
}

/// One exact, versioned boilerplate rule.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BoilerplateRule {
    pub id: String,
    pub exact_line: String,
}

/// Versioned knobs for the structural compactor.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CompactionPolicy {
    pub version: String,
    pub boundary_records: usize,
    pub failure_context_records: usize,
    pub boilerplate_rules: Vec<BoilerplateRule>,
}

impl Default for CompactionPolicy {
    fn default() -> Self {
        Self {
            version: DEFAULT_POLICY_VERSION.to_owned(),
            boundary_records: 20,
            failure_context_records: 3,
            boilerplate_rules: Vec::new(),
        }
    }
}

/// Why an exact source record survived structural compaction.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum RetentionReason {
    FirstBoundary,
    LastBoundary,
    StageBoundary { label: String, byte_offset: u64 },
    FailureNeighborhood { keyword: FailureKeyword },
}

/// A fixed ASCII failure token recognized by the versioned algorithm.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum FailureKeyword {
    Error,
    Fatal,
    Panic,
    Failed,
}

impl FailureKeyword {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Error => "error",
            Self::Fatal => "fatal",
            Self::Panic => "panic",
            Self::Failed => "failed",
        }
    }
}

/// Why an exact source range is represented by an omission marker.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum OmissionReason {
    OutsideRetentionWindow,
    Repeated,
    SupersededProgress,
    Boilerplate { rule_id: String },
}

/// Whether a rendered fragment contains normalized content or an omission marker.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum FragmentKind {
    Retained {
        reasons: Vec<RetentionReason>,
    },
    Omitted {
        reason: OmissionReason,
        record_count: u64,
    },
}

/// A rendered fragment and the exact source bytes that it represents.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CompactedFragment {
    pub source: EvidenceReference,
    pub kind: FragmentKind,
    pub rendered: String,
}

/// Deterministic structural reduction with complete byte-range provenance.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CompactedLog {
    pub algorithm_version: String,
    pub policy_version: String,
    pub policy_digest: ContentDigest,
    pub source: SourceEvidence,
    pub exit_status: Option<i32>,
    pub source_byte_count: u64,
    pub retained_byte_count: u64,
    pub source_record_count: u64,
    pub retained_record_count: u64,
    pub rendered_text: String,
    pub fragments: Vec<CompactedFragment>,
}

/// A bounded validation or integrity failure encountered before compaction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CompactError {
    SourceTooLarge {
        actual_bytes: u64,
        maximum_bytes: u64,
    },
    TooManyRecords {
        maximum_records: u64,
    },
    DigestMismatch {
        expected: ContentDigest,
        actual: ContentDigest,
    },
    InvalidPolicy(PolicyValidationError),
    InvalidMetadata(MetadataValidationError),
}

impl fmt::Display for CompactError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SourceTooLarge {
                actual_bytes,
                maximum_bytes,
            } => write!(
                formatter,
                "log source is {actual_bytes} bytes; maximum is {maximum_bytes}"
            ),
            Self::TooManyRecords { maximum_records } => {
                write!(formatter, "log exceeds {maximum_records} source records")
            }
            Self::DigestMismatch { expected, actual } => write!(
                formatter,
                "log digest mismatch: expected {expected}, computed {actual}"
            ),
            Self::InvalidPolicy(error) => write!(formatter, "invalid compaction policy: {error}"),
            Self::InvalidMetadata(error) => write!(formatter, "invalid log metadata: {error}"),
        }
    }
}

impl Error for CompactError {}

/// The precise policy field that failed bounded validation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PolicyValidationError {
    Version,
    BoundaryRecords,
    FailureContextRecords,
    TooManyBoilerplateRules,
    BoilerplateRuleId { index: usize },
    BoilerplateRuleText { index: usize },
    DuplicateBoilerplateRuleId { index: usize },
    DuplicateBoilerplateRuleText { index: usize },
}

impl fmt::Display for PolicyValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Version => formatter.write_str("version is not a bounded canonical identifier"),
            Self::BoundaryRecords => formatter.write_str("boundary record count exceeds its limit"),
            Self::FailureContextRecords => {
                formatter.write_str("failure context record count exceeds its limit")
            }
            Self::TooManyBoilerplateRules => {
                formatter.write_str("boilerplate rule count exceeds its limit")
            }
            Self::BoilerplateRuleId { index } => {
                write!(formatter, "boilerplate rule {index} has an invalid id")
            }
            Self::BoilerplateRuleText { index } => {
                write!(formatter, "boilerplate rule {index} has invalid exact text")
            }
            Self::DuplicateBoilerplateRuleId { index } => {
                write!(formatter, "boilerplate rule {index} has a duplicate id")
            }
            Self::DuplicateBoilerplateRuleText { index } => {
                write!(
                    formatter,
                    "boilerplate rule {index} has duplicate exact text"
                )
            }
        }
    }
}

impl Error for PolicyValidationError {}

/// The precise stage metadata field that failed bounded validation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MetadataValidationError {
    TooManyStageBoundaries,
    StageLabel {
        index: usize,
    },
    StageWithoutSource {
        index: usize,
    },
    StageOffsetOutOfBounds {
        index: usize,
        byte_offset: u64,
        source_length: u64,
    },
}

impl fmt::Display for MetadataValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooManyStageBoundaries => {
                formatter.write_str("stage boundary count exceeds its limit")
            }
            Self::StageLabel { index } => {
                write!(formatter, "stage boundary {index} has an invalid label")
            }
            Self::StageWithoutSource { index } => {
                write!(formatter, "stage boundary {index} has no source record")
            }
            Self::StageOffsetOutOfBounds {
                index,
                byte_offset,
                source_length,
            } => write!(
                formatter,
                "stage boundary {index} offset {byte_offset} exceeds source length {source_length}"
            ),
        }
    }
}

impl Error for MetadataValidationError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FrameKind {
    Line,
    Progress,
}

#[derive(Clone, Debug)]
struct Record {
    start: usize,
    end: usize,
    display: String,
    frame_kind: FrameKind,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum Disposition {
    Retained(Vec<RetentionReason>),
    Omitted(OmissionReason),
}

/// Structurally compacts terminal output without interpretation or model calls.
///
/// Parsing and rendering are byte-based and locale-independent. Every source byte
/// belongs to exactly one returned fragment, so the original can be rehydrated by
/// reading the fragment ranges from `source.handle` in order.
///
/// # Errors
///
/// Returns [`CompactError`] when the source exceeds a work bound, its SHA-256 does
/// not match, or policy and stage metadata are not bounded canonical values.
pub fn compact_log(
    source: &SourceEvidence,
    exact_bytes: &[u8],
    metadata: &LogMetadata,
    policy: &CompactionPolicy,
) -> Result<CompactedLog, CompactError> {
    validate_source_size(exact_bytes.len())?;
    validate_policy(policy)?;
    validate_metadata(metadata, exact_bytes.len())?;
    verify_digest(source, exact_bytes)?;
    let records = parse_records(exact_bytes)?;
    let mut preprocessing_omissions = progress_omissions(&records);
    apply_boilerplate_omissions(&records, policy, &mut preprocessing_omissions);
    apply_repeat_omissions(&records, &mut preprocessing_omissions);

    let active_indices = preprocessing_omissions
        .iter()
        .enumerate()
        .filter_map(|(index, omission)| omission.is_none().then_some(index))
        .collect::<Vec<_>>();
    let mut retention_reasons = vec![Vec::new(); records.len()];

    retain_boundaries(
        &active_indices,
        policy.boundary_records,
        &mut retention_reasons,
    );
    retain_stages(
        &records,
        &active_indices,
        &metadata.stage_boundaries,
        &mut retention_reasons,
    );
    retain_failure_neighborhoods(
        &records,
        &active_indices,
        policy.failure_context_records,
        &mut retention_reasons,
    );

    let dispositions = preprocessing_omissions
        .into_iter()
        .zip(retention_reasons)
        .map(|(omission, reasons)| match omission {
            Some(reason) => Disposition::Omitted(reason),
            None if reasons.is_empty() => {
                Disposition::Omitted(OmissionReason::OutsideRetentionWindow)
            }
            None => Disposition::Retained(reasons),
        })
        .collect::<Vec<_>>();

    let fragments = build_fragments(source, &records, &dispositions);
    let retained_byte_count = fragments
        .iter()
        .filter_map(|fragment| match fragment.kind {
            FragmentKind::Retained { .. } => Some(fragment.source.length),
            FragmentKind::Omitted { .. } => None,
        })
        .sum();
    let retained_record_count = dispositions
        .iter()
        .filter(|disposition| matches!(disposition, Disposition::Retained(_)))
        .count();
    let mut rendered_text = fragments
        .iter()
        .map(|fragment| fragment.rendered.as_str())
        .collect::<String>();
    if records.is_empty() {
        rendered_text.push_str("[no log output]\n");
    }
    render_exit_status(&mut rendered_text, metadata.exit_status);

    Ok(CompactedLog {
        algorithm_version: ALGORITHM_VERSION.to_owned(),
        policy_version: policy.version.clone(),
        policy_digest: digest_policy(policy),
        source: source.clone(),
        exit_status: metadata.exit_status,
        source_byte_count: usize_to_u64(exact_bytes.len()),
        retained_byte_count,
        source_record_count: usize_to_u64(records.len()),
        retained_record_count: usize_to_u64(retained_record_count),
        rendered_text,
        fragments,
    })
}

fn validate_source_size(source_bytes: usize) -> Result<(), CompactError> {
    if source_bytes > MAX_SOURCE_BYTES {
        return Err(CompactError::SourceTooLarge {
            actual_bytes: usize_to_u64(source_bytes),
            maximum_bytes: usize_to_u64(MAX_SOURCE_BYTES),
        });
    }
    Ok(())
}

fn validate_policy(policy: &CompactionPolicy) -> Result<(), CompactError> {
    if !valid_identifier(&policy.version, MAX_POLICY_VERSION_BYTES) {
        return Err(CompactError::InvalidPolicy(PolicyValidationError::Version));
    }
    if policy.boundary_records > MAX_BOUNDARY_RECORDS {
        return Err(CompactError::InvalidPolicy(
            PolicyValidationError::BoundaryRecords,
        ));
    }
    if policy.failure_context_records > MAX_FAILURE_CONTEXT_RECORDS {
        return Err(CompactError::InvalidPolicy(
            PolicyValidationError::FailureContextRecords,
        ));
    }
    if policy.boilerplate_rules.len() > MAX_BOILERPLATE_RULES {
        return Err(CompactError::InvalidPolicy(
            PolicyValidationError::TooManyBoilerplateRules,
        ));
    }
    for (index, rule) in policy.boilerplate_rules.iter().enumerate() {
        if !valid_identifier(&rule.id, MAX_BOILERPLATE_ID_BYTES) {
            return Err(CompactError::InvalidPolicy(
                PolicyValidationError::BoilerplateRuleId { index },
            ));
        }
        if rule.exact_line.len() > MAX_BOILERPLATE_TEXT_BYTES
            || rule.exact_line.chars().any(char::is_control)
        {
            return Err(CompactError::InvalidPolicy(
                PolicyValidationError::BoilerplateRuleText { index },
            ));
        }
        if policy.boilerplate_rules[..index]
            .iter()
            .any(|previous| previous.id == rule.id)
        {
            return Err(CompactError::InvalidPolicy(
                PolicyValidationError::DuplicateBoilerplateRuleId { index },
            ));
        }
        if policy.boilerplate_rules[..index]
            .iter()
            .any(|previous| previous.exact_line == rule.exact_line)
        {
            return Err(CompactError::InvalidPolicy(
                PolicyValidationError::DuplicateBoilerplateRuleText { index },
            ));
        }
    }
    Ok(())
}

fn validate_metadata(metadata: &LogMetadata, source_bytes: usize) -> Result<(), CompactError> {
    if metadata.stage_boundaries.len() > MAX_STAGE_BOUNDARIES {
        return Err(CompactError::InvalidMetadata(
            MetadataValidationError::TooManyStageBoundaries,
        ));
    }
    let source_length = usize_to_u64(source_bytes);
    for (index, stage) in metadata.stage_boundaries.iter().enumerate() {
        if stage.label.is_empty()
            || stage.label.len() > MAX_STAGE_LABEL_BYTES
            || stage.label.chars().any(char::is_control)
        {
            return Err(CompactError::InvalidMetadata(
                MetadataValidationError::StageLabel { index },
            ));
        }
        if source_bytes == 0 {
            return Err(CompactError::InvalidMetadata(
                MetadataValidationError::StageWithoutSource { index },
            ));
        }
        if stage.byte_offset > source_length {
            return Err(CompactError::InvalidMetadata(
                MetadataValidationError::StageOffsetOutOfBounds {
                    index,
                    byte_offset: stage.byte_offset,
                    source_length,
                },
            ));
        }
    }
    Ok(())
}

fn valid_identifier(value: &str, maximum_bytes: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum_bytes
        && value.as_bytes().iter().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_' | b'.')
        })
}

fn verify_digest(source: &SourceEvidence, exact_bytes: &[u8]) -> Result<(), CompactError> {
    let actual = digest_bytes(exact_bytes);
    if source.digest != actual {
        return Err(CompactError::DigestMismatch {
            expected: source.digest.clone(),
            actual,
        });
    }
    Ok(())
}

fn digest_bytes(bytes: &[u8]) -> ContentDigest {
    ContentDigest::from_sha256(Sha256::digest(bytes).into())
}

fn digest_policy(policy: &CompactionPolicy) -> ContentDigest {
    let mut hasher = Sha256::new();
    hash_length_prefixed(&mut hasher, policy.version.as_bytes());
    hasher.update(usize_to_u64(policy.boundary_records).to_be_bytes());
    hasher.update(usize_to_u64(policy.failure_context_records).to_be_bytes());
    let mut rules = policy.boilerplate_rules.iter().collect::<Vec<_>>();
    rules.sort_by(|left, right| {
        left.id
            .cmp(&right.id)
            .then_with(|| left.exact_line.cmp(&right.exact_line))
    });
    hasher.update(usize_to_u64(rules.len()).to_be_bytes());
    for rule in rules {
        hash_length_prefixed(&mut hasher, rule.id.as_bytes());
        hash_length_prefixed(&mut hasher, rule.exact_line.as_bytes());
    }
    ContentDigest::from_sha256(hasher.finalize().into())
}

fn hash_length_prefixed(hasher: &mut Sha256, value: &[u8]) {
    hasher.update(usize_to_u64(value.len()).to_be_bytes());
    hasher.update(value);
}

fn parse_records(bytes: &[u8]) -> Result<Vec<Record>, CompactError> {
    let mut records = Vec::new();
    let mut start = 0;
    let mut cursor = 0;
    while cursor < bytes.len() {
        match bytes[cursor] {
            b'\r' if bytes.get(cursor + 1) == Some(&b'\n') => {
                push_record(
                    &mut records,
                    bytes,
                    start,
                    cursor,
                    cursor + 2,
                    FrameKind::Line,
                )?;
                cursor += 2;
                start = cursor;
            }
            b'\r' => {
                push_record(
                    &mut records,
                    bytes,
                    start,
                    cursor,
                    cursor + 1,
                    FrameKind::Progress,
                )?;
                cursor += 1;
                start = cursor;
            }
            b'\n' => {
                push_record(
                    &mut records,
                    bytes,
                    start,
                    cursor,
                    cursor + 1,
                    FrameKind::Line,
                )?;
                cursor += 1;
                start = cursor;
            }
            _ => cursor += 1,
        }
    }
    if start < bytes.len() {
        push_record(
            &mut records,
            bytes,
            start,
            bytes.len(),
            bytes.len(),
            FrameKind::Line,
        )?;
    }
    Ok(records)
}

fn push_record(
    records: &mut Vec<Record>,
    bytes: &[u8],
    start: usize,
    content_end: usize,
    end: usize,
    frame_kind: FrameKind,
) -> Result<(), CompactError> {
    if records.len() == MAX_SOURCE_RECORDS {
        return Err(CompactError::TooManyRecords {
            maximum_records: usize_to_u64(MAX_SOURCE_RECORDS),
        });
    }
    records.push(record(bytes, start, content_end, end, frame_kind));
    Ok(())
}

fn record(
    bytes: &[u8],
    start: usize,
    content_end: usize,
    end: usize,
    frame_kind: FrameKind,
) -> Record {
    Record {
        start,
        end,
        display: normalize_display(&bytes[start..content_end]),
        frame_kind,
    }
}

fn normalize_display(bytes: &[u8]) -> String {
    let stripped = strip_terminal_sequences(bytes);
    let lossy = String::from_utf8_lossy(&stripped);
    let mut display = String::with_capacity(lossy.len());
    for character in lossy.chars() {
        if character.is_control() {
            match u32::from(character) {
                0x09 => display.push_str("\\t"),
                code @ 0x00..=0xff => {
                    use std::fmt::Write as _;
                    write!(display, "\\x{code:02x}").expect("writing to a String cannot fail");
                }
                code => {
                    use std::fmt::Write as _;
                    write!(display, "\\u{{{code:x}}}").expect("writing to a String cannot fail");
                }
            }
        } else {
            display.push(character);
        }
    }
    display
}

fn strip_terminal_sequences(bytes: &[u8]) -> Vec<u8> {
    let mut stripped = Vec::with_capacity(bytes.len());
    let mut cursor = 0;
    while cursor < bytes.len() {
        match bytes[cursor] {
            0x1b => cursor = consume_escape(bytes, cursor),
            byte => {
                stripped.push(byte);
                cursor += 1;
            }
        }
    }
    stripped
}

fn consume_escape(bytes: &[u8], cursor: usize) -> usize {
    match bytes.get(cursor + 1) {
        Some(b'[') => consume_csi(bytes, cursor + 2),
        Some(b']') => consume_osc(bytes, cursor + 2),
        Some(_) => cmp::min(cursor + 2, bytes.len()),
        None => bytes.len(),
    }
}

fn consume_csi(bytes: &[u8], mut cursor: usize) -> usize {
    while cursor < bytes.len() {
        let byte = bytes[cursor];
        cursor += 1;
        if (0x40..=0x7e).contains(&byte) {
            break;
        }
    }
    cursor
}

fn consume_osc(bytes: &[u8], mut cursor: usize) -> usize {
    while cursor < bytes.len() {
        match bytes[cursor] {
            0x07 => return cursor + 1,
            0x1b if bytes.get(cursor + 1) == Some(&b'\\') => return cursor + 2,
            _ => cursor += 1,
        }
    }
    cursor
}

fn progress_omissions(records: &[Record]) -> Vec<Option<OmissionReason>> {
    let mut omissions = vec![None; records.len()];
    let mut start = 0;
    while start < records.len() {
        if records[start].frame_kind != FrameKind::Progress {
            start += 1;
            continue;
        }
        let mut end = start + 1;
        while end < records.len() && records[end - 1].frame_kind == FrameKind::Progress {
            end += 1;
        }
        for omission in &mut omissions[start..end.saturating_sub(1)] {
            *omission = Some(OmissionReason::SupersededProgress);
        }
        start = end;
    }
    omissions
}

fn apply_boilerplate_omissions(
    records: &[Record],
    policy: &CompactionPolicy,
    omissions: &mut [Option<OmissionReason>],
) {
    let rules = policy
        .boilerplate_rules
        .iter()
        .map(|rule| (rule.exact_line.as_str(), rule.id.as_str()))
        .collect::<BTreeMap<_, _>>();
    for (record, omission) in records.iter().zip(omissions) {
        if omission.is_some() {
            continue;
        }
        if let Some(rule_id) = rules.get(record.display.as_str()) {
            *omission = Some(OmissionReason::Boilerplate {
                rule_id: (*rule_id).to_owned(),
            });
        }
    }
}

fn apply_repeat_omissions(records: &[Record], omissions: &mut [Option<OmissionReason>]) {
    let mut previous_display: Option<&str> = None;
    for (record, omission) in records.iter().zip(omissions) {
        if omission.is_some() {
            previous_display = None;
            continue;
        }
        if previous_display == Some(record.display.as_str()) {
            *omission = Some(OmissionReason::Repeated);
        } else {
            previous_display = Some(record.display.as_str());
        }
    }
}

fn retain_boundaries(
    active_indices: &[usize],
    boundary_records: usize,
    reasons: &mut [Vec<RetentionReason>],
) {
    for &index in active_indices.iter().take(boundary_records) {
        add_reason(&mut reasons[index], RetentionReason::FirstBoundary);
    }
    for &index in active_indices.iter().rev().take(boundary_records) {
        add_reason(&mut reasons[index], RetentionReason::LastBoundary);
    }
}

fn retain_stages(
    records: &[Record],
    active_indices: &[usize],
    stages: &[StageBoundary],
    reasons: &mut [Vec<RetentionReason>],
) {
    let mut stages = stages.to_vec();
    stages.sort_by(|left, right| {
        left.byte_offset
            .cmp(&right.byte_offset)
            .then_with(|| left.label.cmp(&right.label))
    });
    stages.dedup();
    for stage in stages {
        let target = u64_to_usize(stage.byte_offset);
        let raw_index = record_at_or_after(records, target);
        let Some(index) = raw_index.and_then(|index| nearest_active(active_indices, index)) else {
            continue;
        };
        add_reason(
            &mut reasons[index],
            RetentionReason::StageBoundary {
                label: stage.label,
                byte_offset: stage.byte_offset,
            },
        );
    }
}

fn retain_failure_neighborhoods(
    records: &[Record],
    active_indices: &[usize],
    context_records: usize,
    reasons: &mut [Vec<RetentionReason>],
) {
    for (active_position, &record_index) in active_indices.iter().enumerate() {
        for keyword in FAILURE_KEYWORDS {
            if !contains_ascii_case_insensitive(&records[record_index].display, keyword.as_str()) {
                continue;
            }
            let first = active_position.saturating_sub(context_records);
            let last = cmp::min(
                active_position.saturating_add(context_records),
                active_indices.len().saturating_sub(1),
            );
            for &neighbor in &active_indices[first..=last] {
                add_reason(
                    &mut reasons[neighbor],
                    RetentionReason::FailureNeighborhood { keyword },
                );
            }
        }
    }
}

fn record_at_or_after(records: &[Record], byte_offset: usize) -> Option<usize> {
    let index = records.partition_point(|record| record.end <= byte_offset);
    (index < records.len())
        .then_some(index)
        .or_else(|| (!records.is_empty()).then_some(records.len() - 1))
}

fn nearest_active(active_indices: &[usize], raw_index: usize) -> Option<usize> {
    active_indices
        .iter()
        .copied()
        .find(|&index| index >= raw_index)
        .or_else(|| active_indices.last().copied())
}

fn add_reason(reasons: &mut Vec<RetentionReason>, reason: RetentionReason) {
    if !reasons.contains(&reason) {
        reasons.push(reason);
    }
}

fn contains_ascii_case_insensitive(value: &str, needle: &str) -> bool {
    value
        .as_bytes()
        .windows(needle.len())
        .any(|window| window.eq_ignore_ascii_case(needle.as_bytes()))
}

fn build_fragments(
    source: &SourceEvidence,
    records: &[Record],
    dispositions: &[Disposition],
) -> Vec<CompactedFragment> {
    let mut fragments = Vec::new();
    let mut index = 0;
    while index < records.len() {
        match &dispositions[index] {
            Disposition::Retained(reasons) => {
                fragments.push(CompactedFragment {
                    source: reference(source, &records[index]),
                    kind: FragmentKind::Retained {
                        reasons: reasons.clone(),
                    },
                    rendered: format!("{}\n", records[index].display),
                });
                index += 1;
            }
            Disposition::Omitted(reason) => {
                let start = index;
                index += 1;
                while index < records.len()
                    && dispositions[index] == Disposition::Omitted(reason.clone())
                {
                    index += 1;
                }
                let record_count = index - start;
                let source_reference = EvidenceReference {
                    handle: source.handle.clone(),
                    offset: usize_to_u64(records[start].start),
                    length: usize_to_u64(records[index - 1].end - records[start].start),
                };
                fragments.push(CompactedFragment {
                    source: source_reference,
                    kind: FragmentKind::Omitted {
                        reason: reason.clone(),
                        record_count: usize_to_u64(record_count),
                    },
                    rendered: render_omission(reason, record_count),
                });
            }
        }
    }
    fragments
}

fn render_omission(reason: &OmissionReason, record_count: usize) -> String {
    match reason {
        OmissionReason::OutsideRetentionWindow => {
            format!("[... {record_count} records outside retention windows ...]\n")
        }
        OmissionReason::Repeated => {
            format!("[... {record_count} repeated records collapsed ...]\n")
        }
        OmissionReason::SupersededProgress => {
            format!("[... {record_count} progress frames superseded ...]\n")
        }
        OmissionReason::Boilerplate { rule_id } => {
            format!("[... {record_count} boilerplate records removed by {rule_id} ...]\n")
        }
    }
}

fn render_exit_status(rendered: &mut String, exit_status: Option<i32>) {
    use std::fmt::Write as _;
    match exit_status {
        Some(status) => {
            writeln!(rendered, "[exit status: {status}]").expect("writing to a String cannot fail");
        }
        None => rendered.push_str("[exit status: unknown]\n"),
    }
}

fn reference(source: &SourceEvidence, record: &Record) -> EvidenceReference {
    EvidenceReference {
        handle: source.handle.clone(),
        offset: usize_to_u64(record.start),
        length: usize_to_u64(record.end - record.start),
    }
}

fn usize_to_u64(value: usize) -> u64 {
    u64::try_from(value).expect("usize fits into u64 on supported targets")
}

fn u64_to_usize(value: u64) -> usize {
    usize::try_from(value).unwrap_or(usize::MAX)
}

#[cfg(test)]
mod lib_test;
