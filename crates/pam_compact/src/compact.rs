//! The structural compactor: records in, a rendered reduction plus a
//! complete byte-range map out.
//!
//! Every step is deterministic and byte-based. The only allocation that
//! grows with the input is the record table; the caller bounds the input
//! before calling, and [`compact`] refuses anything past its own limits
//! before doing any work.

use std::cmp;
use std::fmt::Write as _;

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

/// Name of the versioned algorithm implemented here. It appears in every
/// report so a stored reduction says which rules produced it.
pub const ALGORITHM_VERSION: &str = "pam-log-compact-v1";

/// Largest source accepted, in bytes (64 `MiB`).
pub const MAX_SOURCE_BYTES: usize = 64 * 1024 * 1024;

/// Largest number of records a source may frame.
pub const MAX_SOURCE_RECORDS: usize = 100_000;

/// Upper bound on [`Policy::failure_context_records`].
pub const MAX_FAILURE_CONTEXT_RECORDS: usize = 64;

/// Records kept at each end of the log by [`Policy::default`].
pub const DEFAULT_BOUNDARY_RECORDS: usize = 20;

/// Neighbours kept on each side of a failure by [`Policy::default`].
pub const DEFAULT_FAILURE_CONTEXT_RECORDS: usize = 3;

/// How wide the retention windows are. Versioned with the algorithm: the
/// same policy and the same bytes always give the same reduction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Policy {
    /// Records kept at the start and at the end of the log.
    pub boundary_records: usize,
    /// Records kept on each side of a record naming a failure.
    pub failure_context_records: usize,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            boundary_records: DEFAULT_BOUNDARY_RECORDS,
            failure_context_records: DEFAULT_FAILURE_CONTEXT_RECORDS,
        }
    }
}

/// A fixed ASCII token that marks a record as interesting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureKeyword {
    /// `error`
    Error,
    /// `fatal`
    Fatal,
    /// `panic`
    Panic,
    /// `failed`
    Failed,
}

impl FailureKeyword {
    /// Every keyword, in the order they are matched.
    pub const ALL: [Self; 4] = [Self::Error, Self::Fatal, Self::Panic, Self::Failed];

    /// The lowercase token matched case-insensitively against a record.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Error => "error",
            Self::Fatal => "fatal",
            Self::Panic => "panic",
            Self::Failed => "failed",
        }
    }
}

/// Why a record survived the reduction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RetentionReason {
    /// Inside the window at the start of the log.
    FirstBoundary,
    /// Inside the window at the end of the log.
    LastBoundary,
    /// The record names a failure, or sits next to one that does.
    FailureNeighborhood {
        /// The keyword that opened the neighbourhood.
        keyword: FailureKeyword,
    },
}

/// Why a source range is represented by a marker instead of its text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OmissionReason {
    /// Outside every retention window.
    OutsideRetentionWindow,
    /// Identical to the record before it.
    Repeated,
    /// A progress frame overwritten by a later frame in the same run.
    SupersededProgress,
}

/// Whether a fragment carries normalized content or an omission marker.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum FragmentKind {
    /// One record, rendered in display form.
    Retained {
        /// Deduplicated, in the order the rules fired.
        reasons: Vec<RetentionReason>,
    },
    /// A run of consecutive records dropped for the same reason.
    Omitted {
        /// Why the run was dropped.
        reason: OmissionReason,
        /// How many source records the marker stands for.
        record_count: u64,
    },
}

/// A rendered fragment and the exact source bytes behind it.
///
/// Fragments are contiguous and ordered: reading `offset..offset + length`
/// from the source for each fragment in turn rebuilds the original bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Fragment {
    /// Byte offset of the fragment in the source.
    pub offset: u64,
    /// Byte length of the fragment in the source.
    pub length: u64,
    /// Retained content or an omission marker.
    #[serde(flatten)]
    pub kind: FragmentKind,
    /// What this fragment contributes to `rendered_text`.
    pub rendered: String,
}

/// A complete, reversible reduction of one log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Compacted {
    /// Always [`ALGORITHM_VERSION`] — stored so an old report stays readable.
    pub algorithm_version: String,
    /// Lowercase hex SHA-256 of the exact source bytes.
    pub source_sha256: String,
    /// Exit status of the process that wrote the log, when it is known.
    pub exit_status: Option<i32>,
    /// Size of the source in bytes.
    pub source_bytes: u64,
    /// Bytes covered by retained fragments.
    pub retained_bytes: u64,
    /// Records the source framed.
    pub source_records: u64,
    /// Records that survived the reduction.
    pub retained_records: u64,
    /// The reduction, ready to read or to hand to a model.
    pub rendered_text: String,
    /// Where every source byte went.
    pub fragments: Vec<Fragment>,
}

/// A bounded refusal raised before any reduction work happens.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CompactError {
    /// The source is larger than [`MAX_SOURCE_BYTES`].
    #[error("log source is {actual_bytes} bytes; the maximum is {maximum_bytes}")]
    SourceTooLarge {
        /// Size of the source that was offered.
        actual_bytes: u64,
        /// [`MAX_SOURCE_BYTES`], as a `u64`.
        maximum_bytes: u64,
    },
    /// The source frames more than [`MAX_SOURCE_RECORDS`] records.
    #[error("log exceeds {maximum_records} source records")]
    TooManyRecords {
        /// [`MAX_SOURCE_RECORDS`], as a `u64`.
        maximum_records: u64,
    },
    /// A [`Policy`] field is out of bounds.
    #[error("invalid compaction policy: {field} is out of bounds")]
    InvalidPolicy {
        /// The offending field name.
        field: &'static str,
    },
}

impl CompactError {
    /// The stable machine-readable cause, for refusal envelopes.
    #[must_use]
    pub fn cause(&self) -> &'static str {
        match self {
            Self::SourceTooLarge { .. } => "source_too_large",
            Self::TooManyRecords { .. } => "too_many_records",
            Self::InvalidPolicy { .. } => "invalid_policy",
        }
    }
}

/// `fmt::Write` on a `String` never fails; the `Result` is still checked.
const WRITE_TO_STRING: &str = "writing to a String cannot fail";

/// How a record was terminated in the source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FrameKind {
    /// Ended by `\n`, `\r\n`, or the end of the source.
    Line,
    /// Ended by a bare `\r` — a frame a terminal would overwrite.
    Progress,
}

/// One framed record: its byte range, its display form, its terminator.
#[derive(Debug, Clone)]
struct Record {
    start: usize,
    end: usize,
    display: String,
    frame_kind: FrameKind,
}

/// What the rules decided about one record.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Disposition {
    Retained(Vec<RetentionReason>),
    Omitted(OmissionReason),
}

/// Structurally reduces terminal output without interpreting it.
///
/// Parsing and rendering are byte-based and locale-independent, so the same
/// bytes and the same `policy` always produce the same [`Compacted`]. Every
/// source byte belongs to exactly one returned fragment.
///
/// # Errors
///
/// [`CompactError`] when the source is past a work bound or `policy` is not
/// within its own bounds. Nothing is parsed before those checks pass.
pub fn compact(
    bytes: &[u8],
    exit_status: Option<i32>,
    policy: &Policy,
) -> Result<Compacted, CompactError> {
    validate_source_size(bytes.len())?;
    validate_policy(policy)?;
    let records = parse_records(bytes)?;

    let mut omissions = progress_omissions(&records);
    apply_repeat_omissions(&records, &mut omissions);

    let active_indices = omissions
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
    retain_failure_neighborhoods(
        &records,
        &active_indices,
        policy.failure_context_records,
        &mut retention_reasons,
    );

    let dispositions = omissions
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

    let fragments = build_fragments(&records, &dispositions);
    let retained_bytes = fragments
        .iter()
        .filter_map(|fragment| match fragment.kind {
            FragmentKind::Retained { .. } => Some(fragment.length),
            FragmentKind::Omitted { .. } => None,
        })
        .sum();
    let retained_records = dispositions
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
    render_exit_status(&mut rendered_text, exit_status);

    Ok(Compacted {
        algorithm_version: ALGORITHM_VERSION.to_owned(),
        source_sha256: sha256_hex(bytes),
        exit_status,
        source_bytes: usize_to_u64(bytes.len()),
        retained_bytes,
        source_records: usize_to_u64(records.len()),
        retained_records: usize_to_u64(retained_records),
        rendered_text,
        fragments,
    })
}

/// A rough token count for `bytes` of text: four bytes per token, rounded up.
#[must_use]
pub fn estimate_tokens(bytes: u64) -> u64 {
    bytes.div_ceil(4)
}

/// Lowercase hex SHA-256 of `bytes`.
#[must_use]
pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
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

fn validate_policy(policy: &Policy) -> Result<(), CompactError> {
    if policy.boundary_records > MAX_SOURCE_RECORDS {
        return Err(CompactError::InvalidPolicy {
            field: "boundary_records",
        });
    }
    if policy.failure_context_records > MAX_FAILURE_CONTEXT_RECORDS {
        return Err(CompactError::InvalidPolicy {
            field: "failure_context_records",
        });
    }
    Ok(())
}

/// Frames the source: `\r\n` and `\n` end a line, a bare `\r` ends a
/// progress frame, and an unterminated tail is a line.
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
    records.push(Record {
        start,
        end,
        display: normalize_display(&bytes[start..content_end]),
        frame_kind,
    });
    Ok(())
}

/// Terminal sequences stripped, lossy UTF-8, control characters spelled out.
fn normalize_display(bytes: &[u8]) -> String {
    let stripped = strip_terminal_sequences(bytes);
    let lossy = String::from_utf8_lossy(&stripped);
    let mut display = String::with_capacity(lossy.len());
    for character in lossy.chars() {
        if character.is_control() {
            match u32::from(character) {
                0x09 => display.push_str("\\t"),
                code @ 0x00..=0xff => write!(display, "\\x{code:02x}").expect(WRITE_TO_STRING),
                code => write!(display, "\\u{{{code:x}}}").expect(WRITE_TO_STRING),
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

/// A control sequence runs to its first final byte (`0x40..=0x7e`).
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

/// An operating-system command runs to `BEL` or `ESC \`.
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

/// Every frame of a progress run except the last one is superseded.
fn progress_omissions(records: &[Record]) -> Vec<Option<OmissionReason>> {
    let mut omissions = vec![None; records.len()];
    let mut start = 0;
    while start < records.len() {
        if records[start].frame_kind != FrameKind::Progress {
            start += 1;
            continue;
        }
        let mut end = start + 1;
        while end < records.len() && records[end].frame_kind == FrameKind::Progress {
            end += 1;
        }
        for omission in &mut omissions[start..end - 1] {
            *omission = Some(OmissionReason::SupersededProgress);
        }
        start = end;
    }
    omissions
}

/// Adjacent records with the same display form collapse; an already
/// omitted record breaks the comparison.
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

/// A record naming a failure keeps itself and `context_records` surviving
/// neighbours on each side, clamped at both ends of the log.
fn retain_failure_neighborhoods(
    records: &[Record],
    active_indices: &[usize],
    context_records: usize,
    reasons: &mut [Vec<RetentionReason>],
) {
    for (active_position, &record_index) in active_indices.iter().enumerate() {
        for keyword in FailureKeyword::ALL {
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

/// Retained records render one fragment each; consecutive omissions with
/// the same reason merge into one marker fragment.
fn build_fragments(records: &[Record], dispositions: &[Disposition]) -> Vec<Fragment> {
    let mut fragments = Vec::new();
    let mut index = 0;
    while index < records.len() {
        match &dispositions[index] {
            Disposition::Retained(reasons) => {
                let record = &records[index];
                fragments.push(Fragment {
                    offset: usize_to_u64(record.start),
                    length: usize_to_u64(record.end - record.start),
                    kind: FragmentKind::Retained {
                        reasons: reasons.clone(),
                    },
                    rendered: format!("{}\n", record.display),
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
                fragments.push(Fragment {
                    offset: usize_to_u64(records[start].start),
                    length: usize_to_u64(records[index - 1].end - records[start].start),
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
    }
}

fn render_exit_status(rendered: &mut String, exit_status: Option<i32>) {
    match exit_status {
        Some(status) => writeln!(rendered, "[exit status: {status}]").expect(WRITE_TO_STRING),
        None => rendered.push_str("[exit status: unknown]\n"),
    }
}

/// Widens a length or an offset. Saturates instead of panicking: no
/// supported target has a `usize` wider than `u64`, and a saturated count
/// is still a truthful upper bound in a report.
fn usize_to_u64(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}
