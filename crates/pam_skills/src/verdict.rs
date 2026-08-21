use std::{collections::BTreeSet, error::Error, fmt};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::AgentArtifactId;

pub const MIN_VERDICT_ARTIFACT_IDS_PER_FINDING: usize = 2;
pub const MAX_VERDICT_ARTIFACT_IDS_PER_FINDING: usize = 16;
pub const MAX_VERDICT_FINDINGS_PER_CATEGORY: usize = 64;
pub const MAX_VERDICT_FINDING_TEXT_BYTES: usize = 1024;
pub const MAX_VERDICT_OVERALL_SUMMARY_BYTES: usize = 4096;
pub const MAX_VERDICT_JSON_BYTES: usize = 256 * 1024;

const ARTIFACT_ID_LENGTH: usize = 80;
const ARTIFACT_ID_PATTERN: &str = r"^artifact:sha256:[0-9a-f]{64}$";
const SAFE_NONBLANK_TEXT_PATTERN: &str = r"^(?=.*\S)[^\u0000-\u001F\u007F-\u009F]*$";

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SaturationGrade {
    Healthy,
    Elevated,
    High,
    Critical,
}

impl SaturationGrade {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Healthy => "healthy",
            Self::Elevated => "elevated",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VerdictOverlap {
    artifact_ids: Vec<AgentArtifactId>,
    summary: String,
}

impl VerdictOverlap {
    #[must_use]
    pub fn artifact_ids(&self) -> &[AgentArtifactId] {
        &self.artifact_ids
    }

    #[must_use]
    pub fn summary(&self) -> &str {
        &self.summary
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VerdictConflict {
    artifact_ids: Vec<AgentArtifactId>,
    summary: String,
}

impl VerdictConflict {
    #[must_use]
    pub fn artifact_ids(&self) -> &[AgentArtifactId] {
        &self.artifact_ids
    }

    #[must_use]
    pub fn summary(&self) -> &str {
        &self.summary
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VerdictStaleCandidate {
    artifact_id: AgentArtifactId,
    reason: String,
}

impl VerdictStaleCandidate {
    #[must_use]
    pub const fn artifact_id(&self) -> &AgentArtifactId {
        &self.artifact_id
    }

    #[must_use]
    pub fn reason(&self) -> &str {
        &self.reason
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SkillsAuditVerdict {
    overlaps: Vec<VerdictOverlap>,
    conflicts: Vec<VerdictConflict>,
    stale_candidates: Vec<VerdictStaleCandidate>,
    saturation_grade: SaturationGrade,
    overall_summary: String,
}

impl SkillsAuditVerdict {
    #[must_use]
    pub fn overlaps(&self) -> &[VerdictOverlap] {
        &self.overlaps
    }

    #[must_use]
    pub fn conflicts(&self) -> &[VerdictConflict] {
        &self.conflicts
    }

    #[must_use]
    pub fn stale_candidates(&self) -> &[VerdictStaleCandidate] {
        &self.stale_candidates
    }

    #[must_use]
    pub const fn saturation_grade(&self) -> SaturationGrade {
        self.saturation_grade
    }

    #[must_use]
    pub fn overall_summary(&self) -> &str {
        &self.overall_summary
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RawVerdict {
    overlaps: Vec<RawMultiArtifactFinding>,
    conflicts: Vec<RawMultiArtifactFinding>,
    stale_candidates: Vec<RawStaleCandidate>,
    saturation_grade: SaturationGrade,
    overall_summary: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RawMultiArtifactFinding {
    artifact_ids: Vec<String>,
    summary: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RawStaleCandidate {
    artifact_id: String,
    reason: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VerdictParseError {
    JsonTooLarge,
    MalformedJson,
    MalformedArtifactId,
    UnknownArtifactId,
    InvalidArtifactIdCount,
    DuplicateArtifactId,
    InvalidText,
    TooManyFindings,
    DuplicateFinding,
}

impl fmt::Display for VerdictParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::JsonTooLarge => "the evaluator verdict exceeds its JSON byte limit",
            Self::MalformedJson => "the evaluator verdict JSON is malformed",
            Self::MalformedArtifactId => "the evaluator verdict contains a malformed artifact ID",
            Self::UnknownArtifactId => "the evaluator verdict references an unknown artifact ID",
            Self::InvalidArtifactIdCount => "an evaluator finding has an invalid artifact ID count",
            Self::DuplicateArtifactId => "an evaluator finding contains a duplicate artifact ID",
            Self::InvalidText => "the evaluator verdict contains invalid bounded text",
            Self::TooManyFindings => "the evaluator verdict contains too many findings",
            Self::DuplicateFinding => "the evaluator verdict contains a duplicate finding",
        })
    }
}

impl Error for VerdictParseError {}

/// Parses, validates, and canonicalizes one evaluator verdict against the complete scan corpus.
///
/// # Errors
///
/// Returns a typed [`VerdictParseError`] for malformed or unbounded JSON, invalid or corpus-foreign
/// artifact IDs, invalid text, and duplicate IDs or findings. Errors never retain or display the
/// rejected JSON, artifact IDs, or text.
pub fn parse_skills_audit_verdict(
    json: &str,
    allowed_artifact_ids: &BTreeSet<AgentArtifactId>,
) -> Result<SkillsAuditVerdict, VerdictParseError> {
    if json.len() > MAX_VERDICT_JSON_BYTES {
        return Err(VerdictParseError::JsonTooLarge);
    }
    let raw =
        serde_json::from_str::<RawVerdict>(json).map_err(|_| VerdictParseError::MalformedJson)?;
    validate_text(&raw.overall_summary, MAX_VERDICT_OVERALL_SUMMARY_BYTES)?;
    validate_finding_count(raw.overlaps.len())?;
    validate_finding_count(raw.conflicts.len())?;
    validate_finding_count(raw.stale_candidates.len())?;

    let mut overlaps = raw
        .overlaps
        .into_iter()
        .map(|finding| {
            validate_text(&finding.summary, MAX_VERDICT_FINDING_TEXT_BYTES)?;
            Ok(VerdictOverlap {
                artifact_ids: validate_artifact_ids(finding.artifact_ids, allowed_artifact_ids)?,
                summary: finding.summary,
            })
        })
        .collect::<Result<Vec<_>, VerdictParseError>>()?;
    overlaps.sort_by(|left, right| left.artifact_ids.cmp(&right.artifact_ids));
    reject_duplicate_multi_findings(overlaps.windows(2).map(|pair| {
        (
            pair[0].artifact_ids.as_slice(),
            pair[1].artifact_ids.as_slice(),
        )
    }))?;

    let mut conflicts = raw
        .conflicts
        .into_iter()
        .map(|finding| {
            validate_text(&finding.summary, MAX_VERDICT_FINDING_TEXT_BYTES)?;
            Ok(VerdictConflict {
                artifact_ids: validate_artifact_ids(finding.artifact_ids, allowed_artifact_ids)?,
                summary: finding.summary,
            })
        })
        .collect::<Result<Vec<_>, VerdictParseError>>()?;
    conflicts.sort_by(|left, right| left.artifact_ids.cmp(&right.artifact_ids));
    reject_duplicate_multi_findings(conflicts.windows(2).map(|pair| {
        (
            pair[0].artifact_ids.as_slice(),
            pair[1].artifact_ids.as_slice(),
        )
    }))?;

    let mut stale_candidates = raw
        .stale_candidates
        .into_iter()
        .map(|finding| {
            validate_text(&finding.reason, MAX_VERDICT_FINDING_TEXT_BYTES)?;
            let artifact_id = parse_allowed_artifact_id(finding.artifact_id, allowed_artifact_ids)?;
            Ok(VerdictStaleCandidate {
                artifact_id,
                reason: finding.reason,
            })
        })
        .collect::<Result<Vec<_>, VerdictParseError>>()?;
    stale_candidates.sort_by(|left, right| left.artifact_id.cmp(&right.artifact_id));
    if stale_candidates
        .windows(2)
        .any(|pair| pair[0].artifact_id == pair[1].artifact_id)
    {
        return Err(VerdictParseError::DuplicateFinding);
    }

    Ok(SkillsAuditVerdict {
        overlaps,
        conflicts,
        stale_candidates,
        saturation_grade: raw.saturation_grade,
        overall_summary: raw.overall_summary,
    })
}

fn validate_finding_count(count: usize) -> Result<(), VerdictParseError> {
    if count > MAX_VERDICT_FINDINGS_PER_CATEGORY {
        return Err(VerdictParseError::TooManyFindings);
    }
    Ok(())
}

fn validate_artifact_ids(
    artifact_ids: Vec<String>,
    allowed_artifact_ids: &BTreeSet<AgentArtifactId>,
) -> Result<Vec<AgentArtifactId>, VerdictParseError> {
    if !(MIN_VERDICT_ARTIFACT_IDS_PER_FINDING..=MAX_VERDICT_ARTIFACT_IDS_PER_FINDING)
        .contains(&artifact_ids.len())
    {
        return Err(VerdictParseError::InvalidArtifactIdCount);
    }
    let mut artifact_ids = artifact_ids
        .into_iter()
        .map(|artifact_id| parse_allowed_artifact_id(artifact_id, allowed_artifact_ids))
        .collect::<Result<Vec<_>, _>>()?;
    artifact_ids.sort();
    if artifact_ids.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(VerdictParseError::DuplicateArtifactId);
    }
    Ok(artifact_ids)
}

fn parse_allowed_artifact_id(
    artifact_id: String,
    allowed_artifact_ids: &BTreeSet<AgentArtifactId>,
) -> Result<AgentArtifactId, VerdictParseError> {
    let artifact_id =
        AgentArtifactId::parse(artifact_id).map_err(|_| VerdictParseError::MalformedArtifactId)?;
    if !allowed_artifact_ids.contains(&artifact_id) {
        return Err(VerdictParseError::UnknownArtifactId);
    }
    Ok(artifact_id)
}

fn validate_text(value: &str, maximum_bytes: usize) -> Result<(), VerdictParseError> {
    if value.len() > maximum_bytes || value.trim().is_empty() || value.chars().any(char::is_control)
    {
        return Err(VerdictParseError::InvalidText);
    }
    Ok(())
}

fn reject_duplicate_multi_findings<'a>(
    mut adjacent_ids: impl Iterator<Item = (&'a [AgentArtifactId], &'a [AgentArtifactId])>,
) -> Result<(), VerdictParseError> {
    if adjacent_ids.any(|(left, right)| left == right) {
        return Err(VerdictParseError::DuplicateFinding);
    }
    Ok(())
}

/// Returns the strict JSON Schema supplied to supported evaluator CLIs.
#[must_use]
pub fn skills_audit_verdict_json_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "x-maxJsonUtf8Bytes": MAX_VERDICT_JSON_BYTES,
        "additionalProperties": false,
        "required": [
            "overlaps",
            "conflicts",
            "staleCandidates",
            "saturationGrade",
            "overallSummary"
        ],
        "properties": {
            "overlaps": finding_array_schema("#/$defs/overlap", "artifactIds"),
            "conflicts": finding_array_schema("#/$defs/conflict", "artifactIds"),
            "staleCandidates": finding_array_schema("#/$defs/staleCandidate", "artifactId"),
            "saturationGrade": {
                "type": "string",
                "enum": ["healthy", "elevated", "high", "critical"]
            },
            "overallSummary": text_schema(MAX_VERDICT_OVERALL_SUMMARY_BYTES)
        },
        "$defs": {
            "artifactId": {
                "type": "string",
                "minLength": ARTIFACT_ID_LENGTH,
                "maxLength": ARTIFACT_ID_LENGTH,
                "pattern": ARTIFACT_ID_PATTERN
            },
            "overlap": multi_artifact_finding_schema(),
            "conflict": multi_artifact_finding_schema(),
            "staleCandidate": {
                "type": "object",
                "additionalProperties": false,
                "required": ["artifactId", "reason"],
                "properties": {
                    "artifactId": { "$ref": "#/$defs/artifactId" },
                    "reason": text_schema(MAX_VERDICT_FINDING_TEXT_BYTES)
                }
            }
        }
    })
}

fn finding_array_schema(item_reference: &str, unique_by: &str) -> Value {
    json!({
        "type": "array",
        "minItems": 0,
        "maxItems": MAX_VERDICT_FINDINGS_PER_CATEGORY,
        "uniqueItems": true,
        "x-uniqueBy": unique_by,
        "x-canonicalOrder": unique_by,
        "items": { "$ref": item_reference }
    })
}

fn multi_artifact_finding_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["artifactIds", "summary"],
        "properties": {
            "artifactIds": {
                "type": "array",
                "minItems": MIN_VERDICT_ARTIFACT_IDS_PER_FINDING,
                "maxItems": MAX_VERDICT_ARTIFACT_IDS_PER_FINDING,
                "uniqueItems": true,
                "x-canonicalOrder": "ascending",
                "items": { "$ref": "#/$defs/artifactId" }
            },
            "summary": text_schema(MAX_VERDICT_FINDING_TEXT_BYTES)
        }
    })
}

fn text_schema(maximum_bytes: usize) -> Value {
    json!({
        "type": "string",
        "minLength": 1,
        "maxLength": maximum_bytes,
        "pattern": SAFE_NONBLANK_TEXT_PATTERN,
        "x-maxUtf8Bytes": maximum_bytes
    })
}
