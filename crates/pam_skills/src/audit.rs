use std::{collections::BTreeMap, error::Error, fmt};

use pam_core::ContentDigest;
use serde::{Deserialize, Serialize};

use crate::{AgentArtifactId, ArtifactKind, ArtifactScope, LoadSemantics, OriginAgent, ScanReport};

pub const STATIC_FOOTPRINT_SCHEMA_VERSION: u32 = 1;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TokenEstimator {
    #[serde(rename = "raw_bytes_div_4_ceil_v1")]
    RawBytesDiv4CeilV1,
}

impl TokenEstimator {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RawBytesDiv4CeilV1 => "raw_bytes_div_4_ceil_v1",
        }
    }

    #[must_use]
    const fn estimate(self, raw_bytes: u64) -> u64 {
        match self {
            Self::RawBytesDiv4CeilV1 => {
                raw_bytes / 4 + if raw_bytes.is_multiple_of(4) { 0 } else { 1 }
            }
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StaticFootprintArtifact {
    rank: u64,
    id: AgentArtifactId,
    name: String,
    logical_path: String,
    kind: ArtifactKind,
    scope: ArtifactScope,
    origin: OriginAgent,
    load_semantics: LoadSemantics,
    content_hash: ContentDigest,
    raw_bytes: u64,
    estimated_tokens: u64,
}

impl StaticFootprintArtifact {
    #[must_use]
    pub const fn rank(&self) -> u64 {
        self.rank
    }

    #[must_use]
    pub const fn id(&self) -> &AgentArtifactId {
        &self.id
    }

    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    #[must_use]
    pub fn logical_path(&self) -> &str {
        &self.logical_path
    }

    #[must_use]
    pub const fn kind(&self) -> ArtifactKind {
        self.kind
    }

    #[must_use]
    pub const fn scope(&self) -> ArtifactScope {
        self.scope
    }

    #[must_use]
    pub const fn origin(&self) -> OriginAgent {
        self.origin
    }

    #[must_use]
    pub const fn load_semantics(&self) -> LoadSemantics {
        self.load_semantics
    }

    #[must_use]
    pub const fn content_hash(&self) -> &ContentDigest {
        &self.content_hash
    }

    #[must_use]
    pub const fn raw_bytes(&self) -> u64 {
        self.raw_bytes
    }

    #[must_use]
    pub const fn estimated_tokens(&self) -> u64 {
        self.estimated_tokens
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OriginAgentSessionTotals {
    origin: OriginAgent,
    artifact_count: u64,
    raw_bytes: u64,
    estimated_tokens: u64,
}

impl OriginAgentSessionTotals {
    #[must_use]
    pub const fn origin(&self) -> OriginAgent {
        self.origin
    }

    #[must_use]
    pub const fn artifact_count(&self) -> u64 {
        self.artifact_count
    }

    #[must_use]
    pub const fn raw_bytes(&self) -> u64 {
        self.raw_bytes
    }

    #[must_use]
    pub const fn estimated_tokens(&self) -> u64 {
        self.estimated_tokens
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AllSessionScopeTotals {
    scope: ArtifactScope,
    artifact_count: u64,
    raw_bytes: u64,
    estimated_tokens: u64,
}

impl AllSessionScopeTotals {
    #[must_use]
    pub const fn scope(&self) -> ArtifactScope {
        self.scope
    }

    #[must_use]
    pub const fn artifact_count(&self) -> u64 {
        self.artifact_count
    }

    #[must_use]
    pub const fn raw_bytes(&self) -> u64 {
        self.raw_bytes
    }

    #[must_use]
    pub const fn estimated_tokens(&self) -> u64 {
        self.estimated_tokens
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct FootprintTotals {
    artifact_count: u64,
    raw_bytes: u64,
    estimated_tokens: u64,
}

impl FootprintTotals {
    fn include(
        &mut self,
        raw_bytes: u64,
        estimated_tokens: u64,
    ) -> Result<(), StaticFootprintError> {
        self.artifact_count = self
            .artifact_count
            .checked_add(1)
            .ok_or(StaticFootprintError::ArithmeticOverflow)?;
        self.raw_bytes = self
            .raw_bytes
            .checked_add(raw_bytes)
            .ok_or(StaticFootprintError::ArithmeticOverflow)?;
        self.estimated_tokens = self
            .estimated_tokens
            .checked_add(estimated_tokens)
            .ok_or(StaticFootprintError::ArithmeticOverflow)?;
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StaticFootprintReport {
    schema_version: u32,
    estimator: TokenEstimator,
    always_loaded_artifact_count: u64,
    all_session_raw_bytes: u64,
    all_session_estimated_tokens: u64,
    artifacts: Vec<StaticFootprintArtifact>,
    origin_agent_session_totals: Vec<OriginAgentSessionTotals>,
    all_session_scope_totals: Vec<AllSessionScopeTotals>,
}

impl StaticFootprintReport {
    #[must_use]
    pub const fn schema_version(&self) -> u32 {
        self.schema_version
    }

    #[must_use]
    pub const fn estimator(&self) -> TokenEstimator {
        self.estimator
    }

    #[must_use]
    pub const fn always_loaded_artifact_count(&self) -> u64 {
        self.always_loaded_artifact_count
    }

    #[must_use]
    pub const fn all_session_raw_bytes(&self) -> u64 {
        self.all_session_raw_bytes
    }

    #[must_use]
    pub const fn all_session_estimated_tokens(&self) -> u64 {
        self.all_session_estimated_tokens
    }

    #[must_use]
    pub fn artifacts(&self) -> &[StaticFootprintArtifact] {
        &self.artifacts
    }

    /// Returns one independent agent-session total for each origin represented in the scan.
    #[must_use]
    pub fn origin_agent_session_totals(&self) -> &[OriginAgentSessionTotals] {
        &self.origin_agent_session_totals
    }

    /// Returns per-scope totals summed across every origin agent session.
    #[must_use]
    pub fn all_session_scope_totals(&self) -> &[AllSessionScopeTotals] {
        &self.all_session_scope_totals
    }
}

/// Builds the deterministic static context footprint for every always-loaded artifact.
///
/// The estimator counts exact raw source bytes, including native line endings, then applies the
/// versioned `ceil(raw_bytes / 4)` approximation. Source bytes are never retained by the returned
/// report.
///
/// # Errors
///
/// Returns [`StaticFootprintError::MissingAlwaysLoadedSource`] when a normalized always-loaded
/// artifact has no transient source, or [`StaticFootprintError::ArithmeticOverflow`] when a count
/// cannot be represented safely.
pub fn build_static_footprint(
    scan: &ScanReport,
) -> Result<StaticFootprintReport, StaticFootprintError> {
    let estimator = TokenEstimator::RawBytesDiv4CeilV1;
    let mut artifacts = Vec::new();
    let mut all_session_raw_bytes = 0_u64;
    let mut all_session_estimated_tokens = 0_u64;
    let mut totals_by_origin = BTreeMap::<OriginAgent, FootprintTotals>::new();
    let mut totals_by_scope = BTreeMap::<ArtifactScope, FootprintTotals>::new();

    for artifact in scan
        .artifacts()
        .iter()
        .filter(|artifact| artifact.load_semantics() == LoadSemantics::Always)
    {
        let id = artifact.id();
        let source = scan
            .always_loaded_source(&id)
            .ok_or_else(|| StaticFootprintError::MissingAlwaysLoadedSource(id.clone()))?;
        let raw_bytes =
            u64::try_from(source.len()).map_err(|_| StaticFootprintError::ArithmeticOverflow)?;
        let estimated_tokens = estimator.estimate(raw_bytes);
        all_session_raw_bytes = all_session_raw_bytes
            .checked_add(raw_bytes)
            .ok_or(StaticFootprintError::ArithmeticOverflow)?;
        all_session_estimated_tokens = all_session_estimated_tokens
            .checked_add(estimated_tokens)
            .ok_or(StaticFootprintError::ArithmeticOverflow)?;
        totals_by_origin
            .entry(artifact.origin())
            .or_default()
            .include(raw_bytes, estimated_tokens)?;
        totals_by_scope
            .entry(artifact.scope())
            .or_default()
            .include(raw_bytes, estimated_tokens)?;
        artifacts.push(StaticFootprintArtifact {
            rank: 0,
            id,
            name: artifact.name().to_owned(),
            logical_path: artifact.logical_path().to_owned(),
            kind: artifact.kind(),
            scope: artifact.scope(),
            origin: artifact.origin(),
            load_semantics: artifact.load_semantics(),
            content_hash: artifact.content_hash().clone(),
            raw_bytes,
            estimated_tokens,
        });
    }

    artifacts.sort_by(|left, right| {
        right
            .estimated_tokens
            .cmp(&left.estimated_tokens)
            .then_with(|| right.raw_bytes.cmp(&left.raw_bytes))
            .then_with(|| left.id.cmp(&right.id))
    });
    for (index, artifact) in artifacts.iter_mut().enumerate() {
        let rank = index
            .checked_add(1)
            .ok_or(StaticFootprintError::ArithmeticOverflow)?;
        artifact.rank =
            u64::try_from(rank).map_err(|_| StaticFootprintError::ArithmeticOverflow)?;
    }

    let always_loaded_artifact_count =
        u64::try_from(artifacts.len()).map_err(|_| StaticFootprintError::ArithmeticOverflow)?;
    let origin_agent_session_totals = totals_by_origin
        .into_iter()
        .map(|(origin, totals)| OriginAgentSessionTotals {
            origin,
            artifact_count: totals.artifact_count,
            raw_bytes: totals.raw_bytes,
            estimated_tokens: totals.estimated_tokens,
        })
        .collect();
    let all_session_scope_totals = totals_by_scope
        .into_iter()
        .map(|(scope, totals)| AllSessionScopeTotals {
            scope,
            artifact_count: totals.artifact_count,
            raw_bytes: totals.raw_bytes,
            estimated_tokens: totals.estimated_tokens,
        })
        .collect();
    Ok(StaticFootprintReport {
        schema_version: STATIC_FOOTPRINT_SCHEMA_VERSION,
        estimator,
        always_loaded_artifact_count,
        all_session_raw_bytes,
        all_session_estimated_tokens,
        artifacts,
        origin_agent_session_totals,
        all_session_scope_totals,
    })
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StaticFootprintError {
    MissingAlwaysLoadedSource(AgentArtifactId),
    ArithmeticOverflow,
}

impl fmt::Display for StaticFootprintError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingAlwaysLoadedSource(artifact_id) => {
                write!(
                    formatter,
                    "always-loaded source is unavailable for {artifact_id}"
                )
            }
            Self::ArithmeticOverflow => formatter.write_str("static footprint arithmetic overflow"),
        }
    }
}

impl Error for StaticFootprintError {}
