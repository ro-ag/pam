use std::{cmp::Ordering, error::Error, fmt};

use pam_core::ContentDigest;
use serde::{Deserialize, Serialize};

pub const MAX_ARTIFACT_NAME_BYTES: usize = 256;
pub const MAX_ARTIFACT_LOGICAL_PATH_BYTES: usize = 4096;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactKind {
    Skill,
    Plugin,
    Agent,
    Hook,
    Instruction,
    Config,
    Prompt,
    Rule,
    Embedding,
    Reranker,
    Compressor,
    Analyzer,
    WasmComponent,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactScope {
    Managed,
    System,
    User,
    Project,
    Local,
    Plugin,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OriginAgent {
    ClaudeCode,
    Codex,
    Cursor,
    Pam,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LoadSemantics {
    Always,
    Explicit,
    ModelSelected,
    PathConditional,
    EventTriggered,
    ConfigurationLayer,
    PluginEnabled,
    DisabledOrInstalledOnly,
    Unavailable,
}

/// The durable identity of an artifact independent of its content and display metadata.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct AgentArtifactIdentity<'a> {
    pub origin: OriginAgent,
    pub kind: ArtifactKind,
    pub scope: ArtifactScope,
    pub logical_path: &'a str,
}

/// A normalized agent artifact discovered by an ecosystem-specific adapter.
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize)]
pub struct AgentArtifact {
    name: String,
    logical_path: String,
    kind: ArtifactKind,
    scope: ArtifactScope,
    origin: OriginAgent,
    load_semantics: LoadSemantics,
    content_hash: ContentDigest,
}

impl AgentArtifact {
    /// Creates a validated artifact with a portable logical path.
    ///
    /// Backslashes are normalized to `/`. Absolute paths, empty components,
    /// traversal components, NUL bytes, and overlong values are rejected.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidAgentArtifact::Name`] or
    /// [`InvalidAgentArtifact::LogicalPath`] when the corresponding input is invalid.
    pub fn new(
        name: impl Into<String>,
        logical_path: impl Into<String>,
        kind: ArtifactKind,
        scope: ArtifactScope,
        origin: OriginAgent,
        load_semantics: LoadSemantics,
        content_hash: ContentDigest,
    ) -> Result<Self, InvalidAgentArtifact> {
        let name = name.into();
        if name.is_empty() || name.len() > MAX_ARTIFACT_NAME_BYTES || name.contains('\0') {
            return Err(InvalidAgentArtifact::Name);
        }
        let logical_path = logical_path.into();
        let logical_path = normalize_logical_path(&logical_path)?;
        Ok(Self {
            name,
            logical_path,
            kind,
            scope,
            origin,
            load_semantics,
            content_hash,
        })
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
    pub fn identity(&self) -> AgentArtifactIdentity<'_> {
        AgentArtifactIdentity {
            origin: self.origin,
            kind: self.kind,
            scope: self.scope,
            logical_path: &self.logical_path,
        }
    }
}

impl<'de> Deserialize<'de> for AgentArtifact {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct SerializedArtifact {
            name: String,
            logical_path: String,
            kind: ArtifactKind,
            scope: ArtifactScope,
            origin: OriginAgent,
            load_semantics: LoadSemantics,
            content_hash: ContentDigest,
        }

        let artifact = SerializedArtifact::deserialize(deserializer)?;
        Self::new(
            artifact.name,
            artifact.logical_path,
            artifact.kind,
            artifact.scope,
            artifact.origin,
            artifact.load_semantics,
            artifact.content_hash,
        )
        .map_err(serde::de::Error::custom)
    }
}

impl Ord for AgentArtifact {
    fn cmp(&self, other: &Self) -> Ordering {
        self.identity()
            .cmp(&other.identity())
            .then_with(|| self.name.cmp(&other.name))
            .then_with(|| self.load_semantics.cmp(&other.load_semantics))
            .then_with(|| self.content_hash.as_str().cmp(other.content_hash.as_str()))
    }
}

impl PartialOrd for AgentArtifact {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

fn normalize_logical_path(value: &str) -> Result<String, InvalidAgentArtifact> {
    if value.is_empty() || value.len() > MAX_ARTIFACT_LOGICAL_PATH_BYTES || value.contains('\0') {
        return Err(InvalidAgentArtifact::LogicalPath);
    }

    let normalized = value.replace('\\', "/");
    if normalized.starts_with('/')
        || has_windows_drive_prefix(&normalized)
        || normalized
            .split('/')
            .any(|component| component.is_empty() || matches!(component, "." | ".."))
    {
        return Err(InvalidAgentArtifact::LogicalPath);
    }
    Ok(normalized)
}

fn has_windows_drive_prefix(path: &str) -> bool {
    let bytes = path.as_bytes();
    bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':'
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InvalidAgentArtifact {
    Name,
    LogicalPath,
}

impl fmt::Display for InvalidAgentArtifact {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Name => formatter.write_str("artifact name is empty, overlong, or contains NUL"),
            Self::LogicalPath => formatter.write_str(
                "artifact logical path must be a bounded, relative, traversal-free path",
            ),
        }
    }
}

impl Error for InvalidAgentArtifact {}
