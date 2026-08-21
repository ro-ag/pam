use std::{cmp::Ordering, error::Error, fmt, str::FromStr};

use pam_core::ContentDigest;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

pub const MAX_ARTIFACT_NAME_BYTES: usize = 256;
pub const MAX_ARTIFACT_LOGICAL_PATH_BYTES: usize = 4096;
const ARTIFACT_ID_PREFIX: &str = "artifact:sha256:";
const ARTIFACT_ID_HEX_BYTES: usize = 64;
const ARTIFACT_ID_DOMAIN: &[u8] = b"pam-agent-artifact-id-v1";

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

impl ArtifactKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Skill => "skill",
            Self::Plugin => "plugin",
            Self::Agent => "agent",
            Self::Hook => "hook",
            Self::Instruction => "instruction",
            Self::Config => "config",
            Self::Prompt => "prompt",
            Self::Rule => "rule",
            Self::Embedding => "embedding",
            Self::Reranker => "reranker",
            Self::Compressor => "compressor",
            Self::Analyzer => "analyzer",
            Self::WasmComponent => "wasm_component",
        }
    }
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

impl ArtifactScope {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Managed => "managed",
            Self::System => "system",
            Self::User => "user",
            Self::Project => "project",
            Self::Local => "local",
            Self::Plugin => "plugin",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OriginAgent {
    ClaudeCode,
    Codex,
    Cursor,
    Pam,
}

impl OriginAgent {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ClaudeCode => "claude_code",
            Self::Codex => "codex",
            Self::Cursor => "cursor",
            Self::Pam => "pam",
        }
    }
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

impl LoadSemantics {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Always => "always",
            Self::Explicit => "explicit",
            Self::ModelSelected => "model_selected",
            Self::PathConditional => "path_conditional",
            Self::EventTriggered => "event_triggered",
            Self::ConfigurationLayer => "configuration_layer",
            Self::PluginEnabled => "plugin_enabled",
            Self::DisabledOrInstalledOnly => "disabled_or_installed_only",
            Self::Unavailable => "unavailable",
        }
    }
}

macro_rules! impl_from_str {
    ($type:ty, $($variant:ident),+ $(,)?) => {
        impl FromStr for $type {
            type Err = InvalidArtifactEnum;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                $(if value == Self::$variant.as_str() { return Ok(Self::$variant); })+
                Err(InvalidArtifactEnum)
            }
        }
    };
}

impl_from_str!(
    ArtifactKind,
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
);
impl_from_str!(ArtifactScope, Managed, System, User, Project, Local, Plugin);
impl_from_str!(OriginAgent, ClaudeCode, Codex, Cursor, Pam);
impl_from_str!(
    LoadSemantics,
    Always,
    Explicit,
    ModelSelected,
    PathConditional,
    EventTriggered,
    ConfigurationLayer,
    PluginEnabled,
    DisabledOrInstalledOnly,
    Unavailable,
);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidArtifactEnum;

impl fmt::Display for InvalidArtifactEnum {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("unknown normalized artifact enum value")
    }
}

impl Error for InvalidArtifactEnum {}

/// The durable identity of an artifact independent of its content and display metadata.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct AgentArtifactIdentity<'a> {
    pub origin: OriginAgent,
    pub kind: ArtifactKind,
    pub scope: ArtifactScope,
    pub logical_path: &'a str,
}

/// Stable versioned identity used by durable inventory and exact CLI selection.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct AgentArtifactId(String);

impl AgentArtifactId {
    #[must_use]
    pub fn from_identity(identity: AgentArtifactIdentity<'_>) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(ARTIFACT_ID_DOMAIN);
        for field in [
            identity.origin.as_str(),
            identity.kind.as_str(),
            identity.scope.as_str(),
            identity.logical_path,
        ] {
            let bytes = field.as_bytes();
            hasher.update(u64::try_from(bytes.len()).unwrap_or(u64::MAX).to_be_bytes());
            hasher.update(bytes);
        }
        let digest = hasher.finalize();
        let mut value = String::with_capacity(ARTIFACT_ID_PREFIX.len() + ARTIFACT_ID_HEX_BYTES);
        value.push_str(ARTIFACT_ID_PREFIX);
        for byte in digest {
            use fmt::Write as _;
            write!(value, "{byte:02x}").expect("writing to a String cannot fail");
        }
        Self(value)
    }

    /// Parses a canonical stable artifact ID.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidAgentArtifactId`] for another prefix, an invalid length,
    /// or non-lowercase hexadecimal digest text.
    pub fn parse(value: impl Into<String>) -> Result<Self, InvalidAgentArtifactId> {
        let value = value.into();
        let Some(hex) = value.strip_prefix(ARTIFACT_ID_PREFIX) else {
            return Err(InvalidAgentArtifactId);
        };
        if hex.len() != ARTIFACT_ID_HEX_BYTES
            || !hex
                .as_bytes()
                .iter()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        {
            return Err(InvalidAgentArtifactId);
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for AgentArtifactId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl FromStr for AgentArtifactId {
    type Err = InvalidAgentArtifactId;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

impl<'de> Deserialize<'de> for AgentArtifactId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Self::parse(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidAgentArtifactId;

impl fmt::Display for InvalidAgentArtifactId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("artifact ID must be canonical artifact:sha256:<lowercase hex>")
    }
}

impl Error for InvalidAgentArtifactId {}

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

    #[must_use]
    pub fn id(&self) -> AgentArtifactId {
        AgentArtifactId::from_identity(self.identity())
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
