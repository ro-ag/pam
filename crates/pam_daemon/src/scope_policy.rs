//! GUI-owned repository and connector target admission.
//!
//! This authorizes a canonical working directory and explicit remote targets;
//! it does not sandbox a command's filesystem access or trust its output.
//! Missing policy denies work. Grants and caller labels never supply scope.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path, PathBuf};

use pam_connectors::{ArgValue, ConnectorId, descriptor, validate_base_url};
use pam_store::Store;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// One atomic settings value; older installations have no implicit scopes.
pub const SETTING_SCOPE_POLICY: &str = "flows.scope_policy";
/// Recovery for every scope failure; administration stays in the native GUI.
pub const RECOVERY_SCOPE: &str =
    "open Pam → Settings → Flows → approved repositories and connector scopes";
/// Unknown or malformed policy must not become an empty successful policy.
pub const CAUSE_SCOPE_INVALID: &str = "scope_policy_invalid";
/// A valid policy did not authorize this repository or remote target.
pub const CAUSE_SCOPE_DENIED: &str = "scope_denied";
const MAX_POLICY_BYTES: usize = 64 * 1024;
const MAX_REPOSITORIES: usize = 128;
const MAX_TARGETS: usize = 256;
const MAX_TARGET_BYTES: usize = 1024;

/// Versioned settings exchanged only through private administration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScopePolicy {
    /// Currently exactly 1; unknown versions fail closed.
    pub version: u16,
    /// Exact canonical roots, including worktrees registered individually.
    pub repositories: Vec<RepositoryScope>,
}

impl Default for ScopePolicy {
    fn default() -> Self {
        Self {
            version: 1,
            repositories: Vec::new(),
        }
    }
}

/// A GUI-approved repository and its independently approved remote targets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RepositoryScope {
    /// Absolute canonical directory, normalized on save, never retargeted on load.
    pub root: PathBuf,
    /// At most one entry for each configured connector.
    pub connectors: Vec<ConnectorScope>,
}

/// Scope is tied to the configured service URL, not just the product name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectorScope {
    /// Product adapter ID.
    pub connector: ConnectorId,
    /// Normalized service root that the GUI approved.
    pub base_url: String,
    /// Exact targets or an explicit broad approval.
    pub access: ScopeAccess,
    /// Product-specific identifiers; never patterns or query expressions.
    pub targets: Vec<String>,
}

/// Broad searches require the GUI to choose connector-wide access explicitly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScopeAccess {
    /// Only the listed identifiers may be read.
    Targets,
    /// Every read supported by this configured connector is in scope.
    ConnectorWide,
}

/// Scope failures are returned before subprocess, credential or network access.
#[derive(Debug, Error)]
pub enum ScopeError {
    /// Invalid persisted data or GUI input.
    #[error("invalid scope policy: {0}")]
    Invalid(String),
    /// No explicit matching scope.
    #[error("scope denied: {0}")]
    Denied(String),
    /// A storage failure is never interpreted as permission.
    #[error("scope policy storage failed: {0}")]
    Store(#[from] pam_store::StoreError),
}

impl ScopeError {
    /// Stable caller-facing refusal code.
    #[must_use]
    pub fn cause(&self) -> &'static str {
        match self {
            Self::Denied(_) => CAUSE_SCOPE_DENIED,
            Self::Invalid(_) | Self::Store(_) => CAUSE_SCOPE_INVALID,
        }
    }
}

impl ScopePolicy {
    /// Read the current policy on every admission/attempt so revocation applies.
    pub async fn load(store: &Store) -> Result<Self, ScopeError> {
        let Some(raw) = store.get_setting(SETTING_SCOPE_POLICY).await? else {
            return Ok(Self::default());
        };
        if raw.len() > MAX_POLICY_BYTES {
            return Err(invalid("scope policy exceeds 64 KiB"));
        }
        let policy: Self = serde_json::from_str(&raw)
            .map_err(|_| invalid("scope policy is not valid versioned JSON"))?;
        policy.validate()?;
        Ok(policy)
    }

    /// Normalize GUI input before the atomic settings write. Paths must exist.
    pub fn normalize(mut self) -> Result<Self, ScopeError> {
        self.validate()?;
        for repository in &mut self.repositories {
            repository.root = canonical_repo(&repository.root)?;
            for connector in &mut repository.connectors {
                connector.base_url = normalized_url(connector.connector, &connector.base_url)?;
            }
        }
        self.validate()?;
        Ok(self)
    }

    /// Save one complete policy. There is no fallback to grants or old defaults.
    pub async fn save(&self, store: &Store) -> Result<(), ScopeError> {
        self.validate()?;
        let raw =
            serde_json::to_string(self).map_err(|_| invalid("scope policy could not serialize"))?;
        if raw.len() > MAX_POLICY_BYTES {
            return Err(invalid("scope policy exceeds 64 KiB"));
        }
        store.set_setting(SETTING_SCOPE_POLICY, &raw).await?;
        Ok(())
    }

    fn validate(&self) -> Result<(), ScopeError> {
        if self.version != 1 || self.repositories.len() > MAX_REPOSITORIES {
            return Err(invalid("version must be 1 with at most 128 repositories"));
        }
        let mut roots = BTreeSet::new();
        for repository in &self.repositories {
            if !repository.root.is_absolute()
                || repository
                    .root
                    .components()
                    .any(|part| matches!(part, Component::ParentDir | Component::CurDir))
                || !roots.insert(&repository.root)
                || repository.connectors.len() > ConnectorId::ALL.len()
            {
                return Err(invalid(
                    "repository roots must be unique absolute paths without parent traversal",
                ));
            }
            let mut connectors = BTreeSet::new();
            for connector in &repository.connectors {
                if !connectors.insert(connector.connector) {
                    return Err(invalid(
                        "each repository may configure a connector only once",
                    ));
                }
                normalized_url(connector.connector, &connector.base_url)?;
                connector.validate_targets()?;
            }
        }
        Ok(())
    }

    /// Canonicalize the caller-selected directory and require an exact root.
    pub fn authorize_repo(&self, path: &Path) -> Result<PathBuf, ScopeError> {
        let canonical = canonical_repo(path)?;
        self.repository(&canonical)?;
        Ok(canonical)
    }

    fn repository(&self, canonical: &Path) -> Result<&RepositoryScope, ScopeError> {
        self.repositories
            .iter()
            .find(|entry| entry.root == canonical)
            .ok_or_else(|| denied("repository is not explicitly approved"))
    }

    /// Check a remote read using validated adapter arguments and configured URL.
    pub fn authorize_connector(
        &self,
        repo: &Path,
        connector: ConnectorId,
        base_url: &str,
        call: &str,
        args: &BTreeMap<String, ArgValue>,
    ) -> Result<(), ScopeError> {
        let canonical = self.authorize_repo(repo)?;
        let scope = self
            .repository(&canonical)?
            .connectors
            .iter()
            .find(|scope| scope.connector == connector)
            .ok_or_else(|| denied("connector is not approved for this repository"))?;
        if normalized_url(connector, &scope.base_url)? != normalized_url(connector, base_url)? {
            return Err(denied(
                "configured connector URL changed; approve its scope again",
            ));
        }
        if !descriptor(connector)
            .calls
            .iter()
            .any(|entry| entry.name == call)
        {
            return Err(denied("connector operation is not registered"));
        }
        if scope.access == ScopeAccess::ConnectorWide {
            return Ok(());
        }
        let target = call_target(connector, call, args).ok_or_else(|| {
            denied("this read has no approved target mapping; connector-wide approval is required")
        })?;
        if !scope.targets.iter().any(|approved| approved == target) {
            return Err(denied(
                "connector target is not approved for this repository",
            ));
        }
        Ok(())
    }
}

impl ConnectorScope {
    fn validate_targets(&self) -> Result<(), ScopeError> {
        if self.targets.len() > MAX_TARGETS
            || (self.access == ScopeAccess::ConnectorWide && !self.targets.is_empty())
            || (self.access == ScopeAccess::Targets && self.targets.is_empty())
        {
            return Err(invalid(
                "target access needs 1..=256 targets; connector-wide access needs an empty target list",
            ));
        }
        let mut seen = BTreeSet::new();
        for target in &self.targets {
            if !valid_target(self.connector, target) || !seen.insert(target) {
                return Err(invalid(
                    "connector targets must be unique explicit product identifiers",
                ));
            }
        }
        Ok(())
    }
}

fn canonical_repo(path: &Path) -> Result<PathBuf, ScopeError> {
    if !path.is_absolute() {
        return Err(denied("repository must be an absolute directory path"));
    }
    let canonical = path
        .canonicalize()
        .map_err(|_| denied("repository cannot be resolved"))?;
    if !canonical.is_dir() {
        return Err(denied("repository is not a directory"));
    }
    Ok(canonical)
}

fn normalized_url(connector: ConnectorId, raw: &str) -> Result<String, ScopeError> {
    validate_base_url(connector, raw)
        .map(|url| url.to_string())
        .map_err(|_| invalid("connector scope requires a valid service base URL"))
}

fn call_target<'a>(
    connector: ConnectorId,
    call: &str,
    args: &'a BTreeMap<String, ArgValue>,
) -> Option<&'a str> {
    let name = match (connector, call) {
        (ConnectorId::Github, "runs" | "run" | "job_log") => "repo",
        (ConnectorId::Jenkins, "builds" | "console" | "investigate" | "node_evidence") => "job",
        (ConnectorId::Sonarqube, "quality_gate" | "issues" | "analysis") => "project",
        (ConnectorId::Jira, "issue") => "key",
        (ConnectorId::Confluence, "page") => "id",
        (ConnectorId::Sharepoint, "document" | "documents" | "lists") => "site",
        _ => return None,
    };
    let ArgValue::Text(raw) = args.get(name)? else {
        return None;
    };
    let target = if connector == ConnectorId::Jira {
        let (project, number) = raw.rsplit_once('-')?;
        if number.is_empty() || !number.bytes().all(|byte| byte.is_ascii_digit()) {
            return None;
        }
        project
    } else {
        raw.as_str()
    };
    valid_target(connector, target).then_some(target)
}

fn valid_target(connector: ConnectorId, value: &str) -> bool {
    if value.is_empty() || value.len() > MAX_TARGET_BYTES || value.chars().any(char::is_whitespace)
    {
        return false;
    }
    let identifier = |part: &str| {
        !part.is_empty()
            && part != "."
            && part != ".."
            && part
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    };
    match connector {
        ConnectorId::Github => value.split('/').count() == 2 && value.split('/').all(identifier),
        ConnectorId::Jenkins => value.split('/').all(identifier),
        ConnectorId::Sonarqube => value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':')),
        ConnectorId::Jira => value
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_'),
        ConnectorId::Confluence => value.bytes().all(|byte| byte.is_ascii_digit()),
        ConnectorId::Sharepoint => value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b',' | b'-' | b'_')),
        ConnectorId::Aws => false,
    }
}

fn invalid(detail: &str) -> ScopeError {
    ScopeError::Invalid(detail.to_owned())
}
fn denied(detail: &str) -> ScopeError {
    ScopeError::Denied(detail.to_owned())
}
