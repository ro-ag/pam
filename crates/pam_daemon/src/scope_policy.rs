//! GUI-owned repository and connector target admission.
//!
//! This authorizes a canonical working directory and explicit remote targets;
//! it does not sandbox a command's filesystem access or trust its output.
//! Missing policy denies work. Grants and caller labels never supply scope.
//!
//! Every consumer reads the *effective* scopes, [`ScopePolicy::load_effective`]:
//! the human's stored document narrowed by the managed policy (see
//! [`crate::managed_policy`]). A stored entry the policy forbids is dropped
//! from the effective scopes and reported ([`ScopePolicy::dropped`]), never
//! deleted: the store keeps what the human saved, and removing the policy
//! restores it. Only `load_user` reads the stored document as saved; it is
//! crate-private and named only here and by the admin edit path
//! (`admin_flows.rs`), which a source test holds.
//!
//! What the policy narrows, in order:
//! - `scopes.allowed_repository_roots`: a repository whose canonical root is
//!   not under an allowed prefix (compared by path component) is dropped.
//! - `connectors.disabled`: a connector scope for a disabled connector is
//!   dropped.
//! - `connectors.allowed_base_hosts`: a connector scope whose service URL's
//!   host matches no rule is dropped.
//! - `scopes.connector_wide: deny`: connector-wide access becomes target
//!   access with the targets it lists, and a connector-wide scope lists none,
//!   so the scope is dropped.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path, PathBuf};

use pam_connectors::{ArgValue, ConnectorId, descriptor, validate_base_url};
use pam_store::Store;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::managed_policy::{
    CAUSE_POLICY_NOT_ALLOWED, EffectiveEntry, Key, LeafStatus, Mode, PathRule, PolicyView,
    WriteRefusal,
};
use crate::network_service::Source;

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
    /// What the managed policy removed from the stored document to make
    /// this effective one; empty for the document as saved. Never
    /// serialized: the reply carries it as `scope_policy_dropped`.
    #[serde(skip)]
    pub(crate) dropped: Vec<ScopeDrop>,
}

impl Default for ScopePolicy {
    fn default() -> Self {
        Self {
            version: 1,
            repositories: Vec::new(),
            dropped: Vec::new(),
        }
    }
}

/// One stored scope entry the managed policy forbids: reported, never used,
/// never deleted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopeDrop {
    /// The repository root as stored.
    pub root: PathBuf,
    /// The connector scope that was dropped; `None` when the whole
    /// repository was.
    pub connector: Option<ConnectorId>,
    /// The policy key that forbids it.
    pub key: Key,
    /// The sentence the GUI shows.
    pub reason: String,
}

impl ScopeDrop {
    /// The wire shape of one `scope_policy_dropped` entry.
    #[must_use]
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "root": self.root,
            "connector": self.connector.map(ConnectorId::as_str),
            "key": self.key.path(),
            "reason": self.reason,
        })
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
    /// The effective scopes: the stored document narrowed by `view` (see
    /// the module docs). Read on every admission and attempt, with the
    /// view the caller's service holds, so a revocation or a tightened
    /// policy applies to the next check.
    ///
    /// # Errors
    ///
    /// [`CAUSE_SCOPE_INVALID`] for a stored document that is not a valid
    /// policy, and a storage failure; neither is ever read as permission.
    pub async fn load_effective(store: &Store, view: &PolicyView) -> Result<Self, ScopeError> {
        Ok(Self::load_user(store).await?.managed(view))
    }

    /// The document exactly as the human saved it, with no policy applied.
    /// Only the admin edit path (`admin_flows.rs`) and this module may read
    /// it: every consumer reads [`Self::load_effective`].
    pub(crate) async fn load_user(store: &Store) -> Result<Self, ScopeError> {
        let Some(raw) = store.get_setting(SETTING_SCOPE_POLICY).await? else {
            return Ok(Self::default());
        };
        if raw.len() > MAX_POLICY_BYTES {
            return Err(invalid("scope policy exceeds 64 KiB"));
        }
        let mut value: serde_json::Value = serde_json::from_str(&raw)
            .map_err(|_| invalid("scope policy is not valid versioned JSON"))?;
        drop_removed_connector_scopes(&mut value);
        let policy: Self = serde_json::from_value(value)
            .map_err(|_| invalid("scope policy is not valid versioned JSON"))?;
        policy.validate()?;
        Ok(policy)
    }

    /// This document narrowed by `view`: every entry the policy forbids is
    /// removed and recorded in [`Self::dropped`]. Pure: the stored roots
    /// are already canonical (normalized on save) and the policy's prefixes
    /// are compared as written, by path component, so a symlinked prefix
    /// never widens anything.
    #[must_use]
    pub fn managed(mut self, view: &PolicyView) -> Self {
        let mut dropped = Vec::new();
        self.repositories.retain_mut(|repository| {
            if !view.repository_root_allowed(&repository.root) {
                dropped.push(ScopeDrop {
                    root: repository.root.clone(),
                    connector: None,
                    key: Key::ScopesAllowedRepositoryRoots,
                    reason: "this repository is outside the repository roots your \
                             organisation's policy allows"
                        .to_owned(),
                });
                return false;
            }
            repository
                .connectors
                .retain(|scope| match connector_forbidden(view, scope) {
                    None => true,
                    Some((key, reason)) => {
                        dropped.push(ScopeDrop {
                            root: repository.root.clone(),
                            connector: Some(scope.connector),
                            key,
                            reason: reason.to_owned(),
                        });
                        false
                    }
                });
            true
        });
        self.dropped = dropped;
        self
    }

    /// The stored entries the managed policy removed from this effective
    /// document (empty for one that was not narrowed).
    #[must_use]
    pub fn dropped(&self) -> &[ScopeDrop] {
        &self.dropped
    }

    /// Whether the human may save this (normalized) document under `view`.
    /// `current` is the document saved now, when it reads: a write that only
    /// narrows it passes a held key, as tightening always may.
    ///
    /// # Errors
    ///
    /// [`crate::managed_policy::CAUSE_POLICY_FROZEN`] when a scope key is
    /// held and the write is not a narrowing, and
    /// [`CAUSE_POLICY_NOT_ALLOWED`] for a repository outside the allowed
    /// roots, a connector-wide scope the policy denies, or a connector
    /// service whose host is not allowed. A disabled connector's scope is
    /// not refused: it is saved and reported as dropped.
    pub fn check_write(
        &self,
        view: &PolicyView,
        current: Option<&Self>,
    ) -> Result<(), WriteRefusal> {
        if !current.is_some_and(|current| self.narrows(current)) {
            for key in [
                Key::ScopesAllowedRepositoryRoots,
                Key::ScopesConnectorWide,
                Key::ConnectorsAllowedBaseHosts,
            ] {
                view.guard_held(key)?;
            }
        }
        for repository in &self.repositories {
            let root = repository.root.display();
            if !view.repository_root_allowed(&repository.root) {
                return Err(view.refusal(
                    Key::ScopesAllowedRepositoryRoots,
                    CAUSE_POLICY_NOT_ALLOWED,
                    &format!(
                        "repository {root} is outside the repository roots your organisation \
                         allows"
                    ),
                ));
            }
            for scope in &repository.connectors {
                let connector = scope.connector.as_str();
                if scope.access == ScopeAccess::ConnectorWide && view.connector_wide_denied() {
                    return Err(view.refusal(
                        Key::ScopesConnectorWide,
                        CAUSE_POLICY_NOT_ALLOWED,
                        &format!(
                            "connector-wide access for {connector} in {root} is not allowed; \
                             approve explicit targets instead"
                        ),
                    ));
                }
                if !base_url_allowed(view, &scope.base_url) {
                    return Err(view.refusal(
                        Key::ConnectorsAllowedBaseHosts,
                        CAUSE_POLICY_NOT_ALLOWED,
                        &format!(
                            "the {connector} service {} for {root} is not a host your \
                             organisation allows",
                            scope.base_url
                        ),
                    ));
                }
            }
        }
        Ok(())
    }

    /// Whether every entry of `self` is already in `current`, no broader:
    /// the same repository roots, the same connector services, and target
    /// lists that are subsets (or connector-wide where it already was).
    fn narrows(&self, current: &Self) -> bool {
        self.repositories.iter().all(|repository| {
            current
                .repositories
                .iter()
                .find(|earlier| earlier.root == repository.root)
                .is_some_and(|earlier| {
                    repository.connectors.iter().all(|scope| {
                        earlier.connectors.iter().any(|before| {
                            before.connector == scope.connector
                                && before.base_url == scope.base_url
                                && match (scope.access, before.access) {
                                    (_, ScopeAccess::ConnectorWide) => true,
                                    (ScopeAccess::ConnectorWide, ScopeAccess::Targets) => false,
                                    (ScopeAccess::Targets, ScopeAccess::Targets) => scope
                                        .targets
                                        .iter()
                                        .all(|target| before.targets.contains(target)),
                                }
                        })
                    })
                })
        })
    }

    /// [`Self::normalize`] off the async threads: every repository root is
    /// canonicalized, one filesystem round trip per root, on the
    /// repository-identity lane.
    pub async fn normalize_blocking(self) -> Result<Self, ScopeError> {
        crate::blocking_jobs::run(crate::blocking_jobs::Kind::RepositoryIdentity, move || {
            self.normalize()
        })
        .await
        .map_err(identity_unavailable)?
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

    /// [`Self::authorize_repo`] with the canonicalization (a filesystem
    /// round trip) on the repository-identity lane rather than the async
    /// thread that called; for the per-request paths.
    pub async fn authorize_repo_blocking(&self, path: &Path) -> Result<PathBuf, ScopeError> {
        let canonical = canonical_repo_blocking(path.to_path_buf()).await?;
        self.repository(&canonical)?;
        Ok(canonical)
    }

    fn repository(&self, canonical: &Path) -> Result<&RepositoryScope, ScopeError> {
        self.repositories
            .iter()
            .find(|entry| entry.root == canonical)
            .ok_or_else(|| match self.drop_for(canonical, None) {
                Some(entry) => policy_denied(entry),
                None => denied("repository is not explicitly approved"),
            })
    }

    /// The recorded drop of `root` (the whole repository, or `connector`'s
    /// scope in it).
    fn drop_for(&self, root: &Path, connector: Option<ConnectorId>) -> Option<&ScopeDrop> {
        self.dropped.iter().find(|entry| {
            entry.root == root && (entry.connector.is_none() || entry.connector == connector)
        })
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
        self.authorize_connector_at(&canonical, connector, base_url, call, args)
    }

    /// [`Self::authorize_connector`] for a root [`Self::authorize_repo`] (or
    /// its blocking twin) already canonicalized and approved, so the caller
    /// does not pay the filesystem round trip twice.
    pub fn authorize_connector_at(
        &self,
        canonical: &Path,
        connector: ConnectorId,
        base_url: &str,
        call: &str,
        args: &BTreeMap<String, ArgValue>,
    ) -> Result<(), ScopeError> {
        let scope = self
            .repository(canonical)?
            .connectors
            .iter()
            .find(|scope| scope.connector == connector)
            .ok_or_else(|| match self.drop_for(canonical, Some(connector)) {
                Some(entry) => policy_denied(entry),
                None => denied("connector is not approved for this repository"),
            })?;
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

/// [`canonical_repo`] on the repository-identity lane.
async fn canonical_repo_blocking(path: PathBuf) -> Result<PathBuf, ScopeError> {
    crate::blocking_jobs::run(crate::blocking_jobs::Kind::RepositoryIdentity, move || {
        canonical_repo(&path)
    })
    .await
    .map_err(identity_unavailable)?
}

/// The lane could not run the identity check at all: not a scope decision,
/// so it fails closed as an invalid (unanswerable) policy question.
fn identity_unavailable(error: crate::blocking_jobs::Error) -> ScopeError {
    invalid(&format!("repository identity check did not run: {error}"))
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
        (ConnectorId::Github, "runs" | "run" | "run_status" | "job_log") => "repo",
        (
            ConnectorId::Jenkins,
            "builds" | "console" | "investigate" | "build_status" | "node_evidence",
        ) => "job",
        (ConnectorId::Sonarqube, "quality_gate" | "issues" | "analysis" | "ce_status") => "project",
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
    }
}

/// Removes approvals for the connector that no longer exists.
///
/// A policy saved before the AWS adapter was removed can still carry an `aws`
/// approval. Treating it as malformed would lock every other approval out, so
/// it is dropped on read: removing an approval only narrows what is allowed,
/// never widens it. The stored value is left alone until the next save writes
/// the cleaned policy back.
fn drop_removed_connector_scopes(policy: &mut serde_json::Value) {
    let Some(repositories) = policy
        .get_mut("repositories")
        .and_then(serde_json::Value::as_array_mut)
    else {
        return;
    };
    for repository in repositories {
        let Some(connectors) = repository
            .get_mut("connectors")
            .and_then(serde_json::Value::as_array_mut)
        else {
            continue;
        };
        let before = connectors.len();
        connectors.retain(|scope| {
            scope.get("connector").and_then(serde_json::Value::as_str) != Some("aws")
        });
        if connectors.len() != before {
            tracing::warn!(
                connector = "aws",
                recovery = "the AWS CLI adapter was removed; its stored scope approval is ignored and disappears on the next save of the approved-repositories settings",
                "ignoring the scope approval of a removed connector"
            );
        }
    }
}

/// The keys that narrow the scope document, in the order their
/// constraints are reported.
pub const SCOPE_KEYS: [Key; 4] = [
    Key::ScopesAllowedRepositoryRoots,
    Key::ScopesConnectorWide,
    Key::ConnectorsAllowedBaseHosts,
    Key::ConnectorsDisabled,
];

/// The `effective` entry of a field a set of plain policy constraints
/// (`keys`) narrows: `source` is `policy` when the constraints removed
/// something (`clamped`), `locked` when one of the keys is held (its writes
/// refuse `policy_frozen`), `mode` is `forbid` and `constraint` carries
/// each in-force key's value under its path. With none of `keys` in the
/// document it is exactly `{ source: user, locked: false }`.
#[must_use]
pub fn constraint_entry(
    view: &PolicyView,
    keys: &[Key],
    constraint: &serde_json::Map<String, serde_json::Value>,
    clamped: bool,
) -> EffectiveEntry {
    let statuses: Vec<&LeafStatus> = keys.iter().filter_map(|key| view.status(*key)).collect();
    if statuses.is_empty() {
        return EffectiveEntry::unmanaged(Source::User);
    }
    let held = statuses
        .iter()
        .any(|status| matches!(status, LeafStatus::Held { .. }));
    let state = if held {
        "held"
    } else if statuses.iter().any(|status| !status.in_force()) {
        "rejected"
    } else {
        "applied"
    };
    EffectiveEntry {
        source: if clamped {
            Source::Policy
        } else {
            Source::User
        },
        locked: held,
        mode: Some(Mode::Forbid),
        constraint: (!constraint.is_empty()).then(|| serde_json::Value::Object(constraint.clone())),
        reason: None,
        state: Some(state),
        clamped,
    }
}

/// The scope keys' constraints in force, each under its key path.
#[must_use]
pub fn scope_constraints(view: &PolicyView) -> serde_json::Map<String, serde_json::Value> {
    let in_force = |key: Key| view.status(key).is_some_and(LeafStatus::in_force);
    let policy = view.policy();
    let mut constraint = serde_json::Map::new();
    if let Some(roots) = policy
        .allowed_repository_roots
        .as_ref()
        .filter(|_| in_force(Key::ScopesAllowedRepositoryRoots))
    {
        constraint.insert(
            Key::ScopesAllowedRepositoryRoots.path().to_owned(),
            serde_json::json!(roots.iter().map(PathRule::as_str).collect::<Vec<_>>()),
        );
    }
    if view.connector_wide_denied() {
        constraint.insert(
            Key::ScopesConnectorWide.path().to_owned(),
            serde_json::json!("deny"),
        );
    }
    if let Some(hosts) = policy
        .allowed_base_hosts
        .as_ref()
        .filter(|_| in_force(Key::ConnectorsAllowedBaseHosts))
    {
        constraint.insert(
            Key::ConnectorsAllowedBaseHosts.path().to_owned(),
            serde_json::json!(hosts.entries),
        );
    }
    if let Some(disabled) = policy
        .disabled_connectors
        .as_ref()
        .filter(|_| in_force(Key::ConnectorsDisabled))
    {
        constraint.insert(
            Key::ConnectorsDisabled.path().to_owned(),
            serde_json::json!(
                disabled
                    .iter()
                    .map(|connector| connector.as_str())
                    .collect::<Vec<_>>()
            ),
        );
    }
    constraint
}

impl ScopePolicy {
    /// The `effective` entry of the `scope_policy` field: this (effective)
    /// document as its `value`, under [`constraint_entry`] over
    /// [`SCOPE_KEYS`].
    #[must_use]
    pub fn effective_json(&self, view: &PolicyView) -> serde_json::Value {
        let entry = constraint_entry(
            view,
            &SCOPE_KEYS,
            &scope_constraints(view),
            !self.dropped.is_empty(),
        );
        let mut item = entry.to_json();
        item["value"] = serde_json::json!(self);
        item
    }

    /// The `scope_policy_dropped` list of a settings reply.
    #[must_use]
    pub fn dropped_json(&self) -> serde_json::Value {
        serde_json::Value::Array(self.dropped.iter().map(ScopeDrop::to_json).collect())
    }
}

/// Why the managed policy forbids `scope`, if it does: the key and the
/// sentence a [`ScopeDrop`] records.
fn connector_forbidden(view: &PolicyView, scope: &ConnectorScope) -> Option<(Key, &'static str)> {
    if view.connector_disabled(scope.connector) {
        return Some((
            Key::ConnectorsDisabled,
            "your organisation's policy disables this connector",
        ));
    }
    if !base_url_allowed(view, &scope.base_url) {
        return Some((
            Key::ConnectorsAllowedBaseHosts,
            "this connector's service is not on a host your organisation's policy allows",
        ));
    }
    if scope.access == ScopeAccess::ConnectorWide && view.connector_wide_denied() {
        return Some((
            Key::ScopesConnectorWide,
            "your organisation's policy does not allow connector-wide access; approve \
             explicit targets",
        ));
    }
    None
}

/// Whether the policy allows a stored service URL's host. A URL that does
/// not parse matches no host rule, so it passes only while no rule is in
/// force (the stored document was validated when it was saved).
fn base_url_allowed(view: &PolicyView, base_url: &str) -> bool {
    match pam_net::Url::parse(base_url) {
        Ok(url) => view.base_url_allowed(&url),
        Err(_) => !view
            .status(Key::ConnectorsAllowedBaseHosts)
            .is_some_and(LeafStatus::in_force),
    }
}

/// A denial that names the policy: the human cannot fix it in Settings.
fn policy_denied(entry: &ScopeDrop) -> ScopeError {
    ScopeError::Denied(format!(
        "{} ({}); managed by your organisation's policy, ask your administrator",
        entry.reason, entry.key
    ))
}

fn invalid(detail: &str) -> ScopeError {
    ScopeError::Invalid(detail.to_owned())
}
fn denied(detail: &str) -> ScopeError {
    ScopeError::Denied(detail.to_owned())
}
