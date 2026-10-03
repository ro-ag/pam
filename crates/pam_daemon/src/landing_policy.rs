//! GUI-owned landing recipes and exact mutation targets. Missing policy grants nothing.
//!
//! Consumers read the *effective* document, `Snapshot::load_effective`: the
//! human's recipes under the managed policy (see `crate::managed_policy`).
//! `landing.max_permissions` caps every repository's permissions (a `false` turns
//! the human's `true` off) and
//! `landing.allowed_github_servers` drops a repository whose GitHub server is
//! not on an allowed host (reported, never deleted). The revision stays the
//! hash of the stored document, so the compare-and-swap of a save and the
//! revision a landing session froze are unchanged by a policy; the policy is
//! re-applied at every check instead. `Snapshot::load` reads the stored
//! document as saved, for the admin edit path and the workspace sweep.
use pam_store::Store;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
};

use crate::managed_policy::{
    CAUSE_POLICY_DENIED, CAUSE_POLICY_NOT_ALLOWED, Key, LandingCeiling, LeafStatus, PolicyView,
    WriteRefusal,
};

const KEY: &str = "flows.landing_policy";
const MAX_BYTES: usize = 32_768;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Check {
    pub name: String,
    pub argv: Vec<String>,
    pub timeout_seconds: u16,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)] // Independent GUI grants; no mutually exclusive states.
pub(crate) struct Permissions {
    pub push: bool,
    pub create_pr: bool,
    pub merge: bool,
    pub sync: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(clippy::struct_field_names)] // Serialized names distinguish source and provider identities.
pub(crate) struct Repository {
    pub root: PathBuf,
    pub repository: String,
    pub github_server: String,
    pub github_repository: String,
    pub base: String,
    pub branches: Vec<String>,
    pub workspace_root: PathBuf,
    #[serde(default)]
    pub read_cache_roots: Vec<PathBuf>,
    pub checks: Vec<Check>,
    pub required_checks: Vec<String>,
    pub main_checks: Vec<String>,
    pub permissions: Permissions,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Document {
    version: u8,
    repositories: Vec<Repository>,
}

#[derive(Debug, thiserror::Error)]
#[error("{detail}")]
pub(crate) struct Error {
    pub cause: &'static str,
    pub detail: &'static str,
}

fn invalid() -> Error {
    Error {
        cause: "landing_policy_invalid",
        detail: "Landing requires a bounded GUI policy with exact repositories, branches, checks and private workspace directories.",
    }
}
fn storage(_: pam_store::StoreError) -> Error {
    Error {
        cause: "landing_policy_storage",
        detail: "The landing policy could not be read or saved.",
    }
}
fn conflict() -> Error {
    Error {
        cause: "landing_policy_changed",
        detail: "Landing policy changed; reload it before saving or executing another operation.",
    }
}

#[allow(clippy::case_sensitive_file_extension_comparisons)] // Literal Git ref grammar.
pub(crate) fn valid_ref(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 200
        && !value.starts_with(['-', '/'])
        && !value.ends_with(['/', '.'])
        && !value.contains(['\\', '~', '^', ':', '?', '*', '['])
        && !value.contains("..")
        && !value.contains("@{")
        && value != "@"
        && !value
            .chars()
            .any(|ch| ch.is_whitespace() || ch.is_control())
        && value
            .split('/')
            .all(|part| !part.is_empty() && !part.starts_with('.') && !part.ends_with(".lock"))
}

fn names(values: &[String], maximum: usize) -> bool {
    !values.is_empty()
        && values.len() <= maximum
        && values.iter().all(|value| {
            !value.is_empty()
                && value.len() <= 200
                && value.trim() == value
                && !value.chars().any(char::is_control)
        })
        && values.iter().collect::<BTreeSet<_>>().len() == values.len()
}

fn directory(path: &Path) -> Result<(), Error> {
    if !path.is_absolute() || !path.is_dir() || path.canonicalize().map_err(|_| invalid())? != path
    {
        return Err(invalid());
    }
    Ok(())
}

impl Repository {
    fn validate(&self) -> Result<(), Error> {
        directory(&self.root)?;
        directory(&self.workspace_root)?;
        if self.read_cache_roots.len() > 8 {
            return Err(invalid());
        }
        for cache in &self.read_cache_roots {
            directory(cache)?;
            if cache.starts_with(&self.workspace_root)
                || self.workspace_root.starts_with(cache)
                || self.root.starts_with(cache)
                || cache
                    .components()
                    .any(|part| part.as_os_str() == "Keychains" || part.as_os_str() == ".git")
            {
                return Err(invalid());
            }
        }
        if self.root.starts_with(&self.workspace_root)
            || self.workspace_root.starts_with(&self.root)
            || pam_flow::canonical_repository_url(&self.repository).map_err(|_| invalid())?
                != self.repository
            || pam_connectors::validate_base_url(pam_flow::ConnectorId::Github, &self.github_server)
                .map_err(|_| invalid())?
                .as_str()
                != self.github_server
            || !valid_ref(&self.base)
            || !names(&self.branches, 32)
            || self
                .branches
                .iter()
                .any(|branch| !valid_ref(branch) || branch == &self.base)
            || !names(&self.required_checks, 32)
            || !names(&self.main_checks, 32)
            || self.checks.is_empty()
            || self.checks.len() > 8
        {
            return Err(invalid());
        }
        let parts: Vec<_> = self.github_repository.split('/').collect();
        if parts.len() != 2
            || parts.iter().any(|part| {
                part.is_empty()
                    || part.len() > 100
                    || !part.bytes().all(|byte| {
                        byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.')
                    })
                    || matches!(*part, "." | "..")
            })
        {
            return Err(invalid());
        }
        let check_names: Vec<_> = self.checks.iter().map(|check| check.name.clone()).collect();
        if !names(&check_names, 8) {
            return Err(invalid());
        }
        for check in &self.checks {
            if !(1..=600).contains(&check.timeout_seconds)
                || check.argv.is_empty()
                || check.argv.len() > 64
                || check
                    .argv
                    .iter()
                    .any(|arg| arg.len() > 2048 || arg.contains('\0'))
                || check.argv[0].is_empty()
                || !check.argv[0]
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
            {
                return Err(invalid());
            }
        }
        Ok(())
    }

    pub fn authorize_workspace(&self, protected_base: &Path) -> Result<(), Error> {
        self.validate()?;
        let protected = protected_base.canonicalize().map_err(|_| invalid())?;
        if self
            .read_cache_roots
            .iter()
            .any(|cache| protected.starts_with(cache) || cache.starts_with(&protected))
        {
            return Err(invalid());
        }
        if self.workspace_root.starts_with(&protected)
            || protected.starts_with(&self.workspace_root)
        {
            return Err(invalid());
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let metadata = std::fs::metadata(&self.workspace_root).map_err(|_| invalid())?;
            let private = std::fs::metadata(&protected).map_err(|_| invalid())?;
            if metadata.uid() != private.uid() || metadata.mode() & 0o077 != 0 {
                return Err(invalid());
            }
        }
        #[cfg(not(unix))]
        return Err(Error {
            cause: "landing_workspace_unsupported",
            detail: "Landing workspace isolation is not qualified on this platform.",
        });
        #[cfg(unix)]
        Ok(())
    }
}

#[derive(Clone)]
pub(crate) struct Snapshot {
    document: Document,
    canonical: String,
    pub revision: String,
    raw: Option<String>,
    /// The ceiling that capped the permissions; all `true` for the stored
    /// document.
    ceiling: LandingCeiling,
    /// What the managed policy removed; empty for the stored document.
    dropped: Vec<Dropped>,
}

/// One stored landing recipe the managed policy forbids.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Dropped {
    pub root: PathBuf,
    pub key: Key,
    pub reason: &'static str,
}

/// Why a landing save was refused.
#[derive(Debug)]
pub(crate) enum SaveRefusal {
    /// The document itself (shape, workspace, revision).
    Landing(Error),
    /// The managed policy forbids it.
    Managed(WriteRefusal),
}

impl SaveRefusal {
    /// The stable cause.
    #[cfg(test)]
    pub fn cause(&self) -> &'static str {
        match self {
            Self::Landing(error) => error.cause,
            Self::Managed(refusal) => refusal.cause,
        }
    }
}

impl From<Error> for SaveRefusal {
    fn from(error: Error) -> Self {
        Self::Landing(error)
    }
}

/// The detail of a repository the policy dropped.
const DROPPED_DETAIL: &str = "Your organization's policy does not allow landing to this \
     repository's GitHub server (landing.allowed_github_servers); ask your administrator.";

/// Whether `permissions` asks for something `ceiling` caps off; the first
/// such permission's name.
fn above_ceiling(permissions: &Permissions, ceiling: LandingCeiling) -> Option<&'static str> {
    [
        ("push", permissions.push, ceiling.push),
        ("create_pr", permissions.create_pr, ceiling.create_pr),
        ("merge", permissions.merge, ceiling.merge),
        ("sync", permissions.sync, ceiling.sync),
    ]
    .into_iter()
    .find(|(_, wanted, allowed)| *wanted && !*allowed)
    .map(|(name, ..)| name)
}

/// Whether the policy allows a recipe's GitHub server. A server URL that
/// does not parse passes only while no host rule is in force (it was
/// validated when the document was saved).
fn server_allowed(view: &PolicyView, server: &str) -> bool {
    match pam_net::Url::parse(server) {
        Ok(url) => view.github_server_allowed(&url),
        Err(_) => !view
            .status(Key::LandingAllowedGithubServers)
            .is_some_and(LeafStatus::in_force),
    }
}

impl Snapshot {
    fn normalize(document: Document, raw: Option<String>) -> Result<Self, Error> {
        if document.version != 1 || document.repositories.len() > 32 {
            return Err(invalid());
        }
        let mut roots = BTreeSet::new();
        for repo in &document.repositories {
            repo.validate()?;
            if !roots.insert(&repo.root)
                || document.repositories.iter().any(|other| {
                    other.root.starts_with(&repo.workspace_root)
                        || repo.workspace_root.starts_with(&other.root)
                })
            {
                return Err(invalid());
            }
        }
        let canonical = serde_json::to_string(&document).map_err(|_| invalid())?;
        if canonical.len() > MAX_BYTES {
            return Err(invalid());
        }
        let revision = pam_compact::sha256_hex(canonical.as_bytes());
        Ok(Self {
            document,
            canonical,
            revision,
            raw,
            ceiling: LandingCeiling::default(),
            dropped: Vec::new(),
        })
    }

    /// The effective document: the stored one under `view` (see the module
    /// docs). Every landing check reads this one.
    pub async fn load_effective(store: &Store, view: &PolicyView) -> Result<Self, Error> {
        Ok(Self::load(store).await?.managed(view))
    }

    /// This document under `view`: the ceiling caps every
    /// repository's permissions, and every repository on a server the
    /// policy does not allow removed and recorded.
    #[must_use]
    pub fn managed(mut self, view: &PolicyView) -> Self {
        let ceiling = view.landing_ceiling();
        let mut dropped = Vec::new();
        self.document.repositories.retain_mut(|repository| {
            if !server_allowed(view, &repository.github_server) {
                dropped.push(Dropped {
                    root: repository.root.clone(),
                    key: Key::LandingAllowedGithubServers,
                    reason: "this repository's GitHub server is not on a host your \
                             organization's policy allows",
                });
                return false;
            }
            let permissions = &mut repository.permissions;
            permissions.push &= ceiling.push;
            permissions.create_pr &= ceiling.create_pr;
            permissions.merge &= ceiling.merge;
            permissions.sync &= ceiling.sync;
            true
        });
        self.ceiling = ceiling;
        self.dropped = dropped;
        self
    }

    /// Whether the managed ceiling (not the human) caps `permission` off.
    pub fn ceiling_forbids(&self, permission: &str) -> bool {
        match permission {
            "push" => !self.ceiling.push,
            "create_pr" => !self.ceiling.create_pr,
            "merge" => !self.ceiling.merge,
            "sync" => !self.ceiling.sync,
            _ => false,
        }
    }

    /// Whether the human may save `self` (normalized) over `current` (the
    /// stored document) under `view`. A save that only narrows `current`
    /// passes a held key.
    fn check_write(&self, view: &PolicyView, current: &Self) -> Result<(), WriteRefusal> {
        if !self.narrows(current) {
            view.guard_held(Key::LandingMaxPermissions)?;
            view.guard_held(Key::LandingAllowedGithubServers)?;
        }
        let ceiling = view.landing_ceiling();
        for repository in &self.document.repositories {
            let root = repository.root.display();
            if let Some(permission) = above_ceiling(&repository.permissions, ceiling) {
                return Err(view.refusal(
                    Key::LandingMaxPermissions,
                    CAUSE_POLICY_NOT_ALLOWED,
                    &format!(
                        "{permission} for {root} is above the landing permissions your \
                         organization allows"
                    ),
                ));
            }
            if !server_allowed(view, &repository.github_server) {
                return Err(view.refusal(
                    Key::LandingAllowedGithubServers,
                    CAUSE_POLICY_NOT_ALLOWED,
                    &format!(
                        "the GitHub server {} for {root} is not a host your organization \
                         allows",
                        repository.github_server
                    ),
                ));
            }
        }
        Ok(())
    }

    /// Whether every recipe of `self` is in `current` for the same root and
    /// server, with no permission `current` did not already give.
    fn narrows(&self, current: &Self) -> bool {
        self.document.repositories.iter().all(|repository| {
            current.document.repositories.iter().any(|before| {
                before.root == repository.root
                    && before.github_server == repository.github_server
                    && (!repository.permissions.push || before.permissions.push)
                    && (!repository.permissions.create_pr || before.permissions.create_pr)
                    && (!repository.permissions.merge || before.permissions.merge)
                    && (!repository.permissions.sync || before.permissions.sync)
            })
        })
    }

    pub async fn load(store: &Store) -> Result<Self, Error> {
        let raw = store
            .get_setting_bounded(KEY, MAX_BYTES)
            .await
            .map_err(storage)?;
        let document = match raw.as_deref() {
            Some(raw) => serde_json::from_str(raw).map_err(|_| invalid())?,
            None => Document {
                version: 1,
                repositories: Vec::new(),
            },
        };
        Self::normalize(document, raw)
    }

    pub fn repository(&self, root: &Path) -> Result<&Repository, Error> {
        if let Some(repository) = self
            .document
            .repositories
            .iter()
            .find(|repo| repo.root == root)
        {
            return Ok(repository);
        }
        if self.dropped.iter().any(|entry| entry.root == root) {
            return Err(Error {
                cause: CAUSE_POLICY_DENIED,
                detail: DROPPED_DETAIL,
            });
        }
        Err(Error {
            cause: "landing_scope_denied",
            detail: "This repository has no GUI-approved landing recipe and mutation scope.",
        })
    }

    pub fn response(&self) -> Value {
        json!({"revision": self.revision, "repositories": self.document.repositories})
    }

    /// The `admin.flows.landing.get` reply: the stored document (`self`, what
    /// the human edits) plus `effective` (the per-key entries and the
    /// effective recipes, `effective` being `self` under `view`) and
    /// `landing_policy_dropped`.
    pub fn managed_response(&self, view: &PolicyView, effective: &Self) -> Value {
        let in_force = |key: Key| view.status(key).is_some_and(LeafStatus::in_force);
        let mut ceiling = serde_json::Map::new();
        if in_force(Key::LandingMaxPermissions) {
            let caps = view.landing_ceiling();
            ceiling.insert(
                Key::LandingMaxPermissions.path().to_owned(),
                json!({"push": caps.push, "create_pr": caps.create_pr, "merge": caps.merge, "sync": caps.sync}),
            );
        }
        let mut servers = serde_json::Map::new();
        if let Some(hosts) = view
            .policy()
            .allowed_github_servers
            .as_ref()
            .filter(|_| in_force(Key::LandingAllowedGithubServers))
        {
            servers.insert(
                Key::LandingAllowedGithubServers.path().to_owned(),
                json!(hosts.entries),
            );
        }
        let capped =
            self.document.repositories.iter().any(|repository| {
                above_ceiling(&repository.permissions, effective.ceiling).is_some()
            });
        let max_permissions = crate::scope_policy::constraint_entry(
            view,
            &[Key::LandingMaxPermissions],
            &ceiling,
            capped,
        );
        let github_servers = crate::scope_policy::constraint_entry(
            view,
            &[Key::LandingAllowedGithubServers],
            &servers,
            !effective.dropped.is_empty(),
        );
        let mut max_permissions = max_permissions.to_json();
        max_permissions["value"] = json!({
            "push": effective.ceiling.push, "create_pr": effective.ceiling.create_pr,
            "merge": effective.ceiling.merge, "sync": effective.ceiling.sync,
        });
        let mut github_servers = github_servers.to_json();
        github_servers["value"] = json!(servers.values().next());
        let mut body = self.response();
        body["effective"] = json!({
            "max_permissions": max_permissions,
            "allowed_github_servers": github_servers,
            "repositories": effective.document.repositories,
        });
        body["landing_policy_dropped"] = json!(
            effective
                .dropped
                .iter()
                .map(|entry| json!({"root": entry.root, "key": entry.key.path(), "reason": entry.reason}))
                .collect::<Vec<_>>()
        );
        body
    }

    /// Every approved repository's private workspace root, in policy order.
    pub fn workspace_roots(&self) -> impl Iterator<Item = &Path> {
        self.document
            .repositories
            .iter()
            .map(|repository| repository.workspace_root.as_path())
    }

    /// Saves the GUI's document on the exact revision it read, refusing what
    /// the managed policy `view` forbids before anything is written.
    pub async fn save(
        store: &Store,
        view: &PolicyView,
        args: &Value,
        protected_base: &Path,
    ) -> Result<Self, SaveRefusal> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Update {
            expected_revision: String,
            repositories: Vec<Repository>,
        }
        if serde_json::to_vec(args).map_err(|_| invalid())?.len() > MAX_BYTES {
            return Err(invalid().into());
        }
        let update: Update = serde_json::from_value(args.clone()).map_err(|_| invalid())?;
        let current = Self::load(store).await?;
        if update.expected_revision != current.revision {
            return Err(conflict().into());
        }
        let next = Self::normalize(
            Document {
                version: 1,
                repositories: update.repositories,
            },
            None,
        )?;
        next.check_write(view, &current)
            .map_err(SaveRefusal::Managed)?;
        for repo in &next.document.repositories {
            repo.authorize_workspace(protected_base)?;
        }
        if !store
            .compare_exchange_setting(KEY, current.raw.as_deref(), &next.canonical)
            .await
            .map_err(storage)?
        {
            return Err(conflict().into());
        }
        Ok(next)
    }
}
