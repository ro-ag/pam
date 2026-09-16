//! GUI-owned landing recipes and exact mutation targets. Missing policy grants nothing.
use pam_store::Store;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
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

#[derive(Serialize, Deserialize)]
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

pub(crate) struct Snapshot {
    document: Document,
    canonical: String,
    pub revision: String,
    raw: Option<String>,
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
        self.document
            .repositories
            .iter()
            .find(|repo| repo.root == root)
            .ok_or(Error {
                cause: "landing_scope_denied",
                detail: "This repository has no GUI-approved landing recipe and mutation scope.",
            })
    }

    pub fn response(&self) -> Value {
        json!({"revision": self.revision, "repositories": self.document.repositories})
    }

    /// Every approved repository's private workspace root, in policy order.
    pub fn workspace_roots(&self) -> impl Iterator<Item = &Path> {
        self.document
            .repositories
            .iter()
            .map(|repository| repository.workspace_root.as_path())
    }

    pub async fn save(store: &Store, args: &Value, protected_base: &Path) -> Result<Self, Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Update {
            expected_revision: String,
            repositories: Vec<Repository>,
        }
        if serde_json::to_vec(args).map_err(|_| invalid())?.len() > MAX_BYTES {
            return Err(invalid());
        }
        let update: Update = serde_json::from_value(args.clone()).map_err(|_| invalid())?;
        let current = Self::load(store).await?;
        if update.expected_revision != current.revision {
            return Err(conflict());
        }
        let next = Self::normalize(
            Document {
                version: 1,
                repositories: update.repositories,
            },
            None,
        )?;
        for repo in &next.document.repositories {
            repo.authorize_workspace(protected_base)?;
        }
        if !store
            .compare_exchange_setting(KEY, current.raw.as_deref(), &next.canonical)
            .await
            .map_err(storage)?
        {
            return Err(conflict());
        }
        Ok(next)
    }
}
