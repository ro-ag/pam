use std::{collections::BTreeSet, error::Error, fmt, fs, path::Path};

use crate::{ScanDiagnostic, ScanLimits, scan::ScanSession};

const CONFIG_FILE: &str = "config.toml";

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum CodexProjectTrust {
    Trusted,
    Untrusted,
    Unspecified,
}

/// Resolves the current user's persisted Codex trust decision for one project.
///
/// Only the user-level `config.toml` below `codex_home` is considered. Project-local
/// configuration cannot grant its own trust.
///
/// # Errors
///
/// Returns a typed, fail-closed error when the project cannot be canonicalized, the
/// user configuration cannot be read within `limits`, or a trust entry is malformed.
pub fn resolve_codex_project_trust(
    codex_home: Option<&Path>,
    project_root: &Path,
    limits: ScanLimits,
) -> Result<CodexProjectTrust, CodexProjectTrustError> {
    let canonical_project_root = fs::canonicalize(project_root)
        .map_err(|_| CodexProjectTrustError::ProjectRootUnavailable)?;
    if !canonical_project_root.is_dir() {
        return Err(CodexProjectTrustError::ProjectRootUnavailable);
    }
    let Some(codex_home) = codex_home else {
        return Ok(CodexProjectTrust::Unspecified);
    };

    let mut session = ScanSession::new(limits);
    let root = session.open_root(codex_home, "", "codex_home");
    let config = root
        .as_ref()
        .and_then(|root| session.read_optional_file(root, Path::new(CONFIG_FILE)));
    let diagnostics = session.finish().diagnostics().to_vec();
    if !diagnostics.is_empty() {
        return Err(CodexProjectTrustError::ConfigScan(diagnostics));
    }
    let Some(config) = config else {
        return Ok(CodexProjectTrust::Unspecified);
    };
    let source =
        std::str::from_utf8(&config.bytes).map_err(|_| CodexProjectTrustError::NonUtf8Config)?;
    let document = toml::from_str::<toml::Value>(source)
        .map_err(|_| CodexProjectTrustError::MalformedConfig)?;
    let Some(projects) = document.get("projects") else {
        return Ok(CodexProjectTrust::Unspecified);
    };
    let projects = projects
        .as_table()
        .ok_or(CodexProjectTrustError::InvalidProjectsType)?;

    let mut matches = BTreeSet::new();
    for (candidate, entry) in projects {
        let candidate = Path::new(candidate);
        if !candidate.is_absolute() || candidate.as_os_str().as_encoded_bytes().contains(&0) {
            return Err(CodexProjectTrustError::InvalidProjectPath);
        }
        let Ok(canonical_candidate) = fs::canonicalize(candidate) else {
            // Stale absolute entries for other projects do not affect this decision.
            continue;
        };
        if canonical_candidate != canonical_project_root {
            continue;
        }
        let entry = entry
            .as_table()
            .ok_or(CodexProjectTrustError::InvalidProjectEntryType)?;
        let decision = match entry.get("trust_level") {
            None => None,
            Some(value) => Some(parse_trust_level(value)?),
        };
        if let Some(decision) = decision {
            matches.insert(decision);
        }
    }

    let mut matches = matches.into_iter();
    match (matches.next(), matches.next()) {
        (None, _) => Ok(CodexProjectTrust::Unspecified),
        (Some(decision), None) => Ok(decision),
        (Some(_), Some(_)) => Err(CodexProjectTrustError::ConflictingAliases),
    }
}

fn parse_trust_level(value: &toml::Value) -> Result<CodexProjectTrust, CodexProjectTrustError> {
    let value = value
        .as_str()
        .ok_or(CodexProjectTrustError::InvalidTrustLevelType)?;
    match value {
        "trusted" => Ok(CodexProjectTrust::Trusted),
        "untrusted" => Ok(CodexProjectTrust::Untrusted),
        _ => Err(CodexProjectTrustError::InvalidTrustLevelValue),
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CodexProjectTrustError {
    ProjectRootUnavailable,
    ConfigScan(Vec<ScanDiagnostic>),
    NonUtf8Config,
    MalformedConfig,
    InvalidProjectsType,
    InvalidProjectPath,
    InvalidProjectEntryType,
    InvalidTrustLevelType,
    InvalidTrustLevelValue,
    ConflictingAliases,
}

impl fmt::Display for CodexProjectTrustError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ProjectRootUnavailable => {
                formatter.write_str("Codex project root is unavailable")
            }
            Self::ConfigScan(diagnostics) => write!(
                formatter,
                "Codex user configuration scan failed with {} diagnostics",
                diagnostics.len()
            ),
            Self::NonUtf8Config => formatter.write_str("Codex user configuration is not UTF-8"),
            Self::MalformedConfig => formatter.write_str("Codex user configuration is malformed"),
            Self::InvalidProjectsType => {
                formatter.write_str("Codex user configuration projects value is not a table")
            }
            Self::InvalidProjectPath => {
                formatter.write_str("Codex user configuration contains an unsafe project path")
            }
            Self::InvalidProjectEntryType => {
                formatter.write_str("Codex user configuration project entry is not a table")
            }
            Self::InvalidTrustLevelType => {
                formatter.write_str("Codex user configuration trust level is not a string")
            }
            Self::InvalidTrustLevelValue => {
                formatter.write_str("Codex user configuration trust level is unsupported")
            }
            Self::ConflictingAliases => formatter
                .write_str("Codex user configuration has conflicting aliases for this project"),
        }
    }
}

impl Error for CodexProjectTrustError {}
