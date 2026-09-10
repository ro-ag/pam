//! GUI-owned project identity, independent of connector access authorization.
use pam_store::Store;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeSet;

const KEY: &str = "sonar.repository_mappings";
const MAX_BYTES: usize = 32_768;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Mapping {
    server: String,
    project: String,
    repository: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Document {
    version: u8,
    mappings: Vec<Mapping>,
}

#[derive(Debug, thiserror::Error)]
#[error("{detail}")]
pub(crate) struct MappingError {
    cause: &'static str,
    detail: &'static str,
}
impl MappingError {
    pub fn cause(&self) -> &'static str {
        self.cause
    }
}
fn invalid() -> MappingError {
    MappingError {
        cause: "sonar_mapping_invalid",
        detail: "Sonar repository mappings must be a valid bounded version 1 document with unique server/project identities.",
    }
}
fn storage(_: pam_store::StoreError) -> MappingError {
    MappingError {
        cause: "sonar_mapping_storage",
        detail: "Sonar repository mappings could not be read or saved.",
    }
}
fn server(raw: &str) -> Result<String, MappingError> {
    pam_connectors::validate_base_url(pam_flow::ConnectorId::Sonarqube, raw)
        .map(|url| url.to_string())
        .map_err(|_| invalid())
}

pub(crate) struct Snapshot {
    document: Document,
    canonical: String,
    revision: String,
    raw: Option<String>,
}
impl Snapshot {
    pub async fn load(store: &Store) -> Result<Self, MappingError> {
        let raw = store
            .get_setting_bounded(KEY, MAX_BYTES)
            .await
            .map_err(storage)?;
        let document = match raw.as_deref() {
            Some(raw) => serde_json::from_str(raw).map_err(|_| invalid())?,
            None => Document {
                version: 1,
                mappings: Vec::new(),
            },
        };
        Self::normalize(document, raw)
    }
    fn normalize(mut document: Document, raw: Option<String>) -> Result<Self, MappingError> {
        if document.version != 1 || document.mappings.len() > 64 {
            return Err(invalid());
        }
        let mut seen = BTreeSet::new();
        for mapping in &mut document.mappings {
            mapping.server = server(&mapping.server)?;
            mapping.repository =
                pam_flow::canonical_repository_url(&mapping.repository).map_err(|_| invalid())?;
            if mapping.project.is_empty()
                || mapping.project.len() > 400
                || mapping.project.trim() != mapping.project
                || mapping.project.contains(',')
                || mapping.project.chars().any(char::is_control)
                || !seen.insert((mapping.server.clone(), mapping.project.clone()))
            {
                return Err(invalid());
            }
        }
        document
            .mappings
            .sort_by(|a, b| (&a.server, &a.project).cmp(&(&b.server, &b.project)));
        let canonical = serde_json::to_string(&document).map_err(|_| invalid())?;
        if canonical.len() > MAX_BYTES {
            return Err(invalid());
        }
        Ok(Self {
            revision: pam_compact::sha256_hex(canonical.as_bytes()),
            document,
            canonical,
            raw,
        })
    }
    pub fn revision(&self) -> &str {
        &self.revision
    }
    pub fn repository(&self, server_url: &str, project: &str) -> Option<&str> {
        let server = server(server_url).ok()?;
        self.document
            .mappings
            .iter()
            .find(|mapping| mapping.server == server && mapping.project == project)
            .map(|mapping| mapping.repository.as_str())
    }
    pub fn response(&self) -> Value {
        json!({"revision":self.revision,"mappings":self.document.mappings})
    }
    pub async fn save(store: &Store, args: &Value) -> Result<Self, MappingError> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Update {
            expected_revision: String,
            mappings: Vec<Mapping>,
        }
        if serde_json::to_vec(args).map_err(|_| invalid())?.len() > MAX_BYTES {
            return Err(invalid());
        }
        let update: Update = serde_json::from_value(args.clone()).map_err(|_| invalid())?;
        let current = Self::load(store).await?;
        let conflict = || MappingError {
            cause: "sonar_mapping_conflict",
            detail: "Sonar mappings changed since this editor loaded. Reload mappings before saving.",
        };
        if update.expected_revision != current.revision {
            return Err(conflict());
        }
        let next = Self::normalize(
            Document {
                version: 1,
                mappings: update.mappings,
            },
            None,
        )?;
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
