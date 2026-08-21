use std::{
    env, fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use directories::BaseDirs;
use pam_core::ProjectId;
use pam_platform::user_data_dir;
use pam_skills::{
    CursorGlobalRulesStatus, LocalInventoryReport, LocalInventoryRoots, ScanLimits,
    scan_local_inventory,
};
use pam_store::{SkillInventoryDrift, Store, StoredAgentArtifact};
use serde::{Deserialize, Serialize};

use crate::desktop::{DesktopErrorDto, DesktopResult};

pub(crate) const MAX_SKILL_INVENTORY_ITEMS: usize = 256;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SkillInventoryDto {
    pub fence: crate::CommandFence,
    pub data: SkillInventoryDataDto,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SkillInventoryDataDto {
    pub artifacts: Vec<SkillArtifactDto>,
    pub total: usize,
    pub truncated: bool,
    pub drift: SkillInventoryDriftDto,
    pub cursor_global_rules_status: CursorGlobalRulesStatusDto,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SkillArtifactDto {
    pub id: String,
    pub name: String,
    pub logical_path: String,
    pub kind: String,
    pub scope: String,
    pub origin: String,
    pub load_semantics: String,
    pub content_hash: String,
    pub first_seen_at_ms: u64,
    pub last_changed_at_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SkillInventoryDriftDto {
    pub added: usize,
    pub changed: usize,
    pub removed: usize,
    pub resurrected: usize,
}

impl SkillInventoryDriftDto {
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.added == 0 && self.changed == 0 && self.removed == 0 && self.resurrected == 0
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CursorGlobalRulesStatusDto {
    NotLocallyDiscoverable,
    ExplicitlyConfigured,
}

#[derive(Clone, Debug)]
pub(crate) struct SkillInventoryEnvironment {
    user_home: Option<PathBuf>,
    claude_plugin_registry_root: Option<PathBuf>,
    codex_system_config_root: Option<PathBuf>,
    codex_home: Option<PathBuf>,
    project_root: PathBuf,
    current_working_directory: PathBuf,
    state_path: PathBuf,
    observed_at_ms: u64,
}

impl SkillInventoryEnvironment {
    pub(crate) fn discover(project_root: PathBuf) -> DesktopResult<Self> {
        let user_home = BaseDirs::new().map(|directories| directories.home_dir().to_path_buf());
        let claude_plugin_registry_root = user_home.as_ref().and_then(|home| {
            let root = home.join(".claude/plugins");
            fs::symlink_metadata(root.join("installed_plugins.json"))
                .is_ok()
                .then_some(root)
        });
        let codex_system = PathBuf::from("/etc/codex");
        let codex_system_config_root = codex_system.is_dir().then_some(codex_system);
        let codex_home = env::var_os("CODEX_HOME")
            .filter(|path| !path.is_empty())
            .map(PathBuf::from)
            .or_else(|| {
                user_home.as_ref().and_then(|home| {
                    let root = home.join(".codex");
                    root.is_dir().then_some(root)
                })
            });
        let state_path = user_data_dir()
            .map_err(|_| {
                DesktopErrorDto::unavailable(
                    "PAM could not resolve its local inventory state.",
                    Some(
                        "Verify the operating system user data directory and retry Access."
                            .to_owned(),
                    ),
                )
            })?
            .join("state.sqlite3");
        let observed_at_ms = now_ms()?;
        Ok(Self {
            user_home,
            claude_plugin_registry_root,
            codex_system_config_root,
            codex_home,
            current_working_directory: project_root.clone(),
            project_root,
            state_path,
            observed_at_ms,
        })
    }

    fn roots(&self) -> LocalInventoryRoots<'_> {
        LocalInventoryRoots {
            user_home: self.user_home.as_deref(),
            claude_plugin_registry_root: self.claude_plugin_registry_root.as_deref(),
            codex_system_config_root: self.codex_system_config_root.as_deref(),
            codex_home: self.codex_home.as_deref(),
            project_root: &self.project_root,
            current_working_directory: &self.current_working_directory,
            cursor_global_rule: None,
        }
    }

    #[cfg(test)]
    pub(crate) fn for_test(
        user_home: PathBuf,
        project_root: PathBuf,
        state_path: PathBuf,
        observed_at_ms: u64,
    ) -> Self {
        let default_codex_home = user_home.join(".codex");
        let codex_home = default_codex_home.is_dir().then_some(default_codex_home);
        Self {
            user_home: Some(user_home),
            claude_plugin_registry_root: None,
            codex_system_config_root: None,
            codex_home,
            current_working_directory: project_root.clone(),
            project_root,
            state_path,
            observed_at_ms,
        }
    }
}

pub(crate) async fn load_skill_inventory(
    project_id: ProjectId,
    environment: SkillInventoryEnvironment,
) -> DesktopResult<SkillInventoryDataDto> {
    let scan_environment = environment.clone();
    let report = tokio::task::spawn_blocking(move || {
        scan_local_inventory(scan_environment.roots(), ScanLimits::default())
    })
    .await
    .map_err(|_| {
        DesktopErrorDto::unavailable(
            "PAM could not join the bounded skill inventory scan.",
            Some("Retry the Skill inventory panel.".to_owned()),
        )
    })?
    .map_err(|_| {
        DesktopErrorDto::unavailable(
            "PAM could not safely read the local agent inventory configuration.",
            Some("Repair the configured agent plugin registry, then retry Access.".to_owned()),
        )
    })?;
    if !report.complete() {
        return Err(DesktopErrorDto::unavailable(
            format!(
                "The skill inventory scan stopped after {} bounded filesystem diagnostics.",
                report.diagnostics().len()
            ),
            Some(
                "Review local agent file permissions and boundaries, then retry Access.".to_owned(),
            ),
        ));
    }
    persist_inventory(
        project_id,
        &environment.state_path,
        environment.observed_at_ms,
        report,
    )
    .await
}

async fn persist_inventory(
    project_id: ProjectId,
    state_path: &Path,
    observed_at_ms: u64,
    report: LocalInventoryReport,
) -> DesktopResult<SkillInventoryDataDto> {
    let cursor_global_rules_status = report.cursor_global_rules_status();
    let store = Store::open(state_path).map_err(store_error)?;
    let operation = async {
        let drift = store
            .rescan_skill_inventory(
                project_id.clone(),
                report.into_scan_report(),
                observed_at_ms,
            )
            .await?;
        let records = store.skill_artifacts(project_id).await?;
        Ok::<_, pam_store::StoreError>((drift, records))
    }
    .await;
    let shutdown = store.shutdown().await;
    let (drift, records) = operation.map_err(store_error)?;
    shutdown.map_err(store_error)?;
    Ok(inventory_data(&records, &drift, cursor_global_rules_status))
}

fn inventory_data(
    records: &[StoredAgentArtifact],
    drift: &SkillInventoryDrift,
    cursor_status: CursorGlobalRulesStatus,
) -> SkillInventoryDataDto {
    let total = records.len();
    let artifacts = records
        .iter()
        .take(MAX_SKILL_INVENTORY_ITEMS)
        .map(skill_artifact_dto)
        .collect();
    SkillInventoryDataDto {
        artifacts,
        total,
        truncated: total > MAX_SKILL_INVENTORY_ITEMS,
        drift: SkillInventoryDriftDto {
            added: drift.added.len(),
            changed: drift.changed.len(),
            removed: drift.removed.len(),
            resurrected: drift.resurrected.len(),
        },
        cursor_global_rules_status: match cursor_status {
            CursorGlobalRulesStatus::NotLocallyDiscoverable => {
                CursorGlobalRulesStatusDto::NotLocallyDiscoverable
            }
            CursorGlobalRulesStatus::ExplicitlyConfigured => {
                CursorGlobalRulesStatusDto::ExplicitlyConfigured
            }
        },
    }
}

fn skill_artifact_dto(record: &StoredAgentArtifact) -> SkillArtifactDto {
    SkillArtifactDto {
        id: record.id.to_string(),
        name: record.artifact.name().to_owned(),
        logical_path: record.artifact.logical_path().to_owned(),
        kind: record.artifact.kind().as_str().to_owned(),
        scope: record.artifact.scope().as_str().to_owned(),
        origin: record.artifact.origin().as_str().to_owned(),
        load_semantics: record.artifact.load_semantics().as_str().to_owned(),
        content_hash: record.artifact.content_hash().to_string(),
        first_seen_at_ms: record.first_seen_at_ms,
        last_changed_at_ms: record.last_changed_at_ms,
    }
}

fn now_ms() -> DesktopResult<u64> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| {
            DesktopErrorDto::unavailable(
                "The system clock cannot timestamp the skill inventory.",
                Some("Correct the system clock and retry Access.".to_owned()),
            )
        })?
        .as_millis();
    u64::try_from(millis).map_err(|_| {
        DesktopErrorDto::unavailable(
            "The system clock is outside PAM's supported range.",
            Some("Correct the system clock and retry Access.".to_owned()),
        )
    })
}

fn store_error(_error: pam_store::StoreError) -> DesktopErrorDto {
    DesktopErrorDto::unavailable(
        "PAM could not update its durable skill inventory.",
        Some("Verify the local PAM state directory and retry Access.".to_owned()),
    )
}

#[cfg(test)]
pub(crate) fn inventory_data_for_test(
    records: &[StoredAgentArtifact],
    drift: &SkillInventoryDrift,
    cursor_status: CursorGlobalRulesStatus,
) -> SkillInventoryDataDto {
    inventory_data(records, drift, cursor_status)
}
