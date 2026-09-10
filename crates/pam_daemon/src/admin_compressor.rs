//! GUI setup for the pinned Microsoft extraction model; reuses model downloads.

use pam_model::DownloadRequest;
use pam_model::compression::{ASSETS, MODEL_SUBDIR, installed};
use pam_proto::Outcome;
use serde_json::{Value, json};

use crate::admin::{AdminOk, AdminRefusal, AdminService};

/// GUI-only query for asset presence and opt-in status.
pub const OP_STATUS: &str = "admin.models.compressor.status";
/// GUI-only installation through the existing resumable download jobs.
pub const OP_INSTALL: &str = "admin.models.compressor.install";
/// GUI-only opt-in; does not qualify the model for autonomous decisions.
pub const OP_SET: &str = "admin.models.compressor.set";
/// Whether log summaries may use Microsoft record selection.
pub const SETTING_ENABLED: &str = "model.compressor.enabled";

impl AdminService {
    pub(crate) async fn compressor_status(&self) -> Result<AdminOk, AdminRefusal> {
        let directory = self.models.models_dir().join(MODEL_SUBDIR);
        let enabled = self.store.get_setting(SETTING_ENABLED).await?.as_deref() == Some("true");
        Ok(AdminOk {
            outcome: Outcome::Verified,
            body: json!({
                "installed": installed(&directory), "enabled": enabled,
                "directory": directory, "bytes": ASSETS.iter().map(|asset| asset.size).sum::<u64>(),
                "qualification": "experimental_record_selection",
            }),
            audit: json!({"op": OP_STATUS}),
        })
    }

    pub(crate) async fn compressor_install(&self, args: &Value) -> Result<AdminOk, AdminRefusal> {
        let directory = self.models.models_dir().join(MODEL_SUBDIR);
        let repair = args
            .get("repair")
            .and_then(Value::as_bool)
            .ok_or_else(|| AdminRefusal {
                cause: "invalid_admin_args",
                detail: "repair must be a boolean".to_owned(),
                recovery: "Install or reinstall through Models.",
            })?;
        for asset in ASSETS {
            if self
                .models
                .is_downloading(&directory.join(asset.name))
                .await
            {
                return Err(AdminRefusal {
                    cause: "compressor_download_running",
                    detail: "Compressor assets are still downloading.".to_owned(),
                    recovery: "Wait for the download jobs to finish.",
                });
            }
        }
        let mut jobs = Vec::new();
        for asset in ASSETS {
            let dest = directory.join(asset.name);
            if repair && dest.exists() {
                let backup =
                    directory.join(format!("{}.replaced-{}", asset.name, ulid::Ulid::new()));
                tokio::fs::rename(&dest, &backup)
                    .await
                    .map_err(|error| AdminRefusal {
                        cause: "compressor_repair_failed",
                        detail: error.to_string(),
                        recovery: "Wait for active downloads to finish before reinstalling.",
                    })?;
            }
            if dest.metadata().is_ok_and(|meta| meta.len() == asset.size) {
                continue;
            }
            // An unexpected existing file is never replaced implicitly.
            let job = self.models.start_download(DownloadRequest {
                url: asset.url.to_owned(), dest,
                expected_size: Some(asset.size), expected_sha256: Some(asset.sha256.to_owned()),
                license_id: Some("apache-2.0".to_owned()),
            }, &format!("microsoft/llmlingua-2/{}", asset.name)).await.map_err(|error| AdminRefusal {
                cause: "compressor_install_failed", detail: error.to_string(),
                recovery: "Check the Models download jobs. Retry installation after any running jobs finish; existing unexpected files must be corrected explicitly.",
            })?;
            jobs.push(job);
        }
        Ok(AdminOk {
            outcome: Outcome::Changed,
            body: json!({"jobs": jobs}),
            audit: json!({"op": OP_INSTALL, "repair": repair}),
        })
    }

    pub(crate) async fn compressor_set(&self, args: &Value) -> Result<AdminOk, AdminRefusal> {
        let enabled = args
            .get("enabled")
            .and_then(Value::as_bool)
            .ok_or_else(|| AdminRefusal {
                cause: "invalid_admin_args",
                detail: "enabled must be a boolean".to_owned(),
                recovery: "Choose whether to enable Microsoft record selection in Models.",
            })?;
        if enabled && !installed(&self.models.models_dir().join(MODEL_SUBDIR)) {
            return Err(AdminRefusal {
                cause: "compressor_missing",
                detail: "Microsoft compressor assets are not installed".to_owned(),
                recovery: "Install the compressor in Models first.",
            });
        }
        self.store
            .set_setting(SETTING_ENABLED, if enabled { "true" } else { "false" })
            .await?;
        let mut answer = self.compressor_status().await?;
        answer.outcome = Outcome::Changed;
        answer.audit = json!({"op": OP_SET, "enabled": enabled});
        Ok(answer)
    }
}
