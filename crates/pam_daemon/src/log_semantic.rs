//! Optional source-mapped record selection. Failure preserves deterministic evidence.

use std::time::Duration;

use pam_model::compression::{MODEL_SUBDIR, installed};
use serde_json::json;
use tokio::sync::watch;

use crate::admin_compressor::SETTING_ENABLED;
use crate::log_service::{
    CompressReport, EvidenceRef, LogService, ModelSkipped, PROMPT_BUDGET_BYTES, new_evidence_id,
};

impl LogService {
    pub(crate) async fn semantic_prompt(
        &self,
        request_id: &str,
        name: &str,
        compact_id: &str,
        report: &mut CompressReport,
        capture: Option<&crate::evidence_service::CaptureScope>,
    ) {
        match self.store.get_setting(SETTING_ENABLED).await {
            Ok(Some(value)) if value == "true" => {}
            Ok(_) => return,
            Err(error) => {
                record_skip(report, "settings_unavailable", error.to_string());
                return;
            }
        }
        if let Err(error) = self.models.resolve(crate::model_service::Tier::Heavy).await {
            record_skip(report, "investigator_unavailable", error.to_string());
            return;
        }
        if report.compact_text.len() <= PROMPT_BUDGET_BYTES {
            return;
        }
        let Ok(_operation) = self.models.operation.try_lock() else {
            record_skip(
                report,
                "runtime_busy",
                "The model worker is reserved.".to_owned(),
            );
            return;
        };
        let directory = self.models.models_dir().join(MODEL_SUBDIR);
        if !installed(&directory) {
            record_skip(
                report,
                "compressor_missing",
                "Install Microsoft compression in Models.".to_owned(),
            );
            return;
        }
        if self.models.runtime().snapshot().busy {
            record_skip(
                report,
                "runtime_busy",
                "The model worker is busy; deterministic evidence was preserved.".to_owned(),
            );
            return;
        }
        // Refuse conservatively before loading. The runtime also unloads the
        // generator before extraction, and the classifier caps its own input.
        let memory = sysinfo::System::new_with_specifics(
            sysinfo::RefreshKind::nothing().with_memory(sysinfo::MemoryRefreshKind::everything()),
        );
        if memory.available_memory() < 2 * 1024 * 1024 * 1024 {
            record_skip(
                report,
                "memory_pressure",
                "Microsoft compression needs at least 2 GiB available memory.".to_owned(),
            );
            return;
        }
        let (cancel, receiver) = watch::channel(false);
        let operation = self.models.runtime().compress(
            directory,
            report.compact_text.clone(),
            PROMPT_BUDGET_BYTES,
            receiver,
        );
        tokio::pin!(operation);
        let Ok(result) = tokio::time::timeout(Duration::from_secs(30), &mut operation).await else {
            let _ = cancel.send(true);
            record_skip(report, "compression_timeout", "Microsoft compression exceeded 30 seconds; cancellation was requested and deterministic evidence retained.".to_owned());
            return;
        };
        let selection = match result {
            Ok(selection) => selection,
            Err(error) => {
                record_skip(report, "compression_failed", error.to_string());
                return;
            }
        };
        self.store_selection(request_id, name, compact_id, report, selection, capture)
            .await;
    }

    async fn store_selection(
        &self,
        request_id: &str,
        name: &str,
        compact_id: &str,
        report: &mut CompressReport,
        selection: pam_model::compression::CompressionReport,
        capture: Option<&crate::evidence_service::CaptureScope>,
    ) {
        let view = (|| {
            let mapping =
                crate::evidence_view::semantic_segments(&selection, &report.compact_text)?;
            let mut view = crate::evidence_view::redact(selection.text.as_bytes())?;
            view.segments = crate::evidence_view::compose_segments(&view.segments, &mapping)?;
            Ok::<_, crate::evidence_view::ViewError>(view)
        })();
        let view = match view {
            Ok(view) => view,
            Err(error) => {
                record_skip(
                    report,
                    "compression_provenance_unavailable",
                    error.to_string(),
                );
                return;
            }
        };
        let safe_text = match String::from_utf8(view.bytes.clone()) {
            Ok(text) => text,
            Err(_) => return,
        };
        let bytes = match serde_json::to_vec(&selection) {
            Ok(bytes) => bytes,
            Err(error) => {
                record_skip(report, "compression_failed", error.to_string());
                return;
            }
        };
        let id = new_evidence_id();
        let meta = json!({"name": name, "compact_evidence": compact_id,
            "source_evidence": report.source.id,
            "offset_basis": "utf8_bytes_of_compact_rendering", "qualification": "experimental_record_selection"});
        if let Err(error) = self
            .store
            .insert_evidence(
                &id,
                request_id,
                "log.semantic",
                &bytes,
                Some(&meta.to_string()),
            )
            .await
        {
            record_skip(report, "compression_store_failed", error.to_string());
            return;
        }
        if let Some(capture) = capture {
            if let Err(error) = crate::evidence_service::publish(
                &self.store,
                capture,
                request_id,
                &id,
                view,
                json!({"evidence_id": compact_id, "source_sha256": selection.source_sha256,
                    "offset_basis": "compact_view_bytes"}),
            )
            .await
            {
                record_skip(report, "compression_view_unavailable", error);
                return;
            }
        }
        report.semantic = Some(EvidenceRef {
            id,
            bytes: u64::try_from(bytes.len()).unwrap_or(u64::MAX),
        });
        report.semantic_text = Some(safe_text);
    }
}

fn record_skip(report: &mut CompressReport, cause: &str, detail: String) {
    report.compression_skipped = Some(ModelSkipped {
        cause: cause.to_owned(),
        detail,
    });
}
