//! The model half of the admin surface: `admin.models.*` and
//! `admin.curator.*`.
//!
//! These are ordinary admin ops in every way that matters — read
//! [`crate::admin`]'s module docs for the security model, because every
//! word of it applies here. The tripwire, the request row, the single
//! terminal audit row, the deadline, and the structural guard (no
//! [`crate::policy::classify`] entry, never a capability, never grantable)
//! are the same ones; this module only adds op names and bodies. They live
//! in their own file because there are fifteen of them, not because they
//! are a different kind of thing.
//!
//! # What an agent can and cannot do
//!
//! Nothing here is reachable by an agent using PAM as intended: there is
//! no `pam` subcommand that constructs any of these envelopes, and
//! [`pam_client`](https://docs.rs/pam_client) refuses `admin.*` outright.
//! Downloading weights, deleting them, loading them, choosing a tier
//! default, and picking a curator CLI are human acts through the GUI.
//! What agents get is the read-only `model` block on the `status`
//! capability.
//!
//! # Refusals name a cause the GUI can act on
//!
//! Every refusal carries `{ cause, detail, recovery }`. The causes are
//! contract — the GUI matches on them — and the ones that come out of the
//! runtime are [`pam_model::RuntimeError::cause`] verbatim, so a new
//! runtime failure surfaces under its own name instead of being flattened
//! into "internal error".
//!
//! # Long work answers with a job id
//!
//! `admin.models.download` and `admin.models.verify` return a `job_id` and
//! nothing else: the work outlives the op. Its progress and verdict live
//! on `model_job` rows, which [`OP_MODELS_STATUS`] reports (see
//! [`crate::model_service`]).

use std::path::PathBuf;
use std::time::{Duration, Instant};

use pam_model::catalog::{CATALOG, find_preset};
use pam_model::curator::{AgentCli, AgentId};
use pam_model::download::{DownloadError, DownloadRequest, curl_recovery_line};
use pam_model::registry::{MODEL_FLOOR_BYTES, ModelClass, ModelEntry, RegistryError};
use pam_model::runtime::{GenerateRequest, RuntimeState};
use pam_proto::Outcome;
use serde_json::{Value, json};

use crate::admin::{
    AdminOk, AdminRefusal, AdminService, CAUSE_INVALID_ADMIN_ARGS, RECOVERY_FIX_ARGS,
    RECOVERY_INTERNAL, required_str,
};
use crate::daemon::CAUSE_INTERNAL_ERROR;
use crate::model_service::{ModelServiceError, SETTING_CURATOR, Tier};

/// `admin.models.list` → `{ models, models_dir }`.
pub const OP_MODELS_LIST: &str = "admin.models.list";

/// `admin.models.catalog` → the presets, each flagged for this host.
pub const OP_MODELS_CATALOG: &str = "admin.models.catalog";

/// `admin.models.download { preset_id } | { url, vendor }` → `{ job_id }`.
pub const OP_MODELS_DOWNLOAD: &str = "admin.models.download";

/// `admin.models.download.cancel { job_id }` → stops the transfer.
pub const OP_MODELS_DOWNLOAD_CANCEL: &str = "admin.models.download.cancel";

/// `admin.models.delete { model_id }` → removes the weights from disk.
pub const OP_MODELS_DELETE: &str = "admin.models.delete";

/// `admin.models.verify { model_id }` → `{ job_id }` for the digest run.
pub const OP_MODELS_VERIFY: &str = "admin.models.verify";

/// `admin.models.load { model_id }` → maps the weights into memory.
pub const OP_MODELS_LOAD: &str = "admin.models.load";

/// `admin.models.unload` → drops the weights.
pub const OP_MODELS_UNLOAD: &str = "admin.models.unload";

/// `admin.models.status` → runtime, jobs, defaults, settings.
pub const OP_MODELS_STATUS: &str = "admin.models.status";

/// `admin.models.defaults.set { tier, model_id }` → a tier's model.
pub const OP_MODELS_DEFAULTS_SET: &str = "admin.models.defaults.set";

/// `admin.models.settings.set { models_dir?, idle_unload_min? }`.
pub const OP_MODELS_SETTINGS_SET: &str = "admin.models.settings.set";

/// `admin.models.try { prompt, max_tokens? }` → one diagnostic generation.
pub const OP_MODELS_TRY: &str = "admin.models.try";

/// `admin.curator.list` → the vendor agent CLIs on `PATH`.
pub const OP_CURATOR_LIST: &str = "admin.curator.list";

/// `admin.curator.set { agent }` → picks one (or clears the pick).
pub const OP_CURATOR_SET: &str = "admin.curator.set";

/// `admin.curator.test` → asks the picked CLI one question.
pub const OP_CURATOR_TEST: &str = "admin.curator.test";

/// Every op this module answers — the GUI bridge's whitelist reads it so
/// the two can never drift.
pub const MODEL_ADMIN_OPS: &[&str] = &[
    OP_MODELS_LIST,
    OP_MODELS_CATALOG,
    OP_MODELS_DOWNLOAD,
    OP_MODELS_DOWNLOAD_CANCEL,
    OP_MODELS_DELETE,
    OP_MODELS_VERIFY,
    OP_MODELS_LOAD,
    OP_MODELS_UNLOAD,
    OP_MODELS_STATUS,
    OP_MODELS_DEFAULTS_SET,
    OP_MODELS_SETTINGS_SET,
    OP_MODELS_TRY,
    OP_CURATOR_LIST,
    OP_CURATOR_SET,
    OP_CURATOR_TEST,
];

/// Refusal cause: a `test_only` model was offered as a tier default.
pub const CAUSE_BELOW_FLOOR: &str = "below_floor";

/// Refusal cause: no model in the registry carries that id.
pub const CAUSE_UNKNOWN_MODEL: &str = "unknown_model";

/// Refusal cause: that file is already being downloaded.
pub const CAUSE_ALREADY_DOWNLOADING: &str = "already_downloading";

/// Refusal cause: that file is already in the models directory.
pub const CAUSE_ALREADY_INSTALLED: &str = "already_installed";

/// Refusal cause: no `curl` on `PATH`, so nothing can be fetched.
pub const CAUSE_CURL_MISSING: &str = "curl_missing";

/// Refusal cause: the part file on disk belongs to a different transfer.
pub const CAUSE_CHECKPOINT_CONFLICT: &str = "checkpoint_conflict";

/// Refusal cause: the model is loaded and cannot be deleted.
pub const CAUSE_MODEL_LOADED: &str = "model_loaded";

/// Refusal cause: the target is not inside the models directory.
pub const CAUSE_OUTSIDE_MODELS_DIR: &str = "outside_models_dir";

/// Refusal cause: a transfer is writing to that file right now.
pub const CAUSE_DOWNLOAD_IN_PROGRESS: &str = "download_in_progress";

/// Refusal cause: the chosen agent CLI is not on `PATH`.
pub const CAUSE_NOT_DETECTED: &str = "not_detected";

/// Refusal cause: no curator CLI is picked.
pub const CAUSE_NO_CURATOR: &str = "no_curator";

/// Refusal cause: the curator CLI ran and did not answer.
pub const CAUSE_CURATOR_FAILED: &str = "curator_failed";

/// How long `<cli> --version` may take during detection.
const DETECT_DEADLINE: Duration = Duration::from_secs(5);

/// How long the curator has to answer the test question.
const CURATOR_TEST_DEADLINE: Duration = Duration::from_mins(1);

/// The question [`OP_CURATOR_TEST`] asks.
const CURATOR_TEST_PROMPT: &str = "Reply with the single word OK.";

/// Tokens [`OP_MODELS_TRY`] generates when the caller names no budget.
const TRY_DEFAULT_MAX_TOKENS: usize = 256;

/// Sampling temperature for the diagnostic generation.
const TRY_TEMPERATURE: f64 = 0.7;

/// Recovery line pointing at the library on the Models screen.
const RECOVERY_LIBRARY: &str =
    "Check the model id against the library on the PAM GUI Models screen.";

/// Recovery line for the engine floor.
const RECOVERY_FLOOR: &str = "Tier defaults need an engine-class model (18 GB or larger); pick one from the catalog \
     on the PAM GUI Models screen.";

/// Recovery line for a transfer that is already running.
const RECOVERY_DOWNLOAD_RUNNING: &str =
    "That download is already running; watch it on the PAM GUI Models screen.";

/// Recovery line for a file that is already on disk.
const RECOVERY_ALREADY_INSTALLED: &str =
    "The file is already in the models directory; load it from the PAM GUI Models screen.";

/// Recovery line for a stale part file.
const RECOVERY_CHECKPOINT_CONFLICT: &str = "A partial download of that file came from a different source; delete the .pam-model.part \
     and .pam-model.json sidecars and start again.";

/// Recovery line for an operation blocked by the loaded model.
const RECOVERY_UNLOAD_FIRST: &str = "Unload the model on the PAM GUI Models screen, then retry.";

/// Recovery line for a path outside the models directory.
const RECOVERY_OUTSIDE_DIR: &str = "PAM only deletes what it manages; remove that file by hand, or point the models directory \
     at its folder.";

/// Recovery line for a delete racing a download.
const RECOVERY_CANCEL_DOWNLOAD: &str =
    "Cancel the download on the PAM GUI Models screen, then delete the file.";

/// Recovery line for an empty runtime.
const RECOVERY_LOAD_A_MODEL: &str = "Load a model on the PAM GUI Models screen first.";

/// Recovery line for an over-long prompt.
const RECOVERY_SHORTEN_PROMPT: &str = "Shorten the prompt; the context holds 8192 tokens.";

/// Recovery line for a busy runtime.
const RECOVERY_RETRY_LATER: &str = "Another generation is running; retry when it finishes.";

/// Recovery line for an architecture PAM does not implement.
const RECOVERY_SUPPORTED_ARCH: &str =
    "PAM runs qwen3 and qwen3moe GGUF models; pick one of those from the catalog.";

/// Recovery line for a load candle refused.
const RECOVERY_VERIFY_FILE: &str = "Read the load error detail. For an unsupported quantization/backend, choose a supported model/backend and retain the model file and error when reporting it. For a truncated or unreadable GGUF, verify the file on the PAM GUI Models screen.";

/// Recovery line for a curator that is not there.
const RECOVERY_CURATOR_PICK: &str =
    "Pick one of the detected agent CLIs in PAM GUI Settings, Models section.";

/// Recovery line for a curator that failed to answer.
const RECOVERY_CURATOR_FAILED: &str =
    "Check that the CLI runs non-interactively (sign in, or update it), then test again.";

impl AdminService {
    /// Answers one `admin.models.*` / `admin.curator.*` op, or `None` when
    /// the capability belongs to another part of the admin surface.
    pub(crate) async fn dispatch_models(
        &self,
        op: &str,
        args: &Value,
    ) -> Option<Result<AdminOk, AdminRefusal>> {
        Some(match op {
            OP_MODELS_LIST => self.models_list().await,
            OP_MODELS_CATALOG => self.models_catalog().await,
            OP_MODELS_DOWNLOAD => self.models_download(args).await,
            OP_MODELS_DOWNLOAD_CANCEL => self.models_download_cancel(args).await,
            OP_MODELS_DELETE => self.models_delete(args).await,
            OP_MODELS_VERIFY => self.models_verify(args).await,
            OP_MODELS_LOAD => self.models_load(args).await,
            OP_MODELS_UNLOAD => self.models_unload().await,
            OP_MODELS_STATUS => self.models_status().await,
            OP_MODELS_DEFAULTS_SET => self.models_defaults_set(args).await,
            OP_MODELS_SETTINGS_SET => self.models_settings_set(args).await,
            OP_MODELS_TRY => self.models_try(args).await,
            OP_CURATOR_LIST => self.curator_list().await,
            OP_CURATOR_SET => self.curator_set(args).await,
            OP_CURATOR_TEST => self.curator_test().await,
            _ => return None,
        })
    }

    /// Everything under the models directory, header-parsed and classed.
    async fn models_list(&self) -> Result<AdminOk, AdminRefusal> {
        let models = self.models.scan().await.map_err(registry_refusal)?;
        Ok(AdminOk {
            outcome: Outcome::Verified,
            body: json!({
                "models": models,
                "models_dir": self.models.models_dir().display().to_string(),
            }),
            audit: json!({ "op": OP_MODELS_LIST, "count": models.len() }),
        })
    }

    /// The curated catalog, each preset told whether it fits this host and
    /// whether it is already here.
    async fn models_catalog(&self) -> Result<AdminOk, AdminRefusal> {
        let installed = self.models.scan().await.map_err(registry_refusal)?;
        let host_ram = self.models.host_ram_bytes();
        let presets: Vec<Value> = CATALOG
            .iter()
            .map(|preset| {
                let mut value = serde_json::to_value(preset).unwrap_or_else(|_| json!({}));
                let model_id = preset.model_id();
                if let Some(object) = value.as_object_mut() {
                    object.insert("fits_host".to_owned(), json!(preset.fits_host(host_ram)));
                    object.insert(
                        "installed".to_owned(),
                        json!(installed.iter().any(|entry| entry.id == model_id)),
                    );
                }
                value
            })
            .collect();
        Ok(AdminOk {
            outcome: Outcome::Verified,
            body: json!({
                "presets": presets,
                "host_ram_bytes": host_ram,
                "floor_bytes": MODEL_FLOOR_BYTES,
            }),
            audit: json!({ "op": OP_MODELS_CATALOG }),
        })
    }

    /// Starts a transfer, from a catalog preset or a pasted URL.
    async fn models_download(&self, args: &Value) -> Result<AdminOk, AdminRefusal> {
        let registry = self.models.registry();
        let (request, model_id) =
            if let Some(preset_id) = args.get("preset_id").and_then(Value::as_str) {
                let preset = find_preset(preset_id).ok_or_else(|| AdminRefusal {
                    cause: CAUSE_INVALID_ADMIN_ARGS,
                    detail: format!("{preset_id:?} is not a catalog preset"),
                    recovery: RECOVERY_FIX_ARGS,
                })?;
                (
                    DownloadRequest {
                        url: preset.url.to_owned(),
                        dest: registry.dest_for(preset.vendor, preset.file_name),
                        expected_size: Some(preset.size_bytes),
                        expected_sha256: Some(preset.sha256.to_owned()),
                        license_id: Some(preset.license_id.to_owned()),
                    },
                    preset.model_id(),
                )
            } else {
                let url = required_str(args, "url", OP_MODELS_DOWNLOAD)?;
                let vendor = required_str(args, "vendor", OP_MODELS_DOWNLOAD)?;
                let file_name = file_name_from_url(url).ok_or_else(|| AdminRefusal {
                    cause: CAUSE_INVALID_ADMIN_ARGS,
                    detail: format!("{url:?} does not end in a .gguf file name"),
                    recovery: RECOVERY_FIX_ARGS,
                })?;
                let stem = file_name.trim_end_matches(".gguf").to_owned();
                (
                    DownloadRequest {
                        url: url.to_owned(),
                        dest: registry.dest_for(vendor, &file_name),
                        expected_size: None,
                        expected_sha256: None,
                        license_id: None,
                    },
                    format!("{vendor}/{stem}"),
                )
            };

        let source = request.url.clone();
        let job_id = self
            .models
            .start_download(request, &model_id)
            .await
            .map_err(download_refusal)?;
        Ok(AdminOk {
            outcome: Outcome::Changed,
            body: json!({ "job_id": job_id }),
            audit: json!({
                "op": OP_MODELS_DOWNLOAD,
                "job_id": job_id,
                "model_id": model_id,
                "source": source,
            }),
        })
    }

    /// Stops a running transfer; the part file stays for a resume.
    async fn models_download_cancel(&self, args: &Value) -> Result<AdminOk, AdminRefusal> {
        let job_id = required_str(args, "job_id", OP_MODELS_DOWNLOAD_CANCEL)?;
        if !self.models.cancel_download(job_id).await {
            return Err(AdminRefusal {
                cause: CAUSE_INVALID_ADMIN_ARGS,
                detail: format!("no download job {job_id:?} is in flight"),
                recovery: RECOVERY_FIX_ARGS,
            });
        }
        Ok(AdminOk {
            outcome: Outcome::Changed,
            body: json!({ "job_id": job_id, "cancelled": true }),
            audit: json!({ "op": OP_MODELS_DOWNLOAD_CANCEL, "job_id": job_id }),
        })
    }

    /// Removes weights from disk, clearing any tier default that named
    /// them.
    async fn models_delete(&self, args: &Value) -> Result<AdminOk, AdminRefusal> {
        let model_id = required_str(args, "model_id", OP_MODELS_DELETE)?;
        let entry = self.entry(model_id).await?;
        if self.loaded_id() == Some(entry.id.clone()) {
            return Err(AdminRefusal {
                cause: CAUSE_MODEL_LOADED,
                detail: format!("{model_id} is loaded; PAM does not delete weights in use"),
                recovery: RECOVERY_UNLOAD_FIRST,
            });
        }
        if self.models.is_downloading(&entry.path).await {
            return Err(AdminRefusal {
                cause: CAUSE_DOWNLOAD_IN_PROGRESS,
                detail: format!("a transfer is writing to {}", entry.path.display()),
                recovery: RECOVERY_CANCEL_DOWNLOAD,
            });
        }

        let registry = self.models.registry();
        let target = entry.clone();
        let deleted = tokio::task::spawn_blocking(move || registry.delete(&target))
            .await
            .map_err(|err| AdminRefusal {
                cause: CAUSE_INTERNAL_ERROR,
                detail: format!("the delete did not finish: {err}"),
                recovery: RECOVERY_INTERNAL,
            })?;
        match deleted {
            Ok(()) => {}
            Err(RegistryError::OutsideModelsDir(path)) => {
                return Err(AdminRefusal {
                    cause: CAUSE_OUTSIDE_MODELS_DIR,
                    detail: format!("{} is outside the models directory", path.display()),
                    recovery: RECOVERY_OUTSIDE_DIR,
                });
            }
            Err(RegistryError::NotFound(id)) => {
                return Err(AdminRefusal {
                    cause: CAUSE_UNKNOWN_MODEL,
                    detail: format!("no model {id} in the models directory"),
                    recovery: RECOVERY_LIBRARY,
                });
            }
            Err(err) => return Err(registry_refusal(err)),
        }

        // A default pointing at weights that are gone would resolve to
        // `Missing` on every job; clear it here instead.
        let mut cleared: Vec<&str> = Vec::new();
        let (light, heavy) = self.models.defaults().await?;
        for (tier, configured) in [(Tier::Light, light), (Tier::Heavy, heavy)] {
            if configured.as_deref() == Some(entry.id.as_str()) {
                self.models.set_default(tier, None).await?;
                cleared.push(tier.as_str());
            }
        }
        Ok(AdminOk {
            outcome: Outcome::Changed,
            body: json!({ "deleted": true, "model_id": entry.id, "cleared_defaults": cleared }),
            audit: json!({
                "op": OP_MODELS_DELETE,
                "model_id": entry.id,
                "cleared_defaults": cleared,
            }),
        })
    }

    /// Starts a digest run over an installed model.
    async fn models_verify(&self, args: &Value) -> Result<AdminOk, AdminRefusal> {
        let model_id = required_str(args, "model_id", OP_MODELS_VERIFY)?;
        let entry = self.entry(model_id).await?;
        let id = entry.id.clone();
        let job_id = self
            .models
            .start_verify(entry)
            .await
            .map_err(download_refusal)?;
        Ok(AdminOk {
            outcome: Outcome::Changed,
            body: json!({ "job_id": job_id }),
            audit: json!({ "op": OP_MODELS_VERIFY, "job_id": job_id, "model_id": id }),
        })
    }

    /// Maps a model into memory, swapping out whatever was loaded.
    async fn models_load(&self, args: &Value) -> Result<AdminOk, AdminRefusal> {
        let model_id = required_str(args, "model_id", OP_MODELS_LOAD)?;
        let entry = self.entry(model_id).await?;
        let loaded = self
            .models
            .ensure_loaded(&entry)
            .await
            .map_err(|err| runtime_refusal(&err))?;
        Ok(AdminOk {
            outcome: Outcome::Changed,
            body: json!({ "state": self.models.runtime().snapshot().state }),
            audit: json!({
                "op": OP_MODELS_LOAD,
                "model_id": loaded.id,
                "quant": loaded.quant,
                "device": loaded.device,
            }),
        })
    }

    /// Drops the weights. Already idle is a success, not a refusal.
    async fn models_unload(&self) -> Result<AdminOk, AdminRefusal> {
        let previous = self.loaded_id();
        self.models
            .runtime()
            .unload()
            .await
            .map_err(|err| runtime_refusal(&err))?;
        Ok(AdminOk {
            outcome: Outcome::Changed,
            body: json!({ "state": self.models.runtime().snapshot().state }),
            audit: json!({ "op": OP_MODELS_UNLOAD, "model_id": previous }),
        })
    }

    /// Runtime, jobs, defaults and settings in one read.
    async fn models_status(&self) -> Result<AdminOk, AdminRefusal> {
        Ok(AdminOk {
            outcome: Outcome::Verified,
            body: self.models.status().await?,
            audit: json!({ "op": OP_MODELS_STATUS }),
        })
    }

    /// Points a tier at a model, or clears it.
    async fn models_defaults_set(&self, args: &Value) -> Result<AdminOk, AdminRefusal> {
        let raw_tier = required_str(args, "tier", OP_MODELS_DEFAULTS_SET)?;
        let tier = Tier::parse(raw_tier).ok_or_else(|| AdminRefusal {
            cause: CAUSE_INVALID_ADMIN_ARGS,
            detail: format!("{raw_tier:?} is not a tier; expected \"light\" or \"heavy\""),
            recovery: RECOVERY_FIX_ARGS,
        })?;
        let requested = args.get("model_id").and_then(Value::as_str);
        let Some(model_id) = requested else {
            self.models.set_default(tier, None).await?;
            return Ok(AdminOk {
                outcome: Outcome::Changed,
                body: json!({ "tier": tier.as_str(), "model_id": Value::Null }),
                audit: json!({ "op": OP_MODELS_DEFAULTS_SET, "tier": tier.as_str() }),
            });
        };

        let entry = self.entry(model_id).await?;
        if entry.class == ModelClass::TestOnly {
            return Err(AdminRefusal {
                cause: CAUSE_BELOW_FLOOR,
                detail: format!(
                    "{model_id} is {} bytes, under the {MODEL_FLOOR_BYTES}-byte engine floor; \
                     test-only models prove the wiring and never serve a job",
                    entry.size_bytes
                ),
                recovery: RECOVERY_FLOOR,
            });
        }
        self.models.set_default(tier, Some(&entry.id)).await?;
        Ok(AdminOk {
            outcome: Outcome::Changed,
            body: json!({ "tier": tier.as_str(), "model_id": entry.id }),
            audit: json!({
                "op": OP_MODELS_DEFAULTS_SET,
                "tier": tier.as_str(),
                "model_id": entry.id,
            }),
        })
    }

    /// Moves the models directory and/or the idle-unload window.
    async fn models_settings_set(&self, args: &Value) -> Result<AdminOk, AdminRefusal> {
        if let Some(raw) = args.get("models_dir").and_then(Value::as_str) {
            let dir = PathBuf::from(raw);
            if !dir.is_dir() {
                return Err(AdminRefusal {
                    cause: CAUSE_INVALID_ADMIN_ARGS,
                    detail: format!("{raw:?} is not a directory that exists"),
                    recovery: RECOVERY_FIX_ARGS,
                });
            }
            self.models.set_models_dir(&dir).await?;
        }
        if let Some(raw) = args.get("idle_unload_min") {
            let minutes = raw.as_u64().ok_or_else(|| AdminRefusal {
                cause: CAUSE_INVALID_ADMIN_ARGS,
                detail: format!("idle_unload_min must be a non-negative integer, got {raw}"),
                recovery: RECOVERY_FIX_ARGS,
            })?;
            self.models.set_idle_unload_min(minutes).await?;
        }
        let models_dir = self.models.models_dir().display().to_string();
        let idle_unload_min = self.models.idle_unload_min().await?;
        Ok(AdminOk {
            outcome: Outcome::Changed,
            body: json!({ "models_dir": models_dir, "idle_unload_min": idle_unload_min }),
            audit: json!({
                "op": OP_MODELS_SETTINGS_SET,
                "models_dir": models_dir,
                "idle_unload_min": idle_unload_min,
            }),
        })
    }

    /// One diagnostic generation on whatever is loaded.
    ///
    /// Deliberately works on `test_only` models: proving the wiring is the
    /// whole point of this op.
    async fn models_try(&self, args: &Value) -> Result<AdminOk, AdminRefusal> {
        let prompt = required_str(args, "prompt", OP_MODELS_TRY)?;
        let max_tokens = args
            .get("max_tokens")
            .and_then(Value::as_u64)
            .and_then(|value| usize::try_from(value).ok())
            .unwrap_or(TRY_DEFAULT_MAX_TOKENS);
        let snapshot = self.models.runtime().snapshot();
        if snapshot.busy {
            return Err(AdminRefusal {
                cause: pam_model::RuntimeError::Busy.cause(),
                detail: "the model thread is working on another command".to_owned(),
                recovery: RECOVERY_RETRY_LATER,
            });
        }
        let request = GenerateRequest {
            system: None,
            prompt: prompt.to_owned(),
            max_tokens,
            temperature: TRY_TEMPERATURE,
            stop: Vec::new(),
        };
        // No cancel surface on an admin op: the sender outlives the call
        // and never fires; the envelope deadline is the bound.
        let (_never, cancel) = tokio::sync::watch::channel(false);
        let result = self
            .models
            .runtime()
            .generate(request, cancel)
            .await
            .map_err(|err| runtime_refusal(&err))?;
        let body = serde_json::to_value(&result).map_err(|err| AdminRefusal {
            cause: CAUSE_INTERNAL_ERROR,
            detail: format!("the generation result did not serialize: {err}"),
            recovery: RECOVERY_INTERNAL,
        })?;
        Ok(AdminOk {
            outcome: Outcome::Verified,
            body,
            audit: json!({
                "op": OP_MODELS_TRY,
                "prompt_tokens": result.prompt_tokens,
                "completion_tokens": result.completion_tokens,
                "tokens_per_sec": result.tokens_per_sec,
            }),
        })
    }

    /// The vendor agent CLIs on `PATH`, and which one is picked.
    async fn curator_list(&self) -> Result<AdminOk, AdminRefusal> {
        let detected = detect_agents().await?;
        let selected = self.selected_agent().await?;
        Ok(AdminOk {
            outcome: Outcome::Verified,
            body: json!({
                "detected": detected,
                "selected": selected.map(AgentId::as_str),
            }),
            audit: json!({ "op": OP_CURATOR_LIST, "count": detected.len() }),
        })
    }

    /// Picks a curator CLI, or clears the pick.
    async fn curator_set(&self, args: &Value) -> Result<AdminOk, AdminRefusal> {
        let Some(raw) = args.get("agent").and_then(Value::as_str) else {
            self.store.set_setting(SETTING_CURATOR, "null").await?;
            return Ok(AdminOk {
                outcome: Outcome::Changed,
                body: json!({ "selected": Value::Null }),
                audit: json!({ "op": OP_CURATOR_SET, "selected": Value::Null }),
            });
        };
        let agent = AgentId::parse(raw).ok_or_else(|| AdminRefusal {
            cause: CAUSE_INVALID_ADMIN_ARGS,
            detail: format!("{raw:?} is not an agent; expected claude, codex, copilot or gemini"),
            recovery: RECOVERY_FIX_ARGS,
        })?;
        let detected = detect_agents().await?;
        if !detected.iter().any(|cli| cli.id == agent) {
            return Err(AdminRefusal {
                cause: CAUSE_NOT_DETECTED,
                detail: format!("no {raw} executable on the daemon's PATH"),
                recovery: RECOVERY_CURATOR_PICK,
            });
        }
        self.store
            .set_setting(SETTING_CURATOR, &json!(agent.as_str()).to_string())
            .await?;
        Ok(AdminOk {
            outcome: Outcome::Changed,
            body: json!({ "selected": agent.as_str() }),
            audit: json!({ "op": OP_CURATOR_SET, "selected": agent.as_str() }),
        })
    }

    /// Asks the picked CLI one tool-free question and times the answer.
    async fn curator_test(&self) -> Result<AdminOk, AdminRefusal> {
        let selected = self.selected_agent().await?.ok_or(AdminRefusal {
            cause: CAUSE_NO_CURATOR,
            detail: "no curator agent is selected".to_owned(),
            recovery: RECOVERY_CURATOR_PICK,
        })?;
        let detected = detect_agents().await?;
        let cli = detected
            .into_iter()
            .find(|cli| cli.id == selected)
            .ok_or_else(|| AdminRefusal {
                cause: CAUSE_NO_CURATOR,
                detail: format!("{selected} is selected but no longer on the daemon's PATH"),
                recovery: RECOVERY_CURATOR_PICK,
            })?;

        let started = Instant::now();
        let reply = pam_model::curator::invoke(&cli, CURATOR_TEST_PROMPT, CURATOR_TEST_DEADLINE)
            .await
            .map_err(|err| AdminRefusal {
                cause: CAUSE_CURATOR_FAILED,
                detail: err.to_string(),
                recovery: RECOVERY_CURATOR_FAILED,
            })?;
        let ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
        Ok(AdminOk {
            outcome: Outcome::Verified,
            body: json!({ "reply": reply, "ms": ms }),
            audit: json!({ "op": OP_CURATOR_TEST, "agent": selected.as_str(), "ms": ms }),
        })
    }

    /// The installed entry with `model_id`, or an `unknown_model` refusal.
    async fn entry(&self, model_id: &str) -> Result<ModelEntry, AdminRefusal> {
        self.models
            .find(model_id)
            .await
            .ok_or_else(|| AdminRefusal {
                cause: CAUSE_UNKNOWN_MODEL,
                detail: format!("no model {model_id:?} in the models directory"),
                recovery: RECOVERY_LIBRARY,
            })
    }

    /// The id of the loaded model, if any.
    fn loaded_id(&self) -> Option<String> {
        match self.models.runtime().snapshot().state {
            RuntimeState::Loaded(loaded) => Some(loaded.id),
            RuntimeState::Idle | RuntimeState::Loading { .. } => None,
        }
    }

    /// The curator pick from the settings, ignoring a name this binary
    /// does not know.
    async fn selected_agent(&self) -> Result<Option<AgentId>, AdminRefusal> {
        let Some(raw) = self.store.get_setting(SETTING_CURATOR).await? else {
            return Ok(None);
        };
        Ok(serde_json::from_str::<Option<String>>(&raw)
            .unwrap_or(Some(raw))
            .and_then(|name| AgentId::parse(&name)))
    }
}

/// The vendor CLIs on the daemon's own `PATH`, probed off the async
/// threads (detection stats the filesystem and waits on children).
async fn detect_agents() -> Result<Vec<AgentCli>, AdminRefusal> {
    let path = std::env::var_os("PATH").unwrap_or_default();
    tokio::task::spawn_blocking(move || pam_model::curator::detect(&path, DETECT_DEADLINE))
        .await
        .map_err(|err| AdminRefusal {
            cause: CAUSE_INTERNAL_ERROR,
            detail: format!("agent detection did not finish: {err}"),
            recovery: RECOVERY_INTERNAL,
        })
}

/// The `.gguf` file name a pasted URL ends in.
fn file_name_from_url(url: &str) -> Option<String> {
    let without_query = url.split(['?', '#']).next().unwrap_or(url);
    let name = without_query.rsplit('/').next()?;
    // Hugging Face serves `.gguf`; the case-insensitive compare only
    // spares a human who pasted a link a Windows share spelled loudly.
    if !std::path::Path::new(name)
        .extension()
        .is_some_and(|extension| extension.eq_ignore_ascii_case("gguf"))
    {
        return None;
    }
    Some(name.to_owned())
}

/// A refusal for what the service would not start.
fn download_refusal(err: ModelServiceError) -> AdminRefusal {
    match err {
        ModelServiceError::AlreadyDownloading(id) => AdminRefusal {
            cause: CAUSE_ALREADY_DOWNLOADING,
            detail: format!("a transfer of {id} is already running"),
            recovery: RECOVERY_DOWNLOAD_RUNNING,
        },
        ModelServiceError::AlreadyInstalled(id) => AdminRefusal {
            cause: CAUSE_ALREADY_INSTALLED,
            detail: format!("{id} is already in the models directory"),
            recovery: RECOVERY_ALREADY_INSTALLED,
        },
        ModelServiceError::UnknownModel(id) => AdminRefusal {
            cause: CAUSE_UNKNOWN_MODEL,
            detail: format!("no model {id} in the models directory"),
            recovery: RECOVERY_LIBRARY,
        },
        ModelServiceError::Download(DownloadError::CurlMissing) => AdminRefusal {
            cause: CAUSE_CURL_MISSING,
            detail: "no curl executable on the daemon's PATH".to_owned(),
            recovery: curl_recovery_line(),
        },
        ModelServiceError::Download(DownloadError::CheckpointConflict(detail)) => AdminRefusal {
            cause: CAUSE_CHECKPOINT_CONFLICT,
            detail,
            recovery: RECOVERY_CHECKPOINT_CONFLICT,
        },
        ModelServiceError::Download(other) => AdminRefusal {
            cause: CAUSE_INTERNAL_ERROR,
            detail: format!("the transfer could not be started: {other}"),
            recovery: RECOVERY_INTERNAL,
        },
        ModelServiceError::Registry(err) => registry_refusal(err),
        ModelServiceError::Store(err) => AdminRefusal::from(err),
    }
}

/// A refusal for a runtime failure, keeping the runtime's own cause.
pub(crate) fn runtime_refusal(err: &pam_model::RuntimeError) -> AdminRefusal {
    let recovery = match err {
        pam_model::RuntimeError::NoModelLoaded => RECOVERY_LOAD_A_MODEL,
        pam_model::RuntimeError::UnsupportedArchitecture(_) => RECOVERY_SUPPORTED_ARCH,
        pam_model::RuntimeError::LoadFailed(_) => RECOVERY_VERIFY_FILE,
        pam_model::RuntimeError::PromptTooLong { .. } => RECOVERY_SHORTEN_PROMPT,
        pam_model::RuntimeError::Busy => RECOVERY_RETRY_LATER,
        pam_model::RuntimeError::Cancelled => "The generation was cancelled. Try again when ready.",
        pam_model::RuntimeError::GenerationFailed(_) => {
            "Keep the error detail and report it with the model file, architecture, quantization and backend from model status. Try a supported model/backend; restarting does not repair incompatible inference kernels."
        }
        pam_model::RuntimeError::Crashed => RECOVERY_INTERNAL,
    };
    AdminRefusal {
        cause: err.cause(),
        detail: err.to_string(),
        recovery,
    }
}

/// A refusal for an unreadable models directory.
fn registry_refusal(err: RegistryError) -> AdminRefusal {
    match err {
        RegistryError::OutsideModelsDir(path) => AdminRefusal {
            cause: CAUSE_OUTSIDE_MODELS_DIR,
            detail: format!("{} is outside the models directory", path.display()),
            recovery: RECOVERY_OUTSIDE_DIR,
        },
        RegistryError::NotFound(id) => AdminRefusal {
            cause: CAUSE_UNKNOWN_MODEL,
            detail: format!("no model {id} in the models directory"),
            recovery: RECOVERY_LIBRARY,
        },
        other => AdminRefusal {
            cause: CAUSE_INTERNAL_ERROR,
            detail: format!("the models directory could not be read: {other}"),
            recovery: RECOVERY_INTERNAL,
        },
    }
}
