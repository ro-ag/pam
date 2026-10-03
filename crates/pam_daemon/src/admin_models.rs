//! The model half of the admin surface: `admin.models.*` and `admin.curator.*`. Ordinary admin ops
//! — see [`crate::admin`] for the security model: GUI tripwire, request row, single terminal audit
//! row, deadline, structural guard (no [`crate::policy::classify`] entry, never a capability, never
//! grantable). No `pam` subcommand constructs these envelopes, and `pam_client` refuses `admin.*`
//! outright: downloading, deleting, or loading weights, choosing a tier default, and picking a
//! curator CLI are human-only. Agents get only the read-only `model` block on the `status`
//! capability.
//!
//! Every refusal carries `{ cause, detail, recovery }`; causes are contract the GUI matches on, and
//! ones from the runtime are [`pam_model::RuntimeError::cause`] verbatim rather than flattened to
//! "internal error". `admin.models.download`, `.import` and `.verify` return only a `job_id` —
//! the work outlives the op — and its progress and verdict live on `model_job` rows, which
//! [`OP_MODELS_STATUS`] reports (see [`crate::model_service`]). A catalog download is fetched
//! from the models mirror when the human set one (the rewrite is the downloader's own, and
//! the catalog's `fetch` field shows the same address beforehand); a pasted URL is never
//! rewritten. An import copies a file from this machine, never moves it, and is recorded as
//! verified only when its digest is the catalog's or one the human supplied.
//!
//! The managed policy governs four things here, and every refusal is audited as `policy.locked_write`
//! on the op's request: `models.allowed_sources` (a catalog download, a pasted address and an import
//! each need their source listed), `models.allowed_curators` (a curator outside the list cannot be
//! picked, shows as selected, or run), and the two settings `models.dir` and `models.idle_unload_min`
//! ([`OP_MODELS_SETTINGS_SET`]; the reply and status carry an `effective` entry for each).

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use pam_model::catalog::{CATALOG, find_preset};
use pam_model::curator::{AgentId, Detection};
use pam_model::download::{DownloadError, DownloadRequest, ImportRequest, curl_recovery_line};
use pam_model::registry::{ModelEntry, RegistryError};
use pam_model::runtime::{GenerateRequest, RuntimeState};
use pam_proto::Outcome;
use serde_json::{Value, json};

use crate::admin::{
    AdminOk, AdminRefusal, AdminService, CAUSE_INVALID_ADMIN_ARGS, RECOVERY_FIX_ARGS,
    RECOVERY_INTERNAL, required_str,
};
use crate::daemon::CAUSE_INTERNAL_ERROR;
use crate::managed_policy::{
    CAUSE_POLICY_NOT_ALLOWED, EffectiveEntry, Key, ModelSource, PolicyView,
};
use crate::model_readiness::{Stage, admission_blocker};
use crate::model_service::{ModelServiceError, ModelUnavailable, SETTING_CURATOR, Tier};
use crate::network_service::Source;

/// `admin.models.list` → `{ models, models_dir }`.
pub const OP_MODELS_LIST: &str = "admin.models.list";

/// `admin.models.catalog` → the presets, each flagged for this host.
pub const OP_MODELS_CATALOG: &str = "admin.models.catalog";

/// `admin.models.download { preset_id } | { url, vendor }` → `{ job_id }`.
pub const OP_MODELS_DOWNLOAD: &str = "admin.models.download";

/// `admin.models.import { path, confirm: true, vendor?, expected_sha256? }`
/// → `{ job_id, … }`: copies a `.gguf` in from a file on this machine.
pub const OP_MODELS_IMPORT: &str = "admin.models.import";

/// `admin.models.download.cancel { job_id }` → stops the transfer, the
/// import, or the verification, with that job id.
pub const OP_MODELS_DOWNLOAD_CANCEL: &str = "admin.models.download.cancel";

/// `admin.models.download.discard { preset_id } | { url, vendor }` →
/// deletes the partial download so the next one starts from zero.
pub const OP_MODELS_DOWNLOAD_DISCARD: &str = "admin.models.download.discard";

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

/// `admin.models.try { model_id, prompt, max_tokens? }` → one diagnostic generation.
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
    crate::admin_engine::OP_ENGINE_STATUS,
    crate::admin_engine::OP_ENGINE_INSTALL,
    crate::admin_engine::OP_ENGINE_IMPORT,
    crate::admin_engine::OP_ENGINE_REMOVE,
    OP_MODELS_IMPORT,
    OP_MODELS_LIST,
    OP_MODELS_CATALOG,
    OP_MODELS_DOWNLOAD,
    OP_MODELS_DOWNLOAD_CANCEL,
    OP_MODELS_DOWNLOAD_DISCARD,
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

/// Refusal cause: an unverified (`test_only`) model was offered as a tier
/// default.
pub const CAUSE_UNVERIFIED: &str = "unverified";

/// Refusal cause: a verified model with no qualification record on this
/// target was offered as a tier default.
pub const CAUSE_UNQUALIFIED: &str = "unqualified";

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

/// Refusal cause: a diagnostic named a model the engine does not hold;
/// diagnostics never load or swap, so the human loads it first.
pub const CAUSE_MODEL_NOT_LOADED: &str = "model_not_loaded";

/// Refusal cause: the models directory would sit inside (or around) the
/// daemon's own base directory.
pub const CAUSE_MODELS_DIR_OVERLAPS_BASE: &str = "models_dir_overlaps_base";

/// Refusal cause: a transfer is writing to that file right now.
pub const CAUSE_DOWNLOAD_IN_PROGRESS: &str = "download_in_progress";

/// Refusal cause: a model file changed after it was verified.
pub const CAUSE_MODEL_CHANGED: &str = "model_changed";

/// Refusal cause: the chosen agent CLI is not in a directory PAM runs CLIs from.
pub const CAUSE_NOT_DETECTED: &str = "not_detected";

/// Refusal cause: no curator CLI is picked.
pub const CAUSE_NO_CURATOR: &str = "no_curator";

/// Refusal cause: the file an import names does not exist or cannot be read.
pub const CAUSE_IMPORT_SOURCE_MISSING: &str = "import_source_missing";

/// Refusal cause: the file an import names breaks a rule (a symbolic link,
/// not a regular file, not a `.gguf`, already inside the models directory).
pub const CAUSE_IMPORT_SOURCE_REFUSED: &str = "import_source_refused";

/// Refusal cause: the volume holding the models directory has no room for
/// the copy an import makes. The detail names the bytes needed.
pub const CAUSE_NO_SPACE: &str = crate::model_service::CAUSE_NO_SPACE;

/// The vendor directory an imported file lands under when it matches no
/// catalog preset and the caller named none.
pub const IMPORT_DEFAULT_VENDOR: &str = "imported";

/// What the reply says when an import will be checked against a digest.
const IMPORT_NOTE_CHECKED: &str = "PAM copies the file and checks its size and SHA-256 against the value named; the original is not changed. No network is used.";

/// What the reply says when an import has no digest to check against.
const IMPORT_NOTE_UNVERIFIED: &str = "PAM has no expected SHA-256 for this file: it is copied in as an unverified, test-only model, exactly like a file placed in the models directory by hand. Run Verify on it before it can serve jobs. The original is not changed. No network is used.";

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

/// Recovery line for a diagnostic on a model the engine does not hold.
const RECOVERY_LOAD_THAT_MODEL: &str =
    "Load that exact model on the PAM GUI Models screen, then run the diagnostic again.";

/// Recovery line for a models directory overlapping the PAM base.
const RECOVERY_MODELS_DIR_ELSEWHERE: &str = "Pick a models directory outside PAM's own base directory (the folder holding state.sqlite3 and the engine).";

/// Recovery line for an over-long prompt.
const RECOVERY_SHORTEN_PROMPT: &str = "Shorten the prompt; the context holds 8192 tokens.";

/// Recovery line for a busy runtime.
const RECOVERY_RETRY_LATER: &str = "Another generation is running; retry when it finishes.";

/// Recovery line for a load the engine refused.
const RECOVERY_VERIFY_FILE: &str = "Read the load error detail. For an unsupported quantization/backend, choose a supported model/backend and retain the model file and error when reporting it. For a truncated or unreadable GGUF, verify the file on the PAM GUI Models screen.";

/// Recovery line for an engine process that died on its own.
const RECOVERY_ENGINE_EXITED: &str = "The engine process stopped (it may have been killed for memory). The next job loads the model again; to retry now, load the model on the PAM GUI Models screen.";

/// Recovery line for a model file that changed after it was verified.
const RECOVERY_VERIFY_AGAIN: &str =
    "Run Verify on the PAM GUI Models screen; the model serves again once its digest is checked.";

/// Recovery line for a curator that is not there.
const RECOVERY_CURATOR_PICK: &str =
    "Pick one of the detected agent CLIs in PAM GUI Settings, Models section.";

/// Recovery line for a curator that failed to answer.
const RECOVERY_CURATOR_FAILED: &str =
    "Check that the CLI runs non-interactively (sign in, or update it), then test again.";

/// Recovery line for an import source PAM cannot read.
const RECOVERY_IMPORT_SOURCE: &str =
    "Check the path; it must name a .gguf file readable by the user the PAM daemon runs as.";

/// Recovery line for an import source that breaks a rule.
const RECOVERY_IMPORT_RULE: &str =
    "Give the path of the .gguf file itself (not a link to it), outside the models directory.";

/// Recovery line for an import the volume cannot hold.
const RECOVERY_IMPORT_SPACE: &str = "Free the bytes named in the detail on the volume holding the models directory, or move the models directory in Settings, then import again.";

impl AdminService {
    /// Answers one `admin.models.*` / `admin.curator.*` op, or `None` when
    /// the capability belongs to another part of the admin surface.
    ///
    /// `envelope_id` is the admin request's own id: a refusal by the
    /// managed policy writes its `policy.locked_write` row on it.
    pub(crate) async fn dispatch_models(
        &self,
        envelope_id: &str,
        op: &str,
        args: &Value,
    ) -> Option<Result<AdminOk, AdminRefusal>> {
        Some(match op {
            crate::admin_engine::OP_ENGINE_STATUS => self.engine_status(args).await,
            crate::admin_engine::OP_ENGINE_INSTALL => self.engine_install(envelope_id, args).await,
            crate::admin_engine::OP_ENGINE_IMPORT => self.engine_import(envelope_id, args).await,
            crate::admin_engine::OP_ENGINE_REMOVE => self.engine_remove(args).await,
            OP_MODELS_IMPORT => self.models_import(envelope_id, args).await,
            OP_MODELS_LIST => self.models_list().await,
            OP_MODELS_CATALOG => self.models_catalog().await,
            OP_MODELS_DOWNLOAD => self.models_download(envelope_id, args).await,
            OP_MODELS_DOWNLOAD_CANCEL => self.models_download_cancel(args).await,
            OP_MODELS_DOWNLOAD_DISCARD => self.models_download_discard(args).await,
            OP_MODELS_DELETE => self.models_delete(args).await,
            OP_MODELS_VERIFY => self.models_verify(args).await,
            OP_MODELS_LOAD => self.models_load(args).await,
            OP_MODELS_UNLOAD => self.models_unload().await,
            OP_MODELS_STATUS => self.models_status().await,
            OP_MODELS_DEFAULTS_SET => self.models_defaults_set(args).await,
            OP_MODELS_SETTINGS_SET => self.models_settings_set(envelope_id, args).await,
            OP_MODELS_TRY => self.models_try(args).await,
            OP_CURATOR_LIST => self.curator_list().await,
            OP_CURATOR_SET => self.curator_set(envelope_id, args).await,
            OP_CURATOR_TEST => self.curator_test(envelope_id).await,
            _ => return None,
        })
    }

    /// Everything under the models directory, header-parsed and classed.
    async fn models_list(&self) -> Result<AdminOk, AdminRefusal> {
        let models = self.models.scan().await.map_err(download_refusal)?;
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
        let installed = self.models.scan().await.map_err(download_refusal)?;
        let host_ram = self.models.host_ram_bytes();
        // A partial download is invisible to a registry scan — the
        // sidecars are dotfiles — so the catalog reads them directly.
        // Without this the GUI can only infer a resumable transfer from a
        // job row, and job rows age out of the status window.
        let registry = self.models.registry();
        let partials =
            crate::blocking_jobs::run(crate::blocking_jobs::Kind::ModelFilesystem, move || {
                CATALOG
                    .iter()
                    .map(|preset| {
                        let dest = registry.dest_for(preset.vendor, preset.file_name);
                        pam_model::download::inspect_partial(&dest)
                    })
                    .collect::<Vec<_>>()
            })
            .await
            .map_err(blocking_refusal)?;
        // What a download of each preset would actually fetch, computed by
        // the downloader's own rewrite so the confirmation cannot disagree
        // with the request. Settings that cannot be read show upstream and
        // say so in `network_issue`; the download itself still refuses.
        let (models_mirror, network_issue) = match self.mirrors().await {
            Ok((_, models_mirror)) => (models_mirror, None),
            Err(issue) => (None, Some(issue)),
        };
        let presets: Vec<Value> = CATALOG
            .iter()
            .zip(partials)
            .map(|(preset, partial)| {
                let mut value = serde_json::to_value(preset).unwrap_or_else(|_| json!({}));
                let model_id = preset.model_id();
                let fetch = DownloadRequest {
                    url: preset.url.to_owned(),
                    dest: PathBuf::new(),
                    expected_size: None,
                    expected_sha256: None,
                    license_id: None,
                }
                .via_mirror(models_mirror.as_ref(), pam_model::catalog::UPSTREAM_PREFIX)
                .url;
                let mirrored = fetch != preset.url;
                if let Some(object) = value.as_object_mut() {
                    object.insert(
                        "fetch".to_owned(),
                        json!({
                            "host": pam_net::Url::parse(&fetch)
                                .ok()
                                .and_then(|url| url.host_str().map(str::to_owned)),
                            "url": fetch,
                            "source": if mirrored { "mirror" } else { "upstream" },
                        }),
                    );
                    object.insert("fits_host".to_owned(), json!(preset.fits_host(host_ram)));
                    object.insert(
                        "installed".to_owned(),
                        json!(installed.iter().any(|entry| entry.id == model_id)),
                    );
                    object.insert(
                        "partial_bytes".to_owned(),
                        json!(partial.as_ref().map(|found| found.bytes)),
                    );
                }
                value
            })
            .collect();
        let mut body = json!({
            "presets": presets,
            "host_ram_bytes": host_ram,
            "models_mirror": models_mirror.as_ref().map(|mirror| mirror.as_str().to_owned()),
            "effective": { "allowed_sources": self.allowed_sources_entry().to_json() },
        });
        if let Some(issue) = network_issue {
            body["network_issue"] = json!({
                "cause": issue.cause,
                "detail": issue.detail,
                "recovery": issue.recovery,
            });
        }
        Ok(AdminOk {
            outcome: Outcome::Verified,
            body,
            audit: json!({ "op": OP_MODELS_CATALOG }),
        })
    }

    /// The engine and models mirrors the next transfer would use, as a
    /// refusal when the network settings cannot be read.
    async fn mirrors(
        &self,
    ) -> Result<(Option<pam_net::MirrorBase>, Option<pam_net::MirrorBase>), AdminRefusal> {
        self.models.mirrors().await.map_err(|failure| AdminRefusal {
            cause: failure.cause(),
            detail: failure.sentence(),
            recovery: failure.recovery(),
        })
    }

    /// Copies a `.gguf` in from a file on this machine, as a job.
    ///
    /// The trust decision is made here, before the copy ([`import_target`]):
    /// a file whose size is a catalog preset's lands under that preset's
    /// name and must hash to the preset's digest; any other file lands under
    /// the vendor the caller named (or [`IMPORT_DEFAULT_VENDOR`]) and its own
    /// name, held to `expected_sha256` when one was given and otherwise
    /// imported unverified. Nothing a caller sends can make an unknown
    /// digest count as the catalog's: a supplied digest records a
    /// verification the way `admin.models.verify` would, and admission for
    /// jobs still needs a qualification record for that digest.
    async fn models_import(
        &self,
        envelope_id: &str,
        args: &Value,
    ) -> Result<AdminOk, AdminRefusal> {
        let wanted = ImportArgs::parse(args)?;
        self.gate_model_source(envelope_id, OP_MODELS_IMPORT, ModelSource::Import)
            .await?;
        // The source's own facts, read off the async threads: the size
        // picks the catalog preset, if any, and nothing else about the file
        // is trusted until the copy is hashed.
        let probe = wanted.source.clone();
        let size =
            crate::blocking_jobs::run(crate::blocking_jobs::Kind::ModelFilesystem, move || {
                let meta = std::fs::symlink_metadata(&probe).ok()?;
                (meta.is_file() && !meta.file_type().is_symlink()).then_some(meta.len())
            })
            .await
            .map_err(blocking_refusal)?;
        let target = import_target(&self.models.registry(), &wanted, size)?;
        if !target.dest.starts_with(self.models.models_dir()) {
            return Err(AdminRefusal {
                cause: CAUSE_OUTSIDE_MODELS_DIR,
                detail: format!("{} is outside the models directory", target.dest.display()),
                recovery: RECOVERY_OUTSIDE_DIR,
            });
        }
        let verified_on_completion = target.expected_sha256.is_some();
        let request = ImportRequest {
            source: wanted.source.clone(),
            dest: target.dest.clone(),
            expected_size: target.expected_size,
            expected_sha256: target.expected_sha256.clone(),
        };
        let job_id = self
            .models
            .start_import(request, &target.model_id)
            .await
            .map_err(download_refusal)?;
        Ok(AdminOk {
            outcome: Outcome::Changed,
            body: json!({
                "job_id": job_id,
                "model_id": target.model_id,
                "dest": target.dest.display().to_string(),
                "source": wanted.raw,
                "size_bytes": size,
                "catalog": target.catalog.map(|preset| json!({
                    "preset_id": preset.id,
                    "label": preset.label,
                    "sha256": preset.sha256,
                    "size_bytes": preset.size_bytes,
                })),
                "expected_sha256": target.expected_sha256,
                "verified_on_completion": verified_on_completion,
                "note": if verified_on_completion { IMPORT_NOTE_CHECKED } else { IMPORT_NOTE_UNVERIFIED },
            }),
            audit: json!({
                "op": OP_MODELS_IMPORT,
                "job_id": job_id,
                "model_id": target.model_id,
                "source": wanted.raw,
                "catalog_preset": target.catalog.map(|preset| preset.id),
                "verified_on_completion": verified_on_completion,
            }),
        })
    }

    /// Starts a transfer, from a catalog preset or a pasted URL.
    async fn models_download(
        &self,
        envelope_id: &str,
        args: &Value,
    ) -> Result<AdminOk, AdminRefusal> {
        let (request, model_id) = self.download_request(args, OP_MODELS_DOWNLOAD)?;
        // A catalog preset and a pasted address are different sources: an
        // organisation may allow the first (digest pinned in this build)
        // and not the second.
        let source = if args.get("preset_id").is_some() {
            ModelSource::Catalog
        } else {
            ModelSource::CustomUrl
        };
        self.gate_model_source(envelope_id, OP_MODELS_DOWNLOAD, source)
            .await?;
        // A catalog preset is fetched from the models mirror when the human
        // set one: only the scheme-and-host prefix changes, the path, size
        // and digest stay the catalog's. A pasted address is never rewritten
        // (`via_mirror` leaves a URL outside the upstream prefix alone, and
        // only the preset arm carries one under it).
        let request = if args.get("preset_id").is_some() {
            let (_, models_mirror) = self.mirrors().await?;
            request.via_mirror(models_mirror.as_ref(), pam_model::catalog::UPSTREAM_PREFIX)
        } else {
            request
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

    /// Throws away a partial download so the next attempt starts over.
    ///
    /// Takes the same arguments as the download it undoes: the human is
    /// discarding *that* fetch, and asking them for a file path the GUI
    /// never showed them would be absurd.
    async fn models_download_discard(&self, args: &Value) -> Result<AdminOk, AdminRefusal> {
        let (request, model_id) = self.download_request(args, OP_MODELS_DOWNLOAD_DISCARD)?;
        let discarded = self
            .models
            .discard_partial(&request.dest, &model_id)
            .await
            .map_err(download_refusal)?;
        Ok(AdminOk {
            outcome: Outcome::Changed,
            body: json!({ "model_id": model_id, "discarded_bytes": discarded }),
            audit: json!({
                "op": OP_MODELS_DOWNLOAD_DISCARD,
                "model_id": model_id,
                "discarded_bytes": discarded,
            }),
        })
    }

    /// The transfer a `{ preset_id }` or `{ url, vendor }` argument names,
    /// and the registry id it installs as.
    fn download_request(
        &self,
        args: &Value,
        op: &'static str,
    ) -> Result<(DownloadRequest, String), AdminRefusal> {
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
                let url = required_str(args, "url", op)?;
                let vendor = required_str(args, "vendor", op)?;
                let file_name = file_name_from_url(url).ok_or_else(|| AdminRefusal {
                    cause: CAUSE_INVALID_ADMIN_ARGS,
                    detail: format!("{url:?} does not end in a .gguf file name"),
                    recovery: RECOVERY_FIX_ARGS,
                })?;
                // Both names came from the caller: the registry refuses
                // anything but one plain segment each (`..`, separators, an
                // absolute or hidden name), so the destination is always
                // exactly `<models dir>/<vendor>/<file>`.
                let dest = registry
                    .checked_dest_for(vendor, &file_name)
                    .map_err(|error| match error {
                        RegistryError::InvalidName(_) => AdminRefusal {
                            cause: CAUSE_INVALID_ADMIN_ARGS,
                            detail: error.to_string(),
                            recovery: RECOVERY_FIX_ARGS,
                        },
                        other => registry_refusal(other),
                    })?;
                let stem = file_name.trim_end_matches(".gguf").to_owned();
                (
                    DownloadRequest {
                        url: url.to_owned(),
                        dest,
                        expected_size: None,
                        expected_sha256: None,
                        license_id: None,
                    },
                    format!("{vendor}/{stem}"),
                )
            };
        // Belt and braces over the segment checks: whatever the registry
        // joined, the destination stays under the models directory, since
        // this path is what `start_download` creates and `discard_partial`
        // unlinks sidecars beside.
        if !request.dest.starts_with(self.models.models_dir()) {
            return Err(AdminRefusal {
                cause: CAUSE_OUTSIDE_MODELS_DIR,
                detail: format!("{} is outside the models directory", request.dest.display()),
                recovery: RECOVERY_OUTSIDE_DIR,
            });
        }
        Ok((request, model_id))
    }

    /// Stops a running transfer (the part file stays for a resume) or a running
    /// verification (its private copy in progress is removed, nothing is recorded).
    async fn models_download_cancel(&self, args: &Value) -> Result<AdminOk, AdminRefusal> {
        let job_id = required_str(args, "job_id", OP_MODELS_DOWNLOAD_CANCEL)?;
        if !self.models.cancel_download(job_id).await && !self.models.cancel_verify(job_id) {
            return Err(AdminRefusal {
                cause: CAUSE_INVALID_ADMIN_ARGS,
                detail: format!("no download or verification job {job_id:?} is in flight"),
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
        let operation = self
            .models
            .operation
            .clone()
            .try_lock_owned()
            .map_err(|_| runtime_refusal(&pam_model::RuntimeError::Busy))?;
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
        // The blocking closure owns the reservation even if its caller times out.
        let (deleted, _operation) =
            crate::blocking_jobs::run(crate::blocking_jobs::Kind::ModelFilesystem, move || {
                (registry.delete(&target), operation)
            })
            .await
            .map_err(blocking_refusal)?;
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
            body: json!({ "state": self.models.snapshot().state }),
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
        let _operation = self.models.operation.lock().await;
        let previous = self.loaded_id();
        self.models
            .unload_all()
            .await
            .map_err(|err| runtime_refusal(&err))?;
        Ok(AdminOk {
            outcome: Outcome::Changed,
            body: json!({ "state": self.models.snapshot().state }),
            audit: json!({ "op": OP_MODELS_UNLOAD, "model_id": previous }),
        })
    }

    /// Runtime, jobs, defaults and settings in one read.
    async fn models_status(&self) -> Result<AdminOk, AdminRefusal> {
        Ok(AdminOk {
            outcome: Outcome::Verified,
            body: self.models.status().await.map_err(diagnostic_refusal)?,
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
        if let Some((stage, blocker)) = admission_blocker(&entry) {
            return Err(AdminRefusal {
                cause: if stage == Stage::Unverified {
                    CAUSE_UNVERIFIED
                } else {
                    CAUSE_UNQUALIFIED
                },
                detail: blocker.detail,
                recovery: blocker.recovery,
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
    ///
    /// The directory is canonicalised off the async threads (symlinks
    /// resolved, so the registry's containment checks compare like with
    /// like) and refused when it would overlap the daemon's own base:
    /// weights are not PAM state and a registry scan or delete must never
    /// reach `state.sqlite3` or the engine.
    async fn models_settings_set(
        &self,
        envelope_id: &str,
        args: &Value,
    ) -> Result<AdminOk, AdminRefusal> {
        // Every argument is read and checked against the managed policy
        // before anything is written, so a refusal leaves both settings as
        // they were.
        let view = self.policy.view();
        let minutes = match args.get("idle_unload_min") {
            None => None,
            Some(raw) => Some(raw.as_u64().ok_or_else(|| AdminRefusal {
                cause: CAUSE_INVALID_ADMIN_ARGS,
                detail: format!("idle_unload_min must be a non-negative integer, got {raw}"),
                recovery: RECOVERY_FIX_ARGS,
            })?),
        };
        if args.get("models_dir").and_then(Value::as_str).is_some()
            && let Err(refusal) = view.guard_locked(Key::ModelsDir)
        {
            return Err(self
                .policy_refusal(envelope_id, OP_MODELS_SETTINGS_SET, refusal, &view)
                .await);
        }
        if let Some(minutes) = minutes
            // `0` is "never", the forever of this timer.
            && let Err(refusal) =
                view.check_window(Key::ModelsIdleUnloadMin, (minutes != 0).then_some(minutes))
        {
            return Err(self
                .policy_refusal(envelope_id, OP_MODELS_SETTINGS_SET, refusal, &view)
                .await);
        }
        if let Some(raw) = args.get("models_dir").and_then(Value::as_str) {
            let requested = PathBuf::from(raw);
            let canonical =
                crate::blocking_jobs::run(crate::blocking_jobs::Kind::ModelFilesystem, move || {
                    let canonical = requested.canonicalize().ok()?;
                    canonical.is_dir().then_some(canonical)
                })
                .await
                .map_err(blocking_refusal)?
                .ok_or_else(|| AdminRefusal {
                    cause: CAUSE_INVALID_ADMIN_ARGS,
                    detail: format!("{raw:?} is not a directory that exists"),
                    recovery: RECOVERY_FIX_ARGS,
                })?;
            if let Some(base) = self.models.daemon_base()
                && (canonical.starts_with(&base) || base.starts_with(&canonical))
            {
                return Err(AdminRefusal {
                    cause: CAUSE_MODELS_DIR_OVERLAPS_BASE,
                    detail: format!(
                        "{} overlaps PAM's base directory {}",
                        canonical.display(),
                        base.display()
                    ),
                    recovery: RECOVERY_MODELS_DIR_ELSEWHERE,
                });
            }
            self.models
                .set_models_dir(&canonical)
                .await
                .map_err(diagnostic_refusal)?;
        }
        if let Some(minutes) = minutes {
            self.models.set_idle_unload_min(minutes).await?;
        }
        let (models_dir, models_dir_entry) = self.models.models_dir_entry();
        let models_dir = models_dir.display().to_string();
        let (idle_unload_min, idle_entry) = self.models.idle_unload_min_entry().await?;
        Ok(AdminOk {
            outcome: Outcome::Changed,
            body: json!({
                "models_dir": models_dir,
                "idle_unload_min": idle_unload_min,
                "effective": {
                    "models_dir": models_dir_entry.to_json(),
                    "idle_unload_min": idle_entry.to_json(),
                },
            }),
            audit: json!({
                "op": OP_MODELS_SETTINGS_SET,
                "models_dir": models_dir,
                "idle_unload_min": idle_unload_min,
            }),
        })
    }

    /// One diagnostic on the explicitly requested installed and loaded model.
    /// Test-only models remain usable; this does not establish qualification.
    async fn models_try(&self, args: &Value) -> Result<AdminOk, AdminRefusal> {
        let model_id = required_str(args, "model_id", OP_MODELS_TRY)?;
        let prompt = required_str(args, "prompt", OP_MODELS_TRY)?;
        let max_tokens = match args.get("max_tokens") {
            None => TRY_DEFAULT_MAX_TOKENS,
            Some(value) => value
                .as_u64()
                .and_then(|value| usize::try_from(value).ok())
                .filter(|value| *value <= pam_model::runtime::CONTEXT_TOKENS)
                .ok_or_else(|| AdminRefusal {
                    cause: CAUSE_INVALID_ADMIN_ARGS,
                    detail: "max_tokens must be an integer from 0 through 8192".to_owned(),
                    recovery: RECOVERY_FIX_ARGS,
                })?,
        };
        let timeout_ms = match args.get("timeout_ms") {
            None => 120_000,
            Some(value) => value
                .as_u64()
                .filter(|value| (1..=120_000).contains(value))
                .ok_or_else(|| AdminRefusal {
                    cause: CAUSE_INVALID_ADMIN_ARGS,
                    detail: "timeout_ms must be an integer from 1 through 120000".to_owned(),
                    recovery: RECOVERY_FIX_ARGS,
                })?,
        };
        let request = GenerateRequest {
            system: None,
            prompt: prompt.to_owned(),
            max_tokens,
            temperature: TRY_TEMPERATURE,
            stop: Vec::new(),
        };
        let result = tokio::time::timeout(
            std::time::Duration::from_millis(timeout_ms),
            self.models.generate_diagnostic(model_id, request),
        ).await.map_err(|_| AdminRefusal {
            cause: "diagnostic_timeout",
            detail: "The diagnostic deadline elapsed; cancellation was requested. An in-progress forward pass may still finish before the worker stops.".to_owned(),
            recovery: RECOVERY_RETRY_LATER,
        })?.map_err(diagnostic_refusal)?;
        let mut body = serde_json::to_value(&result).map_err(|err| AdminRefusal {
            cause: CAUSE_INTERNAL_ERROR,
            detail: format!("the generation result did not serialize: {err}"),
            recovery: RECOVERY_INTERNAL,
        })?;
        body["requested_model_id"] = json!(model_id);
        body["diagnostic_only"] = json!(true);
        body["qualification"] = json!("not_assessed");
        Ok(AdminOk {
            outcome: Outcome::Verified,
            body,
            audit: json!({
                "op": OP_MODELS_TRY,
                "requested_model_id": model_id,
                "model": result.model,
                "diagnostic_only": true,
                "prompt_tokens": result.prompt_tokens,
                "completion_tokens": result.completion_tokens,
                "tokens_per_sec": result.tokens_per_sec,
            }),
        })
    }

    /// The vendor agent CLIs in trusted directories, those seen elsewhere and refused
    /// (never run), and which one is picked.
    async fn curator_list(&self) -> Result<AdminOk, AdminRefusal> {
        let detection = detect_agents().await?;
        let selected = self.selected_agent().await?;
        Ok(AdminOk {
            outcome: Outcome::Verified,
            body: json!({
                "detected": detection.found,
                "untrusted": detection.untrusted,
                "selected": selected.map(AgentId::as_str),
                "effective": { "curator": self.curator_entry(selected).to_json() },
            }),
            audit: json!({
                "op": OP_CURATOR_LIST,
                "count": detection.found.len(),
                "untrusted": detection.untrusted.len(),
            }),
        })
    }

    /// Picks a curator CLI, or clears the pick.
    async fn curator_set(&self, envelope_id: &str, args: &Value) -> Result<AdminOk, AdminRefusal> {
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
        self.gate_curator(envelope_id, OP_CURATOR_SET, Some(agent))
            .await?;
        let detection = detect_agents().await?;
        if !detection.found.iter().any(|cli| cli.id == agent) {
            return Err(AdminRefusal {
                cause: CAUSE_NOT_DETECTED,
                detail: not_detected_detail(&detection, agent),
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
    async fn curator_test(&self, envelope_id: &str) -> Result<AdminOk, AdminRefusal> {
        // A pick the policy no longer allows is not run: asking the CLI is
        // the egress the policy governs. (The pick itself stays stored.)
        let picked = self.stored_agent().await?;
        self.gate_curator(envelope_id, OP_CURATOR_TEST, picked)
            .await?;
        let selected = self.selected_agent().await?.ok_or(AdminRefusal {
            cause: CAUSE_NO_CURATOR,
            detail: "no curator agent is selected".to_owned(),
            recovery: RECOVERY_CURATOR_PICK,
        })?;
        let detection = detect_agents().await?;
        let cli = detection
            .found
            .iter()
            .find(|cli| cli.id == selected)
            .cloned()
            .ok_or_else(|| AdminRefusal {
                cause: CAUSE_NO_CURATOR,
                detail: format!(
                    "{selected} is selected but no longer where PAM runs it from: {}",
                    not_detected_detail(&detection, selected)
                ),
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
            .map_err(download_refusal)?
            .ok_or_else(|| AdminRefusal {
                cause: CAUSE_UNKNOWN_MODEL,
                detail: format!("no model {model_id:?} in the models directory"),
                recovery: RECOVERY_LIBRARY,
            })
    }

    /// The id of the loaded model, if any.
    fn loaded_id(&self) -> Option<String> {
        match self.models.snapshot().state {
            RuntimeState::Loaded(loaded) => Some(loaded.id),
            RuntimeState::Idle | RuntimeState::Loading { .. } => None,
        }
    }

    /// The curator pick the human saved, ignoring a name this binary does
    /// not know, before any policy is applied.
    async fn stored_agent(&self) -> Result<Option<AgentId>, AdminRefusal> {
        let Some(raw) = self.store.get_setting(SETTING_CURATOR).await? else {
            return Ok(None);
        };
        Ok(serde_json::from_str::<Option<String>>(&raw)
            .unwrap_or(Some(raw))
            .and_then(|name| AgentId::parse(&name)))
    }

    /// The curator in force: the saved pick, unless the managed policy's
    /// `models.allowed_curators` leaves it out.
    async fn selected_agent(&self) -> Result<Option<AgentId>, AdminRefusal> {
        let view = self.policy.view();
        Ok(self
            .stored_agent()
            .await?
            .filter(|agent| view.curator_allowed(*agent)))
    }

    /// Where the curator pick stands under `models.allowed_curators`.
    fn curator_entry(&self, selected: Option<AgentId>) -> EffectiveEntry {
        let view = self.policy.view();
        let allow = view.policy().allowed_curators.as_ref().map(|agents| {
            json!({ "allow": agents.iter().map(|agent| agent.as_str()).collect::<Vec<_>>() })
        });
        let source = if selected.is_some() {
            Source::User
        } else {
            Source::Default
        };
        crate::connector_service::plain_entry(
            &view,
            Key::ModelsAllowedCurators,
            source,
            false,
            allow,
        )
    }

    /// Where `models.allowed_sources` stands, for the catalog's `effective`.
    fn allowed_sources_entry(&self) -> EffectiveEntry {
        let view = self.policy.view();
        let allow = view.policy().allowed_sources.as_ref().map(|sources| {
            json!({ "allow": sources.iter().map(|source| source.as_str()).collect::<Vec<_>>() })
        });
        crate::connector_service::plain_entry(
            &view,
            Key::ModelsAllowedSources,
            Source::Default,
            false,
            allow,
        )
    }

    /// Refuses (and audits) bringing a model in through `source` when the
    /// managed policy's `models.allowed_sources` does not list it, or
    /// cannot be read (a held key pauses the ops it governs).
    pub(crate) async fn gate_model_source(
        &self,
        envelope_id: &str,
        op: &str,
        source: ModelSource,
    ) -> Result<(), AdminRefusal> {
        let view = self.policy.view();
        let key = Key::ModelsAllowedSources;
        let refusal = view.guard_held(key).err().or_else(|| {
            (!view.model_source_allowed(source)).then(|| {
                view.refusal(
                    key,
                    CAUSE_POLICY_NOT_ALLOWED,
                    match source {
                        ModelSource::Catalog => {
                            "downloading catalog models is not allowed on this machine"
                        }
                        ModelSource::CustomUrl => {
                            "downloading a model from an address you type is not allowed on this machine"
                        }
                        ModelSource::Import => {
                            "importing a model file is not allowed on this machine"
                        }
                    },
                )
            })
        });
        match refusal {
            Some(refusal) => Err(self.policy_refusal(envelope_id, op, refusal, &view).await),
            None => Ok(()),
        }
    }

    /// Refuses (and audits) choosing or running `agent` as the curator
    /// when `models.allowed_curators` leaves it out (`[]` leaves out every
    /// one). `None` (clearing the pick) is always allowed.
    async fn gate_curator(
        &self,
        envelope_id: &str,
        op: &str,
        agent: Option<AgentId>,
    ) -> Result<(), AdminRefusal> {
        let view: Arc<PolicyView> = self.policy.view();
        let key = Key::ModelsAllowedCurators;
        let refusal = view.guard_held(key).err().or_else(|| {
            agent
                .filter(|agent| !view.curator_allowed(*agent))
                .map(|agent| {
                    view.refusal(
                        key,
                        CAUSE_POLICY_NOT_ALLOWED,
                        &format!("{agent} is not a curator your organisation allows"),
                    )
                })
        });
        match refusal {
            Some(refusal) => Err(self.policy_refusal(envelope_id, op, refusal, &view).await),
            None => Ok(()),
        }
    }
}

/// What `admin.models.import` was asked for, checked for shape only.
pub(crate) struct ImportArgs {
    /// The path as typed, for the reply and the audit row.
    raw: String,
    /// The same, as a path; absolute.
    source: PathBuf,
    /// The vendor directory a non-catalog file lands under.
    vendor: String,
    /// A digest the human supplied for a non-catalog file.
    supplied_sha256: Option<String>,
}

impl ImportArgs {
    pub(crate) fn parse(args: &Value) -> Result<Self, AdminRefusal> {
        if let Some(object) = args.as_object()
            && let Some(stray) = object.keys().find(|key| {
                !["path", "confirm", "vendor", "expected_sha256"].contains(&key.as_str())
            })
        {
            return Err(AdminRefusal {
                cause: CAUSE_INVALID_ADMIN_ARGS,
                detail: format!("{OP_MODELS_IMPORT} does not take {stray:?}"),
                recovery: RECOVERY_FIX_ARGS,
            });
        }
        if args.get("confirm").and_then(Value::as_bool) != Some(true) {
            return Err(AdminRefusal {
                cause: CAUSE_INVALID_ADMIN_ARGS,
                detail: format!("{OP_MODELS_IMPORT} needs \"confirm\": true"),
                recovery: "Import weights through Models; nothing is copied without an explicit request.",
            });
        }
        let raw = required_str(args, "path", OP_MODELS_IMPORT)?.to_owned();
        let source = PathBuf::from(&raw);
        if !source.is_absolute() {
            return Err(AdminRefusal {
                cause: CAUSE_INVALID_ADMIN_ARGS,
                detail: format!("{raw:?} is not an absolute path"),
                recovery: RECOVERY_FIX_ARGS,
            });
        }
        let supplied_sha256 = match args.get("expected_sha256") {
            None | Some(Value::Null) => None,
            Some(value) => Some(
                value
                    .as_str()
                    .filter(|digest| {
                        digest.len() == 64
                            && digest
                                .bytes()
                                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                    })
                    .ok_or_else(|| AdminRefusal {
                        cause: CAUSE_INVALID_ADMIN_ARGS,
                        detail: "expected_sha256 must be 64 lowercase hex characters".to_owned(),
                        recovery: RECOVERY_FIX_ARGS,
                    })?
                    .to_owned(),
            ),
        };
        let vendor = match args.get("vendor") {
            None | Some(Value::Null) => IMPORT_DEFAULT_VENDOR.to_owned(),
            Some(_) => required_str(args, "vendor", OP_MODELS_IMPORT)?.to_owned(),
        };
        Ok(Self {
            raw,
            source,
            vendor,
            supplied_sha256,
        })
    }
}

/// Where an import lands and what it must hash to.
pub(crate) struct ImportTarget {
    pub(crate) dest: PathBuf,
    pub(crate) model_id: String,
    pub(crate) expected_size: Option<u64>,
    pub(crate) expected_sha256: Option<String>,
    /// The catalog preset the file was matched to by size, if any.
    pub(crate) catalog: Option<&'static pam_model::Preset>,
}

/// The trust decision for an import, before any byte is copied. A file
/// whose size is a catalog preset's is that preset: it lands under the
/// preset's vendor and file name and must hash to the preset's digest,
/// whatever vendor or digest the caller named. Any other file lands under
/// the caller's vendor and its own name, held to the supplied digest if any.
pub(crate) fn import_target(
    registry: &pam_model::Registry,
    wanted: &ImportArgs,
    size: Option<u64>,
) -> Result<ImportTarget, AdminRefusal> {
    let catalog = size.and_then(|size| CATALOG.iter().find(|preset| preset.size_bytes == size));
    if let Some(preset) = catalog {
        return Ok(ImportTarget {
            dest: registry.dest_for(preset.vendor, preset.file_name),
            model_id: preset.model_id(),
            expected_size: Some(preset.size_bytes),
            expected_sha256: Some(preset.sha256.to_owned()),
            catalog: Some(preset),
        });
    }
    let file_name = wanted
        .source
        .file_name()
        .and_then(|name| name.to_str())
        .map(str::to_owned)
        .unwrap_or_default();
    let dest = registry
        .checked_dest_for(&wanted.vendor, &file_name)
        .map_err(|error| match error {
            RegistryError::InvalidName(_) => AdminRefusal {
                cause: CAUSE_INVALID_ADMIN_ARGS,
                detail: error.to_string(),
                recovery: RECOVERY_FIX_ARGS,
            },
            other => registry_refusal(other),
        })?;
    let stem = file_name.trim_end_matches(".gguf").to_owned();
    Ok(ImportTarget {
        dest,
        model_id: format!("{}/{stem}", wanted.vendor),
        expected_size: size,
        expected_sha256: wanted.supplied_sha256.clone(),
        catalog: None,
    })
}

/// The vendor CLIs in trusted directories (never the daemon's inherited `PATH`, which
/// may have been shaped by whatever started the daemon), probed off the async threads
/// (detection stats the filesystem and waits on children). The `PATH` is only looked
/// at, to explain a CLI that was refused.
async fn detect_agents() -> Result<Detection, AdminRefusal> {
    let path = std::env::var_os("PATH").unwrap_or_default();
    let home = std::env::var_os("HOME").map(PathBuf::from);
    crate::blocking_jobs::run(crate::blocking_jobs::Kind::AgentDetection, move || {
        let trusted = pam_model::curator::trusted_dirs(home.as_deref());
        pam_model::curator::detect(&trusted, &path, DETECT_DEADLINE)
    })
    .await
    .map_err(blocking_refusal)
}

/// Why `agent` is not offered: the untrusted candidate that was seen, or simply absent.
fn not_detected_detail(detection: &Detection, agent: AgentId) -> String {
    match detection.untrusted.iter().find(|cli| cli.id == agent) {
        Some(cli) => format!(
            "{agent} was found at {} but PAM will not run it: {}",
            cli.path.display(),
            cli.reason
        ),
        None => format!("no {agent} executable in the directories PAM runs CLIs from"),
    }
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

fn diagnostic_refusal(error: ModelUnavailable) -> AdminRefusal {
    match error {
        ModelUnavailable::NotResident { .. } => AdminRefusal {
            cause: CAUSE_MODEL_NOT_LOADED,
            detail: error.to_string(),
            recovery: RECOVERY_LOAD_THAT_MODEL,
        },
        ModelUnavailable::Runtime(error) => runtime_refusal(&error),
        ModelUnavailable::Service(error) => download_refusal(error),
        ModelUnavailable::Store(error) => AdminRefusal::from(error),
        ModelUnavailable::Missing(id) => download_refusal(ModelServiceError::UnknownModel(id)),
        ModelUnavailable::NoDefault(_)
        | ModelUnavailable::Unverified(_)
        | ModelUnavailable::Unqualified(_) => AdminRefusal {
            cause: CAUSE_INTERNAL_ERROR,
            detail: "Explicit diagnostic unexpectedly attempted tier resolution.".to_owned(),
            recovery: RECOVERY_INTERNAL,
        },
    }
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
        // The launcher refused before any transfer existed: a corrupt
        // `net.settings`, a tampered CA copy, a too-old curl. Named, never
        // an internal error, and never answered by a direct connection.
        ModelServiceError::Download(DownloadError::Network(failure)) => AdminRefusal {
            cause: failure.cause(),
            detail: failure.sentence(),
            recovery: failure.recovery(),
        },
        ModelServiceError::Download(DownloadError::ImportSourceMissing(path)) => AdminRefusal {
            cause: CAUSE_IMPORT_SOURCE_MISSING,
            detail: format!("{} does not exist or cannot be read", path.display()),
            recovery: RECOVERY_IMPORT_SOURCE,
        },
        ModelServiceError::Download(DownloadError::ImportSourceRefused { path, reason }) => {
            AdminRefusal {
                cause: CAUSE_IMPORT_SOURCE_REFUSED,
                detail: format!("{} was not imported: {reason}", path.display()),
                recovery: RECOVERY_IMPORT_RULE,
            }
        }
        ModelServiceError::Download(DownloadError::NoSpace { dir, needed, free }) => AdminRefusal {
            cause: CAUSE_NO_SPACE,
            detail: format!(
                "the copy needs {needed} bytes under {} and {} are free",
                dir.display(),
                free.map_or_else(|| "an unknown number".to_owned(), |b| b.to_string())
            ),
            recovery: RECOVERY_IMPORT_SPACE,
        },
        ModelServiceError::Download(other) => AdminRefusal {
            cause: CAUSE_INTERNAL_ERROR,
            detail: format!("the transfer could not be started: {other}"),
            recovery: RECOVERY_INTERNAL,
        },
        ModelServiceError::Blocking { cause, detail } => AdminRefusal {
            cause,
            detail,
            recovery: if cause == "blocking_capacity_exhausted" {
                crate::blocking_jobs::Error::Busy.recovery()
            } else {
                crate::blocking_jobs::Error::Join.recovery()
            },
        },
        ModelServiceError::Registry(err) => registry_refusal(err),
        ModelServiceError::Store(err) => AdminRefusal::from(err),
    }
}

/// A refusal for a runtime failure, keeping the runtime's own cause.
pub(crate) fn runtime_refusal(err: &pam_model::RuntimeError) -> AdminRefusal {
    let recovery = match err {
        pam_model::RuntimeError::NoModelLoaded => RECOVERY_LOAD_A_MODEL,
        pam_model::RuntimeError::LoadFailed(_) => RECOVERY_VERIFY_FILE,
        pam_model::RuntimeError::PromptTooLong { .. } => RECOVERY_SHORTEN_PROMPT,
        pam_model::RuntimeError::Busy => RECOVERY_RETRY_LATER,
        pam_model::RuntimeError::Cancelled => "The generation was cancelled. Try again when ready.",
        pam_model::RuntimeError::EngineExited(_) => RECOVERY_ENGINE_EXITED,
        pam_model::RuntimeError::GenerationFailed(_) => {
            "Keep the error detail and report it with the model file, architecture, quantization and backend from model status. Try a supported model/backend; restarting does not repair incompatible inference kernels."
        }
    };
    AdminRefusal {
        cause: if matches!(err, pam_model::RuntimeError::Busy) {
            "runtime_busy"
        } else {
            err.cause()
        },
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
        RegistryError::InvalidName(_) => AdminRefusal {
            cause: CAUSE_INVALID_ADMIN_ARGS,
            detail: err.to_string(),
            recovery: RECOVERY_FIX_ARGS,
        },
        RegistryError::Changed { .. } => AdminRefusal {
            cause: CAUSE_MODEL_CHANGED,
            detail: err.to_string(),
            recovery: RECOVERY_VERIFY_AGAIN,
        },
        other => AdminRefusal {
            cause: CAUSE_INTERNAL_ERROR,
            detail: format!("the models directory could not be read: {other}"),
            recovery: RECOVERY_INTERNAL,
        },
    }
}

fn blocking_refusal(error: crate::blocking_jobs::Error) -> AdminRefusal {
    AdminRefusal {
        cause: error.cause(),
        detail: error.to_string(),
        recovery: error.recovery(),
    }
}
