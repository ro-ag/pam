//! GUI setup for the pinned llama.cpp engine: status, install, import,
//! remove.
//!
//! The engine is one exact upstream release, verified by digest and by the
//! build number it reports; see `pam_model::engine`. Every way of supplying
//! it — the upstream host, the human's mirror, a file on this machine — is
//! held to the same compiled-in asset name, size, SHA-256 and build: no
//! argument names a digest, a tag or a URL, and the four ops here refuse
//! any key they do not list ([`CAUSE_INVALID_ADMIN_ARGS`]). Installing,
//! importing and removing are GUI-only actions that must be asked for
//! explicitly (`confirm: true`), so no probe or listing ever starts a
//! download or deletes a file. [`OP_ENGINE_STATUS`] discloses, before any
//! click, exactly what Install would fetch and check.
//!
//! The managed policy's `models.engine_source` decides whether Install is open at all: `import_only`
//! refuses it, and `mirror_only` refuses it unless an engine mirror is in force, in both cases before
//! any network profile is resolved, so upstream is never contacted. Import stays open (it needs
//! `import` among `models.allowed_sources`). [`OP_ENGINE_STATUS`] carries a `source_policy` block
//! saying which of the two is open and why.

use std::path::{Path, PathBuf};

use pam_model::engine::{self, EngineError, EngineRelease, EngineStatus};
use pam_net::MirrorBase;
use pam_proto::Outcome;
use serde_json::{Value, json};

use crate::admin::{
    AdminOk, AdminRefusal, AdminService, CAUSE_INVALID_ADMIN_ARGS, RECOVERY_FIX_ARGS,
};
use crate::managed_policy::{CAUSE_POLICY_NOT_ALLOWED, EngineSource, Key, ModelSource};
use crate::network_service::Source;

/// GUI-only query: pinned tag, target, whether a verified server is present,
/// and what an install would fetch.
pub const OP_ENGINE_STATUS: &str = "admin.models.engine.status";
/// GUI-only install of the pinned release; requires `{ "confirm": true }`.
pub const OP_ENGINE_INSTALL: &str = "admin.models.engine.install";
/// GUI-only install of the pinned release from a file on this machine;
/// requires `{ "path": "...", "confirm": true }`.
pub const OP_ENGINE_IMPORT: &str = "admin.models.engine.import";
/// GUI-only removal of everything under the engine directory; requires
/// `{ "confirm": true }`.
pub const OP_ENGINE_REMOVE: &str = "admin.models.engine.remove";

/// Refusal cause: a model is loaded, and the engine under it would be
/// replaced or removed.
pub const CAUSE_ENGINE_BUSY: &str = "engine_busy";

/// Recovery line for an engine that is in use.
const RECOVERY_UNLOAD_FIRST: &str =
    "Unload the model on the PAM GUI Models screen, then retry the engine action.";

/// Recovery line for a file that is not the pinned archive.
const RECOVERY_GIVE_THE_ASSET: &str = "Give the path of the release archive named in the detail (or a folder that holds it under that exact name), downloaded from the address the engine card shows and checked against its SHA-256.";

/// Recovery line for an archive whose bytes are not the pinned ones.
const RECOVERY_WRONG_BYTES: &str = "Download the archive again from the address the engine card shows and check its SHA-256 against the value there; PAM installs that release and no other.";

/// The upstream host, for the "(upstream is …)" line of the card.
fn upstream_host() -> String {
    engine::ENGINE_RELEASE_BASE
        .trim_start_matches("https://")
        .split('/')
        .next()
        .unwrap_or_default()
        .to_owned()
}

/// The status body: the engine's state, and the disclosure of what an
/// install would do (asset, size, digest, the exact URL and host, whether
/// the mirror is in use), where it lives, where it came from, and whether
/// Remove is possible right now.
fn body(
    status: &EngineStatus,
    release: Option<&EngineRelease>,
    mirror: Option<&MirrorBase>,
    engine_dir: &Path,
    loaded: bool,
    network_issue: Option<AdminRefusal>,
) -> Value {
    let download_url = release.and_then(|release| release.url(mirror).ok());
    let mut body = json!({
        "expected_tag": status.expected_tag,
        "expected_build": status.expected_build,
        "target": status.target.map(engine::Target::name),
        "installed": status.installed,
        "server_path": status.server_path,
        "manifest": status.manifest,
        "cause": status.cause,
        "expected_asset": release.map(|release| release.asset_name.clone()),
        "expected_size": release.map(|release| release.bytes),
        "expected_sha256": release.map(|release| release.sha256.clone()),
        "download_url": download_url,
        "download_host": release.map(|release| release.host(mirror)),
        "mirror_in_use": mirror.is_some(),
        "mirror_host": mirror.map(|mirror| mirror.host().to_owned()),
        "upstream_host": upstream_host(),
        "engine_dir": engine_dir.display().to_string(),
        "install_dir": engine::EngineLayout::new(engine_dir.parent().unwrap_or(engine_dir))
            .install_dir(&status.expected_tag)
            .display()
            .to_string(),
        "source": status.manifest.as_ref().and_then(|manifest| manifest.source.clone()),
        "loaded": loaded,
        "removable": !loaded && engine_dir_has_content(engine_dir),
    });
    if let Some(issue) = network_issue {
        body["network_issue"] = json!({
            "cause": issue.cause,
            "detail": issue.detail,
            "recovery": issue.recovery,
        });
    }
    body
}

/// Whether anything sits under the engine directory for Remove to delete.
fn engine_dir_has_content(engine_dir: &Path) -> bool {
    std::fs::read_dir(engine_dir).is_ok_and(|mut entries| entries.next().is_some())
}

fn refusal(error: &EngineError) -> AdminRefusal {
    let (cause, recovery): (&'static str, &'static str) = match error {
        EngineError::UnsupportedTarget { .. } => (
            "engine_unsupported_target",
            "This operating system and CPU have no pinned llama.cpp release; local inference is unavailable here.",
        ),
        EngineError::Download { .. } => (
            "engine_download_failed",
            "Check the network and retry the install; a partial transfer resumes.",
        ),
        EngineError::Cancelled => ("engine_install_cancelled", "Retry the install."),
        EngineError::Unpack { .. } => (
            "engine_unpack_failed",
            "The operating system's tar could not unpack the release; check the engine directory and retry.",
        ),
        EngineError::Verify { .. } => (
            "engine_verify_failed",
            "The unpacked server did not report the pinned build and was discarded; retry the install.",
        ),
        EngineError::Io { .. } => (
            "engine_io_failed",
            "Check permissions on the engine directory under the PAM base directory and retry.",
        ),
        EngineError::SourceMissing { .. } => (
            "engine_import_source_missing",
            "Check the path; it must be readable by the user the PAM daemon runs as.",
        ),
        EngineError::NotTheAsset { .. } => ("engine_import_not_the_asset", RECOVERY_GIVE_THE_ASSET),
        EngineError::SourceSymlink { .. } => ("engine_import_symlink", RECOVERY_GIVE_THE_ASSET),
        EngineError::SourceInsideEngineDir { .. } => (
            "engine_import_inside_engine_dir",
            "Move the archive outside PAM's engine directory and import it from there.",
        ),
        EngineError::SizeMismatch { .. } => ("engine_size_mismatch", RECOVERY_WRONG_BYTES),
        EngineError::DigestMismatch { .. } => ("engine_digest_mismatch", RECOVERY_WRONG_BYTES),
        EngineError::NoSpace { .. } => (
            "engine_no_space",
            "Free the bytes named in the detail on the volume holding PAM's base directory, then retry.",
        ),
    };
    AdminRefusal {
        cause,
        detail: error.to_string(),
        recovery,
    }
}

/// The cancel signal an install runs under: fires when the owning admin
/// future is dropped (deadline, disconnected client).
pub(crate) fn install_cancellation() -> (
    crate::model_service::CancelOnDrop,
    tokio::sync::watch::Receiver<bool>,
) {
    crate::model_service::CancelOnDrop::new()
}

/// Refuses any key of `args` outside `allowed`: the ops here take no
/// digest, tag, build, URL or size from anyone.
fn only_keys(args: &Value, allowed: &[&str], op: &str) -> Result<(), AdminRefusal> {
    let Some(object) = args.as_object() else {
        return Err(AdminRefusal {
            cause: CAUSE_INVALID_ADMIN_ARGS,
            detail: format!("{op} takes an object of arguments"),
            recovery: RECOVERY_FIX_ARGS,
        });
    };
    if let Some(stray) = object.keys().find(|key| !allowed.contains(&key.as_str())) {
        return Err(AdminRefusal {
            cause: CAUSE_INVALID_ADMIN_ARGS,
            detail: format!(
                "{op} does not take {stray:?}; the release, its digest and its address are fixed in this build of PAM"
            ),
            recovery: RECOVERY_FIX_ARGS,
        });
    }
    Ok(())
}

/// `confirm: true`, or a refusal naming what the op would have done.
fn confirmed(args: &Value, op: &str, would: &str) -> Result<(), AdminRefusal> {
    if args.get("confirm").and_then(Value::as_bool) == Some(true) {
        return Ok(());
    }
    Err(AdminRefusal {
        cause: CAUSE_INVALID_ADMIN_ARGS,
        detail: format!("{op} needs \"confirm\": true"),
        recovery: match would {
            "remove" => {
                "Remove the engine through Models; nothing is deleted without an explicit request."
            }
            _ => {
                "Install the engine through Models; nothing is downloaded or copied without an explicit request."
            }
        },
    })
}

impl AdminService {
    /// The managed policy's verdict on an install. `import_only` refuses
    /// it; `mirror_only` refuses it unless an engine mirror is in force
    /// (so upstream is never contacted); `download` leaves the choice to
    /// the settings. A refusal is audited on this request.
    async fn gate_engine_install(&self, envelope_id: &str) -> Result<(), AdminRefusal> {
        let view = self.policy.view();
        let key = Key::ModelsEngineSource;
        let what = match view.engine_source() {
            EngineSource::Download => return Ok(()),
            EngineSource::ImportOnly => {
                "this machine installs the engine only from a file you import, not from the network"
            }
            EngineSource::MirrorOnly => {
                if self.engine_mirror().await?.is_some() {
                    return Ok(());
                }
                "this machine installs the engine only through an engine mirror, and none is configured"
            }
        };
        let refusal = view.refusal(key, CAUSE_POLICY_NOT_ALLOWED, what);
        Err(self
            .policy_refusal(envelope_id, OP_ENGINE_INSTALL, refusal, &view)
            .await)
    }

    /// The `source_policy` block of the engine status: what
    /// `models.engine_source` allows right now, and why an install would
    /// be refused.
    fn engine_source_policy(&self, mirror_in_force: bool) -> Value {
        let view = self.policy.view();
        let source = view.engine_source();
        let install_blocked = match source {
            EngineSource::Download => None,
            EngineSource::ImportOnly => Some("import_only"),
            EngineSource::MirrorOnly if mirror_in_force => None,
            EngineSource::MirrorOnly => Some("mirror_missing"),
        };
        let entry = crate::connector_service::plain_entry(
            &view,
            Key::ModelsEngineSource,
            if view
                .status(Key::ModelsEngineSource)
                .is_some_and(crate::managed_policy::LeafStatus::in_force)
            {
                Source::Policy
            } else {
                Source::Default
            },
            false,
            Some(serde_json::json!({ "engine_source": source.as_str() })),
        );
        json!({
            "engine_source": source.as_str(),
            "install_allowed": install_blocked.is_none(),
            "install_blocked": install_blocked,
            "import_allowed": view.model_source_allowed(ModelSource::Import),
            "effective": entry.to_json(),
        })
    }

    /// The engine mirror the next install would fetch from, when the
    /// human set one; settings that cannot be used are reported, not used.
    async fn engine_mirror(&self) -> Result<Option<MirrorBase>, AdminRefusal> {
        self.models
            .mirrors()
            .await
            .map(|(engine_mirror, _)| engine_mirror)
            .map_err(|failure| AdminRefusal {
                cause: failure.cause(),
                detail: failure.sentence(),
                recovery: failure.recovery(),
            })
    }

    /// Whether a model is loaded on the engine right now.
    fn engine_loaded(&self) -> bool {
        matches!(
            self.models.snapshot().state,
            pam_model::runtime::RuntimeState::Loaded(_)
        )
    }

    /// Refuses when the engine under a loaded model would be replaced or
    /// removed. Checked before any file is touched.
    fn refuse_if_loaded(&self, what: &str) -> Result<(), AdminRefusal> {
        if self.engine_loaded() {
            return Err(AdminRefusal {
                cause: CAUSE_ENGINE_BUSY,
                detail: format!(
                    "a model is loaded on the engine; PAM does not {what} an engine in use"
                ),
                recovery: RECOVERY_UNLOAD_FIRST,
            });
        }
        Ok(())
    }

    /// The status body for the current state, with the disclosure fields.
    async fn engine_body(&self, status: &EngineStatus) -> Value {
        let (mirror, network_issue) = match self.engine_mirror().await {
            Ok(mirror) => (mirror, None),
            Err(issue) => (None, Some(issue)),
        };
        let source_policy = self.engine_source_policy(mirror.is_some());
        let mut value = body(
            status,
            self.models.engine_release().as_ref(),
            mirror.as_ref(),
            &self.models.engine_base().join("engine"),
            self.engine_loaded(),
            network_issue,
        );
        value["source_policy"] = source_policy;
        value
    }

    pub(crate) async fn engine_status(&self, args: &Value) -> Result<AdminOk, AdminRefusal> {
        only_keys(args, &[], OP_ENGINE_STATUS)?;
        let status = engine::status(&self.models.engine_base());
        Ok(AdminOk {
            outcome: Outcome::Verified,
            body: self.engine_body(&status).await,
            audit: json!({"op": OP_ENGINE_STATUS, "installed": status.installed}),
        })
    }

    pub(crate) async fn engine_install(
        &self,
        envelope_id: &str,
        args: &Value,
    ) -> Result<AdminOk, AdminRefusal> {
        only_keys(args, &["confirm"], OP_ENGINE_INSTALL)?;
        confirmed(args, OP_ENGINE_INSTALL, "install")?;
        // The managed policy's `models.engine_source` is decided before
        // anything else happens: a refused install resolves no network
        // profile and opens no socket.
        self.gate_engine_install(envelope_id).await?;
        let base = self.models.engine_base();
        if !engine::status(&base).installed {
            self.refuse_if_loaded("replace")?;
        }
        // The install runs under the admin deadline: when that drops this
        // future, the guard sends `true` so the transfer stops instead of
        // running detached behind a closed channel.
        let (_cancel_on_drop, cancel) = install_cancellation();
        // The archive is fetched under the network profile downloads use;
        // a profile that cannot be used refuses here, never falls back.
        let net = self
            .models
            .network_settings()
            .await
            .map_err(|failure| AdminRefusal {
                cause: failure.cause(),
                detail: failure.sentence(),
                recovery: failure.recovery(),
            })?;
        // The mirror, when the human or the policy set one, changes only
        // where the pinned archive is fetched from; the digest, size and
        // build it is held to are this build's constants.
        let engine_mirror = self.engine_mirror().await?;
        let status = self
            .run_install(&base, cancel, net, engine_mirror.as_ref())
            .await
            .map_err(|error| refusal(&error))?;
        let source = status
            .manifest
            .as_ref()
            .and_then(|manifest| manifest.source.clone());
        Ok(AdminOk {
            outcome: Outcome::Changed,
            body: self.engine_body(&status).await,
            audit: json!({
                "op": OP_ENGINE_INSTALL,
                "tag": status.expected_tag,
                "sha256": status.manifest.as_ref().map(|m| m.sha256.clone()),
                "source": source,
            }),
        })
    }

    /// `engine::install` for the pinned release; in test builds, the
    /// release the test pinned, fetched over the plain-http allowance.
    async fn run_install(
        &self,
        base: &Path,
        cancel: tokio::sync::watch::Receiver<bool>,
        net: std::sync::Arc<pam_net::NetSettings>,
        mirror: Option<&MirrorBase>,
    ) -> Result<EngineStatus, EngineError> {
        #[cfg(test)]
        if let Some(release) = self.models.engine_release()
            && release.sha256 != engine::Target::current().map_or("", |t| t.asset().sha256)
        {
            return engine::install_release_over_plain_http_for_tests(
                base, &release, cancel, net, mirror,
            )
            .await;
        }
        engine::install(base, cancel, net, mirror).await
    }

    /// `engine::import` for the pinned release; in test builds, the
    /// release the test pinned.
    async fn run_import(
        &self,
        base: &Path,
        path: &Path,
        cancel: tokio::sync::watch::Receiver<bool>,
    ) -> Result<EngineStatus, EngineError> {
        #[cfg(test)]
        if let Some(release) = self.models.engine_release()
            && release.sha256 != engine::Target::current().map_or("", |t| t.asset().sha256)
        {
            return engine::import_release(base, &release, path, cancel).await;
        }
        engine::import(base, path, cancel).await
    }

    /// Installs the pinned release from a file on this machine. No network
    /// profile is resolved and no curl runs: the archive is copied, hashed
    /// and held to the compiled-in size and digest, then unpacked and
    /// checked like a downloaded one.
    pub(crate) async fn engine_import(
        &self,
        envelope_id: &str,
        args: &Value,
    ) -> Result<AdminOk, AdminRefusal> {
        only_keys(args, &["confirm", "path"], OP_ENGINE_IMPORT)?;
        confirmed(args, OP_ENGINE_IMPORT, "import")?;
        // `engine_source: import_only` leaves this op open; the sources the
        // organization allows decide whether a local file may come in.
        self.gate_model_source(envelope_id, OP_ENGINE_IMPORT, ModelSource::Import)
            .await?;
        let raw = crate::admin::required_str(args, "path", OP_ENGINE_IMPORT)?;
        let path = PathBuf::from(raw);
        if !path.is_absolute() {
            return Err(AdminRefusal {
                cause: CAUSE_INVALID_ADMIN_ARGS,
                detail: format!("{raw:?} is not an absolute path"),
                recovery: RECOVERY_FIX_ARGS,
            });
        }
        let base = self.models.engine_base();
        if !engine::status(&base).installed {
            self.refuse_if_loaded("replace")?;
        }
        let (_cancel_on_drop, cancel) = install_cancellation();
        let status = self
            .run_import(&base, &path, cancel)
            .await
            .map_err(|error| refusal(&error))?;
        Ok(AdminOk {
            outcome: Outcome::Changed,
            body: self.engine_body(&status).await,
            audit: json!({
                "op": OP_ENGINE_IMPORT,
                "tag": status.expected_tag,
                "sha256": status.manifest.as_ref().map(|m| m.sha256.clone()),
                "path": raw,
            }),
        })
    }

    /// Deletes everything under the engine directory. Refused while a
    /// model is loaded; the models directory is never touched.
    pub(crate) async fn engine_remove(&self, args: &Value) -> Result<AdminOk, AdminRefusal> {
        only_keys(args, &["confirm"], OP_ENGINE_REMOVE)?;
        confirmed(args, OP_ENGINE_REMOVE, "remove")?;
        // Serialized with loads and deletes: a load admitted after this
        // check would otherwise start a server whose files are going away.
        let _operation = self.models.operation.lock().await;
        self.refuse_if_loaded("remove")?;
        self.models.forget_engine();
        let base = self.models.engine_base();
        let report =
            crate::blocking_jobs::run(crate::blocking_jobs::Kind::ModelFilesystem, move || {
                engine::remove(&base)
            })
            .await
            .map_err(|error| AdminRefusal {
                cause: error.cause(),
                detail: error.to_string(),
                recovery: error.recovery(),
            })?
            .map_err(|error| refusal(&error))?;
        let status = engine::status(&self.models.engine_base());
        Ok(AdminOk {
            outcome: Outcome::Changed,
            body: json!({
                "removed": true,
                "engine_dir": report.engine_dir.display().to_string(),
                "entries_removed": report.removed.len(),
                "status": self.engine_body(&status).await,
            }),
            audit: json!({
                "op": OP_ENGINE_REMOVE,
                "engine_dir": report.engine_dir.display().to_string(),
                "removed": report.removed,
            }),
        })
    }
}
