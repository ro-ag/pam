//! GUI setup for the pinned llama.cpp engine: status and install.
//!
//! The engine is one exact upstream release, verified by digest and by the
//! build number it reports; see `pam_model::engine`. Installing is a
//! GUI-only action that must be asked for explicitly (`confirm: true`), so
//! no probe or listing ever starts a download.

use pam_model::engine::{self, EngineError, EngineStatus};
use pam_proto::Outcome;
use serde_json::{Value, json};

use crate::admin::{AdminOk, AdminRefusal, AdminService};

/// GUI-only query: pinned tag, target, whether a verified server is present.
pub const OP_ENGINE_STATUS: &str = "admin.models.engine.status";
/// GUI-only install of the pinned release; requires `{ "confirm": true }`.
pub const OP_ENGINE_INSTALL: &str = "admin.models.engine.install";

fn body(status: &EngineStatus) -> Value {
    json!({
        "expected_tag": status.expected_tag,
        "expected_build": status.expected_build,
        "target": status.target.map(engine::Target::name),
        "installed": status.installed,
        "server_path": status.server_path,
        "manifest": status.manifest,
        "cause": status.cause,
    })
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

impl AdminService {
    pub(crate) fn engine_status(&self) -> AdminOk {
        let status = engine::status(&self.models.engine_base());
        AdminOk {
            outcome: Outcome::Verified,
            body: body(&status),
            audit: json!({"op": OP_ENGINE_STATUS, "installed": status.installed}),
        }
    }

    pub(crate) async fn engine_install(&self, args: &Value) -> Result<AdminOk, AdminRefusal> {
        if args.get("confirm").and_then(Value::as_bool) != Some(true) {
            return Err(AdminRefusal {
                cause: "invalid_admin_args",
                detail: format!("{OP_ENGINE_INSTALL} needs \"confirm\": true"),
                recovery: "Install the engine through Models; nothing is downloaded without an explicit request.",
            });
        }
        let base = self.models.engine_base();
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
        // The mirror, when the human set one, changes only where the pinned
        // archive is fetched from; the digest, size and build it is held to
        // are this build's constants.
        let (engine_mirror, _) = self
            .models
            .mirrors()
            .await
            .map_err(|failure| AdminRefusal {
                cause: failure.cause(),
                detail: failure.sentence(),
                recovery: failure.recovery(),
            })?;
        let status = engine::install(&base, cancel, net, engine_mirror.as_ref())
            .await
            .map_err(|error| refusal(&error))?;
        Ok(AdminOk {
            outcome: Outcome::Changed,
            body: body(&status),
            audit: json!({
                "op": OP_ENGINE_INSTALL,
                "tag": status.expected_tag,
                "sha256": status.manifest.as_ref().map(|m| m.sha256.clone()),
            }),
        })
    }
}
