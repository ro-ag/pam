//! Login-start commands for Settings › Daemon: thin, blocking-pool
//! wrappers over [`pam_client::service`], the module `pam service …`
//! uses. The report is the module's, serialized as is.

use pam_client::service::{self, CommandRunner, ServiceEnv, ServiceError, ServiceReport};

use crate::bridge::BridgeError;

/// Maps a module failure onto the bridge's refusal shape.
#[must_use]
pub fn bridge_error(err: &ServiceError) -> BridgeError {
    BridgeError::new("service_failed", err.to_string(), err.recovery())
}

/// Which of the three module entry points a command runs.
enum Op {
    Status,
    Install,
    Uninstall,
}

/// Resolves the base dir on the async side, then runs the module's
/// blocking work (file writes, manager commands) off the event loop.
async fn run(op: Op) -> Result<ServiceReport, BridgeError> {
    let base = crate::bridge::resolve_base_dir()?;
    tauri::async_runtime::spawn_blocking(move || {
        let env = ServiceEnv::detect(&base).map_err(|err| bridge_error(&err))?;
        let runner = CommandRunner;
        let result = match op {
            Op::Status => service::status(&env, &runner),
            Op::Install => service::install(&env, &runner),
            Op::Uninstall => service::uninstall(&env, &runner),
        };
        result.map_err(|err| bridge_error(&err))
    })
    .await
    .map_err(|err| {
        BridgeError::new(
            "internal_error",
            format!("the service task failed: {err}"),
            "Retry; report this if it persists.",
        )
    })?
}

/// Whether the login-start unit exists and is loaded.
///
/// # Errors
///
/// [`BridgeError`] when the base dir or the process path cannot be
/// resolved, or a platform manager tool fails.
#[tauri::command]
pub async fn service_status() -> Result<ServiceReport, BridgeError> {
    run(Op::Status).await
}

/// Registers the unit and starts the managed daemon.
///
/// # Errors
///
/// [`BridgeError`] when the unit cannot be written or its manager
/// refuses to register it.
#[tauri::command]
pub async fn service_install() -> Result<ServiceReport, BridgeError> {
    run(Op::Install).await
}

/// Unregisters and removes the unit; on macOS and Linux the manager
/// stops the managed daemon with it (the report's note says so).
///
/// # Errors
///
/// [`BridgeError`] when the unit cannot be removed or its manager
/// refuses to unregister it.
#[tauri::command]
pub async fn service_uninstall() -> Result<ServiceReport, BridgeError> {
    run(Op::Uninstall).await
}
