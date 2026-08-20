#![forbid(unsafe_code)]

mod commands;

#[cfg(test)]
mod commands_test;

use std::error::Error;
use std::path::PathBuf;

use commands::DesktopState;
use pam_gui::DesktopCore;

/// Runs the local PAM Tauri application.
///
/// # Errors
///
/// Returns an error when the process environment cannot be resolved or Tauri
/// cannot start the platform webview runtime.
pub fn run() -> Result<(), Box<dyn Error>> {
    let startup_root = std::env::current_dir()?;
    let core = DesktopCore::with_daemon_executable(startup_root, daemon_executable()?);

    tauri::Builder::default()
        .manage(DesktopState::new(core))
        .invoke_handler(tauri::generate_handler![
            commands::bootstrap,
            commands::catalog,
            commands::activate_project,
            commands::refresh_project,
            commands::start_daemon,
            commands::stop_daemon,
            commands::register_gui_caller,
            commands::decide_approval,
            commands::load_evidence,
            commands::load_flow_workspace,
            commands::open_flow,
            commands::validate_flow,
            commands::save_flow,
        ])
        .run(tauri::generate_context!())?;
    Ok(())
}

fn daemon_executable() -> Result<PathBuf, std::io::Error> {
    let directory = std::env::current_exe()?
        .parent()
        .map(PathBuf::from)
        .ok_or_else(|| std::io::Error::other("PAM executable has no parent directory"))?;
    Ok(directory.join(if cfg!(windows) { "pam.exe" } else { "pam" }))
}
