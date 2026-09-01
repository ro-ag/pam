//! One binary, mode by subcommand: client by default, `pam daemon` for the
//! background service, `pam gui` for the desktop control center.
//!
//! The argument handling here is deliberately a bare `match` — the real
//! CLI (clap, subcommands, the request flow built on
//! [`pam::client::ensure_daemon`]) is the client work (task #13). What
//! is wired today is the daemon mode: logging to `~/.pam/log/`, the
//! single-instance boot, ctrl-c → graceful drain, and the
//! version-handshake self-restart (re-spawning the newer binary from
//! disk after the drain).

use std::path::PathBuf;
use std::process::ExitCode;

use pam_daemon::daemon::{DaemonError, run_daemon};
use pam_daemon::lifecycle::{LifecycleError, LifecyclePhase, init_daemon_logging};

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        None => {
            println!(
                "pam {} (protocol v{})",
                env!("CARGO_PKG_VERSION"),
                pam_proto::PROTOCOL_VERSION
            );
            ExitCode::SUCCESS
        }
        Some("daemon") => daemon_mode(),
        Some(other) => {
            eprintln!("pam: unknown mode {other:?} (the full CLI is still being built)");
            ExitCode::from(2)
        }
    }
}

/// `pam daemon`: logging, lock, serve, drain on ctrl-c, self-restart on
/// a version-handshake request.
fn daemon_mode() -> ExitCode {
    let Some(home) = std::env::home_dir() else {
        eprintln!("pam daemon: cannot resolve the home directory to place ~/.pam; set $HOME");
        return ExitCode::FAILURE;
    };
    let base = home.join(".pam");
    let guard = match init_daemon_logging(&base) {
        Ok(guard) => guard,
        Err(err) => {
            eprintln!("pam daemon: {err}");
            return ExitCode::FAILURE;
        }
    };
    let runtime = match tokio::runtime::Runtime::new() {
        Ok(runtime) => runtime,
        Err(err) => {
            eprintln!("pam daemon: cannot start the async runtime: {err}");
            return ExitCode::FAILURE;
        }
    };
    let code = runtime.block_on(serve(base));
    // Flush the daemon log before exit.
    drop(guard);
    code
}

/// Runs the daemon until ctrl-c (graceful drain) or a self-restart
/// request (drain, then hand over to the newer binary on disk).
async fn serve(base: PathBuf) -> ExitCode {
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let handle = match run_daemon(Some(base), shutdown_rx).await {
        Ok(handle) => handle,
        Err(DaemonError::Lifecycle(LifecycleError::AlreadyRunning { pid, .. })) => {
            // Not an error: lazy auto-start races are expected, and the
            // running daemon is exactly what the spawner wanted.
            let holder = pid.map_or_else(|| "pid unknown".to_owned(), |pid| format!("pid {pid}"));
            eprintln!("pam daemon: already running ({holder}); nothing to do");
            return ExitCode::SUCCESS;
        }
        Err(err) => {
            eprintln!("pam daemon: {err}");
            return ExitCode::FAILURE;
        }
    };

    let mut lifecycle = handle.lifecycle();
    let restarting = tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            let _ = shutdown_tx.send(true);
            false
        }
        result = lifecycle.wait_for(|phase| *phase == LifecyclePhase::Restarting) => {
            result.is_ok()
        }
    };
    // Graceful drain; the instance lock is released when the handle is
    // consumed, so the respawned binary can take it.
    handle.shutdown().await;

    if restarting && let Err(err) = respawn_daemon() {
        eprintln!("pam daemon: cannot respawn the new binary: {err}");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}

/// Spawns `current_exe() daemon` detached: the binary on disk is the
/// newer build that triggered the restart.
fn respawn_daemon() -> std::io::Result<()> {
    let exe = std::env::current_exe()?;
    std::process::Command::new(exe)
        .arg("daemon")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map(|_child| ())
}
