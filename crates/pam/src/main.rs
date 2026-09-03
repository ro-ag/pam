//! One binary, mode by subcommand: client by default, `pam daemon` for the
//! background service, `pam gui` for the desktop control center.
//!
//! The CLI surface is deliberately static — agents interact exclusively
//! through these subcommands (no raw-protocol escape hatch), and there
//! are **no security commands**: grants, approvals, revocations, and
//! profile changes live in the GUI only. See the crate docs in
//! [`pam`] (`lib.rs`) for the subcommand list and the exit-code table.

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use clap::{Parser, Subcommand};
use pam::client::{self, StopOutcome};
use pam::render;
use pam::request::{DEFAULT_DEADLINE_MS, parse_args_object};
use pam_daemon::daemon::{DaemonError, run_daemon};
use pam_daemon::lifecycle::{LifecycleError, LifecyclePhase, init_daemon_logging};
use pam_proto::{Event, Response};

/// Exit code for usage errors.
const EXIT_USAGE: u8 = 2;

/// How long `pam daemon stop` waits for the daemon's drain to finish.
const STOP_WAIT: Duration = Duration::from_secs(15);

/// Default bound on `pam wait` / `pam subscribe`, in milliseconds
/// (10 minutes — [`pam::client::DEFAULT_FOLLOW_TIMEOUT`]).
const DEFAULT_TIMEOUT_MS: u64 = 600_000;

/// Default deadline for `pam flow run`, in milliseconds (30 minutes): a
/// flow that runs `cargo test` is not a 60 s request.
const FLOW_DEADLINE_MS: u64 = 1_800_000;

#[derive(Parser)]
#[command(
    name = "pam",
    version,
    about = "A local lifeguard for developers and AI agents.",
    arg_required_else_help = true
)]
struct Cli {
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Show the daemon's health snapshot.
    Status {
        /// Print the raw response JSON instead of the summary.
        #[arg(long)]
        json: bool,
    },
    /// Diagnostic capability: mirror JSON-object args back through the
    /// daemon (for testing pam itself).
    Echo {
        /// Capability arguments as a JSON object (default `{}`).
        args_json: Option<String>,
        /// Wait for the result (the default).
        #[arg(long, overrides_with = "no_wait")]
        wait: bool,
        /// Return a ticket immediately instead of waiting.
        #[arg(long)]
        no_wait: bool,
        /// Deadline for the request, in milliseconds.
        #[arg(long, default_value_t = DEFAULT_DEADLINE_MS)]
        deadline_ms: u64,
        /// Print the raw response JSON.
        #[arg(long)]
        json: bool,
    },
    /// Cancel a queued or running request by its ticket id.
    Cancel {
        /// The ticket to cancel.
        ticket: String,
        /// Print the raw response JSON.
        #[arg(long)]
        json: bool,
    },
    /// Block until a ticket reaches its terminal event (quiet).
    Wait {
        /// The ticket to wait for.
        ticket: String,
        /// Give up after this many milliseconds.
        #[arg(long, default_value_t = DEFAULT_TIMEOUT_MS)]
        timeout_ms: u64,
    },
    /// Stream a ticket's events until its terminal event.
    Subscribe {
        /// The ticket to follow.
        ticket: String,
        /// Give up after this many milliseconds.
        #[arg(long, default_value_t = DEFAULT_TIMEOUT_MS)]
        timeout_ms: u64,
    },
    /// List, read, and run the flows this machine has.
    Flow {
        #[command(subcommand)]
        action: FlowCmd,
    },
    /// Run the pam daemon in the foreground.
    Daemon {
        #[command(subcommand)]
        action: Option<DaemonCmd>,
    },
    /// Open the desktop control center.
    Gui,
}

#[derive(Subcommand)]
enum DaemonCmd {
    /// Signal the running daemon to drain and exit.
    Stop,
}

/// `pam flow`: the flow library, and one run of one flow.
#[derive(Subcommand)]
enum FlowCmd {
    /// List the flows this machine has: id, source, steps, and name.
    List {
        /// Print the raw response JSON instead of the table.
        #[arg(long)]
        json: bool,
    },
    /// Print one flow's canonical YAML.
    Show {
        /// The flow id, as `pam flow list` spells it.
        id: String,
    },
    /// Run one flow and print its verdict.
    ///
    /// The whole run happens in one request and nothing is printed until
    /// it finishes: there are no live step lines here. To watch a run as
    /// it goes, start it with `--no-wait` and follow the ticket it prints
    /// with `pam subscribe <ticket>`.
    Run {
        /// The flow id, as `pam flow list` spells it.
        id: String,
        /// Values for the flow's declared inputs, as `key=value`.
        inputs: Vec<String>,
        /// Return a ticket immediately instead of waiting for the verdict.
        #[arg(long)]
        no_wait: bool,
        /// Deadline for the run, in milliseconds (default 30 minutes).
        #[arg(long, default_value_t = FLOW_DEADLINE_MS)]
        deadline_ms: u64,
        /// Print the raw response JSON.
        #[arg(long)]
        json: bool,
    },
}

fn main() -> ExitCode {
    if bare_bundle_launch() {
        return gui_mode();
    }
    match Cli::parse().command {
        Cmd::Daemon { action: None } => daemon_mode(),
        Cmd::Daemon {
            action: Some(DaemonCmd::Stop),
        } => daemon_stop(),
        Cmd::Gui => gui_mode(),
        command => client_mode(command),
    }
}

/// A bare launch (no arguments) from inside a macOS `.app` bundle is a
/// double-click: open the GUI instead of printing help. Every other
/// platform, and any bare terminal launch, stays in client mode.
fn bare_bundle_launch() -> bool {
    cfg!(target_os = "macos")
        && std::env::args_os().nth(1).is_none()
        && std::env::current_exe().is_ok_and(|exe| pam::launched_from_app_bundle(&exe))
}

/// `pam gui`: hands the process to the Tauri event loop (must run on the
/// main thread, before any async runtime exists) until the window closes.
///
/// The context (config, icons, capabilities) is generated from this
/// crate's `tauri.conf.json`; which frontend the window loads is a
/// compile-time property of the binary (`tauri build`, or
/// `--features gui-embed`, embed `frontend/dist`; plain builds load the
/// Vite dev server). See the [`pam_gui`] crate docs.
fn gui_mode() -> ExitCode {
    match pam_gui::run(tauri::generate_context!()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("pam gui: {err}");
            ExitCode::FAILURE
        }
    }
}

/// The base directory every mode works under: `$PAM_BASE_DIR` when set
/// and non-empty, otherwise `~/.pam` (see [`pam::default_base_dir`] —
/// shared with the GUI bridge so both resolve the same base).
fn base_dir() -> Option<PathBuf> {
    pam::default_base_dir()
}

/// Runs one client subcommand on a fresh runtime against `~/.pam`.
fn client_mode(command: Cmd) -> ExitCode {
    let Some(base) = base_dir() else {
        eprintln!("pam: cannot resolve the home directory to place ~/.pam; set $HOME");
        return ExitCode::FAILURE;
    };
    let runtime = match tokio::runtime::Runtime::new() {
        Ok(runtime) => runtime,
        Err(err) => {
            eprintln!("pam: cannot start the async runtime: {err}");
            return ExitCode::FAILURE;
        }
    };
    runtime.block_on(run_client_command(&base, command))
}

/// Dispatches one client subcommand (`Daemon` and `Gui` never reach
/// here).
async fn run_client_command(base: &Path, command: Cmd) -> ExitCode {
    match command {
        Cmd::Status { json } => {
            request(base, "status", serde_json::json!({}), true, None, json).await
        }
        Cmd::Echo {
            args_json,
            no_wait,
            deadline_ms,
            json,
            ..
        } => {
            let args = match parse_args_object(args_json.as_deref()) {
                Ok(args) => args,
                Err(err) => {
                    eprintln!("pam echo: {err}");
                    return ExitCode::from(EXIT_USAGE);
                }
            };
            request(base, "echo", args, !no_wait, Some(deadline_ms), json).await
        }
        Cmd::Cancel { ticket, json } => {
            let args = serde_json::json!({ "ticket": ticket });
            request(base, "cancel", args, true, None, json).await
        }
        Cmd::Wait { ticket, timeout_ms } => follow(base, &ticket, timeout_ms, false).await,
        Cmd::Subscribe { ticket, timeout_ms } => follow(base, &ticket, timeout_ms, true).await,
        Cmd::Flow { action } => run_flow_command(base, action).await,
        Cmd::Daemon { .. } | Cmd::Gui => unreachable!("handled in main"),
    }
}

/// Dispatches one `pam flow` subcommand onto its capability.
///
/// `run` sends `wait: !no_wait`: a waiting run answers with the verdict
/// body [`render::render_flow_result`] prints, and `--no-wait` answers
/// with the ticket line — which is also the way to watch a run step by
/// step, through `pam subscribe`.
async fn run_flow_command(base: &Path, action: FlowCmd) -> ExitCode {
    match action {
        FlowCmd::List { json } => {
            request(base, "flow.list", serde_json::json!({}), true, None, json).await
        }
        FlowCmd::Show { id } => {
            let args = serde_json::json!({ "id": id });
            request(base, "flow.show", args, true, None, false).await
        }
        FlowCmd::Run {
            id,
            inputs,
            no_wait,
            deadline_ms,
            json,
        } => {
            let inputs = match render::parse_flow_inputs(&inputs) {
                Ok(inputs) => inputs,
                Err(err) => {
                    eprintln!("pam flow run: {err}");
                    return ExitCode::from(EXIT_USAGE);
                }
            };
            let args = serde_json::json!({ "id": id, "inputs": inputs });
            request(base, "flow.run", args, !no_wait, Some(deadline_ms), json).await
        }
    }
}

/// Sends one capability request and renders its response.
async fn request(
    base: &Path,
    capability: &str,
    args: serde_json::Value,
    wait: bool,
    deadline_ms: Option<u64>,
    json: bool,
) -> ExitCode {
    let deadline_ms = deadline_ms.unwrap_or(DEFAULT_DEADLINE_MS);
    match client::send_request(base, capability, args, wait, deadline_ms, None).await {
        Ok(response) => print_response(capability, &response, json),
        Err(err) => {
            eprintln!("pam {capability}: {err}");
            ExitCode::FAILURE
        }
    }
}

/// Prints a response — raw JSON with `--json`, humane text otherwise —
/// and maps it to the documented exit code either way. Refusals go to
/// stderr; everything else to stdout.
fn print_response(capability: &str, response: &Response, json: bool) -> ExitCode {
    let code = ExitCode::from(render::exit_code(response));
    if json {
        println!("{}", render::render_json(response));
        return code;
    }
    match response {
        Response::Result { body, .. } if capability == "status" => {
            println!("{}", render::render_status(body));
        }
        Response::Result { body, .. } if capability == "flow.list" => {
            println!("{}", render::render_flow_list(body));
        }
        Response::Result { body, .. } if capability == "flow.show" => {
            println!("{}", render::render_flow_show(body));
        }
        Response::Result { body, .. } if capability == "flow.run" => {
            println!("{}", render::render_flow_result(body));
        }
        Response::Result { body, .. } => println!("{}", render::render_body(body)),
        Response::Refusal {
            cause,
            detail,
            recovery,
            ..
        } => eprintln!("{}", render::render_refusal(cause, detail, recovery)),
        Response::Ticket {
            ticket, position, ..
        } => println!("{}", render::render_ticket(ticket, *position)),
    }
    code
}

/// `pam wait` / `pam subscribe`: one code path following the ticket's
/// event stream — subscribe prints every event, wait only the terminal
/// one. Exit code: `done` → 0, `refused` → 3, timeout or transport → 1.
async fn follow(base: &Path, ticket: &str, timeout_ms: u64, verbose: bool) -> ExitCode {
    let timeout = Duration::from_millis(timeout_ms);
    let on_event = |event: &Event| {
        if verbose {
            println!("{}", render::render_event(event));
        }
    };
    match client::follow_ticket(base, ticket, timeout, on_event).await {
        Ok(terminal) => {
            if !verbose {
                println!("{}", render::render_event(&terminal));
            }
            if matches!(terminal, Event::Refused) {
                ExitCode::from(render::EXIT_REFUSED)
            } else {
                ExitCode::SUCCESS
            }
        }
        Err(err) => {
            eprintln!("pam wait: {err}");
            ExitCode::FAILURE
        }
    }
}

/// `pam daemon stop`: name the lock holder, send it SIGTERM (unix), and
/// wait — bounded — for the drain to release the lock. The mechanics
/// live in [`client::stop_daemon`], shared with the GUI bridge.
fn daemon_stop() -> ExitCode {
    let Some(base) = base_dir() else {
        eprintln!("pam daemon stop: cannot resolve the home directory; set $HOME");
        return ExitCode::FAILURE;
    };
    match client::stop_daemon(&base, STOP_WAIT) {
        Ok(StopOutcome::NotRunning) => {
            println!("pam daemon stop: no daemon is running");
            ExitCode::SUCCESS
        }
        Ok(StopOutcome::Stopped { pid }) => {
            println!("pam daemon stopped (pid {pid})");
            ExitCode::SUCCESS
        }
        Ok(StopOutcome::StillDraining { pid }) => {
            eprintln!(
                "pam daemon stop: the daemon (pid {pid}) is still draining after {STOP_WAIT:?}; \
                 it exits when the drain completes"
            );
            ExitCode::FAILURE
        }
        Err(err) => {
            eprintln!("pam daemon stop: {err}");
            ExitCode::FAILURE
        }
    }
}

/// `pam daemon`: logging, lock, serve, drain on ctrl-c / SIGTERM, and
/// the version-handshake self-restart.
fn daemon_mode() -> ExitCode {
    let Some(base) = base_dir() else {
        eprintln!("pam daemon: cannot resolve the home directory to place ~/.pam; set $HOME");
        return ExitCode::FAILURE;
    };
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

/// Runs the daemon until a shutdown signal (graceful drain) or a
/// self-restart request (drain, then hand over to the newer binary on
/// disk).
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
        () = shutdown_signal() => {
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

/// Resolves on ctrl-c (SIGINT), or on SIGTERM on unix — the signal
/// `pam daemon stop` sends. Both trigger the same graceful drain.
async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let Ok(mut term) = signal(SignalKind::terminate()) else {
            // No SIGTERM stream: ctrl-c remains the only trigger.
            let _ = tokio::signal::ctrl_c().await;
            return;
        };
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = term.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
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
