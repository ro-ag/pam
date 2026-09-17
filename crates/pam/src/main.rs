//! One binary, mode by subcommand: client by default, `pam daemon` for the
//! background service, `pam gui` for the desktop control center.
//!
//! The CLI surface is deliberately static — agents interact exclusively
//! through these subcommands (no raw-protocol escape hatch), and there
//! are **no security commands**: grants, approvals, revocations, and
//! profile changes live in the GUI only. The subcommand table lives in
//! `README.md` ("CLI surface"); the exit-code table is in the crate docs
//! of [`pam`] (`lib.rs`).

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use clap::{Args, Parser, Subcommand};
use pam::client::{self, DEFAULT_FOLLOW_TIMEOUT_MS, StopOutcome};
use pam::render;
use pam::request::{DEFAULT_DEADLINE_MS, parse_args_object};
use pam_daemon::daemon::{DaemonError, run_daemon};
use pam_daemon::lifecycle::{LifecycleError, LifecyclePhase, init_daemon_logging};
use pam_proto::{Event, Response};

/// Exit code for usage errors.
const EXIT_USAGE: u8 = 2;

/// How long `pam daemon stop` waits for the daemon's drain to finish.
const STOP_WAIT: Duration = Duration::from_secs(15);

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
        /// Wait for the result (the default); given after `--no-wait`,
        /// cancels it — the last of the two flags wins.
        #[arg(long, overrides_with = "no_wait")]
        wait: bool,
        /// Return a ticket immediately instead of waiting.
        #[arg(long, overrides_with = "wait")]
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
        /// Print the durable terminal response as JSON.
        #[arg(long)]
        json: bool,
        /// The ticket to wait for.
        ticket: String,
        /// Give up after this many milliseconds.
        #[arg(long, default_value_t = DEFAULT_FOLLOW_TIMEOUT_MS)]
        timeout_ms: u64,
    },
    /// Serve a session socket relay for sandboxed clients (unix only).
    ///
    /// Binds `pam.sock` and `events.sock` directly inside `<dir>` and
    /// forwards bytes to the daemon's runtime sockets, so a client running
    /// under an agent sandbox that blocks the daemon's own socket can dial
    /// a path the sandbox permits. Point sandboxed clients at it with
    /// `PAM_SOCKET_DIR=<dir>` — while that is set they never start a
    /// daemon themselves, so a dead relay is a clean error, not a spawn.
    /// The relay is a dumb byte pipe: all admission and authority stays
    /// with the daemon. See docs/session-socket-relay.md.
    #[cfg(unix)]
    Listen {
        /// Directory to bind the session sockets in (created private).
        #[arg(default_value = ".pam-session")]
        dir: PathBuf,
    },
    /// Stream a ticket's events until its terminal event.
    Subscribe {
        /// The ticket to follow.
        ticket: String,
        /// Give up after this many milliseconds.
        #[arg(long, default_value_t = DEFAULT_FOLLOW_TIMEOUT_MS)]
        timeout_ms: u64,
        /// Print the durable terminal response as JSON (events still
        /// stream as text lines first).
        #[arg(long)]
        json: bool,
    },
    /// Read bounded evidence retained for an authorized request.
    Evidence {
        #[command(subcommand)]
        action: EvidenceCmd,
    },
    /// List, read, and run the flows this machine has.
    Flow {
        #[command(subcommand)]
        action: FlowCmd,
    },
    /// Start the daemon at login: a user-scope launch agent, systemd user
    /// unit, or scheduled task. Never sudo or admin.
    Service {
        #[command(subcommand)]
        action: ServiceCmd,
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

/// `pam service`: the login-start unit for the daemon.
#[derive(Subcommand)]
enum ServiceCmd {
    /// Register the unit and start the managed daemon now (a loose
    /// daemon is stopped first so the managed one takes over).
    Install {
        /// Print the report as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Unregister and remove the unit. On macOS and Linux the manager
    /// stops the managed daemon with it; the next pam command starts one.
    Uninstall {
        /// Print the report as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Show whether the unit exists and whether the manager has it loaded.
    Status {
        /// Print the report as JSON.
        #[arg(long)]
        json: bool,
    },
}

/// `pam flow`: the flow library, and one run of one flow.
#[derive(Subcommand)]
enum FlowCmd {
    /// List the flows this machine has: id, source, steps, and name.
    List {
        /// How many flows to skip, for paging past the first page.
        #[arg(long, default_value_t = 0)]
        offset: u64,
        /// Page size, from 1 through 50.
        #[arg(long, default_value_t = 20, value_parser = clap::value_parser!(u32).range(1..=50))]
        limit: u32,
        /// Print the raw response JSON instead of the table.
        #[arg(long)]
        json: bool,
    },
    /// Inspect inputs and readiness without running the flow.
    Inspect {
        /// The flow id, as `pam flow list` spells it.
        id: String,
        /// Values for the flow's declared inputs, as `key=value`.
        inputs: Vec<String>,
        /// Print the raw response JSON.
        #[arg(long)]
        json: bool,
    },
    /// Retrieve the durable result of a flow ticket.
    Result {
        /// The ticket `pam flow run --no-wait` printed.
        ticket: String,
        /// Print the raw response JSON.
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

#[derive(Subcommand)]
enum EvidenceCmd {
    /// Read one byte range; use returned view/digest with `next_offset` to continue.
    Read(EvidenceReadArgs),
}

#[derive(Args)]
struct EvidenceReadArgs {
    /// Evidence id from the originating result.
    evidence_id: String,
    /// The originating request ticket, not this read's request id.
    #[arg(long)]
    request: String,
    /// Byte offset in the immutable evidence view.
    #[arg(long, default_value_t = 0)]
    offset: u64,
    /// Requested bytes, from 1 through 65536 (default 16384).
    #[arg(long, default_value_t = 16_384, value_parser = clap::value_parser!(u32).range(1..=65_536))]
    length: u32,
    /// View identity returned by the first read; required for continuation.
    #[arg(long, requires = "digest")]
    view: Option<String>,
    /// SHA-256 returned with that view; required together with --view.
    #[arg(long, requires = "view")]
    digest: Option<String>,
    /// Print unchanged response JSON, including exact hex-encoded bytes.
    #[arg(long)]
    json: bool,
}

fn evidence_read_args(args: &EvidenceReadArgs) -> Result<serde_json::Value, &'static str> {
    if args.evidence_id.is_empty() || args.request.is_empty() {
        return Err("evidence id and originating request must be nonempty");
    }
    if args.offset > 0 && args.view.is_none() {
        return Err("continuation requires --view and --digest from the previous read");
    }
    if args.view.as_ref().is_some_and(String::is_empty) {
        return Err("the view identity must be nonempty");
    }
    if args.digest.as_ref().is_some_and(|digest| {
        digest.len() != 64 || !digest.bytes().all(|byte| byte.is_ascii_hexdigit())
    }) {
        return Err("--digest must be the view's 64 hexadecimal SHA-256 characters");
    }
    let mut value = serde_json::json!({
        "evidence_id": args.evidence_id,
        "request_id": args.request,
        "offset": args.offset,
        "length": args.length,
    });
    if let (Some(view), Some(digest)) = (&args.view, &args.digest) {
        value["expected_view_id"] = serde_json::json!(view);
        value["expected_sha256"] = serde_json::json!(digest.to_ascii_lowercase());
    }
    Ok(value)
}

fn render_evidence(body: &serde_json::Value) -> Result<String, &'static str> {
    if body.get("encoding").and_then(serde_json::Value::as_str) != Some("hex") {
        return Err("unsupported evidence encoding");
    }
    let data = body
        .get("data")
        .and_then(serde_json::Value::as_str)
        .ok_or("missing evidence bytes")?;
    if data.len() > 2 * 65_536
        || !data.len().is_multiple_of(2)
        || !data.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err("invalid or oversized hex evidence bytes");
    }
    let mut escaped = String::new();
    for pair in data.as_bytes().as_chunks::<2>().0 {
        let digit = |byte: u8| {
            if byte.is_ascii_digit() {
                byte - b'0'
            } else {
                byte.to_ascii_lowercase() - b'a' + 10
            }
        };
        let byte = digit(pair[0]) * 16 + digit(pair[1]);
        escaped.extend(std::ascii::escape_default(byte).map(char::from));
    }
    let mut metadata = body.clone();
    metadata
        .as_object_mut()
        .ok_or("invalid evidence response")?
        .remove("data");
    let metadata =
        serde_json::to_string_pretty(&metadata).map_err(|_| "invalid evidence metadata")?;
    // Preserve JSON formatting, while escaping non-ASCII controls and bidi marks.
    let mut safe_metadata = String::new();
    for ch in metadata.chars() {
        if ch.is_ascii() {
            safe_metadata.push(ch);
        } else {
            safe_metadata.extend(ch.escape_default());
        }
    }
    Ok(format!(
        "{safe_metadata}\ndata (escaped bytes): b\"{escaped}\""
    ))
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
        Cmd::Service { action } => service_command(&action),
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
            wait,
            no_wait,
            deadline_ms,
            json,
        } => {
            let args = match parse_args_object(args_json.as_deref()) {
                Ok(args) => args,
                Err(err) => {
                    eprintln!("pam echo: {err}");
                    return ExitCode::from(EXIT_USAGE);
                }
            };
            // clap keeps only the last of `--wait` / `--no-wait`.
            let wait = wait || !no_wait;
            request(base, "echo", args, wait, Some(deadline_ms), json).await
        }
        Cmd::Cancel { ticket, json } => {
            let args = serde_json::json!({ "ticket": ticket });
            request(base, "cancel", args, true, None, json).await
        }
        Cmd::Wait {
            ticket,
            timeout_ms,
            json,
        } => follow(base, "wait", &ticket, timeout_ms, json).await,
        #[cfg(unix)]
        Cmd::Listen { dir } => listen_mode(base, &dir),
        Cmd::Subscribe {
            ticket,
            timeout_ms,
            json,
        } => follow(base, "subscribe", &ticket, timeout_ms, json).await,
        Cmd::Evidence {
            action: EvidenceCmd::Read(args),
        } => match evidence_read_args(&args) {
            Ok(body) => request(base, "evidence.read", body, true, None, args.json).await,
            Err(error) => {
                eprintln!("pam evidence read: {error}");
                ExitCode::from(EXIT_USAGE)
            }
        },
        Cmd::Flow { action } => run_flow_command(base, action).await,
        Cmd::Daemon { .. } | Cmd::Gui | Cmd::Service { .. } => unreachable!("handled in main"),
    }
}

/// `pam service …`: the shared mechanics live in
/// [`pam_client::service`]; this prints the report and maps failures.
fn service_command(action: &ServiceCmd) -> ExitCode {
    use pam_client::service::{self, CommandRunner, ServiceEnv};
    let Some(base) = base_dir() else {
        eprintln!("pam service: cannot resolve the home directory; set $HOME");
        return ExitCode::FAILURE;
    };
    let env = match ServiceEnv::detect(&base) {
        Ok(env) => env,
        Err(err) => {
            eprintln!("pam service: {err}\n  {}", err.recovery());
            return ExitCode::FAILURE;
        }
    };
    let runner = CommandRunner;
    let (result, json) = match *action {
        ServiceCmd::Install { json } => (service::install(&env, &runner), json),
        ServiceCmd::Uninstall { json } => (service::uninstall(&env, &runner), json),
        ServiceCmd::Status { json } => (service::status(&env, &runner), json),
    };
    match result {
        Ok(report) if json => {
            println!(
                "{}",
                serde_json::to_string_pretty(&report).unwrap_or_default()
            );
            ExitCode::SUCCESS
        }
        Ok(report) => {
            print!("{}", render::render_service_report(&report));
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("pam service: {err}\n  {}", err.recovery());
            ExitCode::FAILURE
        }
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
        FlowCmd::List {
            json,
            offset,
            limit,
        } => {
            request(
                base,
                "flow.list",
                serde_json::json!({"offset": offset, "limit": limit}),
                true,
                None,
                json,
            )
            .await
        }
        FlowCmd::Result { ticket, json } => {
            request(
                base,
                "flow.result",
                serde_json::json!({"ticket":ticket}),
                true,
                None,
                json,
            )
            .await
        }
        FlowCmd::Inspect { id, inputs, json } => {
            let inputs = match render::parse_flow_inputs(&inputs) {
                Ok(inputs) => inputs,
                Err(error) => {
                    eprintln!("pam flow inspect: {error}");
                    return ExitCode::from(EXIT_USAGE);
                }
            };
            request(
                base,
                "flow.inspect",
                serde_json::json!({"id":id,"inputs":inputs}),
                true,
                None,
                json,
            )
            .await
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
    let refused_ticket = capability == "query"
        && matches!(response, Response::Result { body, .. }
            if body.get("state").and_then(serde_json::Value::as_str) == Some("refused"));
    let code = ExitCode::from(if refused_ticket {
        render::EXIT_REFUSED
    } else {
        render::exit_code(response)
    });
    if json {
        println!("{}", render::render_json(response));
        return code;
    }
    match response {
        Response::Result { body, .. } if capability == "status" => {
            println!("{}", render::render_status(body));
        }
        Response::Result { body, .. } if capability == "evidence.read" => {
            match render_evidence(body) {
                Ok(text) => println!("{text}"),
                Err(error) => {
                    eprintln!("pam evidence read: {error}");
                    return ExitCode::FAILURE;
                }
            }
        }
        Response::Result { body, .. } if capability == "flow.list" => {
            println!("{}", render::render_flow_list(body));
        }
        Response::Result { body, .. } if capability == "flow.show" => {
            println!("{}", render::render_flow_show(body));
        }
        Response::Result { body, .. } if matches!(capability, "flow.run" | "flow.result") => {
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

/// Follow events, then resolve the durable response so workflow failure and
/// advisory diagnosis cannot be mistaken for successful stream completion.
///
/// `subcommand` is `wait` (quiet) or `subscribe` (prints each event); it
/// also prefixes every error line. A follow that ends without a terminal
/// event — refused, or past `timeout_ms` — is a stderr line, or with
/// `--json` a refusal object on stdout ([`render::render_follow_failure`])
/// so a machine reader never has to parse prose; the exit code is the
/// same either way (refusal 3, timeout 1).
async fn follow(
    base: &Path,
    subcommand: &str,
    ticket: &str,
    timeout_ms: u64,
    json: bool,
) -> ExitCode {
    let timeout = Duration::from_millis(timeout_ms);
    let verbose = subcommand == "subscribe";
    let on_event = |event: &Event| {
        if verbose {
            println!("{}", render::render_event(event));
        }
    };
    match client::follow_ticket(base, ticket, timeout, on_event).await {
        Ok(_) => terminal_result(base, subcommand, ticket, json).await,
        Err(err) => {
            let code = if matches!(err, client::RequestError::FollowRefused { .. }) {
                ExitCode::from(render::EXIT_REFUSED)
            } else {
                ExitCode::FAILURE
            };
            match render::render_follow_failure(&err, json) {
                Some(object) => println!("{object}"),
                None => eprintln!("pam {subcommand}: {err}"),
            }
            code
        }
    }
}

async fn terminal_result(base: &Path, subcommand: &str, ticket: &str, json: bool) -> ExitCode {
    let args = serde_json::json!({"ticket": ticket});
    match client::send_request(base, "query", args.clone(), true, DEFAULT_DEADLINE_MS, None).await {
        Ok(response) => {
            if matches!(&response, Response::Result { body, .. } if body.get("capability").and_then(serde_json::Value::as_str) == Some("flow.run"))
            {
                request(base, "flow.result", args, true, None, json).await
            } else {
                print_response("query", &response, json)
            }
        }
        Err(error) => {
            eprintln!("pam {subcommand}: {error}");
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

/// `pam listen <dir>`: serves the session socket relay until ctrl-c.
/// Exit codes: 0 on a clean shutdown, 1 when the relay could not start or
/// failed. Unix only — the subcommand does not exist elsewhere.
#[cfg(unix)]
fn listen_mode(base: &Path, dir: &Path) -> ExitCode {
    let runtime = match tokio::runtime::Runtime::new() {
        Ok(runtime) => runtime,
        Err(err) => {
            eprintln!("pam listen: cannot start the async runtime: {err}");
            return ExitCode::FAILURE;
        }
    };
    match runtime.block_on(pam_client::relay::run(dir, base)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("pam listen: {err}");
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

#[cfg(test)]
mod main_test;
