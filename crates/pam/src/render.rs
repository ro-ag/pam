//! Human and machine rendering of daemon responses and events.
//!
//! # Exit codes
//!
//! The CLI maps every terminal state to a stable exit code (documented
//! in the crate docs): `0` for a solved / changed / verified result (and
//! a ticket), `3` for a refusal, `4` for an unresolved result, `5` for a
//! blocked result. Usage errors and stubs exit `2`; transport and other
//! client-side failures exit `1`.
//!
//! # Refusals
//!
//! A refusal always renders all three fields the daemon sends — machine
//! cause, human detail, and the recovery sentence (which points at the
//! GUI, never at a security command):
//!
//! ```text
//! pam: refused (not_granted)
//!   capability "echo" has no active grant
//!   → Open the PAM GUI to grant it, then retry.
//! ```
//!
//! With `--json` the raw [`Response`] JSON goes to stdout instead; the
//! exit code is mapped the same way either way.
//!
//! # Flows
//!
//! `pam flow` gets three bespoke renderers — [`render_flow_list`],
//! [`render_flow_show`], [`render_flow_result`] — plus
//! [`parse_flow_inputs`], which turns the subcommand's positional
//! `key=value` arguments into the `flow.run` args object. Parsing lives
//! here beside the rendering so the clap shell in `main.rs` stays thin
//! and the CLI's whole text surface is unit-testable in one place.

use pam_proto::{Event, Outcome, Response};
use serde_json::Value;

/// Exit code for a refusal.
pub const EXIT_REFUSED: u8 = 3;

/// Exit code for an `unresolved` result.
pub const EXIT_UNRESOLVED: u8 = 4;

/// Exit code for a `blocked` result.
pub const EXIT_BLOCKED: u8 = 5;

/// Maps a terminal [`Response`] to the CLI exit code (see the module
/// docs). A ticket is a successful hand-off, hence `0`.
#[must_use]
pub fn exit_code(response: &Response) -> u8 {
    match response {
        Response::Result { outcome, .. } => match outcome {
            Outcome::Solved | Outcome::Changed | Outcome::Verified => 0,
            Outcome::Unresolved => EXIT_UNRESOLVED,
            Outcome::Blocked => EXIT_BLOCKED,
        },
        Response::Refusal { .. } => EXIT_REFUSED,
        Response::Ticket { .. } => 0,
    }
}

/// The raw response as pretty JSON, for `--json` output.
#[must_use]
pub fn render_json(response: &Response) -> String {
    serde_json::to_string_pretty(response).unwrap_or_else(|_| "{}".to_owned())
}

/// The stderr block for a refusal: cause, detail, recovery — always all
/// three (see the module docs).
#[must_use]
pub fn render_refusal(cause: &str, detail: &str, recovery: &str) -> String {
    format!("pam: refused ({cause})\n  {detail}\n  \u{2192} {recovery}")
}

/// The stdout block for a ticket: the id to follow, plus the hint.
#[must_use]
pub fn render_ticket(ticket: &str, position: u64) -> String {
    format!("ticket {ticket} (queue position {position})\n  follow it with: pam wait {ticket}")
}

/// Humane one-screen summary for `pam status`.
///
/// Reads the fields the `status` capability publishes; anything missing
/// (an older daemon) renders as `?` rather than failing.
#[must_use]
pub fn render_status(body: &serde_json::Value) -> String {
    let field = |name: &str| body.get(name).map_or_else(|| "?".to_owned(), render_scalar);
    format!(
        "pam daemon\n  version:         {}\n  protocol:        {}\n  uptime:          {}\n  active requests: {}\n  model:           {}",
        field("daemon_version"),
        field("protocol"),
        body.get("uptime_s")
            .and_then(serde_json::Value::as_u64)
            .map_or_else(|| "?".to_owned(), render_uptime),
        field("active_requests"),
        render_model(body.get("model")),
    )
}

/// The `model:` line: `idle`, `loading <id>`, or `<id> loaded (<n> tok/s)`.
///
/// A daemon that publishes no `model` block at all is an older build, and
/// renders `?` like every other missing field. A loaded model that has not
/// generated yet has no tokens/sec to report, so the figure is left off
/// rather than invented.
fn render_model(model: Option<&serde_json::Value>) -> String {
    let Some(model) = model else {
        return "?".to_owned();
    };
    let state = model.get("state").and_then(serde_json::Value::as_str);
    let id = model.get("id").and_then(serde_json::Value::as_str);
    match (state, id) {
        (Some("loaded"), Some(id)) => match model
            .get("tokens_per_sec")
            .and_then(serde_json::Value::as_f64)
        {
            Some(tps) => format!("{id} loaded ({tps:.1} tok/s)"),
            None => format!("{id} loaded"),
        },
        (Some("loading"), Some(id)) => format!("loading {id}"),
        (Some(state), _) => state.to_owned(),
        (None, _) => "?".to_owned(),
    }
}

/// A generic result body as pretty JSON — the human fallback for
/// capabilities without a bespoke renderer (e.g. `echo`).
#[must_use]
pub fn render_body(body: &serde_json::Value) -> String {
    serde_json::to_string_pretty(body).unwrap_or_else(|_| body.to_string())
}

/// One `pam subscribe` line per event: `[queued]`, `[progress 40%] ...`.
#[must_use]
pub fn render_event(event: &Event) -> String {
    match event {
        Event::Queued => "[queued]".to_owned(),
        Event::Started => "[started]".to_owned(),
        Event::Progress { pct, note } => match pct {
            Some(pct) => format!("[progress {pct}%] {note}"),
            None => format!("[progress] {note}"),
        },
        Event::ApprovalPending => {
            "[approval_pending] waiting for a human approval in the PAM GUI".to_owned()
        }
        Event::Done => "[done]".to_owned(),
        Event::Refused => "[refused]".to_owned(),
    }
}

/// The `pam flow list` table — `id  source  steps  name`, one row per
/// flow, every column padded to its widest value.
///
/// A flow whose file does not validate has no step count and no name to
/// give, so its row carries `invalid: <message>` in their place: the
/// library stays listable, and the row itself says what to fix.
#[must_use]
pub fn render_flow_list(body: &Value) -> String {
    let Some(flows) = body.get("flows").and_then(Value::as_array) else {
        return render_body(body);
    };
    if flows.is_empty() {
        return "no flows are installed".to_owned();
    }
    let width = |key: &str| {
        flows
            .iter()
            .map(|flow| field(flow, key).chars().count())
            .max()
            .unwrap_or_default()
    };
    let id_width = width("id");
    let source_width = width("source");
    let steps_width = flows
        .iter()
        .filter(|flow| is_valid(flow))
        .map(|flow| step_count(flow).to_string().len())
        .max()
        .unwrap_or_default();

    flows
        .iter()
        .map(|flow| {
            let tail = if is_valid(flow) {
                format!(
                    "{:>steps_width$}  {}",
                    step_count(flow),
                    field(flow, "name")
                )
            } else {
                format!("invalid: {}", field(flow, "error"))
            };
            format!(
                "{:<id_width$}  {:<source_width$}  {tail}",
                field(flow, "id"),
                field(flow, "source")
            )
        })
        .collect::<Vec<String>>()
        .join("\n")
}

/// The `pam flow show` output: the flow's canonical YAML, verbatim.
///
/// A flow that does not validate has no canonical rendering — the daemon
/// sends an empty `normalized_yaml` — so its source text is printed
/// instead, which is exactly the text a human opened `show` to fix.
#[must_use]
pub fn render_flow_show(body: &Value) -> String {
    let normalized = field(body, "normalized_yaml");
    let yaml = if normalized.is_empty() {
        field(body, "yaml")
    } else {
        normalized
    };
    yaml.trim_end().to_owned()
}

/// The `pam flow run` verdict: one line per step, the run's summary
/// sentence, then any step summary text.
///
/// A step that ended well reports how long it took; one that did not
/// reports why — its exit status, or the cause when there was no process
/// to exit — followed by the evidence rows to read, and its recovery line
/// indented underneath. A step whose `output: summarize` produced a
/// paragraph gets that paragraph under its own rule at the bottom, where
/// prose does not break the step table.
///
/// A body without a `steps` array (an older daemon) falls back to
/// [`render_body`] rather than rendering nothing.
#[must_use]
pub fn render_flow_result(body: &Value) -> String {
    let Some(steps) = body.get("steps").and_then(Value::as_array) else {
        return render_body(body);
    };
    let mut lines: Vec<String> = Vec::new();
    for step in steps {
        lines.push(render_step_line(step));
        let recovery = step
            .get("error")
            .map(|error| field(error, "recovery"))
            .unwrap_or_default();
        if !recovery.is_empty() {
            lines.push(format!("  \u{2192} {recovery}"));
        }
    }

    let summary = field(body, "summary");
    if !summary.is_empty() {
        if !lines.is_empty() {
            lines.push(String::new());
        }
        lines.push(summary.to_owned());
    }

    for step in steps {
        let text = field(step, "summary").trim_end();
        if text.is_empty() {
            continue;
        }
        lines.push(String::new());
        lines.push(format!(
            "\u{2500}\u{2500} {} \u{2500}\u{2500}",
            field(step, "id")
        ));
        lines.extend(text.lines().map(|line| format!("  {line}")));
    }
    lines.join("\n")
}

/// Parses `pam flow run`'s positional `key=value` arguments into the
/// `inputs` object the `flow.run` capability takes.
///
/// The first `=` separates the two, so a value may contain more of them.
///
/// # Errors
///
/// The usage message for the first argument that is not a `key=value`
/// pair, ready to print after `pam flow run: `.
pub fn parse_flow_inputs(raw: &[String]) -> Result<Value, String> {
    let mut inputs = serde_json::Map::new();
    for item in raw {
        let (name, value) = item
            .split_once('=')
            .filter(|(name, _)| !name.is_empty())
            .ok_or_else(|| format!("input {item:?} must be key=value"))?;
        inputs.insert(name.to_owned(), Value::String(value.to_owned()));
    }
    Ok(Value::Object(inputs))
}

/// `pam service …` human output: one fact per line, aligned like the
/// rest of the CLI's summaries.
#[must_use]
pub fn render_service_report(report: &pam_client::service::ServiceReport) -> String {
    use pam_client::service::ServiceState;
    use std::fmt::Write as _;
    let mut out = String::new();
    let _ = writeln!(out, "platform  {}", report.platform);
    match &report.state {
        ServiceState::Installed { unit, loaded } => {
            let _ = writeln!(
                out,
                "state     installed, {}",
                if *loaded { "loaded" } else { "not loaded" }
            );
            let _ = writeln!(out, "unit      {unit}");
        }
        ServiceState::NotInstalled { unit } => {
            out.push_str("state     not installed\n");
            let _ = writeln!(out, "unit      {unit}");
        }
        ServiceState::Unsupported { reason } => {
            let _ = writeln!(out, "state     unsupported: {reason}");
        }
    }
    let _ = writeln!(out, "exe       {}", report.exe.display());
    if let Some(note) = &report.note {
        let _ = writeln!(out, "note      {note}");
    }
    out
}

/// One step of a verdict as its table line (see [`render_flow_result`]).
fn render_step_line(step: &Value) -> String {
    let status = field(step, "status");
    let mut parts = vec![status.to_owned()];
    match status {
        "succeeded" => {
            let duration_ms = step
                .get("duration_ms")
                .and_then(Value::as_u64)
                .unwrap_or_default();
            if duration_ms > 0 {
                parts.push(render_duration_ms(duration_ms));
            }
        }
        "skipped" => {}
        _ => {
            if let Some(exit_status) = step.get("exit_status").and_then(Value::as_i64) {
                parts.push(format!("exit {exit_status}"));
            } else {
                let cause = step
                    .get("error")
                    .map(|error| field(error, "cause"))
                    .unwrap_or_default();
                if !cause.is_empty() {
                    parts.push(cause.to_owned());
                }
            }
            if let Some(evidence) = step.get("evidence").and_then(Value::as_array) {
                parts.extend(evidence.iter().filter_map(Value::as_str).map(str::to_owned));
            }
        }
    }
    format!(
        "{} {}  {}",
        step_glyph(status),
        field(step, "id"),
        parts.join("  ")
    )
}

/// The status glyph a step line opens with.
fn step_glyph(status: &str) -> char {
    match status {
        "succeeded" => '\u{2713}',
        "failed" => '\u{2717}',
        "skipped" => '\u{b7}',
        "blocked" => '\u{2298}',
        "cancelled" => '\u{2297}',
        _ => '?',
    }
}

/// A step's wall time as `120ms` under a second, `4.2s` above it.
fn render_duration_ms(total_ms: u64) -> String {
    if total_ms < 1_000 {
        format!("{total_ms}ms")
    } else {
        format!("{}.{}s", total_ms / 1_000, (total_ms % 1_000) / 100)
    }
}

/// A JSON object's string field, empty when it is missing or not a string.
fn field<'a>(value: &'a Value, key: &str) -> &'a str {
    value.get(key).and_then(Value::as_str).unwrap_or_default()
}

/// Whether a flow list entry parsed. A daemon that omits the flag has
/// nothing to complain about, so the entry counts as valid.
fn is_valid(flow: &Value) -> bool {
    flow.get("valid").and_then(Value::as_bool).unwrap_or(true)
}

/// A flow list entry's step count.
fn step_count(flow: &Value) -> u64 {
    flow.get("steps")
        .and_then(Value::as_u64)
        .unwrap_or_default()
}

/// A JSON scalar without quotes, everything else as compact JSON.
fn render_scalar(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::String(text) => text.clone(),
        other => other.to_string(),
    }
}

/// Seconds as a compact `1h 02m 03s` figure.
fn render_uptime(total_s: u64) -> String {
    let (hours, rest) = (total_s / 3600, total_s % 3600);
    let (minutes, seconds) = (rest / 60, rest % 60);
    if hours > 0 {
        format!("{hours}h {minutes:02}m {seconds:02}s")
    } else if minutes > 0 {
        format!("{minutes}m {seconds:02}s")
    } else {
        format!("{seconds}s")
    }
}
