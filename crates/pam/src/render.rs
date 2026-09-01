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

use pam_proto::{Event, Outcome, Response};

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
        "pam daemon\n  version:         {}\n  protocol:        {}\n  uptime:          {}\n  active requests: {}",
        field("daemon_version"),
        field("protocol"),
        body.get("uptime_s")
            .and_then(serde_json::Value::as_u64)
            .map_or_else(|| "?".to_owned(), render_uptime),
        field("active_requests"),
    )
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
