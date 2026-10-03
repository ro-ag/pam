//! Human and machine rendering of daemon responses and events. Exit codes: `0`
//! solved/changed/verified (or a ticket), `1` transport/client failure, `2` usage error, `3`
//! refused, `4` unresolved, `5` blocked, `6` boundary not established (`pam doctor` only); `11`
//! not trusted, `12` invalid file, `13` rejected leaves (`pam policy check` only,
//! [`policy_check_exit_code`]).
//!
//! A refusal always renders all three fields the daemon sends — machine cause, human detail, and
//! the recovery sentence (points at the GUI, never a security command):
//!
//! ```text
//! pam: refused (not_granted)
//!   capability "echo" has no active grant
//!   → Open the PAM GUI to grant it, then retry.
//! ```
//!
//! One refusal is reworded for the human: `client_version_mismatch`, the answer of a running
//! daemon that is another build than this binary. Its detail becomes one plain sentence naming
//! both versions and the daemon's executable ([`version_mismatch_line`]); cause and recovery stay
//! the daemon's.
//!
//! With `--json` the raw [`Response`] JSON goes to stdout instead; the exit code is mapped the
//! same way either way. `pam flow` gets three renderers — [`render_flow_list`],
//! [`render_flow_show`], [`render_flow_result`] — plus [`parse_flow_inputs`], which turns
//! positional `key=value` args into the `flow.run` args object.
//!
//! `pam doctor` renders its own document (`crate::doctor::render`); this module adds what the
//! CLI learns from *sending* it: [`doctor_delivery`] turns the daemon's answer into the
//! document's `report` member, [`render_doctor_reply`] prints how the daemon saw the caller,
//! [`render_doctor_json`] adds that reply to the `--json` document, and [`doctor_exit_code`]
//! maps the local verdict to the exit code.
//!
//! `pam policy check` needs no daemon: [`render_policy_check`] prints one line per key the file
//! sets, [`policy_check_json`] the same as one document, and [`policy_check_exit_code`] maps the
//! verdict.

use std::fmt::Write as _;

use pam_daemon::managed_policy::{self, Key, KeyReport, PolicyView, Verdict as PolicyVerdict};
use pam_daemon::managed_policy_trust::{Untrusted, UntrustedReason};
use pam_proto::doctor::{DoctorReport, ReportRecord, Verdict};
use pam_proto::{Event, Outcome, Response};
use serde_json::{Value, json};

use crate::{PolicyCheck, PolicyContent, PolicyTrust};

/// Exit code for a refusal.
pub const EXIT_REFUSED: u8 = 3;

/// Exit code for an `unresolved` result.
pub const EXIT_UNRESOLVED: u8 = 4;

/// Exit code for a `blocked` result.
pub const EXIT_BLOCKED: u8 = 5;

/// Exit code of `pam doctor` when the boundary is `not_established`: new
/// and distinct, so a script never mistakes a sandbox finding for a daemon
/// decision (`3` refused, `5` blocked).
pub const EXIT_BOUNDARY: u8 = 6;

/// Exit code of `pam policy check --trust` when this machine's production
/// trust rules refuse the file (or a writer was replacing it): the daemon
/// would ignore it, whatever it says.
pub const EXIT_POLICY_UNTRUSTED: u8 = 11;

/// Exit code of `pam policy check` for a file invalid as a whole (not
/// JSON, too large, a duplicate key, an unsupported `version`, ...): the
/// daemon would use none of it.
pub const EXIT_POLICY_INVALID: u8 = 12;

/// Exit code of `pam policy check` for a file that parses but has at least
/// one rejected leaf or unknown key: the rest of it applies.
pub const EXIT_POLICY_LEAF_PROBLEMS: u8 = 13;

/// Maps a `pam policy check` result to the exit code: a trust refusal
/// first ([`EXIT_POLICY_UNTRUSTED`]; the daemon never reads an untrusted
/// file's content), then the document's verdict as the daemon's reader
/// gives it — valid `0`, [`EXIT_POLICY_LEAF_PROBLEMS`],
/// [`EXIT_POLICY_INVALID`] (a file refused for its size is invalid).
#[must_use]
pub fn policy_check_exit_code(check: &PolicyCheck) -> u8 {
    if check
        .trust
        .as_ref()
        .is_some_and(|trust| trust.outcome.is_err())
    {
        return EXIT_POLICY_UNTRUSTED;
    }
    match policy_verdict(check) {
        PolicyVerdict::Valid => 0,
        PolicyVerdict::LeafProblems => EXIT_POLICY_LEAF_PROBLEMS,
        PolicyVerdict::FileInvalid => EXIT_POLICY_INVALID,
    }
}

/// The document's verdict: the daemon reader's own
/// ([`managed_policy::Inspection::verdict`]); a file over the size bound is
/// invalid as a whole, as the reader would say.
fn policy_verdict(check: &PolicyCheck) -> PolicyVerdict {
    match &check.content {
        PolicyContent::Inspected { inspection, .. } => inspection.verdict(),
        PolicyContent::TooLarge { .. } => PolicyVerdict::FileInvalid,
    }
}

/// The verdict's wire word.
fn policy_verdict_word(verdict: PolicyVerdict) -> &'static str {
    match verdict {
        PolicyVerdict::Valid => "valid",
        PolicyVerdict::LeafProblems => "leaf_problems",
        PolicyVerdict::FileInvalid => "file_invalid",
    }
}

/// What a mode means for the human's setting, in a few words.
fn mode_semantics(key: &str, mode: &str) -> &'static str {
    if Key::parse(key).is_some_and(|key| key.section().is_none()) {
        return "label shown to the human";
    }
    match mode {
        "locked" => "forced; the human cannot change it",
        "default" => "used until the human sets their own",
        "floor" => "the human may choose this level or stricter",
        "min" => "lower bound on the human's value",
        "max" => "upper bound on the human's value",
        "allow" => "the human's list is intersected with this set",
        "forbid" => "policy-only constraint",
        _ => "unknown mode",
    }
}

/// The document value a dotted key names, as written in the file.
fn leaf_value<'a>(document: Option<&'a Value>, key: &str) -> Option<&'a Value> {
    key.split('.')
        .try_fold(document?, |value, segment| value.get(segment))
}

/// The file-level failure, when the file cannot be used at all.
fn policy_failure(check: &PolicyCheck) -> Option<(&'static str, String)> {
    match &check.content {
        PolicyContent::Inspected { inspection, .. } => inspection
            .result
            .as_ref()
            .err()
            .map(|failure| (failure.code, failure.detail.clone())),
        PolicyContent::TooLarge { size } => Some((
            managed_policy::CODE_TOO_LARGE,
            format!(
                "the file has {size} bytes; a policy may have at most {} (it was not read)",
                managed_policy::MAX_POLICY_BYTES
            ),
        )),
    }
}

/// The trust facts `--trust` reports, each with the reasons that fail it,
/// in the spirit of `admin.policy.get`'s `origin.trust`. The check stops at
/// the first failure, so once one fact fails the others are `unknown`.
const POLICY_TRUST_FACTS: [(&str, &[UntrustedReason]); 7] = [
    ("owner", &[UntrustedReason::NotOwnedByRoot]),
    ("writable_by_user", &[UntrustedReason::WritableByUser]),
    ("symlink", &[UntrustedReason::Symlink]),
    ("parents", &[UntrustedReason::ParentWritable]),
    ("regular", &[UntrustedReason::NotRegular]),
    (
        "readable",
        &[UntrustedReason::Unreadable, UntrustedReason::Busy],
    ),
    ("size", &[UntrustedReason::TooLarge]),
];

/// Each trust fact as `ok`, `failed`, `unknown` (not reached: the check
/// stopped at an earlier failure) or, for the owner on Windows,
/// `not_checked` (the Windows rule probes what this process's token may
/// do; it cannot read the owner).
fn policy_trust_facts(trust: &PolicyTrust) -> Vec<(&'static str, &'static str)> {
    let failed = trust
        .outcome
        .as_ref()
        .err()
        .map(|untrusted| untrusted.reason);
    POLICY_TRUST_FACTS
        .iter()
        .map(|(name, reasons)| {
            let state = match failed {
                Some(reason) if reasons.contains(&reason) => "failed",
                _ if *name == "owner" && cfg!(windows) => "not_checked",
                Some(_) => "unknown",
                None => "ok",
            };
            (*name, state)
        })
        .collect()
}

/// `trusted`, `busy` (a writer was replacing the file) or `untrusted`.
fn policy_trust_verdict(trust: &PolicyTrust) -> &'static str {
    match &trust.outcome {
        Ok(()) => "trusted",
        Err(untrusted) if untrusted.reason == UntrustedReason::Busy => "busy",
        Err(_) => "untrusted",
    }
}

/// The `trust` member of [`policy_check_json`].
fn policy_trust_json(trust: &PolicyTrust) -> Value {
    let refusal = trust.outcome.as_ref().err();
    let facts: serde_json::Map<String, Value> = policy_trust_facts(trust)
        .into_iter()
        .map(|(name, state)| (name.to_owned(), json!(state)))
        .collect();
    json!({
        "rules": "production",
        "checked_path": trust.checked_path.to_string_lossy(),
        "fixed_path": trust.fixed_path.to_string_lossy(),
        "at_fixed_path": trust.at_fixed_path(),
        "verdict": policy_trust_verdict(trust),
        "code": refusal.map(Untrusted::code),
        "detail": refusal.map(ToString::to_string),
        "recovery": refusal.map(Untrusted::recovery),
        "facts": facts,
        "observed": trust.observed.map(|(uid, mode)| json!({
            "uid": uid,
            "mode": format!("{mode:04o}"),
        })),
    })
}

/// One `keys` entry of [`policy_check_json`]: the daemon's per-key row,
/// plus what each mode means and, for an applied leaf, its value as the
/// file writes it.
fn policy_key_json(report: &KeyReport, document: Option<&Value>) -> Value {
    let mut entry = json!({
        "key": report.key,
        "tier": report.tier,
        "mode": report.mode,
        "semantics": report
            .mode
            .iter()
            .map(|mode| mode_semantics(report.key, mode))
            .collect::<Vec<_>>(),
        "state": report.state,
    });
    if report.state == "applied"
        && let Some(value) = leaf_value(document, report.key)
    {
        entry["value"] = value.clone();
    }
    if let Some(code) = report.code {
        entry["code"] = json!(code);
    }
    if let Some(detail) = &report.detail {
        entry["detail"] = json!(detail);
    }
    entry
}

/// `pam policy check --json`: one document.
///
/// `{ path, platform, verdict: valid|leaf_problems|file_invalid,
/// exit_code, digest, size, failure: {code, detail} | null, meta:
/// {revision, organization, contact, comment}, keys: [{key, tier, mode[],
/// semantics[], state, value?, code?, detail?}], diagnostics: [{code, key,
/// detail}], rejected_leaves, locks: [key], trust: {rules, checked_path,
/// fixed_path, at_fixed_path, verdict: trusted|untrusted|busy, code,
/// detail, recovery, facts: {owner, writable_by_user, symlink, parents,
/// regular, readable, size}, observed: {uid, mode} | null} | null }`.
/// `digest` is the SHA-256 of the raw bytes (null for a file refused
/// unread); `value` is present for an applied leaf.
#[must_use]
pub fn policy_check_json(check: &PolicyCheck) -> Value {
    let (digest, size) = match &check.content {
        PolicyContent::Inspected { inspection, .. } => {
            (Some(inspection.digest.as_str()), inspection.size as u64)
        }
        PolicyContent::TooLarge { size } => (None, *size),
    };
    let (view, document) = match &check.content {
        PolicyContent::Inspected {
            inspection,
            document,
        } => (inspection.result.as_ref().ok(), document.as_ref()),
        PolicyContent::TooLarge { .. } => (None, None),
    };
    let reports = view.map(PolicyView::key_reports).unwrap_or_default();
    json!({
        "path": check.path.to_string_lossy(),
        "platform": check.platform.as_str(),
        "verdict": policy_verdict_word(policy_verdict(check)),
        "exit_code": policy_check_exit_code(check),
        "digest": digest,
        "size": size,
        "failure": policy_failure(check).map(|(code, detail)| json!({
            "code": code,
            "detail": detail,
        })),
        "meta": view.map(|view| json!({
            "revision": view.meta().revision,
            "organization": view.meta().organization,
            "contact": view.meta().contact,
            "comment": view.meta().comment,
        })),
        "keys": reports
            .iter()
            .map(|report| policy_key_json(report, document))
            .collect::<Vec<_>>(),
        "diagnostics": view.map(|view| view.diagnostics().to_vec()).unwrap_or_default(),
        "rejected_leaves": view.map_or(0, PolicyView::rejected_leaves),
        "locks": policy_locks(&reports),
        "trust": check.trust.as_ref().map(policy_trust_json),
    })
}

/// The keys the file locks (a `locked` mode that applied).
fn policy_locks(reports: &[KeyReport]) -> Vec<&'static str> {
    reports
        .iter()
        .filter(|report| report.state == "applied" && report.mode.contains(&"locked"))
        .map(|report| report.key)
        .collect()
}

/// How long a printed leaf value may be before it is cut.
const POLICY_VALUE_WIDTH: usize = 120;

/// `text` with control and bidirectional-formatting characters escaped, so
/// a file under review cannot reorder or hide what the terminal shows.
fn terminal_safe(text: &str) -> String {
    text.chars()
        .flat_map(|ch| {
            let hidden = ch.is_control()
                || matches!(ch, '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{feff}')
                || ('\u{202a}'..='\u{202e}').contains(&ch)
                || ('\u{2066}'..='\u{2069}').contains(&ch);
            if hidden {
                ch.escape_unicode().collect::<Vec<_>>()
            } else {
                vec![ch]
            }
        })
        .collect()
}

/// A leaf value as compact JSON, cut at [`POLICY_VALUE_WIDTH`] characters.
fn policy_value_text(value: &Value) -> String {
    let text = terminal_safe(&value.to_string());
    if text.chars().count() <= POLICY_VALUE_WIDTH {
        return text;
    }
    let cut: String = text.chars().take(POLICY_VALUE_WIDTH).collect();
    format!("{cut}\u{2026}")
}

/// `pam policy check` human output: the file, its digest and labels, one
/// line per key it sets (state, tier, key, each mode with what it means,
/// and the value or the reason it was rejected), any finding not tied to a
/// key, what the file locks, the trust check when asked, and the verdict
/// with its exit code.
#[must_use]
pub fn render_policy_check(check: &PolicyCheck) -> String {
    let mut out = String::new();
    let _ = writeln!(
        out,
        "policy       {} (checked for {})",
        terminal_safe(&check.path.to_string_lossy()),
        check.platform.as_str()
    );
    let json = policy_check_json(check);
    match json["digest"].as_str() {
        Some(digest) => {
            let _ = writeln!(out, "digest       {digest} ({} bytes)", json["size"]);
        }
        None => {
            let _ = writeln!(out, "size         {} bytes", json["size"]);
        }
    }
    for label in ["organization", "revision", "contact"] {
        if let Some(text) = json["meta"][label].as_str() {
            let _ = writeln!(out, "{label:<13}{}", terminal_safe(text));
        }
    }
    let keys = json["keys"]
        .as_array()
        .map(Vec::as_slice)
        .unwrap_or_default();
    if !keys.is_empty() {
        out.push_str("keys\n");
    }
    for entry in keys {
        render_policy_key(&mut out, entry, width_of(keys));
    }
    let reported: Vec<&str> = keys
        .iter()
        .filter_map(|entry| entry["key"].as_str())
        .collect();
    let others: Vec<&Value> = json["diagnostics"]
        .as_array()
        .map(Vec::as_slice)
        .unwrap_or_default()
        .iter()
        .filter(|diagnostic| !reported.contains(&field(diagnostic, "key")))
        .collect();
    if !others.is_empty() {
        out.push_str("findings\n");
        for diagnostic in others {
            let _ = writeln!(
                out,
                "  {}  {}: {}",
                terminal_safe(field(diagnostic, "key")),
                field(diagnostic, "code"),
                terminal_safe(field(diagnostic, "detail"))
            );
        }
    }
    let locks: Vec<&str> = json["locks"]
        .as_array()
        .map(Vec::as_slice)
        .unwrap_or_default()
        .iter()
        .filter_map(Value::as_str)
        .collect();
    if !locks.is_empty() {
        let _ = writeln!(out, "locks        {}", locks.join(", "));
    }
    if let Some(trust) = &check.trust {
        render_policy_trust(&mut out, trust);
    }
    render_policy_verdict(&mut out, check, &json);
    out
}

/// The widest key name, for aligning the rows.
fn width_of(keys: &[Value]) -> usize {
    keys.iter()
        .filter_map(|entry| entry["key"].as_str())
        .map(str::len)
        .max()
        .unwrap_or_default()
}

/// One key row of [`render_policy_check`]: state, tier, key, each mode with
/// what it means (`label` for the meta keys), then the value or the reason
/// it was rejected.
fn render_policy_key(out: &mut String, entry: &Value, width: usize) {
    let is_label = Key::parse(field(entry, "key")).is_some_and(|key| key.section().is_none());
    let modes: Vec<String> = entry["mode"]
        .as_array()
        .map(Vec::as_slice)
        .unwrap_or_default()
        .iter()
        .zip(
            entry["semantics"]
                .as_array()
                .map(Vec::as_slice)
                .unwrap_or_default(),
        )
        .map(|(mode, meaning)| {
            format!(
                "{} ({})",
                mode.as_str().unwrap_or_default(),
                meaning.as_str().unwrap_or_default()
            )
        })
        .collect();
    let modes = if is_label {
        "label".to_owned()
    } else {
        modes.join(", ")
    };
    let tail = match entry.get("value") {
        Some(value) => policy_value_text(value),
        None => format!(
            "{}: {}",
            field(entry, "code"),
            terminal_safe(field(entry, "detail"))
        ),
    };
    let _ = writeln!(
        out,
        "  {:<8}  {}  {:<width$}  {modes}  = {tail}",
        field(entry, "state"),
        field(entry, "tier"),
        field(entry, "key"),
    );
}

/// The `trust` block of [`render_policy_check`].
fn render_policy_trust(out: &mut String, trust: &PolicyTrust) {
    let _ = writeln!(
        out,
        "trust        {} under this machine's production rules",
        policy_trust_verdict(trust)
    );
    let _ = writeln!(
        out,
        "  checked   {}",
        terminal_safe(&trust.checked_path.to_string_lossy())
    );
    let _ = writeln!(
        out,
        "  daemon    reads {}{}",
        trust.fixed_path.display(),
        if trust.at_fixed_path() {
            " (this file)"
        } else {
            "; the rules were applied to the file where it sits"
        }
    );
    let facts: Vec<String> = policy_trust_facts(trust)
        .into_iter()
        .map(|(name, state)| format!("{name} {state}"))
        .collect();
    let _ = writeln!(out, "  rules     {}", facts.join(", "));
    if let Some((uid, mode)) = trust.observed {
        let _ = writeln!(out, "  observed  owner uid {uid}, mode {mode:04o}");
    }
    if let Err(untrusted) = &trust.outcome {
        let _ = writeln!(out, "  refused   {}", terminal_safe(&untrusted.to_string()));
        let _ = writeln!(out, "  \u{2192} {}", untrusted.recovery());
    }
}

/// The last line of [`render_policy_check`]: the verdict and its exit
/// code, in words.
fn render_policy_verdict(out: &mut String, check: &PolicyCheck, json: &Value) {
    let code = policy_check_exit_code(check);
    let sentence = if code == EXIT_POLICY_UNTRUSTED {
        "not trusted: the daemon would ignore this file and say why".to_owned()
    } else if let Some((failure, detail)) = policy_failure(check) {
        format!(
            "invalid ({failure}): {}; the daemon would use none of it",
            terminal_safe(&detail)
        )
    } else {
        let rejected = json["rejected_leaves"].as_u64().unwrap_or_default();
        let applied = json["keys"].as_array().map_or(0, |keys| {
            keys.iter().filter(|key| key["state"] == "applied").count()
        });
        let keys = |count: usize| {
            if count == 1 {
                "1 key applies".to_owned()
            } else {
                format!("{count} keys apply")
            }
        };
        if rejected == 0 {
            format!("valid: {}", keys(applied))
        } else {
            format!(
                "valid with {rejected} rejected: {}; the rejected leaves and unknown keys do not",
                keys(applied)
            )
        }
    };
    let _ = writeln!(out, "verdict      {sentence} (exit {code})");
}

/// Maps a `pam doctor` verdict to the exit code: `established` `0`,
/// `not_established` [`EXIT_BOUNDARY`], `cannot_probe` `1` (the daemon was
/// unreachable or the base could not be resolved — the client failure every
/// other subcommand maps to `1`). The verdict is the client's own; whether
/// the daemon recorded the report never changes it.
#[must_use]
pub fn doctor_exit_code(verdict: Verdict) -> u8 {
    match verdict {
        Verdict::Established => 0,
        Verdict::NotEstablished => EXIT_BOUNDARY,
        Verdict::CannotProbe => 1,
    }
}

/// Deadline the `doctor.report` request carries, in milliseconds: the
/// daemon's control-class cap, so the client never waits longer than the
/// daemon would serve.
pub const DOCTOR_REPORT_DEADLINE_MS: u64 = 10_000;

/// What `pam doctor` learned from sending its report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DoctorDelivery {
    /// The document's `report` member: recorded, under which request id,
    /// or why not.
    pub record: ReportRecord,
    /// The daemon's reply body when it answered with a result: how it saw
    /// the caller (`peer`, `claimed_harness`, `harness_agrees`,
    /// `attributed_admin_contacts`).
    pub reply: Option<Value>,
    /// The stderr text when the report was not recorded; `None` when it was.
    pub stderr: Option<String>,
}

impl DoctorDelivery {
    /// A report that was deliberately not sent (`--no-report`, or a
    /// `cannot_probe` verdict, which the daemon would refuse).
    #[must_use]
    pub fn not_sent(reason: &str) -> Self {
        Self {
            record: ReportRecord {
                recorded: false,
                request_id: None,
                reason: Some(reason.to_owned()),
            },
            reply: None,
            stderr: None,
        }
    }
}

/// How the daemon answered the `doctor.report` request. A result records
/// the report under the daemon's request id and carries the reply; a
/// refusal or a client-side failure leaves it unrecorded with the cause,
/// and says so on stderr. None of it changes the verdict.
#[must_use]
pub fn doctor_delivery(sent: &Result<Response, crate::client::RequestError>) -> DoctorDelivery {
    match sent {
        Ok(Response::Result { body, .. }) => {
            let accepted = body.get("accepted").and_then(Value::as_bool) == Some(true);
            let request_id = body
                .get("request_id")
                .and_then(Value::as_str)
                .map(str::to_owned);
            DoctorDelivery {
                record: ReportRecord {
                    recorded: accepted,
                    request_id,
                    reason: (!accepted)
                        .then(|| "the daemon answered without accepting the report".to_owned()),
                },
                reply: Some(body.clone()),
                stderr: (!accepted).then(|| {
                    "pam doctor: the daemon answered without accepting the report".to_owned()
                }),
            }
        }
        Ok(Response::Refusal {
            cause,
            detail,
            recovery,
            ..
        }) => DoctorDelivery {
            record: ReportRecord {
                recorded: false,
                request_id: None,
                reason: Some(format!("refused ({cause}): {detail}")),
            },
            reply: None,
            stderr: Some(format!(
                "pam doctor: the report was not recorded\n{}",
                render_refusal(cause, detail, recovery)
            )),
        },
        Ok(Response::Ticket { ticket, .. }) => DoctorDelivery {
            record: ReportRecord {
                recorded: false,
                request_id: None,
                reason: Some(format!("the daemon queued the report as ticket {ticket}")),
            },
            reply: None,
            stderr: Some(format!(
                "pam doctor: the daemon queued the report as ticket {ticket} instead of recording it"
            )),
        },
        Err(err) => DoctorDelivery {
            record: ReportRecord {
                recorded: false,
                request_id: None,
                reason: Some(err.to_string()),
            },
            reply: None,
            stderr: Some(format!("pam doctor: the report was not sent: {err}")),
        },
    }
}

/// The human lines for the daemon's `doctor.report` reply, printed after
/// the document: who the daemon saw at the socket (its own kernel-peer
/// resolution, never the client's claim), what the client claimed, whether
/// the two agree, and how many admin contacts the run explained.
#[must_use]
pub fn render_doctor_reply(reply: &Value) -> String {
    let peer = reply.get("peer").unwrap_or(&Value::Null);
    let text = |value: Option<&Value>, missing: &str| -> String {
        match value {
            Some(Value::String(text)) => text.clone(),
            Some(Value::Number(number)) => number.to_string(),
            _ => missing.to_owned(),
        }
    };
    let via = match peer.get("relayed").and_then(Value::as_bool) {
        Some(true) => "relay",
        Some(false) => "direct",
        None => "via unknown",
    };
    let pid = peer
        .get("pid")
        .and_then(Value::as_u64)
        .map_or_else(|| "no pid".to_owned(), |pid| format!("pid {pid}"));
    let exe = peer
        .get("exe")
        .and_then(Value::as_str)
        .map(|exe| format!(" from {exe}"))
        .unwrap_or_default();
    let agrees = match reply.get("harness_agrees").and_then(Value::as_bool) {
        Some(true) => "yes",
        Some(false) => "no",
        None => "undetermined",
    };
    format!(
        "the daemon saw you as: {} ({pid}, {via}){exe}\n  claimed: {}; harness agrees: {agrees}; admin contacts attributed to this run: {}\n",
        text(peer.get("harness"), "unknown"),
        text(reply.get("claimed_harness"), "unknown"),
        text(reply.get("attributed_admin_contacts"), "0"),
    )
}

/// The `--json` document: the report as serde writes it, plus the daemon's
/// reply under `daemon_reply` when it answered. (`daemon` is the hello's
/// facts — version, protocol, epoch, via — so the reply sits beside it, not
/// inside it.) One document, nothing else.
#[must_use]
pub fn render_doctor_json(report: &DoctorReport, reply: Option<&Value>) -> String {
    let mut document = serde_json::to_value(report).unwrap_or_else(
        |error| serde_json::json!({ "error": format!("cannot serialize the report: {error}") }),
    );
    if let (Some(reply), Some(object)) = (reply, document.as_object_mut()) {
        object.insert("daemon_reply".to_owned(), reply.clone());
    }
    serde_json::to_string_pretty(&document).unwrap_or_else(|_| document.to_string())
}

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

/// Stable cause of a follow that ran past its `--timeout-ms`.
pub const CAUSE_FOLLOW_TIMEOUT: &str = "follow_timeout";

/// The `--json` rendering of a follow that ended without a terminal
/// event: `Some` refusal object — the same `kind: refusal` shape every
/// other `--json` refusal has, with the ticket as `id` — for a refused
/// follow or an observation timeout; `None` when `json` is off or the
/// error is a client-side failure (transport, spawn), which stays a
/// stderr line like every other command's.
#[must_use]
pub fn render_follow_failure(err: &crate::client::RequestError, json: bool) -> Option<String> {
    use crate::client::RequestError;
    if !json {
        return None;
    }
    let response = match err {
        RequestError::FollowRefused {
            ticket,
            cause,
            detail,
            recovery,
        } => Response::Refusal {
            retryable: false,
            id: ticket.clone(),
            cause: cause.clone(),
            detail: detail.clone(),
            recovery: recovery.clone(),
        },
        RequestError::FollowTimeout { ticket, waited } => Response::Refusal {
            retryable: false,
            id: ticket.clone(),
            cause: CAUSE_FOLLOW_TIMEOUT.to_owned(),
            detail: format!("no terminal event within {waited:?}; the request keeps running"),
            recovery: format!(
                "Follow it again with `pam wait {ticket}`, or read `pam flow result {ticket}` later."
            ),
        },
        _ => return None,
    };
    Some(render_json(&response))
}

/// True when the request may have reached the daemon even though no reply
/// came back (a missed reply or a broken transport after the send), so it
/// could still be running: the failures a caller must answer by following
/// the original request, not by sending it again.
#[must_use]
pub fn is_unanswered(err: &crate::client::RequestError) -> bool {
    use crate::client::RequestError;
    matches!(
        err,
        RequestError::ReplyTimeout { .. } | RequestError::Transport { .. }
    )
}

/// The recovery lines for an unanswered stateful request: its id (the
/// daemon's ticket), how to follow it, and when resubmitting is safe.
#[must_use]
pub fn render_unanswered_recovery(id: &str) -> String {
    format!(
        "  request id: {id} (the daemon may still be running it)\n  \u{2192} follow it with: pam wait {id}\n    do not submit it again; only if `pam wait {id}` says the request is unavailable did it never reach the daemon, and then it is safe to resubmit"
    )
}

/// The `--json` rendering of an unanswered stateful request: the same
/// `kind: refusal` shape every other `--json` refusal has, with the
/// request id as `id` and the `pam wait` line as the recovery. `cause` is
/// `reply_timeout` or `transport_failure`.
#[must_use]
pub fn render_unanswered_json(id: &str, err: &crate::client::RequestError) -> String {
    let cause = match err {
        crate::client::RequestError::ReplyTimeout { .. } => "reply_timeout",
        _ => "transport_failure",
    };
    render_json(&Response::Refusal {
        retryable: false,
        id: id.to_owned(),
        cause: cause.to_owned(),
        detail: format!("{err}; the request may still be running in the daemon"),
        recovery: format!(
            "Follow it with `pam wait {id}`; do not submit it again. Only if `pam wait {id}` reports the request unavailable did it never reach the daemon."
        ),
    })
}

/// Where a failed request's report goes: a JSON document for stdout (only for
/// an unanswered stateful request under `--json`), and the stderr text.
#[derive(Debug, PartialEq, Eq)]
pub struct RequestFailureReport {
    /// The `--json` refusal object, when the caller asked for JSON and the
    /// request may still be running in the daemon.
    pub stdout: Option<String>,
    /// The stderr text; empty when the JSON object carries everything.
    pub stderr: String,
}

/// How a request that failed client-side is reported.
///
/// A stateful request (`flow.run`) whose reply never arrived may still be
/// running, so it names its `id` and the `pam wait` recovery — as stderr
/// text, or as the `--json` refusal object ([`render_unanswered_json`], one
/// document on stdout and nothing else). Every other failure is the plain
/// `pam <capability>: <error>` line it always was.
#[must_use]
pub fn render_request_failure(
    capability: &str,
    id: &str,
    err: &crate::client::RequestError,
    json: bool,
) -> RequestFailureReport {
    if capability == "flow.run" && is_unanswered(err) {
        if json {
            return RequestFailureReport {
                stdout: Some(render_unanswered_json(id, err)),
                stderr: String::new(),
            };
        }
        return RequestFailureReport {
            stdout: None,
            stderr: format!(
                "pam {capability}: {err}\n{}",
                render_unanswered_recovery(id)
            ),
        };
    }
    RequestFailureReport {
        stdout: None,
        stderr: format!("pam {capability}: {err}"),
    }
}

/// The stderr block for a refusal: cause, detail, recovery — always all
/// three (see the module docs).
#[must_use]
pub fn render_refusal(cause: &str, detail: &str, recovery: &str) -> String {
    let detail = version_mismatch_line(cause, detail).unwrap_or_else(|| detail.to_owned());
    format!("pam: refused ({cause})\n  {detail}\n  \u{2192} {recovery}")
}

/// The plain sentence for a `client_version_mismatch` refusal — this binary
/// is not the build the running daemon was started from — or `None` for any
/// other cause.
///
/// The daemon's detail names the client's version, its own, and the
/// executable it runs from ("client version 0.5.1 does not match daemon
/// version 0.5.0 running from /path/pam; that binary has not changed on
/// disk, …"); all three are lifted into the sentence. A detail in a wording
/// this build does not recognise is kept verbatim behind the sentence, never
/// guessed at.
#[must_use]
pub fn version_mismatch_line(cause: &str, detail: &str) -> Option<String> {
    if cause != pam_proto::wire::cause::CLIENT_VERSION_MISMATCH {
        return None;
    }
    let facts = || {
        let (client, rest) = detail
            .strip_prefix("client version ")?
            .split_once(" does not match daemon version ")?;
        let (daemon, rest) = rest.split_once(" running from ")?;
        let (path, _) = rest.rsplit_once("; ")?;
        (!client.is_empty() && !daemon.is_empty() && !path.is_empty())
            .then_some((client, daemon, path))
    };
    Some(match facts() {
        Some((client, daemon, path)) => format!(
            "this pam (v{client}) is not the build the running daemon (v{daemon}, {path}) was \
             started from"
        ),
        None => format!(
            "this pam (v{}) is not the build the running daemon was started from ({detail})",
            env!("CARGO_PKG_VERSION")
        ),
    })
}

/// The stderr line for a follow that ended without a terminal event:
/// `pam <subcommand>: <error>`, with a `client_version_mismatch` refusal
/// reworded as in [`render_refusal`].
#[must_use]
pub fn render_follow_error(subcommand: &str, err: &crate::client::RequestError) -> String {
    if let crate::client::RequestError::FollowRefused {
        cause,
        detail,
        recovery,
        ..
    } = err
        && let Some(line) = version_mismatch_line(cause, detail)
    {
        return format!("pam {subcommand}: {line}; {recovery}");
    }
    format!("pam {subcommand}: {err}")
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
        "pam daemon\n  version:         {}\n  protocol:        {}\n  uptime:          {}\n  active requests: {}\n  model:           {}\n  keyring:         {}\n  boundary:        {}\n  policy:          {}\n  playbook:        pam playbook (the agent guide)",
        field("daemon_version"),
        field("protocol"),
        body.get("uptime_s")
            .and_then(serde_json::Value::as_u64)
            .map_or_else(|| "?".to_owned(), render_uptime),
        field("active_requests"),
        render_model(body.get("model")),
        render_keyring(body.get("keyring")),
        render_boundary(body.get("boundary")),
        render_policy(body.get("policy")),
    )
}

/// The `policy:` line from the public `status.policy` block, which carries
/// the state, revision, a 12-hex digest prefix and the rejected-leaf count,
/// never the organization or a rule (the content stays on the admin plane):
/// `none (unmanaged)`, `active, rev R, digest D`, `degraded, ...; N leaves
/// rejected`, `last_good, ...` (the file cannot be used; the last good copy
/// is in force) or `frozen` (the file cannot be used and there is no copy).
/// A daemon that publishes no block is an older build and renders `?`.
fn render_policy(policy: Option<&Value>) -> String {
    let Some(policy) = policy.filter(|policy| policy.is_object()) else {
        return "?".to_owned();
    };
    let state = terminal_safe(field(policy, "state"));
    let mut facts = Vec::new();
    if let Some(revision) = policy.get("revision").and_then(Value::as_str) {
        facts.push(format!("rev {}", terminal_safe(revision)));
    }
    if let Some(digest) = policy.get("digest").and_then(Value::as_str) {
        facts.push(format!("digest {}", terminal_safe(digest)));
    }
    let facts = if facts.is_empty() {
        String::new()
    } else {
        format!(", {}", facts.join(", "))
    };
    let rejected = policy
        .get("rejected_leaves")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    match state.as_str() {
        "none" => "none (unmanaged)".to_owned(),
        "active" => format!("active{facts}"),
        "degraded" => format!(
            "degraded{facts}; {rejected} {} rejected, the rest applies",
            if rejected == 1 { "leaf" } else { "leaves" }
        ),
        "last_good" => format!(
            "last_good{facts}; the policy file cannot be used, the last good copy is in force"
        ),
        "frozen" => "frozen; the policy file cannot be used and there is no last good copy: \
                     changes that widen what agents can do are paused"
            .to_owned(),
        "" => "?".to_owned(),
        other => format!("{other}{facts}"),
    }
}

/// The `boundary:` line: the block's own `summary` (`never checked — run
/// pam doctor from the agent`, or the last verdict, its age, who sent it
/// and the unexplained admin contacts), then, when a report exists, the
/// request it was recorded under and its age on a second line. A daemon
/// that publishes no block is an older build and renders `?`; a block
/// without a `summary` is rebuilt from its fields.
fn render_boundary(boundary: Option<&Value>) -> String {
    let Some(boundary) = boundary else {
        return "?".to_owned();
    };
    let report = boundary
        .get("last_report")
        .filter(|report| report.is_object());
    let age = report
        .and_then(|report| report.get("age_s"))
        .and_then(Value::as_u64)
        .map(render_age);
    let summary = match boundary.get("summary").and_then(Value::as_str) {
        Some(summary) => summary.to_owned(),
        None => match (report, &age) {
            (Some(report), Some(age)) => format!("{} {age} ago", field(report, "verdict")),
            (Some(report), None) => field(report, "verdict").to_owned(),
            (None, _) => "never checked — run pam doctor from the agent".to_owned(),
        },
    };
    match report {
        Some(report) => {
            let request = field(report, "request_id");
            let request = if request.is_empty() {
                "(no request id)"
            } else {
                request
            };
            match age {
                Some(age) => format!("{summary}\n    last report:   {request} ({age} ago)"),
                None => format!("{summary}\n    last report:   {request}"),
            }
        }
        None => summary,
    }
}

/// An age the way the daemon's summary spells it: `12 s`, `7 min`, `3 h`,
/// `2 d`.
fn render_age(secs: u64) -> String {
    match secs {
        0..=59 => format!("{secs} s"),
        60..=3_599 => format!("{} min", secs / 60),
        3_600..=86_399 => format!("{} h", secs / 3_600),
        _ => format!("{} d", secs / 86_400),
    }
}

/// The `keyring:` line: `reachable`, or the refusal and its way out.
///
/// This is how a terminal answers "does the app have keychain access?".
/// A daemon that publishes no `keyring` block is an older build and
/// renders `?`, like every other missing field.
fn render_keyring(keyring: Option<&serde_json::Value>) -> String {
    let Some(keyring) = keyring else {
        return "?".to_owned();
    };
    let state = keyring
        .get("state")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("?");
    match keyring.get("recovery").and_then(serde_json::Value::as_str) {
        Some(recovery) => format!("{state}\n    {recovery}"),
        None => state.to_owned(),
    }
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

    let mut rendered = flows
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
        .join("\n");
    if let Some(offset) = body.get("next_offset").and_then(Value::as_u64) {
        let _ = write!(rendered, "\nmore: pam flow list --offset {offset}");
    }
    rendered
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
    if let Some(result) = body.get("agent_result").filter(|value| value.is_object()) {
        return format!(
            "state: {}\n{}\n{}",
            field(body, "state"),
            render_flow_result(result),
            render_body(
                &serde_json::json!({"read_availability":body["read_availability"],"watch":body["watch"]})
            )
        );
    }
    if body.get("schema_version").and_then(Value::as_u64) == Some(1)
        && body.get("workflow").is_some()
    {
        // JSON escaping preserves hostile observations without terminal controls;
        // the typed headings keep workflow authority separate from diagnosis.
        return render_body(body);
    }
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

    lines.extend(render_effects(body));

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
        if is_model_summary(step) {
            // A local model wrote this paragraph from the step's output, so
            // anything in it can be a hostile echo of that output: it is
            // labelled, and its control characters never reach a terminal.
            lines.push(format!("  {UNTRUSTED_SUMMARY_LABEL}"));
            lines.extend(text.lines().map(|line| format!("  {}", printable(line))));
        } else {
            lines.extend(text.lines().map(|line| format!("  {line}")));
        }
    }
    lines.join("\n")
}

/// The label printed above every step summary a local model wrote.
pub const UNTRUSTED_SUMMARY_LABEL: &str = "[untrusted local-model summary]";

/// Whether a step's `summary` text was written by a local model.
///
/// Today the daemon marks that with a `summary_model` object (the model id
/// and its qualification record); a step whose summary was skipped, or
/// composed by the host, has none. A boolean `model_summary`, `untrusted`
/// or `summary_untrusted` set to true on the step says the same, so a
/// daemon that marks it explicitly is honoured too. Any one marker is
/// enough: the label fails towards showing.
fn is_model_summary(step: &Value) -> bool {
    step.get("summary_model").is_some_and(Value::is_object)
        || ["model_summary", "untrusted", "summary_untrusted"]
            .iter()
            .any(|key| step.get(*key).and_then(Value::as_bool) == Some(true))
}

/// `text` with every control character other than a tab replaced by its
/// `\u{..}` escape, so model-written text cannot drive the terminal.
fn printable(text: &str) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        if ch.is_control() && ch != '\t' {
            let _ = write!(out, "\\u{{{:x}}}", u32::from(ch));
        } else {
            out.push(ch);
        }
    }
    out
}

/// The run's `effects` list: what the flow changed, one line per step.
///
/// Absent or empty when no state-changing step ran. When the run stopped
/// `unresolved` or `blocked` the heading says so: the run failed after it
/// had already changed something.
fn render_effects(body: &Value) -> Vec<String> {
    let Some(effects) = body
        .get("effects")
        .and_then(Value::as_array)
        .filter(|effects| !effects.is_empty())
    else {
        return Vec::new();
    };
    let stopped = matches!(field(body, "outcome"), "unresolved" | "blocked");
    let mut lines = vec![
        String::new(),
        if stopped {
            "the run stopped after changing state:".to_owned()
        } else {
            "state this run changed:".to_owned()
        },
    ];
    for effect in effects {
        let mut line = format!(
            "  {}  {}  {}",
            field(effect, "step"),
            field(effect, "kind"),
            field(effect, "state")
        );
        let landing = field(effect, "landing");
        if !landing.is_empty() {
            line.push_str("  ");
            line.push_str(landing);
        }
        lines.push(line);
    }
    lines
}

/// The `pam flow inspect` output: the flow id and digest on one line, so a
/// human can copy the digest into `pam flow run --digest`, then the
/// inspection itself.
#[must_use]
pub fn render_flow_inspect(body: &Value) -> String {
    let flow = body.get("flow").unwrap_or(&Value::Null);
    let digest = field(flow, "digest");
    if digest.is_empty() {
        return render_body(body);
    }
    format!(
        "flow {}  digest {}\n\n{}",
        field(flow, "id"),
        digest,
        render_body(body)
    )
}

/// The `flow.run` arguments: the flow, its inputs, and, only when the
/// caller pinned one, the digest the flow must still have.
#[must_use]
pub fn flow_run_args(id: &str, inputs: &Value, digest: Option<&str>) -> Value {
    let mut args = serde_json::json!({ "id": id, "inputs": inputs });
    if let (Some(digest), Some(map)) = (digest, args.as_object_mut()) {
        map.insert(
            "expected_digest".to_owned(),
            Value::String(digest.to_owned()),
        );
    }
    args
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
    if let Some(pinned) = &report.pinned_exe {
        let _ = writeln!(out, "pinned    {}", pinned.display());
    }
    if let Some(stale) = &report.stale {
        let _ = writeln!(out, "stale     {stale}");
    }
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
