//! The two renderings of a [`DoctorReport`]: the human text and the exact
//! JSON document. No colour codes, no terminal detection; one line per
//! probe in inventory order.

use std::fmt::Write as _;

use pam_proto::doctor::{DoctorReport, Platform, Probe, ProbeState, Skipped, Verdict};

use super::env::profile_for_chain;
use super::profiles::Harness;

/// The profile the final line names: the harness's own when the chain
/// names one, else the generic `sandbox-exec` fragment on macOS and the
/// placeholder on Windows (no reference profile exists there yet).
#[must_use]
pub fn profile_name(report: &DoctorReport) -> &'static str {
    match (
        profile_for_chain(&report.env.harness_chain),
        report.platform,
    ) {
        (Some(harness), _) => harness.name(),
        (None, Platform::Macos) => Harness::SandboxExec.name(),
        (None, Platform::Windows) => "<harness>",
    }
}

/// The JSON document, pretty-printed, exactly as serde writes the report.
#[must_use]
pub fn render_json(report: &DoctorReport) -> String {
    serde_json::to_string_pretty(report).unwrap_or_else(|error| {
        // A report of bounded strings and plain enums always serializes;
        // the fallback keeps the contract of one document on stdout.
        format!("{{\"error\":\"cannot serialize the report: {error}\"}}")
    })
}

/// The human text.
#[must_use]
pub fn render_human(report: &DoctorReport) -> String {
    let mut out = String::new();
    verdict_block(&mut out, report);
    daemon_line(&mut out, report);
    out.push_str("probes:\n");
    for probe in &report.probes {
        probe_line(&mut out, probe);
    }
    env_block(&mut out, report);
    let _ = writeln!(
        out,
        "profile: pam doctor --profile {}",
        profile_name(report)
    );
    report_line(&mut out, report);
    out
}

fn verdict_block(out: &mut String, report: &DoctorReport) {
    let _ = writeln!(out, "boundary: {}", report.verdict);
    match report.verdict {
        Verdict::Established => out.push_str(
            "  this process is held to the public socket: every private path, endpoint\n  \
             and broker it probed was denied or absent.\n",
        ),
        Verdict::NotEstablished => out.push_str(
            "  this process can reach PAM's private state; GUI-only administration is a\n  \
             convention on this machine, not a boundary. Apply a sandbox profile to the\n  \
             agent (pam doctor --profile <harness>) and run pam doctor again from inside it.\n",
        ),
        Verdict::CannotProbe => out.push_str(
            "  the public endpoint did not acknowledge the hello, so nothing can be judged\n  \
             from here; see public.reach.\n",
        ),
    }
    if !report.failed.is_empty() {
        let _ = writeln!(out, "  failed: {}", ids(&report.failed));
    }
    if !report.unverified.is_empty() {
        let _ = writeln!(out, "  unverified: {}", ids(&report.unverified));
    }
    if report.skipped.is_empty() {
        out.push_str("  skipped: none\n");
    } else {
        let _ = writeln!(
            out,
            "  skipped (counted neither way): {}",
            skipped(&report.skipped)
        );
    }
}

fn daemon_line(out: &mut String, report: &DoctorReport) {
    match &report.daemon {
        Some(daemon) => {
            let _ = writeln!(
                out,
                "daemon: version {} proto {} epoch {} via {}",
                daemon.version,
                daemon.proto,
                daemon.epoch,
                match daemon.via {
                    pam_proto::wire::Via::Direct => "direct",
                    pam_proto::wire::Via::Relay => "relay",
                }
            );
        }
        None => out.push_str("daemon: not reached\n"),
    }
}

fn probe_line(out: &mut String, probe: &Probe) {
    let _ = write!(
        out,
        "  {:<24} {:<10} {:<10}",
        probe.id.as_str(),
        probe.class.as_str(),
        probe.result.as_str()
    );
    let mut details = Vec::new();
    if let Some(os_error) = &probe.os_error
        && probe.result != ProbeState::Allowed
    {
        let mut text = os_error.kind.clone();
        if let Some(code) = os_error.code {
            let _ = write!(text, " ({code})");
        }
        if let Some(detail) = &os_error.detail {
            let _ = write!(text, ": {detail}");
        }
        details.push(text);
    }
    if let Some(note) = &probe.note {
        details.push(note.clone());
    }
    if let Some(elapsed) = probe.elapsed_ms {
        details.push(format!("{elapsed} ms"));
    }
    if !details.is_empty() {
        out.push(' ');
        out.push_str(&details.join("; "));
    }
    out.push('\n');
}

fn env_block(out: &mut String, report: &DoctorReport) {
    let env = &report.env;
    out.push_str("env:\n");
    let _ = writeln!(out, "  base: {}", env.resolved_base);
    let _ = writeln!(out, "  endpoint: {}", env.resolved_endpoint);
    let _ = writeln!(
        out,
        "  socket_dir: {}",
        env.socket_dir.as_deref().unwrap_or("unset")
    );
    let _ = writeln!(
        out,
        "  base_dir_override: {}",
        env.base_dir_override.as_deref().unwrap_or("unset")
    );
    let _ = writeln!(out, "  client_version: {}", env.client_version);
    let _ = writeln!(out, "  exe: {}", env.exe.as_deref().unwrap_or("unknown"));
    let _ = writeln!(
        out,
        "  cwd_repo: {}",
        env.cwd_repo.as_deref().unwrap_or("none")
    );
    let _ = writeln!(
        out,
        "  frontend: {}",
        match env.frontend {
            pam_proto::doctor::Frontend::Embedded => "embedded",
            pam_proto::doctor::Frontend::DevelopmentServer =>
                "development_server (not a trusted surface)",
        }
    );
    if env.harness_chain.is_empty() {
        out.push_str("  harness_chain: unknown\n");
    } else {
        let _ = writeln!(out, "  harness_chain: {}", env.harness_chain.join(" < "));
    }
}

fn report_line(out: &mut String, report: &DoctorReport) {
    match &report.report {
        Some(record) if record.recorded => {
            let _ = writeln!(
                out,
                "report: recorded as {}",
                record.request_id.as_deref().unwrap_or("(no request id)")
            );
        }
        Some(record) => {
            let _ = writeln!(
                out,
                "report: not sent ({})",
                record.reason.as_deref().unwrap_or("no reason given")
            );
        }
        None => out.push_str("report: not sent\n"),
    }
}

fn ids(ids: &[pam_proto::doctor::ProbeId]) -> String {
    ids.iter()
        .map(|id| id.as_str())
        .collect::<Vec<_>>()
        .join(" ")
}

fn skipped(rows: &[Skipped]) -> String {
    rows.iter()
        .map(|row| format!("{} ({})", row.id.as_str(), row.why))
        .collect::<Vec<_>>()
        .join(", ")
}
