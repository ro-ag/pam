//! The human and JSON renderings.

use std::path::PathBuf;
use std::sync::Arc;

use pam_proto::doctor::{
    DoctorReport, EnvFacts, Frontend, Platform, ProbeId, ReportRecord, Verdict,
};

use super::os_test::FakeOs;
use super::{Options, profile_name, render_human, render_json, run_with};

fn run_fake(os: FakeOs) -> DoctorReport {
    run_with(
        &Options::new(PathBuf::from("/tmp/pamdoc-base")),
        Arc::new(os),
    )
    .unwrap()
}

#[test]
fn the_human_text_names_the_verdict_every_probe_the_facts_and_the_profile() {
    let report = run_fake(FakeOs::unsandboxed());
    let text = render_human(&report);
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines[0], "boundary: not_established");
    assert!(text.contains("GUI-only administration is a"));
    assert!(text.contains(if cfg!(windows) {
        "  failed: run.lock_write admin.control_read"
    } else {
        "  failed: run.lock_write admin.endpoint"
    }));
    assert!(
        text.contains("  skipped (counted neither way): public.unlink (not_probed: side effect), ")
    );
    if cfg!(not(windows)) {
        assert!(text.contains("bundle.write (absent: not inside an application bundle)"));
    }
    assert!(text.contains("daemon: version 0.4.3 proto 2 epoch 01JBEPOCH via direct"));
    // One line per probe, in inventory order, with id, class and result.
    let probe_lines: Vec<&str> = lines
        .iter()
        .copied()
        .filter(|line| {
            line.starts_with("  ")
                && ProbeId::all().any(|id| line.trim_start().starts_with(id.as_str()))
        })
        .collect();
    assert_eq!(probe_lines.len(), report.probes.len());
    for (line, probe) in probe_lines.iter().zip(&report.probes) {
        assert!(line.trim_start().starts_with(probe.id.as_str()), "{line}");
        assert!(line.contains(probe.class.as_str()), "{line}");
        assert!(line.contains(probe.result.as_str()), "{line}");
    }
    assert!(text.contains("  public.reach             must_allow allowed"));
    assert!(text.contains(if cfg!(windows) {
        "  admin.endpoint           must_deny  not_probed not probed on windows"
    } else {
        "  admin.control_read       must_deny  not_probed not probed on macos"
    }));
    let endpoint = std::path::Path::new("/tmp/pamdoc-base")
        .join("run")
        .join(if cfg!(windows) {
            "public.json"
        } else {
            "pam.sock"
        });
    assert!(text.contains(&format!(
        "env:\n  base: /tmp/pamdoc-base\n  endpoint: {}\n",
        endpoint.display()
    )));
    assert!(text.contains(if cfg!(windows) {
        "  harness_chain: claude.exe < cmd.exe < explorer.exe\n"
    } else {
        "  harness_chain: zsh < claude < launchd\n"
    }));
    assert!(text.contains("profile: pam doctor --profile claude-code\n"));
    assert!(text.ends_with("report: not sent\n"));
    assert!(!text.contains('\u{1b}'), "no colour codes");
}

#[test]
fn an_established_report_and_the_record_line() {
    let mut report = run_fake(FakeOs::sandboxed());
    assert_eq!(report.verdict, Verdict::Established);
    let text = render_human(&report);
    assert!(text.starts_with("boundary: established\n  this process is held to the public socket"));
    assert!(!text.contains("failed:"));
    // EACCES on unix, ERROR_ACCESS_DENIED on Windows.
    let access_denied = if cfg!(windows) { 5 } else { 13 };
    assert!(text.contains(&format!(
        "  store.read               must_deny  denied     PermissionDenied ({access_denied});"
    )));
    report.report = Some(ReportRecord {
        recorded: true,
        request_id: Some("req_01J".to_owned()),
        reason: None,
    });
    assert!(render_human(&report).ends_with("report: recorded as req_01J\n"));
    report.report = Some(ReportRecord {
        recorded: false,
        request_id: None,
        reason: Some("daemon refused".to_owned()),
    });
    assert!(render_human(&report).ends_with("report: not sent (daemon refused)\n"));
}

#[test]
fn a_cannot_probe_report_says_why() {
    let report = run_fake(FakeOs::unsandboxed().with_hello(super::os::HelloAnswer::Silent));
    let text = render_human(&report);
    assert!(text.starts_with("boundary: cannot_probe\n  the public endpoint did not acknowledge"));
    assert!(text.contains("daemon: not reached\n"));
}

// The fake's chain is a `ps` walk; the Windows walk is one fixed script.
#[cfg(unix)]
#[test]
fn the_profile_falls_back_per_platform() {
    let mut os = FakeOs::unsandboxed();
    os.chain = vec!["zsh".to_owned()];
    let report = run_fake(os);
    assert_eq!(profile_name(&report), "sandbox-exec");
}

#[test]
fn the_profile_name_on_windows_without_a_chain_match_is_the_placeholder() {
    let windows = DoctorReport::new(
        Platform::Windows,
        0,
        None,
        Vec::new(),
        EnvFacts {
            socket_dir: None,
            base_dir_override: None,
            resolved_base: String::new(),
            resolved_endpoint: String::new(),
            client_version: String::new(),
            exe: None,
            cwd_repo: None,
            frontend: Frontend::Embedded,
            harness_chain: Vec::new(),
        },
    );
    assert_eq!(profile_name(&windows), "<harness>");
}

#[test]
fn the_json_is_the_exact_serde_document() {
    let report = run_fake(FakeOs::unsandboxed());
    let json = render_json(&report);
    assert_eq!(json, serde_json::to_string_pretty(&report).unwrap());
    let parsed: DoctorReport = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed, report);
    let value: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(value["schema_version"], 1);
    assert_eq!(value["verdict"], "not_established");
    assert_eq!(value["probes"][0]["id"], "public.reach");
    assert_eq!(value["report"], serde_json::Value::Null);
}
