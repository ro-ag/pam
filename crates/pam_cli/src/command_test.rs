use std::{path::PathBuf, time::Duration};

use clap::Parser;
use pam_core::{ApprovalId, EvidenceHandle, RequestId};
use pam_policy::{CapabilityName, ResourceName};

use super::command::{CallerKindArg, Cli, Mode, RetentionScopeArg};

#[test]
fn no_subcommand_selects_client_mode() {
    assert_eq!(Cli::try_parse_from(["pam"]).unwrap().mode(), Mode::Client);
}

#[test]
fn explicit_subcommands_select_runtime_modes() {
    assert_eq!(
        Cli::try_parse_from(["pam", "status"]).unwrap().mode(),
        Mode::Status
    );
    assert_eq!(
        Cli::try_parse_from(["pam", "brief"]).unwrap().mode(),
        Mode::Brief
    );
    assert_eq!(
        Cli::try_parse_from(["pam", "daemon", "--recover"])
            .unwrap()
            .mode(),
        Mode::Daemon { recover: true }
    );
    assert_eq!(
        Cli::try_parse_from(["pam", "gui"]).unwrap().mode(),
        Mode::Gui
    );
    assert_eq!(
        Cli::try_parse_from(["pam", "caller", "register"])
            .unwrap()
            .mode(),
        Mode::CallerRegister {
            kind: CallerKindArg::Cli,
        }
    );
    assert_eq!(
        Cli::try_parse_from(["pam", "caller", "revoke", "--kind", "coding-agent"])
            .unwrap()
            .mode(),
        Mode::CallerRevoke {
            kind: CallerKindArg::CodingAgent,
        }
    );
    assert_eq!(
        Cli::try_parse_from([
            "pam",
            "access",
            "grant",
            "evidence.read",
            "--resource",
            "evidence:failure",
            "--require-approval",
        ])
        .unwrap()
        .mode(),
        Mode::AccessGrant {
            capability: CapabilityName::parse("evidence.read").unwrap(),
            resource: Some(ResourceName::parse("evidence:failure").unwrap()),
            deny: false,
            require_approval: true,
            expires_at_unix_ms: None,
            kind: CallerKindArg::Cli,
        }
    );
    assert_eq!(
        Cli::try_parse_from(["pam", "approval", "approve", "approval-1"])
            .unwrap()
            .mode(),
        Mode::ApprovalApprove {
            approval_id: ApprovalId::from("approval-1"),
        }
    );
    assert_eq!(
        Cli::try_parse_from(["pam", "network", "diagnostics"])
            .unwrap()
            .mode(),
        Mode::NetworkDiagnostics
    );
}

#[test]
fn audit_and_retention_subcommands_select_runtime_modes() {
    assert_eq!(
        Cli::try_parse_from(["pam", "audit", "export", "--output", "audit.ndjson"])
            .unwrap()
            .mode(),
        Mode::AuditExport {
            output: PathBuf::from("audit.ndjson"),
            after: 0,
            through: None,
            approval_id: None,
            limit: 500,
        }
    );
    assert_eq!(
        Cli::try_parse_from([
            "pam",
            "retention",
            "prune",
            "--scope",
            "session",
            "--before-unix-ms",
            "1700000000000",
            "--limit",
            "12",
        ])
        .unwrap()
        .mode(),
        Mode::RetentionPrune {
            scope: RetentionScopeArg::Session,
            before_unix_ms: 1_700_000_000_000,
            approval_id: None,
            limit: 12,
        }
    );
}

#[test]
fn audit_and_retention_commands_require_safe_bounded_arguments() {
    for arguments in [
        vec!["pam", "audit", "export"],
        vec![
            "pam", "audit", "export", "--output", "audit", "--limit", "0",
        ],
        vec![
            "pam", "audit", "export", "--output", "audit", "--limit", "1001",
        ],
        vec!["pam", "retention", "prune"],
        vec!["pam", "retention", "prune", "--scope", "session"],
        vec!["pam", "retention", "prune", "--scope", "persistent"],
    ] {
        assert!(Cli::try_parse_from(arguments).is_err());
    }
}

#[test]
fn wait_selects_request_replay_with_a_bounded_default_timeout() {
    assert_eq!(
        Cli::try_parse_from(["pam", "wait", "request-42"])
            .unwrap()
            .mode(),
        Mode::Wait {
            request_id: RequestId::from("request-42"),
            after: 0,
            timeout: Duration::from_secs(30),
        }
    );
}

#[test]
fn wait_accepts_sequence_and_supported_duration_units() {
    let cases = [
        ("500ms", Duration::from_millis(500)),
        ("45s", Duration::from_secs(45)),
        ("5m", Duration::from_mins(5)),
        ("24h", Duration::from_hours(24)),
    ];

    for (argument, expected) in cases {
        assert_eq!(
            Cli::try_parse_from([
                "pam",
                "wait",
                "request-42",
                "--after",
                "7",
                "--timeout",
                argument,
            ])
            .unwrap()
            .mode(),
            Mode::Wait {
                request_id: RequestId::from("request-42"),
                after: 7,
                timeout: expected,
            }
        );
    }
}

#[test]
fn result_selects_non_blocking_request_inspection() {
    assert_eq!(
        Cli::try_parse_from(["pam", "result", "request-42"])
            .unwrap()
            .mode(),
        Mode::Result {
            request_id: RequestId::from("request-42"),
        }
    );
}

#[test]
fn evidence_show_accepts_default_raw_and_platform_native_output_modes() {
    let handle = EvidenceHandle::parse("evidence://ci/1842/failure").unwrap();
    assert_eq!(
        Cli::try_parse_from(["pam", "evidence", "show", handle.as_str()])
            .unwrap()
            .mode(),
        Mode::EvidenceShow {
            handle: handle.clone(),
            raw: false,
            output: None,
        }
    );
    assert_eq!(
        Cli::try_parse_from(["pam", "evidence", "show", handle.as_str(), "--raw"])
            .unwrap()
            .mode(),
        Mode::EvidenceShow {
            handle: handle.clone(),
            raw: true,
            output: None,
        }
    );
    assert_eq!(
        Cli::try_parse_from([
            "pam",
            "evidence",
            "show",
            handle.as_str(),
            "--output",
            "retained evidence.log",
        ])
        .unwrap()
        .mode(),
        Mode::EvidenceShow {
            handle,
            raw: false,
            output: Some(PathBuf::from("retained evidence.log")),
        }
    );
}

#[test]
fn wait_rejects_missing_or_invalid_request_and_sequence_values() {
    for arguments in [
        vec!["pam", "wait"],
        vec!["pam", "wait", ""],
        vec!["pam", "wait", " request-42"],
        vec!["pam", "wait", "request 42"],
        vec!["pam", "wait", "request-\u{1b}42"],
        vec!["pam", "wait", "request-42", "--after", "not-a-sequence"],
    ] {
        assert!(Cli::try_parse_from(arguments).is_err());
    }
}

#[test]
fn wait_rejects_zero_excessive_fractional_unitless_and_overflowing_durations() {
    for duration in [
        "0ms",
        "0s",
        "25h",
        "1.5s",
        "30",
        "1d",
        "18446744073709551615h",
    ] {
        assert!(
            Cli::try_parse_from(["pam", "wait", "request-42", "--timeout", duration]).is_err(),
            "{duration} should be rejected"
        );
    }
}

#[test]
fn result_rejects_missing_or_non_canonical_request_ids() {
    for arguments in [
        vec!["pam", "result"],
        vec!["pam", "result", ""],
        vec!["pam", "result", "request-42 "],
        vec!["pam", "result", "request\n42"],
    ] {
        assert!(Cli::try_parse_from(arguments).is_err());
    }
}

#[test]
fn evidence_show_rejects_missing_invalid_and_conflicting_arguments() {
    for arguments in [
        vec!["pam", "evidence"],
        vec!["pam", "evidence", "show"],
        vec!["pam", "evidence", "show", "../blob"],
        vec!["pam", "evidence", "show", "evidence://ci/../failure"],
        vec![
            "pam",
            "evidence",
            "show",
            "evidence://ci/1842/failure",
            "--raw",
            "--output",
            "evidence.log",
        ],
        vec![
            "pam",
            "evidence",
            "show",
            "evidence://ci/1842/failure",
            "--output",
        ],
    ] {
        assert!(Cli::try_parse_from(arguments).is_err());
    }
}
