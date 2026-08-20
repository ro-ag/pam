use std::{path::PathBuf, time::Duration};

use clap::Parser;
use pam_core::{ApprovalId, EvidenceHandle, IdempotencyKey, RequestId};
use pam_policy::{CapabilityName, ResourceName};

use super::command::{CallerKindArg, Cli, Mode, RetentionScopeArg};

#[test]
fn no_subcommand_selects_client_mode() {
    assert_eq!(Cli::try_parse_from(["pam"]).unwrap().mode(), Mode::Client);
}

#[test]
fn model_generation_debug_redacts_prompt_and_system_content() {
    let secret_prompt = "private-cli-prompt-do-not-log";
    let secret_system = "private-cli-system-do-not-log";
    let arguments = [
        "pam",
        "model",
        "generate",
        "vendor/model",
        secret_prompt,
        "--system",
        secret_system,
    ];
    let cli = Cli::try_parse_from(arguments).unwrap();
    let cli_debug = format!("{cli:?}");
    assert!(!cli_debug.contains(secret_prompt));
    assert!(!cli_debug.contains(secret_system));
    assert!(cli_debug.contains(&format!("prompt_bytes: {}", secret_prompt.len())));
    assert!(cli_debug.contains(&format!("system_bytes: {}", secret_system.len())));

    let mode_debug = format!("{:?}", Cli::try_parse_from(arguments).unwrap().mode());
    assert!(!mode_debug.contains(secret_prompt));
    assert!(!mode_debug.contains(secret_system));
    assert!(mode_debug.contains(&format!("prompt_bytes: {}", secret_prompt.len())));
    assert!(mode_debug.contains(&format!("system_bytes: {}", secret_system.len())));
}

#[test]
fn explicit_subcommands_select_runtime_modes() {
    assert_eq!(
        Cli::try_parse_from(["pam", "status"]).unwrap().mode(),
        Mode::Status { approval_id: None }
    );
    assert_eq!(
        Cli::try_parse_from(["pam", "brief"]).unwrap().mode(),
        Mode::Brief { approval_id: None }
    );
    assert_eq!(
        Cli::try_parse_from(["pam", "daemon", "--recover"])
            .unwrap()
            .mode(),
        Mode::Daemon {
            recover: true,
            model: None,
        }
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
        Cli::try_parse_from([
            "pam",
            "model",
            "generate",
            "byteshape/qwen3.6-q4ks",
            "What is 37 + 58?",
            "--system",
            "Answer briefly.",
            "--tokens",
            "64",
            "--timeout",
            "2m",
        ])
        .unwrap()
        .mode(),
        Mode::ModelGenerate {
            model: pam_model::ModelKey::new("byteshape", "qwen3.6-q4ks").unwrap(),
            prompt: "What is 37 + 58?".to_owned(),
            system: Some("Answer briefly.".to_owned()),
            tokens: 64,
            timeout: Duration::from_mins(2),
            approval_id: None,
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
        Mode::NetworkDiagnostics { approval_id: None }
    );
}

#[test]
fn flow_subcommands_select_all_runtime_modes_in_the_public_namespace() {
    let approval = ApprovalId::from("approval-1");
    assert_eq!(
        Cli::try_parse_from([
            "pam",
            "flow",
            "run",
            "after-merge",
            "--run-id",
            "run-1",
            "--idempotency-key",
            "stable-1",
            "--timeout",
            "5m",
            "--approval-id",
            "approval-1",
        ])
        .unwrap()
        .mode(),
        Mode::FlowRun {
            selector: "after-merge".to_owned(),
            run_id: Some(RequestId::from("run-1")),
            idempotency_key: Some(IdempotencyKey::from("stable-1")),
            timeout: Duration::from_mins(5),
            approval_id: Some(approval.clone()),
        }
    );
    assert_eq!(
        Cli::try_parse_from(["pam", "flow", "list"]).unwrap().mode(),
        Mode::FlowList
    );
    assert_eq!(
        Cli::try_parse_from(["pam", "flow", "show", "after-merge"])
            .unwrap()
            .mode(),
        Mode::FlowShow {
            selector: "after-merge".to_owned(),
        }
    );
    assert_eq!(
        Cli::try_parse_from(["pam", "flow", "validate"])
            .unwrap()
            .mode(),
        Mode::FlowValidate { selector: None }
    );
    assert_eq!(
        Cli::try_parse_from(["pam", "flow", "cancel", "run-1"])
            .unwrap()
            .mode(),
        Mode::FlowCancel {
            run_id: RequestId::from("run-1"),
            approval_id: None,
        }
    );
    assert_eq!(
        Cli::try_parse_from(["pam", "flow", "logs", "run-1", "--after", "7"])
            .unwrap()
            .mode(),
        Mode::FlowLogs {
            run_id: RequestId::from("run-1"),
            after: 7,
            approval_id: None,
        }
    );
    assert_eq!(
        Cli::try_parse_from(["pam", "flow", "wait", "run-1", "--after", "8"])
            .unwrap()
            .mode(),
        Mode::FlowWait {
            run_id: RequestId::from("run-1"),
            after: 8,
            timeout: Duration::from_secs(30),
            approval_id: None,
        }
    );
    assert_eq!(
        Cli::try_parse_from([
            "pam",
            "flow",
            "result",
            "run-1",
            "--approval-id",
            "approval-1",
        ])
        .unwrap()
        .mode(),
        Mode::FlowResult {
            run_id: RequestId::from("run-1"),
            approval_id: Some(approval),
        }
    );
}

#[test]
fn flow_commands_reject_missing_or_unsafe_bounded_arguments() {
    for arguments in [
        vec!["pam", "flow", "run"],
        vec!["pam", "flow", "cancel"],
        vec!["pam", "flow", "logs", "bad id"],
        vec!["pam", "flow", "cancel", "generic@request"],
        vec!["pam", "flow", "logs", "generic@request"],
        vec!["pam", "flow", "wait", "generic@request"],
        vec!["pam", "flow", "result", "generic@request"],
        vec!["pam", "flow", "wait", "run-1", "--timeout", "0s"],
        vec!["pam", "flow", "run", "x", "--idempotency-key", "bad key"],
        vec!["pam", "flow", "run", "x", "--idempotency-key", "bad;key"],
        vec!["pam", "flow", "run", "x", "--idempotency-key", "$(bad)"],
        vec!["pam", "flow", "run", "x", "--idempotency-key", "-bad"],
        vec![
            "pam",
            "flow",
            "logs",
            "run-1",
            "--after",
            "9223372036854775808",
        ],
    ] {
        assert!(Cli::try_parse_from(arguments).is_err());
    }
    assert!(Cli::try_parse_from(["pam", "wait", "generic@request"]).is_ok());
    assert!(Cli::try_parse_from(["pam", "result", "generic@request"]).is_ok());
}

#[test]
fn direct_model_runtime_and_import_require_explicit_bounded_inputs() {
    let digest = format!("sha256:{}", "ab".repeat(32));
    let license_digest = format!("sha256:{}", "cd".repeat(32));
    let model = pam_model::ModelKey::new("byteshape", "qwen3.6-q4ks").unwrap();

    assert_eq!(
        Cli::try_parse_from(["pam", "daemon", "--model", "byteshape/qwen3.6-q4ks",])
            .unwrap()
            .mode(),
        Mode::Daemon {
            recover: false,
            model: Some(model.clone()),
        }
    );
    assert_eq!(
        Cli::try_parse_from([
            "pam",
            "model",
            "import",
            "byteshape/qwen3.6-q4ks",
            "--path",
            "/tmp/model.gguf",
            "--digest",
            &digest,
            "--size-bytes",
            "16492334496",
            "--license-id",
            "Apache-2.0",
            "--license-url",
            "https://example.test/LICENSE",
            "--license-notice-digest",
            &license_digest,
            "--accept-license",
        ])
        .unwrap()
        .mode(),
        Mode::ModelImport {
            model,
            path: PathBuf::from("/tmp/model.gguf"),
            digest: pam_core::ContentDigest::parse(digest).unwrap(),
            size_bytes: 16_492_334_496,
            license_id: "Apache-2.0".to_owned(),
            license_url: "https://example.test/LICENSE".to_owned(),
            license_notice_digest: pam_core::ContentDigest::parse(license_digest).unwrap(),
            accept_license: true,
            approval_id: None,
        }
    );

    for arguments in [
        vec!["pam", "daemon", "--model", "bad/model/extra"],
        vec!["pam", "model", "import", "vendor/model"],
        vec![
            "pam",
            "model",
            "generate",
            "vendor/model",
            "hi",
            "--tokens",
            "0",
        ],
        vec![
            "pam",
            "model",
            "generate",
            "vendor/model",
            "hi",
            "--tokens",
            "4097",
        ],
        vec![
            "pam",
            "model",
            "generate",
            "vendor/model",
            "hi",
            "--timeout",
            "11m",
        ],
    ] {
        assert!(Cli::try_parse_from(arguments).is_err());
    }
}

#[test]
fn daemon_backed_commands_accept_explicit_approval_receipts() {
    let approval_id = ApprovalId::from("approval-1");

    assert_eq!(
        Cli::try_parse_from(["pam", "status", "--approval-id", "approval-1"])
            .unwrap()
            .mode(),
        Mode::Status {
            approval_id: Some(approval_id.clone()),
        }
    );
    assert_eq!(
        Cli::try_parse_from(["pam", "brief", "--approval-id", "approval-1"])
            .unwrap()
            .mode(),
        Mode::Brief {
            approval_id: Some(approval_id.clone()),
        }
    );
    assert_eq!(
        Cli::try_parse_from(["pam", "wait", "request-42", "--approval-id", "approval-1",])
            .unwrap()
            .mode(),
        Mode::Wait {
            request_id: RequestId::from("request-42"),
            after: 0,
            timeout: Duration::from_secs(30),
            approval_id: Some(approval_id.clone()),
        }
    );
    assert_eq!(
        Cli::try_parse_from(["pam", "result", "request-42", "--approval-id", "approval-1",])
            .unwrap()
            .mode(),
        Mode::Result {
            request_id: RequestId::from("request-42"),
            approval_id: Some(approval_id.clone()),
        }
    );
    assert_eq!(
        Cli::try_parse_from([
            "pam",
            "network",
            "diagnostics",
            "--approval-id",
            "approval-1",
        ])
        .unwrap()
        .mode(),
        Mode::NetworkDiagnostics {
            approval_id: Some(approval_id),
        }
    );
}

#[test]
fn evidence_show_rejects_one_request_approval_receipts() {
    assert!(
        Cli::try_parse_from([
            "pam",
            "evidence",
            "show",
            "evidence://ci/1842/failure",
            "--approval-id",
            "approval-1",
        ])
        .is_err()
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
            approval_id: None,
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
                approval_id: None,
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
            approval_id: None,
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
