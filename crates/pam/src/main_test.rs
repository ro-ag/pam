use super::{
    Cli, Cmd, DOCTOR_TIMEOUT_MS, EvidenceCmd, EvidenceReadArgs, PolicyCmd, ServiceCmd,
    evidence_read_args, render_evidence, resolved_profile_base,
};
use clap::Parser;
use pam_daemon::managed_policy::TargetPlatform;
use serde_json::json;

fn parse(extra: &[&str]) -> EvidenceReadArgs {
    let mut args = vec![
        "pam",
        "evidence",
        "read",
        "ev_source",
        "--request",
        "ticket",
    ];
    args.extend_from_slice(extra);
    let Cmd::Evidence {
        action: EvidenceCmd::Read(args),
    } = Cli::try_parse_from(args).unwrap().command
    else {
        panic!("expected the static evidence command");
    };
    args
}

#[test]
fn first_evidence_read_uses_bounded_defaults_without_guessing_a_view() {
    assert_eq!(
        evidence_read_args(&parse(&["--json"])).unwrap(),
        json!({
            "evidence_id": "ev_source", "request_id": "ticket", "offset": 0, "length": 16_384,
        })
    );
}

#[test]
fn evidence_ranges_require_valid_lengths_and_matching_view_identity() {
    for extra in [
        vec!["--length", "0"],
        vec!["--length", "65537"],
        vec!["--length", "-1"],
        vec!["--view", "view"],
        vec!["--digest", "abc"],
    ] {
        let mut args = vec![
            "pam",
            "evidence",
            "read",
            "ev_source",
            "--request",
            "ticket",
        ];
        args.extend(extra);
        assert!(Cli::try_parse_from(args).is_err());
    }
    assert!(evidence_read_args(&parse(&["--offset", "1"])).is_err());
    assert!(evidence_read_args(&parse(&["--view", "view", "--digest", "xyz"])).is_err());
    let digest = "AB".repeat(32);
    let request = evidence_read_args(&parse(&[
        "--offset",
        "16384",
        "--length",
        "65536",
        "--view",
        "immutable-view",
        "--digest",
        &digest,
    ]))
    .unwrap();
    assert_eq!(request["expected_view_id"], "immutable-view");
    assert_eq!(request["expected_sha256"], digest.to_ascii_lowercase());
    assert_eq!(request["length"], 65_536);
    assert_eq!(request["offset"], 16_384);
}

#[test]
fn evidence_text_preserves_binary_bytes_and_escapes_terminal_controls() {
    let body = json!({
        "encoding": "hex", "data": "411b5b326a00ff0ac3", "returned_bytes": 9,
        "view_id": "view\u{202e}", "view_sha256": "ab", "next_offset": 9,
        "identity": { "name": "name\u{1b}]52;clipboard" },
    });
    let rendered = render_evidence(&body).unwrap();
    assert!(rendered.is_ascii());
    assert!(!rendered.contains('\u{1b}'));
    assert!(!rendered.contains('\0'));
    assert!(rendered.contains(r#"data (escaped bytes): b"A\x1b[2j\x00\xff\n\xc3""#));
    assert!(rendered.contains("next_offset"));
    assert!(rendered.contains("view_sha256"));
    assert!(!rendered.contains("411b5b326a00ff0ac3"));
    assert_eq!(
        body["data"], "411b5b326a00ff0ac3",
        "rendering does not mutate JSON bytes"
    );
}

#[test]
fn malformed_or_oversized_evidence_is_not_silently_decoded() {
    for data in ["0", "zz", "é0"] {
        assert!(render_evidence(&json!({ "encoding": "hex", "data": data })).is_err());
    }
    assert!(render_evidence(&json!({ "encoding": "utf8", "data": "text" })).is_err());
    assert!(render_evidence(&json!({ "encoding": "hex", "data": "00".repeat(65_537) })).is_err());
}

#[test]
fn workflow_commands_have_bounded_discovery_and_typed_arguments() {
    use super::FlowCmd;
    let Cmd::Flow {
        action: FlowCmd::List {
            offset,
            limit,
            json,
        },
    } = Cli::try_parse_from(["pam", "flow", "list", "--json"])
        .unwrap()
        .command
    else {
        panic!("list");
    };
    assert_eq!((offset, limit, json), (0, 20, true));
    for limit in ["0", "51", "4294967296"] {
        assert!(Cli::try_parse_from(["pam", "flow", "list", "--limit", limit]).is_err());
    }
    let Cmd::Flow {
        action: FlowCmd::Inspect { id, inputs, json },
    } = Cli::try_parse_from(["pam", "flow", "inspect", "ci", "build=123", "--json"])
        .unwrap()
        .command
    else {
        panic!("inspect");
    };
    assert_eq!(id, "ci");
    assert_eq!(inputs, ["build=123"]);
    assert!(json);
    assert!(matches!(
        Cli::try_parse_from(["pam", "flow", "result", "ticket", "--json"])
            .unwrap()
            .command,
        Cmd::Flow {
            action: FlowCmd::Result { json: true, .. }
        }
    ));
    assert!(matches!(
        Cli::try_parse_from(["pam", "wait", "ticket", "--json"])
            .unwrap()
            .command,
        Cmd::Wait { json: true, .. }
    ));
}

#[test]
fn follow_commands_share_the_json_flag_and_the_default_timeout() {
    use crate::DEFAULT_FOLLOW_TIMEOUT_MS;
    let Cmd::Subscribe {
        ticket,
        timeout_ms,
        json,
    } = Cli::try_parse_from(["pam", "subscribe", "ticket", "--json"])
        .unwrap()
        .command
    else {
        panic!("subscribe");
    };
    assert_eq!(ticket, "ticket");
    assert_eq!(timeout_ms, DEFAULT_FOLLOW_TIMEOUT_MS);
    assert!(json);
    let Cmd::Wait { timeout_ms, .. } =
        Cli::try_parse_from(["pam", "wait", "ticket", "--timeout-ms", "250"])
            .unwrap()
            .command
    else {
        panic!("wait");
    };
    assert_eq!(timeout_ms, 250);
}

#[test]
fn the_last_of_echo_wait_and_no_wait_wins() {
    let flags = |argv: &[&str]| {
        let mut args = vec!["pam", "echo"];
        args.extend_from_slice(argv);
        let Cmd::Echo { wait, no_wait, .. } = Cli::try_parse_from(args).unwrap().command else {
            panic!("echo");
        };
        // The dispatch rule: wait unless `--no-wait` stands unrevoked.
        wait || !no_wait
    };
    assert!(flags(&[]));
    assert!(flags(&["--wait"]));
    assert!(!flags(&["--no-wait"]));
    assert!(flags(&["--no-wait", "--wait"]));
    assert!(!flags(&["--wait", "--no-wait"]));
}

/// The login unit only ever carries a base directory somebody typed on the command line:
/// `--base-dir` exists on `install` alone, and is optional.
#[test]
fn only_service_install_takes_an_explicit_base_dir() {
    let Cmd::Service {
        action: ServiceCmd::Install { base_dir, .. },
    } = Cli::try_parse_from(["pam", "service", "install"])
        .unwrap()
        .command
    else {
        panic!("expected service install");
    };
    assert_eq!(
        base_dir, None,
        "no flag means the default base, not $PAM_BASE_DIR"
    );

    let Cmd::Service {
        action: ServiceCmd::Install { base_dir, .. },
    } = Cli::try_parse_from(["pam", "service", "install", "--base-dir", "/srv/pam"])
        .unwrap()
        .command
    else {
        panic!("expected service install");
    };
    assert_eq!(base_dir.as_deref(), Some(std::path::Path::new("/srv/pam")));

    for action in ["status", "uninstall"] {
        assert!(
            Cli::try_parse_from(["pam", "service", action, "--base-dir", "/srv/pam"]).is_err(),
            "service {action} has no base override"
        );
    }
}

// --- pam doctor -------------------------------------------------------------

#[test]
fn doctor_parses_its_probe_flags_with_the_engines_default_bound() {
    let Cmd::Doctor {
        json,
        no_report,
        timeout_ms,
        profile,
        base,
        managed,
    } = Cli::try_parse_from(["pam", "doctor"]).unwrap().command
    else {
        panic!("expected the doctor command");
    };
    assert!(!json && !no_report && !managed);
    assert_eq!(timeout_ms, DOCTOR_TIMEOUT_MS);
    assert_eq!(
        u128::from(DOCTOR_TIMEOUT_MS),
        pam::doctor::DEFAULT_TIMEOUT.as_millis()
    );
    assert_eq!(profile, None);
    assert_eq!(base, None);

    let Cmd::Doctor {
        json,
        no_report,
        timeout_ms,
        ..
    } = Cli::try_parse_from([
        "pam",
        "doctor",
        "--json",
        "--no-report",
        "--timeout-ms",
        "500",
    ])
    .unwrap()
    .command
    else {
        panic!("expected the doctor command");
    };
    assert!(json && no_report);
    assert_eq!(timeout_ms, 500);
}

#[test]
fn doctor_profile_takes_a_base_and_managed_only_beside_it() {
    let Cmd::Doctor {
        profile,
        base,
        managed,
        ..
    } = Cli::try_parse_from([
        "pam",
        "doctor",
        "--profile",
        "claude-code",
        "--base",
        "/tmp/x",
        "--managed",
    ])
    .unwrap()
    .command
    else {
        panic!("expected the doctor command");
    };
    assert_eq!(profile.as_deref(), Some("claude-code"));
    assert_eq!(base.as_deref(), Some(std::path::Path::new("/tmp/x")));
    assert!(managed);

    // `--base` and `--managed` describe a profile; without one they are usage errors,
    // and a profile run neither probes nor reports, so those flags are refused too.
    for args in [
        vec!["pam", "doctor", "--base", "/tmp/x"],
        vec!["pam", "doctor", "--managed"],
        vec!["pam", "doctor", "--profile", "codex", "--json"],
        vec!["pam", "doctor", "--profile", "codex", "--no-report"],
        vec!["pam", "doctor", "--profile", "codex", "--timeout-ms", "5"],
    ] {
        assert!(
            Cli::try_parse_from(&args).is_err(),
            "{args:?} must not parse"
        );
    }
}

#[test]
fn a_profile_base_is_made_absolute_and_left_as_given_when_it_does_not_exist() {
    let missing = std::env::temp_dir().join("pam-doctor-profile-base-that-does-not-exist");
    assert_eq!(resolved_profile_base(&missing), missing);
    let relative = resolved_profile_base(std::path::Path::new("relative/base"));
    assert!(relative.is_absolute(), "{}", relative.display());
    assert!(
        relative.ends_with("relative/base"),
        "{}",
        relative.display()
    );
}

#[cfg(unix)]
#[test]
fn a_profile_base_that_exists_is_resolved_through_links() {
    let tmp = tempfile::tempdir().unwrap();
    let real = tmp.path().join("real");
    std::fs::create_dir(&real).unwrap();
    let link = tmp.path().join("link");
    std::os::unix::fs::symlink(&real, &link).unwrap();
    assert_eq!(
        resolved_profile_base(&link),
        real.canonicalize().unwrap(),
        "Seatbelt matches the resolved path"
    );
}

/// The GUI offers the same harness names as `pam doctor --profile`; the
/// list is pinned here because the frontend cannot ask the binary.
#[test]
fn the_gui_offers_every_profile_name_the_cli_takes() {
    let ipc = include_str!("../../../frontend/src/lib/ipc.ts");
    let (_, rest) = ipc
        .split_once("HARNESS_PROFILES = [")
        .expect("ipc.ts pins HARNESS_PROFILES");
    let (list, _) = rest
        .split_once(']')
        .expect("the HARNESS_PROFILES array closes");
    let offered: Vec<&str> = list
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(|item| item.trim_matches('"'))
        .collect();
    let expected: Vec<&str> = pam::doctor::profiles::Harness::ALL
        .iter()
        .map(|harness| harness.name())
        .collect();
    assert_eq!(
        offered, expected,
        "ipc.ts offers the CLI's profile names in order"
    );
}

/// `pam policy check`'s arguments: the platform defaults to the host,
/// `--for` is the spec's spelling of `--platform`, and nothing but
/// `macos` or `windows` is a platform.
#[test]
fn policy_check_takes_a_file_a_platform_and_the_trust_switch() {
    let parse = |args: &[&str]| {
        let mut argv = vec!["pam", "policy", "check"];
        argv.extend_from_slice(args);
        Cli::try_parse_from(argv).map(|cli| match cli.command {
            Cmd::Policy {
                action:
                    PolicyCmd::Check {
                        file,
                        json,
                        platform,
                        trust,
                    },
            } => (file, json, platform, trust),
            _ => panic!("expected pam policy check"),
        })
    };
    assert_eq!(
        parse(&["policy.json"]).unwrap(),
        ("policy.json".into(), false, None, false)
    );
    assert_eq!(
        parse(&["p.json", "--json", "--platform", "windows", "--trust"]).unwrap(),
        ("p.json".into(), true, Some(TargetPlatform::Windows), true)
    );
    assert_eq!(
        parse(&["p.json", "--for", "macos"]).unwrap().2,
        Some(TargetPlatform::Macos)
    );
    assert!(parse(&["p.json", "--platform", "linux"]).is_err());
    assert!(parse(&[]).is_err(), "the file is required");
}
