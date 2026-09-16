use super::{Cli, Cmd, EvidenceCmd, EvidenceReadArgs, evidence_read_args, render_evidence};
use clap::Parser;
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
