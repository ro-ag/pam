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
