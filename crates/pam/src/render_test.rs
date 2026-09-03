use pam_proto::{Event, Outcome, Response};

use crate::render::{
    EXIT_BLOCKED, EXIT_REFUSED, EXIT_UNRESOLVED, exit_code, parse_flow_inputs, render_event,
    render_flow_list, render_flow_result, render_flow_show, render_json, render_refusal,
    render_status, render_ticket,
};

fn result(outcome: Outcome) -> Response {
    Response::Result {
        id: "req_x".to_owned(),
        outcome,
        body: serde_json::json!({}),
        evidence: Vec::new(),
    }
}

#[test]
fn every_response_variant_maps_to_its_documented_exit_code() {
    assert_eq!(exit_code(&result(Outcome::Solved)), 0);
    assert_eq!(exit_code(&result(Outcome::Changed)), 0);
    assert_eq!(exit_code(&result(Outcome::Verified)), 0);
    assert_eq!(exit_code(&result(Outcome::Unresolved)), EXIT_UNRESOLVED);
    assert_eq!(exit_code(&result(Outcome::Blocked)), EXIT_BLOCKED);
    assert_eq!(
        exit_code(&Response::Refusal {
            id: "req_x".to_owned(),
            cause: "not_granted".to_owned(),
            detail: "d".to_owned(),
            recovery: "r".to_owned(),
        }),
        EXIT_REFUSED
    );
    assert_eq!(
        exit_code(&Response::Ticket {
            id: "req_x".to_owned(),
            ticket: "req_x".to_owned(),
            position: 3,
        }),
        0
    );
}

#[test]
fn a_refusal_renders_cause_detail_and_recovery() {
    let text = render_refusal(
        "not_granted",
        "capability \"echo\" has no active grant",
        "Open the PAM GUI to grant it, then retry.",
    );
    assert!(text.contains("refused (not_granted)"), "text: {text}");
    assert!(text.contains("no active grant"), "text: {text}");
    assert!(text.contains("Open the PAM GUI"), "text: {text}");
    // The recovery line is visually set off as the way forward.
    assert!(text.contains('\u{2192}'), "text: {text}");
}

#[test]
fn a_ticket_renders_the_id_and_the_wait_hint() {
    let text = render_ticket("req_abc", 2);
    assert!(text.contains("req_abc"), "text: {text}");
    assert!(text.contains("pam wait req_abc"), "text: {text}");
}

#[test]
fn status_renders_the_daemon_summary() {
    let body = serde_json::json!({
        "daemon_version": "0.1.0",
        "protocol": 1,
        "uptime_s": 3725,
        "active_requests": 2,
    });
    let text = render_status(&body);
    assert!(text.contains("0.1.0"), "text: {text}");
    assert!(text.contains("protocol"), "text: {text}");
    assert!(text.contains("1h 02m 05s"), "text: {text}");
    assert!(text.contains("active requests: 2"), "text: {text}");
}

#[test]
fn status_prints_one_model_line_per_runtime_state() {
    let line = |model: serde_json::Value| {
        let body = serde_json::json!({
            "daemon_version": "0.1.0",
            "protocol": 1,
            "uptime_s": 1,
            "active_requests": 0,
            "model": model,
        });
        render_status(&body)
            .lines()
            .find_map(|line| {
                line.trim()
                    .strip_prefix("model:")
                    .map(str::trim)
                    .map(str::to_owned)
            })
            .expect("a model line")
    };

    assert_eq!(
        line(serde_json::json!({
            "state": "idle",
            "id": null,
            "tokens_per_sec": null,
            "defaults": { "light": null, "heavy": null },
        })),
        "idle"
    );
    assert_eq!(
        line(serde_json::json!({
            "state": "loading",
            "id": "qwen/Qwen3-0.6B-Q8_0",
            "tokens_per_sec": null,
            "defaults": { "light": null, "heavy": null },
        })),
        "loading qwen/Qwen3-0.6B-Q8_0"
    );
    assert_eq!(
        line(serde_json::json!({
            "state": "loaded",
            "id": "qwen/Qwen3-0.6B-Q8_0",
            "tokens_per_sec": 42.25,
            "defaults": { "light": null, "heavy": null },
        })),
        "qwen/Qwen3-0.6B-Q8_0 loaded (42.2 tok/s)"
    );
    // Loaded but never generated: no figure to report, and none invented.
    assert_eq!(
        line(serde_json::json!({
            "state": "loaded",
            "id": "qwen/Qwen3-0.6B-Q8_0",
            "tokens_per_sec": null,
            "defaults": { "light": null, "heavy": null },
        })),
        "qwen/Qwen3-0.6B-Q8_0 loaded"
    );
}

#[test]
fn status_degrades_to_question_marks_on_missing_fields() {
    let text = render_status(&serde_json::json!({}));
    assert!(text.contains('?'), "text: {text}");
}

#[test]
fn json_rendering_round_trips_the_response() {
    let response = result(Outcome::Verified);
    let text = render_json(&response);
    let parsed: Response = serde_json::from_str(&text).expect("valid JSON");
    assert_eq!(parsed, response);
}

#[test]
fn events_render_one_line_each() {
    assert_eq!(render_event(&Event::Queued), "[queued]");
    assert_eq!(render_event(&Event::Started), "[started]");
    assert_eq!(
        render_event(&Event::Progress {
            pct: Some(40),
            note: "half way".to_owned(),
        }),
        "[progress 40%] half way"
    );
    assert_eq!(
        render_event(&Event::Progress {
            pct: None,
            note: "working".to_owned(),
        }),
        "[progress] working"
    );
    assert!(render_event(&Event::ApprovalPending).contains("GUI"));
    assert_eq!(render_event(&Event::Done), "[done]");
    assert_eq!(render_event(&Event::Refused), "[refused]");
}

// --- pam flow -------------------------------------------------------

#[test]
fn the_flow_list_table_aligns_id_source_steps_and_name() {
    let body = serde_json::json!({
        "flows": [
            {
                "id": "after-merge-checks",
                "name": "After-merge checks",
                "description": "Refresh the local view of the remote.",
                "source": "builtin",
                "valid": true,
                "steps": 3,
                "inputs": [],
            },
            {
                "id": "nightly",
                "name": "Nightly",
                "description": "",
                "source": "library",
                "valid": true,
                "steps": 12,
                "inputs": [],
            },
        ]
    });
    let text = render_flow_list(&body);
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), 2, "text: {text}");
    assert!(
        lines[0].starts_with("after-merge-checks  builtin  "),
        "text: {text}"
    );
    assert!(lines[0].ends_with(" 3  After-merge checks"), "text: {text}");
    assert!(
        lines[1].starts_with("nightly             library  "),
        "text: {text}"
    );
    assert!(lines[1].ends_with("12  Nightly"), "text: {text}");
}

#[test]
fn an_invalid_flow_says_why_instead_of_steps_and_name() {
    let body = serde_json::json!({
        "flows": [
            {
                "id": "broken",
                "name": "broken",
                "description": "",
                "source": "library",
                "valid": false,
                "error": "steps: at least one step is required",
                "steps": 0,
                "inputs": [],
            },
        ]
    });
    assert_eq!(
        render_flow_list(&body),
        "broken  library  invalid: steps: at least one step is required"
    );
}

#[test]
fn an_empty_library_says_so_rather_than_printing_nothing() {
    let text = render_flow_list(&serde_json::json!({ "flows": [] }));
    assert!(text.contains("no flows"), "text: {text}");
}

#[test]
fn flow_show_prints_the_canonical_yaml_verbatim() {
    let body = serde_json::json!({
        "id": "after-merge-checks",
        "yaml": "schema: 1\n# a comment the canonical rendering drops\n",
        "normalized_yaml": "schema: 1\nid: after-merge-checks\n",
        "valid": true,
    });
    assert_eq!(render_flow_show(&body), "schema: 1\nid: after-merge-checks");
}

#[test]
fn flow_show_falls_back_to_the_source_text_for_a_broken_flow() {
    // An invalid flow has no canonical rendering, and its raw text is
    // exactly what a human opened `show` to fix.
    let body = serde_json::json!({
        "id": "broken",
        "yaml": "schema: 1\nsteps: []\n",
        "normalized_yaml": "",
        "valid": false,
        "error": "steps: at least one step is required",
    });
    assert_eq!(render_flow_show(&body), "schema: 1\nsteps: []");
}

/// The verdict body of a run with one step of every interesting shape.
fn flow_result_body() -> serde_json::Value {
    serde_json::json!({
        "flow": { "id": "release", "name": "Release", "source": "builtin", "digest": "abc" },
        "repo": "/repo/test",
        "inputs": {},
        "outcome": "unresolved",
        "summary": "4 steps: 1 succeeded, 1 failed, 1 blocked, 1 skipped (test, exit 101)",
        "steps": [
            {
                "id": "clippy",
                "kind": "command",
                "status": "succeeded",
                "attempts": 1,
                "duration_ms": 4_200,
                "evidence": ["ev_clippy"],
            },
            {
                "id": "test",
                "kind": "command",
                "status": "failed",
                "attempts": 2,
                "duration_ms": 900,
                "exit_status": 101,
                "evidence": ["ev_test"],
                "error": {
                    "cause": "exit_status",
                    "detail": "the step exited 101",
                    "recovery": "read the log evidence and fix the failing test",
                },
            },
            {
                "id": "docs",
                "kind": "command",
                "status": "skipped",
                "attempts": 0,
                "duration_ms": 0,
                "evidence": [],
            },
            {
                "id": "deploy",
                "kind": "command",
                "status": "blocked",
                "attempts": 0,
                "duration_ms": 0,
                "evidence": [],
                "error": {
                    "cause": "approval_denied",
                    "detail": "a human denied the approval",
                    "recovery": "open Pam \u{2192} Approvals",
                },
            },
        ],
    })
}

#[test]
fn a_verdict_renders_one_line_per_step_then_the_summary_sentence() {
    let text = render_flow_result(&flow_result_body());
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines[0], "\u{2713} clippy  succeeded  4.2s", "text: {text}");
    assert_eq!(
        lines[1], "\u{2717} test  failed  exit 101  ev_test",
        "text: {text}"
    );
    assert_eq!(
        lines[2], "  \u{2192} read the log evidence and fix the failing test",
        "text: {text}"
    );
    assert_eq!(lines[3], "\u{b7} docs  skipped", "text: {text}");
    assert_eq!(
        lines[4], "\u{2298} deploy  blocked  approval_denied",
        "text: {text}"
    );
    assert_eq!(lines[5], "  \u{2192} open Pam \u{2192} Approvals", "text: {text}");
    assert!(
        text.contains("4 steps: 1 succeeded, 1 failed, 1 blocked, 1 skipped (test, exit 101)"),
        "text: {text}"
    );
}

#[test]
fn a_steps_summary_text_lands_indented_under_its_own_rule() {
    let mut body = flow_result_body();
    body["steps"][0]["summary"] =
        serde_json::json!("Two warnings, both in tests.\nNothing blocking.");
    let text = render_flow_result(&body);
    assert!(
        text.contains("\u{2500}\u{2500} clippy \u{2500}\u{2500}"),
        "text: {text}"
    );
    assert!(text.contains("\n  Two warnings, both in tests.\n"), "text: {text}");
    assert!(text.contains("\n  Nothing blocking."), "text: {text}");
    // A step with no summary contributes no rule.
    assert!(
        !text.contains("\u{2500}\u{2500} docs \u{2500}\u{2500}"),
        "text: {text}"
    );
}

#[test]
fn a_cancelled_step_names_its_cause_and_a_sub_second_step_reports_millis() {
    let body = serde_json::json!({
        "outcome": "unresolved",
        "summary": "2 steps: 1 succeeded, 1 cancelled (fetch, cancelled)",
        "steps": [
            {
                "id": "probe",
                "kind": "command",
                "status": "succeeded",
                "attempts": 1,
                "duration_ms": 120,
                "evidence": [],
            },
            {
                "id": "fetch",
                "kind": "command",
                "status": "cancelled",
                "attempts": 1,
                "duration_ms": 30,
                "evidence": ["ev_fetch"],
                "error": {
                    "cause": "cancelled",
                    "detail": "the request was cancelled",
                    "recovery": "re-run the flow when you are ready",
                },
            },
        ],
    });
    let text = render_flow_result(&body);
    assert!(text.contains("\u{2713} probe  succeeded  120ms"), "text: {text}");
    assert!(
        text.contains("\u{2297} fetch  cancelled  cancelled  ev_fetch"),
        "text: {text}"
    );
}

#[test]
fn a_verdict_without_steps_falls_back_to_the_raw_body() {
    // An older daemon that answers `flow.run` with a different shape is
    // still printed rather than swallowed.
    let body = serde_json::json!({ "note": "nothing to report" });
    assert!(render_flow_result(&body).contains("nothing to report"));
}

#[test]
fn flow_inputs_parse_key_equals_value_pairs() {
    let raw = vec!["repo=ro-ag/pam".to_owned(), "tag=v1.2.3=rc1".to_owned()];
    let inputs = parse_flow_inputs(&raw).expect("well-formed inputs parse");
    assert_eq!(
        inputs,
        serde_json::json!({ "repo": "ro-ag/pam", "tag": "v1.2.3=rc1" })
    );
    // No inputs is an empty object, not a missing one.
    assert_eq!(
        parse_flow_inputs(&[]).expect("no inputs parse"),
        serde_json::json!({})
    );
}

#[test]
fn an_input_without_an_equals_sign_is_a_usage_error_naming_it() {
    let error = parse_flow_inputs(&["x".to_owned()]).expect_err("a bare word is a usage error");
    assert_eq!(error, "input \"x\" must be key=value");
    // An empty name is no better than a missing one.
    let error = parse_flow_inputs(&["=value".to_owned()]).expect_err("an empty name is refused");
    assert_eq!(error, "input \"=value\" must be key=value");
}
