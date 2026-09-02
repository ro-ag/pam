use pam_proto::{Event, Outcome, Response};

use crate::render::{
    EXIT_BLOCKED, EXIT_REFUSED, EXIT_UNRESOLVED, exit_code, render_event, render_json,
    render_refusal, render_status, render_ticket,
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
