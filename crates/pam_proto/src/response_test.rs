use serde_json::json;

use super::{Outcome, Response};

fn round_trip(response: &Response) {
    let wire = serde_json::to_string(response).unwrap();
    let back: Response = serde_json::from_str(&wire).unwrap();
    assert_eq!(&back, response);
}

#[test]
fn result_round_trips() {
    round_trip(&Response::Result {
        id: "req_a".to_owned(),
        outcome: Outcome::Solved,
        body: json!({ "summary": "all green" }),
        evidence: vec!["ev_1".to_owned(), "ev_2".to_owned()],
    });
}

#[test]
fn refusal_round_trips() {
    round_trip(&Response::Refusal {
        id: "req_b".to_owned(),
        cause: "approval_required".to_owned(),
        detail: "capability needs a human approval".to_owned(),
        recovery: "Open the pam GUI and approve the pending request.".to_owned(),
    });
}

#[test]
fn ticket_round_trips() {
    round_trip(&Response::Ticket {
        id: "req_c".to_owned(),
        ticket: "tkt_1".to_owned(),
        position: 3,
    });
}

#[test]
fn every_outcome_round_trips() {
    for outcome in [
        Outcome::Solved,
        Outcome::Changed,
        Outcome::Verified,
        Outcome::Unresolved,
        Outcome::Blocked,
    ] {
        let wire = serde_json::to_string(&outcome).unwrap();
        let back: Outcome = serde_json::from_str(&wire).unwrap();
        assert_eq!(back, outcome);
    }
}

#[test]
fn refusal_wire_format_is_pinned() {
    let refusal = Response::Refusal {
        id: "req_b".to_owned(),
        cause: "approval_required".to_owned(),
        detail: "capability needs a human approval".to_owned(),
        recovery: "Open the pam GUI and approve the pending request.".to_owned(),
    };
    assert_eq!(
        serde_json::to_value(&refusal).unwrap(),
        json!({
            "kind": "refusal",
            "id": "req_b",
            "cause": "approval_required",
            "detail": "capability needs a human approval",
            "recovery": "Open the pam GUI and approve the pending request."
        })
    );
}

#[test]
fn outcome_is_snake_case_on_the_wire() {
    assert_eq!(
        serde_json::to_value(Outcome::Solved).unwrap(),
        json!("solved")
    );
    assert_eq!(
        serde_json::to_value(Outcome::Unresolved).unwrap(),
        json!("unresolved")
    );
}
