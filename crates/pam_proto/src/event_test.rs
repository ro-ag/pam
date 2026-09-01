use serde_json::json;

use super::Event;

fn round_trip(event: &Event) {
    let wire = serde_json::to_string(event).unwrap();
    let back: Event = serde_json::from_str(&wire).unwrap();
    assert_eq!(&back, event);
}

#[test]
fn every_variant_round_trips() {
    for event in [
        Event::Queued,
        Event::Started,
        Event::Progress {
            pct: Some(40),
            note: "summarizing".to_owned(),
        },
        Event::Progress {
            pct: None,
            note: "still working".to_owned(),
        },
        Event::ApprovalPending,
        Event::Done,
        Event::Refused,
    ] {
        round_trip(&event);
    }
}

#[test]
fn variants_are_snake_case_on_the_wire() {
    assert_eq!(
        serde_json::to_value(Event::ApprovalPending).unwrap(),
        json!({ "kind": "approval_pending" })
    );
    assert_eq!(
        serde_json::to_value(Event::Progress {
            pct: Some(40),
            note: "summarizing".to_owned(),
        })
        .unwrap(),
        json!({ "kind": "progress", "pct": 40, "note": "summarizing" })
    );
}

#[test]
fn progress_omits_pct_when_unknown() {
    let wire = serde_json::to_string(&Event::Progress {
        pct: None,
        note: "still working".to_owned(),
    })
    .unwrap();
    assert!(!wire.contains("pct"));
}
