use pam_client::client::{ClientError, RequestError};
use pam_proto::{Outcome, Response};
use serde_json::json;

use crate::bridge::{ADMIN_OPS, BridgeError, is_disconnect, is_known_admin_op};

#[test]
fn every_daemon_admin_op_is_whitelisted() {
    // Kept in lockstep with pam_daemon::admin by importing its constants.
    for op in ADMIN_OPS {
        assert!(is_known_admin_op(op), "{op} must be forwarded");
        assert!(
            op.starts_with(pam_daemon::admin::ADMIN_PREFIX),
            "{op} must live under the reserved admin prefix"
        );
    }
    assert_eq!(ADMIN_OPS.len(), 9, "new admin ops need explicit wiring");
}

#[test]
fn unknown_and_non_admin_ops_are_refused() {
    for op in [
        "admin.grants.dump",
        "admin.",
        "admin.profile.get ",
        "status",
        "echo",
        "",
    ] {
        assert!(!is_known_admin_op(op), "{op:?} must not be forwarded");
    }
}

#[test]
fn bridge_errors_serialize_as_the_refusal_shape() {
    let err = BridgeError {
        cause: "unknown_admin_op".to_owned(),
        detail: "no such op".to_owned(),
        recovery: "pick a real one".to_owned(),
    };
    let value = serde_json::to_value(&err).expect("serializes");
    assert_eq!(
        value,
        json!({
            "cause": "unknown_admin_op",
            "detail": "no such op",
            "recovery": "pick a real one",
        })
    );
}

#[test]
fn client_errors_map_onto_legible_causes() {
    let admin_only = RequestError::AdminOnly {
        capability: "admin.grants.add".to_owned(),
    };
    let mapped = BridgeError::from(admin_only);
    assert_eq!(mapped.cause, "wrong_channel");
    assert!(mapped.detail.contains("admin.grants.add"));
    assert!(!mapped.recovery.is_empty());

    let timeout = RequestError::ReplyTimeout {
        waited: std::time::Duration::from_secs(5),
    };
    assert_eq!(BridgeError::from(timeout).cause, "reply_timeout");

    let not_ready = RequestError::Ensure(ClientError::NotReady {
        waited: std::time::Duration::from_secs(6),
    });
    assert_eq!(BridgeError::from(not_ready).cause, "daemon_unreachable");
}

#[test]
fn disconnects_are_classified_for_the_status_command() {
    let disconnected = [
        RequestError::Ensure(ClientError::NotReady {
            waited: std::time::Duration::from_secs(6),
        }),
        RequestError::ReplyTimeout {
            waited: std::time::Duration::from_secs(5),
        },
    ];
    for err in disconnected {
        assert!(is_disconnect(&err), "{err} must read as disconnected");
    }
    let real_errors = [
        RequestError::AdminOnly {
            capability: "admin.profile.get".to_owned(),
        },
        RequestError::NotAdmin {
            capability: "status".to_owned(),
        },
        RequestError::FollowTimeout {
            ticket: "req_x".to_owned(),
            waited: std::time::Duration::from_secs(5),
        },
    ];
    for err in real_errors {
        assert!(!is_disconnect(&err), "{err} must surface as an error");
    }
}

#[test]
fn daemon_refusals_pass_through_verbatim() {
    let refusal = Response::Refusal {
        id: "req_1".to_owned(),
        cause: "already_granted".to_owned(),
        detail: "capability \"echo\" already has an active grant".to_owned(),
        recovery: "Check the grants view.".to_owned(),
    };
    let err = crate::bridge::expect_result(refusal).expect_err("refusal maps to error");
    assert_eq!(err.cause, "already_granted");
    assert_eq!(
        err.detail,
        "capability \"echo\" already has an active grant"
    );
    assert_eq!(err.recovery, "Check the grants view.");
}

#[test]
fn results_unwrap_to_their_body_and_tickets_are_rejected() {
    let result = Response::Result {
        id: "req_1".to_owned(),
        outcome: Outcome::Verified,
        body: json!({ "profile": "standard" }),
        evidence: Vec::new(),
    };
    assert_eq!(
        crate::bridge::expect_result(result).expect("result unwraps"),
        json!({ "profile": "standard" })
    );

    let ticket = Response::Ticket {
        id: "req_2".to_owned(),
        ticket: "req_2".to_owned(),
        position: 0,
    };
    let err = crate::bridge::expect_result(ticket).expect_err("tickets are unexpected");
    assert_eq!(err.cause, "unexpected_ticket");
}
