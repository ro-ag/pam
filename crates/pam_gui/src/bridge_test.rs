use pam_client::client::{ClientError, RequestError};
use pam_proto::{Outcome, Response};
use serde_json::json;

use crate::bridge::{
    ADMIN_OPS, BridgeError, CONFIRM_GRANT, CONFIRM_RELAXED, admin_call, check_confirmation,
    deadline_for, is_disconnect, is_known_admin_op, required_confirmation,
};

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
    assert_eq!(
        ADMIN_OPS.len(),
        // The ten core ops plus `admin.requests.cancel`, which the bridge names itself.
        11 + pam_daemon::admin_models::MODEL_ADMIN_OPS.len()
            + pam_daemon::admin_logs::LOG_ADMIN_OPS.len()
            + pam_daemon::admin_flows::FLOW_ADMIN_OPS.len()
            + pam_daemon::admin_connectors::CONNECTOR_ADMIN_OPS.len()
            + pam_daemon::admin_retention::RETENTION_ADMIN_OPS.len(),
        "new admin ops need explicit wiring"
    );
}

#[test]
fn every_model_admin_op_is_whitelisted() {
    // The model surface is spliced in from the daemon's own list, so a
    // new op there reaches the GUI without a second edit here.
    for op in pam_daemon::admin_models::MODEL_ADMIN_OPS {
        assert!(is_known_admin_op(op), "{op} must be forwarded");
    }
}

#[test]
fn every_log_admin_op_is_whitelisted() {
    // The log surface is spliced in from the daemon's own list too, so
    // the compression observatory cannot go dark on a rename there.
    for op in pam_daemon::admin_logs::LOG_ADMIN_OPS {
        assert!(is_known_admin_op(op), "{op} must be forwarded");
    }
}

#[test]
fn every_flow_admin_op_is_whitelisted() {
    // The flow surface is spliced in from the daemon's own list, so the
    // Flows screen cannot go dark on a rename there.
    for op in pam_daemon::admin_flows::FLOW_ADMIN_OPS {
        assert!(is_known_admin_op(op), "{op} must be forwarded");
    }
}

#[test]
fn every_connector_admin_op_is_whitelisted() {
    // Same for the connector surface behind Settings → Connectors.
    for op in pam_daemon::admin_connectors::CONNECTOR_ADMIN_OPS {
        assert!(is_known_admin_op(op), "{op} must be forwarded");
    }
}

#[test]
fn every_retention_admin_op_is_whitelisted() {
    // Same for the retention surface behind Settings → Retention: the
    // panel's two selects and its Prune now button all land here.
    for op in pam_daemon::admin_retention::RETENTION_ADMIN_OPS {
        assert!(is_known_admin_op(op), "{op} must be forwarded");
    }
}

#[test]
fn only_the_working_ops_get_the_long_deadline() {
    // Real work runs for minutes; every other admin op is a synchronous
    // read or write and keeps the 30 s ceiling — except the connector
    // test, which talks to a remote service on its own 10 s budget.
    let long = [
        pam_daemon::admin_models::OP_MODELS_TRY,
        pam_daemon::admin_logs::OP_LOG_COMPRESS,
        pam_daemon::admin_engine::OP_ENGINE_INSTALL,
    ];
    for op in long {
        assert_eq!(
            deadline_for(op),
            120_000,
            "{op} decodes tokens or fetches the engine; 30 s would time it out"
        );
    }
    let test_op = pam_daemon::admin_connectors::OP_CONNECTORS_TEST;
    assert_eq!(
        deadline_for(test_op),
        15_000,
        "{test_op} rides just above the daemon's own 10 s connector budget"
    );
    for op in ADMIN_OPS {
        if long.contains(&op) || op == test_op {
            continue;
        }
        assert_eq!(deadline_for(op), 30_000, "{op} answers synchronously");
    }
}

#[test]
fn a_flow_run_is_forwarded_but_never_becomes_a_capability_request() {
    // `admin.flows.run` is the GUI's Run button: an admin op the bridge
    // forwards, which the daemon turns into a real `flow.run` envelope.
    // The bare capability name must never be forwardable here.
    assert!(is_known_admin_op(pam_daemon::admin_flows::OP_FLOWS_RUN));
    assert!(!is_known_admin_op("flow.run"));
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
fn private_admin_transport_failure_warns_against_replaying_unknown_effects() {
    let error = RequestError::AdminTransport {
        source: std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "reply lost"),
    };
    assert!(!is_disconnect(&error));
    let mapped = BridgeError::from(error);
    assert_eq!(mapped.cause, "admin_transport_failed");
    assert!(mapped.detail.contains("operation was not retried"));
    assert!(mapped.recovery.contains("already took effect"));
}

#[test]
fn daemon_refusals_pass_through_verbatim() {
    let refusal = Response::Refusal {
        retryable: false,
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

/// The frontend's `AdminOp` union is the bridge's allowlist, no more and no less: a Rust op the
/// frontend never uses is surface the webview could still reach, and a frontend op missing here
/// would be refused at runtime.
#[test]
fn the_allowlist_is_exactly_the_ops_the_frontend_names() {
    let source = include_str!("../../../frontend/src/lib/ipc.ts");
    let union = source
        .split_once("export type AdminOp =")
        .expect("ipc.ts declares the AdminOp union")
        .1
        .split_once(';')
        .expect("the union ends")
        .0;
    let mut frontend: Vec<&str> = union
        .split('"')
        .skip(1)
        .step_by(2)
        .filter(|name| name.starts_with("admin."))
        .collect();
    frontend.sort_unstable();
    let mut bridge: Vec<&str> = ADMIN_OPS.to_vec();
    bridge.sort_unstable();
    assert_eq!(bridge, frontend);
}

#[test]
fn authority_expanding_ops_need_a_typed_confirmation() {
    // Relaxing the profile, any grant, and approving with "remember".
    assert_eq!(
        required_confirmation("admin.profile.set", &json!({"profile": "relaxed"})),
        Some(CONFIRM_RELAXED)
    );
    assert_eq!(
        required_confirmation("admin.profile.set", &json!({})),
        Some(CONFIRM_RELAXED),
        "an unreadable target fails closed"
    );
    assert_eq!(
        required_confirmation("admin.grants.add", &json!({"capability": "fs.write"})),
        Some(CONFIRM_GRANT)
    );
    assert_eq!(
        required_confirmation(
            "admin.approvals.resolve",
            &json!({"request_id": "r", "resolution": "approved", "remember": true})
        ),
        Some(CONFIRM_GRANT)
    );
    // Narrowing and one-time decisions are one click.
    for (op, args) in [
        ("admin.profile.set", json!({"profile": "standard"})),
        ("admin.profile.set", json!({"profile": "strict"})),
        ("admin.grants.revoke", json!({"capability": "fs.write"})),
        (
            "admin.approvals.resolve",
            json!({"request_id": "r", "resolution": "approved"}),
        ),
        (
            "admin.approvals.resolve",
            json!({"request_id": "r", "resolution": "approved", "remember": false}),
        ),
        (
            "admin.approvals.resolve",
            json!({"request_id": "r", "resolution": "denied", "remember": true}),
        ),
        ("admin.connectors.configure", json!({"id": "sonar"})),
    ] {
        assert_eq!(required_confirmation(op, &args), None, "{op} {args}");
    }
}

#[test]
fn a_missing_or_wrong_confirmation_is_refused_before_the_socket() {
    let args = json!({"profile": "relaxed"});
    for given in [None, Some(""), Some("yes"), Some("grant")] {
        let error = check_confirmation("admin.profile.set", &args, given)
            .expect_err("the phrase is required");
        assert_eq!(error.cause, "confirmation_required", "{given:?}");
        assert!(
            error.recovery.contains(CONFIRM_RELAXED),
            "{}",
            error.recovery
        );
    }
    check_confirmation("admin.profile.set", &args, Some(" Relaxed "))
        .expect("the phrase, trimmed and case-insensitive, authorises it");
}

/// The command itself, not only the helper: an unconfirmed relax never gets as far as resolving
/// a base directory, let alone the admin socket.
#[tokio::test]
async fn admin_call_refuses_an_unconfirmed_relax_without_touching_the_socket() {
    let error = admin_call(
        "admin.profile.set".to_owned(),
        json!({"profile": "relaxed"}),
        None,
    )
    .await
    .expect_err("one click must not relax the profile");
    assert_eq!(error.cause, "confirmation_required");
    let error = admin_call(
        "admin.grants.add".to_owned(),
        json!({"capability": "x"}),
        None,
    )
    .await
    .expect_err("a grant needs confirmation too");
    assert_eq!(error.cause, "confirmation_required");
}

#[tokio::test]
async fn cancel_goes_through_the_private_admin_op_and_nothing_goes_public() {
    // The run card's Cancel is an admin op, forwarded like every other human act.
    assert!(is_known_admin_op("admin.requests.cancel"));
    assert_eq!(deadline_for("admin.requests.cancel"), 30_000);
    // The public-socket capabilities are not reachable through admin_call.
    for name in ["cancel", "echo", "flow.run", "status", "query", ""] {
        let error = admin_call(name.to_owned(), json!({"ticket": "t"}), None)
            .await
            .expect_err("a public capability is not an admin op");
        assert_eq!(error.cause, "unknown_admin_op", "{name}");
    }
}
