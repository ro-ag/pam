//! A managed policy over the daemon's security surface, end to end: a real
//! daemon booted with a trusted scripted policy, agents on the public plane
//! and the GUI on the administration plane. The public refusal of a
//! never-granted capability says `policy_denied` and nothing about the
//! rule; the profile the daemon enforces and reports is the policy's floor;
//! the admin writes the policy forbids are refused with a
//! `policy.locked_write` row; and every terminal row keeps the audit
//! invariant.
#![cfg(any(target_os = "macos", windows))]

use pam_daemon::admin_transport;
use pam_daemon::daemon::ACTION_GATE_REFUSAL;
use pam_daemon::managed_policy::{CAUSE_POLICY_DENIED, CAUSE_POLICY_NOT_ALLOWED};
use pam_daemon::managed_policy_service::{ACTION_POLICY_DENIED, ACTION_POLICY_LOCKED_WRITE};
use pam_daemon::policy::{PROFILE_SETTING_KEY, RECOVERY_POLICY_DENIED};
use pam_proto::{Outcome, Response};
use pam_testkit::{TestDaemon, envelope, with_deadline};
use serde_json::json;

/// `echo` is never allowed and the profile may be no looser than standard.
const POLICY: &str = r#"{
  "version": 1,
  "revision": "sec-1",
  "organization": "Example Corp",
  "contact": "it@example.com",
  "security": {
    "profile": { "floor": "standard", "reason": "SEC-114" },
    "grants": { "never": ["echo"] }
  }
}"#;

fn admin(id: &str, op: &str, args: serde_json::Value) -> pam_proto::Envelope {
    let mut request = envelope(id, op, args, true);
    "pam-gui".clone_into(&mut request.caller.agent);
    request
}

#[tokio::test]
async fn the_daemon_enforces_the_managed_security_policy_on_both_planes() {
    with_deadline(async {
        // The harness seeds the relaxed profile; the floor clamps it.
        let daemon = TestDaemon::spawn_with(|config| {
            config.policy_source = Some(pam_testkit::ScriptedPolicy::trusted(POLICY));
        })
        .await;
        let mut client = daemon.client().await;

        let response = client
            .request(&envelope("req_echo", "echo", json!({ "msg": "hi" }), true))
            .await;
        let Response::Refusal {
            cause,
            detail,
            recovery,
            ..
        } = response
        else {
            panic!("a never-granted capability is refused: {response:?}");
        };
        assert_eq!(cause, CAUSE_POLICY_DENIED);
        assert_eq!(recovery, RECOVERY_POLICY_DENIED);
        for secret in ["never", "SEC-114", "Example Corp", "it@example.com"] {
            assert!(!detail.contains(secret), "{detail}");
        }
        let rows = daemon.audit_rows("req_echo").await;
        let actions: Vec<&str> = rows.iter().map(|row| row.action.as_str()).collect();
        assert_eq!(actions, [ACTION_POLICY_DENIED, ACTION_GATE_REFUSAL]);
        // The refusal row records the profile in force: the floor, not the
        // relaxed choice the harness stored.
        let refusal: serde_json::Value =
            serde_json::from_str(rows[1].detail.as_deref().unwrap()).unwrap();
        assert_eq!(refusal["profile"], "standard", "{refusal}");

        let status = client
            .request(&envelope("req_status", "status", json!({}), true))
            .await;
        let Response::Result { body, .. } = status else {
            panic!("status answers: {status:?}");
        };
        assert_eq!(body["policy"]["state"], "active", "{body}");
        for secret in ["SEC-114", "Example Corp", "it@example.com"] {
            assert!(!body.to_string().contains(secret), "{body}");
        }

        let base = daemon.base_dir();
        let response = admin_transport::exchange(
            &base,
            &admin("req_pset", "admin.profile.set", json!({ "profile": "relaxed" })),
        )
        .await
        .unwrap();
        assert!(
            matches!(&response, Response::Refusal { cause, detail, .. }
                if cause == CAUSE_POLICY_NOT_ALLOWED && detail.contains("SEC-114")),
            "{response:?}"
        );
        let response = admin_transport::exchange(
            &base,
            &admin("req_gadd", "admin.grants.add", json!({ "capability": "echo" })),
        )
        .await
        .unwrap();
        assert!(
            matches!(&response, Response::Refusal { cause, .. } if cause == CAUSE_POLICY_NOT_ALLOWED),
            "{response:?}"
        );
        for id in ["req_pset", "req_gadd"] {
            let actions: Vec<String> = daemon
                .audit_rows(id)
                .await
                .into_iter()
                .map(|row| row.action)
                .collect();
            assert_eq!(actions, [ACTION_POLICY_LOCKED_WRITE, "admin"], "{id}");
        }
        // The human's stored choice is untouched by the clamp and the refusal.
        assert_eq!(
            daemon
                .store()
                .get_setting(PROFILE_SETTING_KEY)
                .await
                .unwrap()
                .as_deref(),
            Some("\"relaxed\"")
        );

        let response = admin_transport::exchange(
            &base,
            &admin("req_pget", "admin.profile.get", json!({})),
        )
        .await
        .unwrap();
        let Response::Result { outcome, body, .. } = response else {
            panic!("profile.get answers: {response:?}");
        };
        assert_eq!(outcome, Outcome::Verified);
        assert_eq!(body["profile"], "standard");
        assert_eq!(body["effective"]["profile"]["clamped"], true);

        daemon.assert_invariant_clean().await;
        daemon.stop().await;
    })
    .await;
}
