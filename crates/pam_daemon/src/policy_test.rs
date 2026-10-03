use std::sync::Arc;
use std::time::Duration;

use pam_store::{Actor, Decision, Store};
use tokio::time::timeout;

use crate::policy::{
    AdmissionPool, CAUSE_NOT_GRANTED, CAUSE_UNKNOWN_CAPABILITY, CapabilityClass, GateDecision,
    PROFILE_SETTING_KEY, PolicyError, PolicyGate, Profile, admission_pool, classify,
};

const DEADLINE: Duration = Duration::from_secs(5);

async fn fresh_store() -> Arc<Store> {
    Arc::new(Store::open_in_memory().await.unwrap())
}

/// Persists `profile` then builds a gate on top of it, with a request row
/// (`req_1`) in place so auto-grant audit rows have a valid parent.
async fn gate_with(store: &Arc<Store>, profile: Profile) -> PolicyGate {
    store
        .set_setting(
            PROFILE_SETTING_KEY,
            &serde_json::to_string(&profile).unwrap(),
        )
        .await
        .unwrap();
    store
        .insert_request("req_1", "echo", "ro-ag/pam", "claude", "{}", None)
        .await
        .unwrap();
    PolicyGate::new(
        Arc::clone(store),
        crate::managed_policy_service::PolicyHandle::none(),
    )
    .await
    .unwrap()
}

#[test]
fn platform_default_matches_target_os() {
    let expected = if cfg!(target_os = "macos") {
        Profile::Relaxed
    } else {
        Profile::Standard
    };
    assert_eq!(Profile::platform_default(), expected);
}

#[test]
fn profile_round_trips_through_json() {
    for (profile, json) in [
        (Profile::Relaxed, "\"relaxed\""),
        (Profile::Standard, "\"standard\""),
        (Profile::Strict, "\"strict\""),
    ] {
        assert_eq!(serde_json::to_string(&profile).unwrap(), json);
        assert_eq!(serde_json::from_str::<Profile>(json).unwrap(), profile);
        assert_eq!(format!("\"{}\"", profile.as_str()), json);
    }
}

#[test]
fn known_capabilities_classify() {
    assert_eq!(classify("status"), Some(CapabilityClass::Control));
    assert_eq!(classify("cancel"), Some(CapabilityClass::Control));
    assert_eq!(classify("query"), Some(CapabilityClass::Control));
    assert_eq!(classify("flow.list"), Some(CapabilityClass::ReadOnly));
    assert_eq!(classify("echo"), Some(CapabilityClass::NonDestructive));
    assert_eq!(classify("frobnicate"), None);
}

#[test]
fn the_admission_pool_comes_from_the_class_and_cancel_has_its_own() {
    // The liveness answer has slots nothing else can take.
    assert_eq!(admission_pool("status"), AdmissionPool::Status);
    assert_eq!(admission_pool("query"), AdmissionPool::Control);
    // The remedy for a saturated daemon never shares a pool with polls.
    assert_eq!(admission_pool("cancel"), AdmissionPool::Cancel);
    // Read-only work is still work: it does real reads and must not be
    // able to spend the reserved control slots.
    assert_eq!(admission_pool("flow.list"), AdmissionPool::Work);
    assert_eq!(admission_pool("evidence.read"), AdmissionPool::Work);
    assert_eq!(admission_pool("echo"), AdmissionPool::Work);
    // Neither can a name the registry does not know, nor an admin op.
    assert_eq!(admission_pool("statusx"), AdmissionPool::Work);
    assert_eq!(admission_pool("admin.grants.list"), AdmissionPool::Work);
    assert!(CapabilityClass::Control.bypasses_lanes());
    assert!(CapabilityClass::ReadOnly.bypasses_lanes());
    assert!(!CapabilityClass::NonDestructive.bypasses_lanes());
}

#[tokio::test]
async fn control_is_allowed_under_every_profile_without_a_grant() {
    timeout(DEADLINE, async {
        for profile in [Profile::Relaxed, Profile::Standard, Profile::Strict] {
            let store = fresh_store().await;
            let gate = gate_with(&store, profile).await;
            for capability in ["status", "query", "cancel"] {
                assert_eq!(
                    gate.evaluate("req_1", capability).await.unwrap(),
                    GateDecision::Allow {
                        auto_granted: false
                    }
                );
                assert!(!store.active_grant(capability).await.unwrap());
            }
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn set_profile_governs_the_next_evaluation_and_persists() {
    timeout(DEADLINE, async {
        let store = fresh_store().await;
        let gate = gate_with(&store, Profile::Relaxed).await;
        // Relaxed: first use of a non-destructive capability is auto-granted.
        assert_eq!(
            gate.evaluate("req_1", "echo").await.unwrap(),
            GateDecision::Allow { auto_granted: true }
        );

        let previous = gate.set_profile(Profile::Strict).await.unwrap();
        assert_eq!(previous, Profile::Relaxed);
        // The live gate and the stored setting agree at once: there is no
        // second source that still says relaxed.
        assert_eq!(gate.profile(), Profile::Strict);
        assert_eq!(
            store
                .get_setting(PROFILE_SETTING_KEY)
                .await
                .unwrap()
                .as_deref(),
            Some("\"strict\"")
        );
        // Without the swap the same gate would still allow this outright.
        assert!(matches!(
            gate.evaluate("req_1", "echo").await.unwrap(),
            GateDecision::RequireApproval { .. }
        ));
        // And a gate built after a restart reads the same profile.
        let rebuilt = PolicyGate::new(
            Arc::clone(&store),
            crate::managed_policy_service::PolicyHandle::none(),
        )
        .await
        .unwrap();
        assert_eq!(rebuilt.profile(), Profile::Strict);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn an_auto_grant_without_its_request_row_writes_neither_grant_nor_audit() {
    timeout(DEADLINE, async {
        let store = fresh_store().await;
        let gate = gate_with(&store, Profile::Relaxed).await;
        // The audit row's parent is missing, so the audit insert fails. The
        // grant must roll back with it: no grant nobody audited.
        let error = gate
            .evaluate("req_missing", "echo")
            .await
            .expect_err("the audit row has no parent request");
        assert!(!matches!(
            error,
            pam_store::StoreError::AlreadyTerminal { .. }
        ));
        assert!(
            !store.active_grant("echo").await.unwrap(),
            "a grant survived although its audit row could not be written"
        );
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn first_construction_persists_platform_default() {
    timeout(DEADLINE, async {
        let store = fresh_store().await;
        let gate = PolicyGate::new(
            Arc::clone(&store),
            crate::managed_policy_service::PolicyHandle::none(),
        )
        .await
        .unwrap();
        assert_eq!(gate.profile(), Profile::platform_default());

        // Persisted so the GUI (and the next construction) sees it.
        let raw = store
            .get_setting(PROFILE_SETTING_KEY)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            raw,
            serde_json::to_string(&Profile::platform_default()).unwrap()
        );

        // A second construction reuses the stored value instead of the
        // platform default: flip the setting, rebuild, observe.
        store
            .set_setting(PROFILE_SETTING_KEY, "\"strict\"")
            .await
            .unwrap();
        let gate = PolicyGate::new(
            Arc::clone(&store),
            crate::managed_policy_service::PolicyHandle::none(),
        )
        .await
        .unwrap();
        assert_eq!(gate.profile(), Profile::Strict);
    })
    .await
    .expect("test within deadline");
}

#[tokio::test]
async fn corrupt_profile_setting_is_a_legible_error() {
    timeout(DEADLINE, async {
        let store = fresh_store().await;
        store
            .set_setting(PROFILE_SETTING_KEY, "\"paranoid\"")
            .await
            .unwrap();
        let err = PolicyGate::new(
            Arc::clone(&store),
            crate::managed_policy_service::PolicyHandle::none(),
        )
        .await
        .unwrap_err();
        let PolicyError::UnrecognizedProfile { value } = err else {
            panic!("expected UnrecognizedProfile, got {err:?}");
        };
        assert_eq!(value, "\"paranoid\"");
    })
    .await
    .expect("test within deadline");
}

#[tokio::test]
async fn unknown_capability_is_refused_with_gui_recovery() {
    timeout(DEADLINE, async {
        let store = fresh_store().await;
        let gate = gate_with(&store, Profile::Relaxed).await;
        let decision = gate.evaluate("req_1", "frobnicate").await.unwrap();
        let GateDecision::Refuse {
            cause,
            detail,
            recovery,
        } = decision
        else {
            panic!("expected Refuse, got {decision:?}");
        };
        assert_eq!(cause, CAUSE_UNKNOWN_CAPABILITY);
        assert!(detail.contains("frobnicate"), "detail names it: {detail}");
        assert!(recovery.contains("PAM GUI"), "recovery points at the GUI");
    })
    .await
    .expect("test within deadline");
}

#[tokio::test]
async fn read_only_is_allowed_under_every_profile() {
    timeout(DEADLINE, async {
        for profile in [Profile::Relaxed, Profile::Standard, Profile::Strict] {
            let store = fresh_store().await;
            let gate = gate_with(&store, profile).await;
            let decision = gate.evaluate("req_1", "status").await.unwrap();
            assert_eq!(
                decision,
                GateDecision::Allow {
                    auto_granted: false
                },
                "status must pass under {profile:?}"
            );
            // No grant row appears: read-only bypasses grants entirely.
            assert!(!store.active_grant("status").await.unwrap());
        }
    })
    .await
    .expect("test within deadline");
}

#[tokio::test]
async fn relaxed_auto_grants_nondestructive_once_and_audits_it() {
    timeout(DEADLINE, async {
        let store = fresh_store().await;
        let gate = gate_with(&store, Profile::Relaxed).await;

        // First use: auto-grant.
        let decision = gate.evaluate("req_1", "echo").await.unwrap();
        assert_eq!(decision, GateDecision::Allow { auto_granted: true });
        assert!(store.active_grant("echo").await.unwrap());

        // The mutation was audited with the active profile in detail.
        let audit = store.audit_for_request("req_1").await.unwrap();
        assert_eq!(audit.len(), 1);
        let row = &audit[0];
        assert_eq!(row.action, "auto_grant");
        assert_eq!(row.decision, Decision::Allow);
        assert_eq!(row.actor, Actor::Policy);
        let detail = row.detail.as_deref().unwrap();
        assert!(
            detail.contains("\"relaxed\""),
            "profile in detail: {detail}"
        );
        assert!(
            detail.contains("\"echo\""),
            "capability in detail: {detail}"
        );

        // Second use: already granted, no new grant and no new audit row.
        let decision = gate.evaluate("req_1", "echo").await.unwrap();
        assert_eq!(
            decision,
            GateDecision::Allow {
                auto_granted: false
            }
        );
        assert_eq!(store.audit_for_request("req_1").await.unwrap().len(), 1);
    })
    .await
    .expect("test within deadline");
}

#[tokio::test]
async fn relaxed_destructive_requires_approval_until_granted() {
    timeout(DEADLINE, async {
        let store = fresh_store().await;
        let gate = gate_with(&store, Profile::Relaxed).await;
        for class in [CapabilityClass::Destructive, CapabilityClass::External] {
            let decision = gate
                .evaluate_classified("req_1", "test.destroy", class)
                .await
                .unwrap();
            assert!(
                matches!(decision, GateDecision::RequireApproval { .. }),
                "ungranted {class:?} must ask under relaxed, got {decision:?}"
            );
        }

        // The approval service inserts the grant on approval ("remember");
        // from then on the gate allows without asking.
        store.insert_grant("test.destroy").await.unwrap();
        let decision = gate
            .evaluate_classified("req_1", "test.destroy", CapabilityClass::Destructive)
            .await
            .unwrap();
        assert_eq!(
            decision,
            GateDecision::Allow {
                auto_granted: false
            }
        );
    })
    .await
    .expect("test within deadline");
}

#[tokio::test]
async fn standard_refuses_ungranted_and_gates_granted_destructive() {
    timeout(DEADLINE, async {
        let store = fresh_store().await;
        let gate = gate_with(&store, Profile::Standard).await;

        // Ungranted anything (non-read-only) is refused with a GUI line.
        let decision = gate.evaluate("req_1", "echo").await.unwrap();
        let GateDecision::Refuse {
            cause,
            detail,
            recovery,
        } = decision
        else {
            panic!("expected Refuse, got {decision:?}");
        };
        assert_eq!(cause, CAUSE_NOT_GRANTED);
        assert!(detail.contains("echo"), "detail names it: {detail}");
        assert!(
            recovery.contains("Security > Capabilities"),
            "recovery points at the GUI: {recovery}"
        );
        // Refusals do not audit inside the gate; the pipeline does that.
        assert!(store.audit_for_request("req_1").await.unwrap().is_empty());

        // Granted non-destructive: allowed, never auto-granted.
        store.insert_grant("echo").await.unwrap();
        let decision = gate.evaluate("req_1", "echo").await.unwrap();
        assert_eq!(
            decision,
            GateDecision::Allow {
                auto_granted: false
            }
        );

        // Granted destructive: per-operation approval.
        store.insert_grant("test.destroy").await.unwrap();
        let decision = gate
            .evaluate_classified("req_1", "test.destroy", CapabilityClass::Destructive)
            .await
            .unwrap();
        assert!(
            matches!(decision, GateDecision::RequireApproval { .. }),
            "granted destructive must ask under standard, got {decision:?}"
        );
    })
    .await
    .expect("test within deadline");
}

#[tokio::test]
async fn strict_requires_approval_even_when_granted() {
    timeout(DEADLINE, async {
        let store = fresh_store().await;
        let gate = gate_with(&store, Profile::Strict).await;

        // Ungranted refuses, same as standard.
        let decision = gate.evaluate("req_1", "echo").await.unwrap();
        assert!(
            matches!(decision, GateDecision::Refuse { ref cause, .. } if cause == CAUSE_NOT_GRANTED),
            "ungranted must refuse under strict, got {decision:?}"
        );

        // Granted non-destructive AND granted destructive both ask.
        store.insert_grant("echo").await.unwrap();
        store.insert_grant("test.destroy").await.unwrap();
        let decision = gate.evaluate("req_1", "echo").await.unwrap();
        assert!(
            matches!(decision, GateDecision::RequireApproval { .. }),
            "granted nondestructive must ask under strict, got {decision:?}"
        );
        let decision = gate
            .evaluate_classified("req_1", "test.destroy", CapabilityClass::Destructive)
            .await
            .unwrap();
        assert!(
            matches!(decision, GateDecision::RequireApproval { .. }),
            "granted destructive must ask under strict, got {decision:?}"
        );
    })
    .await
    .expect("test within deadline");
}

#[test]
fn doctor_report_is_control_class_in_the_control_pool() {
    assert_eq!(
        classify(crate::boundary::CAP_DOCTOR_REPORT),
        Some(CapabilityClass::Control)
    );
    assert_eq!(
        admission_pool(crate::boundary::CAP_DOCTOR_REPORT),
        AdmissionPool::Control
    );
}
