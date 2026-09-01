use std::sync::Arc;
use std::time::Duration;

use pam_store::{Actor, Decision, Store};
use tokio::time::timeout;

use crate::policy::{
    CAUSE_NOT_GRANTED, CAUSE_UNKNOWN_CAPABILITY, CapabilityClass, GateDecision,
    PROFILE_SETTING_KEY, PolicyError, PolicyGate, Profile, classify,
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
    PolicyGate::new(Arc::clone(store)).await.unwrap()
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
    assert_eq!(classify("status"), Some(CapabilityClass::ReadOnly));
    assert_eq!(classify("cancel"), Some(CapabilityClass::ReadOnly));
    assert_eq!(classify("query"), Some(CapabilityClass::ReadOnly));
    assert_eq!(classify("echo"), Some(CapabilityClass::NonDestructive));
    assert_eq!(classify("frobnicate"), None);
}

#[tokio::test]
async fn first_construction_persists_platform_default() {
    timeout(DEADLINE, async {
        let store = fresh_store().await;
        let gate = PolicyGate::new(Arc::clone(&store)).await.unwrap();
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
        let gate = PolicyGate::new(Arc::clone(&store)).await.unwrap();
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
        let err = PolicyGate::new(Arc::clone(&store)).await.unwrap_err();
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
