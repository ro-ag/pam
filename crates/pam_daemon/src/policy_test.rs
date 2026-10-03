use std::sync::Arc;
use std::time::Duration;

use pam_store::{Actor, Decision, Store};
use tokio::time::timeout;

use crate::managed_policy::{
    CAUSE_POLICY_DENIED, CAUSE_POLICY_FROZEN, CAUSE_POLICY_NOT_ALLOWED, CAUSE_SETTING_LOCKED, Key,
};
use crate::managed_policy_service::{
    ABSENCE_CONFIRM_AFTER, ACTION_POLICY_DENIED, Fingerprint, PolicyHandle, PolicySource,
    SourceRead, Trigger,
};
use crate::policy::{
    AdmissionPool, CAUSE_NOT_GRANTED, CAUSE_UNKNOWN_CAPABILITY, CapabilityClass, GateDecision,
    PROFILE_SETTING_KEY, PolicyError, PolicyGate, Profile, RECOVERY_POLICY_DENIED, SetProfileError,
    admission_pool, classify,
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

// --- The managed policy over the gate ---------------------------------------

/// A policy file the test replaces at will: every change bumps the stat,
/// the way a real replace does, so the poll notices it. Shared with the
/// admin and approval tests.
#[derive(Default)]
pub(crate) struct SwitchablePolicy {
    file: std::sync::Mutex<(u64, Option<Vec<u8>>)>,
}

impl SwitchablePolicy {
    pub(crate) fn new(text: Option<&str>) -> Arc<Self> {
        let source = Arc::new(Self::default());
        source.set(text);
        source
    }

    /// Replaces the file (`None` deletes it).
    pub(crate) fn set(&self, text: Option<&str>) {
        let mut file = self
            .file
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        file.0 += 1;
        file.1 = text.map(|text| text.as_bytes().to_vec());
    }
}

impl PolicySource for SwitchablePolicy {
    fn origin(&self) -> String {
        "switchable".to_owned()
    }

    fn read(&self) -> SourceRead {
        let file = self
            .file
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match &file.1 {
            Some(bytes) => SourceRead::Trusted(bytes.clone()),
            None => SourceRead::Absent,
        }
    }

    fn fingerprint(&self) -> Option<Fingerprint> {
        let file = self
            .file
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        file.1.as_ref().map(|_| Fingerprint {
            len: file.0,
            modified: None,
            identity: None,
        })
    }

    fn read_referenced(&self, _path: &std::path::Path, _max_bytes: u64) -> SourceRead {
        SourceRead::Absent
    }
}

/// The handle a daemon would boot with over `source` (no CA is pinned, so
/// the base directory is never written).
pub(crate) async fn managed_handle(
    store: &Arc<Store>,
    source: &Arc<SwitchablePolicy>,
) -> Arc<PolicyHandle> {
    PolicyHandle::load(
        Arc::clone(store),
        Arc::clone(source) as Arc<dyn PolicySource>,
        std::path::Path::new("pam-tests-write-no-ca-copy"),
    )
    .await
}

/// Removes the policy file and lets the handle confirm the absence: one
/// observation, then a poll at least [`ABSENCE_CONFIRM_AFTER`] later. Needs
/// a paused clock.
pub(crate) async fn remove_policy(source: &SwitchablePolicy, handle: &PolicyHandle) {
    source.set(None);
    handle.poll_once().await;
    tokio::time::advance(ABSENCE_CONFIRM_AFTER + Duration::from_secs(1)).await;
    handle.poll_once().await;
    assert!(!handle.view().is_managed(), "the absence is confirmed");
}

/// A gate over the stored `profile`, under the policy `text`, with the
/// request row `req_1`.
async fn managed_gate(
    profile: Profile,
    text: Option<&str>,
) -> (
    Arc<Store>,
    Arc<SwitchablePolicy>,
    Arc<PolicyHandle>,
    PolicyGate,
) {
    let store = fresh_store().await;
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
    let source = SwitchablePolicy::new(text);
    let handle = managed_handle(&store, &source).await;
    let gate = PolicyGate::new(Arc::clone(&store), Arc::clone(&handle))
        .await
        .unwrap();
    (store, source, handle, gate)
}

fn profile_policy(mode: &str, profile: Profile) -> String {
    serde_json::json!({
        "version": 1,
        "revision": "r1",
        "contact": "it@example.com",
        "security": { "profile": { mode: profile.as_str(), "reason": "SEC-114" } },
    })
    .to_string()
}

const ALL_PROFILES: [Profile; 3] = [Profile::Relaxed, Profile::Standard, Profile::Strict];

async fn stored(store: &Store) -> Option<String> {
    store.get_setting(PROFILE_SETTING_KEY).await.unwrap()
}

fn refusal_cause(result: Result<Profile, SetProfileError>) -> &'static str {
    match result {
        Err(SetProfileError::Policy { refusal, .. }) => refusal.cause,
        other => panic!("expected a policy refusal, got {other:?}"),
    }
}

#[tokio::test]
async fn a_locked_profile_is_enforced_without_rewriting_the_stored_choice() {
    let text = profile_policy("locked", Profile::Strict);
    let (store, source, handle, gate) = managed_gate(Profile::Relaxed, Some(&text)).await;
    assert_eq!(gate.profile(), Profile::Strict);
    assert_eq!(gate.stored_profile(), Profile::Relaxed);
    assert_eq!(stored(&store).await.as_deref(), Some("\"relaxed\""));
    let (_, entry) = gate.effective_profile();
    assert_eq!(
        entry.to_json(),
        serde_json::json!({
            "source": "policy", "locked": true, "mode": "locked",
            "reason": "SEC-114", "state": "applied",
        })
    );
    // Locked means the field is not the human's: the locked value too.
    for requested in ALL_PROFILES {
        assert_eq!(
            refusal_cause(gate.set_profile(requested).await),
            CAUSE_SETTING_LOCKED
        );
    }
    assert_eq!(stored(&store).await.as_deref(), Some("\"relaxed\""));
    // The gate enforces it: an ungranted echo is refused, not auto-granted.
    assert!(matches!(
        gate.evaluate("req_1", "echo").await.unwrap(),
        GateDecision::Refuse { ref cause, .. } if cause == CAUSE_NOT_GRANTED
    ));

    // A trusted relaxed lock (a loosening file) is honoured just the same.
    source.set(Some(&profile_policy("locked", Profile::Relaxed)));
    handle.reload(Trigger::Reload { request_id: None }).await;
    assert_eq!(gate.profile(), Profile::Relaxed);
    drop(handle);
}

#[tokio::test(start_paused = true)]
async fn removing_the_policy_restores_the_stored_profile() {
    let text = profile_policy("locked", Profile::Strict);
    let (_store, source, handle, gate) = managed_gate(Profile::Relaxed, Some(&text)).await;
    assert_eq!(gate.profile(), Profile::Strict);
    remove_policy(&source, &handle).await;
    assert_eq!(gate.profile(), Profile::Relaxed);
    assert_eq!(
        gate.set_profile(Profile::Standard).await.unwrap(),
        Profile::Relaxed
    );
}

#[tokio::test]
async fn a_floor_clamps_every_pair_and_refuses_only_looser_choices() {
    for floor in ALL_PROFILES {
        for user in ALL_PROFILES {
            let text = profile_policy("floor", floor);
            let (store, _source, _handle, gate) = managed_gate(user, Some(&text)).await;
            let expected = crate::managed_policy::stricter(user, floor);
            assert_eq!(gate.profile(), expected, "user {user:?} floor {floor:?}");
            let (_, entry) = gate.effective_profile();
            let entry = entry.to_json();
            assert_eq!(entry["locked"], false);
            assert_eq!(entry["constraint"]["floor"], floor.as_str());
            if expected == user {
                assert_eq!(entry["source"], "user", "{entry}");
            } else {
                assert_eq!(entry["source"], "policy", "{entry}");
                assert_eq!(entry["clamped"], true, "{entry}");
            }
            // The stored choice is never rewritten by the clamp.
            assert_eq!(
                stored(&store).await,
                Some(serde_json::to_string(&user).unwrap())
            );
        }
        for requested in ALL_PROFILES {
            let text = profile_policy("floor", floor);
            let (store, _source, _handle, gate) = managed_gate(Profile::Strict, Some(&text)).await;
            let allowed = crate::managed_policy::stricter(requested, floor) == requested;
            let result = gate.set_profile(requested).await;
            if allowed {
                assert!(result.is_ok(), "{requested:?} within floor {floor:?}");
                assert_eq!(gate.profile(), requested);
            } else {
                assert_eq!(refusal_cause(result), CAUSE_POLICY_NOT_ALLOWED);
                assert_eq!(stored(&store).await.as_deref(), Some("\"strict\""));
            }
        }
    }
}

#[tokio::test]
async fn the_first_boot_seeds_the_policy_default_and_later_boots_keep_the_row() {
    let text = profile_policy("default", Profile::Strict);
    let store = fresh_store().await;
    let source = SwitchablePolicy::new(Some(&text));
    let handle = managed_handle(&store, &source).await;
    let gate = PolicyGate::new(Arc::clone(&store), Arc::clone(&handle))
        .await
        .unwrap();
    assert_eq!(gate.profile(), Profile::Strict);
    assert_eq!(stored(&store).await.as_deref(), Some("\"strict\""));
    // A default is not a lock: the human may move off it.
    gate.set_profile(Profile::Relaxed).await.unwrap();

    // A later default never moves an existing install.
    source.set(Some(&profile_policy("default", Profile::Standard)));
    handle.reload(Trigger::Reload { request_id: None }).await;
    let rebuilt = PolicyGate::new(Arc::clone(&store), Arc::clone(&handle))
        .await
        .unwrap();
    assert_eq!(rebuilt.profile(), Profile::Relaxed);
    assert_eq!(stored(&store).await.as_deref(), Some("\"relaxed\""));

    // Without a policy default the platform default is seeded, as before.
    let bare = fresh_store().await;
    let unmanaged = SwitchablePolicy::new(Some(&profile_policy("floor", Profile::Relaxed)));
    let handle = managed_handle(&bare, &unmanaged).await;
    PolicyGate::new(Arc::clone(&bare), handle).await.unwrap();
    assert_eq!(
        stored(&bare).await,
        Some(serde_json::to_string(&Profile::platform_default()).unwrap())
    );
}

#[tokio::test]
async fn a_frozen_profile_lets_only_a_tightening_through() {
    // A file that cannot be used, and no last good copy: the key is held.
    let (store, _source, handle, gate) =
        managed_gate(Profile::Relaxed, Some(r#"{"version":"#)).await;
    assert!(handle.view().is_held(Key::SecurityProfile));
    assert_eq!(
        gate.profile(),
        Profile::Relaxed,
        "a held key reads the user's value"
    );

    // The same value loosens nothing either.
    assert_eq!(
        gate.set_profile(Profile::Relaxed).await.unwrap(),
        Profile::Relaxed
    );
    assert_eq!(
        gate.set_profile(Profile::Standard).await.unwrap(),
        Profile::Relaxed
    );
    assert_eq!(
        gate.set_profile(Profile::Strict).await.unwrap(),
        Profile::Standard
    );
    assert_eq!(
        refusal_cause(gate.set_profile(Profile::Standard).await),
        CAUSE_POLICY_FROZEN
    );
    assert_eq!(stored(&store).await.as_deref(), Some("\"strict\""));
    assert_eq!(gate.profile(), Profile::Strict);
}

/// The policy denying `echo` by name.
const NEVER_ECHO: &str = r#"{
  "version": 1,
  "revision": "never-echo",
  "security": { "grants": { "never": ["echo"] } }
}"#;

#[tokio::test(start_paused = true)]
async fn a_grant_stops_authorizing_under_a_never_rule_and_authorizes_again_without_it() {
    let (store, source, handle, gate) = managed_gate(Profile::Standard, None).await;
    store.insert_grant("echo").await.unwrap();
    assert_eq!(
        gate.evaluate("req_1", "echo").await.unwrap(),
        GateDecision::Allow {
            auto_granted: false
        }
    );

    source.set(Some(NEVER_ECHO));
    handle.reload(Trigger::Reload { request_id: None }).await;
    let decision = gate.evaluate("req_1", "echo").await.unwrap();
    let GateDecision::Refuse {
        cause,
        detail,
        recovery,
    } = decision
    else {
        panic!("a never rule refuses: {decision:?}");
    };
    assert_eq!(cause, CAUSE_POLICY_DENIED);
    assert_eq!(recovery, RECOVERY_POLICY_DENIED);
    assert!(
        !detail.contains("never") && !detail.contains("rule"),
        "{detail}"
    );
    // The rule is in the audit row, with the policy's full digest.
    let denied: Vec<_> = store
        .audit_for_request("req_1")
        .await
        .unwrap()
        .into_iter()
        .filter(|row| row.action == ACTION_POLICY_DENIED)
        .collect();
    assert_eq!(denied.len(), 1);
    assert_eq!(denied[0].decision, Decision::Refuse);
    assert_eq!(denied[0].actor, Actor::Policy);
    let row: serde_json::Value =
        serde_json::from_str(denied[0].detail.as_deref().unwrap()).unwrap();
    assert_eq!(
        row,
        serde_json::json!({
            "capability": "echo",
            "rule": "echo",
            "digest": crate::network_service::sha256_hex(NEVER_ECHO.as_bytes()),
        })
    );
    // The grant is the human's and stays.
    assert!(store.active_grant("echo").await.unwrap());

    remove_policy(&source, &handle).await;
    assert_eq!(
        gate.evaluate("req_1", "echo").await.unwrap(),
        GateDecision::Allow {
            auto_granted: false
        }
    );
}

#[tokio::test]
async fn never_rules_refuse_on_every_profile_but_spare_the_control_plane() {
    let text = r#"{"version":1,"security":{"grants":{"never":["*"]}}}"#;
    for profile in ALL_PROFILES {
        let (store, _source, _handle, gate) = managed_gate(profile, Some(text)).await;
        store.insert_grant("echo").await.unwrap();
        for capability in ["echo", "flow.list"] {
            assert!(
                matches!(
                    gate.evaluate("req_1", capability).await.unwrap(),
                    GateDecision::Refuse { ref cause, .. } if cause == CAUSE_POLICY_DENIED
                ),
                "{capability} under {profile:?}"
            );
        }
        for capability in ["status", "query", "cancel"] {
            assert_eq!(
                gate.evaluate("req_1", capability).await.unwrap(),
                GateDecision::Allow {
                    auto_granted: false
                },
                "{capability} under {profile:?}"
            );
        }
        // Nothing was auto-granted for a denied capability.
        assert!(!store.active_grant("flow.list").await.unwrap());
    }
}

#[tokio::test]
async fn never_classes_refuse_a_flow_step_of_that_class_only() {
    let text = r#"{"version":1,"security":{"grants":{"never_classes":["external"]}}}"#;
    let (store, _source, _handle, gate) = managed_gate(Profile::Relaxed, Some(text)).await;
    store.insert_grant("flow.step:f/call").await.unwrap();
    store.insert_grant("flow.step:f/merge").await.unwrap();
    assert!(matches!(
        gate.evaluate_classified("req_1", "flow.step:f/call", CapabilityClass::External)
            .await
            .unwrap(),
        GateDecision::Refuse { ref cause, .. } if cause == CAUSE_POLICY_DENIED
    ));
    assert_eq!(
        gate.evaluate_classified("req_1", "flow.step:f/merge", CapabilityClass::Destructive)
            .await
            .unwrap(),
        GateDecision::Allow {
            auto_granted: false
        }
    );
    let rules: Vec<serde_json::Value> = store
        .audit_for_request("req_1")
        .await
        .unwrap()
        .into_iter()
        .filter(|row| row.action == ACTION_POLICY_DENIED)
        .map(|row| serde_json::from_str(row.detail.as_deref().unwrap()).unwrap())
        .collect();
    assert_eq!(rules.len(), 1);
    assert_eq!(rules[0]["rule"], "class:external");
}

// --- flow step grants bound to what runs -----------------------------------

fn step_binding(digest: char, class: &str, repository: Option<&str>) -> pam_store::GrantBinding {
    pam_store::GrantBinding {
        flow_id: "f".to_owned(),
        step_id: "push".to_owned(),
        effect_digest: digest.to_string().repeat(64),
        effect_class: class.to_owned(),
        repository: repository.map(str::to_owned),
    }
}

fn grant_row(id: i64, binding: Option<pam_store::GrantBinding>) -> pam_store::GrantRow {
    pam_store::GrantRow {
        id,
        capability: "flow.step:f/push".to_owned(),
        scope: "global".to_owned(),
        granted_ts: 1,
        revoked_ts: None,
        binding,
        bound_ts: None,
    }
}

#[test]
fn a_step_grant_covers_only_its_definition_class_and_repository() {
    use crate::policy::{StepGrant, match_step_grant};
    let wanted = step_binding('a', "destructive", Some("/a"));
    assert_eq!(match_step_grant(&[], &wanted), StepGrant::Missing);
    // Covered: the same definition and class, here or everywhere.
    for repository in [Some("/a"), None] {
        let rows = [grant_row(
            1,
            Some(step_binding('a', "destructive", repository)),
        )];
        assert_eq!(match_step_grant(&rows, &wanted), StepGrant::Bound);
    }
    // A covering row beats a legacy one; a legacy one beats a stale one.
    let rows = [
        grant_row(1, None),
        grant_row(2, Some(step_binding('a', "destructive", Some("/a")))),
    ];
    assert_eq!(match_step_grant(&rows, &wanted), StepGrant::Bound);
    let rows = [
        grant_row(1, Some(step_binding('b', "destructive", Some("/a")))),
        grant_row(2, None),
    ];
    assert_eq!(match_step_grant(&rows, &wanted), StepGrant::Legacy(2));
    // What changed is said, and a same-repository row explains first.
    let rows = [
        grant_row(1, Some(step_binding('a', "destructive", Some("/other")))),
        grant_row(2, Some(step_binding('b', "destructive", Some("/a")))),
    ];
    assert_eq!(
        match_step_grant(&rows, &wanted),
        StepGrant::Changed("the step's command changed since it was approved".to_owned())
    );
    let rows = [grant_row(
        1,
        Some(step_binding('a', "external", Some("/a"))),
    )];
    assert_eq!(
        match_step_grant(&rows, &wanted),
        StepGrant::Changed(
            "the step's effect class changed since it was approved (approved as external, now \
             destructive)"
                .to_owned()
        )
    );
    let rows = [grant_row(
        1,
        Some(step_binding('a', "destructive", Some("/other"))),
    )];
    assert_eq!(
        match_step_grant(&rows, &wanted),
        StepGrant::Changed("the step was approved for /other, not for /a".to_owned())
    );
}

#[tokio::test]
async fn a_step_grant_that_no_longer_covers_the_step_asks_on_every_profile() {
    for profile in [Profile::Relaxed, Profile::Standard, Profile::Strict] {
        let store = fresh_store().await;
        let gate = gate_with(&store, profile).await;
        let cap = "flow.step:f/push";
        // No grant: what the profile always did.
        let (missing, changed) = gate
            .evaluate_step(
                "req_1",
                cap,
                CapabilityClass::Destructive,
                &step_binding('a', "destructive", Some("/a")),
            )
            .await
            .unwrap();
        assert_eq!(changed, None);
        if profile == Profile::Relaxed {
            assert!(matches!(missing, GateDecision::RequireApproval { .. }));
        } else {
            assert!(
                matches!(missing, GateDecision::Refuse { ref cause, .. } if cause == CAUSE_NOT_GRANTED)
            );
        }
        // A grant for another definition: an approval, with the reason.
        store
            .apply_grant_change_audited(
                "req_1",
                pam_store::GrantChange::Bind(cap, &step_binding('b', "destructive", Some("/a"))),
                pam_store::AuditEntry {
                    action: "grant_from_approval",
                    decision: Decision::Allow,
                    actor: Actor::Human,
                    detail: None,
                },
            )
            .await
            .unwrap();
        let (decision, changed) = gate
            .evaluate_step(
                "req_1",
                cap,
                CapabilityClass::Destructive,
                &step_binding('a', "destructive", Some("/a")),
            )
            .await
            .unwrap();
        let GateDecision::RequireApproval { reason } = decision else {
            panic!("{profile:?}: a changed step must ask, got {decision:?}");
        };
        assert!(reason.contains("changed since it was approved"), "{reason}");
        assert_eq!(
            changed.as_deref(),
            Some("the step's command changed since it was approved")
        );
        // The covered definition: what a granted step always got.
        let (decision, changed) = gate
            .evaluate_step(
                "req_1",
                cap,
                CapabilityClass::Destructive,
                &step_binding('b', "destructive", Some("/a")),
            )
            .await
            .unwrap();
        assert_eq!(changed, None);
        if profile == Profile::Relaxed {
            assert_eq!(
                decision,
                GateDecision::Allow {
                    auto_granted: false
                }
            );
        } else {
            assert!(matches!(decision, GateDecision::RequireApproval { .. }));
        }
    }
}

#[tokio::test]
async fn a_never_rule_refuses_a_legacy_step_grant_before_it_is_bound() {
    let text = r#"{"version":1,"security":{"grants":{"never":["flow.step:f/*"]}}}"#;
    let (store, _source, _handle, gate) = managed_gate(Profile::Relaxed, Some(text)).await;
    store.insert_grant("flow.step:f/push").await.unwrap();
    let (decision, changed) = gate
        .evaluate_step(
            "req_1",
            "flow.step:f/push",
            CapabilityClass::Destructive,
            &step_binding('a', "destructive", Some("/a")),
        )
        .await
        .unwrap();
    assert!(
        matches!(decision, GateDecision::Refuse { ref cause, .. } if cause == CAUSE_POLICY_DENIED),
        "{decision:?}"
    );
    assert_eq!(changed, None);
    // The row stays the human's and stays unbound: the policy decided first.
    let rows = store.active_grants("flow.step:f/push").await.unwrap();
    assert_eq!(rows[0].binding, None);
    assert!(
        store
            .audit_for_request("req_1")
            .await
            .unwrap()
            .iter()
            .all(|row| row.action != crate::policy::ACTION_GRANT_BOUND)
    );
}

#[tokio::test]
async fn a_legacy_step_grant_binds_once_with_its_audit_row() {
    let store = fresh_store().await;
    let gate = gate_with(&store, Profile::Relaxed).await;
    store.insert_grant("flow.step:f/push").await.unwrap();
    let wanted = step_binding('a', "destructive", Some("/a"));
    for _ in 0..2 {
        let (decision, changed) = gate
            .evaluate_step(
                "req_1",
                "flow.step:f/push",
                CapabilityClass::Destructive,
                &wanted,
            )
            .await
            .unwrap();
        assert_eq!(
            decision,
            GateDecision::Allow {
                auto_granted: false
            }
        );
        assert_eq!(changed, None);
    }
    let rows = store.active_grants("flow.step:f/push").await.unwrap();
    assert_eq!(rows[0].binding.as_ref(), Some(&wanted));
    let bound: Vec<_> = store
        .audit_for_request("req_1")
        .await
        .unwrap()
        .into_iter()
        .filter(|row| row.action == crate::policy::ACTION_GRANT_BOUND)
        .collect();
    assert_eq!(bound.len(), 1, "bound on first use only");
    assert_eq!(bound[0].actor, Actor::Policy);
}
