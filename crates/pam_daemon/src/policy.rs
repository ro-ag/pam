//! Policy gate: decides, before enqueue, whether a request may proceed.
//!
//! The gate only decides — it never waits; approval-gated operations pause in the executor via the
//! approval service, with [`GateDecision::RequireApproval`] as the signal. An ungranted capability
//! under a manual profile is an immediate [`GateDecision::Refuse`] — nothing enqueued, and the
//! recovery line points the human at the GUI, never a security command.
//! - **Grants**: capability grants are global (machine-wide) only; an active grant is a `grant` row
//!   with `revoked_ts` NULL. Revocation and manual granting are GUI-only administration; the gate
//!   itself only ever adds grants, via the relaxed profile's non-destructive auto-grant path.
//! - **Audit split**: [`PolicyGate::evaluate`] does not audit refusals or approvals — the request
//!   pipeline audits every terminal decision when it acts on the returned [`GateDecision`].
//!   Auto-grants are the exception: they mutate the `grant` table inside `evaluate`, so their audit
//!   row (`auto_grant`, actor `policy`, `allow`, active profile in the detail) is written right
//!   there. Because audit rows reference `request.id` by foreign key, `evaluate` takes the request
//!   id under the contract that the request row already exists (the pipeline inserts it before
//!   gating).
//! - **Profiles**: one policy engine, one [`Profile`] enum, no per-OS code paths — only the default
//!   differs by platform ([`Profile::platform_default`]). The active profile persists in the
//!   `setting` table under [`PROFILE_SETTING_KEY`] as a JSON string; changing it is GUI-only.
//! - **One source of truth for the profile**: the gate reads the setting once, at construction,
//!   and from then on the profile it holds is what every part of the daemon enforces, reports and
//!   stamps (`admin.profile.get`, the flow step gate, the watch/landing authorization stamp).
//!   [`PolicyGate::set_profile`] is the only way to change it: it persists the setting and then
//!   swaps the live value, so a change made in the GUI governs from the next evaluation — there
//!   is no window in which the stored profile refuses work the live one still admits.
//! - **Classes and admission pools**: [`classify`] is the one registry. [`CapabilityClass::Control`]
//!   names the daemon's own bookkeeping requests (`status`, `query`, `cancel`); [`admission_pool`]
//!   derives the dispatcher pool from the class, so no other module matches capability names to
//!   decide how a request is admitted.

use std::sync::{Arc, RwLock};

use pam_store::{Actor, AuditEntry, Decision, GrantChange, Store, StoreError};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// `setting` key holding the active [`Profile`] as a JSON string.
pub const PROFILE_SETTING_KEY: &str = "policy.profile";

/// Refusal cause for a capability the registry does not know.
pub const CAUSE_UNKNOWN_CAPABILITY: &str = "unknown_capability";

/// Refusal cause for a known capability without an active grant.
pub const CAUSE_NOT_GRANTED: &str = "not_granted";

/// `audit.action` for the grant a relaxed-profile first use inserts.
pub const ACTION_AUTO_GRANT: &str = "auto_grant";

/// GUI recovery line for [`CAUSE_UNKNOWN_CAPABILITY`] refusals.
const RECOVERY_UNKNOWN_CAPABILITY: &str = "Open the PAM GUI to see available capabilities.";

/// GUI recovery line for [`CAUSE_NOT_GRANTED`] refusals.
const RECOVERY_NOT_GRANTED: &str =
    "Grant this capability in the PAM GUI (Security > Capabilities).";

/// Approval strictness profile. One engine for every platform; only the
/// default differs ([`Profile::platform_default`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Profile {
    /// Non-destructive capabilities auto-grant on first use;
    /// destructive/external operations ask once per capability.
    Relaxed,
    /// Grants are manual (GUI); destructive/external operations need
    /// per-operation approval.
    Standard,
    /// Grants are manual and every granted non-read-only operation needs
    /// per-operation approval.
    Strict,
}

impl Profile {
    /// The default profile for the platform this binary runs on:
    /// macOS starts relaxed, everything else starts standard.
    #[must_use]
    pub fn platform_default() -> Self {
        if cfg!(target_os = "macos") {
            Self::Relaxed
        } else {
            Self::Standard
        }
    }

    /// Lower-case profile name, matching the stored JSON string.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Relaxed => "relaxed",
            Self::Standard => "standard",
            Self::Strict => "strict",
        }
    }
}

/// How much damage a capability can do, as registered in the capability
/// registry ([`classify`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapabilityClass {
    /// The daemon's own bookkeeping surface (`status`, `query`, `cancel`):
    /// like [`Self::ReadOnly`] it bypasses grants and lanes, and in addition
    /// it is admitted from the reserved control pool and publishes no
    /// lifecycle events — a poll is not work anyone follows.
    Control,
    /// Observes state, changes nothing. Bypasses grants entirely.
    ReadOnly,
    /// Changes state the caller can trivially undo.
    NonDestructive,
    /// Changes state that is hard or impossible to undo.
    Destructive,
    /// Leaves the machine (network side effects, third parties).
    External,
}

impl CapabilityClass {
    /// Whether this class skips grants, approvals, dedupe and lanes: the
    /// request is executed inline by the task that admitted it.
    #[must_use]
    pub fn bypasses_lanes(self) -> bool {
        matches!(self, Self::Control | Self::ReadOnly)
    }
}

/// Which dispatcher pool admits a request (see [`admission_pool`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmissionPool {
    /// Everything that is not daemon bookkeeping.
    Work,
    /// `status`: a snapshot read that cannot be slow. Slots of its own, so
    /// the daemon's liveness answer is never refused because something
    /// else — a `query` waiting on the store — took the control slots.
    Status,
    /// `query`: admitted from the reserved control pool.
    Control,
    /// `cancel`: headroom of its own, so the remedy for a saturated daemon
    /// can never be refused because polls took every control slot.
    Cancel,
}

/// The dispatcher pool for `capability`, derived from [`classify`]. An
/// unknown capability is ordinary work: it is refused by the gate, and must
/// not be able to spend the reserved control slots on the way there.
#[must_use]
pub fn admission_pool(capability: &str) -> AdmissionPool {
    match classify(capability) {
        Some(CapabilityClass::Control) if capability == CAP_STATUS => AdmissionPool::Status,
        Some(CapabilityClass::Control) if capability == CAP_CANCEL => AdmissionPool::Cancel,
        Some(CapabilityClass::Control) => AdmissionPool::Control,
        _ => AdmissionPool::Work,
    }
}

/// Wire name of the daemon health capability.
pub const CAP_STATUS: &str = "status";

/// Wire name of the ticket-state lookup.
pub const CAP_QUERY: &str = "query";

/// Wire name of the cancellation capability.
pub const CAP_CANCEL: &str = "cancel";

/// Static capability registry: what each known capability may do.
///
/// Known capabilities: `status` (read-only), `query` (read-only ticket-state lookup backing `pam
/// wait`/`pam subscribe`), `echo` (first executor capability, non-destructive), `cancel` (built-in
/// behind `pam cancel <ticket>`), and the three flow capabilities. The table is static by design —
/// not something a request can extend. An unknown capability classifies as `None` and the gate
/// refuses with [`CAUSE_UNKNOWN_CAPABILITY`].
///
/// `cancel` mutates state (it fails the target request) but is deliberately classed `Control`
/// beside `status` and `query`: a cancellation must never queue behind the very work it cancels,
/// and the control class gives it the grant bypass and lane bypass. Its effect is bounded to pam's
/// own bookkeeping — nothing outside the daemon changes.
///
/// `flow.run` is `NonDestructive` for the opposite reason: a flow is a recipe, and running one
/// changes nothing by itself. Every step that could change something is gated individually inside
/// the run, under its own `flow.step:<flow>/<step>` capability name — so this class governs
/// admission/lanes, and the steps govern damage (see [`crate::flow_service`]).
#[must_use]
pub fn classify(capability: &str) -> Option<CapabilityClass> {
    match capability {
        CAP_STATUS | CAP_CANCEL | CAP_QUERY => Some(CapabilityClass::Control),
        crate::flow_service::CAP_FLOW_LIST
        | crate::flow_service::CAP_FLOW_SHOW
        | crate::flow_service::CAP_FLOW_INSPECT
        | crate::flow_result_service::CAP_FLOW_RESULT
        | crate::evidence_service::CAP_EVIDENCE_READ => Some(CapabilityClass::ReadOnly),
        "echo" | crate::flow_service::CAP_FLOW_RUN => Some(CapabilityClass::NonDestructive),
        _ => None,
    }
}

/// What the gate decided about one request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GateDecision {
    /// The request may proceed to the queue.
    Allow {
        /// True when this evaluation auto-granted the capability
        /// (relaxed profile, non-destructive, first use).
        auto_granted: bool,
    },
    /// The request may enqueue, but the executor must pause it for a
    /// human approval before running it.
    RequireApproval {
        /// Why an approval is needed, for the approval prompt.
        reason: String,
    },
    /// The request must be refused; nothing is enqueued.
    Refuse {
        /// Machine-readable cause ([`CAUSE_UNKNOWN_CAPABILITY`],
        /// [`CAUSE_NOT_GRANTED`]).
        cause: String,
        /// Human-readable explanation naming the capability.
        detail: String,
        /// Sentence pointing the human at the GUI to recover.
        recovery: String,
    },
}

/// Why the gate could not be constructed or consulted.
#[derive(Debug, Error)]
pub enum PolicyError {
    /// The stored profile setting is not a profile this binary knows.
    #[error("unrecognized policy profile {value:?} stored under \"policy.profile\"")]
    UnrecognizedProfile {
        /// The offending stored value.
        value: String,
    },
    /// Underlying store failure.
    #[error(transparent)]
    Store(#[from] StoreError),
}

/// The policy gate service. Constructed once from the store's persisted
/// profile; consulted by the request pipeline before every enqueue. It is
/// also the daemon's one live copy of the profile (see the module docs).
#[derive(Debug)]
pub struct PolicyGate {
    store: Arc<Store>,
    /// Read on every evaluation, written only by [`Self::set_profile`]. A
    /// sync lock: the critical section is one `Copy`, never held across an
    /// await.
    profile: RwLock<Profile>,
}

impl PolicyGate {
    /// Builds a gate from the profile persisted under
    /// [`PROFILE_SETTING_KEY`], falling back to
    /// [`Profile::platform_default`] — and persisting it — when the
    /// setting is unset.
    pub async fn new(store: Arc<Store>) -> Result<Self, PolicyError> {
        let profile = if let Some(raw) = store.get_setting(PROFILE_SETTING_KEY).await? {
            serde_json::from_str(&raw)
                .map_err(|_| PolicyError::UnrecognizedProfile { value: raw })?
        } else {
            let profile = Profile::platform_default();
            let raw = serde_json::to_string(&profile)
                .expect("a Profile always serializes to a JSON string");
            store.set_setting(PROFILE_SETTING_KEY, &raw).await?;
            profile
        };
        Ok(Self {
            store,
            profile: RwLock::new(profile),
        })
    }

    /// The profile this gate enforces — the daemon's one source of truth.
    #[must_use]
    pub fn profile(&self) -> Profile {
        *self
            .profile
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Changes the enforced profile: persists it under
    /// [`PROFILE_SETTING_KEY`], then swaps the live value. Returns the
    /// profile it replaced.
    ///
    /// Persist first: a failed write leaves the live profile unchanged, so
    /// the daemon never enforces something a restart would not.
    ///
    /// # Errors
    ///
    /// The underlying [`StoreError`] when the setting cannot be written;
    /// nothing changed.
    pub async fn set_profile(&self, profile: Profile) -> Result<Profile, StoreError> {
        let raw =
            serde_json::to_string(&profile).expect("a Profile always serializes to a JSON string");
        self.store.set_setting(PROFILE_SETTING_KEY, &raw).await?;
        let mut live = self
            .profile
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        Ok(std::mem::replace(&mut *live, profile))
    }

    /// Decides whether the request `request_id` may exercise
    /// `capability`.
    ///
    /// Contract: the `request` row for `request_id` already exists (the
    /// pipeline inserts it before gating) so the auto-grant audit row's
    /// foreign key holds. The gate never waits — approval-gated work
    /// pauses in the executor.
    pub async fn evaluate(
        &self,
        request_id: &str,
        capability: &str,
    ) -> Result<GateDecision, StoreError> {
        let Some(class) = classify(capability) else {
            return Ok(GateDecision::Refuse {
                cause: CAUSE_UNKNOWN_CAPABILITY.to_owned(),
                detail: format!("capability {capability:?} is not registered"),
                recovery: RECOVERY_UNKNOWN_CAPABILITY.to_owned(),
            });
        };
        self.evaluate_classified(request_id, capability, class)
            .await
    }

    /// [`Self::evaluate`] after classification.
    ///
    /// Public because a flow's steps are gated one at a time under names
    /// the static registry does not (and must not) carry: the engine
    /// classifies each step itself and evaluates it here. It is also the
    /// seam the tests use to exercise classes no registered capability
    /// has yet.
    pub async fn evaluate_classified(
        &self,
        request_id: &str,
        capability: &str,
        class: CapabilityClass,
    ) -> Result<GateDecision, StoreError> {
        // Read-only and control capabilities bypass grants on every
        // profile (the queue exempts them from lanes for the same reason).
        if class.bypasses_lanes() {
            return Ok(GateDecision::Allow {
                auto_granted: false,
            });
        }
        let granted = self.store.active_grant(capability).await?;
        // One read: the whole decision is made under the profile that was
        // live when it started.
        let profile = self.profile();
        let decision = match (profile, granted, class) {
            // An active grant on relaxed means go; on standard it means
            // go for non-destructive work.
            (Profile::Relaxed, true, _)
            | (Profile::Standard, true, CapabilityClass::NonDestructive) => GateDecision::Allow {
                auto_granted: false,
            },
            // Relaxed auto-grants non-destructive capabilities on first
            // use; the grant mutation is audited right here (see the
            // module docs for the audit split).
            (Profile::Relaxed, false, CapabilityClass::NonDestructive) => {
                self.auto_grant(request_id, capability, profile).await?;
                GateDecision::Allow { auto_granted: true }
            }
            // Relaxed asks once per destructive/external capability; the
            // approval service records the grant on approval, so the next
            // evaluation takes the granted arm above.
            (Profile::Relaxed, false, _) => GateDecision::RequireApproval {
                reason: format!(
                    "capability {capability:?} needs a one-time approval \
                     under the relaxed profile"
                ),
            },
            // Manual profiles refuse anything ungranted outright.
            (Profile::Standard | Profile::Strict, false, _) => GateDecision::Refuse {
                cause: CAUSE_NOT_GRANTED.to_owned(),
                detail: format!("capability {capability:?} has no active grant"),
                recovery: RECOVERY_NOT_GRANTED.to_owned(),
            },
            // Granted destructive/external work on standard — and any
            // granted non-read-only work on strict — needs a
            // per-operation approval.
            (Profile::Standard | Profile::Strict, true, _) => GateDecision::RequireApproval {
                reason: format!(
                    "capability {capability:?} requires per-operation approval \
                     under the {} profile",
                    profile.as_str()
                ),
            },
        };
        Ok(decision)
    }

    /// Inserts the grant row and its audit row for a relaxed-profile
    /// auto-grant, in one transaction: a crash cannot leave a grant nobody
    /// audited. The audit detail records the active profile. A grant that
    /// a concurrent evaluation inserted first is left alone (and audited
    /// by whoever inserted it).
    async fn auto_grant(
        &self,
        request_id: &str,
        capability: &str,
        profile: Profile,
    ) -> Result<(), StoreError> {
        let detail = serde_json::json!({
            "capability": capability,
            "profile": profile.as_str(),
        })
        .to_string();
        self.store
            .apply_grant_change_audited(
                request_id,
                GrantChange::Add(capability),
                AuditEntry {
                    action: ACTION_AUTO_GRANT,
                    decision: Decision::Allow,
                    actor: Actor::Policy,
                    detail: Some(&detail),
                },
            )
            .await
            .map(|_| ())
    }
}
