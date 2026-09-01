//! Policy gate: decides, before enqueue, whether a request may proceed.
//!
//! # Design
//!
//! The gate only **decides** — it never waits. Approval-gated operations
//! pause in the executor via the approval service (a later task); the
//! gate's [`GateDecision::RequireApproval`] is the signal to do so. An
//! ungranted capability under a manual profile is an immediate
//! [`GateDecision::Refuse`] — nothing is enqueued, and the recovery line
//! points the human at the GUI, never at a security command.
//!
//! # Grants
//!
//! Capability grants are global (machine-wide) only; an active grant is a
//! `grant` row whose `revoked_ts` is NULL. Revocation and manual granting
//! are GUI-only administration and arrive with that surface — the gate
//! itself only ever *adds* grants, on the relaxed profile's
//! non-destructive auto-grant path.
//!
//! # Audit split
//!
//! [`PolicyGate::evaluate`] does **not** audit refusals or approvals: the
//! request pipeline (which owns the request context) audits every terminal
//! decision when it acts on the returned [`GateDecision`]. Auto-grants are
//! the one exception — they mutate the `grant` table inside `evaluate`, so
//! the matching audit row (action `auto_grant`, actor `policy`, decision
//! `allow`, active profile in the detail) is written right there.
//!
//! Because audit rows reference `request.id` by foreign key,
//! [`PolicyGate::evaluate`] takes the request id under the contract that
//! **the request row already exists** — the pipeline inserts the request
//! before gating it.
//!
//! # Profiles
//!
//! One policy engine, one [`Profile`] enum, no per-OS code paths — only
//! the *default* differs by platform ([`Profile::platform_default`]).
//! The active profile persists in the `setting` table under
//! [`PROFILE_SETTING_KEY`] as a JSON string; changing it is GUI-only (the
//! GUI writes the setting, and the daemon constructs its gate from it).

use std::sync::Arc;

use pam_store::{Actor, Decision, Store, StoreError};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// `setting` key holding the active [`Profile`] as a JSON string.
pub const PROFILE_SETTING_KEY: &str = "policy.profile";

/// Refusal cause for a capability the registry does not know.
pub const CAUSE_UNKNOWN_CAPABILITY: &str = "unknown_capability";

/// Refusal cause for a known capability without an active grant.
pub const CAUSE_NOT_GRANTED: &str = "not_granted";

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
    /// Observes state, changes nothing. Bypasses grants entirely.
    ReadOnly,
    /// Changes state the caller can trivially undo.
    NonDestructive,
    /// Changes state that is hard or impossible to undo.
    Destructive,
    /// Leaves the machine (network side effects, third parties).
    External,
}

/// Static capability registry: what each known capability may do.
///
/// Known capabilities so far: `status` (read-only) and `echo` (the first
/// executor capability, non-destructive). Connectors and flows register
/// their capabilities later, when the connector host lands; until then
/// the table is static. An unknown capability classifies as `None` and
/// the gate refuses it with cause [`CAUSE_UNKNOWN_CAPABILITY`].
#[must_use]
pub fn classify(capability: &str) -> Option<CapabilityClass> {
    match capability {
        "status" => Some(CapabilityClass::ReadOnly),
        "echo" => Some(CapabilityClass::NonDestructive),
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
/// profile; consulted by the request pipeline before every enqueue.
#[derive(Debug)]
pub struct PolicyGate {
    store: Arc<Store>,
    profile: Profile,
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
        Ok(Self { store, profile })
    }

    /// The profile this gate enforces.
    #[must_use]
    pub fn profile(&self) -> Profile {
        self.profile
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

    /// [`Self::evaluate`] after classification; also the seam the tests
    /// use to exercise classes the static registry does not contain yet.
    pub(crate) async fn evaluate_classified(
        &self,
        request_id: &str,
        capability: &str,
        class: CapabilityClass,
    ) -> Result<GateDecision, StoreError> {
        // Read-only capabilities bypass grants on every profile (the
        // queue exempts them from lanes for the same reason).
        if class == CapabilityClass::ReadOnly {
            return Ok(GateDecision::Allow {
                auto_granted: false,
            });
        }
        let granted = self.store.active_grant(capability).await?;
        let decision = match (self.profile, granted, class) {
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
                self.auto_grant(request_id, capability).await?;
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
                    self.profile.as_str()
                ),
            },
        };
        Ok(decision)
    }

    /// Inserts the grant row and its audit row for a relaxed-profile
    /// auto-grant. The audit detail records the active profile.
    async fn auto_grant(&self, request_id: &str, capability: &str) -> Result<(), StoreError> {
        self.store.insert_grant(capability).await?;
        let detail = serde_json::json!({
            "capability": capability,
            "profile": self.profile.as_str(),
        })
        .to_string();
        self.store
            .append_audit(
                request_id,
                "auto_grant",
                Decision::Allow,
                Actor::Policy,
                Some(&detail),
            )
            .await
    }
}
