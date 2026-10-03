//! Policy gate: decides, before enqueue, whether a request may proceed.
//!
//! The gate only decides — it never waits; approval-gated operations pause in the executor via the
//! approval service, with [`GateDecision::RequireApproval`] as the signal. An ungranted capability
//! under a manual profile is an immediate [`GateDecision::Refuse`] — nothing enqueued, and the
//! recovery line points the human at the GUI, never a security command.
//! - **Grants**: an active grant is a `grant` row with `revoked_ts` NULL. A capability's grant is
//!   global (machine-wide), except a flow step's: a `flow.step:<flow>/<step>` grant is bound to
//!   what the step runs ([`GrantBinding`]: its effect digest, its gate class and the canonical
//!   repository the approval was given for) and authorizes the step only while all three still
//!   match ([`PolicyGate::evaluate_step`]). A mismatch — a flow file edited by hand, a grant
//!   given for another repository — needs an approval again, never passes silently, and the
//!   reason says what changed. An unbound legacy grant (from before the binding existed)
//!   authorizes once more and is bound to what runs right then ([`ACTION_GRANT_BOUND`]).
//!   Revocation and manual granting are GUI-only administration; the gate itself only ever adds
//!   grants, via the relaxed profile's non-destructive auto-grant path, and binds legacy ones.
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
//!   and from then on [`PolicyGate::profile`] is what every part of the daemon enforces, reports
//!   and stamps (`admin.profile.get`, the flow step gate, the watch/landing authorization stamp).
//!   [`PolicyGate::set_profile`] is the only way to change it: it persists the setting and then
//!   swaps the live value, so a change made in the GUI governs from the next evaluation — there
//!   is no window in which the stored profile refuses work the live one still admits.
//! - **Managed policy over the human's choice**: the gate holds the human's stored profile, and
//!   [`PolicyGate::profile`] is the *effective* one, computed at every read from the managed
//!   policy in force ([`crate::managed_policy::PolicyView::effective_profile`]): a `locked`
//!   profile forces, a `floor` clamps a more permissive choice, and the stored row is never
//!   rewritten, so removing the policy restores what the human had. A policy change therefore
//!   needs no hook: the next evaluation reads the new view. [`PolicyGate::set_profile`] refuses
//!   a locked value and one more permissive than the floor; while the key is held (the policy
//!   cannot be read and its intent is unknown) it lets only a tightening through. The first
//!   boot seeds the row from the policy's `default` when it has one.
//! - **Never-grant rules**: a capability matching the policy's `security.grants.never` name
//!   globs or `never_classes` is refused [`CAUSE_POLICY_DENIED`] before anything else is looked
//!   at — on every profile, with or without an active grant (the grant row stays the human's and
//!   authorizes again once the policy no longer denies it). The refusal names nothing about the
//!   rule; the rule goes into a `policy.denied` audit row on the request, which the gate writes
//!   itself like the auto-grant row. Control capabilities (`status`, `query`, `cancel`, the
//!   doctor report) are the daemon's own bookkeeping, not work, and are never denied.
//! - **One decision, two callers**: what the gate decides is a pure function of the policy view,
//!   the effective profile, the capability, its class and how its grant stands
//!   ([`decide_before_grant`] then [`decide_with_grant`], or [`decide`] for both). The run's gate
//!   ([`PolicyGate::evaluate`], [`PolicyGate::evaluate_step`]) calls the two halves around the
//!   grant read, so a denied or read-only capability never touches the grant table, and then
//!   performs the decision's side effects (the `policy.denied` audit row, the auto-grant, the
//!   legacy binding); `flow.inspect` calls [`decide`] on the grants as they are now and performs
//!   none. Both turn the [`Verdict`] into a [`GateDecision`] with [`Verdict::decision`], so they
//!   cannot disagree.
//! - **Classes and admission pools**: [`classify`] is the one registry. [`CapabilityClass::Control`]
//!   names the daemon's own bookkeeping requests (`status`, `query`, `cancel`); [`admission_pool`]
//!   derives the dispatcher pool from the class, so no other module matches capability names to
//!   decide how a request is admitted.

use std::sync::{Arc, RwLock};

use pam_store::{
    Actor, AuditEntry, Decision, GrantBinding, GrantChange, GrantRow, Store, StoreError,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::managed_policy::{CAUSE_POLICY_DENIED, EffectiveEntry, Key, PolicyView, WriteRefusal};
use crate::managed_policy_service::{ACTION_POLICY_DENIED, PolicyHandle, denied_detail};

/// `setting` key holding the active [`Profile`] as a JSON string.
pub const PROFILE_SETTING_KEY: &str = "policy.profile";

/// Refusal cause for a capability the registry does not know.
pub const CAUSE_UNKNOWN_CAPABILITY: &str = "unknown_capability";

/// Refusal cause for a known capability without an active grant.
pub const CAUSE_NOT_GRANTED: &str = "not_granted";

/// `audit.action` for the grant a relaxed-profile first use inserts.
pub const ACTION_AUTO_GRANT: &str = "auto_grant";

/// `audit.action` for an unbound legacy flow step grant bound, on its first
/// use, to what the step was about to run.
pub const ACTION_GRANT_BOUND: &str = "grant_bound";

/// How a flow step's active grants stand against what is about to run
/// ([`match_step_grant`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StepGrant {
    /// A bound grant covers this step, this definition, this repository.
    Bound,
    /// No bound grant covers it, but this unbound legacy grant row does:
    /// it authorizes once more and is bound to what runs now.
    Legacy(i64),
    /// Grants exist and none covers what runs now; the reason says what
    /// changed since the approval.
    Changed(String),
    /// No active grant at all.
    Missing,
}

/// How `rows` — the active grants of one flow step capability — stand
/// against `binding`, what the step is about to run. A bound row covers it
/// when the effect digest and class match and its repository is the
/// request's (or every repository). Covered beats legacy beats changed.
#[must_use]
pub fn match_step_grant(rows: &[GrantRow], binding: &GrantBinding) -> StepGrant {
    let in_scope =
        |bound: &GrantBinding| bound.repository.is_none() || bound.repository == binding.repository;
    let bound: Vec<&GrantBinding> = rows.iter().filter_map(|row| row.binding.as_ref()).collect();
    if bound.iter().any(|row| {
        in_scope(row)
            && row.effect_digest == binding.effect_digest
            && row.effect_class == binding.effect_class
    }) {
        return StepGrant::Bound;
    }
    if let Some(legacy) = rows.iter().find(|row| row.binding.is_none()) {
        return StepGrant::Legacy(legacy.id);
    }
    if let Some(row) = bound.iter().find(|row| in_scope(row)) {
        return StepGrant::Changed(if row.effect_digest == binding.effect_digest {
            format!(
                "the step's effect class changed since it was approved (approved as {}, now {})",
                row.effect_class, binding.effect_class
            )
        } else {
            "the step's command changed since it was approved".to_owned()
        });
    }
    match bound.first() {
        Some(row) => StepGrant::Changed(format!(
            "the step was approved for {}, not for {}",
            row.repository.as_deref().unwrap_or("every repository"),
            binding.repository.as_deref().unwrap_or("this repository")
        )),
        None => StepGrant::Missing,
    }
}

/// How a capability's grant stands when the gate decides.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GrantStanding {
    /// An active grant covers it (for a flow step: a bound grant, or a
    /// legacy one the run binds).
    Granted,
    /// No active grant.
    Missing,
    /// A flow step's grants exist and none covers what runs now; the reason
    /// says what changed.
    Changed(String),
}

impl From<&StepGrant> for GrantStanding {
    /// How inspection reads a step's grants: a legacy grant counts as
    /// granted (the run binds it), a changed one as changed.
    fn from(grant: &StepGrant) -> Self {
        match grant {
            StepGrant::Bound | StepGrant::Legacy(_) => Self::Granted,
            StepGrant::Missing => Self::Missing,
            StepGrant::Changed(reason) => Self::Changed(reason.clone()),
        }
    }
}

/// What the gate decided, before any of its side effects (see the module
/// docs on one decision, two callers).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// A managed never-grant rule matches; the rule is for the audit row only.
    PolicyDenied {
        /// The matching rule.
        rule: String,
    },
    /// Go: read-only or control, or granted where the profile lets a grant
    /// alone admit it.
    Allow,
    /// Go, granting it first (relaxed profile, non-destructive, first use).
    AutoGrant,
    /// A human must approve this operation.
    RequireApproval {
        /// Why, for the approval prompt.
        reason: String,
        /// For a flow step whose grant no longer covers what runs: what changed.
        changed: Option<String>,
    },
    /// Refused: no active grant under a manual profile.
    NotGranted,
}

impl Verdict {
    /// The [`GateDecision`] this verdict is, for `capability`. The run's gate
    /// returns it once the side effects are done; inspection returns it as it
    /// is (an [`Self::AutoGrant`] is an allow that would grant on execution).
    #[must_use]
    pub fn decision(&self, capability: &str) -> GateDecision {
        match self {
            Self::PolicyDenied { .. } => GateDecision::Refuse {
                cause: CAUSE_POLICY_DENIED.to_owned(),
                detail: format!("capability {capability:?} is not available on this machine"),
                recovery: RECOVERY_POLICY_DENIED.to_owned(),
            },
            Self::Allow => GateDecision::Allow {
                auto_granted: false,
            },
            Self::AutoGrant => GateDecision::Allow { auto_granted: true },
            Self::RequireApproval { reason, .. } => GateDecision::RequireApproval {
                reason: reason.clone(),
            },
            Self::NotGranted => GateDecision::Refuse {
                cause: CAUSE_NOT_GRANTED.to_owned(),
                detail: format!("capability {capability:?} has no active grant"),
                recovery: RECOVERY_NOT_GRANTED.to_owned(),
            },
        }
    }
}

/// The first half of the gate's decision, taken before any grant is read:
/// a never-grant rule refuses first, on every profile, grant or not
/// (control requests are the daemon's own bookkeeping, never work); a
/// read-only or control capability bypasses grants on every profile. `None`:
/// the grant decides ([`decide_with_grant`]).
#[must_use]
pub fn decide_before_grant(
    view: &PolicyView,
    capability: &str,
    class: CapabilityClass,
) -> Option<Verdict> {
    if class != CapabilityClass::Control
        && let Some(rule) = view.never_match(capability, Some(class))
    {
        return Some(Verdict::PolicyDenied { rule });
    }
    class.bypasses_lanes().then_some(Verdict::Allow)
}

/// The second half of the gate's decision: the profile and how the grant
/// stands. A grant that no longer covers what runs is never a pass and
/// never a plain refusal: the human sees the step as it is now and decides
/// again.
#[must_use]
pub fn decide_with_grant(
    profile: Profile,
    capability: &str,
    class: CapabilityClass,
    grant: &GrantStanding,
) -> Verdict {
    let granted = match grant {
        GrantStanding::Granted => true,
        GrantStanding::Missing => false,
        GrantStanding::Changed(changed) => {
            return Verdict::RequireApproval {
                reason: format!("{capability:?}: {changed}"),
                changed: Some(changed.clone()),
            };
        }
    };
    match (profile, granted, class) {
        // An active grant on relaxed means go; on standard it means go for
        // non-destructive work.
        (Profile::Relaxed, true, _)
        | (Profile::Standard, true, CapabilityClass::NonDestructive) => Verdict::Allow,
        // Relaxed auto-grants non-destructive capabilities on first use.
        (Profile::Relaxed, false, CapabilityClass::NonDestructive) => Verdict::AutoGrant,
        // Relaxed asks once per destructive/external capability; the
        // approval service records the grant on approval, so the next
        // evaluation takes the granted arm above.
        (Profile::Relaxed, false, _) => Verdict::RequireApproval {
            reason: format!(
                "capability {capability:?} needs a one-time approval \
                 under the relaxed profile"
            ),
            changed: None,
        },
        // Manual profiles refuse anything ungranted outright.
        (Profile::Standard | Profile::Strict, false, _) => Verdict::NotGranted,
        // Granted destructive/external work on standard — and any granted
        // non-read-only work on strict — needs a per-operation approval.
        (Profile::Standard | Profile::Strict, true, _) => Verdict::RequireApproval {
            reason: format!(
                "capability {capability:?} requires per-operation approval \
                 under the {} profile",
                profile.as_str()
            ),
            changed: None,
        },
    }
}

/// The whole decision for a caller that has the grant up front and
/// performs no side effects (`flow.inspect`).
#[must_use]
pub fn decide(
    view: &PolicyView,
    profile: Profile,
    capability: &str,
    class: CapabilityClass,
    grant: &GrantStanding,
) -> Verdict {
    decide_before_grant(view, capability, class)
        .unwrap_or_else(|| decide_with_grant(profile, capability, class, grant))
}

/// The lower-case name a [`CapabilityClass`] is recorded under in a grant's
/// binding (`grant.effect_class`).
#[must_use]
pub fn class_name(class: CapabilityClass) -> &'static str {
    match class {
        CapabilityClass::Control => "control",
        CapabilityClass::ReadOnly => "read_only",
        CapabilityClass::NonDestructive => "non_destructive",
        CapabilityClass::Destructive => "destructive",
        CapabilityClass::External => "external",
    }
}

/// GUI recovery line for [`CAUSE_UNKNOWN_CAPABILITY`] refusals.
const RECOVERY_UNKNOWN_CAPABILITY: &str = "Open the PAM GUI to see available capabilities.";

/// GUI recovery line for [`CAUSE_NOT_GRANTED`] refusals.
const RECOVERY_NOT_GRANTED: &str =
    "Grant this capability in the PAM GUI (Security > Capabilities).";

/// Recovery line for a capability the managed policy never allows. It says
/// nothing about the rule: an agent learns that, not why.
pub const RECOVERY_POLICY_DENIED: &str =
    "This capability is not available on this machine; ask your administrator.";

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
/// behind `pam cancel <ticket>`), `doctor.report` (the boundary self-check record, Control class:
/// a bookkeeping request that changes no authority — see [`crate::boundary`]), and the three flow
/// capabilities. The table is static by design —
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
        CAP_STATUS | CAP_CANCEL | CAP_QUERY | crate::boundary::CAP_DOCTOR_REPORT => {
            Some(CapabilityClass::Control)
        }
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
        /// [`CAUSE_NOT_GRANTED`], [`CAUSE_POLICY_DENIED`]).
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

/// Why [`PolicyGate::set_profile`] changed nothing.
#[derive(Debug, Error)]
pub enum SetProfileError {
    /// The managed policy refuses the profile: locked, more permissive than
    /// its floor, or held. `view` is the snapshot the check was made on, so
    /// the refusal's audit row names the policy that refused.
    #[error("{}", refusal.detail)]
    Policy {
        /// The policy's refusal (cause, detail, recovery).
        refusal: WriteRefusal,
        /// The policy in force when the change was checked.
        view: Arc<PolicyView>,
    },
    /// The setting could not be written.
    #[error(transparent)]
    Store(#[from] StoreError),
}

/// Whether the human may change the profile from `current` (the effective
/// profile now) to `requested` under `view`.
///
/// [`PolicyView::check_profile`], with one exception: while the key is held
/// — the policy cannot be read and its intent is unknown — a change that
/// only tightens (`requested` at least as strict as `current`) passes. A
/// held key reads the human's value, so tightening it can loosen nothing a
/// policy could have meant.
///
/// # Errors
///
/// The policy's refusal: `policy_frozen` for a held key and a request that
/// is not stricter, `setting_locked` for a locked one, `policy_not_allowed`
/// below the floor.
pub fn check_profile_write(
    view: &PolicyView,
    requested: Profile,
    current: Profile,
) -> Result<(), WriteRefusal> {
    if view.is_held(Key::SecurityProfile)
        && crate::managed_policy::stricter(requested, current) == requested
    {
        return Ok(());
    }
    view.check_profile(requested)
}

/// The profile the first boot persists: the managed policy's `default` when
/// one is in force, else [`Profile::platform_default`]. Only the first boot
/// reads it; a later change of the default never moves an existing install.
fn seed_profile(view: &PolicyView) -> Profile {
    let in_force = view
        .status(Key::SecurityProfile)
        .is_some_and(crate::managed_policy::LeafStatus::in_force);
    view.policy()
        .profile
        .as_ref()
        .filter(|_| in_force)
        .and_then(|leaf| leaf.default)
        .unwrap_or_else(Profile::platform_default)
}

/// The policy gate service. Constructed once from the store's persisted
/// profile; consulted by the request pipeline before every enqueue. It is
/// also the daemon's one live copy of the profile (see the module docs).
#[derive(Debug)]
pub struct PolicyGate {
    store: Arc<Store>,
    /// The human's stored profile: read on every evaluation (under the
    /// managed policy), written only by [`Self::set_profile`]. A sync lock:
    /// the critical section is one `Copy`, never held across an await.
    profile: RwLock<Profile>,
    /// The managed policy in force (see [`crate::managed_policy_service`]).
    policy: Arc<PolicyHandle>,
}

impl PolicyGate {
    /// Builds a gate from the profile persisted under
    /// [`PROFILE_SETTING_KEY`], falling back — and persisting it — when the
    /// setting is unset to the managed policy's `default` profile, or
    /// [`Profile::platform_default`] when the policy has none. Holds
    /// `policy`, the managed policy read at boot before the gate is built.
    pub async fn new(store: Arc<Store>, policy: Arc<PolicyHandle>) -> Result<Self, PolicyError> {
        let profile = if let Some(raw) = store.get_setting(PROFILE_SETTING_KEY).await? {
            serde_json::from_str(&raw)
                .map_err(|_| PolicyError::UnrecognizedProfile { value: raw })?
        } else {
            let profile = seed_profile(&policy.view());
            let raw = serde_json::to_string(&profile)
                .expect("a Profile always serializes to a JSON string");
            store.set_setting(PROFILE_SETTING_KEY, &raw).await?;
            profile
        };
        Ok(Self {
            store,
            profile: RwLock::new(profile),
            policy,
        })
    }

    /// The managed policy handle this gate reads through (see
    /// [`crate::managed_policy_service`]).
    #[must_use]
    pub fn policy(&self) -> &Arc<PolicyHandle> {
        &self.policy
    }

    /// The profile this gate enforces — the daemon's one source of truth:
    /// the human's stored choice under the managed policy in force (see the
    /// module docs).
    #[must_use]
    pub fn profile(&self) -> Profile {
        self.effective_profile().0
    }

    /// [`Self::profile`] with its `effective` entry (where the value came
    /// from, whether the human can change it, the floor), for
    /// `admin.profile.get`.
    #[must_use]
    pub fn effective_profile(&self) -> (Profile, EffectiveEntry) {
        self.policy
            .view()
            .effective_profile(Some(self.stored_profile()))
    }

    /// The human's stored choice, before the managed policy.
    #[must_use]
    pub fn stored_profile(&self) -> Profile {
        *self
            .profile
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Changes the human's profile: checks it against the managed policy
    /// ([`check_profile_write`]), persists it under [`PROFILE_SETTING_KEY`],
    /// then swaps the live value. Returns the stored profile it replaced.
    ///
    /// Persist first: a failed write leaves the live profile unchanged, so
    /// the daemon never enforces something a restart would not.
    ///
    /// # Errors
    ///
    /// [`SetProfileError::Policy`] when the managed policy refuses the
    /// value, [`SetProfileError::Store`] when the setting cannot be
    /// written; either way nothing changed.
    pub async fn set_profile(&self, profile: Profile) -> Result<Profile, SetProfileError> {
        // One snapshot for the check: a reload mid-op applies to the next.
        let view = self.policy.view();
        let current = view.effective_profile(Some(self.stored_profile())).0;
        if let Err(refusal) = check_profile_write(&view, profile, current) {
            return Err(SetProfileError::Policy { refusal, view });
        }
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
        Ok(self
            .evaluate_bound(request_id, capability, class, None)
            .await?
            .0)
    }

    /// [`Self::evaluate_classified`] for a flow step, against what it is
    /// about to run (`binding`; see the module docs). The second value is
    /// what changed since the step's grant was given, when a grant exists
    /// that no longer covers it — the decision is then
    /// [`GateDecision::RequireApproval`] on every profile, with that reason.
    /// An unbound legacy grant is bound to `binding` here, with an
    /// [`ACTION_GRANT_BOUND`] audit row, and authorizes as a bound one.
    ///
    /// Same contract as [`Self::evaluate`]: the request row exists.
    pub async fn evaluate_step(
        &self,
        request_id: &str,
        capability: &str,
        class: CapabilityClass,
        binding: &GrantBinding,
    ) -> Result<(GateDecision, Option<String>), StoreError> {
        self.evaluate_bound(request_id, capability, class, Some(binding))
            .await
    }

    /// Whether a flow step's grant covers `binding`, binding a legacy row
    /// on the way (see [`Self::evaluate_step`]). `Ok(Err(reason))` is a
    /// grant that no longer covers what runs.
    async fn step_granted(
        &self,
        request_id: &str,
        capability: &str,
        binding: &GrantBinding,
        profile: Profile,
    ) -> Result<Result<bool, String>, StoreError> {
        // A concurrent first use may bind the legacy row between the read
        // and the bind; the second read sees that binding.
        for _ in 0..2 {
            let rows = self.store.active_grants(capability).await?;
            match match_step_grant(&rows, binding) {
                StepGrant::Bound => return Ok(Ok(true)),
                StepGrant::Missing => return Ok(Ok(false)),
                StepGrant::Changed(reason) => return Ok(Err(reason)),
                StepGrant::Legacy(id) => {
                    let detail = serde_json::json!({
                        "capability": capability,
                        "grant_id": id,
                        "flow": binding.flow_id,
                        "step": binding.step_id,
                        "repository": binding.repository,
                        "effect_digest": binding.effect_digest,
                        "effect_class": binding.effect_class,
                        "profile": profile.as_str(),
                    })
                    .to_string();
                    let audit = AuditEntry {
                        action: ACTION_GRANT_BOUND,
                        decision: Decision::Allow,
                        actor: Actor::Policy,
                        detail: Some(&detail),
                    };
                    if self
                        .store
                        .bind_legacy_grant_audited(request_id, id, binding, audit)
                        .await?
                    {
                        return Ok(Ok(true));
                    }
                }
            }
        }
        Ok(Ok(false))
    }

    /// The one decision behind [`Self::evaluate_classified`] and
    /// [`Self::evaluate_step`].
    async fn evaluate_bound(
        &self,
        request_id: &str,
        capability: &str,
        class: CapabilityClass,
        binding: Option<&GrantBinding>,
    ) -> Result<(GateDecision, Option<String>), StoreError> {
        // One snapshot of the managed policy for the whole decision.
        let view = self.policy.view();
        match decide_before_grant(&view, capability, class) {
            Some(Verdict::PolicyDenied { rule }) => {
                return Ok((
                    self.deny_by_policy(request_id, capability, &rule, &view)
                        .await?,
                    None,
                ));
            }
            Some(verdict) => return Ok((verdict.decision(capability), None)),
            None => {}
        }
        // One read: the whole decision is made under the profile that was
        // live when it started.
        let profile = view.effective_profile(Some(self.stored_profile())).0;
        let grant = match binding {
            None => {
                if self.store.active_grant(capability).await? {
                    GrantStanding::Granted
                } else {
                    GrantStanding::Missing
                }
            }
            Some(binding) => match self
                .step_granted(request_id, capability, binding, profile)
                .await?
            {
                Ok(true) => GrantStanding::Granted,
                Ok(false) => GrantStanding::Missing,
                Err(changed) => GrantStanding::Changed(changed),
            },
        };
        let verdict = decide_with_grant(profile, capability, class, &grant);
        // The auto-grant mutation is audited right here (see the module
        // docs for the audit split).
        if verdict == Verdict::AutoGrant {
            self.auto_grant(request_id, capability, profile).await?;
        }
        let changed = match &verdict {
            Verdict::RequireApproval { changed, .. } => changed.clone(),
            _ => None,
        };
        Ok((verdict.decision(capability), changed))
    }

    /// The refusal for a capability a never-grant `rule` matches. The
    /// rule goes into the request's `policy.denied` audit row (the admin
    /// plane can read it); the refusal itself does not name it.
    async fn deny_by_policy(
        &self,
        request_id: &str,
        capability: &str,
        rule: &str,
        view: &PolicyView,
    ) -> Result<GateDecision, StoreError> {
        let detail = denied_detail(capability, rule, view).to_string();
        self.store
            .append_audit(
                request_id,
                ACTION_POLICY_DENIED,
                Decision::Refuse,
                Actor::Policy,
                Some(&detail),
            )
            .await?;
        Ok(Verdict::PolicyDenied {
            rule: rule.to_owned(),
        }
        .decision(capability))
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
