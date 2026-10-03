//! The intent a flow run journals before a step's effect.
//!
//! Before a step can change anything, the run writes down what it is about
//! to do, so a crash, a cancel or an expired lease afterwards reads as "this
//! may have happened" rather than "nothing happened". Two journals hold that
//! intent, and both are built from the one [`EffectIntent`] type:
//!
//! - the **flow journal** row every step attempt goes through
//!   (`crate::flow_recovery::Recovery::prepare`, then `arm_effect` once a
//!   gated step has passed its gate). Its operation is a [`StepAttempt`]:
//!   whether this attempt is journaled as effectful, and whether a stateful
//!   step is still waiting at its gate. A command step, a connector call and
//!   a landing operation all go through it;
//! - a landing session's document (`flow_service::landing_runtime`), whose
//!   operation is the typed [`pam_flow::LandingOperation`] and whose
//!   `expected` value is what the operation should leave behind (the ref it
//!   moves, the pull request it opens). Its serialized form is part of the
//!   persisted session (`{"step_id", "operation", "state", "expected"}`), and
//!   the store reads `state` back as `"prepared"` when boot recovery decides
//!   whether a landing may resume its read-only reconciliation.
//!
//! An intent is [`IntentState::Prepared`] until the effect's outcome is
//! known; a landing mutation the remote refused outright is settled
//! [`IntentState::Rejected`] (nothing happened, and the step blocks instead
//! of reading as an uncertain effect).

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::flow_recovery::Prepare;

/// Where an intent stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum IntentState {
    /// Journaled; the effect may or may not have happened yet.
    Prepared,
    /// The remote refused the mutation outright: nothing happened.
    Rejected,
}

/// The intent journaled before a step's effect (see the module docs). `O`
/// is what the step is about to do: a [`StepAttempt`] for the flow journal,
/// a landing operation for a landing session.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EffectIntent<O> {
    /// The step the intent belongs to.
    pub(crate) step_id: String,
    /// What it is about to do.
    pub(crate) operation: O,
    /// Where the intent stands.
    pub(crate) state: IntentState,
    /// What the effect should leave behind, when the journal records it
    /// (`null` for the flow journal).
    pub(crate) expected: Value,
}

impl<O: PartialEq> EffectIntent<O> {
    /// A freshly prepared intent.
    pub(crate) fn prepared(step_id: &str, operation: O, expected: Value) -> Self {
        Self {
            step_id: step_id.to_owned(),
            operation,
            state: IntentState::Prepared,
            expected,
        }
    }

    /// Whether this is `step_id`'s intent and it is still prepared: its
    /// effect may already exist.
    pub(crate) fn is_prepared_for(&self, step_id: &str) -> bool {
        self.step_id == step_id && self.state == IntentState::Prepared
    }

    /// Whether this is `step_id`'s prepared intent to do `operation`.
    pub(crate) fn is_prepared(&self, step_id: &str, operation: &O) -> bool {
        self.is_prepared_for(step_id) && self.operation == *operation
    }

    /// Settles the intent as refused outright, recording the cause.
    pub(crate) fn reject(&mut self, cause: &str) {
        self.state = IntentState::Rejected;
        self.expected["rejection"] = Value::from(cause);
    }
}

/// One attempt of a step, as the flow journal records it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct StepAttempt {
    /// Journaled as effectful: a stateful step that runs now, or one that
    /// has just passed its gate.
    pub(crate) effectful: bool,
    /// A stateful step journaled as not started while its scope check and
    /// approval are outstanding; `arm_effect` journals the effect itself.
    pub(crate) gating: bool,
}

impl EffectIntent<StepAttempt> {
    /// The intent journaled for `step` before its gate (see [`Prepare`]): a
    /// [`Prepare::Run`] of a stateful step is effectful, a [`Prepare::Gate`]
    /// is not until it is armed, and a [`Prepare::Skip`] never is, whatever
    /// the step declares.
    pub(crate) fn attempt(step: &pam_flow::Step, prepare: Prepare) -> Self {
        let stateful = step.effect == pam_flow::Effect::Stateful;
        Self::prepared(
            &step.id,
            StepAttempt {
                effectful: prepare == Prepare::Run && stateful,
                gating: prepare == Prepare::Gate && stateful,
            },
            Value::Null,
        )
    }

    /// The intent journaled once a gated step has passed its gate: the
    /// effect itself.
    pub(crate) fn armed(step: &pam_flow::Step) -> Self {
        Self::prepared(
            &step.id,
            StepAttempt {
                effectful: true,
                gating: false,
            },
            Value::Null,
        )
    }
}
