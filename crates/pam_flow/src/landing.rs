//! Typed landing stages; target authority belongs to GUI policy and frozen receipts.
use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::schema::RawStep;
use crate::{Action, Approval, Effect, FlowError, OutputPolicy, Retry, Role, Step, When};

/// One fixed landing operation. No operation accepts recipe-supplied commands or URLs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LandingOperation {
    /// Capture the exact repository, branch, commit and approved configuration.
    Freeze,
    /// Execute configured checks against the frozen source tree.
    Validate,
    /// Push only the frozen commit to the approved branch.
    Push,
    /// Create or reconcile the pull request for the frozen head and base.
    EnsurePr,
    /// Verify the exact pull-request checks and current head.
    VerifyPr,
    /// Merge the verified pull request under its distinct authorization.
    Merge,
    /// Verify checks for the confirmed resulting main commit.
    VerifyMain,
    /// Synchronize the local checkout only after confirmed merge verification.
    Sync,
}

impl LandingOperation {
    /// Mandatory order; a preview may end after any prefix of this sequence.
    pub const ORDER: [Self; 8] = [
        Self::Freeze,
        Self::Validate,
        Self::Push,
        Self::EnsurePr,
        Self::VerifyPr,
        Self::Merge,
        Self::VerifyMain,
        Self::Sync,
    ];

    /// Fixed policy classification; a recipe cannot downgrade a mutation.
    #[must_use]
    pub fn effect(self) -> Effect {
        match self {
            Self::Push | Self::EnsurePr | Self::Merge | Self::Sync => Effect::Stateful,
            Self::Freeze | Self::Validate | Self::VerifyPr | Self::VerifyMain => Effect::ReadOnly,
        }
    }

    /// Only operations that establish a verification receipt may use that role.
    #[must_use]
    pub fn allows_verify(self) -> bool {
        matches!(self, Self::Validate | Self::VerifyPr | Self::VerifyMain)
    }
}

fn invalid(at: &str, detail: &str) -> FlowError {
    FlowError::Invalid {
        path: at.to_owned(),
        message: detail.to_owned(),
    }
}

pub(crate) fn step(raw: RawStep, at: &str, earlier: &BTreeSet<String>) -> Result<Step, FlowError> {
    let operation = raw
        .landing
        .ok_or_else(|| invalid(at, "landing operation is missing"))?;
    if raw.run.is_some()
        || raw.connector.is_some()
        || raw.call.is_some()
        || raw.with.is_some()
        || raw.env.is_some()
        || raw.expect_empty_output.is_some()
        || raw.expect_status.is_some()
        || raw.watch.is_some()
        || raw.output.is_some_and(|p| p != OutputPolicy::Compact)
    {
        return Err(invalid(
            at,
            "landing accepts no command, connector arguments, environment, watch, expectation flags or non-compact output",
        ));
    }
    let effect = operation.effect();
    if raw.effect.is_some_and(|value| value != effect) {
        return Err(invalid(at, "landing effect is fixed by its operation"));
    }
    let role = raw.role.unwrap_or_else(|| Role::default_for(effect));
    if role == Role::Verify && !operation.allows_verify() {
        return Err(invalid(
            at,
            "only validate, verify_pr and verify_main may verify",
        ));
    }
    if crate::validate::validate_retry(raw.retry, at)? != Retry::default() {
        return Err(invalid(
            at,
            "landing retries are managed by the daemon; custom retries are forbidden",
        ));
    }
    let needs = raw.needs.unwrap_or_default();
    if needs.iter().any(|name| !earlier.contains(name)) {
        return Err(invalid(at, "landing dependencies must name earlier steps"));
    }
    Ok(Step {
        id: raw.id,
        action: Action::Landing { operation },
        timeout: crate::validate::validate_timeout(raw.timeout.as_deref(), at)?,
        effect,
        role,
        output: OutputPolicy::Compact,
        expect_empty_output: false,
        expect_status: None,
        needs,
        when: raw.when.unwrap_or_default(),
        retry: Retry::default(),
        watch: None,
        approval: if effect == Effect::Stateful {
            Approval::Required
        } else {
            raw.approval.unwrap_or_default()
        },
        env: std::collections::BTreeMap::default(),
        note: crate::validate::validate_note(raw.note.as_deref(), at)?,
    })
}

pub(crate) fn sequence(steps: &[Step], has_correlation: bool) -> Result<(), FlowError> {
    let mut previous: Option<&Step> = None;
    let mut count = 0;
    for (index, step) in steps.iter().enumerate() {
        let Action::Landing { operation } = step.action else {
            continue;
        };
        let at = format!("steps[{index}].landing");
        if !has_correlation {
            return Err(invalid(
                "correlation",
                "landing requires an explicit repository and full commit target",
            ));
        }
        if LandingOperation::ORDER.get(count) != Some(&operation) {
            return Err(invalid(
                &at,
                "landing operations must form a non-repeating prefix: freeze, validate, push, ensure_pr, verify_pr, merge, verify_main, sync",
            ));
        }
        let gated = match previous {
            None => {
                step.needs.is_empty() && matches!(step.when, When::Always | When::NeedsSucceeded)
            }
            Some(previous) => match &step.when {
                When::NeedsSucceeded => step.needs.contains(&previous.id),
                When::Succeeded(id) => {
                    id == &previous.id && step.needs.len() == 1 && step.needs[0] == previous.id
                }
                When::Always | When::Failed(_) => false,
            },
        };
        if !gated {
            return Err(invalid(
                &at,
                "landing must require successful completion of its direct predecessor; conditions cannot bypass dependencies",
            ));
        }
        previous = Some(step);
        count += 1;
    }
    Ok(())
}
