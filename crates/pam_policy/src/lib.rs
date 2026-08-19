#![forbid(unsafe_code)]

use std::{error::Error, fmt};

use pam_core::{ApprovalId, CallerId, GrantId, ProjectId};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

mod redaction;

#[cfg(test)]
mod lib_test;
#[cfg(test)]
mod redaction_test;

pub use redaction::{
    MAX_AUDIT_DETAIL_INPUT_BYTES, MAX_AUDIT_DETAIL_OUTPUT_BYTES, REDACTION_MARKER,
    TRUNCATION_MARKER, redact_audit_detail,
};

pub const MAX_CAPABILITY_NAME_BYTES: usize = 128;
pub const MAX_RESOURCE_NAME_BYTES: usize = 512;

macro_rules! bounded_name {
    ($name:ident, $error:ident, $maximum:ident, $message:literal) => {
        #[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            /// Parses a nonempty name with no Unicode control characters.
            ///
            /// # Errors
            ///
            /// Returns an error when the value is empty, exceeds the byte limit, or
            /// contains a control character. The error never includes the rejected value.
            pub fn parse(value: impl Into<String>) -> Result<Self, $error> {
                let value = value.into();
                if value.is_empty() || value.len() > $maximum || value.chars().any(char::is_control)
                {
                    return Err($error);
                }
                Ok(Self(value))
            }

            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }

        impl TryFrom<String> for $name {
            type Error = $error;

            fn try_from(value: String) -> Result<Self, Self::Error> {
                Self::parse(value)
            }
        }

        impl From<$name> for String {
            fn from(value: $name) -> Self {
                value.0
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                let value = String::deserialize(deserializer)?;
                Self::parse(value).map_err(serde::de::Error::custom)
            }
        }

        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        pub struct $error;

        impl fmt::Display for $error {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str($message)
            }
        }

        impl Error for $error {}
    };
}

bounded_name!(
    CapabilityName,
    InvalidCapabilityName,
    MAX_CAPABILITY_NAME_BYTES,
    "capability name must be 1 to 128 UTF-8 bytes with no control characters"
);
bounded_name!(
    ResourceName,
    InvalidResourceName,
    MAX_RESOURCE_NAME_BYTES,
    "resource name must be 1 to 512 UTF-8 bytes with no control characters"
);

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum Effect {
    Allow,
    Deny,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum ResourceScope {
    Any,
    Exact(ResourceName),
}

impl ResourceScope {
    fn matches(&self, resource: &ResourceName) -> bool {
        match self {
            Self::Any => true,
            Self::Exact(expected) => expected == resource,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum ApprovalRequirement {
    None,
    Once,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Grant {
    pub id: GrantId,
    pub caller: CallerId,
    pub project: ProjectId,
    pub capability: CapabilityName,
    pub resource: ResourceScope,
    pub effect: Effect,
    pub approval: ApprovalRequirement,
    pub expires_at_ms: Option<u64>,
    pub revoked_at_ms: Option<u64>,
}

impl Grant {
    fn is_active_at(&self, now_ms: u64) -> bool {
        self.expires_at_ms.is_none_or(|expiry| now_ms < expiry)
            && self
                .revoked_at_ms
                .is_none_or(|revocation| now_ms < revocation)
    }

    fn matches(
        &self,
        caller: &CallerId,
        project: &ProjectId,
        capability: &CapabilityName,
        resource: &ResourceName,
        now_ms: u64,
    ) -> bool {
        self.is_active_at(now_ms)
            && self.caller == *caller
            && self.project == *project
            && self.capability == *capability
            && self.resource.matches(resource)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Decision {
    Allowed,
    Denied,
    ApprovalRequired,
}

/// Evaluates active grants using deny-overrides semantics.
#[must_use]
pub fn evaluate(
    grants: &[Grant],
    caller: &CallerId,
    project: &ProjectId,
    capability: &CapabilityName,
    resource: &ResourceName,
    now_ms: u64,
) -> Decision {
    let mut found_allow = false;
    let mut found_unconditional_allow = false;

    for grant in grants
        .iter()
        .filter(|grant| grant.matches(caller, project, capability, resource, now_ms))
    {
        match grant.effect {
            Effect::Deny => return Decision::Denied,
            Effect::Allow => {
                found_allow = true;
                found_unconditional_allow |= grant.approval == ApprovalRequirement::None;
            }
        }
    }

    if found_unconditional_allow {
        Decision::Allowed
    } else if found_allow {
        Decision::ApprovalRequired
    } else {
        Decision::Denied
    }
}

/// A SHA-256 digest that binds an approval to one exact effect.
#[derive(Clone, Copy, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(transparent)]
pub struct EffectFingerprint([u8; 32]);

impl EffectFingerprint {
    #[must_use]
    pub fn compute(
        caller: &CallerId,
        project: &ProjectId,
        capability: &CapabilityName,
        resource: &ResourceName,
    ) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(b"pam-effect-fingerprint-v1\0");
        update_length_prefixed(&mut hasher, caller.as_str());
        update_length_prefixed(&mut hasher, project.as_str());
        update_length_prefixed(&mut hasher, capability.as_str());
        update_length_prefixed(&mut hasher, resource.as_str());
        Self(hasher.finalize().into())
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for EffectFingerprint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        use fmt::Write as _;

        formatter.write_str("EffectFingerprint(sha256:")?;
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        formatter.write_char(')')
    }
}

fn update_length_prefixed(hasher: &mut Sha256, value: &str) {
    let length = u64::try_from(value.len()).expect("a String cannot exceed u64::MAX bytes");
    hasher.update(length.to_be_bytes());
    hasher.update(value.as_bytes());
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum ApprovalState {
    Requested,
    Approved,
    Denied,
    Consumed,
    Expired,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ApprovalTransitionError {
    InvalidTransition,
    FingerprintMismatch,
}

impl fmt::Display for ApprovalTransitionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidTransition => formatter.write_str("invalid approval state transition"),
            Self::FingerprintMismatch => {
                formatter.write_str("approval fingerprint does not match the requested effect")
            }
        }
    }
}

impl Error for ApprovalTransitionError {}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Approval {
    id: ApprovalId,
    caller: CallerId,
    project: ProjectId,
    capability: CapabilityName,
    resource: ResourceName,
    fingerprint: EffectFingerprint,
    expires_at_ms: u64,
    state: ApprovalState,
}

impl Approval {
    #[must_use]
    pub fn requested(
        id: ApprovalId,
        caller: CallerId,
        project: ProjectId,
        capability: CapabilityName,
        resource: ResourceName,
        expires_at_ms: u64,
    ) -> Self {
        let fingerprint = EffectFingerprint::compute(&caller, &project, &capability, &resource);
        Self {
            id,
            caller,
            project,
            capability,
            resource,
            fingerprint,
            expires_at_ms,
            state: ApprovalState::Requested,
        }
    }

    #[must_use]
    pub fn id(&self) -> &ApprovalId {
        &self.id
    }

    #[must_use]
    pub fn caller(&self) -> &CallerId {
        &self.caller
    }

    #[must_use]
    pub fn project(&self) -> &ProjectId {
        &self.project
    }

    #[must_use]
    pub fn capability(&self) -> &CapabilityName {
        &self.capability
    }

    #[must_use]
    pub fn resource(&self) -> &ResourceName {
        &self.resource
    }

    #[must_use]
    pub const fn fingerprint(&self) -> &EffectFingerprint {
        &self.fingerprint
    }

    #[must_use]
    pub const fn expires_at_ms(&self) -> u64 {
        self.expires_at_ms
    }

    #[must_use]
    pub const fn state(&self) -> ApprovalState {
        self.state
    }

    /// Approves a pending request, or expires it when its deadline has passed.
    ///
    /// # Errors
    ///
    /// Returns [`ApprovalTransitionError::InvalidTransition`] unless the current
    /// state is [`ApprovalState::Requested`]. Errors leave the approval unchanged.
    pub fn approve(&mut self, now_ms: u64) -> Result<ApprovalState, ApprovalTransitionError> {
        if self.expire_if_due(now_ms) {
            return Ok(ApprovalState::Expired);
        }
        if self.state != ApprovalState::Requested {
            return Err(ApprovalTransitionError::InvalidTransition);
        }
        self.state = ApprovalState::Approved;
        Ok(self.state)
    }

    /// Denies a pending request, or expires it when its deadline has passed.
    ///
    /// # Errors
    ///
    /// Returns [`ApprovalTransitionError::InvalidTransition`] unless the current
    /// state is [`ApprovalState::Requested`]. Errors leave the approval unchanged.
    pub fn deny(&mut self, now_ms: u64) -> Result<ApprovalState, ApprovalTransitionError> {
        if self.expire_if_due(now_ms) {
            return Ok(ApprovalState::Expired);
        }
        if self.state != ApprovalState::Requested {
            return Err(ApprovalTransitionError::InvalidTransition);
        }
        self.state = ApprovalState::Denied;
        Ok(self.state)
    }

    /// Consumes an approved request for the exact fingerprint once.
    ///
    /// # Errors
    ///
    /// Returns [`ApprovalTransitionError::InvalidTransition`] unless the current
    /// state is [`ApprovalState::Approved`], or
    /// [`ApprovalTransitionError::FingerprintMismatch`] when the effect differs.
    /// Errors leave the approval unchanged.
    pub fn consume(
        &mut self,
        fingerprint: &EffectFingerprint,
        now_ms: u64,
    ) -> Result<ApprovalState, ApprovalTransitionError> {
        if self.expire_if_due(now_ms) {
            return Ok(ApprovalState::Expired);
        }
        if self.state != ApprovalState::Approved {
            return Err(ApprovalTransitionError::InvalidTransition);
        }
        if self.fingerprint != *fingerprint {
            return Err(ApprovalTransitionError::FingerprintMismatch);
        }
        self.state = ApprovalState::Consumed;
        Ok(self.state)
    }

    fn expire_if_due(&mut self, now_ms: u64) -> bool {
        if matches!(
            self.state,
            ApprovalState::Requested | ApprovalState::Approved
        ) && now_ms >= self.expires_at_ms
        {
            self.state = ApprovalState::Expired;
            true
        } else {
            false
        }
    }
}
