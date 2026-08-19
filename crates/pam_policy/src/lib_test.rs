use pam_core::{ApprovalId, CallerId, GrantId, ProjectId};

use super::{
    Approval, ApprovalRequirement, ApprovalState, ApprovalTransitionError, CapabilityName,
    Decision, Effect, EffectFingerprint, Grant, MAX_CAPABILITY_NAME_BYTES, MAX_RESOURCE_NAME_BYTES,
    ResourceName, ResourceScope, evaluate,
};

fn capability(value: &str) -> CapabilityName {
    CapabilityName::parse(value).expect("test capability must be valid")
}

fn resource(value: &str) -> ResourceName {
    ResourceName::parse(value).expect("test resource must be valid")
}

fn grant(effect: Effect, resource: ResourceScope, approval: ApprovalRequirement) -> Grant {
    Grant {
        id: GrantId::from("grant-1"),
        caller: CallerId::from("caller-1"),
        project: ProjectId::from("project-1"),
        capability: capability("shell.execute"),
        resource,
        effect,
        approval,
        expires_at_ms: None,
        revoked_at_ms: None,
    }
}

fn decision(grants: &[Grant], requested_resource: &ResourceName, now_ms: u64) -> Decision {
    evaluate(
        grants,
        &CallerId::from("caller-1"),
        &ProjectId::from("project-1"),
        &capability("shell.execute"),
        requested_resource,
        now_ms,
    )
}

fn requested_approval(expires_at_ms: u64) -> Approval {
    Approval::requested(
        ApprovalId::from("approval-1"),
        CallerId::from("caller-1"),
        ProjectId::from("project-1"),
        capability("shell.execute"),
        resource("workspace"),
        expires_at_ms,
    )
}

#[test]
fn explicit_deny_takes_precedence_over_allow() {
    let target = resource("workspace");
    let grants = [
        grant(
            Effect::Allow,
            ResourceScope::Exact(target.clone()),
            ApprovalRequirement::None,
        ),
        grant(
            Effect::Deny,
            ResourceScope::Exact(target.clone()),
            ApprovalRequirement::Once,
        ),
    ];

    assert_eq!(decision(&grants, &target, 100), Decision::Denied);
}

#[test]
fn no_matching_grant_denies_by_default() {
    assert_eq!(decision(&[], &resource("workspace"), 100), Decision::Denied);
}

#[test]
fn grants_are_isolated_by_caller_project_and_capability() {
    let target = resource("workspace");
    let allow = grant(
        Effect::Allow,
        ResourceScope::Exact(target.clone()),
        ApprovalRequirement::None,
    );

    assert_eq!(
        evaluate(
            std::slice::from_ref(&allow),
            &CallerId::from("other-caller"),
            &allow.project,
            &allow.capability,
            &target,
            100,
        ),
        Decision::Denied
    );
    assert_eq!(
        evaluate(
            std::slice::from_ref(&allow),
            &allow.caller,
            &ProjectId::from("other-project"),
            &allow.capability,
            &target,
            100,
        ),
        Decision::Denied
    );
    assert_eq!(
        evaluate(
            std::slice::from_ref(&allow),
            &allow.caller,
            &allow.project,
            &capability("filesystem.read"),
            &target,
            100,
        ),
        Decision::Denied
    );
}

#[test]
fn wildcard_and_exact_resources_match_only_their_intended_targets() {
    let exact_target = resource("workspace/src");
    let other_target = resource("workspace/docs");
    let exact = grant(
        Effect::Allow,
        ResourceScope::Exact(exact_target.clone()),
        ApprovalRequirement::None,
    );

    assert_eq!(
        decision(std::slice::from_ref(&exact), &exact_target, 100),
        Decision::Allowed
    );
    assert_eq!(
        decision(std::slice::from_ref(&exact), &other_target, 100),
        Decision::Denied
    );

    let wildcard = grant(Effect::Allow, ResourceScope::Any, ApprovalRequirement::None);
    assert_eq!(decision(&[wildcard], &other_target, 100), Decision::Allowed);
}

#[test]
fn expiry_and_revocation_are_inclusive_boundaries() {
    let target = resource("workspace");
    let mut expiring = grant(Effect::Allow, ResourceScope::Any, ApprovalRequirement::None);
    expiring.expires_at_ms = Some(100);

    assert_eq!(
        decision(std::slice::from_ref(&expiring), &target, 99),
        Decision::Allowed
    );
    assert_eq!(
        decision(std::slice::from_ref(&expiring), &target, 100),
        Decision::Denied
    );

    let mut revoking = expiring;
    revoking.expires_at_ms = None;
    revoking.revoked_at_ms = Some(100);
    assert_eq!(
        decision(std::slice::from_ref(&revoking), &target, 99),
        Decision::Allowed
    );
    assert_eq!(decision(&[revoking], &target, 100), Decision::Denied);
}

#[test]
fn approval_is_required_only_when_every_matching_allow_requires_it() {
    let target = resource("workspace");
    let approval_allow = grant(Effect::Allow, ResourceScope::Any, ApprovalRequirement::Once);
    assert_eq!(
        decision(std::slice::from_ref(&approval_allow), &target, 100),
        Decision::ApprovalRequired
    );

    let unconditional_allow = grant(Effect::Allow, ResourceScope::Any, ApprovalRequirement::None);
    assert_eq!(
        decision(&[approval_allow, unconditional_allow], &target, 100),
        Decision::Allowed
    );
}

#[test]
fn fingerprints_are_deterministic_and_length_prefixes_prevent_ambiguity() {
    let capability = capability("d");
    let resource = resource("e");
    let first = EffectFingerprint::compute(
        &CallerId::from("ab"),
        &ProjectId::from("c"),
        &capability,
        &resource,
    );
    let repeated = EffectFingerprint::compute(
        &CallerId::from("ab"),
        &ProjectId::from("c"),
        &capability,
        &resource,
    );
    let ambiguous_without_lengths = EffectFingerprint::compute(
        &CallerId::from("a"),
        &ProjectId::from("bc"),
        &capability,
        &resource,
    );

    assert_eq!(first, repeated);
    assert_ne!(first, ambiguous_without_lengths);
    assert_eq!(first.as_bytes().len(), 32);

    let debug = format!("{first:?}");
    assert!(debug.starts_with("EffectFingerprint(sha256:"));
    assert_eq!(debug.len(), "EffectFingerprint(sha256:)".len() + 64);
    assert!(debug.bytes().all(|byte| byte.is_ascii_graphic()));
}

#[test]
fn approval_is_bound_to_the_exact_effect_and_consumed_once() {
    let mut approval = requested_approval(200);
    let exact = *approval.fingerprint();
    let different = EffectFingerprint::compute(
        approval.caller(),
        approval.project(),
        approval.capability(),
        &resource("other-workspace"),
    );

    assert_eq!(approval.approve(100), Ok(ApprovalState::Approved));
    assert_eq!(
        approval.consume(&different, 101),
        Err(ApprovalTransitionError::FingerprintMismatch)
    );
    assert_eq!(approval.state(), ApprovalState::Approved);
    assert_eq!(approval.consume(&exact, 101), Ok(ApprovalState::Consumed));
    assert_eq!(
        approval.consume(&exact, 102),
        Err(ApprovalTransitionError::InvalidTransition)
    );
    assert_eq!(approval.state(), ApprovalState::Consumed);
}

#[test]
fn denied_approval_cannot_be_approved_or_consumed() {
    let mut approval = requested_approval(200);
    let fingerprint = *approval.fingerprint();

    assert_eq!(approval.deny(100), Ok(ApprovalState::Denied));
    assert_eq!(
        approval.approve(101),
        Err(ApprovalTransitionError::InvalidTransition)
    );
    assert_eq!(
        approval.consume(&fingerprint, 101),
        Err(ApprovalTransitionError::InvalidTransition)
    );
    assert_eq!(approval.state(), ApprovalState::Denied);
}

#[test]
fn approvals_expire_at_the_deadline_before_transition_or_consumption() {
    let mut requested = requested_approval(100);
    assert_eq!(requested.approve(100), Ok(ApprovalState::Expired));
    assert_eq!(requested.state(), ApprovalState::Expired);

    let mut approved = requested_approval(100);
    let fingerprint = *approved.fingerprint();
    assert_eq!(approved.approve(99), Ok(ApprovalState::Approved));
    assert_eq!(
        approved.consume(&fingerprint, 100),
        Ok(ApprovalState::Expired)
    );
    assert_eq!(approved.state(), ApprovalState::Expired);
}

#[test]
fn invalid_approval_transitions_do_not_mutate_state() {
    let mut approval = requested_approval(200);
    let fingerprint = *approval.fingerprint();

    assert_eq!(
        approval.consume(&fingerprint, 100),
        Err(ApprovalTransitionError::InvalidTransition)
    );
    assert_eq!(approval.state(), ApprovalState::Requested);

    assert_eq!(approval.approve(100), Ok(ApprovalState::Approved));
    assert_eq!(
        approval.deny(101),
        Err(ApprovalTransitionError::InvalidTransition)
    );
    assert_eq!(approval.state(), ApprovalState::Approved);
}

#[test]
fn capability_names_enforce_bounds_controls_and_utf8_byte_length() {
    assert!(CapabilityName::parse("").is_err());
    assert!(CapabilityName::parse("x").is_ok());
    assert!(CapabilityName::parse("x".repeat(MAX_CAPABILITY_NAME_BYTES)).is_ok());
    assert!(CapabilityName::parse("x".repeat(MAX_CAPABILITY_NAME_BYTES + 1)).is_err());
    assert!(CapabilityName::parse("shell\nexecute").is_err());
    assert!(CapabilityName::parse("shell\u{80}execute").is_err());
    assert!(CapabilityName::parse("é".repeat(MAX_CAPABILITY_NAME_BYTES / 2)).is_ok());
    assert!(CapabilityName::parse("é".repeat(MAX_CAPABILITY_NAME_BYTES / 2 + 1)).is_err());
}

#[test]
fn resource_names_enforce_bounds_controls_and_utf8_byte_length() {
    assert!(ResourceName::parse("").is_err());
    assert!(ResourceName::parse("x").is_ok());
    assert!(ResourceName::parse("x".repeat(MAX_RESOURCE_NAME_BYTES)).is_ok());
    assert!(ResourceName::parse("x".repeat(MAX_RESOURCE_NAME_BYTES + 1)).is_err());
    assert!(ResourceName::parse("workspace\0secret").is_err());
    assert!(ResourceName::parse("é".repeat(MAX_RESOURCE_NAME_BYTES / 2)).is_ok());
    assert!(ResourceName::parse("é".repeat(MAX_RESOURCE_NAME_BYTES / 2 + 1)).is_err());
}

#[test]
fn maximum_evidence_handle_and_range_fit_an_exact_resource_name() {
    let prefix = "evidence://ci/";
    let handle = format!("{prefix}{}", "a".repeat(512 - prefix.len()));
    let resource = format!("evidence:{handle}:offset={}:length={}", u64::MAX, u64::MAX);

    assert!(resource.len() < MAX_RESOURCE_NAME_BYTES);
    assert_eq!(ResourceName::parse(&resource).unwrap().as_str(), resource);
}

#[test]
fn validation_errors_never_echo_rejected_input() {
    let capability_secret = "secret-capability\n";
    let resource_secret = "secret-resource\0";
    let capability_error = CapabilityName::parse(capability_secret).expect_err("must fail");
    let resource_error = ResourceName::parse(resource_secret).expect_err("must fail");

    assert!(!capability_error.to_string().contains(capability_secret));
    assert!(!format!("{capability_error:?}").contains(capability_secret));
    assert!(!resource_error.to_string().contains(resource_secret));
    assert!(!format!("{resource_error:?}").contains(resource_secret));
    assert_eq!(
        resource_error.to_string(),
        "resource name must be 1 to 1024 UTF-8 bytes with no control characters"
    );
}
