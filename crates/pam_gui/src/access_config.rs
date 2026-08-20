use std::time::Duration;

use pam_core::{CallerCredential, CallerId, IdempotencyKey, ProjectId, RequestId};
use pam_daemon::request_exchange;
use pam_platform::LocalEndpoint;
use pam_protocol::{
    ConfigurationPresence, Failure, FailureCode, NetworkDiagnosticsResult, OperationTruth,
    PacState, RequestEnvelope, ResultBody, ResultPayload,
};
use uuid::Uuid;

const ACCESS_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum AccessConfigState {
    Available(AccessConfigView),
    Blocked {
        code: FailureCode,
        detail: String,
        recovery: Option<String>,
        approval_id: Option<String>,
        expires_at_ms: Option<u64>,
    },
    Unavailable {
        code: Option<FailureCode>,
        detail: String,
        recovery: Option<String>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AccessConfigView {
    pub(crate) truth: OperationTruth,
    pub(crate) platform_roots_enabled: bool,
    pub(crate) system_proxy_discovery_enabled: bool,
    pub(crate) proxy_environment: &'static str,
    pub(crate) no_proxy: &'static str,
    pub(crate) pac: &'static str,
}

pub(crate) async fn load_access_config(
    caller_id: CallerId,
    credential: CallerCredential,
    project_id: ProjectId,
) -> AccessConfigState {
    let suffix = Uuid::new_v4();
    let request = RequestEnvelope::network_diagnostics(
        RequestId::new(format!("gui-network-{suffix}")),
        caller_id,
        project_id,
        IdempotencyKey::new(format!("gui-network-{suffix}")),
    )
    .authenticated(credential);
    let exchange = match request_exchange(
        &LocalEndpoint::default_for_user(),
        &request,
        ACCESS_TIMEOUT,
    )
    .await
    {
        Ok(exchange) => exchange,
        Err(error) => {
            return AccessConfigState::Unavailable {
                code: None,
                detail: error.to_string(),
                recovery: error.recovery_action().map(str::to_owned),
            };
        }
    };
    if !exchange.events.is_empty() {
        return AccessConfigState::Unavailable {
            code: None,
            detail: "PAM returned events for a configuration read.".to_owned(),
            recovery: None,
        };
    }
    match exchange.result.body {
        ResultBody::Success {
            truth,
            payload: ResultPayload::NetworkDiagnostics(diagnostics),
        } => AccessConfigState::Available(map_diagnostics(truth, &diagnostics)),
        ResultBody::Failure(failure) => access_failure(failure),
        ResultBody::Success { .. } => AccessConfigState::Unavailable {
            code: None,
            detail: "PAM returned an unexpected configuration response.".to_owned(),
            recovery: None,
        },
    }
}

fn access_failure(failure: Failure) -> AccessConfigState {
    if matches!(
        failure.code,
        FailureCode::Forbidden | FailureCode::ApprovalRequired
    ) {
        let approval = failure.approval;
        AccessConfigState::Blocked {
            code: failure.code,
            detail: failure.message,
            recovery: failure.recovery,
            approval_id: approval
                .as_ref()
                .map(|challenge| challenge.approval_id.as_str().to_owned()),
            expires_at_ms: approval.map(|challenge| challenge.expires_at_unix_ms),
        }
    } else {
        AccessConfigState::Unavailable {
            code: Some(failure.code),
            detail: failure.message,
            recovery: failure.recovery,
        }
    }
}

fn map_diagnostics(
    truth: OperationTruth,
    diagnostics: &NetworkDiagnosticsResult,
) -> AccessConfigView {
    AccessConfigView {
        truth,
        platform_roots_enabled: diagnostics.platform_roots_enabled,
        system_proxy_discovery_enabled: diagnostics.system_proxy_discovery_enabled,
        proxy_environment: presence_label(diagnostics.proxy_environment_presence),
        no_proxy: presence_label(diagnostics.no_proxy_presence),
        pac: pac_label(diagnostics.pac_state),
    }
}

const fn presence_label(presence: ConfigurationPresence) -> &'static str {
    match presence {
        ConfigurationPresence::NotConfigured => "not configured",
        ConfigurationPresence::Configured => "configured",
        ConfigurationPresence::Invalid => "invalid",
    }
}

const fn pac_label(state: PacState) -> &'static str {
    match state {
        PacState::NotDetected => "not detected",
        PacState::DetectedUnsupported => "detected but unsupported",
        PacState::InspectionUnavailable => "inspection unavailable",
    }
}

#[cfg(test)]
pub(crate) fn map_diagnostics_for_test(
    truth: OperationTruth,
    diagnostics: &NetworkDiagnosticsResult,
) -> AccessConfigView {
    map_diagnostics(truth, diagnostics)
}

#[cfg(test)]
pub(crate) const fn access_copy_for_test() -> (&'static str, &'static str) {
    (
        "Policy gated / no ambient access",
        "Current model identity is not reported by protocol",
    )
}

#[cfg(test)]
pub(crate) fn access_failure_for_test(failure: Failure) -> AccessConfigState {
    access_failure(failure)
}
