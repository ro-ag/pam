use std::time::Duration;

use pam_core::{CallerCredential, CallerId, ProjectId};
use pam_daemon::request_exchange;
use pam_platform::LocalEndpoint;
use pam_protocol::{
    ActivityResult, CallerListResult, Failure, FailureCode, RequestEnvelope, ResultBody,
    ResultPayload,
};

use crate::current::{unique_idempotency, unique_request_id};

const OBSERVATORY_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum ObservatoryState<T> {
    Available(T),
    Blocked {
        code: FailureCode,
        detail: String,
        recovery: Option<String>,
    },
    Unavailable {
        code: Option<String>,
        detail: String,
        recovery: Option<String>,
    },
}

pub(crate) async fn load_daemon_activity(
    caller_id: CallerId,
    credential: CallerCredential,
    project_id: ProjectId,
    limit: u32,
) -> ObservatoryState<ActivityResult> {
    let request = RequestEnvelope::daemon_activity(
        unique_request_id("gui-daemon-activity"),
        caller_id,
        project_id,
        unique_idempotency("gui-daemon-activity"),
        limit,
    )
    .authenticated(credential);
    load(request, "daemon-activity", |payload| match payload {
        ResultPayload::DaemonActivity(result) => Some(result),
        _ => None,
    })
    .await
}

pub(crate) async fn load_caller_registry(
    caller_id: CallerId,
    credential: CallerCredential,
    project_id: ProjectId,
) -> ObservatoryState<CallerListResult> {
    let request = RequestEnvelope::caller_list(
        unique_request_id("gui-caller-registry"),
        caller_id,
        project_id,
        unique_idempotency("gui-caller-registry"),
    )
    .authenticated(credential);
    load(request, "caller-registry", |payload| match payload {
        ResultPayload::CallerList(result) => Some(result),
        _ => None,
    })
    .await
}

async fn load<T>(
    request: RequestEnvelope,
    surface: &str,
    extract: fn(ResultPayload) -> Option<T>,
) -> ObservatoryState<T> {
    let exchange = match request_exchange(
        &LocalEndpoint::default_for_user(),
        &request,
        OBSERVATORY_TIMEOUT,
    )
    .await
    {
        Ok(exchange) => exchange,
        Err(error) => {
            return unavailable(
                error.to_string(),
                error.recovery_action().map(str::to_owned),
            );
        }
    };
    if !exchange.events.is_empty() {
        return unavailable(format!("PAM returned events for a {surface} read."), None);
    }
    match exchange.result.body {
        ResultBody::Success { payload, .. } => match extract(payload) {
            Some(result) => ObservatoryState::Available(result),
            None => unavailable(
                format!("PAM returned an unexpected {surface} response."),
                None,
            ),
        },
        ResultBody::Failure(failure) => failure_state(failure),
    }
}

fn unavailable<T>(detail: String, recovery: Option<String>) -> ObservatoryState<T> {
    ObservatoryState::Unavailable {
        code: None,
        detail,
        recovery,
    }
}

/// Both observatory capabilities are baseline reads: an explicit policy deny
/// (or an unexpected approval demand) is blocked; everything else, including
/// an offline daemon, is unavailable.
fn failure_state<T>(failure: Failure) -> ObservatoryState<T> {
    if matches!(
        failure.code,
        FailureCode::Forbidden | FailureCode::ApprovalRequired
    ) {
        ObservatoryState::Blocked {
            code: failure.code,
            detail: failure.message,
            recovery: failure.recovery,
        }
    } else {
        ObservatoryState::Unavailable {
            code: None,
            detail: failure.message,
            recovery: failure.recovery,
        }
    }
}

#[cfg(test)]
pub(crate) fn failure_state_for_test<T>(failure: Failure) -> ObservatoryState<T> {
    failure_state(failure)
}
