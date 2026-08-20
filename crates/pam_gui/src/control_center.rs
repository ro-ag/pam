use std::{path::Path, time::Duration};

#[cfg(test)]
use std::{collections::HashSet, path::PathBuf};

use pam_core::{CallerCredential, CallerId, IdempotencyKey, ProjectId, RequestId};
use pam_daemon::{ExchangeError, request_exchange, request_status};
use pam_platform::{LocalEndpoint, NativeSecretBackend, SecretLocator, SecretStore};
use pam_protocol::{RequestEnvelope, ResultBody, ResultPayload, StatusResult};
use uuid::Uuid;

use crate::{
    access_config::{AccessConfigState, load_access_config},
    current::{CurrentState, load_current},
};

const HEALTH_TIMEOUT: Duration = Duration::from_secs(2);
pub(crate) const MAX_PROJECTS: usize = 64;

#[cfg(test)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ProjectEntry {
    pub(crate) name: String,
    pub(crate) root: PathBuf,
    pub(crate) id: Option<ProjectId>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum HealthState {
    Healthy {
        daemon_version: String,
        queue_depth: u64,
    },
    Offline,
    Degraded {
        detail: String,
        recovery: Option<String>,
    },
}

#[cfg(test)]
impl HealthState {
    #[must_use]
    pub(crate) const fn can_start(&self) -> bool {
        matches!(self, Self::Offline)
    }

    #[must_use]
    pub(crate) const fn can_stop(&self) -> bool {
        matches!(self, Self::Healthy { .. })
    }
}

pub(crate) async fn load_project_surfaces(
    caller_id: CallerId,
    credential: CallerCredential,
    project_id: ProjectId,
) -> (HealthState, CurrentState, AccessConfigState) {
    tokio::join!(
        probe_health_authenticated(caller_id.clone(), credential.clone(), project_id.clone(),),
        load_current(caller_id.clone(), credential.clone(), project_id.clone(),),
        load_access_config(caller_id, credential, project_id),
    )
}

pub(crate) async fn load_credential(caller_id: CallerId) -> Result<CallerCredential, String> {
    tokio::task::spawn_blocking(move || {
        let locator = SecretLocator::for_caller(&caller_id).map_err(|error| error.to_string())?;
        let backend = NativeSecretBackend::new().map_err(|error| error.to_string())?;
        SecretStore::new(backend)
            .get(&locator)
            .map_err(|error| error.to_string())
    })
    .await
    .map_err(|_| "PAM could not access the native credential worker.".to_owned())?
}

pub(crate) async fn request_daemon_stop_authenticated(
    caller_id: CallerId,
    credential: CallerCredential,
    project_id: ProjectId,
) -> Result<(), String> {
    let suffix = Uuid::new_v4();
    let request = RequestEnvelope::stop(
        RequestId::new(format!("gui-stop-{suffix}")),
        caller_id.clone(),
        project_id.clone(),
        IdempotencyKey::new(format!("gui-stop-{suffix}")),
    )
    .authenticated(credential.clone());
    let exchange = request_exchange(&LocalEndpoint::default_for_user(), &request, HEALTH_TIMEOUT)
        .await
        .map_err(|error| error.to_string())?;
    match exchange.result.body {
        ResultBody::Success {
            payload: ResultPayload::DaemonLifecycle(result),
            ..
        } if result.stopping => {}
        ResultBody::Failure(failure) => {
            return Err(failure
                .recovery
                .map_or(failure.message.clone(), |recovery| {
                    format!("{} Recovery: {recovery}", failure.message)
                }));
        }
        ResultBody::Success { .. } => {
            return Err("PAM daemon returned an unexpected stop response.".to_owned());
        }
    }

    for _ in 0..20 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        if matches!(
            probe_health_authenticated(caller_id.clone(), credential.clone(), project_id.clone(),)
                .await,
            HealthState::Offline
        ) {
            return Ok(());
        }
    }
    Err("PAM acknowledged stop but did not become unavailable before the deadline.".to_owned())
}

#[cfg(test)]
pub(crate) fn merge_projects(
    current: ProjectEntry,
    candidates: impl IntoIterator<Item = ProjectEntry>,
) -> Vec<ProjectEntry> {
    let current_root = current.root.clone();
    let mut roots = HashSet::from([current_root.clone()]);
    let mut projects = vec![current];
    for mut candidate in candidates.into_iter().take(MAX_PROJECTS.saturating_sub(1)) {
        if roots.insert(candidate.root.clone()) {
            if candidate.root == current_root {
                candidate.id.clone_from(&projects[0].id);
                projects[0] = candidate;
            } else {
                projects.push(candidate);
            }
        }
    }
    projects.sort_by(|left, right| {
        right
            .id
            .is_some()
            .cmp(&left.id.is_some())
            .then_with(|| left.name.cmp(&right.name))
            .then_with(|| left.root.cmp(&right.root))
    });
    projects
}

async fn probe_health_authenticated(
    caller_id: CallerId,
    credential: CallerCredential,
    project_id: ProjectId,
) -> HealthState {
    let endpoint = LocalEndpoint::default_for_user();
    let suffix = Uuid::new_v4();
    let request = RequestEnvelope::status(
        RequestId::new(format!("gui-status-{suffix}")),
        caller_id,
        project_id,
        IdempotencyKey::new(format!("gui-status-{suffix}")),
    )
    .authenticated(credential);

    match request_status(&endpoint, &request, HEALTH_TIMEOUT).await {
        Ok(exchange) => health_from_result(exchange.result.body),
        Err(error) => health_from_exchange_error(&error),
    }
}

fn health_from_result(body: ResultBody) -> HealthState {
    match body {
        ResultBody::Success {
            payload: ResultPayload::Status(status),
            ..
        } => health_from_status(status),
        ResultBody::Failure(failure) => HealthState::Degraded {
            detail: failure.message,
            recovery: failure.recovery,
        },
        ResultBody::Success { .. } => HealthState::Degraded {
            detail: "PAM daemon returned an unexpected health response.".to_owned(),
            recovery: None,
        },
    }
}

fn health_from_status(status: StatusResult) -> HealthState {
    if status.ready && status.healthy {
        HealthState::Healthy {
            daemon_version: status.daemon_version,
            queue_depth: status.queue_depth,
        }
    } else {
        HealthState::Degraded {
            detail: "PAM daemon is running but not ready.".to_owned(),
            recovery: Some("Review daemon diagnostics and retry health.".to_owned()),
        }
    }
}

fn health_from_exchange_error(error: &ExchangeError) -> HealthState {
    if error.is_unavailable() {
        HealthState::Offline
    } else {
        HealthState::Degraded {
            detail: error.to_string(),
            recovery: error.recovery_action().map(str::to_owned),
        }
    }
}

pub(crate) fn bounded_name(name: &str, root: &Path) -> String {
    let name = name.trim();
    if name.is_empty() || name.len() > 256 {
        project_name(root)
    } else {
        name.to_owned()
    }
}

pub(crate) fn project_name(root: &Path) -> String {
    root.file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty())
        .unwrap_or("Project")
        .to_owned()
}

#[cfg(test)]
pub(crate) fn classify_status(status: StatusResult) -> HealthState {
    health_from_status(status)
}

#[cfg(test)]
pub(crate) fn merge_test_projects(
    current: ProjectEntry,
    candidates: Vec<ProjectEntry>,
) -> Vec<ProjectEntry> {
    merge_projects(current, candidates)
}
