use pam_core::{
    ApprovalId, CallerCredential, CallerId, EvidenceHandle, IdempotencyKey, ProjectId, RequestId,
};
use pam_platform::{
    CallerKind, IdentityError, NativeSecretBackend, ProjectIdentity, SecretLocator, SecretStore,
    SecretStoreError, SecretStoreErrorKind, caller_id, discover_project,
};
use pam_protocol::{ExpectedTargetKind, ModelMessage, ProtocolContractError, RequestEnvelope};
use std::{error::Error, fmt, path::Path};
use uuid::Uuid;

#[derive(Clone, Debug)]
pub(crate) struct RequestContext {
    caller_id: CallerId,
    project_id: ProjectId,
    credential: CallerCredential,
    approval_id: Option<ApprovalId>,
}

impl RequestContext {
    pub(crate) async fn discover(
        approval_id: Option<ApprovalId>,
    ) -> Result<Self, RequestContextError> {
        let project = discover_project(".").map_err(RequestContextError::Identity)?;
        Self::discover_for_project(&project, approval_id).await
    }

    pub(crate) async fn discover_for_project(
        project: &ProjectIdentity,
        approval_id: Option<ApprovalId>,
    ) -> Result<Self, RequestContextError> {
        let caller_id = caller_id(CallerKind::Cli).map_err(RequestContextError::Identity)?;
        let credential = load_native_credential(caller_id.clone()).await?;
        Ok(Self {
            caller_id,
            project_id: project.id().clone(),
            credential,
            approval_id,
        })
    }

    #[cfg(test)]
    pub(crate) fn new(
        caller_id: CallerId,
        project_id: ProjectId,
        approval_id: Option<ApprovalId>,
    ) -> Self {
        Self {
            caller_id,
            project_id,
            credential: CallerCredential::new("test-caller-credential"),
            approval_id,
        }
    }

    #[cfg(test)]
    pub(crate) fn new_for_project(
        caller_id: CallerId,
        project: &ProjectIdentity,
        approval_id: Option<ApprovalId>,
    ) -> Self {
        Self::new(caller_id, project.id().clone(), approval_id)
    }

    pub(crate) fn status(&self) -> RequestEnvelope {
        let (request_id, idempotency_key) = operation_ids("status");
        self.authenticate(RequestEnvelope::status(
            request_id,
            self.caller_id.clone(),
            self.project_id.clone(),
            idempotency_key,
        ))
    }

    pub(crate) fn brief(&self) -> RequestEnvelope {
        let (request_id, idempotency_key) = operation_ids("brief");
        self.authenticate(RequestEnvelope::brief(
            request_id,
            self.caller_id.clone(),
            self.project_id.clone(),
            idempotency_key,
        ))
    }

    pub(crate) fn network_diagnostics(&self) -> RequestEnvelope {
        let (request_id, idempotency_key) = operation_ids("network-diagnostics");
        self.authenticate(RequestEnvelope::network_diagnostics(
            request_id,
            self.caller_id.clone(),
            self.project_id.clone(),
            idempotency_key,
        ))
    }

    pub(crate) fn model_infer(
        &self,
        model: String,
        messages: Vec<ModelMessage>,
        max_output_tokens: u32,
        deadline_unix_ms: u64,
    ) -> Result<RequestEnvelope, ProtocolContractError> {
        let (request_id, idempotency_key) = operation_ids("model-infer");
        RequestEnvelope::model_infer(
            request_id,
            self.caller_id.clone(),
            self.project_id.clone(),
            idempotency_key,
            model,
            messages,
            max_output_tokens,
            deadline_unix_ms,
        )
        .map(|request| self.authenticate(request))
    }

    pub(crate) fn wait(&self, target_request_id: RequestId, after: u64) -> RequestEnvelope {
        let (request_id, idempotency_key) = operation_ids("wait");
        self.authenticate(RequestEnvelope::wait_for_result(
            request_id,
            self.caller_id.clone(),
            self.project_id.clone(),
            idempotency_key,
            target_request_id,
            after,
        ))
    }

    pub(crate) fn result(&self, target_request_id: RequestId) -> RequestEnvelope {
        let (request_id, idempotency_key) = operation_ids("result");
        self.authenticate(RequestEnvelope::get_result(
            request_id,
            self.caller_id.clone(),
            self.project_id.clone(),
            idempotency_key,
            target_request_id,
        ))
    }

    pub(crate) fn flow_run(
        &self,
        definition: String,
        run_id: Option<RequestId>,
        idempotency_key: Option<IdempotencyKey>,
        project_root: &Path,
    ) -> Result<RequestEnvelope, ProtocolContractError> {
        let run_id =
            run_id.unwrap_or_else(|| RequestId::new(format!("flow-run-{}", Uuid::new_v4())));
        let idempotency_key =
            idempotency_key.unwrap_or_else(|| IdempotencyKey::new(format!("flow-run:{run_id}")));
        RequestEnvelope::flow_run(
            run_id,
            self.caller_id.clone(),
            self.project_id.clone(),
            idempotency_key,
            definition,
            project_root.to_str().unwrap_or_default(),
        )
        .map(|request| self.authenticate(request))
    }

    pub(crate) fn flow_cancel(&self, run_id: RequestId) -> RequestEnvelope {
        let (request_id, idempotency_key) = operation_ids("flow-cancel");
        self.authenticate(RequestEnvelope::cancel_with_expected_target(
            request_id,
            self.caller_id.clone(),
            self.project_id.clone(),
            idempotency_key,
            run_id,
            ExpectedTargetKind::FlowRun,
        ))
    }

    pub(crate) fn flow_logs(&self, run_id: RequestId, after: u64) -> RequestEnvelope {
        let (request_id, idempotency_key) = operation_ids("flow-logs");
        self.authenticate(RequestEnvelope::replay_with_expected_target(
            request_id,
            self.caller_id.clone(),
            self.project_id.clone(),
            idempotency_key,
            run_id,
            after,
            ExpectedTargetKind::FlowRun,
        ))
    }

    pub(crate) fn flow_wait(&self, run_id: RequestId, after: u64) -> RequestEnvelope {
        let (request_id, idempotency_key) = operation_ids("flow-wait");
        self.authenticate(RequestEnvelope::wait_for_result_with_expected_target(
            request_id,
            self.caller_id.clone(),
            self.project_id.clone(),
            idempotency_key,
            run_id,
            after,
            ExpectedTargetKind::FlowRun,
        ))
    }

    pub(crate) fn flow_result(&self, run_id: RequestId) -> RequestEnvelope {
        let (request_id, idempotency_key) = operation_ids("flow-result");
        self.authenticate(RequestEnvelope::get_result_with_expected_target(
            request_id,
            self.caller_id.clone(),
            self.project_id.clone(),
            idempotency_key,
            run_id,
            ExpectedTargetKind::FlowRun,
        ))
    }

    pub(crate) fn inspect_evidence(&self, handle: EvidenceHandle) -> RequestEnvelope {
        let (request_id, idempotency_key) = operation_ids("evidence-inspect");
        RequestEnvelope::inspect_evidence(
            request_id,
            self.caller_id.clone(),
            self.project_id.clone(),
            idempotency_key,
            handle,
        )
        .authenticated(self.credential.clone())
    }

    pub(crate) fn read_evidence(
        &self,
        handle: EvidenceHandle,
        offset: u64,
        length: u64,
    ) -> Result<RequestEnvelope, ProtocolContractError> {
        let (request_id, idempotency_key) = operation_ids("evidence-read");
        RequestEnvelope::read_evidence(
            request_id,
            self.caller_id.clone(),
            self.project_id.clone(),
            idempotency_key,
            handle,
            offset,
            length,
        )
        .map(|request| request.authenticated(self.credential.clone()))
    }

    fn authenticate(&self, request: RequestEnvelope) -> RequestEnvelope {
        let request = request.authenticated(self.credential.clone());
        match &self.approval_id {
            Some(approval_id) => request.with_approval(approval_id.clone()),
            None => request,
        }
    }
}

#[derive(Debug)]
pub(crate) enum NativeCredentialError {
    Store(SecretStoreError),
    WorkerUnavailable,
}

impl NativeCredentialError {
    pub(crate) fn is_not_found(&self) -> bool {
        matches!(
            self,
            Self::Store(error) if error.kind() == SecretStoreErrorKind::NotFound
        )
    }
}

impl fmt::Display for NativeCredentialError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Store(error) => error.fmt(formatter),
            Self::WorkerUnavailable => {
                formatter.write_str("PAM could not access the native credential worker.")
            }
        }
    }
}

impl Error for NativeCredentialError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Store(error) => Some(error),
            Self::WorkerUnavailable => None,
        }
    }
}

#[derive(Debug)]
pub(crate) enum RequestContextError {
    Identity(IdentityError),
    Credential(NativeCredentialError),
}

impl fmt::Display for RequestContextError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Identity(error) => error.fmt(formatter),
            Self::Credential(error) => error.fmt(formatter),
        }
    }
}

impl Error for RequestContextError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Identity(error) => Some(error),
            Self::Credential(error) => Some(error),
        }
    }
}

impl From<NativeCredentialError> for RequestContextError {
    fn from(error: NativeCredentialError) -> Self {
        Self::Credential(error)
    }
}

pub(crate) async fn load_native_credential(
    caller_id: CallerId,
) -> Result<CallerCredential, NativeCredentialError> {
    tokio::task::spawn_blocking(move || {
        let locator =
            SecretLocator::for_caller(&caller_id).map_err(NativeCredentialError::Store)?;
        let backend = NativeSecretBackend::new()
            .map_err(SecretStoreError::from)
            .map_err(NativeCredentialError::Store)?;
        SecretStore::new(backend)
            .get(&locator)
            .map_err(NativeCredentialError::Store)
    })
    .await
    .map_err(|_| NativeCredentialError::WorkerUnavailable)?
}

pub(crate) async fn store_native_credential(
    caller_id: CallerId,
    credential: CallerCredential,
) -> Result<(), NativeCredentialError> {
    tokio::task::spawn_blocking(move || {
        let locator =
            SecretLocator::for_caller(&caller_id).map_err(NativeCredentialError::Store)?;
        let backend = NativeSecretBackend::new()
            .map_err(SecretStoreError::from)
            .map_err(NativeCredentialError::Store)?;
        SecretStore::new(backend)
            .set(&locator, &credential)
            .map_err(NativeCredentialError::Store)
    })
    .await
    .map_err(|_| NativeCredentialError::WorkerUnavailable)?
}

pub(crate) async fn delete_native_credential(
    caller_id: CallerId,
) -> Result<(), NativeCredentialError> {
    tokio::task::spawn_blocking(move || {
        let locator =
            SecretLocator::for_caller(&caller_id).map_err(NativeCredentialError::Store)?;
        let backend = NativeSecretBackend::new()
            .map_err(SecretStoreError::from)
            .map_err(NativeCredentialError::Store)?;
        SecretStore::new(backend)
            .delete(&locator)
            .map_err(NativeCredentialError::Store)
    })
    .await
    .map_err(|_| NativeCredentialError::WorkerUnavailable)?
}

fn operation_ids(operation: &str) -> (RequestId, IdempotencyKey) {
    (
        RequestId::new(format!("{operation}-observer-{}", Uuid::new_v4())),
        IdempotencyKey::new(format!("{operation}-idempotency-{}", Uuid::new_v4())),
    )
}
