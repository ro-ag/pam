use pam_core::{
    ApprovalId, CallerCredential, CallerId, EvidenceHandle, IdempotencyKey, ProjectId, RequestId,
};
use pam_platform::{
    CallerKind, IdentityError, NativeSecretBackend, SecretLocator, SecretStore, SecretStoreError,
    SecretStoreErrorKind, caller_id, discover_project_id,
};
use pam_protocol::{ProtocolContractError, RequestEnvelope};
use std::{error::Error, fmt};
use uuid::Uuid;

#[derive(Clone, Debug)]
pub(crate) struct RequestContext {
    caller_id: CallerId,
    project_id: ProjectId,
    credential: CallerCredential,
    approval_id: Option<ApprovalId>,
}

impl RequestContext {
    pub(crate) async fn discover() -> Result<Self, RequestContextError> {
        let caller_id = caller_id(CallerKind::Cli).map_err(RequestContextError::Identity)?;
        let project_id = discover_project_id(".").map_err(RequestContextError::Identity)?;
        let credential = load_native_credential(caller_id.clone()).await?;
        Ok(Self {
            caller_id,
            project_id,
            credential,
            approval_id: std::env::var("PAM_APPROVAL_ID").ok().map(ApprovalId::new),
        })
    }

    #[cfg(test)]
    pub(crate) fn new(caller_id: CallerId, project_id: ProjectId) -> Self {
        Self {
            caller_id,
            project_id,
            credential: CallerCredential::new("test-caller-credential"),
            approval_id: None,
        }
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

    pub(crate) fn inspect_evidence(&self, handle: EvidenceHandle) -> RequestEnvelope {
        let (request_id, idempotency_key) = operation_ids("evidence-inspect");
        self.authenticate(RequestEnvelope::inspect_evidence(
            request_id,
            self.caller_id.clone(),
            self.project_id.clone(),
            idempotency_key,
            handle,
        ))
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
        .map(|request| self.authenticate(request))
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
