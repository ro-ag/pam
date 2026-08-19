use pam_core::{
    ApprovalId, CallerCredential, CallerId, EvidenceHandle, IdempotencyKey, ProjectId, RequestId,
};
use pam_platform::{CallerKind, IdentityError, caller_id, discover_project_id};
use pam_protocol::{ProtocolContractError, RequestEnvelope};
use uuid::Uuid;

#[derive(Clone, Debug)]
pub(crate) struct RequestContext {
    caller_id: CallerId,
    project_id: ProjectId,
    credential: Option<CallerCredential>,
    approval_id: Option<ApprovalId>,
}

impl RequestContext {
    pub(crate) fn discover() -> Result<Self, IdentityError> {
        Ok(Self {
            caller_id: caller_id(CallerKind::Cli)?,
            project_id: discover_project_id(".")?,
            credential: std::env::var("PAM_CALLER_CREDENTIAL")
                .ok()
                .map(CallerCredential::new),
            approval_id: std::env::var("PAM_APPROVAL_ID").ok().map(ApprovalId::new),
        })
    }

    #[cfg(test)]
    pub(crate) fn new(caller_id: CallerId, project_id: ProjectId) -> Self {
        Self {
            caller_id,
            project_id,
            credential: Some(CallerCredential::new("test-caller-credential")),
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
        let request = match &self.credential {
            Some(credential) => request.authenticated(credential.clone()),
            None => request,
        };
        match &self.approval_id {
            Some(approval_id) => request.with_approval(approval_id.clone()),
            None => request,
        }
    }
}

fn operation_ids(operation: &str) -> (RequestId, IdempotencyKey) {
    (
        RequestId::new(format!("{operation}-observer-{}", Uuid::new_v4())),
        IdempotencyKey::new(format!("{operation}-idempotency-{}", Uuid::new_v4())),
    )
}
