use pam_core::{CallerId, IdempotencyKey, ProjectId, RequestId};
use serde::{Deserialize, Serialize};

use crate::PROTOCOL_VERSION;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RequestEnvelope {
    pub protocol_version: u16,
    pub request_id: RequestId,
    pub caller_id: CallerId,
    pub project_id: ProjectId,
    pub capability: Capability,
    pub idempotency_key: IdempotencyKey,
    pub deadline_unix_ms: Option<u64>,
    pub payload: RequestPayload,
}

impl RequestEnvelope {
    #[must_use]
    pub fn status(
        request_id: RequestId,
        caller_id: CallerId,
        project_id: ProjectId,
        idempotency_key: IdempotencyKey,
    ) -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION,
            request_id,
            caller_id,
            project_id,
            capability: Capability::DaemonStatus,
            idempotency_key,
            deadline_unix_ms: None,
            payload: RequestPayload::Status,
        }
    }

    #[must_use]
    pub fn unsupported_version_failure(&self) -> Option<ResultEnvelope> {
        (self.protocol_version != PROTOCOL_VERSION).then(|| ResultEnvelope {
            protocol_version: PROTOCOL_VERSION,
            request_id: self.request_id.clone(),
            project_id: self.project_id.clone(),
            body: ResultBody::Failure(Failure {
                code: FailureCode::UnsupportedProtocolVersion,
                message: format!(
                    "protocol version {} is unsupported; this daemon supports version {PROTOCOL_VERSION}",
                    self.protocol_version
                ),
                recovery: None,
            }),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    DaemonStatus,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RequestPayload {
    Status,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ResultEnvelope {
    pub protocol_version: u16,
    pub request_id: RequestId,
    pub project_id: ProjectId,
    pub body: ResultBody,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ResultBody {
    Success {
        truth: OperationTruth,
        payload: ResultPayload,
    },
    Failure(Failure),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationTruth {
    Observed,
    Changed,
    Verified,
    Unresolved,
    Blocked,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ResultPayload {
    Status(StatusResult),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct StatusResult {
    pub ready: bool,
    pub healthy: bool,
    pub daemon_version: String,
    pub protocol_version: u16,
    pub queue_depth: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Failure {
    pub code: FailureCode,
    pub message: String,
    pub recovery: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureCode {
    UnsupportedProtocolVersion,
    InvalidRequest,
    FrameTooLarge,
    Internal,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EventEnvelope {
    pub protocol_version: u16,
    pub request_id: RequestId,
    pub project_id: ProjectId,
    pub sequence: u64,
    pub event: Event,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Event {
    Accepted,
    Started,
    Completed,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "message_type", rename_all = "snake_case")]
pub enum ServerMessage {
    Event(EventEnvelope),
    Result(ResultEnvelope),
}

impl ServerMessage {
    #[must_use]
    pub fn protocol_version(&self) -> u16 {
        match self {
            Self::Event(envelope) => envelope.protocol_version,
            Self::Result(envelope) => envelope.protocol_version,
        }
    }
}
