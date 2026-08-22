use std::{
    error::Error,
    fmt,
    path::{Component, Path, PathBuf},
};

use pam_core::{
    ApprovalId, CallerCredential, CallerId, ContentDigest, EvidenceHandle, IdempotencyKey,
    MAX_CALLER_CREDENTIAL_LENGTH, ProjectId, RequestId,
};
use pam_flow::{FlowDefinition, MAX_FLOW_DOCUMENT_BYTES, RunId};
use serde::{Deserialize, Serialize};

use crate::{
    MAX_EVIDENCE_CHUNK_SIZE, MAX_FRAME_SIZE, MAX_MODEL_MESSAGE_BYTES, MAX_MODEL_MESSAGES,
    MAX_MODEL_OUTPUT_BYTES, MAX_MODEL_OUTPUT_TOKENS, MAX_MODEL_PROMPT_BYTES, PROTOCOL_VERSION,
};

// Flow requests are authenticated and may carry one exact approval receipt.
// Reserve their maximum validated values plus named-MessagePack field overhead
// so the infallible attachment builders cannot push a constructed request over
// the frame boundary. Daemon request identifiers, including issued approval
// IDs, are bounded to 256 bytes.
const MAX_FLOW_APPROVAL_ID_BYTES: usize = 256;
const MAX_FLOW_REQUEST_ATTACHMENT_BYTES: usize =
    MAX_CALLER_CREDENTIAL_LENGTH + MAX_FLOW_APPROVAL_ID_BYTES + 64;
pub const MAX_FLOW_PROJECT_ROOT_BYTES: usize = 4 * 1024;
pub const MAX_PROJECT_CURRENT_QUEUED: usize = 64;
pub const MAX_PROJECT_OPERATION_KIND_BYTES: usize = 128;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RequestEnvelope {
    pub protocol_version: u16,
    pub request_id: RequestId,
    pub caller_id: CallerId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authentication: Option<CallerCredential>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_id: Option<ApprovalId>,
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
            authentication: None,
            approval_id: None,
            project_id,
            capability: Capability::DaemonStatus,
            idempotency_key,
            deadline_unix_ms: None,
            payload: RequestPayload::Status,
        }
    }

    /// Creates an authenticated request to stop the daemon gracefully.
    ///
    /// Attach the caller credential with [`Self::authenticated`] before sending
    /// the request.
    #[must_use]
    pub fn stop(
        request_id: RequestId,
        caller_id: CallerId,
        project_id: ProjectId,
        idempotency_key: IdempotencyKey,
    ) -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION,
            request_id,
            caller_id,
            authentication: None,
            approval_id: None,
            project_id,
            capability: Capability::DaemonStop,
            idempotency_key,
            deadline_unix_ms: None,
            payload: RequestPayload::Stop,
        }
    }

    /// Creates an authenticated, policy-gated snapshot request for the project
    /// identified by this envelope.
    ///
    /// Attach the caller credential with [`Self::authenticated`] before sending
    /// the request. The result contains bounded scheduling metadata only; it
    /// never exposes stored operation payloads.
    #[must_use]
    pub fn project_current(
        request_id: RequestId,
        caller_id: CallerId,
        project_id: ProjectId,
        idempotency_key: IdempotencyKey,
    ) -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION,
            request_id,
            caller_id,
            authentication: None,
            approval_id: None,
            project_id,
            capability: Capability::ProjectCurrent,
            idempotency_key,
            deadline_unix_ms: None,
            payload: RequestPayload::ProjectCurrent,
        }
    }

    /// Creates an authenticated daemon-wide activity feed request.
    ///
    /// Attach the caller credential with [`Self::authenticated`] before sending
    /// the request. The daemon clamps `limit` to its bounded maximum; zero
    /// requests the daemon default. The result contains bounded audit metadata
    /// only; redacted event detail never crosses this contract.
    #[must_use]
    pub fn daemon_activity(
        request_id: RequestId,
        caller_id: CallerId,
        project_id: ProjectId,
        idempotency_key: IdempotencyKey,
        limit: u32,
    ) -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION,
            request_id,
            caller_id,
            authentication: None,
            approval_id: None,
            project_id,
            capability: Capability::DaemonActivity,
            idempotency_key,
            deadline_unix_ms: None,
            payload: RequestPayload::DaemonActivity { limit },
        }
    }

    /// Creates an authenticated caller registry listing request.
    ///
    /// Attach the caller credential with [`Self::authenticated`] before sending
    /// the request. The result never contains credential verifiers.
    #[must_use]
    pub fn caller_list(
        request_id: RequestId,
        caller_id: CallerId,
        project_id: ProjectId,
        idempotency_key: IdempotencyKey,
    ) -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION,
            request_id,
            caller_id,
            authentication: None,
            approval_id: None,
            project_id,
            capability: Capability::CallerList,
            idempotency_key,
            deadline_unix_ms: None,
            payload: RequestPayload::CallerList,
        }
    }

    /// Creates an authenticated decision for one pending approval challenge.
    ///
    /// The daemon must authenticate this envelope and verify that the approval
    /// is bound to its exact `project_id` and `caller_id` before applying the
    /// decision. It must handle the decision before ordinary policy evaluation:
    /// policy-gating this capability would recursively require another approval.
    /// The approval ID is a challenge identifier, not a reusable receipt, and
    /// this payload deliberately has no field capable of carrying a token or
    /// secret.
    #[must_use]
    pub fn approval_decide(
        request_id: RequestId,
        caller_id: CallerId,
        project_id: ProjectId,
        idempotency_key: IdempotencyKey,
        approval_id: ApprovalId,
        decision: ApprovalDecision,
    ) -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION,
            request_id,
            caller_id,
            authentication: None,
            approval_id: None,
            project_id,
            capability: Capability::ApprovalDecide,
            idempotency_key,
            deadline_unix_ms: None,
            payload: RequestPayload::ApprovalDecide {
                approval_id,
                decision,
            },
        }
    }

    /// Creates a cancellation request for `target_request_id`.
    ///
    /// The envelope's `request_id` identifies and correlates this cancellation
    /// operation. The target remains separately identified in the payload so a
    /// response to the observer is never mistaken for the target's result.
    #[must_use]
    pub fn cancel(
        request_id: RequestId,
        caller_id: CallerId,
        project_id: ProjectId,
        idempotency_key: IdempotencyKey,
        target_request_id: RequestId,
    ) -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION,
            request_id,
            caller_id,
            authentication: None,
            approval_id: None,
            project_id,
            capability: Capability::CancelRequest,
            idempotency_key,
            deadline_unix_ms: None,
            payload: RequestPayload::Cancel {
                target_request_id,
                expected_target_kind: None,
            },
        }
    }

    /// Creates a cancellation request bound to an immutable target kind.
    #[must_use]
    pub fn cancel_with_expected_target(
        request_id: RequestId,
        caller_id: CallerId,
        project_id: ProjectId,
        idempotency_key: IdempotencyKey,
        target_request_id: RequestId,
        expected_target_kind: ExpectedTargetKind,
    ) -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION,
            request_id,
            caller_id,
            authentication: None,
            approval_id: None,
            project_id,
            capability: Capability::CancelRequest,
            idempotency_key,
            deadline_unix_ms: None,
            payload: RequestPayload::Cancel {
                target_request_id,
                expected_target_kind: Some(expected_target_kind),
            },
        }
    }

    /// Creates an event replay request for `target_request_id`.
    ///
    /// The envelope's `request_id` correlates the replay operation, while
    /// replayed event and terminal result envelopes retain the target request's
    /// identity. Callers may deliberately use the target ID as the observer ID
    /// when reconnecting to the original request. `after_sequence` is exclusive.
    #[must_use]
    pub fn replay(
        request_id: RequestId,
        caller_id: CallerId,
        project_id: ProjectId,
        idempotency_key: IdempotencyKey,
        target_request_id: RequestId,
        after_sequence: u64,
    ) -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION,
            request_id,
            caller_id,
            authentication: None,
            approval_id: None,
            project_id,
            capability: Capability::ReplayEvents,
            idempotency_key,
            deadline_unix_ms: None,
            payload: RequestPayload::Replay {
                target_request_id,
                after_sequence,
                expected_target_kind: None,
            },
        }
    }

    /// Creates an event replay request bound to an immutable target kind.
    #[must_use]
    pub fn replay_with_expected_target(
        request_id: RequestId,
        caller_id: CallerId,
        project_id: ProjectId,
        idempotency_key: IdempotencyKey,
        target_request_id: RequestId,
        after_sequence: u64,
        expected_target_kind: ExpectedTargetKind,
    ) -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION,
            request_id,
            caller_id,
            authentication: None,
            approval_id: None,
            project_id,
            capability: Capability::ReplayEvents,
            idempotency_key,
            deadline_unix_ms: None,
            payload: RequestPayload::Replay {
                target_request_id,
                after_sequence,
                expected_target_kind: Some(expected_target_kind),
            },
        }
    }

    /// Creates a read-only request for a compact continuity brief.
    #[must_use]
    pub fn brief(
        request_id: RequestId,
        caller_id: CallerId,
        project_id: ProjectId,
        idempotency_key: IdempotencyKey,
    ) -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION,
            request_id,
            caller_id,
            authentication: None,
            approval_id: None,
            project_id,
            capability: Capability::Brief,
            idempotency_key,
            deadline_unix_ms: None,
            payload: RequestPayload::Brief,
        }
    }

    /// Creates an authenticated, policy-gated read-only network diagnostics request.
    #[must_use]
    pub fn network_diagnostics(
        request_id: RequestId,
        caller_id: CallerId,
        project_id: ProjectId,
        idempotency_key: IdempotencyKey,
    ) -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION,
            request_id,
            caller_id,
            authentication: None,
            approval_id: None,
            project_id,
            capability: Capability::NetworkDiagnostics,
            idempotency_key,
            deadline_unix_ms: None,
            payload: RequestPayload::NetworkDiagnostics,
        }
    }

    /// Creates an authenticated, policy-gated request for direct embedded inference.
    ///
    /// # Errors
    ///
    /// Returns a contract error when the model identity, chat messages, prompt byte
    /// budget, output-token bound, or absolute deadline is invalid.
    #[allow(clippy::too_many_arguments)]
    pub fn model_infer(
        request_id: RequestId,
        caller_id: CallerId,
        project_id: ProjectId,
        idempotency_key: IdempotencyKey,
        model: impl Into<String>,
        messages: Vec<ModelMessage>,
        max_output_tokens: u32,
        deadline_unix_ms: u64,
    ) -> Result<Self, ProtocolContractError> {
        let model = model.into();
        validate_model_generation(&model, &messages, max_output_tokens)?;
        validate_model_deadline(Some(deadline_unix_ms))?;
        Ok(Self {
            protocol_version: PROTOCOL_VERSION,
            request_id,
            caller_id,
            authentication: None,
            approval_id: None,
            project_id,
            capability: Capability::ModelInfer,
            idempotency_key,
            deadline_unix_ms: Some(deadline_unix_ms),
            payload: RequestPayload::ModelInfer {
                model,
                messages,
                max_output_tokens,
            },
        })
    }

    /// Creates an authenticated, policy-gated request to run a validated flow.
    ///
    /// Attach the caller credential with [`Self::authenticated`] before sending
    /// the request. The raw TOML and canonical project root remain available to
    /// the daemon but are redacted from debug output.
    ///
    /// # Errors
    ///
    /// Returns a contract error when the definition is malformed, either field
    /// exceeds its budget, the project root is not canonical absolute UTF-8, or
    /// the encoded request would exceed the protocol frame limit.
    pub fn flow_run(
        request_id: RequestId,
        caller_id: CallerId,
        project_id: ProjectId,
        idempotency_key: IdempotencyKey,
        definition: impl Into<String>,
        project_root: impl Into<String>,
    ) -> Result<Self, ProtocolContractError> {
        let request = Self {
            protocol_version: PROTOCOL_VERSION,
            request_id,
            caller_id,
            authentication: None,
            approval_id: None,
            project_id,
            capability: Capability::FlowRun,
            idempotency_key,
            deadline_unix_ms: None,
            payload: RequestPayload::FlowRun {
                definition: FlowDefinitionDocument::new(definition)?,
                project_root: FlowProjectRoot::new(project_root)?,
            },
        };
        request.validate_flow_request()?;
        validate_flow_request_frame(&request)?;
        Ok(request)
    }

    /// Revalidates the bounded direct-inference payload after deserialization.
    ///
    /// # Errors
    ///
    /// Returns a contract error for a malformed or over-budget model request.
    pub fn validate_model_request(&self) -> Result<(), ProtocolContractError> {
        match &self.payload {
            RequestPayload::ModelInfer {
                model,
                messages,
                max_output_tokens,
                ..
            } => {
                validate_model_generation(model, messages, *max_output_tokens)?;
                validate_model_deadline(self.deadline_unix_ms)
            }
            _ => Ok(()),
        }
    }

    /// Revalidates a flow definition after the request has been deserialized.
    ///
    /// # Errors
    ///
    /// Returns a contract error for an invalid run identity or malformed,
    /// unsafe, or over-budget TOML.
    pub fn validate_flow_request(&self) -> Result<(), ProtocolContractError> {
        match &self.payload {
            RequestPayload::FlowRun {
                definition,
                project_root,
            } => {
                RunId::parse(self.request_id.as_str())
                    .map_err(|_| ProtocolContractError::InvalidFlowRunId)?;
                definition.validate()?;
                project_root.validate()
            }
            _ => Ok(()),
        }
    }

    /// Creates a read-only wait request for `target_request_id`.
    ///
    /// The envelope ID correlates this observer operation. Replayed events retain
    /// the target ID, while the terminal [`ResultEnvelope`] uses the observer ID
    /// with the target's original persisted [`ResultBody`] unchanged.
    #[must_use]
    pub fn wait_for_result(
        request_id: RequestId,
        caller_id: CallerId,
        project_id: ProjectId,
        idempotency_key: IdempotencyKey,
        target_request_id: RequestId,
        after_sequence: u64,
    ) -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION,
            request_id,
            caller_id,
            authentication: None,
            approval_id: None,
            project_id,
            capability: Capability::WaitForResult,
            idempotency_key,
            deadline_unix_ms: None,
            payload: RequestPayload::WaitForResult {
                target_request_id,
                after_sequence,
                expected_target_kind: None,
            },
        }
    }

    /// Creates a wait request bound to an immutable target kind.
    #[must_use]
    pub fn wait_for_result_with_expected_target(
        request_id: RequestId,
        caller_id: CallerId,
        project_id: ProjectId,
        idempotency_key: IdempotencyKey,
        target_request_id: RequestId,
        after_sequence: u64,
        expected_target_kind: ExpectedTargetKind,
    ) -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION,
            request_id,
            caller_id,
            authentication: None,
            approval_id: None,
            project_id,
            capability: Capability::WaitForResult,
            idempotency_key,
            deadline_unix_ms: None,
            payload: RequestPayload::WaitForResult {
                target_request_id,
                after_sequence,
                expected_target_kind: Some(expected_target_kind),
            },
        }
    }

    /// Creates a non-blocking read of a target request's terminal result.
    ///
    /// A completed target's original persisted [`ResultBody`] is returned in an
    /// envelope correlated to this observer request. Pending and missing targets
    /// use [`FailureCode::Pending`] and [`FailureCode::NotFound`], respectively.
    #[must_use]
    pub fn get_result(
        request_id: RequestId,
        caller_id: CallerId,
        project_id: ProjectId,
        idempotency_key: IdempotencyKey,
        target_request_id: RequestId,
    ) -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION,
            request_id,
            caller_id,
            authentication: None,
            approval_id: None,
            project_id,
            capability: Capability::GetResult,
            idempotency_key,
            deadline_unix_ms: None,
            payload: RequestPayload::GetResult {
                target_request_id,
                expected_target_kind: None,
            },
        }
    }

    /// Creates a non-blocking result read bound to an immutable target kind.
    #[must_use]
    pub fn get_result_with_expected_target(
        request_id: RequestId,
        caller_id: CallerId,
        project_id: ProjectId,
        idempotency_key: IdempotencyKey,
        target_request_id: RequestId,
        expected_target_kind: ExpectedTargetKind,
    ) -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION,
            request_id,
            caller_id,
            authentication: None,
            approval_id: None,
            project_id,
            capability: Capability::GetResult,
            idempotency_key,
            deadline_unix_ms: None,
            payload: RequestPayload::GetResult {
                target_request_id,
                expected_target_kind: Some(expected_target_kind),
            },
        }
    }

    /// Creates a read-only metadata lookup for an exact evidence handle.
    #[must_use]
    pub fn inspect_evidence(
        request_id: RequestId,
        caller_id: CallerId,
        project_id: ProjectId,
        idempotency_key: IdempotencyKey,
        handle: EvidenceHandle,
    ) -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION,
            request_id,
            caller_id,
            authentication: None,
            approval_id: None,
            project_id,
            capability: Capability::InspectEvidence,
            idempotency_key,
            deadline_unix_ms: None,
            payload: RequestPayload::InspectEvidence { handle },
        }
    }

    /// Creates a bounded exact-evidence range request.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolContractError::InvalidEvidenceReadLength`] when `length`
    /// is zero or exceeds [`MAX_EVIDENCE_CHUNK_SIZE`].
    pub fn read_evidence(
        request_id: RequestId,
        caller_id: CallerId,
        project_id: ProjectId,
        idempotency_key: IdempotencyKey,
        handle: EvidenceHandle,
        offset: u64,
        length: u64,
    ) -> Result<Self, ProtocolContractError> {
        validate_evidence_read_length(length)?;
        Ok(Self {
            protocol_version: PROTOCOL_VERSION,
            request_id,
            caller_id,
            authentication: None,
            approval_id: None,
            project_id,
            capability: Capability::ReadEvidence,
            idempotency_key,
            deadline_unix_ms: None,
            payload: RequestPayload::ReadEvidence {
                handle,
                offset,
                length,
            },
        })
    }

    /// Attaches the revocable caller credential used to authenticate this request.
    #[must_use]
    pub fn authenticated(mut self, credential: CallerCredential) -> Self {
        self.authentication = Some(credential);
        self
    }

    /// Attaches a previously approved exact-effect receipt for one-time use.
    #[must_use]
    pub fn with_approval(mut self, approval_id: ApprovalId) -> Self {
        self.approval_id = Some(approval_id);
        self
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
                approval: None,
            }),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    DaemonStatus,
    DaemonStop,
    DaemonActivity,
    CallerList,
    ProjectCurrent,
    ApprovalDecide,
    CancelRequest,
    ReplayEvents,
    Brief,
    NetworkDiagnostics,
    WaitForResult,
    GetResult,
    InspectEvidence,
    ReadEvidence,
    ModelInfer,
    FlowRun,
}

impl Capability {
    #[must_use]
    pub const fn policy_name(&self) -> &'static str {
        match self {
            Self::DaemonStatus => "daemon.status",
            Self::DaemonStop => "daemon.stop",
            Self::DaemonActivity => "daemon.activity",
            Self::CallerList => "caller.list",
            Self::ProjectCurrent => "project.current",
            Self::ApprovalDecide => "approval.decide",
            Self::CancelRequest => "request.cancel",
            Self::ReplayEvents => "request.replay",
            Self::Brief => "brief.read",
            Self::NetworkDiagnostics => "network.diagnostics",
            Self::WaitForResult => "request.wait",
            Self::GetResult => "request.result.read",
            Self::InspectEvidence => "evidence.inspect",
            Self::ReadEvidence => "evidence.read",
            Self::ModelInfer => "model.infer",
            Self::FlowRun => "flow.run",
        }
    }
}

/// Bounded flow TOML transported without exposing its contents through debug logs.
#[derive(Clone, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct FlowDefinitionDocument(String);

impl<'de> Deserialize<'de> for FlowDefinitionDocument {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let definition = String::deserialize(deserializer)?;
        Self::new(definition).map_err(serde::de::Error::custom)
    }
}

impl fmt::Debug for FlowDefinitionDocument {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FlowDefinitionDocument")
            .field("bytes", &self.0.len())
            .finish()
    }
}

impl FlowDefinitionDocument {
    /// Creates a document within the flow schema's transport budget.
    ///
    /// Parsing is performed by [`RequestEnvelope::validate_flow_request`] so
    /// constructors and canonical request decoding share one validation path.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolContractError::FlowDefinitionTooLarge`] when the TOML
    /// exceeds [`MAX_FLOW_DOCUMENT_BYTES`].
    pub fn new(definition: impl Into<String>) -> Result<Self, ProtocolContractError> {
        let definition = definition.into();
        if definition.len() > MAX_FLOW_DOCUMENT_BYTES {
            return Err(ProtocolContractError::FlowDefinitionTooLarge {
                actual: definition.len(),
                maximum: MAX_FLOW_DOCUMENT_BYTES,
            });
        }
        Ok(Self(definition))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn validate(&self) -> Result<(), ProtocolContractError> {
        FlowDefinition::parse_toml(&self.0)
            .map(|_| ())
            .map_err(|_| ProtocolContractError::InvalidFlowDefinition)
    }
}

/// Bounded canonical project root transported without exposing its path in debug logs.
#[derive(Clone, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct FlowProjectRoot(String);

impl<'de> Deserialize<'de> for FlowProjectRoot {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let project_root = String::deserialize(deserializer)?;
        Self::new(project_root).map_err(serde::de::Error::custom)
    }
}

impl fmt::Debug for FlowProjectRoot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FlowProjectRoot")
            .field("bytes", &self.0.len())
            .finish()
    }
}

impl FlowProjectRoot {
    /// Creates a bounded, lexically canonical absolute project root.
    ///
    /// The daemon still resolves the supplied path and verifies that its
    /// canonical filesystem identity matches the request's project ID before
    /// reading any workspace content.
    ///
    /// # Errors
    ///
    /// Returns a contract error when the root is over budget, relative, or
    /// contains path syntax that a canonical path would have removed.
    pub fn new(project_root: impl Into<String>) -> Result<Self, ProtocolContractError> {
        let project_root = project_root.into();
        if project_root.len() > MAX_FLOW_PROJECT_ROOT_BYTES {
            return Err(ProtocolContractError::FlowProjectRootTooLarge {
                actual: project_root.len(),
                maximum: MAX_FLOW_PROJECT_ROOT_BYTES,
            });
        }
        let root = Self(project_root);
        root.validate()?;
        Ok(root)
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn validate(&self) -> Result<(), ProtocolContractError> {
        let path = Path::new(&self.0);
        let components_are_canonical = path.components().all(|component| {
            matches!(
                component,
                Component::Prefix(_) | Component::RootDir | Component::Normal(_)
            )
        });
        let normalized = path.components().collect::<PathBuf>();
        if self.0.is_empty()
            || !path.is_absolute()
            || !components_are_canonical
            || normalized.as_os_str() != path.as_os_str()
        {
            return Err(ProtocolContractError::InvalidFlowProjectRoot);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RequestPayload {
    Status,
    Stop,
    DaemonActivity {
        limit: u32,
    },
    CallerList,
    ProjectCurrent,
    ApprovalDecide {
        approval_id: ApprovalId,
        decision: ApprovalDecision,
    },
    Cancel {
        target_request_id: RequestId,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        expected_target_kind: Option<ExpectedTargetKind>,
    },
    Replay {
        target_request_id: RequestId,
        after_sequence: u64,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        expected_target_kind: Option<ExpectedTargetKind>,
    },
    Brief,
    NetworkDiagnostics,
    WaitForResult {
        target_request_id: RequestId,
        after_sequence: u64,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        expected_target_kind: Option<ExpectedTargetKind>,
    },
    GetResult {
        target_request_id: RequestId,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        expected_target_kind: Option<ExpectedTargetKind>,
    },
    InspectEvidence {
        handle: EvidenceHandle,
    },
    ReadEvidence {
        handle: EvidenceHandle,
        offset: u64,
        #[serde(deserialize_with = "deserialize_evidence_read_length")]
        length: u64,
    },
    ModelInfer {
        model: String,
        messages: Vec<ModelMessage>,
        max_output_tokens: u32,
    },
    FlowRun {
        definition: FlowDefinitionDocument,
        project_root: FlowProjectRoot,
    },
}

/// Optional immutable target classification bound by observer operations.
///
/// A flow-namespaced observer sets this to [`Self::FlowRun`] so a request ID
/// belonging to unrelated durable work cannot be cancelled or observed by
/// mistake. Generic observer commands omit the expectation.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExpectedTargetKind {
    FlowRun,
}

impl ExpectedTargetKind {
    #[must_use]
    pub const fn policy_label(self) -> &'static str {
        match self {
            Self::FlowRun => "flow_run",
        }
    }
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
    DaemonLifecycle(DaemonLifecycleResult),
    DaemonActivity(ActivityResult),
    CallerList(CallerListResult),
    ProjectCurrent(ProjectCurrentResult),
    ApprovalDecision(ApprovalDecisionResult),
    Cancellation(CancellationResult),
    Replay(ReplayResult),
    Brief(BriefResult),
    NetworkDiagnostics(NetworkDiagnosticsResult),
    EvidenceMetadata(EvidenceMetadata),
    EvidenceChunk(EvidenceChunk),
    ModelGeneration(ModelGenerationResult),
    FlowRun(pam_flow::FlowRunResult),
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ModelRole {
    System,
    User,
    Assistant,
}

#[derive(Clone, Eq, PartialEq, Serialize)]
pub struct ModelMessage {
    role: ModelRole,
    content: String,
}

impl<'de> Deserialize<'de> for ModelMessage {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Fields {
            role: ModelRole,
            content: String,
        }

        let fields = Fields::deserialize(deserializer)?;
        Self::new(fields.role, fields.content).map_err(serde::de::Error::custom)
    }
}

impl fmt::Debug for ModelMessage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ModelMessage")
            .field("role", &self.role)
            .field("content_bytes", &self.content.len())
            .finish()
    }
}

impl ModelMessage {
    /// Creates one bounded text-only chat message.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolContractError::InvalidModelMessage`] for empty or
    /// over-budget content.
    pub fn new(role: ModelRole, content: impl Into<String>) -> Result<Self, ProtocolContractError> {
        let content = content.into();
        validate_model_message(&content)?;
        Ok(Self { role, content })
    }

    #[must_use]
    pub const fn role(&self) -> ModelRole {
        self.role
    }

    #[must_use]
    pub fn content(&self) -> &str {
        &self.content
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ModelFinishReason {
    Stop,
    Length,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ModelUsage {
    pub input_tokens: u32,
    pub sampled_output_tokens: u32,
    pub emitted_output_tokens: u32,
}

#[derive(Clone, Eq, PartialEq, Serialize)]
pub struct ModelGenerationResult {
    pub model: String,
    text: String,
    pub finish_reason: ModelFinishReason,
    pub usage: ModelUsage,
}

impl<'de> Deserialize<'de> for ModelGenerationResult {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Fields {
            model: String,
            text: String,
            finish_reason: ModelFinishReason,
            usage: ModelUsage,
        }

        let fields = Fields::deserialize(deserializer)?;
        Self::new(
            fields.model,
            fields.text,
            fields.finish_reason,
            fields.usage,
        )
        .map_err(serde::de::Error::custom)
    }
}

impl fmt::Debug for ModelGenerationResult {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ModelGenerationResult")
            .field("model", &self.model)
            .field("text_bytes", &self.text.len())
            .field("finish_reason", &self.finish_reason)
            .field("usage", &self.usage)
            .finish()
    }
}

impl ModelGenerationResult {
    /// Creates one bounded direct-runtime result for protocol transport.
    ///
    /// # Errors
    ///
    /// Returns an error when the model identity or output byte bound is invalid.
    pub fn new(
        model: impl Into<String>,
        text: impl Into<String>,
        finish_reason: ModelFinishReason,
        usage: ModelUsage,
    ) -> Result<Self, ProtocolContractError> {
        let model = model.into();
        let text = text.into();
        validate_model_id(&model)?;
        if text.len() > MAX_MODEL_OUTPUT_BYTES {
            return Err(ProtocolContractError::ModelOutputTooLarge {
                actual: text.len(),
                maximum: MAX_MODEL_OUTPUT_BYTES,
            });
        }
        Ok(Self {
            model,
            text,
            finish_reason,
            usage,
        })
    }

    #[must_use]
    pub fn text(&self) -> &str {
        &self.text
    }
}

/// A compact continuity snapshot in stable presentation order.
///
/// Every entry carries an explicit truth classification. `provenance` records
/// source availability so unavailable context cannot be mistaken for an empty or
/// verified source.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BriefResult {
    pub goal: Option<BriefItem>,
    pub decisions: Vec<BriefItem>,
    pub verified: Vec<BriefItem>,
    pub next: Vec<BriefItem>,
    pub provenance: Vec<BriefProvenance>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BriefItem {
    pub text: String,
    pub truth: OperationTruth,
    pub evidence: Vec<EvidenceHandle>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BriefProvenance {
    pub source: String,
    pub availability: SourceAvailability,
    pub truth: OperationTruth,
    pub evidence: Option<EvidenceHandle>,
    pub detail: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceAvailability {
    Available,
    Partial,
    Unavailable,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EvidenceMetadata {
    pub handle: EvidenceHandle,
    pub digest: ContentDigest,
    pub size_bytes: u64,
    pub media_type: String,
    pub retention: EvidenceRetention,
    pub redaction: EvidenceRedaction,
    pub created_at_unix_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceRetention {
    Session,
    Project,
    Persistent,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceRedaction {
    Unredacted,
    Redacted,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EvidenceChunk {
    pub handle: EvidenceHandle,
    pub offset: u64,
    #[serde(deserialize_with = "deserialize_evidence_chunk_bytes")]
    bytes: Vec<u8>,
    pub eof: bool,
}

impl EvidenceChunk {
    /// Creates a bounded exact-evidence response chunk.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolContractError::EvidenceChunkTooLarge`] when `bytes`
    /// exceeds [`MAX_EVIDENCE_CHUNK_SIZE`]. Empty chunks are valid at EOF.
    pub fn new(
        handle: EvidenceHandle,
        offset: u64,
        bytes: Vec<u8>,
        eof: bool,
    ) -> Result<Self, ProtocolContractError> {
        if bytes.len() > MAX_EVIDENCE_CHUNK_SIZE {
            return Err(ProtocolContractError::EvidenceChunkTooLarge {
                actual: bytes.len(),
                maximum: MAX_EVIDENCE_CHUNK_SIZE,
            });
        }
        Ok(Self {
            handle,
            offset,
            bytes,
            eof,
        })
    }

    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProtocolContractError {
    InvalidEvidenceReadLength { actual: u64, maximum: u64 },
    EvidenceChunkTooLarge { actual: usize, maximum: usize },
    InvalidModelIdentity,
    InvalidModelMessage,
    InvalidModelConversation,
    InvalidModelDeadline,
    ModelPromptTooLarge { actual: usize, maximum: usize },
    InvalidModelOutputTokens { actual: u32, maximum: u32 },
    ModelOutputTooLarge { actual: usize, maximum: usize },
    FlowDefinitionTooLarge { actual: usize, maximum: usize },
    FlowProjectRootTooLarge { actual: usize, maximum: usize },
    InvalidFlowProjectRoot,
    InvalidFlowRunId,
    InvalidFlowDefinition,
    FlowRequestTooLarge { actual: usize, maximum: usize },
    FlowRequestEncoding,
    InvalidProjectOperationKind,
    ProjectCurrentQueueTooLarge { actual: usize, maximum: usize },
}

impl fmt::Display for ProtocolContractError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidEvidenceReadLength { actual, maximum } => write!(
                formatter,
                "evidence read length is {actual}; it must be between 1 and {maximum} bytes"
            ),
            Self::EvidenceChunkTooLarge { actual, maximum } => write!(
                formatter,
                "evidence chunk is {actual} bytes; maximum is {maximum}"
            ),
            Self::InvalidModelIdentity => {
                formatter.write_str("model identity must use bounded vendor/name form")
            }
            Self::InvalidModelMessage => write!(
                formatter,
                "model messages must contain 1 to {MAX_MODEL_MESSAGE_BYTES} bytes"
            ),
            Self::InvalidModelConversation => write!(
                formatter,
                "model conversations must contain 1 to {MAX_MODEL_MESSAGES} messages and end with a user message"
            ),
            Self::InvalidModelDeadline => {
                formatter.write_str("model inference requires a positive absolute deadline")
            }
            Self::ModelPromptTooLarge { actual, maximum } => write!(
                formatter,
                "model prompt is {actual} bytes; maximum is {maximum} bytes"
            ),
            Self::InvalidModelOutputTokens { actual, maximum } => write!(
                formatter,
                "model output token bound is {actual}; it must be between 1 and {maximum}"
            ),
            Self::ModelOutputTooLarge { actual, maximum } => write!(
                formatter,
                "model output is {actual} bytes; maximum is {maximum} bytes"
            ),
            Self::FlowDefinitionTooLarge { actual, maximum } => write!(
                formatter,
                "flow definition is {actual} bytes; maximum is {maximum} bytes"
            ),
            Self::FlowProjectRootTooLarge { actual, maximum } => write!(
                formatter,
                "flow project root is {actual} bytes; maximum is {maximum} bytes"
            ),
            Self::InvalidFlowProjectRoot => formatter
                .write_str("flow project root must be a bounded canonical absolute UTF-8 path"),
            Self::InvalidFlowRunId => formatter.write_str(
                "flow run request identifier must use the bounded portable run-ID format",
            ),
            Self::InvalidFlowDefinition => {
                formatter.write_str("flow definition is malformed or invalid")
            }
            Self::FlowRequestTooLarge { actual, maximum } => write!(
                formatter,
                "encoded flow request is {actual} bytes; maximum is {maximum} bytes"
            ),
            Self::FlowRequestEncoding => {
                formatter.write_str("flow request could not be encoded for size validation")
            }
            Self::InvalidProjectOperationKind => write!(
                formatter,
                "project operation kind must contain 1 to {MAX_PROJECT_OPERATION_KIND_BYTES} bytes"
            ),
            Self::ProjectCurrentQueueTooLarge { actual, maximum } => write!(
                formatter,
                "project current queue contains {actual} summaries; maximum is {maximum}"
            ),
        }
    }
}

impl Error for ProtocolContractError {}

fn validate_flow_request_frame(request: &RequestEnvelope) -> Result<(), ProtocolContractError> {
    let encoded = rmp_serde::to_vec_named(request)
        .map_err(|_| ProtocolContractError::FlowRequestEncoding)?
        .len();
    let actual = encoded.saturating_add(MAX_FLOW_REQUEST_ATTACHMENT_BYTES);
    if actual > MAX_FRAME_SIZE {
        Err(ProtocolContractError::FlowRequestTooLarge {
            actual,
            maximum: MAX_FRAME_SIZE,
        })
    } else {
        Ok(())
    }
}

fn validate_model_generation(
    model: &str,
    messages: &[ModelMessage],
    max_output_tokens: u32,
) -> Result<(), ProtocolContractError> {
    validate_model_id(model)?;
    if messages.is_empty()
        || messages.len() > MAX_MODEL_MESSAGES
        || messages.last().map(ModelMessage::role) != Some(ModelRole::User)
    {
        return Err(ProtocolContractError::InvalidModelConversation);
    }
    let mut total = 0_usize;
    for message in messages {
        validate_model_message(message.content())?;
        total = total.checked_add(message.content().len()).ok_or(
            ProtocolContractError::ModelPromptTooLarge {
                actual: usize::MAX,
                maximum: MAX_MODEL_PROMPT_BYTES,
            },
        )?;
        if total > MAX_MODEL_PROMPT_BYTES {
            return Err(ProtocolContractError::ModelPromptTooLarge {
                actual: total,
                maximum: MAX_MODEL_PROMPT_BYTES,
            });
        }
    }
    if max_output_tokens == 0 || max_output_tokens > MAX_MODEL_OUTPUT_TOKENS {
        return Err(ProtocolContractError::InvalidModelOutputTokens {
            actual: max_output_tokens,
            maximum: MAX_MODEL_OUTPUT_TOKENS,
        });
    }
    Ok(())
}

fn validate_model_deadline(deadline_unix_ms: Option<u64>) -> Result<(), ProtocolContractError> {
    if deadline_unix_ms.is_some_and(|deadline| deadline > 0) {
        Ok(())
    } else {
        Err(ProtocolContractError::InvalidModelDeadline)
    }
}

fn validate_model_message(content: &str) -> Result<(), ProtocolContractError> {
    if content.is_empty() || content.len() > MAX_MODEL_MESSAGE_BYTES || content.contains('\0') {
        Err(ProtocolContractError::InvalidModelMessage)
    } else {
        Ok(())
    }
}

fn validate_model_id(model: &str) -> Result<(), ProtocolContractError> {
    let Some((vendor, name)) = model.split_once('/') else {
        return Err(ProtocolContractError::InvalidModelIdentity);
    };
    if name.contains('/') || !valid_model_segment(vendor) || !valid_model_segment(name) {
        return Err(ProtocolContractError::InvalidModelIdentity);
    }
    Ok(())
}

fn valid_model_segment(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value != "."
        && value != ".."
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn validate_evidence_read_length(length: u64) -> Result<(), ProtocolContractError> {
    let maximum = MAX_EVIDENCE_CHUNK_SIZE as u64;
    if length == 0 || length > maximum {
        return Err(ProtocolContractError::InvalidEvidenceReadLength {
            actual: length,
            maximum,
        });
    }
    Ok(())
}

fn deserialize_evidence_read_length<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let length = u64::deserialize(deserializer)?;
    validate_evidence_read_length(length).map_err(serde::de::Error::custom)?;
    Ok(length)
}

fn deserialize_evidence_chunk_bytes<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let bytes = Vec::<u8>::deserialize(deserializer)?;
    if bytes.len() > MAX_EVIDENCE_CHUNK_SIZE {
        return Err(serde::de::Error::custom(
            ProtocolContractError::EvidenceChunkTooLarge {
                actual: bytes.len(),
                maximum: MAX_EVIDENCE_CHUNK_SIZE,
            },
        ));
    }
    Ok(bytes)
}

fn validate_project_operation_kind(operation_kind: &str) -> Result<(), ProtocolContractError> {
    if operation_kind.is_empty()
        || operation_kind.len() > MAX_PROJECT_OPERATION_KIND_BYTES
        || operation_kind.contains('\0')
    {
        Err(ProtocolContractError::InvalidProjectOperationKind)
    } else {
        Ok(())
    }
}

fn deserialize_project_operation_kind<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let operation_kind = String::deserialize(deserializer)?;
    validate_project_operation_kind(&operation_kind).map_err(serde::de::Error::custom)?;
    Ok(operation_kind)
}

fn validate_project_current_queued(
    queued: &[ProjectRequestSummary],
) -> Result<(), ProtocolContractError> {
    if queued.len() > MAX_PROJECT_CURRENT_QUEUED {
        Err(ProtocolContractError::ProjectCurrentQueueTooLarge {
            actual: queued.len(),
            maximum: MAX_PROJECT_CURRENT_QUEUED,
        })
    } else {
        Ok(())
    }
}

fn deserialize_project_current_queued<'de, D>(
    deserializer: D,
) -> Result<Vec<ProjectRequestSummary>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let queued = Vec::<ProjectRequestSummary>::deserialize(deserializer)?;
    validate_project_current_queued(&queued).map_err(serde::de::Error::custom)?;
    Ok(queued)
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CancellationResult {
    pub target_request_id: RequestId,
    pub disposition: CancellationDisposition,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CancellationDisposition {
    Requested,
    AlreadyRequested,
    AlreadyCancelled,
    AlreadyTerminal,
}

/// Snapshot returned after replaying all available events after the requested sequence.
///
/// `pending` is true when the target has no stored terminal result yet. For a
/// terminal target, the daemon can replay the original stored [`ResultEnvelope`]
/// after its events; that envelope remains correlated to `target_request_id`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReplayResult {
    pub target_request_id: RequestId,
    pub through_sequence: u64,
    pub pending: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct StatusResult {
    pub ready: bool,
    pub healthy: bool,
    pub daemon_version: String,
    pub protocol_version: u16,
    pub queue_depth: u64,
}

/// Acknowledgement that an authenticated daemon lifecycle change has begun.
///
/// Process identifiers are intentionally absent from the caller-facing
/// contract.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DaemonLifecycleResult {
    pub stopping: bool,
}

/// Bounded newest-first slice of the daemon audit ledger.
///
/// `truncated` is true when older events beyond the served limit remain.
/// Redacted event detail and retention metadata never cross this contract.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ActivityResult {
    pub events: Vec<ActivityEventSummary>,
    pub truncated: bool,
}

/// One bounded audit ledger entry safe to expose in an activity feed.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ActivityEventSummary {
    pub sequence: u64,
    pub project_id: ProjectId,
    pub caller_id: CallerId,
    pub action: String,
    pub decision: String,
    pub outcome: String,
    pub occurred_at_ms: u64,
}

/// The complete caller registry, including revoked callers.
///
/// Credential verifiers never cross this contract.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CallerListResult {
    pub callers: Vec<CallerSummary>,
}

/// One registered caller without any credential material.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CallerSummary {
    pub caller_id: CallerId,
    pub registered_at_ms: u64,
    pub revoked_at_ms: Option<u64>,
}

/// One bounded, payload-free request summary for the native control center.
///
/// `operation_kind` is a classification label only. The stored operation body
/// and any embedded command, prompt, path, credential, or model data never
/// cross this contract.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProjectRequestSummary {
    pub request_id: RequestId,
    #[serde(deserialize_with = "deserialize_project_operation_kind")]
    operation_kind: String,
    pub state: ProjectRequestState,
    pub queue_sequence: u64,
    pub accepted_at_ms: u64,
    pub completed_at_ms: Option<u64>,
}

impl ProjectRequestSummary {
    /// Creates a request summary with a bounded, non-empty operation kind.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolContractError::InvalidProjectOperationKind`] when the
    /// classification is empty, contains a NUL, or exceeds
    /// [`MAX_PROJECT_OPERATION_KIND_BYTES`].
    pub fn new(
        request_id: RequestId,
        operation_kind: impl Into<String>,
        state: ProjectRequestState,
        queue_sequence: u64,
        accepted_at_ms: u64,
        completed_at_ms: Option<u64>,
    ) -> Result<Self, ProtocolContractError> {
        let operation_kind = operation_kind.into();
        validate_project_operation_kind(&operation_kind)?;
        Ok(Self {
            request_id,
            operation_kind,
            state,
            queue_sequence,
            accepted_at_ms,
            completed_at_ms,
        })
    }

    #[must_use]
    pub fn operation_kind(&self) -> &str {
        &self.operation_kind
    }
}

/// Stable wire projection of durable scheduler states.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProjectRequestState {
    Queued,
    Leased,
    CancellationRequested,
    Succeeded,
    Failed,
    Cancelled,
}

/// Bounded current-work snapshot for the project bound by the result envelope.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProjectCurrentResult {
    #[serde(deserialize_with = "deserialize_project_current_queued")]
    queued: Vec<ProjectRequestSummary>,
    pub active: Option<ProjectRequestSummary>,
    pub latest: Option<ProjectRequestSummary>,
    pub truncated: bool,
}

impl ProjectCurrentResult {
    /// Creates a bounded project-current result.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolContractError::ProjectCurrentQueueTooLarge`] when
    /// `queued` contains more than [`MAX_PROJECT_CURRENT_QUEUED`] summaries.
    pub fn new(
        queued: Vec<ProjectRequestSummary>,
        active: Option<ProjectRequestSummary>,
        latest: Option<ProjectRequestSummary>,
        truncated: bool,
    ) -> Result<Self, ProtocolContractError> {
        validate_project_current_queued(&queued)?;
        Ok(Self {
            queued,
            active,
            latest,
            truncated,
        })
    }

    #[must_use]
    pub fn queued(&self) -> &[ProjectRequestSummary] {
        &self.queued
    }
}

/// Human decision applied to one pending exact-effect approval challenge.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalDecision {
    Approve,
    Deny,
}

/// Terminal disposition of an approval decision request.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalDecisionDisposition {
    Approved,
    Denied,
    Expired,
}

/// Typed acknowledgement for an approval decision.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ApprovalDecisionResult {
    pub approval_id: ApprovalId,
    pub disposition: ApprovalDecisionDisposition,
}

/// Sanitized network configuration facts safe to return across the caller boundary.
///
/// The contract deliberately cannot carry proxy URLs, hosts, usernames, or
/// free-form backend diagnostics.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NetworkDiagnosticsResult {
    pub platform_roots_enabled: bool,
    pub system_proxy_discovery_enabled: bool,
    pub proxy_environment_presence: ConfigurationPresence,
    pub no_proxy_presence: ConfigurationPresence,
    pub pac_state: PacState,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfigurationPresence {
    NotConfigured,
    Configured,
    Invalid,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PacState {
    NotDetected,
    DetectedUnsupported,
    InspectionUnavailable,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Failure {
    pub code: FailureCode,
    pub message: String,
    pub recovery: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval: Option<ApprovalChallenge>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ApprovalChallenge {
    pub approval_id: ApprovalId,
    pub expires_at_unix_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureCode {
    Unauthenticated,
    Forbidden,
    ApprovalRequired,
    ApprovalDenied,
    ApprovalExpired,
    UnsupportedProtocolVersion,
    InvalidRequest,
    FrameTooLarge,
    NotFound,
    Pending,
    IdempotencyConflict,
    Cancelled,
    LeaseConflict,
    Busy,
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
    LeaseExpired,
    CancellationRequested,
    Cancelled,
    Completed,
    Failed,
    FlowTransition(pam_flow::RunTransition),
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
