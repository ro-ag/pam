#![forbid(unsafe_code)]

mod codec;
mod contract;

#[cfg(test)]
mod codec_test;
#[cfg(test)]
mod contract_test;

pub use codec::{
    CodecError, decode_request, decode_request_envelope, decode_server_message,
    decode_server_message_envelope, encode,
};
pub use contract::{
    ApprovalChallenge, BriefItem, BriefProvenance, BriefResult, CancellationDisposition,
    CancellationResult, Capability, ConfigurationPresence, Event, EventEnvelope, EvidenceChunk,
    EvidenceMetadata, EvidenceRedaction, EvidenceRetention, ExpectedTargetKind, Failure,
    FailureCode, FlowDefinitionDocument, FlowProjectRoot, MAX_FLOW_PROJECT_ROOT_BYTES,
    ModelFinishReason, ModelGenerationResult, ModelMessage, ModelRole, ModelUsage,
    NetworkDiagnosticsResult, OperationTruth, PacState, ProtocolContractError, ReplayResult,
    RequestEnvelope, RequestPayload, ResultBody, ResultEnvelope, ResultPayload, ServerMessage,
    SourceAvailability, StatusResult,
};

pub const PROTOCOL_VERSION: u16 = 5;
pub const MAX_FRAME_SIZE: usize = 1024 * 1024;
pub const MAX_EVIDENCE_CHUNK_SIZE: usize = 256 * 1024;
pub const MAX_MODEL_MESSAGES: usize = 32;
pub const MAX_MODEL_MESSAGE_BYTES: usize = 64 * 1024;
pub const MAX_MODEL_PROMPT_BYTES: usize = 256 * 1024;
pub const MAX_MODEL_OUTPUT_TOKENS: u32 = 4_096;
pub const MAX_MODEL_OUTPUT_BYTES: usize = 512 * 1024;
