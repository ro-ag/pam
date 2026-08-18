#![forbid(unsafe_code)]

mod codec;
mod contract;

#[cfg(test)]
mod codec_test;
#[cfg(test)]
mod contract_test;

pub use codec::{
    CodecError, decode_request, decode_request_envelope, decode_server_message, encode,
};
pub use contract::{
    Capability, Event, EventEnvelope, Failure, FailureCode, OperationTruth, RequestEnvelope,
    RequestPayload, ResultBody, ResultEnvelope, ResultPayload, ServerMessage, StatusResult,
};

pub const PROTOCOL_VERSION: u16 = 1;
pub const MAX_FRAME_SIZE: usize = 1024 * 1024;
