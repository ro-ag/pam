use std::{error::Error, fmt};

use serde::{Serialize, de::DeserializeOwned};

use crate::{
    FailureCode, MAX_FRAME_SIZE, PROTOCOL_VERSION, ProtocolContractError, RequestEnvelope,
    ResultBody, ServerMessage,
};

#[derive(Debug)]
pub enum CodecError {
    FrameTooLarge { actual: usize, maximum: usize },
    Decode(rmp_serde::decode::Error),
    Encode(rmp_serde::encode::Error),
    Contract(ProtocolContractError),
    UnsupportedProtocolVersion { actual: u16, supported: u16 },
}

impl fmt::Display for CodecError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FrameTooLarge { actual, maximum } => {
                write!(formatter, "frame is {actual} bytes; maximum is {maximum}")
            }
            Self::Decode(error) => write!(formatter, "invalid MessagePack frame: {error}"),
            Self::Encode(error) => write!(formatter, "could not encode MessagePack frame: {error}"),
            Self::Contract(error) => write!(formatter, "invalid protocol contract: {error}"),
            Self::UnsupportedProtocolVersion { actual, supported } => write!(
                formatter,
                "protocol version {actual} is unsupported; supported version is {supported}"
            ),
        }
    }
}

impl Error for CodecError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Decode(error) => Some(error),
            Self::Encode(error) => Some(error),
            Self::Contract(error) => Some(error),
            Self::FrameTooLarge { .. } | Self::UnsupportedProtocolVersion { .. } => None,
        }
    }
}

/// Encodes a value as named-field `MessagePack` within the protocol frame limit.
///
/// # Errors
///
/// Returns [`CodecError::Encode`] when serialization fails or
/// [`CodecError::FrameTooLarge`] when the encoded frame exceeds the limit.
pub fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>, CodecError> {
    let bytes = rmp_serde::to_vec_named(value).map_err(CodecError::Encode)?;
    enforce_frame_limit(bytes.len())?;
    Ok(bytes)
}

/// Decodes and version-checks a request envelope.
///
/// # Errors
///
/// Returns a codec error when the frame is oversized, malformed, or uses an
/// unsupported protocol version.
pub fn decode_request(bytes: &[u8]) -> Result<RequestEnvelope, CodecError> {
    let request = decode_request_envelope(bytes)?;
    enforce_version(request.protocol_version)?;
    request
        .validate_model_request()
        .map_err(CodecError::Contract)?;
    Ok(request)
}

/// Decodes a request envelope without enforcing its application protocol version.
///
/// Daemons use this to retain request correlation when returning a typed
/// unsupported-version result.
///
/// # Errors
///
/// Returns a codec error when the frame is oversized or malformed.
pub fn decode_request_envelope(bytes: &[u8]) -> Result<RequestEnvelope, CodecError> {
    decode(bytes)
}

/// Decodes and version-checks a daemon message.
///
/// # Errors
///
/// Returns a codec error when the frame is oversized, malformed, or uses an
/// unsupported protocol version.
pub fn decode_server_message(bytes: &[u8]) -> Result<ServerMessage, CodecError> {
    let message: ServerMessage = decode(bytes)?;
    if !is_version_negotiation_failure(&message) {
        enforce_version(message.protocol_version())?;
    }
    Ok(message)
}

fn is_version_negotiation_failure(message: &ServerMessage) -> bool {
    matches!(
        message,
        ServerMessage::Result(result)
            if matches!(
                &result.body,
                ResultBody::Failure(failure)
                    if failure.code == FailureCode::UnsupportedProtocolVersion
            )
    )
}

fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, CodecError> {
    enforce_frame_limit(bytes.len())?;
    rmp_serde::from_slice(bytes).map_err(CodecError::Decode)
}

fn enforce_frame_limit(actual: usize) -> Result<(), CodecError> {
    if actual > MAX_FRAME_SIZE {
        return Err(CodecError::FrameTooLarge {
            actual,
            maximum: MAX_FRAME_SIZE,
        });
    }
    Ok(())
}

fn enforce_version(actual: u16) -> Result<(), CodecError> {
    if actual != PROTOCOL_VERSION {
        return Err(CodecError::UnsupportedProtocolVersion {
            actual,
            supported: PROTOCOL_VERSION,
        });
    }
    Ok(())
}
