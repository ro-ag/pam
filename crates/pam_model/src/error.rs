use std::{error::Error, fmt};

#[derive(Debug)]
pub enum ModelError {
    InvalidModelIdentity,
    InvalidFilename,
    InvalidPath,
    UnsafePath,
    NotRegularFile,
    InvalidGguf,
    UnsupportedGgufVersion(u32),
    InvalidLicense,
    LicenseNotAccepted,
    InvalidSource,
    InsecureSource,
    RedirectNotAllowed,
    TooManyRedirects,
    Network,
    UnexpectedStatus(u16),
    InvalidContentEncoding,
    InvalidContentLength,
    InvalidContentRange,
    RangeIgnored,
    TransferInterrupted,
    SizeMismatch { expected: u64, actual: u64 },
    DigestMismatch,
    ExistingDestination,
    CheckpointConflict,
    ConcurrentAcquisition,
    Io(std::io::Error),
}

impl fmt::Display for ModelError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidModelIdentity => {
                formatter.write_str("model vendor and name must be safe path segments")
            }
            Self::InvalidFilename => {
                formatter.write_str("model filename must be one safe .gguf path segment")
            }
            Self::InvalidPath => formatter.write_str("model paths must be absolute Unicode paths"),
            Self::UnsafePath => formatter.write_str("model path contains an unsafe symbolic link"),
            Self::NotRegularFile => formatter.write_str("model path is not a regular file"),
            Self::InvalidGguf => {
                formatter.write_str("model file is not a valid bounded GGUF header")
            }
            Self::UnsupportedGgufVersion(version) => {
                write!(formatter, "GGUF version {version} is not supported")
            }
            Self::InvalidLicense => formatter.write_str("model license metadata is invalid"),
            Self::LicenseNotAccepted => formatter
                .write_str("the exact model descriptor and license snapshot were not accepted"),
            Self::InvalidSource => formatter.write_str("model download source is invalid"),
            Self::InsecureSource => {
                formatter.write_str("model downloads require HTTPS without embedded credentials")
            }
            Self::RedirectNotAllowed => {
                formatter.write_str("model download redirect is outside the allowed hosts")
            }
            Self::TooManyRedirects => {
                formatter.write_str("model download exceeded its redirect limit")
            }
            Self::Network => formatter
                .write_str("model download failed before a verified artifact was available"),
            Self::UnexpectedStatus(status) => {
                write!(formatter, "model download returned HTTP status {status}")
            }
            Self::InvalidContentEncoding => {
                formatter.write_str("model download used a transformed content encoding")
            }
            Self::InvalidContentLength => {
                formatter.write_str("model download declared an invalid content length")
            }
            Self::InvalidContentRange => {
                formatter.write_str("model download returned a non-contiguous content range")
            }
            Self::RangeIgnored => {
                formatter.write_str("model download could not safely resume the partial file")
            }
            Self::TransferInterrupted => {
                formatter.write_str("model download stopped before the expected byte count")
            }
            Self::SizeMismatch { expected, actual } => write!(
                formatter,
                "model size mismatch: expected {expected} bytes, received {actual}"
            ),
            Self::DigestMismatch => {
                formatter.write_str("model SHA-256 did not match the expected digest")
            }
            Self::ExistingDestination => {
                formatter.write_str("model destination already exists and was not replaced")
            }
            Self::CheckpointConflict => {
                formatter.write_str("partial download belongs to different model metadata")
            }
            Self::ConcurrentAcquisition => {
                formatter.write_str("another acquisition already owns this model partial")
            }
            Self::Io(_) => formatter.write_str("model storage is unavailable"),
        }
    }
}

impl Error for ModelError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

impl From<std::io::Error> for ModelError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}
