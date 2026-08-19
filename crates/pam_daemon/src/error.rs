use std::{error::Error, fmt};

use pam_model::RuntimeError;
use pam_platform::{IdentityError, TransportError};
use pam_protocol::CodecError;
use pam_store::StoreError;

#[derive(Debug)]
pub enum DaemonError {
    AlreadyRunning,
    Handler(tokio::task::JoinError),
    Identity(IdentityError),
    StaleState(String),
    Io(std::io::Error),
    Model(RuntimeError),
    Protocol(CodecError),
    Store(StoreError),
    Transport(TransportError),
}

impl DaemonError {
    #[must_use]
    pub const fn recovery_action(&self) -> Option<&'static str> {
        match self {
            Self::AlreadyRunning => Some("pam status"),
            Self::StaleState(_) => Some("pam daemon --recover"),
            Self::Transport(error) => error.recovery_action(),
            Self::Handler(_)
            | Self::Identity(_)
            | Self::Io(_)
            | Self::Model(_)
            | Self::Protocol(_)
            | Self::Store(_) => None,
        }
    }
}

impl fmt::Display for DaemonError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AlreadyRunning => formatter
                .write_str("PAM daemon ownership is already claimed. Check it with `pam status`."),
            Self::Handler(_) => formatter.write_str("PAM daemon request handling failed."),
            Self::Identity(error) => error.fmt(formatter),
            Self::StaleState(_) => formatter
                .write_str("PAM daemon endpoint is stale. Recover it with `pam daemon --recover`."),
            Self::Io(_) => formatter.write_str("PAM could not prepare its local runtime state."),
            Self::Model(_) => {
                formatter.write_str("PAM could not start the embedded model runtime.")
            }
            Self::Protocol(_) => formatter.write_str("PAM could not process a protocol message."),
            Self::Store(_) => formatter.write_str("PAM durable state is unavailable."),
            Self::Transport(error) => error.fmt(formatter),
        }
    }
}

impl Error for DaemonError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Handler(error) => Some(error),
            Self::Identity(error) => Some(error),
            Self::Io(error) => Some(error),
            Self::Model(error) => Some(error),
            Self::Protocol(error) => Some(error),
            Self::Store(error) => Some(error),
            Self::Transport(error) => Some(error),
            Self::AlreadyRunning | Self::StaleState(_) => None,
        }
    }
}

impl From<TransportError> for DaemonError {
    fn from(error: TransportError) -> Self {
        Self::Transport(error)
    }
}

impl From<CodecError> for DaemonError {
    fn from(error: CodecError) -> Self {
        Self::Protocol(error)
    }
}

impl From<StoreError> for DaemonError {
    fn from(error: StoreError) -> Self {
        Self::Store(error)
    }
}

impl From<IdentityError> for DaemonError {
    fn from(error: IdentityError) -> Self {
        Self::Identity(error)
    }
}

impl From<std::io::Error> for DaemonError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<RuntimeError> for DaemonError {
    fn from(error: RuntimeError) -> Self {
        Self::Model(error)
    }
}

#[derive(Debug)]
pub enum ExchangeError {
    Correlation(String),
    DeadlineExceeded,
    EventLimitExceeded,
    Protocol(CodecError),
    Transport(TransportError),
}

impl ExchangeError {
    #[must_use]
    pub fn is_unavailable(&self) -> bool {
        matches!(
            self,
            Self::Transport(error)
                if error.kind() == pam_platform::TransportErrorKind::Unavailable
        )
    }

    #[must_use]
    pub const fn recovery_action(&self) -> Option<&'static str> {
        match self {
            Self::Transport(error) => error.recovery_action(),
            Self::Correlation(_)
            | Self::DeadlineExceeded
            | Self::EventLimitExceeded
            | Self::Protocol(_) => None,
        }
    }
}

impl fmt::Display for ExchangeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Correlation(_) => {
                formatter.write_str("PAM daemon returned an uncorrelated response.")
            }
            Self::DeadlineExceeded => formatter.write_str("PAM daemon request timed out."),
            Self::EventLimitExceeded => {
                formatter.write_str("PAM daemon response exceeded the event limit.")
            }
            Self::Protocol(_) => formatter.write_str("PAM daemon returned an invalid response."),
            Self::Transport(error) => error.fmt(formatter),
        }
    }
}

impl Error for ExchangeError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Protocol(error) => Some(error),
            Self::Transport(error) => Some(error),
            Self::Correlation(_) | Self::DeadlineExceeded | Self::EventLimitExceeded => None,
        }
    }
}

impl From<CodecError> for ExchangeError {
    fn from(error: CodecError) -> Self {
        Self::Protocol(error)
    }
}

impl From<TransportError> for ExchangeError {
    fn from(error: TransportError) -> Self {
        Self::Transport(error)
    }
}

pub type StatusError = ExchangeError;
