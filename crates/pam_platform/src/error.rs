use std::{error::Error, fmt};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransportErrorKind {
    ClientDisconnected,
    Unavailable,
    EndpointInUse,
    FrameTooLarge,
    StaleEndpoint,
    InvalidMessage,
    Internal,
}

#[derive(Debug)]
pub struct TransportError {
    kind: TransportErrorKind,
    diagnostic: String,
}

impl TransportError {
    pub(crate) fn new(kind: TransportErrorKind, diagnostic: impl Into<String>) -> Self {
        Self {
            kind,
            diagnostic: diagnostic.into(),
        }
    }

    #[must_use]
    pub const fn kind(&self) -> TransportErrorKind {
        self.kind
    }

    #[must_use]
    pub fn diagnostic(&self) -> &str {
        &self.diagnostic
    }

    #[must_use]
    pub const fn recovery_action(&self) -> Option<&'static str> {
        match self.kind {
            TransportErrorKind::Unavailable => Some("pam daemon"),
            TransportErrorKind::EndpointInUse => Some("pam status"),
            TransportErrorKind::StaleEndpoint => Some("pam gui"),
            TransportErrorKind::ClientDisconnected
            | TransportErrorKind::FrameTooLarge
            | TransportErrorKind::InvalidMessage
            | TransportErrorKind::Internal => None,
        }
    }
}

impl fmt::Display for TransportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.kind {
            TransportErrorKind::ClientDisconnected => {
                formatter.write_str("PAM client disconnected before receiving its response.")
            }
            TransportErrorKind::Unavailable => {
                formatter.write_str("PAM daemon is not reachable. Start it with `pam daemon`.")
            }
            TransportErrorKind::EndpointInUse => formatter
                .write_str("PAM daemon ownership is already claimed. Check it with `pam status`."),
            TransportErrorKind::FrameTooLarge => {
                formatter.write_str("PAM rejected an oversized local protocol message.")
            }
            TransportErrorKind::StaleEndpoint => formatter.write_str(
                "PAM daemon endpoint is stale. Restart PAM from the control center (`pam gui`).",
            ),
            TransportErrorKind::InvalidMessage => {
                formatter.write_str("PAM received an invalid local protocol message.")
            }
            TransportErrorKind::Internal => formatter.write_str("PAM local transport failed."),
        }
    }
}

impl Error for TransportError {}
