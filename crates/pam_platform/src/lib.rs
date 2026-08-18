#![forbid(unsafe_code)]

mod endpoint;
mod error;
mod identity;
mod transport;

#[cfg(test)]
mod endpoint_test;
#[cfg(test)]
mod identity_test;
#[cfg(test)]
mod transport_test;

pub use endpoint::LocalEndpoint;
pub use error::{TransportError, TransportErrorKind};
pub use identity::{
    CallerKind, IdentityError, IdentityErrorKind, ProjectIdentity, caller_id, discover_project,
    discover_project_id, user_data_dir,
};
pub use transport::{ClientTransport, IncomingRequest, ServerTransport};

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum PlatformTransport {
    UnixIpc,
    LoopbackTcp,
}

#[must_use]
pub const fn selected_transport() -> PlatformTransport {
    if cfg!(windows) {
        PlatformTransport::LoopbackTcp
    } else {
        PlatformTransport::UnixIpc
    }
}
