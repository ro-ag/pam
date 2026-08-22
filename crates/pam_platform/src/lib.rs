#![forbid(unsafe_code)]

mod endpoint;
mod error;
mod identity;
mod network;
mod secrets;
mod transport;

#[cfg(test)]
mod endpoint_test;
#[cfg(test)]
mod identity_test;
#[cfg(test)]
mod network_test;
#[cfg(test)]
mod secrets_test;
#[cfg(test)]
mod transport_test;

pub use endpoint::{
    LAUNCH_GRANT_ENV, LAUNCH_GRANT_FILE, LocalEndpoint, consume_launch_grant, issue_launch_grant,
};
pub use error::{TransportError, TransportErrorKind};
pub use identity::{
    CallerKind, IdentityError, IdentityErrorKind, ProjectIdentity, caller_id, discover_project,
    discover_project_id, user_data_dir,
};
pub use network::{
    CertificateTrust, CorporateHttpClientError, CorporateHttpClientFactory,
    CorporateHttpClientRequirements, PacDiagnostic, ProcessProxyEnvironment, ProxyAuthentication,
    ProxyBypassDiagnostic, ProxyDiagnostic, ProxyDiagnosticStatus, ProxyDiscovery,
    ProxyEnvironment, ProxyEnvironmentValue, ProxyEnvironmentVariable, ProxyInputIssue,
    ProxyInputIssueKind, ProxyRouteDiagnostic, ProxySource, ReqwestCorporateHttpClientFactory,
    SystemPacSetting, SystemProxyFailure, SystemProxyInspection, SystemProxySetting,
    SystemProxySnapshot, SystemProxySource, UnsupportedSystemProxySource, diagnose_process_proxy,
    diagnose_proxy,
};
pub use secrets::{
    MAX_SECRET_CONTEXT_BYTES, NativeSecretBackend, SecretBackend, SecretBackendError,
    SecretLocator, SecretStore, SecretStoreError, SecretStoreErrorKind,
};
pub use transport::{ClientTransport, IncomingRequest, ServerTransport};

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum PlatformTransport {
    UnixIpc,
}

#[must_use]
pub const fn selected_transport() -> PlatformTransport {
    PlatformTransport::UnixIpc
}
