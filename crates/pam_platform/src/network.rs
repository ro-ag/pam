use std::{env, error::Error, fmt, time::Duration};

const CORPORATE_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const CORPORATE_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Environment variables consulted by the proxy resolver, in explicit precedence order.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ProxyEnvironmentVariable {
    RequestMethod,
    HttpProxyUpper,
    HttpProxyLower,
    HttpsProxyUpper,
    HttpsProxyLower,
    AllProxyUpper,
    AllProxyLower,
    NoProxyUpper,
    NoProxyLower,
}

impl ProxyEnvironmentVariable {
    const fn name(self) -> &'static str {
        match self {
            Self::RequestMethod => "REQUEST_METHOD",
            Self::HttpProxyUpper => "HTTP_PROXY",
            Self::HttpProxyLower => "http_proxy",
            Self::HttpsProxyUpper => "HTTPS_PROXY",
            Self::HttpsProxyLower => "https_proxy",
            Self::AllProxyUpper => "ALL_PROXY",
            Self::AllProxyLower => "all_proxy",
            Self::NoProxyUpper => "NO_PROXY",
            Self::NoProxyLower => "no_proxy",
        }
    }
}

/// A proxy-related environment value with a deliberately redacted debug representation.
#[derive(Clone, Eq, PartialEq)]
pub struct ProxyEnvironmentValue {
    kind: ProxyEnvironmentValueKind,
}

#[derive(Clone, Eq, PartialEq)]
enum ProxyEnvironmentValueKind {
    Missing,
    Text(String),
    NonUnicode,
}

impl ProxyEnvironmentValue {
    #[must_use]
    pub const fn missing() -> Self {
        Self {
            kind: ProxyEnvironmentValueKind::Missing,
        }
    }

    #[must_use]
    pub fn text(value: impl Into<String>) -> Self {
        Self {
            kind: ProxyEnvironmentValueKind::Text(value.into()),
        }
    }

    #[must_use]
    pub const fn non_unicode() -> Self {
        Self {
            kind: ProxyEnvironmentValueKind::NonUnicode,
        }
    }

    const fn is_present(&self) -> bool {
        !matches!(self.kind, ProxyEnvironmentValueKind::Missing)
    }
}

impl fmt::Debug for ProxyEnvironmentValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.kind {
            ProxyEnvironmentValueKind::Missing => formatter.write_str("Missing"),
            ProxyEnvironmentValueKind::Text(_) => formatter.write_str("Text([redacted])"),
            ProxyEnvironmentValueKind::NonUnicode => formatter.write_str("NonUnicode([redacted])"),
        }
    }
}

/// Injectable source for proxy-related environment state.
pub trait ProxyEnvironment: Send + Sync {
    #[must_use]
    fn read(&self, variable: ProxyEnvironmentVariable) -> ProxyEnvironmentValue;
}

/// The current process environment.
#[derive(Clone, Copy, Debug, Default)]
pub struct ProcessProxyEnvironment;

impl ProxyEnvironment for ProcessProxyEnvironment {
    fn read(&self, variable: ProxyEnvironmentVariable) -> ProxyEnvironmentValue {
        match env::var_os(variable.name()) {
            None => ProxyEnvironmentValue::missing(),
            Some(value) => match value.into_string() {
                Ok(text) => ProxyEnvironmentValue::text(text),
                Err(_) => ProxyEnvironmentValue::non_unicode(),
            },
        }
    }
}

/// Whether a proxy endpoint is known to carry authentication material.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProxyAuthentication {
    Absent,
    Present,
    Unknown,
}

/// Sanitized platform proxy state for one URL scheme.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SystemProxySetting {
    NotConfigured,
    Configured { authentication: ProxyAuthentication },
    Malformed,
}

/// Sanitized platform PAC state. A PAC URL or script must never enter this model.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SystemPacSetting {
    NotConfigured,
    Configured,
}

/// A sanitized snapshot produced by a platform-specific proxy adapter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SystemProxySnapshot {
    pub http: SystemProxySetting,
    pub https: SystemProxySetting,
    pub bypass_configured: bool,
    pub pac: SystemPacSetting,
}

impl SystemProxySnapshot {
    #[must_use]
    pub const fn direct() -> Self {
        Self {
            http: SystemProxySetting::NotConfigured,
            https: SystemProxySetting::NotConfigured,
            bypass_configured: false,
            pac: SystemPacSetting::NotConfigured,
        }
    }
}

/// Stable, non-sensitive reasons why native proxy inspection was unavailable.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SystemProxyFailure {
    UnsupportedPlatform,
    AccessDenied,
    TemporarilyUnavailable,
    InvalidConfiguration,
}

/// Result returned by a native proxy adapter; it cannot carry a raw backend error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SystemProxyInspection {
    Snapshot(SystemProxySnapshot),
    Unavailable(SystemProxyFailure),
}

/// Injectable native proxy configuration source.
pub trait SystemProxySource: Send + Sync {
    #[must_use]
    fn inspect(&self) -> SystemProxyInspection;
}

/// A conservative source for platforms without a native adapter.
#[derive(Clone, Copy, Debug, Default)]
pub struct UnsupportedSystemProxySource;

impl SystemProxySource for UnsupportedSystemProxySource {
    fn inspect(&self) -> SystemProxyInspection {
        SystemProxyInspection::Unavailable(SystemProxyFailure::UnsupportedPlatform)
    }
}

/// The sanitized origin of an effective proxy route.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProxySource {
    Environment(ProxyEnvironmentVariable),
    System,
}

/// Effective proxy disposition for one URL scheme.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProxyRouteDiagnostic {
    Direct,
    Configured {
        source: ProxySource,
        authentication: ProxyAuthentication,
    },
    SuppressedByCgi,
    Unresolved(SystemProxyFailure),
    InvalidSystemConfiguration,
}

/// Sanitized state of a proxy bypass list.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProxyBypassDiagnostic {
    NotConfigured,
    Configured { source: ProxySource },
    SuppressedByCgi,
    Malformed { source: ProxySource },
    Unresolved(SystemProxyFailure),
}

/// PAC state reported without exposing its URL, script, or discovered destinations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PacDiagnostic {
    NotDetected,
    DetectedButUnsupported,
    InspectionUnavailable(SystemProxyFailure),
}

/// Overall truthfulness classification for proxy diagnosis.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProxyDiagnosticStatus {
    Observed,
    SuppressedByCgi,
    UnresolvedPac,
    UnresolvedSystem,
}

/// Sanitized reason an environment input was ignored.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProxyInputIssueKind {
    Malformed,
    NonUnicode,
}

/// An ignored proxy input identified only by variable name and safe reason code.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProxyInputIssue {
    pub variable: ProxyEnvironmentVariable,
    pub kind: ProxyInputIssueKind,
}

/// A complete sanitized proxy diagnostic snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProxyDiagnostic {
    pub status: ProxyDiagnosticStatus,
    pub http: ProxyRouteDiagnostic,
    pub https: ProxyRouteDiagnostic,
    pub bypass: ProxyBypassDiagnostic,
    pub pac: PacDiagnostic,
    pub ignored_inputs: Vec<ProxyInputIssue>,
}

/// Produces a sanitized proxy snapshot using reqwest-compatible environment precedence.
#[must_use]
pub fn diagnose_proxy(
    environment: &dyn ProxyEnvironment,
    system: &dyn SystemProxySource,
) -> ProxyDiagnostic {
    let cgi = environment
        .read(ProxyEnvironmentVariable::RequestMethod)
        .is_present();
    let (snapshot, failure, pac) = match system.inspect() {
        SystemProxyInspection::Snapshot(snapshot) => {
            let pac = match snapshot.pac {
                SystemPacSetting::NotConfigured => PacDiagnostic::NotDetected,
                SystemPacSetting::Configured => PacDiagnostic::DetectedButUnsupported,
            };
            (Some(snapshot), None, pac)
        }
        SystemProxyInspection::Unavailable(failure) => (
            None,
            Some(failure),
            PacDiagnostic::InspectionUnavailable(failure),
        ),
    };

    if cgi {
        return ProxyDiagnostic {
            status: match pac {
                PacDiagnostic::DetectedButUnsupported => ProxyDiagnosticStatus::UnresolvedPac,
                PacDiagnostic::InspectionUnavailable(_) => ProxyDiagnosticStatus::UnresolvedSystem,
                PacDiagnostic::NotDetected => ProxyDiagnosticStatus::SuppressedByCgi,
            },
            http: ProxyRouteDiagnostic::SuppressedByCgi,
            https: ProxyRouteDiagnostic::SuppressedByCgi,
            bypass: ProxyBypassDiagnostic::SuppressedByCgi,
            pac,
            ignored_inputs: Vec::new(),
        };
    }

    let mut ignored_inputs = Vec::new();
    let web_proxy = inspect_proxy_variables(
        environment,
        &[
            ProxyEnvironmentVariable::HttpProxyUpper,
            ProxyEnvironmentVariable::HttpProxyLower,
        ],
        &mut ignored_inputs,
    );
    let secure_proxy = inspect_proxy_variables(
        environment,
        &[
            ProxyEnvironmentVariable::HttpsProxyUpper,
            ProxyEnvironmentVariable::HttpsProxyLower,
        ],
        &mut ignored_inputs,
    );
    let fallback_proxy = inspect_proxy_variables(
        environment,
        &[
            ProxyEnvironmentVariable::AllProxyUpper,
            ProxyEnvironmentVariable::AllProxyLower,
        ],
        &mut ignored_inputs,
    );
    let bypass_environment = inspect_bypass_variables(environment, &mut ignored_inputs);

    let http = resolve_route(
        web_proxy,
        fallback_proxy,
        snapshot.map(|value| value.http),
        failure,
    );
    let https = resolve_route(
        secure_proxy,
        fallback_proxy,
        snapshot.map(|value| value.https),
        failure,
    );
    let bypass = resolve_bypass(
        bypass_environment,
        snapshot.map(|value| value.bypass_configured),
        failure,
    );
    let status = if matches!(pac, PacDiagnostic::DetectedButUnsupported) {
        ProxyDiagnosticStatus::UnresolvedPac
    } else if matches!(pac, PacDiagnostic::InspectionUnavailable(_))
        || route_is_unresolved(http)
        || route_is_unresolved(https)
        || matches!(bypass, ProxyBypassDiagnostic::Unresolved(_))
    {
        ProxyDiagnosticStatus::UnresolvedSystem
    } else {
        ProxyDiagnosticStatus::Observed
    };

    ProxyDiagnostic {
        status,
        http,
        https,
        bypass,
        pac,
        ignored_inputs,
    }
}

/// Diagnoses process proxy inputs without claiming unavailable native settings
/// or PAC scripts were inspected.
#[must_use]
pub fn diagnose_process_proxy() -> ProxyDiagnostic {
    diagnose_proxy(&ProcessProxyEnvironment, &UnsupportedSystemProxySource)
}

#[derive(Clone, Copy)]
enum EnvironmentProxyCandidate {
    Missing,
    Invalid,
    Configured {
        variable: ProxyEnvironmentVariable,
        authentication: ProxyAuthentication,
    },
}

#[derive(Clone, Copy)]
enum EnvironmentBypassCandidate {
    Missing,
    Configured(ProxyEnvironmentVariable),
    Malformed(ProxyEnvironmentVariable),
}

fn inspect_proxy_variables(
    environment: &dyn ProxyEnvironment,
    variables: &[ProxyEnvironmentVariable],
    ignored_inputs: &mut Vec<ProxyInputIssue>,
) -> EnvironmentProxyCandidate {
    for variable in variables {
        match environment.read(*variable).kind {
            ProxyEnvironmentValueKind::Missing => {}
            ProxyEnvironmentValueKind::NonUnicode => {
                ignored_inputs.push(ProxyInputIssue {
                    variable: *variable,
                    kind: ProxyInputIssueKind::NonUnicode,
                });
            }
            ProxyEnvironmentValueKind::Text(value) => {
                if value.is_empty() {
                    return EnvironmentProxyCandidate::Missing;
                }
                return if let Some(authentication) = inspect_proxy_value(&value) {
                    EnvironmentProxyCandidate::Configured {
                        variable: *variable,
                        authentication,
                    }
                } else {
                    ignored_inputs.push(ProxyInputIssue {
                        variable: *variable,
                        kind: ProxyInputIssueKind::Malformed,
                    });
                    EnvironmentProxyCandidate::Invalid
                };
            }
        }
    }
    EnvironmentProxyCandidate::Missing
}

fn inspect_bypass_variables(
    environment: &dyn ProxyEnvironment,
    ignored_inputs: &mut Vec<ProxyInputIssue>,
) -> EnvironmentBypassCandidate {
    for variable in [
        ProxyEnvironmentVariable::NoProxyUpper,
        ProxyEnvironmentVariable::NoProxyLower,
    ] {
        match environment.read(variable).kind {
            ProxyEnvironmentValueKind::Missing => {}
            ProxyEnvironmentValueKind::NonUnicode => {
                ignored_inputs.push(ProxyInputIssue {
                    variable,
                    kind: ProxyInputIssueKind::NonUnicode,
                });
            }
            ProxyEnvironmentValueKind::Text(value) => {
                if value.is_empty() {
                    return EnvironmentBypassCandidate::Missing;
                }
                if !is_safe_bypass_value(&value) {
                    ignored_inputs.push(ProxyInputIssue {
                        variable,
                        kind: ProxyInputIssueKind::Malformed,
                    });
                    return EnvironmentBypassCandidate::Malformed(variable);
                }
                return EnvironmentBypassCandidate::Configured(variable);
            }
        }
    }
    EnvironmentBypassCandidate::Missing
}

fn is_safe_bypass_value(value: &str) -> bool {
    if value.chars().any(char::is_control) {
        return false;
    }

    let mut configured = false;
    for entry in value.split(',').map(str::trim) {
        if entry.is_empty() {
            continue;
        }
        configured = true;
        if entry.chars().any(char::is_whitespace) {
            return false;
        }
    }
    configured
}

fn inspect_proxy_value(value: &str) -> Option<ProxyAuthentication> {
    if value.is_empty() || contains_unsafe_text(value) {
        return None;
    }

    let authority = if let Some((scheme, remainder)) = value.split_once("://") {
        if !matches!(
            scheme.to_ascii_lowercase().as_str(),
            "http" | "https" | "socks4" | "socks4a" | "socks5" | "socks5h"
        ) {
            return None;
        }
        remainder.split(['/', '?', '#']).next()?
    } else {
        value.split(['/', '?', '#']).next()?
    };
    if authority.is_empty() {
        return None;
    }

    let (authentication, host_port) = match authority.rsplit_once('@') {
        Some((userinfo, host_port)) if !userinfo.is_empty() => {
            (ProxyAuthentication::Present, host_port)
        }
        Some(_) => return None,
        None => (ProxyAuthentication::Absent, authority),
    };
    if valid_host_port(host_port) {
        Some(authentication)
    } else {
        None
    }
}

fn contains_unsafe_text(value: &str) -> bool {
    value
        .chars()
        .any(|character| character.is_control() || character.is_whitespace())
}

fn valid_host_port(value: &str) -> bool {
    if value.is_empty() || value.contains('@') || value.contains('\\') {
        return false;
    }
    if let Some(after_open) = value.strip_prefix('[') {
        let Some((host, suffix)) = after_open.split_once(']') else {
            return false;
        };
        return !host.is_empty()
            && (suffix.is_empty() || suffix.strip_prefix(':').is_some_and(valid_port));
    }
    if value.matches(':').count() > 1 {
        return false;
    }
    match value.rsplit_once(':') {
        Some((host, port)) => !host.is_empty() && valid_port(port),
        None => !value.is_empty(),
    }
}

fn valid_port(port: &str) -> bool {
    !port.is_empty() && port.bytes().all(|byte| byte.is_ascii_digit())
}

fn resolve_route(
    specific: EnvironmentProxyCandidate,
    all: EnvironmentProxyCandidate,
    system: Option<SystemProxySetting>,
    failure: Option<SystemProxyFailure>,
) -> ProxyRouteDiagnostic {
    if let Some(route) = configured_environment_route(specific) {
        return route;
    }

    if matches!(specific, EnvironmentProxyCandidate::Invalid) {
        return configured_environment_route(all).unwrap_or(ProxyRouteDiagnostic::Direct);
    }

    match (system, failure) {
        (Some(SystemProxySetting::Configured { authentication }), _) => {
            ProxyRouteDiagnostic::Configured {
                source: ProxySource::System,
                authentication,
            }
        }
        (Some(SystemProxySetting::NotConfigured), _) => {
            configured_environment_route(all).unwrap_or(ProxyRouteDiagnostic::Direct)
        }
        (Some(SystemProxySetting::Malformed), _) => configured_environment_route(all)
            .unwrap_or(ProxyRouteDiagnostic::InvalidSystemConfiguration),
        (None, Some(failure)) => {
            configured_environment_route(all).unwrap_or(ProxyRouteDiagnostic::Unresolved(failure))
        }
        (None, None) => unreachable!("system proxy inspection always has one outcome"),
    }
}

fn configured_environment_route(
    candidate: EnvironmentProxyCandidate,
) -> Option<ProxyRouteDiagnostic> {
    match candidate {
        EnvironmentProxyCandidate::Configured {
            variable,
            authentication,
        } => Some(ProxyRouteDiagnostic::Configured {
            source: ProxySource::Environment(variable),
            authentication,
        }),
        EnvironmentProxyCandidate::Missing | EnvironmentProxyCandidate::Invalid => None,
    }
}

fn resolve_bypass(
    environment: EnvironmentBypassCandidate,
    system: Option<bool>,
    failure: Option<SystemProxyFailure>,
) -> ProxyBypassDiagnostic {
    match environment {
        EnvironmentBypassCandidate::Configured(variable) => {
            return ProxyBypassDiagnostic::Configured {
                source: ProxySource::Environment(variable),
            };
        }
        EnvironmentBypassCandidate::Malformed(variable) => {
            return ProxyBypassDiagnostic::Malformed {
                source: ProxySource::Environment(variable),
            };
        }
        EnvironmentBypassCandidate::Missing => {}
    }

    match (system, failure) {
        (Some(true), _) => ProxyBypassDiagnostic::Configured {
            source: ProxySource::System,
        },
        (Some(false), _) => ProxyBypassDiagnostic::NotConfigured,
        (None, Some(failure)) => ProxyBypassDiagnostic::Unresolved(failure),
        (None, None) => unreachable!("system proxy inspection always has one outcome"),
    }
}

const fn route_is_unresolved(route: ProxyRouteDiagnostic) -> bool {
    matches!(
        route,
        ProxyRouteDiagnostic::Unresolved(_) | ProxyRouteDiagnostic::InvalidSystemConfiguration
    )
}

/// TLS and proxy posture required from every corporate HTTP adapter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CorporateHttpClientRequirements {
    pub certificate_trust: CertificateTrust,
    pub proxy_discovery: ProxyDiscovery,
}

impl CorporateHttpClientRequirements {
    #[must_use]
    pub const fn secure_default() -> Self {
        Self {
            certificate_trust: CertificateTrust::NativePlatform,
            proxy_discovery: ProxyDiscovery::EnvironmentThenSystem,
        }
    }
}

impl Default for CorporateHttpClientRequirements {
    fn default() -> Self {
        Self::secure_default()
    }
}

/// Certificate verifier available to corporate HTTP adapters.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CertificateTrust {
    NativePlatform,
}

/// Proxy discovery mode available to corporate HTTP adapters.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProxyDiscovery {
    EnvironmentThenSystem,
}

/// Sanitized HTTP-client initialization failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CorporateHttpClientError {
    NativeTrustUnavailable,
    ProxyDiscoveryUnavailable,
    InitializationFailed,
}

impl fmt::Display for CorporateHttpClientError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NativeTrustUnavailable => {
                formatter.write_str("the operating-system certificate verifier is unavailable")
            }
            Self::ProxyDiscoveryUnavailable => {
                formatter.write_str("operating-system proxy discovery is unavailable")
            }
            Self::InitializationFailed => {
                formatter.write_str("the corporate HTTP client could not be initialized")
            }
        }
    }
}

impl Error for CorporateHttpClientError {}

/// Adapter seam for a future reqwest client using native trust and system proxy discovery.
pub trait CorporateHttpClientFactory: Send + Sync {
    type Client;

    /// Builds a client with the exact required trust and proxy posture.
    ///
    /// # Errors
    ///
    /// Returns a sanitized error when native trust, proxy discovery, or client
    /// initialization is unavailable. Implementations must not retain a raw
    /// backend error in the returned value.
    fn build(
        &self,
        requirements: CorporateHttpClientRequirements,
    ) -> Result<Self::Client, CorporateHttpClientError>;
}

/// Reqwest client factory fixed to native certificate verification and native
/// plus environment proxy discovery.
#[derive(Clone, Copy, Debug, Default)]
pub struct ReqwestCorporateHttpClientFactory;

impl CorporateHttpClientFactory for ReqwestCorporateHttpClientFactory {
    type Client = reqwest::Client;

    fn build(
        &self,
        requirements: CorporateHttpClientRequirements,
    ) -> Result<Self::Client, CorporateHttpClientError> {
        if requirements.certificate_trust != CertificateTrust::NativePlatform {
            return Err(CorporateHttpClientError::NativeTrustUnavailable);
        }
        if requirements.proxy_discovery != ProxyDiscovery::EnvironmentThenSystem {
            return Err(CorporateHttpClientError::ProxyDiscoveryUnavailable);
        }
        reqwest::Client::builder()
            .use_rustls_tls()
            .connect_timeout(CORPORATE_CONNECT_TIMEOUT)
            .timeout(CORPORATE_REQUEST_TIMEOUT)
            .build()
            .map_err(|_| CorporateHttpClientError::InitializationFailed)
    }
}
