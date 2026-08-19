use std::collections::HashMap;

use super::network::{
    CertificateTrust, CorporateHttpClientError, CorporateHttpClientFactory,
    CorporateHttpClientRequirements, PacDiagnostic, ProxyAuthentication, ProxyBypassDiagnostic,
    ProxyDiagnosticStatus, ProxyDiscovery, ProxyEnvironment, ProxyEnvironmentValue,
    ProxyEnvironmentVariable, ProxyInputIssue, ProxyInputIssueKind, ProxyRouteDiagnostic,
    ProxySource, ReqwestCorporateHttpClientFactory, SystemPacSetting, SystemProxyFailure,
    SystemProxyInspection, SystemProxySetting, SystemProxySnapshot, SystemProxySource,
    diagnose_proxy,
};

#[derive(Debug, Default)]
struct FakeEnvironment {
    values: HashMap<ProxyEnvironmentVariable, ProxyEnvironmentValue>,
}

impl FakeEnvironment {
    fn with(mut self, variable: ProxyEnvironmentVariable, value: ProxyEnvironmentValue) -> Self {
        self.values.insert(variable, value);
        self
    }
}

impl ProxyEnvironment for FakeEnvironment {
    fn read(&self, variable: ProxyEnvironmentVariable) -> ProxyEnvironmentValue {
        self.values
            .get(&variable)
            .cloned()
            .unwrap_or_else(ProxyEnvironmentValue::missing)
    }
}

#[derive(Debug)]
struct FakeSystemProxy {
    inspection: SystemProxyInspection,
    raw_error_that_must_not_escape: Option<&'static str>,
}

impl FakeSystemProxy {
    fn direct() -> Self {
        Self {
            inspection: SystemProxyInspection::Snapshot(SystemProxySnapshot::direct()),
            raw_error_that_must_not_escape: None,
        }
    }
}

impl SystemProxySource for FakeSystemProxy {
    fn inspect(&self) -> SystemProxyInspection {
        let _ = self.raw_error_that_must_not_escape;
        self.inspection
    }
}

#[test]
fn upper_case_specific_proxy_wins_without_exposing_endpoint_or_credentials() {
    let environment = FakeEnvironment::default()
        .with(
            ProxyEnvironmentVariable::HttpProxyUpper,
            ProxyEnvironmentValue::text("http://agent:secret@private.proxy.example:8443"),
        )
        .with(
            ProxyEnvironmentVariable::HttpProxyLower,
            ProxyEnvironmentValue::text("http://ignored-lower.example:8080"),
        )
        .with(
            ProxyEnvironmentVariable::AllProxyUpper,
            ProxyEnvironmentValue::text("http://ignored-all.example:8080"),
        );

    let diagnostic = diagnose_proxy(&environment, &FakeSystemProxy::direct());

    assert_eq!(
        diagnostic.http,
        ProxyRouteDiagnostic::Configured {
            source: ProxySource::Environment(ProxyEnvironmentVariable::HttpProxyUpper),
            authentication: ProxyAuthentication::Present,
        }
    );
    assert_eq!(diagnostic.status, ProxyDiagnosticStatus::Observed);
    let rendered = format!("{diagnostic:?}");
    for sensitive in [
        "agent",
        "secret",
        "private.proxy",
        "ignored-lower",
        "ignored-all",
    ] {
        assert!(!rendered.contains(sensitive));
    }
}

#[test]
fn lower_case_specific_and_all_proxy_fallback_follow_declared_precedence() {
    let environment = FakeEnvironment::default()
        .with(
            ProxyEnvironmentVariable::HttpProxyLower,
            ProxyEnvironmentValue::text("http://http.proxy.example:8080"),
        )
        .with(
            ProxyEnvironmentVariable::AllProxyLower,
            ProxyEnvironmentValue::text("socks5://all.proxy.example:1080"),
        );

    let diagnostic = diagnose_proxy(&environment, &FakeSystemProxy::direct());

    assert_eq!(
        diagnostic.http,
        ProxyRouteDiagnostic::Configured {
            source: ProxySource::Environment(ProxyEnvironmentVariable::HttpProxyLower),
            authentication: ProxyAuthentication::Absent,
        }
    );
    assert_eq!(
        diagnostic.https,
        ProxyRouteDiagnostic::Configured {
            source: ProxySource::Environment(ProxyEnvironmentVariable::AllProxyLower),
            authentication: ProxyAuthentication::Absent,
        }
    );
}

#[test]
fn native_scheme_proxy_precedes_all_proxy_when_specific_environment_is_absent() {
    let environment = FakeEnvironment::default().with(
        ProxyEnvironmentVariable::AllProxyUpper,
        ProxyEnvironmentValue::text("http://all.proxy.example:8080"),
    );
    let system = FakeSystemProxy {
        inspection: SystemProxyInspection::Snapshot(SystemProxySnapshot {
            http: SystemProxySetting::Configured {
                authentication: ProxyAuthentication::Unknown,
            },
            https: SystemProxySetting::NotConfigured,
            bypass_configured: false,
            pac: SystemPacSetting::NotConfigured,
        }),
        raw_error_that_must_not_escape: None,
    };

    let diagnostic = diagnose_proxy(&environment, &system);

    assert_eq!(
        diagnostic.http,
        ProxyRouteDiagnostic::Configured {
            source: ProxySource::System,
            authentication: ProxyAuthentication::Unknown,
        }
    );
    assert_eq!(
        diagnostic.https,
        ProxyRouteDiagnostic::Configured {
            source: ProxySource::Environment(ProxyEnvironmentVariable::AllProxyUpper),
            authentication: ProxyAuthentication::Absent,
        }
    );
}

#[test]
fn non_unicode_upper_variant_is_ignored_before_lower_variant() {
    let environment = FakeEnvironment::default()
        .with(
            ProxyEnvironmentVariable::HttpsProxyUpper,
            ProxyEnvironmentValue::non_unicode(),
        )
        .with(
            ProxyEnvironmentVariable::HttpsProxyLower,
            ProxyEnvironmentValue::text("https://lower.proxy.example:8443"),
        );

    let diagnostic = diagnose_proxy(&environment, &FakeSystemProxy::direct());

    assert_eq!(
        diagnostic.https,
        ProxyRouteDiagnostic::Configured {
            source: ProxySource::Environment(ProxyEnvironmentVariable::HttpsProxyLower),
            authentication: ProxyAuthentication::Absent,
        }
    );
    assert_eq!(
        diagnostic.ignored_inputs,
        vec![ProxyInputIssue {
            variable: ProxyEnvironmentVariable::HttpsProxyUpper,
            kind: ProxyInputIssueKind::NonUnicode,
        }]
    );
    assert!(!format!("{diagnostic:?}").contains("lower.proxy"));
}

#[test]
fn malformed_specific_proxy_falls_back_to_all_without_echoing_controls() {
    let environment = FakeEnvironment::default()
        .with(
            ProxyEnvironmentVariable::HttpProxyUpper,
            ProxyEnvironmentValue::text("http://private.proxy\r\nInjected: secret"),
        )
        .with(
            ProxyEnvironmentVariable::AllProxyUpper,
            ProxyEnvironmentValue::text("http://fallback.proxy.example:8080"),
        );

    let diagnostic = diagnose_proxy(&environment, &FakeSystemProxy::direct());

    assert_eq!(
        diagnostic.http,
        ProxyRouteDiagnostic::Configured {
            source: ProxySource::Environment(ProxyEnvironmentVariable::AllProxyUpper),
            authentication: ProxyAuthentication::Absent,
        }
    );
    assert!(diagnostic.ignored_inputs.contains(&ProxyInputIssue {
        variable: ProxyEnvironmentVariable::HttpProxyUpper,
        kind: ProxyInputIssueKind::Malformed,
    }));
    let rendered = format!("{diagnostic:?}");
    assert!(!rendered.contains("Injected"));
    assert!(!rendered.contains("fallback.proxy"));
    assert!(!rendered.contains('\r'));
    assert!(!rendered.contains('\n'));
}

#[test]
fn nonempty_malformed_specific_proxy_blocks_native_scheme_fallback() {
    let environment = FakeEnvironment::default().with(
        ProxyEnvironmentVariable::HttpProxyUpper,
        ProxyEnvironmentValue::text("invalid://private.proxy.example"),
    );
    let system = FakeSystemProxy {
        inspection: SystemProxyInspection::Snapshot(SystemProxySnapshot {
            http: SystemProxySetting::Configured {
                authentication: ProxyAuthentication::Unknown,
            },
            ..SystemProxySnapshot::direct()
        }),
        raw_error_that_must_not_escape: None,
    };

    let diagnostic = diagnose_proxy(&environment, &system);

    assert_eq!(diagnostic.http, ProxyRouteDiagnostic::Direct);
    assert!(diagnostic.ignored_inputs.contains(&ProxyInputIssue {
        variable: ProxyEnvironmentVariable::HttpProxyUpper,
        kind: ProxyInputIssueKind::Malformed,
    }));
    assert!(!format!("{diagnostic:?}").contains("private.proxy"));
}

#[test]
fn no_proxy_is_reported_by_presence_only() {
    let environment = FakeEnvironment::default().with(
        ProxyEnvironmentVariable::NoProxyUpper,
        ProxyEnvironmentValue::text("localhost,.internal.example,10.0.0.0/8"),
    );

    let diagnostic = diagnose_proxy(&environment, &FakeSystemProxy::direct());

    assert_eq!(
        diagnostic.bypass,
        ProxyBypassDiagnostic::Configured {
            source: ProxySource::Environment(ProxyEnvironmentVariable::NoProxyUpper),
        }
    );
    let rendered = format!("{diagnostic:?}");
    assert!(!rendered.contains("internal.example"));
    assert!(!rendered.contains("10.0.0.0"));
}

#[test]
fn malformed_no_proxy_is_typed_and_redacted() {
    let environment = FakeEnvironment::default().with(
        ProxyEnvironmentVariable::NoProxyLower,
        ProxyEnvironmentValue::text("private.example\r\nsecret"),
    );

    let diagnostic = diagnose_proxy(&environment, &FakeSystemProxy::direct());

    assert_eq!(
        diagnostic.bypass,
        ProxyBypassDiagnostic::Malformed {
            source: ProxySource::Environment(ProxyEnvironmentVariable::NoProxyLower),
        }
    );
    assert_eq!(
        diagnostic.ignored_inputs,
        vec![ProxyInputIssue {
            variable: ProxyEnvironmentVariable::NoProxyLower,
            kind: ProxyInputIssueKind::Malformed,
        }]
    );
    assert!(!format!("{diagnostic:?}").contains("private.example"));
}

#[test]
fn cgi_request_method_suppresses_environment_and_system_proxy_routes() {
    let environment = FakeEnvironment::default()
        .with(
            ProxyEnvironmentVariable::RequestMethod,
            ProxyEnvironmentValue::text("GET"),
        )
        .with(
            ProxyEnvironmentVariable::HttpsProxyUpper,
            ProxyEnvironmentValue::text("https://secret.proxy.example"),
        );
    let system = FakeSystemProxy {
        inspection: SystemProxyInspection::Snapshot(SystemProxySnapshot {
            http: SystemProxySetting::Configured {
                authentication: ProxyAuthentication::Unknown,
            },
            https: SystemProxySetting::Configured {
                authentication: ProxyAuthentication::Unknown,
            },
            bypass_configured: true,
            pac: SystemPacSetting::NotConfigured,
        }),
        raw_error_that_must_not_escape: None,
    };

    let diagnostic = diagnose_proxy(&environment, &system);

    assert_eq!(diagnostic.status, ProxyDiagnosticStatus::SuppressedByCgi);
    assert_eq!(diagnostic.http, ProxyRouteDiagnostic::SuppressedByCgi);
    assert_eq!(diagnostic.https, ProxyRouteDiagnostic::SuppressedByCgi);
    assert_eq!(diagnostic.bypass, ProxyBypassDiagnostic::SuppressedByCgi);
    assert!(!format!("{diagnostic:?}").contains("secret.proxy"));
}

#[test]
fn pac_is_detected_but_never_reported_as_evaluated() {
    let system = FakeSystemProxy {
        inspection: SystemProxyInspection::Snapshot(SystemProxySnapshot {
            pac: SystemPacSetting::Configured,
            ..SystemProxySnapshot::direct()
        }),
        raw_error_that_must_not_escape: None,
    };

    let diagnostic = diagnose_proxy(&FakeEnvironment::default(), &system);

    assert_eq!(diagnostic.pac, PacDiagnostic::DetectedButUnsupported);
    assert_eq!(diagnostic.status, ProxyDiagnosticStatus::UnresolvedPac);
}

#[test]
fn native_inspection_failure_drops_raw_backend_error() {
    let system = FakeSystemProxy {
        inspection: SystemProxyInspection::Unavailable(SystemProxyFailure::AccessDenied),
        raw_error_that_must_not_escape: Some(
            "proxy private.proxy.example rejected agent:secret and certificate bytes deadbeef",
        ),
    };

    let diagnostic = diagnose_proxy(&FakeEnvironment::default(), &system);

    assert_eq!(diagnostic.status, ProxyDiagnosticStatus::UnresolvedSystem);
    assert_eq!(
        diagnostic.pac,
        PacDiagnostic::InspectionUnavailable(SystemProxyFailure::AccessDenied)
    );
    assert_eq!(
        diagnostic.http,
        ProxyRouteDiagnostic::Unresolved(SystemProxyFailure::AccessDenied)
    );
    let rendered = format!("{diagnostic:?}");
    for sensitive in ["private.proxy", "agent", "secret", "deadbeef"] {
        assert!(!rendered.contains(sensitive));
    }
}

#[test]
fn injected_environment_values_have_redacted_debug_output() {
    let text = ProxyEnvironmentValue::text("http://agent:secret@private.proxy.example");
    let non_unicode = ProxyEnvironmentValue::non_unicode();

    assert_eq!(format!("{text:?}"), "Text([redacted])");
    assert_eq!(format!("{non_unicode:?}"), "NonUnicode([redacted])");
}

#[derive(Debug)]
struct FakeHttpClient;

#[derive(Debug)]
struct FakeHttpClientFactory;

impl CorporateHttpClientFactory for FakeHttpClientFactory {
    type Client = FakeHttpClient;

    fn build(
        &self,
        requirements: CorporateHttpClientRequirements,
    ) -> Result<Self::Client, CorporateHttpClientError> {
        assert_eq!(
            requirements,
            CorporateHttpClientRequirements {
                certificate_trust: CertificateTrust::NativePlatform,
                proxy_discovery: ProxyDiscovery::EnvironmentThenSystem,
            }
        );
        Ok(FakeHttpClient)
    }
}

#[test]
fn corporate_http_factory_seam_requires_native_trust_and_system_proxy_discovery() {
    let factory = FakeHttpClientFactory;

    let client = factory.build(CorporateHttpClientRequirements::secure_default());

    assert!(client.is_ok());
}

#[test]
fn reqwest_corporate_factory_builds_without_network_access() {
    let client =
        ReqwestCorporateHttpClientFactory.build(CorporateHttpClientRequirements::secure_default());

    assert!(client.is_ok());
}
