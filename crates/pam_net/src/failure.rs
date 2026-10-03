//! Why a request never became an answer, in words a human can act on.
//!
//! [`NetFailure`] is the vocabulary both curl consumers share: connectors,
//! downloads and the "Test network settings" action report the same cause
//! for the same situation. Each failure has a stable [`NetFailure::cause`]
//! (what the daemon stores and the GUI switches on), a
//! [`NetFailure::sentence`] (what happened) and a [`NetFailure::recovery`]
//! (what to do about it).
//!
//! Classification reads numbers before prose. curl's exit code is the first
//! signal; the launcher's `write-out` line adds the proxy's `CONNECT` status,
//! the final HTTP status, the TLS library's verify result and the number of
//! connections made. Only where no number exists — which certificate check
//! failed on a backend that reports no verify result — is curl's error text
//! matched, against the fixed tokens recorded below.
//!
//! Recorded on macOS, `/usr/bin/curl` 8.7.1 (`LibreSSL` active,
//! `SecureTransport` available), 2026-10-02:
//!
//! | Situation | exit | `http_connect` | `ssl_verify` | `num_connects` | error text |
//! | --- | --- | --- | --- | --- | --- |
//! | closed port, direct | 7 | 000 | 0 | 0 | `Failed to connect to … Couldn't connect to server` |
//! | closed proxy port | 7 | 000 | 0 | 0 | same text, naming the proxy |
//! | name does not resolve | 6 | 000 | 0 | 0 | `Could not resolve host: …` |
//! | proxy name does not resolve | 5 | 000 | 0 | 0 | `Could not resolve proxy: …` |
//! | connect timeout | 28 | 000 | 0 | 0 | `Failed to connect to … Timeout was reached` |
//! | proxy answers 407 to `CONNECT` | 56 | 407 | 0 | 1 | `CONNECT tunnel failed, response 407` |
//! | proxy answers 403 to `CONNECT` | 56 | 403 | 0 | 1 | `CONNECT tunnel failed, response 403` |
//! | issuer not in the bundle | 60 | 000 | 20 | 1 | `SSL certificate problem: unable to get local issuer certificate` |
//! | certificate expired | 60 | 000 | 10 | 1 | `SSL certificate problem: certificate has expired` |
//! | name not in the certificate | 60 | 000 | 1 | 1 | `SSL: no alternative certificate subject name matches target host name '…'` |
//! | CA file missing or not PEM | 77 | 000 | 1 | 1 | `error setting certificate verify locations: CAfile: …` (the path follows) |
//!
//! The `write-out` line is printed on failed transfers too, after curl's own
//! error line. With `verbose`, this curl prints `issuer:` and `subject:`
//! only after a *successful* verification, so an untrusted issuer cannot be
//! named on this backend; the sentence says so instead.
//!
//! Recorded on Windows 11 (build 26200, ARM64), `System32\curl.exe` 8.21.0
//! (`Schannel`), 2026-10-02. `Schannel` reports no verify result
//! (`ssl_verify=0` on every row), so these are matched on the text, which
//! names no Windows error code:
//!
//! | Situation | exit | error text |
//! | --- | --- | --- |
//! | issuer not in the store, no bundle | 60 | `schannel: SEC_E_UNTRUSTED_ROOT (0x80090325) - The certificate chain was issued by an authority that is not trusted.` |
//! | bundle of another CA | 60 | `schannel: the certificate chain is incomplete` |
//! | public site, bundle of the test CA | 60 | `schannel: the certificate or certificate chain is based on an untrusted root` |
//! | issuer in the bundle, leaf with no CRL or OCSP address | 60 | `schannel: the revocation status is unknown` |
//! | name not in the certificate (revocation not checked) | 60 | `schannel: CertGetNameString() failed to match connection hostname (…) against server certificate names` |
//! | certificate expired | 60 | `schannel: this certificate or one of the certificates in the certificate chain is not time valid` |
//! | CA file missing | 2 | `The file '…' provided to --cacert does not exist` (rejected while reading the config, so no `write-out` line) |
//! | CA file not PEM | 60 | `schannel: the certificate chain is incomplete` (no certificate was added) |
//! | closed proxy port | 7 | `Failed to connect to … over proxy … Could not connect to server` |
//!
//! With the bundle, `Schannel` checks revocation before the name, so a wrong
//! name behind a leaf with no revocation address is reported as the
//! revocation failure.

use std::fmt;

use crate::settings::{Route, SettingsError};
use crate::trusted::TlsBackend;

/// The longest excerpt of curl's own complaint kept in a failure.
const EXCERPT_CHARS: usize = 512;

/// Why a curl request produced no usable answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetFailure {
    /// The operating system's curl is missing or its ownership would let an
    /// ordinary process replace it. No process was started.
    CurlUnavailable,
    /// The trusted curl predates something the request needs.
    CurlTooOld {
        /// The version found, as `major.minor.patch`.
        found: String,
        /// The oldest version that works.
        needed: &'static str,
        /// What needs it.
        feature: &'static str,
    },
    /// The stored network settings cannot be used. Never answered by falling
    /// back to a direct connection.
    SettingsInvalid(String),
    /// The private CA bundle copy no longer matches its recorded digest.
    CaBundleTampered,
    /// A value could not be written into curl's config safely, or the
    /// request asks for something the launcher does not allow. No process
    /// was started.
    RequestInvalid {
        /// Which part of the request.
        field: &'static str,
        /// What is wrong with it.
        detail: String,
    },
    /// curl could not be started or fed its config.
    Spawn(String),
    /// The proxy's name did not resolve.
    ProxyDnsFailed {
        /// The proxy, as `host:port`.
        proxy: String,
    },
    /// Nothing accepted the connection to the proxy.
    ProxyUnreachable {
        /// The proxy, as `host:port`.
        proxy: String,
    },
    /// The proxy asked for a credential and none was sent.
    ProxyAuthRequired {
        /// The proxy, as `host:port`.
        proxy: String,
        /// The schemes the proxy offered, when the request ran in
        /// diagnostic mode (`Basic`, `NTLM`, …); otherwise empty.
        offered: Vec<String>,
    },
    /// The proxy refused the credential that was sent.
    ProxyAuthRejected {
        /// The proxy, as `host:port`.
        proxy: String,
    },
    /// The proxy answered the `CONNECT` with a refusal.
    ProxyDenied {
        /// The proxy, as `host:port`.
        proxy: String,
        /// The target the proxy would not connect to, as `host:port`.
        target: String,
        /// The proxy's status.
        status: u16,
    },
    /// The target's name did not resolve.
    DnsFailed {
        /// The target host.
        host: String,
    },
    /// Nothing accepted the connection to the target.
    ConnectFailed {
        /// The target host.
        host: String,
    },
    /// The connection to the target was not established in time.
    ConnectTimeout {
        /// The target host.
        host: String,
    },
    /// The server's certificate chains to an issuer that is not trusted.
    TlsUntrustedIssuer {
        /// The target host.
        host: String,
        /// The issuer, where this curl printed it.
        issuer: Option<String>,
        /// The TLS backend, named when the issuer could not be read.
        backend: String,
    },
    /// The certificate is not valid for the host that was asked for.
    TlsHostnameMismatch {
        /// The target host.
        host: String,
    },
    /// The certificate has expired or is not yet valid.
    TlsExpired {
        /// The target host.
        host: String,
    },
    /// Windows could not check whether the certificate is revoked.
    TlsRevocationUnavailable {
        /// The target host.
        host: String,
    },
    /// A TLS failure with no more specific cause.
    TlsFailed {
        /// The target host.
        host: String,
        /// curl's own complaint, excerpted.
        detail: String,
    },
    /// curl could not read the CA bundle it was pointed at.
    CaBundleUnreadable,
    /// curl gave up: its own time limit or its stalled-transfer limit.
    Timeout,
    /// The caller's hard deadline passed and the process was killed.
    Deadline,
    /// The answer passed the size limit.
    TooLarge {
        /// The limit that was passed, in bytes.
        maximum: u64,
    },
    /// The server answered an error status and the request asked for that
    /// to be a failure.
    HttpStatus {
        /// The status, when curl reported it.
        status: Option<u16>,
    },
    /// curl could not write the output file.
    WriteFailed,
    /// The connection broke mid-transfer.
    TransferInterrupted {
        /// curl's exit code.
        exit: i32,
    },
    /// The server would not continue from the partial file.
    ResumeUnsupported,
    /// Anything else, with curl's exit code and complaint.
    Other {
        /// curl's exit code; `None` when it was ended by a signal.
        exit: Option<i32>,
        /// curl's own complaint, one line, excerpted.
        detail: String,
    },
}

impl NetFailure {
    /// The stable cause: what is stored on a job row, put in an audit
    /// detail, and switched on by the GUI.
    #[must_use]
    pub fn cause(&self) -> &'static str {
        match self {
            Self::CurlUnavailable => "curl_unavailable",
            Self::CurlTooOld { .. } => "curl_too_old",
            Self::SettingsInvalid(_) => "network_settings_invalid",
            Self::CaBundleTampered => "network_ca_tampered",
            Self::RequestInvalid { .. } => "request_invalid",
            Self::Spawn(_) => "curl_spawn_failed",
            Self::ProxyDnsFailed { .. } => "proxy_dns_failed",
            Self::ProxyUnreachable { .. } => "proxy_unreachable",
            Self::ProxyAuthRequired { .. } => "proxy_auth_required",
            Self::ProxyAuthRejected { .. } => "proxy_auth_rejected",
            Self::ProxyDenied { .. } => "proxy_denied",
            Self::DnsFailed { .. } => "dns_failed",
            Self::ConnectFailed { .. } => "connect_failed",
            Self::ConnectTimeout { .. } => "connect_timeout",
            Self::TlsUntrustedIssuer { .. } => "tls_untrusted_issuer",
            Self::TlsHostnameMismatch { .. } => "tls_hostname_mismatch",
            Self::TlsExpired { .. } => "tls_expired",
            Self::TlsRevocationUnavailable { .. } => "tls_revocation_unavailable",
            Self::TlsFailed { .. } => "tls_error",
            Self::CaBundleUnreadable => "ca_bundle_unreadable",
            Self::Timeout => "timeout",
            Self::Deadline => "deadline",
            Self::TooLarge { .. } => "too_large",
            Self::HttpStatus { .. } => "http_error",
            Self::WriteFailed => "disk_error",
            Self::TransferInterrupted { .. } => "transfer_interrupted",
            Self::ResumeUnsupported => "resume_unsupported",
            Self::Other { .. } => "curl_failed",
        }
    }

    /// What happened, as one sentence for a human.
    #[must_use]
    pub fn sentence(&self) -> String {
        match self {
            Self::CurlUnavailable => {
                "A trusted operating-system curl is unavailable; no request was started.".to_owned()
            }
            Self::CurlTooOld {
                found,
                needed,
                feature,
            } => {
                format!("This computer's curl is {found}; {feature} needs curl {needed} or newer.")
            }
            Self::SettingsInvalid(detail) => {
                format!("The network settings cannot be used: {detail}")
            }
            Self::CaBundleTampered => {
                "PAM's copy of the CA bundle changed since it was imported; the request was not \
                 sent."
                    .to_owned()
            }
            Self::RequestInvalid { field, detail } => {
                format!("The request was not sent: {field}: {detail}")
            }
            Self::Spawn(detail) => format!("curl could not run: {detail}"),
            Self::CaBundleUnreadable => {
                "curl could not read PAM's copy of the CA bundle.".to_owned()
            }
            Self::Timeout => "The request timed out.".to_owned(),
            Self::Deadline => "The request passed its deadline and was stopped.".to_owned(),
            Self::TooLarge { maximum } => format!("The response passed the {maximum} byte limit."),
            Self::HttpStatus {
                status: Some(status),
            } => format!("The server answered HTTP {status}."),
            Self::HttpStatus { status: None } => {
                "The server answered an HTTP error status.".to_owned()
            }
            Self::WriteFailed => "curl could not write the output file.".to_owned(),
            Self::TransferInterrupted { exit } => {
                format!("The connection broke mid-transfer (curl exit {exit}).")
            }
            Self::ResumeUnsupported => {
                "The server would not continue from the partial file.".to_owned()
            }
            Self::Other {
                exit: Some(exit),
                detail,
            } => format!("curl exited {exit}: {detail}"),
            Self::Other { exit: None, detail } => {
                format!("curl was terminated before it answered: {detail}")
            }
            _ => self.path_sentence(),
        }
    }

    /// The sentences about the path to the host: proxy, name, connection,
    /// certificate.
    fn path_sentence(&self) -> String {
        match self {
            Self::ProxyDnsFailed { proxy } => format!("The proxy name in {proxy} did not resolve."),
            Self::ProxyUnreachable { proxy } => {
                format!("Nothing accepted the connection at {proxy}.")
            }
            Self::ProxyAuthRequired { proxy, offered } if offered.is_empty() => {
                format!("The proxy {proxy} wants authentication.")
            }
            Self::ProxyAuthRequired { proxy, offered } => format!(
                "The proxy {proxy} wants authentication. It offers: {}.",
                offered.join(", ")
            ),
            Self::ProxyAuthRejected { proxy } => {
                format!("The proxy {proxy} refused the stored user name and password.")
            }
            Self::ProxyDenied {
                proxy,
                target,
                status,
            } => format!("The proxy {proxy} refused to connect to {target} (HTTP {status})."),
            Self::DnsFailed { host } => format!("{host} did not resolve."),
            Self::ConnectFailed { host } => format!("Nothing accepted the connection to {host}."),
            Self::ConnectTimeout { host } => {
                format!("The connection to {host} was not established in time.")
            }
            Self::TlsUntrustedIssuer {
                host,
                issuer: Some(issuer),
                ..
            } => format!("The certificate of {host} was issued by {issuer}, which is not trusted."),
            Self::TlsUntrustedIssuer {
                host,
                issuer: None,
                backend,
            } => format!(
                "The certificate of {host} was issued by an authority that is not trusted; the \
                 issuer could not be read from this curl ({backend})."
            ),
            Self::TlsHostnameMismatch { host } => {
                format!("The certificate is not valid for {host}.")
            }
            Self::TlsExpired { host } => {
                format!("The certificate of {host} has expired or is not yet valid.")
            }
            Self::TlsRevocationUnavailable { host } => format!(
                "Windows could not check whether the certificate of {host} is revoked (no \
                 reachable revocation list)."
            ),
            Self::TlsFailed { host, detail } => {
                format!("The TLS connection to {host} failed: {detail}")
            }
            // Every other variant is sentenced by `sentence` itself.
            _ => self.cause().replace('_', " "),
        }
    }

    /// What to do about it, as one sentence.
    #[must_use]
    pub fn recovery(&self) -> &'static str {
        match self {
            Self::CurlUnavailable => curl_install_line(),
            Self::CurlTooOld { .. } => {
                "Update the operating system so its curl is current, or remove the setting that \
                 needs the newer version."
            }
            Self::SettingsInvalid(_) => {
                "Open Settings › Network, correct the setting named here and save."
            }
            Self::CaBundleTampered | Self::CaBundleUnreadable => {
                "Re-import the CA bundle in Settings › Network."
            }
            Self::RequestInvalid { .. } => "Correct the value named here; nothing was sent.",
            Self::Spawn(_) => "Check that this computer can start programs, then try again.",
            Self::ProxyDnsFailed { .. } => {
                "Check the proxy address in Settings › Network and this computer's DNS or VPN."
            }
            Self::ProxyUnreachable { .. } => {
                "Check the proxy host and port in Settings › Network and that this computer is on \
                 the network the proxy serves."
            }
            Self::ProxyAuthRequired { .. } => {
                "Set the proxy sign-in mode, user name and password in Settings › Network."
            }
            Self::ProxyAuthRejected { .. } => {
                "Re-enter the proxy user name and password in Settings › Network; with NTLM the \
                 user name is DOMAIN\\user."
            }
            Self::ProxyDenied { .. } => {
                "Ask the proxy's administrator to allow this host, or add an internal host to the \
                 no-proxy list in Settings › Network."
            }
            Self::DnsFailed { .. } => {
                "Check the address, this computer's DNS and any VPN; if the name only resolves \
                 through the proxy, remove it from the no-proxy list."
            }
            Self::ConnectFailed { .. } | Self::ConnectTimeout { .. } => {
                "Check the address and that this network allows a direct connection; if it must \
                 leave through a proxy, set one in Settings › Network."
            }
            Self::TlsUntrustedIssuer { .. } => {
                "If your organisation inspects TLS, import its root CA in Settings › Network, or \
                 ask IT to deploy it to this computer's trust store."
            }
            Self::TlsHostnameMismatch { .. } => {
                "Check the address; if a proxy inspects TLS, ask its administrator why it presents \
                 a certificate for another name."
            }
            Self::TlsExpired { .. } => {
                "Check this computer's clock; otherwise the service's certificate needs renewing."
            }
            Self::TlsRevocationUnavailable { .. } => {
                "Publish the CA's CRL over http so this computer can reach it, or install the CA \
                 in the operating system's certificate store."
            }
            Self::TlsFailed { .. } => {
                "Check this computer's clock and certificate trust, and any proxy that inspects \
                 TLS, then try again."
            }
            Self::Timeout | Self::Deadline => {
                "Try again; if it keeps happening, check the network path with Test network \
                 settings."
            }
            Self::TooLarge { .. } => "Narrow the request so the answer is smaller.",
            Self::HttpStatus { .. } => {
                "The network path works; the service refused the request itself."
            }
            Self::WriteFailed => "Check free space and permissions on the destination, then retry.",
            Self::TransferInterrupted { .. } => {
                "Try again; a partial download is kept and resumes from where it stopped."
            }
            Self::ResumeUnsupported => "Discard the partial download and start it over.",
            Self::Other { .. } => {
                "Run Test network settings in Settings › Network to see where the request stops."
            }
        }
    }
}

impl fmt::Display for NetFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.sentence())
    }
}

impl std::error::Error for NetFailure {}

impl From<SettingsError> for NetFailure {
    fn from(error: SettingsError) -> Self {
        Self::SettingsInvalid(error.to_string())
    }
}

/// How to get curl on this platform, in one sentence.
#[must_use]
pub fn curl_install_line() -> &'static str {
    #[cfg(target_os = "windows")]
    {
        "curl.exe ships with Windows 10 1803 and newer in System32; repair Windows if it is missing."
    }
    #[cfg(not(target_os = "windows"))]
    {
        "curl ships with macOS at /usr/bin/curl; reinstall the operating system's command line \
         tools if it is missing."
    }
}

/// What the launcher's `write-out` line reported for one transfer.
///
/// Every field is `None` when curl printed no line (it was killed, or it is
/// too old to print one) or printed curl's "nothing happened" zero.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Diagnostics {
    /// The proxy's status for the last `CONNECT`.
    pub http_connect: Option<u16>,
    /// The status of the final response.
    pub http_code: Option<u16>,
    /// The TLS library's verify result; meaningful on OpenSSL-family
    /// backends, always absent on `Schannel`.
    pub ssl_verify: Option<u32>,
    /// How many connections curl opened. `Some(0)` means not even the first
    /// TCP connection was established.
    pub num_connects: Option<u32>,
}

impl Diagnostics {
    /// Reads a `pam-net key=value …` line. Unknown keys are ignored, so the
    /// line can grow.
    pub(crate) fn parse(line: &str) -> Self {
        let mut parsed = Self::default();
        for pair in line.split_whitespace() {
            let Some((key, value)) = pair.split_once('=') else {
                continue;
            };
            match key {
                "http_connect" => parsed.http_connect = value.parse().ok().filter(|v| *v != 0),
                "http_code" => parsed.http_code = value.parse().ok().filter(|v| *v != 0),
                "ssl_verify" => parsed.ssl_verify = value.parse().ok().filter(|v| *v != 0),
                "num_connects" => parsed.num_connects = value.parse().ok(),
                _ => {}
            }
        }
        parsed
    }
}

/// Everything classification looks at for one failed transfer.
pub(crate) struct Transfer<'a> {
    /// curl's exit code; `None` when a signal ended it.
    pub exit: Option<i32>,
    /// curl's own error lines (never verbose output).
    pub stderr: &'a str,
    pub diagnostics: Diagnostics,
    /// The route the launcher chose for the first hop.
    pub route: &'a Route,
    pub target_host: &'a str,
    pub target_port: u16,
    pub credential_sent: bool,
    pub cacert_set: bool,
    pub backend: &'a TlsBackend,
    pub max_filesize: Option<u64>,
    /// `Proxy-Authenticate` schemes seen in diagnostic mode.
    pub offered: &'a [String],
    /// The certificate issuer seen in diagnostic mode.
    pub issuer: Option<&'a str>,
}

/// Names the failure for a curl run that did not exit zero.
pub(crate) fn classify(transfer: &Transfer<'_>) -> NetFailure {
    let proxy = match transfer.route {
        Route::Proxy { host, port } => Some(format!("{host}:{port}")),
        Route::Direct | Route::Bypass => None,
    };
    let host = transfer.target_host.to_owned();

    // The proxy's answer to CONNECT is a number; it outranks the exit code,
    // which is the same 56 for every refused tunnel.
    if let (Some(proxy), Some(status)) = (&proxy, transfer.diagnostics.http_connect)
        && !(200..300).contains(&status)
    {
        return match status {
            407 if transfer.credential_sent => NetFailure::ProxyAuthRejected {
                proxy: proxy.clone(),
            },
            407 => NetFailure::ProxyAuthRequired {
                proxy: proxy.clone(),
                offered: transfer.offered.to_vec(),
            },
            status => NetFailure::ProxyDenied {
                proxy: proxy.clone(),
                target: format!("{host}:{}", transfer.target_port),
                status,
            },
        };
    }

    let Some(exit) = transfer.exit else {
        return NetFailure::Other {
            exit: None,
            detail: excerpt(transfer.stderr),
        };
    };
    let never_connected = transfer.diagnostics.num_connects == Some(0);
    match (exit, proxy) {
        (5, Some(proxy)) => NetFailure::ProxyDnsFailed { proxy },
        (6, _) => NetFailure::DnsFailed { host },
        (7, Some(proxy)) => NetFailure::ProxyUnreachable { proxy },
        (7, None) => NetFailure::ConnectFailed { host },
        // Through a proxy the only TCP connection curl makes is to the
        // proxy, so a timeout before any connection is the proxy's.
        (28, Some(proxy)) if never_connected => NetFailure::ProxyUnreachable { proxy },
        (28, None) if never_connected => NetFailure::ConnectTimeout { host },
        (28, _) => NetFailure::Timeout,
        (22, _) => NetFailure::HttpStatus {
            status: transfer.diagnostics.http_code,
        },
        (23, _) => NetFailure::WriteFailed,
        (63, _) => NetFailure::TooLarge {
            maximum: transfer.max_filesize.unwrap_or(0),
        },
        (77, _) if transfer.cacert_set => NetFailure::CaBundleUnreadable,
        // Schannel's curl refuses a missing file while it reads the config,
        // before any transfer: exit 2 naming the option.
        (2, _)
            if transfer.cacert_set && transfer.stderr.to_ascii_lowercase().contains("cacert") =>
        {
            NetFailure::CaBundleUnreadable
        }
        (35 | 51 | 53 | 54 | 58 | 59 | 60 | 66 | 77 | 80 | 82 | 83 | 90 | 91 | 98, _) => {
            classify_tls(transfer, host)
        }
        (18 | 52 | 55 | 56 | 92, _) => NetFailure::TransferInterrupted { exit },
        (33 | 36, _) => NetFailure::ResumeUnsupported,
        _ => NetFailure::Other {
            exit: Some(exit),
            detail: excerpt(transfer.stderr),
        },
    }
}

/// Which certificate check failed.
///
/// The verify result is the number where the backend reports one (the
/// `X509_V_ERR_*` values of the OpenSSL family). Only without it is the
/// error text matched, and only for these fixed tokens.
fn classify_tls(transfer: &Transfer<'_>, host: String) -> NetFailure {
    let untrusted = |host: String| NetFailure::TlsUntrustedIssuer {
        host,
        issuer: transfer.issuer.map(str::to_owned),
        backend: transfer.backend.to_string(),
    };
    match transfer.diagnostics.ssl_verify {
        // 2 unable to get issuer, 18 self-signed leaf, 19 self-signed in
        // chain, 20 unable to get local issuer, 21 unable to verify the
        // first certificate, 27 not trusted.
        Some(2 | 18 | 19 | 20 | 21 | 27) => return untrusted(host),
        // 9 not yet valid, 10 expired.
        Some(9 | 10) => return NetFailure::TlsExpired { host },
        // 62 hostname mismatch.
        Some(62) => return NetFailure::TlsHostnameMismatch { host },
        _ => {}
    }
    let text = transfer.stderr.to_ascii_lowercase();
    let has = |tokens: &[&str]| tokens.iter().any(|token| text.contains(token));
    if has(&[
        "no alternative certificate subject name matches",
        "does not match target host",
        "failed to match connection hostname",
        "sec_e_wrong_principal",
        "cert_e_cn_no_match",
    ]) {
        return NetFailure::TlsHostnameMismatch { host };
    }
    if has(&[
        "crypt_e_no_revocation_check",
        "crypt_e_revocation_offline",
        "unable to check revocation",
        "revocation status is unknown",
        // Older Schannel builds name the chain-trust flag instead of the sentence.
        "cert_trust_revocation_status_unknown",
    ]) {
        return NetFailure::TlsRevocationUnavailable { host };
    }
    if has(&[
        "certificate has expired",
        "not yet valid",
        "not time valid",
        "sec_e_cert_expired",
        "cert_e_expired",
    ]) {
        return NetFailure::TlsExpired { host };
    }
    if has(&[
        "unable to get local issuer certificate",
        "self signed certificate",
        "self-signed certificate",
        "sec_e_untrusted_root",
        "cert_e_untrustedroot",
        "certificate chain is incomplete",
        "based on an untrusted root",
        "unknown ca",
    ]) {
        return untrusted(host);
    }
    NetFailure::TlsFailed {
        host,
        detail: excerpt(transfer.stderr),
    }
}

/// curl's complaint as one bounded line with no control characters.
pub(crate) fn excerpt(raw: &str) -> String {
    let line = raw.split_whitespace().collect::<Vec<_>>().join(" ");
    let line: String = line.chars().filter(|c| !c.is_control()).collect();
    if line.is_empty() {
        return "(curl printed nothing)".to_owned();
    }
    if line.chars().count() <= EXCERPT_CHARS {
        return line;
    }
    let mut cut: String = line.chars().take(EXCERPT_CHARS).collect();
    cut.push('…');
    cut
}
