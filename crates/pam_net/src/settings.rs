//! What the human set for the network, as validated values.
//!
//! [`NetSettings`] is the resolved profile one curl process runs under: an
//! optional proxy, the proxy password the caller read from the keychain, the
//! no-proxy list and an optional CA bundle path. Nothing in it comes from the
//! process environment, and nothing in it is stored by this crate: the daemon
//! loads its settings document, builds a `NetSettings` through the parsers
//! here, and hands it to the launcher for exactly one spawn.
//!
//! Every parser is also the validator: a value that exists is a value that
//! passed. The stored document keeps strings; the daemon re-parses them on
//! every spawn, so a rule added here applies to settings saved before it.

use std::fmt;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;

use url::{Host, Url};

use crate::failure::NetFailure;

/// The longest proxy address accepted, in bytes.
pub const MAX_PROXY_URL_BYTES: usize = 255;

/// The longest proxy user name accepted, in bytes.
pub const MAX_PROXY_USERNAME_BYTES: usize = 128;

/// The longest proxy password accepted, in bytes.
pub const MAX_PROXY_PASSWORD_BYTES: usize = 1024;

/// The most entries a no-proxy list may hold.
pub const MAX_NO_PROXY_ENTRIES: usize = 64;

/// The longest single no-proxy entry, in bytes.
pub const MAX_NO_PROXY_ENTRY_BYTES: usize = 255;

/// A setting that was refused, with the field it belongs to.
///
/// `field` is the settings-document path (`proxy.url`, `no_proxy`, …) so the
/// GUI can put the sentence beside the right input; `detail` is the sentence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SettingsError {
    /// Which setting was refused, as its document path.
    pub field: &'static str,
    /// What is wrong with it and what would be accepted, for a human.
    pub detail: String,
}

impl SettingsError {
    pub(crate) fn new(field: &'static str, detail: impl Into<String>) -> Self {
        Self {
            field,
            detail: detail.into(),
        }
    }
}

impl fmt::Display for SettingsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.field, self.detail)
    }
}

impl std::error::Error for SettingsError {}

/// How curl talks to the proxy itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyScheme {
    /// A plain listener that tunnels HTTPS with `CONNECT`: the usual
    /// enterprise proxy.
    Http,
    /// A proxy that is itself reached over TLS.
    Https,
}

impl ProxyScheme {
    /// The scheme as it appears in the proxy address.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Https => "https",
        }
    }
}

/// How curl authenticates to the proxy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ProxyAuth {
    /// No credential is sent.
    #[default]
    None,
    /// Basic, sent with the first `CONNECT`.
    Basic,
    /// curl picks among Basic, Digest and NTLM from the proxy's challenge.
    AnyAuth,
}

impl ProxyAuth {
    /// Reads the settings-document spelling: `none`, `basic` or `anyauth`.
    pub fn parse(raw: &str) -> Result<Self, SettingsError> {
        match raw {
            "none" => Ok(Self::None),
            "basic" => Ok(Self::Basic),
            "anyauth" => Ok(Self::AnyAuth),
            other => Err(SettingsError::new(
                "proxy.auth",
                format!(
                    "`{}` is not a proxy sign-in mode; use none, basic or anyauth.",
                    printable(other)
                ),
            )),
        }
    }

    /// The settings-document spelling.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Basic => "basic",
            Self::AnyAuth => "anyauth",
        }
    }
}

/// A validated proxy: where it listens and how to sign in to it.
///
/// The password is not here. It lives in the keychain and reaches the
/// launcher as a [`ProxyPassword`] beside this value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proxy {
    scheme: ProxyScheme,
    host: String,
    port: u16,
    auth: ProxyAuth,
    username: Option<String>,
}

impl Proxy {
    /// Validates a proxy address, sign-in mode and user name.
    ///
    /// Accepted: `http://host:port` and `https://host:port`, the port
    /// spelled out (curl sends a bare proxy to port 1080, which surprises).
    /// Refused, each with its own sentence: SOCKS, a value with no scheme,
    /// user information in the address, a query, a fragment, a path.
    pub fn parse(
        url: &str,
        auth: ProxyAuth,
        username: Option<&str>,
    ) -> Result<Self, SettingsError> {
        const FIELD: &str = "proxy.url";
        let raw = url.trim();
        if raw.is_empty() {
            return Err(SettingsError::new(FIELD, "The proxy address is empty."));
        }
        if raw.len() > MAX_PROXY_URL_BYTES {
            return Err(SettingsError::new(
                FIELD,
                format!("The proxy address is longer than {MAX_PROXY_URL_BYTES} bytes."),
            ));
        }
        if raw.chars().any(|c| c.is_control() || c.is_whitespace()) {
            return Err(SettingsError::new(
                FIELD,
                "The proxy address holds a space or a control character.",
            ));
        }
        let (scheme, rest) = split_scheme(raw)?;
        let split = rest.find(['/', '?', '#']).unwrap_or(rest.len());
        let (authority, tail) = rest.split_at(split);
        if authority.contains('@') {
            return Err(SettingsError::new(
                FIELD,
                "Leave the user name and password out of the proxy address; enter the user name \
                 in its own field and the password is kept in the keychain.",
            ));
        }
        match tail {
            "" | "/" => {}
            tail if tail.contains('?') => {
                return Err(SettingsError::new(
                    FIELD,
                    "A proxy address takes no query; use scheme://host:port.",
                ));
            }
            tail if tail.contains('#') => {
                return Err(SettingsError::new(
                    FIELD,
                    "A proxy address takes no fragment; use scheme://host:port.",
                ));
            }
            _ => {
                return Err(SettingsError::new(
                    FIELD,
                    "A proxy address takes no path; use scheme://host:port.",
                ));
            }
        }
        if authority.is_empty() || authority.starts_with(':') {
            return Err(SettingsError::new(FIELD, "The proxy address has no host."));
        }
        let port = explicit_port(authority).ok_or_else(|| {
            SettingsError::new(
                FIELD,
                "Give the proxy port explicitly, for example http://proxy.corp.example:3128.",
            )
        })?;
        // The `url` crate is the judge of what a host is; it also lowercases
        // the name and renders an international one as punycode.
        let parsed =
            Url::parse(&format!("{}://{authority}/", scheme.as_str())).map_err(|error| {
                SettingsError::new(FIELD, format!("The proxy host is not valid: {error}."))
            })?;
        let host = parsed
            .host_str()
            .filter(|host| !host.is_empty())
            .ok_or_else(|| SettingsError::new(FIELD, "The proxy address has no host."))?
            .to_owned();
        let username = username.map(validate_username).transpose()?;
        Ok(Self {
            scheme,
            host,
            port,
            auth,
            username,
        })
    }

    /// `http` or `https`.
    #[must_use]
    pub fn scheme(&self) -> ProxyScheme {
        self.scheme
    }

    /// The proxy host, lowercase; an IPv6 literal keeps its brackets.
    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }

    /// The proxy port.
    #[must_use]
    pub fn port(&self) -> u16 {
        self.port
    }

    /// The sign-in mode.
    #[must_use]
    pub fn auth(&self) -> ProxyAuth {
        self.auth
    }

    /// The user name, when one was set. Not secret.
    #[must_use]
    pub fn username(&self) -> Option<&str> {
        self.username.as_deref()
    }

    /// The normalized address: `scheme://host:port`, no trailing slash.
    #[must_use]
    pub fn url(&self) -> String {
        format!("{}://{}:{}", self.scheme.as_str(), self.host, self.port)
    }

    /// `host:port`, the form a sentence names the proxy by.
    #[must_use]
    pub fn authority(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

/// The proxy scheme and what follows `://`, or the sentence for a scheme
/// that is missing or not supported.
fn split_scheme(raw: &str) -> Result<(ProxyScheme, &str), SettingsError> {
    const FIELD: &str = "proxy.url";
    let Some((scheme, rest)) = raw.split_once("://") else {
        return Err(SettingsError::new(
            FIELD,
            format!(
                "A proxy address needs a scheme; did you mean http://{}?",
                printable(raw)
            ),
        ));
    };
    match scheme.to_ascii_lowercase().as_str() {
        "http" => Ok((ProxyScheme::Http, rest)),
        "https" => Ok((ProxyScheme::Https, rest)),
        "socks" | "socks4" | "socks4a" | "socks5" | "socks5h" => Err(SettingsError::new(
            FIELD,
            "SOCKS proxies are not supported; use an http:// or https:// proxy address.",
        )),
        other => Err(SettingsError::new(
            FIELD,
            format!(
                "`{}://` is not a supported proxy scheme; use http:// or https://.",
                printable(other)
            ),
        )),
    }
}

/// The port an authority spells out, if it spells one.
///
/// `Url::port` cannot answer this: it reports `None` for a scheme's default
/// port whether or not the text carried it.
fn explicit_port(authority: &str) -> Option<u16> {
    let (host, port) = authority.rsplit_once(':')?;
    // `[::1]` has colons and no port; `[::1]:3128` has one after the bracket.
    if host.is_empty() || (host.starts_with('[') && !host.ends_with(']')) {
        return None;
    }
    if port.is_empty() || !port.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    port.parse::<u16>().ok().filter(|port| *port != 0)
}

fn validate_username(raw: &str) -> Result<String, SettingsError> {
    const FIELD: &str = "proxy.username";
    let name = raw.trim();
    if name.is_empty() {
        return Err(SettingsError::new(FIELD, "The proxy user name is empty."));
    }
    if name.len() > MAX_PROXY_USERNAME_BYTES {
        return Err(SettingsError::new(
            FIELD,
            format!("The proxy user name is longer than {MAX_PROXY_USERNAME_BYTES} bytes."),
        ));
    }
    if name.contains(':') {
        return Err(SettingsError::new(
            FIELD,
            "A proxy user name cannot hold a colon; curl reads everything after it as the password.",
        ));
    }
    if name.chars().any(char::is_control) {
        return Err(SettingsError::new(
            FIELD,
            "The proxy user name holds a control character.",
        ));
    }
    Ok(name.to_owned())
}

/// The proxy password, held only long enough to be written to curl's stdin.
///
/// Never part of the settings document. The value is absent from
/// [`fmt::Debug`] and overwritten when dropped (best effort: this crate has
/// no `unsafe`, so the buffer is refilled rather than wiped in place).
pub struct ProxyPassword(String);

impl ProxyPassword {
    /// Wraps a password read from the keychain. Surrounding whitespace is
    /// trimmed; an empty value, an oversized one, or one holding a control
    /// character is refused.
    pub fn new(value: &str) -> Result<Self, SettingsError> {
        const FIELD: &str = "credential";
        let trimmed = value.trim();
        if trimmed.is_empty() {
            return Err(SettingsError::new(FIELD, "The proxy password is empty."));
        }
        if trimmed.len() > MAX_PROXY_PASSWORD_BYTES {
            return Err(SettingsError::new(
                FIELD,
                format!("The proxy password is longer than {MAX_PROXY_PASSWORD_BYTES} bytes."),
            ));
        }
        if trimmed.chars().any(char::is_control) {
            return Err(SettingsError::new(
                FIELD,
                "The proxy password holds a control character or a line break.",
            ));
        }
        Ok(Self(trimmed.to_owned()))
    }

    /// The password itself. The only call site is the `proxy-user` line of
    /// curl's stdin config.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for ProxyPassword {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("[REDACTED]")
    }
}

impl Drop for ProxyPassword {
    fn drop(&mut self) {
        let len = self.0.len();
        self.0.clear();
        for _ in 0..len {
            self.0.push('\0');
        }
    }
}

/// One entry of the no-proxy list.
///
/// The grammar is the portable subset curl evaluates the same way on every
/// supported version: `*`, a host name (which also covers its subdomains,
/// with or without a leading dot), an IP literal, or a CIDR range. No ports,
/// no wildcards inside names, no `<local>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NoProxyRule {
    text: String,
    kind: RuleKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum RuleKind {
    /// `*`: every target bypasses the proxy.
    Any,
    /// A name and its subdomains; stored without the leading dot.
    Host(String),
    /// One address, exactly.
    Ip(IpAddr),
    /// A network and its prefix length.
    Cidr(IpAddr, u8),
}

impl NoProxyRule {
    /// Validates one entry. The result is trimmed and lowercased.
    pub fn parse(raw: &str) -> Result<Self, SettingsError> {
        const FIELD: &str = "no_proxy";
        let text = raw.trim().to_ascii_lowercase();
        let refuse = |detail: String| Err(SettingsError::new(FIELD, detail));
        if text.is_empty() {
            return refuse("A no-proxy entry is empty.".to_owned());
        }
        if text.len() > MAX_NO_PROXY_ENTRY_BYTES {
            return refuse(format!(
                "A no-proxy entry is longer than {MAX_NO_PROXY_ENTRY_BYTES} bytes."
            ));
        }
        let shown = printable(&text);
        if text
            .chars()
            .any(|c| c.is_control() || c.is_whitespace() || c == ',')
        {
            return refuse(format!(
                "`{shown}` holds a space, a comma or a control character; give one host per entry."
            ));
        }
        if text == "*" {
            return Ok(Self {
                text,
                kind: RuleKind::Any,
            });
        }
        if text.contains("://") {
            return refuse(format!(
                "`{shown}` is a URL; a no-proxy entry is a host name, an IP address or a CIDR range."
            ));
        }
        if text == "<local>" {
            return refuse(
                "`<local>` is not supported; list the internal host names or domains instead."
                    .to_owned(),
            );
        }
        if let Some(address) = parse_ip(&text) {
            return Ok(Self {
                text: address.to_string(),
                kind: RuleKind::Ip(address),
            });
        }
        if let Some((network, prefix)) = text.split_once('/') {
            let address = parse_ip(network);
            let prefix = prefix.parse::<u8>().ok();
            return match (address, prefix) {
                (Some(address), Some(prefix)) if prefix <= max_prefix(address) => Ok(Self {
                    text: format!("{address}/{prefix}"),
                    kind: RuleKind::Cidr(address, prefix),
                }),
                _ => refuse(format!(
                    "`{shown}` is not a CIDR range; write it like 10.0.0.0/8."
                )),
            };
        }
        if text.contains('*') {
            return refuse(format!(
                "`{shown}` uses a wildcard; a domain already covers its subdomains, so write the \
                 domain alone."
            ));
        }
        if text.contains(':') {
            return refuse(format!(
                "`{shown}` names a port; a no-proxy entry matches a host on every port."
            ));
        }
        let name = text.strip_prefix('.').unwrap_or(&text);
        let label_ok = |label: &str| {
            !label.is_empty()
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
        };
        if name.is_empty() || !name.split('.').all(label_ok) {
            return refuse(format!(
                "`{shown}` is not a host name; use letters, digits, hyphens and dots (an \
                 international name in its punycode form)."
            ));
        }
        let name = name.to_owned();
        Ok(Self {
            text,
            kind: RuleKind::Host(name),
        })
    }

    /// The entry as stored and shown: trimmed, lowercase.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// Whether the entry is a CIDR range, which only curl 7.86 and newer
    /// evaluates.
    #[must_use]
    pub fn is_cidr(&self) -> bool {
        matches!(self.kind, RuleKind::Cidr(..))
    }

    /// Whether the entry is `*`.
    #[must_use]
    pub fn is_any(&self) -> bool {
        self.kind == RuleKind::Any
    }

    /// Whether `target`'s host matches this entry.
    ///
    /// A name is never resolved: a host rule matches names only, an address
    /// or range rule matches IP literals only.
    #[must_use]
    pub fn matches(&self, target: &Url) -> bool {
        match (&self.kind, target.host()) {
            (RuleKind::Any, Some(_)) => true,
            (RuleKind::Host(rule), Some(Host::Domain(name))) => {
                let name = name.strip_suffix('.').unwrap_or(name).to_ascii_lowercase();
                name == *rule
                    || name
                        .strip_suffix(rule.as_str())
                        .is_some_and(|head| head.ends_with('.'))
            }
            (RuleKind::Ip(rule), Some(Host::Ipv4(address))) => *rule == IpAddr::V4(address),
            (RuleKind::Ip(rule), Some(Host::Ipv6(address))) => *rule == IpAddr::V6(address),
            (RuleKind::Cidr(network, prefix), Some(Host::Ipv4(address))) => {
                in_range(*network, *prefix, IpAddr::V4(address))
            }
            (RuleKind::Cidr(network, prefix), Some(Host::Ipv6(address))) => {
                in_range(*network, *prefix, IpAddr::V6(address))
            }
            _ => false,
        }
    }

    /// The spelling handed to curl: a name loses its leading dot (every
    /// supported curl treats the two alike, older ones only without it).
    pub(crate) fn curl_text(&self) -> &str {
        match &self.kind {
            RuleKind::Host(name) => name,
            _ => &self.text,
        }
    }
}

/// Validates a whole no-proxy list: every entry, the entry count, and
/// duplicates removed (first spelling wins, order kept).
pub fn parse_no_proxy<S: AsRef<str>>(entries: &[S]) -> Result<Vec<NoProxyRule>, SettingsError> {
    if entries.len() > MAX_NO_PROXY_ENTRIES {
        return Err(SettingsError::new(
            "no_proxy",
            format!("The no-proxy list holds more than {MAX_NO_PROXY_ENTRIES} entries."),
        ));
    }
    let mut rules: Vec<NoProxyRule> = Vec::with_capacity(entries.len());
    for entry in entries {
        let rule = NoProxyRule::parse(entry.as_ref())?;
        if !rules.contains(&rule) {
            rules.push(rule);
        }
    }
    Ok(rules)
}

/// An IP literal, with or without the brackets a URL puts around IPv6.
fn parse_ip(text: &str) -> Option<IpAddr> {
    let bare = text
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
        .unwrap_or(text);
    bare.parse::<IpAddr>().ok()
}

fn max_prefix(address: IpAddr) -> u8 {
    match address {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    }
}

/// Whether `address` is inside `network/prefix`. Families never mix.
fn in_range(network: IpAddr, prefix: u8, address: IpAddr) -> bool {
    match (network, address) {
        (IpAddr::V4(network), IpAddr::V4(address)) => {
            let mask = u32::MAX.checked_shl(32 - u32::from(prefix)).unwrap_or(0);
            u32::from(network) & mask == u32::from(address) & mask
        }
        (IpAddr::V6(network), IpAddr::V6(address)) => {
            let mask = u128::MAX.checked_shl(128 - u32::from(prefix)).unwrap_or(0);
            u128::from(network) & mask == u128::from(address) & mask
        }
        _ => false,
    }
}

/// Where a request to one target goes, as the settings decide it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Route {
    /// No proxy is configured.
    Direct,
    /// A proxy is configured but this target goes around it: it matched the
    /// no-proxy list, or it is this machine's own loopback.
    Bypass,
    /// Through the proxy.
    Proxy {
        /// The proxy host.
        host: String,
        /// The proxy port.
        port: u16,
    },
}

impl Route {
    /// `direct`, `bypass` or `proxy`: the word the GUI and the Test reply use.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Direct => "direct",
            Self::Bypass => "bypass",
            Self::Proxy { .. } => "proxy",
        }
    }
}

/// The network profile one curl process runs under.
///
/// Built by the caller per spawn from what the human saved; immutable
/// afterwards. [`NetSettings::direct`] is the default: no proxy, the
/// platform's own certificate trust.
#[derive(Debug, Default)]
pub struct NetSettings {
    proxy: Option<Proxy>,
    proxy_password: Option<ProxyPassword>,
    no_proxy: Vec<NoProxyRule>,
    ca_bundle: Option<PathBuf>,
}

impl NetSettings {
    /// A direct connection with the platform's certificate trust.
    #[must_use]
    pub fn direct() -> Self {
        Self::default()
    }

    /// Assembles a profile from validated parts.
    ///
    /// `proxy_password` is the keychain value, passed in for this one use.
    /// `ca_bundle` is the file curl is told to trust instead of the
    /// platform's store; it must be an absolute path this crate can write
    /// into curl's config. What the file contains is the caller's check.
    pub fn new(
        proxy: Option<Proxy>,
        proxy_password: Option<ProxyPassword>,
        no_proxy: Vec<NoProxyRule>,
        ca_bundle: Option<PathBuf>,
    ) -> Result<Self, SettingsError> {
        if no_proxy.len() > MAX_NO_PROXY_ENTRIES {
            return Err(SettingsError::new(
                "no_proxy",
                format!("The no-proxy list holds more than {MAX_NO_PROXY_ENTRIES} entries."),
            ));
        }
        if let Some(path) = &ca_bundle {
            validate_ca_path(path)?;
        }
        Ok(Self {
            proxy,
            proxy_password,
            no_proxy,
            ca_bundle,
        })
    }

    /// The configured proxy, if any.
    #[must_use]
    pub fn proxy(&self) -> Option<&Proxy> {
        self.proxy.as_ref()
    }

    /// The no-proxy list.
    #[must_use]
    pub fn no_proxy(&self) -> &[NoProxyRule] {
        &self.no_proxy
    }

    /// The CA bundle curl is pointed at, if any.
    #[must_use]
    pub fn ca_bundle(&self) -> Option<&Path> {
        self.ca_bundle.as_deref()
    }

    /// The user name and password to send to the proxy, when the sign-in
    /// mode asks for a credential and both halves are present.
    pub(crate) fn proxy_credential(&self) -> Option<(&str, &ProxyPassword)> {
        let proxy = self.proxy.as_ref()?;
        if proxy.auth() == ProxyAuth::None {
            return None;
        }
        Some((proxy.username()?, self.proxy_password.as_ref()?))
    }

    /// Whether a proxy credential would be sent.
    #[must_use]
    pub fn sends_proxy_credential(&self) -> bool {
        self.proxy_credential().is_some()
    }

    /// Where a request to `target` goes: the preview the GUI shows and the
    /// launcher's own decision for the first hop.
    ///
    /// curl evaluates the same list for every later hop of a followed
    /// redirect; a real-curl test holds this preview to curl's behaviour.
    #[must_use]
    pub fn route_for(&self, target: &Url) -> Route {
        let Some(proxy) = &self.proxy else {
            return Route::Direct;
        };
        if is_loopback(target) || self.no_proxy.iter().any(|rule| rule.matches(target)) {
            return Route::Bypass;
        }
        Route::Proxy {
            host: proxy.host().to_owned(),
            port: proxy.port(),
        }
    }
}

fn validate_ca_path(path: &Path) -> Result<(), SettingsError> {
    const FIELD: &str = "ca_bundle";
    if !path.is_absolute() {
        return Err(SettingsError::new(
            FIELD,
            "The CA bundle path must be absolute.",
        ));
    }
    let Some(text) = path.to_str() else {
        return Err(SettingsError::new(
            FIELD,
            "The CA bundle path is not valid Unicode and cannot be handed to curl.",
        ));
    };
    if text.chars().any(char::is_control) {
        return Err(SettingsError::new(
            FIELD,
            "The CA bundle path holds a control character.",
        ));
    }
    Ok(())
}

/// Whether `target` is this machine's own loopback: `localhost`, a name
/// under `.localhost`, `127.0.0.0/8`, `::1` or its IPv4-mapped form.
///
/// Such a target never goes through a proxy: the proxy could not reach it,
/// and would learn an internal address by being asked.
#[must_use]
pub fn is_loopback(target: &Url) -> bool {
    match target.host() {
        Some(Host::Domain(name)) => {
            let name = name.strip_suffix('.').unwrap_or(name).to_ascii_lowercase();
            name == "localhost" || name.ends_with(".localhost")
        }
        Some(Host::Ipv4(address)) => address.is_loopback(),
        Some(Host::Ipv6(address)) => v6_is_loopback(address),
        None => false,
    }
}

fn v6_is_loopback(address: Ipv6Addr) -> bool {
    address.is_loopback()
        || address
            .to_ipv4_mapped()
            .is_some_and(|mapped: Ipv4Addr| mapped.is_loopback())
}

/// Where the launcher's callers get the profile for the next spawn.
///
/// Implemented once in the daemon over its settings store and keychain.
/// Consumers hold an `Arc<dyn NetworkSource>` and ask before every spawn, so
/// a change the human saves applies to the next request. A source that
/// cannot produce a valid profile answers a [`NetFailure`]; it never falls
/// back to a direct connection.
pub trait NetworkSource: Send + Sync {
    /// The profile to run the next curl process under.
    fn settings(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<Arc<NetSettings>, NetFailure>> + Send + '_>>;
}

/// A fixed profile is its own source: tests, and callers with nothing to
/// reload.
impl NetworkSource for Arc<NetSettings> {
    fn settings(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<Arc<NetSettings>, NetFailure>> + Send + '_>> {
        let settings = Arc::clone(self);
        Box::pin(async move { Ok(settings) })
    }
}

/// A value made safe to quote back in a sentence: control characters
/// removed, length bounded.
pub(crate) fn printable(raw: &str) -> String {
    let mut shown: String = raw.chars().filter(|c| !c.is_control()).take(80).collect();
    if raw.chars().count() > 80 {
        shown.push('…');
    }
    shown
}
