//! Internal mirror addresses for the engine archive and for model weights.
//!
//! A mirror changes where bytes are fetched from and nothing else: the
//! digest, size and build a download is held to stay compile-time constants
//! of the caller. [`MirrorBase`] is the validated directory URL; the rules
//! below run when the human saves it and again on every use.

use std::net::{Ipv4Addr, Ipv6Addr};

use url::{Host, Url};

use crate::settings::{NoProxyRule, SettingsError, printable};

/// The longest mirror address accepted, in bytes.
pub const MAX_MIRROR_URL_BYTES: usize = 512;

/// A validated mirror directory: an `https` URL ending in `/`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MirrorBase(Url);

impl MirrorBase {
    /// Validates a mirror address.
    ///
    /// `https` only, a host, no user information, query or fragment, no `.`
    /// or `..` segment, at most [`MAX_MIRROR_URL_BYTES`]. The host may be a
    /// name or an IP literal (internal mirrors are often on private
    /// addresses), but never this machine's loopback, a link-local address
    /// (the cloud metadata address among them), the unspecified address or
    /// a multicast one. The result always ends in `/`.
    ///
    /// `field` is the settings-document path the refusal is reported under
    /// (`engine_mirror` or `models_mirror`).
    pub fn parse(raw: &str, field: &'static str) -> Result<Self, SettingsError> {
        let refuse = |detail: &str| Err(SettingsError::new(field, detail));
        let raw = raw.trim();
        if raw.is_empty() {
            return refuse("The mirror address is empty.");
        }
        if raw.len() > MAX_MIRROR_URL_BYTES {
            return Err(SettingsError::new(
                field,
                format!("The mirror address is longer than {MAX_MIRROR_URL_BYTES} bytes."),
            ));
        }
        if raw.chars().any(|c| c.is_control() || c.is_whitespace()) {
            return refuse("The mirror address holds a space or a control character.");
        }
        if !raw
            .get(..8)
            .is_some_and(|head| head.eq_ignore_ascii_case("https://"))
        {
            return refuse("A mirror address must start with https://.");
        }
        // Checked on the text: the URL parser resolves dot segments away,
        // and a mirror address that needs resolving is not one to accept.
        let path_start = raw[8..].find('/').map_or(raw.len(), |at| at + 8);
        let path_end = raw.find(['?', '#']).unwrap_or(raw.len());
        if path_start < path_end && raw[path_start..path_end].split('/').any(is_dot_segment) {
            return refuse("A mirror address cannot hold a `.` or `..` path segment.");
        }
        let mut url = Url::parse(raw).map_err(|error| {
            SettingsError::new(
                field,
                format!("The mirror address does not parse: {error}."),
            )
        })?;
        if !url.username().is_empty() || url.password().is_some() {
            return refuse("Leave user names and passwords out of a mirror address.");
        }
        if url.query().is_some() {
            return refuse("A mirror address takes no query.");
        }
        if url.fragment().is_some() {
            return refuse("A mirror address takes no fragment.");
        }
        match url.host() {
            None => return refuse("The mirror address has no host."),
            Some(Host::Domain(name)) => {
                let name = name.strip_suffix('.').unwrap_or(name);
                if name == "localhost" || name.ends_with(".localhost") {
                    return refuse("A mirror cannot be this computer itself (localhost).");
                }
            }
            Some(Host::Ipv4(address)) => {
                if !v4_allowed(address) {
                    return refuse(
                        "A mirror cannot be a loopback, link-local, unspecified or multicast \
                         address.",
                    );
                }
            }
            Some(Host::Ipv6(address)) => {
                if !v6_allowed(address) {
                    return refuse(
                        "A mirror cannot be a loopback, link-local, unspecified or multicast \
                         address.",
                    );
                }
            }
        }
        if !url.path().ends_with('/') {
            let path = format!("{}/", url.path());
            url.set_path(&path);
        }
        Ok(Self(url))
    }

    /// The normalized address, ending in `/`.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }

    /// The mirror as a URL.
    #[must_use]
    pub fn url(&self) -> &Url {
        &self.0
    }

    /// The mirror's host, as the audit row and the disclosure copy name it.
    #[must_use]
    pub fn host(&self) -> &str {
        self.0.host_str().unwrap_or_default()
    }

    /// The URL of `relative` under this mirror: the pinned asset name for
    /// the engine, the rest of a catalog URL for a model.
    ///
    /// Refused when the result would not stay under the mirror directory
    /// (a leading `/`, a dot segment, a control character).
    pub fn join(&self, relative: &str) -> Result<Url, SettingsError> {
        const FIELD: &str = "mirror";
        let refuse = || {
            Err(SettingsError::new(
                FIELD,
                format!(
                    "`{}` cannot be fetched from the mirror {}.",
                    printable(relative),
                    self.as_str()
                ),
            ))
        };
        let path_end = relative.find(['?', '#']).unwrap_or(relative.len());
        if relative.is_empty()
            || relative.starts_with('/')
            || relative.contains('\\')
            || relative.chars().any(char::is_control)
            || relative[..path_end].split('/').any(is_dot_segment)
        {
            return refuse();
        }
        let joined = format!("{}{relative}", self.as_str());
        match Url::parse(&joined) {
            Ok(url) if url.as_str().starts_with(self.as_str()) => Ok(url),
            _ => refuse(),
        }
    }

    /// Rewrites a catalog URL onto this mirror: when `url` starts with
    /// `upstream_prefix` (for example `https://huggingface.co/`), the prefix
    /// is replaced by the mirror and the rest is kept. `None` when the URL
    /// is not under that prefix, in which case it is fetched as it is.
    #[must_use]
    pub fn rebase(&self, url: &Url, upstream_prefix: &str) -> Option<Url> {
        let rest = url.as_str().strip_prefix(upstream_prefix)?;
        self.join(rest).ok()
    }

    /// Whether the mirror's host is allowed by a managed allowlist. An
    /// empty list allows every host; entries use the no-proxy grammar.
    #[must_use]
    pub fn host_allowed(&self, allowed: &[NoProxyRule]) -> bool {
        allowed.is_empty() || allowed.iter().any(|rule| rule.matches(&self.0))
    }
}

/// Whether a path segment is `.` or `..`, spelled plainly or with the dot
/// percent-encoded (a URL parser treats `%2e` as a dot here).
fn is_dot_segment(segment: &str) -> bool {
    let plain = segment.to_ascii_lowercase().replace("%2e", ".");
    plain == "." || plain == ".."
}

fn v4_allowed(address: Ipv4Addr) -> bool {
    !(address.is_loopback()
        || address.is_link_local()
        || address.is_unspecified()
        || address.is_multicast()
        || address.is_broadcast())
}

fn v6_allowed(address: Ipv6Addr) -> bool {
    if let Some(mapped) = address.to_ipv4_mapped() {
        return v4_allowed(mapped);
    }
    // fe80::/10 is link-local unicast.
    let link_local = address.segments()[0] & 0xffc0 == 0xfe80;
    !(address.is_loopback() || address.is_unspecified() || address.is_multicast() || link_local)
}
