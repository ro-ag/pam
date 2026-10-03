//! The daemon's network settings: the `net.settings` document, the managed
//! overlay a later policy layer supplies, and the one
//! [`pam_net::NetworkSource`] every curl spawn reads its profile from.
//!
//! One JSON document in the `setting` table, key [`SETTING_KEY`], version
//! [`DOCUMENT_VERSION`], `deny_unknown_fields`, at most [`MAX_DOCUMENT_BYTES`].
//! A missing document is the default: a direct connection with the
//! platform's trust. A document that is present but does not parse, has
//! another version, or fails validation is **not** the default: every
//! consumer is refused with `network_settings_invalid` until the human
//! saves the settings again. Falling back to a direct connection on a
//! corrupt proxy setting would send traffic around a proxy the
//! organisation requires.
//!
//! What a consumer gets ([`NetworkService::settings`]) is the resolved
//! profile: the user's document under the managed overlay
//! ([`ManagedNetworkLayer`]), re-validated, with the proxy password read
//! from the keychain when the sign-in mode needs one, and the CA bundle's
//! private copy (`<base>/net/ca-<sha12>.pem`) re-hashed and compared with
//! the recorded digest — a mismatch is `network_ca_tampered`. The profile
//! is cached for [`CACHE_TTL`] so a flow with many connector steps does not
//! read the keychain per step; every save invalidates it, so a change
//! applies to the next spawn.
//!
//! The overlay has three parts. A **locked** field (`current`) is the
//! policy's value and the human cannot edit it. A **default**
//! (`defaults`) applies only while the human has stored no value, and the
//! field stays editable. A **closure** (`closed`) means the policy named a
//! proxy, no-proxy list or CA bundle that could not be put in force: every
//! connector call and download is refused, never sent around the proxy the
//! organisation requires. The managed CA bundle is imported, trust-checked
//! and digest-pinned by the policy loader (`PolicyHandle`); this module only
//! re-hashes the loader's private copy and never imports a second time.
//!
//! The password is never in the document, an audit row, a reply or a log
//! line: it lives in the keychain under connector id [`PROXY_CREDENTIAL_ID`]
//! and is handed to curl's stdin config and nowhere else.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use pam_net::{
    CaError, MirrorBase, NetFailure, NetSettings, NetworkSource, NoProxyRule, Proxy, ProxyAuth,
    ProxyPassword, SettingsError, normalize_pem, parse_no_proxy,
};
use pam_store::{Store, StoreError};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::managed_policy::{Key, LeafStatus};
use crate::managed_policy_service::PolicyHandle;
use crate::secrets::{Secret, SecretError, SecretStore};

/// The `setting` row the document lives under.
pub const SETTING_KEY: &str = "net.settings";

/// The document version this daemon writes and reads.
pub const DOCUMENT_VERSION: u16 = 1;

/// The most bytes a stored document may have.
pub const MAX_DOCUMENT_BYTES: usize = 16 * 1024;

/// The connector id the proxy password is filed under in the keychain
/// (account `pam.connector.v1.network.proxy`).
pub const PROXY_CREDENTIAL_ID: &str = "network.proxy";

/// The private directory under the base where CA bundle copies live.
pub const NET_DIR: &str = "net";

/// How long a resolved profile is reused before the document and the
/// keychain are read again. Saves invalidate it at once.
pub const CACHE_TTL: Duration = Duration::from_secs(2);

/// How many hex characters of the digest name a private copy.
const COPY_DIGEST_CHARS: usize = 12;

/// Proxy and certificate variables a daemon's environment may carry. They
/// are never read; `admin.network.get` lists which are present so the
/// screen can say they are ignored.
pub const IGNORED_ENV: [&str; 11] = [
    "HTTPS_PROXY",
    "https_proxy",
    "HTTP_PROXY",
    "http_proxy",
    "ALL_PROXY",
    "all_proxy",
    "NO_PROXY",
    "no_proxy",
    "CURL_CA_BUNDLE",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
];

/// The stored proxy: address, sign-in mode and user name. The password is
/// in the keychain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProxyEntry {
    /// `scheme://host:port`, normalized when saved.
    pub url: String,
    /// `none`, `basic` or `anyauth`.
    pub auth: String,
    /// The proxy user name; not secret.
    #[serde(default)]
    pub username: Option<String>,
}

/// The private copy PAM made of an imported CA bundle, as recorded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaBundleEntry {
    /// SHA-256 of the normalized copy, lowercase hex.
    pub sha256: String,
    /// How many certificate blocks the copy holds.
    pub certificates: usize,
    /// Where it was imported from; display only, never read again on a
    /// spawn.
    #[serde(default)]
    pub source_path: Option<String>,
    /// When it was imported, unix seconds.
    #[serde(default)]
    pub imported_ts: Option<i64>,
}

/// The `net.settings` document as stored.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkDocument {
    /// [`DOCUMENT_VERSION`]; anything else fails closed.
    pub version: u16,
    /// The proxy, or `None` for a direct connection.
    #[serde(default)]
    pub proxy: Option<ProxyEntry>,
    /// Targets that go around the proxy.
    #[serde(default)]
    pub no_proxy: Vec<String>,
    /// The imported CA bundle, if any.
    #[serde(default)]
    pub ca_bundle: Option<CaBundleEntry>,
    /// Where the engine archive is fetched from instead of GitHub.
    #[serde(default)]
    pub engine_mirror: Option<String>,
    /// Where catalog weights are fetched from instead of Hugging Face.
    #[serde(default)]
    pub models_mirror: Option<String>,
}

impl Default for NetworkDocument {
    fn default() -> Self {
        Self {
            version: DOCUMENT_VERSION,
            proxy: None,
            no_proxy: Vec::new(),
            ca_bundle: None,
            engine_mirror: None,
            models_mirror: None,
        }
    }
}

impl NetworkDocument {
    /// Parses a stored document: the version must be [`DOCUMENT_VERSION`]
    /// and no field may be unknown. Validation of the values is
    /// [`Self::validate`].
    ///
    /// # Errors
    ///
    /// The sentence a `network_settings_invalid` refusal carries.
    pub fn parse(raw: &str) -> Result<Self, String> {
        if raw.len() > MAX_DOCUMENT_BYTES {
            return Err(format!(
                "the stored network settings are {} bytes, more than the {MAX_DOCUMENT_BYTES} \
                 allowed",
                raw.len()
            ));
        }
        let document: Self = serde_json::from_str(raw)
            .map_err(|error| format!("the stored network settings do not parse: {error}"))?;
        if document.version != DOCUMENT_VERSION {
            return Err(format!(
                "the stored network settings are version {}; this daemon reads version \
                 {DOCUMENT_VERSION}",
                document.version
            ));
        }
        Ok(document)
    }

    /// The document as the store keeps it.
    #[must_use]
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).expect("a network document always serializes")
    }

    /// Checks every field with the rules `pam_net` applies at spawn, so a
    /// save and a spawn agree. `allowed_hosts` is the policy's mirror
    /// allowlist (empty: any host).
    ///
    /// # Errors
    ///
    /// The first field that fails, with its sentence.
    pub fn validate(&self, allowed_hosts: &[NoProxyRule]) -> Result<ValidNetwork, SettingsError> {
        let proxy = self
            .proxy
            .as_ref()
            .map(|entry| {
                let auth = ProxyAuth::parse(&entry.auth)?;
                Proxy::parse(&entry.url, auth, entry.username.as_deref())
            })
            .transpose()?;
        let no_proxy = parse_no_proxy(&self.no_proxy)?;
        let mirror = |raw: &Option<String>, field: &'static str| {
            raw.as_deref()
                .map(|raw| {
                    let base = MirrorBase::parse(raw, field)?;
                    if !base.host_allowed(allowed_hosts) {
                        return Err(SettingsError {
                            field,
                            detail: format!(
                                "the mirror host {} is not in your organisation's allowed list",
                                base.host()
                            ),
                        });
                    }
                    Ok(base)
                })
                .transpose()
        };
        let engine_mirror = mirror(&self.engine_mirror, "engine_mirror")?;
        let models_mirror = mirror(&self.models_mirror, "models_mirror")?;
        if let Some(bundle) = &self.ca_bundle {
            validate_digest(&bundle.sha256)?;
        }
        Ok(ValidNetwork {
            proxy,
            no_proxy,
            ca_bundle: self.ca_bundle.clone(),
            engine_mirror,
            models_mirror,
        })
    }
}

/// A document whose every field passed validation.
#[derive(Debug, Clone)]
pub struct ValidNetwork {
    /// The proxy, parsed.
    pub proxy: Option<Proxy>,
    /// The no-proxy rules, parsed and deduplicated.
    pub no_proxy: Vec<NoProxyRule>,
    /// The CA bundle record, digest checked for shape.
    pub ca_bundle: Option<CaBundleEntry>,
    /// The engine mirror, parsed.
    pub engine_mirror: Option<MirrorBase>,
    /// The models mirror, parsed.
    pub models_mirror: Option<MirrorBase>,
}

fn validate_digest(sha256: &str) -> Result<(), SettingsError> {
    if sha256.len() != 64 || !sha256.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(SettingsError {
            field: "ca_bundle",
            detail: "the recorded CA bundle digest is not a SHA-256".to_owned(),
        });
    }
    Ok(())
}

/// The fields a managed policy may pin. Present means pinned and locked;
/// absent means the user's value applies (or a [`ManagedDefaults`] entry,
/// while the user has none). `mirror_allowed_hosts` is policy-only: a list
/// the same human could edit would not be a control.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ManagedNetwork {
    /// A pinned proxy (`Some(None)` pins "direct").
    pub proxy: Option<Option<ProxyEntry>>,
    /// A pinned no-proxy list.
    pub no_proxy: Option<Vec<String>>,
    /// A pinned CA bundle record. The policy loader performs the same
    /// import this module does, so the record names a private copy under
    /// `<base>/net` and the digest check applies to it unchanged.
    pub ca_bundle: Option<Option<CaBundleEntry>>,
    /// A pinned engine mirror (`Some(None)` pins upstream).
    pub engine_mirror: Option<Option<String>>,
    /// A pinned models mirror.
    pub models_mirror: Option<Option<String>>,
    /// Hosts a mirror may name; empty allows any.
    pub mirror_allowed_hosts: Vec<String>,
}

/// The unlocked layer of the overlay: what applies while the human has
/// stored no value for the field, and never replaces one. The proxy and the
/// CA bundle take no default (the policy can only lock them).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ManagedDefaults {
    /// A default no-proxy list, used while the user's list is empty.
    pub no_proxy: Option<Vec<String>>,
    /// A default engine mirror (`Some(None)` names upstream).
    pub engine_mirror: Option<Option<String>>,
    /// A default models mirror.
    pub models_mirror: Option<Option<String>>,
}

impl ManagedDefaults {
    /// Whether no field has a default.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }
}

/// Why connector calls and downloads are refused under the policy: it named
/// a proxy, no-proxy list or CA bundle that could not be put in force and
/// there is no last-known-good value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyClosed {
    /// The policy key (`network.ca_bundle`, ...).
    pub key: String,
    /// A stable code: the trust code, or the validation code.
    pub code: String,
    /// The sentence.
    pub detail: String,
}

/// Where the managed overlay comes from. The default answers `None`, no
/// defaults and no closure; the policy handle ([`PolicyNetwork`]) is the
/// production layer.
pub trait ManagedNetworkLayer: Send + Sync {
    /// The locked fields, or `None` when nothing is locked.
    fn current(&self) -> Option<ManagedNetwork>;

    /// The unlocked defaults.
    fn defaults(&self) -> ManagedDefaults {
        ManagedDefaults::default()
    }

    /// Why every consumer must refuse, when the policy cannot be put in
    /// force for a proxy, no-proxy list or CA bundle.
    fn closed(&self) -> Option<PolicyClosed> {
        None
    }
}

/// No policy: every field is the user's.
#[derive(Debug, Default)]
pub struct NoManagedNetwork;

impl ManagedNetworkLayer for NoManagedNetwork {
    fn current(&self) -> Option<ManagedNetwork> {
        None
    }
}

/// A fixed overlay, for tests of the resolution and the lock.
#[derive(Debug, Default)]
pub struct FixedManagedNetwork {
    /// The locked fields.
    pub locked: Mutex<Option<ManagedNetwork>>,
    /// The unlocked defaults.
    pub defaults: Mutex<ManagedDefaults>,
    /// The closure.
    pub closed: Mutex<Option<PolicyClosed>>,
}

impl FixedManagedNetwork {
    /// An overlay that answers `managed` until changed.
    #[must_use]
    pub fn new(managed: Option<ManagedNetwork>) -> Self {
        Self {
            locked: Mutex::new(managed),
            ..Self::default()
        }
    }

    /// The same overlay with unlocked defaults.
    #[must_use]
    pub fn with_defaults(self, defaults: ManagedDefaults) -> Self {
        *lock_ignoring_poison(&self.defaults) = defaults;
        self
    }

    /// The same overlay, closed.
    #[must_use]
    pub fn with_closed(self, closed: PolicyClosed) -> Self {
        *lock_ignoring_poison(&self.closed) = Some(closed);
        self
    }
}

impl ManagedNetworkLayer for FixedManagedNetwork {
    fn current(&self) -> Option<ManagedNetwork> {
        lock_ignoring_poison(&self.locked).clone()
    }

    fn defaults(&self) -> ManagedDefaults {
        lock_ignoring_poison(&self.defaults).clone()
    }

    fn closed(&self) -> Option<PolicyClosed> {
        lock_ignoring_poison(&self.closed).clone()
    }
}

fn lock_ignoring_poison<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// The managed policy as the overlay: the handle's locked fields (the CA
/// record included, imported by the loader), the policy's defaults, and the
/// handle's closure. The closure is `PolicyHandle::network_closed`, not the
/// view's, because only the handle knows about a CA import that failed.
#[derive(Debug, Clone)]
pub struct PolicyNetwork(Arc<PolicyHandle>);

impl PolicyNetwork {
    /// The overlay over `policy`.
    #[must_use]
    pub fn new(policy: Arc<PolicyHandle>) -> Self {
        Self(policy)
    }
}

impl ManagedNetworkLayer for PolicyNetwork {
    fn current(&self) -> Option<ManagedNetwork> {
        self.0.managed_network()
    }

    fn defaults(&self) -> ManagedDefaults {
        let view = self.0.view();
        let policy = view.policy();
        // A default applies only while its leaf is in force and not a lock
        // (the modes exclude each other; a lock is `current`'s).
        let in_force = |key: Key| view.status(key).is_some_and(LeafStatus::in_force);
        ManagedDefaults {
            no_proxy: policy
                .no_proxy
                .as_ref()
                .filter(|_| in_force(Key::NetworkNoProxy))
                .and_then(|leaf| leaf.default.clone()),
            engine_mirror: policy
                .engine_mirror
                .as_ref()
                .filter(|_| in_force(Key::NetworkEngineMirror))
                .and_then(|leaf| leaf.default.clone()),
            models_mirror: policy
                .models_mirror
                .as_ref()
                .filter(|_| in_force(Key::NetworkModelsMirror))
                .and_then(|leaf| leaf.default.clone()),
        }
    }

    fn closed(&self) -> Option<PolicyClosed> {
        self.0.network_closed().map(|closed| PolicyClosed {
            key: closed.key.path().to_owned(),
            code: closed.code.to_owned(),
            detail: closed.detail,
        })
    }
}

/// Where a field's effective value comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    /// Neither the user nor a policy set it.
    Default,
    /// The user's document.
    User,
    /// The managed policy: a locked value, or an unlocked default (see
    /// [`Lock`]).
    Policy,
}

impl Source {
    /// The wire word.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Default => "default",
            Self::User => "user",
            Self::Policy => "policy",
        }
    }

    /// Whether a value from this source is locked *unless the policy only
    /// supplied a default*: true for [`Self::Policy`]. The authority on
    /// whether the human may edit a field is [`Resolved::lock`].
    #[must_use]
    pub fn locked(self) -> bool {
        self == Self::Policy
    }
}

/// Whether the human may edit a field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lock {
    /// The human may change it.
    Open,
    /// The policy owns it.
    Locked,
}

impl Lock {
    /// Whether the policy owns the field.
    #[must_use]
    pub fn is_locked(self) -> bool {
        self == Self::Locked
    }
}

/// The fields of the document, as the ops name them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Field {
    /// `proxy`.
    Proxy,
    /// `no_proxy`.
    NoProxy,
    /// `ca_bundle`.
    CaBundle,
    /// `engine_mirror`.
    EngineMirror,
    /// `models_mirror`.
    ModelsMirror,
}

impl Field {
    /// Every field, in document order.
    pub const ALL: [Self; 5] = [
        Self::Proxy,
        Self::NoProxy,
        Self::CaBundle,
        Self::EngineMirror,
        Self::ModelsMirror,
    ];

    /// The document key.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proxy => "proxy",
            Self::NoProxy => "no_proxy",
            Self::CaBundle => "ca_bundle",
            Self::EngineMirror => "engine_mirror",
            Self::ModelsMirror => "models_mirror",
        }
    }

    /// The policy key that governs the field.
    #[must_use]
    pub fn policy_key(self) -> Key {
        match self {
            Self::Proxy => Key::NetworkProxy,
            Self::NoProxy => Key::NetworkNoProxy,
            Self::CaBundle => Key::NetworkCaBundle,
            Self::EngineMirror => Key::NetworkEngineMirror,
            Self::ModelsMirror => Key::NetworkModelsMirror,
        }
    }
}

/// The user's document under the managed overlay: the effective values,
/// and per field where each came from and whether the human may edit it.
#[derive(Debug, Clone)]
pub struct Resolved {
    /// The effective document.
    pub document: NetworkDocument,
    /// Where each field's value came from, and whether it is locked.
    pub sources: [(Field, Source, Lock); 5],
    /// The policy's mirror allowlist (empty: any host).
    pub mirror_allowed_hosts: Vec<String>,
}

impl Resolved {
    /// Where `field` came from.
    #[must_use]
    pub fn source(&self, field: Field) -> Source {
        self.entry(field).0
    }

    /// Whether the human may edit `field`.
    #[must_use]
    pub fn lock(&self, field: Field) -> Lock {
        self.entry(field).1
    }

    /// Whether the policy owns `field`.
    #[must_use]
    pub fn is_locked(&self, field: Field) -> bool {
        self.lock(field).is_locked()
    }

    /// `field`'s source and lock.
    #[must_use]
    pub fn entry(&self, field: Field) -> (Source, Lock) {
        self.sources
            .iter()
            .find(|(candidate, _, _)| *candidate == field)
            .map_or((Source::Default, Lock::Open), |(_, source, lock)| {
                (*source, *lock)
            })
    }

    /// The fields the policy owns, in document order.
    #[must_use]
    pub fn locked_fields(&self) -> Vec<Field> {
        self.sources
            .iter()
            .filter(|(_, _, lock)| lock.is_locked())
            .map(|(field, _, _)| *field)
            .collect()
    }

    /// Whether the proxy password is the policy's to lock: the proxy is
    /// locked and needs no password (`auth: none`, or a pinned direct
    /// connection). With `basic` or `anyauth` the policy never carries the
    /// secret, so the password stays the human's to type.
    #[must_use]
    pub fn credential_locked(&self) -> bool {
        self.is_locked(Field::Proxy)
            && self
                .document
                .proxy
                .as_ref()
                .is_none_or(|proxy| proxy.auth == ProxyAuth::None.as_str())
    }
}

/// `effective = locked.or(user).or(default)`, per field, with its source
/// and lock. No defaults: see [`resolve_layers`].
#[must_use]
pub fn resolve(user: &NetworkDocument, managed: Option<&ManagedNetwork>) -> Resolved {
    resolve_layers(user, managed, &ManagedDefaults::default())
}

/// `effective = locked.or(user).or(default).unwrap_or(builtin)`, per
/// field. A locked field is `(Policy, Locked)`; the user's value is
/// `(User, Open)`; a policy default, used only while the user has none, is
/// `(Policy, Open)`; otherwise `(Default, Open)`.
#[must_use]
pub fn resolve_layers(
    user: &NetworkDocument,
    managed: Option<&ManagedNetwork>,
    defaults: &ManagedDefaults,
) -> Resolved {
    fn pick<T: Clone>(
        locked: Option<&Option<T>>,
        user: Option<&T>,
        default: Option<&Option<T>>,
    ) -> (Option<T>, Source, Lock) {
        match (locked, user, default) {
            (Some(pinned), _, _) => (pinned.clone(), Source::Policy, Lock::Locked),
            (None, Some(value), _) => (Some(value.clone()), Source::User, Lock::Open),
            (None, None, Some(default)) => (default.clone(), Source::Policy, Lock::Open),
            (None, None, None) => (None, Source::Default, Lock::Open),
        }
    }
    let (proxy, proxy_source, proxy_lock) = pick(
        managed.and_then(|m| m.proxy.as_ref()),
        user.proxy.as_ref(),
        None,
    );
    let (no_proxy, no_proxy_source, no_proxy_lock) = match managed.and_then(|m| m.no_proxy.as_ref())
    {
        Some(pinned) => (pinned.clone(), Source::Policy, Lock::Locked),
        None if !user.no_proxy.is_empty() => (user.no_proxy.clone(), Source::User, Lock::Open),
        None => match &defaults.no_proxy {
            Some(default) => (default.clone(), Source::Policy, Lock::Open),
            None => (Vec::new(), Source::Default, Lock::Open),
        },
    };
    let (ca_bundle, ca_source, ca_lock) = pick(
        managed.and_then(|m| m.ca_bundle.as_ref()),
        user.ca_bundle.as_ref(),
        None,
    );
    let (engine_mirror, engine_source, engine_lock) = pick(
        managed.and_then(|m| m.engine_mirror.as_ref()),
        user.engine_mirror.as_ref(),
        defaults.engine_mirror.as_ref(),
    );
    let (models_mirror, models_source, models_lock) = pick(
        managed.and_then(|m| m.models_mirror.as_ref()),
        user.models_mirror.as_ref(),
        defaults.models_mirror.as_ref(),
    );
    Resolved {
        document: NetworkDocument {
            version: DOCUMENT_VERSION,
            proxy,
            no_proxy,
            ca_bundle,
            engine_mirror,
            models_mirror,
        },
        sources: [
            (Field::Proxy, proxy_source, proxy_lock),
            (Field::NoProxy, no_proxy_source, no_proxy_lock),
            (Field::CaBundle, ca_source, ca_lock),
            (Field::EngineMirror, engine_source, engine_lock),
            (Field::ModelsMirror, models_source, models_lock),
        ],
        mirror_allowed_hosts: managed
            .map(|m| m.mirror_allowed_hosts.clone())
            .unwrap_or_default(),
    }
}

/// Everything one read of the settings produced: the raw bytes (for the
/// compare-and-swap a save does), the user's document, the overlay
/// resolution and the validated values.
#[derive(Debug, Clone)]
pub struct Loaded {
    /// The stored bytes, `None` when no document exists.
    pub raw: Option<String>,
    /// The user's own document (defaults when none is stored).
    pub user: NetworkDocument,
    /// The effective document and its sources.
    pub resolved: Resolved,
    /// The effective document, validated.
    pub valid: ValidNetwork,
}

/// Why a stored document cannot be used. The raw bytes come along so a
/// save can still replace the document.
#[derive(Debug, Clone)]
pub struct Invalid {
    /// The stored bytes.
    pub raw: Option<String>,
    /// The sentence.
    pub detail: String,
}

/// Why a CA bundle import was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CaImportError {
    /// The path, or the file behind it, is not one PAM reads.
    Source(String),
    /// The content is not a certificate bundle.
    Content(CaError),
    /// The private copy could not be written.
    Copy(String),
}

impl std::fmt::Display for CaImportError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Source(detail) => write!(formatter, "the CA bundle was not imported: {detail}"),
            Self::Content(error) => write!(formatter, "the CA bundle was not imported: {error}"),
            Self::Copy(detail) => write!(
                formatter,
                "the CA bundle was read but its private copy could not be written: {detail}"
            ),
        }
    }
}

impl std::error::Error for CaImportError {}

/// The daemon's network settings service (see the module docs).
pub struct NetworkService {
    store: Arc<Store>,
    /// The keychain the proxy password lives in; `None` when the platform
    /// store did not open, in which case a sign-in mode that needs a
    /// password refuses rather than sending none.
    secrets: Option<Arc<SecretStore>>,
    /// The daemon's base directory; private copies live under `<base>/net`.
    base: PathBuf,
    managed: Arc<dyn ManagedNetworkLayer>,
    /// The last resolved profile and when it was taken.
    cache: Mutex<Option<(Instant, Arc<NetSettings>)>>,
    /// Lets the in-crate tests probe a plain-http loopback origin; production
    /// has no such switch.
    #[cfg(test)]
    plain_http_for_tests: std::sync::atomic::AtomicBool,
}

impl std::fmt::Debug for NetworkService {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NetworkService")
            .field("base", &self.base)
            .field("store_available", &self.secrets.is_some())
            .finish_non_exhaustive()
    }
}

impl NetworkService {
    /// Builds the service over the store, the keychain (when it opened)
    /// and the daemon's base directory. No policy layer: every field is
    /// the user's until [`Self::with_managed`].
    #[must_use]
    pub fn new(store: Arc<Store>, secrets: Option<Arc<SecretStore>>, base: PathBuf) -> Self {
        Self {
            store,
            secrets,
            base,
            managed: Arc::new(NoManagedNetwork),
            cache: Mutex::new(None),
            #[cfg(test)]
            plain_http_for_tests: std::sync::atomic::AtomicBool::new(false),
        }
    }

    /// The same service under a managed overlay.
    #[must_use]
    pub fn with_managed(mut self, managed: Arc<dyn ManagedNetworkLayer>) -> Self {
        self.managed = managed;
        self.invalidate();
        self
    }

    /// The same service under the managed policy: its locked fields, its
    /// defaults, its closure, and the CA copy its loader imported. Same as
    /// `with_managed(PolicyNetwork::new(policy))`.
    #[must_use]
    pub fn with_policy(self, policy: Arc<PolicyHandle>) -> Self {
        self.with_managed(Arc::new(PolicyNetwork::new(policy)))
    }

    /// Whether the keychain opened: what `credential.store_available` reports.
    #[must_use]
    pub fn store_available(&self) -> bool {
        self.secrets.is_some()
    }

    /// `<base>/net`, where private CA copies live.
    #[must_use]
    pub fn net_dir(&self) -> PathBuf {
        self.base.join(NET_DIR)
    }

    /// The private copy a digest names: `<base>/net/ca-<sha12>.pem`.
    #[must_use]
    pub fn copy_path(&self, sha256: &str) -> PathBuf {
        let prefix: String = sha256.chars().take(COPY_DIGEST_CHARS).collect();
        self.net_dir().join(format!("ca-{prefix}.pem"))
    }

    /// Lets this service's probes reach a plain-`http` loopback origin, the
    /// way the fixtures are served. Test builds only.
    #[cfg(test)]
    pub(crate) fn allow_plain_http_probes_for_tests(&self) {
        self.plain_http_for_tests
            .store(true, std::sync::atomic::Ordering::Release);
    }

    /// Whether probes may use plain http (test builds only).
    #[must_use]
    #[cfg_attr(
        not(test),
        allow(clippy::unused_self, reason = "the switch exists in test builds only")
    )]
    pub(crate) fn plain_http_probes(&self) -> bool {
        #[cfg(test)]
        {
            self.plain_http_for_tests
                .load(std::sync::atomic::Ordering::Acquire)
        }
        #[cfg(not(test))]
        {
            false
        }
    }

    /// Forgets the cached profile: the next spawn reads the document and
    /// the keychain again.
    pub fn invalidate(&self) {
        *self
            .cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
    }

    /// Reads the document, resolves the overlay and validates. A corrupt
    /// document is `Err(Invalid)` with the sentence and the bytes.
    ///
    /// # Errors
    ///
    /// `Ok(Err(_))` is a corrupt document; `Err(_)` the store.
    pub async fn load(&self) -> Result<Result<Loaded, Invalid>, StoreError> {
        let raw = match self
            .store
            .get_setting_bounded(SETTING_KEY, MAX_DOCUMENT_BYTES)
            .await
        {
            Ok(raw) => raw,
            Err(StoreError::UnexpectedValue { .. }) => {
                return Ok(Err(Invalid {
                    raw: None,
                    detail: format!(
                        "the stored network settings exceed {MAX_DOCUMENT_BYTES} bytes"
                    ),
                }));
            }
            Err(error) => return Err(error),
        };
        let user = match raw.as_deref() {
            None => NetworkDocument::default(),
            Some(text) => match NetworkDocument::parse(text) {
                Ok(document) => document,
                Err(detail) => return Ok(Err(Invalid { raw, detail })),
            },
        };
        Ok(self.resolve_user(raw, user))
    }

    /// Resolves and validates a user document that already parsed.
    fn resolve_user(&self, raw: Option<String>, user: NetworkDocument) -> Result<Loaded, Invalid> {
        let managed = self.managed.current();
        let resolved = resolve_layers(&user, managed.as_ref(), &self.managed.defaults());
        let allowed = match parse_no_proxy(&resolved.mirror_allowed_hosts) {
            Ok(rules) => rules,
            Err(error) => {
                return Err(Invalid {
                    raw,
                    detail: format!("the policy's mirror_allowed_hosts is not valid: {error}"),
                });
            }
        };
        match resolved.document.validate(&allowed) {
            Ok(valid) => Ok(Loaded {
                raw,
                user,
                resolved,
                valid,
            }),
            Err(error) => Err(Invalid {
                raw,
                detail: error.to_string(),
            }),
        }
    }

    /// Validates a candidate user document under the current overlay,
    /// without touching the store: what a save checks before writing.
    ///
    /// # Errors
    ///
    /// The field and sentence of the first rule the document breaks.
    pub fn check(&self, user: &NetworkDocument) -> Result<Loaded, String> {
        self.resolve_user(None, user.clone())
            .map_err(|invalid| invalid.detail)
    }

    /// Writes `document` when the stored bytes are still `expected`,
    /// answering whether they were. The cache is invalidated either way.
    ///
    /// # Errors
    ///
    /// The store's.
    pub async fn save(
        &self,
        expected: Option<&str>,
        document: &NetworkDocument,
    ) -> Result<bool, StoreError> {
        let written = self
            .store
            .compare_exchange_setting(SETTING_KEY, expected, &document.to_json())
            .await;
        self.invalidate();
        written
    }

    /// Whether a proxy password is stored, and whether the keychain
    /// answered.
    pub async fn credential_present(&self) -> (bool, bool) {
        let Some(secrets) = &self.secrets else {
            return (false, false);
        };
        match secrets.present(PROXY_CREDENTIAL_ID).await {
            Ok(present) => (present, true),
            Err(error) => {
                tracing::warn!(
                    cause = error.cause(),
                    "could not read whether a proxy password is stored"
                );
                (false, false)
            }
        }
    }

    /// Stores the proxy password. The value was validated as a
    /// [`ProxyPassword`] by the caller.
    ///
    /// # Errors
    ///
    /// The keychain's sanitized error; `Unavailable` when it never opened.
    pub async fn set_credential(&self, secret: Secret) -> Result<(), SecretError> {
        let secrets = self.secrets.as_ref().ok_or(SecretError::Unavailable)?;
        let written = secrets.set(PROXY_CREDENTIAL_ID, secret).await;
        self.invalidate();
        written
    }

    /// Deletes the proxy password, answering whether one existed.
    ///
    /// # Errors
    ///
    /// The keychain's sanitized error; `Unavailable` when it never opened.
    pub async fn clear_credential(&self) -> Result<bool, SecretError> {
        let secrets = self.secrets.as_ref().ok_or(SecretError::Unavailable)?;
        let cleared = secrets.clear(PROXY_CREDENTIAL_ID).await;
        self.invalidate();
        cleared
    }

    /// Imports the bundle at `source`: checks the file, normalizes its
    /// certificate blocks, writes the private copy named by their digest
    /// and answers the record to store. Runs on the blocking lane; the
    /// source is read once and never again.
    ///
    /// # Errors
    ///
    /// [`CaImportError`], with nothing written on a refusal.
    pub async fn import_ca(&self, source: &Path) -> Result<CaBundleEntry, CaImportError> {
        let source = source.to_path_buf();
        let net_dir = self.net_dir();
        let imported_ts = crate::retention::now_ts();
        crate::blocking_jobs::run(crate::blocking_jobs::Kind::ModelFilesystem, move || {
            import_ca_blocking(&source, &net_dir, imported_ts)
        })
        .await
        .map_err(|error| CaImportError::Copy(error.to_string()))?
    }

    /// Removes private copies no record names any more. `keep` is the
    /// digest still in use; the managed policy's copy, which the policy
    /// loader wrote into the same directory, is always kept.
    pub fn prune_ca_copies(&self, keep: Option<&str>) {
        let managed = self
            .managed
            .current()
            .and_then(|managed| managed.ca_bundle)
            .flatten();
        let keep_paths: Vec<PathBuf> = keep
            .into_iter()
            .chain(managed.as_ref().map(|bundle| bundle.sha256.as_str()))
            .map(|sha256| self.copy_path(sha256))
            .collect();
        let Ok(entries) = std::fs::read_dir(self.net_dir()) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if !name.starts_with("ca-") || !name.ends_with(".pem") {
                continue;
            }
            if keep_paths.contains(&path) {
                continue;
            }
            if let Err(error) = std::fs::remove_file(&path) {
                tracing::debug!(%error, path = %path.display(), "an unreferenced CA copy stayed");
            }
        }
    }

    /// Whether the source file a bundle was imported from still
    /// normalizes to the recorded digest; `None` when it cannot be read.
    pub async fn source_changed(&self, bundle: &CaBundleEntry) -> Option<bool> {
        let source = PathBuf::from(bundle.source_path.as_deref()?);
        let recorded = bundle.sha256.clone();
        crate::blocking_jobs::run(crate::blocking_jobs::Kind::ModelFilesystem, move || {
            let metadata = std::fs::metadata(&source).ok()?;
            if !metadata.is_file() || metadata.len() > pam_net::ca::MAX_BUNDLE_BYTES {
                return None;
            }
            let bytes = std::fs::read(&source).ok()?;
            let normalized = normalize_pem(&bytes).ok()?;
            Some(sha256_hex(normalized.pem.as_bytes()) != recorded)
        })
        .await
        .ok()
        .flatten()
    }

    /// The resolved profile for the next spawn: the document under the
    /// overlay, the keychain password when the sign-in mode needs one, and
    /// the CA copy checked against its digest. Cached for [`CACHE_TTL`].
    ///
    /// # Errors
    ///
    /// A [`NetFailure`] naming the cause; never a direct fallback.
    pub async fn resolve_settings(&self) -> Result<Arc<NetSettings>, NetFailure> {
        // Before the cache: a closure applies the moment the policy says so.
        self.refuse_when_closed()?;
        if let Some(cached) = self.cached() {
            return Ok(cached);
        }
        let loaded = self
            .load()
            .await
            .map_err(|error| {
                NetFailure::SettingsInvalid(format!("the store did not answer: {error}"))
            })?
            .map_err(|invalid| NetFailure::SettingsInvalid(invalid.detail))?;
        let password = match &loaded.valid.proxy {
            Some(proxy) if proxy.auth() != ProxyAuth::None => self.read_password().await?,
            _ => None,
        };
        let ca_path = match &loaded.valid.ca_bundle {
            Some(bundle) => Some(self.checked_copy(bundle).await?),
            None => None,
        };
        let settings = NetSettings::new(
            loaded.valid.proxy.clone(),
            password,
            loaded.valid.no_proxy.clone(),
            ca_path,
        )
        .map_err(NetFailure::from)?;
        let settings = Arc::new(settings);
        *self
            .cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) =
            Some((Instant::now(), Arc::clone(&settings)));
        Ok(settings)
    }

    /// The validated mirrors of the effective document, for the download
    /// paths and the Test. Not cached: read per call, like a save.
    ///
    /// # Errors
    ///
    /// `network_settings_invalid` for a corrupt document, or for a policy
    /// that cannot be put in force (see [`Self::policy_closed`]).
    pub async fn mirrors(&self) -> Result<(Option<MirrorBase>, Option<MirrorBase>), NetFailure> {
        self.refuse_when_closed()?;
        let loaded = self
            .load()
            .await
            .map_err(|error| {
                NetFailure::SettingsInvalid(format!("the store did not answer: {error}"))
            })?
            .map_err(|invalid| NetFailure::SettingsInvalid(invalid.detail))?;
        Ok((loaded.valid.engine_mirror, loaded.valid.models_mirror))
    }

    /// Why the managed policy closes every consumer, when it does: it named
    /// a proxy, no-proxy list or CA bundle that could not be put in force
    /// and has no last-known-good value. `admin.network.get` reports it.
    #[must_use]
    pub fn policy_closed(&self) -> Option<PolicyClosed> {
        self.managed.closed()
    }

    /// The refusal for [`Self::policy_closed`]. A direct connection would
    /// go around the proxy or the trust the organisation requires, so
    /// nothing is sent. The sentence names the policy key, the code and who
    /// can fix it; the failure is the settings-invalid one every consumer
    /// already maps.
    fn refuse_when_closed(&self) -> Result<(), NetFailure> {
        match self.managed.closed() {
            Some(closed) => Err(NetFailure::SettingsInvalid(policy_closed_sentence(&closed))),
            None => Ok(()),
        }
    }

    fn cached(&self) -> Option<Arc<NetSettings>> {
        let slot = self
            .cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let (taken, settings) = slot.as_ref()?;
        (taken.elapsed() < CACHE_TTL).then(|| Arc::clone(settings))
    }

    /// The proxy password, when one is stored. A keychain that will not
    /// answer refuses the spawn: sending no credential to a proxy that
    /// needs one would fail anyway, but with the wrong story.
    async fn read_password(&self) -> Result<Option<ProxyPassword>, NetFailure> {
        let Some(secrets) = &self.secrets else {
            return Err(NetFailure::SettingsInvalid(
                "the proxy sign-in mode needs a password from the OS credential store, which is \
                 unavailable"
                    .to_owned(),
            ));
        };
        let stored = secrets.get(PROXY_CREDENTIAL_ID).await.map_err(|error| {
            NetFailure::SettingsInvalid(format!(
                "the proxy password could not be read from the OS credential store ({})",
                error.cause()
            ))
        })?;
        stored
            .map(|secret| ProxyPassword::new(secret.expose()).map_err(NetFailure::from))
            .transpose()
    }

    /// The private copy's path once its digest matched the record.
    async fn checked_copy(&self, bundle: &CaBundleEntry) -> Result<PathBuf, NetFailure> {
        let path = self.copy_path(&bundle.sha256);
        let bytes = tokio::fs::read(&path).await.map_err(|error| {
            tracing::warn!(
                %error,
                path = %path.display(),
                "the CA bundle's private copy could not be read"
            );
            NetFailure::CaBundleTampered
        })?;
        if sha256_hex(&bytes) != bundle.sha256 {
            tracing::warn!(
                path = %path.display(),
                "the CA bundle's private copy does not hash to the recorded digest"
            );
            return Err(NetFailure::CaBundleTampered);
        }
        Ok(path)
    }
}

impl NetworkSource for NetworkService {
    fn settings(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<Arc<NetSettings>, NetFailure>> + Send + '_>> {
        Box::pin(self.resolve_settings())
    }
}

/// The names of proxy and CA variables present in this process's
/// environment. Names only, never values; nothing reads them.
#[must_use]
pub fn ignored_env() -> Vec<String> {
    let present: BTreeSet<String> = IGNORED_ENV
        .iter()
        .filter(|name| std::env::var_os(name).is_some())
        .map(|name| (*name).to_owned())
        .collect();
    present.into_iter().collect()
}

/// The sentence a closed consumer is refused with.
#[must_use]
pub fn policy_closed_sentence(closed: &PolicyClosed) -> String {
    format!(
        "your organisation's policy ({}) could not be put in force ({}): {}; nothing was sent \
         because it would bypass what your organisation requires. Ask your administrator to \
         correct the policy file",
        closed.key, closed.code, closed.detail
    )
}

/// Lowercase hex SHA-256 of `bytes`.
#[must_use]
pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// The import, on a blocking thread: source checks, normalization, private
/// copy.
fn import_ca_blocking(
    source: &Path,
    net_dir: &Path,
    imported_ts: i64,
) -> Result<CaBundleEntry, CaImportError> {
    let refuse = |detail: String| Err(CaImportError::Source(detail));
    if !source.is_absolute() {
        return refuse("give an absolute path to the bundle".to_owned());
    }
    let canonical = match std::fs::canonicalize(source) {
        Ok(path) => path,
        Err(error) => return refuse(format!("{} cannot be opened: {error}", source.display())),
    };
    let metadata = match std::fs::metadata(&canonical) {
        Ok(metadata) => metadata,
        Err(error) => return refuse(format!("{} cannot be read: {error}", source.display())),
    };
    if !metadata.is_file() {
        return refuse(format!("{} is not a regular file", source.display()));
    }
    if metadata.len() > pam_net::ca::MAX_BUNDLE_BYTES {
        return refuse(format!(
            "{} is {} bytes; a CA bundle is at most {} bytes",
            source.display(),
            metadata.len(),
            pam_net::ca::MAX_BUNDLE_BYTES
        ));
    }
    // The private directory exists before the ownership check: a file this
    // process just created is how it learns its own user id without the
    // environment or `unsafe`.
    if let Err(error) = create_private_dir(net_dir) {
        return Err(CaImportError::Copy(format!(
            "{} could not be created: {error}",
            net_dir.display()
        )));
    }
    #[cfg(unix)]
    if let Some(detail) = unix_source_refusal(&canonical, &metadata, net_dir) {
        return refuse(detail);
    }
    let bytes = match std::fs::read(&canonical) {
        Ok(bytes) => bytes,
        Err(error) => return refuse(format!("{} cannot be read: {error}", source.display())),
    };
    let normalized = normalize_pem(&bytes).map_err(CaImportError::Content)?;
    let sha256 = sha256_hex(normalized.pem.as_bytes());
    let prefix: String = sha256.chars().take(COPY_DIGEST_CHARS).collect();
    let copy = net_dir.join(format!("ca-{prefix}.pem"));
    // Content-addressed: an existing copy with this name holds these bytes
    // already, and is never overwritten while in use.
    if !copy.exists() {
        write_private_file(&copy, normalized.pem.as_bytes())
            .map_err(|error| CaImportError::Copy(format!("{}: {error}", copy.display())))?;
    }
    Ok(CaBundleEntry {
        sha256,
        certificates: normalized.certificates,
        source_path: Some(source.display().to_string()),
        imported_ts: Some(imported_ts),
    })
}

/// The trust rule for a source file on macOS: owned by root or by this
/// user, and neither it nor its directory writable by the group or the
/// world — the rule the trusted curl path uses, so an agent-writable file
/// cannot become what PAM trusts.
#[cfg(unix)]
fn unix_source_refusal(
    canonical: &Path,
    metadata: &std::fs::Metadata,
    net_dir: &Path,
) -> Option<String> {
    use std::os::unix::fs::MetadataExt as _;
    let own_uid = std::fs::metadata(net_dir).ok()?.uid();
    if metadata.uid() != 0 && metadata.uid() != own_uid {
        return Some(format!(
            "{} is owned by another user (uid {}); PAM imports only files owned by root or by \
             the user it runs as",
            canonical.display(),
            metadata.uid()
        ));
    }
    if metadata.mode() & 0o022 != 0 {
        return Some(format!(
            "{} is writable by its group or by everyone; a file other users can change cannot \
             be what PAM trusts",
            canonical.display()
        ));
    }
    let parent = canonical.parent()?;
    let dir = std::fs::metadata(parent).ok()?;
    if dir.mode() & 0o022 != 0 && dir.mode() & 0o1000 == 0 {
        return Some(format!(
            "the directory {} is writable by its group or by everyone; move the bundle to a \
             directory only you or root can write",
            parent.display()
        ));
    }
    None
}

/// Creates `dir` owner-only on Unix.
fn create_private_dir(dir: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir_all(dir)
    }
}

/// Writes `bytes` to `path` atomically, owner-only on Unix: a sibling temp
/// file, synced, renamed into place.
fn write_private_file(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write as _;
    let temp = path.with_extension("tmp");
    let _ = std::fs::remove_file(&temp);
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options.open(&temp)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);
    std::fs::rename(&temp, path).inspect_err(|_| {
        let _ = std::fs::remove_file(&temp);
    })
}
