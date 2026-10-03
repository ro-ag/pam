//! The managed policy document: an organisation's read-only file, parsed,
//! validated leaf by leaf, and merged over the human's settings at read time.
//!
//! This module is pure: no I/O, no async, no store. The trust check that
//! reads the file lives in `managed_policy_trust`; the service that holds
//! the current view, the last-known-good copy and the reload loop lives in
//! a later module. What is here:
//!
//! - **The strict reader** ([`inspect_bytes`]): at most [`MAX_POLICY_BYTES`],
//!   a leading UTF-8 byte-order mark stripped (the digest covers the raw
//!   bytes, mark included), JSON nested at most [`MAX_DEPTH`] deep, and a
//!   duplicate key at any depth refused (`serde_json` would silently keep
//!   the last). `version` must be [`POLICY_VERSION`]. Any of these failing
//!   is a *file-level* failure ([`FileFailure`]): every leaf is lost at once.
//! - **The closed key table** ([`Key`]): every leaf the grammar knows, with
//!   its [`Tier`] (the failure class) and its [`KeyRefusal`] (what an admin
//!   op refuses with when the key blocks a write). An unknown name is a
//!   rejected leaf, never ignored and never fatal.
//! - **Per-leaf validation** that reuses the validators the human's own
//!   admin ops apply (`pam_net`'s `Proxy`, `MirrorBase` and
//!   `parse_no_proxy`, the flow allowlist rule `check_allowed_program`, the
//!   retention pair rule [`crate::retention::validate`], the profile,
//!   connector and curator names), so a policy value is never one the GUI
//!   would refuse. A rejected leaf is a [`Diagnostic`] with a stable code
//!   (the `CODE_*` constants) and its key's [`LeafStatus`].
//! - **The merge functions** (the `effective_*` methods of [`PolicyView`]
//!   and the plain functions [`stricter`], [`clamp_window`],
//!   [`intersect_exact`], [`pattern_matches`]): `effective = locked ??
//!   clamp(user, bounds) ?? default ?? builtin`, a function of `(user,
//!   policy)` only, monotone in the safe direction. A policy tightens; it
//!   loosens only through an explicit, validated key (`locked` or
//!   `default`).
//! - **The `effective` entry** ([`EffectiveEntry`]): the per-field shape
//!   `admin.network.get` already answers (`{ source, locked }`, with
//!   [`Source`] from the network service), extended with `mode`,
//!   `constraint`, `reason`, `state` and `clamped` when a policy is in play.
//!
//! A held key (Tier A, rejected, no last-known-good value) reads as the
//! user's value and refuses every write with [`CAUSE_POLICY_FROZEN`]; see
//! [`PolicyView::with_fallback`] and [`PolicyView::frozen`].

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{self, Write as _};
use std::path::Path;

use pam_connectors::ConnectorId;
use pam_model::curator::AgentId;
use pam_net::{MirrorBase, NoProxyRule, Proxy, ProxyAuth, Url, parse_no_proxy};
use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Number, Value, json};
use sha2::{Digest, Sha256};

use crate::network_service::{ManagedNetwork, ProxyEntry, Source};
use crate::policy::{CapabilityClass, Profile};
use crate::retention::{MAX_DAYS, RetentionSettings};

/// The one document version this binary reads.
pub const POLICY_VERSION: u64 = 1;

/// The most bytes a policy file may have.
pub const MAX_POLICY_BYTES: usize = 64 * 1024;

/// The most bytes any string in the document may have.
pub const MAX_STRING_BYTES: usize = 1024;

/// The most entries any list in the document may have.
pub const MAX_LIST_ENTRIES: usize = 256;

/// The most characters a mode object's `reason` may have.
pub const MAX_REASON_CHARS: usize = 200;

/// The deepest the JSON may nest (the top-level object is depth 1). The
/// grammar itself needs five.
pub const MAX_DEPTH: usize = 8;

/// The UTF-8 byte-order mark Windows PowerShell 5.1 writes.
const BOM: &[u8] = b"\xEF\xBB\xBF";

/// Refusal cause for a write to a key the policy locks (the network
/// settings' existing cause).
pub const CAUSE_SETTING_LOCKED: &str = crate::admin_network::CAUSE_SETTING_LOCKED;

/// Refusal cause for a value outside a policy allowlist or bound.
pub const CAUSE_POLICY_NOT_ALLOWED: &str = "policy_not_allowed";

/// Refusal cause for a write to a held key: the policy governs it but its
/// value cannot be resolved right now.
pub const CAUSE_POLICY_FROZEN: &str = "policy_frozen";

/// Refusal cause the gate gives for a capability a `never` rule matches.
pub const CAUSE_POLICY_DENIED: &str = "policy_denied";

/// The validation cause a mirror outside `mirror_allowed_hosts` already
/// refuses with.
pub const CAUSE_NETWORK_SETTINGS_INVALID: &str = crate::admin_network::CAUSE_NETWORK_INVALID;

/// The recovery line every policy refusal carries.
pub const RECOVERY_MANAGED: &str = "Managed by your organisation's policy; ask your administrator.";

// --- File-level diagnostic codes ---------------------------------------

/// File-level: more than [`MAX_POLICY_BYTES`].
pub const CODE_TOO_LARGE: &str = "policy_too_large";
/// File-level: the bytes are not UTF-8.
pub const CODE_NOT_UTF8: &str = "policy_not_utf8";
/// File-level: the text is not JSON.
pub const CODE_NOT_JSON: &str = "policy_not_json";
/// File-level: a key appears twice in one object.
pub const CODE_DUPLICATE_KEY: &str = "policy_duplicate_key";
/// File-level: the JSON nests deeper than [`MAX_DEPTH`].
pub const CODE_TOO_DEEP: &str = "policy_too_deep";
/// File-level: the top level is not an object.
pub const CODE_NOT_OBJECT: &str = "policy_not_object";
/// File-level: no `version`.
pub const CODE_VERSION_MISSING: &str = "policy_version_missing";
/// File-level: a `version` this binary does not read.
pub const CODE_VERSION_UNSUPPORTED: &str = "policy_version_unsupported";

// --- Leaf-level diagnostic codes ---------------------------------------

/// Leaf: a name the closed key table does not have.
pub const CODE_UNKNOWN_KEY: &str = "policy_unknown_key";
/// Leaf: the value has the wrong JSON type.
pub const CODE_WRONG_TYPE: &str = "policy_wrong_type";
/// Leaf: a mode object names no mode.
pub const CODE_MODE_MISSING: &str = "policy_mode_missing";
/// Leaf: a mode this key does not take.
pub const CODE_MODE_UNSUPPORTED: &str = "policy_mode_unsupported";
/// Leaf: modes that contradict each other (`locked` with another, a
/// `default` outside the bounds, `min` above `max`).
pub const CODE_MODE_CONFLICT: &str = "policy_mode_conflict";
/// Leaf: the value fails the setting's own validation.
pub const CODE_VALUE_INVALID: &str = "policy_value_invalid";
/// Leaf: a string longer than [`MAX_STRING_BYTES`].
pub const CODE_STRING_TOO_LONG: &str = "policy_string_too_long";
/// Leaf: a list longer than [`MAX_LIST_ENTRIES`].
pub const CODE_LIST_TOO_LONG: &str = "policy_list_too_long";
/// Leaf: a string holding a control character.
pub const CODE_CONTROL_CHARACTER: &str = "policy_control_character";
/// Leaf: a `reason` longer than [`MAX_REASON_CHARS`].
pub const CODE_REASON_TOO_LONG: &str = "policy_reason_too_long";
/// Leaf: the retention windows the policy forces break "evidence may not
/// outlive audit" (reported on `retention.evidence_days`).
pub const CODE_RETENTION_PAIR: &str = "policy_retention_pair_invalid";
/// Held: the key is managed but its value cannot be resolved.
pub const CODE_FROZEN: &str = CAUSE_POLICY_FROZEN;

/// Every diagnostic code, file-level and leaf-level, for the tests that
/// keep them stable and unique.
pub const ALL_CODES: [&str; 22] = [
    CODE_TOO_LARGE,
    CODE_NOT_UTF8,
    CODE_NOT_JSON,
    CODE_DUPLICATE_KEY,
    CODE_TOO_DEEP,
    CODE_NOT_OBJECT,
    CODE_VERSION_MISSING,
    CODE_VERSION_UNSUPPORTED,
    CODE_UNKNOWN_KEY,
    CODE_WRONG_TYPE,
    CODE_MODE_MISSING,
    CODE_MODE_UNSUPPORTED,
    CODE_MODE_CONFLICT,
    CODE_VALUE_INVALID,
    CODE_STRING_TOO_LONG,
    CODE_LIST_TOO_LONG,
    CODE_CONTROL_CHARACTER,
    CODE_REASON_TOO_LONG,
    CODE_RETENTION_PAIR,
    CODE_FROZEN,
    CAUSE_POLICY_NOT_ALLOWED,
    CAUSE_POLICY_DENIED,
];

// --- Platform -----------------------------------------------------------

/// The platform a document's paths are checked for. `pam policy check
/// --for windows` checks a Windows file on a Mac.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TargetPlatform {
    /// `/absolute/paths`, compared case-sensitively.
    Macos,
    /// `C:\drive\paths` or `\\server\share`, compared case-insensitively.
    Windows,
}

impl TargetPlatform {
    /// The platform this binary runs on.
    #[must_use]
    pub fn host() -> Self {
        if cfg!(windows) {
            Self::Windows
        } else {
            Self::Macos
        }
    }

    /// `macos` or `windows`.
    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "macos" => Some(Self::Macos),
            "windows" => Some(Self::Windows),
            _ => None,
        }
    }

    /// The wire word.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Macos => "macos",
            Self::Windows => "windows",
        }
    }
}

// --- The closed key table ----------------------------------------------

/// The failure class of a key (see the spec's two-tier rule).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tier {
    /// Authority, audit, egress: a failure *exposes*. A rejected leaf with
    /// no last-known-good value is held: writes freeze, nothing loosens.
    A,
    /// Convenience: a failure *inconveniences*. A rejected leaf falls back
    /// to the user's value, with a diagnostic.
    B,
}

impl Tier {
    /// The wire word: `A` or `B`.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::A => "A",
            Self::B => "B",
        }
    }
}

/// A mode of a mode object, or the kind of a plain constraint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Mode {
    /// Value forced, field read-only.
    Locked,
    /// Applied until the human sets their own.
    Default,
    /// An ordered-enum floor: this level or stricter.
    Floor,
    /// A numeric lower bound.
    Min,
    /// A numeric upper bound.
    Max,
    /// The human's set is intersected with this one.
    Allow,
    /// A policy-only constraint that filters or forbids.
    Forbid,
}

impl Mode {
    /// The wire word (also the mode object's field name, except `forbid`).
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Locked => "locked",
            Self::Default => "default",
            Self::Floor => "floor",
            Self::Min => "min",
            Self::Max => "max",
            Self::Allow => "allow",
            Self::Forbid => "forbid",
        }
    }

    /// The mode a mode-object field names.
    fn from_field(name: &str) -> Option<Self> {
        Some(match name {
            "locked" => Self::Locked,
            "default" => Self::Default,
            "floor" => Self::Floor,
            "min" => Self::Min,
            "max" => Self::Max,
            "allow" => Self::Allow,
            _ => return None,
        })
    }
}

/// What an admin op refuses with when a key blocks a write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyRefusal {
    /// A mode object: `locked` refuses [`CAUSE_SETTING_LOCKED`]; a value
    /// outside `floor`/`min`/`max`/`allow` refuses
    /// [`CAUSE_POLICY_NOT_ALLOWED`].
    ByMode,
    /// A plain constraint with one cause.
    Fixed(&'static str),
    /// The key never refuses a write (meta, compliance signal). Chosen
    /// explicitly per key, never by omission.
    Never,
}

impl KeyRefusal {
    /// The cause for a write blocked under `mode` (ignored for plain keys);
    /// `None` when the key never refuses.
    #[must_use]
    pub fn cause(self, mode: Mode) -> Option<&'static str> {
        match self {
            Self::ByMode if mode == Mode::Locked => Some(CAUSE_SETTING_LOCKED),
            Self::ByMode => Some(CAUSE_POLICY_NOT_ALLOWED),
            Self::Fixed(cause) => Some(cause),
            Self::Never => None,
        }
    }
}

/// Every leaf the grammar knows. Declaration order is processing order
/// (`network.mirror_allowed_hosts` before the mirrors it governs).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Key {
    /// `revision`: the administrator's own label.
    Revision,
    /// `organization`: shown in the GUI.
    Organization,
    /// `contact`: shown in refusals.
    Contact,
    /// `comment`: JSON has no comments.
    Comment,
    /// `security.profile`.
    SecurityProfile,
    /// `security.grants.manual`.
    GrantsManual,
    /// `security.grants.remember`.
    GrantsRemember,
    /// `security.grants.never`.
    GrantsNever,
    /// `security.grants.never_classes`.
    GrantsNeverClasses,
    /// `scopes.allowed_repository_roots`.
    ScopesAllowedRepositoryRoots,
    /// `scopes.connector_wide`.
    ScopesConnectorWide,
    /// `connectors.allowed_base_hosts`.
    ConnectorsAllowedBaseHosts,
    /// `connectors.disabled`.
    ConnectorsDisabled,
    /// `flows.programs`.
    FlowsPrograms,
    /// `flows.extra_path`.
    FlowsExtraPath,
    /// `flows.read_cache_roots`.
    FlowsReadCacheRoots,
    /// `flows.artifacts_root`.
    FlowsArtifactsRoot,
    /// `landing.max_permissions`.
    LandingMaxPermissions,
    /// `landing.allowed_github_servers`.
    LandingAllowedGithubServers,
    /// `models.engine_source`.
    ModelsEngineSource,
    /// `models.allowed_sources`.
    ModelsAllowedSources,
    /// `models.allowed_curators`.
    ModelsAllowedCurators,
    /// `models.dir`.
    ModelsDir,
    /// `models.idle_unload_min`.
    ModelsIdleUnloadMin,
    /// `retention.evidence_days`.
    RetentionEvidenceDays,
    /// `retention.audit_days`.
    RetentionAuditDays,
    /// `network.proxy`.
    NetworkProxy,
    /// `network.no_proxy`.
    NetworkNoProxy,
    /// `network.ca_bundle`.
    NetworkCaBundle,
    /// `network.mirror_allowed_hosts`.
    NetworkMirrorAllowedHosts,
    /// `network.engine_mirror`.
    NetworkEngineMirror,
    /// `network.models_mirror`.
    NetworkModelsMirror,
    /// `service.require_login_unit`.
    ServiceRequireLoginUnit,
}

/// The sections of the document, in grammar order.
pub const SECTIONS: [&str; 9] = [
    "security",
    "scopes",
    "connectors",
    "flows",
    "landing",
    "models",
    "retention",
    "network",
    "service",
];

impl Key {
    /// Every key, in declaration order. A compile-time assertion below
    /// keeps its length equal to the number of variants.
    pub const ALL: [Self; 33] = [
        Self::Revision,
        Self::Organization,
        Self::Contact,
        Self::Comment,
        Self::SecurityProfile,
        Self::GrantsManual,
        Self::GrantsRemember,
        Self::GrantsNever,
        Self::GrantsNeverClasses,
        Self::ScopesAllowedRepositoryRoots,
        Self::ScopesConnectorWide,
        Self::ConnectorsAllowedBaseHosts,
        Self::ConnectorsDisabled,
        Self::FlowsPrograms,
        Self::FlowsExtraPath,
        Self::FlowsReadCacheRoots,
        Self::FlowsArtifactsRoot,
        Self::LandingMaxPermissions,
        Self::LandingAllowedGithubServers,
        Self::ModelsEngineSource,
        Self::ModelsAllowedSources,
        Self::ModelsAllowedCurators,
        Self::ModelsDir,
        Self::ModelsIdleUnloadMin,
        Self::RetentionEvidenceDays,
        Self::RetentionAuditDays,
        Self::NetworkProxy,
        Self::NetworkNoProxy,
        Self::NetworkCaBundle,
        Self::NetworkMirrorAllowedHosts,
        Self::NetworkEngineMirror,
        Self::NetworkModelsMirror,
        Self::ServiceRequireLoginUnit,
    ];

    /// The variant's declaration position (`ALL[key.ordinal()] == key`).
    #[must_use]
    pub const fn ordinal(self) -> usize {
        self as usize
    }

    /// The dotted document path.
    #[must_use]
    pub fn path(self) -> &'static str {
        match self {
            Self::Revision => "revision",
            Self::Organization => "organization",
            Self::Contact => "contact",
            Self::Comment => "comment",
            Self::SecurityProfile => "security.profile",
            Self::GrantsManual => "security.grants.manual",
            Self::GrantsRemember => "security.grants.remember",
            Self::GrantsNever => "security.grants.never",
            Self::GrantsNeverClasses => "security.grants.never_classes",
            Self::ScopesAllowedRepositoryRoots => "scopes.allowed_repository_roots",
            Self::ScopesConnectorWide => "scopes.connector_wide",
            Self::ConnectorsAllowedBaseHosts => "connectors.allowed_base_hosts",
            Self::ConnectorsDisabled => "connectors.disabled",
            Self::FlowsPrograms => "flows.programs",
            Self::FlowsExtraPath => "flows.extra_path",
            Self::FlowsReadCacheRoots => "flows.read_cache_roots",
            Self::FlowsArtifactsRoot => "flows.artifacts_root",
            Self::LandingMaxPermissions => "landing.max_permissions",
            Self::LandingAllowedGithubServers => "landing.allowed_github_servers",
            Self::ModelsEngineSource => "models.engine_source",
            Self::ModelsAllowedSources => "models.allowed_sources",
            Self::ModelsAllowedCurators => "models.allowed_curators",
            Self::ModelsDir => "models.dir",
            Self::ModelsIdleUnloadMin => "models.idle_unload_min",
            Self::RetentionEvidenceDays => "retention.evidence_days",
            Self::RetentionAuditDays => "retention.audit_days",
            Self::NetworkProxy => "network.proxy",
            Self::NetworkNoProxy => "network.no_proxy",
            Self::NetworkCaBundle => "network.ca_bundle",
            Self::NetworkMirrorAllowedHosts => "network.mirror_allowed_hosts",
            Self::NetworkEngineMirror => "network.engine_mirror",
            Self::NetworkModelsMirror => "network.models_mirror",
            Self::ServiceRequireLoginUnit => "service.require_login_unit",
        }
    }

    /// The key a dotted path names.
    #[must_use]
    pub fn parse(path: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|key| key.path() == path)
    }

    /// The failure class.
    #[must_use]
    pub fn tier(self) -> Tier {
        match self {
            Self::SecurityProfile
            | Self::GrantsManual
            | Self::GrantsRemember
            | Self::GrantsNever
            | Self::GrantsNeverClasses
            | Self::ScopesAllowedRepositoryRoots
            | Self::ScopesConnectorWide
            | Self::ConnectorsAllowedBaseHosts
            | Self::ConnectorsDisabled
            | Self::FlowsPrograms
            | Self::FlowsExtraPath
            | Self::FlowsReadCacheRoots
            | Self::LandingMaxPermissions
            | Self::LandingAllowedGithubServers
            | Self::ModelsAllowedSources
            | Self::ModelsAllowedCurators
            | Self::RetentionEvidenceDays
            | Self::RetentionAuditDays
            | Self::NetworkProxy
            | Self::NetworkNoProxy
            | Self::NetworkCaBundle => Tier::A,
            Self::Revision
            | Self::Organization
            | Self::Contact
            | Self::Comment
            | Self::FlowsArtifactsRoot
            | Self::ModelsEngineSource
            | Self::ModelsDir
            | Self::ModelsIdleUnloadMin
            | Self::NetworkMirrorAllowedHosts
            | Self::NetworkEngineMirror
            | Self::NetworkModelsMirror
            | Self::ServiceRequireLoginUnit => Tier::B,
        }
    }

    /// What a blocked write refuses with.
    #[must_use]
    pub fn refusal(self) -> KeyRefusal {
        match self {
            Self::SecurityProfile
            | Self::FlowsPrograms
            | Self::FlowsExtraPath
            | Self::FlowsReadCacheRoots
            | Self::FlowsArtifactsRoot
            | Self::ModelsDir
            | Self::ModelsIdleUnloadMin
            | Self::RetentionEvidenceDays
            | Self::RetentionAuditDays
            | Self::NetworkProxy
            | Self::NetworkNoProxy
            | Self::NetworkCaBundle
            | Self::NetworkEngineMirror
            | Self::NetworkModelsMirror => KeyRefusal::ByMode,
            Self::GrantsManual | Self::GrantsRemember | Self::ConnectorsDisabled => {
                KeyRefusal::Fixed(CAUSE_SETTING_LOCKED)
            }
            Self::GrantsNever
            | Self::GrantsNeverClasses
            | Self::ScopesAllowedRepositoryRoots
            | Self::ScopesConnectorWide
            | Self::ConnectorsAllowedBaseHosts
            | Self::LandingMaxPermissions
            | Self::LandingAllowedGithubServers
            | Self::ModelsEngineSource
            | Self::ModelsAllowedSources
            | Self::ModelsAllowedCurators => KeyRefusal::Fixed(CAUSE_POLICY_NOT_ALLOWED),
            Self::NetworkMirrorAllowedHosts => KeyRefusal::Fixed(CAUSE_NETWORK_SETTINGS_INVALID),
            Self::Revision
            | Self::Organization
            | Self::Contact
            | Self::Comment
            | Self::ServiceRequireLoginUnit => KeyRefusal::Never,
        }
    }

    /// The modes a mode-object key takes; empty for a plain value.
    #[must_use]
    pub fn modes(self) -> &'static [Mode] {
        const LOCKED: &[Mode] = &[Mode::Locked];
        const LOCKED_DEFAULT: &[Mode] = &[Mode::Locked, Mode::Default];
        const PROFILE: &[Mode] = &[Mode::Locked, Mode::Default, Mode::Floor];
        const BOUNDED: &[Mode] = &[Mode::Locked, Mode::Default, Mode::Min, Mode::Max];
        const LIST: &[Mode] = &[Mode::Locked, Mode::Allow];
        match self {
            Self::SecurityProfile => PROFILE,
            Self::FlowsPrograms | Self::FlowsExtraPath | Self::FlowsReadCacheRoots => LIST,
            Self::FlowsArtifactsRoot
            | Self::ModelsDir
            | Self::NetworkNoProxy
            | Self::NetworkEngineMirror
            | Self::NetworkModelsMirror => LOCKED_DEFAULT,
            Self::ModelsIdleUnloadMin | Self::RetentionEvidenceDays | Self::RetentionAuditDays => {
                BOUNDED
            }
            Self::NetworkProxy | Self::NetworkCaBundle => LOCKED,
            Self::Revision
            | Self::Organization
            | Self::Contact
            | Self::Comment
            | Self::GrantsManual
            | Self::GrantsRemember
            | Self::GrantsNever
            | Self::GrantsNeverClasses
            | Self::ScopesAllowedRepositoryRoots
            | Self::ScopesConnectorWide
            | Self::ConnectorsAllowedBaseHosts
            | Self::ConnectorsDisabled
            | Self::LandingMaxPermissions
            | Self::LandingAllowedGithubServers
            | Self::ModelsEngineSource
            | Self::ModelsAllowedSources
            | Self::ModelsAllowedCurators
            | Self::NetworkMirrorAllowedHosts
            | Self::ServiceRequireLoginUnit => &[],
        }
    }

    /// Whether the key is a plain value (a policy-only constraint).
    #[must_use]
    pub fn is_plain(self) -> bool {
        self.modes().is_empty()
    }

    /// The section a key belongs to, `None` for a top-level meta key.
    #[must_use]
    pub fn section(self) -> Option<&'static str> {
        self.path().split_once('.').map(|(section, _)| section)
    }
}

const _: () = assert!(Key::ALL.len() == Key::ServiceRequireLoginUnit.ordinal() + 1);

impl fmt::Display for Key {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.path())
    }
}

// --- Leaf types --------------------------------------------------------

/// A plain `"allow"` / `"deny"` switch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Permit {
    /// The human may.
    Allow,
    /// The human may not.
    Deny,
}

/// A class a `never_classes` entry forbids.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum NeverClass {
    /// [`CapabilityClass::Destructive`].
    Destructive,
    /// [`CapabilityClass::External`].
    External,
}

impl NeverClass {
    /// The wire word.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Destructive => "destructive",
            Self::External => "external",
        }
    }

    /// Whether `class` is this one.
    #[must_use]
    pub fn matches(self, class: CapabilityClass) -> bool {
        matches!(
            (self, class),
            (Self::Destructive, CapabilityClass::Destructive)
                | (Self::External, CapabilityClass::External)
        )
    }
}

/// Where the engine may come from (`models.engine_source`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum EngineSource {
    /// Upstream or the effective mirror (the builtin behaviour).
    #[default]
    Download,
    /// Only through an effective engine mirror; upstream is never contacted.
    MirrorOnly,
    /// Install refuses; `engine.import` stays open.
    ImportOnly,
}

impl EngineSource {
    /// The wire word.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Download => "download",
            Self::MirrorOnly => "mirror_only",
            Self::ImportOnly => "import_only",
        }
    }
}

/// A way a model may arrive (`models.allowed_sources`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ModelSource {
    /// A catalog preset (digest pinned in the binary).
    Catalog,
    /// A download from a URL the human typed.
    CustomUrl,
    /// A local file import.
    Import,
}

impl ModelSource {
    /// The wire word.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Catalog => "catalog",
            Self::CustomUrl => "custom_url",
            Self::Import => "import",
        }
    }
}

/// The landing permission ceiling: `false` caps the permission off on
/// every repository; `true` (or absent) leaves it to the human.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)] // Independent ceilings, as the landing permissions are.
pub struct LandingCeiling {
    /// May push.
    pub push: bool,
    /// May open a pull request.
    pub create_pr: bool,
    /// May merge.
    pub merge: bool,
    /// May sync.
    pub sync: bool,
}

impl Default for LandingCeiling {
    fn default() -> Self {
        Self {
            push: true,
            create_pr: true,
            merge: true,
            sync: true,
        }
    }
}

/// A list of host rules in the no-proxy grammar, as typed and as parsed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostList {
    /// The normalized entries (trimmed, lowercase, deduplicated).
    pub entries: Vec<String>,
    /// The parsed rules.
    pub rules: Vec<NoProxyRule>,
}

impl HostList {
    /// Whether `url`'s host matches a rule. A URL with no host never does.
    #[must_use]
    pub fn allows(&self, url: &Url) -> bool {
        self.rules.iter().any(|rule| rule.matches(url))
    }
}

/// An anchored capability-name glob: `*` matches any run of characters,
/// nothing else is special.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityPattern(String);

impl CapabilityPattern {
    /// The pattern as written.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Whether `capability` matches the whole pattern.
    #[must_use]
    pub fn matches(&self, capability: &str) -> bool {
        pattern_matches(&self.0, capability)
    }
}

/// A CA bundle the policy pins: the file (trust-checked when loaded) and
/// the SHA-256 of its normalized copy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaBundlePin {
    /// An absolute path on the target platform.
    pub path: String,
    /// Lowercase hex.
    pub sha256: String,
}

/// How a path rule is anchored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Anchor {
    /// An absolute path.
    Absolute,
    /// `~` or `%USERPROFILE%`, expanded against a home the caller supplies.
    Home,
}

/// A path prefix compared by component, never by string: `/Users` covers
/// `/Users/x` and `/Users`, never `/UsersX`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathRule {
    raw: String,
    anchor: Anchor,
    components: Vec<String>,
    platform: TargetPlatform,
}

impl PathRule {
    /// The rule as written.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.raw
    }

    /// Whether `candidate` (a path as the human typed it, `~` allowed) is
    /// this prefix or under it. Both sides are expanded against `home`; a
    /// home-relative side with no home, or a candidate that is not
    /// absolute, is never covered.
    #[must_use]
    pub fn covers(&self, candidate: &str, home: Option<&Path>) -> bool {
        let (Some(prefix), Some(candidate)) = (
            self.expanded(home),
            path_components(candidate, self.platform, home, true),
        ) else {
            return false;
        };
        candidate.len() >= prefix.len() && candidate[..prefix.len()] == prefix[..]
    }

    /// [`Self::covers`] for a path the daemon already canonicalized.
    #[must_use]
    pub fn covers_path(&self, candidate: &Path, home: Option<&Path>) -> bool {
        self.covers(&candidate.to_string_lossy(), home)
    }

    fn expanded(&self, home: Option<&Path>) -> Option<Vec<String>> {
        match self.anchor {
            Anchor::Absolute => Some(self.components.clone()),
            Anchor::Home => {
                let mut base =
                    path_components(&home?.to_string_lossy(), self.platform, None, false)?;
                base.extend(self.components.iter().cloned());
                Some(base)
            }
        }
    }
}

/// The two prefixes `expand_home` in the flow service expands.
const HOME_PREFIXES: [&str; 2] = ["~", "%USERPROFILE%"];

/// Splits a path into comparable components for `platform`: `None` when
/// it is not absolute (after a home expansion, when `allow_home`), holds a
/// NUL, or holds a `.` or `..` component. Windows components are
/// lowercased and both separators count.
fn path_components(
    raw: &str,
    platform: TargetPlatform,
    home: Option<&Path>,
    allow_home: bool,
) -> Option<Vec<String>> {
    let raw = raw.trim();
    if raw.contains('\0') {
        return None;
    }
    if allow_home {
        for prefix in HOME_PREFIXES {
            if let Some(rest) = raw.strip_prefix(prefix)
                && (rest.is_empty() || rest.starts_with(['/', '\\']))
            {
                let mut base = path_components(&home?.to_string_lossy(), platform, None, false)?;
                base.extend(relative_components(rest, platform)?);
                return Some(base);
            }
        }
    }
    match platform {
        TargetPlatform::Macos => {
            let rest = raw.strip_prefix('/')?;
            relative_components(rest, platform)
        }
        TargetPlatform::Windows => {
            let bytes = raw.as_bytes();
            if raw.starts_with(r"\\") || raw.starts_with("//") {
                let parts = relative_components(&raw[2..], platform)?;
                // A UNC path names at least a server and a share.
                (parts.len() >= 2).then_some(parts).map(|mut parts| {
                    parts.insert(0, String::from(r"\\"));
                    parts
                })
            } else if bytes.len() >= 3
                && bytes[0].is_ascii_alphabetic()
                && bytes[1] == b':'
                && matches!(bytes[2], b'\\' | b'/')
            {
                let mut parts = vec![raw[..2].to_ascii_lowercase()];
                parts.extend(relative_components(&raw[3..], platform)?);
                Some(parts)
            } else {
                None
            }
        }
    }
}

/// The components of a path tail; `None` on a `.` or `..` component.
fn relative_components(rest: &str, platform: TargetPlatform) -> Option<Vec<String>> {
    let separators: &[char] = match platform {
        TargetPlatform::Macos => &['/'],
        TargetPlatform::Windows => &['/', '\\'],
    };
    let mut parts = Vec::new();
    for part in rest.split(separators).filter(|part| !part.is_empty()) {
        if part == "." || part == ".." {
            return None;
        }
        parts.push(match platform {
            TargetPlatform::Macos => part.to_owned(),
            TargetPlatform::Windows => part.to_ascii_lowercase(),
        });
    }
    Some(parts)
}

/// A mode object over a single value type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValueLeaf<T> {
    /// Forced value.
    pub locked: Option<T>,
    /// Applied while the human has no value.
    pub default: Option<T>,
    /// The administrator's reason, shown with the lock.
    pub reason: Option<String>,
}

/// `security.profile`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileLeaf {
    /// Forced profile.
    pub locked: Option<Profile>,
    /// First-boot profile (and the value while the human has none).
    pub default: Option<Profile>,
    /// The most permissive profile the human may choose.
    pub floor: Option<Profile>,
    /// The administrator's reason.
    pub reason: Option<String>,
}

/// A number with bounds. `None` inside `locked`/`default` is forever:
/// retention's `null`, and `models.idle_unload_min`'s `0` ("never
/// unload"), which the parser stores as `None`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundedLeaf {
    /// Forced value.
    pub locked: Option<Option<u64>>,
    /// Applied while the human has no value.
    pub default: Option<Option<u64>>,
    /// Lower bound, inclusive.
    pub min: Option<u64>,
    /// Upper bound, inclusive; "forever" is clamped to it.
    pub max: Option<u64>,
    /// The administrator's reason.
    pub reason: Option<String>,
}

/// A list of names (`flows.programs`, `network.no_proxy`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListLeaf {
    /// Exactly this list.
    pub locked: Option<Vec<String>>,
    /// The human's list is intersected with this set.
    pub allow: Option<Vec<String>>,
    /// Applied while the human's list is empty.
    pub default: Option<Vec<String>>,
    /// The administrator's reason.
    pub reason: Option<String>,
}

/// A list of paths (`flows.extra_path`, `flows.read_cache_roots`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathListLeaf {
    /// Exactly this list, as written (`~` allowed).
    pub locked: Option<Vec<String>>,
    /// The human's entries must sit under one of these prefixes.
    pub allow: Option<Vec<PathRule>>,
    /// The administrator's reason.
    pub reason: Option<String>,
}

/// The document's top-level labels.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Meta {
    /// `revision`.
    pub revision: Option<String>,
    /// `organization`.
    pub organization: Option<String>,
    /// `contact`.
    pub contact: Option<String>,
    /// `comment`.
    pub comment: Option<String>,
}

/// Every accepted leaf, typed. A rejected or absent leaf is `None`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[allow(missing_docs)] // Each field is the key of the same name; see [`Key`].
pub struct Policy {
    pub profile: Option<ProfileLeaf>,
    pub grants_manual: Option<Permit>,
    pub grants_remember: Option<Permit>,
    pub grants_never: Option<Vec<CapabilityPattern>>,
    pub grants_never_classes: Option<Vec<NeverClass>>,
    pub allowed_repository_roots: Option<Vec<PathRule>>,
    pub connector_wide: Option<Permit>,
    pub allowed_base_hosts: Option<HostList>,
    pub disabled_connectors: Option<Vec<ConnectorId>>,
    pub programs: Option<ListLeaf>,
    pub extra_path: Option<PathListLeaf>,
    pub read_cache_roots: Option<PathListLeaf>,
    pub artifacts_root: Option<ValueLeaf<String>>,
    pub max_permissions: Option<LandingCeiling>,
    pub allowed_github_servers: Option<HostList>,
    pub engine_source: Option<EngineSource>,
    pub allowed_sources: Option<Vec<ModelSource>>,
    pub allowed_curators: Option<Vec<AgentId>>,
    pub models_dir: Option<ValueLeaf<String>>,
    pub idle_unload_min: Option<BoundedLeaf>,
    pub evidence_days: Option<BoundedLeaf>,
    pub audit_days: Option<BoundedLeaf>,
    pub proxy: Option<ValueLeaf<Option<ProxyEntry>>>,
    pub no_proxy: Option<ListLeaf>,
    pub ca_bundle: Option<ValueLeaf<Option<CaBundlePin>>>,
    pub mirror_allowed_hosts: Option<HostList>,
    pub engine_mirror: Option<ValueLeaf<Option<String>>>,
    pub models_mirror: Option<ValueLeaf<Option<String>>>,
    pub require_login_unit: Option<bool>,
}

impl Policy {
    /// Copies `key`'s leaf from `source` (the last-known-good policy).
    fn copy_leaf(&mut self, source: &Self, meta: &mut Meta, source_meta: &Meta, key: Key) {
        match key {
            Key::Revision => meta.revision.clone_from(&source_meta.revision),
            Key::Organization => meta.organization.clone_from(&source_meta.organization),
            Key::Contact => meta.contact.clone_from(&source_meta.contact),
            Key::Comment => meta.comment.clone_from(&source_meta.comment),
            Key::SecurityProfile => self.profile.clone_from(&source.profile),
            Key::GrantsManual => self.grants_manual = source.grants_manual,
            Key::GrantsRemember => self.grants_remember = source.grants_remember,
            Key::GrantsNever => self.grants_never.clone_from(&source.grants_never),
            Key::GrantsNeverClasses => self
                .grants_never_classes
                .clone_from(&source.grants_never_classes),
            Key::ScopesAllowedRepositoryRoots => self
                .allowed_repository_roots
                .clone_from(&source.allowed_repository_roots),
            Key::ScopesConnectorWide => self.connector_wide = source.connector_wide,
            Key::ConnectorsAllowedBaseHosts => {
                self.allowed_base_hosts
                    .clone_from(&source.allowed_base_hosts);
            }
            Key::ConnectorsDisabled => self
                .disabled_connectors
                .clone_from(&source.disabled_connectors),
            Key::FlowsPrograms => self.programs.clone_from(&source.programs),
            Key::FlowsExtraPath => self.extra_path.clone_from(&source.extra_path),
            Key::FlowsReadCacheRoots => self.read_cache_roots.clone_from(&source.read_cache_roots),
            Key::FlowsArtifactsRoot => self.artifacts_root.clone_from(&source.artifacts_root),
            Key::LandingMaxPermissions => self.max_permissions = source.max_permissions,
            Key::LandingAllowedGithubServers => self
                .allowed_github_servers
                .clone_from(&source.allowed_github_servers),
            Key::ModelsEngineSource => self.engine_source = source.engine_source,
            Key::ModelsAllowedSources => self.allowed_sources.clone_from(&source.allowed_sources),
            Key::ModelsAllowedCurators => {
                self.allowed_curators.clone_from(&source.allowed_curators);
            }
            Key::ModelsDir => self.models_dir.clone_from(&source.models_dir),
            Key::ModelsIdleUnloadMin => self.idle_unload_min.clone_from(&source.idle_unload_min),
            Key::RetentionEvidenceDays => self.evidence_days.clone_from(&source.evidence_days),
            Key::RetentionAuditDays => self.audit_days.clone_from(&source.audit_days),
            Key::NetworkProxy => self.proxy.clone_from(&source.proxy),
            Key::NetworkNoProxy => self.no_proxy.clone_from(&source.no_proxy),
            Key::NetworkCaBundle => self.ca_bundle.clone_from(&source.ca_bundle),
            Key::NetworkMirrorAllowedHosts => self
                .mirror_allowed_hosts
                .clone_from(&source.mirror_allowed_hosts),
            Key::NetworkEngineMirror => self.engine_mirror.clone_from(&source.engine_mirror),
            Key::NetworkModelsMirror => self.models_mirror.clone_from(&source.models_mirror),
            Key::ServiceRequireLoginUnit => self.require_login_unit = source.require_login_unit,
        }
    }

    /// The reason a mode-object key carries.
    fn reason(&self, key: Key) -> Option<&str> {
        let reason = match key {
            Key::SecurityProfile => self.profile.as_ref().and_then(|l| l.reason.as_ref()),
            Key::FlowsPrograms => self.programs.as_ref().and_then(|l| l.reason.as_ref()),
            Key::FlowsExtraPath => self.extra_path.as_ref().and_then(|l| l.reason.as_ref()),
            Key::FlowsReadCacheRoots => self
                .read_cache_roots
                .as_ref()
                .and_then(|l| l.reason.as_ref()),
            Key::FlowsArtifactsRoot => self.artifacts_root.as_ref().and_then(|l| l.reason.as_ref()),
            Key::ModelsDir => self.models_dir.as_ref().and_then(|l| l.reason.as_ref()),
            Key::ModelsIdleUnloadMin => self
                .idle_unload_min
                .as_ref()
                .and_then(|l| l.reason.as_ref()),
            Key::RetentionEvidenceDays => {
                self.evidence_days.as_ref().and_then(|l| l.reason.as_ref())
            }
            Key::RetentionAuditDays => self.audit_days.as_ref().and_then(|l| l.reason.as_ref()),
            Key::NetworkProxy => self.proxy.as_ref().and_then(|l| l.reason.as_ref()),
            Key::NetworkNoProxy => self.no_proxy.as_ref().and_then(|l| l.reason.as_ref()),
            Key::NetworkCaBundle => self.ca_bundle.as_ref().and_then(|l| l.reason.as_ref()),
            Key::NetworkEngineMirror => self.engine_mirror.as_ref().and_then(|l| l.reason.as_ref()),
            Key::NetworkModelsMirror => self.models_mirror.as_ref().and_then(|l| l.reason.as_ref()),
            _ => None,
        };
        reason.map(String::as_str)
    }

    /// The bounded leaf a key names.
    fn bounded(&self, key: Key) -> Option<&BoundedLeaf> {
        match key {
            Key::ModelsIdleUnloadMin => self.idle_unload_min.as_ref(),
            Key::RetentionEvidenceDays => self.evidence_days.as_ref(),
            Key::RetentionAuditDays => self.audit_days.as_ref(),
            _ => None,
        }
    }

    /// The string leaf a key names.
    fn string_leaf(&self, key: Key) -> Option<&ValueLeaf<String>> {
        match key {
            Key::FlowsArtifactsRoot => self.artifacts_root.as_ref(),
            Key::ModelsDir => self.models_dir.as_ref(),
            _ => None,
        }
    }

    /// The path-list leaf a key names.
    fn path_list(&self, key: Key) -> Option<&PathListLeaf> {
        match key {
            Key::FlowsExtraPath => self.extra_path.as_ref(),
            Key::FlowsReadCacheRoots => self.read_cache_roots.as_ref(),
            _ => None,
        }
    }
}

// --- View, statuses, diagnostics ----------------------------------------

/// What became of one key that the document (or the fallback) mentions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LeafStatus {
    /// The file's value is in force.
    Applied,
    /// The file's value was refused; the user's value stands (Tier B, or a
    /// view before [`PolicyView::with_fallback`]).
    Rejected {
        /// A stable leaf-level code.
        code: &'static str,
        /// The sentence.
        detail: String,
    },
    /// The file's value was refused; the last-known-good value is in force.
    LastGood {
        /// Why the file's value was refused.
        code: &'static str,
        /// The sentence.
        detail: String,
    },
    /// Tier A, managed but unresolved: reads show the user's value, writes
    /// refuse [`CAUSE_POLICY_FROZEN`].
    Held {
        /// Why (a leaf code, or a file-level code for a frozen view).
        code: &'static str,
        /// The sentence.
        detail: String,
        /// The file named this key and the value was refused (a degraded
        /// file), rather than the whole file being unusable. Only then do
        /// the network keys close their consumers.
        intent_known: bool,
    },
}

impl LeafStatus {
    /// The wire word: `applied`, `rejected` or `held` (a last-good value is
    /// `applied`).
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Applied | Self::LastGood { .. } => "applied",
            Self::Rejected { .. } => "rejected",
            Self::Held { .. } => "held",
        }
    }

    /// Whether a value from the policy is in force for the key.
    #[must_use]
    pub fn in_force(&self) -> bool {
        matches!(self, Self::Applied | Self::LastGood { .. })
    }

    fn detail(&self) -> Option<(&'static str, &str)> {
        match self {
            Self::Applied => None,
            Self::Rejected { code, detail }
            | Self::LastGood { code, detail }
            | Self::Held { code, detail, .. } => Some((code, detail)),
        }
    }
}

/// One finding about the document: a rejected leaf or an unknown name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Diagnostic {
    /// A stable code (one of the `CODE_*` constants).
    pub code: &'static str,
    /// The dotted path the finding is about (also for unknown names).
    pub key: String,
    /// The sentence.
    pub detail: String,
}

/// Why a document could not be used at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileFailure {
    /// A stable file-level code.
    pub code: &'static str,
    /// The sentence.
    pub detail: String,
}

impl fmt::Display for FileFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.detail)
    }
}

impl std::error::Error for FileFailure {}

/// One row of the per-key table (`admin.policy.get` `keys`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct KeyReport {
    /// The dotted path.
    pub key: &'static str,
    /// `A` or `B`.
    pub tier: &'static str,
    /// The modes the document used (`forbid` for a plain constraint).
    pub mode: Vec<&'static str>,
    /// `applied`, `rejected` or `held`.
    pub state: &'static str,
    /// The code and sentence when not plainly applied.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<&'static str>,
    /// The sentence.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LeafRecord {
    status: LeafStatus,
    modes: Vec<Mode>,
}

/// A parsed policy: the accepted leaves, every key's status and the
/// diagnostics. Built by [`inspect_bytes`]; [`Self::unmanaged`] is "no
/// policy".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyView {
    digest: Option<String>,
    platform: TargetPlatform,
    meta: Meta,
    policy: Policy,
    leaves: BTreeMap<Key, LeafRecord>,
    diagnostics: Vec<Diagnostic>,
}

/// What [`inspect_bytes`] found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Inspection {
    /// SHA-256 of the raw bytes (a byte-order mark included), lowercase hex.
    pub digest: String,
    /// How many bytes were inspected.
    pub size: usize,
    /// The view, or the file-level failure.
    pub result: Result<PolicyView, FileFailure>,
}

/// The one-word verdict `pam policy check` turns into an exit code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Every leaf accepted, no unknown name.
    Valid,
    /// The file parses but at least one leaf was refused.
    LeafProblems,
    /// The file cannot be used at all.
    FileInvalid,
}

impl Inspection {
    /// The verdict.
    #[must_use]
    pub fn verdict(&self) -> Verdict {
        match &self.result {
            Err(_) => Verdict::FileInvalid,
            Ok(view) if view.diagnostics.is_empty() => Verdict::Valid,
            Ok(_) => Verdict::LeafProblems,
        }
    }
}

/// Parses and validates a policy document for `platform`. Pure: no file is
/// opened, nothing referenced is checked for presence or ownership.
#[must_use]
pub fn inspect_bytes(bytes: &[u8], platform: TargetPlatform) -> Inspection {
    let digest = hex::encode(Sha256::digest(bytes));
    let result = parse_document(bytes, platform, &digest);
    Inspection {
        digest,
        size: bytes.len(),
        result,
    }
}

impl PolicyView {
    /// No policy: every key is the user's.
    #[must_use]
    pub fn unmanaged() -> Self {
        Self {
            digest: None,
            platform: TargetPlatform::host(),
            meta: Meta::default(),
            policy: Policy::default(),
            leaves: BTreeMap::new(),
            diagnostics: Vec::new(),
        }
    }

    /// A file-level failure with no last-known-good policy: the intent is
    /// unknown, so nothing is enforced, but every Tier A key is held (its
    /// writes refuse [`CAUSE_POLICY_FROZEN`]). `digest` is the unusable
    /// file's, when it was read.
    #[must_use]
    pub fn frozen(failure: &FileFailure, digest: Option<String>) -> Self {
        let leaves = Key::ALL
            .into_iter()
            .filter(|key| key.tier() == Tier::A)
            .map(|key| {
                (
                    key,
                    LeafRecord {
                        status: LeafStatus::Held {
                            code: failure.code,
                            detail: failure.detail.clone(),
                            intent_known: false,
                        },
                        modes: Vec::new(),
                    },
                )
            })
            .collect();
        Self {
            digest,
            platform: TargetPlatform::host(),
            meta: Meta::default(),
            policy: Policy::default(),
            leaves,
            diagnostics: Vec::new(),
        }
    }

    /// The fallback chain for a degraded file: a rejected leaf takes the
    /// last-known-good value when that policy had one in force
    /// ([`LeafStatus::LastGood`]); otherwise a Tier A leaf is held and a
    /// Tier B leaf stays rejected (the user's value stands). Applied leaves
    /// and diagnostics are unchanged.
    #[must_use]
    pub fn with_fallback(mut self, last_good: Option<&Self>) -> Self {
        let rejected: Vec<(Key, &'static str, String)> = self
            .leaves
            .iter()
            .filter_map(|(key, record)| match &record.status {
                LeafStatus::Rejected { code, detail } => Some((*key, *code, detail.clone())),
                _ => None,
            })
            .collect();
        for (key, code, detail) in rejected {
            let good = last_good.and_then(|view| {
                view.leaves
                    .get(&key)
                    .filter(|record| record.status.in_force())
                    .map(|record| (view, record.modes.clone()))
            });
            let record = self.leaves.get_mut(&key).expect("collected from the map");
            if let Some((view, modes)) = good {
                self.policy
                    .copy_leaf(&view.policy, &mut self.meta, &view.meta, key);
                record.status = LeafStatus::LastGood { code, detail };
                record.modes = modes;
            } else if key.tier() == Tier::A {
                record.status = LeafStatus::Held {
                    code,
                    detail,
                    intent_known: true,
                };
            }
        }
        self
    }

    /// SHA-256 of the file this view came from, lowercase hex.
    #[must_use]
    pub fn digest(&self) -> Option<&str> {
        self.digest.as_deref()
    }

    /// The first twelve hex characters of the digest, as refusals show it.
    #[must_use]
    pub fn digest12(&self) -> Option<&str> {
        self.digest.as_deref().and_then(|digest| digest.get(..12))
    }

    /// The platform the paths were checked for.
    #[must_use]
    pub fn platform(&self) -> TargetPlatform {
        self.platform
    }

    /// The top-level labels.
    #[must_use]
    pub fn meta(&self) -> &Meta {
        &self.meta
    }

    /// The accepted leaves.
    #[must_use]
    pub fn policy(&self) -> &Policy {
        &self.policy
    }

    /// Every finding, sorted by key.
    #[must_use]
    pub fn diagnostics(&self) -> &[Diagnostic] {
        &self.diagnostics
    }

    /// Whether the document manages anything at all.
    #[must_use]
    pub fn is_managed(&self) -> bool {
        self.digest.is_some() || !self.leaves.is_empty()
    }

    /// `key`'s status, `None` when the document does not mention it.
    #[must_use]
    pub fn status(&self, key: Key) -> Option<&LeafStatus> {
        self.leaves.get(&key).map(|record| &record.status)
    }

    /// The modes the document used for `key`.
    #[must_use]
    pub fn modes(&self, key: Key) -> &[Mode] {
        self.leaves
            .get(&key)
            .map_or(&[], |record| record.modes.as_slice())
    }

    /// Whether `key` is held.
    #[must_use]
    pub fn is_held(&self, key: Key) -> bool {
        matches!(self.status(key), Some(LeafStatus::Held { .. }))
    }

    /// How many keys the document mentions whose value was refused.
    #[must_use]
    pub fn rejected_leaves(&self) -> usize {
        self.leaves
            .values()
            .filter(|record| !matches!(record.status, LeafStatus::Applied))
            .count()
            + self
                .diagnostics
                .iter()
                .filter(|diagnostic| Key::parse(&diagnostic.key).is_none())
                .count()
    }

    /// The per-key table, in key order.
    #[must_use]
    pub fn key_reports(&self) -> Vec<KeyReport> {
        self.leaves
            .iter()
            .map(|(key, record)| {
                let detail = record.status.detail();
                KeyReport {
                    key: key.path(),
                    tier: key.tier().as_str(),
                    mode: record.modes.iter().map(|mode| mode.as_str()).collect(),
                    state: record.status.as_str(),
                    code: detail.map(|(code, _)| code),
                    detail: detail.map(|(_, detail)| detail.to_owned()),
                }
            })
            .collect()
    }
}

// --- The strict reader --------------------------------------------------

/// What the strict visitor tripped on, beyond plain JSON syntax.
#[derive(Debug, Clone)]
enum Trap {
    Duplicate(String),
    TooDeep(String),
}

/// A `serde_json::Value` builder that refuses duplicate keys and nesting
/// deeper than [`MAX_DEPTH`].
struct Strict<'a> {
    depth: usize,
    path: String,
    trap: &'a RefCell<Option<Trap>>,
}

impl<'a> Strict<'a> {
    fn child(&self, segment: &str) -> Strict<'a> {
        Strict {
            depth: self.depth + 1,
            path: if self.path.is_empty() {
                segment.to_owned()
            } else {
                format!("{}.{segment}", self.path)
            },
            trap: self.trap,
        }
    }

    fn enter<E: de::Error>(&self) -> Result<(), E> {
        if self.depth >= MAX_DEPTH {
            let at = if self.path.is_empty() {
                "the top level"
            } else {
                &self.path
            };
            *self.trap.borrow_mut() = Some(Trap::TooDeep(at.to_owned()));
            return Err(E::custom("too deep"));
        }
        Ok(())
    }
}

impl<'de> DeserializeSeed<'de> for Strict<'_> {
    type Value = Value;

    fn deserialize<D: de::Deserializer<'de>>(self, deserializer: D) -> Result<Value, D::Error> {
        deserializer.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for Strict<'_> {
    type Value = Value;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON value")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Value, E> {
        Ok(Value::Bool(value))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Value, E> {
        Ok(Value::Number(value.into()))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Value, E> {
        Ok(Value::Number(value.into()))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Value, E> {
        Ok(Number::from_f64(value).map_or(Value::Null, Value::Number))
    }

    fn visit_str<E>(self, value: &str) -> Result<Value, E> {
        Ok(Value::String(value.to_owned()))
    }

    fn visit_string<E>(self, value: String) -> Result<Value, E> {
        Ok(Value::String(value))
    }

    fn visit_unit<E>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_none<E>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Value, A::Error> {
        self.enter::<A::Error>()?;
        let mut items = Vec::new();
        while let Some(item) = seq.next_element_seed(self.child(&format!("[{}]", items.len())))? {
            items.push(item);
        }
        Ok(Value::Array(items))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
        self.enter::<A::Error>()?;
        let mut object = Map::new();
        while let Some(key) = map.next_key::<String>()? {
            if object.contains_key(&key) {
                let at = self.child(&key).path;
                *self.trap.borrow_mut() = Some(Trap::Duplicate(at));
                return Err(de::Error::custom("duplicate key"));
            }
            let value = map.next_value_seed(self.child(&key))?;
            object.insert(key, value);
        }
        Ok(Value::Object(object))
    }
}

/// Parses `text` strictly.
fn strict_parse(text: &str) -> Result<Value, FileFailure> {
    let trap = RefCell::new(None);
    let mut deserializer = serde_json::Deserializer::from_str(text);
    let parsed = Strict {
        depth: 0,
        path: String::new(),
        trap: &trap,
    }
    .deserialize(&mut deserializer)
    .and_then(|value| deserializer.end().map(|()| value));
    match (parsed, trap.into_inner()) {
        (Ok(value), _) => Ok(value),
        (Err(_), Some(Trap::Duplicate(path))) => Err(FileFailure {
            code: CODE_DUPLICATE_KEY,
            detail: format!(
                "the key {path:?} appears more than once in the same object; the intent is \
                 ambiguous, so the file is not used"
            ),
        }),
        (Err(_), Some(Trap::TooDeep(path))) => Err(FileFailure {
            code: CODE_TOO_DEEP,
            detail: format!("the JSON nests deeper than {MAX_DEPTH} levels at {path}"),
        }),
        (Err(error), None) => Err(FileFailure {
            code: CODE_NOT_JSON,
            detail: format!("the file is not valid JSON: {error}"),
        }),
    }
}

fn parse_document(
    bytes: &[u8],
    platform: TargetPlatform,
    digest: &str,
) -> Result<PolicyView, FileFailure> {
    if bytes.len() > MAX_POLICY_BYTES {
        return Err(FileFailure {
            code: CODE_TOO_LARGE,
            detail: format!(
                "the file is {} bytes, more than the {MAX_POLICY_BYTES} allowed",
                bytes.len()
            ),
        });
    }
    let body = bytes.strip_prefix(BOM).unwrap_or(bytes);
    let text = std::str::from_utf8(body).map_err(|error| FileFailure {
        code: CODE_NOT_UTF8,
        detail: format!("the file is not UTF-8: {error}"),
    })?;
    let Value::Object(top) = strict_parse(text)? else {
        return Err(FileFailure {
            code: CODE_NOT_OBJECT,
            detail: "the top level of the file must be a JSON object".to_owned(),
        });
    };
    match top.get("version") {
        None => {
            return Err(FileFailure {
                code: CODE_VERSION_MISSING,
                detail: format!(
                    "the file has no \"version\"; this PAM reads version {POLICY_VERSION}"
                ),
            });
        }
        Some(version) if version.as_u64() == Some(POLICY_VERSION) => {}
        Some(version) => {
            return Err(FileFailure {
                code: CODE_VERSION_UNSUPPORTED,
                detail: format!(
                    "the file is version {version}; this PAM reads version {POLICY_VERSION}"
                ),
            });
        }
    }
    let mut builder = Builder::new(platform);
    builder.walk(&top);
    builder.check_retention_pair();
    Ok(builder.finish(digest))
}

/// A refused leaf value.
#[derive(Debug, Clone)]
struct Rejection {
    code: &'static str,
    detail: String,
}

fn reject(code: &'static str, detail: impl Into<String>) -> Rejection {
    Rejection {
        code,
        detail: detail.into(),
    }
}

/// Accumulates leaves while the document is walked.
struct Builder {
    platform: TargetPlatform,
    meta: Meta,
    policy: Policy,
    leaves: BTreeMap<Key, LeafRecord>,
    diagnostics: Vec<Diagnostic>,
}

impl Builder {
    fn new(platform: TargetPlatform) -> Self {
        Self {
            platform,
            meta: Meta::default(),
            policy: Policy::default(),
            leaves: BTreeMap::new(),
            diagnostics: Vec::new(),
        }
    }

    fn finish(mut self, digest: &str) -> PolicyView {
        self.diagnostics
            .sort_by(|left, right| left.key.cmp(&right.key).then(left.code.cmp(right.code)));
        PolicyView {
            digest: Some(digest.to_owned()),
            platform: self.platform,
            meta: self.meta,
            policy: self.policy,
            leaves: self.leaves,
            diagnostics: self.diagnostics,
        }
    }

    fn unknown(&mut self, path: String) {
        self.diagnostics.push(Diagnostic {
            code: CODE_UNKNOWN_KEY,
            detail: format!(
                "{path:?} is not a key this policy version has; it is rejected, not ignored"
            ),
            key: path,
        });
    }

    fn rejected(&mut self, key: Key, modes: Vec<Mode>, rejection: Rejection) {
        self.diagnostics.push(Diagnostic {
            code: rejection.code,
            key: key.path().to_owned(),
            detail: rejection.detail.clone(),
        });
        self.leaves.insert(
            key,
            LeafRecord {
                status: LeafStatus::Rejected {
                    code: rejection.code,
                    detail: rejection.detail,
                },
                modes,
            },
        );
    }

    /// Every key under `prefix` in the closed table (a section, or
    /// `security.grants`).
    fn keys_under(prefix: &str) -> impl Iterator<Item = Key> + '_ {
        Key::ALL.into_iter().filter(move |key| {
            key.path()
                .strip_prefix(prefix)
                .is_some_and(|rest| rest.starts_with('.'))
        })
    }

    fn walk(&mut self, top: &Map<String, Value>) {
        let mut present: Vec<(Key, &Value)> = Vec::new();
        for (name, value) in top {
            if name == "version" {
                continue;
            }
            if let Some(key) = Key::parse(name).filter(|key| key.section().is_none()) {
                present.push((key, value));
            } else if SECTIONS.contains(&name.as_str()) {
                self.walk_object(name, value, &mut present);
            } else {
                self.unknown(name.clone());
            }
        }
        present.sort_by_key(|(key, _)| *key);
        for (key, value) in present {
            self.leaf(key, value);
        }
    }

    /// One section (or `security.grants`): every member is a key or a
    /// nested object of keys. A section that is not an object rejects every
    /// key it would hold: the intent is known to be there, so a Tier A key
    /// in it must not silently read as unmanaged.
    fn walk_object<'v>(
        &mut self,
        prefix: &str,
        value: &'v Value,
        present: &mut Vec<(Key, &'v Value)>,
    ) {
        let Value::Object(members) = value else {
            let keys: Vec<Key> = Self::keys_under(prefix).collect();
            for key in keys {
                self.rejected(
                    key,
                    Vec::new(),
                    reject(
                        CODE_WRONG_TYPE,
                        format!("{prefix:?} must be an object, so {key} cannot be read"),
                    ),
                );
            }
            return;
        };
        for (name, member) in members {
            let path = format!("{prefix}.{name}");
            if name.is_empty() || name.contains('.') {
                // A dotted member name would otherwise reach a key by a
                // second spelling.
                self.unknown(path);
            } else if let Some(key) = Key::parse(&path) {
                present.push((key, member));
            } else if Self::keys_under(&path).next().is_some() {
                self.walk_object(&path, member, present);
            } else {
                self.unknown(path);
            }
        }
    }

    fn leaf(&mut self, key: Key, value: &Value) {
        let modes = if key.is_plain() {
            vec![Mode::Forbid]
        } else {
            value
                .as_object()
                .map(|object| {
                    let modes: BTreeSet<Mode> = object
                        .keys()
                        .filter_map(|name| Mode::from_field(name))
                        .collect();
                    modes.into_iter().collect()
                })
                .unwrap_or_default()
        };
        let parsed = check_limits(value).and_then(|()| self.parse_leaf(key, value));
        match parsed {
            Ok(()) => {
                self.leaves.insert(
                    key,
                    LeafRecord {
                        status: LeafStatus::Applied,
                        modes,
                    },
                );
            }
            Err(rejection) => self.rejected(key, modes, rejection),
        }
    }

    /// Validates one leaf and stores its typed value.
    fn parse_leaf(&mut self, key: Key, value: &Value) -> Result<(), Rejection> {
        let platform = self.platform;
        let policy = &mut self.policy;
        match key {
            Key::Revision => self.meta.revision = Some(text(key, value)?.to_owned()),
            Key::Organization => self.meta.organization = Some(text(key, value)?.to_owned()),
            Key::Contact => self.meta.contact = Some(text(key, value)?.to_owned()),
            Key::Comment => self.meta.comment = Some(text(key, value)?.to_owned()),
            Key::SecurityProfile => policy.profile = Some(parse_profile(key, value)?),
            Key::GrantsManual => policy.grants_manual = Some(parse_permit(key, value, true)?),
            Key::GrantsRemember => policy.grants_remember = Some(parse_permit(key, value, true)?),
            Key::GrantsNever => policy.grants_never = Some(parse_patterns(key, value)?),
            Key::GrantsNeverClasses => {
                policy.grants_never_classes = Some(parse_classes(key, value)?);
            }
            Key::ScopesAllowedRepositoryRoots => {
                policy.allowed_repository_roots =
                    Some(parse_path_rules(key, value, platform, false)?);
            }
            Key::ScopesConnectorWide => {
                policy.connector_wide = Some(parse_permit(key, value, false)?);
            }
            Key::ConnectorsAllowedBaseHosts => {
                policy.allowed_base_hosts = Some(parse_hosts(key, value)?);
            }
            Key::ConnectorsDisabled => {
                policy.disabled_connectors = Some(parse_connectors(key, value)?);
            }
            Key::FlowsPrograms => policy.programs = Some(parse_programs(key, value)?),
            Key::FlowsExtraPath => policy.extra_path = Some(parse_path_list(key, value, platform)?),
            Key::FlowsReadCacheRoots => {
                policy.read_cache_roots = Some(parse_path_list(key, value, platform)?);
            }
            Key::FlowsArtifactsRoot => {
                policy.artifacts_root = Some(parse_string_leaf(key, value, platform, true)?);
            }
            Key::LandingMaxPermissions => policy.max_permissions = Some(parse_ceiling(key, value)?),
            Key::LandingAllowedGithubServers => {
                policy.allowed_github_servers = Some(parse_hosts(key, value)?);
            }
            Key::ModelsEngineSource => {
                policy.engine_source = Some(parse_engine_source(key, value)?);
            }
            Key::ModelsAllowedSources => {
                policy.allowed_sources = Some(parse_model_sources(key, value)?);
            }
            Key::ModelsAllowedCurators => {
                policy.allowed_curators = Some(parse_curators(key, value)?);
            }
            Key::ModelsDir => {
                policy.models_dir = Some(parse_string_leaf(key, value, platform, false)?);
            }
            Key::ModelsIdleUnloadMin => policy.idle_unload_min = Some(parse_bounded(key, value)?),
            Key::RetentionEvidenceDays => policy.evidence_days = Some(parse_bounded(key, value)?),
            Key::RetentionAuditDays => policy.audit_days = Some(parse_bounded(key, value)?),
            Key::NetworkProxy => policy.proxy = Some(parse_proxy(key, value)?),
            Key::NetworkNoProxy => policy.no_proxy = Some(parse_no_proxy_leaf(key, value)?),
            Key::NetworkCaBundle => policy.ca_bundle = Some(parse_ca_bundle(key, value, platform)?),
            Key::NetworkMirrorAllowedHosts => {
                let hosts = parse_hosts(key, value)?;
                if hosts.rules.is_empty() {
                    // The network service reads an empty list as "any
                    // host"; an administrator who wrote [] meant the
                    // opposite, so the leaf is refused rather than guessed.
                    return Err(reject(
                        CODE_VALUE_INVALID,
                        format!("{key} is empty; list the mirror hosts, or leave the key out"),
                    ));
                }
                policy.mirror_allowed_hosts = Some(hosts);
            }
            Key::NetworkEngineMirror | Key::NetworkModelsMirror => {
                let allowed = policy.mirror_allowed_hosts.as_ref();
                let leaf = parse_mirror(key, value, allowed)?;
                if key == Key::NetworkEngineMirror {
                    policy.engine_mirror = Some(leaf);
                } else {
                    policy.models_mirror = Some(leaf);
                }
            }
            Key::ServiceRequireLoginUnit => policy.require_login_unit = Some(boolean(key, value)?),
        }
        Ok(())
    }

    /// "Evidence may not outlive audit", across the two retention leaves:
    /// the shortest evidence window the policy forces (its lock or `min`)
    /// may not exceed the longest audit window it allows (its lock or
    /// `max`), and two finite defaults keep the same order. A breach
    /// rejects `retention.evidence_days`.
    fn check_retention_pair(&mut self) {
        let (Some(evidence), Some(audit)) = (
            self.policy.evidence_days.clone(),
            self.policy.audit_days.clone(),
        ) else {
            return;
        };
        let forced = |leaf: &BoundedLeaf| match leaf.locked {
            Some(value) => value,
            None => leaf.min,
        };
        let allowed = |leaf: &BoundedLeaf| match leaf.locked {
            Some(value) => value,
            None => leaf.max,
        };
        let mut pairs = vec![(forced(&evidence), allowed(&audit))];
        if let (Some(Some(evidence)), Some(Some(audit))) = (evidence.default, audit.default) {
            pairs.push((Some(evidence), Some(audit)));
        }
        for (evidence_days, audit_days) in pairs {
            let pair = RetentionSettings {
                evidence_days: evidence_days.and_then(|days| u32::try_from(days).ok()),
                audit_days: audit_days.and_then(|days| u32::try_from(days).ok()),
            };
            if let Err(detail) = crate::retention::validate(pair) {
                self.policy.evidence_days = None;
                self.rejected(
                    Key::RetentionEvidenceDays,
                    self.leaves
                        .get(&Key::RetentionEvidenceDays)
                        .map(|record| record.modes.clone())
                        .unwrap_or_default(),
                    reject(
                        CODE_RETENTION_PAIR,
                        format!("the policy's retention windows break the rule: {detail}"),
                    ),
                );
                return;
            }
        }
    }
}

/// The generic limits on any leaf value: string length, control
/// characters, list length.
fn check_limits(value: &Value) -> Result<(), Rejection> {
    match value {
        Value::String(text) => check_string(text),
        Value::Array(items) => {
            if items.len() > MAX_LIST_ENTRIES {
                return Err(reject(
                    CODE_LIST_TOO_LONG,
                    format!(
                        "a list holds {} entries, more than the {MAX_LIST_ENTRIES} allowed",
                        items.len()
                    ),
                ));
            }
            items.iter().try_for_each(check_limits)
        }
        Value::Object(members) => members.iter().try_for_each(|(name, member)| {
            check_string(name)?;
            check_limits(member)
        }),
        Value::Null | Value::Bool(_) | Value::Number(_) => Ok(()),
    }
}

fn check_string(text: &str) -> Result<(), Rejection> {
    if text.len() > MAX_STRING_BYTES {
        return Err(reject(
            CODE_STRING_TOO_LONG,
            format!(
                "a string is {} bytes, more than the {MAX_STRING_BYTES} allowed",
                text.len()
            ),
        ));
    }
    if text.chars().any(char::is_control) {
        return Err(reject(
            CODE_CONTROL_CHARACTER,
            "a string holds a control character",
        ));
    }
    Ok(())
}

// --- Leaf parsers -------------------------------------------------------

fn wrong_type(key: Key, expected: &str) -> Rejection {
    reject(CODE_WRONG_TYPE, format!("{key} must be {expected}"))
}

fn text(key: Key, value: &Value) -> Result<&str, Rejection> {
    value.as_str().ok_or_else(|| wrong_type(key, "a string"))
}

fn boolean(key: Key, value: &Value) -> Result<bool, Rejection> {
    value
        .as_bool()
        .ok_or_else(|| wrong_type(key, "true or false"))
}

fn strings(key: Key, value: &Value) -> Result<Vec<&str>, Rejection> {
    let Value::Array(items) = value else {
        return Err(wrong_type(key, "a list of strings"));
    };
    items
        .iter()
        .map(|item| {
            item.as_str()
                .ok_or_else(|| wrong_type(key, "a list of strings"))
        })
        .collect()
}

/// Trimmed, non-empty, deduplicated (first spelling wins), as the human's
/// lists are cleaned; an empty entry is refused rather than dropped.
fn clean_entries(key: Key, value: &Value) -> Result<Vec<String>, Rejection> {
    let mut cleaned: Vec<String> = Vec::new();
    for entry in strings(key, value)? {
        let entry = entry.trim();
        if entry.is_empty() {
            return Err(reject(
                CODE_VALUE_INVALID,
                format!("{key} holds an empty entry"),
            ));
        }
        if !cleaned.iter().any(|kept| kept == entry) {
            cleaned.push(entry.to_owned());
        }
    }
    Ok(cleaned)
}

/// A mode object, checked for shape: only the key's modes and `reason`,
/// `locked` alone, at least one mode.
struct Modes<'v> {
    fields: BTreeMap<Mode, &'v Value>,
    reason: Option<String>,
}

impl<'v> Modes<'v> {
    fn parse(key: Key, value: &'v Value) -> Result<Self, Rejection> {
        let Value::Object(members) = value else {
            return Err(wrong_type(
                key,
                "a mode object such as {\"locked\": …} or {\"default\": …}",
            ));
        };
        let mut fields = BTreeMap::new();
        let mut reason = None;
        for (name, member) in members {
            if name == "reason" {
                let text = member.as_str().ok_or_else(|| {
                    reject(CODE_WRONG_TYPE, format!("{key}.reason must be a string"))
                })?;
                if text.chars().count() > MAX_REASON_CHARS {
                    return Err(reject(
                        CODE_REASON_TOO_LONG,
                        format!("{key}.reason is longer than {MAX_REASON_CHARS} characters"),
                    ));
                }
                reason = Some(text.to_owned());
                continue;
            }
            match Mode::from_field(name) {
                Some(mode) if key.modes().contains(&mode) => {
                    fields.insert(mode, member);
                }
                Some(mode) => {
                    return Err(reject(
                        CODE_MODE_UNSUPPORTED,
                        format!("{key} does not take the mode {:?}", mode.as_str()),
                    ));
                }
                None => {
                    return Err(reject(
                        CODE_UNKNOWN_KEY,
                        format!("{key}.{name} is not a mode; {key} takes {}", mode_list(key)),
                    ));
                }
            }
        }
        if fields.is_empty() {
            return Err(reject(
                CODE_MODE_MISSING,
                format!("{key} names no mode; it takes {}", mode_list(key)),
            ));
        }
        if fields.contains_key(&Mode::Locked) && fields.len() > 1 {
            return Err(reject(
                CODE_MODE_CONFLICT,
                format!("{key}: \"locked\" excludes every other mode"),
            ));
        }
        Ok(Self { fields, reason })
    }

    fn get(&self, mode: Mode) -> Option<&'v Value> {
        self.fields.get(&mode).copied()
    }
}

fn mode_list(key: Key) -> String {
    key.modes()
        .iter()
        .map(|mode| format!("{:?}", mode.as_str()))
        .collect::<Vec<_>>()
        .join(", ")
}

/// How permissive a profile is: strict < standard < relaxed.
fn permissiveness(profile: Profile) -> u8 {
    match profile {
        Profile::Strict => 0,
        Profile::Standard => 1,
        Profile::Relaxed => 2,
    }
}

fn parse_profile_value(key: Key, mode: Mode, value: &Value) -> Result<Profile, Rejection> {
    serde_json::from_value(value.clone()).map_err(|_| {
        reject(
            CODE_VALUE_INVALID,
            format!(
                "{key}.{} must be \"relaxed\", \"standard\" or \"strict\"",
                mode.as_str()
            ),
        )
    })
}

fn parse_profile(key: Key, value: &Value) -> Result<ProfileLeaf, Rejection> {
    let modes = Modes::parse(key, value)?;
    let pick = |mode| {
        modes
            .get(mode)
            .map(|value| parse_profile_value(key, mode, value))
            .transpose()
    };
    let leaf = ProfileLeaf {
        locked: pick(Mode::Locked)?,
        default: pick(Mode::Default)?,
        floor: pick(Mode::Floor)?,
        reason: modes.reason.clone(),
    };
    if let (Some(default), Some(floor)) = (leaf.default, leaf.floor)
        && permissiveness(default) > permissiveness(floor)
    {
        return Err(reject(
            CODE_MODE_CONFLICT,
            format!(
                "{key}: the default {:?} is more permissive than the floor {:?}",
                default.as_str(),
                floor.as_str()
            ),
        ));
    }
    Ok(leaf)
}

fn parse_permit(key: Key, value: &Value, allow_ok: bool) -> Result<Permit, Rejection> {
    match text(key, value)? {
        "deny" => Ok(Permit::Deny),
        "allow" if allow_ok => Ok(Permit::Allow),
        _ if allow_ok => Err(reject(
            CODE_VALUE_INVALID,
            format!("{key} must be \"allow\" or \"deny\""),
        )),
        _ => Err(reject(
            CODE_VALUE_INVALID,
            format!("{key} must be \"deny\""),
        )),
    }
}

fn parse_patterns(key: Key, value: &Value) -> Result<Vec<CapabilityPattern>, Rejection> {
    clean_entries(key, value)?
        .into_iter()
        .map(|pattern| {
            let valid = pattern.bytes().all(|byte| {
                byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || matches!(byte, b'.' | b':' | b'/' | b'-' | b'_' | b'*')
            });
            if valid {
                Ok(CapabilityPattern(pattern))
            } else {
                Err(reject(
                    CODE_VALUE_INVALID,
                    format!(
                        "{key}: {pattern:?} is not a capability pattern; use lower-case letters, \
                         digits, `.`, `:`, `/`, `-`, `_` and `*` (any run of characters)"
                    ),
                ))
            }
        })
        .collect()
}

fn parse_classes(key: Key, value: &Value) -> Result<Vec<NeverClass>, Rejection> {
    let mut classes = BTreeSet::new();
    for entry in strings(key, value)? {
        classes.insert(match entry {
            "destructive" => NeverClass::Destructive,
            "external" => NeverClass::External,
            other => {
                return Err(reject(
                    CODE_VALUE_INVALID,
                    format!("{key}: {other:?} is not a class; expected destructive or external"),
                ));
            }
        });
    }
    Ok(classes.into_iter().collect())
}

/// A path for `platform`, absolute (or `~`-relative when `home_ok`), with no
/// `.` or `..` component.
fn parse_path_rule(
    key: Key,
    raw: &str,
    platform: TargetPlatform,
    home_ok: bool,
) -> Result<PathRule, Rejection> {
    let refuse = || {
        reject(
            CODE_VALUE_INVALID,
            format!(
                "{key}: {raw:?} is not an absolute {} path{} without `.` or `..`",
                platform.as_str(),
                if home_ok {
                    " (or one starting with ~)"
                } else {
                    ""
                }
            ),
        )
    };
    if home_ok {
        for prefix in HOME_PREFIXES {
            if let Some(rest) = raw.strip_prefix(prefix)
                && (rest.is_empty() || rest.starts_with(['/', '\\']))
            {
                let components = relative_components(rest, platform).ok_or_else(refuse)?;
                return Ok(PathRule {
                    raw: raw.to_owned(),
                    anchor: Anchor::Home,
                    components,
                    platform,
                });
            }
        }
    }
    let components = path_components(raw, platform, None, false).ok_or_else(refuse)?;
    Ok(PathRule {
        raw: raw.to_owned(),
        anchor: Anchor::Absolute,
        components,
        platform,
    })
}

fn parse_path_rules(
    key: Key,
    value: &Value,
    platform: TargetPlatform,
    home_ok: bool,
) -> Result<Vec<PathRule>, Rejection> {
    clean_entries(key, value)?
        .iter()
        .map(|raw| parse_path_rule(key, raw, platform, home_ok))
        .collect()
}

fn parse_hosts(key: Key, value: &Value) -> Result<HostList, Rejection> {
    let entries = strings(key, value)?;
    let rules = parse_no_proxy(&entries)
        .map_err(|error| reject(CODE_VALUE_INVALID, format!("{key}: {}", error.detail)))?;
    Ok(HostList {
        entries: rules.iter().map(|rule| rule.as_str().to_owned()).collect(),
        rules,
    })
}

fn parse_connectors(key: Key, value: &Value) -> Result<Vec<ConnectorId>, Rejection> {
    let mut ids = BTreeSet::new();
    for entry in strings(key, value)? {
        ids.insert(ConnectorId::parse(entry).ok_or_else(|| {
            reject(
                CODE_VALUE_INVALID,
                format!(
                    "{key}: {entry:?} is not a connector; expected one of {}",
                    ConnectorId::ALL.map(ConnectorId::as_str).join(", ")
                ),
            )
        })?);
    }
    Ok(ids.into_iter().collect())
}

/// Program names held to the human's allowlist rule.
fn program_list(key: Key, value: &Value) -> Result<Vec<String>, Rejection> {
    let programs = clean_entries(key, value)?;
    for program in &programs {
        crate::flow_service::check_allowed_program(program)
            .map_err(|refusal| reject(CODE_VALUE_INVALID, format!("{key}: {}", refusal.detail)))?;
    }
    Ok(programs)
}

fn parse_programs(key: Key, value: &Value) -> Result<ListLeaf, Rejection> {
    let modes = Modes::parse(key, value)?;
    Ok(ListLeaf {
        locked: modes
            .get(Mode::Locked)
            .map(|v| program_list(key, v))
            .transpose()?,
        allow: modes
            .get(Mode::Allow)
            .map(|v| program_list(key, v))
            .transpose()?,
        default: None,
        reason: modes.reason,
    })
}

fn parse_path_list(
    key: Key,
    value: &Value,
    platform: TargetPlatform,
) -> Result<PathListLeaf, Rejection> {
    let modes = Modes::parse(key, value)?;
    let locked = modes
        .get(Mode::Locked)
        .map(|v| {
            parse_path_rules(key, v, platform, true)
                .map(|rules| rules.into_iter().map(|rule| rule.raw).collect())
        })
        .transpose()?;
    Ok(PathListLeaf {
        locked,
        allow: modes
            .get(Mode::Allow)
            .map(|v| parse_path_rules(key, v, platform, true))
            .transpose()?,
        reason: modes.reason,
    })
}

fn parse_string_leaf(
    key: Key,
    value: &Value,
    platform: TargetPlatform,
    home_ok: bool,
) -> Result<ValueLeaf<String>, Rejection> {
    let modes = Modes::parse(key, value)?;
    let path = |value: &Value| -> Result<String, Rejection> {
        let raw = text(key, value)?.trim();
        parse_path_rule(key, raw, platform, home_ok).map(|rule| rule.raw)
    };
    Ok(ValueLeaf {
        locked: modes.get(Mode::Locked).map(path).transpose()?,
        default: modes.get(Mode::Default).map(path).transpose()?,
        reason: modes.reason,
    })
}

fn parse_ceiling(key: Key, value: &Value) -> Result<LandingCeiling, Rejection> {
    let Value::Object(members) = value else {
        return Err(wrong_type(
            key,
            "an object of push, create_pr, merge and sync",
        ));
    };
    let mut ceiling = LandingCeiling::default();
    for (name, member) in members {
        let slot = match name.as_str() {
            "push" => &mut ceiling.push,
            "create_pr" => &mut ceiling.create_pr,
            "merge" => &mut ceiling.merge,
            "sync" => &mut ceiling.sync,
            _ => {
                return Err(reject(
                    CODE_UNKNOWN_KEY,
                    format!("{key}.{name} is not a landing permission"),
                ));
            }
        };
        *slot = member.as_bool().ok_or_else(|| {
            reject(
                CODE_WRONG_TYPE,
                format!("{key}.{name} must be true or false"),
            )
        })?;
    }
    Ok(ceiling)
}

fn parse_engine_source(key: Key, value: &Value) -> Result<EngineSource, Rejection> {
    match text(key, value)? {
        "download" => Ok(EngineSource::Download),
        "mirror_only" => Ok(EngineSource::MirrorOnly),
        "import_only" => Ok(EngineSource::ImportOnly),
        _ => Err(reject(
            CODE_VALUE_INVALID,
            format!("{key} must be \"download\", \"mirror_only\" or \"import_only\""),
        )),
    }
}

fn parse_model_sources(key: Key, value: &Value) -> Result<Vec<ModelSource>, Rejection> {
    let mut sources = BTreeSet::new();
    for entry in strings(key, value)? {
        sources.insert(match entry {
            "catalog" => ModelSource::Catalog,
            "custom_url" => ModelSource::CustomUrl,
            "import" => ModelSource::Import,
            other => {
                return Err(reject(
                    CODE_VALUE_INVALID,
                    format!(
                        "{key}: {other:?} is not a source; expected catalog, custom_url or import"
                    ),
                ));
            }
        });
    }
    Ok(sources.into_iter().collect())
}

fn parse_curators(key: Key, value: &Value) -> Result<Vec<AgentId>, Rejection> {
    let mut agents: Vec<AgentId> = Vec::new();
    for entry in strings(key, value)? {
        let agent = AgentId::parse(entry).ok_or_else(|| {
            reject(
                CODE_VALUE_INVALID,
                format!(
                    "{key}: {entry:?} is not an agent; expected claude, codex, copilot or gemini"
                ),
            )
        })?;
        if !agents.contains(&agent) {
            agents.push(agent);
        }
    }
    Ok(agents)
}

/// One number of a bounded leaf. Retention: `1..=MAX_DAYS`, `null` for
/// forever where `nullable`. Idle unload: any minutes, `0` = never, and a
/// `max` of at least one.
fn bounded_value(key: Key, mode: Mode, value: &Value) -> Result<Option<u64>, Rejection> {
    let retention = matches!(key, Key::RetentionEvidenceDays | Key::RetentionAuditDays);
    let nullable = retention && matches!(mode, Mode::Locked | Mode::Default);
    if value.is_null() && nullable {
        return Ok(None);
    }
    let number = value.as_u64().ok_or_else(|| {
        wrong_type(
            key,
            if nullable {
                "a whole number of days or null (forever)"
            } else {
                "a non-negative whole number"
            },
        )
    })?;
    let max_days = u64::from(MAX_DAYS);
    if retention && !(1..=max_days).contains(&number) {
        return Err(reject(
            CODE_VALUE_INVALID,
            format!(
                "{key}.{}: a window must be between 1 and {MAX_DAYS} days, not {number}",
                mode.as_str()
            ),
        ));
    }
    if !retention && mode == Mode::Max && number == 0 {
        return Err(reject(
            CODE_VALUE_INVALID,
            format!("{key}.max must be at least 1 minute; 0 means never unload"),
        ));
    }
    Ok(Some(number))
}

fn parse_bounded(key: Key, value: &Value) -> Result<BoundedLeaf, Rejection> {
    let modes = Modes::parse(key, value)?;
    let pick = |mode| {
        modes
            .get(mode)
            .map(|value| bounded_value(key, mode, value))
            .transpose()
    };
    // `0` minutes is "never unload", this timer's forever.
    let never = |value: Option<Option<u64>>| match value {
        Some(Some(0)) if key == Key::ModelsIdleUnloadMin => Some(None),
        other => other,
    };
    let leaf = BoundedLeaf {
        locked: never(pick(Mode::Locked)?),
        default: never(pick(Mode::Default)?),
        min: pick(Mode::Min)?.flatten(),
        max: pick(Mode::Max)?.flatten(),
        reason: modes.reason.clone(),
    };
    if let (Some(min), Some(max)) = (leaf.min, leaf.max)
        && min > max
    {
        return Err(reject(
            CODE_MODE_CONFLICT,
            format!("{key}: min {min} is above max {max}"),
        ));
    }
    if let Some(default) = leaf.default
        && clamp_window(default, leaf.min, leaf.max) != default
    {
        return Err(reject(
            CODE_MODE_CONFLICT,
            format!("{key}: the default is outside min/max"),
        ));
    }
    Ok(leaf)
}

fn parse_proxy(key: Key, value: &Value) -> Result<ValueLeaf<Option<ProxyEntry>>, Rejection> {
    let modes = Modes::parse(key, value)?;
    let entry = |value: &Value| -> Result<Option<ProxyEntry>, Rejection> {
        if value.is_null() {
            return Ok(None);
        }
        let raw: ProxyEntry = serde_json::from_value(value.clone()).map_err(|error| {
            reject(
                CODE_WRONG_TYPE,
                format!(
                    "{key}.locked must be null (direct) or {{ url, auth, username? }}: {error}"
                ),
            )
        })?;
        let invalid = |error: pam_net::SettingsError| {
            reject(CODE_VALUE_INVALID, format!("{key}: {}", error.detail))
        };
        let auth = ProxyAuth::parse(&raw.auth).map_err(invalid)?;
        let proxy = Proxy::parse(&raw.url, auth, raw.username.as_deref()).map_err(invalid)?;
        Ok(Some(ProxyEntry {
            url: proxy.url(),
            auth: auth.as_str().to_owned(),
            username: proxy.username().map(str::to_owned),
        }))
    };
    Ok(ValueLeaf {
        locked: modes.get(Mode::Locked).map(entry).transpose()?,
        default: None,
        reason: modes.reason,
    })
}

fn parse_no_proxy_leaf(key: Key, value: &Value) -> Result<ListLeaf, Rejection> {
    let modes = Modes::parse(key, value)?;
    let rules = |value: &Value| -> Result<Vec<String>, Rejection> {
        let entries = strings(key, value)?;
        let rules = parse_no_proxy(&entries)
            .map_err(|error| reject(CODE_VALUE_INVALID, format!("{key}: {}", error.detail)))?;
        Ok(rules.iter().map(|rule| rule.as_str().to_owned()).collect())
    };
    Ok(ListLeaf {
        locked: modes.get(Mode::Locked).map(rules).transpose()?,
        allow: None,
        default: modes.get(Mode::Default).map(rules).transpose()?,
        reason: modes.reason,
    })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawCaPin {
    path: String,
    sha256: String,
}

fn parse_ca_bundle(
    key: Key,
    value: &Value,
    platform: TargetPlatform,
) -> Result<ValueLeaf<Option<CaBundlePin>>, Rejection> {
    let modes = Modes::parse(key, value)?;
    let pin = |value: &Value| -> Result<Option<CaBundlePin>, Rejection> {
        if value.is_null() {
            return Ok(None);
        }
        let raw: RawCaPin = serde_json::from_value(value.clone()).map_err(|error| {
            reject(
                CODE_WRONG_TYPE,
                format!("{key}.locked must be null or {{ path, sha256 }}: {error}"),
            )
        })?;
        let path = parse_path_rule(key, raw.path.trim(), platform, false)?.raw;
        let sha256 = raw.sha256.trim().to_ascii_lowercase();
        if sha256.len() != 64 || !sha256.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(reject(
                CODE_VALUE_INVALID,
                format!("{key}.locked.sha256 must be 64 hexadecimal characters"),
            ));
        }
        Ok(Some(CaBundlePin { path, sha256 }))
    };
    Ok(ValueLeaf {
        locked: modes.get(Mode::Locked).map(pin).transpose()?,
        default: None,
        reason: modes.reason,
    })
}

fn parse_mirror(
    key: Key,
    value: &Value,
    allowed: Option<&HostList>,
) -> Result<ValueLeaf<Option<String>>, Rejection> {
    let modes = Modes::parse(key, value)?;
    let field = if key == Key::NetworkEngineMirror {
        "engine_mirror"
    } else {
        "models_mirror"
    };
    let mirror = |value: &Value| -> Result<Option<String>, Rejection> {
        if value.is_null() {
            return Ok(None);
        }
        let raw = text(key, value)?;
        let base = MirrorBase::parse(raw, field)
            .map_err(|error| reject(CODE_VALUE_INVALID, format!("{key}: {}", error.detail)))?;
        if let Some(allowed) = allowed
            && !base.host_allowed(&allowed.rules)
        {
            return Err(reject(
                CODE_VALUE_INVALID,
                format!(
                    "{key}: the mirror host {} is not in network.mirror_allowed_hosts",
                    base.host()
                ),
            ));
        }
        Ok(Some(base.as_str().to_owned()))
    };
    Ok(ValueLeaf {
        locked: modes.get(Mode::Locked).map(mirror).transpose()?,
        default: modes.get(Mode::Default).map(mirror).transpose()?,
        reason: modes.reason,
    })
}

// --- Pure merge functions -----------------------------------------------

/// The less permissive of two profiles.
#[must_use]
pub fn stricter(left: Profile, right: Profile) -> Profile {
    if permissiveness(right) < permissiveness(left) {
        right
    } else {
        left
    }
}

/// A window (`None` = forever) clamped into `[min, max]`. Forever becomes
/// `max` when a `max` exists and stays forever otherwise.
#[must_use]
pub fn clamp_window(value: Option<u64>, min: Option<u64>, max: Option<u64>) -> Option<u64> {
    match value {
        None => max,
        Some(value) => Some(value.max(min.unwrap_or(0)).min(max.unwrap_or(u64::MAX))),
    }
}

/// `user ∩ allow`, keeping the user's order.
#[must_use]
pub fn intersect_exact(user: &[String], allow: &[String]) -> Vec<String> {
    user.iter()
        .filter(|entry| allow.contains(entry))
        .cloned()
        .collect()
}

/// Whether `name` matches the anchored glob `pattern`, where `*` matches
/// any run of characters (possibly empty) and nothing else is special.
#[must_use]
pub fn pattern_matches(pattern: &str, name: &str) -> bool {
    let mut parts = pattern.split('*');
    let first = parts.next().unwrap_or_default();
    let Some(mut rest) = name.strip_prefix(first) else {
        return false;
    };
    let tail: Vec<&str> = parts.collect();
    let Some((last, middle)) = tail.split_last() else {
        // No `*`: the whole name must equal the pattern.
        return rest.is_empty();
    };
    for part in middle {
        match rest.find(part) {
            Some(at) => rest = &rest[at + part.len()..],
            None => return false,
        }
    }
    rest.len() >= last.len() && rest.ends_with(last)
}

// --- The effective entry -----------------------------------------------

/// One field of a settings `get` reply's `effective` block (see the spec's
/// "Effective view on every get"). With no policy in play it is exactly
/// `{ source, locked }`, the shape `admin.network.get` already answers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectiveEntry {
    /// Where the effective value came from.
    pub source: Source,
    /// Whether the human can edit the field at all.
    pub locked: bool,
    /// The mode that decided the value, when a policy is in play.
    pub mode: Option<Mode>,
    /// The permitted range or set, for `allow`/`floor`/`min`/`max`.
    pub constraint: Option<Value>,
    /// The administrator's reason.
    pub reason: Option<String>,
    /// `applied`, `held` or `rejected`, when the document names the key.
    pub state: Option<&'static str>,
    /// The policy clamped the user's value into range.
    pub clamped: bool,
}

impl EffectiveEntry {
    /// A field no policy touches: `source` is `user` or `default`.
    #[must_use]
    pub fn unmanaged(source: Source) -> Self {
        Self {
            source,
            locked: source.locked(),
            mode: None,
            constraint: None,
            reason: None,
            state: None,
            clamped: false,
        }
    }

    /// The wire shape.
    #[must_use]
    pub fn to_json(&self) -> Value {
        let mut body = json!({ "source": self.source.as_str(), "locked": self.locked });
        if let Some(mode) = self.mode {
            body["mode"] = json!(mode.as_str());
        }
        if let Some(constraint) = &self.constraint {
            body["constraint"] = constraint.clone();
        }
        if let Some(reason) = &self.reason {
            body["reason"] = json!(reason);
        }
        if let Some(state) = self.state {
            body["state"] = json!(state);
        }
        if self.clamped {
            body["clamped"] = json!(true);
        }
        body
    }
}

/// An admin write the policy refuses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriteRefusal {
    /// [`CAUSE_SETTING_LOCKED`], [`CAUSE_POLICY_NOT_ALLOWED`] or
    /// [`CAUSE_POLICY_FROZEN`] (or a key's fixed cause).
    pub cause: &'static str,
    /// The key that blocked the write.
    pub key: Key,
    /// Names the key, the reason, the contact and `(policy <digest12>,
    /// rev <revision>)`.
    pub detail: String,
    /// [`RECOVERY_MANAGED`].
    pub recovery: &'static str,
}

// --- Merges and checks over a view --------------------------------------

impl PolicyView {
    /// A refusal for `key` with `cause`; `what` says what was refused.
    #[must_use]
    pub fn refusal(&self, key: Key, cause: &'static str, what: &str) -> WriteRefusal {
        let mut detail = format!("{what} ({key})");
        if let Some(reason) = self.policy.reason(key) {
            let _ = write!(detail, "; reason: {reason}");
        }
        if let Some(contact) = &self.meta.contact {
            let _ = write!(detail, "; contact {contact}");
        }
        let _ = write!(
            detail,
            " (policy {}, rev {})",
            self.digest12().unwrap_or("none"),
            self.meta.revision.as_deref().unwrap_or("none")
        );
        WriteRefusal {
            cause,
            key,
            detail,
            recovery: RECOVERY_MANAGED,
        }
    }

    /// Refuses any write to a held key with [`CAUSE_POLICY_FROZEN`].
    ///
    /// # Errors
    ///
    /// The refusal when `key` is held.
    pub fn guard_held(&self, key: Key) -> Result<(), WriteRefusal> {
        if self.is_held(key) {
            return Err(self.refusal(
                key,
                CAUSE_POLICY_FROZEN,
                "this setting is managed by your organisation's policy, which cannot be read \
                 right now; changes to it are paused",
            ));
        }
        Ok(())
    }

    /// [`Self::guard_held`], then [`CAUSE_SETTING_LOCKED`] when the key's
    /// mode object locks it.
    ///
    /// # Errors
    ///
    /// The refusal when `key` is held or locked.
    pub fn guard_locked(&self, key: Key) -> Result<(), WriteRefusal> {
        self.guard_held(key)?;
        if self.is_locked(key) {
            return Err(self.refusal(
                key,
                CAUSE_SETTING_LOCKED,
                "this setting is set by your organisation's policy; nothing was changed",
            ));
        }
        Ok(())
    }

    /// Whether `key`'s mode object locks it (and a value is in force).
    #[must_use]
    pub fn is_locked(&self, key: Key) -> bool {
        if !self.status(key).is_some_and(LeafStatus::in_force) {
            return false;
        }
        let policy = &self.policy;
        match key {
            Key::SecurityProfile => policy.profile.as_ref().is_some_and(|l| l.locked.is_some()),
            Key::FlowsPrograms => policy.programs.as_ref().is_some_and(|l| l.locked.is_some()),
            Key::NetworkNoProxy => policy.no_proxy.as_ref().is_some_and(|l| l.locked.is_some()),
            Key::FlowsExtraPath | Key::FlowsReadCacheRoots => {
                policy.path_list(key).is_some_and(|l| l.locked.is_some())
            }
            Key::FlowsArtifactsRoot | Key::ModelsDir => {
                policy.string_leaf(key).is_some_and(|l| l.locked.is_some())
            }
            Key::ModelsIdleUnloadMin | Key::RetentionEvidenceDays | Key::RetentionAuditDays => {
                policy.bounded(key).is_some_and(|l| l.locked.is_some())
            }
            Key::NetworkProxy => policy.proxy.as_ref().is_some_and(|l| l.locked.is_some()),
            Key::NetworkCaBundle => policy
                .ca_bundle
                .as_ref()
                .is_some_and(|l| l.locked.is_some()),
            Key::NetworkEngineMirror => policy
                .engine_mirror
                .as_ref()
                .is_some_and(|l| l.locked.is_some()),
            Key::NetworkModelsMirror => policy
                .models_mirror
                .as_ref()
                .is_some_and(|l| l.locked.is_some()),
            _ => false,
        }
    }

    /// The entry for a key whose user value stands because the key is
    /// held, rejected, or not in the document.
    fn passthrough(&self, key: Key, source: Source) -> EffectiveEntry {
        match self.status(key) {
            Some(LeafStatus::Held { .. }) => EffectiveEntry {
                locked: true,
                state: Some("held"),
                ..EffectiveEntry::unmanaged(source)
            },
            Some(LeafStatus::Rejected { .. }) => EffectiveEntry {
                state: Some("rejected"),
                ..EffectiveEntry::unmanaged(source)
            },
            _ => EffectiveEntry::unmanaged(source),
        }
    }

    /// The entry for a value the policy supplied or bounded.
    fn managed(
        &self,
        key: Key,
        source: Source,
        locked: bool,
        mode: Mode,
        constraint: Option<Value>,
        clamped: bool,
    ) -> EffectiveEntry {
        EffectiveEntry {
            source,
            locked,
            mode: Some(mode),
            constraint,
            reason: self.policy.reason(key).map(str::to_owned),
            state: self.status(key).map(LeafStatus::as_str),
            clamped,
        }
    }

    fn applied(&self, key: Key) -> bool {
        self.status(key).is_some_and(LeafStatus::in_force)
    }

    /// The effective profile: `locked`, else `stricter(user, floor)` where
    /// the user value is the stored one, the policy `default`, or the
    /// platform default, in that order. The stored row is never touched.
    #[must_use]
    pub fn effective_profile(&self, user: Option<Profile>) -> (Profile, EffectiveEntry) {
        let key = Key::SecurityProfile;
        let (base, source) = match user {
            Some(profile) => (profile, Source::User),
            None => (Profile::platform_default(), Source::Default),
        };
        let Some(leaf) = self.policy.profile.as_ref().filter(|_| self.applied(key)) else {
            return (base, self.passthrough(key, source));
        };
        if let Some(locked) = leaf.locked {
            return (
                locked,
                self.managed(key, Source::Policy, true, Mode::Locked, None, false),
            );
        }
        let (base, source, mode) = match (user, leaf.default) {
            (Some(profile), _) => (profile, Source::User, None),
            (None, Some(default)) => (default, Source::Policy, Some(Mode::Default)),
            (None, None) => (base, Source::Default, None),
        };
        let Some(floor) = leaf.floor else {
            return (
                base,
                self.managed(key, source, false, Mode::Default, None, false),
            );
        };
        let effective = stricter(base, floor);
        let clamped = effective != base;
        let constraint = Some(json!({ "floor": floor.as_str() }));
        let source = if clamped { Source::Policy } else { source };
        let mode = if clamped {
            Mode::Floor
        } else {
            mode.unwrap_or(Mode::Floor)
        };
        (
            effective,
            self.managed(key, source, false, mode, constraint, clamped),
        )
    }

    /// Whether the human may choose `requested`.
    ///
    /// # Errors
    ///
    /// [`CAUSE_POLICY_FROZEN`] when held, [`CAUSE_SETTING_LOCKED`] when
    /// locked (to anything, the same value included: the field is not the
    /// human's), [`CAUSE_POLICY_NOT_ALLOWED`] when more permissive than the
    /// floor.
    pub fn check_profile(&self, requested: Profile) -> Result<(), WriteRefusal> {
        let key = Key::SecurityProfile;
        self.guard_locked(key)?;
        if let Some(floor) = self
            .policy
            .profile
            .as_ref()
            .filter(|_| self.applied(key))
            .and_then(|leaf| leaf.floor)
            && stricter(requested, floor) != requested
        {
            return Err(self.refusal(
                key,
                CAUSE_POLICY_NOT_ALLOWED,
                &format!(
                    "the profile {:?} is more permissive than your organisation allows (at most {:?})",
                    requested.as_str(),
                    floor.as_str()
                ),
            ));
        }
        Ok(())
    }

    /// The effective number for a bounded key. `user` is the stored value
    /// (`None` = the human has none; `Some(None)` = forever). `builtin` is
    /// what applies with neither a user value nor a policy default.
    #[must_use]
    pub fn effective_window(
        &self,
        key: Key,
        user: Option<Option<u64>>,
        builtin: Option<u64>,
    ) -> (Option<u64>, EffectiveEntry) {
        let (base, source) = match user {
            Some(value) => (value, Source::User),
            None => (builtin, Source::Default),
        };
        let Some(leaf) = self.policy.bounded(key).filter(|_| self.applied(key)) else {
            return (base, self.passthrough(key, source));
        };
        if let Some(locked) = leaf.locked {
            return (
                locked,
                self.managed(key, Source::Policy, true, Mode::Locked, None, false),
            );
        }
        let (base, source) = match (user, leaf.default) {
            (Some(value), _) => (value, Source::User),
            (None, Some(default)) => (default, Source::Policy),
            (None, None) => (builtin, Source::Default),
        };
        let effective = clamp_window(base, leaf.min, leaf.max);
        let clamped = effective != base;
        let mut constraint = Map::new();
        if let Some(min) = leaf.min {
            constraint.insert("min".to_owned(), json!(min));
        }
        if let Some(max) = leaf.max {
            constraint.insert("max".to_owned(), json!(max));
        }
        let mode = match (clamped, base, leaf.min) {
            (true, Some(value), Some(min)) if value < min => Mode::Min,
            (true, _, _) => Mode::Max,
            (false, _, _) if source == Source::Policy => Mode::Default,
            (false, _, _) if leaf.max.is_some() => Mode::Max,
            (false, _, _) if leaf.min.is_some() => Mode::Min,
            (false, _, _) => Mode::Default,
        };
        let constraint = (!constraint.is_empty()).then_some(Value::Object(constraint));
        let source = if clamped { Source::Policy } else { source };
        (
            effective,
            self.managed(key, source, false, mode, constraint, clamped),
        )
    }

    /// Whether the human may store `requested` (`None` = forever) for a
    /// bounded key.
    ///
    /// # Errors
    ///
    /// Held, locked, or outside `min`/`max` (forever under a `max`).
    pub fn check_window(&self, key: Key, requested: Option<u64>) -> Result<(), WriteRefusal> {
        self.guard_locked(key)?;
        let Some(leaf) = self.policy.bounded(key).filter(|_| self.applied(key)) else {
            return Ok(());
        };
        if clamp_window(requested, leaf.min, leaf.max) != requested {
            let shown = requested.map_or_else(|| "forever".to_owned(), |value| value.to_string());
            return Err(self.refusal(
                key,
                CAUSE_POLICY_NOT_ALLOWED,
                &format!(
                    "{shown} is outside what your organisation allows (min {}, max {})",
                    leaf.min
                        .map_or_else(|| "none".to_owned(), |v| v.to_string()),
                    leaf.max
                        .map_or_else(|| "none".to_owned(), |v| v.to_string())
                ),
            ));
        }
        Ok(())
    }

    /// The effective idle-unload minutes (`0` = never, the "forever" of
    /// this timer). `user` is the stored value, `None` when unset.
    #[must_use]
    pub fn effective_idle_unload_min(
        &self,
        user: Option<u64>,
        builtin: u64,
    ) -> (u64, EffectiveEntry) {
        let to_window = |minutes: u64| (minutes != 0).then_some(minutes);
        let (value, entry) = self.effective_window(
            Key::ModelsIdleUnloadMin,
            user.map(to_window),
            to_window(builtin),
        );
        (value.unwrap_or(0), entry)
    }

    /// The effective retention pair. `user` holds the stored windows, each
    /// `None` when the human has no stored value and `Some(None)` for
    /// forever. After each window is bounded, a pair the bounds pushed out
    /// of order is put back in order without leaving either window's
    /// bounds: the evidence window comes down to the audit one when it
    /// may, otherwise both meet at the evidence floor (records are kept
    /// longer, never shorter).
    #[must_use]
    pub fn effective_retention(
        &self,
        evidence: Option<Option<u32>>,
        audit: Option<Option<u32>>,
    ) -> (RetentionSettings, [EffectiveEntry; 2]) {
        let widen = |value: Option<Option<u32>>| value.map(|days| days.map(u64::from));
        let (mut evidence_days, mut evidence_entry) =
            self.effective_window(Key::RetentionEvidenceDays, widen(evidence), None);
        let (mut audit_days, mut audit_entry) =
            self.effective_window(Key::RetentionAuditDays, widen(audit), None);
        if let (Some(evidence), Some(audit)) = (evidence_days, audit_days)
            && evidence > audit
        {
            let floor = self
                .policy
                .evidence_days
                .as_ref()
                .filter(|_| self.applied(Key::RetentionEvidenceDays))
                .and_then(|leaf| leaf.locked.flatten().or(leaf.min))
                .unwrap_or(1);
            if audit >= floor {
                evidence_days = Some(audit);
                evidence_entry.clamped = true;
                evidence_entry.source = Source::Policy;
            } else {
                evidence_days = Some(floor);
                audit_days = Some(floor);
                audit_entry.clamped = true;
                audit_entry.source = Source::Policy;
            }
        }
        let narrow = |days: Option<u64>| days.and_then(|days| u32::try_from(days).ok());
        (
            RetentionSettings {
                evidence_days: narrow(evidence_days),
                audit_days: narrow(audit_days),
            },
            [evidence_entry, audit_entry],
        )
    }

    /// The effective program allowlist: `locked`, else the user's list
    /// intersected with `allow`. `user` is the stored list.
    #[must_use]
    pub fn effective_programs(&self, user: &[String]) -> (Vec<String>, EffectiveEntry) {
        let key = Key::FlowsPrograms;
        let Some(leaf) = self.policy.programs.as_ref().filter(|_| self.applied(key)) else {
            return (user.to_vec(), self.passthrough(key, Source::User));
        };
        if let Some(locked) = &leaf.locked {
            return (
                locked.clone(),
                self.managed(key, Source::Policy, true, Mode::Locked, None, false),
            );
        }
        let allow = leaf.allow.as_deref().unwrap_or_default();
        let kept = intersect_exact(user, allow);
        let clamped = kept.len() != user.len();
        let source = if clamped {
            Source::Policy
        } else {
            Source::User
        };
        let constraint = Some(json!({ "allow": allow }));
        (
            kept,
            self.managed(key, source, false, Mode::Allow, constraint, clamped),
        )
    }

    /// The effective path list for `flows.extra_path` or
    /// `flows.read_cache_roots`: `locked`, else the user's entries that
    /// sit under an `allow` prefix (compared by component after `~`
    /// expansion against `home`).
    #[must_use]
    pub fn effective_path_list(
        &self,
        key: Key,
        user: &[String],
        home: Option<&Path>,
    ) -> (Vec<String>, EffectiveEntry) {
        let Some(leaf) = self.policy.path_list(key).filter(|_| self.applied(key)) else {
            return (user.to_vec(), self.passthrough(key, Source::User));
        };
        if let Some(locked) = &leaf.locked {
            return (
                locked.clone(),
                self.managed(key, Source::Policy, true, Mode::Locked, None, false),
            );
        }
        let allow = leaf.allow.as_deref().unwrap_or_default();
        let kept: Vec<String> = user
            .iter()
            .filter(|entry| allow.iter().any(|rule| rule.covers(entry, home)))
            .cloned()
            .collect();
        let clamped = kept.len() != user.len();
        let source = if clamped {
            Source::Policy
        } else {
            Source::User
        };
        let constraint = Some(json!({
            "allow": allow.iter().map(PathRule::as_str).collect::<Vec<_>>()
        }));
        (
            kept,
            self.managed(key, source, false, Mode::Allow, constraint, clamped),
        )
    }

    /// Whether every entry of `requested` passes the policy for a list key
    /// (`flows.programs`, `flows.extra_path`, `flows.read_cache_roots`).
    ///
    /// # Errors
    ///
    /// Held, locked, or an entry outside `allow` (named in the detail).
    pub fn check_list(
        &self,
        key: Key,
        requested: &[String],
        home: Option<&Path>,
    ) -> Result<(), WriteRefusal> {
        self.guard_locked(key)?;
        let outside: Vec<&String> = match key {
            Key::FlowsPrograms => {
                let (kept, _) = self.effective_programs(requested);
                requested
                    .iter()
                    .filter(|entry| !kept.contains(entry))
                    .collect()
            }
            Key::FlowsExtraPath | Key::FlowsReadCacheRoots => {
                let (kept, _) = self.effective_path_list(key, requested, home);
                requested
                    .iter()
                    .filter(|entry| !kept.contains(entry))
                    .collect()
            }
            _ => Vec::new(),
        };
        if let Some(first) = outside.first() {
            return Err(self.refusal(
                key,
                CAUSE_POLICY_NOT_ALLOWED,
                &format!("{first:?} is not in the list your organisation allows"),
            ));
        }
        Ok(())
    }

    /// The effective value of a `locked`/`default` string key
    /// (`flows.artifacts_root`, `models.dir`): `locked`, else the user's,
    /// else the policy `default`, else `None` (the consumer's builtin).
    #[must_use]
    pub fn effective_string(
        &self,
        key: Key,
        user: Option<String>,
    ) -> (Option<String>, EffectiveEntry) {
        let source = if user.is_some() {
            Source::User
        } else {
            Source::Default
        };
        let Some(leaf) = self.policy.string_leaf(key).filter(|_| self.applied(key)) else {
            return (user, self.passthrough(key, source));
        };
        if let Some(locked) = &leaf.locked {
            return (
                Some(locked.clone()),
                self.managed(key, Source::Policy, true, Mode::Locked, None, false),
            );
        }
        match (user, &leaf.default) {
            (Some(user), _) => (
                Some(user),
                self.managed(key, Source::User, false, Mode::Default, None, false),
            ),
            (None, Some(default)) => (
                Some(default.clone()),
                self.managed(key, Source::Policy, false, Mode::Default, None, false),
            ),
            (None, None) => (None, self.passthrough(key, Source::Default)),
        }
    }

    /// Whether `security.grants.manual` denies adding grants (in force).
    #[must_use]
    pub fn grants_manual_denied(&self) -> bool {
        self.applied(Key::GrantsManual) && self.policy.grants_manual == Some(Permit::Deny)
    }

    /// Whether `security.grants.remember` denies remembered approvals.
    #[must_use]
    pub fn grants_remember_denied(&self) -> bool {
        self.applied(Key::GrantsRemember) && self.policy.grants_remember == Some(Permit::Deny)
    }

    /// The `never` rule (a pattern, or `class:<name>`) that matches
    /// `capability` of `class`, if any. A match refuses
    /// [`CAUSE_POLICY_DENIED`] on every profile, active grant or not.
    #[must_use]
    pub fn never_match(&self, capability: &str, class: Option<CapabilityClass>) -> Option<String> {
        if self.applied(Key::GrantsNever)
            && let Some(rule) = self
                .policy
                .grants_never
                .iter()
                .flatten()
                .find(|pattern| pattern.matches(capability))
        {
            return Some(rule.as_str().to_owned());
        }
        if self.applied(Key::GrantsNeverClasses)
            && let Some(class) = class
            && let Some(rule) = self
                .policy
                .grants_never_classes
                .iter()
                .flatten()
                .find(|never| never.matches(class))
        {
            return Some(format!("class:{}", rule.as_str()));
        }
        None
    }

    /// Whether `admin.grants.add` may add `capability`.
    ///
    /// # Errors
    ///
    /// [`CAUSE_POLICY_FROZEN`] when any grants key is held,
    /// [`CAUSE_SETTING_LOCKED`] under `manual: deny`,
    /// [`CAUSE_POLICY_NOT_ALLOWED`] for a `never` match.
    pub fn check_grant_add(
        &self,
        capability: &str,
        class: Option<CapabilityClass>,
    ) -> Result<(), WriteRefusal> {
        for key in [Key::GrantsManual, Key::GrantsNever, Key::GrantsNeverClasses] {
            self.guard_held(key)?;
        }
        if self.grants_manual_denied() {
            return Err(self.refusal(
                Key::GrantsManual,
                CAUSE_SETTING_LOCKED,
                "your organisation's policy does not allow adding grants by hand",
            ));
        }
        if let Some(rule) = self.never_match(capability, class) {
            let key = if rule.starts_with("class:") {
                Key::GrantsNeverClasses
            } else {
                Key::GrantsNever
            };
            return Err(self.refusal(
                key,
                CAUSE_POLICY_NOT_ALLOWED,
                &format!("the capability {capability:?} is never allowed on this machine"),
            ));
        }
        Ok(())
    }

    /// Whether an approval may be remembered as a grant.
    ///
    /// # Errors
    ///
    /// Held, or [`CAUSE_SETTING_LOCKED`] under `remember: deny`.
    pub fn check_remember(&self) -> Result<(), WriteRefusal> {
        self.guard_held(Key::GrantsRemember)?;
        if self.grants_remember_denied() {
            return Err(self.refusal(
                Key::GrantsRemember,
                CAUSE_SETTING_LOCKED,
                "your organisation's policy does not allow remembering an approval",
            ));
        }
        Ok(())
    }

    /// Whether a canonical repository root sits under an allowed prefix
    /// (always, when the key is not in force).
    #[must_use]
    pub fn repository_root_allowed(&self, root: &Path) -> bool {
        let key = Key::ScopesAllowedRepositoryRoots;
        match self
            .policy
            .allowed_repository_roots
            .as_ref()
            .filter(|_| self.applied(key))
        {
            Some(rules) => rules.iter().any(|rule| rule.covers_path(root, None)),
            None => true,
        }
    }

    /// Whether connector-wide scope access is denied.
    #[must_use]
    pub fn connector_wide_denied(&self) -> bool {
        self.applied(Key::ScopesConnectorWide) && self.policy.connector_wide == Some(Permit::Deny)
    }

    /// Whether a connector base URL's host is allowed (always, when the key
    /// is not in force).
    #[must_use]
    pub fn base_url_allowed(&self, base_url: &Url) -> bool {
        let key = Key::ConnectorsAllowedBaseHosts;
        self.policy
            .allowed_base_hosts
            .as_ref()
            .filter(|_| self.applied(key))
            .is_none_or(|hosts| hosts.allows(base_url))
    }

    /// Whether the policy disables `connector`.
    #[must_use]
    pub fn connector_disabled(&self, connector: ConnectorId) -> bool {
        self.applied(Key::ConnectorsDisabled)
            && self
                .policy
                .disabled_connectors
                .as_ref()
                .is_some_and(|ids| ids.contains(&connector))
    }

    /// The landing permission ceiling (all `true` when not in force).
    #[must_use]
    pub fn landing_ceiling(&self) -> LandingCeiling {
        self.policy
            .max_permissions
            .filter(|_| self.applied(Key::LandingMaxPermissions))
            .unwrap_or_default()
    }

    /// Whether a GitHub server URL's host is allowed for landing.
    #[must_use]
    pub fn github_server_allowed(&self, server: &Url) -> bool {
        let key = Key::LandingAllowedGithubServers;
        self.policy
            .allowed_github_servers
            .as_ref()
            .filter(|_| self.applied(key))
            .is_none_or(|hosts| hosts.allows(server))
    }

    /// Where the engine may come from.
    #[must_use]
    pub fn engine_source(&self) -> EngineSource {
        self.policy
            .engine_source
            .filter(|_| self.applied(Key::ModelsEngineSource))
            .unwrap_or_default()
    }

    /// Whether models may arrive through `source`.
    #[must_use]
    pub fn model_source_allowed(&self, source: ModelSource) -> bool {
        self.policy
            .allowed_sources
            .as_ref()
            .filter(|_| self.applied(Key::ModelsAllowedSources))
            .is_none_or(|sources| sources.contains(&source))
    }

    /// Whether `agent` may be the curator (`[]` disables every one).
    #[must_use]
    pub fn curator_allowed(&self, agent: AgentId) -> bool {
        self.policy
            .allowed_curators
            .as_ref()
            .filter(|_| self.applied(Key::ModelsAllowedCurators))
            .is_none_or(|agents| agents.contains(&agent))
    }

    /// Whether the organisation requires the login unit (a compliance
    /// signal, never an enforcement).
    #[must_use]
    pub fn require_login_unit(&self) -> bool {
        self.applied(Key::ServiceRequireLoginUnit) && self.policy.require_login_unit == Some(true)
    }

    /// The locked network fields as the network service's overlay: a field
    /// is present exactly when the policy locks it. The CA bundle is not
    /// included: its record names a private copy the loader must import
    /// (trust check and digest) first; the pin is
    /// `policy().ca_bundle`. `None` when nothing in the network section is
    /// in force.
    #[must_use]
    pub fn managed_network(&self) -> Option<ManagedNetwork> {
        let policy = &self.policy;
        let locked = |key: Key| self.applied(key) && self.is_locked(key);
        let managed = ManagedNetwork {
            proxy: policy
                .proxy
                .as_ref()
                .filter(|_| locked(Key::NetworkProxy))
                .and_then(|leaf| leaf.locked.clone()),
            no_proxy: policy
                .no_proxy
                .as_ref()
                .filter(|_| locked(Key::NetworkNoProxy))
                .and_then(|leaf| leaf.locked.clone()),
            ca_bundle: None,
            engine_mirror: policy
                .engine_mirror
                .as_ref()
                .filter(|_| locked(Key::NetworkEngineMirror))
                .and_then(|leaf| leaf.locked.clone()),
            models_mirror: policy
                .models_mirror
                .as_ref()
                .filter(|_| locked(Key::NetworkModelsMirror))
                .and_then(|leaf| leaf.locked.clone()),
            mirror_allowed_hosts: policy
                .mirror_allowed_hosts
                .as_ref()
                .filter(|_| self.applied(Key::NetworkMirrorAllowedHosts))
                .map(|hosts| hosts.entries.clone())
                .unwrap_or_default(),
        };
        (managed != ManagedNetwork::default()).then_some(managed)
    }

    /// The network key that closes connector calls and downloads
    /// (`network_policy_invalid`): a proxy, no-proxy or CA bundle leaf the
    /// file named, that was rejected, with no last-known-good value.
    #[must_use]
    pub fn network_closed(&self) -> Option<Key> {
        [Key::NetworkProxy, Key::NetworkNoProxy, Key::NetworkCaBundle]
            .into_iter()
            .find(|key| {
                matches!(
                    self.status(*key),
                    Some(LeafStatus::Held {
                        intent_known: true,
                        ..
                    })
                )
            })
    }
}
