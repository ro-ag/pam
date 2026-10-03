//! The boundary self-check (`pam doctor`): the probe inventory, the verdict
//! rule and the report document a client prints and sends to the daemon as
//! the arguments of the public `doctor.report` capability.
//!
//! A probe is one side-effect-free test run from the agent's position
//! against a path, socket or broker the boundary says the agent must reach
//! ([`ProbeClass::MustAllow`]) or must not ([`ProbeClass::MustDeny`]); the
//! inventory is [`INVENTORY`], keyed by [`ProbeId`]. The verdict
//! ([`judge`]) is a pure function over the rows: a boundary is claimed from
//! evidence only, so an [`ProbeState::Unknown`] must-deny probe fails it.
//!
//! The daemon receives the document from a public client, so it validates
//! before storing anything ([`DoctorReport::from_args`]): the schema version,
//! the byte and count bounds, every string (bounded, no control characters),
//! that each row's class and platform agree with the inventory, and that the
//! claimed verdict and lists are exactly what the rows compute. A report
//! that fails any of these is refused and nothing is stored. The verdict
//! never changes authority: it is a fact for the human and for fleet
//! tooling.
//!
//! The schema is versioned and additive. Readers key on `verdict`, `failed`
//! and the exit code.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::wire::Via;

/// Version of the report document; bumped when a field changes meaning.
pub const SCHEMA_VERSION: u32 = 1;

/// Largest report the daemon accepts as `doctor.report` arguments, in
/// serialized bytes. A full inventory with every row carrying an OS error
/// fits with room to spare.
pub const MAX_REPORT_BYTES: usize = 16 * 1024;

/// Most probe rows a report may carry, and the longest `failed`,
/// `unverified` and `skipped` lists. The inventory has fewer; the headroom
/// is for additive versions.
pub const MAX_PROBES: usize = 64;

/// Longest free text (notes, reasons, versions, process names), in bytes.
pub const MAX_TEXT_BYTES: usize = 256;

/// Longest path (base, endpoint, executable, repository), in bytes.
pub const MAX_PATH_BYTES: usize = 1024;

/// Longest `skipped[].why`: a state name, a separator and a note.
pub const MAX_WHY_BYTES: usize =
    ProbeState::NotProbed.as_str().len() + WHY_SEPARATOR.len() + MAX_TEXT_BYTES;

/// Most names a self-reported harness chain may list. The client's walk is
/// bounded by [`crate::caller::MAX_CHAIN_DEPTH`].
pub const MAX_CHAIN_NAMES: usize = 16;

/// Joins a skipped probe's state and note in `skipped[].why`.
const WHY_SEPARATOR: &str = ": ";

/// A supported platform; the probe mechanisms differ between the two.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Platform {
    /// macOS arm64.
    Macos,
    /// Windows amd64 and arm64.
    Windows,
}

impl Platform {
    /// The platform this binary was built for; `None` where `doctor` has no
    /// probes (not a supported platform).
    #[must_use]
    pub const fn current() -> Option<Self> {
        if cfg!(target_os = "macos") {
            Some(Self::Macos)
        } else if cfg!(windows) {
            Some(Self::Windows)
        } else {
            None
        }
    }

    /// The wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Macos => "macos",
            Self::Windows => "windows",
        }
    }
}

impl fmt::Display for Platform {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// What the boundary requires of a probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbeClass {
    /// The agent needs it; anything but `allowed` means there is nothing
    /// to report to.
    MustAllow,
    /// The boundary requires it denied; `allowed` or `unknown` fails the
    /// verdict.
    MustDeny,
    /// Reported, never judged.
    Info,
}

impl ProbeClass {
    /// The wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MustAllow => "must_allow",
            Self::MustDeny => "must_deny",
            Self::Info => "info",
        }
    }
}

impl fmt::Display for ProbeClass {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// What a probe observed. The default is `unknown`: a row nothing filled
/// in fails closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbeState {
    /// The operation succeeded (or the OS granted the access and only a
    /// share mode refused it).
    Allowed,
    /// The OS refused the access: `PermissionDenied`, or the helper's
    /// pinned refusal string.
    Denied,
    /// The path does not exist. Reported, not judged.
    Absent,
    /// Could not classify: a timeout, an unexpected error, a helper that
    /// could not run or answered with an unpinned string.
    #[default]
    Unknown,
    /// Never attempted: no side-effect-free test exists, or the probe does
    /// not apply on this platform. Reported, not judged.
    NotProbed,
}

impl ProbeState {
    /// The wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Allowed => "allowed",
            Self::Denied => "denied",
            Self::Absent => "absent",
            Self::Unknown => "unknown",
            Self::NotProbed => "not_probed",
        }
    }
}

impl fmt::Display for ProbeState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// One probe of the inventory. The discriminant is its row in [`INVENTORY`];
/// the wire spelling is the row's `name`. Serialized as that string; a
/// string naming no row does not deserialize.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ProbeId {
    /// `public.reach`: connect the public endpoint and complete a hello.
    PublicReach,
    /// `run.lock_probe`: the client's own readiness test on the lock file.
    RunLockProbe,
    /// `run.lock_write`: open the lock file for write.
    RunLockWrite,
    /// `public.unlink`: never probed; the only test has a side effect.
    PublicUnlink,
    /// `admin.endpoint`: connect the administration socket; send nothing.
    AdminEndpoint,
    /// `admin.endpoint_alias`: the same through a `run/../admin` alias.
    AdminEndpointAlias,
    /// `admin.control_read`: open the Windows `control.json` for read
    /// without reading a byte.
    AdminControlRead,
    /// `admin.dir`: list the administration directory.
    AdminDir,
    /// `store.read`: open the store for read.
    StoreRead,
    /// `store.write`: open the store for write.
    StoreWrite,
    /// `store.wal_read`: open the write-ahead log for read.
    StoreWalRead,
    /// `store.wal_write`: open the write-ahead log for write.
    StoreWalWrite,
    /// `store.shm_read`: open the shared-memory index for read.
    StoreShmRead,
    /// `store.shm_write`: open the shared-memory index for write.
    StoreShmWrite,
    /// `backup.read`: list the store backups.
    BackupRead,
    /// `model_trust.read`: list the model trust records.
    ModelTrustRead,
    /// `engine.read`: list the engine install.
    EngineRead,
    /// `engine.runtime_read`: list the engine's runtime directory (API key).
    EngineRuntimeRead,
    /// `engine.socket`: connect the engine's private socket.
    EngineSocket,
    /// `flows.read`: list the flow library.
    FlowsRead,
    /// `log.read`: list the daemon log.
    LogRead,
    /// `keychain.search`: search the connector keychain service for an
    /// absent item.
    KeychainSearch,
    /// `daemon.signal`: signal 0 to the daemon's pid.
    DaemonSignal,
    /// `daemon.process_query`: query the daemon process's executable
    /// (Windows; query rights are attribution, not control).
    DaemonProcessQuery,
    /// `broker.launchservices`: ask `LaunchServices` for an absent bundle.
    BrokerLaunchServices,
    /// `broker.appleevents`: address an `AppleEvent` to an absent app id.
    BrokerAppleEvents,
    /// `broker.shellexecute`: create a process (Windows).
    BrokerShellExecute,
    /// `exe.write`: open the running executable for write.
    ExeWrite,
    /// `bundle.write`: open the `.app` bundle's `Info.plist` for write.
    BundleWrite,
}

/// One row of the inventory: what a probe is and where it runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProbeSpec {
    /// The probe.
    pub id: ProbeId,
    /// Its stable wire id.
    pub name: &'static str,
    /// What the boundary requires of it.
    pub class: ProbeClass,
    /// Where it is attempted; elsewhere its row is `not_probed`. Empty for
    /// a probe that is never attempted.
    pub platforms: &'static [Platform],
    /// What it checks, in one sentence; the method is the probe engine's.
    pub checks: &'static str,
}

const MACOS: &[Platform] = &[Platform::Macos];
const WINDOWS: &[Platform] = &[Platform::Windows];
const BOTH: &[Platform] = &[Platform::Macos, Platform::Windows];
const NEVER: &[Platform] = &[];

const fn row(
    id: ProbeId,
    name: &'static str,
    class: ProbeClass,
    platforms: &'static [Platform],
    checks: &'static str,
) -> ProbeSpec {
    ProbeSpec {
        id,
        name,
        class,
        platforms,
        checks,
    }
}

/// The probe inventory, in report order: the must-allow probe first, then
/// the private state the boundary excludes. Row `i` is the probe whose
/// discriminant is `i`.
pub static INVENTORY: [ProbeSpec; 29] = [
    row(
        ProbeId::PublicReach,
        "public.reach",
        ProbeClass::MustAllow,
        BOTH,
        "the public endpoint accepts a connection and answers a hello",
    ),
    row(
        ProbeId::RunLockProbe,
        "run.lock_probe",
        ProbeClass::Info,
        BOTH,
        "the daemon lock can be opened and shared-locked (what lazy start needs)",
    ),
    row(
        ProbeId::RunLockWrite,
        "run.lock_write",
        ProbeClass::MustDeny,
        BOTH,
        "the daemon lock cannot be opened for write",
    ),
    row(
        ProbeId::PublicUnlink,
        "public.unlink",
        ProbeClass::MustDeny,
        NEVER,
        "the public socket cannot be unlinked (no side-effect-free test; never probed)",
    ),
    row(
        ProbeId::AdminEndpoint,
        "admin.endpoint",
        ProbeClass::MustDeny,
        MACOS,
        "the administration socket refuses a connection (nothing is sent)",
    ),
    row(
        ProbeId::AdminEndpointAlias,
        "admin.endpoint_alias",
        ProbeClass::MustDeny,
        MACOS,
        "the administration socket refuses a connection through a run/../admin alias",
    ),
    row(
        ProbeId::AdminControlRead,
        "admin.control_read",
        ProbeClass::MustDeny,
        WINDOWS,
        "the administration control file cannot be opened for read (no byte is read)",
    ),
    row(
        ProbeId::AdminDir,
        "admin.dir",
        ProbeClass::MustDeny,
        BOTH,
        "the administration directory cannot be listed",
    ),
    row(
        ProbeId::StoreRead,
        "store.read",
        ProbeClass::MustDeny,
        BOTH,
        "the store cannot be opened for read",
    ),
    row(
        ProbeId::StoreWrite,
        "store.write",
        ProbeClass::MustDeny,
        BOTH,
        "the store cannot be opened for write",
    ),
    row(
        ProbeId::StoreWalRead,
        "store.wal_read",
        ProbeClass::MustDeny,
        BOTH,
        "the store's write-ahead log cannot be opened for read",
    ),
    row(
        ProbeId::StoreWalWrite,
        "store.wal_write",
        ProbeClass::MustDeny,
        BOTH,
        "the store's write-ahead log cannot be opened for write",
    ),
    row(
        ProbeId::StoreShmRead,
        "store.shm_read",
        ProbeClass::MustDeny,
        BOTH,
        "the store's shared-memory index cannot be opened for read",
    ),
    row(
        ProbeId::StoreShmWrite,
        "store.shm_write",
        ProbeClass::MustDeny,
        BOTH,
        "the store's shared-memory index cannot be opened for write",
    ),
    row(
        ProbeId::BackupRead,
        "backup.read",
        ProbeClass::MustDeny,
        BOTH,
        "the store backups cannot be listed",
    ),
    row(
        ProbeId::ModelTrustRead,
        "model_trust.read",
        ProbeClass::MustDeny,
        BOTH,
        "the model trust records cannot be listed",
    ),
    row(
        ProbeId::EngineRead,
        "engine.read",
        ProbeClass::MustDeny,
        BOTH,
        "the engine install cannot be listed",
    ),
    row(
        ProbeId::EngineRuntimeRead,
        "engine.runtime_read",
        ProbeClass::MustDeny,
        BOTH,
        "the engine's runtime directory (its API key) cannot be listed",
    ),
    row(
        ProbeId::EngineSocket,
        "engine.socket",
        ProbeClass::MustDeny,
        MACOS,
        "the engine's private socket refuses a connection",
    ),
    row(
        ProbeId::FlowsRead,
        "flows.read",
        ProbeClass::MustDeny,
        BOTH,
        "the flow library cannot be listed",
    ),
    row(
        ProbeId::LogRead,
        "log.read",
        ProbeClass::MustDeny,
        BOTH,
        "the daemon log cannot be listed",
    ),
    row(
        ProbeId::KeychainSearch,
        "keychain.search",
        ProbeClass::MustDeny,
        BOTH,
        "the connector keychain service refuses a search for an absent item",
    ),
    row(
        ProbeId::DaemonSignal,
        "daemon.signal",
        ProbeClass::MustDeny,
        MACOS,
        "signal 0 to the daemon's pid is refused",
    ),
    row(
        ProbeId::DaemonProcessQuery,
        "daemon.process_query",
        ProbeClass::MustDeny,
        WINDOWS,
        "the daemon process's executable cannot be queried (query only, never termination)",
    ),
    row(
        ProbeId::BrokerLaunchServices,
        "broker.launchservices",
        ProbeClass::MustDeny,
        MACOS,
        "LaunchServices refuses a lookup of an absent bundle id",
    ),
    row(
        ProbeId::BrokerAppleEvents,
        "broker.appleevents",
        ProbeClass::MustDeny,
        MACOS,
        "the AppleEvent runtime refuses to address an absent application id",
    ),
    row(
        ProbeId::BrokerShellExecute,
        "broker.shellexecute",
        ProbeClass::MustDeny,
        WINDOWS,
        "a process cannot be created (the broker; allowed whenever doctor itself runs)",
    ),
    row(
        ProbeId::ExeWrite,
        "exe.write",
        ProbeClass::MustDeny,
        BOTH,
        "the running executable cannot be opened for write",
    ),
    row(
        ProbeId::BundleWrite,
        "bundle.write",
        ProbeClass::MustDeny,
        MACOS,
        "the .app bundle's Info.plist cannot be opened for write",
    ),
];

impl ProbeId {
    /// The inventory row for this probe.
    #[must_use]
    pub const fn spec(self) -> &'static ProbeSpec {
        &INVENTORY[self as usize]
    }

    /// The stable wire id, e.g. `public.reach`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        self.spec().name
    }

    /// What the boundary requires of this probe.
    #[must_use]
    pub const fn class(self) -> ProbeClass {
        self.spec().class
    }

    /// Where this probe is attempted.
    #[must_use]
    pub const fn platforms(self) -> &'static [Platform] {
        self.spec().platforms
    }

    /// What this probe checks, in one sentence.
    #[must_use]
    pub const fn checks(self) -> &'static str {
        self.spec().checks
    }

    /// Whether this probe is attempted on `platform`; elsewhere its row
    /// must be `not_probed`.
    #[must_use]
    pub fn applies_to(self, platform: Platform) -> bool {
        self.platforms().contains(&platform)
    }

    /// Every probe, in report order.
    pub fn all() -> impl Iterator<Item = Self> {
        INVENTORY.iter().map(|row| row.id)
    }
}

impl fmt::Display for ProbeId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// A string that names no inventory row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownProbe(pub String);

impl fmt::Display for UnknownProbe {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "unknown probe id {:?}", self.0)
    }
}

impl std::error::Error for UnknownProbe {}

impl FromStr for ProbeId {
    type Err = UnknownProbe;

    fn from_str(name: &str) -> Result<Self, Self::Err> {
        INVENTORY
            .iter()
            .find(|row| row.name == name)
            .map(|row| row.id)
            .ok_or_else(|| UnknownProbe(name.chars().take(64).collect()))
    }
}

impl Serialize for ProbeId {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for ProbeId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let name = String::deserialize(deserializer)?;
        name.parse().map_err(serde::de::Error::custom)
    }
}

/// The OS error a probe saw, as the classifier read it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OsError {
    /// The error's kind, as `std::io::ErrorKind` prints it (e.g.
    /// `PermissionDenied`), or the helper's own category.
    pub kind: String,
    /// The raw OS error code when there is one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<i32>,
    /// A bounded, human-readable detail (a helper's pinned line).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

impl OsError {
    /// The kind and raw code of an `io::Error`; the message is left to the
    /// probe engine, which knows what is safe to echo.
    #[must_use]
    pub fn from_io(error: &std::io::Error) -> Self {
        Self {
            kind: format!("{:?}", error.kind()),
            code: error.raw_os_error(),
            detail: None,
        }
    }

    /// An error of a named kind with no OS code.
    #[must_use]
    pub fn of_kind(kind: impl Into<String>) -> Self {
        Self {
            kind: kind.into(),
            code: None,
            detail: None,
        }
    }

    /// The same error with a detail line.
    #[must_use]
    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }
}

/// What one probe attempt produced, before it is tied to an id: the state,
/// the OS error that led to it, a note where the state needs one, and how
/// long it took.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ProbeResult {
    /// What the probe observed.
    pub state: ProbeState,
    /// The OS error it saw, when it saw one.
    pub os_error: Option<OsError>,
    /// Why the state is what it is, for `unknown` and `not_probed`.
    pub note: Option<String>,
    /// How long the attempt took, when it was attempted.
    pub elapsed_ms: Option<u64>,
}

impl ProbeResult {
    /// The operation succeeded.
    #[must_use]
    pub fn allowed() -> Self {
        Self {
            state: ProbeState::Allowed,
            ..Self::default()
        }
    }

    /// The OS refused the access.
    #[must_use]
    pub fn denied(os_error: OsError) -> Self {
        Self {
            state: ProbeState::Denied,
            os_error: Some(os_error),
            ..Self::default()
        }
    }

    /// The path does not exist.
    #[must_use]
    pub fn absent() -> Self {
        Self {
            state: ProbeState::Absent,
            ..Self::default()
        }
    }

    /// The outcome could not be classified; `note` says why.
    #[must_use]
    pub fn unknown(note: impl Into<String>) -> Self {
        Self {
            state: ProbeState::Unknown,
            note: Some(note.into()),
            ..Self::default()
        }
    }

    /// The probe was not attempted; `reason` says why.
    #[must_use]
    pub fn not_probed(reason: impl Into<String>) -> Self {
        Self {
            state: ProbeState::NotProbed,
            note: Some(reason.into()),
            ..Self::default()
        }
    }

    /// The same result with the OS error attached.
    #[must_use]
    pub fn with_os_error(mut self, os_error: OsError) -> Self {
        self.os_error = Some(os_error);
        self
    }

    /// The same result with a note attached.
    #[must_use]
    pub fn with_note(mut self, note: impl Into<String>) -> Self {
        self.note = Some(note.into());
        self
    }

    /// The same result with its duration.
    #[must_use]
    pub fn with_elapsed_ms(mut self, elapsed_ms: u64) -> Self {
        self.elapsed_ms = Some(elapsed_ms);
        self
    }
}

/// One row of the report: a probe and what it observed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Probe {
    /// The probe.
    pub id: ProbeId,
    /// Its class, repeated from the inventory for readers of the document.
    pub class: ProbeClass,
    /// What it observed.
    pub result: ProbeState,
    /// The OS error it saw, when it saw one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub os_error: Option<OsError>,
    /// Why the state is what it is, for `unknown` and `not_probed`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    /// How long the attempt took, when it was attempted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub elapsed_ms: Option<u64>,
}

impl Probe {
    /// The row for `id` from what its attempt produced.
    #[must_use]
    pub fn new(id: ProbeId, result: ProbeResult) -> Self {
        Self {
            id,
            class: id.class(),
            result: result.state,
            os_error: result.os_error,
            note: result.note,
            elapsed_ms: result.elapsed_ms,
        }
    }

    /// The row for a probe that was not attempted.
    #[must_use]
    pub fn not_probed(id: ProbeId, reason: impl Into<String>) -> Self {
        Self::new(id, ProbeResult::not_probed(reason))
    }

    /// The row for a probe the inventory does not attempt on `platform`.
    #[must_use]
    pub fn not_applicable(id: ProbeId, platform: Platform) -> Self {
        Self::not_probed(id, format!("not probed on {platform}"))
    }

    /// The `skipped[].why` text of a row that was absent or not probed.
    fn why(&self) -> String {
        match &self.note {
            Some(note) => format!("{}{WHY_SEPARATOR}{note}", self.result),
            None => self.result.to_string(),
        }
    }
}

/// A must-deny probe that counted neither way, with the reason.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Skipped {
    /// The probe.
    pub id: ProbeId,
    /// `absent`, or `not_probed` followed by the reason.
    pub why: String,
}

/// What the rows prove.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    /// The agent reaches the public endpoint and every must-deny probe was
    /// denied, absent or not probed.
    Established,
    /// The agent reaches the public endpoint and at least one must-deny
    /// probe was allowed or could not be classified.
    NotEstablished,
    /// The public endpoint was not reached (or the base could not be
    /// resolved): there is nothing to report to.
    CannotProbe,
}

impl Verdict {
    /// The wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Established => "established",
            Self::NotEstablished => "not_established",
            Self::CannotProbe => "cannot_probe",
        }
    }
}

impl fmt::Display for Verdict {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// The verdict and the lists that explain it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Judgement {
    /// What the rows prove.
    pub verdict: Verdict,
    /// Must-deny probes that were `allowed`: denial was required.
    pub failed: Vec<ProbeId>,
    /// Must-deny probes that were `unknown`: no evidence either way.
    pub unverified: Vec<ProbeId>,
    /// Must-deny probes that were `absent` or `not_probed`, with the
    /// reason; they count neither way.
    pub skipped: Vec<Skipped>,
}

/// The verdict rule, over the rows in order:
///
/// - `cannot_probe` when `public.reach` is missing or not `allowed` (or any
///   other must-allow probe is not `allowed`);
/// - otherwise `established` when every must-deny probe is `denied`,
///   `absent` or `not_probed`;
/// - otherwise `not_established`, with `failed` the must-deny probes that
///   were `allowed` and `unverified` those that were `unknown`.
///
/// Classes come from the inventory, not from the rows' `class` field;
/// [`DoctorReport::validate`] refuses a row where the two disagree.
/// `info` rows are never counted.
#[must_use]
pub fn judge(probes: &[Probe]) -> Judgement {
    let mut failed = Vec::new();
    let mut unverified = Vec::new();
    let mut skipped = Vec::new();
    let mut reached = false;
    let mut must_allow_missing = false;
    for probe in probes {
        match probe.id.class() {
            ProbeClass::MustAllow => {
                if probe.result == ProbeState::Allowed {
                    reached |= probe.id == ProbeId::PublicReach;
                } else {
                    must_allow_missing = true;
                }
            }
            ProbeClass::MustDeny => match probe.result {
                ProbeState::Allowed => failed.push(probe.id),
                ProbeState::Unknown => unverified.push(probe.id),
                ProbeState::Absent | ProbeState::NotProbed => skipped.push(Skipped {
                    id: probe.id,
                    why: probe.why(),
                }),
                ProbeState::Denied => {}
            },
            ProbeClass::Info => {}
        }
    }
    let verdict = if !reached || must_allow_missing {
        Verdict::CannotProbe
    } else if failed.is_empty() && unverified.is_empty() {
        Verdict::Established
    } else {
        Verdict::NotEstablished
    };
    Judgement {
        verdict,
        failed,
        unverified,
        skipped,
    }
}

/// What the public hello answered.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DaemonFacts {
    /// The daemon's version.
    pub version: String,
    /// The wire protocol it speaks.
    pub proto: u32,
    /// Its boot epoch.
    pub epoch: String,
    /// How the client reached it. Self-reported.
    pub via: Via,
}

/// The build of the frontend this binary carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Frontend {
    /// The frontend assets are embedded in the binary (`gui-embed`).
    Embedded,
    /// A development build serving the frontend from a dev server; not a
    /// trusted surface.
    DevelopmentServer,
}

/// The facts the client already computes about its own position. Every
/// one is self-reported; the daemon shows them beside what it observed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnvFacts {
    /// `PAM_SOCKET_DIR`, when set (the session relay).
    #[serde(default)]
    pub socket_dir: Option<String>,
    /// `PAM_BASE_DIR`, when set.
    #[serde(default)]
    pub base_dir_override: Option<String>,
    /// The base directory the run resolved.
    pub resolved_base: String,
    /// The public endpoint the run dialled.
    pub resolved_endpoint: String,
    /// The client binary's version.
    pub client_version: String,
    /// The client binary's path, when it could be resolved.
    #[serde(default)]
    pub exe: Option<String>,
    /// The repository the working directory is in, when it is in one.
    #[serde(default)]
    pub cwd_repo: Option<String>,
    /// The frontend build of this binary.
    pub frontend: Frontend,
    /// The client's parent-process names, nearest first, as
    /// [`crate::caller::classify_chain`] would read them.
    #[serde(default)]
    pub harness_chain: Vec<String>,
}

/// Whether and how the report reached the daemon. Filled by the client
/// after sending; absent in the document it sends.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReportRecord {
    /// The daemon recorded the report.
    pub recorded: bool,
    /// The request id it was recorded under.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    /// Why it was not recorded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// The report document: what `pam doctor --json` prints and what it sends
/// as `doctor.report` arguments (without `report`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DoctorReport {
    /// [`SCHEMA_VERSION`].
    pub schema_version: u32,
    /// What the rows prove.
    pub verdict: Verdict,
    /// Where the run happened.
    pub platform: Platform,
    /// Unix time of the run, in seconds.
    pub ts: u64,
    /// What the hello answered; `null` when the daemon was not reached.
    #[serde(default)]
    pub daemon: Option<DaemonFacts>,
    /// One row per probe, in inventory order.
    pub probes: Vec<Probe>,
    /// Must-deny probes that were `allowed`.
    pub failed: Vec<ProbeId>,
    /// Must-deny probes that were `unknown`.
    pub unverified: Vec<ProbeId>,
    /// Must-deny probes that counted neither way, with the reason.
    pub skipped: Vec<Skipped>,
    /// The client's own position.
    pub env: EnvFacts,
    /// Whether the daemon recorded the report; `null` until sent.
    #[serde(default)]
    pub report: Option<ReportRecord>,
}

impl DoctorReport {
    /// A report over `probes`, judged by [`judge`].
    #[must_use]
    pub fn new(
        platform: Platform,
        ts: u64,
        daemon: Option<DaemonFacts>,
        probes: Vec<Probe>,
        env: EnvFacts,
    ) -> Self {
        let Judgement {
            verdict,
            failed,
            unverified,
            skipped,
        } = judge(&probes);
        Self {
            schema_version: SCHEMA_VERSION,
            verdict,
            platform,
            ts,
            daemon,
            probes,
            failed,
            unverified,
            skipped,
            env,
            report: None,
        }
    }

    /// The document the client sends as `doctor.report` arguments: this
    /// report without the `report` member, which only the reply can fill.
    #[must_use]
    pub fn as_args(&self) -> Self {
        Self {
            report: None,
            ..self.clone()
        }
    }

    /// Reads and validates `doctor.report` arguments from a public client.
    /// Fails closed: a document over [`MAX_REPORT_BYTES`], with an unknown
    /// member, failing [`validate`](Self::validate), or whose verdict is
    /// `cannot_probe` (it could not have been sent) is refused.
    pub fn from_args(args: &serde_json::Value) -> Result<Self, ReportError> {
        let bytes =
            serde_json::to_vec(args).map_err(|error| ReportError::Json(error.to_string()))?;
        if bytes.len() > MAX_REPORT_BYTES {
            return Err(ReportError::TooLarge { bytes: bytes.len() });
        }
        let report: Self =
            serde_json::from_slice(&bytes).map_err(|error| ReportError::Json(error.to_string()))?;
        report.validate()?;
        if report.verdict == Verdict::CannotProbe {
            return Err(ReportError::NotRecordable(report.verdict));
        }
        Ok(report)
    }

    /// Checks the bounds and the internal consistency of the document:
    /// the schema version, the row count, unique ids, each row's class and
    /// platform against the inventory, every string's length and
    /// characters, and that `verdict`, `failed`, `unverified` and `skipped`
    /// are what [`judge`] computes from `probes`.
    pub fn validate(&self) -> Result<(), ReportError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(ReportError::SchemaVersion(self.schema_version));
        }
        self.validate_probes()?;
        self.validate_lists()?;
        if let Some(daemon) = &self.daemon {
            check_text("daemon.version", &daemon.version, MAX_TEXT_BYTES)?;
            check_text("daemon.epoch", &daemon.epoch, MAX_TEXT_BYTES)?;
        }
        self.env.validate()?;
        if let Some(record) = &self.report {
            check_optional(
                "report.request_id",
                record.request_id.as_deref(),
                MAX_TEXT_BYTES,
            )?;
            check_optional("report.reason", record.reason.as_deref(), MAX_TEXT_BYTES)?;
        }
        Ok(())
    }

    fn validate_probes(&self) -> Result<(), ReportError> {
        if self.probes.len() > MAX_PROBES {
            return Err(ReportError::TooManyProbes(self.probes.len()));
        }
        let mut seen = std::collections::HashSet::new();
        for probe in &self.probes {
            if !seen.insert(probe.id) {
                return Err(ReportError::DuplicateProbe(probe.id));
            }
            if probe.class != probe.id.class() {
                return Err(ReportError::ClassMismatch {
                    id: probe.id,
                    class: probe.class,
                });
            }
            if !probe.id.applies_to(self.platform) && probe.result != ProbeState::NotProbed {
                return Err(ReportError::NotApplicable {
                    id: probe.id,
                    platform: self.platform,
                });
            }
            check_optional("probes[].note", probe.note.as_deref(), MAX_TEXT_BYTES)?;
            if let Some(os_error) = &probe.os_error {
                check_text("probes[].os_error.kind", &os_error.kind, MAX_TEXT_BYTES)?;
                check_optional(
                    "probes[].os_error.detail",
                    os_error.detail.as_deref(),
                    MAX_TEXT_BYTES,
                )?;
            }
        }
        Ok(())
    }

    fn validate_lists(&self) -> Result<(), ReportError> {
        for (field, count) in [
            ("failed", self.failed.len()),
            ("unverified", self.unverified.len()),
            ("skipped", self.skipped.len()),
        ] {
            if count > MAX_PROBES {
                return Err(ReportError::TooManyListed { field, count });
            }
        }
        for skipped in &self.skipped {
            check_text("skipped[].why", &skipped.why, MAX_WHY_BYTES)?;
        }
        let computed = judge(&self.probes);
        if computed.verdict != self.verdict {
            return Err(ReportError::Inconsistent { field: "verdict" });
        }
        if computed.failed != self.failed {
            return Err(ReportError::Inconsistent { field: "failed" });
        }
        if computed.unverified != self.unverified {
            return Err(ReportError::Inconsistent {
                field: "unverified",
            });
        }
        if computed.skipped != self.skipped {
            return Err(ReportError::Inconsistent { field: "skipped" });
        }
        Ok(())
    }
}

impl EnvFacts {
    fn validate(&self) -> Result<(), ReportError> {
        check_optional("env.socket_dir", self.socket_dir.as_deref(), MAX_PATH_BYTES)?;
        check_optional(
            "env.base_dir_override",
            self.base_dir_override.as_deref(),
            MAX_PATH_BYTES,
        )?;
        check_text("env.resolved_base", &self.resolved_base, MAX_PATH_BYTES)?;
        check_text(
            "env.resolved_endpoint",
            &self.resolved_endpoint,
            MAX_PATH_BYTES,
        )?;
        check_text("env.client_version", &self.client_version, MAX_TEXT_BYTES)?;
        check_optional("env.exe", self.exe.as_deref(), MAX_PATH_BYTES)?;
        check_optional("env.cwd_repo", self.cwd_repo.as_deref(), MAX_PATH_BYTES)?;
        if self.harness_chain.len() > MAX_CHAIN_NAMES {
            return Err(ReportError::TooManyChainNames(self.harness_chain.len()));
        }
        for name in &self.harness_chain {
            check_text("env.harness_chain[]", name, MAX_TEXT_BYTES)?;
        }
        Ok(())
    }
}

/// What is wrong with a string field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TextFault {
    /// Longer than the field's bound.
    TooLong {
        /// Its length.
        bytes: usize,
        /// The bound.
        max: usize,
    },
    /// Contains a control character (including a line break or tab).
    ControlCharacter,
}

fn check_text(field: &'static str, text: &str, max: usize) -> Result<(), ReportError> {
    if text.len() > max {
        return Err(ReportError::Text {
            field,
            fault: TextFault::TooLong {
                bytes: text.len(),
                max,
            },
        });
    }
    if text.chars().any(char::is_control) {
        return Err(ReportError::Text {
            field,
            fault: TextFault::ControlCharacter,
        });
    }
    Ok(())
}

fn check_optional(field: &'static str, text: Option<&str>, max: usize) -> Result<(), ReportError> {
    text.map_or(Ok(()), |text| check_text(field, text, max))
}

/// Why a report document was refused. The daemon answers `invalid_args`
/// with the message as its detail; nothing is stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReportError {
    /// Larger than [`MAX_REPORT_BYTES`] when serialized.
    TooLarge {
        /// Its size.
        bytes: usize,
    },
    /// Not the document shape (including an unknown member).
    Json(String),
    /// Not [`SCHEMA_VERSION`].
    SchemaVersion(u32),
    /// More rows than [`MAX_PROBES`].
    TooManyProbes(usize),
    /// A probe appears twice.
    DuplicateProbe(ProbeId),
    /// A row's class is not the inventory's.
    ClassMismatch {
        /// The row.
        id: ProbeId,
        /// The class it claimed.
        class: ProbeClass,
    },
    /// A row carries a result on a platform where the probe is not
    /// attempted.
    NotApplicable {
        /// The row.
        id: ProbeId,
        /// The report's platform.
        platform: Platform,
    },
    /// A string field is over its bound or holds a control character.
    Text {
        /// The field, in document notation.
        field: &'static str,
        /// What is wrong with it.
        fault: TextFault,
    },
    /// A list is longer than [`MAX_PROBES`].
    TooManyListed {
        /// The list.
        field: &'static str,
        /// Its length.
        count: usize,
    },
    /// More harness names than [`MAX_CHAIN_NAMES`].
    TooManyChainNames(usize),
    /// `verdict`, `failed`, `unverified` or `skipped` is not what the rows
    /// compute.
    Inconsistent {
        /// The field that disagrees.
        field: &'static str,
    },
    /// The verdict is one the daemon does not record.
    NotRecordable(Verdict),
}

impl fmt::Display for ReportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLarge { bytes } => write!(
                formatter,
                "report is {bytes} bytes; the limit is {MAX_REPORT_BYTES}"
            ),
            Self::Json(detail) => write!(formatter, "report is not a doctor document: {detail}"),
            Self::SchemaVersion(version) => write!(
                formatter,
                "report schema version {version} is not {SCHEMA_VERSION}"
            ),
            Self::TooManyProbes(count) => write!(
                formatter,
                "report lists {count} probes; the limit is {MAX_PROBES}"
            ),
            Self::DuplicateProbe(id) => write!(formatter, "probe {id} appears more than once"),
            Self::ClassMismatch { id, class } => write!(
                formatter,
                "probe {id} claims class {class}; the inventory says {}",
                id.class()
            ),
            Self::NotApplicable { id, platform } => write!(
                formatter,
                "probe {id} carries a result but is not probed on {platform}"
            ),
            Self::Text {
                field,
                fault: TextFault::TooLong { bytes, max },
            } => write!(formatter, "{field} is {bytes} bytes; the limit is {max}"),
            Self::Text {
                field,
                fault: TextFault::ControlCharacter,
            } => write!(formatter, "{field} contains a control character"),
            Self::TooManyListed { field, count } => write!(
                formatter,
                "{field} lists {count} probes; the limit is {MAX_PROBES}"
            ),
            Self::TooManyChainNames(count) => write!(
                formatter,
                "env.harness_chain lists {count} names; the limit is {MAX_CHAIN_NAMES}"
            ),
            Self::Inconsistent { field } => {
                write!(formatter, "{field} is not what the probe rows compute")
            }
            Self::NotRecordable(verdict) => write!(
                formatter,
                "a {verdict} report cannot have reached the daemon; nothing to record"
            ),
        }
    }
}

impl std::error::Error for ReportError {}
