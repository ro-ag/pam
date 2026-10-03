//! The managed policy service: where the policy comes from, the view every
//! settings consumer reads, and how that view changes.
//!
//! - **The source** ([`PolicySource`]): one verified read of the policy
//!   file, a cheap stat for the poll, and a verified read of a file the
//!   policy names (a CA bundle). Production has exactly one,
//!   [`FileSource::platform`]: the fixed per-platform path under
//!   `TrustRules::production()`. Nothing (no environment variable, flag,
//!   `<base>` file or op) can move it; tests inject a scripted source.
//! - **The handle** ([`PolicyHandle`]): holds the view in force behind a
//!   lock taken for the swap only. [`PolicyHandle::view`] is a cheap
//!   snapshot; an op takes one at entry and uses it for both its check and
//!   its write.
//! - **The state machine**: `none` (no file), `active` (trusted, every leaf
//!   accepted), `degraded` (trusted, a leaf refused), `last_good` (the file
//!   cannot be used; the last good copy is in force), `frozen` (the file
//!   cannot be used and there is no last good copy). A file replaced while
//!   it was being checked (`busy`) keeps the previous view, and the next
//!   poll reads again.
//! - **One fallback chain**, per key: the value in this file, else the value
//!   in the last-known-good copy, else by tier (Tier A held: reads show the
//!   user's value, writes refuse `policy_frozen`; Tier B unmanaged with a
//!   diagnostic). A rejected `network.proxy`, `no_proxy` or `ca_bundle`
//!   with no last-good value closes network consumers
//!   ([`PolicyHandle::network_closed`]) and nothing else.
//! - **The last-known-good copy**: the exact bytes of a trusted file, with
//!   their digest and load time, in the `setting` row
//!   [`pam_store::SETTING_POLICY_LAST_GOOD`]. Re-validated by this binary
//!   when read back, so a copy this build no longer accepts degrades to
//!   `frozen`, never to a crash. A trusted file replaces the copy unless one
//!   of its leaves is in force *from* the copy (then the copy is what keeps
//!   that leaf, and it stays). Deleted when absence is confirmed.
//! - **Absence** after a managed state is confirmed by two observations at
//!   least [`ABSENCE_CONFIRM_AFTER`] apart, the second a poll: an MDM's
//!   delete-then-write window keeps the view in force. A boot has no
//!   history and trusts what it sees.
//! - **The poll** ([`PolicyHandle::spawn_poller`]): a stat every
//!   [`STAT_INTERVAL`], a full verified read when the stat changed, and a
//!   full re-verify every [`REVERIFY_INTERVAL`] regardless (a chmod or an
//!   ACL edit changes no content). Ends on the shutdown watch.
//! - **The managed CA bundle** is imported here, at load: the file the
//!   policy pins passes the same trust check as the policy, its normalized
//!   certificates must hash to the pinned digest, and the private copy is
//!   written under `<base>/net` named by that digest, exactly the copy the
//!   network service already re-hashes on every spawn. A pin that fails
//!   falls back to the last good copy's pin (whose private copy the digest
//!   still proves), else closes network consumers.
//! - **Audit**: every row is `actor = policy`, its detail JSON carries the
//!   full digest and revision and never a leaf value. Rows hang off the
//!   admin op's own request when one caused them, otherwise off a fresh
//!   daemon-owned request ([`CAPABILITY_POLICY_LOAD`],
//!   [`DAEMON_CALLER_AGENT`], ingress `admin`), inserted `running` and
//!   finished `done`. `policy.load` on a new digest in force,
//!   `policy.reject` once per stuck `(verdict, digest, stat)`,
//!   `policy.clear` on confirmed absence.
//! - **Change hooks** ([`PolicyHandle::on_change`]) run once after every
//!   swap that changed the effective policy.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, SystemTime};

use pam_net::normalize_pem;
use pam_store::{Actor, AuditEntry, Decision, RequestOrigin, RequestState, Store, StoreError};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio::time::Instant;

use crate::managed_policy::{
    CODE_VALUE_INVALID, CaBundlePin, Diagnostic, FileFailure, Key, KeyReport, LeafStatus,
    PolicyView, TargetPlatform, WriteRefusal, inspect_bytes,
};
use crate::managed_policy_trust::{
    TrustRules, TrustedBytes, Untrusted, UntrustedReason, policy_path, verify_and_read,
};
use crate::network_service::{
    CaBundleEntry, ManagedNetwork, ManagedNetworkLayer, NET_DIR, sha256_hex,
};

/// How often the poll stats the file.
pub const STAT_INTERVAL: Duration = Duration::from_secs(60);

/// How often the poll re-reads and re-verifies the file whatever its stat
/// says.
pub const REVERIFY_INTERVAL: Duration = Duration::from_mins(10);

/// How far apart the two observations that confirm absence must be.
pub const ABSENCE_CONFIRM_AFTER: Duration = Duration::from_secs(10);

/// The capability of a daemon-owned request row the policy rows hang off.
pub const CAPABILITY_POLICY_LOAD: &str = "policy.load";

/// The caller agent of a daemon-owned request row. Never the GUI's
/// `pam-gui`, so the row cannot be mistaken for a human act.
pub const DAEMON_CALLER_AGENT: &str = "pam-daemon";

/// The repository column of a daemon-owned request row.
pub const DAEMON_REPO: &str = "daemon";

/// Audit action: a verified load put a new digest in force.
pub const ACTION_POLICY_LOAD: &str = "policy.load";

/// Audit action: the file failed or rejected leaves (once per change).
pub const ACTION_POLICY_REJECT: &str = "policy.reject";

/// Audit action: absence was confirmed after a managed state.
pub const ACTION_POLICY_CLEAR: &str = "policy.clear";

/// Audit action: an admin op was refused by the policy.
pub const ACTION_POLICY_LOCKED_WRITE: &str = "policy.locked_write";

/// Audit action: the gate refused a capability for a `never` match.
pub const ACTION_POLICY_DENIED: &str = "policy.denied";

/// The status reason while an absence waits for its confirming poll.
pub const REASON_ABSENT_UNCONFIRMED: &str = "absent_unconfirmed";

/// The format of the last-known-good row's header line.
const LAST_GOOD_FORMAT: u64 = 1;

/// How many hex characters of a digest name a private CA copy (the network
/// service's naming, `<base>/net/ca-<sha12>.pem`).
const COPY_DIGEST_CHARS: usize = 12;

// --- Sources ------------------------------------------------------------

/// What one read of a source found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SourceRead {
    /// No file at the path (the `none` state).
    Absent,
    /// The file passed the trust check; its raw bytes.
    Trusted(Vec<u8>),
    /// The file is there but is not trusted: a file-level failure.
    Untrusted {
        /// A stable trust code (`not_owned_by_root`, `writable_by_user`, ...).
        code: &'static str,
        /// The sentence.
        detail: String,
    },
    /// The file changed while it was checked, or a writer holds it: keep
    /// the previous view, read again next poll.
    Busy {
        /// The sentence.
        detail: String,
    },
}

impl From<Result<TrustedBytes, Untrusted>> for SourceRead {
    fn from(read: Result<TrustedBytes, Untrusted>) -> Self {
        match read {
            Ok(bytes) => Self::Trusted(bytes.into_bytes()),
            Err(error) if error.is_absent() => Self::Absent,
            Err(error) if error.reason.is_transient() => Self::Busy {
                detail: error.to_string(),
            },
            Err(error) => Self::Untrusted {
                code: error.code(),
                detail: error.to_string(),
            },
        }
    }
}

/// What a stat of the file says, compared between polls: a change triggers
/// a full verified read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fingerprint {
    /// Length in bytes.
    pub len: u64,
    /// Modification time, where the platform reports one.
    pub modified: Option<SystemTime>,
    /// Unix: device, inode, mode, owner and change time (a chmod or chown
    /// moves the change time, not the modification time).
    pub identity: Option<(u64, u64, u32, u32, i64, i64)>,
}

impl Fingerprint {
    /// The fingerprint of `metadata` (from `symlink_metadata`).
    #[must_use]
    pub fn of(metadata: &std::fs::Metadata) -> Self {
        #[cfg(unix)]
        let identity = {
            use std::os::unix::fs::MetadataExt as _;
            Some((
                metadata.dev(),
                metadata.ino(),
                metadata.mode(),
                metadata.uid(),
                metadata.ctime(),
                metadata.ctime_nsec(),
            ))
        };
        #[cfg(not(unix))]
        let identity = None;
        Self {
            len: metadata.len(),
            modified: metadata.modified().ok(),
            identity,
        }
    }
}

/// Where the managed policy comes from. Blocking: the handle calls it off
/// the async threads.
pub trait PolicySource: Send + Sync {
    /// The path (or other origin) the status names.
    fn origin(&self) -> String;

    /// One full verified read.
    fn read(&self) -> SourceRead;

    /// A cheap stat; `None` when nothing can be stat'ed there.
    fn fingerprint(&self) -> Option<Fingerprint>;

    /// A verified read of a file the policy names (a CA bundle), under the
    /// same trust rules as the policy and at most `max_bytes`.
    fn read_referenced(&self, path: &Path, max_bytes: u64) -> SourceRead;
}

/// The policy file at a path, read through the trust check.
#[derive(Clone)]
pub struct FileSource {
    path: PathBuf,
    rules: TrustRules,
}

impl std::fmt::Debug for FileSource {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("FileSource")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

impl FileSource {
    /// The production source: the fixed per-platform path under
    /// `TrustRules::production()`.
    #[must_use]
    pub fn platform() -> Self {
        Self {
            path: policy_path(),
            rules: TrustRules::production(),
        }
    }

    /// A file at `path` under `rules`. Test builds only: production has no
    /// way to name another path.
    #[cfg(test)]
    #[cfg_attr(windows, allow(dead_code))]
    #[must_use]
    pub(crate) fn at(path: impl Into<PathBuf>, rules: TrustRules) -> Self {
        Self {
            path: path.into(),
            rules,
        }
    }
}

impl PolicySource for FileSource {
    fn origin(&self) -> String {
        self.path.display().to_string()
    }

    fn read(&self) -> SourceRead {
        verify_and_read(&self.path, &self.rules).into()
    }

    fn fingerprint(&self) -> Option<Fingerprint> {
        std::fs::symlink_metadata(&self.path)
            .ok()
            .map(|metadata| Fingerprint::of(&metadata))
    }

    fn read_referenced(&self, path: &Path, max_bytes: u64) -> SourceRead {
        verify_and_read(path, &self.rules.clone().with_max_bytes(max_bytes)).into()
    }
}

/// The source of [`PolicyHandle::none`]: never a file.
struct NoSource;

impl PolicySource for NoSource {
    fn origin(&self) -> String {
        String::new()
    }

    fn read(&self) -> SourceRead {
        SourceRead::Absent
    }

    fn fingerprint(&self) -> Option<Fingerprint> {
        None
    }

    fn read_referenced(&self, _path: &Path, _max_bytes: u64) -> SourceRead {
        SourceRead::Absent
    }
}

// --- States, triggers, status ---------------------------------------------

/// What the daemon and `status` report about the policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyState {
    /// No file: unmanaged.
    None,
    /// Trusted, every leaf accepted.
    Active,
    /// Trusted, some leaves rejected.
    Degraded,
    /// The file could not be used; the last good policy is in force.
    LastGood,
    /// The file could not be used and there is no last good policy.
    Frozen,
}

impl PolicyState {
    /// The wire word.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Active => "active",
            Self::Degraded => "degraded",
            Self::LastGood => "last_good",
            Self::Frozen => "frozen",
        }
    }
}

/// Why the file was read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Trigger {
    /// The boot read, before the gate and the listeners exist.
    Boot,
    /// The background poll (a changed stat, or the periodic re-verify).
    Poll,
    /// An explicit reload (`admin.policy.reload`, the GUI opening
    /// Settings). With the op's request id, the audit rows hang off that
    /// row; without one, off a daemon-owned row.
    Reload {
        /// The admin envelope's id, when an op caused the reload.
        request_id: Option<String>,
    },
}

impl Trigger {
    /// The audit word: `boot`, `poll` or `reload`.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Boot => "boot",
            Self::Poll => "poll",
            Self::Reload { .. } => "reload",
        }
    }

    fn request_id(&self) -> Option<&str> {
        match self {
            Self::Reload { request_id } => request_id.as_deref(),
            Self::Boot | Self::Poll => None,
        }
    }
}

/// Network consumers are closed (`network_policy_invalid`): a proxy,
/// no-proxy or CA bundle the policy named could not be resolved and there
/// is no last good value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkClosed {
    /// The key that closed them.
    pub key: Key,
    /// A stable code.
    pub code: &'static str,
    /// The sentence.
    pub detail: String,
}

/// The last-known-good copy, as the status names it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LastGoodInfo {
    /// Its full digest.
    pub digest: String,
    /// When it was loaded, unix seconds.
    pub loaded_ts: i64,
}

/// Everything the status, the doctor and `admin.policy.get` say about the
/// policy. [`Self::public_json`] is the public `status.policy` block;
/// [`Self::admin_json`] the admin body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyStatus {
    /// The state.
    pub state: PolicyState,
    /// Why the file is not plainly in force: a trust code, a file-level
    /// code, `busy`, or [`REASON_ABSENT_UNCONFIRMED`].
    pub reason_code: Option<&'static str>,
    /// The sentence for [`Self::reason_code`].
    pub reason_detail: Option<String>,
    /// Where the policy is read from.
    pub origin: String,
    /// The platform the paths were checked for.
    pub platform: TargetPlatform,
    /// The digest of the policy in force (the last good copy's in
    /// `last_good`).
    pub digest: Option<String>,
    /// The digest of the file last read, when it was read at all.
    pub file_digest: Option<String>,
    /// The revision of the policy in force.
    pub revision: Option<String>,
    /// The organization of the policy in force.
    pub organization: Option<String>,
    /// The contact of the policy in force.
    pub contact: Option<String>,
    /// When the policy in force was loaded, unix seconds.
    pub loaded_ts: Option<i64>,
    /// When the file was last read, unix seconds.
    pub checked_ts: Option<i64>,
    /// The last-known-good copy.
    pub last_good: Option<LastGoodInfo>,
    /// The last-known-good copy could not be written to the store.
    pub lkg_persist_failed: bool,
    /// The file is gone, waiting for the confirming poll.
    pub absence_pending: bool,
    /// Network consumers are closed.
    pub network_closed: Option<NetworkClosed>,
    /// How many keys the policy mentions whose value was refused.
    pub rejected_leaves: usize,
    /// The per-key table.
    pub keys: Vec<KeyReport>,
    /// Every finding.
    pub diagnostics: Vec<Diagnostic>,
}

impl PolicyStatus {
    fn unmanaged(origin: String) -> Self {
        Self {
            state: PolicyState::None,
            reason_code: None,
            reason_detail: None,
            origin,
            platform: TargetPlatform::host(),
            digest: None,
            file_digest: None,
            revision: None,
            organization: None,
            contact: None,
            loaded_ts: None,
            checked_ts: None,
            last_good: None,
            lkg_persist_failed: false,
            absence_pending: false,
            network_closed: None,
            rejected_leaves: 0,
            keys: Vec::new(),
            diagnostics: Vec::new(),
        }
    }

    /// The public `status.policy` block: the state, revision and a short
    /// digest, never a value or a reason.
    #[must_use]
    pub fn public_json(&self) -> Value {
        json!({
            "state": self.state.as_str(),
            "revision": self.revision,
            "digest": self.digest.as_deref().and_then(|digest| digest.get(..12)),
            "loaded_ts": self.loaded_ts,
            "managed": self.state != PolicyState::None,
            "rejected_leaves": self.rejected_leaves,
        })
    }

    /// The admin body (`admin.policy.get` adds the trust breakdown and the
    /// compliance block).
    #[must_use]
    pub fn admin_json(&self) -> Value {
        json!({
            "state": self.state.as_str(),
            "reason_code": self.reason_code,
            "reason_detail": self.reason_detail,
            "origin": { "path": self.origin, "platform": self.platform.as_str() },
            "digest": self.digest,
            "file_digest": self.file_digest,
            "revision": self.revision,
            "organization": self.organization,
            "contact": self.contact,
            "loaded_ts": self.loaded_ts,
            "checked_ts": self.checked_ts,
            "last_good": self.last_good.as_ref().map(|good| json!({
                "digest": good.digest,
                "loaded_ts": good.loaded_ts,
            })),
            "lkg_persist_failed": self.lkg_persist_failed,
            "absence_pending": self.absence_pending,
            "network_closed": self.network_closed.as_ref().map(|closed| json!({
                "key": closed.key.path(),
                "code": closed.code,
                "detail": closed.detail,
            })),
            "rejected_leaves": self.rejected_leaves,
            "keys": self.keys,
            "diagnostics": self.diagnostics,
        })
    }
}

// --- The handle -----------------------------------------------------------

/// The managed CA bundle's resolution.
#[derive(Debug, Clone, PartialEq, Eq)]
enum CaState {
    /// The policy does not pin a bundle.
    Unmanaged,
    /// The policy pins this record (`None` pins "no bundle").
    Pinned(Option<CaBundleEntry>),
    /// The pin could not be resolved: network consumers close.
    Closed { code: &'static str, detail: String },
}

/// The CA resolution plus what the status says about it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct CaResolution {
    state: CaState,
    /// Why the policy's own pin failed, when it did.
    problem: Option<(&'static str, String)>,
    /// The pin in force came from the last good copy.
    from_last_good: bool,
}

impl CaResolution {
    const UNMANAGED: Self = Self {
        state: CaState::Unmanaged,
        problem: None,
        from_last_good: false,
    };
}

/// What consumers read; a change of it fires the hooks.
#[derive(Debug, Clone, PartialEq)]
struct Effective {
    view: Arc<PolicyView>,
    ca: CaState,
}

struct Current {
    effective: Effective,
    status: PolicyStatus,
}

/// The last-known-good copy in memory.
#[derive(Debug, Clone)]
struct LastGood {
    digest: String,
    loaded_ts: i64,
    view: Arc<PolicyView>,
}

/// What a `policy.reject` row was last written for.
#[derive(Debug, Clone, PartialEq, Eq)]
struct RejectKey {
    code: &'static str,
    digest: Option<String>,
    fingerprint: Option<Fingerprint>,
}

/// The reload state, behind the reload lock.
#[derive(Debug, Default)]
struct Machine {
    last_good: Option<LastGood>,
    /// The first observation of an absence not yet confirmed.
    absence_since: Option<Instant>,
    last_reject: Option<RejectKey>,
    /// The stat as of the last full read.
    fingerprint: Option<Fingerprint>,
    /// The next poll reads in full whatever the stat says (after `busy`).
    force_full: bool,
    last_full: Option<Instant>,
    state: Option<PolicyState>,
    reason: Option<(&'static str, String)>,
    file_digest: Option<String>,
    loaded_ts: Option<i64>,
    checked_ts: Option<i64>,
    lkg_persist_failed: bool,
    ca: Option<CaResolution>,
}

/// One audit row to write.
struct Row {
    action: &'static str,
    decision: Decision,
    detail: Value,
}

type ChangeHook = dyn Fn(&PolicyView) + Send + Sync;

/// The one policy every settings consumer reads through.
pub struct PolicyHandle {
    source: Arc<dyn PolicySource>,
    store: Option<Arc<Store>>,
    net_dir: Option<PathBuf>,
    current: RwLock<Arc<Current>>,
    machine: tokio::sync::Mutex<Machine>,
    hooks: Mutex<Vec<Arc<ChangeHook>>>,
}

impl std::fmt::Debug for PolicyHandle {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PolicyHandle")
            .field("origin", &self.source.origin())
            .field("state", &self.status().state)
            .finish_non_exhaustive()
    }
}

impl PolicyHandle {
    fn new(
        source: Arc<dyn PolicySource>,
        store: Option<Arc<Store>>,
        net_dir: Option<PathBuf>,
    ) -> Self {
        let status = PolicyStatus::unmanaged(source.origin());
        Self {
            source,
            store,
            net_dir,
            current: RwLock::new(Arc::new(Current {
                effective: Effective {
                    view: Arc::new(PolicyView::unmanaged()),
                    ca: CaState::Unmanaged,
                },
                status,
            })),
            machine: tokio::sync::Mutex::new(Machine::default()),
            hooks: Mutex::new(Vec::new()),
        }
    }

    /// No policy, ever: for tests and consumers that do not care. Reloads
    /// find nothing.
    #[must_use]
    pub fn none() -> Arc<Self> {
        Arc::new(Self::new(Arc::new(NoSource), None, None))
    }

    /// The boot read: the last-known-good copy from `store`, then one
    /// verified read of `source`. Never fails: a store that does not answer
    /// or a file that cannot be used is a state, not an error. Private CA
    /// copies go under `<base>/net`.
    pub async fn load(store: Arc<Store>, source: Arc<dyn PolicySource>, base: &Path) -> Arc<Self> {
        let handle = Arc::new(Self::new(
            source,
            Some(Arc::clone(&store)),
            Some(base.join(NET_DIR)),
        ));
        {
            let mut machine = handle.machine.lock().await;
            machine.last_good = read_last_good(&store).await;
            handle.observe(&mut machine, &Trigger::Boot, true).await;
        }
        handle
    }

    /// The view in force: one snapshot an op uses for its check and its
    /// write.
    #[must_use]
    pub fn view(&self) -> Arc<PolicyView> {
        Arc::clone(&self.current().effective.view)
    }

    /// What the status reports.
    #[must_use]
    pub fn status(&self) -> PolicyStatus {
        self.current().status.clone()
    }

    /// Whether connector calls and downloads must refuse
    /// (`network_policy_invalid`), and why. Consumers ask this, never
    /// `PolicyView::network_closed` alone: the CA bundle's import is
    /// resolved here.
    #[must_use]
    pub fn network_closed(&self) -> Option<NetworkClosed> {
        self.current().status.network_closed.clone()
    }

    /// The network overlay: the fields the policy locks, the managed CA
    /// record included.
    #[must_use]
    pub fn managed_network(&self) -> Option<ManagedNetwork> {
        let current = self.current();
        let mut managed = current.effective.view.managed_network().unwrap_or_default();
        if let CaState::Pinned(entry) = &current.effective.ca {
            managed.ca_bundle = Some(entry.clone());
        }
        (managed != ManagedNetwork::default()).then_some(managed)
    }

    /// Registers a hook run after every swap that changed the effective
    /// policy (the network cache, the gate's live profile, the GUI event).
    /// Hooks run on the reloading task; keep them short.
    pub fn on_change(&self, hook: impl Fn(&PolicyView) + Send + Sync + 'static) {
        self.hooks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(Arc::new(hook));
    }

    /// Reads the file now and answers the status. An explicit reload counts
    /// as an observation of an absence but never confirms one by itself.
    pub async fn reload(&self, trigger: Trigger) -> PolicyStatus {
        let mut machine = self.machine.lock().await;
        self.observe(&mut machine, &trigger, false).await;
        drop(machine);
        self.status()
    }

    /// One poll: a stat, and a full read when the stat changed, when the
    /// periodic re-verify is due, after a `busy` read, or while an absence
    /// waits for its confirmation.
    pub async fn poll_once(&self) {
        let mut machine = self.machine.lock().await;
        let source = Arc::clone(&self.source);
        let fingerprint = blocking(move || source.fingerprint()).await.flatten();
        let reverify_due = machine
            .last_full
            .is_none_or(|at| at.elapsed() >= REVERIFY_INTERVAL);
        let due = machine.force_full
            || machine.absence_since.is_some()
            || reverify_due
            || fingerprint != machine.fingerprint;
        if due {
            self.observe(&mut machine, &Trigger::Poll, false).await;
        }
    }

    /// Spawns the poll: [`Self::poll_once`] every [`STAT_INTERVAL`] until
    /// `shutdown` turns `true` or its sender drops.
    #[must_use]
    pub fn spawn_poller(self: &Arc<Self>, mut shutdown: watch::Receiver<bool>) -> JoinHandle<()> {
        let handle = Arc::clone(self);
        tokio::spawn(async move {
            let mut ticker =
                tokio::time::interval_at(Instant::now() + STAT_INTERVAL, STAT_INTERVAL);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tokio::select! {
                    () = signalled(&mut shutdown) => break,
                    _ = ticker.tick() => handle.poll_once().await,
                }
            }
        })
    }

    fn current(&self) -> Arc<Current> {
        Arc::clone(
            &self
                .current
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        )
    }

    /// One observation of the source, and whatever it changes.
    async fn observe(&self, machine: &mut Machine, trigger: &Trigger, boot: bool) {
        let now = Instant::now();
        machine.checked_ts = Some(crate::retention::now_ts());
        machine.last_full = Some(now);
        let source = Arc::clone(&self.source);
        let (fingerprint, read) = blocking(move || (source.fingerprint(), source.read()))
            .await
            .unwrap_or_else(|| {
                (
                    None,
                    SourceRead::Busy {
                        detail: "the policy read did not finish".to_owned(),
                    },
                )
            });
        let prior = self.current().effective.clone();
        match read {
            SourceRead::Busy { detail } => {
                machine.absence_since = None;
                machine.force_full = true;
                machine.fingerprint = None;
                if boot {
                    let failure = FileFailure {
                        code: UntrustedReason::Busy.code(),
                        detail,
                    };
                    self.file_failed(machine, trigger, &prior, failure, None)
                        .await;
                } else {
                    machine.reason = Some((UntrustedReason::Busy.code(), detail));
                    self.publish(machine, &prior, None);
                }
            }
            SourceRead::Absent => {
                machine.force_full = false;
                machine.fingerprint = fingerprint;
                let managed = prior.view.is_managed() || machine.last_good.is_some();
                if boot || !managed {
                    self.clear(machine, trigger, &prior).await;
                    return;
                }
                match machine.absence_since {
                    Some(first)
                        if *trigger == Trigger::Poll
                            && now.duration_since(first) >= ABSENCE_CONFIRM_AFTER =>
                    {
                        self.clear(machine, trigger, &prior).await;
                    }
                    Some(_) => self.publish(machine, &prior, None),
                    None => {
                        machine.absence_since = Some(now);
                        machine.reason = Some((
                            REASON_ABSENT_UNCONFIRMED,
                            "the policy file is gone; the policy stays in force until the next \
                             check confirms it"
                                .to_owned(),
                        ));
                        self.publish(machine, &prior, None);
                    }
                }
            }
            SourceRead::Untrusted { code, detail } => {
                machine.absence_since = None;
                machine.force_full = false;
                machine.fingerprint = fingerprint;
                let failure = FileFailure { code, detail };
                self.file_failed(machine, trigger, &prior, failure, None)
                    .await;
            }
            SourceRead::Trusted(bytes) => {
                machine.absence_since = None;
                machine.force_full = false;
                machine.fingerprint = fingerprint;
                let inspection = inspect_bytes(&bytes, TargetPlatform::host());
                match inspection.result {
                    Err(failure) => {
                        self.file_failed(
                            machine,
                            trigger,
                            &prior,
                            failure,
                            Some(inspection.digest),
                        )
                        .await;
                    }
                    Ok(view) => {
                        self.trusted(machine, trigger, &prior, view, &bytes, inspection.digest)
                            .await;
                    }
                }
            }
        }
    }

    /// No file: unmanaged, the last good copy deleted, `policy.clear` when
    /// something was managed before.
    async fn clear(&self, machine: &mut Machine, trigger: &Trigger, prior: &Effective) {
        let prior_digest = prior
            .view
            .digest()
            .map(str::to_owned)
            .or_else(|| machine.last_good.as_ref().map(|good| good.digest.clone()));
        let was_managed = prior.view.is_managed() || machine.last_good.is_some();
        machine.absence_since = None;
        machine.last_reject = None;
        machine.reason = None;
        machine.file_digest = None;
        machine.loaded_ts = None;
        machine.state = Some(PolicyState::None);
        machine.ca = Some(CaResolution::UNMANAGED);
        if was_managed {
            self.write_rows(
                trigger,
                vec![Row {
                    action: ACTION_POLICY_CLEAR,
                    decision: Decision::Allow,
                    detail: json!({ "trigger": trigger.as_str(), "prior_digest": prior_digest }),
                }],
            )
            .await;
        }
        if machine.last_good.take().is_some()
            && let Some(store) = &self.store
            && let Err(error) = store.clear_policy_last_good().await
        {
            tracing::warn!(%error, "the policy's last good copy could not be deleted");
        }
        let next = Effective {
            view: Arc::new(PolicyView::unmanaged()),
            ca: CaState::Unmanaged,
        };
        self.publish(machine, prior, Some(next));
    }

    /// The file cannot be used as a whole: the last good copy, else frozen.
    async fn file_failed(
        &self,
        machine: &mut Machine,
        trigger: &Trigger,
        prior: &Effective,
        failure: FileFailure,
        digest: Option<String>,
    ) {
        let (state, view, loaded_ts) = match &machine.last_good {
            Some(good) => (
                PolicyState::LastGood,
                Arc::clone(&good.view),
                Some(good.loaded_ts),
            ),
            None => (
                PolicyState::Frozen,
                Arc::new(PolicyView::frozen(&failure, digest.clone())),
                None,
            ),
        };
        let ca = self.resolve_ca(&view, None, &prior.ca).await;
        let key = RejectKey {
            code: failure.code,
            digest: digest.clone(),
            fingerprint: machine.fingerprint.clone(),
        };
        if machine.last_reject.as_ref() != Some(&key) {
            let row = Row {
                action: ACTION_POLICY_REJECT,
                decision: Decision::Refuse,
                detail: json!({
                    "trigger": trigger.as_str(),
                    "state": state.as_str(),
                    "code": failure.code,
                    "digest": digest,
                    "last_good_digest": machine.last_good.as_ref().map(|good| good.digest.clone()),
                    "rejected": [],
                }),
            };
            self.write_rows(trigger, vec![row]).await;
            machine.last_reject = Some(key);
        }
        machine.state = Some(state);
        machine.reason = Some((failure.code, failure.detail));
        machine.file_digest = digest;
        machine.loaded_ts = loaded_ts;
        let next = Effective {
            view,
            ca: ca.state.clone(),
        };
        machine.ca = Some(ca);
        self.publish(machine, prior, Some(next));
    }

    /// A trusted file that parsed: the fallback chain, the CA import, the
    /// audit rows, the last good copy, the swap.
    async fn trusted(
        &self,
        machine: &mut Machine,
        trigger: &Trigger,
        prior: &Effective,
        parsed: PolicyView,
        bytes: &[u8],
        digest: String,
    ) {
        let last_good_view = machine
            .last_good
            .as_ref()
            .map(|good| Arc::clone(&good.view));
        let view = Arc::new(parsed.with_fallback(last_good_view.as_deref()));
        let ca = self
            .resolve_ca(&view, last_good_view.as_deref(), &prior.ca)
            .await;
        let mut rejected: Vec<Value> = view
            .diagnostics()
            .iter()
            .map(|diagnostic| json!({ "key": diagnostic.key, "code": diagnostic.code }))
            .collect();
        if let Some((code, _)) = &ca.problem {
            rejected.push(json!({ "key": Key::NetworkCaBundle.path(), "code": code }));
        }
        let state = if rejected.is_empty() {
            PolicyState::Active
        } else {
            PolicyState::Degraded
        };
        let mut rows = Vec::new();
        if prior.view.digest() != Some(digest.as_str()) {
            rows.push(Row {
                action: ACTION_POLICY_LOAD,
                decision: Decision::Allow,
                detail: json!({
                    "trigger": trigger.as_str(),
                    "state": state.as_str(),
                    "digest": digest,
                    "revision": view.meta().revision,
                    "prior_digest": prior.view.digest(),
                    "rejected": rejected,
                }),
            });
        }
        if state == PolicyState::Degraded {
            let first_code = view
                .diagnostics()
                .first()
                .map(|diagnostic| diagnostic.code)
                .or(ca.problem.as_ref().map(|(code, _)| *code))
                .unwrap_or(CODE_VALUE_INVALID);
            let key = RejectKey {
                code: first_code,
                digest: Some(digest.clone()),
                fingerprint: machine.fingerprint.clone(),
            };
            if machine.last_reject.as_ref() != Some(&key) {
                rows.push(Row {
                    action: ACTION_POLICY_REJECT,
                    decision: Decision::Refuse,
                    detail: json!({
                        "trigger": trigger.as_str(),
                        "state": state.as_str(),
                        "code": first_code,
                        "digest": digest,
                        "last_good_digest": machine.last_good.as_ref().map(|good| good.digest.clone()),
                        "rejected": rejected,
                    }),
                });
                machine.last_reject = Some(key);
            }
        } else {
            machine.last_reject = None;
        }
        self.write_rows(trigger, rows).await;

        let loaded_ts = if prior.view.digest() == Some(digest.as_str()) {
            machine.loaded_ts.unwrap_or_else(crate::retention::now_ts)
        } else {
            crate::retention::now_ts()
        };
        // The copy is replaced unless a leaf of this file is in force from
        // it: then the copy is what holds that leaf, on this read and on
        // every later one.
        let leans_on_copy = ca.from_last_good
            || Key::ALL
                .iter()
                .any(|key| matches!(view.status(*key), Some(LeafStatus::LastGood { .. })));
        let unchanged = machine
            .last_good
            .as_ref()
            .is_some_and(|good| good.digest == digest);
        if !leans_on_copy && !unchanged {
            machine.lkg_persist_failed = !self.persist_last_good(bytes, &digest, loaded_ts).await;
            machine.last_good = Some(LastGood {
                digest: digest.clone(),
                loaded_ts,
                view: Arc::clone(&view),
            });
        }

        machine.state = Some(state);
        machine.reason = None;
        machine.file_digest = Some(digest);
        machine.loaded_ts = Some(loaded_ts);
        let next = Effective {
            view,
            ca: ca.state.clone(),
        };
        machine.ca = Some(ca);
        self.publish(machine, prior, Some(next));
    }

    /// Writes the last good row; answers whether it landed.
    async fn persist_last_good(&self, bytes: &[u8], digest: &str, loaded_ts: i64) -> bool {
        let Some(store) = &self.store else {
            return true;
        };
        let Ok(text) = std::str::from_utf8(bytes) else {
            tracing::warn!("the trusted policy is not text; its last good copy was not kept");
            return false;
        };
        let header = LastGoodHeader {
            format: LAST_GOOD_FORMAT,
            digest: digest.to_owned(),
            loaded_ts,
        };
        let Ok(header) = serde_json::to_string(&header) else {
            return false;
        };
        match store
            .set_policy_last_good(&format!("{header}\n{text}"))
            .await
        {
            Ok(()) => true,
            Err(error) => {
                tracing::warn!(%error, "the policy's last good copy could not be stored");
                false
            }
        }
    }

    /// Swaps in `next` (or keeps the effective policy when `None`),
    /// refreshes the status and runs the hooks when the effective policy
    /// changed.
    fn publish(&self, machine: &Machine, prior: &Effective, next: Option<Effective>) {
        let effective = next.unwrap_or_else(|| prior.clone());
        let changed = effective != *prior;
        let status = self.build_status(machine, &effective);
        let view = Arc::clone(&effective.view);
        *self
            .current
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) =
            Arc::new(Current { effective, status });
        if changed {
            let hooks: Vec<Arc<ChangeHook>> = self
                .hooks
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone();
            for hook in hooks {
                hook(&view);
            }
        }
    }

    fn build_status(&self, machine: &Machine, effective: &Effective) -> PolicyStatus {
        let view = &effective.view;
        let ca = machine.ca.clone().unwrap_or(CaResolution::UNMANAGED);
        let mut keys = view.key_reports();
        let mut diagnostics = view.diagnostics().to_vec();
        let mut rejected_leaves = view.rejected_leaves();
        if let Some((code, detail)) = &ca.problem {
            diagnostics.push(Diagnostic {
                code,
                key: Key::NetworkCaBundle.path().to_owned(),
                detail: detail.clone(),
            });
            if let Some(row) = keys
                .iter_mut()
                .find(|row| row.key == Key::NetworkCaBundle.path())
            {
                if row.code.is_none() {
                    rejected_leaves += 1;
                }
                row.state = if matches!(ca.state, CaState::Closed { .. }) {
                    "held"
                } else {
                    "applied"
                };
                row.code = Some(code);
                row.detail = Some(detail.clone());
            }
        }
        let network_closed = view
            .network_closed()
            .map(|key| {
                let (code, detail) = match view.status(key) {
                    Some(LeafStatus::Held { code, detail, .. }) => (*code, detail.clone()),
                    _ => (CODE_VALUE_INVALID, String::new()),
                };
                NetworkClosed { key, code, detail }
            })
            .or_else(|| match &effective.ca {
                CaState::Closed { code, detail } => Some(NetworkClosed {
                    key: Key::NetworkCaBundle,
                    code,
                    detail: detail.clone(),
                }),
                CaState::Unmanaged | CaState::Pinned(_) => None,
            });
        let meta = view.meta();
        PolicyStatus {
            state: machine.state.unwrap_or(PolicyState::None),
            reason_code: machine.reason.as_ref().map(|(code, _)| *code),
            reason_detail: machine.reason.as_ref().map(|(_, detail)| detail.clone()),
            origin: self.source.origin(),
            platform: view.platform(),
            digest: view.digest().map(str::to_owned),
            file_digest: machine.file_digest.clone(),
            revision: meta.revision.clone(),
            organization: meta.organization.clone(),
            contact: meta.contact.clone(),
            loaded_ts: machine.loaded_ts,
            checked_ts: machine.checked_ts,
            last_good: machine.last_good.as_ref().map(|good| LastGoodInfo {
                digest: good.digest.clone(),
                loaded_ts: good.loaded_ts,
            }),
            lkg_persist_failed: machine.lkg_persist_failed,
            absence_pending: machine.absence_since.is_some(),
            network_closed,
            rejected_leaves,
            keys,
            diagnostics,
        }
    }

    /// Resolves the CA bundle `view` pins: the policy's own pin through the
    /// trust check and the digest, else the last good copy's pin, else
    /// closed. A record already in force for the same digest is kept as it
    /// is, so a re-verify changes nothing.
    async fn resolve_ca(
        &self,
        view: &PolicyView,
        last_good: Option<&PolicyView>,
        current: &CaState,
    ) -> CaResolution {
        let Some(pin) = locked_ca_pin(view) else {
            return CaResolution::UNMANAGED;
        };
        let CaPin::Bundle(pin) = pin else {
            return CaResolution {
                state: CaState::Pinned(None),
                problem: None,
                from_last_good: false,
            };
        };
        let fallback = last_good
            .and_then(locked_ca_pin)
            .and_then(|old| match old {
                CaPin::Bundle(old) => Some(old),
                CaPin::NoBundle => None,
            })
            .filter(|old| *old != pin);
        let source = Arc::clone(&self.source);
        let net_dir = self.net_dir.clone();
        let imported_ts = crate::retention::now_ts();
        let resolution = blocking(move || {
            let Some(net_dir) = net_dir else {
                return CaResolution {
                    state: CaState::Closed {
                        code: CODE_VALUE_INVALID,
                        detail: "this daemon has no private directory for the CA bundle".to_owned(),
                    },
                    problem: Some((
                        CODE_VALUE_INVALID,
                        "this daemon has no private directory for the CA bundle".to_owned(),
                    )),
                    from_last_good: false,
                };
            };
            resolve_ca_blocking(
                source.as_ref(),
                &net_dir,
                &pin,
                fallback.as_ref(),
                imported_ts,
            )
        })
        .await
        .unwrap_or_else(|| CaResolution {
            state: CaState::Closed {
                code: UntrustedReason::Busy.code(),
                detail: "the CA bundle import did not finish".to_owned(),
            },
            problem: Some((
                UntrustedReason::Busy.code(),
                "the CA bundle import did not finish".to_owned(),
            )),
            from_last_good: false,
        });
        keep_import_time(resolution, current)
    }

    /// Writes `rows` on the trigger's request, or on a fresh daemon-owned
    /// request inserted `running` and finished `done` with the last row.
    async fn write_rows(&self, trigger: &Trigger, rows: Vec<Row>) {
        let Some(store) = &self.store else {
            return;
        };
        if rows.is_empty() {
            return;
        }
        if let Err(error) = write_rows_to(store, trigger.request_id(), rows).await {
            tracing::warn!(%error, "a policy audit row was not recorded");
        }
    }
}

impl ManagedNetworkLayer for PolicyHandle {
    fn current(&self) -> Option<ManagedNetwork> {
        self.managed_network()
    }
}

/// The detail of a `policy.locked_write` row: `{ op, keys, cause, digest,
/// revision }`, never a value.
#[must_use]
pub fn locked_write_detail(op: &str, keys: &[Key], cause: &str, view: &PolicyView) -> Value {
    json!({
        "op": op,
        "keys": keys.iter().map(|key| key.path()).collect::<Vec<_>>(),
        "cause": cause,
        "digest": view.digest(),
        "revision": view.meta().revision,
    })
}

/// Writes the `policy.locked_write` row for an admin op the policy refused,
/// on the op's own request row (the terminal `admin`/`refuse` row is the
/// op's own).
pub async fn audit_locked_write(
    store: &Store,
    request_id: &str,
    op: &str,
    refusal: &WriteRefusal,
    view: &PolicyView,
) -> Result<(), StoreError> {
    let detail = locked_write_detail(op, &[refusal.key], refusal.cause, view).to_string();
    store
        .append_audit(
            request_id,
            ACTION_POLICY_LOCKED_WRITE,
            Decision::Refuse,
            Actor::Policy,
            Some(&detail),
        )
        .await
}

/// The detail of a `policy.denied` row: `{ capability, rule, digest }`.
#[must_use]
pub fn denied_detail(capability: &str, rule: &str, view: &PolicyView) -> Value {
    json!({ "capability": capability, "rule": rule, "digest": view.digest() })
}

// --- Helpers ----------------------------------------------------------------

/// Resolves when the shutdown flag turns `true` (a dropped sender counts
/// as shutdown).
async fn signalled(shutdown: &mut watch::Receiver<bool>) {
    let _ = shutdown.wait_for(|stop| *stop).await;
}

/// Runs `call` on the blocking pool; `None` when it panicked.
async fn blocking<T: Send + 'static>(call: impl FnOnce() -> T + Send + 'static) -> Option<T> {
    tokio::task::spawn_blocking(call).await.ok()
}

async fn write_rows_to(
    store: &Store,
    request_id: Option<&str>,
    rows: Vec<Row>,
) -> Result<(), StoreError> {
    let owned;
    let id = if let Some(id) = request_id {
        id
    } else {
        owned = format!("req_{}", ulid::Ulid::new());
        store
            .insert_running_request_from(
                &owned,
                CAPABILITY_POLICY_LOAD,
                DAEMON_REPO,
                DAEMON_CALLER_AGENT,
                "{}",
                None,
                &RequestOrigin::ADMIN,
            )
            .await?;
        &owned
    };
    let mut rows = rows.into_iter().peekable();
    while let Some(row) = rows.next() {
        let detail = row.detail.to_string();
        if request_id.is_none() && rows.peek().is_none() {
            store
                .finish_request(
                    id,
                    RequestState::Done,
                    None,
                    AuditEntry {
                        action: row.action,
                        decision: row.decision,
                        actor: Actor::Policy,
                        detail: Some(&detail),
                    },
                )
                .await?;
        } else {
            store
                .append_audit(id, row.action, row.decision, Actor::Policy, Some(&detail))
                .await?;
        }
    }
    Ok(())
}

/// The header line of the last good row.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LastGoodHeader {
    format: u64,
    digest: String,
    loaded_ts: i64,
}

/// Reads the last good row back and re-validates it with this binary. A
/// row that does not hash to its digest, or that this build no longer
/// parses, is no last good copy.
async fn read_last_good(store: &Store) -> Option<LastGood> {
    let raw = match store.policy_last_good().await {
        Ok(raw) => raw?,
        Err(error) => {
            tracing::warn!(%error, "the policy's last good copy could not be read");
            return None;
        }
    };
    let parsed = parse_last_good(&raw);
    if parsed.is_none() {
        tracing::warn!("the policy's last good copy is not usable by this build; ignored");
    }
    parsed
}

fn parse_last_good(raw: &str) -> Option<LastGood> {
    let (header, text) = raw.split_once('\n')?;
    let header: LastGoodHeader = serde_json::from_str(header).ok()?;
    if header.format != LAST_GOOD_FORMAT || sha256_hex(text.as_bytes()) != header.digest {
        return None;
    }
    let view = inspect_bytes(text.as_bytes(), TargetPlatform::host())
        .result
        .ok()?
        .with_fallback(None);
    Some(LastGood {
        digest: header.digest,
        loaded_ts: header.loaded_ts,
        view: Arc::new(view),
    })
}

/// The CA pin a view has in force: `Some(None)` pins "no bundle".
fn locked_ca_pin(view: &PolicyView) -> Option<CaPin> {
    if !view
        .status(Key::NetworkCaBundle)
        .is_some_and(LeafStatus::in_force)
    {
        return None;
    }
    let locked = view.policy().ca_bundle.as_ref()?.locked.as_ref()?;
    Some(locked.clone().map_or(CaPin::NoBundle, CaPin::Bundle))
}

/// What a locked `network.ca_bundle` pins.
enum CaPin {
    /// This file, by digest.
    Bundle(CaBundlePin),
    /// No bundle: the platform's trust.
    NoBundle,
}

fn resolve_ca_blocking(
    source: &dyn PolicySource,
    net_dir: &Path,
    pin: &CaBundlePin,
    fallback: Option<&CaBundlePin>,
    imported_ts: i64,
) -> CaResolution {
    let problem = match import_pinned_ca(source, net_dir, pin, imported_ts) {
        Ok(entry) => {
            return CaResolution {
                state: CaState::Pinned(Some(entry)),
                problem: None,
                from_last_good: false,
            };
        }
        Err(problem) => problem,
    };
    if let Some(old) = fallback
        && let Ok(entry) = import_pinned_ca(source, net_dir, old, imported_ts)
    {
        return CaResolution {
            state: CaState::Pinned(Some(entry)),
            problem: Some(problem),
            from_last_good: true,
        };
    }
    CaResolution {
        state: CaState::Closed {
            code: problem.0,
            detail: problem.1.clone(),
        },
        problem: Some(problem),
        from_last_good: false,
    }
}

/// Imports the bundle `pin` names: the file through the trust check, its
/// normalized certificates against the pinned digest, the private copy
/// under `net_dir`. A file being replaced (`busy`) falls back to a private
/// copy that still hashes to the pin: its content is what the trusted
/// policy pinned.
fn import_pinned_ca(
    source: &dyn PolicySource,
    net_dir: &Path,
    pin: &CaBundlePin,
    imported_ts: i64,
) -> Result<CaBundleEntry, (&'static str, String)> {
    let prefix: String = pin.sha256.chars().take(COPY_DIGEST_CHARS).collect();
    let copy = net_dir.join(format!("ca-{prefix}.pem"));
    let entry = |certificates: usize| CaBundleEntry {
        sha256: pin.sha256.clone(),
        certificates,
        source_path: Some(pin.path.clone()),
        imported_ts: Some(imported_ts),
    };
    let bytes = match source.read_referenced(Path::new(&pin.path), pam_net::ca::MAX_BUNDLE_BYTES) {
        SourceRead::Trusted(bytes) => bytes,
        SourceRead::Busy { detail } => {
            return existing_copy(&copy, &pin.sha256)
                .map(entry)
                .ok_or((UntrustedReason::Busy.code(), detail));
        }
        SourceRead::Absent => {
            return Err((
                UntrustedReason::Unreadable.code(),
                format!("the CA bundle {} the policy pins does not exist", pin.path),
            ));
        }
        SourceRead::Untrusted { code, detail } => {
            return Err((
                code,
                format!("the CA bundle the policy pins is not trusted: {detail}"),
            ));
        }
    };
    let normalized = normalize_pem(&bytes).map_err(|error| {
        (
            CODE_VALUE_INVALID,
            format!(
                "the CA bundle {} is not a certificate bundle: {error}",
                pin.path
            ),
        )
    })?;
    let sha256 = sha256_hex(normalized.pem.as_bytes());
    if sha256 != pin.sha256 {
        return Err((
            CODE_VALUE_INVALID,
            format!(
                "the CA bundle {} normalizes to sha256 {sha256}, not the {} the policy pins",
                pin.path, pin.sha256
            ),
        ));
    }
    if existing_copy(&copy, &pin.sha256).is_none() {
        create_private_dir(net_dir)
            .and_then(|()| write_private_file(&copy, normalized.pem.as_bytes()))
            .map_err(|error| {
                (
                    CODE_VALUE_INVALID,
                    format!(
                        "the CA bundle's private copy {} could not be written: {error}",
                        copy.display()
                    ),
                )
            })?;
    }
    Ok(entry(normalized.certificates))
}

/// The certificate count of a private copy that hashes to `sha256`.
fn existing_copy(copy: &Path, sha256: &str) -> Option<usize> {
    let bytes = std::fs::read(copy).ok()?;
    if sha256_hex(&bytes) != sha256 {
        return None;
    }
    normalize_pem(&bytes).ok().map(|bundle| bundle.certificates)
}

/// Keeps the record already in force when the new one names the same
/// copy, so a re-verify of an unchanged pin is no change.
fn keep_import_time(mut resolution: CaResolution, current: &CaState) -> CaResolution {
    if let (CaState::Pinned(Some(new)), CaState::Pinned(Some(old))) = (&resolution.state, current)
        && new.sha256 == old.sha256
        && new.source_path == old.source_path
    {
        resolution.state = CaState::Pinned(Some(old.clone()));
    }
    resolution
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

/// Writes `bytes` to `path` atomically, owner-only on Unix.
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
