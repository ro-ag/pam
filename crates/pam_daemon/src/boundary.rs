//! The daemon's side of the boundary self-check: the `doctor.report`
//! capability, the peer facts the daemon resolves itself, what it observes on
//! the private admin listener, and the `boundary` block of `status`.
//!
//! What the client sends (`pam doctor`'s document) is a claim; it is stored
//! under the kernel's peer facts the daemon recorded at accept and the
//! resolution the daemon made from them: the executable behind `peer_pid`
//! and the classification of its ancestry ([`pam_proto::caller`]). What the
//! daemon vouches for is only what it saw on its own: that a request with
//! those peer facts arrived, the admin contacts it accepted, and whether a
//! contact was followed by a report from the same pid (attribution by kernel
//! pid within [`ATTRIBUTION_WINDOW`], never by the client's document). None
//! of it changes any authority: the gate, grants and approvals never read it.
//!
//! The record lives in the store ([`pam_store::Store::insert_boundary_report`]
//! and the observation tables, bounded there); the `status` block is served
//! from a census kept in memory and reloaded after every write, so a poll
//! reads no row.
//!
//! Peer resolution is bounded: it runs on the blocking pool under
//! [`RESOLVE_BUDGET`] and a miss records nothing (null). On Windows the
//! public plane has no kernel peer, so there is nothing to resolve and every
//! peer fact is null; the block says so (`peer_identity: "none"`).
//!
//! The private listener's adapters are bound by code this module does not
//! own, so the observation sink is reached through a registry keyed by the
//! daemon's base directory ([`register_admin_sink`], [`admin_sink_for`]):
//! the daemon registers its sink before it binds the admin listener, and the
//! adapter looks the sink up by the base it was given.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::{Arc, Mutex, OnceLock, RwLock};
use std::task::{Context, Poll};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use pam_proto::Outcome;
use pam_proto::caller::{
    MAX_CHAIN_DEPTH, RELAY_HARNESS, UNKNOWN_AGENT, canonical_agent, classify_chain,
};
use pam_proto::doctor::DoctorReport;
use pam_store::{
    Actor, AuditEntry, BoundaryCensus, BoundaryObservationInsert, BoundaryObservationRow,
    BoundaryPeer, BoundaryReportInsert, Decision, MAX_BOUNDARY_REPORT_BYTES,
    OBSERVATION_ADMIN_CONTACT, OBSERVATION_ADMIN_HANDSHAKE_FAILED,
    OBSERVATION_PUBLIC_UNKNOWN_HARNESS, RequestOrigin, Store,
};
use serde_json::{Value, json};
use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, System, UpdateKind};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;

use crate::executor::{CapabilityFailure, CapabilityOutput, ExecContext};
use crate::framed::Accept;
use crate::ingress::PeerIdentity;

/// Wire name of the report capability.
pub const CAP_DOCTOR_REPORT: &str = "doctor.report";

/// The audit action of an accepted report (one non-terminal row per
/// report, beside the pipeline's terminal `execute` row).
pub const ACTION_DOCTOR_REPORT: &str = "doctor.report";

/// Refusal cause for a document that does not validate.
pub const CAUSE_INVALID_REPORT: &str = "invalid_args";

/// Refusal cause when the daemon has no boundary observer attached (a
/// harness that built an executor without one).
pub const CAUSE_BOUNDARY_UNAVAILABLE: &str = "boundary_unavailable";

/// Recovery line for [`CAUSE_INVALID_REPORT`].
pub const RECOVERY_INVALID_REPORT: &str = "Run pam doctor again from the agent's position and \
     send the document it produced unchanged.";

/// An admin contact and a `doctor.report` from the same kernel pid this
/// close together explain each other.
pub const ATTRIBUTION_WINDOW: Duration = Duration::from_secs(60);

/// Bound on resolving one peer (executable and ancestry) on the blocking
/// pool; over it the request goes on with null facts.
pub const RESOLVE_BUDGET: Duration = Duration::from_millis(300);

/// Unexpected contacts from one kernel pid closer than this write one row
/// (the counter still moves). The doctor's two admin probes are one row.
pub const CONTACT_DEDUP_WINDOW: Duration = Duration::from_secs(5);

/// Expected contacts (the trusted image's own) from one kernel pid closer
/// than this write one row: a polling GUI is one row an hour.
pub const EXPECTED_CONTACT_DEDUP_WINDOW: Duration = Duration::from_secs(3600);

/// What the public plane knows about a peer on this platform: the kernel's
/// uid and pid at accept (unix), or nothing (Windows, where the peer proved
/// possession of the owner nonce and no process identity exists).
pub const PEER_IDENTITY: &str = if cfg!(unix) { "kernel_pid" } else { "none" };

/// Dedup entries older than this are forgotten.
const RECENT_TTL: Duration = Duration::from_secs(3600);

/// Bound on the in-memory dedup maps.
const RECENT_CAP: usize = 1024;

/// The executable and ancestry behind a kernel pid, as a resolver saw it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ResolvedPeer {
    /// The peer process's executable path.
    pub exe: Option<PathBuf>,
    /// The names of its ancestors, nearest first, excluding the peer
    /// itself; at most [`MAX_CHAIN_DEPTH`].
    pub chain: Vec<String>,
}

/// Resolves a kernel pid into its executable and ancestry. The production
/// resolver is [`SystemResolver`]; tests inject a table.
pub trait PeerResolver: Send + Sync + 'static {
    /// Everything known about `pid`; an unknown pid yields the default.
    /// Blocking: called on the blocking pool.
    fn resolve(&self, pid: u32) -> ResolvedPeer;
}

/// The process-table resolver: the same bounded, cycle-safe walk the client
/// makes over its own ancestry, done by the daemon over the peer's.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemResolver;

impl PeerResolver for SystemResolver {
    fn resolve(&self, pid: u32) -> ResolvedPeer {
        let mut system = System::new();
        let mut seen = HashSet::new();
        let mut resolved = ResolvedPeer::default();
        let mut current = Pid::from_u32(pid);
        for depth in 0..=MAX_CHAIN_DEPTH {
            if !seen.insert(current) {
                break;
            }
            let exe = if depth == 0 {
                UpdateKind::Always
            } else {
                UpdateKind::Never
            };
            system.refresh_processes_specifics(
                ProcessesToUpdate::Some(&[current]),
                false,
                ProcessRefreshKind::nothing().with_exe(exe),
            );
            let Some(process) = system.process(current) else {
                break;
            };
            if depth == 0 {
                resolved.exe = process.exe().map(Path::to_path_buf);
            } else {
                resolved
                    .chain
                    .push(process.name().to_string_lossy().into_owned());
            }
            let Some(parent) = process.parent() else {
                break;
            };
            current = parent;
        }
        resolved
    }
}

/// The daemon's resolution of a public request's peer, as the request row
/// and the report record it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PeerFacts {
    /// The executable path behind the kernel pid.
    pub exe: Option<String>,
    /// `relay` through `pam listen`; otherwise the nearest known agent in
    /// the ancestry, or the nearest ancestor's name verbatim.
    pub harness: Option<String>,
}

impl PeerFacts {
    /// Classifies a resolution. `relayed` is the hello's own statement
    /// (self-reported; the kernel peer is then the relay process).
    #[must_use]
    pub fn classify(resolved: &ResolvedPeer, relayed: bool) -> Self {
        let exe = resolved
            .exe
            .as_ref()
            .map(|exe| exe.to_string_lossy().into_owned());
        let harness = if relayed {
            Some(RELAY_HARNESS.to_owned())
        } else if resolved.chain.is_empty() {
            None
        } else {
            Some(classify_chain(&resolved.chain))
        };
        Self { exe, harness }
    }

    /// Nothing was resolved.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.exe.is_none() && self.harness.is_none()
    }
}

/// One connection the private admin listener saw.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdminContact {
    /// Accepted (unix: the kernel's peer). `spoke` says the peer sent at
    /// least one byte before the connection ended; the doctor's probe
    /// sends none.
    Accepted {
        /// The kernel's view of the peer.
        peer: PeerIdentity,
        /// Whether the peer sent anything.
        spoke: bool,
    },
    /// A loopback connection failed the owner-nonce handshake (Windows);
    /// no process identity exists for it.
    HandshakeFailed,
    /// A connection was accepted and gone before the kernel could say who
    /// it was (unix: the peer closed before `getpeereid`): a contact with
    /// no pid, so nothing can attribute it. A doctor probe that holds its
    /// socket for a moment is seen with its pid instead.
    Vanished,
}

/// Where an adapter sends what it saw. Cheap to clone; sending never
/// blocks or fails loudly (a daemon that has stopped observing drops it).
#[derive(Debug, Clone)]
pub struct AdminContactSink(mpsc::UnboundedSender<AdminContact>);

impl AdminContactSink {
    /// Hands one contact to the observer.
    pub fn record(&self, contact: AdminContact) {
        let _ = self.0.send(contact);
    }
}

type Registry = Mutex<Vec<(PathBuf, AdminContactSink)>>;

fn registry() -> &'static Registry {
    static REGISTRY: OnceLock<Registry> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(Vec::new()))
}

fn registry_key(base: &Path) -> PathBuf {
    base.canonicalize().unwrap_or_else(|_| base.to_path_buf())
}

/// Registers the sink the admin adapters bound under `base` report to; a
/// later registration for the same base replaces the earlier one.
pub fn register_admin_sink(base: &Path, sink: AdminContactSink) {
    let key = registry_key(base);
    let mut entries = registry()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    entries.retain(|(registered, _)| *registered != key);
    entries.push((key, sink));
}

/// The sink registered for `base`, if a daemon observes it.
#[must_use]
pub fn admin_sink_for(base: &Path) -> Option<AdminContactSink> {
    let key = registry_key(base);
    registry()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .iter()
        .find(|(registered, _)| *registered == key)
        .map(|(_, sink)| sink.clone())
}

/// An acceptor whose connections report themselves to a sink when they
/// end: the kernel peer and whether it ever sent a byte.
pub struct Observed<A> {
    inner: A,
    sink: Option<AdminContactSink>,
}

impl<A: Accept> Observed<A> {
    /// Wraps `inner`; with no sink the connections are passed through
    /// unobserved.
    pub fn new(inner: A, sink: Option<AdminContactSink>) -> Self {
        Self { inner, sink }
    }
}

impl<A: Accept> Accept for Observed<A> {
    type Stream = ObservedStream<A::Stream>;

    async fn accept(&mut self) -> std::io::Result<(Self::Stream, PeerIdentity)> {
        let (stream, peer) = match self.inner.accept().await {
            Ok(accepted) => accepted,
            Err(error) => {
                // The acceptor reports a peer whose credentials could not be
                // read as aborted: it connected and went away. That is a
                // contact, even with nobody to pin it on.
                if error.kind() == std::io::ErrorKind::ConnectionAborted
                    && let Some(sink) = &self.sink
                {
                    sink.record(AdminContact::Vanished);
                }
                return Err(error);
            }
        };
        Ok((
            ObservedStream {
                inner: Some(stream),
                peer,
                spoke: false,
                report: true,
                sink: self.sink.clone(),
            },
            peer,
        ))
    }

    fn reject(mut stream: Self::Stream, frame: &[u8]) -> impl Future<Output = ()> + Send {
        // Refused over the connection cap, which the listener logs: not a
        // contact anyone explains.
        stream.report = false;
        let inner = stream.inner.take();
        async move {
            if let Some(inner) = inner {
                A::reject(inner, frame).await;
            }
        }
    }

    fn close(&mut self) {
        self.inner.close();
    }
}

/// One observed connection; records itself when dropped.
pub struct ObservedStream<S> {
    inner: Option<S>,
    peer: PeerIdentity,
    spoke: bool,
    report: bool,
    sink: Option<AdminContactSink>,
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for ObservedStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let Some(inner) = this.inner.as_mut() else {
            return Poll::Ready(Ok(()));
        };
        let before = buf.filled().len();
        let polled = Pin::new(inner).poll_read(cx, buf);
        if buf.filled().len() > before {
            this.spoke = true;
        }
        polled
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for ObservedStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match self.get_mut().inner.as_mut() {
            Some(inner) => Pin::new(inner).poll_write(cx, data),
            None => Poll::Ready(Err(std::io::ErrorKind::NotConnected.into())),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut().inner.as_mut() {
            Some(inner) => Pin::new(inner).poll_flush(cx),
            None => Poll::Ready(Ok(())),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut().inner.as_mut() {
            Some(inner) => Pin::new(inner).poll_shutdown(cx),
            None => Poll::Ready(Ok(())),
        }
    }
}

impl<S> Drop for ObservedStream<S> {
    fn drop(&mut self) {
        if self.report
            && let Some(sink) = &self.sink
        {
            sink.record(AdminContact::Accepted {
                peer: self.peer,
                spoke: self.spoke,
            });
        }
    }
}

/// In-memory dedup and attribution state.
#[derive(Default)]
struct Recent {
    /// `(pid, expected)` → when a row was last written for it.
    contacts: HashMap<(u32, bool), Instant>,
    /// `pid` → the `doctor.report` request it sent and when.
    reports: HashMap<u32, (String, Instant)>,
    /// `pid` → when an unknown-harness row was last written for it.
    unknown: HashMap<u32, Instant>,
}

impl Recent {
    fn forget_old(&mut self) {
        let stale = |at: &Instant| at.elapsed() > RECENT_TTL;
        if self.contacts.len() > RECENT_CAP {
            self.contacts.retain(|_, at| !stale(at));
        }
        if self.reports.len() > RECENT_CAP {
            self.reports.retain(|_, (_, at)| !stale(at));
        }
        if self.unknown.len() > RECENT_CAP {
            self.unknown.retain(|_, at| !stale(at));
        }
    }
}

/// The observer: one per daemon, shared by the pipeline (peer facts on
/// every public request), the executor (`doctor.report`), the admin
/// adapters (contacts) and `status` (the block).
pub struct Boundary {
    store: Arc<Store>,
    resolver: Arc<dyn PeerResolver>,
    /// The daemon's own executable image path; a contact from it is the GUI.
    image: Option<PathBuf>,
    /// [`Self::image`] with symlinks resolved, for the comparison: the
    /// process table reports real paths, the boot image whatever the
    /// daemon was started as.
    image_canonical: Option<PathBuf>,
    census: RwLock<Option<BoundaryCensus>>,
    recent: Mutex<Recent>,
}

impl std::fmt::Debug for Boundary {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Boundary")
            .field("image", &self.image)
            .finish_non_exhaustive()
    }
}

fn now_ts() -> i64 {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs());
    i64::try_from(secs).unwrap_or(i64::MAX)
}

fn window_secs(window: Duration) -> i64 {
    i64::try_from(window.as_secs()).unwrap_or(i64::MAX)
}

impl Boundary {
    /// An observer over `store`, resolving peers with `resolver`; `image`
    /// is the daemon's boot image path (the GUI is the same binary).
    /// Nothing is read until [`Self::load`].
    #[must_use]
    pub fn new(
        store: Arc<Store>,
        image: Option<PathBuf>,
        resolver: Arc<dyn PeerResolver>,
    ) -> Arc<Self> {
        let image_canonical = image
            .as_deref()
            .map(|image| image.canonicalize().unwrap_or_else(|_| image.to_path_buf()));
        Arc::new(Self {
            store,
            resolver,
            image,
            image_canonical,
            census: RwLock::new(None),
            recent: Mutex::new(Recent::default()),
        })
    }

    /// The trusted image path this observer compares contacts against.
    #[must_use]
    pub fn image(&self) -> Option<&Path> {
        self.image.as_deref()
    }

    /// Reads the census from the store into memory. A store that cannot
    /// answer leaves the previous census (none at boot: "never checked").
    pub async fn load(&self) {
        match self.store.boundary_census().await {
            Ok(census) => {
                *self
                    .census
                    .write()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(census);
            }
            Err(error) => {
                tracing::warn!(%error, "the boundary census could not be read");
            }
        }
    }

    fn census(&self) -> Option<BoundaryCensus> {
        self.census
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Resolves the peer of a public request within [`RESOLVE_BUDGET`]: a
    /// kernel pid on the blocking pool, nothing without one. A miss is
    /// empty facts, never an error.
    pub async fn resolve(&self, pid: Option<u32>, relayed: bool) -> PeerFacts {
        let Some(pid) = pid else {
            return PeerFacts::default();
        };
        let table = Arc::clone(&self.resolver);
        let outcome = tokio::time::timeout(
            RESOLVE_BUDGET,
            tokio::task::spawn_blocking(move || table.resolve(pid)),
        )
        .await;
        if let Ok(Ok(found)) = outcome {
            return PeerFacts::classify(&found, relayed);
        }
        tracing::debug!(pid, "peer resolution missed its budget");
        if relayed {
            PeerFacts {
                exe: None,
                harness: Some(RELAY_HARNESS.to_owned()),
            }
        } else {
            PeerFacts::default()
        }
    }

    /// Whether `facts` name a harness that is neither a known agent, nor the
    /// relay, nor the daemon's own image (the CLI run by the human from the
    /// installed binary): what `public_unknown_harness` counts.
    #[must_use]
    pub fn is_unknown_harness(&self, facts: &PeerFacts) -> bool {
        let Some(harness) = facts.harness.as_deref() else {
            return false;
        };
        if harness == RELAY_HARNESS || canonical_agent(harness).is_some() {
            return false;
        }
        !self.is_image(facts.exe.as_deref())
    }

    /// Whether `exe` names the daemon's own image, symlinks resolved on
    /// both sides (the process table reports real paths).
    fn is_image(&self, exe: Option<&str>) -> bool {
        match (self.image_canonical.as_deref(), exe) {
            (Some(image), Some(exe)) => {
                let exe = Path::new(exe);
                exe == image || exe.canonicalize().is_ok_and(|real| real == image)
            }
            _ => false,
        }
    }

    /// Writes the daemon's resolution on the request row and counts an
    /// unknown harness. Bookkeeping: failures are logged, never answered.
    pub async fn note_public_request(
        &self,
        request_id: &str,
        origin: &RequestOrigin,
        facts: &PeerFacts,
    ) {
        if facts.is_empty() {
            return;
        }
        if let Err(error) = self
            .store
            .set_request_peer_facts(request_id, facts.exe.as_deref(), facts.harness.as_deref())
            .await
        {
            tracing::debug!(%error, request = request_id, "peer facts not recorded");
        }
        if !self.is_unknown_harness(facts) {
            return;
        }
        let pid = origin.peer_pid.unwrap_or(0);
        let deduped = {
            let mut recent = self
                .recent
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            recent.forget_old();
            match recent.unknown.get(&pid) {
                Some(at) if at.elapsed() < CONTACT_DEDUP_WINDOW => true,
                _ => {
                    recent.unknown.insert(pid, Instant::now());
                    false
                }
            }
        };
        let peer = BoundaryPeer {
            uid: origin.peer_uid,
            pid: origin.peer_pid,
            exe: facts.exe.clone(),
            harness: facts.harness.clone(),
        };
        let written = if deduped {
            self.store
                .count_boundary_observation(OBSERVATION_PUBLIC_UNKNOWN_HARNESS, false)
                .await
                .map(|()| None)
        } else {
            self.store
                .insert_boundary_observation(BoundaryObservationInsert {
                    kind: OBSERVATION_PUBLIC_UNKNOWN_HARNESS,
                    expected: false,
                    peer: &peer,
                    detail: Some(request_id),
                    attributed: None,
                })
                .await
                .map(Some)
        };
        match written {
            Ok(_) => self.load().await,
            Err(error) => tracing::debug!(%error, "unknown-harness observation not recorded"),
        }
    }

    /// Starts the task that records admin contacts until `shutdown` moves
    /// or its sender drops. The sink is what the adapters report to.
    pub fn spawn_admin_observer(
        self: &Arc<Self>,
        mut shutdown: watch::Receiver<bool>,
    ) -> (AdminContactSink, JoinHandle<()>) {
        let (sender, mut receiver) = mpsc::unbounded_channel();
        let observer = Arc::clone(self);
        let task = tokio::spawn(async move {
            loop {
                tokio::select! {
                    contact = receiver.recv() => match contact {
                        Some(contact) => observer.observe_admin_contact(contact).await,
                        None => return,
                    },
                    _ = shutdown.changed() => return,
                }
            }
        });
        (AdminContactSink(sender), task)
    }

    /// Records one admin contact: resolves the peer, decides whether it is
    /// the trusted image's own (expected), deduplicates per pid, writes the
    /// row or moves the counter, and attributes it to a recent report from
    /// the same pid.
    pub async fn observe_admin_contact(&self, contact: AdminContact) {
        let (kind, peer, spoke) = match contact {
            AdminContact::Accepted { peer, spoke } => {
                (OBSERVATION_ADMIN_CONTACT, Some(peer), spoke)
            }
            AdminContact::HandshakeFailed => (OBSERVATION_ADMIN_HANDSHAKE_FAILED, None, false),
            AdminContact::Vanished => (OBSERVATION_ADMIN_CONTACT, None, false),
        };
        let pid = peer.and_then(|peer| peer.pid());
        let facts = self.resolve(pid, false).await;
        let expected = spoke && self.is_image(facts.exe.as_deref());
        let detail = match (kind, spoke, expected) {
            (OBSERVATION_ADMIN_HANDSHAKE_FAILED, ..) => "failed the owner-nonce handshake",
            (_, false, _) if peer.is_none() => {
                "accepted; gone before its credentials could be read"
            }
            (_, false, _) => "accepted; the peer sent nothing",
            (_, true, true) => "hello from the daemon's own image",
            (_, true, false) => "hello from another executable",
        };
        let window = if expected {
            EXPECTED_CONTACT_DEDUP_WINDOW
        } else {
            CONTACT_DEDUP_WINDOW
        };
        let key = (pid.unwrap_or(u32::MAX), expected);
        let (deduped, attributed) = {
            let mut recent = self
                .recent
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            recent.forget_old();
            let deduped = match recent.contacts.get(&key) {
                Some(at) if at.elapsed() < window => true,
                _ => {
                    recent.contacts.insert(key, Instant::now());
                    false
                }
            };
            let attributed = pid
                .and_then(|pid| recent.reports.get(&pid))
                .filter(|(_, at)| at.elapsed() <= ATTRIBUTION_WINDOW)
                .map(|(request_id, _)| request_id.clone());
            (deduped, if expected { None } else { attributed })
        };
        let row = BoundaryPeer {
            uid: peer.and_then(|peer| peer.uid()),
            pid,
            exe: facts.exe,
            harness: facts.harness,
        };
        let written = if deduped {
            self.store
                .count_boundary_observation(kind, expected)
                .await
                .map(|()| None)
        } else {
            self.store
                .insert_boundary_observation(BoundaryObservationInsert {
                    kind,
                    expected,
                    peer: &row,
                    detail: Some(detail),
                    attributed: attributed.as_deref(),
                })
                .await
                .map(Some)
        };
        match written {
            Ok(_) => self.load().await,
            Err(error) => tracing::warn!(%error, "admin contact not recorded"),
        }
    }

    /// `doctor.report`: validates the document, stores it under the daemon's
    /// own peer facts with its audit row, attributes the admin contacts the
    /// same kernel pid made in the last [`ATTRIBUTION_WINDOW`], and answers
    /// what the daemon saw.
    pub async fn record_report(
        &self,
        ctx: &ExecContext,
    ) -> Result<CapabilityOutput, CapabilityFailure> {
        let report = DoctorReport::from_args(&ctx.args)
            .map_err(|error| invalid_report(&error.to_string()))?;
        let report_json = ctx.args.to_string();
        if report_json.len() > MAX_BOUNDARY_REPORT_BYTES {
            return Err(invalid_report(&format!(
                "the document is {} bytes; at most {MAX_BOUNDARY_REPORT_BYTES} are stored",
                report_json.len()
            )));
        }
        let pid = ctx.peer.peer_pid;
        let peer = self.report_peer(ctx).await;
        let report_id = self.store_report(ctx, &report, &peer, &report_json).await?;
        let attributed = self.attribute_after_report(ctx, pid).await;
        self.load().await;
        let claimed = classify_chain(&report.env.harness_chain);
        let harness_agrees = harness_agreement(peer.harness.as_deref(), &claimed);
        Ok(CapabilityOutput {
            outcome: Outcome::Verified,
            body: json!({
                "accepted": true,
                "report_id": report_id,
                "request_id": ctx.request_id,
                "verdict": report.verdict,
                "peer": {
                    "uid": peer.uid,
                    "pid": peer.pid,
                    "exe": peer.exe,
                    "harness": peer.harness,
                    "relayed": ctx.peer.relayed,
                },
                "claimed_harness": claimed,
                "harness_agrees": harness_agrees,
                "attributed_admin_contacts": attributed,
            }),
            evidence: Vec::new(),
        })
    }

    /// The peer a report is stored under: the pipeline's resolution from
    /// the request row, or one made now for a harness that submitted
    /// without it.
    async fn report_peer(&self, ctx: &ExecContext) -> BoundaryPeer {
        let pid = ctx.peer.peer_pid;
        let facts = match ctx.store.request_peer_facts(&ctx.request_id).await {
            Ok(Some((exe, harness))) if exe.is_some() || harness.is_some() => {
                PeerFacts { exe, harness }
            }
            _ => self.resolve(pid, ctx.peer.relayed).await,
        };
        BoundaryPeer {
            uid: ctx.peer.peer_uid,
            pid,
            exe: facts.exe,
            harness: facts.harness,
        }
    }

    /// Remembers the report for contacts that follow it and attributes the
    /// unexplained contacts of the same pid in the window before it.
    async fn attribute_after_report(&self, ctx: &ExecContext, pid: Option<u32>) -> u64 {
        let Some(pid) = pid else {
            return 0;
        };
        {
            let mut recent = self
                .recent
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            recent.forget_old();
            recent
                .reports
                .insert(pid, (ctx.request_id.clone(), Instant::now()));
        }
        self.store
            .attribute_boundary_observations(
                pid,
                now_ts() - window_secs(ATTRIBUTION_WINDOW),
                &ctx.request_id,
            )
            .await
            .unwrap_or(0)
    }

    /// The report row and its audit row, in one transaction.
    async fn store_report(
        &self,
        ctx: &ExecContext,
        report: &DoctorReport,
        peer: &BoundaryPeer,
        report_json: &str,
    ) -> Result<i64, CapabilityFailure> {
        let failed_json = serde_json::to_string(&report.failed).unwrap_or_else(|_| "[]".to_owned());
        let unverified_json =
            serde_json::to_string(&report.unverified).unwrap_or_else(|_| "[]".to_owned());
        let detail = json!({
            "verdict": report.verdict,
            "failed": report.failed,
            "unverified": report.unverified,
            "peer_harness": peer.harness,
        })
        .to_string();
        let report_ts = i64::try_from(report.ts).unwrap_or(i64::MAX);
        self.store
            .insert_boundary_report(
                BoundaryReportInsert {
                    request_id: &ctx.request_id,
                    report_ts,
                    verdict: report.verdict.as_str(),
                    failed_json: &failed_json,
                    unverified_json: &unverified_json,
                    agent: &ctx.caller.agent,
                    repo: &ctx.caller.repo,
                    peer,
                    relayed: ctx.peer.relayed,
                    client_version: &report.env.client_version,
                    report_json,
                },
                AuditEntry {
                    action: ACTION_DOCTOR_REPORT,
                    decision: Decision::Allow,
                    actor: Actor::System,
                    detail: Some(&detail),
                },
            )
            .await
            .map_err(|error| CapabilityFailure::Failed {
                detail: format!("the report could not be recorded: {error}"),
            })
    }

    /// The `boundary` block of `status`, from the census in memory.
    #[must_use]
    pub fn status_block(&self) -> Value {
        self.census()
            .map_or_else(never_checked_block, |census| block(&census, now_ts()))
    }
}

/// The refusal for a document that does not validate: the cause spelled
/// out, the recovery the same every time.
fn invalid_report(why: &str) -> CapabilityFailure {
    CapabilityFailure::Refused {
        cause: CAUSE_INVALID_REPORT.to_owned(),
        detail: format!("doctor.report was refused: {why}"),
        recovery: RECOVERY_INVALID_REPORT.to_owned(),
    }
}

/// `doctor.report` as the executor dispatches it.
pub async fn report(ctx: &ExecContext) -> Result<CapabilityOutput, CapabilityFailure> {
    let Some(boundary) = ctx.status.boundary() else {
        return Err(CapabilityFailure::Refused {
            cause: CAUSE_BOUNDARY_UNAVAILABLE.to_owned(),
            detail: "this daemon has no boundary observer attached; nothing can record a report"
                .to_owned(),
            recovery: "Restart the daemon: the boundary observer is attached at boot.".to_owned(),
        });
    };
    boundary.record_report(ctx).await
}

/// Whether the harness the daemon resolved for the peer (`seen`) and the
/// one the client's own walk claimed (`claimed`) name the same harness.
/// Three-valued: `Some(false)` only when both sides know and differ.
/// `None` (undetermined) when either side does not know — the daemon has
/// no resolution (Windows, a missed budget), it sees the relay process in
/// place of the client, or the client's walk produced nothing (a profile
/// that denies `/bin/ps` leaves its chain empty, which classifies as
/// `unknown`). A correct sandboxed run must not read as a disagreement.
#[must_use]
pub fn harness_agreement(seen: Option<&str>, claimed: &str) -> Option<bool> {
    match seen {
        None | Some(RELAY_HARNESS) => None,
        Some(_) if claimed == UNKNOWN_AGENT => None,
        Some(seen) => Some(seen == claimed),
    }
}

/// The block before any report and with no observations: what a daemon
/// serves when the census was never loaded.
#[must_use]
pub fn never_checked_block() -> Value {
    block(&BoundaryCensus::default(), now_ts())
}

/// The one human line: the verdict, its age, who sent it and how, and the
/// unexplained admin contacts.
#[must_use]
pub fn summary(census: &BoundaryCensus, now: i64) -> String {
    let Some(report) = &census.last_report else {
        return "never checked — run pam doctor from the agent".to_owned();
    };
    let via = if report.relayed { "relay" } else { "direct" };
    let pid = report
        .peer
        .pid
        .map_or_else(|| "no pid".to_owned(), |pid| format!("pid {pid}"));
    format!(
        "{} {} ago by {} ({pid}, {via}); admin contacts unattributed: {}",
        report.verdict,
        age(now.saturating_sub(report.ts).max(0)),
        report.agent,
        census.admin_unattributed
    )
}

/// `12 s`, `7 min`, `3 h`, `2 d`.
fn age(secs: i64) -> String {
    match secs {
        0..=59 => format!("{secs} s"),
        60..=3599 => format!("{} min", secs / 60),
        3600..=86_399 => format!("{} h", secs / 3600),
        _ => format!("{} d", secs / 86_400),
    }
}

fn observation_json(row: &BoundaryObservationRow) -> Value {
    json!({
        "ts": row.ts,
        "kind": row.kind,
        "peer_pid": row.peer.pid,
        "peer_exe": row.peer.exe,
        "peer_harness": row.peer.harness,
        "attributed": row.attributed,
    })
}

fn block(census: &BoundaryCensus, now: i64) -> Value {
    let last_report = census.last_report.as_ref().map(|report| {
        json!({
            "verdict": report.verdict,
            "ts": report.report_ts,
            "received_ts": report.ts,
            "age_s": now.saturating_sub(report.ts).max(0),
            "agent": report.agent,
            "repo": report.repo,
            "relayed": report.relayed,
            "peer_pid": report.peer.pid,
            "peer_exe": report.peer.exe,
            "peer_harness": report.peer.harness,
            "failed": report.failed,
            "unverified": report.unverified,
            "request_id": report.request_id,
        })
    });
    json!({
        "peer_identity": PEER_IDENTITY,
        "last_report": last_report,
        "reports": {
            "retained": census.reports_retained,
            "established": census.reports_established,
            "not_established": census.reports_not_established,
        },
        "admin_contacts": {
            "unattributed": census.admin_unattributed,
            "unattributed_24h": census.admin_unattributed_24h,
            "total": census.admin_total,
            "expected_total": census.admin_expected_total,
            "last": census.last_admin_contact.as_ref().map(observation_json),
            "last_expected": census.last_expected_admin_contact.as_ref().map(observation_json),
        },
        "public_unknown_harness": {
            "total": census.public_unknown_total,
            "last": census.last_public_unknown.as_ref().map(|row| json!({
                "ts": row.ts,
                "peer_pid": row.peer.pid,
                "peer_exe": row.peer.exe,
                "peer_harness": row.peer.harness,
            })),
        },
        "summary": summary(census, now),
    })
}
