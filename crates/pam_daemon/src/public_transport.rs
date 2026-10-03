//! The public plane on the framed transport: the policy and the
//! per-connection handler.
//!
//! The public listener serves [`crate::framed`] frames on
//! [`crate::runtime_dir::RuntimeDir::public_socket`] (unix) or behind
//! [`crate::runtime_dir::RuntimeDir::public_control`] (Windows). A connection
//! carries a hello, then exactly one request: a unary call answered with one
//! reply, or a follow of one ticket that ends with the durable result. The
//! daemon closes it after the answer.
//!
//! What this plane does with a connection, and nothing else in the daemon:
//!
//! - **Peer.** The kernel's view of the peer ([`PublicPeer`]) is recorded with
//!   the request and never admits or refuses anything. A uid other than the
//!   daemon's is logged.
//! - **Hello.** A ZMTP greeting (a pre-migration client) is closed unanswered
//!   and logged at most once a minute with the peer's uid and pid. The version
//!   rule both planes share ([`framed::version_rule`], over [`crate::image`])
//!   is applied to the hello's version: equal versions
//!   are served; a different version is `error client_version_mismatch` while
//!   the binary on disk is the one running, and `error daemon_outdated` — with
//!   the daemon moving to `Restarting` — once it was replaced. Neither writes a
//!   request row. The envelope's own `client_version` decides nothing here.
//! - **Request.** The envelope's identity and scope fields are bounded,
//!   `admin.*` is refused before anything is retained, and the request is
//!   handed to the daemon core through [`Ingress`]. The connection then waits
//!   on the reply, on the peer going away, on the listener's stop and on a
//!   backstop past the handler's own hard deadline, all at once. A peer that
//!   goes away releases its connection permit and never cancels the work: the
//!   result stays in the store. A reply over the frame limit becomes the
//!   `response_budget_exhausted` refusal. A request the core accepted is never
//!   answered with a bare end of file.
//! - **Follow.** The envelope must be a waiting `query` for one ticket and is
//!   run through the pipeline like any `query`: one request row, one terminal
//!   audit row, a control slot and a rate token. A refusal, or a ticket that
//!   is already terminal, is answered `end` at once. Otherwise the connection
//!   attaches to the event hub (registering its queue and taking the replay
//!   after `after_seq` in one critical section), writes `following` and the
//!   replay, reads the store again, and then streams events until the ticket
//!   ends. Because a terminal event is published only after the durable
//!   terminal write, either that second read or the queue sees the ending:
//!   there is no window in which a follower waits for an event that already
//!   went by. The stream ends with `end`, carrying the scoped `query` answer
//!   authorised again at that moment. The store is also re-checked every
//!   [`FOLLOW_RECONCILE`], which covers an ending whose event was never
//!   published. A follower sees only what the hub gives public followers
//!   (progress prose replaced by a constant), is disconnected when a frame
//!   write does not complete within the write timeout, is closed with
//!   `error follow_expired` after [`FOLLOW_LIFETIME`], with
//!   `error daemon_shutting_down` as soon as the daemon leaves `Serving`, and
//!   with `error bad_frame` if it sends anything after `follow`. A follower
//!   going away detaches its queue and frees its slot; it never cancels work.
//!
//! A client must keep its side of the connection open until it has read the
//! answer: end of file from the client is a disconnect, also on a unary call.
//!
//! The listener is started by [`crate::transport::Transport::bind`] and
//! stopped by [`crate::transport::Transport::shutdown`].

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use pam_proto::wire::{
    End, Follow, Following, Frame, FrameError, HelloAck, Via, WIRE_PROTOCOL, cause,
};
use pam_proto::{Envelope, Event, Outcome, Response};
use pam_store::{RequestState, Store};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};
use tokio::sync::{oneshot, watch};
use tokio::time::Instant;

use crate::admin::{ADMIN_PREFIX, CAUSE_ADMIN_DENIED};
use crate::daemon::{
    DAEMON_VERSION, DEFAULT_HANDLER_GRACE, deadline_refusal_response, internal_refusal,
    outdated_refusal, shutting_down_refusal,
};
use crate::event_hub::{AttachError, EventHub, Followed, Follower};
use crate::executor::CapabilityFailure;
use crate::flow_result_service::authorized_metadata;
use crate::framed::{self, HandshakeError, Limits, Policy};
use crate::image::ImageWatch;
use crate::ingress::{Ingress, Origin, PeerIdentity, PublicPeer};
use crate::lifecycle::LifecyclePhase;
use crate::policy::CAP_QUERY;
use crate::transport::{bad_request, envelope_within_limits};

/// The longest one follow connection lives: the request wall-time ceiling. A
/// client whose own timeout is longer reconnects and resumes.
pub const FOLLOW_LIFETIME: Duration = Duration::from_hours(1);

/// How often a follow re-reads the store, as a backstop for a terminal
/// transition whose event was never published.
pub const FOLLOW_RECONCILE: Duration = Duration::from_secs(15);

/// The shortest interval between two log lines about a ZMTP greeting.
pub const LEGACY_LOG_INTERVAL: Duration = Duration::from_secs(60);

/// How long past the handler's own hard deadline a connection waits for its
/// reply before answering `deadline_exceeded` itself. The dispatcher's reply
/// guard answers every request at its deadline plus its grace; this only
/// bounds a connection whose reply never comes at all. It assumes
/// [`crate::daemon::DaemonConfig::handler_grace`] is not raised above its
/// default by more than this margin.
pub const REPLY_BACKSTOP_MARGIN: Duration = Duration::from_secs(15);

/// Refusal cause when a reply would not fit one public frame.
pub const CAUSE_RESPONSE_BUDGET: &str = "response_budget_exhausted";

/// How often a follow re-reads the store after the ticket's terminal event
/// arrived while its terminal row is not yet readable (a verdict parked for
/// retry is published before the row is durable).
const TERMINAL_SETTLE: Duration = Duration::from_millis(250);

/// How long a connection that sent bytes after its one request is read and
/// discarded after its `error` frame was written.
const EXTRA_BYTES_DRAIN: Duration = Duration::from_secs(1);

/// Recovery line for frames this protocol does not allow.
const RECOVERY_BAD_FRAME: &str = "Upgrade pam and the pam GUI to matching versions, then retry.";

/// Recovery line for a follower cut by the drain.
const RECOVERY_SHUTTING_DOWN: &str = "Reconnect shortly with the last sequence number seen; the next pam command starts a fresh daemon.";

/// Recovery line for [`cause::FOLLOWER_CAPACITY_EXHAUSTED`].
const RECOVERY_FOLLOWERS: &str =
    "Retry shortly; a follower slot frees when another pam wait or pam subscribe ends.";

/// Recovery line for an `admin.*` request on the public plane.
const RECOVERY_ADMIN_DENIED: &str =
    "Administration is GUI-only; open the PAM GUI — agents have no security commands.";

/// The two clocks of a follow connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FollowTimes {
    /// How long one follow connection may live ([`FOLLOW_LIFETIME`]).
    pub lifetime: Duration,
    /// How often the store is re-read as a backstop ([`FOLLOW_RECONCILE`]).
    pub reconcile: Duration,
}

impl FollowTimes {
    /// One hour, re-checked every fifteen seconds.
    pub const DEFAULT: Self = Self {
        lifetime: FOLLOW_LIFETIME,
        reconcile: FOLLOW_RECONCILE,
    };
}

/// Lets one log line about pre-migration clients through per
/// [`LEGACY_LOG_INTERVAL`] and counts the rest, so a stale binary retrying
/// in a loop names itself without flooding the log.
#[derive(Debug, Default)]
pub(crate) struct LegacyLog {
    last: Mutex<Option<Instant>>,
    suppressed: AtomicU64,
}

impl LegacyLog {
    /// `Some(greetings not logged since the last line)` when this greeting
    /// should be logged, `None` when it is inside the interval.
    pub(crate) fn admit(&self, now: Instant) -> Option<u64> {
        let mut last = self.last.lock().unwrap_or_else(PoisonError::into_inner);
        if last.is_some_and(|at| now.saturating_duration_since(at) < LEGACY_LOG_INTERVAL) {
            self.suppressed.fetch_add(1, Ordering::Relaxed);
            return None;
        }
        *last = Some(now);
        Some(self.suppressed.swap(0, Ordering::Relaxed))
    }
}

/// The public plane's policy over a framed listener. See the module docs.
#[derive(Debug)]
pub struct PublicPolicy {
    ingress: Ingress,
    store: Arc<Store>,
    /// Read to cut followers when the daemon leaves `Serving`; written to
    /// request the restart a replaced binary calls for.
    phase: watch::Sender<LifecyclePhase>,
    hub: Arc<EventHub>,
    image: Arc<ImageWatch>,
    limits: Limits,
    follow: FollowTimes,
    /// The daemon's own uid, where the platform has one, to notice a peer
    /// that is somebody else.
    own_uid: Option<u32>,
    legacy: LegacyLog,
}

impl PublicPolicy {
    /// The public policy with the public limits and the default follow
    /// clocks.
    #[must_use]
    pub fn new(
        ingress: Ingress,
        store: Arc<Store>,
        phase: watch::Sender<LifecyclePhase>,
        hub: Arc<EventHub>,
        image: Arc<ImageWatch>,
    ) -> Arc<Self> {
        Self::with_limits(
            ingress,
            store,
            phase,
            hub,
            image,
            Limits::PUBLIC,
            FollowTimes::DEFAULT,
        )
    }

    /// [`Self::new`] with explicit limits and follow clocks (tests).
    #[must_use]
    pub fn with_limits(
        ingress: Ingress,
        store: Arc<Store>,
        phase: watch::Sender<LifecyclePhase>,
        hub: Arc<EventHub>,
        image: Arc<ImageWatch>,
        limits: Limits,
        follow: FollowTimes,
    ) -> Arc<Self> {
        Arc::new(Self {
            ingress,
            store,
            phase,
            hub,
            image,
            limits,
            follow,
            own_uid: own_uid(),
            legacy: LegacyLog::default(),
        })
    }

    /// Logs a peer that greeted in ZMTP, at most once per
    /// [`LEGACY_LOG_INTERVAL`], so the stale binary can be found.
    fn log_legacy_peer(&self, peer: PeerIdentity) {
        if let Some(suppressed) = self.legacy.admit(Instant::now()) {
            tracing::warn!(
                peer_uid = ?peer.uid(),
                peer_pid = ?peer.pid(),
                suppressed,
                "a pre-migration pam client greeted the public socket in ZMTP and was closed; \
                 upgrade or remove the stale pam binary that process runs"
            );
        }
    }

    /// The refusal every request gets once the daemon has left `Serving`:
    /// `daemon_outdated` while it restarts into a replaced binary (the
    /// client waits for the replacement and retries once),
    /// `daemon_shutting_down` while it drains. `None` while serving. No row
    /// is written for either: the retry is recorded by the next daemon.
    fn leaving(&self, id: &str, client_version: &str) -> Option<Response> {
        match *self.phase.borrow() {
            LifecyclePhase::Serving => None,
            LifecyclePhase::Restarting => {
                Some(outdated_refusal(id, client_version, self.image.boot_path()))
            }
            LifecyclePhase::Draining => Some(shutting_down_refusal(id)),
        }
    }

    /// The refusal for a request the core accepted and then dropped without
    /// answering: the deadline when it has passed, the drain or the restart
    /// when the daemon is leaving, otherwise an internal failure. Never a
    /// bare end of file.
    fn unanswered(
        &self,
        id: &str,
        client_version: &str,
        deadline_ms: u64,
        expires: Instant,
    ) -> Response {
        if Instant::now() >= expires {
            return deadline_refusal_response(id, deadline_ms);
        }
        self.leaving(id, client_version)
            .unwrap_or_else(|| internal_refusal(id))
    }

    /// Hands `envelope` to the daemon core and waits for its one response,
    /// the peer, the listener's stop and the backstop at once.
    async fn run<S>(
        &self,
        stream: &mut S,
        envelope: Envelope,
        peer: PublicPeer,
        stop: &mut watch::Receiver<bool>,
    ) -> Ran
    where
        S: AsyncRead + Unpin,
    {
        let id = envelope.id.clone();
        let version = envelope.client_version.clone();
        // Decided here, not left to the core: once the daemon is leaving the
        // dispatcher may already be gone, and the answer must not depend on
        // which of the two went first.
        if let Some(refusal) = self.leaving(&id, &version) {
            return Ran::Answer(refusal);
        }
        let deadline_ms = envelope.deadline_ms;
        let asked = Duration::from_millis(deadline_ms).min(crate::queue::MAX_LEASE);
        let expires = Instant::now() + asked;
        let backstop = expires + DEFAULT_HANDLER_GRACE + REPLY_BACKSTOP_MARGIN;
        let Ok(mut answer) = self
            .ingress
            .submit(Origin::Public, Some(peer), envelope)
            .await
        else {
            // The dispatcher is gone: the daemon is on its way out.
            return Ran::Answer(
                self.leaving(&id, &version)
                    .unwrap_or_else(|| shutting_down_refusal(&id)),
            );
        };
        match await_answer(stream, &mut answer, stop, backstop).await {
            Awaited::Answer(response) => Ran::Answer(response),
            Awaited::Unanswered => {
                Ran::Answer(self.unanswered(&id, &version, deadline_ms, expires))
            }
            Awaited::Overdue => Ran::Answer(deadline_refusal_response(&id, deadline_ms)),
            // The answer may have landed in the instant the stop was seen.
            Awaited::Stopped => Ran::Answer(answer.try_recv().unwrap_or_else(|_| {
                self.leaving(&id, &version)
                    .unwrap_or_else(|| shutting_down_refusal(&id))
            })),
            Awaited::PeerGone => Ran::PeerGone,
            Awaited::PeerSpoke => Ran::PeerSpoke,
        }
    }

    /// The unary path: one request, one reply.
    async fn request<S>(
        &self,
        stream: &mut S,
        envelope: Envelope,
        peer: PublicPeer,
        stop: &mut watch::Receiver<bool>,
    ) where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let maximum = self.limits.reply_bytes;
        if !envelope_within_limits(&envelope) {
            let refusal = bad_request(
                "unknown".to_owned(),
                "request identity or scope fields exceed their limits",
            );
            let _ = write_reply(stream, &refusal, maximum).await;
            return;
        }
        if envelope.capability.starts_with(ADMIN_PREFIX) {
            // Refused here, before the core sees it: no row, no audit, and
            // nothing a caller label could change.
            tracing::warn!(
                request = %envelope.id,
                capability = %envelope.capability,
                peer_uid = ?peer.identity.uid(),
                peer_pid = ?peer.identity.pid(),
                "refused an admin operation on the public socket"
            );
            let _ = write_reply(stream, &admin_refusal(&envelope.id), maximum).await;
            return;
        }
        let id = envelope.id.clone();
        match self.run(stream, envelope, peer, stop).await {
            Ran::Answer(response) => {
                if let Err(error) = write_reply(stream, &response, maximum).await {
                    tracing::debug!(request = %id, %error, "the reply could not be written");
                }
            }
            // The connection permit is released; the request is not
            // cancelled and its result stays in the store.
            Ran::PeerGone => {
                tracing::debug!(request = %id, "the client went away before its reply");
            }
            Ran::PeerSpoke => refuse_extra_bytes(stream).await,
        }
    }

    /// The follow path. See the module docs.
    async fn follow<S>(
        &self,
        stream: &mut S,
        follow: Follow,
        peer: PublicPeer,
        stop: &mut watch::Receiver<bool>,
    ) where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let maximum = self.limits.reply_bytes;
        let Follow {
            envelope,
            after_seq,
            epoch,
        } = follow;
        let id = envelope.id.clone();
        let Some(ticket) = followable_ticket(&envelope) else {
            let refusal = bad_request(
                if envelope_within_limits(&envelope) {
                    id
                } else {
                    "unknown".to_owned()
                },
                "a follow carries a waiting query envelope whose args.ticket names one ticket",
            );
            let _ = write_end(stream, None, None, refusal, maximum).await;
            return;
        };
        let lifetime = Instant::now() + self.follow.lifetime;
        // A position from another epoch counts another daemon's events.
        let after_seq = if epoch.as_deref() == Some(self.hub.epoch()) {
            after_seq
        } else {
            0
        };
        let caller_repo = envelope.caller.repo.clone();

        // 1. The authorising query, through the pipeline like any query.
        let response = match self.run(stream, envelope, peer, stop).await {
            Ran::Answer(response) => response,
            Ran::PeerGone => return,
            Ran::PeerSpoke => return refuse_extra_bytes(stream).await,
        };
        let state = match pending_state(&response) {
            Queried::Pending(state) => state,
            Queried::Terminal(event) => {
                let _ = write_end(stream, None, Some(event), response, maximum).await;
                return;
            }
            Queried::Refused => {
                let _ = write_end(stream, None, None, response, maximum).await;
                return;
            }
        };

        // 2. Attach: the queue is registered and the replay taken in one
        //    critical section, so nothing published from here on is missed.
        let attached = match self.hub.attach(&ticket, after_seq) {
            Ok(attached) => attached,
            Err(AttachError::TotalCapacity | AttachError::TicketCapacity) => {
                let refusal = Response::transient_refusal(
                    id,
                    cause::FOLLOWER_CAPACITY_EXHAUSTED,
                    "every follower slot for this ticket or for the daemon is taken",
                    RECOVERY_FOLLOWERS,
                );
                let _ = write_end(stream, None, None, refusal, maximum).await;
                return;
            }
            Err(AttachError::Closed) => return refuse_shutting_down(stream).await,
        };

        // 3. `following`, then what the ring held after the resume position.
        let following = Frame::Following(Following {
            ticket: ticket.clone(),
            epoch: self.hub.epoch().to_owned(),
            state: state.as_str().to_owned(),
            seq: attached.seq,
        });
        if framed::send(stream, &following, maximum).await.is_err() {
            return;
        }
        for (seq, event) in attached.replay {
            if framed::send(stream, &Frame::follow_event(seq, event), maximum)
                .await
                .is_err()
            {
                return;
            }
        }

        // 4. The store again, then the stream.
        let scope = FollowScope {
            id: &id,
            caller_repo: &caller_repo,
            ticket: &ticket,
        };
        self.stream_events(stream, attached.follower, &scope, lifetime, stop)
            .await;
    }

    /// Steps 4 onward of a follow: re-read the store, then deliver events
    /// until the ticket ends, the follower goes, or the daemon stops.
    async fn stream_events<S>(
        &self,
        stream: &mut S,
        mut follower: Follower,
        scope: &FollowScope<'_>,
        lifetime: Instant,
        stop: &mut watch::Receiver<bool>,
    ) where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let maximum = self.limits.reply_bytes;
        let mut phase = self.phase.subscribe();
        let mut reconcile = tokio::time::interval_at(
            Instant::now() + self.follow.reconcile,
            self.follow.reconcile,
        );
        reconcile.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // The terminal event, once it arrived: a flag beside the queue.
        let mut terminal: Option<(u64, Event)> = None;
        let mut probe = [0u8; 1];
        let mut recheck = true;
        loop {
            if recheck {
                if let Some(end) = self.settled(scope, terminal.as_ref()).await {
                    let _ = framed::send(stream, &Frame::End(end), maximum).await;
                    return;
                }
                recheck = false;
            }
            tokio::select! {
                biased;
                () = framed::stopped(stop) => return refuse_shutting_down(stream).await,
                () = framed::left_serving(&mut phase) => {
                    return refuse_shutting_down(stream).await;
                }
                // Ahead of the events: a ticket that never stops publishing
                // must not keep a connection past its lifetime.
                () = tokio::time::sleep_until(lifetime) => {
                    framed::refuse(
                        stream,
                        cause::FOLLOW_EXPIRED,
                        "this follow reached its maximum lifetime of one connection",
                        "Reconnect with the last sequence number seen to keep following.",
                    )
                    .await;
                    return;
                }
                read = stream.read(&mut probe) => {
                    return match read {
                        // The follower went away: its queue detaches and
                        // its slot is freed. The work is not touched.
                        Ok(0) | Err(_) => {}
                        Ok(_) => refuse_extra_bytes(stream).await,
                    };
                }
                next = follower.next(), if terminal.is_none() => match next {
                    Followed::Event { seq, event } => {
                        if framed::send(stream, &Frame::follow_event(seq, event), maximum)
                            .await
                            .is_err()
                        {
                            // A follower that does not read is disconnected;
                            // it can reconnect and resume.
                            return;
                        }
                    }
                    Followed::Terminal { seq, event } => {
                        terminal = Some((seq, event));
                        recheck = true;
                    }
                    Followed::Closed => return refuse_shutting_down(stream).await,
                },
                _ = reconcile.tick() => recheck = true,
                () = tokio::time::sleep(TERMINAL_SETTLE), if terminal.is_some() => recheck = true,
            }
        }
    }

    /// Re-runs the scoped authorisation against the store, without a request
    /// row. `Some` is the `end` to write: the durable answer once the ticket
    /// is terminal, or the refusal once the caller may no longer see it.
    /// `None` means the ticket is still in flight.
    async fn settled(
        &self,
        scope: &FollowScope<'_>,
        terminal: Option<&(u64, Event)>,
    ) -> Option<End> {
        let status = match authorized_metadata(&self.store, scope.caller_repo, scope.ticket).await {
            Ok((status, _)) => status,
            Err(failure) => {
                return Some(End {
                    seq: None,
                    event: None,
                    response: failure_refusal(scope.id, failure),
                });
            }
        };
        if !status.state.is_terminal() {
            return None;
        }
        let (seq, event) = match terminal {
            Some((seq, event)) => (Some(*seq), event.clone()),
            None => (None, terminal_event(status.state)),
        };
        Some(End {
            seq,
            event: Some(event),
            response: query_answer(
                scope.id,
                scope.ticket,
                status.state,
                status.outcome.as_deref(),
                &status.capability,
            ),
        })
    }
}

impl<S> Policy<S> for PublicPolicy
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    fn plane(&self) -> &'static str {
        "public"
    }

    fn limits(&self) -> Limits {
        self.limits
    }

    async fn serve(
        self: Arc<Self>,
        mut stream: S,
        identity: PeerIdentity,
        mut stop: watch::Receiver<bool>,
    ) {
        let stream = &mut stream;
        if let (Some(own), Some(uid)) = (self.own_uid, identity.uid())
            && own != uid
        {
            tracing::warn!(
                peer_uid = uid,
                peer_pid = ?identity.pid(),
                daemon_uid = own,
                "a public connection came from another user"
            );
        }
        let deadline = framed::handshake_deadline(&self.limits);
        let hello = match framed::read_hello(stream, deadline).await {
            Ok(hello) => hello,
            Err(HandshakeError::LegacyZmtp) => return self.log_legacy_peer(identity),
            Err(HandshakeError::Untyped(_)) => {
                framed::refuse(
                    stream,
                    cause::BAD_FRAME,
                    "the first frame has no \"t\" member: this daemon speaks framed pam requests",
                    RECOVERY_BAD_FRAME,
                )
                .await;
                return framed::discard_frame(stream, deadline).await;
            }
            // Answered on the wire where the peer can read an answer, and
            // the request behind a refused hello already read off.
            Err(error) => return log_handshake(&error, identity),
        };
        // The same rule as on the administration plane, by the same
        // function: it answers, reads off the request behind the hello, and
        // only a replaced binary moves the phase.
        if let Err(refusal) =
            framed::version_rule(stream, &hello, &self.image, &self.phase, deadline).await
        {
            tracing::debug!(
                cause = %refusal.cause,
                peer_uid = ?identity.uid(),
                peer_pid = ?identity.pid(),
                "refused a hello"
            );
            return;
        }
        let ack = HelloAck {
            proto: WIRE_PROTOCOL,
            version: DAEMON_VERSION.to_owned(),
            epoch: self.hub.epoch().to_owned(),
            pid: std::process::id(),
        };
        let body =
            match framed::accept_hello(stream, ack, self.limits.request_bytes, deadline).await {
                Ok(body) => body,
                Err(error) => return log_handshake(&error, identity),
            };
        let peer = PublicPeer {
            identity,
            relayed: hello.via == Via::Relay,
        };
        let maximum = self.limits.reply_bytes;
        match Frame::decode(&body) {
            Ok(Frame::Request { envelope }) => {
                self.request(stream, envelope, peer, &mut stop).await;
            }
            Ok(Frame::Follow(follow)) => self.follow(stream, follow, peer, &mut stop).await,
            // JSON of the right type whose envelope does not parse keeps
            // today's shape: a `bad_request` refusal naming the request.
            Err(FrameError::Invalid { t, detail }) if t == "request" || t == "follow" => {
                let id = pam_proto::wire::salvage_envelope_id(&body)
                    .filter(|id| !id.is_empty() && id.len() <= 128)
                    .unwrap_or_else(|| "unknown".to_owned());
                let refusal = bad_request(id, &format!("cannot parse request envelope: {detail}"));
                let _ = if t == "request" {
                    write_reply(stream, &refusal, maximum).await
                } else {
                    write_end(stream, None, None, refusal, maximum).await
                };
            }
            Ok(other) => {
                let detail = format!(
                    "expected request or follow on the public socket, got {}",
                    other.type_name()
                );
                framed::refuse(stream, cause::BAD_FRAME, &detail, RECOVERY_BAD_FRAME).await;
            }
            Err(error) => {
                framed::refuse(
                    stream,
                    cause::BAD_FRAME,
                    &error.to_string(),
                    RECOVERY_BAD_FRAME,
                )
                .await;
            }
        }
    }
}

/// What one follow re-authorises with.
struct FollowScope<'a> {
    /// The follow envelope's id: what `end.response` answers.
    id: &'a str,
    /// The caller's repository as the envelope spelled it.
    caller_repo: &'a str,
    /// The followed ticket.
    ticket: &'a str,
}

/// How a wait on the daemon core ended.
enum Awaited {
    Answer(Response),
    /// The reply channel was dropped without an answer.
    Unanswered,
    /// The backstop elapsed.
    Overdue,
    Stopped,
    /// End of file, or a connection error, from the peer.
    PeerGone,
    /// The peer sent bytes after its one request.
    PeerSpoke,
}

/// [`Awaited`] with the cases that still have an answer folded into one.
enum Ran {
    Answer(Response),
    PeerGone,
    PeerSpoke,
}

async fn await_answer<S: AsyncRead + Unpin>(
    stream: &mut S,
    answer: &mut oneshot::Receiver<Response>,
    stop: &mut watch::Receiver<bool>,
    backstop: Instant,
) -> Awaited {
    let mut probe = [0u8; 1];
    tokio::select! {
        biased;
        answered = &mut *answer => match answered {
            Ok(response) => Awaited::Answer(response),
            Err(_) => Awaited::Unanswered,
        },
        read = stream.read(&mut probe) => match read {
            Ok(0) | Err(_) => Awaited::PeerGone,
            Ok(_) => Awaited::PeerSpoke,
        },
        () = framed::stopped(stop) => Awaited::Stopped,
        () = tokio::time::sleep_until(backstop) => Awaited::Overdue,
    }
}

/// What the authorising query of a follow said about the ticket.
enum Queried {
    /// In flight, in this durable state.
    Pending(RequestState),
    /// Already terminal: this is the event a follower would have seen.
    Terminal(Event),
    /// Refused, or an answer with no readable state.
    Refused,
}

fn pending_state(response: &Response) -> Queried {
    let Response::Result { body, .. } = response else {
        return Queried::Refused;
    };
    let Some(state) = body
        .get("state")
        .and_then(serde_json::Value::as_str)
        .and_then(|state| RequestState::parse(state).ok())
    else {
        return Queried::Refused;
    };
    if state.is_terminal() {
        Queried::Terminal(terminal_event(state))
    } else {
        Queried::Pending(state)
    }
}

/// The terminal event a subscriber sees for a ticket that ended in `state`.
const fn terminal_event(state: RequestState) -> Event {
    match state {
        RequestState::Done => Event::Done,
        _ => Event::Refused,
    }
}

/// The ticket a follow envelope names, when the envelope is what a follow
/// must carry: a waiting `query`, within the envelope limits, for one
/// ticket of at most 128 bytes.
fn followable_ticket(envelope: &Envelope) -> Option<String> {
    if !envelope_within_limits(envelope) || envelope.capability != CAP_QUERY || !envelope.wait {
        return None;
    }
    envelope
        .args
        .get("ticket")
        .and_then(serde_json::Value::as_str)
        .filter(|ticket| !ticket.is_empty() && ticket.len() <= 128)
        .map(str::to_owned)
}

/// The scoped `query` answer for a ticket in `state`: the body and outcome
/// `flow_result_service::scoped_query` produces, built from the same
/// authorised metadata so `end` carries what a `query` sent at that moment
/// would have been answered.
fn query_answer(
    id: &str,
    ticket: &str,
    state: RequestState,
    outcome: Option<&str>,
    capability: &str,
) -> Response {
    let verdict = if state.is_terminal() {
        match outcome {
            Some("solved") => Outcome::Solved,
            Some("changed") => Outcome::Changed,
            Some("verified") => Outcome::Verified,
            Some("unresolved") => Outcome::Unresolved,
            _ => Outcome::Blocked,
        }
    } else {
        Outcome::Blocked
    };
    Response::Result {
        id: id.to_owned(),
        outcome: verdict,
        body: serde_json::json!({
            "ticket": ticket,
            "state": state.as_str(),
            "outcome": outcome,
            "capability": capability,
        }),
        evidence: Vec::new(),
    }
}

/// The refusal a failed re-authorisation ends a follow with.
fn failure_refusal(id: &str, failure: CapabilityFailure) -> Response {
    match failure {
        CapabilityFailure::Refused {
            cause,
            detail,
            recovery,
        } => Response::refusal(id, cause, detail, recovery),
        // The scoped read only ever refuses; anything else is the daemon's.
        CapabilityFailure::Failed { .. }
        | CapabilityFailure::Cancelled
        | CapabilityFailure::Parked { .. } => internal_refusal(id),
    }
}

/// The refusal for an `admin.*` request on the public plane: the cause the
/// pipeline's tripwire answers with, without the row it writes.
fn admin_refusal(id: &str) -> Response {
    Response::refusal(
        id,
        CAUSE_ADMIN_DENIED,
        "admin operations require the private native channel; public IPC cannot administer PAM",
        RECOVERY_ADMIN_DENIED,
    )
}

/// The small refusal that stands in for a reply over the frame limit.
fn budget_refusal(id: &str) -> Response {
    Response::refusal(
        if id.len() <= 128 { id } else { "unknown" },
        CAUSE_RESPONSE_BUDGET,
        "The response exceeds the public 1 MiB transport limit; evidence remains in PAM",
        "Request a bounded evidence range or inspect the ticket in PAM",
    )
}

/// A `reply` frame over a borrowed response, so a large reply is encoded
/// once and never cloned.
#[derive(serde::Serialize)]
struct ReplyRef<'a> {
    t: &'static str,
    response: &'a Response,
}

/// The body of the `reply` frame for `response`, never over `maximum`
/// bytes: a response that does not fit is replaced by
/// [`CAUSE_RESPONSE_BUDGET`]. Encoded through a bounded writer, so an
/// oversized response cannot allocate a second unbounded copy.
pub(crate) fn reply_body(response: &Response, maximum: usize) -> Vec<u8> {
    struct Bounded {
        bytes: Vec<u8>,
        maximum: usize,
    }
    impl std::io::Write for Bounded {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if bytes.len() > self.maximum.saturating_sub(self.bytes.len()) {
                return Err(std::io::Error::other("response budget exhausted"));
            }
            self.bytes.extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut writer = Bounded {
        bytes: Vec::new(),
        maximum,
    };
    let frame = ReplyRef {
        t: "reply",
        response,
    };
    if serde_json::to_writer(&mut writer, &frame).is_ok() {
        return writer.bytes;
    }
    let refusal = budget_refusal(response.id());
    serde_json::to_vec(&ReplyRef {
        t: "reply",
        response: &refusal,
    })
    .unwrap_or_default()
}

/// Writes the one `reply` of a unary call under the write timeout.
async fn write_reply<S: AsyncWrite + Unpin>(
    stream: &mut S,
    response: &Response,
    maximum: usize,
) -> std::io::Result<()> {
    let body = reply_body(response, maximum);
    tokio::time::timeout(
        framed::WRITE_TIMEOUT,
        framed::write_frame(stream, &body, maximum),
    )
    .await
    .map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "the peer did not read its reply within the write timeout",
        )
    })?
}

/// Writes the `end` frame of a follow.
async fn write_end<S: AsyncWrite + Unpin>(
    stream: &mut S,
    seq: Option<u64>,
    event: Option<Event>,
    response: Response,
    maximum: usize,
) -> std::io::Result<()> {
    let end = Frame::End(End {
        seq,
        event,
        response,
    });
    framed::send(stream, &end, maximum).await
}

/// `error daemon_shutting_down`: a follow stream cut by the drain.
async fn refuse_shutting_down<S: AsyncWrite + Unpin>(stream: &mut S) {
    framed::refuse(
        stream,
        cause::DAEMON_SHUTTING_DOWN,
        "the daemon is draining in-flight work before it exits",
        RECOVERY_SHUTTING_DOWN,
    )
    .await;
}

/// `error bad_frame`: the client sent something after its one request. What
/// else it sent is read and dropped for a moment (`drain_extra`).
async fn refuse_extra_bytes<S: AsyncRead + AsyncWrite + Unpin>(stream: &mut S) {
    framed::refuse(
        stream,
        cause::BAD_FRAME,
        "a connection carries one request; the client sent more after it",
        RECOVERY_BAD_FRAME,
    )
    .await;
    drain_extra(stream, Instant::now() + EXTRA_BYTES_DRAIN).await;
}

/// After an `error` frame answered bytes that followed the one request:
/// closing a TCP connection with bytes unread resets it, which can discard
/// the `error` frame before the client reads it. Where those bytes end is
/// unknown (they are not a frame this protocol allows), so what is pending is
/// read and dropped — at most one frame's worth, and not past `deadline` —
/// until the client closes. A refused hello is followed by
/// [`framed::discard_frame`] instead, which knows where the request ends.
async fn drain_extra<S: AsyncRead + Unpin>(stream: &mut S, deadline: Instant) {
    let mut budget = pam_proto::wire::MAX_FRAME_BYTES + 4;
    let mut scratch = [0u8; 1024];
    let _ = tokio::time::timeout_at(deadline, async {
        while budget > 0 {
            match stream.read(&mut scratch).await {
                Ok(0) | Err(_) => break,
                Ok(read) => budget = budget.saturating_sub(read),
            }
        }
    })
    .await;
}

/// Logs a handshake that did not produce a request. Timeouts and bad frames
/// were already answered on the wire; none of them is the daemon's problem.
fn log_handshake(error: &HandshakeError, peer: PeerIdentity) {
    tracing::debug!(
        %error,
        peer_uid = ?peer.uid(),
        peer_pid = ?peer.pid(),
        "a public connection ended in its handshake"
    );
}

/// This process's uid as a peer would see it, where the platform has one.
#[cfg(unix)]
fn own_uid() -> Option<u32> {
    crate::framed_unix::own_identity()
        .ok()
        .and_then(|identity| identity.uid())
}

/// Windows has no uid to compare.
#[cfg(not(unix))]
fn own_uid() -> Option<u32> {
    None
}
