//! The event stream: one long-lived task on the daemon's private all-events stream
//! ([`pam_daemon::admin_transport::events`]), forwarding every event to the frontend as a Tauri
//! event.
//!
//! Lazy, singleton: nothing runs until the frontend calls [`events_subscribe`] once; an atomic
//! guard makes later calls no-ops, so exactly one subscriber task exists per GUI process (frontend
//! listens via `@tauri-apps/api/event`'s `listen` on [`EVENT_CHANNEL`]). The stream is the admin
//! socket's, so it is the owner's view: the real progress notes and, for each ticket, its
//! capability, repository, agent label and ingress. It carries no `status`, `query` or `cancel`
//! traffic (the daemon publishes no lifecycle events for control requests), so the GUI's own polls
//! cannot come back as events and nothing here filters them.
//!
//! Resilient: the stream has no replay and the daemon restarts on its own, so the task reconnects
//! forever with exponential backoff ([`next_pause`], capped at [`BACKOFF_MAX`], reset after any
//! forwarded event). The frontend is told to refresh its lists with a distinct **resync** payload
//! ([`EventPayload::resync`]) wherever events may have been missed: after every successful
//! connect (nothing published before the subscription is replayed), and when the daemon-wide
//! counter `n` skips (progress was dropped for this subscriber). A `subscriber_lagged` close makes
//! the pump reconnect after [`BACKOFF_MIN`], and the connect's resync is the one refresh that
//! follows. A fifth window (`subscriber_capacity_exhausted`) and a draining daemon back off
//! quietly; a window that is not the daemon's build (`client_version_mismatch`) retries slowly,
//! since the Settings screen already says so.
//!
//! The pump knows nothing of Tauri: [`pump`] runs over a [`Connect`] (the real admin dial, or a
//! script in a test) and an [`EventSink`] (the app handle, or a collector).

use std::future::Future;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use pam_daemon::admin_transport::{self, AdminEvents};
use pam_daemon::framed::DialError;
use pam_proto::Event;
use pam_proto::wire::{EventFrame, Ingress, cause};
use serde::Serialize;
use tauri::{AppHandle, Emitter};

use crate::bridge::{BridgeError, resolve_base_dir};

/// The Tauri event channel every daemon event is forwarded on.
pub const EVENT_CHANNEL: &str = "pam://event";

/// First pause before a reconnect attempt.
pub const BACKOFF_MIN: Duration = Duration::from_millis(500);

/// Cap on the reconnect backoff.
pub const BACKOFF_MAX: Duration = Duration::from_secs(10);

/// Guard: only the first [`events_subscribe`] call spawns the task.
static SUBSCRIBER_STARTED: AtomicBool = AtomicBool::new(false);

/// The next reconnect pause: doubled, capped at [`BACKOFF_MAX`].
#[must_use]
pub fn next_backoff(current: Duration) -> Duration {
    current.saturating_mul(2).min(BACKOFF_MAX)
}

/// The `kind` of the marker the frontend treats as "refetch your lists once".
pub const RESYNC_KIND: &str = "resync";

/// The `event` member of a forwarded payload: a daemon lifecycle event, tagged by `kind` like the
/// Rust [`Event`], or the pump's own resync marker.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(untagged)]
pub enum PayloadEvent {
    /// A lifecycle event the daemon published.
    Lifecycle(Event),
    /// "Events may have been missed": the frontend refetches once. Not a daemon event.
    Resync {
        /// Always [`RESYNC_KIND`].
        kind: &'static str,
    },
}

/// What the frontend receives on [`EVENT_CHANNEL`]: the ticket and the event, plus what the daemon
/// knows about the ticket. The members after `event` are absent when the daemon has no admission
/// record for the ticket, and on a resync.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct EventPayload {
    /// The request id the event belongs to; empty on a resync.
    pub ticket: String,
    /// The lifecycle event, or the resync marker.
    pub event: PayloadEvent,
    /// The daemon-wide event counter; a skip means events were missed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub n: Option<u64>,
    /// The ticket's capability.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capability: Option<String>,
    /// The caller's repository as admitted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repo: Option<String>,
    /// The caller's self-reported agent label (attribution, not authority).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent: Option<String>,
    /// The plane the ticket was admitted on.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ingress: Option<Ingress>,
}

impl EventPayload {
    /// The "refetch once" marker.
    #[must_use]
    pub const fn resync() -> Self {
        Self {
            ticket: String::new(),
            event: PayloadEvent::Resync { kind: RESYNC_KIND },
            n: None,
            capability: None,
            repo: None,
            agent: None,
            ingress: None,
        }
    }
}

/// Turns one all-events frame into the forwarded shape; `None` for a frame with no ticket (the
/// daemon always sets it, so this is wire noise and is dropped rather than fatal).
#[must_use]
pub fn payload_from_frame(frame: EventFrame) -> Option<EventPayload> {
    Some(EventPayload {
        ticket: frame.ticket?,
        event: PayloadEvent::Lifecycle(frame.event),
        n: frame.n,
        capability: frame.capability,
        repo: frame.repo,
        agent: frame.agent,
        ingress: frame.ingress,
    })
}

/// Where forwarded payloads go: the webview, or a collector in a test.
pub trait EventSink: Send + Sync {
    /// Delivers one payload; `false` when nobody can receive it any more.
    fn emit(&self, payload: &EventPayload) -> bool;
}

impl EventSink for AppHandle {
    fn emit(&self, payload: &EventPayload) -> bool {
        Emitter::emit(self, EVENT_CHANNEL, payload).is_ok()
    }
}

/// One live all-events stream.
pub trait EventSource: Send {
    /// The next event. Any `Err` ends the stream.
    fn next_event(&mut self) -> impl Future<Output = Result<EventFrame, DialError>> + Send;
}

impl EventSource for AdminEvents {
    async fn next_event(&mut self) -> Result<EventFrame, DialError> {
        self.next().await
    }
}

/// Opens an all-events stream: the admin dial, or a script in a test.
pub trait Connect: Send + Sync {
    /// The stream this opens.
    type Source: EventSource;

    /// Dials and subscribes. Returns once the subscription is registered.
    fn connect(&self) -> impl Future<Output = Result<Self::Source, DialError>> + Send;
}

/// The real dial: the daemon's private admin socket under `base`.
#[derive(Debug, Clone)]
pub struct AdminConnect {
    base: PathBuf,
}

impl AdminConnect {
    /// A dial against the daemon whose base directory is `base`.
    #[must_use]
    pub const fn new(base: PathBuf) -> Self {
        Self { base }
    }
}

impl Connect for AdminConnect {
    type Source = AdminEvents;

    async fn connect(&self) -> Result<AdminEvents, DialError> {
        // Never starts the daemon: `daemon_status` does that, and a stream that spawned one would
        // fight a deliberate `Stop daemon`.
        admin_transport::events(&self.base).await
    }
}

/// What the pump does after one stream ends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Next {
    /// Reconnect after the running backoff.
    Backoff,
    /// The subscriber overflowed its queue: reconnect after [`BACKOFF_MIN`].
    Lagged,
    /// Nothing about this will fix itself soon (this window is not the daemon's build): retry at
    /// the cap.
    Slow,
}

/// How one stream ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionEnd {
    /// Whether any event was forwarded; feeds the backoff reset.
    pub delivered: bool,
    /// What to do next.
    pub next: Next,
}

/// What an error from the dial or the stream means for the reconnect.
#[must_use]
pub fn classify(error: &DialError) -> Next {
    match error {
        DialError::Refused(frame) => match frame.cause.as_str() {
            cause::SUBSCRIBER_LAGGED => Next::Lagged,
            cause::CLIENT_VERSION_MISMATCH | cause::PROTOCOL_MISMATCH => Next::Slow,
            // `subscriber_capacity_exhausted`, `daemon_shutting_down`, `daemon_outdated`,
            // `connection_capacity_exhausted`: the daemon is busy or on its way out.
            _ => Next::Backoff,
        },
        DialError::LegacyDaemon => Next::Slow,
        DialError::Io(_) | DialError::Protocol(_) => Next::Backoff,
    }
}

/// The pause before the next attempt and the backoff to carry forward, given how the last stream
/// ended and the backoff it ran under. A stream that delivered anything starts over from
/// [`BACKOFF_MIN`].
#[must_use]
pub fn next_pause(end: SessionEnd, backoff: Duration) -> (Duration, Duration) {
    let backoff = if end.delivered { BACKOFF_MIN } else { backoff };
    match end.next {
        Next::Backoff => (backoff, next_backoff(backoff)),
        Next::Lagged => (BACKOFF_MIN, next_backoff(BACKOFF_MIN)),
        Next::Slow => (BACKOFF_MAX, BACKOFF_MAX),
    }
}

/// One subscription's lifetime: connect, tell the frontend to refresh, and forward events until
/// the stream ends. A step in `n` (events dropped for this subscriber) asks for another refresh.
pub async fn run_session<C: Connect>(connect: &C, sink: &impl EventSink) -> SessionEnd {
    let mut source = match connect.connect().await {
        Ok(source) => source,
        Err(error) => {
            return SessionEnd {
                delivered: false,
                next: classify(&error),
            };
        }
    };
    let mut delivered = false;
    // Nothing published before the subscription was registered is replayed.
    if !sink.emit(&EventPayload::resync()) {
        return SessionEnd {
            delivered,
            next: Next::Backoff,
        };
    }
    let mut previous: Option<u64> = None;
    loop {
        match source.next_event().await {
            Ok(frame) => {
                let skipped = matches!((previous, frame.n), (Some(last), Some(n)) if n != last.wrapping_add(1));
                if frame.n.is_some() {
                    previous = frame.n;
                }
                let Some(payload) = payload_from_frame(frame) else {
                    continue;
                };
                if skipped && !sink.emit(&EventPayload::resync()) {
                    return SessionEnd {
                        delivered,
                        next: Next::Backoff,
                    };
                }
                if !sink.emit(&payload) {
                    return SessionEnd {
                        delivered,
                        next: Next::Backoff,
                    };
                }
                delivered = true;
            }
            Err(error) => {
                return SessionEnd {
                    delivered,
                    next: classify(&error),
                };
            }
        }
    }
}

/// The forever loop: stream until the connection dies, pause ([`next_pause`]), reconnect.
pub async fn pump<C: Connect, S: EventSink>(connect: C, sink: S) {
    let mut backoff = BACKOFF_MIN;
    loop {
        let end = run_session(&connect, &sink).await;
        let (pause, next) = next_pause(end, backoff);
        tokio::time::sleep(pause).await;
        backoff = next;
    }
}

/// Starts the event-forwarding task on first call; later calls are
/// no-ops. Returns whether this call started it.
#[tauri::command]
pub fn events_subscribe(app: AppHandle) -> Result<bool, BridgeError> {
    let base = resolve_base_dir()?;
    if SUBSCRIBER_STARTED.swap(true, Ordering::SeqCst) {
        return Ok(false);
    }
    tauri::async_runtime::spawn(pump(AdminConnect::new(base), app));
    Ok(true)
}
