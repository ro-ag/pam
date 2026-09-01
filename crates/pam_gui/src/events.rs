//! The event stream: one long-lived task subscribing to the daemon's
//! `events.sock` `PUB` socket on **all** topics (empty prefix) and
//! forwarding every event to the frontend as a Tauri event.
//!
//! # Design
//!
//! - **Lazy, singleton.** Nothing runs until the frontend calls the
//!   [`events_subscribe`] command once; an atomic guard makes later
//!   calls no-ops, so exactly one subscriber task exists per GUI
//!   process. The frontend listens with `@tauri-apps/api/event`'s
//!   `listen` on [`EVENT_CHANNEL`].
//! - **Resilient.** `PUB` has no replay and the daemon restarts on its
//!   own (drain/respawn on version handshake, `daemon_stop` from the
//!   GUI). The task reconnects forever: every stream failure — connect
//!   refused, socket closed, an idle stretch during which the daemon's
//!   instance lock turned out to be free — tears the subscription down
//!   and retries with exponential backoff ([`next_backoff`], capped),
//!   reset after any successfully forwarded event.
//! - **Payload.** `PUB` frames are `[topic, payload]` with the ticket as
//!   topic; the forwarded shape is `{ ticket, event }`
//!   ([`decode_event_frames`]). Undecodable frames are dropped — noise
//!   on the wire must not kill the stream.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use pam_client::client::{self, DaemonStatus};
use pam_daemon::runtime_dir::RuntimeDir;
use pam_proto::Event;
use serde::Serialize;
use tauri::{AppHandle, Emitter};
use zeromq::{Socket, SocketRecv, SubSocket};

use crate::bridge::{BridgeError, resolve_base_dir};

/// The Tauri event channel every daemon event is forwarded on.
pub const EVENT_CHANNEL: &str = "pam://event";

/// First pause before a reconnect attempt.
pub const BACKOFF_MIN: Duration = Duration::from_millis(500);

/// Cap on the reconnect backoff.
pub const BACKOFF_MAX: Duration = Duration::from_secs(10);

/// With no event for this long, the daemon lock is probed; a free lock
/// means the connection is stale (the daemon is gone) and the stream
/// reconnects instead of trusting a silent socket forever.
const IDLE_RECHECK: Duration = Duration::from_secs(30);

/// Guard: only the first [`events_subscribe`] call spawns the task.
static SUBSCRIBER_STARTED: AtomicBool = AtomicBool::new(false);

/// The next reconnect pause: doubled, capped at [`BACKOFF_MAX`].
#[must_use]
pub fn next_backoff(current: Duration) -> Duration {
    current.saturating_mul(2).min(BACKOFF_MAX)
}

/// What the frontend receives on [`EVENT_CHANNEL`]: the ticket (the
/// `PUB` topic) and the event itself.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct EventPayload {
    /// The request id the event belongs to.
    pub ticket: String,
    /// The lifecycle event.
    pub event: Event,
}

/// Decodes one `PUB` message (`[topic, payload]` frames) into the
/// forwarded shape; `None` for anything malformed.
#[must_use]
pub fn decode_event_frames<T: AsRef<[u8]>>(frames: &[T]) -> Option<EventPayload> {
    let topic = frames.first()?;
    let payload = frames.get(1)?;
    let event: Event = serde_json::from_slice(payload.as_ref()).ok()?;
    Some(EventPayload {
        ticket: String::from_utf8_lossy(topic.as_ref()).into_owned(),
        event,
    })
}

/// Starts the event-forwarding task on first call; later calls are
/// no-ops. Returns whether this call started it.
#[tauri::command]
pub fn events_subscribe(app: AppHandle) -> Result<bool, BridgeError> {
    let base = resolve_base_dir()?;
    if SUBSCRIBER_STARTED.swap(true, Ordering::SeqCst) {
        return Ok(false);
    }
    tauri::async_runtime::spawn(pump_events(app, base));
    Ok(true)
}

/// The forever loop: stream until the connection dies, back off,
/// reconnect. Backoff resets whenever a stream forwarded something.
async fn pump_events(app: AppHandle, base: PathBuf) {
    let mut backoff = BACKOFF_MIN;
    loop {
        if stream_events(&app, &base).await {
            backoff = BACKOFF_MIN;
        }
        tokio::time::sleep(backoff).await;
        backoff = next_backoff(backoff);
    }
}

/// One subscription's lifetime: connect, subscribe to every topic, and
/// forward events until the stream fails or goes stale. Returns whether
/// any event was forwarded (feeds the backoff reset).
async fn stream_events(app: &AppHandle, base: &Path) -> bool {
    let mut delivered = false;
    let Ok(dirs) = RuntimeDir::at_base(base) else {
        return delivered;
    };
    let mut sub = SubSocket::new();
    if sub.connect(&dirs.events_endpoint()).await.is_err() {
        return delivered;
    }
    // Empty prefix: every topic, i.e. every ticket's events.
    if sub.subscribe("").await.is_err() {
        return delivered;
    }
    loop {
        match tokio::time::timeout(IDLE_RECHECK, sub.recv()).await {
            Ok(Ok(message)) => {
                if let Some(payload) = decode_event_frames(&message.into_vec()) {
                    if app.emit(EVENT_CHANNEL, &payload).is_err() {
                        return delivered;
                    }
                    delivered = true;
                }
            }
            Ok(Err(_closed)) => return delivered,
            Err(_idle) => {
                // Quiet is normal; a quiet socket with no daemon behind
                // it is not.
                let alive = matches!(client::probe_daemon(base), Ok(DaemonStatus::Running { .. }));
                if !alive {
                    return delivered;
                }
            }
        }
    }
}
