//! Transport service: zmq `ROUTER` serving requests on `pam.sock`, zmq
//! `PUB` broadcasting events on `events.sock`.
//!
//! # Design
//!
//! The transport owns both sockets and forwards in two directions only —
//! it never interprets a request beyond envelope validation:
//!
//! - **Requests in**: the `ROUTER` receive half runs in a task. Each frame
//!   pair `[identity, payload]` is parsed as a JSON [`Envelope`]; a valid
//!   one is forwarded to the daemon core over the `mpsc` channel handed to
//!   [`Transport::bind`], a malformed one is answered immediately with a
//!   `bad_request` [`Response::Refusal`].
//! - **Replies out**: every [`IncomingRequest`] carries a `oneshot` sender
//!   for its single [`Response`]. A small per-request forwarding task
//!   awaits the `oneshot` and pushes `(identity, response)` onto an
//!   internal reply `mpsc`; the `ROUTER` send half drains that channel.
//!   The forwarder exits quietly when the daemon core drops the `oneshot`
//!   without answering.
//! - **Events out**: [`EventPublisher`] is a clone-able handle over an
//!   `mpsc`; a task owning the `PUB` socket drains it, sending
//!   `[request-id topic, JSON event]` frame pairs.
//!
//! Shutdown is a `tokio::sync::watch` flag: [`Transport::shutdown`] flips
//! it and joins the three socket tasks; dropping the sockets closes the
//! binds and removes the `ipc` files.

use std::io;
use std::path::PathBuf;

use pam_proto::{Envelope, Event, Response};
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::{Semaphore, mpsc, oneshot, watch};
use tokio::task::JoinHandle;
use zeromq::{
    PubSocket, RouterRecvHalf, RouterSendHalf, RouterSocket, Socket, SocketRecv, SocketSend,
    ZmqMessage,
};

use crate::runtime_dir::{RuntimeDir, remove_stale};

/// Capacity of the internal reply and event channels.
const CHANNEL_CAPACITY: usize = 256;

/// Why the transport could not start.
#[derive(Debug, Error)]
pub enum TransportError {
    /// A stale socket file could not be removed before binding.
    #[error("cannot remove stale socket file {}: {source}", path.display())]
    RemoveStale {
        /// The socket file that could not be removed.
        path: PathBuf,
        /// The underlying I/O error.
        #[source]
        source: io::Error,
    },
    /// Binding a socket failed.
    #[error("cannot bind {endpoint}: {source}")]
    Bind {
        /// The `ipc://` endpoint that failed to bind.
        endpoint: String,
        /// The underlying zmq error.
        #[source]
        source: zeromq::ZmqError,
    },
}

/// The transport was shut down; the event was dropped.
#[derive(Debug, Error)]
#[error("transport is shut down; event dropped")]
pub struct PublishError;

/// A validated request received from a client.
///
/// The daemon core answers by sending exactly one [`Response`] into
/// `reply`; dropping it unanswered leaves the client to its own deadline.
#[derive(Debug)]
pub struct IncomingRequest {
    /// zmq routing identity of the requesting peer.
    pub identity: Vec<u8>,
    /// The parsed request envelope.
    pub envelope: Envelope,
    /// Channel for this request's single response.
    pub reply: oneshot::Sender<Response>,
}

/// Clone-able handle daemon services use to broadcast lifecycle events.
#[derive(Debug, Clone)]
pub struct EventPublisher {
    tx: mpsc::Sender<(String, Event)>,
}

impl EventPublisher {
    /// A publisher over a bare channel, for in-crate unit tests that
    /// need to observe published events without binding real sockets.
    #[cfg(test)]
    pub(crate) fn for_tests() -> (Self, mpsc::Receiver<(String, Event)>) {
        let (tx, rx) = mpsc::channel(CHANNEL_CAPACITY);
        (Self { tx }, rx)
    }

    /// Best-effort notification: queue the event or drop it when slow peers
    /// have filled the bounded queue. Authoritative results remain in Store;
    /// subscribers reconcile missed terminal events through `query`.
    ///
    /// The ready future preserves callers' awaitable API without letting a
    /// notification delay request completion, cancellation or administration.
    pub fn publish(
        &self,
        request_id: &str,
        event: Event,
    ) -> std::future::Ready<Result<(), PublishError>> {
        let result = match self.tx.try_send((request_id.to_owned(), event)) {
            Ok(()) | Err(mpsc::error::TrySendError::Full(_)) => Ok(()),
            Err(mpsc::error::TrySendError::Closed(_)) => Err(PublishError),
        };
        std::future::ready(result)
    }
}

/// Running transport service: both sockets bound, tasks pumping.
#[derive(Debug)]
pub struct Transport {
    events: EventPublisher,
    shutdown: watch::Sender<bool>,
    tasks: Vec<JoinHandle<()>>,
}

impl Transport {
    /// Removes stale socket files, binds `ROUTER` and `PUB` under `dirs`,
    /// and starts the socket tasks. Valid requests arrive on `incoming`.
    pub async fn bind(
        dirs: &RuntimeDir,
        incoming: mpsc::Sender<IncomingRequest>,
    ) -> Result<Self, TransportError> {
        for path in [dirs.router_socket(), dirs.events_socket()] {
            remove_stale(path).map_err(|source| TransportError::RemoveStale {
                path: path.to_path_buf(),
                source,
            })?;
        }

        let mut router = RouterSocket::new();
        bind_socket(&mut router, &dirs.router_endpoint()).await?;
        let mut pub_socket = PubSocket::new();
        bind_socket(&mut pub_socket, &dirs.events_endpoint()).await?;

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let (reply_tx, reply_rx) = mpsc::channel(CHANNEL_CAPACITY);
        let (event_tx, event_rx) = mpsc::channel(CHANNEL_CAPACITY);

        let (send_half, recv_half) = router.split();
        let tasks = vec![
            tokio::spawn(recv_loop(
                recv_half,
                incoming,
                reply_tx,
                shutdown_rx.clone(),
            )),
            tokio::spawn(reply_loop(send_half, reply_rx, shutdown_rx.clone())),
            tokio::spawn(publish_loop(pub_socket, event_rx, shutdown_rx)),
        ];

        Ok(Self {
            events: EventPublisher { tx: event_tx },
            shutdown: shutdown_tx,
            tasks,
        })
    }

    /// A new handle for publishing events.
    #[must_use]
    pub fn event_publisher(&self) -> EventPublisher {
        self.events.clone()
    }

    /// Signals the socket tasks to stop and waits for them to finish.
    pub async fn shutdown(self) {
        let _ = self.shutdown.send(true);
        drop(self.events);
        for task in self.tasks {
            let _ = task.await;
        }
    }
}

async fn bind_socket<S: Socket>(socket: &mut S, endpoint: &str) -> Result<(), TransportError> {
    socket
        .bind(endpoint)
        .await
        .map(|_| ())
        .map_err(|source| TransportError::Bind {
            endpoint: endpoint.to_owned(),
            source,
        })
}

/// Resolves when the shutdown flag flips to `true`.
async fn signalled(shutdown: &mut watch::Receiver<bool>) {
    // An error means the `Transport` (sender) is gone: treat as shutdown.
    let _ = shutdown.wait_for(|stop| *stop).await;
}

async fn recv_loop(
    mut router: RouterRecvHalf,
    incoming: mpsc::Sender<IncomingRequest>,
    reply_tx: mpsc::Sender<(Vec<u8>, Response)>,
    mut shutdown: watch::Receiver<bool>,
) {
    let work_replies = Arc::new(Semaphore::new(128));
    let control_replies = Arc::new(Semaphore::new(16));
    loop {
        let message = tokio::select! {
            () = signalled(&mut shutdown) => break,
            received = router.recv() => match received {
                Ok(message) => message,
                // `recv` only fails when the socket is torn down.
                Err(error) => {
                    tracing::warn!(%error, "router receive loop ended");
                    break;
                }
            },
        };
        handle_frames(
            message,
            &incoming,
            &reply_tx,
            &work_replies,
            &control_replies,
        )
        .await;
    }
}

async fn handle_frames(
    message: ZmqMessage,
    incoming: &mpsc::Sender<IncomingRequest>,
    reply_tx: &mpsc::Sender<(Vec<u8>, Response)>,
    work_replies: &Arc<Semaphore>,
    control_replies: &Arc<Semaphore>,
) {
    // `ROUTER` prepends the peer identity, so a well-formed request is
    // exactly [identity, payload].
    let frames = message.into_vec();
    let Some(identity) = frames.first().map(|frame| frame.to_vec()) else {
        return;
    };
    if frames.len() != 2 {
        let refusal = bad_request(
            "unknown".to_owned(),
            &format!("expected one payload frame, got {}", frames.len() - 1),
        );
        let _ = reply_tx.send((identity, refusal)).await;
        return;
    }
    let payload = &frames[1];

    if payload.len() > 1024 * 1024 {
        let _ = reply_tx
            .send((
                identity,
                bad_request("unknown".to_owned(), "request payload exceeds 1 MiB"),
            ))
            .await;
        return;
    }
    match serde_json::from_slice::<Envelope>(payload) {
        Ok(envelope) => {
            if envelope.id.is_empty()
                || envelope.id.len() > 128
                || envelope.capability.len() > 128
                || envelope.caller.agent.len() > 128
                || envelope.caller.repo.len() > 4096
                || envelope
                    .idempotency_key
                    .as_ref()
                    .is_some_and(|key| key.len() > 128)
            {
                let _ = reply_tx
                    .send((
                        identity,
                        bad_request(
                            "unknown".to_owned(),
                            "request identity or scope fields exceed their limits",
                        ),
                    ))
                    .await;
                return;
            }
            let slots = if matches!(envelope.capability.as_str(), "status" | "query" | "cancel") {
                control_replies
            } else {
                work_replies
            };
            let Ok(permit) = Arc::clone(slots).try_acquire_owned() else {
                let response = Response::Refusal {
                    id: envelope.id,
                    cause: "request_capacity_exhausted".to_owned(),
                    detail: "PAM has reached its waiting reply limit".to_owned(),
                    recovery: "Wait for work to finish or cancel an existing request".to_owned(),
                };
                let _ = reply_tx.send((identity, response)).await;
                return;
            };
            let (tx, rx) = oneshot::channel();
            let request = IncomingRequest {
                identity: identity.clone(),
                envelope,
                reply: tx,
            };
            if incoming.send(request).await.is_err() {
                // The daemon core is gone; nothing can answer any more.
                return;
            }
            // Per-request forwarder: bridge the oneshot reply back onto
            // the ROUTER send half via the shared reply channel.
            let reply_tx = reply_tx.clone();
            tokio::spawn(async move {
                let _permit = permit;
                if let Ok(response) = rx.await {
                    let _ = reply_tx.send((identity, response)).await;
                }
            });
        }
        Err(err) => {
            let refusal = bad_request(
                salvage_request_id(payload),
                &format!("cannot parse request envelope: {err}"),
            );
            let _ = reply_tx.send((identity, refusal)).await;
        }
    }
}

/// Builds the immediate refusal for a payload the transport cannot parse.
fn bad_request(id: String, detail: &str) -> Response {
    Response::Refusal {
        id,
        cause: "bad_request".to_owned(),
        detail: detail.to_owned(),
        recovery: "Upgrade pam and the pam GUI to matching versions, then retry from the GUI."
            .to_owned(),
    }
}

/// Best-effort extraction of the request id from an unparseable envelope,
/// so the refusal can still name the request it answers.
fn salvage_request_id(payload: &[u8]) -> String {
    serde_json::from_slice::<serde_json::Value>(payload)
        .ok()
        .as_ref()
        .and_then(|value| value.get("id"))
        .and_then(serde_json::Value::as_str)
        .map_or_else(|| "unknown".to_owned(), str::to_owned)
}

async fn reply_loop(
    mut router: RouterSendHalf,
    mut reply_rx: mpsc::Receiver<(Vec<u8>, Response)>,
    mut shutdown: watch::Receiver<bool>,
) {
    loop {
        let (identity, response) = tokio::select! {
            () = signalled(&mut shutdown) => break,
            item = reply_rx.recv() => match item {
                Some(item) => item,
                None => break,
            },
        };
        let Ok(payload) = bounded_response(&response) else {
            continue;
        };
        let mut message = ZmqMessage::from(identity);
        message.push_back(payload.into());
        // A send failure means the peer already disconnected; it has no
        // address to be told at, so the response is dropped.
        let request_id = match &response {
            Response::Result { id, .. }
            | Response::Refusal { id, .. }
            | Response::Ticket { id, .. } => id,
        };
        if let Err(error) = router.send(message).await {
            tracing::debug!(request_id, %error, "router reply send failed");
        }
    }
}

async fn publish_loop(
    mut pub_socket: PubSocket,
    mut event_rx: mpsc::Receiver<(String, Event)>,
    mut shutdown: watch::Receiver<bool>,
) {
    loop {
        let (topic, event) = tokio::select! {
            () = signalled(&mut shutdown) => break,
            item = event_rx.recv() => match item {
                Some(item) => item,
                None => break,
            },
        };
        let Ok(payload) = serde_json::to_vec(&event) else {
            continue;
        };
        let mut message = ZmqMessage::from(topic);
        message.push_back(payload.into());
        // zeromq's PUB send awaits slow peers. Notifications must not keep
        // shutdown waiting for an abandoned subscriber to read its socket.
        tokio::select! {
            () = signalled(&mut shutdown) => break,
            _ = pub_socket.send(message) => {}
        }
    }
}

/// Encode through a bounded writer, so oversized replies cannot allocate a
/// second unbounded copy or leave the caller waiting on a dropped wire frame.
pub(crate) fn bounded_response(response: &Response) -> Result<Vec<u8>, serde_json::Error> {
    struct Writer(Vec<u8>);
    impl std::io::Write for Writer {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if bytes.len() > (1024 * 1024_usize).saturating_sub(self.0.len()) {
                return Err(std::io::Error::other("response budget exhausted"));
            }
            self.0.extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut writer = Writer(Vec::new());
    if serde_json::to_writer(&mut writer, response).is_ok() {
        return Ok(writer.0);
    }
    let (Response::Result { id, .. } | Response::Refusal { id, .. } | Response::Ticket { id, .. }) =
        response;
    serde_json::to_vec(&Response::Refusal {
        id: if id.len() <= 128 {
            id.clone()
        } else {
            "unknown".to_owned()
        },
        cause: "response_budget_exhausted".to_owned(),
        detail: "The response exceeds the public 1 MiB transport limit; evidence remains in PAM"
            .to_owned(),
        recovery: "Request a bounded evidence range or inspect the ticket in PAM".to_owned(),
    })
}
