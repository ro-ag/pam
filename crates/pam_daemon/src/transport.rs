//! Transport service: zmq `ROUTER` serving requests on `pam.sock`, zmq `PUB` broadcasting events on
//! `events.sock`. It owns both sockets and only forwards, never interpreting past envelope
//! validation. **In**: each `[identity, payload]` frame pair is parsed as a JSON [`Envelope`] and
//! forwarded to the daemon core over the `mpsc` handed to [`Transport::bind`]; a malformed one gets
//! an immediate `bad_request` [`Response::Refusal`]. **Out**: each [`IncomingRequest`] carries a
//! `oneshot` for its one [`Response`], forwarded onto a reply `mpsc` the `ROUTER` drains.
//! [`EventPublisher`] drains into the `PUB` socket as `[request-id topic, JSON event]` pairs — a
//! public broadcast: a wildcard subscriber sees opaque request IDs, lifecycle states, timing, and
//! progress percentages, and topic filters are not access control. Progress prose is replaced with
//! a constant before enqueueing; task, product, repository and evidence details require scoped
//! result reads. Shutdown is a `tokio::sync::watch` flag: [`Transport::shutdown`] flips it, joins
//! the three socket tasks, and dropping the sockets removes the `ipc` files.
//!
//! The transport takes no admission permits: the dispatcher
//! ([`crate::daemon`]) is the single admission point, and it classifies requests through
//! [`crate::policy::admission_pool`]. A per-request forwarder lives exactly as long as that
//! request's `oneshot`, which the dispatcher's reply guard always resolves, so forwarders are
//! bounded by the dispatcher's own pools plus the ingress channel.
//!
//! [`EventPublisher`] itself lives in [`crate::event_hub`] and is re-exported here: services
//! publish into the daemon's one event hub, and the `PUB` loop is one of the hub's sinks, fed the
//! same sanitised `(request id, event)` pairs it always carried. [`Transport::bind_with`] is the
//! daemon's entry point and takes what the framed public listener needs (store, lifecycle phase,
//! hub, boot image); that listener is served next to this one until the `ZeroMQ` sockets are
//! removed. [`Transport::bind`] keeps the old signature over a hub of its own.

use std::io;
use std::path::PathBuf;
use std::sync::Arc;

use pam_proto::{Envelope, Event, Response};
use pam_store::Store;
use thiserror::Error;
use tokio::sync::{mpsc, oneshot, watch};
use tokio::task::JoinHandle;
use zeromq::{
    PubSocket, RouterRecvHalf, RouterSendHalf, RouterSocket, Socket, SocketRecv, SocketSend,
    ZmqMessage,
};

use crate::event_hub::{EventHub, LEGACY_SINK_CAPACITY};
pub use crate::event_hub::{EventPublisher, PUBLIC_PROGRESS_NOTE, PublishError};
use crate::image::ImageWatch;
use crate::ingress::{Origin, PublicPeer};
use crate::lifecycle::LifecyclePhase;
use crate::runtime_dir::{RuntimeDir, remove_stale};

/// Capacity of the internal reply channel.
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

/// A validated request received from a client.
///
/// The daemon core answers by sending exactly one [`Response`] into
/// `reply`; the dispatcher's reply guard makes sure it always does.
#[derive(Debug)]
pub struct IncomingRequest {
    /// zmq routing identity of the requesting peer.
    pub identity: Vec<u8>,
    /// Which plane the request arrived on (see [`crate::ingress`]).
    pub origin: Origin,
    /// The connection the request arrived on, as the framed public listener
    /// saw it; `None` for the `ZeroMQ` listener and for requests the
    /// administration plane submits.
    pub peer: Option<PublicPeer>,
    /// The parsed request envelope.
    pub envelope: Envelope,
    /// Channel for this request's single response.
    pub reply: oneshot::Sender<Response>,
}

/// Running transport service: both sockets bound, tasks pumping.
#[derive(Debug)]
pub struct Transport {
    hub: Arc<EventHub>,
    shutdown: watch::Sender<bool>,
    tasks: Vec<JoinHandle<()>>,
}

impl Transport {
    /// Removes stale socket files, binds `ROUTER` and `PUB` under `dirs`,
    /// and starts the socket tasks. Valid requests arrive on `incoming`.
    /// Events go through an event hub of the transport's own.
    pub async fn bind(
        dirs: &RuntimeDir,
        incoming: mpsc::Sender<IncomingRequest>,
    ) -> Result<Self, TransportError> {
        Self::bind_legacy(dirs, incoming, EventHub::new()).await
    }

    /// [`Self::bind`] for the daemon: events go through the daemon's `hub`,
    /// and `store`, `phase` and `image` are what the framed public listener
    /// on [`RuntimeDir::public_socket`] serves from.
    pub async fn bind_with(
        dirs: &RuntimeDir,
        incoming: mpsc::Sender<IncomingRequest>,
        store: Arc<Store>,
        phase: watch::Sender<LifecyclePhase>,
        hub: Arc<EventHub>,
        image: Arc<ImageWatch>,
    ) -> Result<Self, TransportError> {
        // The framed public listener starts here from these; until it does
        // the daemon serves the legacy sockets only.
        let _ = (store, phase, image);
        Self::bind_legacy(dirs, incoming, hub).await
    }

    /// Binds the `ZeroMQ` sockets and makes the `PUB` loop a sink of `hub`.
    async fn bind_legacy(
        dirs: &RuntimeDir,
        incoming: mpsc::Sender<IncomingRequest>,
        hub: Arc<EventHub>,
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
        let (event_tx, event_rx) = mpsc::channel(LEGACY_SINK_CAPACITY);
        hub.set_legacy_sink(event_tx);

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
            hub,
            shutdown: shutdown_tx,
            tasks,
        })
    }

    /// A new handle for publishing events.
    #[must_use]
    pub fn event_publisher(&self) -> EventPublisher {
        self.hub.publisher()
    }

    /// Signals the socket tasks to stop, waits for them to finish and closes
    /// the event hub: a publish after this errors.
    pub async fn shutdown(self) {
        let _ = self.shutdown.send(true);
        for task in self.tasks {
            let _ = task.await;
        }
        self.hub.close();
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
        handle_frames(message, &incoming, &reply_tx).await;
    }
}

async fn handle_frames(
    message: ZmqMessage,
    incoming: &mpsc::Sender<IncomingRequest>,
    reply_tx: &mpsc::Sender<(Vec<u8>, Response)>,
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
            if !envelope_within_limits(&envelope) {
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
            let (tx, rx) = oneshot::channel();
            let request = IncomingRequest {
                identity: identity.clone(),
                origin: Origin::Public,
                peer: None,
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

/// Whether the envelope's identity and scope fields fit their ceilings: a
/// non-empty id of at most 128 bytes; capability, client version, agent label
/// and idempotency key of at most 128 bytes each; a repository spelling of at
/// most 4,096 bytes. Checked before anything is retained.
pub(crate) fn envelope_within_limits(envelope: &Envelope) -> bool {
    !envelope.id.is_empty()
        && envelope.id.len() <= 128
        && envelope.capability.len() <= 128
        && envelope.client_version.len() <= 128
        && envelope.caller.agent.len() <= 128
        && envelope.caller.repo.len() <= 4096
        && envelope
            .idempotency_key
            .as_ref()
            .is_none_or(|key| key.len() <= 128)
}

/// Builds the immediate refusal for a payload the transport cannot parse.
pub(crate) fn bad_request(id: String, detail: &str) -> Response {
    Response::Refusal {
        retryable: false,
        id,
        cause: "bad_request".to_owned(),
        detail: detail.to_owned(),
        recovery: "Upgrade pam and the pam GUI to matching versions, then retry from the GUI."
            .to_owned(),
    }
}

/// Best-effort extraction of the request id from an unparseable envelope,
/// so the refusal can still name the request it answers.
pub(crate) fn salvage_request_id(payload: &[u8]) -> String {
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
        retryable: false,
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
