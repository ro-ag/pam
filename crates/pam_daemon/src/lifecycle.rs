use std::{
    collections::HashMap,
    fmt,
    fs::{self, OpenOptions},
    future::Future,
    io::Write,
    path::{Path, PathBuf},
    pin::Pin,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use pam_core::{APPLICATION_VERSION, EvidenceHandle, ProjectId, RequestId};
use pam_platform::{
    IncomingRequest, LocalEndpoint, ServerTransport, TransportError, TransportErrorKind,
    user_data_dir,
};
use pam_protocol::{
    BriefProvenance, BriefResult, CancellationDisposition, CancellationResult, Capability,
    CodecError, Event, EventEnvelope, EvidenceChunk, EvidenceMetadata, EvidenceRedaction,
    EvidenceRetention, Failure, FailureCode, OperationTruth, PROTOCOL_VERSION, ReplayResult,
    RequestEnvelope, RequestPayload, ResultBody, ResultEnvelope, ResultPayload, ServerMessage,
    SourceAvailability, StatusResult, decode_request_envelope, decode_server_message, encode,
};
use pam_store::{
    AcceptOutcome, AcceptRequest, CancelOutcome, EventRecord, LeasedRequest, Replay, RequestState,
    Store, StoreError, TerminalState,
};
use tokio::{
    sync::{mpsc, oneshot},
    task::JoinSet,
};

use crate::DaemonError;
use crate::ptrack::PtrackBriefProvider;

const RESPONSE_CAPACITY: usize = 64;
const SCHEDULER_CAPACITY: usize = 64;
const LEASE_DURATION: Duration = Duration::from_secs(3);
const LEASE_HEARTBEAT: Duration = Duration::from_secs(1);
const RECOVERY_INTERVAL: Duration = Duration::from_millis(50);
// UUIDs and current semantic IDs fit comfortably; this also leaves ample room for
// a maximum evidence chunk and its response envelope in the 1 MiB protocol frame.
const MAX_REQUEST_IDENTIFIER_BYTES: usize = 256;
const MAX_BRIEF_SECTION_ITEMS: usize = 16;
const MAX_BRIEF_PROVENANCE_ITEMS: usize = 32;
const MAX_BRIEF_TEXT_BYTES: usize = 4 * 1024;
const MAX_BRIEF_EVIDENCE_HANDLES: usize = 4;
const MAX_BRIEF_SOURCE_BYTES: usize = 256;
const MAX_BRIEF_DETAIL_BYTES: usize = 4 * 1024;

enum Outbound {
    Routed {
        incoming: IncomingRequest,
        messages: Vec<ServerMessage>,
        subscribe: Option<SubscriptionRequest>,
        registered: Option<oneshot::Sender<()>>,
    },
    Persisted {
        request_id: RequestId,
        messages: Vec<ServerMessage>,
        terminal: bool,
    },
}

struct SubscriptionRequest {
    canonical_request_id: RequestId,
    event_request_id: RequestId,
    observer_request_id: RequestId,
    project_id: ProjectId,
    last_sequence: u64,
}

struct Subscription {
    incoming: IncomingRequest,
    event_request_id: RequestId,
    observer_request_id: RequestId,
    project_id: ProjectId,
    last_sequence: u64,
}

#[derive(Clone, Debug)]
pub struct DaemonConfig {
    pub endpoint: LocalEndpoint,
    pub recover: bool,
    /// Overrides the durable `SQLite` path, primarily for isolated tests.
    pub state_path: Option<PathBuf>,
    /// Supplies planning context for read-only brief requests.
    pub brief_provider: Option<Arc<dyn BriefProvider>>,
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            endpoint: LocalEndpoint::default_for_user(),
            recover: false,
            state_path: None,
            brief_provider: None,
        }
    }
}

/// Provider-neutral seam for planning-context integrations.
///
/// Providers must represent source failures and partial availability explicitly in
/// [`BriefResult::provenance`]; an unavailable source is not an empty verified one.
/// Results are bounded to 16 items per section, 32 provenance entries, 4 KiB per
/// item/detail, 256 bytes per source name, and 4 evidence handles per item.
pub trait BriefProvider: fmt::Debug + Send + Sync {
    fn brief<'a>(
        &'a self,
        project_id: &'a ProjectId,
        store: &'a Store,
    ) -> Pin<Box<dyn Future<Output = BriefResult> + Send + 'a>>;
}

#[derive(Debug)]
struct UnavailableBriefProvider;

impl BriefProvider for UnavailableBriefProvider {
    fn brief<'a>(
        &'a self,
        _project_id: &'a ProjectId,
        _store: &'a Store,
    ) -> Pin<Box<dyn Future<Output = BriefResult> + Send + 'a>> {
        Box::pin(async {
            BriefResult {
                goal: None,
                decisions: Vec::new(),
                verified: Vec::new(),
                next: Vec::new(),
                provenance: vec![BriefProvenance {
                    source: "planning-context".to_owned(),
                    availability: SourceAvailability::Unavailable,
                    truth: OperationTruth::Unresolved,
                    evidence: None,
                    detail: Some("No planning-context provider is configured.".to_owned()),
                }],
            }
        })
    }
}

/// Runs the foreground daemon until an operating-system shutdown signal arrives.
///
/// # Errors
///
/// Returns [`DaemonError`] when ownership, durable state, endpoint preparation,
/// transport, or protocol handling fails.
pub async fn run(recover: bool) -> Result<(), DaemonError> {
    let brief_provider = std::env::current_dir()
        .ok()
        .and_then(|directory| {
            pam_platform::discover_project(&directory)
                .ok()
                .map(|project| {
                    Arc::new(PtrackBriefProvider::new(
                        project.root().to_path_buf(),
                        project.id().clone(),
                    ))
                })
        })
        .map(|provider| provider as Arc<dyn BriefProvider>);
    let config = DaemonConfig {
        recover,
        brief_provider,
        ..DaemonConfig::default()
    };
    serve_until(config, async {
        let _ = tokio::signal::ctrl_c().await;
    })
    .await
}

/// Serves requests until the supplied shutdown future resolves.
///
/// # Errors
///
/// Returns [`DaemonError`] when ownership, durable state, endpoint preparation,
/// transport, or protocol handling fails.
pub async fn serve_until<F>(config: DaemonConfig, shutdown: F) -> Result<(), DaemonError>
where
    F: Future<Output = ()> + Send,
{
    serve_until_with_delay(config, shutdown, Duration::ZERO).await
}

pub(super) async fn serve_until_with_delay<F>(
    config: DaemonConfig,
    shutdown: F,
    processing_delay: Duration,
) -> Result<(), DaemonError>
where
    F: Future<Output = ()> + Send,
{
    let ownership = Ownership::acquire(&config.endpoint)?;
    prepare_endpoint(&config)?;
    let state_path = match &config.state_path {
        Some(path) => path.clone(),
        None => user_data_dir()?.join("state.sqlite3"),
    };
    let store = Store::open(state_path)?;
    store.recover_all_leases(now_ms()).await?;
    let brief_provider = config
        .brief_provider
        .clone()
        .unwrap_or_else(|| Arc::new(UnavailableBriefProvider));
    let mut server = ServerTransport::bind(&config.endpoint).await?;
    let (outbound_tx, mut outbound_rx) = mpsc::channel::<Outbound>(RESPONSE_CAPACITY);
    let (scheduler_tx, scheduler_rx) = mpsc::channel::<()>(SCHEDULER_CAPACITY);
    let mut handlers = JoinSet::new();
    let mut scheduler = tokio::spawn(run_scheduler(
        store.clone(),
        scheduler_rx,
        outbound_tx.clone(),
        processing_delay,
    ));
    let mut subscriptions = HashMap::<RequestId, Vec<Subscription>>::new();

    println!("PAM daemon ready (version {APPLICATION_VERSION}, protocol {PROTOCOL_VERSION}).");

    let _ = scheduler_tx.try_send(());
    tokio::pin!(shutdown);
    let result = loop {
        let action = tokio::select! {
            () = &mut shutdown => ServeAction::Shutdown,
            incoming = server.receive() => ServeAction::Incoming(incoming),
            outbound = outbound_rx.recv() => ServeAction::Outbound(outbound),
            completed = handlers.join_next(), if !handlers.is_empty() => {
                ServeAction::HandlerCompleted(completed)
            }
            completed = &mut scheduler => ServeAction::SchedulerCompleted(completed),
        };

        match action {
            ServeAction::Shutdown
            | ServeAction::Outbound(None)
            | ServeAction::SchedulerCompleted(Ok(Ok(()))) => break Ok(()),
            ServeAction::Incoming(Ok(incoming)) => {
                let request_store = store.clone();
                let request_outbound = outbound_tx.clone();
                let request_scheduler = scheduler_tx.clone();
                let request_brief_provider = Arc::clone(&brief_provider);
                handlers.spawn(async move {
                    handle_incoming(
                        incoming,
                        request_store,
                        request_outbound,
                        request_scheduler,
                        request_brief_provider,
                    )
                    .await
                });
            }
            ServeAction::Incoming(Err(error))
                if matches!(
                    error.kind(),
                    TransportErrorKind::InvalidMessage | TransportErrorKind::FrameTooLarge
                ) => {}
            ServeAction::Incoming(Err(error)) => break Err(error.into()),
            ServeAction::Outbound(Some(outbound)) => {
                if let Err(error) =
                    deliver_outbound(&mut server, &mut subscriptions, outbound).await
                {
                    break Err(error);
                }
            }
            ServeAction::HandlerCompleted(Some(Err(error)))
            | ServeAction::SchedulerCompleted(Err(error)) => {
                break Err(DaemonError::Handler(error));
            }
            ServeAction::HandlerCompleted(Some(Ok(Err(error))))
            | ServeAction::SchedulerCompleted(Ok(Err(error))) => break Err(error),
            ServeAction::HandlerCompleted(Some(Ok(Ok(()))) | None) => {}
        }
    };

    handlers.abort_all();
    while handlers.join_next().await.is_some() {}
    drop(scheduler_tx);
    scheduler.abort();
    let _ = scheduler.await;
    drop(outbound_tx);
    server.close().await?;
    store.shutdown().await?;
    drop(ownership);
    result
}

async fn deliver_outbound(
    server: &mut ServerTransport,
    subscriptions: &mut HashMap<RequestId, Vec<Subscription>>,
    outbound: Outbound,
) -> Result<(), DaemonError> {
    match outbound {
        Outbound::Routed {
            incoming,
            messages,
            subscribe,
            registered,
        } => {
            if send_messages(server, &incoming, &messages).await?
                && let Some(subscription) = subscribe
            {
                subscriptions
                    .entry(subscription.canonical_request_id)
                    .or_default()
                    .push(Subscription {
                        incoming,
                        event_request_id: subscription.event_request_id,
                        observer_request_id: subscription.observer_request_id,
                        project_id: subscription.project_id,
                        last_sequence: subscription.last_sequence,
                    });
            }
            if let Some(registered) = registered {
                let _ = registered.send(());
            }
        }
        Outbound::Persisted {
            request_id,
            messages,
            terminal,
        } => {
            let mut remove_request = false;
            if let Some(observers) = subscriptions.get_mut(&request_id) {
                let mut retained = Vec::with_capacity(observers.len());
                for mut observer in observers.drain(..) {
                    let filtered = messages_for_observer(&messages, &mut observer);
                    if send_messages(server, &observer.incoming, &filtered).await? && !terminal {
                        retained.push(observer);
                    }
                }
                *observers = retained;
                remove_request = observers.is_empty();
            }
            if remove_request {
                subscriptions.remove(&request_id);
            }
        }
    }
    Ok(())
}

async fn send_messages(
    server: &mut ServerTransport,
    incoming: &IncomingRequest,
    messages: &[ServerMessage],
) -> Result<bool, DaemonError> {
    for message in messages {
        let payload = match encode(message) {
            Ok(payload) => payload,
            Err(CodecError::FrameTooLarge { .. }) => {
                let fallback = oversized_response_failure(message);
                let Ok(payload) = encode(&fallback) else {
                    return Ok(false);
                };
                if let Err(error) = server.respond(incoming, payload).await
                    && error.kind() != TransportErrorKind::ClientDisconnected
                {
                    return Err(error.into());
                }
                return Ok(false);
            }
            Err(error) => return Err(error.into()),
        };
        if let Err(error) = server.respond(incoming, payload).await {
            if error.kind() == TransportErrorKind::ClientDisconnected {
                return Ok(false);
            }
            return Err(error.into());
        }
    }
    Ok(true)
}

fn oversized_response_failure(message: &ServerMessage) -> ServerMessage {
    let (request_id, project_id) = match message {
        ServerMessage::Event(event) => (&event.request_id, &event.project_id),
        ServerMessage::Result(result) => (&result.request_id, &result.project_id),
    };
    ServerMessage::Result(ResultEnvelope {
        protocol_version: PROTOCOL_VERSION,
        request_id: request_id.clone(),
        project_id: project_id.clone(),
        body: ResultBody::Failure(Failure {
            code: FailureCode::FrameTooLarge,
            message: "response exceeded the local protocol frame limit".to_owned(),
            recovery: None,
        }),
    })
}

fn messages_for_observer(
    messages: &[ServerMessage],
    observer: &mut Subscription,
) -> Vec<ServerMessage> {
    let mut filtered = Vec::new();
    for message in messages {
        match message {
            ServerMessage::Event(event) if event.sequence > observer.last_sequence => {
                observer.last_sequence = event.sequence;
                filtered.push(ServerMessage::Event(EventEnvelope {
                    protocol_version: event.protocol_version,
                    request_id: observer.event_request_id.clone(),
                    project_id: observer.project_id.clone(),
                    sequence: event.sequence,
                    event: event.event.clone(),
                }));
            }
            ServerMessage::Result(result) => {
                filtered.push(ServerMessage::Result(ResultEnvelope {
                    protocol_version: result.protocol_version,
                    request_id: observer.observer_request_id.clone(),
                    project_id: observer.project_id.clone(),
                    body: result.body.clone(),
                }));
            }
            ServerMessage::Event(_) => {}
        }
    }
    filtered
}

fn remap_messages(
    messages: Vec<ServerMessage>,
    event_request_id: &RequestId,
    observer_request_id: &RequestId,
    project_id: &ProjectId,
) -> Vec<ServerMessage> {
    messages
        .into_iter()
        .map(|message| match message {
            ServerMessage::Event(event) => ServerMessage::Event(EventEnvelope {
                protocol_version: event.protocol_version,
                request_id: event_request_id.clone(),
                project_id: project_id.clone(),
                sequence: event.sequence,
                event: event.event,
            }),
            ServerMessage::Result(result) => ServerMessage::Result(ResultEnvelope {
                protocol_version: result.protocol_version,
                request_id: observer_request_id.clone(),
                project_id: project_id.clone(),
                body: result.body,
            }),
        })
        .collect()
}

async fn handle_incoming(
    incoming: IncomingRequest,
    store: Store,
    outbound: mpsc::Sender<Outbound>,
    scheduler: mpsc::Sender<()>,
    brief_provider: Arc<dyn BriefProvider>,
) -> Result<(), DaemonError> {
    let Ok(request) = decode_request_envelope(incoming.payload()) else {
        return Ok(());
    };
    if !request_identifiers_are_bounded(&request) {
        send_routed(
            &outbound,
            incoming,
            vec![ServerMessage::Result(failure_result(
                &request,
                FailureCode::InvalidRequest,
                "request identifiers must contain 1 to 256 UTF-8 bytes",
            ))],
            None,
        )
        .await;
        return Ok(());
    }
    if let Some(failure) = request.unsupported_version_failure() {
        send_routed(
            &outbound,
            incoming,
            vec![ServerMessage::Result(failure)],
            None,
        )
        .await;
        return Ok(());
    }

    match (&request.capability, &request.payload) {
        (Capability::DaemonStatus, RequestPayload::Status) => {
            handle_status(request, incoming, &store, &outbound, &scheduler).await
        }
        (Capability::CancelRequest, RequestPayload::Cancel { target_request_id }) => {
            handle_cancel(
                &request,
                target_request_id.clone(),
                incoming,
                &store,
                &outbound,
                &scheduler,
            )
            .await
        }
        (
            Capability::ReplayEvents,
            RequestPayload::Replay {
                target_request_id,
                after_sequence,
            },
        ) => {
            handle_replay(
                &request,
                target_request_id.clone(),
                *after_sequence,
                incoming,
                &store,
                &outbound,
            )
            .await
        }
        _ => {
            handle_read_only(
                &request,
                incoming,
                &store,
                &outbound,
                brief_provider.as_ref(),
            )
            .await
        }
    }
}

async fn handle_read_only(
    request: &RequestEnvelope,
    incoming: IncomingRequest,
    store: &Store,
    outbound: &mpsc::Sender<Outbound>,
    brief_provider: &dyn BriefProvider,
) -> Result<(), DaemonError> {
    match (&request.capability, &request.payload) {
        (Capability::Brief, RequestPayload::Brief) => {
            handle_brief(request, incoming, store, outbound, brief_provider).await
        }
        (
            Capability::WaitForResult,
            RequestPayload::WaitForResult {
                target_request_id,
                after_sequence,
            },
        ) => {
            handle_wait_for_result(
                request,
                target_request_id.clone(),
                *after_sequence,
                incoming,
                store,
                outbound,
            )
            .await
        }
        (Capability::GetResult, RequestPayload::GetResult { target_request_id }) => {
            handle_get_result(
                request,
                target_request_id.clone(),
                incoming,
                store,
                outbound,
            )
            .await
        }
        (Capability::InspectEvidence, RequestPayload::InspectEvidence { handle }) => {
            handle_inspect_evidence(request, handle.clone(), incoming, store, outbound).await
        }
        (
            Capability::ReadEvidence,
            RequestPayload::ReadEvidence {
                handle,
                offset,
                length,
            },
        ) => {
            handle_read_evidence(
                request,
                handle.clone(),
                *offset,
                *length,
                incoming,
                store,
                outbound,
            )
            .await
        }
        _ => {
            send_routed(
                outbound,
                incoming,
                vec![ServerMessage::Result(failure_result(
                    request,
                    FailureCode::InvalidRequest,
                    "capability and payload do not match",
                ))],
                None,
            )
            .await;
            Ok(())
        }
    }
}

async fn handle_status(
    request: RequestEnvelope,
    incoming: IncomingRequest,
    store: &Store,
    outbound: &mpsc::Sender<Outbound>,
    scheduler: &mpsc::Sender<()>,
) -> Result<(), DaemonError> {
    let accepted = store
        .accept(
            AcceptRequest {
                request_id: request.request_id.clone(),
                caller_id: request.caller_id.clone(),
                project_id: request.project_id.clone(),
                idempotency_key: request.idempotency_key.clone(),
                operation_kind: "daemon_status".to_owned(),
                operation: Vec::new(),
            },
            now_ms(),
        )
        .await;
    let canonical_request_id = match accepted {
        Ok(
            AcceptOutcome::Created { request_id, .. } | AcceptOutcome::Existing { request_id, .. },
        ) => request_id,
        Err(error) => {
            send_store_failure(outbound, incoming, &request, &error).await;
            return Ok(());
        }
    };
    let replay = store.replay(canonical_request_id.clone(), 0).await?;
    let snapshot = store.snapshot(canonical_request_id.clone()).await?;
    let terminal = replay.result.is_some();
    let last_sequence = replay.events.last().map_or(0, |event| event.sequence);
    let messages = remap_messages(
        replay_messages(&snapshot.project_id, &canonical_request_id, replay)?,
        &request.request_id,
        &request.request_id,
        &request.project_id,
    );
    let subscription = (!terminal).then_some(SubscriptionRequest {
        canonical_request_id: canonical_request_id.clone(),
        event_request_id: request.request_id.clone(),
        observer_request_id: request.request_id.clone(),
        project_id: request.project_id.clone(),
        last_sequence,
    });
    if terminal {
        send_routed(outbound, incoming, messages, None).await;
    } else {
        let (registered_tx, registered_rx) = oneshot::channel();
        let _ = outbound
            .send(Outbound::Routed {
                incoming,
                messages,
                subscribe: subscription,
                registered: Some(registered_tx),
            })
            .await;
        if registered_rx.await.is_ok() {
            let replay = store.replay(canonical_request_id.clone(), 0).await?;
            let terminal = replay.result.is_some();
            let messages = replay_messages(&snapshot.project_id, &canonical_request_id, replay)?;
            let _ = outbound
                .send(Outbound::Persisted {
                    request_id: canonical_request_id,
                    messages,
                    terminal,
                })
                .await;
        }
        let _ = scheduler.send(()).await;
    }
    Ok(())
}

async fn handle_cancel(
    request: &RequestEnvelope,
    target_request_id: RequestId,
    incoming: IncomingRequest,
    store: &Store,
    outbound: &mpsc::Sender<Outbound>,
    scheduler: &mpsc::Sender<()>,
) -> Result<(), DaemonError> {
    let snapshot = match store.snapshot(target_request_id.clone()).await {
        Ok(snapshot) if snapshot.project_id == request.project_id => snapshot,
        Ok(_) => {
            send_routed(
                outbound,
                incoming,
                vec![ServerMessage::Result(failure_result(
                    request,
                    FailureCode::NotFound,
                    "target request was not found in this project",
                ))],
                None,
            )
            .await;
            return Ok(());
        }
        Err(StoreError::RequestNotFound(_)) => {
            send_routed(
                outbound,
                incoming,
                vec![ServerMessage::Result(failure_result(
                    request,
                    FailureCode::NotFound,
                    "target request was not found",
                ))],
                None,
            )
            .await;
            return Ok(());
        }
        Err(error) => return Err(error.into()),
    };
    let target_project_id = snapshot.project_id;
    let cancelled_result = ResultEnvelope {
        protocol_version: PROTOCOL_VERSION,
        request_id: target_request_id.clone(),
        project_id: target_project_id.clone(),
        body: ResultBody::Failure(Failure {
            code: FailureCode::Cancelled,
            message: "request was cancelled".to_owned(),
            recovery: None,
        }),
    };
    let stored = encode(&ServerMessage::Result(cancelled_result))?;
    let outcome = store
        .cancel(target_request_id.clone(), now_ms(), stored)
        .await?;
    let disposition = match outcome {
        CancelOutcome::Cancelled | CancelOutcome::CancellationRequested => {
            CancellationDisposition::Requested
        }
        CancelOutcome::AlreadyTerminal(RequestState::Cancelled) => {
            CancellationDisposition::AlreadyCancelled
        }
        CancelOutcome::AlreadyTerminal(_) => CancellationDisposition::AlreadyTerminal,
    };
    let truth = if disposition == CancellationDisposition::Requested {
        OperationTruth::Changed
    } else {
        OperationTruth::Observed
    };
    let result = ResultEnvelope {
        protocol_version: PROTOCOL_VERSION,
        request_id: request.request_id.clone(),
        project_id: request.project_id.clone(),
        body: ResultBody::Success {
            truth,
            payload: ResultPayload::Cancellation(CancellationResult {
                target_request_id: target_request_id.clone(),
                disposition,
            }),
        },
    };
    send_routed(
        outbound,
        incoming,
        vec![ServerMessage::Result(result)],
        None,
    )
    .await;
    let replay = store.replay(target_request_id.clone(), 0).await?;
    let terminal = replay.result.is_some();
    let messages = replay_messages(&target_project_id, &target_request_id, replay)?;
    let _ = outbound
        .send(Outbound::Persisted {
            request_id: target_request_id,
            messages,
            terminal,
        })
        .await;
    let _ = scheduler.send(()).await;
    Ok(())
}

async fn handle_replay(
    request: &RequestEnvelope,
    target_request_id: RequestId,
    after_sequence: u64,
    incoming: IncomingRequest,
    store: &Store,
    outbound: &mpsc::Sender<Outbound>,
) -> Result<(), DaemonError> {
    if after_sequence > i64::MAX as u64 {
        send_routed(
            outbound,
            incoming,
            vec![ServerMessage::Result(failure_result(
                request,
                FailureCode::InvalidRequest,
                "replay sequence exceeds the supported range",
            ))],
            None,
        )
        .await;
        return Ok(());
    }
    let snapshot = match store.snapshot(target_request_id.clone()).await {
        Ok(snapshot) if snapshot.project_id == request.project_id => snapshot,
        Ok(_) | Err(StoreError::RequestNotFound(_)) => {
            send_routed(
                outbound,
                incoming,
                vec![ServerMessage::Result(failure_result(
                    request,
                    FailureCode::NotFound,
                    "target request was not found in this project",
                ))],
                None,
            )
            .await;
            return Ok(());
        }
        Err(error) => return Err(error.into()),
    };
    let replay = store
        .replay(target_request_id.clone(), after_sequence)
        .await?;
    let terminal = replay.result.is_some();
    let through_sequence = replay
        .events
        .last()
        .map_or(after_sequence, |event| event.sequence);
    let include_target_result = request.request_id == target_request_id;
    let mut messages =
        replay_messages_without_result(&snapshot.project_id, &target_request_id, &replay.events)?;
    if terminal && include_target_result {
        if let Some(result) = replay.result {
            messages.push(decode_stored_result(&result.payload)?);
        }
    } else {
        messages.push(ServerMessage::Result(ResultEnvelope {
            protocol_version: PROTOCOL_VERSION,
            request_id: request.request_id.clone(),
            project_id: request.project_id.clone(),
            body: ResultBody::Success {
                truth: OperationTruth::Observed,
                payload: ResultPayload::Replay(ReplayResult {
                    target_request_id,
                    through_sequence,
                    pending: !terminal,
                }),
            },
        }));
    }
    send_routed(outbound, incoming, messages, None).await;
    Ok(())
}

async fn handle_brief(
    request: &RequestEnvelope,
    incoming: IncomingRequest,
    store: &Store,
    outbound: &mpsc::Sender<Outbound>,
    provider: &dyn BriefProvider,
) -> Result<(), DaemonError> {
    let brief = provider.brief(&request.project_id, store).await;
    if !brief_is_bounded(&brief) {
        send_routed(
            outbound,
            incoming,
            vec![ServerMessage::Result(failure_result(
                request,
                FailureCode::FrameTooLarge,
                "brief provider response exceeded bounded limits",
            ))],
            None,
        )
        .await;
        return Ok(());
    }
    send_routed(
        outbound,
        incoming,
        vec![ServerMessage::Result(success_result(
            request,
            brief_truth(&brief),
            ResultPayload::Brief(brief),
        ))],
        None,
    )
    .await;
    Ok(())
}

async fn handle_wait_for_result(
    request: &RequestEnvelope,
    target_request_id: RequestId,
    after_sequence: u64,
    incoming: IncomingRequest,
    store: &Store,
    outbound: &mpsc::Sender<Outbound>,
) -> Result<(), DaemonError> {
    if !valid_replay_cursor(after_sequence) {
        send_routed(
            outbound,
            incoming,
            vec![ServerMessage::Result(failure_result(
                request,
                FailureCode::InvalidRequest,
                "wait sequence exceeds the supported range",
            ))],
            None,
        )
        .await;
        return Ok(());
    }
    let snapshot = match store.snapshot(target_request_id.clone()).await {
        Ok(snapshot) if snapshot.project_id == request.project_id => snapshot,
        Ok(_) | Err(StoreError::RequestNotFound(_)) => {
            send_target_not_found(outbound, incoming, request).await;
            return Ok(());
        }
        Err(error) => return Err(error.into()),
    };
    let replay = store
        .replay(target_request_id.clone(), after_sequence)
        .await?;
    let terminal = replay.result.is_some();
    let last_sequence = replay
        .events
        .last()
        .map_or(after_sequence, |event| event.sequence);
    let messages = wait_messages(request, &snapshot.project_id, &target_request_id, replay)?;
    if terminal {
        send_routed(outbound, incoming, messages, None).await;
        return Ok(());
    }

    let (registered_tx, registered_rx) = oneshot::channel();
    let _ = outbound
        .send(Outbound::Routed {
            incoming,
            messages,
            subscribe: Some(SubscriptionRequest {
                canonical_request_id: target_request_id.clone(),
                event_request_id: target_request_id.clone(),
                observer_request_id: request.request_id.clone(),
                project_id: request.project_id.clone(),
                last_sequence,
            }),
            registered: Some(registered_tx),
        })
        .await;
    if registered_rx.await.is_ok() {
        let replay = store
            .replay(target_request_id.clone(), last_sequence)
            .await?;
        let terminal = replay.result.is_some();
        let messages = replay_messages(&snapshot.project_id, &target_request_id, replay)?;
        let _ = outbound
            .send(Outbound::Persisted {
                request_id: target_request_id,
                messages,
                terminal,
            })
            .await;
    }
    Ok(())
}

async fn handle_get_result(
    request: &RequestEnvelope,
    target_request_id: RequestId,
    incoming: IncomingRequest,
    store: &Store,
    outbound: &mpsc::Sender<Outbound>,
) -> Result<(), DaemonError> {
    let snapshot = match store.snapshot(target_request_id.clone()).await {
        Ok(snapshot) if snapshot.project_id == request.project_id => snapshot,
        Ok(_) | Err(StoreError::RequestNotFound(_)) => {
            send_target_not_found(outbound, incoming, request).await;
            return Ok(());
        }
        Err(error) => return Err(error.into()),
    };
    let replay = store
        .replay(target_request_id.clone(), i64::MAX as u64)
        .await?;
    let result = match replay.result {
        Some(stored) => remap_stored_result(
            &stored.payload,
            &target_request_id,
            &snapshot.project_id,
            &request.request_id,
        )?,
        None => failure_result(
            request,
            FailureCode::Pending,
            "target request has not completed",
        ),
    };
    send_routed(
        outbound,
        incoming,
        vec![ServerMessage::Result(result)],
        None,
    )
    .await;
    Ok(())
}

async fn handle_inspect_evidence(
    request: &RequestEnvelope,
    handle: EvidenceHandle,
    incoming: IncomingRequest,
    store: &Store,
    outbound: &mpsc::Sender<Outbound>,
) -> Result<(), DaemonError> {
    match store
        .inspect_evidence(request.project_id.clone(), handle)
        .await
    {
        Ok(metadata) => {
            send_routed(
                outbound,
                incoming,
                vec![ServerMessage::Result(success_result(
                    request,
                    OperationTruth::Observed,
                    ResultPayload::EvidenceMetadata(protocol_evidence_metadata(metadata)),
                ))],
                None,
            )
            .await;
        }
        Err(error) => send_evidence_failure(outbound, incoming, request, &error).await,
    }
    Ok(())
}

async fn handle_read_evidence(
    request: &RequestEnvelope,
    handle: EvidenceHandle,
    offset: u64,
    length: u64,
    incoming: IncomingRequest,
    store: &Store,
    outbound: &mpsc::Sender<Outbound>,
) -> Result<(), DaemonError> {
    let metadata = match store
        .inspect_evidence(request.project_id.clone(), handle.clone())
        .await
    {
        Ok(metadata) => metadata,
        Err(error) => {
            send_evidence_failure(outbound, incoming, request, &error).await;
            return Ok(());
        }
    };
    let bytes = match store
        .read_evidence_range(request.project_id.clone(), handle.clone(), offset, length)
        .await
    {
        Ok(bytes) => bytes,
        Err(error) => {
            send_evidence_failure(outbound, incoming, request, &error).await;
            return Ok(());
        }
    };
    let end = offset
        .checked_add(usize_to_u64(bytes.len()))
        .ok_or_else(|| StoreError::InvalidState("evidence range overflowed".to_owned()))?;
    let chunk = EvidenceChunk::new(handle, offset, bytes, end == metadata.size_bytes)
        .map_err(|error| StoreError::InvalidState(error.to_string()))?;
    send_routed(
        outbound,
        incoming,
        vec![ServerMessage::Result(success_result(
            request,
            OperationTruth::Observed,
            ResultPayload::EvidenceChunk(chunk),
        ))],
        None,
    )
    .await;
    Ok(())
}

fn wait_messages(
    request: &RequestEnvelope,
    project_id: &ProjectId,
    target_request_id: &RequestId,
    replay: Replay,
) -> Result<Vec<ServerMessage>, DaemonError> {
    let mut messages =
        replay_messages_without_result(project_id, target_request_id, &replay.events)?;
    if let Some(stored) = replay.result {
        messages.push(ServerMessage::Result(remap_stored_result(
            &stored.payload,
            target_request_id,
            project_id,
            &request.request_id,
        )?));
    }
    Ok(messages)
}

fn remap_stored_result(
    payload: &[u8],
    target_request_id: &RequestId,
    project_id: &ProjectId,
    observer_request_id: &RequestId,
) -> Result<ResultEnvelope, DaemonError> {
    let ServerMessage::Result(result) = decode_stored_result(payload)? else {
        unreachable!("decode_stored_result accepts only result messages")
    };
    if result.request_id != *target_request_id || result.project_id != *project_id {
        return Err(StoreError::InvalidState(
            "stored result correlation does not match its request".to_owned(),
        )
        .into());
    }
    Ok(ResultEnvelope {
        protocol_version: result.protocol_version,
        request_id: observer_request_id.clone(),
        project_id: project_id.clone(),
        body: result.body,
    })
}

fn success_result(
    request: &RequestEnvelope,
    truth: OperationTruth,
    payload: ResultPayload,
) -> ResultEnvelope {
    ResultEnvelope {
        protocol_version: PROTOCOL_VERSION,
        request_id: request.request_id.clone(),
        project_id: request.project_id.clone(),
        body: ResultBody::Success { truth, payload },
    }
}

async fn send_target_not_found(
    outbound: &mpsc::Sender<Outbound>,
    incoming: IncomingRequest,
    request: &RequestEnvelope,
) {
    send_routed(
        outbound,
        incoming,
        vec![ServerMessage::Result(failure_result(
            request,
            FailureCode::NotFound,
            "target request was not found in this project",
        ))],
        None,
    )
    .await;
}

async fn send_evidence_failure(
    outbound: &mpsc::Sender<Outbound>,
    incoming: IncomingRequest,
    request: &RequestEnvelope,
    error: &StoreError,
) {
    let (code, message) = match error {
        StoreError::EvidenceNotFound { .. } => (
            FailureCode::NotFound,
            "evidence was not found in this project",
        ),
        StoreError::EvidenceRangeTooLarge { .. } | StoreError::EvidenceRangeOutOfBounds { .. } => {
            (FailureCode::InvalidRequest, "evidence range is invalid")
        }
        StoreError::EvidenceBlobMissing(_)
        | StoreError::EvidenceBlobCorrupt(_)
        | StoreError::UnsafeEvidencePath => (
            FailureCode::Internal,
            "evidence is unavailable or failed integrity verification",
        ),
        _ => (FailureCode::Internal, "evidence storage is unavailable"),
    };
    send_routed(
        outbound,
        incoming,
        vec![ServerMessage::Result(failure_result(
            request, code, message,
        ))],
        None,
    )
    .await;
}

fn protocol_evidence_metadata(metadata: pam_store::EvidenceMetadata) -> EvidenceMetadata {
    EvidenceMetadata {
        handle: metadata.handle,
        digest: metadata.digest,
        size_bytes: metadata.size_bytes,
        media_type: metadata.media_type,
        retention: match metadata.retention {
            pam_store::EvidenceRetention::Session => EvidenceRetention::Session,
            pam_store::EvidenceRetention::Project => EvidenceRetention::Project,
            pam_store::EvidenceRetention::Persistent => EvidenceRetention::Persistent,
        },
        redaction: match metadata.redaction {
            pam_store::EvidenceRedaction::Unredacted => EvidenceRedaction::Unredacted,
            pam_store::EvidenceRedaction::Redacted => EvidenceRedaction::Redacted,
        },
        created_at_unix_ms: metadata.created_at_ms,
    }
}

const fn valid_replay_cursor(sequence: u64) -> bool {
    sequence <= i64::MAX as u64
}

fn request_identifiers_are_bounded(request: &RequestEnvelope) -> bool {
    [
        request.request_id.as_str(),
        request.caller_id.as_str(),
        request.project_id.as_str(),
        request.idempotency_key.as_str(),
    ]
    .into_iter()
    .all(identifier_is_bounded)
        && target_request_id(request).is_none_or(|target| identifier_is_bounded(target.as_str()))
}

fn target_request_id(request: &RequestEnvelope) -> Option<&RequestId> {
    match &request.payload {
        RequestPayload::Cancel { target_request_id }
        | RequestPayload::Replay {
            target_request_id, ..
        }
        | RequestPayload::WaitForResult {
            target_request_id, ..
        }
        | RequestPayload::GetResult { target_request_id } => Some(target_request_id),
        RequestPayload::Status
        | RequestPayload::Brief
        | RequestPayload::InspectEvidence { .. }
        | RequestPayload::ReadEvidence { .. } => None,
    }
}

fn identifier_is_bounded(value: &str) -> bool {
    !value.is_empty() && value.len() <= MAX_REQUEST_IDENTIFIER_BYTES
}

fn brief_is_bounded(brief: &BriefResult) -> bool {
    brief.goal.as_ref().is_none_or(brief_item_is_bounded)
        && brief.decisions.len() <= MAX_BRIEF_SECTION_ITEMS
        && brief.decisions.iter().all(brief_item_is_bounded)
        && brief.verified.len() <= MAX_BRIEF_SECTION_ITEMS
        && brief.verified.iter().all(brief_item_is_bounded)
        && brief.next.len() <= MAX_BRIEF_SECTION_ITEMS
        && brief.next.iter().all(brief_item_is_bounded)
        && brief.provenance.len() <= MAX_BRIEF_PROVENANCE_ITEMS
        && brief.provenance.iter().all(|entry| {
            entry.source.len() <= MAX_BRIEF_SOURCE_BYTES
                && entry
                    .detail
                    .as_ref()
                    .is_none_or(|detail| detail.len() <= MAX_BRIEF_DETAIL_BYTES)
        })
}

fn brief_truth(brief: &BriefResult) -> OperationTruth {
    if brief.provenance.is_empty() {
        return OperationTruth::Unresolved;
    }
    if brief
        .provenance
        .iter()
        .any(|source| source.truth == OperationTruth::Blocked)
    {
        OperationTruth::Blocked
    } else if brief
        .provenance
        .iter()
        .any(|source| source.truth == OperationTruth::Unresolved)
    {
        OperationTruth::Unresolved
    } else {
        OperationTruth::Observed
    }
}

fn brief_item_is_bounded(item: &pam_protocol::BriefItem) -> bool {
    item.text.len() <= MAX_BRIEF_TEXT_BYTES && item.evidence.len() <= MAX_BRIEF_EVIDENCE_HANDLES
}

async fn send_store_failure(
    outbound: &mpsc::Sender<Outbound>,
    incoming: IncomingRequest,
    request: &RequestEnvelope,
    error: &StoreError,
) {
    let (code, message) = match error {
        StoreError::IdempotencyConflict { .. } => {
            (FailureCode::IdempotencyConflict, error.to_string())
        }
        StoreError::RequestIdConflict(_) => (FailureCode::InvalidRequest, error.to_string()),
        _ => (FailureCode::Internal, error.to_string()),
    };
    send_routed(
        outbound,
        incoming,
        vec![ServerMessage::Result(failure_result(
            request, code, &message,
        ))],
        None,
    )
    .await;
}

async fn send_routed(
    outbound: &mpsc::Sender<Outbound>,
    incoming: IncomingRequest,
    messages: Vec<ServerMessage>,
    subscribe: Option<SubscriptionRequest>,
) {
    let _ = outbound
        .send(Outbound::Routed {
            incoming,
            messages,
            subscribe,
            registered: None,
        })
        .await;
}

async fn run_scheduler(
    store: Store,
    mut wakeups: mpsc::Receiver<()>,
    outbound: mpsc::Sender<Outbound>,
    processing_delay: Duration,
) -> Result<(), DaemonError> {
    let mut workers = JoinSet::new();
    let mut recovery = tokio::time::interval(RECOVERY_INTERVAL);
    recovery.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let owner = format!("daemon-{}", std::process::id());
    loop {
        for request_id in store.recover_expired_requests(now_ms()).await? {
            let snapshot = store.snapshot(request_id.clone()).await?;
            let replay = store.replay(request_id.clone(), 0).await?;
            let terminal = replay.result.is_some();
            let messages = replay_messages(&snapshot.project_id, &request_id, replay)?;
            let _ = outbound
                .send(Outbound::Persisted {
                    request_id,
                    messages,
                    terminal,
                })
                .await;
        }
        while let Some(leased) = store
            .claim(&owner, now_ms(), duration_ms(LEASE_DURATION))
            .await?
        {
            let worker_store = store.clone();
            let worker_outbound = outbound.clone();
            workers.spawn(async move {
                process_leased(
                    leased,
                    worker_store,
                    worker_outbound,
                    processing_delay,
                    LEASE_DURATION,
                )
                .await
            });
        }

        if wakeups.is_closed() && workers.is_empty() {
            return Ok(());
        }

        tokio::select! {
            _ = recovery.tick() => {}
            wakeup = wakeups.recv() => {
                if wakeup.is_none() && workers.is_empty() {
                    return Ok(());
                }
            }
            completed = workers.join_next(), if !workers.is_empty() => {
                match completed {
                    Some(Ok(result)) => result?,
                    Some(Err(error)) => return Err(DaemonError::Handler(error)),
                    None => {}
                }
            }
        }
    }
}

async fn process_leased(
    mut leased: LeasedRequest,
    store: Store,
    outbound: mpsc::Sender<Outbound>,
    processing_delay: Duration,
    lease_duration: Duration,
) -> Result<(), DaemonError> {
    if !processing_delay.is_zero() {
        let mut processing = std::pin::pin!(tokio::time::sleep(processing_delay));
        let mut heartbeat = tokio::time::interval(LEASE_HEARTBEAT);
        heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // The first interval tick is immediate; the initial lease is already live.
        heartbeat.tick().await;
        loop {
            tokio::select! {
                () = &mut processing => break,
                _ = heartbeat.tick() => {
                    match store
                        .renew(
                            leased.lease.clone(),
                            now_ms(),
                            duration_ms(lease_duration),
                        )
                        .await
                    {
                        Ok(lease) => {
                            leased.lease = lease;
                            if store
                                .snapshot(leased.lease.request_id.clone())
                                .await?
                                .state
                                == RequestState::CancellationRequested
                            {
                                break;
                            }
                        }
                        Err(StoreError::StaleLease(_)) => return Ok(()),
                        Err(error) => return Err(error.into()),
                    }
                }
            }
        }
    }
    let queue_depth = store.queued_behind(leased.lease.request_id.clone()).await?;
    let (terminal_state, result) = if leased.operation_kind == "daemon_status" {
        (
            TerminalState::Succeeded,
            ResultEnvelope {
                protocol_version: PROTOCOL_VERSION,
                request_id: leased.lease.request_id.clone(),
                project_id: leased.lease.project_id.clone(),
                body: ResultBody::Success {
                    truth: OperationTruth::Observed,
                    payload: ResultPayload::Status(StatusResult {
                        ready: true,
                        healthy: true,
                        daemon_version: APPLICATION_VERSION.to_owned(),
                        protocol_version: PROTOCOL_VERSION,
                        queue_depth,
                    }),
                },
            },
        )
    } else {
        (
            TerminalState::Failed,
            ResultEnvelope {
                protocol_version: PROTOCOL_VERSION,
                request_id: leased.lease.request_id.clone(),
                project_id: leased.lease.project_id.clone(),
                body: ResultBody::Failure(Failure {
                    code: FailureCode::InvalidRequest,
                    message: format!("unknown durable operation {}", leased.operation_kind),
                    recovery: None,
                }),
            },
        )
    };
    let stored = encode(&ServerMessage::Result(result))?;
    match store
        .finish(leased.lease.clone(), now_ms(), terminal_state, stored)
        .await
    {
        Ok(_) => {}
        Err(StoreError::StaleLease(_)) => return Ok(()),
        Err(error) => return Err(error.into()),
    }
    let replay = store.replay(leased.lease.request_id.clone(), 0).await?;
    let messages = replay_messages(&leased.lease.project_id, &leased.lease.request_id, replay)?;
    let _ = outbound
        .send(Outbound::Persisted {
            request_id: leased.lease.request_id,
            messages,
            terminal: true,
        })
        .await;
    Ok(())
}

fn replay_messages(
    project_id: &ProjectId,
    request_id: &RequestId,
    replay: Replay,
) -> Result<Vec<ServerMessage>, DaemonError> {
    let mut messages = replay_messages_without_result(project_id, request_id, &replay.events)?;
    if let Some(result) = replay.result {
        let message = decode_stored_result(&result.payload)?;
        let ServerMessage::Result(envelope) = &message else {
            unreachable!("decode_stored_result accepts only result messages")
        };
        if envelope.request_id != *request_id || envelope.project_id != *project_id {
            return Err(StoreError::InvalidState(
                "stored result correlation does not match its request".to_owned(),
            )
            .into());
        }
        messages.push(message);
    }
    Ok(messages)
}

fn replay_messages_without_result(
    project_id: &ProjectId,
    request_id: &RequestId,
    events: &[EventRecord],
) -> Result<Vec<ServerMessage>, DaemonError> {
    events
        .iter()
        .map(|record| {
            Ok(ServerMessage::Event(EventEnvelope {
                protocol_version: PROTOCOL_VERSION,
                request_id: request_id.clone(),
                project_id: project_id.clone(),
                sequence: record.sequence,
                event: stored_event(&record.kind)?,
            }))
        })
        .collect()
}

fn decode_stored_result(payload: &[u8]) -> Result<ServerMessage, DaemonError> {
    let message = decode_server_message(payload)?;
    if matches!(message, ServerMessage::Result(_)) {
        Ok(message)
    } else {
        Err(StoreError::InvalidState("stored result is not a result envelope".to_owned()).into())
    }
}

fn stored_event(kind: &str) -> Result<Event, DaemonError> {
    match kind {
        "accepted" => Ok(Event::Accepted),
        "started" => Ok(Event::Started),
        "lease_expired" => Ok(Event::LeaseExpired),
        "cancellation_requested" => Ok(Event::CancellationRequested),
        "cancelled" => Ok(Event::Cancelled),
        "completed" => Ok(Event::Completed),
        "failed" => Ok(Event::Failed),
        other => Err(StoreError::InvalidState(format!("unknown event kind {other}")).into()),
    }
}

fn failure_result(request: &RequestEnvelope, code: FailureCode, message: &str) -> ResultEnvelope {
    ResultEnvelope {
        protocol_version: PROTOCOL_VERSION,
        request_id: request.request_id.clone(),
        project_id: request.project_id.clone(),
        body: ResultBody::Failure(Failure {
            code,
            message: message.to_owned(),
            recovery: None,
        }),
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

fn duration_ms(duration: Duration) -> u64 {
    duration.as_millis().try_into().unwrap_or(u64::MAX)
}

fn usize_to_u64(value: usize) -> u64 {
    u64::try_from(value).expect("usize fits into u64 on supported targets")
}

pub(super) fn prepare_endpoint(config: &DaemonConfig) -> Result<(), DaemonError> {
    if let Some(socket_path) = config.endpoint.socket_path()
        && socket_path.exists()
    {
        if config.recover {
            remove_if_present(socket_path)?;
        } else {
            return Err(DaemonError::StaleState(
                "Unix socket path already exists".to_owned(),
            ));
        }
    }
    Ok(())
}

fn remove_if_present(path: &Path) -> Result<(), DaemonError> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

enum ServeAction {
    Shutdown,
    Incoming(Result<IncomingRequest, TransportError>),
    Outbound(Option<Outbound>),
    HandlerCompleted(Option<Result<Result<(), DaemonError>, tokio::task::JoinError>>),
    SchedulerCompleted(Result<Result<(), DaemonError>, tokio::task::JoinError>),
}

pub(super) struct Ownership {
    _file: fs::File,
}

impl Ownership {
    pub(super) fn acquire(endpoint: &LocalEndpoint) -> Result<Self, DaemonError> {
        fs::create_dir_all(endpoint.runtime_dir())?;
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(endpoint.ownership_path())?;
        file.try_lock().map_err(|error| match error {
            fs::TryLockError::WouldBlock => DaemonError::AlreadyRunning,
            fs::TryLockError::Error(error) => DaemonError::Io(error),
        })?;
        file.set_len(0)?;
        writeln!(file, "{}", std::process::id())?;
        Ok(Self { _file: file })
    }
}
