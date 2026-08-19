use std::{
    collections::HashMap,
    fmt,
    fs::{self, OpenOptions},
    future::Future,
    io::Write,
    path::{Path, PathBuf},
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use pam_core::{
    APPLICATION_VERSION, ApprovalId, ContentDigest, EvidenceHandle, ProjectId, RequestId,
};
#[cfg(target_os = "macos")]
use pam_model::{MacosLlamaCppRuntime, ModelRuntime};
use pam_model::{
    ModelKey, RuntimeError, RuntimeFinishReason, RuntimeMessage, RuntimeMessageRole,
    RuntimeRequest, RuntimeResponse,
};
use pam_platform::{
    CorporateHttpClientFactory, CorporateHttpClientRequirements, IncomingRequest, LocalEndpoint,
    PacDiagnostic, ProxyBypassDiagnostic, ProxyDiagnosticStatus, ProxyEnvironmentVariable,
    ProxyInputIssueKind, ProxyRouteDiagnostic, ProxySource, ReqwestCorporateHttpClientFactory,
    ServerTransport, TransportError, TransportErrorKind, diagnose_process_proxy, user_data_dir,
};
use pam_policy::{CapabilityName, InvalidResourceName, ResourceName, redact_audit_detail};
use pam_protocol::{
    ApprovalChallenge, BriefProvenance, BriefResult, CancellationDisposition, CancellationResult,
    Capability, CodecError, ConfigurationPresence, Event, EventEnvelope, EvidenceChunk,
    EvidenceMetadata, EvidenceRedaction, EvidenceRetention, Failure, FailureCode,
    ModelFinishReason, ModelGenerationResult, ModelMessage, ModelRole, ModelUsage,
    NetworkDiagnosticsResult, OperationTruth, PROTOCOL_VERSION, PacState, ReplayResult,
    RequestEnvelope, RequestPayload, ResultBody, ResultEnvelope, ResultPayload, ServerMessage,
    SourceAvailability, StatusResult, decode_request_envelope, decode_server_message, encode,
};
use pam_store::{
    AcceptOutcome, AcceptRequest, AppendAuditEvent, AuthorizationAudit, AuthorizationOutcome,
    AuthorizationRequest, CallerAuthentication, CancelOutcome, EventRecord, LeasedRequest, Replay,
    RequestState, Store, StoreError, TerminalState,
};
use sha2::{Digest as _, Sha256};
use tokio::{
    sync::{mpsc, oneshot},
    task::JoinSet,
};

use crate::DaemonError;
#[cfg(target_os = "macos")]
use crate::macos_admission::MacosRuntimeHostAdmission;
use crate::model_service::{ModelService, ModelServiceError, ModelWorker};
use crate::ptrack::PtrackBriefProvider;

const RESPONSE_CAPACITY: usize = 64;
const SCHEDULER_CAPACITY: usize = 64;
const LEASE_DURATION: Duration = Duration::from_secs(3);
const LEASE_HEARTBEAT: Duration = Duration::from_secs(1);
const RECOVERY_INTERVAL: Duration = Duration::from_millis(50);
const APPROVAL_LIFETIME: Duration = Duration::from_mins(5);
const AUDIT_RETENTION: Duration = Duration::from_hours(30 * 24);
static AUDIT_EVENT_COUNTER: AtomicU64 = AtomicU64::new(0);
// UUIDs and current semantic IDs fit comfortably; this also leaves ample room for
// a maximum evidence chunk and its response envelope in the 1 MiB protocol frame.
const MAX_REQUEST_IDENTIFIER_BYTES: usize = 256;
const MAX_BRIEF_SECTION_ITEMS: usize = 16;
const MAX_BRIEF_PROVENANCE_ITEMS: usize = 32;
const MAX_BRIEF_TEXT_BYTES: usize = 4 * 1024;
const MAX_BRIEF_EVIDENCE_HANDLES: usize = 4;
const MAX_BRIEF_SOURCE_BYTES: usize = 256;
const MAX_BRIEF_DETAIL_BYTES: usize = 4 * 1024;
const DEFAULT_MODEL_DEADLINE: Duration = Duration::from_mins(5);
const MAX_MODEL_DEADLINE: Duration = Duration::from_mins(10);

#[derive(Clone)]
struct LoadedModelService {
    key: ModelKey,
    service: ModelService,
}

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
    /// Selects one registered model for the embedded runtime. No model is
    /// loaded and inference remains unavailable when this is absent.
    pub model: Option<ModelKey>,
    /// Overrides the durable `SQLite` path, primarily for isolated tests.
    pub state_path: Option<PathBuf>,
    /// Supplies planning context for read-only brief requests.
    pub brief_provider: Option<Arc<dyn BriefProvider>>,
    #[cfg(test)]
    pub(crate) bypass_authentication: bool,
    #[cfg(test)]
    pub(crate) bypass_policy: bool,
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            endpoint: LocalEndpoint::default_for_user(),
            recover: false,
            model: None,
            state_path: None,
            brief_provider: None,
            #[cfg(test)]
            bypass_authentication: false,
            #[cfg(test)]
            bypass_policy: false,
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
pub async fn run(recover: bool, model: Option<ModelKey>) -> Result<(), DaemonError> {
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
        model,
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

#[allow(clippy::too_many_lines)]
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
    #[cfg(test)]
    let authentication_required = !config.bypass_authentication;
    #[cfg(not(test))]
    let authentication_required = true;
    #[cfg(test)]
    let policy_required = !config.bypass_policy;
    #[cfg(not(test))]
    let policy_required = true;
    let mut server = ServerTransport::bind(&config.endpoint).await?;
    let (loaded_model, model_worker) = start_model_service(&store, config.model.clone()).await?;
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

    if let Some(model) = &loaded_model {
        println!(
            "PAM daemon ready (version {APPLICATION_VERSION}, protocol {PROTOCOL_VERSION}, model {}).",
            model.key
        );
    } else {
        println!("PAM daemon ready (version {APPLICATION_VERSION}, protocol {PROTOCOL_VERSION}).");
    }

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
                let request_model = loaded_model.clone();
                handlers.spawn(async move {
                    handle_incoming(
                        incoming,
                        request_store,
                        request_outbound,
                        request_scheduler,
                        request_brief_provider,
                        request_model,
                        authentication_required,
                        policy_required,
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
    if let Some(worker) = model_worker {
        worker.shutdown().await;
    }
    drop(outbound_tx);
    server.close().await?;
    store.shutdown().await?;
    drop(ownership);
    result
}

#[cfg(target_os = "macos")]
async fn start_model_service(
    store: &Store,
    key: Option<ModelKey>,
) -> Result<(Option<LoadedModelService>, Option<ModelWorker>), DaemonError> {
    let Some(key) = key else {
        return Ok((None, None));
    };
    let registered = store.model(key.clone()).await?;
    let runtime = tokio::task::spawn_blocking(move || {
        MacosLlamaCppRuntime::load(registered, Arc::new(MacosRuntimeHostAdmission))
    })
    .await
    .map_err(DaemonError::Handler)??;
    let runtime: Arc<dyn ModelRuntime> = Arc::new(runtime);
    let (service, worker) = ModelService::start(runtime);
    Ok((
        Some(LoadedModelService {
            key,
            service: service.clone(),
        }),
        Some(worker),
    ))
}

#[cfg(not(target_os = "macos"))]
async fn start_model_service(
    store: &Store,
    key: Option<ModelKey>,
) -> Result<(Option<LoadedModelService>, Option<ModelWorker>), DaemonError> {
    let Some(key) = key else {
        return Ok((None, None));
    };
    let _ = store.model(key).await?;
    Err(RuntimeError::InitializationFailed("embedded llama.cpp is available only on macOS").into())
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
            approval: None,
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

#[allow(clippy::too_many_arguments)]
async fn handle_incoming(
    incoming: IncomingRequest,
    store: Store,
    outbound: mpsc::Sender<Outbound>,
    scheduler: mpsc::Sender<()>,
    brief_provider: Arc<dyn BriefProvider>,
    loaded_model: Option<LoadedModelService>,
    authentication_required: bool,
    policy_required: bool,
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
                "request identifiers must contain 1 to 256 UTF-8 bytes without control characters",
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
    if let Some(failure) =
        request_preflight(&request, &store, authentication_required, policy_required).await?
    {
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
                loaded_model.as_ref(),
            )
            .await
        }
    }
}

pub(super) async fn request_preflight(
    request: &RequestEnvelope,
    store: &Store,
    authentication_required: bool,
    policy_required: bool,
) -> Result<Option<ResultEnvelope>, StoreError> {
    if !request_shape_is_valid(request) {
        return Ok(Some(failure_result(
            request,
            FailureCode::InvalidRequest,
            "capability and payload do not match",
        )));
    }
    let Ok(resource) = policy_resource(request) else {
        return Ok(Some(failure_result(
            request,
            FailureCode::InvalidRequest,
            "request cannot be represented as a policy resource",
        )));
    };
    if authentication_required
        && !matches!(
            authenticate_request(request, store).await?,
            CallerAuthentication::Authenticated
        )
    {
        append_request_audit(
            store,
            request,
            &resource,
            "deny",
            "unauthenticated",
            "authentication failed",
        )
        .await?;
        let mut failure = failure_result(
            request,
            FailureCode::Unauthenticated,
            "caller authentication failed",
        );
        if let ResultBody::Failure(body) = &mut failure.body {
            body.recovery = Some("pam caller register".to_owned());
        }
        return Ok(Some(failure));
    }
    if policy_required {
        let outcome = authorize_request(request, resource, store).await?;
        if !matches!(outcome, AuthorizationOutcome::Allowed) {
            return Ok(Some(authorization_failure(request, outcome)));
        }
    } else if authentication_required {
        append_request_audit(
            store,
            request,
            &resource,
            "allow",
            "authenticated",
            "authentication succeeded; policy enforcement disabled",
        )
        .await?;
    }
    Ok(None)
}

fn request_shape_is_valid(request: &RequestEnvelope) -> bool {
    let capability_matches = matches!(
        (&request.capability, &request.payload),
        (Capability::DaemonStatus, RequestPayload::Status)
            | (Capability::CancelRequest, RequestPayload::Cancel { .. })
            | (Capability::ReplayEvents, RequestPayload::Replay { .. })
            | (Capability::Brief, RequestPayload::Brief)
            | (
                Capability::NetworkDiagnostics,
                RequestPayload::NetworkDiagnostics
            )
            | (
                Capability::WaitForResult,
                RequestPayload::WaitForResult { .. }
            )
            | (Capability::GetResult, RequestPayload::GetResult { .. })
            | (
                Capability::InspectEvidence,
                RequestPayload::InspectEvidence { .. }
            )
            | (
                Capability::ReadEvidence,
                RequestPayload::ReadEvidence { .. }
            )
            | (Capability::ModelInfer, RequestPayload::ModelInfer { .. })
    );
    capability_matches && request.validate_model_request().is_ok()
}

async fn append_request_audit(
    store: &Store,
    request: &RequestEnvelope,
    resource: &ResourceName,
    decision: &str,
    outcome: &str,
    detail: &str,
) -> Result<(), StoreError> {
    let occurred_at_ms = now_ms();
    let redacted_detail = redact_audit_detail(
        format!(
            "capability={} resource={} detail={detail}",
            request.capability.policy_name(),
            resource.as_str()
        )
        .as_bytes(),
    );
    store
        .append_audit_event(AppendAuditEvent {
            event_id: request_audit_event_id(request, "authentication", occurred_at_ms),
            project_id: request.project_id.clone(),
            caller_id: request.caller_id.clone(),
            action: "request.preflight".to_owned(),
            decision: decision.to_owned(),
            outcome: outcome.to_owned(),
            redacted_detail,
            occurred_at_ms,
            retain_until_ms: occurred_at_ms
                .saturating_add(duration_ms(AUDIT_RETENTION))
                .min(i64::MAX as u64),
        })
        .await?;
    Ok(())
}

pub(super) fn request_audit_event_id(
    request: &RequestEnvelope,
    stage: &str,
    occurred_at_ms: u64,
) -> String {
    let mut hasher = Sha256::new();
    for field in [
        request.request_id.as_str(),
        request.project_id.as_str(),
        request.caller_id.as_str(),
        request.idempotency_key.as_str(),
        request.capability.policy_name(),
        stage,
    ] {
        hasher.update(u64::try_from(field.len()).unwrap_or(u64::MAX).to_le_bytes());
        hasher.update(field.as_bytes());
    }
    if let Some(approval_id) = &request.approval_id {
        hasher.update(approval_id.as_str().as_bytes());
    }
    hasher.update(occurred_at_ms.to_le_bytes());
    hasher.update(std::process::id().to_le_bytes());
    hasher.update(
        AUDIT_EVENT_COUNTER
            .fetch_add(1, Ordering::Relaxed)
            .to_le_bytes(),
    );
    hasher.update(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
            .to_le_bytes(),
    );
    let digest = ContentDigest::from_sha256(hasher.finalize().into());
    format!("request-preflight-{}", digest.sha256_hex())
}

async fn authenticate_request(
    request: &RequestEnvelope,
    store: &Store,
) -> Result<CallerAuthentication, StoreError> {
    let Some(credential) = request.authentication.clone() else {
        return Ok(CallerAuthentication::InvalidCredential);
    };
    store
        .authenticate_caller(request.caller_id.clone(), credential)
        .await
}

async fn authorize_request(
    request: &RequestEnvelope,
    resource: ResourceName,
    store: &Store,
) -> Result<AuthorizationOutcome, StoreError> {
    let capability = CapabilityName::parse(request.capability.policy_name())
        .expect("protocol capability names are statically valid");
    let now = now_ms();
    let detail = redact_audit_detail(
        format!(
            "capability={} resource={} detail=project policy evaluated",
            capability.as_str(),
            resource.as_str()
        )
        .as_bytes(),
    );
    store
        .authorize_audited(
            AuthorizationRequest {
                caller_id: request.caller_id.clone(),
                project_id: request.project_id.clone(),
                capability,
                resource,
                approval_id: request.approval_id.clone(),
            },
            AuthorizationAudit {
                event_id: request_audit_event_id(request, "policy", now),
                action: "request.preflight".to_owned(),
                redacted_detail: detail,
                retain_until_ms: now
                    .saturating_add(duration_ms(AUDIT_RETENTION))
                    .min(i64::MAX as u64),
            },
            now,
            duration_ms(APPROVAL_LIFETIME),
        )
        .await
}

pub(super) fn policy_resource(
    request: &RequestEnvelope,
) -> Result<ResourceName, InvalidResourceName> {
    let resource = match &request.payload {
        RequestPayload::Status => "daemon".to_owned(),
        RequestPayload::Brief => format!("project:{}", request.project_id),
        RequestPayload::NetworkDiagnostics => "network:configuration".to_owned(),
        RequestPayload::Cancel { target_request_id }
        | RequestPayload::GetResult { target_request_id } => {
            format!("request:{target_request_id}")
        }
        RequestPayload::Replay {
            target_request_id,
            after_sequence,
        }
        | RequestPayload::WaitForResult {
            target_request_id,
            after_sequence,
        } => format!("request:{target_request_id}:after={after_sequence}"),
        RequestPayload::InspectEvidence { handle } => format!("evidence:{handle}"),
        RequestPayload::ReadEvidence {
            handle,
            offset,
            length,
        } => format!("evidence:{handle}:offset={offset}:length={length}"),
        RequestPayload::ModelInfer {
            model,
            messages,
            max_output_tokens,
        } => {
            let digest = model_infer_effect_digest(model, messages, *max_output_tokens);
            format!("model:{model}:effect={digest}")
        }
    };
    ResourceName::parse(resource)
}

fn model_infer_effect_digest(
    model: &str,
    messages: &[ModelMessage],
    max_output_tokens: u32,
) -> ContentDigest {
    let mut hasher = Sha256::new();
    hash_effect_field(&mut hasher, b"pam-model-infer-effect-v1");
    hash_effect_field(&mut hasher, model.as_bytes());
    hasher.update(
        u64::try_from(messages.len())
            .unwrap_or(u64::MAX)
            .to_le_bytes(),
    );
    for message in messages {
        hasher.update([match message.role() {
            ModelRole::System => 0,
            ModelRole::User => 1,
            ModelRole::Assistant => 2,
        }]);
        hash_effect_field(&mut hasher, message.content().as_bytes());
    }
    hasher.update(max_output_tokens.to_le_bytes());
    ContentDigest::from_sha256(hasher.finalize().into())
}

fn hash_effect_field(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update(u64::try_from(bytes.len()).unwrap_or(u64::MAX).to_le_bytes());
    hasher.update(bytes);
}

fn authorization_failure(
    request: &RequestEnvelope,
    outcome: AuthorizationOutcome,
) -> ResultEnvelope {
    let (code, message, recovery, approval) = match outcome {
        AuthorizationOutcome::Allowed => unreachable!("allowed requests are dispatched"),
        AuthorizationOutcome::Denied => (
            FailureCode::Forbidden,
            "project policy denied this capability".to_owned(),
            Some(grant_recovery(
                &request.capability,
                &policy_resource(request),
            )),
            None,
        ),
        AuthorizationOutcome::ApprovalRequired {
            approval_id,
            expires_at_ms,
        } => {
            let recovery = approval_recovery(&request.capability, &approval_id);
            (
                FailureCode::ApprovalRequired,
                "this exact effect requires approval".to_owned(),
                Some(recovery),
                Some(ApprovalChallenge {
                    approval_id,
                    expires_at_unix_ms: expires_at_ms,
                }),
            )
        }
        AuthorizationOutcome::ApprovalDenied => (
            FailureCode::ApprovalDenied,
            "approval was denied".to_owned(),
            None,
            None,
        ),
        AuthorizationOutcome::ApprovalExpired => (
            FailureCode::ApprovalExpired,
            "approval expired before use".to_owned(),
            None,
            None,
        ),
    };
    ResultEnvelope {
        protocol_version: PROTOCOL_VERSION,
        request_id: request.request_id.clone(),
        project_id: request.project_id.clone(),
        body: ResultBody::Failure(Failure {
            code,
            message,
            recovery,
            approval,
        }),
    }
}

pub(super) fn approval_recovery(capability: &Capability, approval_id: &ApprovalId) -> String {
    match capability {
        Capability::DaemonStatus
        | Capability::Brief
        | Capability::NetworkDiagnostics
        | Capability::WaitForResult
        | Capability::GetResult
        | Capability::ModelInfer => format!(
            "pam approval approve {approval_id}, then retry the original command with --approval-id {approval_id}"
        ),
        Capability::InspectEvidence | Capability::ReadEvidence => format!(
            "pam approval approve {approval_id}; pam evidence show spans inspection and range reads, so this one-request receipt must be retried by a protocol client against the exact challenged request"
        ),
        Capability::CancelRequest | Capability::ReplayEvents => format!(
            "pam approval approve {approval_id}; PAM has no CLI retry surface for this capability, so a protocol client must attach this one-request receipt to the exact challenged request"
        ),
    }
}

pub(super) fn grant_recovery(
    capability: &Capability,
    resource: &Result<ResourceName, InvalidResourceName>,
) -> String {
    let capability = capability.policy_name();
    let Ok(resource) = resource else {
        return "review the denied capability and resource before adding a grant".to_owned();
    };
    if shell_safe_policy_argument(capability) && shell_safe_policy_argument(resource.as_str()) {
        format!(
            "pam access grant {capability} --resource {}",
            resource.as_str()
        )
    } else {
        "run pam access grant with the denied capability and exact resource, quoted for your shell"
            .to_owned()
    }
}

fn shell_safe_policy_argument(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/' | b'=' | b'+')
        })
}

async fn handle_read_only(
    request: &RequestEnvelope,
    incoming: IncomingRequest,
    store: &Store,
    outbound: &mpsc::Sender<Outbound>,
    brief_provider: &dyn BriefProvider,
    loaded_model: Option<&LoadedModelService>,
) -> Result<(), DaemonError> {
    match (&request.capability, &request.payload) {
        (Capability::Brief, RequestPayload::Brief) => {
            handle_brief(request, incoming, store, outbound, brief_provider).await
        }
        (Capability::NetworkDiagnostics, RequestPayload::NetworkDiagnostics) => {
            handle_network_diagnostics(request, incoming, store, outbound).await
        }
        (Capability::ModelInfer, RequestPayload::ModelInfer { .. }) => {
            handle_model_infer(request, incoming, store, outbound, loaded_model).await
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

#[allow(clippy::too_many_lines)]
async fn handle_model_infer(
    request: &RequestEnvelope,
    incoming: IncomingRequest,
    store: &Store,
    outbound: &mpsc::Sender<Outbound>,
    loaded: Option<&LoadedModelService>,
) -> Result<(), DaemonError> {
    let RequestPayload::ModelInfer {
        model,
        messages,
        max_output_tokens,
    } = &request.payload
    else {
        unreachable!("model inference is dispatched only for its matching payload")
    };
    let Some(loaded) = loaded.filter(|loaded| loaded.key.id() == *model) else {
        let mut failure = failure_result(
            request,
            FailureCode::NotFound,
            "the requested model is not loaded in this daemon",
        );
        if let ResultBody::Failure(body) = &mut failure.body {
            body.recovery = Some(format!("restart PAM with `pam daemon --model {model}`"));
        }
        send_routed(
            outbound,
            incoming,
            vec![ServerMessage::Result(failure)],
            None,
        )
        .await;
        return Ok(());
    };
    let deadline = match model_deadline(request.deadline_unix_ms) {
        Ok(deadline) => deadline,
        Err((code, message)) => {
            send_routed(
                outbound,
                incoming,
                vec![ServerMessage::Result(failure_result(
                    request, code, message,
                ))],
                None,
            )
            .await;
            return Ok(());
        }
    };
    let Ok(runtime_messages) = messages
        .iter()
        .map(|message| {
            RuntimeMessage::new(
                match message.role() {
                    ModelRole::System => RuntimeMessageRole::System,
                    ModelRole::User => RuntimeMessageRole::User,
                    ModelRole::Assistant => RuntimeMessageRole::Assistant,
                },
                message.content(),
            )
        })
        .collect::<Result<Vec<_>, _>>()
    else {
        send_routed(
            outbound,
            incoming,
            vec![ServerMessage::Result(failure_result(
                request,
                FailureCode::InvalidRequest,
                "model messages are invalid",
            ))],
            None,
        )
        .await;
        return Ok(());
    };
    let Ok(runtime_request) = RuntimeRequest::new(runtime_messages, *max_output_tokens) else {
        send_routed(
            outbound,
            incoming,
            vec![ServerMessage::Result(failure_result(
                request,
                FailureCode::InvalidRequest,
                "model request is invalid",
            ))],
            None,
        )
        .await;
        return Ok(());
    };
    let result = loaded.service.infer(runtime_request, deadline).await;
    let (response, audit_outcome, audit_detail) = match result {
        Ok(result) => model_runtime_result(request, model, result),
        Err(error) => {
            let (code, message, outcome) = model_service_failure(&error);
            (
                failure_result(request, code, message),
                outcome,
                format!("model={model} outcome={outcome}"),
            )
        }
    };
    append_model_audit(store, request, audit_outcome, &audit_detail).await?;
    send_routed(
        outbound,
        incoming,
        vec![ServerMessage::Result(response)],
        None,
    )
    .await;
    Ok(())
}

pub(super) fn model_runtime_result(
    request: &RequestEnvelope,
    model: &str,
    result: RuntimeResponse,
) -> (ResultEnvelope, &'static str, String) {
    let finish_reason = match result.finish_reason {
        RuntimeFinishReason::Stop => ModelFinishReason::Stop,
        RuntimeFinishReason::Length => ModelFinishReason::Length,
    };
    let usage = ModelUsage {
        input_tokens: result.usage.input_tokens,
        sampled_output_tokens: result.usage.sampled_output_tokens,
        emitted_output_tokens: result.usage.emitted_output_tokens,
    };
    match ModelGenerationResult::new(model, result.text, finish_reason, usage) {
        Ok(generation) => (
            success_result(
                request,
                OperationTruth::Observed,
                ResultPayload::ModelGeneration(generation),
            ),
            "observed",
            format!(
                "model={model} finish={} input_tokens={} sampled_output_tokens={} emitted_output_tokens={}",
                model_finish_label(finish_reason),
                usage.input_tokens,
                usage.sampled_output_tokens,
                usage.emitted_output_tokens,
            ),
        ),
        Err(_) => (
            failure_result(
                request,
                FailureCode::Internal,
                "embedded model returned an invalid result",
            ),
            "failed",
            format!("model={model} outcome=invalid_result"),
        ),
    }
}

fn model_deadline(deadline_unix_ms: Option<u64>) -> Result<Instant, (FailureCode, &'static str)> {
    let now_unix_ms = now_ms();
    let deadline_unix_ms = deadline_unix_ms
        .unwrap_or_else(|| now_unix_ms.saturating_add(duration_ms(DEFAULT_MODEL_DEADLINE)));
    if deadline_unix_ms <= now_unix_ms {
        return Err((FailureCode::Cancelled, "model request deadline has elapsed"));
    }
    let remaining_ms = deadline_unix_ms - now_unix_ms;
    if remaining_ms > duration_ms(MAX_MODEL_DEADLINE) {
        return Err((
            FailureCode::InvalidRequest,
            "model request deadline exceeds the 10 minute limit",
        ));
    }
    Instant::now()
        .checked_add(Duration::from_millis(remaining_ms))
        .ok_or((
            FailureCode::InvalidRequest,
            "model request deadline is invalid",
        ))
}

fn model_service_failure(error: &ModelServiceError) -> (FailureCode, &'static str, &'static str) {
    match error {
        ModelServiceError::Busy | ModelServiceError::Runtime(RuntimeError::Busy) => (
            FailureCode::Busy,
            "the embedded model worker is busy",
            "busy",
        ),
        ModelServiceError::DeadlineExceeded => (
            FailureCode::Cancelled,
            "model request deadline elapsed",
            "deadline_exceeded",
        ),
        ModelServiceError::Runtime(RuntimeError::Cancelled) => (
            FailureCode::Cancelled,
            "model inference was cancelled",
            "cancelled",
        ),
        ModelServiceError::Runtime(RuntimeError::InvalidRequest(_)) => (
            FailureCode::InvalidRequest,
            "model request is invalid",
            "invalid_request",
        ),
        ModelServiceError::Runtime(_) | ModelServiceError::Unavailable => (
            FailureCode::Internal,
            "embedded model inference failed",
            "failed",
        ),
    }
}

async fn append_model_audit(
    store: &Store,
    request: &RequestEnvelope,
    outcome: &str,
    detail: &str,
) -> Result<(), StoreError> {
    let occurred_at_ms = now_ms();
    store
        .append_audit_event(AppendAuditEvent {
            event_id: request_audit_event_id(request, "model-inference", occurred_at_ms),
            project_id: request.project_id.clone(),
            caller_id: request.caller_id.clone(),
            action: "model.infer".to_owned(),
            decision: "execute".to_owned(),
            outcome: outcome.to_owned(),
            redacted_detail: redact_audit_detail(detail.as_bytes()),
            occurred_at_ms,
            retain_until_ms: occurred_at_ms
                .saturating_add(duration_ms(AUDIT_RETENTION))
                .min(i64::MAX as u64),
        })
        .await?;
    Ok(())
}

const fn model_finish_label(reason: ModelFinishReason) -> &'static str {
    match reason {
        ModelFinishReason::Stop => "stop",
        ModelFinishReason::Length => "length",
    }
}

async fn handle_network_diagnostics(
    request: &RequestEnvelope,
    incoming: IncomingRequest,
    store: &Store,
    outbound: &mpsc::Sender<Outbound>,
) -> Result<(), DaemonError> {
    let (truth, result) = tokio::task::spawn_blocking(collect_network_diagnostics)
        .await
        .map_err(DaemonError::Handler)?;
    let occurred_at_ms = now_ms();
    let detail = format!(
        "platform_roots={} system_proxy={} proxy_environment={} no_proxy={} pac={}",
        result.platform_roots_enabled,
        result.system_proxy_discovery_enabled,
        configuration_presence_label(result.proxy_environment_presence),
        configuration_presence_label(result.no_proxy_presence),
        pac_state_label(result.pac_state)
    );
    store
        .append_audit_event(AppendAuditEvent {
            event_id: request_audit_event_id(request, "network-observation", occurred_at_ms),
            project_id: request.project_id.clone(),
            caller_id: request.caller_id.clone(),
            action: "network.diagnostics".to_owned(),
            decision: "observe".to_owned(),
            outcome: truth_label(&truth).to_owned(),
            redacted_detail: redact_audit_detail(detail.as_bytes()),
            occurred_at_ms,
            retain_until_ms: occurred_at_ms
                .saturating_add(duration_ms(AUDIT_RETENTION))
                .min(i64::MAX as u64),
        })
        .await?;
    send_routed(
        outbound,
        incoming,
        vec![ServerMessage::Result(success_result(
            request,
            truth,
            ResultPayload::NetworkDiagnostics(result),
        ))],
        None,
    )
    .await;
    Ok(())
}

const fn configuration_presence_label(value: ConfigurationPresence) -> &'static str {
    match value {
        ConfigurationPresence::Configured => "configured",
        ConfigurationPresence::NotConfigured => "not_configured",
        ConfigurationPresence::Invalid => "invalid",
    }
}

const fn pac_state_label(value: PacState) -> &'static str {
    match value {
        PacState::NotDetected => "not_detected",
        PacState::DetectedUnsupported => "detected_unsupported",
        PacState::InspectionUnavailable => "inspection_unavailable",
    }
}

const fn truth_label(value: &OperationTruth) -> &'static str {
    match value {
        OperationTruth::Observed => "observed",
        OperationTruth::Changed => "changed",
        OperationTruth::Verified => "verified",
        OperationTruth::Unresolved => "unresolved",
        OperationTruth::Blocked => "blocked",
    }
}

fn collect_network_diagnostics() -> (OperationTruth, NetworkDiagnosticsResult) {
    let proxy = diagnose_process_proxy();
    let client_ready = ReqwestCorporateHttpClientFactory
        .build(CorporateHttpClientRequirements::secure_default())
        .is_ok();
    let proxy_environment_presence = proxy_environment_presence(&proxy);
    let no_proxy_presence = no_proxy_presence(&proxy);
    let truth = if client_ready && proxy.status == ProxyDiagnosticStatus::Observed {
        OperationTruth::Observed
    } else {
        OperationTruth::Unresolved
    };
    let result = NetworkDiagnosticsResult {
        platform_roots_enabled: client_ready,
        system_proxy_discovery_enabled: client_ready,
        proxy_environment_presence,
        no_proxy_presence,
        pac_state: match proxy.pac {
            PacDiagnostic::DetectedButUnsupported => PacState::DetectedUnsupported,
            PacDiagnostic::NotDetected => PacState::NotDetected,
            PacDiagnostic::InspectionUnavailable(_) => PacState::InspectionUnavailable,
        },
    };
    (truth, result)
}

fn proxy_environment_presence(proxy: &pam_platform::ProxyDiagnostic) -> ConfigurationPresence {
    let environment_route = |route| {
        matches!(
            route,
            ProxyRouteDiagnostic::Configured {
                source: ProxySource::Environment(_),
                ..
            }
        )
    };
    if environment_route(proxy.http) || environment_route(proxy.https) {
        ConfigurationPresence::Configured
    } else if proxy.ignored_inputs.iter().any(|issue| {
        issue.kind == ProxyInputIssueKind::Malformed
            && matches!(
                issue.variable,
                ProxyEnvironmentVariable::HttpProxyUpper
                    | ProxyEnvironmentVariable::HttpProxyLower
                    | ProxyEnvironmentVariable::HttpsProxyUpper
                    | ProxyEnvironmentVariable::HttpsProxyLower
                    | ProxyEnvironmentVariable::AllProxyUpper
                    | ProxyEnvironmentVariable::AllProxyLower
            )
    }) {
        ConfigurationPresence::Invalid
    } else {
        ConfigurationPresence::NotConfigured
    }
}

const fn no_proxy_presence(proxy: &pam_platform::ProxyDiagnostic) -> ConfigurationPresence {
    match proxy.bypass {
        ProxyBypassDiagnostic::Configured {
            source: ProxySource::Environment(_),
        } => ConfigurationPresence::Configured,
        ProxyBypassDiagnostic::Malformed {
            source: ProxySource::Environment(_),
        } => ConfigurationPresence::Invalid,
        ProxyBypassDiagnostic::NotConfigured
        | ProxyBypassDiagnostic::Configured {
            source: ProxySource::System,
        }
        | ProxyBypassDiagnostic::Malformed {
            source: ProxySource::System,
        }
        | ProxyBypassDiagnostic::SuppressedByCgi
        | ProxyBypassDiagnostic::Unresolved(_) => ConfigurationPresence::NotConfigured,
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
            approval: None,
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
        | RequestPayload::NetworkDiagnostics
        | RequestPayload::InspectEvidence { .. }
        | RequestPayload::ReadEvidence { .. }
        | RequestPayload::ModelInfer { .. } => None,
    }
}

fn identifier_is_bounded(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_REQUEST_IDENTIFIER_BYTES
        && !value.chars().any(is_unsafe_identifier_character)
}

fn is_unsafe_identifier_character(character: char) -> bool {
    character.is_control()
        || matches!(
            character,
            '\u{00ad}'
                | '\u{0600}'..='\u{0605}'
                | '\u{061c}'
                | '\u{06dd}'
                | '\u{070f}'
                | '\u{0890}'..='\u{0891}'
                | '\u{08e2}'
                | '\u{180e}'
                | '\u{200b}'..='\u{200f}'
                | '\u{202a}'..='\u{202e}'
                | '\u{2060}'..='\u{2064}'
                | '\u{2066}'..='\u{206f}'
                | '\u{feff}'
                | '\u{fff9}'..='\u{fffb}'
                | '\u{110bd}'
                | '\u{110cd}'
                | '\u{13430}'..='\u{1343f}'
                | '\u{1bca0}'..='\u{1bca3}'
                | '\u{1d173}'..='\u{1d17a}'
                | '\u{e0001}'
                | '\u{e0020}'..='\u{e007f}'
        )
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
                    approval: None,
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
            approval: None,
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
