use std::{
    fs::{self, OpenOptions},
    future::Future,
    io::Write,
    path::Path,
    time::Duration,
};

use pam_core::{APPLICATION_VERSION, ProjectPermit, ProjectQueue};
use pam_platform::{
    IncomingRequest, LocalEndpoint, ServerTransport, TransportError, TransportErrorKind,
};
use pam_protocol::{
    Event, EventEnvelope, OperationTruth, PROTOCOL_VERSION, RequestEnvelope, ResultBody,
    ResultEnvelope, ResultPayload, ServerMessage, StatusResult, decode_request_envelope, encode,
};

use crate::DaemonError;

type QueuedResponse = (IncomingRequest, HandledRequest);

struct HandledRequest {
    responses: Vec<ServerMessage>,
    permit: Option<ProjectPermit>,
}

#[derive(Clone, Debug)]
pub struct DaemonConfig {
    pub endpoint: LocalEndpoint,
    pub recover: bool,
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            endpoint: LocalEndpoint::default_for_user(),
            recover: false,
        }
    }
}

/// Runs the foreground daemon until an operating-system shutdown signal arrives.
///
/// # Errors
///
/// Returns [`DaemonError`] when ownership, endpoint preparation, transport, or
/// protocol handling fails.
pub async fn run(recover: bool) -> Result<(), DaemonError> {
    let config = DaemonConfig {
        recover,
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
/// Returns [`DaemonError`] when ownership, endpoint preparation, transport, or
/// protocol handling fails.
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
    let mut server = ServerTransport::bind(&config.endpoint).await?;
    let queue = ProjectQueue::default();
    let (response_tx, mut response_rx) = tokio::sync::mpsc::channel::<QueuedResponse>(64);
    let mut handlers = tokio::task::JoinSet::new();

    println!("PAM daemon ready (version {APPLICATION_VERSION}, protocol {PROTOCOL_VERSION}).");

    tokio::pin!(shutdown);
    loop {
        let action = tokio::select! {
            () = &mut shutdown => ServeAction::Shutdown,
            incoming = server.receive() => ServeAction::Incoming(incoming),
            response = response_rx.recv() => ServeAction::Response(response),
            completed = handlers.join_next(), if !handlers.is_empty() => {
                ServeAction::HandlerCompleted(completed)
            }
        };

        match action {
            ServeAction::Shutdown | ServeAction::Response(None) => break,
            ServeAction::Incoming(Ok(incoming)) => {
                let request_queue = queue.clone();
                let response_tx = response_tx.clone();
                handlers.spawn(async move {
                    if let Some(responses) =
                        handle_request(incoming.payload(), &request_queue, processing_delay).await
                    {
                        let _ = response_tx.send((incoming, responses)).await;
                    }
                });
            }
            ServeAction::Incoming(Err(error))
                if matches!(
                    error.kind(),
                    TransportErrorKind::InvalidMessage | TransportErrorKind::FrameTooLarge
                ) => {}
            ServeAction::Incoming(Err(error)) => return Err(error.into()),
            ServeAction::Response(Some((incoming, handled))) => {
                for response in handled.responses {
                    if let Err(error) = server.respond(&incoming, encode(&response)?).await {
                        if error.kind() == TransportErrorKind::ClientDisconnected {
                            break;
                        }
                        return Err(error.into());
                    }
                }
                drop(handled.permit);
            }
            ServeAction::HandlerCompleted(Some(Err(error))) => {
                return Err(DaemonError::Handler(error));
            }
            ServeAction::HandlerCompleted(Some(Ok(())) | None) => {}
        }
    }

    handlers.abort_all();
    while handlers.join_next().await.is_some() {}
    drop(response_tx);
    server.close().await?;
    drop(ownership);
    Ok(())
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

async fn handle_request(
    payload: &[u8],
    queue: &ProjectQueue,
    processing_delay: Duration,
) -> Option<HandledRequest> {
    let request = decode_request_envelope(payload).ok()?;
    if let Some(failure) = request.unsupported_version_failure() {
        return Some(HandledRequest {
            responses: vec![ServerMessage::Result(failure)],
            permit: None,
        });
    }

    let accepted = event(&request, 1, Event::Accepted);
    let permit = queue.enter(&request.project_id).await;
    let started = event(&request, 2, Event::Started);
    if !processing_delay.is_zero() {
        tokio::time::sleep(processing_delay).await;
    }
    let completed = event(&request, 3, Event::Completed);

    let result = ResultEnvelope {
        protocol_version: PROTOCOL_VERSION,
        request_id: request.request_id,
        project_id: request.project_id,
        body: ResultBody::Success {
            truth: OperationTruth::Observed,
            payload: ResultPayload::Status(StatusResult {
                ready: true,
                healthy: true,
                daemon_version: APPLICATION_VERSION.to_owned(),
                protocol_version: PROTOCOL_VERSION,
                queue_depth: permit.queued_behind(),
            }),
        },
    };
    Some(HandledRequest {
        responses: vec![
            ServerMessage::Event(accepted),
            ServerMessage::Event(started),
            ServerMessage::Event(completed),
            ServerMessage::Result(result),
        ],
        permit: Some(permit),
    })
}

enum ServeAction {
    Shutdown,
    Incoming(Result<IncomingRequest, TransportError>),
    Response(Option<QueuedResponse>),
    HandlerCompleted(Option<Result<(), tokio::task::JoinError>>),
}

fn event(request: &RequestEnvelope, sequence: u64, event: Event) -> EventEnvelope {
    EventEnvelope {
        protocol_version: PROTOCOL_VERSION,
        request_id: request.request_id.clone(),
        project_id: request.project_id.clone(),
        sequence,
        event,
    }
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
