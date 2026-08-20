use pam_core::RequestId;
use pam_platform::{ClientTransport, LocalEndpoint};
use pam_protocol::{
    EventEnvelope, RequestEnvelope, RequestPayload, ResultEnvelope, ServerMessage,
    decode_server_message, encode,
};
use std::{error::Error, fmt, future::Future};

use crate::{ExchangeError, StatusError};
use tokio::time::{Duration, Instant, timeout};

const MAX_EXCHANGE_EVENTS: usize = 100_000;

#[derive(Debug)]
pub struct ClientExchange {
    pub events: Vec<EventEnvelope>,
    pub result: ResultEnvelope,
}

pub type StatusExchange = ClientExchange;

/// Successful streaming exchange with the last durably observed event cursor.
#[derive(Debug)]
pub struct StreamingExchange {
    pub result: ResultEnvelope,
    pub last_sequence: u64,
}

/// Streaming exchange failure retaining the last fully validated event cursor.
#[derive(Debug)]
pub struct StreamingExchangeError {
    error: ExchangeError,
    last_sequence: u64,
    request_may_have_been_sent: bool,
}

impl StreamingExchangeError {
    #[must_use]
    pub const fn error(&self) -> &ExchangeError {
        &self.error
    }

    #[must_use]
    pub const fn last_sequence(&self) -> u64 {
        self.last_sequence
    }

    /// Whether transport submission began before the failure.
    ///
    /// This becomes true immediately before awaiting the local send/flush boundary,
    /// so callers conservatively treat both a send timeout and a later observation
    /// failure as potentially durable.
    #[must_use]
    pub const fn request_may_have_been_sent(&self) -> bool {
        self.request_may_have_been_sent
    }

    /// Compatibility alias for callers compiled against the initial streaming API.
    #[must_use]
    pub const fn request_sent(&self) -> bool {
        self.request_may_have_been_sent()
    }

    #[must_use]
    pub fn into_error(self) -> ExchangeError {
        self.error
    }
}

impl fmt::Display for StreamingExchangeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.error.fmt(formatter)
    }
}

impl Error for StreamingExchangeError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.error.source()
    }
}

/// Sends one request and receives its correlated events and terminal response.
///
/// Wait and replay operations may resume after a nonzero event sequence. All other
/// operations require event sequences to begin at one. Dropping this future closes
/// only the observer transport; it never sends a cancellation request.
///
/// # Errors
///
/// Returns [`ExchangeError`] when the daemon is unavailable, the deadline expires,
/// or a frame violates correlation, sequence, size, or protocol requirements.
pub async fn request_exchange(
    endpoint: &LocalEndpoint,
    request: &RequestEnvelope,
    wait: Duration,
) -> Result<ClientExchange, ExchangeError> {
    let mut events = Vec::new();
    let exchange = request_exchange_streaming(endpoint, request, wait, |event| {
        events.push(event.clone());
    })
    .await
    .map_err(StreamingExchangeError::into_error)?;
    Ok(ClientExchange {
        events,
        result: exchange.result,
    })
}

/// Sends one request and delivers each event immediately after complete validation.
///
/// The callback is never invoked for an uncorrelated or out-of-sequence event. On failure, the
/// returned error retains the last delivered sequence so callers can resume without losing
/// durable progress. Dropping this future closes only the observer transport.
///
/// # Errors
///
/// Returns [`StreamingExchangeError`] when the daemon is unavailable, the deadline expires, or a
/// frame violates correlation, sequence, size, or protocol requirements.
pub async fn request_exchange_streaming<F>(
    endpoint: &LocalEndpoint,
    request: &RequestEnvelope,
    wait: Duration,
    mut on_event: F,
) -> Result<StreamingExchange, StreamingExchangeError>
where
    F: FnMut(&EventEnvelope),
{
    let (_, initial_sequence) = event_correlation(request);
    let mut last_sequence = initial_sequence;
    let mut request_may_have_been_sent = false;
    request_exchange_streaming_inner(
        endpoint,
        request,
        wait,
        &mut last_sequence,
        &mut request_may_have_been_sent,
        &mut on_event,
    )
    .await
    .map_err(|error| StreamingExchangeError {
        error,
        last_sequence,
        request_may_have_been_sent,
    })
}

async fn request_exchange_streaming_inner<F>(
    endpoint: &LocalEndpoint,
    request: &RequestEnvelope,
    wait: Duration,
    last_sequence: &mut u64,
    request_may_have_been_sent: &mut bool,
    on_event: &mut F,
) -> Result<StreamingExchange, ExchangeError>
where
    F: FnMut(&EventEnvelope),
{
    let deadline = Instant::now() + wait;
    let endpoint_present = endpoint.socket_path().map_or_else(
        || endpoint.ownership_path().exists(),
        std::path::Path::exists,
    );
    let mut client = match ClientTransport::connect(endpoint, remaining(deadline)?).await {
        Ok(client) => client,
        Err(_) if endpoint_present && remaining(deadline).is_err() => {
            return Err(ExchangeError::DeadlineExceeded);
        }
        Err(error) => return Err(error.into()),
    };
    let encoded = encode(request)?;
    submit_maybe_sent(request_may_have_been_sent, deadline, client.send(encoded)).await?;
    let (event_request_id, initial_sequence) = event_correlation(request);
    debug_assert_eq!(*last_sequence, initial_sequence);
    let mut event_count = 0_usize;

    loop {
        let receive_deadline = remaining(deadline)?;
        let transport_wait = receive_deadline.saturating_add(Duration::from_secs(1));
        let frame = timeout(receive_deadline, client.receive(transport_wait))
            .await
            .map_err(|_| ExchangeError::DeadlineExceeded)??;
        let message = decode_server_message(&frame)?;
        match message {
            ServerMessage::Event(event) => {
                if event_count >= MAX_EXCHANGE_EVENTS {
                    return Err(ExchangeError::EventLimitExceeded);
                }
                let Some(expected_sequence) = last_sequence.checked_add(1) else {
                    return Err(ExchangeError::Correlation(
                        "event sequence overflowed".to_owned(),
                    ));
                };
                if event.request_id != event_request_id
                    || event.project_id != request.project_id
                    || event.sequence != expected_sequence
                {
                    return Err(ExchangeError::Correlation(format!(
                        "expected request {event_request_id} project {} sequence {expected_sequence}",
                        request.project_id
                    )));
                }
                *last_sequence = event.sequence;
                event_count += 1;
                on_event(&event);
            }
            ServerMessage::Result(result) => {
                if result.request_id != request.request_id
                    || result.project_id != request.project_id
                {
                    return Err(ExchangeError::Correlation(format!(
                        "expected request {} for project {}",
                        request.request_id, request.project_id
                    )));
                }
                return Ok(StreamingExchange {
                    result,
                    last_sequence: *last_sequence,
                });
            }
        }
    }
}

pub(super) async fn submit_maybe_sent<F, E>(
    request_may_have_been_sent: &mut bool,
    deadline: Instant,
    submission: F,
) -> Result<(), ExchangeError>
where
    F: Future<Output = Result<(), E>>,
    ExchangeError: From<E>,
{
    *request_may_have_been_sent = true;
    timeout(remaining(deadline)?, submission)
        .await
        .map_err(|_| ExchangeError::DeadlineExceeded)?
        .map_err(ExchangeError::from)
}

/// Sends a status request through the selected local transport.
///
/// # Errors
///
/// Returns [`StatusError`] when the daemon is unavailable or a frame violates
/// the application protocol.
pub async fn request_status(
    endpoint: &LocalEndpoint,
    request: &RequestEnvelope,
    wait: Duration,
) -> Result<StatusExchange, StatusError> {
    request_exchange(endpoint, request, wait).await
}

fn event_correlation(request: &RequestEnvelope) -> (RequestId, u64) {
    match &request.payload {
        RequestPayload::Replay {
            target_request_id,
            after_sequence,
            ..
        }
        | RequestPayload::WaitForResult {
            target_request_id,
            after_sequence,
            ..
        } => (target_request_id.clone(), *after_sequence),
        _ => (request.request_id.clone(), 0),
    }
}

fn remaining(deadline: Instant) -> Result<Duration, ExchangeError> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        Err(ExchangeError::DeadlineExceeded)
    } else {
        Ok(remaining)
    }
}
