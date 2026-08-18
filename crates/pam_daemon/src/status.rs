use pam_core::RequestId;
use pam_platform::{ClientTransport, LocalEndpoint};
use pam_protocol::{
    EventEnvelope, RequestEnvelope, RequestPayload, ResultEnvelope, ServerMessage,
    decode_server_message, encode,
};

use crate::{ExchangeError, StatusError};
use tokio::time::{Duration, Instant, timeout};

const MAX_EXCHANGE_EVENTS: usize = 100_000;

#[derive(Debug)]
pub struct ClientExchange {
    pub events: Vec<EventEnvelope>,
    pub result: ResultEnvelope,
}

pub type StatusExchange = ClientExchange;

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
    let deadline = Instant::now() + wait;
    let mut client = ClientTransport::connect(endpoint, remaining(deadline)?).await?;
    timeout(remaining(deadline)?, client.send(encode(request)?))
        .await
        .map_err(|_| ExchangeError::DeadlineExceeded)??;
    let (event_request_id, mut last_sequence) = event_correlation(request);
    let mut events = Vec::new();

    loop {
        let receive_deadline = remaining(deadline)?;
        let transport_wait = receive_deadline.saturating_add(Duration::from_secs(1));
        let frame = timeout(receive_deadline, client.receive(transport_wait))
            .await
            .map_err(|_| ExchangeError::DeadlineExceeded)??;
        let message = decode_server_message(&frame)?;
        match message {
            ServerMessage::Event(event) => {
                if events.len() >= MAX_EXCHANGE_EVENTS {
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
                last_sequence = event.sequence;
                events.push(event);
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
                return Ok(ClientExchange { events, result });
            }
        }
    }
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
        }
        | RequestPayload::WaitForResult {
            target_request_id,
            after_sequence,
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
