use pam_platform::{ClientTransport, LocalEndpoint};
use pam_protocol::{
    EventEnvelope, RequestEnvelope, ResultEnvelope, ServerMessage, decode_server_message, encode,
};

use crate::StatusError;
use tokio::time::{Duration, Instant, timeout};

const MAX_STATUS_EVENTS: usize = 64;

#[derive(Debug)]
pub struct StatusExchange {
    pub events: Vec<EventEnvelope>,
    pub result: ResultEnvelope,
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
    let deadline = Instant::now() + wait;
    let mut client = ClientTransport::connect(endpoint, remaining(deadline)?).await?;
    timeout(remaining(deadline)?, client.send(encode(request)?))
        .await
        .map_err(|_| StatusError::DeadlineExceeded)??;
    let mut events = Vec::new();

    loop {
        let message = decode_server_message(&client.receive(remaining(deadline)?).await?)?;
        match message {
            ServerMessage::Event(event) => {
                if events.len() >= MAX_STATUS_EVENTS {
                    return Err(StatusError::EventLimitExceeded);
                }
                let expected_sequence = events.len() as u64 + 1;
                if event.request_id != request.request_id
                    || event.project_id != request.project_id
                    || event.sequence != expected_sequence
                {
                    return Err(StatusError::Correlation(format!(
                        "expected request {} project {} sequence {expected_sequence}",
                        request.request_id, request.project_id
                    )));
                }
                events.push(event);
            }
            ServerMessage::Result(result) => {
                if result.request_id != request.request_id
                    || result.project_id != request.project_id
                {
                    return Err(StatusError::Correlation(format!(
                        "expected request {} for project {}",
                        request.request_id, request.project_id
                    )));
                }
                return Ok(StatusExchange { events, result });
            }
        }
    }
}

fn remaining(deadline: Instant) -> Result<Duration, StatusError> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        Err(StatusError::DeadlineExceeded)
    } else {
        Ok(remaining)
    }
}
