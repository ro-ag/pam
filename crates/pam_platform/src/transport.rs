use std::time::Duration;

use tokio::time::timeout;
use zeromq::{
    DealerSocket, RouterSocket, Socket, SocketOptions, SocketRecv, SocketSend, ZmqMessage,
};

use crate::{LocalEndpoint, TransportError, TransportErrorKind};
use pam_protocol::MAX_FRAME_SIZE;

pub struct IncomingRequest {
    route: Vec<u8>,
    payload: Vec<u8>,
}

impl IncomingRequest {
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }
}

pub struct ServerTransport {
    socket: RouterSocket,
}

impl ServerTransport {
    /// Binds a daemon-side Router socket to the local endpoint.
    ///
    /// # Errors
    ///
    /// Returns a friendly endpoint or internal transport error when binding fails.
    pub async fn bind(endpoint: &LocalEndpoint) -> Result<Self, TransportError> {
        std::fs::create_dir_all(endpoint.runtime_dir()).map_err(|error| {
            TransportError::new(TransportErrorKind::Internal, error.to_string())
        })?;

        if endpoint.socket_path().is_some_and(std::path::Path::exists) {
            return Err(TransportError::new(
                TransportErrorKind::StaleEndpoint,
                "Unix socket path already exists",
            ));
        }

        let mut socket = RouterSocket::new();
        socket.bind(endpoint.address()).await.map_err(|error| {
            let kind = match &error {
                zeromq::ZmqError::Network(io_error)
                    if io_error.kind() == std::io::ErrorKind::AddrInUse =>
                {
                    TransportErrorKind::EndpointInUse
                }
                _ => TransportErrorKind::Internal,
            };
            TransportError::new(kind, error.to_string())
        })?;
        Ok(Self { socket })
    }

    /// Receives one routed client request.
    ///
    /// # Errors
    ///
    /// Returns an invalid-message error for unexpected multipart shapes and an
    /// internal error for receive failures.
    pub async fn receive(&mut self) -> Result<IncomingRequest, TransportError> {
        let message = self.socket.recv().await.map_err(|error| {
            TransportError::new(TransportErrorKind::Internal, error.to_string())
        })?;
        if message.len() != 2 {
            return Err(TransportError::new(
                TransportErrorKind::InvalidMessage,
                format!(
                    "expected identity and body frames, received {}",
                    message.len()
                ),
            ));
        }
        if message
            .get(1)
            .is_some_and(|payload| payload.len() > MAX_FRAME_SIZE)
        {
            return Err(TransportError::new(
                TransportErrorKind::FrameTooLarge,
                format!("application frame exceeds {MAX_FRAME_SIZE} bytes"),
            ));
        }
        let frames = message.into_vec();

        Ok(IncomingRequest {
            route: frames[0].to_vec(),
            payload: frames[1].to_vec(),
        })
    }

    /// Sends one response to the client that originated an incoming request.
    ///
    /// # Errors
    ///
    /// Returns an internal transport error when delivery fails.
    pub async fn respond(
        &mut self,
        request: &IncomingRequest,
        payload: Vec<u8>,
    ) -> Result<(), TransportError> {
        let mut message = ZmqMessage::from(payload);
        message.push_front(request.route.clone().into());
        self.socket.send(message).await.map_err(|error| {
            let kind = match &error {
                zeromq::ZmqError::Other("Destination client not found by identity")
                | zeromq::ZmqError::BufferFull(_)
                | zeromq::ZmqError::ReturnToSender { .. }
                | zeromq::ZmqError::ReturnToSenderMultipart { .. } => {
                    TransportErrorKind::ClientDisconnected
                }
                _ => TransportErrorKind::Internal,
            };
            TransportError::new(kind, error.to_string())
        })
    }

    /// Closes the endpoint and waits for its listener to release filesystem state.
    ///
    /// # Errors
    ///
    /// Returns an internal transport error when the endpoint cannot be released.
    pub async fn close(self) -> Result<(), TransportError> {
        let errors = self.socket.close().await;
        if errors.is_empty() {
            Ok(())
        } else {
            Err(TransportError::new(
                TransportErrorKind::Internal,
                format!("errors while closing endpoint: {errors:?}"),
            ))
        }
    }
}

pub struct ClientTransport {
    socket: DealerSocket,
}

impl ClientTransport {
    /// Connects a client-side Dealer socket to a local daemon.
    ///
    /// # Errors
    ///
    /// Returns [`TransportErrorKind::Unavailable`] when no daemon accepts the
    /// connection within the supplied timeout.
    pub async fn connect(endpoint: &LocalEndpoint, wait: Duration) -> Result<Self, TransportError> {
        let mut options = SocketOptions::default();
        options.connect_timeout(wait);
        let mut socket = DealerSocket::with_options(options);
        socket.connect(endpoint.address()).await.map_err(|error| {
            TransportError::new(TransportErrorKind::Unavailable, error.to_string())
        })?;
        Ok(Self { socket })
    }

    /// Sends one application-protocol frame.
    ///
    /// # Errors
    ///
    /// Returns an unavailable error when the frame cannot be sent.
    pub async fn send(&mut self, payload: Vec<u8>) -> Result<(), TransportError> {
        self.socket.send(payload.into()).await.map_err(|error| {
            TransportError::new(TransportErrorKind::Unavailable, error.to_string())
        })
    }

    /// Waits for one application-protocol frame.
    ///
    /// # Errors
    ///
    /// Returns an unavailable error when the daemon does not reply before the
    /// supplied timeout or the connection fails.
    pub async fn receive(&mut self, wait: Duration) -> Result<Vec<u8>, TransportError> {
        let message = timeout(wait, self.socket.recv())
            .await
            .map_err(|error| {
                TransportError::new(TransportErrorKind::Unavailable, error.to_string())
            })?
            .map_err(|error| {
                TransportError::new(TransportErrorKind::Unavailable, error.to_string())
            })?;
        Vec::<u8>::try_from(message)
            .map_err(|error| TransportError::new(TransportErrorKind::InvalidMessage, error))
    }
}
