//! Frames of the length-prefixed JSON protocol both daemon planes speak.
//!
//! A frame on the wire is a 4-byte big-endian length `N` followed by `N` bytes
//! of UTF-8 JSON holding one object with a `"t"` member naming its type. This
//! module owns the JSON half: the [`Frame`] type, the protocol number, the byte
//! limits and the cause names of transport-level errors. The length prefix, the
//! sockets and every timeout live in the daemon crate.
//!
//! A connection carries a `hello`, then exactly one request, then its answer:
//!
//! - client to daemon: `hello`, then one of `request`, `follow` (public plane)
//!   or `request`, `events` (administration plane);
//! - daemon to client: `hello_ack`, then `reply`; or `following`, `event`*,
//!   `end`; or `subscribed`, `event`* (all events); or `error` at any point,
//!   after which the daemon closes.
//!
//! Unknown members are ignored. A frame whose `"t"` the receiver does not know
//! is [`FrameError::UnknownType`]: a protocol error for the daemon, skipped by
//! a client inside a follow stream.

use serde::{Deserialize, Serialize};

use crate::{Envelope, Event, Response};

/// Wire protocol number carried in `hello` and `hello_ack`. The envelope
/// protocol of pre-migration builds (ZMTP) was 1.
pub const WIRE_PROTOCOL: u32 = 2;

/// Largest public request, reply or event frame, and the largest
/// administration request frame, in bytes.
pub const MAX_FRAME_BYTES: usize = 1024 * 1024;

/// Largest administration reply frame, in bytes.
pub const MAX_ADMIN_REPLY_BYTES: usize = 16 * 1024 * 1024;

/// Largest `hello` frame, in bytes. Nothing legitimate is larger.
pub const MAX_HELLO_BYTES: usize = 4 * 1024;

/// Longest `version` a `hello` may carry, in bytes.
pub const MAX_VERSION_BYTES: usize = 64;

/// First byte of a ZMTP greeting: what a pre-migration peer sends on connect.
/// No valid first frame starts with it, because a first frame is at most
/// [`MAX_HELLO_BYTES`] long and so begins with `0x00`.
pub const ZMTP_GREETING_FIRST_BYTE: u8 = 0xFF;

/// Cause names of `error` frames and of the refusals the framed transport
/// itself raises.
pub mod cause {
    /// `hello.proto` is not one this daemon speaks.
    pub const PROTOCOL_MISMATCH: &str = "protocol_mismatch";
    /// The hello's version differs and the daemon's image on disk is unchanged.
    pub const CLIENT_VERSION_MISMATCH: &str = "client_version_mismatch";
    /// The hello's version differs and the daemon's image was replaced; the
    /// daemon is restarting.
    pub const DAEMON_OUTDATED: &str = "daemon_outdated";
    /// Not JSON, no `"t"`, an unknown or out-of-order frame type, a length
    /// outside the limit, or bytes after `follow`.
    pub const BAD_FRAME: &str = "bad_frame";
    /// The hello and the request frame did not arrive in time.
    pub const HANDSHAKE_TIMEOUT: &str = "handshake_timeout";
    /// The listener's connection cap is reached.
    pub const CONNECTION_CAPACITY_EXHAUSTED: &str = "connection_capacity_exhausted";
    /// A stream was cut by the daemon's drain.
    pub const DAEMON_SHUTTING_DOWN: &str = "daemon_shutting_down";
    /// A follow reached its maximum lifetime.
    pub const FOLLOW_EXPIRED: &str = "follow_expired";
    /// An all-events subscriber overflowed its queue.
    pub const SUBSCRIBER_LAGGED: &str = "subscriber_lagged";
    /// Every all-events subscriber slot is taken. Transient: a slot frees when
    /// another subscriber's connection ends.
    pub const SUBSCRIBER_CAPACITY_EXHAUSTED: &str = "subscriber_capacity_exhausted";
    /// Every follower slot (in total, or for one ticket) is taken. Carried by
    /// a refusal in an `end` frame; transient.
    pub const FOLLOWER_CAPACITY_EXHAUSTED: &str = "follower_capacity_exhausted";
}

/// How a client reached the daemon. Self-reported; attribution only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Via {
    /// Dialled the daemon's own socket.
    #[default]
    Direct,
    /// Dialled a `pam listen` session relay (`PAM_SOCKET_DIR`).
    Relay,
}

/// Which plane a ticket was admitted on, as the all-events stream reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Ingress {
    /// The public listener.
    Public,
    /// The private administration listener.
    Admin,
}

/// First frame of every connection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hello {
    /// Wire protocol number; [`WIRE_PROTOCOL`] for this build.
    pub proto: u32,
    /// The client binary's version, at most [`MAX_VERSION_BYTES`]. A hint:
    /// the daemon never restarts on it alone.
    pub version: String,
    /// How the client reached the daemon.
    #[serde(default)]
    pub via: Via,
}

/// The daemon's answer to an accepted [`Hello`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HelloAck {
    /// Wire protocol number the daemon speaks.
    pub proto: u32,
    /// The daemon's version.
    pub version: String,
    /// A ULID minted at daemon boot. A follower that sees a different epoch
    /// knows its sequence numbers belong to a daemon that is gone.
    pub epoch: String,
}

/// Public follow request: a waiting `query` for one ticket, plus where a
/// resuming client left off.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Follow {
    /// The authorising `query` envelope.
    pub envelope: Envelope,
    /// Last sequence number this client saw; `0` for a fresh follow.
    #[serde(default)]
    pub after_seq: u64,
    /// The epoch `after_seq` was seen under; `None` for a fresh follow.
    #[serde(default)]
    pub epoch: Option<String>,
}

/// First frame of an accepted follow stream.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Following {
    /// The followed ticket.
    pub ticket: String,
    /// The daemon's epoch (see [`HelloAck::epoch`]).
    pub epoch: String,
    /// Durable state at attach: `queued`, `running` or `waiting_approval`.
    pub state: String,
    /// The ticket's latest sequence number at attach.
    pub seq: u64,
}

/// One lifecycle event. A follow stream sets `seq` only; the administration
/// all-events stream sets `n`, `ticket` and whatever admission metadata the
/// daemon holds for the ticket.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EventFrame {
    /// Per-ticket sequence number, starting at 1 (follow stream).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seq: Option<u64>,
    /// Daemon-wide counter; a gap means the subscriber missed events
    /// (all-events stream).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub n: Option<u64>,
    /// The ticket the event belongs to (all-events stream).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ticket: Option<String>,
    /// The ticket's capability (all-events stream).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capability: Option<String>,
    /// The caller's repository as admitted (all-events stream).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repo: Option<String>,
    /// The caller's self-reported agent label (all-events stream).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent: Option<String>,
    /// The plane the ticket was admitted on (all-events stream).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ingress: Option<Ingress>,
    /// The event itself.
    pub event: Event,
}

/// Last frame of a follow stream: the durable answer.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct End {
    /// Sequence number of the terminal event; absent when the follow itself
    /// was refused.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seq: Option<u64>,
    /// The terminal event (`done` or `refused`); absent when the follow
    /// itself was refused.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event: Option<Event>,
    /// The scoped `query` answer read from the store, or the refusal.
    pub response: Response,
}

/// A transport-level failure with no request to answer. The daemon closes
/// after sending it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorFrame {
    /// Machine-readable cause; see [`cause`].
    pub cause: String,
    /// Human-readable explanation.
    pub detail: String,
    /// What to do about it.
    pub recovery: String,
}

impl ErrorFrame {
    /// An error frame from borrowed parts.
    #[must_use]
    pub fn new(cause: &str, detail: &str, recovery: &str) -> Self {
        Self {
            cause: cause.to_owned(),
            detail: detail.to_owned(),
            recovery: recovery.to_owned(),
        }
    }
}

/// One frame, tagged by its `"t"` member.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum Frame {
    /// Client: first frame of every connection.
    Hello(Hello),
    /// Daemon: the hello was accepted.
    HelloAck(HelloAck),
    /// Client: one unary call.
    Request {
        /// The request envelope, unchanged from the envelope protocol.
        envelope: Envelope,
    },
    /// Daemon: the answer to a `request`.
    Reply {
        /// The response, unchanged from the envelope protocol.
        response: Response,
    },
    /// Client (public plane): follow one ticket.
    Follow(Follow),
    /// Daemon: the follow was authorised and attached.
    Following(Following),
    /// Daemon: one event of a follow or all-events stream.
    Event(EventFrame),
    /// Daemon: the follow stream's final frame.
    End(End),
    /// Client (administration plane): stream every event. A bare marker:
    /// the daemon publishes no lifecycle events for control requests
    /// (`status`, `query`, `cancel`), so there is nothing to select.
    Events,
    /// Daemon (administration plane): the `events` subscription is in place.
    /// Every event published from here on is delivered or shows as a gap in
    /// `n`; nothing published before it is replayed.
    Subscribed,
    /// Daemon: a transport-level failure; the connection closes.
    Error(ErrorFrame),
}

/// Every frame type name this build understands.
pub const FRAME_TYPES: [&str; 11] = [
    "hello",
    "hello_ack",
    "request",
    "reply",
    "follow",
    "following",
    "event",
    "end",
    "events",
    "subscribed",
    "error",
];

/// Why a frame body could not be decoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrameError {
    /// The body is not JSON, or not a JSON object.
    NotJson(String),
    /// The object has no string `"t"` member. A pre-migration client's bare
    /// envelope looks like this.
    Untyped,
    /// `"t"` names a type this build does not know.
    UnknownType(String),
    /// `"t"` is known but the rest of the object does not fit it (for a
    /// `request`, typically an envelope that does not parse).
    Invalid {
        /// The frame type the object claimed.
        t: String,
        /// What did not fit.
        detail: String,
    },
}

impl std::fmt::Display for FrameError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotJson(detail) => write!(formatter, "frame is not a JSON object: {detail}"),
            Self::Untyped => formatter.write_str("frame has no \"t\" member"),
            Self::UnknownType(t) => write!(formatter, "unknown frame type {t:?}"),
            Self::Invalid { t, detail } => write!(formatter, "malformed {t} frame: {detail}"),
        }
    }
}

impl std::error::Error for FrameError {}

impl Frame {
    /// The frame's `"t"` value.
    #[must_use]
    pub fn type_name(&self) -> &'static str {
        match self {
            Self::Hello(_) => "hello",
            Self::HelloAck(_) => "hello_ack",
            Self::Request { .. } => "request",
            Self::Reply { .. } => "reply",
            Self::Follow(_) => "follow",
            Self::Following(_) => "following",
            Self::Event(_) => "event",
            Self::End(_) => "end",
            Self::Events => "events",
            Self::Subscribed => "subscribed",
            Self::Error(_) => "error",
        }
    }

    /// The frame body as JSON bytes, without the length prefix.
    pub fn encode(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(self)
    }

    /// Decodes one frame body, telling apart the ways it can be wrong.
    pub fn decode(body: &[u8]) -> Result<Self, FrameError> {
        let fast = match serde_json::from_slice::<Self>(body) {
            Ok(frame) => return Ok(frame),
            Err(error) => error.to_string(),
        };
        // The slow path only names the failure; the body is already bounded
        // by the frame limit.
        let value: serde_json::Value =
            serde_json::from_slice(body).map_err(|error| FrameError::NotJson(error.to_string()))?;
        let Some(object) = value.as_object() else {
            return Err(FrameError::NotJson("not an object".to_owned()));
        };
        let Some(t) = object.get("t").and_then(serde_json::Value::as_str) else {
            return Err(FrameError::Untyped);
        };
        if FRAME_TYPES.contains(&t) {
            Err(FrameError::Invalid {
                t: t.to_owned(),
                detail: fast,
            })
        } else {
            // Bound what an error message can echo back.
            Err(FrameError::UnknownType(t.chars().take(64).collect()))
        }
    }

    /// A follow-stream event frame.
    #[must_use]
    pub fn follow_event(seq: u64, event: Event) -> Self {
        Self::Event(EventFrame {
            seq: Some(seq),
            n: None,
            ticket: None,
            capability: None,
            repo: None,
            agent: None,
            ingress: None,
            event,
        })
    }

    /// An `error` frame from borrowed parts.
    #[must_use]
    pub fn error(cause: &str, detail: &str, recovery: &str) -> Self {
        Self::Error(ErrorFrame::new(cause, detail, recovery))
    }
}

/// Best-effort extraction of `envelope.id` from a `request` or `follow` frame
/// whose envelope did not parse, so the refusal can still name the request.
#[must_use]
pub fn salvage_envelope_id(body: &[u8]) -> Option<String> {
    serde_json::from_slice::<serde_json::Value>(body)
        .ok()
        .as_ref()
        .and_then(|value| value.get("envelope"))
        .and_then(|envelope| envelope.get("id"))
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
}
