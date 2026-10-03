//! Wire types shared by the pam client and daemon.
//!
//! The protocol is internal: agents only ever see `pam` subcommands, so
//! these types may evolve freely as long as client and daemon ship in the
//! same binary. Envelopes, responses and events travel inside the frames of
//! [`wire`]; a connection's `hello` is what tells a daemon and a client of
//! different builds apart, not anything in the envelope.

pub mod caller;
pub mod doctor;
mod envelope;
mod event;
mod response;
pub mod wire;

pub use envelope::{Caller, Envelope};
pub use event::Event;
pub use response::{Outcome, Response};

/// Protocol version stamped on every request envelope: the wire protocol
/// number ([`wire::WIRE_PROTOCOL`]). It is recorded, not judged; the hello is.
pub const PROTOCOL_VERSION: u32 = wire::WIRE_PROTOCOL;

#[cfg(test)]
mod caller_test;
#[cfg(test)]
mod doctor_test;
#[cfg(test)]
mod envelope_test;
#[cfg(test)]
mod event_test;
#[cfg(test)]
mod lib_test;
#[cfg(test)]
mod response_test;
#[cfg(test)]
mod wire_test;
