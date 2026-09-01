//! Wire types shared by the pam client and daemon.
//!
//! The protocol is internal: agents only ever see `pam` subcommands, so
//! these types may evolve freely as long as client and daemon ship in the
//! same binary. The envelope still carries a version field to detect a
//! daemon that predates the installed binary.

mod envelope;
mod event;
mod response;

pub use envelope::{Caller, Envelope};
pub use event::Event;
pub use response::{Outcome, Response};

/// Protocol version stamped on every request envelope.
pub const PROTOCOL_VERSION: u32 = 1;

#[cfg(test)]
mod envelope_test;
#[cfg(test)]
mod event_test;
#[cfg(test)]
mod lib_test;
#[cfg(test)]
mod response_test;
