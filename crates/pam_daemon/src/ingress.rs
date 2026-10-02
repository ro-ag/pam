//! Where a request entered the daemon.
//!
//! Every [`crate::transport::IncomingRequest`] carries an [`Origin`]. It is the
//! only thing the pipeline may use to tell a request that arrived on the public
//! socket from one the private administration plane submitted on a human's
//! behalf: `caller.agent`, `caller.repo` and `caller.pid` are self-reported
//! attribution and authorize nothing.
//!
//! The audit actor is decided by origin, never by label: a public `cancel` is
//! recorded as `system` whatever its `caller.agent` says, and only a request of
//! [`Origin::Admin`] is recorded as `human`.
//!
//! This is the transport-independent half of the ingress seam. The peer's
//! kernel identity and the relay marker join [`Origin::Public`] when the
//! public listener can supply them; nothing that reads an origin today depends
//! on how the bytes arrived.

/// Which plane a request arrived on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {
    /// Arrived on the public listener: an agent, the CLI, or anything else
    /// that can reach `pam.sock`.
    Public,
    /// Submitted by [`crate::admin::AdminService`] on behalf of a request that
    /// arrived on the private admin listener (the GUI: a run, an inspect, a
    /// cancel).
    Admin,
}
