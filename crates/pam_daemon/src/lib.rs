//! Daemon services. Each domain (transport, policy gate, queue manager,
//! executor, approvals, audit) runs as a long-lived task owning its state
//! and communicating over typed channels.
