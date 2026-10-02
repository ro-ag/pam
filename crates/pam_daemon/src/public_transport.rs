//! The public plane on the framed transport: the policy and the
//! per-connection handler.
//!
//! The public listener serves [`crate::framed`] frames on
//! [`crate::runtime_dir::RuntimeDir::public_socket`] (unix) or behind
//! [`crate::runtime_dir::RuntimeDir::public_control`] (Windows), next to the
//! `ZeroMQ` sockets until those are removed. A connection carries a hello, then
//! exactly one request: a unary call answered with one reply, or a follow of
//! one ticket that ends with the durable result.
//!
//! What this plane does with a connection, and nothing else in the daemon:
//!
//! - records the kernel's view of the peer ([`crate::ingress::PublicPeer`]) and
//!   never admits or refuses by it;
//! - applies the version rule of [`crate::image`] to the hello;
//! - refuses `admin.*` before anything is retained;
//! - hands a request to the daemon core through [`crate::ingress::Ingress`] and
//!   waits on its reply, the peer going away, and the listener's stop at once;
//! - follows a ticket through [`crate::event_hub::EventHub::attach`], with the
//!   sanitised events a public client may see.
//!
//! The listener is started by [`crate::transport::Transport::bind_with`]. The
//! policy and the handler are not written yet: this module holds its place.
