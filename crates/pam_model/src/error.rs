//! One import for the crate's error types.
//!
//! Each module owns the failure shape that fits it — [`GgufError`] talks
//! about headers, [`RegistryError`] about paths — because a single
//! flattened enum would force every caller to match on variants that
//! cannot happen to it. This module exists so a consumer that handles
//! several at once (the daemon's model service does) can write one `use`
//! line, and so the wave-2 modules have an obvious place to add theirs.
//!
//! There is deliberately no crate-wide error type. Refusal shaping — the
//! `{ cause, detail, recovery }` triple the GUI renders — belongs to the
//! daemon, which is the layer that knows which screen a recovery sentence
//! should point at.

pub use crate::gguf::GgufError;
pub use crate::registry::RegistryError;
