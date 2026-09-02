//! The model layer: what weights exist, what they are, and (from wave 2 on)
//! how to fetch and run them.
//!
//! This crate knows nothing about the daemon. It reads files, inspects GGUF
//! headers, describes a curated catalog, and owns the inference runtime; the
//! daemon's `ModelService` is what turns any of that into an admin op. Keeping
//! the split sharp means the whole layer is testable without a socket, a
//! store, or a request.
//!
//! # Shape
//!
//! - [`gguf`] — a bounded header parser. It reads the header and nothing
//!   else, under hard caps, so a hostile or truncated file is a legible
//!   error instead of a multi-gigabyte allocation.
//! - [`catalog`] — the static list of models PAM offers to download,
//!   with exact sizes and SHA-256 digests.
//! - [`registry`] — what is actually on disk under the models directory:
//!   scan, classify, verify, delete.
//! - [`download`], [`tokenizer`], [`runtime`], [`curator`] — filled by the
//!   wave-2 tasks; declared here so the module list never has to change
//!   under them.
//! - [`error`] — one place to reach for the crate's error types.
//!
//! # The floor
//!
//! [`registry::MODEL_FLOOR_BYTES`] is the line between a model that may
//! serve a job and one that may only prove the wiring works. Anything under
//! 18 GB is [`ModelClass::TestOnly`]: loadable and promptable from the GUI,
//! refused as a tier default. The catalog never lists anything below it. The
//! rule lives here rather than in the daemon because it is a property of the
//! weights, not of the policy around them.
//!
//! # Blocking
//!
//! Registry and GGUF calls are synchronous and hit the filesystem —
//! [`registry::sha256_file`] streams whole gigabytes. Callers on an async
//! runtime run them through `spawn_blocking`; this crate does not decide
//! that for them.

pub mod catalog;
pub mod curator;
pub mod download;
pub mod error;
pub mod gguf;
pub mod registry;
pub mod runtime;
pub mod tokenizer;

pub use catalog::{CATALOG, Preset, find_preset};
pub use gguf::{GgufError, GgufInfo, read_info};
pub use registry::{
    MODEL_FLOOR_BYTES, ModelClass, ModelEntry, Registry, RegistryError, VerifiedRecord,
    VerifyOutcome, classify, default_models_dir,
};

#[cfg(test)]
mod catalog_test;
#[cfg(test)]
mod gguf_test;
#[cfg(test)]
mod registry_test;
