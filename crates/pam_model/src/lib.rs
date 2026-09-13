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
//! - [`download`] — resumable transfers through the system `curl`, with
//!   the integrity check done here rather than trusted to the network.
//! - [`runtime`] — shared inference types (requests, results, snapshots,
//!   errors). Inference itself runs out of process, in the pinned
//!   `llama.cpp` release [`engine`] installs and [`engine_server`]
//!   supervises.
//! - [`curator`] — the vendor agent CLIs installed on the machine: detect
//!   them, ask one a single tool-free question.
//! - [`error`] — one place to reach for the crate's error types.
//!
//! # Admission
//!
//! [`registry::classify`] admits a model only once its digest is verified:
//! a verified file is [`ModelClass::Engine`] and may be a tier default;
//! anything unverified is [`ModelClass::TestOnly`], loadable and promptable
//! from the GUI to prove the wiring, refused as a tier default. Size decides
//! nothing since the llama.cpp engine replaced the in-process runtime.
//!
//! # Blocking
//!
//! Registry and GGUF calls are synchronous and hit the filesystem —
//! [`registry::sha256_file`] streams whole gigabytes. Callers on an async
//! runtime run them through `spawn_blocking`; this crate does not decide
//! that for them.

pub mod catalog;
pub mod curator;
pub mod diagnosis;
#[cfg(test)]
mod diagnosis_test;
pub mod download;
pub mod engine;
pub mod engine_http;
pub mod engine_server;
pub mod error;
pub mod gguf;
pub mod registry;
pub mod runtime;

/// A range-serving HTTP origin for download tests.
///
/// Compiled for this crate's own tests, and for anyone who turns on the
/// `testing` feature — the daemon's admin-op suite drives a real download
/// end to end and needs the same origin rather than a second copy of it.
#[cfg(any(test, feature = "testing"))]
pub mod testing;

pub use catalog::{CATALOG, Preset, find_preset};
pub use curator::{
    AgentCli, AgentId, CuratorError, INVOKE_MAX_OUTPUT, detect, invoke, invoke_args,
};
pub use download::{
    DownloadError, DownloadHandle, DownloadProgress, DownloadRequest, DownloadState, curl_path,
    start,
};
pub use gguf::{GgufError, GgufInfo, read_info};
pub use registry::{
    ModelClass, ModelEntry, Registry, RegistryError, VerifiedRecord, VerifyOutcome, classify,
    default_models_dir,
};
pub use runtime::{
    CONTEXT_TOKENS, GenerateRequest, GenerateResult, LoadedModel, RuntimeError, RuntimeSnapshot,
    RuntimeState,
};

#[cfg(test)]
mod catalog_test;
#[cfg(test)]
mod curator_test;
#[cfg(test)]
mod download_test;
#[cfg(test)]
mod gguf_test;
#[cfg(test)]
mod registry_test;
