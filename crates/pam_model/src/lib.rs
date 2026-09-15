//! The model layer: what weights exist, what they are, and how to fetch and run them.
//!
//! Knows nothing about the daemon — reads files, inspects GGUF headers, describes a
//! curated catalog, owns the inference runtime; `ModelService` (daemon) turns that into
//! admin ops, keeping this layer testable without a socket, store, or request. Modules:
//! [`gguf`], [`catalog`], [`registry`], [`download`], [`runtime`], [`engine`] /
//! [`engine_server`] (out-of-process `llama.cpp`), [`curator`], [`error`].
//! [`registry::classify`] admits a model only once its digest is verified
//! ([`ModelClass::Engine`]); unverified is [`ModelClass::TestOnly`] — loadable/promptable to
//! prove wiring, never a tier default. Serving a job takes more: the verified digest must
//! match a [`qualification`] record measured on the pinned engine and this target.
//! Registry/GGUF calls are synchronous filesystem hits ([`registry::sha256_file`] streams
//! gigabytes); async callers must wrap them in `spawn_blocking` themselves.

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
pub mod qualification;
#[cfg(test)]
mod qualification_test;
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
pub use qualification::{QUALIFIED, Qualification};
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
