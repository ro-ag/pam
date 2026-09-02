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
//! - [`tokenizer`] — a byte-level BPE rebuilt from the model file's own
//!   metadata, so a model stays one file on disk.
//! - [`runtime`] — the candle inference thread: load, unload, generate.
//! - [`curator`] — the vendor agent CLIs installed on the machine: detect
//!   them, ask one a single tool-free question.
//! - [`qwen3_moe`] — candle's mixture-of-experts model, vendored so that its
//!   KV cache can be cleared between generations instead of the whole model
//!   being rebuilt.
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
pub mod qwen3_moe;
pub mod registry;
pub mod runtime;
pub mod tokenizer;

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
    MODEL_FLOOR_BYTES, ModelClass, ModelEntry, Registry, RegistryError, VerifiedRecord,
    VerifyOutcome, classify, default_models_dir,
};
pub use runtime::{
    CONTEXT_TOKENS, GenerateRequest, GenerateResult, LoadedModel, Runtime, RuntimeError,
    RuntimeSnapshot, RuntimeState,
};
pub use tokenizer::{GgufTokenizer, TokenizerError, chatml};

#[cfg(test)]
mod catalog_test;
#[cfg(test)]
mod curator_test;
#[cfg(test)]
mod download_server_test;
#[cfg(test)]
mod download_test;
#[cfg(test)]
mod gguf_test;
#[cfg(test)]
mod registry_test;
#[cfg(test)]
mod runtime_test;
#[cfg(test)]
mod tokenizer_test;
