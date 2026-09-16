//! Shared inference types.
//!
//! The in-process candle runtime that used to live here is gone (2026-09-13,
//! plan 37): llama.cpp via [`crate::engine`] and [`crate::engine_server`] is
//! the only inference path now. This module keeps the types every caller —
//! [`crate::engine_server`], `pam_daemon::model_service`, the admin surface —
//! still shares: the request/result shapes, the loaded-model description,
//! the runtime snapshot the GUI polls, and the error contract the daemon's
//! refusals are built from.

/// The context window PAM runs models in, in tokens.
///
/// Capped at 8192 and lowered to the header's `<arch>.context_length` when
/// the header reports less (`pam_daemon::model_service::context_tokens_for`
/// does this now). The cap exists because the KV cache for a 30B `MoE` at
/// its advertised context does not fit in the machines PAM targets, and a
/// number that is true on paper but fails at token 40 000 is a lie the human
/// pays for. 8192 is the figure pam-old ran on.
pub const CONTEXT_TOKENS: usize = 8192;

/// What to generate, and how far to let it run.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct GenerateRequest {
    /// System prompt. `None` omits the system turn entirely rather than
    /// sending an empty one.
    pub system: Option<String>,
    /// The user turn.
    pub prompt: String,
    /// Hard ceiling on generated tokens.
    pub max_tokens: usize,
    /// 0 means greedy (argmax); anything above samples.
    pub temperature: f64,
    /// Strings that end generation when they appear in the decoded text.
    pub stop: Vec<String>,
}

/// What a generation produced, and what it cost.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct GenerateResult {
    /// Identity captured from the worker that performed this generation.
    /// This is loaded-model metadata, not a freshly verified file digest.
    pub model: GenerationModel,
    /// The decoded completion, special tokens dropped and truncated at a
    /// stop string when one hit.
    pub text: String,
    /// Tokens in the framed prompt, after the model's own chat template.
    pub prompt_tokens: usize,
    /// Tokens generated.
    pub completion_tokens: usize,
    /// Milliseconds spent framing, encoding and running the prompt forward.
    pub prompt_ms: u64,
    /// Milliseconds spent in the per-token loop.
    pub decode_ms: u64,
    /// `completion_tokens` over decode seconds, 0.0 when nothing was
    /// generated.
    pub tokens_per_sec: f64,
}

/// Actual loaded-model identity associated with a single generation.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct GenerationModel {
    /// Registry ID of the loaded artifact.
    pub id: String,
    /// Architecture actually loaded by the worker.
    pub architecture: String,
    /// Quantization label recorded at load.
    pub quant: String,
    /// Actual backend, for example `llama.cpp`.
    pub device: String,
    /// Artifact size recorded at load, not a working-set measurement.
    pub weight_bytes: u64,
}

impl From<&LoadedModel> for GenerationModel {
    fn from(model: &LoadedModel) -> Self {
        Self {
            id: model.id.clone(),
            architecture: model.architecture.clone(),
            quant: model.quant.clone(),
            device: model.device.clone(),
            weight_bytes: model.weight_bytes,
        }
    }
}

/// The model currently in memory.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct LoadedModel {
    /// Registry id, `<vendor>/<file stem>`.
    pub id: String,
    /// Quantization label from the GGUF header, or `unknown`.
    pub quant: String,
    /// `general.architecture`.
    pub architecture: String,
    /// The context the engine was started with. Today that is always
    /// [`CONTEXT_TOKENS`] (the daemon loads every model with
    /// `ServerOptions::default()`); the header's own
    /// `<arch>.context_length` is reported by the registry but not
    /// consulted at load, so a model advertising less than 8192 is started
    /// above its window rather than clamped.
    pub context_length: usize,
    /// Artifact file size. Not a working-set measurement.
    pub weight_bytes: u64,
    /// `llama.cpp` — the engine is the only inference path.
    pub device: String,
    /// Unix seconds when the load finished.
    pub loaded_at: i64,
    /// Unix seconds of the last generation, or of the load.
    pub last_used_at: i64,
    /// Decode rate of the last generation.
    pub last_tokens_per_sec: Option<f64>,
}

/// Where the runtime is.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum RuntimeState {
    /// Nothing loaded; the memory is back with the developer.
    Idle,
    /// A load is in flight.
    Loading {
        /// The phase name.
        phase: String,
        /// Registry id being loaded.
        id: String,
    },
    /// Weights are in memory.
    Loaded(LoadedModel),
}

/// The whole runtime state in one readable value.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct RuntimeSnapshot {
    /// Idle, loading, or loaded.
    pub state: RuntimeState,
    /// True while a generation is in flight.
    pub busy: bool,
}

/// Everything the model layer can refuse or fail at.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RuntimeError {
    /// A generate arrived with nothing loaded.
    #[error("no model is loaded")]
    NoModelLoaded,
    /// The engine could not load, or is not installed.
    #[error("load failed: {0}")]
    LoadFailed(String),
    /// The framed prompt plus its token budget does not fit the context.
    #[error("prompt is {tokens} tokens; the context allows {limit}")]
    PromptTooLong {
        /// Tokens in the framed prompt.
        tokens: usize,
        /// [`CONTEXT_TOKENS`].
        limit: usize,
    },
    /// Another generation holds the worker.
    #[error("another generation is running")]
    Busy,
    /// The cancel watch flipped mid-generation.
    #[error("generation cancelled")]
    Cancelled,
    /// The engine failed during generation.
    #[error("generation failed: {0}")]
    GenerationFailed(String),
}

impl RuntimeError {
    /// The stable machine-readable cause the daemon puts in a refusal.
    ///
    /// These strings are contract: the GUI matches on them to pick a
    /// recovery sentence, so they change only when the GUI does.
    #[must_use]
    pub fn cause(&self) -> &'static str {
        match self {
            Self::NoModelLoaded => "no_model_loaded",
            Self::LoadFailed(_) => "load_failed",
            Self::PromptTooLong { .. } => "prompt_too_long",
            Self::Busy => "busy",
            Self::Cancelled => "cancelled",
            Self::GenerationFailed(_) => "generation_failed",
        }
    }
}
