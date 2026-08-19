use std::{
    error::Error,
    fmt,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use pam_core::ContentDigest;
use serde::{Deserialize, Serialize};

use crate::{MemoryEstimateError, ModelError, RuntimeMemoryProjection};

const MAX_RUNTIME_MESSAGES: usize = 128;
const MAX_RUNTIME_MESSAGE_BYTES: usize = 1024 * 1024;
const MAX_RUNTIME_REQUEST_BYTES: usize = 4 * 1024 * 1024;
const MAX_RUNTIME_OUTPUT_TOKENS: u32 = 4096;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeMessageRole {
    System,
    User,
    Assistant,
}

impl RuntimeMessageRole {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::System => "system",
            Self::User => "user",
            Self::Assistant => "assistant",
        }
    }
}

#[derive(Clone, Eq, PartialEq, Serialize)]
pub struct RuntimeMessage {
    role: RuntimeMessageRole,
    content: String,
}

impl fmt::Debug for RuntimeMessage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RuntimeMessage")
            .field("role", &self.role)
            .field("content_bytes", &self.content.len())
            .finish()
    }
}

impl RuntimeMessage {
    /// Creates one bounded chat message without runtime-specific types.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeError::InvalidRequest`] for empty, oversized, or
    /// NUL-containing content.
    pub fn new(role: RuntimeMessageRole, content: impl Into<String>) -> Result<Self, RuntimeError> {
        let content = content.into();
        if content.is_empty() {
            return Err(RuntimeError::InvalidRequest("message content is empty"));
        }
        if content.len() > MAX_RUNTIME_MESSAGE_BYTES {
            return Err(RuntimeError::InvalidRequest("message content is too large"));
        }
        if content.contains('\0') {
            return Err(RuntimeError::InvalidRequest(
                "message content contains a NUL byte",
            ));
        }
        Ok(Self { role, content })
    }

    #[must_use]
    pub const fn role(&self) -> RuntimeMessageRole {
        self.role
    }

    #[must_use]
    pub fn content(&self) -> &str {
        &self.content
    }
}

#[derive(Clone, Eq, PartialEq, Serialize)]
pub struct RuntimeRequest {
    messages: Vec<RuntimeMessage>,
    max_output_tokens: u32,
}

impl fmt::Debug for RuntimeRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let content_bytes = self
            .messages
            .iter()
            .map(|message| message.content.len())
            .sum::<usize>();
        formatter
            .debug_struct("RuntimeRequest")
            .field("message_count", &self.messages.len())
            .field("content_bytes", &content_bytes)
            .field("max_output_tokens", &self.max_output_tokens)
            .finish()
    }
}

impl RuntimeRequest {
    /// Creates a bounded text-only chat-completion request.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeError::InvalidRequest`] unless there is a bounded,
    /// non-empty conversation ending in a user message and a positive output
    /// token limit no greater than 4096.
    pub fn new(
        messages: Vec<RuntimeMessage>,
        max_output_tokens: u32,
    ) -> Result<Self, RuntimeError> {
        if messages.is_empty() || messages.len() > MAX_RUNTIME_MESSAGES {
            return Err(RuntimeError::InvalidRequest(
                "request must contain between 1 and 128 messages",
            ));
        }
        if messages.last().map(RuntimeMessage::role) != Some(RuntimeMessageRole::User) {
            return Err(RuntimeError::InvalidRequest(
                "request must end with a user message",
            ));
        }
        if !(1..=MAX_RUNTIME_OUTPUT_TOKENS).contains(&max_output_tokens) {
            return Err(RuntimeError::InvalidRequest(
                "max output tokens must be between 1 and 4096",
            ));
        }
        let total_message_bytes = messages.iter().try_fold(0_usize, |total, message| {
            total.checked_add(message.content.len())
        });
        if total_message_bytes.is_none_or(|total| total > MAX_RUNTIME_REQUEST_BYTES) {
            return Err(RuntimeError::InvalidRequest(
                "aggregate message content is too large",
            ));
        }
        Ok(Self {
            messages,
            max_output_tokens,
        })
    }

    #[must_use]
    pub fn messages(&self) -> &[RuntimeMessage] {
        &self.messages
    }

    #[must_use]
    pub const fn max_output_tokens(&self) -> u32 {
        self.max_output_tokens
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeFinishReason {
    Stop,
    Length,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RuntimeUsage {
    pub input_tokens: u32,
    pub sampled_output_tokens: u32,
    pub emitted_output_tokens: u32,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
pub struct RuntimeResponse {
    pub text: String,
    pub finish_reason: RuntimeFinishReason,
    pub usage: RuntimeUsage,
}

impl fmt::Debug for RuntimeResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RuntimeResponse")
            .field("text_bytes", &self.text.len())
            .field("finish_reason", &self.finish_reason)
            .field("usage", &self.usage)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeGpuOffload {
    All,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeFlashAttention {
    Auto,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeKvCachePrecision {
    F16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeSampling {
    Greedy,
    TopKTopPTemperature,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeProfile {
    model_digest: ContentDigest,
    context_tokens: u32,
    batch_tokens: u32,
    physical_batch_tokens: u32,
    parallel_sequences: u32,
    gpu_offload: RuntimeGpuOffload,
    flash_attention: RuntimeFlashAttention,
    kv_cache_precision: RuntimeKvCachePrecision,
    kv_cache_unified: bool,
    sampling: RuntimeSampling,
    max_projected_bytes: u64,
    projection: RuntimeMemoryProjection,
}

impl RuntimeProfile {
    #[cfg(target_os = "macos")]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        model_digest: ContentDigest,
        context_tokens: u32,
        batch_tokens: u32,
        physical_batch_tokens: u32,
        parallel_sequences: u32,
        gpu_offload: RuntimeGpuOffload,
        flash_attention: RuntimeFlashAttention,
        kv_cache_precision: RuntimeKvCachePrecision,
        kv_cache_unified: bool,
        sampling: RuntimeSampling,
        max_projected_bytes: u64,
        projection: RuntimeMemoryProjection,
    ) -> Result<Self, RuntimeError> {
        if context_tokens == 0
            || batch_tokens == 0
            || physical_batch_tokens == 0
            || physical_batch_tokens > batch_tokens
            || parallel_sequences == 0
            || max_projected_bytes == 0
            || projection.model_digest() != &model_digest
            || projection.allocated_context_tokens() != context_tokens
        {
            return Err(RuntimeError::InitializationFailed(
                "runtime profile invariants are invalid",
            ));
        }
        Ok(Self {
            model_digest,
            context_tokens,
            batch_tokens,
            physical_batch_tokens,
            parallel_sequences,
            gpu_offload,
            flash_attention,
            kv_cache_precision,
            kv_cache_unified,
            sampling,
            max_projected_bytes,
            projection,
        })
    }

    #[must_use]
    pub fn model_digest(&self) -> &ContentDigest {
        &self.model_digest
    }

    #[must_use]
    pub const fn context_tokens(&self) -> u32 {
        self.context_tokens
    }

    #[must_use]
    pub const fn batch_tokens(&self) -> u32 {
        self.batch_tokens
    }

    #[must_use]
    pub const fn physical_batch_tokens(&self) -> u32 {
        self.physical_batch_tokens
    }

    #[must_use]
    pub const fn parallel_sequences(&self) -> u32 {
        self.parallel_sequences
    }

    #[must_use]
    pub const fn gpu_offload(&self) -> RuntimeGpuOffload {
        self.gpu_offload
    }

    #[must_use]
    pub const fn flash_attention(&self) -> RuntimeFlashAttention {
        self.flash_attention
    }

    #[must_use]
    pub const fn kv_cache_precision(&self) -> RuntimeKvCachePrecision {
        self.kv_cache_precision
    }

    #[must_use]
    pub const fn kv_cache_unified(&self) -> bool {
        self.kv_cache_unified
    }

    #[must_use]
    pub const fn sampling(&self) -> RuntimeSampling {
        self.sampling
    }

    #[must_use]
    pub const fn max_projected_bytes(&self) -> u64 {
        self.max_projected_bytes
    }

    #[must_use]
    pub const fn projection(&self) -> &RuntimeMemoryProjection {
        &self.projection
    }
}

pub trait CancellationSignal: Send + Sync {
    fn is_cancelled(&self) -> bool;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeMemoryPressure {
    Normal,
    Warning,
    Critical,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeSwapTrend {
    /// Two bounded monotonic swap-out samples were equal.
    Stable,
    /// The later bounded swap-out sample increased.
    Rising,
    /// Swap activity could not be ordered safely.
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuntimeHostSnapshot {
    total_bytes: u64,
    available_bytes: u64,
    reserved_os_bytes: u64,
    reserved_application_bytes: u64,
    projection_contingency_bytes: u64,
    pressure: RuntimeMemoryPressure,
    swap_trend: RuntimeSwapTrend,
}

impl RuntimeHostSnapshot {
    /// Creates a fresh model-neutral host-memory snapshot.
    ///
    /// The macOS adapter obtains Metal's working-set ceiling from the same
    /// llama.cpp projection used for runtime admission; callers provide only
    /// operating-system memory facts, a bounded swap-activity trend, and PAM's
    /// explicit reserve policy.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeError::AdmissionUnavailable`] when the snapshot is
    /// internally inconsistent.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        total_bytes: u64,
        available_bytes: u64,
        reserved_os_bytes: u64,
        reserved_application_bytes: u64,
        projection_contingency_bytes: u64,
        pressure: RuntimeMemoryPressure,
        swap_trend: RuntimeSwapTrend,
    ) -> Result<Self, RuntimeError> {
        if total_bytes == 0 || available_bytes > total_bytes || reserved_os_bytes > total_bytes {
            return Err(RuntimeError::AdmissionUnavailable(
                "host memory snapshot is invalid",
            ));
        }
        Ok(Self {
            total_bytes,
            available_bytes,
            reserved_os_bytes,
            reserved_application_bytes,
            projection_contingency_bytes,
            pressure,
            swap_trend,
        })
    }

    #[must_use]
    pub const fn total_bytes(self) -> u64 {
        self.total_bytes
    }

    #[must_use]
    pub const fn available_bytes(self) -> u64 {
        self.available_bytes
    }

    #[must_use]
    pub const fn reserved_os_bytes(self) -> u64 {
        self.reserved_os_bytes
    }

    #[must_use]
    pub const fn reserved_application_bytes(self) -> u64 {
        self.reserved_application_bytes
    }

    #[must_use]
    pub const fn projection_contingency_bytes(self) -> u64 {
        self.projection_contingency_bytes
    }

    #[must_use]
    pub const fn pressure(self) -> RuntimeMemoryPressure {
        self.pressure
    }

    #[must_use]
    pub const fn swap_trend(self) -> RuntimeSwapTrend {
        self.swap_trend
    }
}

pub trait RuntimeHostAdmission: Send + Sync {
    /// Captures current operating-system memory and pressure.
    ///
    /// The macOS adapter calls this after projection and immediately before
    /// model load so callers cannot substitute a persisted availability value.
    /// It obtains the accelerator working-set limit independently from the
    /// same llama.cpp projection report used for model admission.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeError`] when any required host fact cannot be sampled.
    /// Adapters must reject [`RuntimeSwapTrend::Rising`] and
    /// [`RuntimeSwapTrend::Unknown`] before loading model weights.
    fn snapshot(&self) -> Result<RuntimeHostSnapshot, RuntimeError>;
}

#[derive(Clone, Debug, Default)]
pub struct CancellationToken {
    cancelled: Arc<AtomicBool>,
}

impl CancellationToken {
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
    }
}

impl CancellationSignal for CancellationToken {
    fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }
}

pub trait ModelRuntime: Send + Sync {
    fn profile(&self) -> &RuntimeProfile;

    /// Runs one request on the runtime's serialized generation worker.
    ///
    /// This method blocks until generation completes. Async callers must run
    /// it on a blocking executor; service-level queueing belongs outside the
    /// model runtime.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeError`] when validation, cancellation, runtime state,
    /// or inference fails.
    fn generate(
        &self,
        request: RuntimeRequest,
        cancellation: CancellationToken,
    ) -> Result<RuntimeResponse, RuntimeError>;
}

pub enum RuntimeError {
    InvalidRequest(&'static str),
    ArtifactValidationFailed,
    UnsupportedArtifact,
    AdmissionRejected {
        projected_bytes: u64,
        maximum_bytes: u64,
    },
    AdmissionUnavailable(&'static str),
    Busy,
    Cancelled,
    InitializationFailed(&'static str),
    GenerationFailed(&'static str),
    Unavailable,
    Memory(MemoryEstimateError),
}

impl fmt::Debug for RuntimeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

impl fmt::Display for RuntimeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRequest(message) => {
                write!(formatter, "invalid runtime request: {message}")
            }
            Self::ArtifactValidationFailed => {
                formatter.write_str("registered model revalidation failed")
            }
            Self::UnsupportedArtifact => formatter
                .write_str("registered model does not match the calibrated macOS runtime profile"),
            Self::AdmissionRejected {
                projected_bytes,
                maximum_bytes,
            } => write!(
                formatter,
                "projected runtime allocation of {projected_bytes} bytes exceeds the {maximum_bytes}-byte profile ceiling"
            ),
            Self::AdmissionUnavailable(message) => {
                write!(formatter, "runtime admission unavailable: {message}")
            }
            Self::Busy => formatter.write_str("model runtime is busy"),
            Self::Cancelled => formatter.write_str("model request was cancelled"),
            Self::InitializationFailed(message) => {
                write!(formatter, "model runtime initialization failed: {message}")
            }
            Self::GenerationFailed(message) => {
                write!(formatter, "model generation failed: {message}")
            }
            Self::Unavailable => formatter.write_str("model runtime worker is unavailable"),
            Self::Memory(error) => write!(formatter, "runtime memory admission failed: {error}"),
        }
    }
}

impl Error for RuntimeError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Memory(error) => Some(error),
            _ => None,
        }
    }
}

impl From<ModelError> for RuntimeError {
    fn from(_error: ModelError) -> Self {
        Self::ArtifactValidationFailed
    }
}

impl From<MemoryEstimateError> for RuntimeError {
    fn from(error: MemoryEstimateError) -> Self {
        Self::Memory(error)
    }
}
