//! The candle inference runtime and its dedicated thread.
//!
//! One [`Runtime`] owns one OS thread named `pam-model`, and that thread owns
//! the weights. Nothing else in the process ever touches them. The async side
//! talks to it over a `std::sync::mpsc` channel with
//! [`tokio::sync::oneshot`] replies, so generation is strictly serialized: a
//! second caller waits in the queue behind the first rather than racing it
//! through a lock. That is the honest shape for a single set of weights and a
//! single KV cache — there is no concurrency to be had here, only the
//! illusion of it, and the illusion would cost correctness.
//!
//! The channel is unbounded rather than a rendezvous `sync_channel(0)`:
//! sending on a rendezvous channel blocks until the thread picks the command
//! up, which on the async side means parking a tokio worker for the whole of
//! whatever generation is already running. Serialization comes from there
//! being one consumer, not from the channel's capacity, so an unbounded queue
//! costs nothing and blocks no one.
//!
//! A dedicated thread rather than a task pool because a forward pass is a
//! multi-second, non-yielding block of arithmetic. On a tokio worker it would
//! stall every other future sharing that worker; on its own thread it stalls
//! nothing.
//!
//! # What is supported
//!
//! `qwen3` (dense) and `qwen3moe` (mixture of experts), the two
//! architectures the catalog offers. Everything else is refused as
//! [`RuntimeError::UnsupportedArchitecture`] — and refused from the GGUF
//! header the registry already parsed, before candle is asked to map a
//! single tensor, so a wrong file costs a millisecond instead of a minute.
//!
//! # Mixture-of-experts and the KV cache
//!
//! The dense model exposes `clear_kv_cache`; `GGUFQWenMoE` in candle 0.9.2
//! does not, and its layers are private, so there is no way to reset its
//! caches in place. Rather than let a second generation concatenate onto the
//! first one's keys and produce quiet nonsense, the `MoE` path **rebuilds the
//! model from the file before every generation**. That is honest and it is
//! expensive — re-mapping a quantized 30B `MoE` costs seconds — and it is what
//! correctness costs until candle exposes a reset. The dense path pays
//! nothing.
//!
//! # Crashes
//!
//! Every command runs inside `catch_unwind`. A panic inside candle therefore
//! kills the loaded model, not the daemon: the reply channel drops, the
//! caller sees [`RuntimeError::Crashed`], the snapshot mirror resets to
//! [`RuntimeState::Idle`], and the next `load` starts from nothing. A thread
//! that died outright is respawned on that same next `load`.
//!
//! # The snapshot mirror
//!
//! [`Runtime::snapshot`] is synchronous and never talks to the thread: the
//! thread writes its state into a `Mutex<RuntimeSnapshot>` as it moves
//! through load phases and generations, and the GUI's poll reads that. A
//! status call that had to queue behind a running generation would report
//! the state as it was minutes ago, which is worse than useless on a screen
//! whose whole job is to say what is happening now.

use std::io::{Read, Seek};
use std::panic::AssertUnwindSafe;
use std::path::PathBuf;
use std::sync::mpsc::{Receiver, Sender, channel};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use candle_core::quantized::gguf_file;
use candle_core::{DType, Device, Tensor};
use candle_transformers::generation::{LogitsProcessor, Sampling};
use candle_transformers::models::{quantized_qwen3, quantized_qwen3_moe};
use tokio::sync::{oneshot, watch};

use crate::registry::ModelEntry;
use crate::tokenizer::{self, GgufTokenizer};

/// The context window PAM runs models in, in tokens.
///
/// Fixed rather than read from `<arch>.context_length` because the KV cache
/// for a 30B `MoE` at its advertised context does not fit in the machines PAM
/// targets, and a number that is true on paper but fails at token 40 000 is
/// a lie the human pays for. 8192 is the figure pam-old ran on.
pub const CONTEXT_TOKENS: usize = 8192;

/// The architectures the runtime implements.
const SUPPORTED_ARCHITECTURES: [&str; 2] = ["qwen3", "qwen3moe"];

/// Sampling seed. Fixed so two runs of the same prompt at the same
/// temperature give the same answer — a diagnostic surface that changes its
/// mind between clicks cannot be used to diagnose anything.
const SAMPLING_SEED: u64 = 299_792_458;

/// Compute dtype for the KV cache and attention masks.
///
/// The dense model defaults to `F16` when `general.dtype` is absent, which it
/// always is; the `MoE` path is handed the same dtype so both behave alike on
/// the same hardware.
const COMPUTE_DTYPE: DType = DType::F16;

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
    /// The decoded completion, special tokens dropped and truncated at a
    /// stop string when one hit.
    pub text: String,
    /// Tokens in the framed prompt, after the `ChatML` template.
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

/// The model currently in memory.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct LoadedModel {
    /// Registry id, `<vendor>/<file stem>`.
    pub id: String,
    /// Quantization label from the GGUF header, or `unknown`.
    pub quant: String,
    /// `general.architecture`.
    pub architecture: String,
    /// Effective context: [`CONTEXT_TOKENS`], or the model's own figure when
    /// that is smaller.
    pub context_length: usize,
    /// File size — the mapped footprint. No invented KV-cache byte figures.
    pub weight_bytes: u64,
    /// `metal` or `cpu`.
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
    /// A load is in flight. `phase` is `reading_header`, `mapping_tensors`
    /// or `ready` — candle exposes no per-tensor progress, so PAM reports
    /// the phases it can actually observe instead of a fake percentage.
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
    /// True while the thread is working on a command.
    pub busy: bool,
}

/// Everything the runtime can refuse or fail at.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RuntimeError {
    /// A generate arrived with nothing loaded.
    #[error("no model is loaded")]
    NoModelLoaded,
    /// The file is a model PAM does not implement.
    #[error("architecture {0:?} is not supported (qwen3, qwen3moe)")]
    UnsupportedArchitecture(String),
    /// candle could not map the weights.
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
    /// Another generation holds the thread.
    #[error("another generation is running")]
    Busy,
    /// The cancel watch flipped mid-generation.
    #[error("generation cancelled")]
    Cancelled,
    /// candle failed during the forward pass or sampling.
    #[error("generation failed: {0}")]
    GenerationFailed(String),
    /// The model thread panicked or died.
    #[error("the model thread crashed; runtime reset to idle")]
    Crashed,
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
            Self::UnsupportedArchitecture(_) => "unsupported_architecture",
            Self::LoadFailed(_) => "load_failed",
            Self::PromptTooLong { .. } => "prompt_too_long",
            Self::Busy => "busy",
            Self::Cancelled => "cancelled",
            Self::GenerationFailed(_) => "generation_failed",
            Self::Crashed => "runtime_crashed",
        }
    }
}

/// One request to the model thread, with the channel its answer goes back on.
enum Command {
    /// Map a model into memory, replacing whatever is loaded.
    Load {
        /// The model to map.
        entry: Box<ModelEntry>,
        /// Where the answer goes.
        reply: oneshot::Sender<Result<LoadedModel, RuntimeError>>,
    },
    /// Drop the weights. Idle is not an error.
    Unload {
        /// Where the acknowledgement goes.
        reply: oneshot::Sender<()>,
    },
    /// Run one generation to completion.
    Generate {
        /// What to generate.
        request: Box<GenerateRequest>,
        /// Flips to true to stop between tokens.
        cancel: watch::Receiver<bool>,
        /// Where the answer goes.
        reply: oneshot::Sender<Result<GenerateResult, RuntimeError>>,
    },
}

/// Shared state behind every [`Runtime`] handle.
#[derive(Debug)]
struct Inner {
    /// `None` before the first load and after the thread dies; the next
    /// `load` respawns it.
    sender: Mutex<Option<Sender<Command>>>,
    /// What the thread last said about itself.
    snapshot: Arc<Mutex<RuntimeSnapshot>>,
}

/// A handle to the model thread. Cheap to clone; every clone talks to the
/// same weights.
#[derive(Debug, Clone)]
pub struct Runtime {
    /// The shared channel and mirror.
    inner: Arc<Inner>,
}

impl Default for Runtime {
    fn default() -> Self {
        Self::new()
    }
}

impl Runtime {
    /// A runtime with no thread and no weights. The thread is spawned on the
    /// first [`load`](Runtime::load), so a daemon that never loads a model
    /// never pays for one.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Inner {
                sender: Mutex::new(None),
                snapshot: Arc::new(Mutex::new(RuntimeSnapshot {
                    state: RuntimeState::Idle,
                    busy: false,
                })),
            }),
        }
    }

    /// The current state, read from the mirror without touching the thread.
    #[must_use]
    pub fn snapshot(&self) -> RuntimeSnapshot {
        lock(&self.inner.snapshot).clone()
    }

    /// Maps a model into memory, replacing whatever was loaded.
    ///
    /// An architecture the runtime does not implement is refused here, from
    /// the header the registry already parsed, before the thread is spawned
    /// or candle is called at all. A file whose header never parsed reaches
    /// the thread and is refused there instead.
    pub async fn load(&self, entry: &ModelEntry) -> Result<LoadedModel, RuntimeError> {
        if let Some(info) = &entry.info
            && !SUPPORTED_ARCHITECTURES.contains(&info.architecture.as_str())
        {
            return Err(RuntimeError::UnsupportedArchitecture(
                info.architecture.clone(),
            ));
        }
        let (reply, answer) = oneshot::channel();
        let command = Command::Load {
            entry: Box::new(entry.clone()),
            reply,
        };
        if !self.send(command, true) {
            self.reset_to_idle();
            return Err(RuntimeError::Crashed);
        }
        self.await_reply(answer).await?
    }

    /// Drops the weights. Idle — and a runtime that never spawned a thread —
    /// is `Ok`.
    pub async fn unload(&self) -> Result<(), RuntimeError> {
        let (reply, answer) = oneshot::channel();
        if !self.send(Command::Unload { reply }, false) {
            self.reset_to_idle();
            return Ok(());
        }
        self.await_reply(answer).await
    }

    /// Runs one generation, waiting behind any command already queued.
    pub async fn generate(
        &self,
        request: GenerateRequest,
        cancel: watch::Receiver<bool>,
    ) -> Result<GenerateResult, RuntimeError> {
        let (reply, answer) = oneshot::channel();
        let command = Command::Generate {
            request: Box::new(request),
            cancel,
            reply,
        };
        if !self.send(command, false) {
            let crashed = matches!(lock(&self.inner.snapshot).state, RuntimeState::Loaded(_));
            self.reset_to_idle();
            return Err(if crashed {
                RuntimeError::Crashed
            } else {
                RuntimeError::NoModelLoaded
            });
        }
        self.await_reply(answer).await?
    }

    /// Queues a command, spawning the thread when `spawn` is set and the
    /// previous one is gone. Returns false when there is no live thread to
    /// take the command.
    fn send(&self, command: Command, spawn: bool) -> bool {
        let mut slot = lock(&self.inner.sender);
        if slot.is_none() {
            if !spawn {
                return false;
            }
            *slot = spawn_thread(Arc::clone(&self.inner.snapshot));
        }
        let Some(sender) = slot.as_ref() else {
            return false;
        };
        let Err(rejected) = sender.send(command) else {
            return true;
        };
        // The thread died between the last command and this one. Retry once
        // on a fresh thread when we are allowed to make one.
        *slot = None;
        if !spawn {
            return false;
        }
        *slot = spawn_thread(Arc::clone(&self.inner.snapshot));
        slot.as_ref()
            .is_some_and(|sender| sender.send(rejected.0).is_ok())
    }

    /// Awaits a reply, turning a dropped sender — a panicked command — into
    /// [`RuntimeError::Crashed`] and an idle mirror.
    async fn await_reply<T>(&self, answer: oneshot::Receiver<T>) -> Result<T, RuntimeError> {
        answer.await.map_err(|_| {
            self.reset_to_idle();
            RuntimeError::Crashed
        })
    }

    /// Puts the mirror back to idle after a crash or a missing thread.
    fn reset_to_idle(&self) {
        *lock(&self.inner.snapshot) = RuntimeSnapshot {
            state: RuntimeState::Idle,
            busy: false,
        };
    }
}

/// Locks a mutex, taking the value back out of a poisoned lock.
///
/// A panic on the model thread is expected — that is what `catch_unwind` is
/// for — and a poisoned mirror must not turn a recoverable crash into a
/// permanently unreadable status.
fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Spawns the `pam-model` thread, or `None` when the OS refuses.
fn spawn_thread(mirror: Arc<Mutex<RuntimeSnapshot>>) -> Option<Sender<Command>> {
    let (sender, receiver) = channel();
    std::thread::Builder::new()
        .name("pam-model".to_string())
        .spawn(move || thread_main(&receiver, &mirror))
        .ok()
        .map(|_| sender)
}

// ---------------------------------------------------------------------------
// The model thread
// ---------------------------------------------------------------------------

/// The two architectures, each owning its own weights.
enum Model {
    /// `qwen3`.
    Dense(Box<quantized_qwen3::ModelWeights>),
    /// `qwen3moe`.
    Moe(Box<quantized_qwen3_moe::GGUFQWenMoE>),
}

/// Everything the thread holds for one loaded model.
struct Loaded {
    /// The weights.
    model: Model,
    /// Vocabulary rebuilt from the same file.
    tokenizer: GgufTokenizer,
    /// Metal or CPU.
    device: Device,
    /// The file, kept so the `MoE` path can rebuild itself.
    path: PathBuf,
    /// What the mirror and the caller are told about this model.
    meta: LoadedModel,
}

impl Loaded {
    /// Puts the KV cache back to offset zero.
    ///
    /// Dense clears in place. `MoE` has no reset in candle 0.9.2, so the model
    /// is rebuilt from its file — seconds, not microseconds, and the reason
    /// the `MoE` path is slower per call than the dense one.
    fn reset_cache(&mut self) -> Result<(), RuntimeError> {
        match &mut self.model {
            Model::Dense(model) => {
                model.clear_kv_cache();
                Ok(())
            }
            Model::Moe(_) => {
                let (content, mut file) = read_header(&self.path).map_err(map_generation)?;
                let rebuilt = quantized_qwen3_moe::GGUFQWenMoE::from_gguf(
                    content,
                    &mut file,
                    &self.device,
                    COMPUTE_DTYPE,
                )
                .map_err(|err| RuntimeError::GenerationFailed(err.to_string()))?;
                self.model = Model::Moe(Box::new(rebuilt));
                Ok(())
            }
        }
    }

    /// One forward pass, returning the last position's logits as a 1-D
    /// tensor — the shape [`LogitsProcessor`] samples from.
    fn forward(&mut self, input: &Tensor, offset: usize) -> Result<Tensor, RuntimeError> {
        let logits = match &mut self.model {
            Model::Dense(model) => model.forward(input, offset),
            Model::Moe(model) => model.forward(input, offset),
        }
        .and_then(|logits| logits.squeeze(0));
        logits.map_err(|err| RuntimeError::GenerationFailed(err.to_string()))
    }
}

/// The thread body: take a command, run it inside `catch_unwind`, repeat
/// until every handle is gone.
fn thread_main(receiver: &Receiver<Command>, mirror: &Arc<Mutex<RuntimeSnapshot>>) {
    let mut loaded: Option<Loaded> = None;
    while let Ok(command) = receiver.recv() {
        lock(mirror).busy = true;
        let outcome = std::panic::catch_unwind(AssertUnwindSafe(|| {
            handle(command, &mut loaded, mirror);
        }));
        if outcome.is_err() {
            // The reply channel went with the panic, so the caller already
            // sees `Crashed`; drop the weights and say so.
            loaded = None;
            *lock(mirror) = RuntimeSnapshot {
                state: RuntimeState::Idle,
                busy: false,
            };
        } else {
            lock(mirror).busy = false;
        }
    }
}

/// Runs one command against the thread's state.
fn handle(command: Command, loaded: &mut Option<Loaded>, mirror: &Mutex<RuntimeSnapshot>) {
    match command {
        Command::Load { entry, reply } => {
            // Free the old weights before mapping the new ones: two models in
            // memory at once is how a 32 GB machine dies.
            *loaded = None;
            match load_model(&entry, mirror) {
                Ok(model) => {
                    let meta = model.meta.clone();
                    set_state(mirror, RuntimeState::Loaded(meta.clone()));
                    *loaded = Some(model);
                    drop(reply.send(Ok(meta)));
                }
                Err(err) => {
                    set_state(mirror, RuntimeState::Idle);
                    drop(reply.send(Err(err)));
                }
            }
        }
        Command::Unload { reply } => {
            *loaded = None;
            set_state(mirror, RuntimeState::Idle);
            let _ = reply.send(());
        }
        Command::Generate {
            request,
            cancel,
            reply,
        } => {
            let Some(model) = loaded.as_mut() else {
                drop(reply.send(Err(RuntimeError::NoModelLoaded)));
                return;
            };
            let result = generate_on_thread(model, &request, &cancel);
            if let Ok(generated) = &result {
                model.meta.last_used_at = now();
                model.meta.last_tokens_per_sec = Some(generated.tokens_per_sec);
                set_state(mirror, RuntimeState::Loaded(model.meta.clone()));
            }
            drop(reply.send(result));
        }
    }
}

/// Replaces the mirrored state, leaving `busy` to the thread loop.
fn set_state(mirror: &Mutex<RuntimeSnapshot>, state: RuntimeState) {
    lock(mirror).state = state;
}

/// Opens a model file and reads its GGUF header, leaving the reader
/// positioned where candle expects it.
fn read_header(path: &PathBuf) -> Result<(gguf_file::Content, std::fs::File), String> {
    let mut file = std::fs::File::open(path).map_err(|err| err.to_string())?;
    let content = gguf_file::Content::read(&mut file).map_err(|err| err.to_string())?;
    Ok((content, file))
}

/// Turns a header-reading failure into a generation failure.
fn map_generation(detail: String) -> RuntimeError {
    RuntimeError::GenerationFailed(detail)
}

/// Reads the header, refuses unsupported architectures, then maps the
/// tensors, reporting each phase into the mirror as it goes.
fn load_model(entry: &ModelEntry, mirror: &Mutex<RuntimeSnapshot>) -> Result<Loaded, RuntimeError> {
    set_state(mirror, loading(&entry.id, "reading_header"));
    let (content, mut file) = read_header(&entry.path).map_err(RuntimeError::LoadFailed)?;

    let architecture = content
        .metadata
        .get("general.architecture")
        .and_then(|value| value.to_string().ok())
        .cloned()
        .unwrap_or_default();
    if !SUPPORTED_ARCHITECTURES.contains(&architecture.as_str()) {
        return Err(RuntimeError::UnsupportedArchitecture(architecture));
    }

    let context_length = content
        .metadata
        .get(&format!("{architecture}.context_length"))
        .and_then(|value| value.to_u32().ok())
        .map_or(CONTEXT_TOKENS, |declared| {
            CONTEXT_TOKENS.min(declared as usize)
        });
    let tokenizer =
        tokenizer::from_gguf(&content).map_err(|err| RuntimeError::LoadFailed(err.to_string()))?;

    set_state(mirror, loading(&entry.id, "mapping_tensors"));
    let device = select_device();
    let model = build_model(&architecture, content, &mut file, &device)?;
    set_state(mirror, loading(&entry.id, "ready"));

    let loaded_at = now();
    Ok(Loaded {
        model,
        tokenizer,
        device: device.clone(),
        path: entry.path.clone(),
        meta: LoadedModel {
            id: entry.id.clone(),
            quant: entry
                .info
                .as_ref()
                .map_or_else(|| "unknown".to_string(), |info| info.quant_label.clone()),
            architecture,
            context_length,
            weight_bytes: entry.size_bytes,
            device: device_label(&device).to_string(),
            loaded_at,
            last_used_at: loaded_at,
            last_tokens_per_sec: None,
        },
    })
}

/// A `Loading` state for one phase.
fn loading(id: &str, phase: &str) -> RuntimeState {
    RuntimeState::Loading {
        phase: phase.to_string(),
        id: id.to_string(),
    }
}

/// Maps the tensors with the model implementation the architecture names.
fn build_model<R: Read + Seek>(
    architecture: &str,
    content: gguf_file::Content,
    reader: &mut R,
    device: &Device,
) -> Result<Model, RuntimeError> {
    match architecture {
        "qwen3" => quantized_qwen3::ModelWeights::from_gguf(content, reader, device)
            .map(|model| Model::Dense(Box::new(model)))
            .map_err(|err| RuntimeError::LoadFailed(err.to_string())),
        "qwen3moe" => {
            quantized_qwen3_moe::GGUFQWenMoE::from_gguf(content, reader, device, COMPUTE_DTYPE)
                .map(|model| Model::Moe(Box::new(model)))
                .map_err(|err| RuntimeError::LoadFailed(err.to_string()))
        }
        other => Err(RuntimeError::UnsupportedArchitecture(other.to_string())),
    }
}

/// Metal on macOS, CPU everywhere else — and CPU on macOS too when Metal
/// will not start, because a slow answer beats a refusal.
fn select_device() -> Device {
    #[cfg(target_os = "macos")]
    {
        Device::new_metal(0).unwrap_or(Device::Cpu)
    }
    #[cfg(not(target_os = "macos"))]
    {
        Device::Cpu
    }
}

/// The device name the GUI shows.
fn device_label(device: &Device) -> &'static str {
    if device.is_metal() { "metal" } else { "cpu" }
}

// ---------------------------------------------------------------------------
// Generation
// ---------------------------------------------------------------------------

/// What the decode loop produced.
#[derive(Default)]
struct Decoded {
    /// Text so far, already truncated at a stop string when one hit.
    text: String,
    /// How many tokens were accepted.
    completion_tokens: usize,
}

/// Frames, encodes, checks the budget, runs the prompt, then decodes.
///
/// The context rule: a request is refused when `prompt_tokens + max_tokens`
/// exceeds [`CONTEXT_TOKENS`]. Checking the sum rather than just the prompt
/// is what stops a generation from running into the end of the window
/// halfway through a sentence — PAM would rather refuse up front than hand
/// back a truncated answer that looks finished.
///
/// `prompt_ms` covers everything before the first sampled token — framing,
/// encoding, the cache reset and the prompt forward pass. On the `MoE` path
/// the cache reset is a full model rebuild, so that figure carries it;
/// reporting the rebuild anywhere else would hide it.
fn generate_on_thread(
    loaded: &mut Loaded,
    request: &GenerateRequest,
    cancel: &watch::Receiver<bool>,
) -> Result<GenerateResult, RuntimeError> {
    if *cancel.borrow() {
        return Err(RuntimeError::Cancelled);
    }
    let started = Instant::now();
    let framed = tokenizer::chatml(request.system.as_deref(), &request.prompt);
    let encoding = loaded
        .tokenizer
        .inner
        .encode(framed, true)
        .map_err(|err| RuntimeError::GenerationFailed(err.to_string()))?;
    let mut ids = encoding.get_ids().to_vec();
    if loaded.tokenizer.add_bos
        && let Some(bos) = loaded.tokenizer.bos_id
        && ids.first() != Some(&bos)
    {
        ids.insert(0, bos);
    }
    let prompt_tokens = ids.len();
    if prompt_tokens + request.max_tokens > CONTEXT_TOKENS {
        return Err(RuntimeError::PromptTooLong {
            tokens: prompt_tokens,
            limit: CONTEXT_TOKENS,
        });
    }

    loaded.reset_cache()?;
    let input = Tensor::new(ids.as_slice(), &loaded.device)
        .and_then(|tensor| tensor.unsqueeze(0))
        .map_err(|err| RuntimeError::GenerationFailed(err.to_string()))?;
    let logits = loaded.forward(&input, 0)?;
    let prompt_ms = millis(started.elapsed());

    let decode_started = Instant::now();
    let decoded = decode_loop(loaded, request, logits, prompt_tokens, cancel)?;
    let decode_elapsed = decode_started.elapsed();

    Ok(GenerateResult {
        text: decoded.text,
        prompt_tokens,
        completion_tokens: decoded.completion_tokens,
        prompt_ms,
        decode_ms: millis(decode_elapsed),
        tokens_per_sec: tokens_per_sec(decoded.completion_tokens, decode_elapsed),
    })
}

/// The per-token loop: sample, accept, check the stops, forward again.
///
/// Cancellation is checked between tokens rather than inside a forward pass,
/// because a forward pass cannot be interrupted; the worst a cancel costs is
/// one more token.
fn decode_loop(
    loaded: &mut Loaded,
    request: &GenerateRequest,
    logits: Tensor,
    prompt_tokens: usize,
    cancel: &watch::Receiver<bool>,
) -> Result<Decoded, RuntimeError> {
    let mut decoded = Decoded::default();
    if request.max_tokens == 0 {
        return Ok(decoded);
    }
    let mut processor =
        LogitsProcessor::from_sampling(SAMPLING_SEED, sampling(request.temperature));
    let mut logits = logits;
    let mut offset = prompt_tokens;
    let mut generated: Vec<u32> = Vec::with_capacity(request.max_tokens);

    loop {
        let next = processor
            .sample(&logits)
            .map_err(|err| RuntimeError::GenerationFailed(err.to_string()))?;
        if next == loaded.tokenizer.eos_id {
            break;
        }
        generated.push(next);
        decoded.completion_tokens = generated.len();
        decoded.text = loaded
            .tokenizer
            .inner
            .decode(&generated, true)
            .map_err(|err| RuntimeError::GenerationFailed(err.to_string()))?;
        if let Some(cut) = first_stop(&decoded.text, &request.stop) {
            decoded.text.truncate(cut);
            break;
        }
        if generated.len() >= request.max_tokens {
            break;
        }
        if *cancel.borrow() {
            return Err(RuntimeError::Cancelled);
        }
        let input = Tensor::new(&[next], &loaded.device)
            .and_then(|tensor| tensor.unsqueeze(0))
            .map_err(|err| RuntimeError::GenerationFailed(err.to_string()))?;
        logits = loaded.forward(&input, offset)?;
        offset += 1;
    }
    Ok(decoded)
}

/// Greedy at temperature 0, sampled above it.
fn sampling(temperature: f64) -> Sampling {
    if temperature <= 0.0 {
        Sampling::ArgMax
    } else {
        Sampling::All { temperature }
    }
}

/// The earliest byte index at which any stop string starts.
fn first_stop(text: &str, stop: &[String]) -> Option<usize> {
    stop.iter()
        .filter(|needle| !needle.is_empty())
        .filter_map(|needle| text.find(needle.as_str()))
        .min()
}

/// Whole milliseconds, saturating rather than wrapping.
fn millis(elapsed: Duration) -> u64 {
    u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
}

/// Decode rate, 0.0 when nothing was generated or no time passed.
fn tokens_per_sec(completion_tokens: usize, elapsed: Duration) -> f64 {
    let seconds = elapsed.as_secs_f64();
    if completion_tokens == 0 || seconds <= 0.0 {
        return 0.0;
    }
    let tokens = u32::try_from(completion_tokens).map_or(f64::from(u32::MAX), f64::from);
    tokens / seconds
}

/// Unix seconds now, or 0 before the epoch.
fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|since| i64::try_from(since.as_secs()).ok())
        .unwrap_or_default()
}
