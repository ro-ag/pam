use std::{
    num::NonZeroU32,
    ops::Range,
    sync::{
        Arc, Mutex, TryLockError,
        mpsc::{self, Receiver, SyncSender},
    },
    thread::{self, JoinHandle},
};

use llama_cpp_4::prelude::{
    AddBos, LlamaBackend, LlamaBackendDeviceType, LlamaBatch, LlamaChatMessage, LlamaContext,
    LlamaContextParams, LlamaFlashAttnType, LlamaModel, LlamaModelParams, LlamaSampler, LlamaToken,
    Special, StreamDetokenizer,
};
use llama_cpp_4::{ChatTemplateError, quantize::GgmlType};
use pam_core::ContentDigest;

use crate::{
    CancellationSignal, CancellationToken, HostMemoryBudget, MemoryFit, ModelRuntime,
    RegisteredModel, RuntimeError, RuntimeFinishReason, RuntimeFlashAttention, RuntimeGpuOffload,
    RuntimeHostAdmission, RuntimeHostSnapshot, RuntimeKvCachePrecision, RuntimeMemoryPressure,
    RuntimeMemoryProjection, RuntimeProfile, RuntimeRequest, RuntimeResponse, RuntimeSampling,
    RuntimeSwapTrend, RuntimeUsage, UnifiedWorkingSetLimit, estimate_memory,
    revalidate_registered_model,
};

const CALIBRATED_MODEL_DIGEST: &str =
    "sha256:56a7d00783419bcb0ae566253c371bcb3678261bb79881a553539f5679864db4";
const CALIBRATED_MODEL_SIZE_BYTES: u64 = 17_456_012_448;
const CONTEXT_TOKENS: u32 = 8_192;
const BATCH_TOKENS: u32 = 512;
const PHYSICAL_BATCH_TOKENS: u32 = 512;
const PARALLEL_SEQUENCES: u32 = 1;
const MAX_MODEL_ALLOCATION_BYTES: u64 = 20_000_000_000;
const MIN_OS_RESERVE_BYTES: u64 = 8 * 1024 * 1024 * 1024;
const MIN_CALIBRATED_CONTINGENCY_BYTES: u64 = 256 * 1024 * 1024;
const INITIAL_CHAT_TEMPLATE_BYTES: usize = 4 * 1024;
const MAX_CHAT_TEMPLATE_BYTES: usize = 1024 * 1024;
const SAMPLING_SEED: u32 = 42;
const REPETITION_PENALTY_HISTORY_TOKENS: i32 = 8_192;

pub struct MacosLlamaCppRuntime {
    profile: RuntimeProfile,
    commands: SyncSender<WorkerCommand>,
    generation_gate: Mutex<()>,
    shutdown: CancellationToken,
    worker: Option<JoinHandle<()>>,
}

impl MacosLlamaCppRuntime {
    /// Revalidates and loads the calibrated user-owned GGUF on one serialized
    /// llama.cpp worker.
    ///
    /// This call blocks through a full-file integrity check, projection, and
    /// model load. Async callers must invoke it on a blocking executor.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeError`] when the registered artifact is no longer exact,
    /// does not match the calibrated profile, exceeds admission, or cannot load.
    pub fn load(
        model: RegisteredModel,
        admission: Arc<dyn RuntimeHostAdmission>,
    ) -> Result<Self, RuntimeError> {
        validate_calibrated_artifact(&model)?;

        let (commands, command_receiver) = mpsc::sync_channel(0);
        let (ready_sender, ready_receiver) = mpsc::sync_channel(0);
        let shutdown = CancellationToken::default();
        let worker_shutdown = shutdown.clone();
        let worker = thread::Builder::new()
            .name("pam-llama-cpp".to_owned())
            .spawn(move || {
                runtime_worker(
                    &model,
                    admission.as_ref(),
                    &worker_shutdown,
                    &ready_sender,
                    &command_receiver,
                );
            })
            .map_err(|_| RuntimeError::InitializationFailed("worker thread could not start"))?;

        match ready_receiver.recv() {
            Ok(Ok(profile)) => Ok(Self {
                profile,
                commands,
                generation_gate: Mutex::new(()),
                shutdown,
                worker: Some(worker),
            }),
            Ok(Err(error)) => {
                let _ = worker.join();
                Err(error)
            }
            Err(_) => {
                let _ = worker.join();
                Err(RuntimeError::Unavailable)
            }
        }
    }
}

impl ModelRuntime for MacosLlamaCppRuntime {
    fn profile(&self) -> &RuntimeProfile {
        &self.profile
    }

    fn generate(
        &self,
        request: RuntimeRequest,
        cancellation: CancellationToken,
    ) -> Result<RuntimeResponse, RuntimeError> {
        if cancellation.is_cancelled() {
            return Err(RuntimeError::Cancelled);
        }
        let _permit = match self.generation_gate.try_lock() {
            Ok(permit) => permit,
            Err(TryLockError::WouldBlock) => return Err(RuntimeError::Busy),
            Err(TryLockError::Poisoned(_)) => return Err(RuntimeError::Unavailable),
        };
        let (reply, response) = mpsc::sync_channel(0);
        self.commands
            .send(WorkerCommand::Generate {
                request,
                cancellation,
                reply,
            })
            .map_err(|_| RuntimeError::Unavailable)?;
        response.recv().map_err(|_| RuntimeError::Unavailable)?
    }
}

impl Drop for MacosLlamaCppRuntime {
    fn drop(&mut self) {
        self.shutdown.cancel();
        let _ = self.commands.send(WorkerCommand::Shutdown);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

enum WorkerCommand {
    Generate {
        request: RuntimeRequest,
        cancellation: CancellationToken,
        reply: SyncSender<Result<RuntimeResponse, RuntimeError>>,
    },
    Shutdown,
}

struct PreparedModel {
    backend: LlamaBackend,
    model: LlamaModel,
    context_params: LlamaContextParams,
    chat_template: String,
    profile: RuntimeProfile,
}

fn runtime_worker(
    registered: &RegisteredModel,
    admission: &dyn RuntimeHostAdmission,
    shutdown: &CancellationToken,
    ready: &SyncSender<Result<RuntimeProfile, RuntimeError>>,
    commands: &Receiver<WorkerCommand>,
) {
    let prepared = match prepare_model(registered, admission) {
        Ok(prepared) => prepared,
        Err(error) => {
            let _ = ready.send(Err(error));
            return;
        }
    };
    let Ok(mut context) = prepared
        .model
        .new_context(&prepared.backend, prepared.context_params)
    else {
        let _ = ready.send(Err(RuntimeError::InitializationFailed(
            "context creation failed",
        )));
        return;
    };
    if let Err(error) = admit_live_context(&context, prepared.profile.projection()) {
        let _ = ready.send(Err(error));
        return;
    }
    if ready.send(Ok(prepared.profile)).is_err() {
        return;
    }

    while let Ok(command) = commands.recv() {
        match command {
            WorkerCommand::Generate {
                request,
                cancellation,
                reply,
            } => {
                let result = generate(
                    &prepared.model,
                    &mut context,
                    &prepared.chat_template,
                    &request,
                    &cancellation,
                    shutdown,
                );
                let _ = reply.send(result);
            }
            WorkerCommand::Shutdown => return,
        }
    }
}

fn prepare_model(
    registered: &RegisteredModel,
    admission: &dyn RuntimeHostAdmission,
) -> Result<PreparedModel, RuntimeError> {
    let backend = LlamaBackend::init()
        .map_err(|_| RuntimeError::InitializationFailed("backend initialization failed"))?;
    if !llama_cpp_4::supports_gpu_offload() {
        return Err(RuntimeError::InitializationFailed(
            "Metal GPU offload is unavailable",
        ));
    }
    revalidate_registered_model(registered)?;

    let model_params = fixed_model_params();
    let context_params = fixed_context_params();
    let projection_report = llama_cpp_4::fit::get_device_memory_data(
        &registered.path,
        &model_params,
        &context_params,
        llama_cpp_sys_4::GGML_LOG_LEVEL_ERROR,
    )
    .map_err(|_| RuntimeError::InitializationFailed("memory projection failed"))?;
    if projection_report.hyperparams.n_ctx_train < CONTEXT_TOKENS {
        return Err(RuntimeError::InitializationFailed(
            "model training context is below the calibrated profile",
        ));
    }
    let (metal_working_set_limit, projected_host_total) =
        metal_and_host_memory_limits(projection_report.entries.iter().map(|entry| entry.total))?;
    let projection = projection_from_entries(
        registered.digest.clone(),
        projection_report
            .entries
            .iter()
            .map(|entry| (entry.model, entry.context, entry.compute)),
    )?;
    admit_projection(&projection)?;
    validate_host_admission(
        registered,
        &projection,
        admission.snapshot()?,
        metal_working_set_limit,
        projected_host_total,
    )?;

    let model = LlamaModel::load_from_file(&backend, &registered.path, &model_params)
        .map_err(|_| RuntimeError::InitializationFailed("model load failed"))?;
    if model.n_ctx_train() < CONTEXT_TOKENS {
        return Err(RuntimeError::InitializationFailed(
            "loaded model training context is below the calibrated profile",
        ));
    }
    let gpu_device_count = model
        .devices()
        .filter(|device| {
            matches!(
                device.device_type(),
                LlamaBackendDeviceType::Gpu | LlamaBackendDeviceType::IntegratedGpu
            )
        })
        .count();
    if gpu_device_count != 1 {
        return Err(RuntimeError::InitializationFailed(
            "loaded model did not use exactly one GPU device",
        ));
    }
    let chat_template = embedded_chat_template(&model)?;
    let profile = calibrated_runtime_profile(registered.digest.clone(), projection)?;
    Ok(PreparedModel {
        backend,
        model,
        context_params,
        chat_template,
        profile,
    })
}

pub(crate) fn calibrated_runtime_profile(
    digest: ContentDigest,
    projection: RuntimeMemoryProjection,
) -> Result<RuntimeProfile, RuntimeError> {
    RuntimeProfile::new(
        digest,
        CONTEXT_TOKENS,
        BATCH_TOKENS,
        PHYSICAL_BATCH_TOKENS,
        PARALLEL_SEQUENCES,
        RuntimeGpuOffload::All,
        RuntimeFlashAttention::Auto,
        RuntimeKvCachePrecision::F16,
        false,
        RuntimeSampling::TopKTopPTemperature,
        MAX_MODEL_ALLOCATION_BYTES,
        projection,
    )
}

pub(crate) fn validate_calibrated_artifact(model: &RegisteredModel) -> Result<(), RuntimeError> {
    if model.digest.as_str() != CALIBRATED_MODEL_DIGEST
        || model.size_bytes != CALIBRATED_MODEL_SIZE_BYTES
    {
        return Err(RuntimeError::UnsupportedArtifact);
    }
    Ok(())
}

pub(crate) fn fixed_model_params() -> LlamaModelParams {
    LlamaModelParams::default().with_n_gpu_layers(u32::MAX)
}

pub(crate) fn fixed_context_params() -> LlamaContextParams {
    LlamaContextParams::default()
        .with_n_ctx(NonZeroU32::new(CONTEXT_TOKENS))
        .with_n_batch(BATCH_TOKENS)
        .with_n_ubatch(PHYSICAL_BATCH_TOKENS)
        .with_n_seq_max(PARALLEL_SEQUENCES)
        .with_flash_attn_type(LlamaFlashAttnType::Auto)
        .with_cache_type_k(GgmlType::F16)
        .with_cache_type_v(GgmlType::F16)
        .with_kv_unified(false)
}

pub(crate) fn projection_from_entries(
    digest: ContentDigest,
    entries: impl IntoIterator<Item = (usize, usize, usize)>,
) -> Result<RuntimeMemoryProjection, RuntimeError> {
    let (weights, context, compute) = entries.into_iter().try_fold(
        (0_u64, 0_u64, 0_u64),
        |(weights, context, compute), (entry_weights, entry_context, entry_compute)| {
            Ok::<_, RuntimeError>((
                weights
                    .checked_add(u64::try_from(entry_weights).map_err(|_| {
                        RuntimeError::InitializationFailed("projected weight bytes exceed u64")
                    })?)
                    .ok_or_else(projection_overflow)?,
                context
                    .checked_add(u64::try_from(entry_context).map_err(|_| {
                        RuntimeError::InitializationFailed("projected context bytes exceed u64")
                    })?)
                    .ok_or_else(projection_overflow)?,
                compute
                    .checked_add(u64::try_from(entry_compute).map_err(|_| {
                        RuntimeError::InitializationFailed("projected compute bytes exceed u64")
                    })?)
                    .ok_or_else(projection_overflow)?,
            ))
        },
    )?;
    RuntimeMemoryProjection::new(digest, CONTEXT_TOKENS, weights, context, compute)
        .map_err(|_| RuntimeError::InitializationFailed("projected memory is invalid"))
}

pub(crate) fn metal_and_host_memory_limits(
    totals: impl IntoIterator<Item = i64>,
) -> Result<(u64, u64), RuntimeError> {
    let totals = totals.into_iter().collect::<Vec<_>>();
    // Pinned llama.cpp reports model devices first and one host entry last.
    // This full-Metal profile requires exactly one model device, so any shape
    // other than `[Metal, host]` is missing or ambiguous and fails closed.
    let [metal_total, host_total] = totals.as_slice() else {
        return Err(RuntimeError::AdmissionUnavailable(
            "projected Metal and host memory limits are ambiguous",
        ));
    };
    let metal_total = u64::try_from(*metal_total)
        .ok()
        .filter(|total| *total > 0)
        .ok_or(RuntimeError::AdmissionUnavailable(
            "Metal working-set limit is unavailable",
        ))?;
    let host_total = u64::try_from(*host_total)
        .ok()
        .filter(|total| *total > 0)
        .ok_or(RuntimeError::AdmissionUnavailable(
            "projected host memory total is unavailable",
        ))?;
    Ok((metal_total, host_total))
}

fn projection_overflow() -> RuntimeError {
    RuntimeError::InitializationFailed("projected memory total overflowed")
}

fn admit_projection(projection: &RuntimeMemoryProjection) -> Result<(), RuntimeError> {
    let projected_bytes = projected_runtime_bytes(projection)?;
    let contingency = calibrated_contingency(projected_bytes)?;
    let calibrated_bytes = projected_bytes
        .checked_add(contingency)
        .ok_or_else(projection_overflow)?;
    admit_bytes(calibrated_bytes)
}

fn projected_runtime_bytes(projection: &RuntimeMemoryProjection) -> Result<u64, RuntimeError> {
    projection
        .weight_bytes()
        .checked_add(projection.context_bytes())
        .and_then(|total| total.checked_add(projection.compute_bytes()))
        .ok_or_else(projection_overflow)
}

pub(crate) fn calibrated_contingency(projected_bytes: u64) -> Result<u64, RuntimeError> {
    let five_percent = projected_bytes
        .checked_add(19)
        .ok_or_else(projection_overflow)?
        / 20;
    Ok(five_percent.max(MIN_CALIBRATED_CONTINGENCY_BYTES))
}

pub(crate) fn validate_host_admission(
    registered: &RegisteredModel,
    projection: &RuntimeMemoryProjection,
    snapshot: RuntimeHostSnapshot,
    metal_working_set_limit: u64,
    projected_host_total: u64,
) -> Result<(), RuntimeError> {
    if snapshot.swap_trend() != RuntimeSwapTrend::Stable {
        return Err(RuntimeError::AdmissionUnavailable(
            "swap activity is rising or unavailable",
        ));
    }
    if snapshot.pressure() != RuntimeMemoryPressure::Normal {
        return Err(RuntimeError::AdmissionUnavailable(
            "memory pressure is not normal",
        ));
    }
    if snapshot.total_bytes() != projected_host_total {
        return Err(RuntimeError::AdmissionUnavailable(
            "projected host memory does not match the current host",
        ));
    }
    if snapshot.reserved_os_bytes() < required_os_reserve(snapshot.total_bytes()) {
        return Err(RuntimeError::AdmissionUnavailable(
            "OS memory reserve is below the calibrated minimum",
        ));
    }
    if snapshot.reserved_application_bytes() == 0 {
        return Err(RuntimeError::AdmissionUnavailable(
            "PAM application memory reserve is missing",
        ));
    }
    let required_contingency = calibrated_contingency(projected_runtime_bytes(projection)?)?;
    if snapshot.projection_contingency_bytes() < required_contingency {
        return Err(RuntimeError::AdmissionUnavailable(
            "projection contingency is below the calibrated minimum",
        ));
    }
    let host = HostMemoryBudget::new(
        snapshot.total_bytes(),
        snapshot.available_bytes(),
        UnifiedWorkingSetLimit::Known(metal_working_set_limit),
        snapshot.reserved_os_bytes(),
        snapshot.reserved_application_bytes(),
        snapshot.projection_contingency_bytes(),
    )
    .map_err(|_| RuntimeError::AdmissionUnavailable("host memory snapshot is invalid"))?;
    if !matches!(
        estimate_memory(registered, projection, host)?.fit,
        MemoryFit::Fits { .. }
    ) {
        return Err(RuntimeError::AdmissionUnavailable(
            "current host memory does not fit the runtime profile",
        ));
    }
    Ok(())
}

pub(crate) fn required_os_reserve(total_bytes: u64) -> u64 {
    total_bytes.div_ceil(5).max(MIN_OS_RESERVE_BYTES)
}

fn admit_live_context(
    context: &LlamaContext<'_>,
    projection: &RuntimeMemoryProjection,
) -> Result<(), RuntimeError> {
    let live_bytes = context
        .memory_breakdown()
        .into_iter()
        .try_fold(0_u64, |total, entry| {
            let entry_total = u64::try_from(entry.model)
                .ok()
                .and_then(|model| {
                    u64::try_from(entry.context)
                        .ok()
                        .and_then(|context| model.checked_add(context))
                })
                .and_then(|total| {
                    u64::try_from(entry.compute)
                        .ok()
                        .and_then(|compute| total.checked_add(compute))
                })
                .ok_or_else(projection_overflow)?;
            total
                .checked_add(entry_total)
                .ok_or_else(projection_overflow)
        })?;
    let live_with_contingency = live_bytes
        .checked_add(calibrated_contingency(projected_runtime_bytes(
            projection,
        )?)?)
        .ok_or_else(projection_overflow)?;
    admit_bytes(live_with_contingency)
}

pub(crate) fn admit_bytes(bytes: u64) -> Result<(), RuntimeError> {
    if bytes > MAX_MODEL_ALLOCATION_BYTES {
        return Err(RuntimeError::AdmissionRejected {
            projected_bytes: bytes,
            maximum_bytes: MAX_MODEL_ALLOCATION_BYTES,
        });
    }
    Ok(())
}

fn embedded_chat_template(model: &LlamaModel) -> Result<String, RuntimeError> {
    match model.get_chat_template(INITIAL_CHAT_TEMPLATE_BYTES) {
        Ok(template) => Ok(template),
        Err(ChatTemplateError::BuffSizeError(required)) => {
            let required = bounded_template_size(required)?;
            model
                .get_chat_template(required)
                .map_err(|_| RuntimeError::InitializationFailed("chat template retry failed"))
        }
        Err(_) => Err(RuntimeError::InitializationFailed(
            "embedded chat template retrieval failed",
        )),
    }
}

pub(crate) fn bounded_template_size(required: usize) -> Result<usize, RuntimeError> {
    if required == 0 || required > MAX_CHAT_TEMPLATE_BYTES {
        return Err(RuntimeError::InitializationFailed(
            "embedded chat template buffer size is invalid",
        ));
    }
    Ok(required)
}

fn generate(
    model: &LlamaModel,
    context: &mut LlamaContext<'_>,
    chat_template: &str,
    request: &RuntimeRequest,
    cancellation: &impl CancellationSignal,
    shutdown: &CancellationToken,
) -> Result<RuntimeResponse, RuntimeError> {
    let cancellation = CombinedCancellation {
        request: cancellation,
        shutdown,
    };
    if cancellation.is_cancelled() {
        return Err(RuntimeError::Cancelled);
    }
    context.clear_kv_cache();
    let prompt = format_chat_prompt(model, chat_template, request)?;
    let prompt_tokens = model
        .str_to_token(&prompt, AddBos::Always)
        .map_err(|_| RuntimeError::GenerationFailed("tokenization failed"))?;
    validate_context_capacity(prompt_tokens.len(), request.max_output_tokens())?;
    let prompt_sample_slot = prefill(context, &prompt_tokens, &cancellation)?;
    generate_tokens(
        model,
        context,
        &prompt_tokens,
        prompt_sample_slot,
        request.max_output_tokens(),
        &cancellation,
    )
}

struct CombinedCancellation<'a, T: CancellationSignal> {
    request: &'a T,
    shutdown: &'a CancellationToken,
}

impl<T: CancellationSignal> CancellationSignal for CombinedCancellation<'_, T> {
    fn is_cancelled(&self) -> bool {
        self.request.is_cancelled() || self.shutdown.is_cancelled()
    }
}

fn format_chat_prompt(
    model: &LlamaModel,
    chat_template: &str,
    request: &RuntimeRequest,
) -> Result<String, RuntimeError> {
    let messages = build_chat_messages(request)?;
    model
        .apply_chat_template(Some(chat_template), &messages, true)
        .map_err(|_| RuntimeError::GenerationFailed("chat template application failed"))
}

pub(crate) fn build_chat_messages(
    request: &RuntimeRequest,
) -> Result<Vec<LlamaChatMessage>, RuntimeError> {
    let messages = request
        .messages()
        .iter()
        .map(|message| {
            LlamaChatMessage::new(
                message.role().as_str().to_owned(),
                message.content().to_owned(),
            )
            .map_err(|_| RuntimeError::GenerationFailed("chat message creation failed"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(messages)
}

fn validate_context_capacity(
    prompt_tokens: usize,
    max_output_tokens: u32,
) -> Result<(), RuntimeError> {
    let output_tokens = usize::try_from(max_output_tokens)
        .map_err(|_| RuntimeError::InvalidRequest("output token count exceeds usize"))?;
    let required = prompt_tokens
        .checked_add(output_tokens)
        .ok_or(RuntimeError::InvalidRequest(
            "request context size overflowed",
        ))?;
    let context_tokens = usize::try_from(CONTEXT_TOKENS)
        .map_err(|_| RuntimeError::InvalidRequest("runtime context size exceeds usize"))?;
    if prompt_tokens == 0 || required > context_tokens {
        return Err(RuntimeError::InvalidRequest(
            "formatted request exceeds the runtime context",
        ));
    }
    Ok(())
}

fn prefill(
    context: &mut LlamaContext<'_>,
    tokens: &[LlamaToken],
    cancellation: &impl CancellationSignal,
) -> Result<i32, RuntimeError> {
    for range in prefill_chunk_ranges(tokens.len())? {
        if cancellation.is_cancelled() {
            return Err(RuntimeError::Cancelled);
        }
        let mut batch = LlamaBatch::new(range.len(), 1);
        for absolute_index in range.clone() {
            let position = i32::try_from(absolute_index)
                .map_err(|_| RuntimeError::GenerationFailed("prompt position exceeds i32"))?;
            let logits = absolute_index + 1 == tokens.len();
            batch
                .add(tokens[absolute_index], position, &[0], logits)
                .map_err(|_| RuntimeError::GenerationFailed("prefill batch failed"))?;
        }
        context
            .decode(&mut batch)
            .map_err(|_| RuntimeError::GenerationFailed("prefill decode failed"))?;
    }
    if cancellation.is_cancelled() {
        return Err(RuntimeError::Cancelled);
    }
    final_prefill_sample_slot(tokens.len())
}

pub(crate) fn prefill_chunk_ranges(token_count: usize) -> Result<Vec<Range<usize>>, RuntimeError> {
    if token_count == 0 {
        return Err(RuntimeError::InvalidRequest(
            "formatted prompt produced no tokens",
        ));
    }
    let chunk = usize::try_from(BATCH_TOKENS)
        .map_err(|_| RuntimeError::InitializationFailed("batch size exceeds usize"))?;
    Ok((0..token_count)
        .step_by(chunk)
        .map(|start| start..start.saturating_add(chunk).min(token_count))
        .collect())
}

pub(crate) fn final_prefill_sample_slot(token_count: usize) -> Result<i32, RuntimeError> {
    let chunk = usize::try_from(BATCH_TOKENS)
        .map_err(|_| RuntimeError::InitializationFailed("batch size exceeds usize"))?;
    let slot = token_count
        .checked_sub(1)
        .ok_or(RuntimeError::InvalidRequest(
            "formatted prompt produced no tokens",
        ))?
        % chunk;
    i32::try_from(slot).map_err(|_| RuntimeError::GenerationFailed("sampling slot exceeds i32"))
}

fn generate_tokens(
    model: &LlamaModel,
    context: &mut LlamaContext<'_>,
    prompt_tokens: &[LlamaToken],
    mut sample_slot: i32,
    max_output_tokens: u32,
    cancellation: &impl CancellationSignal,
) -> Result<RuntimeResponse, RuntimeError> {
    let sampler = LlamaSampler::chain(
        [
            LlamaSampler::penalties_simple(
                model.n_vocab(),
                REPETITION_PENALTY_HISTORY_TOKENS,
                1.05,
            ),
            LlamaSampler::top_k(20),
            LlamaSampler::top_p(0.8, 1),
            LlamaSampler::temp(0.7),
            LlamaSampler::dist(SAMPLING_SEED),
        ],
        true,
    )
    .with_tokens(prompt_tokens);
    let mut detokenizer = StreamDetokenizer::new(model, Special::Plaintext);
    let mut text = String::new();
    let mut sampled_output_tokens = 0_u32;
    let mut emitted_output_tokens = 0_u32;
    let mut finish_reason = RuntimeFinishReason::Length;
    let mut position = i32::try_from(prompt_tokens.len())
        .map_err(|_| RuntimeError::GenerationFailed("generation position exceeds i32"))?;

    for index in 0..max_output_tokens {
        if cancellation.is_cancelled() {
            return Err(RuntimeError::Cancelled);
        }
        let token = sampler.sample(context, sample_slot);
        sampled_output_tokens += 1;
        if model.is_eog_token(token) {
            finish_reason = RuntimeFinishReason::Stop;
            break;
        }
        text.push_str(
            &detokenizer
                .push(token)
                .map_err(|_| RuntimeError::GenerationFailed("output detokenization failed"))?,
        );
        emitted_output_tokens += 1;
        if index + 1 == max_output_tokens {
            break;
        }

        let mut batch = LlamaBatch::new(1, 1);
        batch
            .add(token, position, &[0], true)
            .map_err(|_| RuntimeError::GenerationFailed("generation batch failed"))?;
        context
            .decode(&mut batch)
            .map_err(|_| RuntimeError::GenerationFailed("generation decode failed"))?;
        position = position
            .checked_add(1)
            .ok_or(RuntimeError::GenerationFailed(
                "generation position overflowed",
            ))?;
        sample_slot = 0;
    }
    text.push_str(
        &detokenizer
            .finish()
            .map_err(|_| RuntimeError::GenerationFailed("output detokenization failed"))?,
    );
    let input_tokens = u32::try_from(prompt_tokens.len())
        .map_err(|_| RuntimeError::GenerationFailed("input token usage exceeds u32"))?;
    Ok(RuntimeResponse {
        text,
        finish_reason,
        usage: RuntimeUsage {
            input_tokens,
            sampled_output_tokens,
            emitted_output_tokens,
        },
    })
}

#[cfg(test)]
pub(crate) fn test_calibrated_digest() -> &'static str {
    CALIBRATED_MODEL_DIGEST
}

#[cfg(test)]
pub(crate) fn test_calibrated_size() -> u64 {
    CALIBRATED_MODEL_SIZE_BYTES
}
