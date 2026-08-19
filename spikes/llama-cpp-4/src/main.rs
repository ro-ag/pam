#![forbid(unsafe_code)]

use std::env;
use std::error::Error;
use std::ffi::OsString;
use std::fmt;
use std::fs;
use std::io::{self, Write};
use std::num::NonZeroU32;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{Duration, Instant};

use llama_cpp_4::ChatTemplateError;
use llama_cpp_4::prelude::{
    AddBos, LlamaBackend, LlamaBatch, LlamaChatMessage, LlamaContext, LlamaContextParams,
    LlamaFlashAttnType, LlamaModel, LlamaModelParams, LlamaSampler, LlamaToken, Special,
};
use llama_cpp_4::quantize::GgmlType;
use serde::Serialize;

#[cfg(test)]
mod main_test;

const DEFAULT_PROMPT: &str = "Summarize why durable evidence matters in one sentence.";
const DEFAULT_GENERATION_TOKENS: usize = 32;
const MAX_GENERATION_TOKENS: usize = 4096;
const MIN_CONTEXT_TOKENS: u32 = 512;
const RUNTIME_BATCH_TOKENS: u32 = 512;
const INITIAL_CHAT_TEMPLATE_BYTES: usize = 4 * 1024;
const MAX_CHAT_TEMPLATE_BYTES: usize = 1024 * 1024;

const USAGE: &str = "Usage:\n  pam-llama-cpp-4-spike --model <PATH.gguf> [--prompt <TEXT>] [--chat] [--tokens <COUNT>] [--context <COUNT>] [--max-projected-bytes <BYTES>]\n\nOptions:\n  --model <PATH.gguf>          Required local GGUF path; the spike never downloads weights\n  --prompt <TEXT>              Prompt text, at most 512 tokens after optional chat templating (default: a short evidence-summary prompt)\n  --chat                       Apply the GGUF's embedded tokenizer.chat_template to one user message and add an assistant prompt\n  --tokens <COUNT>             Maximum generated tokens, 1..=4096 (default: 32)\n  --context <COUNT>            Context tokens, 512..=model training context (default: prompt + generation, at least 512)\n  --max-projected-bytes <BYTES>  Fail before model load when the fixed-profile projection exceeds this positive byte cap; requires --context\n  -h, --help                   Show this help";

#[derive(Debug)]
struct AppError(String);

impl AppError {
    fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl fmt::Display for AppError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl Error for AppError {}

type AppResult<T> = Result<T, AppError>;

#[derive(Debug)]
struct Config {
    model_path: PathBuf,
    prompt: String,
    chat: bool,
    generation_tokens: usize,
    context_tokens: Option<u32>,
    max_projected_bytes: Option<u64>,
}

enum ParsedArgs {
    Run(Config),
    Help,
}

impl Config {
    fn parse(args: impl IntoIterator<Item = OsString>) -> AppResult<ParsedArgs> {
        let mut args = args.into_iter();
        let _program = args.next();

        let mut model_path = None;
        let mut prompt = None;
        let mut chat = false;
        let mut generation_tokens = None;
        let mut context_tokens = None;
        let mut max_projected_bytes = None;

        while let Some(argument) = args.next() {
            let flag = argument
                .to_str()
                .ok_or_else(|| AppError::new("option names must be valid UTF-8"))?;

            match flag {
                "--model" => {
                    set_once(
                        &mut model_path,
                        PathBuf::from(next_value(&mut args, "--model")?),
                        "--model",
                    )?;
                }
                "--prompt" => {
                    let value = next_value(&mut args, "--prompt")?
                        .into_string()
                        .map_err(|_| AppError::new("--prompt must be valid UTF-8"))?;
                    set_once(&mut prompt, value, "--prompt")?;
                }
                "--chat" => {
                    if chat {
                        return Err(AppError::new("--chat may only be specified once"));
                    }
                    chat = true;
                }
                "--tokens" => {
                    let value = next_value(&mut args, "--tokens")?
                        .into_string()
                        .map_err(|_| AppError::new("--tokens must be valid UTF-8"))?;
                    let count = value.parse::<usize>().map_err(|error| {
                        AppError::new(format!("invalid --tokens value {value:?}: {error}"))
                    })?;
                    if !(1..=MAX_GENERATION_TOKENS).contains(&count) {
                        return Err(AppError::new(format!(
                            "--tokens must be between 1 and {MAX_GENERATION_TOKENS}"
                        )));
                    }
                    set_once(&mut generation_tokens, count, "--tokens")?;
                }
                "--context" => {
                    let value = next_value(&mut args, "--context")?
                        .into_string()
                        .map_err(|_| AppError::new("--context must be valid UTF-8"))?;
                    let count = value.parse::<u32>().map_err(|error| {
                        AppError::new(format!("invalid --context value {value:?}: {error}"))
                    })?;
                    if count < MIN_CONTEXT_TOKENS {
                        return Err(AppError::new(format!(
                            "--context must be at least {MIN_CONTEXT_TOKENS}"
                        )));
                    }
                    set_once(&mut context_tokens, count, "--context")?;
                }
                "--max-projected-bytes" => {
                    let value = next_value(&mut args, "--max-projected-bytes")?
                        .into_string()
                        .map_err(|_| AppError::new("--max-projected-bytes must be valid UTF-8"))?;
                    let bytes = value.parse::<u64>().map_err(|error| {
                        AppError::new(format!(
                            "invalid --max-projected-bytes value {value:?}: {error}"
                        ))
                    })?;
                    if bytes == 0 {
                        return Err(AppError::new(
                            "--max-projected-bytes must be greater than zero",
                        ));
                    }
                    set_once(&mut max_projected_bytes, bytes, "--max-projected-bytes")?;
                }
                "-h" | "--help" => return Ok(ParsedArgs::Help),
                unknown => return Err(AppError::new(format!("unknown option {unknown:?}"))),
            }
        }

        let model_path = model_path.ok_or_else(|| AppError::new("--model is required"))?;
        if max_projected_bytes.is_some() && context_tokens.is_none() {
            return Err(AppError::new(
                "--max-projected-bytes requires an explicit --context",
            ));
        }
        validate_model_path(&model_path)?;

        Ok(ParsedArgs::Run(Self {
            model_path,
            prompt: prompt.unwrap_or_else(|| DEFAULT_PROMPT.to_owned()),
            chat,
            generation_tokens: generation_tokens.unwrap_or(DEFAULT_GENERATION_TOKENS),
            context_tokens,
            max_projected_bytes,
        }))
    }
}

fn next_value(args: &mut impl Iterator<Item = OsString>, flag: &str) -> AppResult<OsString> {
    args.next()
        .ok_or_else(|| AppError::new(format!("{flag} requires a value")))
}

fn set_once<T>(target: &mut Option<T>, value: T, flag: &str) -> AppResult<()> {
    if target.replace(value).is_some() {
        return Err(AppError::new(format!("{flag} may only be specified once")));
    }
    Ok(())
}

fn validate_model_path(path: &PathBuf) -> AppResult<()> {
    let metadata = fs::metadata(path).map_err(|error| {
        AppError::new(format!(
            "cannot access local model {}: {error}",
            path.display()
        ))
    })?;
    if !metadata.is_file() {
        return Err(AppError::new(format!(
            "model path is not a file: {}",
            path.display()
        )));
    }

    let is_gguf = path
        .extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| extension.eq_ignore_ascii_case("gguf"));
    if !is_gguf {
        return Err(AppError::new(format!(
            "model path must have a .gguf extension: {}",
            path.display()
        )));
    }
    Ok(())
}

#[derive(Serialize)]
struct BenchmarkReport {
    schema_version: u32,
    binding: BindingReport,
    runtime: RuntimeReport,
    model: ModelReport,
    request: RequestReport,
    memory_bytes: MemoryReport,
    timings_us: TimingReport,
    result: ResultReport,
}

#[derive(Serialize)]
struct BindingReport {
    crate_name: &'static str,
    crate_version: &'static str,
    llama_cpp_version: &'static str,
    features: [&'static str; 1],
}

#[derive(Serialize)]
struct RuntimeReport {
    os: &'static str,
    arch: &'static str,
    system_info: String,
    gpu_offload_supported: bool,
    devices: Vec<DeviceReport>,
    context_tokens: u32,
    batch_tokens: u32,
    physical_batch_tokens: u32,
    parallel_sequences: u32,
    flash_attention: &'static str,
    kv_cache_k_type: &'static str,
    kv_cache_v_type: &'static str,
    kv_cache_unified: bool,
}

#[derive(Serialize)]
struct DeviceReport {
    name: String,
    description: String,
    device_type: String,
    free_bytes: usize,
    total_bytes: usize,
}

#[derive(Serialize)]
struct ModelReport {
    path: String,
    file_size_bytes: u64,
    loaded_size_bytes: u64,
    parameter_count: u64,
    description: String,
    training_context_tokens: u32,
}

#[derive(Serialize)]
struct RequestReport {
    prompt: String,
    chat_template_applied: bool,
    chat_template_source: Option<&'static str>,
    prompt_tokens: usize,
    requested_generation_tokens: usize,
    requested_context_tokens: Option<u32>,
}

#[derive(Serialize)]
struct MemoryReport {
    projected: ProjectedMemoryReport,
    live: LiveMemoryReport,
}

#[derive(Serialize)]
struct ProjectedMemoryReport {
    source: &'static str,
    query_point: &'static str,
    availability_semantics: &'static str,
    entries: Vec<ProjectedMemoryEntry>,
    total_projected_bytes: usize,
    model_gpu_layers: u32,
    model_training_context_tokens: u32,
    model_expert_count: u32,
    admission: ProjectionAdmissionReport,
}

#[derive(Serialize)]
struct ProjectionAdmissionReport {
    configured_max_bytes: Option<u64>,
    result: &'static str,
}

#[derive(Serialize)]
struct ProjectedMemoryEntry {
    index: usize,
    model_bytes: usize,
    context_bytes: usize,
    compute_bytes: usize,
    total_projected_bytes: usize,
}

#[derive(Serialize)]
struct LiveMemoryReport {
    source: &'static str,
    entries: Vec<LiveMemoryEntry>,
    total_bytes: usize,
}

#[derive(Serialize)]
struct LiveMemoryEntry {
    buffer_type: String,
    model_bytes: usize,
    context_bytes: usize,
    compute_bytes: usize,
    total_bytes: usize,
}

#[derive(Serialize)]
struct TimingReport {
    backend_init: u64,
    model_load: u64,
    prompt_tokenize: u64,
    memory_projection: u64,
    context_create: u64,
    prompt_eval: u64,
    time_to_first_token: u64,
    first_token_after_prompt_eval: u64,
    total_generation: u64,
    total_inference: u64,
}

#[derive(Serialize)]
struct ResultReport {
    sampled_generation_tokens: usize,
    emitted_generation_tokens: usize,
    stopped_on_end_of_generation: bool,
    generated_text: String,
}

struct SetupMeasurement {
    config: Config,
    model_path: PathBuf,
    file_size_bytes: u64,
    prompt_tokens: usize,
    training_context_tokens: u32,
    backend_init: Duration,
    model_load: Duration,
    prompt_tokenize: Duration,
    memory_projection: Duration,
    context_create: Duration,
    projected_memory: ProjectedMemoryReport,
}

struct GenerationMeasurement {
    prompt_eval: Duration,
    time_to_first_token: Duration,
    first_token_after_prompt_eval: Duration,
    total_generation: Duration,
    total_inference: Duration,
    sampled_tokens: usize,
    emitted_tokens: usize,
    stopped_on_end_of_generation: bool,
    generated_bytes: Vec<u8>,
}

struct RuntimeProjection {
    context_params: LlamaContextParams,
    elapsed: Duration,
    report: ProjectedMemoryReport,
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error}\n\n{USAGE}");
            ExitCode::from(2)
        }
    }
}

fn run() -> AppResult<()> {
    let config = match Config::parse(env::args_os())? {
        ParsedArgs::Run(config) => config,
        ParsedArgs::Help => {
            println!("{USAGE}");
            return Ok(());
        }
    };

    let report = benchmark(config)?;
    let stdout = io::stdout();
    let mut output = stdout.lock();
    serde_json::to_writer_pretty(&mut output, &report)
        .map_err(|error| AppError::new(format!("JSON serialization failed: {error}")))?;
    writeln!(output).map_err(|error| AppError::new(format!("JSON output failed: {error}")))?;
    Ok(())
}

fn benchmark(config: Config) -> AppResult<BenchmarkReport> {
    let model_path = config.model_path.canonicalize().map_err(|error| {
        AppError::new(format!(
            "cannot resolve model path {}: {error}",
            config.model_path.display()
        ))
    })?;
    let file_size_bytes = fs::metadata(&model_path)
        .map_err(|error| {
            AppError::new(format!("cannot inspect {}: {error}", model_path.display()))
        })?
        .len();

    let backend_start = Instant::now();
    let backend = LlamaBackend::init().map_err(|error| {
        AppError::new(format!("llama.cpp backend initialization failed: {error}"))
    })?;
    let backend_init = backend_start.elapsed();

    let model_params = LlamaModelParams::default().with_n_gpu_layers(u32::MAX);
    let preflight_projection = if let Some(maximum_bytes) = config.max_projected_bytes {
        let context_tokens = config
            .context_tokens
            .ok_or_else(|| AppError::new("--max-projected-bytes requires an explicit --context"))?;
        Some(project_runtime_memory(
            &model_path,
            &model_params,
            context_tokens,
            "after_backend_init_before_model_load",
            Some(maximum_bytes),
        )?)
    } else {
        None
    };

    let model_load_start = Instant::now();
    let model = LlamaModel::load_from_file(&backend, &model_path, &model_params)
        .map_err(|error| AppError::new(format!("model load failed: {error}")))?;
    let model_load = model_load_start.elapsed();

    let tokenization_prompt = prepare_tokenization_prompt(&config, &model)?;
    let tokenize_start = Instant::now();
    let prompt_tokens = model
        .str_to_token(&tokenization_prompt, AddBos::Always)
        .map_err(|error| AppError::new(format!("prompt tokenization failed: {error}")))?;
    let prompt_tokenize = tokenize_start.elapsed();
    if prompt_tokens.is_empty() {
        return Err(AppError::new("prompt tokenization produced no tokens"));
    }
    validate_prompt_batch_size(prompt_tokens.len())?;

    let prompt_token_count = u32::try_from(prompt_tokens.len())
        .map_err(|_| AppError::new("prompt token count exceeds llama.cpp limits"))?;
    let generation_token_count = u32::try_from(config.generation_tokens)
        .map_err(|_| AppError::new("generation token count exceeds llama.cpp limits"))?;
    let required_context_tokens = prompt_token_count
        .checked_add(generation_token_count)
        .ok_or_else(|| AppError::new("requested context size overflowed"))?;
    let training_context_tokens = model.n_ctx_train();
    if required_context_tokens > training_context_tokens {
        return Err(AppError::new(format!(
            "prompt plus generation requires {required_context_tokens} context tokens, but the model reports a training context of {training_context_tokens}"
        )));
    }

    let context_tokens = select_context_tokens(
        config.context_tokens,
        required_context_tokens,
        training_context_tokens,
    )?;
    let runtime_projection = if let Some(projection) = preflight_projection {
        projection
    } else {
        project_runtime_memory(
            &model_path,
            &model_params,
            context_tokens,
            "after_model_load_before_context_create",
            None,
        )?
    };

    let context_create_start = Instant::now();
    let mut context = model
        .new_context(&backend, runtime_projection.context_params)
        .map_err(|error| AppError::new(format!("context creation failed: {error}")))?;
    let context_create = context_create_start.elapsed();

    let generation = measure_generation(
        &mut context,
        &model,
        &prompt_tokens,
        config.generation_tokens,
    )?;
    let setup = SetupMeasurement {
        config,
        model_path,
        file_size_bytes,
        prompt_tokens: prompt_tokens.len(),
        training_context_tokens,
        backend_init,
        model_load,
        prompt_tokenize,
        memory_projection: runtime_projection.elapsed,
        context_create,
        projected_memory: runtime_projection.report,
    };
    assemble_report(setup, &model, &context, &generation)
}

fn prepare_tokenization_prompt(config: &Config, model: &LlamaModel) -> AppResult<String> {
    if !config.chat {
        return Ok(config.prompt.clone());
    }

    let message = LlamaChatMessage::new("user".to_owned(), config.prompt.clone())
        .map_err(|error| AppError::new(format!("chat message creation failed: {error}")))?;
    let template = embedded_chat_template(model)?;
    model
        .apply_chat_template(Some(&template), &[message], true)
        .map_err(|error| AppError::new(format!("chat template application failed: {error}")))
}

fn embedded_chat_template(model: &LlamaModel) -> AppResult<String> {
    match model.get_chat_template(INITIAL_CHAT_TEMPLATE_BYTES) {
        Ok(template) => Ok(template),
        Err(ChatTemplateError::BuffSizeError(required)) => {
            let required = bounded_chat_template_retry_size(required)?;
            model.get_chat_template(required).map_err(|error| {
                AppError::new(format!(
                    "embedded chat template retrieval failed after retry: {error}"
                ))
            })
        }
        Err(error) => Err(AppError::new(format!(
            "embedded chat template retrieval failed: {error}"
        ))),
    }
}

fn bounded_chat_template_retry_size(required: usize) -> AppResult<usize> {
    if required == 0 {
        return Err(AppError::new(
            "embedded chat template reported an invalid required buffer size of zero",
        ));
    }
    if required > MAX_CHAT_TEMPLATE_BYTES {
        return Err(AppError::new(format!(
            "embedded chat template requires {required} bytes, exceeding the {MAX_CHAT_TEMPLATE_BYTES}-byte safety limit"
        )));
    }
    Ok(required)
}

fn fixed_runtime_context_params(context_tokens: u32) -> LlamaContextParams {
    LlamaContextParams::default()
        .with_n_ctx(NonZeroU32::new(context_tokens))
        .with_n_batch(RUNTIME_BATCH_TOKENS)
        .with_n_ubatch(RUNTIME_BATCH_TOKENS)
        .with_n_seq_max(1)
        .with_flash_attn_type(LlamaFlashAttnType::Auto)
        .with_cache_type_k(GgmlType::F16)
        .with_cache_type_v(GgmlType::F16)
        .with_kv_unified(false)
}

fn project_runtime_memory(
    model_path: &std::path::Path,
    model_params: &LlamaModelParams,
    context_tokens: u32,
    query_point: &'static str,
    maximum_bytes: Option<u64>,
) -> AppResult<RuntimeProjection> {
    let context_params = fixed_runtime_context_params(context_tokens);
    let started = Instant::now();
    let projection = llama_cpp_4::fit::get_device_memory_data(
        model_path,
        model_params,
        &context_params,
        llama_cpp_sys_4::GGML_LOG_LEVEL_ERROR,
    )
    .map_err(|error| AppError::new(format!("memory projection failed: {error}")))?;
    let elapsed = started.elapsed();
    let report = projected_memory_report(projection, query_point, maximum_bytes)?;
    if let Some(maximum_bytes) = maximum_bytes {
        enforce_projected_memory_cap(report.total_projected_bytes, maximum_bytes)?;
    }

    Ok(RuntimeProjection {
        context_params,
        elapsed,
        report,
    })
}

fn select_context_tokens(
    requested: Option<u32>,
    required: u32,
    training_context: u32,
) -> AppResult<u32> {
    if training_context < MIN_CONTEXT_TOKENS {
        return Err(AppError::new(format!(
            "model training context {training_context} is below the spike minimum of {MIN_CONTEXT_TOKENS}"
        )));
    }
    let selected = requested.unwrap_or_else(|| required.max(MIN_CONTEXT_TOKENS));
    if selected > training_context {
        return Err(AppError::new(format!(
            "selected context requests {selected} tokens, but the model reports a training context of {training_context}"
        )));
    }
    if selected < required {
        return Err(AppError::new(format!(
            "prompt plus generation requires {required} context tokens, but the selected context is {selected}"
        )));
    }
    Ok(selected)
}

fn validate_prompt_batch_size(prompt_tokens: usize) -> AppResult<()> {
    let maximum = usize::try_from(RUNTIME_BATCH_TOKENS).map_err(|_| {
        AppError::new("fixed runtime batch size exceeds the platform integer range")
    })?;
    if prompt_tokens > maximum {
        return Err(AppError::new(format!(
            "prompt tokenization produced {prompt_tokens} tokens, but the fixed runtime batch supports at most {maximum} prompt tokens"
        )));
    }
    Ok(())
}

fn measure_generation(
    context: &mut LlamaContext<'_>,
    model: &LlamaModel,
    prompt_tokens: &[LlamaToken],
    generation_tokens: usize,
) -> AppResult<GenerationMeasurement> {
    let mut batch = LlamaBatch::new(prompt_tokens.len(), 1);
    batch
        .add_sequence(prompt_tokens, 0, false)
        .map_err(|error| AppError::new(format!("prompt batch creation failed: {error}")))?;

    let prompt_eval_start = Instant::now();
    context
        .decode(&mut batch)
        .map_err(|error| AppError::new(format!("prompt evaluation failed: {error}")))?;
    let prompt_eval_finished = Instant::now();
    let sampler = LlamaSampler::greedy();
    let mut first_token_at = None;
    let mut generated_bytes = Vec::new();
    let mut sampled_tokens = 0usize;
    let mut emitted_tokens = 0usize;
    let mut stopped_on_end_of_generation = false;
    let mut next_position = i32::try_from(prompt_tokens.len())
        .map_err(|_| AppError::new("prompt position exceeds llama.cpp limits"))?;
    let mut sample_index = next_position - 1;

    for token_index in 0..generation_tokens {
        let token = sampler.sample(context, sample_index);
        first_token_at.get_or_insert_with(Instant::now);
        sampled_tokens += 1;

        if model.is_eog_token(token) {
            stopped_on_end_of_generation = true;
            break;
        }

        let bytes = model
            .token_to_bytes(token, Special::Plaintext)
            .map_err(|error| AppError::new(format!("generated token decoding failed: {error}")))?;
        generated_bytes.extend_from_slice(&bytes);
        emitted_tokens += 1;

        if token_index + 1 == generation_tokens {
            break;
        }

        batch.clear();
        batch
            .add(token, next_position, &[0], true)
            .map_err(|error| AppError::new(format!("generation batch creation failed: {error}")))?;
        context
            .decode(&mut batch)
            .map_err(|error| AppError::new(format!("generation decode failed: {error}")))?;
        sample_index = 0;
        next_position = next_position
            .checked_add(1)
            .ok_or_else(|| AppError::new("generation position overflowed"))?;
    }

    let generation_finished = Instant::now();
    let first_token_at = first_token_at
        .ok_or_else(|| AppError::new("generation finished without sampling a token"))?;
    Ok(GenerationMeasurement {
        prompt_eval: prompt_eval_finished.duration_since(prompt_eval_start),
        time_to_first_token: first_token_at.duration_since(prompt_eval_start),
        first_token_after_prompt_eval: first_token_at.duration_since(prompt_eval_finished),
        total_generation: generation_finished.duration_since(prompt_eval_finished),
        total_inference: generation_finished.duration_since(prompt_eval_start),
        sampled_tokens,
        emitted_tokens,
        stopped_on_end_of_generation,
        generated_bytes,
    })
}

fn assemble_report(
    setup: SetupMeasurement,
    model: &LlamaModel,
    context: &LlamaContext<'_>,
    generation: &GenerationMeasurement,
) -> AppResult<BenchmarkReport> {
    let live_memory = live_memory_report(context)?;
    Ok(BenchmarkReport {
        schema_version: 3,
        binding: BindingReport {
            crate_name: "llama-cpp-4",
            crate_version: "0.6.0",
            llama_cpp_version: llama_cpp_4::llama_version(),
            features: ["metal"],
        },
        runtime: RuntimeReport {
            os: env::consts::OS,
            arch: env::consts::ARCH,
            system_info: llama_cpp_4::print_system_info(),
            gpu_offload_supported: llama_cpp_4::supports_gpu_offload(),
            devices: collect_devices(model),
            context_tokens: context.n_ctx(),
            batch_tokens: context.n_batch(),
            physical_batch_tokens: context.n_ubatch(),
            parallel_sequences: 1,
            flash_attention: "auto",
            kv_cache_k_type: "f16",
            kv_cache_v_type: "f16",
            kv_cache_unified: false,
        },
        model: ModelReport {
            path: setup.model_path.to_string_lossy().into_owned(),
            file_size_bytes: setup.file_size_bytes,
            loaded_size_bytes: model.model_size(),
            parameter_count: model.n_params(),
            description: model
                .desc(256)
                .unwrap_or_else(|error| format!("<unavailable: {error}>")),
            training_context_tokens: setup.training_context_tokens,
        },
        request: RequestReport {
            prompt: setup.config.prompt,
            chat_template_applied: setup.config.chat,
            chat_template_source: setup.config.chat.then_some("gguf:tokenizer.chat_template"),
            prompt_tokens: setup.prompt_tokens,
            requested_generation_tokens: setup.config.generation_tokens,
            requested_context_tokens: setup.config.context_tokens,
        },
        memory_bytes: MemoryReport {
            projected: setup.projected_memory,
            live: live_memory,
        },
        timings_us: TimingReport {
            backend_init: micros(setup.backend_init),
            model_load: micros(setup.model_load),
            prompt_tokenize: micros(setup.prompt_tokenize),
            memory_projection: micros(setup.memory_projection),
            context_create: micros(setup.context_create),
            prompt_eval: micros(generation.prompt_eval),
            time_to_first_token: micros(generation.time_to_first_token),
            first_token_after_prompt_eval: micros(generation.first_token_after_prompt_eval),
            total_generation: micros(generation.total_generation),
            total_inference: micros(generation.total_inference),
        },
        result: ResultReport {
            sampled_generation_tokens: generation.sampled_tokens,
            emitted_generation_tokens: generation.emitted_tokens,
            stopped_on_end_of_generation: generation.stopped_on_end_of_generation,
            generated_text: String::from_utf8_lossy(&generation.generated_bytes).into_owned(),
        },
    })
}

fn projected_memory_report(
    report: llama_cpp_4::fit::DeviceMemoryReport,
    query_point: &'static str,
    maximum_bytes: Option<u64>,
) -> AppResult<ProjectedMemoryReport> {
    let entries = report
        .entries
        .into_iter()
        .enumerate()
        .map(|(index, entry)| {
            Ok(ProjectedMemoryEntry {
                index,
                model_bytes: entry.model,
                context_bytes: entry.context,
                compute_bytes: entry.compute,
                total_projected_bytes: checked_memory_total(
                    entry.model,
                    entry.context,
                    entry.compute,
                )?,
            })
        })
        .collect::<AppResult<Vec<_>>>()?;
    let total_projected_bytes =
        checked_projected_memory_sum(entries.iter().map(|entry| entry.total_projected_bytes))?;

    Ok(ProjectedMemoryReport {
        source: "llama_cpp_4::fit::get_device_memory_data",
        query_point,
        availability_semantics: if maximum_bytes.is_some() {
            "projection_cap_enforced_before_model_load_without_os_availability_snapshot"
        } else {
            "diagnostic_only_use_fresh_os_snapshot_for_admission"
        },
        entries,
        total_projected_bytes,
        model_gpu_layers: report.hyperparams.n_gpu_layers,
        model_training_context_tokens: report.hyperparams.n_ctx_train,
        model_expert_count: report.hyperparams.n_expert,
        admission: ProjectionAdmissionReport {
            configured_max_bytes: maximum_bytes,
            result: if maximum_bytes.is_some() {
                "accepted"
            } else {
                "not_requested"
            },
        },
    })
}

fn checked_projected_memory_sum(totals: impl IntoIterator<Item = usize>) -> AppResult<usize> {
    totals.into_iter().try_fold(0usize, |total, entry| {
        total.checked_add(entry).ok_or_else(|| {
            AppError::new("total projected memory exceeded the platform integer range")
        })
    })
}

fn enforce_projected_memory_cap(total_projected_bytes: usize, maximum_bytes: u64) -> AppResult<()> {
    let total_projected_bytes = u64::try_from(total_projected_bytes).map_err(|_| {
        AppError::new("total projected memory cannot be represented by the configured byte cap")
    })?;
    if total_projected_bytes > maximum_bytes {
        return Err(AppError::new(format!(
            "projected runtime memory {total_projected_bytes} bytes exceeds --max-projected-bytes cap of {maximum_bytes} bytes"
        )));
    }
    Ok(())
}

fn live_memory_report(context: &LlamaContext<'_>) -> AppResult<LiveMemoryReport> {
    let entries = context
        .memory_breakdown()
        .into_iter()
        .map(|entry| {
            Ok(LiveMemoryEntry {
                buffer_type: entry.buft_name,
                model_bytes: entry.model,
                context_bytes: entry.context,
                compute_bytes: entry.compute,
                total_bytes: checked_memory_total(entry.model, entry.context, entry.compute)?,
            })
        })
        .collect::<AppResult<Vec<_>>>()?;
    let total_bytes = entries.iter().try_fold(0usize, |total, entry| {
        total
            .checked_add(entry.total_bytes)
            .ok_or_else(|| AppError::new("total live memory exceeded the platform integer range"))
    })?;

    Ok(LiveMemoryReport {
        source: "LlamaContext::memory_breakdown",
        entries,
        total_bytes,
    })
}

fn checked_memory_total(model: usize, context: usize, compute: usize) -> AppResult<usize> {
    model
        .checked_add(context)
        .and_then(|total| total.checked_add(compute))
        .ok_or_else(|| AppError::new("memory component total exceeded the platform integer range"))
}

fn collect_devices(model: &LlamaModel) -> Vec<DeviceReport> {
    model
        .devices()
        .map(|device| {
            let (free_bytes, total_bytes) = device.memory();
            DeviceReport {
                name: device.name().unwrap_or("<unavailable>").to_owned(),
                description: device.description().unwrap_or("<unavailable>").to_owned(),
                device_type: format!("{:?}", device.device_type()),
                free_bytes,
                total_bytes,
            }
        })
        .collect()
}

fn micros(duration: Duration) -> u64 {
    u64::try_from(duration.as_micros()).unwrap_or(u64::MAX)
}
