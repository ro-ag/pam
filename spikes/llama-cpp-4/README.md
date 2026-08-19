# llama-cpp-4 Metal spike

This isolated Cargo workspace measures `llama-cpp-4` 0.6.0 with only its
`metal` feature. It is not part of PAM's production workspace and never
downloads model weights. `--model` must name an existing user-owned GGUF file.

```sh
cargo run --release --locked \
  --manifest-path spikes/llama-cpp-4/Cargo.toml -- \
  --model /absolute/path/to/model.gguf \
  --prompt "Summarize this retained evidence." \
  --chat \
  --recommended-sampling \
  --tokens 32 \
  --context 8192 \
  --max-projected-bytes 20000000000
```

llama.cpp writes native diagnostics to stderr. The spike writes one JSON object
to stdout. `--context` makes the context allocation explicit; when it is
omitted, the spike selects prompt plus generation length with a 512-token
minimum. The selected context may not exceed the training context reported by
the model. `--chat` applies the GGUF's embedded `tokenizer.chat_template` to one
user message and records the template source in the report; it fails closed if
the template is missing, invalid, or larger than the bounded retrieval limit.
Raw-prompt mode remains the default. Sampling also defaults to greedy for
historical comparisons. `--recommended-sampling` selects the fixed Qwen3-Coder
profile: temperature 0.7, top-p 0.8, top-k 20, repetition penalty 1.05 over the
complete 8,192-token sequence (initialized with every prompt token), and seed
42. Schema-v4 JSON records the selected sampling mode.

`--max-projected-bytes` requires an explicit context. The spike initializes the
backend, runs llama.cpp's no-allocation projection, sums every device entry with
checked arithmetic, and rejects an over-budget profile before allocating the
model. An accepted run reuses the exact projected model and context parameters
for live inference so admission and execution cannot drift.

The JSON `memory_bytes` object records two views of the same pinned parameters:

- `projected` comes from `llama_cpp_4::fit::get_device_memory_data`, which asks
  the vendored llama.cpp to construct a no-allocation model and context and
  classify model, context, and compute bytes per device entry. With
  `--max-projected-bytes`, the query and cap check run after backend
  initialization but before model load. Without a cap they remain diagnostic
  and run after model load but before live context creation.
- `live` comes from `LlamaContext::memory_breakdown` after inference and
  classifies the buffers actually associated with the live context by backend
  buffer type.

On Apple unified-memory systems, sum every projected entry before comparing the
core allocation with system or Metal working-set limits; host and Metal are not
independent physical-memory pools. Mapped bytes are not proof that every page is
resident, so this report is an allocation projection, not a process-footprint
measurement. The report deliberately omits the fit query's per-device free and
total snapshots. Admission must use one fresh OS availability snapshot and must
never sum per-entry free or total values. A projection cap is not proof of live
physical footprint, so benchmark evidence must still record live buffers, peak
RSS, pressure, and swap.

Timing values are monotonic-clock microseconds with these boundaries:

- `backend_init`: `LlamaBackend::init` only;
- `model_load`: `LlamaModel::load_from_file` only;
- `memory_projection`: the complete pinned no-allocation memory query;
- `prompt_eval`: the complete prompt `decode` call;
- `time_to_first_token`: prompt-decode start through the first sampled token;
- `first_token_after_prompt_eval`: prompt-decode completion through first sample;
- `total_generation`: prompt-decode completion through the last sampled token;
- `total_inference`: prompt-decode start through the last sampled token.

Greedy mode and the fixed seed in recommended mode make repeated runs
comparable. The final sampled token is not decoded back into the context when
the requested limit is reached, because there is no subsequent token to
prepare. `sampled_generation_tokens` includes an end-of-generation token;
`emitted_generation_tokens` does not.

`LlamaSampler::sample` takes the logits-enabled native batch slot and does not
return an error for a wrong slot; llama.cpp aborts the process instead. The
spike therefore samples the final prompt slot after prefill and slot zero after
each single-token generation decode. Cancellation is outside this timing spike:
the binding's abort-callback methods are unsafe and this crate forbids unsafe
code.

Validate the isolated spike with:

```sh
cargo fmt --manifest-path spikes/llama-cpp-4/Cargo.toml -- --check
cargo check --locked --manifest-path spikes/llama-cpp-4/Cargo.toml
cargo clippy --locked --manifest-path spikes/llama-cpp-4/Cargo.toml -- -D warnings
```
