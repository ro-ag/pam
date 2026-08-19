# llama-cpp-4 Metal spike

This isolated Cargo workspace measures `llama-cpp-4` 0.6.0 with only its
`metal` feature. It is not part of PAM's production workspace and never
downloads model weights. `--model` must name an existing user-owned GGUF file.

```sh
cargo run --release --locked \
  --manifest-path spikes/llama-cpp-4/Cargo.toml -- \
  --model /absolute/path/to/model.gguf \
  --prompt "Summarize this retained evidence." \
  --tokens 32
```

llama.cpp writes native diagnostics to stderr. The spike writes one JSON object
to stdout. Timing values are monotonic-clock microseconds with these boundaries:

- `backend_init`: `LlamaBackend::init` only;
- `model_load`: `LlamaModel::load_from_file` only;
- `prompt_eval`: the complete prompt `decode` call;
- `time_to_first_token`: prompt-decode start through the first sampled token;
- `first_token_after_prompt_eval`: prompt-decode completion through first sample;
- `total_generation`: prompt-decode completion through the last sampled token;
- `total_inference`: prompt-decode start through the last sampled token.

The greedy sampler makes repeated runs comparable. The final sampled token is
not decoded back into the context when the requested limit is reached, because
there is no subsequent token to prepare. `sampled_generation_tokens` includes an
end-of-generation token; `emitted_generation_tokens` does not.

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
