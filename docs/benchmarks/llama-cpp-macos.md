# llama.cpp Rust binding spike on macOS

Date: 2026-08-18

## Decision

Use `llama-cpp-4` 0.6.0 with `default-features = false` and only the `metal`
feature for PAM's first embedded runtime adapter. Keep the binding behind a
model-neutral contract and do not expose its types outside the adapter.

This is a conditional selection, not a claim that the M1/32 GiB target has
passed. The adapter must:

- forbid unsafe code and never call the binding's unsafe abort callback;
- split prompt evaluation into bounded chunks so cancellation can be checked
  between native calls;
- own each mutable context on a bounded worker and serialize requests by
  default rather than assuming concurrent contexts are affordable;
- validate grammar input before constructing a grammar sampler; and
- ship the upstream llama.cpp MIT notice because the sys crate archive does not
  contain the upstream root `LICENSE` file.

The safe wrapper and static Metal build are a better fit than a hand-maintained
C ABI layer at this stage. Revisit the choice if the wrapper cannot preserve
these constraints, its native-abort sampler behavior cannot be contained, or
the target-machine profile fails.

## Reproducible artifact

The isolated workspace at `spikes/llama-cpp-4` accepts an explicit local GGUF
path, never downloads weights, and emits versioned JSON on stdout. It is not a
member of PAM's production workspace.

```sh
cargo build --release --locked \
  --manifest-path spikes/llama-cpp-4/Cargo.toml

PAM_SPIKE_TARGET=$(cargo metadata --no-deps --format-version 1 \
  --manifest-path spikes/llama-cpp-4/Cargo.toml | jq -r .target_directory)
/usr/bin/time -lp \
  "$PAM_SPIKE_TARGET/release/pam-llama-cpp-4-spike" \
  --model "$MODEL" \
  --prompt 'Return exactly OK.' \
  --tokens 16
```

## Host and inputs

| Item | Measured value |
| --- | --- |
| Host | MacBook Pro Mac16,5, Apple M4 Max, 16 CPU cores, 40 GPU cores |
| Memory | 64 GiB unified memory; Metal reported 55,662,788,608 total bytes |
| OS | macOS 26.5.2 (25F84), arm64 |
| Toolchain | Rust 1.97.0; Apple clang 21.0; Command Line Tools 26.6; CMake 4.4.0 |
| Binding | `llama-cpp-4` 0.6.0 / `llama-cpp-sys-4` 0.6.0 |
| llama.cpp | binding reports `0.1.1-dev`; sys crate pins upstream commit `34af94cd9ab277632e27caeec2d41de2fd091b31` |
| Cargo features | `metal`; default features disabled |
| Model | Qwen3.6-35B-A3B UD Q6_K_XL GGUF, user-owned path intentionally omitted |
| Model license | Apache-2.0, as recorded in GGUF metadata |
| Model file | 31,843,777,504 bytes; SHA-256 `f6b6c6d5cfa6f00d964eeb7add28eb14ce7481734d506b90681007678cd2c484` |
| Parameters | 34,660,610,688 |

The model was already present on the host. No weight was fetched, copied into
the repository, or included in a build artifact.

## Results

The first independently reproduced spike run after a fresh build compiled the
embedded Metal library at runtime. A prior warmed run shows the cache effect.

| Measurement | First reproduced run | Warm run |
| --- | ---: | ---: |
| Backend initialization | 7,102.250 ms | 49.985 ms |
| Model load | 1,719.155 ms | 1,540.585 ms |
| Context creation | 25.476 ms | not recorded |
| Prompt evaluation, 4 tokens | 8.391 ms | 5.416 ms |
| Time to first sampled token | 42.943 ms | 37.427 ms |
| First sample after prompt evaluation | 34.551 ms | 32.011 ms |
| Generate 16 tokens | 230.099 ms | not comparable; 4-token run |
| Peak resident set size | 32,066,781,184 bytes | not recorded |
| Swaps | 0 | 0 |

A Homebrew llama.cpp b9960 control run against the same GGUF used
`llama-bench -p 128 -n 32 -r 3 -ngl 99 -fa auto -o json` and measured
820.865 +/- 19.542 prompt tokens/s, 77.284 +/- 1.047 generation tokens/s, and
31,459,475,456 bytes peak RSS. It is a useful host/model control, not a direct
binding comparison: it is an older dynamically linked llama.cpp build.

## Gate results

| Gate | Result | Evidence and consequence |
| --- | --- | --- |
| Static aarch64 build | Pass | Release build completed with Command Line Tools and embedded Metal. |
| Universal build | Unproven | Only the aarch64 Rust target is installed. Do not claim x86_64 packaging. |
| Signing and linkage | Pass for development | 5,241,632-byte arm64 Mach-O; ad-hoc signature verifies; `otool -L` lists only macOS system frameworks and libraries. |
| Metal | Pass on this host | Runtime selected MTL0 Apple M4 Max and offloaded all model layers. |
| Startup and first token | Pass on this host | Cold embedded-library and warm-cache timings are reported separately above. |
| Resident memory | Pass only for 64 GiB host | 32.07 GB peak RSS with no swap. This result is unsafe to extrapolate to 32 GiB. |
| Cancellation | Conditional | Safe generation/chunk boundaries are available; the in-call abort callback is unsafe and prohibited. Production must chunk prefill and cap chunk work. |
| Concurrent requests | Deliberately serialized | The model can be shared, but contexts are mutable and a second 32 GB request is not an acceptable default. Use a bounded one-worker queue first. |
| Grammar output | API present, runtime proof deferred | Grammar samplers exist, but invalid construction/native failure requires validation and containment in the adapter. |
| Unload/reload | API-level pass, RSS proof deferred | Model/context use RAII drops. In-process repeated-cycle RSS needs the production adapter, not a process smoke test. |
| License inventory | Conditional | Cargo metadata reports wrapper/sys as MIT OR Apache-2.0 and llama.cpp is MIT; PAM must add the missing upstream notice to distributed artifacts. |

## Known binding hazards

`LlamaSampler::sample` accepts a native logits slot and returns a token rather
than a `Result`. Supplying a non-logits slot aborts in native llama.cpp. The
spike uses the final prompt slot after prefill and slot zero after each
single-token decode. The production adapter must keep this index handling
private and cover it with subprocess-level fault tests where feasible.

The spike intentionally benchmarks raw prompt execution rather than chat
template quality. Model profiles and the local API own templating, sampling,
structured-output validation, and user-visible quality decisions.

## Scope boundary

This evidence completes the binding decision on the available Mac. It does not
complete the separate Qwen profile proof on an M1 with 32 GiB RAM. That target
requires a smaller quantization and measurement on the actual target hardware.
