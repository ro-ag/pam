# llama.cpp Rust binding spike on macOS

Date: 2026-08-18

## Decision

Use `llama-cpp-4` 0.6.0 with `default-features = false` and only the `metal`
feature for PAM's first embedded runtime adapter. Keep the binding behind a
model-neutral contract and do not expose its types outside the adapter.

This is a conditional binding selection. The 20 GB Q4 profile measured below
sets M1 Pro with 32 GB memory as PAM's minimum supported Mac, but its timings
are M4 Max measurements and must not be presented as M1 performance. The
adapter must:

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

## Q4 profile under a 20 GB model-memory ceiling

Date: 2026-08-19

The user authorized the available Mac16,5 M4 Max/64 GiB host as the benchmark
machine and defined an M1 Pro with 32 GB memory as the minimum supported Mac.
The hardware distinction is important: these measurements prove the selected
artifact and runtime profile stay below a 20,000,000,000-byte model-memory
ceiling on this Apple-unified-memory runtime. They do not establish M1 Pro
throughput or latency.

The exact user-owned artifact is
[`byteshape/Qwen3.6-35B-A3B-GGUF`](https://huggingface.co/byteshape/Qwen3.6-35B-A3B-GGUF/tree/57f6dec8727b4c3f5498ff2564a0333ac1f6624a),
`Qwen3.6-35B-A3B-Q4_K_S-3.80bpw.gguf`: 16,492,334,496 bytes, SHA-256
`ecc07b85c6c3110d1b210aa85935967c7f29f994e6e1c3a07ee486946ae535c1`,
Apache-2.0, derived from `Qwen/Qwen3.6-35B-A3B`. The file remains outside the
repository in a user-owned directory.

The release spike used full Metal offload, one sequence, batch and micro-batch
512, automatic flash attention, f16 K/V cache, non-unified KV, greedy sampling,
and an exact 20,000,000,000-byte no-allocation projection cap. The cap runs
after backend initialization but before model load, and the accepted run reuses
the exact projected parameters.

The final-binary matrix was captured with:

```sh
PAM_Q4_MODEL=/absolute/path/to/Qwen3.6-35B-A3B-Q4_K_S-3.80bpw.gguf
PAM_SPIKE_TARGET=$(cargo metadata --no-deps --format-version 1 \
  --manifest-path spikes/llama-cpp-4/Cargo.toml | jq -r .target_directory)

for PAM_Q4_CONTEXT in 512 4096 8192 32768 65536 131072 262144; do
  /usr/bin/time -lp \
    "$PAM_SPIKE_TARGET/release/pam-llama-cpp-4-spike" \
    --model "$PAM_Q4_MODEL" \
    --prompt 'Return exactly OK.' \
    --tokens 16 \
    --context "$PAM_Q4_CONTEXT" \
    --max-projected-bytes 20000000000 \
    > "/tmp/pam-q4-final-$PAM_Q4_CONTEXT.json" \
    2> "/tmp/pam-q4-final-$PAM_Q4_CONTEXT.stderr"
done
```

The selected chat run retained system snapshots around the exact process:

```sh
/usr/bin/memory_pressure > /tmp/pam-q4-selected-before-memory-pressure.txt
sysctl vm.swapusage > /tmp/pam-q4-selected-before-swap.txt
/usr/bin/time -lp \
  "$PAM_SPIKE_TARGET/release/pam-llama-cpp-4-spike" \
  --model "$PAM_Q4_MODEL" \
  --prompt 'Answer with only the number: What is 37 + 58?' \
  --chat \
  --tokens 64 \
  --context 65536 \
  --max-projected-bytes 20000000000 \
  > /tmp/pam-q4-selected-evidence.json \
  2> /tmp/pam-q4-selected-evidence.stderr
/usr/bin/memory_pressure > /tmp/pam-q4-selected-after-memory-pressure.txt
sysctl vm.swapusage > /tmp/pam-q4-selected-after-swap.txt
```

| Context tokens | Projected bytes | Live buffer bytes | Peak RSS bytes | Process swaps | Decision |
| ---: | ---: | ---: | ---: | ---: | --- |
| 512 | 17,084,121,664 | 17,250,992,704 | 16,725,098,496 | 0 | Pass |
| 4,096 | 17,160,649,248 | 17,327,520,288 | 16,793,255,936 | 0 | Pass |
| 8,192 | 17,248,729,632 | 17,415,600,672 | 16,876,404,736 | 0 | Pass |
| 32,768 | 17,777,211,936 | 17,944,082,976 | 17,388,961,792 | 0 | Pass |
| 65,536 | 18,481,855,008 | 18,648,726,048 | 18,052,808,704 | 0 | Selected ceiling |
| 131,072 | 19,891,141,152 | 20,058,012,192 | 19,394,084,864 | 0 | Reject: live buffers exceed 20 GB |
| 262,144 | 22,709,713,440 | not loaded | 228,638,720 | 0 | Rejected before model load |

The selected 65,536-token profile leaves 1,351,273,952 bytes beneath the live
20 GB ceiling. On its final chat-templated arithmetic run, backend initialization
took 38.880 ms, model load 752.149 ms, context creation 83.510 ms, prompt
evaluation 11.942 ms for 24 tokens, time to first token 89.422 ms, and seven
sampled tokens completed in 151.884 ms. Peak RSS was 18,053,513,216 bytes.
Snapshots retained immediately before and after that run report system-wide
free memory moving from 90% to 63%; encrypted swap usage stayed at 610.38 MiB
and `/usr/bin/time` recorded zero process swaps.

The no-allocation projection under-reported live buffers by 166,871,040 bytes
for every measured context. That is covered by a 5% calibrated contingency at
the selected profile. The 131,072-token row demonstrates why the product
profile uses measured live evidence rather than treating an accepted raw
projection as sufficient.

### Quality observations

Quality checks used the GGUF's embedded `tokenizer.chat_template`; raw prompts
are not representative of the compatible API. The arithmetic prompt returned
95 and the evidence-integrity prompt produced a correct one-sentence SHA-256
explanation. The sequence prompt returned 42 with `/no_think`. Exact-format
output remained unreliable because this model/template emitted visible
reasoning and could exhaust a 64- or 128-token budget before the final answer.
Task #25 must therefore make reasoning behavior explicit and must not promise
strict structured output from greedy text generation alone.

The other quality prompts used the same selected profile and this command,
changing only the prompt and token bound shown below:

```sh
run_q4_quality() {
  /usr/bin/time -lp \
    "$PAM_SPIKE_TARGET/release/pam-llama-cpp-4-spike" \
    --model "$PAM_Q4_MODEL" \
    --prompt "$1" \
    --chat \
    --tokens "$2" \
    --context 65536 \
    --max-projected-bytes 20000000000
}

run_q4_quality \
  'In one sentence, explain why recording a model file SHA-256 digest matters.' \
  128
run_q4_quality 'Answer with only the next number: 2, 6, 12, 20, 30, ?' 128
run_q4_quality \
  'Answer with only the next number: 2, 6, 12, 20, 30, ? /no_think' \
  64
run_q4_quality 'Return exactly PAM.' 128
run_q4_quality 'Return exactly PAM. /no_think' 64
```

## Gate results

| Gate | Result | Evidence and consequence |
| --- | --- | --- |
| Static aarch64 build | Pass | Release build completed with Command Line Tools and embedded Metal. |
| Universal build | Unproven | Only the aarch64 Rust target is installed. Do not claim x86_64 packaging. |
| Signing and linkage | Pass for development | 5,241,632-byte arm64 Mach-O; ad-hoc signature verifies; `otool -L` lists only macOS system frameworks and libraries. |
| Metal | Pass on this host | Runtime selected MTL0 Apple M4 Max and offloaded all model layers. |
| Startup and first token | Pass on this host | Cold embedded-library and warm-cache timings are reported separately above. |
| Resident memory | Pass for selected Q4 profile | The 65,536-token Q4 profile used 18.65 GB live buffers and 18.05 GB peak RSS with zero process swaps. The earlier 32.07 GB Q6 control remains 64-GiB-only evidence. |
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

The spike supports both raw prompts and an explicit embedded-chat-template
path. Model profiles and the local API own sampling, structured-output
validation, and user-visible quality decisions.

## Production Qwen3-Coder profile

Date: 2026-08-19

The first production profile is the user-owned
[`Qwen3-Coder-30B-A3B-Instruct-Q4_K_S.gguf`](https://huggingface.co/unsloth/Qwen3-Coder-30B-A3B-Instruct-GGUF/blob/b17cb02dd882d5b6ab62fc777ad2995f19668350/Qwen3-Coder-30B-A3B-Instruct-Q4_K_S.gguf)
from Unsloth revision `b17cb02dd882d5b6ab62fc777ad2995f19668350`:
17,456,012,448 bytes, SHA-256
`56a7d00783419bcb0ae566253c371bcb3678261bb79881a553539f5679864db4`.
The source model is Apache-2.0 and text-only; the exact license notice snapshot
used for registration has SHA-256
`832dd9e00a68dd83b3c3fb9f5588dad7dcf337a0db50f7d9483f310cd292e92e`.

The final schema-v4 release spike projected every context without allocating
the model by intentionally setting a one-byte cap:

```sh
PAM_CODER_MODEL=/absolute/path/to/Qwen3-Coder-30B-A3B-Instruct-Q4_K_S.gguf
PAM_SPIKE_TARGET=$(cargo metadata --no-deps --format-version 1 \
  --manifest-path spikes/llama-cpp-4/Cargo.toml | jq -r .target_directory)

for PAM_CODER_CONTEXT in 512 4096 8192 32768 65536 131072 262144; do
  "$PAM_SPIKE_TARGET/release/pam-llama-cpp-4-spike" \
    --model "$PAM_CODER_MODEL" \
    --prompt 'Return exactly OK.' \
    --tokens 16 \
    --context "$PAM_CODER_CONTEXT" \
    --max-projected-bytes 1 \
    > "/tmp/pam-coder-projection-$PAM_CODER_CONTEXT.json" \
    2> "/tmp/pam-coder-projection-$PAM_CODER_CONTEXT.stderr"
done
```

Only contexts whose projection could satisfy the calibrated 20 GB allocation
were loaded:

```sh
for PAM_CODER_CONTEXT in 512 4096 8192; do
  /usr/bin/time -lp \
    "$PAM_SPIKE_TARGET/release/pam-llama-cpp-4-spike" \
    --model "$PAM_CODER_MODEL" \
    --prompt 'Return exactly OK.' \
    --chat \
    --recommended-sampling \
    --tokens 16 \
    --context "$PAM_CODER_CONTEXT" \
    --max-projected-bytes 20000000000 \
    > "/tmp/pam-coder-live-$PAM_CODER_CONTEXT.json" \
    2> "/tmp/pam-coder-live-$PAM_CODER_CONTEXT.stderr"
done
```

| Context tokens | Projected bytes | Live buffer bytes | Peak RSS bytes | Process swaps | Decision |
| ---: | ---: | ---: | ---: | ---: | --- |
| 512 | 17,824,657,408 | 17,999,687,680 | 17,613,914,112 | 0 | Pass |
| 4,096 | 18,180,648,960 | 18,355,679,232 | 17,966,153,728 | 0 | Pass |
| 8,192 | 18,587,496,448 | 18,762,526,720 | 18,372,165,632 | 0 | Selected profile |
| 32,768 | 21,032,775,680 | not loaded | not measured | not measured | Rejected before load |
| 65,536 | 24,287,555,584 | not loaded | not measured | not measured | Rejected before load |
| 131,072 | 30,797,115,392 | not loaded | not measured | not measured | Rejected before load |
| 262,144 | 43,846,411,776 | not loaded | not measured | not measured | Rejected before load |

At the selected 8,192 context, final-binary backend initialization took
59.515 ms, model load 771.028 ms, and context creation 50.194 ms on the M4 Max. The calibrated
5% contingency is 929,374,823 bytes, producing a 19,516,871,271-byte admission
value. Snapshots around the quality suite found unchanged encrypted swap usage
at 602.38 MiB, an unchanged `vm_stat` Swapouts counter of 43,160, and system
free-memory pressure moving from 91% to 70%. These are M4 Max measurements, not
an M1 Pro speed claim.

Quality runs used `--chat --recommended-sampling`, the embedded GGUF template,
and the selected 8,192 context. The repetition sampler was initialized with all
prompt tokens and retained the complete bounded 8,192-token sequence. Initial
short prompts correctly solved the analysis case but missed important requested constraints in the Rust, Python,
and SQL cases. Four revised prompts that made their acceptance contract
explicit all passed: Rust used `.first()` and explained the panic, Python
filtered paid rows and returned ISO-date `Decimal` totals in sorted order, SQL
filtered paid orders and used `DENSE_RANK() <= 3`, and the numerical case
returned 2.4%, 2.76%, 0.36 percentage points, and 15% relative lift. This is a
focused smoke suite, not a general quality ranking. Applications must treat
model output as untrusted and validate any required structure.

The production proof then registered the exact digest and license notice,
started `pam daemon --model qwen/qwen3-coder-30b-a3b-instruct-q4-k-s`, received
a default-deny response for the first inference, granted only its exact effect
hash, and successfully retried the same request through PAM's authenticated
local IPC. No HTTP listener, sidecar model server, or subprocess runtime was
used.

## Scope boundary

This evidence completes the binding decision and the constrained Q4 profile on
the available Mac. PAM's minimum supported Mac is M1 Pro with 32 GB memory;
startup must still use the exact digest-bound admission check on the live host.
M1 Pro speed remains unmeasured, so only the M4 Max timings above may be quoted.
