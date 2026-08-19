# Model memory estimates and admission headroom

Date: 2026-08-18

## Decision

PAM does not derive a fit recommendation from GGUF file size or a generic KV
formula. The selected runtime must project the exact model, context, batch,
micro-batch, sequence count, cache types, flash-attention mode, and offload
configuration. `pam_model::RuntimeMemoryProjection` keeps the resulting weight,
context/recurrent, and compute totals behind a model-neutral boundary and binds
them to the registered artifact digest.

`pam_model::estimate_memory` applies caller-supplied projection contingency,
PAM application budget, operating-system reserve, current availability, and an
explicit unified-memory working-set state with checked arithmetic. It reports
physical-capacity, working-set, and transient-availability failures separately.
The estimate is an admission input, not a reservation and not benchmark proof.
It is deliberately not persisted in schema v7 because availability and runtime
configuration are volatile.

## Authoritative projection

For the selected `llama-cpp-4` 0.6.0 spike, PAM uses
`get_device_memory_data`. The binding wraps llama.cpp's
`common_get_device_memory_data`, loads the exact GGUF with `no_alloc`, constructs
the requested context, and reports per-buffer model, context, and compute bytes.
On Apple unified memory, PAM sums every distinct Metal and Host entry once;
these are not independent physical pools. The live context's
`memory_breakdown()` is the calibration check after load.

The component meanings are:

- **weights**: projected backend tensor allocations, not file length, mmap
  virtual size, or an assumption that every mapped page is resident;
- **context**: KV cache plus architecture-specific recurrent, hybrid, SWA, or
  MLA state;
- **compute**: temporary graphs, output buffers, and backend scratch affected
  by micro-batch and attention implementation;
- **headroom**: projection contingency, PAM's non-model budget, and memory left
  to the OS and other applications.

llama.cpp's own `fit_params` device fitting is useful but not sufficient as the
product admission policy: its contract explicitly assumes system memory is
unlimited. PAM therefore evaluates OS and unified-memory limits separately.
See the pinned upstream
[`fit.h`](https://github.com/ggml-org/llama.cpp/blob/34af94cd9ab277632e27caeec2d41de2fd091b31/common/fit.h)
and
[`fit.cpp`](https://github.com/ggml-org/llama.cpp/blob/34af94cd9ab277632e27caeec2d41de2fd091b31/common/fit.cpp).

## Initial macOS headroom policy

The policy inputs remain explicit in code so task #24 can tune them from the
target Mac rather than turning today's assumptions into hidden constants. The
conservative starting point for that measurement is:

```text
core = sum(weight + context + compute across distinct runtime entries)
projection contingency = max(2 GiB, ceil(10% of core))
model working set = core + projection contingency + PAM application budget
OS reserve = max(8 GiB, 20% of physical RAM)

require model working set <= Metal recommended maximum working set
require model working set + OS reserve <= physical RAM
require the same allocation to pass a fresh availability/pressure check
```

The 10%, 2 GiB, 8 GiB, and 20% values are conservative task-#24 starting
policy, not measured constants. The contingency covers mapped-buffer/layout
variance, allocator and page-table overhead, Metal pipelines, tokenizer/native
objects, and projection error. PAM's own daemon/API/UI budget is separate so it
cannot disappear inside a model estimate. Before load, task #25 must re-run the
projection and check normal memory pressure with no rising swap; warning or
critical pressure, an unknown limit, an overflow, or a projection failure must
fail closed.

`UnifiedWorkingSetLimit` distinguishes `NotApplicable`, `Known`, and
`Unknown`. macOS Metal admission requires `Known`; a failed platform query is
`Unknown` and returns an error rather than silently behaving like an unlimited
host. The spike's projection query runs after its live model has loaded, so its
device free/total values are diagnostic and are omitted from the JSON. A real
admission decision must take one fresh OS availability snapshot before load and
must never sum per-device free or total values on unified memory.

Metal's recommended maximum working set is a device allocation limit, not
physical RAM. The measured M4 Max reports 55,662,788,608 bytes while the host
has 64 GiB of unified physical memory. The M1/32 GiB value is unknown and is a
required input to task #24, not something PAM extrapolates from the M4.

## Pinned Qwen projection

The isolated spike uses `llama-cpp-4` 0.6.0, its pinned llama.cpp commit, full
Metal offload, one sequence, f16 K/V cache, automatic flash attention, batch
512, and micro-batch 512. The exact user-owned Qwen3.6-35B-A3B Q6_K_XL
artifact is 31,843,777,504 bytes; llama.cpp projects 31,832,787,456 bytes of
backend weight buffers.

The Qwen architecture has ten full-attention layers plus recurrent state. For
this exact configuration, the runtime projection is:

| Allocated context | Context/recurrent bytes |
| ---: | ---: |
| 512 | 76,349,440 |
| 4,096 | 149,749,760 |
| 8,192 | 233,635,840 |
| 32,768 | 736,952,320 |
| 131,072 | 2,750,218,240 |
| 262,144 | 5,434,572,800 |

This happens to decompose as 65,863,680 recurrent bytes per sequence plus
20,480 KV bytes per token for f16, but PAM does not generalize that equation to
another architecture or cache configuration. At 8,192 tokens the pinned
runtime instead projected 154,992,640 context bytes with q8_0 cache and
113,049,600 with q4_0. Four parallel sequences also multiply recurrent state;
the total configured context already contains all four sequences and must not
be multiplied a second time. Flash attention changed compute rather than
persistent context in this matrix, while reducing micro-batch from 512 to 128
cut the Metal compute projection from roughly 493 MiB to 123 MiB.

At only 512 tokens, the exact Q6 projection is already:

| Component | Bytes |
| --- | ---: |
| Weight buffers | 31,832,787,456 |
| Context/recurrent | 76,349,440 |
| Compute | 526,424,128 |
| Core total before any headroom | 32,435,561,024 |

The schema-v2 release spike reported 32,975,905,344 live allocated bytes for
the same 512-token configuration, 540,344,320 bytes above the no-allocation
projection because the live mapped Metal weight buffer is larger. The initial
2 GiB minimum contingency covers that observed allocation-layout delta; task
#24 still has to compare the estimate with physical-footprint peak, pressure,
and swap on the target host.

That leaves only 1,924,177,344 bytes of a 32 GiB physical-memory budget before
projection contingency, PAM, or the OS. The initial 10% contingency alone
exceeds the remaining capacity, before applying the 8 GiB OS reserve. Q6_K_XL
is therefore rejected as a 32 GiB candidate without pretending that this M4
projection is the missing M1 benchmark.

## Candidate screen for task #24

The official Unsloth Hugging Face repository currently lists Qwen3.6-35B-A3B
GGUF artifact sizes of 24.9 GB for UD-Q5_K_S, 22.1 GB for UD-Q4_K_M, 20.9 GB
for UD-Q4_K_S, and 17.7 GB for UD-IQ4_XS. These catalog bytes are storage and
screening facts only; exact runtime projections require each digest.
[Hugging Face model files](https://huggingface.co/unsloth/Qwen3.6-35B-A3B-GGUF/tree/main)

- Q6_K_XL is eliminated for 32 GiB by the exact projection above.
- Q5_K_S is too close to capacity to justify an M1 benchmark under the initial
  reserve policy.
- Q4_K_M remains a tight low-context candidate, matching the publisher's
  general llama.cpp example, but is not a fit recommendation.
- Q4_K_S is the preferred task-#24 starting candidate because its smaller
  storage lower bound leaves more room for runtime and PAM overhead.
- IQ4_XS is a fallback with more capacity headroom and an explicit quality
  trade-off; task #24 must measure quality as well as memory and speed.

No candidate becomes a default until the exact digest is projected and then
measured on the actual M1 with 32 GiB RAM. A safe calibration must cover the
observed peak physical-footprint increase by at least `max(5%, 256 MiB)` without
overestimating a calibrated configuration by more than 20%; otherwise the
contingency is retuned and the candidate remains unavailable.

## Scope and portability

This slice implements pure component accounting and macOS unified-memory
admission inputs. It does not implement or claim Windows support. Runtime
projection, system-memory sampling, unified working-set limits, and pressure
monitoring remain narrow adapter inputs, so a later Windows implementation can
supply its own memory pools without changing model acquisition or GGUF domain
types.
