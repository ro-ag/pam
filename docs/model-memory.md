# Model memory estimates and admission headroom

Date: 2026-08-19

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

The policy inputs remain explicit in code so a new artifact or host does not
turn today's measurements into hidden constants. The conservative starting
point for an uncalibrated profile is:

```text
core = sum(weight + context + compute across distinct runtime entries)
projection contingency = max(2 GiB, ceil(10% of core))
model working set = core + projection contingency + PAM application budget
OS reserve = max(8 GiB, 20% of physical RAM)

require model working set <= Metal recommended maximum working set
require model working set + OS reserve <= physical RAM
require the same allocation to pass a fresh availability/pressure check
```

The 10%, 2 GiB, 8 GiB, and 20% values are conservative uncalibrated defaults,
not universal constants. The contingency covers mapped-buffer/layout
variance, allocator and page-table overhead, Metal pipelines, tokenizer/native
objects, and projection error. PAM's own daemon/API/UI budget is separate so it
cannot disappear inside a model estimate. Before load, task #25 must re-run the
projection and check normal memory pressure with no rising swap; warning or
critical pressure, an unknown limit, an overflow, or a projection failure must
fail closed.

`UnifiedWorkingSetLimit` distinguishes `NotApplicable`, `Known`, and
`Unknown`. macOS Metal admission requires `Known`; a failed platform query is
`Unknown` and returns an error rather than silently behaving like an unlimited
host. The capped spike runs its no-allocation projection after backend
initialization and before model load, then reuses the exact accepted parameters.
Device free/total values remain diagnostic and are omitted from the JSON. A
real admission decision must take one fresh OS availability snapshot before
load and must never sum per-device free or total values on unified memory.

Metal's recommended maximum working set is a device allocation limit, not
physical RAM. The measured M4 Max reports 55,662,788,608 bytes while the host
has 64 GiB of unified physical memory. M1 Pro with 32 GB memory is PAM's
minimum supported Mac, but each live host still supplies its own working-set
limit and pressure snapshot. The M4 results below establish the model-memory
profile, not M1 Pro throughput.

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
2 GiB minimum contingency covers that observed allocation-layout delta. The Q6
artifact remains rejected under the 20 GB product ceiling.

That leaves only 1,924,177,344 bytes of a 32 GiB physical-memory budget before
projection contingency, PAM, or the OS. The initial 10% contingency alone
exceeds the remaining capacity, before applying the 8 GiB OS reserve. Q6_K_XL
is therefore rejected as a 32 GiB candidate.

## Selected 20 GB Q4 profile

The selected artifact is the Apache-2.0
[`byteshape/Qwen3.6-35B-A3B-GGUF`](https://huggingface.co/byteshape/Qwen3.6-35B-A3B-GGUF/tree/57f6dec8727b4c3f5498ff2564a0333ac1f6624a)
`Qwen3.6-35B-A3B-Q4_K_S-3.80bpw.gguf`: 16,492,334,496 bytes,
SHA-256
`ecc07b85c6c3110d1b210aa85935967c7f29f994e6e1c3a07ee486946ae535c1`.
PAM does not bundle this user-owned file.

The exact profile uses full Metal offload, one sequence, batch and micro-batch
512, automatic flash attention, f16 K/V cache, and non-unified KV. The measured
context matrix is:

| Context tokens | Projected bytes | Live buffer bytes | Peak RSS bytes | Decision |
| ---: | ---: | ---: | ---: | --- |
| 512 | 17,084,121,664 | 17,250,992,704 | 16,725,098,496 | Pass |
| 4,096 | 17,160,649,248 | 17,327,520,288 | 16,793,255,936 | Pass |
| 8,192 | 17,248,729,632 | 17,415,600,672 | 16,876,404,736 | Pass |
| 32,768 | 17,777,211,936 | 17,944,082,976 | 17,388,961,792 | Pass |
| 65,536 | 18,481,855,008 | 18,648,726,048 | 18,052,808,704 | Selected maximum |
| 131,072 | 19,891,141,152 | 20,058,012,192 | 19,394,084,864 | Reject: live buffers exceed cap |
| 262,144 | 22,709,713,440 | not loaded | 228,638,720 | Rejected before model load |

Every live run recorded zero process swaps. Snapshots immediately before and
after the selected chat run report system-free memory moving from 90% to 63%
and encrypted swap usage unchanged at 610.38 MiB. The no-allocation projection
under-reported live buffers by 166,871,040 bytes. A calibrated contingency of
`max(5%, 256 MiB)` is 924,092,751 bytes here, producing a calibrated model
allocation estimate of 19,405,947,759 bytes before PAM's application budget:
below the 20,000,000,000-byte model ceiling and above the measured live
allocation. The larger uncalibrated 10%/2 GiB rule continues to apply to any
other digest or runtime profile.

On a 32 GiB minimum host, the separate 8 GiB OS reserve plus this calibrated
model allocation uses 27,995,882,351 bytes before PAM's application budget,
leaving 6,363,856,017 bytes. Startup still fails closed if the live Metal
working-set limit, availability, or pressure check is unknown or insufficient.

Quality checks through the embedded GGUF chat template passed arithmetic and a
one-sentence integrity explanation. A sequence prompt returned the correct
answer with `/no_think`; exact-format output remained unreliable because the
model could spend the output budget on visible reasoning. This profile is
therefore suitable for bounded text generation, but task #25 must expose
reasoning behavior and validate structured output rather than promise it from
greedy sampling alone. Full commands and timings are in
`docs/benchmarks/llama-cpp-macos.md`.

## Scope and portability

This slice implements pure component accounting and macOS unified-memory
admission inputs. It does not implement or claim Windows support. Runtime
projection, system-memory sampling, unified working-set limits, and pressure
monitoring remain narrow adapter inputs, so a later Windows implementation can
supply its own memory pools without changing model acquisition or GGUF domain
types.
