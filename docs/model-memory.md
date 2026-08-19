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
cannot disappear inside a model estimate. Before load, the macOS adapter re-runs
the projection and checks normal memory pressure with a stable swapout counter;
warning or critical pressure, a rising or unknown swap trend, an unknown limit,
an overflow, or a projection failure fails closed.

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

## Calibration 20 GB Q4 profile

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
therefore retained as calibration evidence, not selected as PAM's coding and
data-analysis model. Full measurements are in
`docs/benchmarks/llama-cpp-macos.md`.

## Production coder profile

PAM's first supported runtime profile is the text-only
[`Qwen/Qwen3-Coder-30B-A3B-Instruct`](https://huggingface.co/Qwen/Qwen3-Coder-30B-A3B-Instruct)
model using the user-owned Unsloth `Q4_K_S` GGUF at revision
`b17cb02dd882d5b6ab62fc777ad2995f19668350`. The exact file is
17,456,012,448 bytes with SHA-256
`56a7d00783419bcb0ae566253c371bcb3678261bb79881a553539f5679864db4`.
PAM accepts no other size/digest pair for this profile.

The selected configuration is full Metal offload, one sequence, 8,192 context
tokens, batch and micro-batch 512, automatic flash attention, f16 K/V cache,
and non-unified KV. The admission matrix from the final release spike is:

| Context tokens | Projected bytes | Live buffer bytes | Peak RSS bytes | Process swaps | Decision |
| ---: | ---: | ---: | ---: | ---: | --- |
| 512 | 17,824,657,408 | 17,999,687,680 | 17,613,914,112 | 0 | Pass |
| 4,096 | 18,180,648,960 | 18,355,679,232 | 17,966,153,728 | 0 | Pass |
| 8,192 | 18,587,496,448 | 18,762,526,720 | 18,372,165,632 | 0 | Selected profile |
| 32,768 | 21,032,775,680 | not loaded | not measured | not measured | Rejected before model load |
| 65,536 | 24,287,555,584 | not loaded | not measured | not measured | Rejected before model load |
| 131,072 | 30,797,115,392 | not loaded | not measured | not measured | Rejected before model load |
| 262,144 | 43,846,411,776 | not loaded | not measured | not measured | Rejected before model load |

At 8,192 tokens, the projection comprises 17,275,009,024 Metal weight bytes,
805,306,368 Metal context bytes, 315,359,232 Metal compute bytes,
175,030,272 Host weight bytes, and 16,791,552 Host compute bytes. The live
allocation exceeded the no-allocation projection by 175,030,272 bytes. The
calibrated contingency is `max(ceil(5%), 256 MiB)` = 929,374,823 bytes, so the
admitted model allocation is 19,516,871,271 bytes. That is 483,128,729 bytes
below the 20,000,000,000-byte ceiling and 754,344,551 bytes above the measured
live allocation. PAM and OS reserves remain separate admission requirements.

Quality acceptance uses the GGUF's embedded chat template and the model card's
recommended non-thinking sampler: temperature 0.7, top-p 0.8, top-k 20, and
repetition penalty 1.05 over the complete bounded 8,192-token sequence; the
sampler is seeded with every prompt token and the profile fixes seed 42 for
reproducibility. Explicit contract prompts passed four focused checks: Python
filtering/grouping with
`Decimal`, SQL paid-order aggregation and `DENSE_RANK`, Rust panic diagnosis
and safe `.first()`, and conversion-rate arithmetic. Earlier implicit prompts
missed requested output constraints in three of four cases, so generated text
is untrusted and callers must specify and validate their output contract. The
model supports only non-thinking mode; PAM exposes no reasoning toggle.

The same final binary was loaded by the production daemon and invoked through
an authenticated, exact-effect PAM IPC grant. That establishes the adapter and
policy path on the measured M4 Max. It does not establish M1 Pro throughput;
M1 Pro with 32 GB remains the minimum supported Mac, and every startup repeats
host-specific admission before model load.

### Alternatives considered

Qwen3-Coder is the only supported profile in this release, not the only model
that could ever fit. GLM-4.7-Flash Q4_K_S is the closest future challenger: its
30B-A3B architecture and approximately 17.2 GB community quant appear capable
of fitting, but PAM has not verified an exact artifact, projection, chat
contract, or local quality suite. Devstral Small 2 is coding-specialized and
targets 32 GB Macs, but its dense 24B runtime is expected to be materially
slower on M1 Pro and its added vision capability is outside PAM's text-only
scope. GPT-OSS-20B fits the memory class but requires Harmony formatting and a
reasoning-oriented contract. Kimi K2.5 is multimodal and its official weight
repository is hundreds of gigabytes, so it is outside the host envelope.

These are screening decisions, not cross-model quality claims. Promoting any
alternative requires the same exact-digest memory matrix and coding, Python,
SQL, and numerical-analysis acceptance suite used for the selected profile.

### Prompt-compression memory equation

LLMLingua is a prompt compressor, not an alternative generation model. The
20 GB ceiling is the active Qwen generation-profile cap, not a limit on models
installed on disk or on auxiliary tools loaded in a different phase. For any
phase with more than one resident model, PAM still accounts for their combined
allocation:

```text
concurrent model allocation = coder admission + semantic-compressor weights
                              + semantic-compressor runtime allocations
require the Qwen phase allocation <= 20,000,000,000 bytes
```

The selected coder already admits 19,516,871,271 bytes. Microsoft's smallest
published LLMLingua-2 MeetingBank repository is about 713 MB before encoder
activations, so even that pair would be about 20.23 GB and fail the ceiling.
The 2.25 GB XLM-RoBERTa-large variant is farther outside it. A future semantic
compressor therefore does not remain resident with Qwen by default. It can load
on demand in its own separately measured preprocessing phase, fully unload,
demonstrate recovered memory, and trigger a fresh pressure/swap/admission
snapshot before the coder loads. Its installed bytes do not consume Qwen's
runtime ceiling.

Original LLMLingua uses causal-LM perplexity, commonly with GPT-2-small or a
7B-class model, and is the less attractive local candidate. LLMLingua-2 turns
compression into extractive token classification with a BERT-level encoder;
its authors report 3x-6x lower compressor latency and 2x-5x compression in
their evaluated tasks. PAM would screen the 713 MB mBERT variant first, but it
is multilingual, trained from MeetingBank seed data, and shipped through a
Python/Transformers stack. It is not yet evidence for English code, compiler
logs, paths, hashes, or a single Rust binary.

Accordingly, deterministic source-span compaction remains the production first
stage. LLMLingua-2 is an optional follow-up experiment only. Promotion requires
an exact model digest and license, staged load/unload RSS evidence, M1 Pro
latency, compression-quality tests over coding and data-analysis evidence, and
an output map back to retained source spans. Original evidence remains
authoritative; neither compressor output nor Qwen output can replace it.

## Scope and portability

This slice implements component accounting and production macOS unified-memory
admission, including fresh physical availability, pressure, Metal working-set,
and swap-trend checks. It does not implement or claim Windows support. These
remain narrow adapter inputs so a later Windows implementation can supply its
own memory pools without changing model acquisition or GGUF domain types.
