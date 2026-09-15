# Bounded evidence and local-model qualification

Status: target qualification contract · updated 2026-09-10 · plans 31–35

Implementation tracking: [delivery roadmap](../agent-companion-roadmap.md).
Task #119 added experimental Microsoft record selection and initial summary
limits; it did not establish qualification or complete every admission boundary.

Companion to [agent investigation](2026-09-09-local-model-triage.md) and
[model prompts](2026-09-09-local-model-prompts.md). This defines admission and
qualification requirements; it does not qualify a model or change runtime behavior.

## Objective

Save the frontier agent repeated access attempts, evidence retrieval, diagnosis
turns, tokens, and elapsed time while preserving correct, actionable outcomes.
The comparison baseline is deterministic PAM with brokered connectors and compact
evidence, not an agent receiving an entire raw log. Model chat is a diagnostic
smoke test only; a greeting does not establish task competence.

## Admit before collecting, compressing, and generating

The daemon owns these checks. CLI validation improves errors but is not an
authorization or resource boundary. Every phase rechecks its remaining budget;
missing size headers do not authorize an unlimited stream.

| Boundary | Required checks | If the request cannot fit |
| --- | --- | --- |
| Request | Caller/project scope, declared operation, validated target references, deadline, rate/concurrency limits | Refuse with cause and recovery; do not start collection |
| Collection | Per-response and cumulative bytes/records, pages, redirects, expanded archive size, timeout; correlate revision and product attempt | Fetch bounded ranges/pages if supported, otherwise return partial/unavailable |
| Evidence preparation | Integrity, redaction, source identity, required fields, retained/omitted ranges, completeness | Preserve exact source where authorized; identify missing evidence |
| Compressor | Exact supported artifact/backend, input/output bounds, fresh memory admission, required-fact retention contract | Use deterministic evidence or escalate; no automatic remote fallback |
| Investigator | Qualified artifact/task/template/backend, actual formatted token count plus output reserve, prefill/working-set envelope, pressure and queue budget | Select or split meaningful evidence units, shorten the task, or escalate |
| Result | Schema, permitted values, references/quotes, completeness, authoritative-status consistency, route budget | Reject interpretation and return an honest unresolved result |

A configured 8,192-token window is an upper bound, not a promise that every
8,192-token request fits memory. Admission uses the smaller of context capacity,
qualified prompt length, current available memory, and task budget. Serialize
inference and cap both queued request count and retained request bytes. Cancellation
and deadlines must remain responsive during prefill, not only token generation.

An oversized file is not itself proof the model would hallucinate: it must never
reach inference outside the admitted envelope. A small but incomplete excerpt can
still mislead. An omission marker is disclosure, not proof of sufficient context.

## Evidence contract

Every packet records source handle and digest, exact revision/build attempt or
analysis/artifact identity, collection time, represented ranges, omitted ranges,
truncation/pagination state, redaction state, and required evidence still missing.
Cross-product identifiers must be correlated by collected facts, never guessed
from a model's text or substituted with an unrelated latest run.

Required fields are task-specific. A Sonar gate observation requires the correct
analysis and its reported conditions; explaining an unexpected coverage result
may additionally require scanner output and configuration. A publish investigation
must distinguish artifact upload from later metadata publication or verification.
If those facts are absent, the permitted outcome is an observation plus an explicit
unresolved question, not an unsupported cause or successful workflow verdict.

Prefer complete diagnostic records and stage boundaries over arbitrary chunks.
Bound the number of chunks and aggregation work. Preserve cross-chunk dependencies
and conflicting evidence; if these exceed the budget, escalate instead of silently
dropping them. No failure visible in a slice establishes only that observation.

## Microsoft semantic compression

Pipeline: deterministic source-preserving reduction, optional qualified
LLMLingua-2 extraction, then bounded local investigation. Task #119 implemented
an experimental pure-Rust scorer with PAM whole-record retention and source maps.
It defaults off and remains unqualified for logs; see
[implementation and measured smoke limits](../microsoft-compression.md).

`pam-old` considered the approximately 713 MB LLMLingua-2 mBERT candidate, but its
later task-25 decision restricted proposed use to prose and explicitly excluded
logs, code, SQL, JSON, diffs, diagnostics, identifiers, and numbers until fidelity
is demonstrated. That unresolved evidence gap carries forward for
non-keyword-anchored facts: the 2026-09-12 held-out qualification proved
decisive-fact retention for keyword-anchored classes and lost a non-keyword
negation line at the product budget, so those classes stay restricted out and
compression stays off by default
([records](../benchmarks/2026-09-12-compression-qualification/compressor.json),
[sequence](../benchmarks/2026-09-12-compression-qualification/sequence.json)).
Do not introduce a Python service, native build dependency, or remote inference
to bypass it.

Qualification must bind an exact licensed artifact to a supported pure-Rust
backend and prove source-span mapping and decisive-fact retention for each input
class. Preserve identifiers, numbers, operators, relationships and diagnostic
boundaries needed by the task. A verbatim token subsequence alone does not prove
the resulting sentence retains its meaning. Deterministic structured fields stay
outside semantic rewriting.

Stage compressor and investigator residency: unload the compressor, verify memory
recovery, then take a fresh admission snapshot. Include compressor time, memory and
errors in end-to-end results. If extraction fails its contract, fall back to bounded
deterministic evidence or escalate. Do not force a compression ratio that destroys
the evidence merely to fit a model.

## Candidate envelope and existing evidence

The owner's requested screening range is 9–14 decimal GB of weights for a 32 GB
workstation. It is neither a minimum quality floor nor a total runtime-memory cap.

| Candidate | Artifact bytes | Role in comparison |
| --- | ---: | --- |
| Qwen3-14B Q5_K_M | 10,514,569,568 | Initial dense candidate with more weight headroom |
| Qwen3-Coder-30B-A3B-Instruct Q3_K_S | 13,292,471,456 | Coding-specialized challenger from the old model family |
| Qwen3-14B Q4_K_M / Q6_K | 9,001,752,960 / 12,121,937,248 | Optional quantization controls, only if needed |

Sizes were checked on 2026-09-10 in [Qwen's repository](https://huggingface.co/Qwen/Qwen3-14B-GGUF/tree/main)
and [Unsloth's repository](https://huggingface.co/unsloth/Qwen3-Coder-30B-A3B-Instruct-GGUF/tree/main).
Before evaluation, pin revision, exact file SHA-256, license and tensor formats;
these mutable links are discovery references, not artifact identities. Existing
`qwen3`/`qwen3moe` and K-quant paths do not establish exact-artifact qualification.

The old 30B Coder Q4_K_S passed four explicit-contract Rust/Python/SQL/numerical
smoke checks after earlier constraint misses and recorded about 18.76 GB live
buffers through llama.cpp. Preserve that evidence as a reference, not a Candle
memory result or a measured incident-diagnosis error rate. See
[`pam-old` benchmark](../../../pam-old/docs/benchmarks/llama-cpp-macos.md).

Current Candle prefill forwards the entire prompt and materializes attention
scores. Static inspection at 8,192 input tokens calculates 4 GiB for one MoE F16
32-head scores tensor; the dense Metal path uses F32, implying 10 GiB for one
40-head scores tensor and 2.5 GiB full KV. Dequantized embeddings and other
intermediates add memory. These are allocation calculations, not measured peaks;
the runtime's general F16-cache comment must not become an admission assumption.

Start qualification with at most 2,048 input tokens including framing, reserving
output separately. Test larger contexts only within measured envelopes. Investigate
chunked prefill or memory-efficient attention before claiming full-context fit;
such backend work is a separate implementation task. Weight-size eligibility must
be replaced by artifact/task/backend qualification, not another arbitrary floor.

**2026-09-13 (plan 37, task #155):** the 18 GB size floor is gone. Admission is
verification-based: a model whose SHA-256 was checked (a completed Verify job or a
catalog download) is engine-class and may be a tier default; anything unverified
stays test-only. Size no longer decides anything — the llama.cpp engine runs
whatever fits, and quality is the capability bench's verdict (see
`docs/benchmarks/2026-09-13-llama-engine-screen`), which is what let gpt-oss-20b
(12.1 GB, the best-scoring artifact) become a default.

**2026-09-15 (plan 34, task #96):** verification admits nothing to a job on its own.
A compiled-in qualification table (`pam_model::qualification::QUALIFIED`) binds an
exact artifact SHA-256 to the pinned engine tag, the targets it was measured on, the
frozen contract and case-set digest, the gate figures and the evidence record path.
A registry entry is *qualified* when its verified digest matches a record covering
the current target; `admin.models.defaults.set` and `ModelService::resolve` both
refuse anything else (`unverified`, `unqualified`), so a default seeded past the
admin op is refused at the same line. Diagnostics (`admin.models.try`) still run on
any installed model. A unit test refuses a record whose engine tag is not the pinned
one, so bumping the engine forces requalification. The only record is
gpt-oss-20b-MXFP4 on b10938/macos-arm64 under answer contract v2
(`docs/benchmarks/2026-09-15-answer-contract-v2`); Linux and Windows builds stay
unqualified until measured there. Memory is not a gate and is not in the record.

## One paired acceptance experiment

Replay frozen incident bundles from git, lint, tests, builds, Sonar and publishing.
Use synthetic/redacted JFrog bundles until an authorized connector and real evidence
exist; label them accordingly. Include ordinary cases, ambiguous/missing evidence,
cross-attempt mismatches, hostile text, partial responses, and failures in collection
itself. Ground truth comes from full evidence and reviewer adjudication; genuine
ambiguity has no forced cause label. Separate development examples from held-out
incident families so retries of one failure do not masquerade as independent cases.

Compare three arms with the same task and information access:

1. Deterministic broker/reduction plus frontier handoff.
2. The same broker plus local investigation and bounded follow-up reads.
3. The same as arm 2 plus qualified semantic compression.

An initial 60-case screen, ten per failure stage, can reject a bad candidate but
cannot qualify it. The proposed qualification gate uses 500 ordinary held-out
incidents plus 100 hostile variants. Require at least 300 correct non-abstaining
ordinary results, zero materially wrong accepted results, and zero authority or
authoritative-status violations. A correct result includes the decisive evidence;
its proposed next read must actually address an unresolved question. At zero errors
in 300 independent accepted results the approximate 95% upper error bound is still
1%, not a guarantee. Publish coverage, per-product errors, omissions and abstentions.

Require at least 30% fewer total frontier tokens through the correct resolution
versus arm 1, including corrections and extra reads. Also report avoided access
attempts, connector calls and end-to-end time. Do not count hypothetical raw-log
tokens as realized savings. Frontier replay uses only explicitly exportable evidence;
evaluation does not authorize sending private logs to a vendor CLI or hosted API.

Proposed resource targets: peak incremental PAM working set at most 16 GiB,
p95 admitted local inference at most 15 seconds warm / 30 seconds cold, normal
memory pressure with no sustained added swapouts, and under 5% slowdown in a fixed
representative developer workload. These are targets to validate, not declarations
that 16 GiB fits every 32 GB host; live admission may demand a lower limit. Include
load/unload, worst admitted prefill, compressor phases, queue bursts and cancellation.

The previously authorized M4 Max/64 GiB host may run capped experiments. Record
the host, resource cap and concurrent workload; do not relabel its speed or pressure
results as M1 Pro/32 GB measurements. Lack of that exact machine does not block
candidate evaluation. A qualification record must state its tested host envelope.

## Release decision

Bind qualification to artifact digest, backend/version, device class, compute/cache
dtype, template/sampler, task contract, prompt/output limits, compressor configuration
and evidence-selection version. Requalify material changes. Existing configured
defaults remain visible as unqualified until they pass; diagnostics may test them
within resource limits without silently enabling production investigations.

If no candidate passes, retain deterministic flows, connectors, evidence and explicit
escalation. If a candidate passes only some products or shorter inputs, enable only
that envelope. The benchmark qualifies advisory investigation and permitted reads;
it never authorizes model decisions to merge, publish, waive checks or grant access.
