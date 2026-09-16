# Model and compression qualification decisions

Status: checkpoint record · task #123 · 2026-09-15 · plan 34

This is the explicit disposition the [admission specification](specs/2026-09-10-model-admission-and-qualification.md)
asks for: which exact artifacts may serve a job, on which engine and platform, under
which contract, and what was decided about everything else. The compiled-in table in
`pam_model::qualification` is the enforcement of this document; the two must agree,
and a unit test holds each table record to its `record.json`. Nothing here is a
readiness claim for a machine that was not measured.

## Decision summary

| Subject | Decision | Envelope | Evidence |
| --- | --- | --- | --- |
| gpt-oss-20b-MXFP4 (`27cd6c43…35901`, 12.1 GB) | **Qualified** for bounded local investigation | llama.cpp b10938, `macos-arm64` (Metal), answer contract v2, reasoning budget 0, 8,192-token context, 160-token output cap, 16-token engine floor | [2026-09-15-answer-contract-v2](benchmarks/2026-09-15-answer-contract-v2/record.json) run 3: accuracy 0.980, 0 false passes, 0 false alarms, 0 over-abstentions, coverage 0.974, warm p95 593 ms |
| gpt-oss-20b-MXFP4 on `ubuntu-*`, `macos-x64`, `win-cpu-*` | **Not qualified** | — | No measurement on those backends; Metal figures are not carried over |
| Qwen3-Coder-30B-A3B-Instruct Q4_K_M / Q5_K_M / Q6_K / Q8_0 (catalog) | **No-go** as a job default | — | [2026-09-13-llama-engine-screen](benchmarks/2026-09-13-llama-engine-screen/record.json): Q4_K_M 0.853, 7 false passes on contract v1; not re-run on v2 (user decision 2026-09-15: gpt-oss-20b only) |
| Qwen3.8-27B, Qwen3.6-35B-A3B, gemma-4-26B-A4B, GLM-4.7-Flash, Nemotron-3.5-Lightning, Devstral-Small-2-24B | **No-go** | — | [2026-09-14-engine-candidate-screen](benchmarks/2026-09-14-engine-candidate-screen/record.json): none met the gates on contract v1; see the table below |
| gpt-oss-120b, Qwen3-Coder-Next | **Not screened** | — | 63 GB and 48 GB; do not fit the screening host |
| Microsoft record selection (LLMLingua-2 scorer) | **Default off, feature removed** | — | [2026-09-12-compression-qualification](benchmarks/2026-09-12-compression-qualification/compressor.json); removed 2026-09-13 with the candle runtime (plan 37) |

Everything not named above is unqualified: the registry lists it as `engine` (verified)
or `test only` (unverified), `admin.models.try` still runs it, and `admin.models.defaults.set`
and every tier resolve refuse it with cause `unqualified` or `unverified`. The download
catalog (`pam_model::catalog`) offers gpt-oss-20b-MXFP4 under the digest and size pinned
here (a unit test holds the preset to the qualification record) alongside the four
Qwen3-Coder no-go quantizations, which stay downloadable as test-only artifacts; a
catalog entry is an offer to fetch, never a readiness claim. Qualification is also
enforced on the admission path, not only by the table's unit test:
`pam_model::qualification::find_in` ignores a record whose engine tag is not the pinned
one or whose figures no longer clear the gates.

## The gates, and what they do not cover

The gates applied to every screen are the ones the roadmap fixed on 2026-09-12:
accuracy at least 0.95 on decidable cases, zero false passes, warm p95 under 10 s on
short tasks. A false pass is a model verdict of "passed" where the record shows a
failure; it is the one error the product cannot afford, so one is disqualifying
regardless of accuracy.

Not gated, on purpose:

- **Memory.** The user ruled on 2026-09-13/14 that memory is not a gate. The screening
  host (Apple M4 Max, 64 GiB) cannot measure footprints because Metal reserves memory it
  does not use, and a threshold measured on one host does not predict admission on
  another. Admission-time measurement on the installed machine is the only honest
  check; task #137 stays parked until a real 32 GB machine exists.
- **The 500 + 100 held-out corpus** the admission specification proposes. The frozen
  bench is 150 cases in four families (build triage, abstention traps, fact extraction,
  Jenkins labels). It can reject a candidate and it measured gpt-oss-20b against the
  product contract; it is not the held-out qualification corpus, which has not been
  built. This record says so rather than relabelling the bench.
- **Reasoning arms.** Every figure is with the reasoning budget at 0 and thinking
  switched off through the template. Reasoning modes need their own output envelope
  and were not measured.

## gpt-oss-20b-MXFP4: qualified on macos-arm64

Three v2 runs on the same host and engine, differing only in the contract details
that were being fixed:

| Run | Output cap | Answer parser | Accuracy | False passes | False alarms | Missing answers | Warm p95 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | 96 | whole line | 0.960 | 0 | 0 | 6 | 918 ms |
| 2 | 160 | whole line | 0.967 | 0 | 2 | 3 | 722 ms |
| 3 (reference) | 160 | first word | 0.980 | 0 | 0 | 3 | 593 ms |

Run 3 is the product contract as shipped: host-parsed exit facts on every build
question, the every-stage trap question, first-word answer parsing, the 160-token cap
recorded in the summary, and the 16-token engine output floor
(`pam_model::engine_server::output_budget`). Families: abstention traps 22/22, build
triage 47/48, fact extraction 40/40, Jenkins labels 38/40.

What the qualification does **not** say:

- The three missing answers (2.0 %) are real. On the two PARALLEL records with a failing
  first branch the model reasons inline and exhausts 160 tokens before its answer line;
  on bt-038 it states the verdict in prose without the marker. These count against
  accuracy and coverage and never as a pass. They are the residual gap tracked on the
  roadmap.
- Every v1 false pass and over-abstention turned out to be a contract artefact
  (ambiguous trap wording, model-parsed exit codes). The v1 numbers below are therefore
  not comparable with v2 and are kept as history only.
- Deterministic exit parsing owns exit truth in the product (#139). The model reads the
  host's facts on build questions; it does not establish them.
- The figures are from a 64 GiB host under ambient load. Latency and correctness are
  portable across hosts of the same target; nothing about memory is.

Requalification is mandatory, and mechanically forced, when any of these move: the
engine tag (`ENGINE_TAG`, a unit test refuses a record on another tag), the artifact
digest, the contract or case set, the prompt framing, sampler settings, or the output
envelope. A new target needs its own measurement; adding `ubuntu-x64` to the record
without a run on that backend is not permitted.

## Candidate screens: no-go

All on llama.cpp b10938, Metal, contract v1 (case set `a324c2e3…5dc8c6`), reasoning off.
Contract v1 numbers are not comparable with v2; they were enough to reject, not to
qualify.

| Artifact | Bytes | Accuracy | False passes | Coverage | Warm p95 | Why no-go |
| --- | --- | --- | --- | --- | --- | --- |
| gpt-oss-20b-MXFP4 (v1 reference) | 12.1 GB | 0.867 | 3 | 0.895 | 574 ms | Failed v1 gates; every false pass was an abstention-trap variant, fixed by the contract — see v2 above |
| Qwen3-Coder-30B-A3B Q4_K_M | 18.6 GB | 0.853 | 7 | 0.912 | 671 ms | 7 false passes, all abstention traps; not re-run on v2 |
| Qwen3.8-27B Q4_K_M | 19.0 GB | 0.893 | 9 | 0.982 | 2351 ms | Highest v1 accuracy, but 3 of 9 false passes on decidable build triage |
| Qwen3.6-35B-A3B Q4_K_M | 20.4 GB | 0.880 | 12 | 0.991 | 796 ms | 12 false passes |
| gemma-4-26B-A4B-it Q4_0 | 14.6 GB | 0.793 | 2 | 0.754 | 516 ms | Fewest false passes but refuses 23 decidable triage records; safety bought with unusable coverage |
| GLM-4.7-Flash Q4_K | 18.2 GB | 0.820 | 13 | 0.904 | 512 ms | Worst on the critical class |
| Nemotron-3.5-Lightning-30B-A3B Q4_0 | 18.9 GB | 0.653 | 11 | 0.982 | 940 ms | Not a fair measurement: 38 contract violations, the answer format did not survive its template |
| Devstral-Small-2-24B Q4_K_M | 14.3 GB | 0.893 | 8 | 0.965 | 1587 ms | 4 of 8 false passes on decidable build triage, the class every other artifact keeps clean |

The screen's own conclusion stands: the false-pass set was stable across artifacts,
which pointed at the contract rather than at another model, and fixing the contract is
what qualified gpt-oss-20b. No second artifact was re-screened on v2 (user decision
2026-09-15). Re-screening the strongest v1 candidates on v2 is the path to a second
qualified artifact, and it is not scheduled.

Earlier candle-runtime screens ([2026-09-12-candidate-accuracy](benchmarks/2026-09-12-candidate-accuracy/record.json),
[2026-09-10-model-screen](benchmarks/2026-09-10-model-screen/screen.json)) are
superseded: the candle runtime was removed on 2026-09-13 and none of those artifacts
qualified there either.

## Microsoft record selection: default off, then removed

The 2026-09-12 held-out qualification ([compressor.json](benchmarks/2026-09-12-compression-qualification/compressor.json))
proved decisive-fact retention for the keyword-anchored classes (cleanup boundary,
identifiers, multibyte, numbers, operators, parallel boundary, retry boundary, scale)
and lost a decisive non-keyword negation line at the product budget, so the
`context_relation` and `negation` classes stayed restricted and the feature stayed off
by default. On 2026-09-13 the candle runtime that hosted the scorer was removed
(plan 37) and the feature with it; log summaries go straight from deterministic
compaction to the bounded model summary. See [the removal note](microsoft-compression.md).
Decision: no semantic compression ships; evidence reduction is deterministic framing only.

## What this checkpoint changes, and what it does not

- The product ships one qualified investigator on one platform. On every other target
  the deterministic path is the product: flows, connectors, compact evidence, explicit
  escalation. That is the fallback the roadmap required if nothing qualified, applied
  per target.
- Configured defaults that are not qualified stay configured and visible, refuse at
  resolve time with a named cause, and keep answering `admin.models.try`.
- No hosted fallback exists or is planned to make a qualification graph turn green.
- Open after this checkpoint: the three missing-answer cases; a second artifact on v2;
  Linux and Windows measurements; the held-out corpus; #105 surfacing configured /
  installed / verified / qualified / admitted as distinct readiness states in the GUI.
