# PAM delivery roadmap: what a sandboxed agent needs

Status: implementation roadmap, 2026-09-10. Planning source of truth: ptrack.
This document orders the remaining work; it does not claim these features ship.
The [agent workflow contract](agent-workflow-contract.md) defines the desired
interaction and the instructions future implementers must follow.

## The outcome

As an agent, I need PAM to take an exact operational question, perform the
already-authorized work outside my sandbox, keep watching while nothing useful
is happening, and return the smallest sufficient evidence-backed result. I
should spend reasoning on changing the project, not rediscovering credentials,
retrying blocked commands, chasing unrelated builds, or reading megabytes of logs.

A useful first outcome is: **investigate this Jenkins build, show what actually
happened, let me retrieve the relevant evidence, and say what remains unknown**.
The next outcome is: **validate this revision, land it under the project's rules,
watch the resulting jobs, and stop with precise evidence at any failed gate**.
A local model may reduce the remaining investigation work. It is not required
for access, evidence, polling, validation, or landing decisions.

## Boundaries that do not change

- Reuse the single binary, CLI, daemon, internal ZeroMQ/Unix IPC, flows, GUI,
  audit/evidence store, Candle runtime, and existing adapters. No MCP interface.
- Enterprise policy must allow executable and IPC access. A Unix socket does
  not make activity invisible to the sandbox or establish caller identity.
- Administration stays GUI-only, with verified enforcement rather than a
  self-reported GUI label. The daemon owns authority and enforces every call.
- Pure-Rust dependency constraint remains. No inference API keys, hosted core
  inference, Python inference service, or silent vendor-CLI fallback. Connector
  secrets remain in the OS keychain and never enter agent/model context.
- Workflow state is durable; inference is stateless. Models make advisory
  observations and request only host-defined, scoped reads. They cannot grant
  access, make a check pass, merge, rerun a job, or publish.
- Land does not authorize tag/release/publication. JFrog was discussed as a
  future publication integration; it is not among the six committed adapters
  and no connector exists today. Return unsupported until separately scoped.

## Current baseline and the gaps

| Area | Present on this branch | Still required |
| --- | --- | --- |
| CLI and broker | Flow list/show/run, tickets, wait/subscribe/cancel, policy and audit | Predictable discovery/admission, authenticated admin isolation, scoped evidence reads |
| Enterprise access | Existing Jira, Confluence, SharePoint, Jenkins, GitHub, Sonar adapters | Deployment-specific acceptance and exact cross-product correlations |
| Jenkins | Explicit build investigation, bounded stages/nodes/logs, CLI observation summary, coverage gaps | Decisive-evidence follow-up and CLI retrieval; root cause remains unresolved |
| Evidence | Deterministic reduction with source maps; original/compact/semantic storage | Common identity/completeness/redaction contract and authorized range reads |
| Orchestration | Flows, checks, approvals, retries, tickets, durable remote polling, guarded landing through sync (bounds-proven pack transfer, exact-lease fast-forward); plan 30 checkpoint #94 recorded 2026-09-15 in enterprise-evidence-checkpoint.md | Live enterprise connectors with the owner's tokens; native-app capture; a real 32 GB host |
| Models | llama.cpp engine as a pinned, digest-verified external process (b10938; Unix socket, Windows loopback) routing every generation path; candle removed 2026-09-13 (plan 37); frozen bench on the engine under answer contract v2 (gpt-oss-20b 0.980/0 FP @593 ms warm p95, 2026-09-15); evidence-backed admission (#96, 2026-09-15): a tier default must be verified and match a compiled-in qualification record on this engine and target — gpt-oss-20b on macos-arm64 is the only one | The three missing-answer cases; qualification on Linux/Windows targets |
| Microsoft compression | Removed 2026-09-13 with the candle runtime (plan 37); qualification records stay under docs/benchmarks | Nothing: evidence reduction is deterministic framing only |

The Microsoft smoke preserved evidence and reduced 1,017 tokens to 459, but took
70.88 seconds in an unoptimized CPU build. Release-build qualification has since
landed: optimized latency meets the caller budget, held-out decisive-fact
retention is proven for keyword-anchored classes and disproven for
non-keyword-anchored ones (restricted out), and the full compressor/unload/
investigator sequence shows compression is the only path that fits oversized
evidence inside the 2,048-token envelope. Compression stays off by default; the
real artifact's verdicts were refused at measurement time by the byte-offset
citation contract in every arm; that gap is closed by host-side quote-to-offset
resolution (issue #25), so enablement now waits on the #108 gates, not
compressor work.
See [implementation notes](microsoft-compression.md) and
[Jenkins behavior](jenkins-investigation.md) for shipped limits.
gpt-oss-20b-MXFP4 (12.1 GB) is the one qualified investigator, on b10938/macos-arm64
under answer contract v2. Weight-size eligibility is gone (#155, #96): admission is a
verified digest plus a qualification record for this engine and target.

## Dependency-ordered plans

The five workstreams below are real ptrack plans. Existing unfinished tasks
were moved with their history and issue links preserved. Plan #30 remains the
umbrella and historical delivery record; #94 was its final integration gate,
recorded on 2026-09-15 in [the enterprise checkpoint](enterprise-evidence-checkpoint.md#plan-30-final-checkpoint-task-94-2026-09-15)
with its named blockers (native capture, 32 GB hardware, live connectors, Windows).
Task dependencies, rather than broad plan barriers, allow independent work.
Every task carries its own caller/integration and acceptance note in ptrack.

### Plan #31 — Verify broker authority and expose bounded agent evidence

| Task | Deliverable | Proof required |
| --- | --- | --- |
| #125 | Verified administration boundary | Forged GUI labels/direct clients cannot administer under the declared threat model; legitimate GUI works |
| #126 | Scoped daemon admission and cumulative budgets | Denied, oversized, expired, redirected and revoked requests cannot exceed authority or resource bounds |
| #127 | Evidence identity and bounded retrieval | Agent can retrieve cited bytes with digest, offset basis, omissions and expiry; cross-scope handles fail |
| #103 | Discoverable CLI task/result contract | Configured operations and actionable refusals are usable without a model; no agent-facing admin API |
| #143 | Broker child-process containment | Repository code and descendants cannot reach private authority; unsupported execution refuses before workload spawn |
| #120 | End-to-end checkpoint | Sandboxed CLI runs one investigation and retrieves its decisive evidence without GUI-only data access |

The administration boundary, scoped budgets and evidence retrieval are implemented;
see [administration](admin-boundary.md), [budgets](scoped-admission-and-budgets.md)
and [flow CLI contracts](flow-cli-contract.md). Broker commands additionally require
[child-process containment](command-containment.md), whose network and artifact-write
limits must be addressed by the guarded landing workstream. Use ptrack for current task status.
Caller and broker-child macOS sandbox fixtures now pass; public progress text is
generic and scoped evidence retrieval remains enforced. These fixtures do not attest
every enterprise sandbox deployment. Checkpoint #120 remains held by the unresolved
GUI compiler conflict in the [native build audit](native-build-dependencies.md).
Hiding a socket pathname is not isolation.
#103 does not depend on model eligibility #96.

Explicit revision-bound GitHub and Jenkins flows now use immutable
[workflow correlation](workflow-correlation.md). Missing or conflicting source
identity blocks downstream use while retaining evidence. The separate
[Sonar analysis flow](sonar-analysis.md) adds an exact historical gate and
GUI-owned repository mapping. [Durable exact-job watches](job-watches.md) now
use cheap status reads and terminal-only evidence collection. Guarded local
verification remains separate work.

Explicit issue/page/document flows provide [cited enterprise context](enterprise-context.md)
with bounded excerpts and clear unsupported or partial states. SharePoint text
capture checks site membership, download origin and metadata consistency.

### Plan #32 — Correlate enterprise products and collect decisive evidence

The [enterprise connector contracts](enterprise-connector-contracts.md) record supported deployment/auth modes, bounded coverage, and the distinction between fixtures and live qualification.

| Task | Deliverable | Proof required |
| --- | --- | --- |
| #128 | Six deployment-specific adapter contracts | Explicit API/auth/pagination/rate-limit support, contract fixtures, separately labeled live smoke |
| #129 | Immutable cross-product target associations | Unrelated latest runs, rebases, retries or concurrent builds never substitute for the target |
| #130 | Jenkins decisive-evidence follow-up | Retry/catch/post/parallel/capped graph cases yield observations and missing evidence, not false causality |
| #131 | Exact Sonar analysis and gate explanation | Pending/stale/wrong-branch analyses and failing conditions remain distinct and authoritative |
| #132 | Bounded issue/document context | Scope, version, source citations, content limits and permission failures survive retrieval |
| #121 | Product checkpoint | Six adapters return useful bounded facts; unsupported configurations are explicit |

Product contracts are **Jira Data Center**, **Confluence Cloud**, **SharePoint
365**, **Jenkins with Pipeline REST**, **GitHub**, and **SonarQube**. Use their
REST adapters; GitHub also permits reviewed `gh` operations, and local git is a
separate brokered command capability. Reuse authentication mechanisms that are
actually supported; do not silently claim every enterprise SSO mode works.
Pin supported server/API versions during implementation using official docs.

Jira/Confluence/SharePoint provide relevant issue and documentation context, not
an excuse to collect every page. Sonar facts must identify the analysis and its
conditions, not a project-wide latest gate. Publication evidence distinguishes
upload, metadata and verification outcomes even before a JFrog adapter exists.

### Plan #33 — Run durable watches and guarded landing workflows

| Task | Deliverable | Proof required |
| --- | --- | --- |
| #133 | Durable workflow state and effect reconciliation | Restart at each effect boundary never blindly repeats push/merge; uncertain outcomes stop or reconcile |
| #134 | Model-free correlated polling | 100 unchanged polls make zero inference calls and no duplicate notifications; cancel/revoke/deadline work |
| #135 | Project-aware landing and post-merge checks | Exact revision gates, current-head recheck, remote reconciliation, main-commit verification and bounds-proven local sync prevent false success; the complete recipe runs end to end against fixtures |
| #122 | Recovery checkpoint | DONE 2026-09-12: failure/restart matrix covers push, PR, merge and sync intents (prepared-then-crashed, effect landed, effect never landed, base moved), watch parking across restart, cancel/expiry/revocation; sync reconciliation after a landed effect required accepting the merge commit as the base ref in the live check |

Use each repository's existing validation/landing recipe where available. Persist
recipe version/digest, scoped targets, evidence references, deadlines, remaining
budgets, phase and effect-intent receipts. Resume reconciles reality before acting;
remote exactly-once execution is not assumed. Checkpoint/durable result retrieval
must work after a CLI disconnect or a missed transient event.

Local git, lint, test, build and tag-policy checks can fail independently. Jenkins,
GitHub checks and Sonar can also fail or remain unknown. A request to land must
never infer success from retrieval success, absence of a failure message, cancelled
checks, or a later successful cleanup step. Cleanup follows confirmed merge and
must preserve user changes; releases and artifact publishing remain separate.

### Plan #34 — Qualify local investigation on a 32 GB workstation

| Task | Deliverable | Proof required |
| --- | --- | --- |
| #136 | Frozen incident corpus and deterministic baseline | Adjudicated ground truth, real ambiguity, independent held-out families and measured total costs |
| #137 | Exact 9–14 GB artifact screen | Pinned artifact/backend/template, measured cold/warm working set and realistic concurrent workload |
| #138 | Measured runtime admission | Framed tokens, output reserve, current memory, bounded queues and responsive prefill cancellation |
| #139 | Structured advisory diagnosis and scoped reads | Invalid/hostile/unsupported claims fail safely; quotes, target membership and run-wide budgets enforced |
| #140 | Microsoft compression qualification | DONE 2026-09-12: held-out retention proven and restricted per class; sequence measured against deterministic-only; decision recorded (default off, enablement blocked on the citation-offset contract) |
| #108 | Paired end-to-end qualification | Published acceptance report, per-product coverage/errors/abstention/resources and realized frontier savings. Status 2026-09-12: targets confirmed as gates; accuracy-first candidate screen (candle: 14B 82%/9 FP, 32B 84%/8 FP, 30B-A3B 74%/8 FP, Qwen3-Coder-30B-A3B 84.7%/7 FP; llama.cpp engine, Metal: coder 85.3%/7 FP at warm p95 671 ms, gpt-oss-20b 86.7%/3 FP at 574 ms — docs/benchmarks/2026-09-13-llama-engine-screen; 2026 candidates Qwen3.8-27B 89.3%/9 FP, Qwen3.6-35B-A3B 88%/12 FP, gemma-4-26B-A4B 79.3%/2 FP at coverage 0.754, GLM-4.7-Flash 82%/13 FP, Devstral-Small-2-24B 89.3%/8 FP with 4 on decidable triage — docs/benchmarks/2026-09-14-engine-candidate-screen; gpt-oss-20b stays the reference) shows the false-pass set is stable across artifacts, so the gates must be measured on the product contract and the ambiguous trap cases reworded before any artifact can pass (docs/benchmarks/2026-09-12-candidate-accuracy). Status 2026-09-15: answer contract v2 (host-parsed exit facts, every-stage trap question, first-word answer parsing, 160-token cap, 16-token engine floor) — gpt-oss-20b 98.0%/0 FP/0 FA/0 over-abstentions at warm p95 593 ms, three missing answers remain (docs/benchmarks/2026-09-15-answer-contract-v2); the gates are met on this host under the product contract |
| #96 | Artifact/task/backend eligibility | DONE 2026-09-15: `pam_model::qualification` binds digest + engine tag + target + contract + gates + record; `defaults.set` and `resolve` refuse unverified/unqualified; unqualified defaults stay configured and visible, Try still works; only gpt-oss-20b on macos-arm64 qualifies |
| #123 | Qualification checkpoint | DONE 2026-09-15: [model-qualification-decisions.md](model-qualification-decisions.md) records the one qualified envelope (gpt-oss-20b-MXFP4 on b10938/macos-arm64 under contract v2), the no-go for every screened candidate, the not-measured targets and corpus, and the compression default-off/removed decision; the compiled-in table enforces it |

Follow the [admission specification](specs/2026-09-10-model-admission-and-qualification.md)
and [prompt specification](specs/2026-09-09-local-model-prompts.md) verbatim for
measurement definitions; the standing dispositions are in
[model qualification decisions](model-qualification-decisions.md). Initial 60-case screening may reject a candidate;
qualification uses the documented 500 ordinary plus 100 hostile held-out cases,
at least 300 correct accepted ordinary results, zero materially wrong accepted
results, and zero authority/status violations. Include abstention and per-product
coverage so a model cannot pass by answering almost nothing. Zero observed errors
is not proof of zero risk.

The three arms are deterministic broker/reduction, local investigation, and local
investigation plus compression. Proposed benefit gate: at least 30% lower total
frontier tokens through correct resolution, counting corrections and extra reads.
Resource targets remain incremental peak PAM working set ≤16 GiB, p95 warm/cold
local inference ≤15/30 seconds, normal pressure with no sustained added swapouts,
and <5% slowdown of a fixed developer workload. Measure end-to-end compression
and residency overhead too. A capped 64 GB test host is useful but cannot be
reported as a measured 32 GB host. No private evidence goes to an external provider or vendor CLI
without explicit export authorization.

The old dependency cycle is removed: corpus/artifact/resource work can proceed
before eligibility promotion, and qualification does not wait for Home polish.
Artifact attribution #100 must pass before screening #137 and qualification #108.
Compressor-only timing may start early; closing #140 requires the admitted
runtime #138 and structured investigator #139 to measure the complete sequence.
If no model qualifies, publish the no-go evidence and retain the deterministic
product. Closing blocked #96 in that case needs a documented product decision,
not an unauthorized force-close or a lower arbitrary weight floor.

### Plan #35 — Deliver actionable handoffs and truthful operator readiness

| Task | Deliverable | Proof required |
| --- | --- | --- |
| #100 | Correct model diagnostics and attribution | Requested artifact is actually used and reported, including concurrent activity; diagnostic success is not qualification |
| #104 | Actionable escalation and cost accounting | Target, status, citations, missing evidence and next permitted action reach the agent; actual total spend is measured |
| #105 | Honest model/operator readiness | DONE 2026-09-15: the daemon computes one readiness record per tier (`pam_daemon::model_readiness`: configured → installed → verified → qualified → engine → ready, first failing rung with the job's own refusal cause and a recovery line; residency reported beside it, never as a rung) in `admin.models.status`; the Models runtime tab, the Settings tier selects, Home's rephrase line and the log-compression form all read that record and name the one repair; compression is stated off |
| #106 | Task-first entry points | DONE 2026-09-12: Home leads with starter task cards and a start_task Ask intent that deep-link to a flow's run overview; the run tab checks readiness through admin.flows.inspect and shows blockers with a destination; no model needed. Resume by ticket stays the Run history tab and `pam wait <ticket>` |
| #124 | Usability checkpoint | DONE 2026-09-15: CLI-only agent path verified live on a scratch daemon with the real models and engine — flow inspect named blockers with recovery, flow run/wait/result returned the bounded handoff, evidence read followed next_action verbatim, the qualified model summarized a real build failure honestly, and clearing the default produced an explicit model_skipped observation on the deterministic path; live admission refusals and GUI readiness on real replies; residuals filed as issues #29 (model identity absent from the agent result) and #30 (flow.inspect ignores readiness) |

#100 is a diagnostic correctness repair, not a conversational feature. #104
provides measurement for #108. Model readiness can show an explicit unqualified
state; absence of a successful candidate must not obscure ordinary broker work.

## Delivery sequence and completion

1. Complete #125–#127 and #103: trustworthy access plus retrievable evidence.
2. Establish #128–#132 and #104: exact product facts and useful handoff.
3. Deliver #133–#135: watches and landing with deterministic recovery. DONE.
4. Plan 36 (2026-09-13): run local inference on the llama.cpp release binaries — acquisition, supervisor, routing, requalification, GUI/CLI readiness. DONE; spec: docs/specs/2026-09-13-llama-cpp-engine.md.
4. In parallel after evidence exists, fix diagnostic attribution #100, run
   #136–#140 in dependency order, then #108 and #96.
5. Complete operator integration and each workstream checkpoint. #94 verifies
   the complete target workflow and the final qualification/no-go disposition.

No plan creates a new transport, GUI framework, connector framework, or chatbot.
Backend memory work is justified by measurements, not undertaken speculatively.
Do not add a hosted fallback to make a qualification graph turn green.

At each checkpoint, record what calls the implementation now, exact tests and
artifact/fixture versions, residual gaps, and measured user/agent benefit. A new
module or a passing prompt parser alone does not complete an integration task.
Use ptrack notes for decisions and task links for dependencies; update the rolling
summary for the next session. This planning change neither implements the queued
features nor authorizes a push, merge, release, or production rollout.


### Task 133: restart-safe flow continuation

[Workflow recovery](workflow-recovery.md) documents private bounded checkpoints,
intent-before-step ordering, durable budgets, retained ticket/deadline and
fail-closed uncertain effects. Ordinary failed stateful commands execute once;
completed step prefixes restore under current access checks. Task 134 adds
[durable job polling](job-watches.md); product-specific remote-effect
reconciliation remains task 135, not a generic retry.

### Task 134: exact remote-job watches

The existing flow runtime now calls cheap GitHub run-attempt, Jenkins build and
Sonar compute-task status operations. Pending watches commit bounded progress
and park outside ready repository lanes while retaining their ticket, expiry,
authority and cumulative budget. Only terminal observations trigger the full
collector. Unchanged observations produce no duplicate watch-change notification
and polling makes no inference calls. Exact pins, separate bounded GitHub job
membership, outage limits and terminal-collection headroom prevent latest-result
substitution and unbounded waiting. The [watch contract](job-watches.md) records
CLI usage, limits and the legacy membership recovery refusal. Local fixtures do
not claim live product compatibility or model qualification. Guarded landing
and publication remain separate work.
