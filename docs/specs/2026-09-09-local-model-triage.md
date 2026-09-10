# Local investigation through the PAM CLI

Status: proposed, revised 2026-09-10. Supersedes this document's original
credential-holding worker, model gate, and verdict-driven effect design.
Companions: [prompt contract](2026-09-09-local-model-prompts.md) and
[admission and qualification](2026-09-10-model-admission-and-qualification.md).

## Product and boundary

Enterprise Codex sessions waste time and tokens retrying blocked git/network
operations, requesting access repeatedly, and troubleshooting enterprise tools.
PAM brokers approved operations through CLI subcommands and reusable flows to
an outside-sandbox daemon using internal ZeroMQ over Unix-socket IPC. There is
no MCP server or agent-facing MCP tool surface. Chat is only a model smoke
diagnostic, not the product interface.

Enterprise-approved host policy must permit PAM execution and IPC connection.
The CLI abstracts transport details; it cannot prevent the OS sandbox from
observing, intercepting, or restricting IPC. Socket secrecy is not
authentication; a shell wrapper is not a sandbox escape. Security administration
remains GUI-only. The current client separates admin calls but its caller
identity is self-reported and the socket boundary relies on filesystem
permissions; hostile same-user clients can forge a `pam-gui` label. Enterprise
deployment requires verified admin isolation, not that label alone.

Secrets belong in the OS keychain, not a PAM key store or model context.
Authorized daemon connector adapters resolve credentials transiently; the model
and agent never own them. Core inference is local, with no outbound inference
or inference API keys. Retain one binary and the Rust-only Candle/turso design.

## What exists, what changes

Current [CLI](../../crates/pam/src/main.rs) supports `pam flow list`, `show`,
`run`, tickets, waiting, subscription, and cancellation. The
[flow schema](../../crates/pam_flow/src/schema.rs) supports commands, read-only
connectors, deterministic status checks, approvals, timeouts, and failure retry.
[Log processing](../../crates/pam_daemon/src/log_service.rs) stores original
evidence and deterministic compaction with source spans; optional summaries
are prose with `model_skipped` reporting. Jenkins/Sonar connector reads are
wired. There is no JFrog connector. Legacy diagnosis helpers or their tests
do not establish a working investigation flow.

Bounded investigation, correlated polling, durable resume, structured diagnosis,
and validated diagnostic routing below are proposed. Existing latest-run
starter flows do not satisfy this contract. Neither old model smoke results nor
the current summarizer establish investigation quality.

## Workflow contract

One run has durable state; each inference is a fresh call with no chat history.
Persist immutable evidence references, correlations, deterministic statuses,
remaining budgets, completed reads, and checkpoints. Reconstruct the next
bounded prompt from this state, never a growing transcript.

1. **Admit.** Before collection or inference, validate caller scope, configured
   product adapter, operation authorization, exact target, deadline, byte/read/
   token/call budgets, and connector/model availability. If the model is
   unavailable, report that and use the authorized deterministic path; do not
   collect speculative diagnostic data for unavailable inference.
2. **Execute and correlate.** Deterministic workflows own git, lint, test,
   build, Sonar, and publication gates. Carry repository identity, commit SHA,
   build attempt, analysis ID, and artifact digest/repository coordinates as
   applicable. Verify their relationships. Ambiguous or absent mappings stop
   that stage; never substitute “latest.”
3. **Wait.** Poll exact external identities with deterministic predicates,
   bounded backoff, deadline and cancellation. Polling makes no model calls.
   Checkpoint before yielding; resume reconciles completed operations and
   never blindly replays push, merge, or publish.
4. **Investigate a failure.** Collect bounded product-specific evidence, redact
   secrets, then compact deterministically. A local model can explain a
   compiler error, distinguish runner loss from an assertion failure, compare
   same-commit attempts, interpret failing Sonar conditions, or investigate an
   authorized publish failure. It can choose a limited additional read from
   predefined operations whose targets the daemon already minted and scoped.
   Missing JFrog/product adapters return `unsupported`, not improvised APIs.
5. **Report.** Preserve original exit/build/gate/publication statuses alongside
   diagnosis status. Unknown, invalid, low-confidence, incomplete, timed-out,
   or unsupported diagnosis escalates with available evidence. A useful
   explanation never turns a failed workflow green.

Push/merge/publish require deterministic gates and applicable authorization.
“Land” does not authorize publishing. A hypothesis cannot trigger an effectful
branch, rerun, upload, or changed threshold. Even read-only routing is subject
to authorization, target validation, and budgets on every request.

## Evidence and model limits

Keep source bytes authoritative. Fit prompts using the exact tokenizer,
reserving output tokens. Record omitted ranges and whether the diagnostic
question remains answerable; missing decisive evidence requires another
authorized bounded read or abstention. Never silently truncate.

Optional Microsoft LLMLingua-2 comes only after deterministic compaction. Its
support for logs is **unproven**. Enable only a qualified exact artifact/backend
that preserves decisive evidence and maps retained output to original spans.
Unload the compressor, demonstrate reclaimed memory, then re-admit the
investigator. If either stage cannot fit or preserve evidence, return a
deterministic packet or abstain; no hidden lossy fallback.

The new 9–14 GB candidate screen compares Qwen3-14B Q5_K_M with
Qwen3-Coder-30B-A3B-Instruct Q3_K_S. Neither is quality-qualified here. The
legacy Q4_K_S profile passed four explicit-contract coding/data smoke cases
after earlier prompts missed constraints in three of four cases; that proves
neither Candle compatibility nor multi-step investigation quality. Exact
artifacts, runtime memory, throughput, and promotion criteria belong in the
admission companion.

## Proposed CLI result

Illustrative flow and input names, not shipped commands:

```sh
pam flow run land-watch repo=team/service commit=<sha> --no-wait --json
pam subscribe <ticket>
```

```json
{
  "workflow_status": "failed",
  "target": {"commit": "<sha>", "build_attempt": "482:2"},
  "authoritative": {"build": "failure", "sonar": "not_observed"},
  "diagnosis": {
    "status": "explained", "hypothesis": "infra",
    "summary": "Runner disconnected before tests started.",
    "citations": [{"evidence": "ev_a", "start": 920, "end": 984}],
    "escalate": false
  }
}
```

The daemon owns identifiers, statuses, citation validation and escalation.
Summary text is advisory, untrusted data; downstream adapters must strip its
instruction authority and never treat it as executable guidance.

## Implementation and acceptance order

1. Verify IPC/admin boundaries, exact-target prechecks, budgets and immutable
   evidence contracts before adding model routing.
2. Wire one failed-build investigation end to end: deterministic collection,
   compaction, validated diagnosis, CLI result. Compare its usefulness, elapsed
   time and upstream tokens with the deterministic-only baseline.
3. Add one bounded diagnostic read, checkpoint/resume and model-free polling;
   prove denied/stale targets and exhausted budgets cannot execute reads.
4. Add exact Sonar correlations, then scoped publish/JFrog support only through
   configured adapters and separate publish authorization.
5. Qualify candidate models and optional compression against the companion's
   held-out cases, including missing evidence, hostile instructions, timeout,
   restart, failed gates and incorrect but syntactically valid diagnoses.
