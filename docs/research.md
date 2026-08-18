# Research synthesis

Research date: 2026-08-18

Method: review of official product documentation, current project sources, and
public issue reports; community discussions are supporting anecdotes only.

The public-source baseline and the still-empty field-research record are kept
in the [managed-environment research synthesis](managed-environment-interviews/synthesis.md).
Its status is **recruitment not started**: none of the public authors cited
there are treated as interview participants or observation sessions.

## Executive synthesis

The strongest opportunity is not another chat interface. Corporate developers
and their agents need a durable local control layer between a short-lived model
context and a fragmented, permission-heavy toolchain. Public reports show
recurring context loss after compaction, sandbox friction around filesystem and
credential access, and diagnostic evidence that is either too large or too
thin. PAM can reduce both risk and token spend by preserving an ordered project
record, brokering narrow capabilities, compacting evidence locally, and stating
outcomes precisely. The GUI should therefore behave like a calm operations
desk, not a model playground: current project, daemon/model health, active flow,
approval boundary, solved result, and exact evidence should be visible at a
glance. The stack should optimize for one local binary and native Mac quality
while hiding platform-specific transport, trust-store, and model-runtime details
behind small interfaces.

## Ranked user problems

| Rank | Problem | Severity | Frequency | Confidence | Product move |
| ---: | --- | --- | --- | --- | --- |
| 1 | Agents lose goals, decisions, rules, and task state after restart or context compaction. | Critical | Frequent | High | `pam brief`, durable project ledger, evidence provenance, `ptrack` adapter, handoff/result contracts. |
| 2 | Strong sandboxes block useful work or tempt teams to expose broad credentials and host access. | Critical | Frequent in managed environments | High | Authenticated caller identity, capability grants, project policy, approval gates, brokered connector calls. |
| 3 | CI and build logs are too noisy for economical model input, yet summaries can omit the line that proves the failure. | High | Frequent | High | Deterministic log compaction first, exact evidence handles, optional local semantic compression second. |
| 4 | Work is split across Git, CI, SonarQube, Jira, Confluence, certificates, and local commands. | High | Daily | High | Per-project queue, connectors behind one protocol, named flows, unified outcome report. |
| 5 | Automation reports activity instead of outcomes, leaving users unsure what was fixed or verified. | High | Frequent | Medium-high | Durable state machine and explicit solved/changed/verified/unresolved/blocked fields. |
| 6 | Local models are difficult to acquire, size, run, and share safely on developer hardware. | Medium-high | Occasional setup, continuous use | High | Model catalog/import, memory estimate, `llama.cpp` adapter, user-owned paths, authenticated compatible API. |
| 7 | Context switching creates mental fatigue and makes repeated operational sequences error-prone. | Medium-high | Daily | Medium-high | GUI flow builder, event timeline, resumable runs, reusable policies and evidence packs. |

## Managed-environment public observations

Fresh public reports add specificity to the managed-Mac problem without
closing the validation gap:

- Codex users describe active work becoming invisible or impossible to resume
  across restarts and authentication events. This strengthens the continuity
  hypothesis, but does not establish how often it affects corporate developers.
- Corporate proxy reports show that a CA trusted by macOS may still be absent
  from Node.js, Python, Java, or other tool-specific trust stores.
- Platform SSO documentation and administrator reports show that local
  password, FileVault, IdP, VPN, token freshness, and offline policy form an
  authentication chain rather than one login state.
- Standard-user deployments can move administrator prompts from installation
  into later helper-tool updates or integrations, while MDM can make some
  capabilities unavailable by policy.
- Internal-tool access and visible agent activity do not by themselves prove
  identity propagation, causal history, or a verified result.

These are reported observations, public discussions, and documented platform
capabilities—not interviews. Their direct citations, evidence classes,
counterevidence rules, and provisional product implications are maintained in
the [living study report](managed-environment-interviews/synthesis.md).

## Evidence map

### Context continuity

- Anthropic users report critical working knowledge being lost during context
  compaction: [issue 29890](https://github.com/anthropics/claude-code/issues/29890).
- Team and subagent state can be lost after the coordinating context is
  compacted: [issue 23620](https://github.com/anthropics/claude-code/issues/23620)
  and [issue 23821](https://github.com/anthropics/claude-code/issues/23821).
- OpenAI Codex users report project rules and task progress being forgotten
  after compaction: [issue 25792](https://github.com/openai/codex/issues/25792).

These are public issue reports rather than controlled research, but the pattern
is consistent across products. PAM should persist a small verified project
record outside any one model context.

### Sandbox and authority

- VS Code's agent documentation describes sandboxing as restricting filesystem
  and network access while retaining user control: [Trust and
  safety](https://code.visualstudio.com/docs/agents/concepts/trust-and-safety).
- Anthropic users have raised concerns that tool execution and environment
  credentials need stronger isolation: [issue
  26616](https://github.com/anthropics/claude-code/issues/26616).
- Codex users report that sandbox boundaries can block required local resources:
  [issue 15625](https://github.com/openai/codex/issues/15625).

The product inference is that PAM should bridge capabilities, not weaken the
sandbox: a caller proves identity, asks for a named capability, and receives a
scoped result rather than the credential itself.

### Diagnostic volume and fragmentation

- Jenkins plugin users report cases where available error information is too
  thin to explain the failure: [explain-error-plugin issue
  116](https://github.com/jenkinsci/explain-error-plugin/issues/116).
- Grafana community users describe CI build logs as high-volume operational
  data: [Loki discussion](https://community.grafana.com/t/best-practice-for-storing-ci-build-logs-in-loki/65229).
- Atlassian summarizes the productivity cost of frequent context switching:
  [Context switching](https://www.atlassian.com/work-management/project-management/context-switching).

PAM must solve the tension between too much and too little evidence. It should
remove ANSI escapes, repeated lines, progress animation, and known boilerplate;
retain boundaries, error neighborhoods, exit status, and checksums; and make the
original source available by handle.

## Technical findings

- [GPUI](https://github.com/zed-industries/zed/tree/main/crates/gpui) is the
  native GPU UI framework used by Zed. Its current manifest reports version
  0.2.2 and cross-platform feature support. It offers the closest fit to the
  requested Zed-like native stack, but its public API is younger than the
  editor, so PAM should pin versions and isolate the UI crate.
- [zeromq 0.6](https://docs.rs/crate/zeromq/latest) is a Tokio-based native Rust
  implementation with Router/Dealer and Unix IPC support. It avoids a system
  `libzmq` dependency, but does not claim complete ZeroMQ compatibility; PAM
  needs protocol tests and a transport fallback.
- [rusqlite](https://docs.rs/crate/rusqlite/latest) provides a compact embedded
  state store and can bundle SQLite, reducing platform drift.
- [rustls-platform-verifier](https://docs.rs/rustls-platform-verifier/latest/rustls_platform_verifier/)
  uses platform certificate facilities on macOS and Windows and supports
  system-local roots, which matters for corporate CAs and proxies.
- [llama.cpp](https://github.com/ggml-org/llama.cpp) provides Apple Silicon
  Metal acceleration and GGUF support. The current
  [llama-cpp-4](https://docs.rs/llama-cpp-4/latest/llama_cpp_4/) bindings expose
  Metal and server/chat examples, but are new enough to require a measured
  integration spike before adoption.
- [LLMLingua](https://github.com/microsoft/LLMLingua) is Microsoft's prompt
  compression project. It is optional inspiration or an external compression
  stage, not the foundation of PAM's loss-aware log reduction.
- [Qwen3.6-35B-A3B](https://github.com/QwenLM/Qwen3.6) is a current open MoE
  coding/agent model with 35B total and 3B active parameters. Quantized GGUF
  variants are candidates for an M1 Mac with 32 GB RAM, but PAM should benchmark
  memory, context size, and tokens per second rather than hard-code one model.

## Opportunity map

### Prove this week

- A single project record can survive a new agent session and produce a useful
  `pam brief` in a small response.
- A log reducer can remove repetition while every retained conclusion points to
  exact source bytes.
- GPUI can deliver a credible daemon/queue/approval shell on the minimum macOS
  version.
- Embedded `llama.cpp` can load one candidate GGUF within a safe memory budget
  on the target M1/32 GB machine.

### Build this quarter

- Authenticated daemon protocol, durable queues, cancellation, and event replay.
- First end-to-end GitHub Actions diagnostic flow.
- Policy, approvals, operating-system secrets, and enterprise certificate
  handling.
- GUI flow builder and versioned `.pam/flows/` schema.
- Model acquisition/import, integrity verification, and compatible local API.

### Deeper bets

- Jira, Confluence, Jenkins, and SonarQube capability packs.
- Team-exportable evidence packs with automatic secret redaction.
- Linux and Windows native transports and packaging.
- Outcome-based caching that lets multiple agents reuse verified work safely.

## Research risks

Public issue trackers overrepresent failure cases, and community discussions are
not population-level evidence. Recruitment has not started. Before broad
implementation, interview five to eight developers in managed environments and
observe one real CI diagnosis and one approval-heavy task. Validate willingness
to run a daemon, acceptable audit retention, company policy around local
models, and whether the primary control surface should emphasize queues, flows,
or access policy. Until those sessions meet the study's explicit completion
gate, the managed-environment findings remain provisional.
