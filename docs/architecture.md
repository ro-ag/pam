# Architecture

## Shape

PAM is distributed as one application artifact. Subcommands select a mode, but
all modes share the same versioned domain types and policy engine.

```mermaid
flowchart LR
  H["Human"] --> G["pam gui\nGPUI control center"]
  A["Coding agent"] --> C["pam client\ndefault mode"]
  G --> T["Local transport"]
  C --> T
  X["Approved local apps"] --> O["Authenticated\nOpenAI-compatible API"]
  O --> D
  T --> D["pam daemon"]
  D --> Q["Per-project scheduler"]
  Q --> S["SQLite state +\nevidence index"]
  Q --> P["Policy + approvals"]
  Q --> F["Flow engine"]
  Q --> M["Model runtime adapter\nllama.cpp"]
  Q --> K["Capability adapters"]
  K --> R["Git / GitHub / Jira /\nConfluence / Jenkins / Sonar"]
  P --> OS["OS credential store +\ncertificate trust"]
  M --> W["User-owned GGUF weights"]
  S --> B["Content-addressed\nevidence blobs"]
```

The GUI is a client of the same daemon protocol as the CLI. It may start and
stop the daemon, but it does not gain a private path around policy or durable
state.

## Runtime modes

| Invocation | Responsibility |
| --- | --- |
| `pam …` | Fast client; discovers project and caller, submits requests, streams events, and prints compact results. |
| `pam daemon` | Owns queues, durable state, connectors, policy, model runtime, and local APIs. |
| `pam gui` | Native control center for daemon lifecycle, project queues, flows, models, access, certificates, and evidence. |

If the client cannot reach the daemon, it should provide an exact recovery
action. Automatic daemon start may be offered only when policy and installation
mode allow it.

## Identity and queueing

Caller identity and project identity are separate.

- A **caller** is a registered CLI session, coding-agent integration, GUI, or
  approved local application. It receives a revocable credential and declared
  capabilities.
- A **project** is resolved from explicit input, a `.pam/project.toml` marker,
  or a normalized repository root. Its stable ID must not depend only on a path
  that can move.
- A **request** carries protocol version, request ID, caller ID, project ID,
  capability, idempotency key, deadline, and payload.

Each project has one durable ordered queue. The scheduler serializes stateful or
conflicting operations. A flow can declare read-only collection steps safe for
parallel execution, but their results rejoin the ordered project event stream.
Global resources such as the model runtime have separate capacity controls so a
large inference request cannot starve every project.

## Protocol and transport

The application protocol is transport-neutral and versioned independently from
the binary. The first transport adapter uses ZeroMQ Router/Dealer semantics:

| Platform | First transport | Planned hardening |
| --- | --- | --- |
| macOS | Unix-domain IPC endpoint in the user runtime directory | launchd integration and signed peer registration |
| Linux | Unix-domain IPC endpoint | systemd user service and peer credential checks |
| Windows | authenticated loopback TCP | native named-pipe adapter after protocol stabilization |

ZeroMQ availability is a build/runtime implementation detail, never exposed in
the command contract. Message envelopes use Serde with a compact binary encoding
and an explicit maximum frame size. Large logs and artifacts are stored once and
referenced by content hash instead of traveling through IPC frames.

The daemon publishes a replayable event sequence per request. Reconnect uses a
request ID and last observed sequence number; it does not restart the work.

## Durable state

SQLite in WAL mode stores metadata, queues, leases, flow definitions and runs,
policy decisions, audit events, model registrations, and evidence references.
A dedicated database worker owns the connection behavior rather than allowing
unbounded blocking work on async executors.

Potentially large or sensitive evidence lives in a content-addressed blob
directory with checksums, size/type metadata, project ownership, retention, and
redaction state. A compact result stores references into this evidence graph.
Deletion and retention are explicit operations with audit events.

PAM integrates with `ptrack` through its supported command or future protocol.
It does not read or mutate `ptrack`'s database schema directly.

## Evidence pipeline

```mermaid
flowchart LR
  I["Raw logs / tool output"] --> N["Normalize encoding\nand strip terminal noise"]
  N --> D["Deduplicate repeats\nand collapse progress"]
  D --> W["Retain failure windows,\nboundaries, status, metadata"]
  W --> E["Store exact evidence\nwith checksums"]
  W --> L["Optional local semantic\ncompression"]
  E --> R["Compact result +\nevidence handles"]
  L --> R
```

Deterministic reduction always runs first. Model compression is optional,
policy-controlled, and never replaces the exact retained source. Every model
claim must cite an evidence handle or be labeled as an inference.

## Flow execution

A flow definition is data, not arbitrary daemon code. Initial step types are:

- run an allowlisted local command in a declared working directory;
- call a registered connector capability;
- transform or compact evidence;
- evaluate a condition over structured output;
- request human approval;
- emit a result or handoff.

The engine records a state transition before and after each externally visible
effect. Idempotency keys protect retries. Destructive, publishing, merging, or
ticket-mutating steps require policy evaluation at the point of effect, even if
the flow itself was previously approved.

## Security boundaries

1. **Caller boundary:** local reachability is not identity. Callers register and
   authenticate; credentials are revocable and never written to flow files.
2. **Project boundary:** evidence and policy are scoped to a stable project ID.
   Cross-project reads require a separate grant.
3. **Capability boundary:** connectors expose typed operations rather than raw
   secrets or a universal shell.
4. **Approval boundary:** PAM displays the exact effect, target, and evidence
   before a sensitive action.
5. **Network boundary:** connectors honor operating-system trust, corporate CAs,
   proxies, explicit destinations, and project egress policy.
6. **Model boundary:** untrusted prompts and tool output cannot authorize
   capabilities. Model output is data until validated by the engine.

Local API listeners bind only to loopback, require authentication, redact
secrets from logs, impose body/concurrency limits, and are disabled until the
user explicitly enables them.

## Portability rules

- Platform paths, IPC, credential stores, service managers, code signing, and
  hardware acceleration live behind interfaces with contract tests.
- Core queue, protocol, flow, policy, compaction, and evidence crates contain no
  platform UI or service-manager code.
- macOS may ship first, but portable tests run on Linux from the start.
- Windows-specific implementation begins only after protocol and path semantics
  are explicit; callers never assemble Unix-only paths.
