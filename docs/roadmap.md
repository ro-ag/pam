# Roadmap

The roadmap is organized around user-visible proof, not subsystem completion.
`ptrack` is the live task ledger; this document is the stable product view.

## Milestone 1 — macOS developer preview

### 0. Product foundation

Deliverables:

- product goal, principles, research, architecture, stack decisions, and UI
  direction;
- public repository, durable `ptrack` context, and cheap main-branch CI;
- documented open decisions and technical spikes.

Exit: a new contributor can explain the user, first vertical slice, security
boundary, and why each foundational technology was chosen.

### 1. Walking skeleton

Deliverables:

- minimal Rust workspace and command contract for client/daemon/GUI modes;
- versioned request/result/event types;
- daemon lifecycle and health check;
- one in-memory project queue before persistence is introduced;
- Linux portable tests and a Mac developer build.

Exit: `pam status` reaches a daemon and returns a structured versioned result.

### 2. Durable project continuity

Deliverables:

- stable caller/project IDs and repository discovery;
- SQLite migrations, per-project queue, leases, cancellation, and replay;
- evidence store and deterministic log compactor;
- `pam brief`, `pam wait`, `pam result`, and evidence inspection;
- supported `ptrack` adapter.

Exit: accepted work survives a daemon restart and a fresh agent can resume from
a compact, provenance-backed brief.

### 3. Trust and policy

Deliverables:

- caller registration/revocation and authenticated local protocol;
- capability grants and project policies;
- approval request/result lifecycle;
- native secrets, enterprise CA/proxy behavior, and redaction tests;
- audit export and retention controls.

Exit: a sandboxed caller can perform one approved capability without receiving
the underlying credential or cross-project evidence.

### 4. Local intelligence

Deliverables:

- llama.cpp binding spike and recorded decision;
- model import/download, integrity, licensing, memory estimate, and chosen paths;
- one Qwen-capable profile proven on the M1/32 GB target;
- bounded inference queue and optional semantic evidence compression;
- authenticated local compatible API if it passes the preview scope gate.

Exit: PAM can compact a retained diagnostic evidence set locally within a safe
memory budget and another approved app can use the model without direct weight
or credential management.

### 5. Flows and useful feedback

Deliverables:

- versioned flow schema, validator, runner, conditions, retries, and approvals;
- `pam flow run/list/show/validate/cancel/logs/wait/result`;
- durable meaningful events and explicit outcome contract;
- GUI flow editor with dry run and version diff;
- one after-merge validation flow.

Exit: a developer can create a flow, run it after a merge, see only meaningful
progress, and hand its compact verified result to an agent.

### 6. Native control center

Deliverables:

- approved Project Current direction and Baywatch visual tokens translated to
  GPUI;
- daemon start/stop and health;
- project switcher, queue, active run, approval, and solved-result views;
- models, access, certificates, configuration, and evidence surfaces;
- keyboard navigation, accessibility review, failure/recovery states;
- signed developer preview packaging.

Exit: the primary daemon/flow/approval loop works without the terminal and the
UI never bypasses the shared protocol or policy engine.

### 7. First corporate connector

Deliverables:

- typed connector SDK and test harness;
- GitHub Actions run discovery, log collection, diagnosis, and evidence links;
- one safe remediation or rerun action behind explicit approval;
- rate-limit, timeout, certificate, and partial-data behavior.

Exit: PAM diagnoses a real failing GitHub Actions run, compacts the evidence,
and reports solved/verified/unresolved state end to end.

## Milestone 2 — corporate tool belt

- Git and working-tree troubleshooting pack.
- SonarQube quality-gate evidence and remediation guidance.
- Jenkins diagnosis with bounded log retrieval.
- Jira read/update capabilities and post-merge validation flows.
- Confluence read, diagram conversion, and controlled documentation updates.
- Reusable evidence packs and connector health diagnostics.

Every connector begins read-only. Mutations ship only with scoped capability,
preview, approval, idempotency, and verification.

## Milestone 3 — portable companion

- Linux user service, Secret Service/keyring behavior, Unix IPC, and packaging.
- Windows service lifecycle, Credential Manager, path semantics, and named-pipe
  transport.
- Cross-platform migration/recovery, protocol compatibility, and upgrade tests.
- Hardware/runtime profiles beyond Apple Metal.

## Immediate decision tasks

- Set the minimum supported macOS release.
- Validate GPUI accessibility and packaging constraints.
- Complete the llama.cpp binding benchmark.
- Define the first flow schema and protocol golden fixture.
- Recruit five to eight managed-environment developers for workflow interviews.

## Definition of done for every slice

- The user-visible outcome and failure states are documented.
- Relevant local format, lint, unit, contract, and integration checks pass.
- A sensitive effect has policy, approval, idempotency, and an audit event.
- Compact output links back to exact retained evidence.
- `ptrack` tasks and decision notes reflect the current state.
- Documentation changes with the behavior; no release occurs without a separate
  explicit request.
