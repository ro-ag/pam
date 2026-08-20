# PAM product brief

Status: product foundation

Primary platform: macOS on Apple Silicon

Secondary constraints: Linux and Windows

## Main goal

Build PAM as the trusted local companion that gives developers and AI agents
durable project continuity, compact evidence, safe access to corporate tools,
and verified automated flows.

Success means an agent can enter an unfamiliar or heavily sandboxed corporate
workspace, ask PAM for a concise project brief, run an approved operation, and
receive a durable answer that clearly separates what PAM observed, what it
solved, what it changed, how it verified the result, and what still needs a
human.

## Who it serves

The primary user is a professional developer using one or more coding agents on
a company-managed Mac. Their work spans local repositories, GitHub or Jenkins,
SonarQube, Jira, Confluence, internal certificates, and access policies. They
care about speed, but cannot trade away auditability, secret safety, or the
ability to understand what ran.

The second user is the coding agent. It has no reliable persistent memory and
may be confined to a strong sandbox. It needs a small, stable local interface
for approved capabilities and evidence without gaining ambient authority.

Platform and security teams are stakeholders. They need clear policy, revocable
access, audit records, and a product that can operate without an unapproved
hosted control plane.

## Core jobs

1. **Resume safely.** Give a fresh agent the current goal, decisions, active
   work, blockers, and recent verified outcomes for one project.
2. **Diagnose cheaply.** Collect local and remote evidence, reduce repetitive
   logs deterministically, and return the smallest useful explanation with
   links or handles to exact source material.
3. **Act with boundaries.** Broker only the requested capability, apply project
   policy, request approval at the meaningful boundary, and avoid exposing raw
   credentials.
4. **Run a repeatable flow.** Execute a named sequence with conditions,
   approvals, retries, and durable feedback.
5. **Report the truth.** Communicate solved, changed, verified, unresolved, and
   blocked states without pretending an attempted action succeeded.

## Product principles

- **Evidence before confidence.** Every conclusion should retain provenance.
- **One project, one ordered story.** Project queues serialize conflicting work
  while allowing safe parallel collection where the flow declares it.
- **Authority is explicit and temporary.** Caller identity, project identity,
  capability, and approval are different concepts.
- **Compression is reversible.** PAM preserves the source evidence behind every
  compact answer.
- **Human control stays visible.** The GUI makes daemon state, access grants,
  certificates, queues, flows, and model use understandable.
- **Local is the default, not a slogan.** No model weights are bundled and no
  remote service is required for the core loop.
- **Personality serves clarity.** PAM is calm, direct, protective, and honest;
  it is never flirtatious at the cost of operational trust.

## First delivery: macOS developer preview

The first usable slice proves the complete local loop on an M1-class Mac with
32 GB RAM:

- one signed development binary with client, daemon, and GUI entry points;
- project discovery and a durable SQLite-backed queue;
- authenticated local IPC and caller registration;
- a native Tauri control center that starts or stops the daemon;
- `pam brief`, one diagnostic operation, and one file-defined flow;
- deterministic build-log compaction with source evidence retained;
- import or assisted download of one compatible GGUF model;
- local `llama.cpp` inference behind a runtime adapter;
- compact streamed feedback plus a durable final result;
- policy prompts and secrets held in the operating-system credential store.

The preview may use GitHub Actions as its first remote connector. Jira,
Confluence, Jenkins, and SonarQube follow through the same capability boundary
after the local loop is trustworthy.

## Flows

"Flow" is the product term. A flow is a versioned, inspectable recipe stored in
`.pam/flows/` or a user configuration directory. It may contain commands,
connector calls, conditions, approvals, retries, and compact output contracts.

The user can create and inspect flows in the GUI, then run one with:

```text
pam flow run "after merge checks"
```

A run returns a small final report and durable evidence handles. During the run,
PAM emits meaningful events such as waiting, approval required, evidence found,
fix applied, verification passed, or unresolved. Raw command chatter is not the
product feedback channel.

## Non-goals for the preview

- Shipping or licensing third-party model weights.
- Replacing Jira, Confluence, GitHub, Jenkins, or SonarQube.
- Giving an agent unrestricted shell or credential access.
- Building a hosted orchestration service or team synchronization backend.
- Promising autonomous repair for every failure class.
- Hiding a destructive or externally visible action behind blanket approval.

## Measures

Early validation should track:

- time from request to a useful diagnosis;
- input bytes/tokens avoided by deterministic compaction;
- percentage of reports with resolvable evidence handles;
- repeated work avoided after agent restart or context compaction;
- approval prompts per completed outcome;
- flows completed, partially solved, blocked, or cancelled;
- queue wait time and daemon/model memory footprint;
- connector and certificate failures by platform.

No metric may incentivize suppressing evidence or bypassing policy.
