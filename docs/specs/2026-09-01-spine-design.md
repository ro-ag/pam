# Spine (daemon core) — design

Status: approved by owner (brainstorming session, 2026-09-01)
Umbrella vision: `~/dev/rs/new-map.md` (to be folded into `docs/product-brief.md`)

## Scope

The spine is the daemon skeleton every other subsystem hangs off: transport,
caller identity, policy gate, queue manager, store, audit, and lifecycle.
Out of scope here: model runtime, log compression, flows engine, GUI,
connectors (they plug into spine contracts later).

## Decisions (owner-approved)

- Transport: ZeroMQ over `ipc://` unix domain sockets. JSON payloads.
- The protocol is **internal only**: agents interact exclusively through
  static `pam` subcommands and options; flow names are the only dynamic
  surface. No raw-protocol escape hatch.
- Caller identity is **advisory**: the CLI self-reports invoker (parent
  process chain) and repo (cwd); used for attribution, filtering, and
  audit — not authentication. Filesystem permissions on the runtime dir
  are the security wall.
- Queue serializes **per-repo lanes**; different repos run in parallel.
- Capability grants are **global only** (machine-wide). A `scope` column
  exists for future fine-grain but only holds `global` for now.
- Security administration (grants, approvals, revocations, profile) is
  **GUI-only**. The CLI has no security commands.
- Daemon starts by **lazy auto-start** from any client.
- OS integration is **user-scope only** — systemd user units, macOS
  LaunchAgent, Windows per-user scheduled task. Never sudo/admin/root.
- Connectors are **static**, the same set as pam-old: GitHub (Actions),
  Jenkins, SonarQube, Jira Data Center, Confluence Cloud, SharePoint,
  allowlisted read-only AWS CLI passthrough. Dormant until enabled,
  credentialed (OS keychain), and tested in the GUI.
- Approvals profile: **relaxed / standard / strict**, default by platform
  (macOS → relaxed; Linux/Windows → standard). One policy engine, one
  enum — no per-OS code paths.
- Runtime architecture: **tokio async monolith**; each domain is a
  long-lived task owning its state, communicating over typed mpsc
  channels. Single daemon lib crate first; split crates when boundaries
  settle.

## Deferred (recorded, not built now)

- **Stable project identity fallback**: today `repo` is the normalized
  cwd path. A moved repo therefore starts a fresh activity history.
  Low stakes since repos are filters, not authorities — but when it
  itches, the fix is a small marker file (v1's `.pam/project.toml`
  idea) or a first-commit-hash fingerprint mapping old path → same
  identity. Schema keeps `repo` as plain text so the mapping can be
  introduced without migration pain.

## Wire protocol (internal)

Sockets in `~/.pam/run/` (path length validated at boot; violation is a
legible error naming the 104-byte limit and the offending path):

- `pam.sock` — zmq ROUTER (daemon) serving all commands.
- `events.sock` — zmq PUB broadcasting progress events; no requests.

Request envelope (JSON, versioned; unknown fields ignored):

```json
{
  "v": 1,
  "id": "req_<ulid>",
  "capability": "log.summarize",
  "caller": { "agent": "claude", "repo": "/abs/path", "pid": 4242 },
  "args": { },
  "idempotency_key": "opt-caller-chosen",
  "deadline_ms": 60000,
  "wait": true
}
```

`idempotency_key` (optional): duplicate in-flight detection uses it when
present, falling back to capability+args+repo equality. `deadline_ms`:
every request carries one deadline; the daemon refuses (not hangs) past
it — v1 testkit lesson.

Response is exactly one of:

- `result`  — `{id, outcome: solved|changed|verified|unresolved|blocked, body, evidence: [ev_ids]}`
- `refusal` — `{id, cause, detail, recovery}` — machine cause plus human
  recovery sentence, always both; recovery points at the GUI, never at a
  security command.
- `ticket`  — `{id, ticket, position}` when `wait: false`.

Events (PUB topic = request id): `queued`, `started`,
`progress {pct?, note}`, `approval_pending`, `done`, `refused`.

## Request path

```
pam <cmd> → parse/validate → envelope → pam.sock
  → schema check → policy gate → queue → executor → audit → response
```

- Policy gate runs **before** enqueue. Ungranted capability → immediate
  refusal (audited, nothing enqueued) with GUI recovery line.
- Queue manager: per-repo ordered lanes derived from the store. Read-only
  capabilities (status, brief, evidence fetch) bypass lanes. Duplicate
  in-flight request (same capability+args+repo) → second caller attaches
  to the first request's result and events.
- Approval-gated operations: executor pauses, emits `approval_pending`,
  GUI surfaces it (beacon amber + banner). Approve → continue;
  deny or timeout (default 15 min) → refusal, audited with resolution.
- Every terminal state writes its own audit row: success, refusal,
  failure, timeout, denial, cancellation. No silent paths (v1 issue #49
  lesson).
- Cancellation: `pam cancel <ticket>` (and GUI) cancels queued requests
  outright and signals running executors cooperatively; a cancelled
  request is a terminal state (`failed`, cause `cancelled`), audited.
  Executors take work under a lease; a lease that outlives its deadline
  is reaped the same way (adopted from v1's queue design).

## Policy profiles

- **relaxed** (macOS default): non-destructive capabilities auto-granted
  on first use (recorded as auto-grant in audit); destructive/external
  operations ask once per capability with "remember", audited always.
- **standard** (Linux/Windows default): grants manual in GUI;
  destructive operations per-operation approval.
- **strict** (future corporate): everything manual and per-operation.
- Profile changes are GUI-only. Audit rows record the active profile.

## Store (SQLite)

`~/.pam/state.sqlite3`, WAL, embedded versioned migrations.

- `request` — id, capability, repo, caller_agent, args_json, state
  (`queued|running|waiting_approval|done|refused|failed`), outcome,
  timestamps. Queue lanes are derived from this table — restart-safe.
- `audit` — append-only: request_id, action, decision
  (`allow|refuse|approve|deny|timeout`), actor (`policy|human|system`),
  detail, ts. Never updated or deleted by normal operations.
- `evidence` — `ev_` id, request_id, kind, content BLOB or path,
  content_hash, ts. Compact answers reference these ids.
- `grant` — capability, scope (`global`), granted_ts, revoked_ts
  (nullable). History preserved: revoke sets timestamp, re-grant is a
  new row.
- `approval` — request_id, capability, requested_ts, resolved_ts,
  resolution (`approved|denied|timeout`), note.
- `caller` — observed agent+repo pairs (first_seen, last_seen); feeds
  GUI sidebar and activity filters. Advisory registry, not authz.
- `setting` — key/value JSON; single source for GUI Settings.

Retention: pruning by age policy from Settings — evidence first, audit
last. Secrets never in this file (OS keychain only).

## Lifecycle & recovery

- Lazy auto-start: client finds dead socket → spawns `pam daemon`
  detached → bounded readiness wait (~3 s) → retry once.
- Single instance via `~/.pam/run/daemon.lock` (flock + pid); stale
  socket with no lock holder is removed and rebound.
- Version handshake: envelope carries client build version; daemon older
  than client → drain, self-restart, client retries.
- Crash recovery on boot: `running`/`waiting_approval` rows from a dead
  daemon → `failed` with cause `daemon_restart`, audited; lanes rebuilt
  from `queued` rows; ticket holders get a legible failure + retry hint.
- Graceful shutdown: stop accepting, bounded drain or checkpoint, flush
  audit, close store.
- Daemon self-logs (tracing) to `~/.pam/log/daemon.log`, rotated —
  debugging PAM itself; never mixed with product evidence.

## Crate layout

- `pam` — the single binary (subcommand modes: client default,
  `daemon`, `gui`).
- `pam_daemon` — service tasks (transport, gate, queue, executor,
  approval, audit).
- `pam_proto` — envelope/response/event types shared client↔daemon.
- `pam_store` — SQLite access + migrations.

Unit tests as Go-style sibling files (`module.rs` + `module_test.rs`,
declared `#[cfg(test)] mod module_test;` from the parent).

## Testing

- Unit: per-service logic in sibling test files.
- Integration: real daemon on a temp runtime dir (short path), real zmq,
  real SQLite; driven through `pam_proto`; asserts states and audit rows.
  Deadline discipline per v1 testkit lesson (CPU-vs-wall classification).
- Invariants: same-repo lane requests never interleave; every terminal
  state has exactly one audit row.
- CI: cheap — Linux fmt/clippy/unit only; nothing added without an
  explicit request.
