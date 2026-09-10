# Scoped admission and work budgets

PAM's daemon owns admission. Agent labels are attribution; changing a label never
creates another rate allowance or grants access to another target. Private GUI
administration is described in [admin-boundary.md](admin-boundary.md).

## Configure a repository in the GUI

Open Settings → Flows and add the repository's exact existing absolute path.
Add each connector, its configured base URL, and the targets this repository may
read. Save explicitly. Existing capability grants and old flow settings do not
implicitly approve roots or connector access. Empty or malformed scope policy
refuses work before resolving repository variables, reading credentials, or
starting a connector request. Status and discovery remain available.

Target values are exact:

| Product | Target entry |
| --- | --- |
| GitHub | `owner/repository` |
| Jenkins | Exact job path, including folders |
| SonarQube | Project key |
| Jira DC | Project key; only structurally validated issue keys resolve to it |
| Confluence Cloud | Numeric page ID |
| SharePoint 365 | Exact Graph site identifier |

Broad searches, unresolvable resource IDs, and AWS require an explicit
connector-wide approval. The GUI currently edits the six HTTP products above;
it does not invent an AWS target policy. Jenkins folder prefixes and filesystem
string prefixes are not wildcard grants. A separately checked-out worktree must
be approved as its own root. Connector URL changes invalidate the old scope.

PAM checks the canonical repository before the preliminary `git remote` lookup,
before each attempt, before credentials, and before each HTTP call. It checks
scope again for an authorized log-delivery redirect and strips authentication.
The configured original product URL remains bound to the operation. A redirect
is restricted to one HTTPS hop with no user information or fragment; its signed
URL is delivery authority from the approved product response, not a new connector
credential or permission to route arbitrary agent-supplied URLs.

Approving a working directory does not sandbox a build script or an allowed
program's filesystem access. Trusted flow definitions, executable files and
private PAM state must remain outside the agent's write authority. Repository
approval must therefore be considered together with the approved flow/programs
and the host's OS policy.

## Queue and restart behavior

Admission persists an absolute expiry and the current grant-revocation revision.
Requests enter `running` before gating; they become `queued` only through an
atomic post-gate authorization write. A crash cannot convert an unapproved row
into executable queued work. Placement requires the revision captured before
gating to remain unchanged, including during an approval wait. Revocation
invalidates stale admissions even if a grant is subsequently restored. This is
conservative: an unrelated grant revocation can also require a fresh submission.

Recovery preserves the original expiry and rejects stale or legacy queued rows
without authorization metadata. Running/interrupted work is not automatically
replayed. Idempotency attachment requires the same key (when supplied), repository,
capability and arguments. Caller labels do not provide a separate authorization
boundary. A new invocation after completion is new work, not durable exactly-once
execution; the landing/watch plans must add their own reconciliation contracts.

## Enforced limits

| Resource | Ceiling |
| --- | --- |
| Public JSON request or response frame | 1 MiB |
| ZMTP multipart message | Four frames; 2 MiB including data-frame headers |
| Inbound ZMTP connections, including handshakes | 256 process-wide |
| Inbound handshake | Five seconds |
| Request ID, capability, caller label, idempotency key | 128 bytes each |
| Caller repository spelling | 4,096 bytes |
| Active admitted requests | 128 |
| Persisted fields of active admitted requests | 8 MiB cumulative |
| Public dispatcher/reply slots | 128 work; 16 reserved control |
| Aggregate admission rate | 256 work/second; 64 control/second |
| Request wall time | One hour, including admission and queue wait |
| Command/connector attempts per request | 256 |
| Physical HTTP calls per request | 128 |
| Accepted HTTP bodies per request | 128 MiB cumulative |
| Command capture per request | 128 MiB cumulative |
| Accounted blocking jobs | Eight outstanding, including waiting resource lanes |

Individual adapter and step ceilings can be smaller. Identity and payload checks
happen before retaining a decoded request for execution. The patched existing
ZeroMQ dependency checks declared frame sizes before allocating, including on
clients. An oversized public reply becomes a small explicit refusal; callers
must use bounded evidence retrieval rather than request a complete large blob.
See [the dependency patch record](../vendor/zeromq/PAM-PATCH.md) for wire limits
and its separate regression command.

Every flow step and retry shares the same request budget. Preliminary git reads
consume an attempt and capture allowance. Each physical HTTP hop reserves its
maximum body size before sending; completed bounded bodies return unused bytes.
Errors or cancelled futures without an exact byte count keep their reservation.
This bounds accepted/captured data, not all bytes transmitted by an uncooperative
remote peer. HTTP deadlines are enforced around the transport, not merely passed
to curl. AWS reserves both of its bounded pipe captures conservatively.

Failed attempt evidence is filed before retry/backoff. Budget and scope refusals
are nonretryable and stop the run with an explicit cause. Successful flow replies
include `budget_usage`; that field reports measured or conservatively reserved
work, not frontier-token savings or diagnosis accuracy.

Blocking work retains its permit inside the actual closure after callers time
out. Keychain operations and model filesystem operations use serialized resource
lanes. `status.blocking_jobs` exposes a bounded history with fixed operation
labels and no arguments or secrets. `returned` means the closure returned, not
that its business operation succeeded. Cancellation cannot undo a completed
filesystem/keychain effect. Existing asynchronous download workers have their
own lifecycle; the blocking counter must not be presented as a count of all
background work in PAM.

## Implementation and verification

The relevant callers are public transport → daemon admission → queue or bypass
executor → flow engine → scoped connector transport / budgeted command runner.
`RequestBudget` is an explicit shared object in `ExecContext`; new capabilities
must carry it through follow-up work. Do not create a fresh budget for each page,
step, retry, redirect, or attachment. Running requests currently fail on daemon
restart; future durable resume must persist consumed counters before supporting
resume, rather than replenishing them from defaults.

Run `bash tools/check.sh`. It includes the vendored codec regressions separately
from workspace tests. Integration acceptance includes forged admin requests,
crash-before-gate recovery, expiry, revocation between admission and placement,
cross-repository idempotency, zero-access scope refusals, redirected credential
stripping, retry accounting, retained failed evidence, and actual blocking-job
permit ownership after cancellation.

This is broker/resource qualification. It does not qualify the local model,
Microsoft compression quality, or a production enterprise sandbox profile. Those
remain separate roadmap gates.
