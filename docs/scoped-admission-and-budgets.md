# Scoped admission and work budgets

PAM's daemon owns admission. Agent labels are attribution; changing a label never
creates another rate allowance or grants access to another target. Private GUI
administration is described in [admin-boundary.md](admin-boundary.md).

Repository and product scopes are global permissions for public clients, not
per-agent identity boundaries. A client may select any globally approved root.
Ticket ownership binds evidence to the original canonical target; it does not
prevent another globally authorized public client from requesting that target.
See [administration boundary](admin-boundary.md#global-target-authority).

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

Broad searches and unresolvable resource IDs require an explicit
connector-wide approval. The GUI edits the six HTTP products above, which are
all the connectors there are. A scope policy saved before the AWS adapter was
removed may still carry an `aws` approval; it is ignored when the policy is read
(removing an approval only narrows access) and disappears on the next save.
Jenkins folder prefixes and filesystem
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
gating to remain unchanged, including during an approval wait. The revision is
scoped: a request is void only when a grant it depends on was revoked after its
admission, meaning its own capability or, for a `flow.run` ticket, any
`flow.step:` capability. Revocation invalidates those admissions even if the
grant is subsequently restored; a revocation a request does not depend on
leaves queued, parked and finished work alone. Because the store cannot tell
which flow a run belongs to, a step revocation of any flow still voids every
`flow.run` ticket.

Startup recovery reads pages of at most 16 rows and 8 MiB of text. SQL byte guards refuse oversized legacy fields before materializing them; the rows remain intact and startup gives an explicit backup/repair error. Recovery preserves the original expiry and rejects stale or legacy queued rows
without authorization metadata. Running/interrupted work is not automatically
replayed. Idempotency attachment requires the same key (when supplied), repository,
capability and arguments. Caller labels do not provide a separate authorization
boundary. A new invocation after completion is new work, not durable exactly-once
execution; the landing/watch plans must add their own reconciliation contracts.

The original caller, approval wait and queue lease share that persisted expiry;
moving between phases never starts a fresh request clock. Public expiry replies
use `deadline_exceeded`; the queue records `lease_expired` internally, separately
from an explicit `cancelled` request. An attached caller's observation timeout
does not cancel the underlying work.

Every request handler runs under one hard deadline around admission, the gate,
execution and the terminal write: the request deadline (clamped to the one-hour
ceiling) plus a 30-second grace, and for `status`, `query` and `cancel` the
smaller of the deadline and 10 seconds plus 2 seconds. When it elapses the caller
is answered `deadline_exceeded` at once, the slot is released and the terminal
row is written in a detached task. A handler that is only parked on the
completion router lets go when its caller disconnects; the laned work continues.
A terminal write that fails is retried and then parked for the maintenance loop
(one that finds the store already closed, at the very end of a shutdown, is
neither: nothing can record it any more, and boot recovery closes its row),
and a reconciler fails any in-flight row whose deadline passed (plus the handler
grace and 15 seconds) and drops it from the lanes, so a stranded row cannot hold
admission capacity.

## Enforced limits

| Resource | Ceiling |
| --- | --- |
| Public JSON request, reply or event frame | 1 MiB; the declared length is checked before any buffer is allocated |
| `hello` frame | 4 KiB; the version it carries, 64 bytes |
| Inbound public connections, including handshakes and follows | 256 process-wide; one over the cap is told `connection_capacity_exhausted` |
| Inbound handshake (the `hello` and the one request frame) | Five seconds |
| Frame write to a peer | Five seconds; a peer that does not read is disconnected |
| Request ID, capability, caller label, idempotency key | 128 bytes each |
| Caller repository spelling | 4,096 bytes |
| Active admitted requests | 128; a row past its deadline stops counting |
| Persisted fields of active admitted requests | 8 MiB cumulative |
| Public dispatcher slots | 128 work; 16 `status`; 16 `query`; 8 `cancel` (falls back to a control slot); 32 for requests the private admin plane submits. The transport holds none |
| Aggregate admission rate | 256 work/second; 64 `status`/second; 64 `query`/second; 16 `cancel`/second |
| Request handler | Request deadline plus 30 seconds; control class: the smaller of deadline and 10 seconds, plus 2 seconds |
| Public followers (`pam wait`, `pam subscribe`) | 96 in total; 16 per ticket; refusal `follower_capacity_exhausted` (retried by the client) |
| Follower queue | 64 events; the oldest `progress` event is dropped first, the ending never |
| Replay kept per live ticket | The last 32 events, for a late or resumed follower |
| Tickets the event hub tracks | 512; the oldest one nobody follows is dropped, which only loses replay |
| Follow lifetime | One hour (`follow_expired`), after which the client reconnects; the daemon re-checks the ticket and the follower's authorization every 15 seconds |
| All-events subscribers (private admin plane, the GUI) | 4; 1,024 queued events each, then `subscriber_lagged` |
| Private admin plane | 1 MiB requests, 16 MiB replies, 32 connections, five-second handshake |
| Finished replies kept for attached duplicates | 256 entries, 8 MiB, 60 seconds; the oldest is evicted first |
| `echo` diagnostic | Delay at most 60 seconds; arguments at most 64 KiB |
| Request wall time | One hour, including admission and queue wait |
| Command/connector attempts per request | 256 |
| Physical HTTP calls per request | 128 |
| Accepted HTTP bodies per request | 128 MiB cumulative |
| `admin.network.test` | 20 seconds in the daemon (25 in the GUI bridge); at most 12 targets, 4 probed at a time, each one credential-free `HEAD` with an 8-second transfer limit and a 5-second connect limit; targets come from configured state only, never a free-form address |
| Network settings document (`net.settings`) | 16 KiB; proxy address 255 bytes with an explicit port; proxy user name 128 bytes; no-proxy list 64 entries of 255 bytes; a mirror address 512 bytes |
| CA bundle import | A 4 MiB source file holding at most 512 certificate blocks; the private copy holds certificates only |
| Engine install and import (`admin.models.engine.install`, `.import`) | One synchronous op under the GUI bridge's 120-second deadline; a timed-out download resumes on the next Install, an import copies again |
| Engine and weights imports, free space | Refused before the copy when the volume holding the destination has less than the file's size plus 64 MiB free (measured on macOS; elsewhere a full volume is reported from the write) |
| Command capture per request | 128 MiB cumulative |
| Accounted blocking jobs | Eight executing; 128 outstanding including waiting lanes |
| Store calls queued per connection | 1,024, waiting plus running, on the writing connection and on the read-only one. The next call is refused before it runs and writes nothing; a public request that meets it is refused `store_overloaded`, marked retryable (a follow and a patient read retry it with backoff), and the admin plane shows the store's sentence |

Individual adapter and step ceilings can be smaller. Identity and payload checks
happen before retaining a decoded request for execution. Both the daemon and
the client check a frame's declared length against the direction's limit before
allocating or reading its body. An oversized public reply becomes a small
explicit refusal (`response_budget_exhausted`); callers must use bounded
evidence retrieval rather than request a complete large blob. A connection
carries exactly one request, so a pending reply and an active handler are the
same thing: the transport holds no permits of its own beyond the connection
cap. The wire protocol and the reasons for each follow limit are in the
[transport specification](specs/2026-10-02-framed-public-transport.md).

Every flow step and retry shares the same request budget. Preliminary git reads
consume an attempt and capture allowance. Each physical HTTP hop reserves its
maximum body size before sending; completed bounded bodies return unused bytes.
Errors or cancelled futures without an exact byte count keep their reservation.
This bounds accepted/captured data, not all bytes transmitted by an uncooperative
remote peer. HTTP deadlines are enforced around the transport, not merely passed
to curl.

Failed attempt evidence is filed before retry/backoff. Budget and scope refusals
are nonretryable and stop the run with an explicit cause. Successful flow replies
include `budget_usage`; that field reports measured or conservatively reserved
work, not frontier-token savings or diagnosis accuracy.

Blocking work retains its permit inside the actual closure after callers time
out. Keychain operations and model filesystem operations use serialized resource
lanes. `status.blocking_jobs` exposes a bounded history with fixed operation
labels and no arguments or secrets. Saturation returns `blocking_capacity_exhausted`; it does not imply a missing model or unhealthy keychain. `returned` means the closure returned, not
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
