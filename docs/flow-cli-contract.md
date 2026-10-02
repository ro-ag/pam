# Bounded flow CLI contract

Task #103 extends the existing request pipeline. The daemon still owns policy,
queueing, deadlines, execution, cancellation, audit and evidence. Inspection
creates no grants, launches no command, contacts no connector and loads no model.

## Discover, inspect, execute, retrieve

```sh
pam flow list --limit 20 --offset 0 --json
pam flow inspect jenkins-build-investigation job=platform/nightly build=41 --json
pam flow run jenkins-build-investigation job=platform/nightly build=41 --no-wait --json
pam wait <ticket> --json
pam flow result <ticket> --json
pam evidence read <evidence-id> --request <ticket> --json
```

Run these from the approved repository. A ticket is a reference, not authority.
Run refuses inputs the flow does not declare (`input_unknown`) and input
values that are not scalars (`input_invalid`) before a ticket exists; a
declared input with neither a value nor a default refuses as `input_missing`.
`pam flow run <id> --digest <sha256>` (`expected_digest` on the wire) pins the run
to the digest `flow.inspect` returned: when the library's flow has changed, the run
refuses `flow_changed` before any work, with a recovery line to inspect again, and
a value that is not 64 hex characters refuses `input_invalid`. If the reply to a
`flow run` is lost, the CLI prints the request id and `pam wait <id>` as the
recovery; do not submit it again unless `pam wait` says the request is unavailable.
List pages default to 20 entries and accept at most 50. Continue using the
returned `next_offset`; a byte limit may end a page before its entry limit.

Inspection returns the flow identity/digest, declared inputs, effects, products,
permission snapshot and structured blockers. It distinguishes required approval
from missing permission and relaxed-profile automatic admission. It never calls
the policy operation that would create that automatic grant. Credential and live
service availability remain unknown where they cannot be established without
accessing external state. Execution rechecks admission; a successful inspection
is neither approval nor proof that the job will succeed.

The `model` block says what a summarize step will get, from the heavy tier's
readiness record (2026-09-15): `used_by` names the steps with `output: summarize`;
`summary` is `model` when the tier is ready or `skipped` with a `blocker`
(`cause`, `detail`, `recovery`) otherwise; `stage` is the first failing rung of
configured → installed → verified → qualified → engine → ready; `qualification`
is `qualified`, `unqualified`, `unverified`, `missing` or `none`. `required`
stays false — a skipped summary leaves the compact evidence in place — and a flow
with no summarize step reports `qualification: not_assessed`. The same verdict,
reduced to `stage` and `cause` per tier, sits under `model.readiness` in
`pam status --json`.

Revision-bound recipes additionally expose a declared correlation target during
inspection and a frozen target digest in results. Use `revision-jenkins-check`
or `revision-ci-triage` with explicit repository, full commit and product IDs;
see [exact workflow evidence](workflow-correlation.md). A matched association
identifies the evidence's revision; product success is a separate observation.

## Compact results and retained detail

`flow.run` returns a versioned projection containing `ticket`, `flow`, `workflow`,
`diagnosis`, `observations`, `evidence` and `omitted`. The complete wire response is
at most 16 KiB; combined observation text is at most 6,000 UTF-8 bytes. Limits
account for JSON encoding. Excess detail is represented by omission counts and
retained evidence references, never by cutting a JSON document in half.

`workflow.outcome` alone does not say whether state changed, so the projection also
carries `effects`, omitted when empty: one entry per state-changing step with its
`step`, `kind`, `state` (`applied` for a step that succeeded, `possibly_applied` for
one that started and failed, timed out or hit its output cap) and, for a landing
step, the `landing` operation, so a `freeze, validate, push` prefix is
distinguishable from a synced landing. A run that ended `unresolved` or `blocked`
after a state change has `handoff.reason` `workflow_not_completed_after_state_change`
and a last summary line naming the steps. Effects are never dropped to fit the size
limit; when observations must be dropped to fit, succeeded and skipped ones go first
(latest first) and a failed or blocked one only when nothing else is left.
`pam flow result` prints the effects and labels a local-model summary
`[untrusted local-model summary]`.

The outer response references the full report. The projection includes bounded
additional evidence references; the full redacted report retains step details.
Read it through the scoped evidence command. The evidence-range API has its own
larger page limit; the 16 KiB result ceiling is not its page size.

`workflow.outcome` describes flow verification. Lifecycle `done` only means that
execution finished. Product observations preserve independently known statuses:
a successful Jenkins retrieval does not prove a successful Jenkins build.
`diagnosis.status` remains `not_attempted` for this deterministic projection;
optional prose summarization does not establish a causal diagnosis.

`flow.result` returns current `state` and `outcome` plus the same persisted
projection as `agent_result`. An authorized running or early terminal request
without a projection returns `agent_result: null` and an explicit
`result_unavailable` cause. It does not manufacture a completed report.

## Authorization and retention

Result and status reads use bounded metadata queries, never raw request arguments
or protected report blobs. They recheck canonical repository ownership, the
original admission revision and every retained captured connector origin before
and after retrieval. Oversized metadata, legacy rows without an admission
revision, and incomplete origin capture fail closed. A missing ticket is not
distinguished from an unreadable one to an unauthorized caller.

Stored result metadata survives client disconnects. Replay does not consume or
reset the separate evidence-range allowance. Retention can remove detailed view
content; origin tombstones remain until request retention removes them. Access
revocation still applies to retained result metadata.

## Waiting and exit status

`pam wait` and `pam subscribe` follow one ticket on one connection. The follow
opens with the durable status query, which is its authorization and the one
`query` request it costs: a refusal ends the follow immediately with the
original ticket and cause, and a ticket that already finished is answered at
once. Otherwise the daemon attaches the follower, replays the events of that
ticket it still holds (so a late `pam subscribe` shows `queued` and `started`),
streams the rest, and ends the stream with the durable result read from the
store at that moment. The CLI prints that result; for a `flow.run` ticket it
then reads the full verdict once through `flow.result`. An event is a
notification, never proof of success: the ending is the store's answer, and the
daemon re-checks the ticket and the caller's authorization on a terminal event
and every 15 seconds, so an ending whose event was lost still ends the follow.
Events carry no detail (a progress note is fixed generic text), and a gap in
their sequence numbers needs no action.

The CLI uses the same outcome mapping for synchronous execution and a completed
wait: success 0, usage error 2, refusal 3, unresolved verification 4 and blocked
work 5. Client/internal errors and observation timeout use 1. Transient daemon
conditions (capacity, rate, a full follower table, shutdown, restart, deadline,
internal error, a follow that reached its one-hour lifetime) and a dropped
connection are retried with backoff until the observation timeout: the client
reconnects and resumes after the last event it saw, and a restarted daemon is
followed from the start. The follow then ends with exit 1 and `follow_timeout`.
Refusal 3 is what the daemon decided and a retry will not change: a policy
refusal, or `client_version_mismatch` (also `protocol_mismatch`) when this `pam`
is not the build the running daemon was started from. That refusal names the
daemon's version and executable; the daemon is neither restarted nor stopped by
it, and the fix is to use the matching binary or stop the daemon. Cancellation
and request expiry remain explicit terminal causes in JSON; observation timeout
does not cancel the original request. Keep the ticket to inspect it later.

A daemon of version 0.4 or older that is still running after an upgrade is not
a refusal: the first command outside a sandbox stops it and starts the current
one, and a command that may not signal it (under a sandbox, or through
`PAM_SOCKET_DIR`) exits 1 with the instruction to run `pam daemon stop` and
then `pam status` outside the sandbox.

Without `--json`, a refused or timed-out follow is one `pam wait:` (or
`pam subscribe:`) line on stderr naming the ticket. With `--json` (`pam wait`
and `pam subscribe` both take it), it is instead a `kind: refusal` object on
stdout — the same shape as every other refusal — whose `id` is the ticket;
an observation timeout uses cause `follow_timeout`. Exit codes are the same
either way. Client-side failures (no daemon, transport) stay on stderr.

See [agent workflow](agent-workflow-contract.md), [evidence retrieval](evidence-retrieval.md)
and [admission budgets](scoped-admission-and-budgets.md). Embedded
[exact job watches](job-watches.md) use the same run/wait/result commands; guarded
landing remains separate roadmap work.

## Restart continuation

A journaled flow resumes under its original ticket, deadline and spent budget.
Use the existing `pam wait` and `pam flow result` commands after reconnecting;
resumption does not create a new request. Completed steps are not executed again.
A prepared state-changing step without a durable receipt stops with
`flow_effect_uncertain`, including cancellation or lease expiry at that boundary.
The intent is journaled only after the approval gate has passed, immediately
before any I/O: a cancel, expiry or restart while the step waits for approval is
`cancelled` or requeued, not uncertain.
Inspect retained evidence and reconcile the effect before submitting new work.
See [workflow recovery](workflow-recovery.md) for retention and authorization
checks. Remote polling uses [durable parking](job-watches.md), which frees the
repository lane without resetting admission. Typed landing reconciliation remains
separate work.

## Remote-job watch progress

Use `watch-github-run`, `watch-jenkins-build` or `watch-sonar-analysis` with exact
execution inputs. `flow inspect` exposes each step's watch policy. Pending work
parks as `queued`; `flow result` can include a scoped `watch` projection even
while `agent_result` is unavailable. Its poll count and next-poll time come from
the committed checkpoint; its evidence reference points to the last changed
redacted observation. Unchanged polls do not duplicate notifications or invoke
a model. Detailed limits and stop causes are in [job watches](job-watches.md).
