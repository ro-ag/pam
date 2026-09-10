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
List pages default to 20 entries and accept at most 50. Continue using the
returned `next_offset`; a byte limit may end a page before its entry limit.

Inspection returns the flow identity/digest, declared inputs, effects, products,
permission snapshot and structured blockers. It distinguishes required approval
from missing permission and relaxed-profile automatic admission. It never calls
the policy operation that would create that automatic grant. Credential and live
service availability remain unknown where they cannot be established without
accessing external state. Execution rechecks admission; a successful inspection
is neither approval nor proof that the job will succeed.

## Compact results and retained detail

`flow.run` returns a versioned projection containing `ticket`, `flow`, `workflow`,
`diagnosis`, `observations`, `evidence` and `omitted`. The complete wire response is
at most 16 KiB; combined observation text is at most 6,000 UTF-8 bytes. Limits
account for JSON encoding. Excess detail is represented by omission counts and
retained evidence references, never by cutting a JSON document in half.

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

Waiting authorizes through the durable status query before subscribing. A refusal
ends the follow immediately with the original ticket and cause. A terminal event
triggers a durable recheck rather than being treated as proof of success.

The CLI uses the same outcome mapping for synchronous execution and a completed
wait: success 0, usage error 2, refusal 3, unresolved verification 4 and blocked
work 5. Client/internal errors and observation timeout use 1. Cancellation and
request expiry remain explicit terminal causes in JSON; observation timeout does
not cancel the original request. Keep the ticket to inspect it later.

See [agent workflow](agent-workflow-contract.md), [evidence retrieval](evidence-retrieval.md)
and [admission budgets](scoped-admission-and-budgets.md). Durable remote-job
watching and guarded landing remain separate roadmap work.
