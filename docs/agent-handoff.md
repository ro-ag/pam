# Reusable agent handoff

`pam flow run` and the persisted `pam flow result <ticket> --json` use the existing
bounded `AgentResult` contract. The additive `handoff` field records local workflow
completion versus escalation. Workflow status and product observations retain their
authority; `diagnosis.status=not_attempted` does not imply a model diagnosed the task.

The handoff carries the structured frozen repository/commit/optional PR target when
one was declared. Without that declaration, target state is `not_declared`; prose,
step names and URLs in logs are never used to invent an association. Existing
correlation status still determines whether product observations match that target.

Each observation carries up to four evidence handles with an explicit omitted count.
These are supporting evidence, not authenticated decisive quotes. Current flows do
not record formal quote attribution, so `decisive_citations` is empty and the missing
fact is explicit. The first action names the request-bound `evidence.read` capability,
its retained verdict handle, and the default 16 KiB first page. No action runs
automatically. `evidence.read` returns immutable view identity, digest and provenance;
continuations must pin that identity. Missing views, retention and current permissions
can still refuse a known handle. No raw private checkpoint is exposed.

`flow.result` additionally returns `read_availability` from existing stored counters.
Reporting creates no allowance and renews no deadline. Original execution expiry is
milliseconds; evidence allowance expiry is the store's Unix seconds. Execution and
evidence budgets are separate. An absent allowance is `not_initialized`, with null
remaining values, not an unlimited grant. Values are a snapshot, not permission or a
promise that a later read succeeds; each read rechecks scope and retention.

Work counters are charged attempt/HTTP slots and captured-or-reserved bytes. Cancelled
or unsettled operations can remain fully charged. These are not exact physical wire
traffic, measured frontier consumption, avoided retries, or savings. Handoff frontier
tokens, correction turns and realized token savings stay null until an independently
reviewed paired experiment measures them. The packet initiates no local inference,
vendor CLI or hosted request, and handles no additional credentials.

Old persisted projections without handoff fields remain readable. Complete result
size stays bounded by the existing 14 KiB projection and 16 KiB wire limits; omitted
observations and evidence counts remain explicit. The optional sections never cost
the primary result: when the projection plus watch plus accounting would exceed the
16 KiB wire limit, `read_availability` collapses first to `{"omitted":"response_limit"}`
and only then does `watch` collapse to the same marker. The projection itself is never
dropped, the collapse is measured against the real serialized response rather than a
guessed reserve, and an omitted section is always marked, never silently absent or
reported as null. Text CLI output uses JSON escaping
for untrusted content and preserves the additional availability metadata.
