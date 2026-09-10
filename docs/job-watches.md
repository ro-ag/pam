# Watching exact remote jobs

PAM can watch one GitHub run attempt, Jenkins build, or Sonar compute task through
the existing flow engine. Each poll uses a small status operation. A terminal
observation triggers the recipe's bounded evidence collector; pending polls do
not fetch job logs, Jenkins node evidence, or Sonar historical gate details.
Polling uses no model. Terminal collection retains the existing evidence,
redaction, correlation and optional diagnostic gates.

## Start and follow

Configure the connector, approved repository/targets and permissions through the
GUI, then run from that approved repository:

```sh
pam flow inspect watch-github-run repository=https://github.example/team/app.git commit=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa repo=team/app run_id=42 run_attempt=3 --json
pam flow run watch-github-run repository=https://github.example/team/app.git commit=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa repo=team/app run_id=42 run_attempt=3 --deadline-ms 1800000 --no-wait --json
pam flow result <ticket> --json
pam wait <ticket> --json
pam cancel <ticket> --json
```

The identifiers are examples, not discovered defaults. Other embedded recipes:

| Recipe | Required inputs in addition to `repository` and full `commit` | Poll → terminal collector |
|---|---|---|
| `watch-github-run` | `repo`, `run_id`, `run_attempt` | `run_status` → `run` |
| `watch-jenkins-build` | `job`, `build` | `build_status` → `investigate` |
| `watch-sonar-analysis` | `project`, `ce_task` | `ce_status` → `analysis` |

These starters verify respectively GitHub `success`, Jenkins `SUCCESS`, and
Sonar gate `OK`, with a matched revision association. A successful HTTP request,
terminal product state, or completed PAM lifecycle alone does not satisfy that
verification. `pam wait` follows the original ticket; it does not poll the product
itself. Disconnecting or timing out a client wait does not create a new watch or
cancel the original request.

## Recipe policy and limits

A supported read-only connector step opts in with:

```yaml
watch:
  max_polls: 60
  interval: 5s
  max_interval: 30s
```

These are also the defaults for `watch: {}`. `max_polls` accepts 1–100 and includes
the first sample. The interval must be at least five seconds; the maximum interval
must be no smaller and cannot exceed 300 seconds. Delay grows exponentially up
to that ceiling. A server `Retry-After` can require a longer delay, but cannot
extend the original deadline. Custom step retries cannot be combined with watch.
Target arguments must be fixed literals or whole declared input references;
prior-step output cannot select a different execution. Sonar branch and PR
selectors are mutually exclusive.

The request retains its original cumulative ceilings: 256 attempts, 128 physical
HTTP sends, 128 MiB HTTP capture and 128 MiB command capture, with an admission
lifetime of at most one hour. CLI flow execution defaults to 30 minutes. Before
another poll, the watch checks that one status send plus terminal-collection
headroom remains: two HTTP sends for GitHub, 40 for Jenkins, four for Sonar.
Other steps and failed attempts spend the same allowance. Byte limits, request
expiry, and collector limits still apply; headroom does not promise completion.
A configured 100-poll watch may stop earlier, especially for Jenkins.

## Durable parking and progress

After each observation, PAM commits a bounded checkpoint with the original
arguments, identity pins, poll/outage counters and next poll time. While waiting,
the request is durably `queued` with a future resume time, outside ready execution
lanes. Its repository lane is free for other requests. The parked ticket still
counts toward the 128-request/8 MiB admission limits. Due work rejoins the ordinary
queue, then rechecks authorization and the original deadline before I/O.

Restart restores the same ticket, recipe digest, checkpoint, expiry and spent
budget. It neither refreshes permissions nor resets sampling counters. Missing
checkpoints or retained evidence stop recovery. A crash after checkpointing but
before parking is safe: the restored next-poll time prevents early product I/O.
See [workflow recovery](workflow-recovery.md) for uncertain effects.

`pam flow result` includes a bounded `watch` object when readable committed
progress exists: step, connector, status, watch state, poll count, next-poll Unix
milliseconds, evidence ID and omissions. It selects the journal-committed
observation, not the newest evidence row. The protected checkpoint is never
returned. Poll counters and schedule can advance while the evidence ID stays the
same: unchanged normalized observations reuse evidence and produce no duplicate
watch-change notification. Read the referenced redacted observation through
`pam evidence read`. Public subscription text remains generic; product details
require scoped result/evidence retrieval. A final `agent_result` is absent until
available and consistent with the durable terminal outcome.

## Identity and stop conditions

GitHub pins the exact run and attempt; Jenkins pins job/build; Sonar pins project,
compute task and selectors. Previously established source proof cannot change.
A pending Sonar task may acquire its first analysis ID; once observed, that ID
cannot change. Terminal collection must match these pins and independently meet
[revision correlation](workflow-correlation.md), including the GUI-owned Sonar
repository mapping. Missing revision proof remains unresolved. There is no
fallback to a latest green execution or gate.

Observed GitHub jobs form a separate, durable union of at most 256 positive IDs
per step. New membership is accepted only under the identical matched server,
repository, run and attempt binding. Overflow rejects the collection without a
partial append. A job log requires membership already established in this
request. Legacy retained bindings that embedded `job_ids` in immutable identity
refuse recovery explicitly; inspect their evidence and start a new request after
upgrading rather than rewriting the original association.

Three consecutive unavailable observations stop with `watch_outage_limit`.
PAM policy, credential-availability and configuration refusals stop directly, as
do observations rejected by the watch normalizer. Other adapter errors currently
consume the outage allowance, including rejected credentials or product access. Target
changes retain conflicting evidence and stop with `watch_target_changed`;
accepted pins are not replaced. Poll, collection-budget and scheduling limits
produce `watch_poll_limit`, `watch_collection_budget` or `watch_deadline`.
Cancellation and actual request expiry retain their lifecycle causes. Parked
expiry/revocation also wakes the original waiting caller through bounded terminal
notices. None of these outcomes becomes a successful product result.

Local fixtures exercise these contracts with fake transports and credentials.
They are not live enterprise compatibility results or local-model qualification.
Guarded landing, remote mutations and artifact publication remain separate work.
