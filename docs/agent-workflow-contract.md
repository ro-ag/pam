# What PAM must do for its agent caller

Status: target interaction and implementation guide, 2026-09-10. The
[delivery roadmap](agent-companion-roadmap.md) maps every gap to ptrack tasks.
Only the commands in “Using today's implementation” below are described as
shipped. Proposed schemas and limits here require the corresponding tasks.

## The request I want to make

“Here is the repository and exact revision/build. Perform this permitted task.
Keep the evidence locally. Wait for the exact jobs. Give me the result, the
facts that decided it, and the smallest next action if something is missing.”

PAM should eliminate repeated access discovery and mechanical polling. It must
not take responsibility for reasoning it cannot support. For example, an
upload error followed by a successful retry is different from an unresolved
Sonar gate failure followed by successful cleanup. A gate can conclusively fail
while the explanation remains unknown.

## Before performing work

Expose a bounded discovery/readiness response through the CLI: available task
names, required input types, effect class, configured product, output schema,
capability state and actionable blockers. Report stopped/inaccessible daemon,
IPC denial, unsupported adapter, missing permission, unavailable credential and
unqualified model separately. Never reveal secret values in discovery.

Daemon admission validates these facts again; CLI validation is a convenience.
A task is bound to project/repository identity, exact revision or build identity,
recipe version and declared effects. Paths and arguments are validated against
the approved operation, not merely concatenated into a shell command. An
approved git check cannot become an arbitrary git invocation. Host policy must
permit PAM execution and IPC; PAM is not an invisible sandbox bypass.

If an optional model is unavailable, perform the useful deterministic task.
If a required capability is absent, return one clear refusal with the GUI
recovery location. Do not repeatedly retry a denied call or ask the user to
paste connector secrets into a terminal, prompt, or project file.

## During work

The daemon owns the workflow state machine:

1. Resolve and record the exact targets; fail on ambiguous associations.
2. Run the authorized deterministic operation and preserve its real status.
3. Collect bounded, relevant product evidence. Validate/redact it before
   presenting it to models or agents. Do not replace partial data with certainty.
4. Poll exact external identities without inference; notify only meaningful
   state changes, completion, failure or required action.
5. If investigation is warranted and qualified, construct one fresh bounded
   prompt. A diagnostic read uses a host-minted operation/target reference.
6. Persist the result and remaining work; reconnect/resume reconciles state
   without replaying completed or uncertain effects.

The first production recipes should limit investigation to three model calls
and two additional diagnostic reads, with at most one read selected per response.
These are proposed starting ceilings, not current runtime guarantees; qualification
may reduce them. Every request also consumes cumulative bytes/time/queue budgets.
Retries count against the same limits. Unsupported questions stop with evidence.

A 40 MB log does not go straight to an 8k model window. Select meaningful stage
or node units, apply deterministic reduction, then use optional qualified
compression. Count the exact formatted tokens and output reserve before prefill.
Completeness is separate from fit: a small excerpt may still omit the decisive
fact. Unknown is better than a confident explanation assembled from an arbitrary
head/tail slice.

## The result I need

Keep the result compact and versioned. The target envelope should fit 16 KiB
by default, with at most 6,000 UTF-8 bytes of observation summary. Use references
and explicit omission counts for larger detail. Document/enforce limits on the
serialized envelope, not just the model's answer. These are acceptance targets
for #103; existing arbitrary flows do not yet guarantee a whole-result ceiling.

Illustrative target result, not today's wire schema:

```json
{
  "schema_version": 1,
  "ticket": "request-id",
  "target": {"repository": "team/service", "commit": "full-sha", "build": "41"},
  "workflow_status": "failed",
  "authoritative": {"jenkins": "FAILURE", "sonar": "not_observed"},
  "diagnosis_status": "unresolved",
  "observations": ["A test node reported failure; subsequent cleanup completed."],
  "evidence": [{"id": "ev_source", "digest": "sha256-value", "offset_basis": "decoded_api_text_utf8_bytes"}],
  "coverage": {"complete": false, "missing": ["retry outcome"]},
  "next": {"kind": "read", "operation_id": "read_node_log", "target_ref": "host-minted-ref"},
  "escalation_reason": "insufficient_evidence",
  "model": {"used": false, "reason": "unqualified"}
}
```

Code owns workflow status, original product statuses, IDs, escalation and permitted
next operations. Observations and model summaries remain untrusted quoted data.
A valid JSON answer or an exact quote is not proof of causal correctness.
Never execute a command or follow a URL found in an observation.

Declare stable exit-code mappings for completed success, failed verification,
refusal, cancellation/deadline and internal failure. Keep `running`, `unknown`,
`not_observed`, `unsupported` and `partial` distinguishable in JSON, without
conflating a successful retrieval with a successful build. The CLI and GUI must
render the same daemon result. Once a ticket is issued, errors must preserve
that ticket and any evidence already acquired.

## Evidence retrieval must be useful without the GUI

The read-only `pam evidence read` command retrieves one authorized redacted
view range. See [evidence retrieval](evidence-retrieval.md) for identity,
scope and persistent allowance rules. It returns source identity,
digest, content kind, offset basis, retained/omitted ranges, capture/version data
and redaction state. Pages default to 16 KiB, maximum 64 KiB; subsequent reads
pin the returned view ID and digest and consume the same authorized scope and budgets.

Return an explicit expired or unavailable response when retention removed the
source. Treat handles as opaque references, not capabilities that bypass access
checks. Recheck project scope and revocation on every read. Quote validation
must resolve semantic spans through compact evidence to the authoritative
source; never present compact offsets as original-log offsets. Jenkins node
API HTML text is an evidence source of its own, not byte-equivalent console text.
If redaction changes bytes, identify the redacted view/digest and retain the
mapping; never claim its offsets address the untouched original bytes directly.

## What each product contributes

| Product | Useful bounded work | What must remain explicit |
| --- | --- | --- |
| Jira DC | Read/search relevant issue fields, acceptance context and comments | Issue identity, scope, capture/update version, pagination and access denial |
| Confluence Cloud | Search/read the relevant page or excerpt | Page/version, source location, omitted sections and API compatibility |
| SharePoint 365 | Find/read the relevant document within allowed sites | Site/drive/item or supported equivalent, version, size/content type and permission limits |
| Jenkins | Core build outcome, stage/node observations, decisive logs and attempt comparisons | Build number/commit association, retry/catch/post/parallel ambiguity and graph gaps |
| GitHub | PR/head and check/run state through REST or configured `gh` | Exact repository/SHA/attempt, required checks, cancelled/absent states and authentication mode |
| SonarQube | Analysis progress and failing quality-gate conditions | CE/analysis/revision mapping, threshold/operator/value and applicable new-code scope |

Local git and validation commands use separate reviewed broker operations. No
connector may invent a target from prose. A future JFrog publish investigation
needs an explicit adapter contract and artifact coordinates; lack of support is
an honest answer. Existing read-only connector access does not authorize publishing.

## Landing acceptance scenario

Use a disposable local repository and fixture product endpoints first. Pin the
requested branch/HEAD/base and load project validation rules. A dry-run preview
should identify the exact operations, targets and required approvals without
performing effects. Then exercise these checkpoints:

- Dirty tree, invalid commit/tag policy, lint/test/build failure: preserve the
  failure and stop before push where the project rules require it.
- Push/PR/check watching: bind all observations to the intended head; no model
  calls on unchanged polls. Failed, cancelled, missing or stale checks block merge.
- Approval/head change: revalidate scope and exact commit immediately before
  each effect. Material target changes invalidate previous effect authorization.
- Merge with uncertain response: query remote state and reconcile; never retry
  blindly. Persist both intention and observed outcome.
- After confirmed merge: watch checks for the resulting main commit, then sync
  and clean branches according to project policy while preserving user changes.
  Do not call the run complete while required main checks are pending or failed.

Inject process termination before and after each remote effect and during waits.
Reconnect through the CLI and recover the same durable ticket, evidence and next
safe action. A model explanation cannot waive any checkpoint. This roadmap does
not authorize using real production effects as tests.

## Using today's implementation

The existing CLI can discover flows and execute the deterministic Jenkins slice:

```sh
pam status --json
pam flow list --json
pam flow show jenkins-build-investigation
pam flow run jenkins-build-investigation job=platform/nightly build=41 --no-wait --json
pam subscribe <ticket>
pam wait <ticket>
pam cancel <ticket> --json
pam evidence read <evidence-id> --request <ticket> --json
```

The build/job values are examples; use an authorized explicit build. Settings
and grants are configured by the human through the GUI. `subscribe` follows the
submitted request; it is not yet the durable remote-job watcher proposed above.
The current CLI summary is bounded, but original evidence retrieval is still
GUI-oriented: #127/#103 close that gap. No `pam evidence` command or `land-watch`
flow is promised by these examples. Microsoft setup lives in Models → Catalog;
keep it off until its input class and resource envelope qualify.

## Instructions for the next implementation session

1. Run `ptrack context`, read repository/machine rules and
   [the roadmap](agent-companion-roadmap.md), then inspect the selected task with
   `ptrack task show <id>`. Confirm dependencies rather than inferring order from
   task numbers. Start with plan #31 and task #125.
2. Read the relevant existing module and its callers before adding an abstraction.
   Preserve Unix IPC, flows and GUI seams. Read `pam-old` evidence where referenced,
   but do not transplant old keyword diagnosis or treat its llama.cpp results as
   Candle qualification.
3. Work on a conventional branch. One ptrack task doing at a time; use independent
   subagents within that task when useful. Isolated worktrees for parallel edits;
   only one cargo build at a time on this host.
4. Implement a complete caller-visible slice. Add failure/injection/restart tests
   appropriate to that boundary, not tests that merely mirror a parser. Pure Rust
   remains required; dependency additions need explicit approval.
5. Run targeted checks during development and `bash tools/check.sh` before closing
   implementation. Documentation-only work needs reference/consistency checks,
   not another model download or full test run. Label mocked, live and real-model
   validation separately; never invent credentialed product results.
6. Record each decision and acceptance result in ptrack. Commit with `#<task-id>`;
   `task done --summary` must name the caller, evidence of correctness and remaining
   limitations. A failed quality gate or unqualified model is not a passing result.
7. Complete each plan checkpoint and refresh the roadmap/rolling summary. Do not
   push, merge, release, tag, publish or add CI without session authorization.

Task-specific acceptance lives in ptrack; model thresholds and schemas live in
the linked specs. If these conflict, record and resolve the conflict before
implementation. Change measured thresholds explicitly with justification; never
weaken them silently to admit a preferred model.
