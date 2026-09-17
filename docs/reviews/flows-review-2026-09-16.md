# Flow surface review, 2026-09-16

Review of the PAM flow system against the contracts in `docs/flow-cli-contract.md`,
`docs/agent-workflow-contract.md`, `docs/command-containment.md`,
`docs/scoped-admission-and-budgets.md`, `docs/enterprise-connector-contracts.md`,
`docs/guarded-landing.md`, `docs/job-watches.md`, `docs/workflow-recovery.md`,
`docs/workflow-correlation.md`, `docs/evidence-retrieval.md` and the two specs
(`2026-09-02-flows-connectors-design.md`, `2026-09-12-guarded-sync.md`). Method:
full read of `crates/pam_flow/src`, the daemon `flow_*` files,
`connector_service.rs`, `scope_policy.rs`, `crates/pam/src`, `crates/pam/tests/cli.rs`,
all 21 built-in YAML files, and a live exercise of every flow CLI verb against a
scratch daemon (`PAM_BASE_DIR=/tmp/pamrv`): `flow list` paging, `flow inspect`
with missing/extra inputs, `flow run --no-wait`, `wait`, `flow result`,
`evidence read`, and cancel/refusal paths, including the connector-without-
credentials refusal shape.

Findings, one line each, sorted by severity. `drift` means the code contradicts a
listed contract document; `validation` means a shape the validator should refuse
(or the run should refuse) but does not; `recipe` is a built-in YAML problem;
`ergonomic` is an agent-facing output problem.

## Findings

- crates/pam_daemon/src/flow_service.rs:874: drift: the inspect step sentinel
  `credential: "unknown_not_probed"` never reaches an agent — `redact_json`
  masks every value whose key contains `credential`
  (crates/pam_daemon/src/evidence_view.rs:820), so the field that
  `docs/flow-cli-contract.md` §"Discover, inspect, execute, retrieve" promises
  ("credential … remain unknown") always renders `[REDACTED]` and an agent
  cannot tell a configured connector from a masked field. <Fix: rename the
  inspect field to `auth_probe` (its normalized key passes the sensitive-key
  filter) so the sentinel survives the redaction pass; no reader consumes the
  old key.>

- crates/pam_daemon/src/flow_service.rs:1211: validation: `flow.run` silently
  ignores supplied input names the flow does not declare — `resolve_vars` walks
  only `flow.inputs`, so `pam flow run revision-ci-triage pagee=2` runs with the
  declared `page` default and the typo is invisible in the public projection
  (which does not echo inputs), while `flow.inspect` flags the same input as
  `input_unknown` (flow_service.rs:701). A recipe can thereby run against
  defaults the caller never chose. <Fix: refuse an undeclared input name with
  the inspect surface's `input_unknown` cause before admission does any work.>

- crates/pam_daemon/src/flow_service.rs:396: validation: `RunArgs::from_value`
  silently drops non-scalar `inputs` values (`filter_map(scalar_text)`), so an
  envelope carrying `{"repo": ["x"]}` runs as if the input were absent —
  `input_missing` if there is no default, the default silently used if there
  is one; the inspect path refuses the same shape
  (flow_service.rs:2906-2918). <Fix: refuse with `input_invalid` instead of
  dropping.>

- crates/pam_flow/src/validate.rs:484: validation: a declared input no step,
  env value or correlation declaration reads is accepted, so the GUI shows an
  input field and an agent may supply a value the recipe never uses — the
  "fails at validation, never at step 7" rule does not hold for this shape.
  <Fix: refuse with an `inputs.<name>` error when `${inputs.<name>}` appears
  nowhere in the flow.>

- crates/pam_flow/src/validate.rs:967: validation: `check_input_name` accepts a
  leading `-` (`-foo` is lowercase + `-`), but `pam flow run -foo=bar` is
  unparsable as `key=value` by clap, so the input is declared, validatable and
  unusable through the only public CLI. <Fix: refuse a leading `-` in input
  names.>

- crates/pam_flow/flows/after-merge-checks.yaml:2: recipe: the description
  promises "refresh the local view of the remote", but the `fetch` step runs
  `git fetch`, which command containment always denies (`(deny network*)`,
  docs/command-containment.md §"Deliberate execution limits"); the step fails
  with git's own exit 255 every run. <Fix: say in the description that the
  fetch step needs network access and fails under the contained profile while
  the local checks still run.>

- crates/pam_flow/flows/pr-readiness.yaml:4: recipe: same claim — "an
  up-to-date remote" — over a `git fetch` step that cannot succeed under
  containment, and `branch-commits` depends on it, so the flow can never get
  past `fetch`. <Fix: describe the contained-profile reality (fetch fails
  without network; the remaining local gates are what the recipe proves
  elsewhere).>

- crates/pam_flow/flows/dependency-audit.yaml:2: recipe: `cargo audit` also
  needs network on first run (it clones the advisory database), and the
  description names only a missing `cargo-audit` binary as the failure mode.
  <Fix: name the offline/advisory-database caveat next to the cargo-audit
  requirement.>

- docs/flow-cli-contract.md:18: drift (follows from the run-side input fixes
  above): the contract never states how `flow.run` treats undeclared or
  non-scalar inputs. <Fix: after the fix, record that run refuses
  `input_unknown` and `input_invalid` before a ticket is issued.>

Reported, not fixed (outside the allowed file set or deliberately left):

- crates/pam_daemon/src/flow_service.rs:1413: `github_owner_name` splits at the
  first `github.com` occurrence anywhere in the origin URL, so a host like
  `evil.github.com.ua` yields a bogus `owner/name` for `${repo.origin}`.
  Contained: the value only reaches connector calls as a `repo` argument, which
  scope policy (`scope_policy.rs:358`) and the GitHub adapter
  (`github.rs:313`) both re-validate, and an unapproved target is refused.
- crates/pam_flow/src/validate.rs:950: flow and step ids may start with `-`
  (spec-legal `[a-z0-9-]`), which is awkward as a CLI positional; ids come from
  file stems and changing the rule would churn digests, so left as is.
- crates/pam_daemon/src/flow_service.rs:2601: after a watch pin conflict
  (`watch_target_changed`) the step's raw result stays readable through
  `${steps.*}`; unreachable from the shipped single-step watch recipes and the
  value is already retained evidence, so noted as a residual only.
- crates/pam_flow/src/validate.rs does not flag a step whose result nobody
  reads — deliberate: evidence-bearing steps (e.g. `job_log` with
  `output: summarize`) legitimately have unread results.

## What was checked and holds (security posture, condensed)

No open security finding. The injection surfaces named in the review brief were
traced end to end: program names are bare-name validated and re-checked against
the allowlist after substitution (validate.rs:798, flow_service.rs:2074,
flow_exec.rs:535); connector argument values are percent-encoded as URL
segments (transport.rs:285) and re-validated per call (github.rs:313,
jenkins.rs:158, transport.rs:477); watch target arguments must be fixed
literals or whole input references (watch.rs:77); correlation targets require
canonical credential-free HTTPS and full 40/64-hex commits
(correlation.rs:254-343); scope admission re-checks the canonical repository
and configured base URL before every attempt and every physical HTTP hop, GET
only, with one auth-stripped HTTPS redirect hop
(connector_service.rs:812-905); repository writes are granted only to
`effect: stateful` commands (flow_service.rs:2994, command_containment.rs:224);
AWS is refused at validation (validate.rs:286) and again before any process
(connector_service.rs:963); inspection is classed read-only and never calls
the grant-creating gate path, so approval cannot be satisfied by inspection
(policy.rs:114); every recipe call name resolves through the shared
`pam_flow::connector_calls` table the connectors dispatch on, so a validated
flow cannot name an unimplemented call. `expect_empty_output`
(flow_service.rs:2246) and `role: verify` + `expect_status`
(flow_service.rs:1944) are enforced on the success path only, and a step that
fails early fails the run — neither can be bypassed into a passing outcome.

## Live exercise (agent ergonomics)

Verified against the scratch daemon: `flow list --json` paging with
`next_offset` and the 1–50 limit; `flow inspect` exits 0 with structured
blockers (`scope_denied`, `input_unavailable`, `input_unknown`,
`approval_required`, `target_unresolved`, `connector_username_missing`) and the
model block (`not_assessed` for flows without summarize); `flow run --no-wait`
always answers a ticket (exit 0); exit codes held 0/3/4/5 across success,
refusal, unresolved and blocked; `--json` never mixed prose into stdout;
`pam wait --json` on a finished ticket resolves through the durable result;
`flow result` on an unauthorized or unknown ticket is the same
`result_unavailable` refusal (exit 3), per the contract's
indistinguishability rule; `evidence read` returned the full identity envelope
(view id, digest, allowance, provenance) and refused a foreign `--request`;
the connector-less run blocked with a Settings recovery line; a repository
inside PAM's protected base was refused by containment before spawn with exit
5 and one blocked observation. Contract drift found in the live shapes is the
`credential` sentinel finding above; everything else matched
`docs/flow-cli-contract.md`.

## Built-in recipes: what each proves and cannot prove

- after-merge-checks: proves the working tree is clean and lists recent
  commits. Cannot refresh remote state under containment (fetch denied), and
  the clean-tree/recent-commits steps run regardless of the fetch failure, so
  the recipe never proves the local view is current.
- ci-failure-triage: proves a specific failed run existed and carries its jobs
  page and one job log (failure-first within the fetched page). Cannot prove
  the failure cause, cover jobs beyond the first page, or run at all without
  GitHub scope, credential and `${repo.origin}` pointing at GitHub.
- confluence-page-context: proves one explicit page was retrieved. Proves
  nothing about builds, revisions or page completeness beyond the 64 KiB body
  bound.
- dependency-audit: proves the advisory scan and duplicate-version report ran
  and their output; cannot prove absence of vulnerabilities when cargo-audit
  is missing or the advisory database could not update offline.
- guarded-land: proves the frozen revision passed GUI-configured checks and
  that each push/PR/merge/sync effect produced its exact receipt; cannot prove
  a landed branch from a prefix, cannot run any stage without the GUI landing
  policy, and its sync stage never touches the working tree.
- jenkins-build-investigation: proves the exact build's core result was
  SUCCESS. Cannot attribute a failure cause; Pipeline REST availability and
  caught/retry/post/parallel ambiguities remain observations.
- jenkins-node-evidence: proves bounded node evidence for one explicit node id
  was retrieved. Does not verify the build or assert a failure cause.
- jira-issue-context: proves one explicit issue was read. Proves nothing about
  code state; partial when the description exceeds 16 KiB.
- pam-pr-readiness: proves the PAM tree was clean and every shipped gate
  (fmt, clippy, zeromq lib tests, workspace tests, frontend lint/build/test)
  passed in sequence. Cannot prove anything outside those gates, and it is not
  bound to the PAM repository by anything but its description.
- pr-readiness: proves a clean tree and the local Rust gates; the fetch step
  (and therefore `branch-commits`) cannot run under containment, so the
  "up-to-date remote" half is unprovable as shipped.
- release-readiness: proves the tree is clean, tests pass, and lists what
  cargo would package. Cannot prove the package builds from a clean checkout
  (`--allow-dirty`, `--list` only) or that the tag policy is right.
- revision-ci-triage: proves the fetched run/jobs page and job log belong to
  the declared repository+commit via matched association. Cannot prove the
  pipeline passed, cover pages beyond the requested one, or establish anything
  when the association is unresolved.
- revision-jenkins-check: proves the build's structured SCM evidence matches
  the declared target and the core result was SUCCESS. Cannot prove it when
  SCM metadata is missing/ambiguous, and it never substitutes a latest run.
- revision-sonar-check: proves the exact analysis' historical gate was OK and
  its reported revision matched, through the GUI-owned mapping. Cannot prove
  the live project state or run without that mapping.
- sharepoint-document-context: proves one explicit drive item was read within
  bounds. Proves nothing about builds or revisions; no Office/PDF parsing.
- sonar-analysis-evidence: proves the historical gate status of one exact
  compute task. Explicitly does not verify a revision.
- sonar-gate-check: proves the live project gate was OK and, whatever it said,
  lists open issues. Cannot bind the live measurement to a commit (live gates
  are request-bound, not revision-bound).
- summarize-build-log: proves the build ran and hands back a model summary of
  its log; a skipped model leaves compact evidence only, and the summary is
  untrusted quoted data, not a diagnosis.
- watch-github-run: proves the pinned run/attempt reached `success` with a
  matched revision association. Cannot promise completion inside the poll or
  request budget, and pending polls never fetch logs.
- watch-jenkins-build: proves the pinned build reached `SUCCESS` with matched
  SCM association, subject to the same budget honesty.
- watch-sonar-analysis: proves the pinned compute task reached gate `OK` with
  its first-observed analysis id pinned, subject to the same budget honesty.

## Residual scope

The landing runtime (`flow_landing_runtime.rs`, `connector_landing*.rs`) was
reviewed at its contract and inspection boundaries; its mutation/reconciliation
internals rest on the macOS-gated integration tests and the guarded-landing and
guarded-sync specs, and were not line-audited here. The same is true of the
store-side journal, evidence and budget primitives behind the flow engine.
