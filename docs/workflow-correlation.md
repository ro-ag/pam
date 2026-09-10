# Exact workflow evidence

PAM can bind a flow request to an explicit repository URL and full commit before
collecting product evidence. This is deterministic; no model selects the target.
The `revision-jenkins-check` and `revision-ci-triage` embedded flows expose this
contract. Existing discovery flows remain unbound.

```yaml
correlation:
  repository: "${inputs.repository}"
  commit: "${inputs.commit}"
```

An optional `pull_request` and `pull_request_head` must appear together. References
must be whole declared input or supported repository values, never step output.
Commit IDs must be full nonzero 40- or 64-digit hexadecimal values. Repository
URLs currently require HTTPS and reject credentials, queries, fragments and
ambiguous paths. Host case and default port are normalized; path case and `.git`
are preserved. SSH/SCP aliases are not silently equated with HTTPS. Supply the
product's exact HTTPS repository identity or expect an unresolved association.

## What the execution proves

The store freezes the request's local repository, flow digest and declared target
before collection. Each successful connector response is associated before its
values become available to subsequent steps. A missing or conflicting association
blocks the step, retains the response as evidence and prevents downstream use.
Retries cannot overwrite the original association. A changed intended target
requires a new request. Run reports retain the target and step decisions; compact
CLI results include a target digest, revision and association status. Inspection
resolves the declaration without executing it and reports unavailable inputs.

GitHub compares the run's reported head repository and full source revision,
including fork identity. Optional PR number/head pins are checked separately.
A job log must belong to a job listed by an already matched run attempt on the
same configured server and repository. Job names and latest-run discovery cannot
establish that association. Job IDs are sorted before immutable comparison, so
status-driven ordering changes do not alter identity. A changed returned job set
currently requires a new request; durable watch reconciliation must handle this
explicitly rather than substituting a later attempt.

Jenkins uses structured SCM actions from the explicitly requested build. Missing,
invalid, partial or multiple SCM identities remain unresolved. Log text cannot
supply missing authority. The build's authoritative result remains separate from
SCM association and from uncertain failure attribution.

Live Sonar project/branch measurements do not prove the requested commit.
The separate [exact analysis operation](sonar-analysis.md) joins an explicit
compute task, historical analysis and reported revision with a GUI-owned
repository mapping. Documentation and issue reads may supply unbound supporting context;
they cannot certify a revision. Artifact publication has no association contract
until a supported adapter provides immutable artifact identity.

## Limits and implementation guidance

A matched association proves provenance, not that CI passed. The Jenkins starter
also requires a terminal SUCCESS result. The GitHub starter gathers evidence and
makes no whole-pipeline success claim. Local command verification is refused in
revision-bound flows because it has no authenticated local revision binding;
guarded landing must separately recheck
HEAD, worktree state, approvals and remote identities before mutation.

Target records are bounded to 16 KiB; each step binding to 8 KiB, with at most 64
bindings and 512 KiB aggregate. Storage failures block publication. Existing scope,
redaction, expiry and evidence retrieval rules continue to apply. Targets and
associations never grant connector, filesystem or mutation permissions.

Implementers must preserve evidence on refusal, avoid latest-run substitution,
and test retries, fork/host mismatches, missing SCM and simultaneous targets. Use
`ptrack context` first; task #129 tracks this foundation, #130 Jenkins context,
#131 exact Sonar analysis, #133 reconciliation and #135 guarded landing.
