# Enterprise evidence checkpoint

Plan #32's checkpoint combines the deterministic enterprise paths in one
revision-bound daemon workflow. The connector transport and credential backend
are fixtures; the daemon, policy, flow execution, correlation, store, projection
and evidence mechanisms are real. This is not live deployment qualification.

| Evidence | Required interpretation |
| --- | --- |
| GitHub run | Exact reported source repository and full revision; job logs require matched run-attempt membership |
| Jenkins build | Exact build and structured SCM identity; terminal core result determines gate outcome; node failures alone do not establish cause |
| Sonar analysis | Exact compute task and historical analysis gate; reported revision plus GUI-owned repository mapping |
| Jira issue | Validated key, modification timestamp and bounded cited description; supporting context, not revision proof |
| Confluence page | Validated page ID, storage representation and reported version; supporting context |
| SharePoint document | Authorized site/drive/item metadata, explicit content state; unsupported formats remain metadata with a limitation |

A source mismatch must stop downstream use and retain the conflicting evidence.
A successful context read cannot repair a failed quality gate or establish a
revision. Every object remains associated with the request and current access
scope controls retrieval. Fake credentials must never appear in public results.

Relevant execution proofs include:

- `pam_daemon/tests/enterprise_workflow.rs`: combined provider workflow and source mismatch.
- `pam_daemon/tests/flow_correlation.rs`: forks, retries, job membership, concurrent targets and durable retrieval.
- `pam_daemon/tests/sonar_correlation.rs`: GUI mapping, exact analysis, mid-run mapping changes and historical evidence.
- `pam/tests/context_cli.rs`: actual CLI citation, redaction and revoked evidence access.
- `pam_daemon/src/scope_policy_test.rs`: per-hop revocation, signed redirects and target scope.

Run the checkpoint using the repository-local Cargo target directory; only one
Cargo build may run on this machine. Full `tools/check.sh` validation accompanies
the implementation tasks. The checkpoint's new fixture adds cross-provider
composition coverage without replacing individual adapter and boundary tests.

Remaining work is tracked in ptrack: restart reconciliation, durable watches,
guarded landing, model admission/qualification and task-focused GUI completion.
No release or push is implied by this checkpoint. The no-C constraint is
settled (issue #16, 2026-09-12): PAM's own dependency choices stay pure Rust —
no C libraries, no cmake, no vendored C code (turso rather than rusqlite, the
zeromq crate rather than libzmq) — while the platform binding shims Tauri and
objc2 compile on macOS (the Objective-C exception helper, also required by the
Metal inference kernels) are an accepted exception, not PAM code. Deployment-
specific compatibility claims still wait until the documented live protocol is
run with authorized credentials.
