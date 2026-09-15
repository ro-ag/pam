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

## Plan 30 final checkpoint (task #94, 2026-09-15)

What was verified on `main` at ac92690 (plus the docs of this checkpoint):

- **Local gate.** `tools/check.sh` on the merged tree: fmt, clippy `-D warnings`
  across every target, the bounded ZeroMQ codec tests, `cargo test --workspace`,
  frontend lint, `tsc` + Vite build, and 630 vitest across 38 files — green
  on 2026-09-15. Main CI is green for b5e6092 (run 34970288211) on the gate, macOS,
  Ubuntu ARM and both Windows targets; the ac92690 main run is 34974171920.
- **Agent path, CLI only** (task #124, same day): `flow inspect` named every
  blocker with a recovery line; `flow run --no-wait`, `wait` and `flow result --json`
  returned the bounded `AgentResult` with the handoff; `evidence read` followed
  `next_action` verbatim and returned digested, provenance-bearing rows; the one
  qualified model (gpt-oss-20b-MXFP4 on llama.cpp b10938, macOS arm64) summarized a
  real cargo failure and said what it could not determine; with the heavy default
  cleared the same flow reported `model_skipped: no_default` and ran the
  deterministic path.
- **Admission.** Verified but unmeasured weights are refused as a tier default with
  cause `unqualified`, unverified ones with `unverified`, live on the real models
  directory; the daemon's readiness record and the GUI agree on the same verdict
  ([model qualification decisions](model-qualification-decisions.md)).
- **Broker authority and evidence** stay as recorded above (task #120); no
  transport, GUI framework, connector framework or chatbot was added.

Named blockers — acceptance is not claimed for these:

- **Native app capture.** The owner denies computer-use control of the PAM app,
  and a window on another Space captures blank. GUI verification ran through the
  Vite fixture shim on the daemon's real `admin.models.status` and `list` replies,
  not on the installed native binary.
- **32 GB hardware.** No 32 GB machine exists; every memory figure in the
  benchmarks comes from a 64 GiB M4 Max and is labelled so. Memory is not a gate
  (owner, 2026-09-13/14) and task #137 stays parked.
- **Live enterprise connectors.** GitHub, Jenkins, Sonar, Jira, Confluence,
  SharePoint and JFrog are proven against fake transports and a real-curl local
  origin; a live run needs the owner's tokens entered in Settings → Connectors.
- **Windows.** Excluded by the owner on 2026-09-15: issues #22 (no admin adapter),
  #24 (connector save-and-test on CI), #110 (`pam wait` race) and #31 (one
  `curl_origin` flake on windows-11-arm, main run 34959772710) remain open.

Residual issues carried forward at the checkpoint, and their disposition the
same day (plan 38): #4 retired after a 30-minute churn on the current build
(1,581 fresh connections, 316 abandoned subscribers, descriptors flat, every
probe instant; the 2026-09-03 wedge predates #102's publisher fix — reopen with
a fresh sample if a post-#102 daemon stops answering); #28 closed (a refused
download start now unlocks its transfer lock explicitly, PR 142); #29 closed
(observations and the summary evidence identity name the model and the record
that admitted it, PR 141); #30 closed (`flow.inspect` and `pam status` carry the
tier readiness verdict, PR 140). Plan 39 then closed #32: a follower's `query`
landing between a running flow's evidence insert and its view publish had been
refused as `result_unavailable`; the store now tells an unpublished view
(pending while the request runs) from a view under another repository (never
readable), PR 145. Open after plan 39: the Windows set only. `pam_daemon::diagnosis_service`
still has no production caller — a product decision, not dead code.

No release, tag or push is implied by this checkpoint.
