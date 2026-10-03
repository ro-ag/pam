# Design review, 2026-10-02

Review of PAM's goals, design, logic and implementation at `c8b939d` (v0.4.3), run
on the branch `fix/design-review-2026-10`. It looked past the contracts in `docs/`
to ask whether the system does what it is for: that a sandboxed agent gets
controlled, audited access to real capabilities, and that a human can see and
control it. Its trigger was a second Mac on which the daemon stopped answering
`status` and `cancel` (ptrack issue 35).

Method: five read-only area reviews, one per area: daemon core, flows and landing,
store and evidence, model and connectors, client and GUI. Each reviewer read the
code, did not run it, and labelled a finding "confirmed" when it had read the exact
path and the failure followed from it, or "plausible" when the path was confirmed
and the runtime behaviour assumed. Six fix agents then re-read every finding in the
code before touching it, recorded false positives as "not a bug", and fixed the
confirmed high and medium findings plus the small, safe lows. Fixing removed no
product surface (curator, diagnosis, connectors, flows): removal is an owner
decision and is listed below. Each behavioural fix has a regression test that fails
without it.

Severity is the reviewer's, as written. Dispositions are taken from the fix
reports: `fixed`, `partly fixed` (what remains is named), `deferred` (with the
reason in [Deferred](#deferred)), `needs owner decision` (listed under
[Owner decisions recorded](#owner-decisions-recorded)), `not a bug`, and
`superseded by the transport replacement`
([spec](../specs/2026-10-02-framed-public-transport.md)). Line references in the
tables are to `c8b939d` and have since moved.

What the changes mean for users and agents is in `CHANGELOG.md` under
`[Unreleased]`; the contract documents were edited to match.

## Daemon core

`crates/pam_daemon`, `crates/pam_proto`.

| # | Severity | Finding | Where | Disposition |
| --- | --- | --- | --- | --- |
| 1 | High | Control permits can be pinned for as long as a client's deadline and the control plane shares locks and lanes with anything slow, so `status` and `cancel` stop answering (issue 35) | `daemon.rs:764-1010`, `transport.rs:213-326`, `executor.rs:298-351` | fixed: one hard deadline around every handler, a reply guard that always answers and frees the slot, `status` served from a background snapshot, separate pools (128 work, 16 status, 16 query, 8 cancel, 32 admin-submitted), one classifier |
| 2 | High | Any public caller can force a daemon restart with a fake `client_version`; two installed versions restart it in a loop | `daemon.rs:915-935` | fixed: restart only when the daemon's own binary was replaced on disk; otherwise `client_version_mismatch`; the version is bounded at ingress; respawn uses the path recorded at boot |
| 3 | High | Non-terminal rows can be stranded forever and count toward the 128 admission cap; terminal writes are swallowed; there is no reconciler | `daemon.rs:1240-1772`, `store.rs:760` | fixed: terminal writes retry and park in a bounded queue, a reconciler closes expired rows, admission ignores rows past their deadline, panics in handlers and leased runs are caught |
| 4 | High (plausible) | Store transactions are not cancellation-safe; a dropped future leaves the connection mid-transaction | `store.rs:1085-1103`, `1985-2141` | fixed (see store and evidence, finding 1) |
| 5 | Medium | `cancel` has no authorization, and a `pam-gui` label forges a human actor in the audit | `executor.rs:396-413`, `queue.rs:620-660` | fixed: a public cancel is `system`, bound to the caller's repository, and `admin.requests.cancel` is the human's cancel |
| 6 | Medium | Attached duplicate callers are never released when the original is gate-refused or fails internally | `daemon.rs:978-1740` | fixed |
| 7 | Medium | The completion router retains every terminal response for 60 s with no entry or byte bound | `daemon.rs:259-330` | fixed: at most 256 entries and 8 MiB, oldest evicted; a late attacher reads the durable result |
| 8 | Medium | One global async mutex over the queue is held across store I/O on every path | `queue.rs:267-750` | fixed (plan 55, task 227): the lock guards only in-memory lane state; store calls run outside it with a per-request in-progress mark; the lock order is in the `queue.rs` module docs |
| 9 | Medium | A failed terminal write after a successful execution strands the lane and discards the real result | `queue.rs:605-613`, `daemon.rs:1437-1583` | fixed: the lane is released at once, the verdict parked and retried, waiters still get the real result |
| 10 | Medium (plausible) | Reply path has head-of-line blocking behind one peer and drops final replies at shutdown | `transport.rs:360-389` | superseded by the transport replacement |
| 11 | Medium | The `echo` test hook is a production lane-hog primitive reachable by any caller | `executor.rs:368-378` | fixed: delay over 60 s or arguments over 64 KiB refused (`echo_limit_exceeded`) |
| 12 | Medium | The admin listener dies silently on a transient accept error and shares the public admission pools; a local process can hold the Windows pending-handshake slots | `admin_transport_unix.rs:186`, `admin_transport_windows.rs:214` | partly fixed: accept errors retried with backoff and admin-submitted requests have their own pool (Unix tested; the Windows file was edited without a Windows compile); the pending-handshake exhaustion is deferred to the new listener |
| 13 | Medium-low | Two sources of truth for the policy profile; `admin.profile.set` applied at the next start | `policy.rs:173-195`, `admin.rs:395-421` | fixed: the gate holds the live profile and `admin.profile.set` swaps it (`"applies": "now"`) |
| 14 | Low-medium | Audit gaps for refusals; every `status` poll writes a request row, an audit row and a caller row | `daemon.rs:911-1010`, `admin.rs:285-306` | fixed: `status` is ledger-free, and refusals decided before admission are recorded in their own table and listed in Activity (see [the audit contract](../admin-boundary.md#the-audit-contract-request-rows-and-refusal-rows)) |
| 15 | Low (plausible) | Approval resolve can report success for an approval recorded as timed out | `approval.rs:159-211` | fixed: `resolve` waits for the waiter's acknowledgement, sent after the resolution is durable |

## Flows and landing

`crates/pam_flow`, the daemon's flow and landing files.

| # | Severity | Finding | Where | Disposition |
| --- | --- | --- | --- | --- |
| 1 | High | Stateful steps may write `.git/hooks` and `.git/config` of the real checkout | `command_containment.rs:224-239` | fixed: Git's control surface (the `.git` entry, hooks, config, commondir, in submodule and worktree directories and through gitfile redirects) is denied for writes; objects, index, refs and logs stay writable |
| 2 | High | Approval and grants bind to a name (`flow.step:<flow>/<step>`), not to what runs | `flow_service.rs:238`, `policy.rs:246-263`, `approval.rs:278-285` | partly fixed: saving or deleting a flow revokes grants of changed steps, `flow.run` can be pinned to a digest, an approval is pinned to the resolved command; a flow edited outside the admin surface keeps its grants, and a grant is still global (needs an owner decision: store migration) |
| 3 | High | Guarded landing can strand a ticket after the irreversible merge, with no flow path to finish | `flow_landing_runtime.rs:19-20`, `729-752` | fixed: a new ticket finishes a landing whose PR is already merged at the frozen head; since ptrack task 224 PR and main verification back off from 5 s, doubling to a 60 s cap with jitter, until the request deadline ([guarded landing](../guarded-landing.md#durable-effects-and-bounded-waiting)) |
| 4 | Medium | The credentialed, uncontained git broker is resolved from user-writable PATH-first directories | `flow_landing_runtime.rs:216-231`, `landing_git.rs:155-188` | fixed (task 224): never looked up on `PATH`; an explicit `git_path` (GUI or managed `landing.git_path`) else a fixed allowlist, each refused unless the file and every ancestor are owned by root or the daemon's user and not group/other-writable; the pin is recorded at freeze and checked before every Git process ([guarded landing](../guarded-landing.md#configure-and-inspect)) |
| 5 | Medium | Substituted values reach argv with no argument-shape guard | `validate.rs:839-860`, `vars.rs:95-113` | partly fixed: a substituted value that would become an option blocks the step; typed inputs are an owner decision |
| 6 | Medium | Effect intent is journaled before the approval gate, so a cancel during the approval wait reads as `flow_effect_uncertain` | `flow_service.rs:1666-1676` | fixed: the intent is journaled after the gate allows the step (a narrow window between arming and spawn remains) |
| 7 | Medium | Default `when: needs_succeeded` is vacuously true, so later steps run after a failure | `flow_service.rs:1753-1766` | partly fixed: a stateful step with no `needs` no longer runs after a failure; a read-only step with no `needs` stays independent, by design (an owner may prefer a stricter validation) |
| 8 | Medium | Timeout and cancel kill only the child pid | `flow_exec.rs:456-476` | fixed: the whole process group is killed on timeout, cancel, output limit and abandonment (a `setsid` descendant escapes) |
| 9 | Medium | The verdict hides that an effect happened, and a landing prefix reads as a full landing | `flow_exec.rs:192-222`, `flow_contract.rs:100-290` | fixed: `effects` beside the outcome; the claim that an all-skipped run is `solved` is not a bug |
| 10 | Medium-low | PR create and merge rejections are recorded as uncertain; merge method is hard-coded | `flow_landing_runtime.rs:360-412`, `github_landing.rs:369` | fixed (task 224): typed `ConnectorError::Rejected` for 405/409/422, so the intent is `rejected` and the step blocks; the merge method is a landing setting (`squash` default, managed `landing.merge_method`) |
| 11 | Medium-low | `${...}` in `env:` is validated but never substituted; env can override isolation variables | `validate.rs:786-799`, `flow_service.rs:2137` | partly fixed: substituted at run time; reserving `PATH`, `HOME` and `GIT_CONFIG_*` is an owner decision |
| 12 | Low (plausible) | The daemon writes into an agent-writable `.git` after a stale layout check (symlink swap) | `landing_git.rs:565-650`, `1113-1251` | partly fixed: each directory is walked and checked immediately before each write; a swap in the instants between walk and write remains |
| 13 | Low | Required PR and main checks are matched by name only | `github_landing.rs:385-465` | fixed (task 224): checks can be pinned as `{ name, app_id }`; a same-named check from another app or a commit status never satisfies a pinned one; name-only checks show "Unpinned app" |
| 14 | Low | Stringly-typed, duplicated state machines | `flow_landing_runtime.rs:39-44`, `landing_session.rs:97-108`, `flow_contract.rs:391-409` | fixed (plan 55, task 227): one `request_state` transition table used by every writer, one `EffectIntent` type, and a pure gate function shared by `flow.inspect` and the run; `flow_service.rs` split into a `StepExecutor` per step kind |
| 15 | Low | The compact result drops the last steps first | `flow_contract.rs:292-304` | fixed: succeeded and skipped observations are dropped first |
| c1 | Carry-over | `github_owner_name` matches the first `github.com` anywhere in the origin URL (reported in the 2026-09-16 flow review) | `flow_service.rs:1413` | fixed: the host must be exactly `github.com` |

## Store and evidence

`crates/pam_store`, `crates/pam_compact`, the daemon's evidence files.

| # | Severity | Finding | Where | Disposition |
| --- | --- | --- | --- | --- |
| 1 | High (plausible) | `BEGIN..COMMIT` is not cancel-safe; one dropped future wedges the only connection | `store.rs:1097-1102`, `1990-2039`, `2127-2141` | fixed: the mutex owns the connection (`conn_gate.rs`), a call that finds an open transaction rolls it back first |
| 2 | High | The 16 KiB `map_json` cap against a 100,000-segment map makes failing logs lose their views and the ticket `unavailable` | `evidence_views.rs:6`, `127-137` | fixed: its own bound (8,192 segments, 1 MiB), deterministic coarsening, a notice view when preparation fails |
| 3 | High | Security-relevant mutations are not atomic with their audit row; terminal and audit writes discard errors | `admin.rs:449-482`, `753-805` | fixed: single-transaction store methods adopted by the daemon |
| 4 | High | The GUI's polling creates unbounded request and audit rows, and no index supports the hot list query | `bridge.rs:325-335`, `queue.rs:321`, `store.rs` | fixed: indexes (schema 12) and ledger-free `status`; admission ignores expired rows |
| 5 | Medium | The grant revocation revision is a global count; any revoke orphans every older ticket's results and evidence | `store.rs:704-757`, `evidence_service.rs:175-182` | fixed: scoped to the grants a request depends on; since task 222 `request.flow_id` is written at admission (schema 17) and a step revocation voids only that flow's tickets. Revoking is per capability, so it ends that step's grant for every repository |
| 6 | Medium | `update_request_state` can resurrect a terminal request | `store.rs:1055-1062` | fixed: returns `AlreadyTerminal` and writes nothing |
| 7 | Medium | Head-of-line blocking: hashing, large blobs and unbatched sweeps run while holding the connection lock | `store.rs:1837`, `evidence_views.rs:141-165`, `1985-2075` | partly fixed: hashing moved before the lock, prunes batched, the read connection built (T7 of the [SQLite plan](../specs/2026-10-02-sqlite-store.md)); chunked view storage done (schema 20, task 228: 64 KiB chunks, a page of a 32 MiB view 3.8 ms to 0.17 ms in release); since plan 56 the first scheduled prune waits two minutes after boot (`FIRST_PRUNE_DELAY`) |
| 8 | Medium | "One audit row per operation, refusals included" is not structural: pre-admission refusals leave no row | `migrations.rs:153`, `daemon.rs:792-963` | fixed: the `refusal` table (schema 18) holds them, coalesced and bounded, and `admin.activity.list` interleaves them; what is still unrecorded is listed in the audit contract |
| 9 | Medium | Immutability of audit and evidence is by convention only | `migrations.rs`, `store.rs:1265-1289` | fixed: triggers make `audit` append-only and `evidence_view` immutable except retention's tombstone; since task 228 one terminal audit row per request by a partial unique index (schema 19), served bytes re-hashed per chunk (`evidence_corrupt`), and `evidence_view.source_id` a foreign key with a CHECK that a live view has its evidence (schema 20) |
| 10 | Medium | Retention is irreversible, runs on an unvalidated wall clock, and its settings flow is non-atomic | `retention.rs:200-216`, `store.rs:2075-2089` | fixed: an out-of-range stored window reads as forever, both windows save in one transaction; since task 221 a clock guard with a watermark refuses to prune after a forward clock jump and `admin.retention.get` reports it |
| 11 | Medium | A beta engine under the audit and authorization spine: no integrity check, no backup, no fallback, engine types leak | `migrations.rs`, `store.rs:592`, `lib.rs` | partly fixed: boot `quick_check` (files up to 256 MiB), on-demand check, corruption mapped to a legible error; backup, export and an alternate backend need an owner decision (decided 2026-10-02: SQLite, [spec](../specs/2026-10-02-sqlite-store.md); backup in its T2) |
| 12 | Low | Evidence range edge cases: end-of-view reads error, a NULL blob pages forever | `evidence_views.rs:223-244` | fixed |
| 13 | Low | Crash-window leftovers: ghost pending approvals, orphan checkpoints, unrecoverable journal | `lifecycle.rs:218-246`, `store.rs:1595` | fixed: finished requests' approvals are hidden and the approval insert is atomic; since task 228 journal and checkpoint are one transaction (journal first) and boot recovery removes checkpoints without a journal (`flow.checkpoint_orphaned`) ([workflow recovery](../workflow-recovery.md#durable-boundary)) |
| 14 | Low | Version skew: a stale client makes a newer daemon drain and restart | `migrations.rs:91-96`, `daemon.rs:915-935` | fixed (daemon core, finding 2) |
| 15 | Low | Compaction: "reversible" depends on retained, optional artifacts; the failure keyword set is narrow | `log_service.rs:287-323`, `pam_compact` | deferred (recorded only) |
| x | Found while fixing | Boot recovery came within 8 KiB of a 2 MiB test-thread stack in a debug build | `store.rs` recovery queries | fixed: three deep expressions flattened; a test pins a 1.5 MiB budget |

## Model and connectors

`crates/pam_model`, `crates/pam_connectors`, the daemon's model and connector files.

| # | Severity | Finding | Where | Disposition |
| --- | --- | --- | --- | --- |
| 1 | High | Weight "verification" is an unauthenticated sidecar beside the file, and load never re-hashes | `registry.rs:307-471`, `model_service.rs:595` | partly fixed: the record lives in `<base>/model-trust` with a file fingerprint checked before and after load; a swap between the check and the engine's open is narrowed, not closed (a private copy of the weights is an owner decision) |
| 2 | High (conditional) | The curator executes PATH-resolved vendor CLIs with the daemon's full environment | `curator.rs:167-390`, `admin_models.rs:762` | fixed: trusted install directories, ownership checks, minimal environment; the curator is kept |
| 3 | Medium | The engine API key travels on argv | `engine_server.rs:407-409` | fixed: `--api-key-file`; the pinned build's acceptance of the flag is unconfirmed (the opt-in real-engine test has not been run) |
| 4 | Medium | Port pick-then-bind race, and the identity check does not close it (issue 36) | `engine_server.rs:223-371` | fixed: bind grace, wrong-key proof, retry on a fresh port |
| 5 | Medium | A dead engine is never noticed and an orphaned engine is never reaped | `engine_server.rs:146-245`, `model_service.rs:434-698` | fixed: dead-child detection with `engine_exited` and reload, a pid file, orphan reaping at boot |
| 6 | Medium | The advisory model sits on the flow's critical path with a 15-minute, uncancellable, globally serialized call | `model_service.rs:612-1197`, `log_service.rs:473-515` | fixed: 5 minutes in all, 2 minutes in the engine, cancel threaded from the flow step |
| 7 | Medium | The summary prompt mixes the host's exit status with untrusted log text, and the summary reaches the agent unlabelled | `compact.rs:657`, `log_service.rs:42-648` | fixed: host facts in the system turn, evidence fenced by a per-call token, `[untrusted local-model summary]` in the CLI; the GUI summary is still unlabelled |
| 8 | Medium | The structured diagnosis stack has no production caller and two latent authority bugs | `diagnosis_service.rs:512` | partly fixed: both latent bugs fixed; wiring or deleting the stack is an owner decision |
| 9 | Medium | Two curl launchers with divergent policy; connectors cannot be configured for enterprise networks | `curl.rs:154`, `download.rs:818-853` | fixed (2026-10-02, [enterprise network and engine delivery](../specs/2026-10-02-enterprise-network-and-engine-delivery.md)): one launcher in `pam_net` with a constant argv, a cleared environment and https-only; daemon-owned proxy, no-proxy, CA bundle and mirror settings set in Settings › Network, applied to connectors and downloads alike; no environment variable is read. Since 2026-10-03 an organization can lock or default them with the [managed policy file](../specs/2026-10-02-managed-policy-file.md) |
| 10 | Low-medium | The log redirect hop has no host or port constraint, and a second weaker redirect implementation exists | `connector_service.rs:876-902`, `curl.rs:320-339` | partly fixed: IP literals, local-looking names and ports other than 443 refused; since 2026-10-02 every redirect, download and mirror hop may only go to https (`proto-redir`), mirror hosts must be https and never loopback or link-local, and a managed `mirror_allowed_hosts` allowlist exists for mirrors (delivered by the managed policy file since 2026-10-03); a strict host allowlist for the log redirect itself is still an owner decision |
| 11 | Low-medium | Credentials are stored untrimmed; control characters round-trip into the header | `admin_connectors.rs:307`, `curl.rs:218-406` | fixed |
| 12 | Low | One hung keychain prompt stalls every connector | `blocking_jobs.rs:151`, `secrets.rs:631` | fixed for reads (20 s bound); writes stay unbounded; a per-request credential cache is deferred |
| 13 | Low | The AWS refusal is a single `if` in the daemon; the adapter is unsafe if it moves | `connector_service.rs:514`, `aws.rs:126-287` | fixed: the adapter's one spawn point refuses; deleting or containing the adapter is an owner decision |
| 14 | Low | Silent `.` and `..` dropping makes the fetched resource differ from the audited identity | `transport.rs:285-295` | fixed |
| 15 | Low | Every resolve rescans and reparses all GGUF headers on a lane shared with the multi-GB hash | `registry.rs:210-367`, `blocking_jobs.rs:152` | fixed: header cache per file fingerprint, a 1 KiB key cap, a separate hash lane |

## Client and GUI

`crates/pam`, `crates/pam_client`, `crates/pam_gui`, `frontend/`.

| # | Severity | Finding | Where | Disposition |
| --- | --- | --- | --- | --- |
| 1 | High | The GUI beacon feeds on its own status polls: a self-sustaining refetch loop that eats the control budget (likely cause of issue 35) | `useDaemonStatus.ts:66-72` | fixed: throttled refreshes, own requests filtered from the event stream, per-command timeouts, backoff while the daemon is busy or down |
| 2 | High | Any public-socket peer can drain, cancel and restart the daemon by lying about `client_version` | `daemon.rs:915-935` | fixed (daemon core, finding 2); the client waits out the handover |
| 3 | High when it applies | A plain build of `pam gui` loads `http://127.0.0.1:1420` with the full admin bridge | `build.rs:4-9`, `Cargo.toml:9-13` | fixed (task 229): a build without the embedded frontend refuses to start `pam gui` unless `PAM_GUI_DEV=1` asks for the development server (`pam_gui::frontend`) |
| 4 | Medium-high | `pam wait` and `subscribe` turn a transient refusal into exit 3 and abort on protocol noise | `client.rs:664-674` | fixed |
| 5 | Medium | The daemon-ready probe is true during boot when a stale `pam.sock` exists | `client.rs:237-242` | fixed (the reviewer's premise that the first connect does not retry was partly wrong: a dead socket parked every command for 30 s, now 5 s) |
| 6 | Medium | Lazy start runs the daemon as a plain child of the caller: environment, directory, process group | `client.rs:279-288`, `main.rs:857` | fixed: environment allowlist, `/` as the directory, own process group, reaper thread (the Windows creation flags are untested) |
| 7 | Medium | The Activity view hides forged admin attempts | `store.rs:1440-1446` | fixed (store) |
| 8 | Medium | The approval card shows the submitted args, not what will run, and trusts unauthenticated strings | `Approvals.tsx:147-160` | fixed: resolved-command snapshot pinned by digest, one token per argument, hidden characters escaped |
| 9 | Medium | The webview is a full-admin root: `admin_call` and `request_capability` are generic passthroughs | `bridge.rs:355-372` | fixed: a typed confirmation checked in Rust for relaxed, grant, remember and the network proxy and CA bundle, `request_capability` removed, and (2026-10-03, ptrack task 226) a native "Confirm in PAM" dialog the bridge draws from Rust with a sentence built from the op's own arguments, the op sent only on Allow; the webview holds no dialog permission. A same-user process with UI automation could still press Allow; the sandbox must exclude it |
| 10 | Medium | `pam service install` pins whatever binary and environment the caller has, and `status` cannot detect a stale pin | `main.rs:134-510` | fixed: refusals for temp, build and writable binaries, explicit `--base-dir`, `pinned_exe` and `stale` in the report |
| 11 | Medium | Session relay: an accept error kills the relay; no connection bounds; chmod and bind follow symlinks | `relay.rs:168-211` | fixed: accept errors retried, 64 connections per socket, bounded dial, and `prepare` refuses a symlinked or foreign directory, a symlinked, foreign or non-socket `pam.sock` entry and replaces only a stale socket it owns (the same-user check-then-bind race is narrowed, not closed: std has no `bindat`; documented in the relay doc) |
| 12 | Medium | A synchronous request that times out leaves work running with no request id printed | `main.rs:598`, `701` | fixed: the id and the `pam wait` recovery are printed; a random idempotency key was rejected on purpose because it would defeat the daemon's shape dedupe |
| 13 | Low-medium | The version handshake is semver-string only and its retry does not land on the new daemon | `client.rs:496-500` | fixed |
| 14 | Low-medium | The audit actor trusts a forgeable label, and the real GUI never gets it | `executor.rs:402-406` | fixed (daemon core, finding 5; the GUI cancels through `admin.requests.cancel`) |
| 15 | Low (plausible) | Smaller issues: (a) Ask Pam rephrase accepts extra text, (b) `flows.save` has no expected digest, (c) Stop daemon is a no-op while the GUI polls, (d) `kill` is resolved through `PATH`, (e) `subscribe --json` interleaves text, (f) `detect_caller` per poll | `rephrase.ts:40-60`, `ipc.ts:1206`, `client.rs:789-797` | fixed: (a) the rephrase must have the template's shape; (b) `admin.flows.save` takes `expected_digest` and refuses `flow_changed`; (c) Stop keeps the daemon down until the human presses Start; (d) absolute `kill` (the test helper too); (e) `subscribe --json` writes JSON only; (f) the caller identity is detected once per process |

## Owner decisions recorded

These are product-level questions the review raised and the fixes deliberately did
not settle. The first five are ptrack issues 38 to 42.

1. **No C dependencies, and turso under the audit spine (issue 38).** The rule
   that PAM links pure Rust keeps the store on a beta engine that carries the
   audit and authorization data. The fixes added a boot integrity check, an
   on-demand check and a legible corruption error, plus triggers for append-only
   audit rows. Still open: a pre-migration backup, an export, and whether to keep
   a fallback backend.
   **Decided 2026-10-02: SQLite.** The store runs on real SQLite, bundled through
   `rusqlite`, and SQLite becomes a named exception to the no-C rule beside the
   Tauri and objc2 shims. The one-time pre-upgrade backup, the full check on
   first open and the downgrade refusal are part of the plan; an alternate
   backend is not planned. Design and plan:
   [the SQLite store spec](../specs/2026-10-02-sqlite-store.md).
2. **The public transport (issue 39).** Decided 2026-10-02: replace ZeroMQ with the
   framed protocol the administration plane already speaks, on the same socket
   path, with per-connection events and the kernel's view of who connected. The
   design and its four resolved questions are in
   [the spec](../specs/2026-10-02-framed-public-transport.md); ptrack plan 49
   carries the work.
3. **Platform and connector breadth against one live end-to-end flow (issue 40).**
   PAM carries six HTTP connectors, an AWS adapter that is refused, a flow
   designer, a curator, diagnosis and a landing recipe, on five targets of which
   only macOS has command containment. The review asks whether depth on one
   supported flow, verified live, should come first. Not changed.
4. **The boundary depends on an agent sandbox PAM neither installs nor verifies,
   and authority is global rather than per project (issue 41).** Grants, scopes and
   approvals apply to every public client; labels are attribution. The fixes
   narrowed what a label can do (cancel, restart) but not who may use a grant.
   Per-agent or per-project authority, and whether PAM should install or verify a
   sandbox profile, remain open.
   **Resolved 2026-10-02 (ptrack plan 53).** Verification: `pam doctor` probes
   the boundary from the caller's position, the daemon records the report and
   its own observations of the private plane (a `boundary` block in `status`),
   and reference sandbox profiles per harness ship with it; PAM still does not
   install or lock the harness's sandbox. Per-agent authority: not built, by
   decision. Authority is per operating-system user; caller labels, pids and
   executable paths are attribution, never a boundary; agents that need
   different authority run as different users; `pam doctor` proves each one's
   sandbox. Windows has no supported configuration that establishes the
   boundary, and the documents say so. Design, decisions and the as-built
   record: [the boundary self-check spec](../specs/2026-10-02-boundary-self-check.md);
   the statement itself: [the administration boundary](../admin-boundary.md#global-target-authority).
   Plan 53 also found that the engine's socket and API key live in the run
   directory (issue 44); the profiles deny them and the relocation is filed.
5. **Proportion of the model layer (issue 42).** The curator, the structured
   diagnosis stack (no production caller), the readiness ladder and the catalog
   are large against what runs in production, which is prose summaries. The fixes
   hardened them and removed none.

From the fix reports:

- Bind a grant to a flow digest, step and effect class, so a flow file edited
  outside the admin surface cannot keep its approvals, and decide whether a grant
  should be bound to a repository or to input values (a store migration).
  **Done 2026-10-03 (ptrack task 222, schema 17)**: a flow step's grant is bound
  to the step's effect digest (from the normalized step), its gate class and the
  canonical repository, not to input values; a mismatch asks again and says what
  changed; legacy grants bind on first use. See
  [the administration boundary](../admin-boundary.md#confirmation-in-the-gui-bridge).
- Narrow a flow step revocation to the flow's own tickets, which needs the flow id
  recorded on the request row at admission. **Done 2026-10-03 (task 222)**:
  `request.flow_id`; rows admitted before it still fail closed.
- Pin the credentialed git broker to a root-owned Git, which would refuse a
  Homebrew Git, against an explicit GUI-set path. **Done 2026-10-03 (ptrack task
  224)**: an explicit `git_path` or a fixed allowlist, owned by root or the
  daemon's user with no group/other write on the file or any ancestor; a
  Homebrew Git qualifies only when its directories are not group-writable, which
  a default Homebrew is not.
- Replace the fixed 20 x 5 s landing poll budget with backoff to the request
  deadline (changes `docs/guarded-landing.md`). **Done 2026-10-03 (task 224)**.
- Make the merge method a landing policy field and choose its default; require
  `{ name, app_id }` for required checks. **Done 2026-10-03 (task 224)**:
  `squash` by default, lockable by the managed `landing.merge_method`; pinned
  checks are `{ name, app_id }`, name-only checks still run labelled "Unpinned
  app".
- Add typed flow inputs (`ref`, `sha`, `path`, `int`); reserve `PATH`, `HOME` and
  `GIT_CONFIG_*` in step `env:`; or refuse at validation a non-first stateful step
  with neither `needs` nor `when`.
- Retention policy for a forward clock jump (a maximum jump or a trusted time
  source).
- A private copy of the model weights to close the swap window between the
  fingerprint check and the engine's open.
- Daemon-owned proxy and certificate settings so connector reads and downloads
  work on an enterprise network, and unifying the two curl launchers.
  **Done 2026-10-02** ([spec](../specs/2026-10-02-enterprise-network-and-engine-delivery.md)):
  Settings › Network, `pam_net`, mirrors, install from a file, import weights
  from a file, remove engine, and the disclosure on the engine card and in the
  README that closes ptrack issue 43 (the owner had not been told that
  inference runs a downloaded `llama-server` process).
- Managed settings for enterprise fleets: the network spec deferred "the policy
  file itself", so an organization could not lock or default what a person
  sets. **Done 2026-10-03 (ptrack plan 54,
  [managed policy spec](../specs/2026-10-02-managed-policy-file.md))**: one
  read-only JSON file at a fixed root/Administrators-owned path, trust-checked
  before use, that can lock, default, bound or allowlist every settings document
  (profile, grants, scopes, connectors, flows, landing, models, retention,
  network) and add organization-only constraints; Settings shows each managed
  value; a damaged or untrusted file never loosens anything; `pam policy check`
  validates a file before the push and checks it on the endpoint. Delivery
  guide: [docs/policy/](../policy/README.md).
- A strict host allowlist for log redirects (mirrors have a policy-only
  allowlist since 2026-10-02; the log redirect hop does not).
- Bind the model qualification record to the prompt and server options, so a
  change in framing drops the "qualified" badge.
- Whether the AWS adapter stays, is contained, or is deleted.
- A native confirmation dialog for authority-expanding admin operations (the
  bridge's typed phrase does not stop a compromised webview). **Done 2026-10-03
  (ptrack task 226)**: the owner approved `tauri-plugin-dialog`; the bridge
  shows a native "Confirm in PAM" dialog from Rust, with a sentence it builds
  from the op's arguments, after the typed phrase, and sends the op only on
  Allow (`confirmation_declined` on Cancel); the webview is granted no dialog
  permission. A same-user process that can drive the user interface could still
  press Allow, which the sandbox must exclude; see
  [the administration boundary](../admin-boundary.md#confirmation-in-the-gui-bridge).
  Before that, on a managed machine the policy already narrowed it: a key the policy locks or bounds (a
  `strict` profile, `grants.manual: deny`, `grants.remember: deny`, never-grant
  rules) is refused by the daemon whatever the webview sends, so a compromised
  webview cannot widen it (2026-10-03, plan 54). Whether Stop daemon should stay a
  no-op while the GUI is open is **decided and done (2026-10-03, ptrack task
  229)**: Stop keeps the daemon down until the human presses Start or the window is
  restarted, and the window's polls only look.

## Deferred

Not done, with the reason. Items marked done were closed by plan 55 (PR 170) or later.

- **Windows pending-handshake slots** (daemon core 12): the Windows listener was
  replaced by the framed transport (plan 49), which has its own bounds.
- **`watch_target_changed` raw results readable through `${steps.*}`** and builtin
  descriptions that over-promise `git fetch`: unreachable from shipped recipes, and
  description text only.
- **A delayed first prune** (store 7). **Done** (plan 56): two minutes after boot.
- **Compaction reversibility and keyword set** (store 15): code outside the
  store's files.
- **The branch of the integrity check that fails after a successful open** (store
  11): no such file could be constructed, so it is untested.
- **A dedicated `client_version_mismatch` message in the client and a Settings
  surface in the GUI**. **Done** (task 229).
- **Unifying the two trusted-curl path checks** (model 9). **Done 2026-10-02**: the
  leaf crate `pam_net` owns the one check and the one launcher.
- **A per-request credential cache, and a bound on keychain writes** (model 12):
  reads are bounded at 20 s; writes are not.
- **The development-build GUI URL** (client 3). **Done** (task 229, `PAM_GUI_DEV=1`).
- **A GUI label on model summaries**. **Done** (task 220): the step summary carries
  the same untrusted-summary label as the CLI.
- **A measurement of the summary prompt contract**: the qualification badge
  certifies the capability bench, not the summary prompt (plan 55 decision, task
  220).
- **Not run:** the opt-in real-engine test that would confirm `--api-key-file` on
  the pinned build. Windows is no longer unverified: plans 48 to 55 ran the
  workspace suite in a Windows 11 ARM64 VM and on both Windows CI targets, and
  command containment is reported unavailable there (`status.containment`, plan 56).

## Verification

Each fix agent ran targeted tests and clippy on its crates and recorded the commands
in its report. The full local gate (`tools/check.sh`) runs on the branch before the
merge and is not restated here.
