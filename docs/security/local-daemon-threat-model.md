# PAM local daemon threat model

## Overview

PAM is a local-first companion for developers and coding agents. Its current
runtime is one Rust application with CLI, foreground-daemon, and GUI-shell
modes. The implemented daemon authenticates callers, enforces project-scoped
capability policy, schedules durable work in SQLite, retains exact evidence in
a content-addressed store, reads bounded project continuity from `ptrack`, and
returns typed results over a local ZeroMQ transport. Native credential storage,
native certificate trust, sanitized proxy diagnostics, a durable audit ledger,
explicit retention controls, verified user-owned model registration, and
bounded direct llama.cpp inference are also implemented.

Connector effects, service-manager integration, signed peer registration,
Unix peer-credential checks, and Windows named pipes are planned, not current
security controls. The Tauri control center is an implemented presentation
boundary over typed Rust commands; it does not receive caller credentials,
raw project identifiers, or unrestricted filesystem authority. Model inference
uses the existing authenticated PAM IPC protocol and an in-process
Rust/llama.cpp adapter; there is no HTTP model listener or bearer-token export.

This model covers the whole repository, while concentrating on deployed runtime
code under `crates/` and the Tauri shell under `src-tauri/`. The React frontend
is a presentation layer and is not a production security boundary.

## Threat Model, Trust Boundaries, and Assumptions

### Assets

- Caller credentials in the operating system's native credential store and
  their SHA-256 verifiers in SQLite.
- Project identities, capability grants, explicit denies, policy versions, and
  exact-effect approval receipts.
- Durable requests, results, replayable event history, and lease/cancellation
  state.
- Project continuity returned by `ptrack`, including exact retained JSON.
- Evidence blobs, metadata, retention classifications, redaction state, and
  cross-project isolation.
- Audit records, redacted detail, global sequence/high-water state, and export
  integrity.
- Corporate certificate/proxy configuration confidentiality, especially proxy
  credentials, endpoints, bypass lists, and backend diagnostics.
- Availability and integrity of the local endpoint, SQLite database, evidence
  directories, and native keyring.
- User-owned GGUF weights, verified model registrations, exact license consent,
  and ephemeral model prompts and generated text.
- Future connector credentials, flow definitions, and external effects. These
  are design assets but are not yet exposed by production code.

### Actors and controlled inputs

| Actor | Inputs or authority | Trust level |
| --- | --- | --- |
| Human local administrator | Runs caller/grant/approval commands; controls the OS account, native keyring prompts, project checkout, and retention/export destinations | Trusted administrator in the current design |
| Registered CLI, coding agent, GUI, or local application | Sends authenticated protocol frames and attacker-influenced request IDs, project IDs, capabilities, resources, cursors, and payloads | Authenticated but not automatically authorized |
| Unregistered local process or another OS user | Can attempt endpoint connections, malformed/oversized frames, endpoint occupation, replay, or denial of service | Untrusted; must gain no capability from reachability alone |
| Unrestricted process running as the PAM OS user | Can invoke administrative CLI paths and may be able to read or alter per-user files subject to OS controls | Inside the current administrative boundary; not isolated by PAM |
| Project/workspace content | `.pam/project.toml`, Git metadata, paths, filenames, logs, evidence, and tool output | Untrusted data even when the checkout is operator-selected |
| `ptrack` executable and JSON output | Program resolved from `PATH`; project registration data and context JSON | Operator/developer-controlled dependency; returned content is untrusted |
| OS keyring, filesystem, SQLite, certificate verifier, and proxy configuration | Security services, errors, environment variables, proxy URLs, PAC state, and trusted roots | Trusted platform boundary, but values and failure text may be sensitive or malformed |
| Repository developer and CI | Dependencies, migrations, feature flags, tests, release artifacts | Trusted supply-chain actor; compromise can replace all controls |

### Trust boundaries

1. **Operating-system account and native-secret boundary.** PAM assumes the OS
   kernel, login account, per-user data directories, and native credential store
   enforce their advertised isolation. Native keyring calls may block or prompt,
   so they are opened lazily on a blocking worker. Unavailable or headless
   stores fail closed without a plaintext fallback.
2. **Local transport boundary.** A Unix-domain endpoint is current on macOS and
   Linux; Windows uses loopback TCP with application-layer caller
   authentication. Endpoint access is not identity. Every production request
   must carry a registered caller credential, and policy is enforced after
   authentication. Peer credentials and a Windows named-pipe adapter are planned
   hardening.
3. **Local-administrator boundary.** Caller registration/revocation,
   grant/revocation, and approval decisions currently open protected per-user
   state directly. They treat unrestricted execution as the PAM OS user as
   administrative authority; they do not prove user presence or pass through
   daemon policy. Audit export and retention pruning do authenticate and apply
   project policy. Sandboxes that run untrusted agents must withhold the admin
   CLI and direct state-file access.
4. **Project boundary.** Project IDs scope grants, requests, evidence, audit
   export, and retention. A project marker is an identity input, not a secret or
   credential. Copying or replacing a known marker can select that identity but
   does not create a caller credential or grant.
5. **Capability and approval boundary.** Grants bind caller, project,
   capability, and exact/any resource. Default deny and explicit-deny precedence
   apply. A one-time approval is fingerprint-bound and consumed in the same
   transaction as the final authorization audit.
6. **Durable-state/filesystem boundary.** SQLite metadata and content-addressed
   evidence files cannot be changed in one atomic transaction. Logical deletion
   commits first; descriptor-relative, no-follow physical cleanup is idempotent
   and reports pending or unresolved state without claiming unknown deletion.
7. **Subprocess boundary.** PAM invokes fixed `ptrack` commands without a shell,
   with a fixed working directory, timeouts, output caps, JSON parsing, and exact
   project-root validation. The binary found through `PATH` is still executable
   code trusted by the OS user.
8. **Corporate network boundary.** The HTTP factory fixes native platform
   certificate verification and supported environment/system-proxy discovery.
   Diagnostics return typed presence/state values only. PAC evaluation is not
   implemented and is never claimed.
9. **Untrusted-content and presentation boundary.** Protocol text, audit detail,
   logs, evidence, proxy configuration, and `ptrack` content can contain secrets,
   invalid UTF-8, terminal controls, or adversarial structure. Bounded parsing,
   terminal-safe rendering, evidence hashes, and persistence-boundary audit
   redaction limit their effect. Redaction is defense in depth, not a license to
   place arbitrary secrets in audit detail.
10. **Model and planned flow/connector boundary.** Model requests cross the same
    authenticated, project-scoped policy gate as other PAM protocol operations.
    The daemon loads only an exact registered digest that passes fresh
    fail-closed memory admission, serializes native execution, and treats output
    as untrusted data. Future flows and connectors must still validate that data
    and re-check policy at the point of every external effect.

### Security objectives and invariants

- A caller label or local socket connection must never substitute for a caller
  credential.
- Unknown, revoked, and wrong credentials remain externally indistinguishable;
  no credential is written to TOML, SQLite, diagnostics, logs, or debug output.
- A grant or approval for one caller/project/capability/resource must not
  authorize any other tuple. Revocation and expiry are inclusive boundaries.
- An approval-required effect and its authorization audit either commit together
  or neither commits; a receipt is consumed at most once.
- Requests, evidence, audit export, and retention never cross project IDs without
  a separately authorized resource.
- Untrusted evidence paths never redirect reads or cleanup through symlinks,
  FIFOs, or namespace swaps; bytes returned as exact evidence must match their
  digest. User-selected output trusts its parent directory but creates a new
  target without overwrite.
- Audit detail is redacted and terminal-safe before persistence, bounded on input
  inspection and output, and re-redacted at the Store transaction boundary.
- Audit pagination is fenced against later appends with a captured high-water.
  It is not a snapshot under concurrent retention pruning.
- Physical retention results distinguish exact deletions, known pending items,
  and unresolved cleanup; they never fabricate a byte-deletion claim.
- Corporate diagnostics never expose proxy URLs, credentials, hosts, bypass-list
  contents, PAC URLs/scripts, or backend error text.
- Model weights remain user-owned and are revalidated by size and SHA-256 before
  load. Prompt and generated text are bounded, excluded from Debug and audit
  detail, and never persisted by the inference path.
- Model load fails closed when the exact runtime projection exceeds the 20 GB
  ceiling or fresh host pressure, availability, swap trend, physical reserve,
  or Metal working-set evidence is unavailable or insufficient.
- At most one native inference is active and one is queued; additional callers
  receive a typed busy result rather than blocking an async executor.
- Unavailable sources and failed operations are reported as unavailable,
  unresolved, or failed rather than converted into verified facts.

### Assumptions and explicit exclusions

- Compromise of the OS kernel, PAM binary, native keyring implementation, build
  toolchain, or repository supply chain is outside the runtime boundary.
- PAM does not defend its per-user database from an unrestricted malicious
  process already running as the same OS user. This is especially important for
  coding-agent sandboxes: arbitrary same-user process execution currently
  reaches administrative commands unless the sandbox policy blocks them.
- Project IDs are stable routing identifiers, not secrets, proof of repository
  ownership, or tenant authentication.
- Data at rest is not application-level encrypted. PAM relies on OS account and
  disk protections, plus the native keyring for caller credentials.
- Managed-enterprise CA, authenticated-proxy, PAC, keyring-prompt, and headless
  behavior has contract-test coverage only. No live managed environment result
  is asserted.
- Physical presence, root/administrator access, malicious hardware, and denial
  of service by a privileged system administrator are out of scope.

## Attack Surface, Mitigations, and Attacker Stories

### Caller identity, native secrets, and local administration

An attacker may spoof a caller label, steal/replay a credential, race
registration with native-store writes, or keep using a secret after revocation.
`pam_core::CallerCredential` redacts `Debug` and exposes the value only through
an explicit accessor. `pam_store` validates its byte length, stores only a
SHA-256 verifier, compares in constant time, and rechecks active caller state at
authorization. Re-registration of a revoked caller rotates the credential.
`pam_platform::SecretStore` derives a domain-separated opaque locator and uses
Keychain, Credential Manager, or Secret Service with sanitized typed errors and
no file fallback.

The SQLite verifier is an unsalted SHA-256 digest, so security relies on the
CLI-generated credential's high entropy rather than password-hardening. Repeated
local authentication failures are not currently rate-limited.

Registration writes the native secret before the verifier and restores the
previous secret on an ordinary database failure. Revocation commits first, so a
crash that leaves a keyring entry does not restore authorization. Native calls
may still trigger prompts or hang in unhealthy desktop services; the blocking
boundary protects async executors, not user experience.

Residual risk: caller/grant/approval administration trusts same-user execution
and does not require a fresh native credential, OS user-presence proof, or
transactional audit event. A same-user agent with unrestricted command execution
can grant itself capabilities or approve an effect. This is acceptable only
under the documented local-administrator assumption and must be hardened before
PAM treats mutually untrusted same-user processes as separate administrators.
Caller labels are also one durable identity per declared surface kind, not one
identity per process, session, or integration instance; grants are therefore
coarse across callers that intentionally share that kind and bearer credential.
Approval decisions require an active registered caller but no distinct approver
role, fresh credential check, or human-presence proof.

### Local transport and protocol

Malformed frames, unsupported versions, oversized evidence chunks, correlation
confusion, replay, and endpoint squatting are realistic local attacks. The
protocol is typed, versioned independently, uses named-field MessagePack, caps
frames at 1 MiB and evidence chunks at 256 KiB, and preserves observer versus
target request identity. Durable idempotency and replay cursors prevent a client
reconnect from silently restarting work. Daemon authentication and policy
bypass switches exist only under `cfg(test)`.

The Unix endpoint and ownership file reject ordinary duplicate ownership and
require explicit stale-state recovery. The fallback runtime path under the
system temporary directory and the Windows loopback endpoint do not yet provide
peer-credential identity, and runtime-directory ownership/mode is not explicitly
verified before use. On the predictable temporary-directory fallback,
`Ownership::acquire` opens `daemon.lock` with symlink-following path APIs before
truncating and writing it. Another OS user who can precreate that runtime
directory and lock symlink may redirect truncation or writes to a file accessible
by the PAM user. Planned hardening must use a private owner/mode-validated
runtime directory and descriptor-relative, no-follow lock creation.

Caller authentication prevents endpoint possession from granting capability,
but a local attacker may still cause availability loss, connection churn, or
stale-path interference. There is no documented per-caller transport rate
limiter, and the protocol deadline field is not yet enforced by the daemon.
Planned Unix peer-credential checks, service-manager-owned directories, Windows
named pipes, and admission limits further reduce this residual attack surface.

### Project identity, policy, and approvals

A hostile request may name another project, use an any-resource grant, exploit
an expiry boundary, substitute an approval ID, or race revocation with dispatch.
Project discovery rejects unsafe marker types and hostile Git environment
redirection, while policy remains the authorization control: it is default-deny,
explicit deny wins, and every match dimension is exact unless a grant explicitly
chooses any-resource scope. Caller revocation is rechecked during authorization.

Approval fingerprints are length-delimited SHA-256 values over caller, project,
capability, and resource. Approved receipts are durable, exact-effect, and
one-time. `authorize_audited` evaluates policy, creates/expires/consumes approval
state, and appends the decision audit in one SQLite transaction. Dispatch occurs
only after that commit. Audit event IDs use request fields plus a per-process
atomic nonce and high-resolution time to avoid collapsing same-millisecond
attempts.

Residual risk: a malicious repository that can replace its project marker can
select a known project ID. The ID itself is not authentication; impact still
requires a registered bearer credential and matching grant, but requests assert
their project ID and operators must not use project markers as proof of
repository ownership. Broad any-resource grants increase impact and should be
reserved for deliberate administrator choices.

### SQLite, audit, and retention

Database corruption, event-ID collisions, cross-project export, log injection,
secret-bearing errors, pagination races, and dishonest cleanup reports are the
primary stories. SQLite uses schema migrations, foreign-key/integrity checks,
bounded workers, transactions, and durable monotonic audit sequences. Audit
identifiers reject controls and Unicode format characters. Detail passes through
an adversarial bounded redactor near collection and again inside
`append_audit_event_tx` before idempotency comparison or insert.

Exports are project-scoped, deterministically encoded as versioned NDJSON, and
published to a new file without overwrite. A captured inclusive high-water
prevents concurrent appends from extending later pages; supplied future
high-waters are rejected. Concurrent audit pruning can remove rows inside that
fence, so exports are not long-lived snapshots and operators should finish
paging before pruning.

The ledger is durable but not signed, hash-chained, or tamper-evident against the
same OS user. Its global sequence values can also reveal gaps corresponding to
other projects' activity even though event contents remain project-scoped.

Audit retention and evidence retention are explicit, inclusive, and bounded.
Persistent evidence is excluded from the current prune command. Evidence
deletion may complete before its audit completion record; CLI failures therefore
report exact already-applied counts. Network observations and daemon
authentication/policy decisions are audited, as are local audit-export and
retention authorization/outcomes. Caller registration/revocation, grant
mutation, and approval decisions are not yet transactionally represented in the
general audit ledger; direct SQLite tampering by the same OS user also lies
outside ledger integrity.

The public Store also retains an unaudited `authorize` seam alongside
`authorize_audited`; production daemon and sensitive local retention/export
paths use the audited seam, but this invariant is currently enforced by call-site
discipline rather than the type system.

### Evidence content-addressed storage and output

Attackers may submit oversized bytes, reuse a semantic handle for different
content, corrupt a blob, race put with garbage collection, swap directories, or
place symlinks/FIFOs at expected paths. Evidence size/media type and read ranges
are bounded. Handles are immutable mappings; blobs are keyed and verified by
SHA-256; reads re-verify type, size, and digest. Directory handles and no-follow
opens prevent path swaps and special-file blocking.

Put writes and fully verifies an optimistic blob outside the global SQLite
writer, then rechecks/reinstalls under writer exclusion before publishing a
handle. A per-attempt install intent identifies the exact temporary filename.
Stale cleanup removes only that attempt's no-follow temporary file and protects
a final blob while another install attempt exists. Logical handle deletion
commits before zero-reference blob cleanup; retry ordering prevents an unsafe
entry from starving later candidates. Partial failures preserve committed
counts and set `cleanup_unresolved` instead of inventing a pending count.

Residual risk: SQLite and filesystem effects are intentionally not atomic.
Crashes can leave recoverable intents or unreferenced bytes, and malicious
same-user filesystem changes can keep cleanup pending. Exact evidence and
unredacted `ptrack` JSON are plaintext at rest under the per-user data directory;
retention does not promise secure erasure from storage media or backups. Each
bounded range read currently verifies the whole blob, so repeated small reads
can amplify hashing and I/O work.

### Native trust, proxies, and diagnostics

Proxy environment variables can contain credentials, control characters,
attacker endpoints, or conflicting upper/lower-case settings. Native proxy APIs
can return PAC configuration or sensitive backend failures. Diagnostics model
precedence, CGI suppression, malformed/non-Unicode inputs, bypass-list presence,
and PAC state with typed enums; their `Debug`, protocol result, CLI rendering,
and audit event contain no raw endpoint, host, userinfo, bypass-list, PAC URL, or
backend error.

The reqwest factory fixes rustls platform certificate verification, supported
environment/system proxy discovery, and bounded connect/request timeouts. It
does not expose an invalid-certificate switch. PAC scripts are not evaluated by
the selected stack. A detector may report `detected-but-unsupported`; otherwise
PAM reports inspection unavailable. The current diagnostics path performs no
connector request, and tests do not establish live behavior behind a managed
proxy or enterprise CA.

The production `diagnose_process_proxy` path currently uses an unsupported
native system-proxy inspector, so it cannot detect native PAC configuration on
its own; PAC detection is proven only through an injected test seam.

Residual risk: environment proxy configuration is operator/process-controlled
and can route future traffic through an attacker. Platform trust intentionally
accepts roots trusted by the OS user/administrator. Connector destination
allowlists and egress policy remain planned.

### `ptrack`, untrusted content, compaction, and presentation

PAM executes `ptrack projects --json` and `ptrack context --json` with fixed
arguments, no shell, the project root as working directory, a one-second command
timeout, bounded output drains, strict JSON types, exact registered-root
validation, and bounded result sections. Failures remain unavailable rather than
becoming empty verified facts. Exact context JSON is retained as project-scoped
evidence, and terminal output/preview paths escape controls and non-ASCII bytes.
Deterministic log compaction strips terminal noise, enforces source/record/policy
bounds, remains byte-stable, and preserves evidence spans. Compaction is not
secret redaction.

Residual risk: `ptrack` is resolved through `PATH`; replacement is arbitrary
code execution with the daemon user's authority, already inside the same-user
administrator assumption. The child inherits the process environment, and the
timeout does not establish process-group termination for grandchildren. Valid
JSON may contain sensitive content not recognized as a secret and is currently
stored as unredacted evidence. Policy must therefore protect evidence reads, and
future integrations should prefer an authenticated protocol or explicitly
pinned executable.

`pam evidence show --raw` intentionally writes exact bytes to the terminal and
therefore bypasses preview escaping; it is an operator-selected exfiltration and
terminal-control risk. File export uses new-file-only atomic publication, but
the user-selected parent directory remains trusted.

### Implemented model boundary and planned flows, connectors, and GUI

The model runtime is embedded directly and reached only through the bounded PAM
protocol. It has no HTTP/SSE surface, does not disclose a transferable model
credential, and does not persist prompts or outputs. Before shipping flows,
connectors, or the full GUI, the design still requires typed connector
capabilities, destination and command allowlists, policy evaluation immediately
before every external effect, one-time approvals for destructive/publishing
actions, evidence citations for claims, and no GUI-only bypass around the
daemon. Allowing prompt/model/tool output to choose a raw shell command,
destination, credential, or approval target would cross the highest-risk
boundaries in this repository.

## Test-linked validation matrix

Within the table, a leading `::test_name` continues the immediately preceding
repository-relative test-file path in that cell.

| Invariant | Implementation evidence | Validation evidence | Residual limitation |
| --- | --- | --- | --- |
| Credentials are separate, bounded, redacted, and not stored raw in SQLite | `crates/pam_core/src/identity.rs`; `crates/pam_store/src/store.rs` | `crates/pam_core/src/identity_test.rs::caller_credential_debug_output_is_redacted`; `crates/pam_store/src/store_test.rs::caller_secret_is_absent_from_storage_and_diagnostics` | Same-user process memory/OS compromise is out of scope |
| Native secrets have opaque caller locators and no plaintext fallback | `crates/pam_platform/src/secrets.rs`; `crates/pam_cli/src/request.rs` | `crates/pam_platform/src/secrets_test.rs::locator_is_stable_bounded_and_distinguishes_adjacent_callers`; `::credentials_round_trip_update_delete_and_report_missing`; `::backend_failures_are_mapped_to_sanitized_error_kinds` | Live Keychain/Credential Manager/Secret Service prompts are not exercised |
| Wrong, unknown, and revoked callers do not authorize requests | `crates/pam_store/src/store.rs::authenticate_caller`; `crates/pam_daemon/src/lifecycle.rs::request_preflight` | `crates/pam_store/src/store_test.rs::caller_authentication_rejects_wrong_unknown_and_duplicate_credentials`; `::caller_revocation_is_immediate_idempotent_and_persistent`; `crates/pam_daemon/tests/status_round_trip.rs::authentication_rejects_missing_wrong_and_revoked_credentials` | Admin CLI is a separate same-user boundary |
| Project identity resists unsafe markers and Git environment redirection | `crates/pam_platform/src/identity.rs` | `crates/pam_platform/src/identity_test.rs::dangling_marker_symlink_is_rejected_without_following_it`; `::fifo_marker_is_rejected_without_blocking_on_open`; `::git_environment_cannot_redirect_project_discovery`; `::git_fallback_survives_moves_is_shared_by_worktrees_and_differs_in_clones` | A valid copied marker can intentionally select a known project ID |
| Policy is default-deny and exact across caller/project/capability/resource | `crates/pam_policy/src/lib.rs::evaluate`; `crates/pam_store/src/store.rs::authorize` | `crates/pam_policy/src/lib_test.rs::no_matching_grant_denies_by_default`; `::explicit_deny_takes_precedence_over_allow`; `crates/pam_store/src/store_test.rs::authorization_is_default_deny_and_matches_exact_policy_dimensions`; `::authorization_rechecks_caller_revocation_after_grant_creation`; `crates/pam_daemon/src/lifecycle_test.rs::max_length_evidence_handles_are_safe_and_exactly_policy_bound` | Administrators can deliberately issue broad any-resource grants |
| Exact approvals are one-time, explicitly retried for single requests, and audit-atomic | `crates/pam_policy/src/lib.rs::EffectFingerprint`; `crates/pam_store/src/store.rs::authorize_audited`; `crates/pam_cli/src/request.rs::RequestContext` | `crates/pam_policy/src/lib_test.rs::approval_is_bound_to_the_exact_effect_and_consumed_once`; `crates/pam_store/src/store_test.rs::approvals_are_exact_durable_and_consumed_atomically_once`; `::audit_failure_rolls_back_approval_creation`; `::audit_failure_rolls_back_one_time_approval_consumption`; `crates/pam_daemon/tests/status_round_trip.rs::exact_approval_is_required_bound_to_effect_and_consumed_once`; `crates/pam_daemon/src/lifecycle_test.rs::malformed_request_shape_cannot_consume_a_cancel_approval`; `::replay_approval_is_bound_to_the_exact_after_sequence`; `crates/pam_cli/src/request_test.rs::explicit_approval_receipt_is_attached_to_each_supported_single_request` | Approval decisions assume same-user admin authority; multi-request evidence downloads do not accept one reusable receipt |
| Protocol input and evidence chunks are bounded and versioned | `crates/pam_protocol/src/codec.rs`; `crates/pam_protocol/src/contract.rs` | `crates/pam_protocol/src/codec_test.rs::oversized_frames_are_rejected_before_decode`; `::unsupported_protocol_versions_are_rejected`; `::invalid_evidence_read_lengths_are_rejected_during_decode`; `::maximum_evidence_chunk_fits_the_protocol_frame_and_round_trips` | No per-caller request-rate limiter is documented |
| Direct model inference is authenticated, bounded, redacted, and capacity-limited | `crates/pam_protocol/src/contract.rs`; `crates/pam_daemon/src/model_service.rs`; `crates/pam_model/src/runtime.rs`; `crates/pam_model/src/llama_cpp_macos.rs` | `crates/pam_protocol/src/codec_test.rs::aggregate_model_prompt_budget_is_enforced_by_the_canonical_decoder`; `::oversized_model_generation_is_rejected_by_the_canonical_decoder`; `crates/pam_daemon/src/model_service_test.rs`; `crates/pam_model/src/runtime_test.rs`; `crates/pam_model/src/llama_cpp_macos_test.rs` | Native live-model qualification is artifact- and macOS-host-specific; model output remains untrusted |
| Local endpoint ownership/recovery does not replace authentication | `crates/pam_platform/src/endpoint.rs`; `crates/pam_platform/src/transport.rs`; `crates/pam_daemon/src/lifecycle.rs::Ownership` | `crates/pam_daemon/src/lifecycle_test.rs::ownership_rejects_a_second_daemon`; `::stale_socket_reports_recovery_command`; `crates/pam_daemon/tests/status_round_trip.rs::status_crosses_transport_queue_events_and_result` | Predictable fallback lock is symlink-following; peer credentials and hardened service directories are planned |
| Evidence is immutable, project-scoped, digest-verified, and path-safe | `crates/pam_store/src/evidence.rs` | `crates/pam_store/src/evidence_test.rs::blobs_deduplicate_globally_while_handles_remain_project_scoped`; `::semantic_handle_puts_are_idempotent_but_immutable`; `::missing_and_corrupt_blobs_are_never_returned`; `::symlinked_evidence_directory_is_rejected_before_put`; `::fifo_blob_is_rejected_without_blocking_evidence_requests_or_shutdown`; `::held_directory_handles_prevent_namespace_swap_from_redirecting_publication`; `crates/pam_daemon/src/lifecycle_test.rs::evidence_inspection_and_chunk_reads_are_bounded_and_project_scoped` | Plaintext evidence relies on per-user filesystem isolation |
| Put/GC races and crash orphans recover without false deletion claims | install intents and prune logic in `crates/pam_store/src/evidence.rs` | `crates/pam_store/src/evidence_test.rs::put_recovers_when_prune_removes_optimistic_install_before_handle_publish`; `::stale_intent_removes_its_exact_crash_temp_before_hardlink_idempotently`; `::stale_same_digest_attempt_cannot_clear_or_delete_a_non_stale_attempt`; `::cleanup_reports_committed_removals_when_a_later_database_step_fails` | Filesystem and SQLite cannot be one atomic unit |
| Audit detail is secret-redacted, terminal-safe, and bounded at persistence | `crates/pam_policy/src/redaction.rs`; `crates/pam_store/src/store.rs::append_audit_event_tx` | `crates/pam_policy/src/redaction_test.rs::incomplete_sensitive_headers_consume_unindented_crlf_tail`; `::json_secret_value_after_multiline_whitespace_is_redacted_idempotently`; `::overlapping_header_bearer_and_jwt_matches_collapse_without_leaking_fragments`; `::arbitrary_bytes_controls_ansi_and_bidi_are_rendered_as_safe_utf8`; `::output_bound_is_exact_and_always_uses_an_explicit_truncation_marker`; `crates/pam_store/src/store_test.rs::audit_rejects_control_and_format_characters_in_every_text_field`; `crates/pam_daemon/src/lifecycle_test.rs::authenticated_policy_preflight_appends_a_redacted_project_audit_event` | Pattern redaction cannot recognize every future semantic secret format |
| Audit export is project-scoped, append-fenced, deterministic, and no-overwrite | `crates/pam_store/src/store.rs::export_audit_events`; `crates/pam_cli/src/audit.rs`; `crates/pam_cli/src/evidence.rs::write_new_output` | `crates/pam_store/src/store_test.rs::audit_export_is_project_scoped_ordered_paginated_and_deterministic`; `::audit_export_rejects_a_high_water_before_the_exclusive_cursor`; `crates/pam_cli/src/audit_test.rs::audit_export_is_deterministic_versioned_ascii_ndjson`; `crates/pam_cli/src/evidence_test.rs::atomic_output_creates_exact_file_and_never_overwrites_existing_target` | Concurrent pruning means the fence is not a database snapshot |
| Retention is bounded, excludes persistent evidence, and reports partial truth | `crates/pam_store/src/evidence.rs::prune`; `crates/pam_cli/src/app.rs::retention_prune` | `crates/pam_store/src/evidence_test.rs::retention_prune_is_bounded_inclusive_and_strictly_scoped`; `::shared_blob_is_removed_only_after_its_last_handle`; `::retention_prune_reports_symlinked_blob_cleanup_pending_without_following_target`; `::pending_blob_cleanup_does_not_starve_later_unreferenced_blobs`; `::retention_prune_rejects_persistent_unbounded_and_invalid_cutoffs`; `crates/pam_cli/src/app_test.rs::administrative_storage_ranges_are_rejected_before_local_authorization` | Automatic session lifecycle expiry is not implemented |
| Proxy/PAC diagnostics expose typed state only and corporate HTTP fixes native trust | `crates/pam_platform/src/network.rs`; `crates/pam_protocol/src/contract.rs::NetworkDiagnosticsResult`; `crates/pam_daemon/src/lifecycle.rs::handle_network_diagnostics` | `crates/pam_platform/src/network_test.rs::upper_case_specific_proxy_wins_without_exposing_endpoint_or_credentials`; `::no_proxy_accepts_reqwest_compatible_entry_whitespace_without_disclosure`; `::pac_is_detected_but_never_reported_as_evaluated`; `::native_inspection_failure_drops_raw_backend_error`; `::reqwest_corporate_factory_builds_without_network_access`; `crates/pam_daemon/tests/status_round_trip.rs::network_diagnostics_require_an_authenticated_project_grant`; `crates/pam_daemon/src/lifecycle_test.rs::network_diagnostics_are_typed_read_only_and_sanitized` | No live managed-enterprise validation; PAC is not evaluated |
| `ptrack` failures and hostile output remain bounded and project-specific | `crates/pam_daemon/src/ptrack.rs` | `crates/pam_daemon/src/ptrack_test.rs::registered_project_validation_requires_the_exact_pam_root`; `::subprocess_output_reader_drains_but_retains_only_the_bound`; `::oversized_fields_and_sections_are_truncated_and_marked_partial`; `::provider_does_not_invoke_or_expose_a_source_for_another_project`; `::provider_reports_a_missing_supported_cli_without_storing_evidence` | Executable resolution through `PATH` is trusted code selection |
| Durable scheduling, cancellation, replay, and recovery do not duplicate effects | `crates/pam_store/src/store.rs`; `crates/pam_daemon/src/lifecycle.rs` | `crates/pam_store/src/store_test.rs::claims_preserve_project_fifo_while_other_projects_make_progress`; `::expired_lease_is_recovered_after_reopen_and_old_token_is_fenced`; `::cancellation_and_completion_race_has_exactly_one_terminal_outcome`; `crates/pam_daemon/src/lifecycle_test.rs::accepted_work_survives_restart_and_replays_the_original_result`; `::idempotent_retry_keeps_both_observers_correlated_without_duplicate_events` | Future external effects still require connector-specific idempotency |

## Severity Calibration (Critical, High, Medium, Low)

### Critical

- A production authentication or policy bypass that lets an unregistered caller
  invoke a destructive future connector/flow effect, publish code, or exfiltrate
  credentials without the required approval.
- Arbitrary code execution across the local transport boundary in the daemon
  user's context, or a supply-chain change that silently disables native TLS
  verification for connector traffic.
- Cross-user extraction of native-store credentials with no additional local
  privilege. Same-user extraction is still serious but is scoped by the stated
  administrative assumption.

Current impact may be lower when the vulnerable path reaches only status,
brief, or untrusted local model output because connectors, flows, and public
network APIs are not implemented.

### High

- Cross-project disclosure or deletion of exact evidence/audit data by a caller
  that lacks the target project's grant.
- Approval fingerprint substitution, reuse, double consumption, or a failure
  that commits an effect without its required audit decision.
- Path traversal, symlink following, or namespace-swap behavior that reads or
  deletes files outside PAM's evidence/output roots.
- Persisting a caller credential, proxy credential, private key, or comparable
  secret in SQLite, audit export, diagnostics, or terminal output.
- Bypassing explicit deny, caller revocation, or inclusive expiry at dispatch.

### Medium

- Same-host denial of service through endpoint occupation, request flooding,
  lock contention, malformed but bounded messages, or persistent cleanup
  interference when no privilege or cross-project data is gained.
- Audit truncation, pagination, or retention behavior that loses accountability
  but does not enable or conceal a sensitive effect.
- A redaction bypass that exposes a non-credential secret only to another
  process already able to read the same user's PAM data.
- Misreporting PAC/proxy support or managed-environment state without leaking an
  endpoint or causing unsafe outbound traffic.

### Low

- Benign presence-only metadata disclosure, confusing recovery text, or output
  instability that does not cross caller/project boundaries or hide failure.
- A developer/test-only issue in the prototype or `cfg(test)` bypass path with
  no route into the production binary.
- Availability loss that requires the trusted local administrator to corrupt
  their own state and is recovered by documented, bounded repair.

The cache version below identifies a deterministic inventory of the reviewed
mutable Git worktree. This generated threat-model artifact is excluded from its
own snapshot digest to avoid a self-referential hash.

Repository: target_sha256_cf07463cb2c12678153d6a7b23dc66d48faa84d15a657400db735728ec85adcd
Version: codex-security-snapshot/v1:sha256:f01cc375f09a9070a744e370bdfd3d2944fb30aab5d0da0f8567952dca93f4ad
