# Changelog

All notable changes to pam are documented in this file. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and pam adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `pam flow run --digest <sha256>` runs a flow only if it still has the digest
  `pam flow inspect` reported; a flow edited in between refuses as
  `flow_changed`. `pam flow inspect` now prints the digest on its first line.
  The GUI pins Run to the flow it shows in the same way.
- Flow results list `effects` (step, kind, `applied` or `possibly_applied`, and
  the landing operation for landing steps) beside the outcome. They are kept
  when the outcome is `unresolved` or `blocked`, where the handoff reason is
  `workflow_not_completed_after_state_change`. `pam flow result` and the GUI
  run card print them.
- Refusals carry a `retryable` flag for momentary daemon conditions. Clients
  retry on the flag and keep their own list of causes for older daemons.
- `admin.requests.cancel`: the GUI cancels a ticket over the private
  administration channel, and the audit records it as the human's act. The
  public `request_capability` bridge command is removed.
- `admin.flows.save` and `admin.flows.delete` replies list `grants_revoked`
  and `reapproval_required`, and the GUI tells the human which steps lost
  their remembered approval.
- Pending approvals for a flow step show the resolved command: program, one
  token per argument, directory and the names of the variables it sets.
  Approving is pinned to that snapshot (`expected_digest`); a flow edited
  while the approval waited refuses as `flow_changed` and stays pending.
- `pam status` gains `snapshot` (`stale`, `model_age_ms`, `keyring_age_ms`).
- The daemon checks the store's integrity at boot (files up to 256 MiB) and
  reports a damaged file with a cause and recovery line instead of an engine
  error.
- `pam service status` reports the binary the unit pins and whether it is
  stale; Settings offers "Repoint to this binary".
- `pam flow result` labels local-model summaries `[untrusted local-model
  summary]` and escapes control characters in them.
- Request rows record where a request entered the daemon and who connected:
  `ingress` (`public` or `admin`), the kernel's uid and pid of the peer
  (`peer_uid`, `peer_pid`; empty on Windows, which reports none) and whether
  the client said it came through `pam listen` (`relayed`).
  `admin.activity.list` returns them. They are attribution, never
  authorization.
- The GUI receives every lifecycle event over the private administration
  channel, with the ticket's capability, repository, agent label and the real
  progress note. Settings › Daemon explains a window and a daemon of different
  builds, and Models readiness says what a qualification covers.

### Changed

- The public transport is PAM's own framed protocol on the same socket,
  `<base>/run/pam.sock`: length-prefixed JSON, a `hello`, then one request per
  connection. On Windows it is a loopback port behind an owner nonce published
  in `<base>\run\public.json`. The daemon closes a connection after its
  answer, tells a connection over its 256-connection cap why
  (`connection_capacity_exhausted`), and keeps answering with a refusal frame
  while it drains instead of refusing the connect.
- Events are no longer broadcast. `pam wait` and `pam subscribe` follow one
  ticket on one connection, authorized like a result read, and the stream ends
  with the durable result: a follow costs one `query` request, a finished
  ticket is answered at once, and a late `pam subscribe` is shown the earlier
  events of a running ticket. At most 16 followers per ticket and 96 in total.
- `pam listen` binds one socket. It refuses a session directory that is a
  link, is owned by someone else or is writable by group or others, and a
  socket entry that is a link or not a socket. The daemon records the relay
  process as the peer of a relayed request.
- A `pam gui` built without the embedded frontend refuses to start unless
  `PAM_GUI_DEV=1` is set, because its window would load the development server
  with full control of the daemon. `npm run gui:dev` and `npm run dev:desktop`
  set it, on Windows too.
- `pam daemon stop` reports what `kill` said inside its own error line.

- `pam cancel` only acts on a ticket submitted from the caller's own
  repository; another repository's ticket answers `not_found`, like a missing
  one. Run it from the repository the ticket was submitted from. A public
  cancel is always recorded as `system`, whatever the caller's label says.
- Saving an edited flow removes the remembered approvals of every step whose
  definition changed, and deleting a flow removes those of its steps. The
  changed steps ask again.
- `admin.profile.set` applies immediately; the reply says `"applies": "now"`.
  It used to apply at the next daemon start.
- A client of a different version no longer restarts the daemon. The daemon
  restarts only when its own binary was replaced on disk; otherwise it
  refuses with `client_version_mismatch`, naming its version and path; the
  CLI prints one sentence with both versions and exits `3`. The version is
  judged on each connection's hello, on both planes. While it restarts, every
  request is answered `daemon_outdated`.
- `status` is served from a snapshot refreshed in the background, and a poll
  is no longer a request: it leaves no request or audit row, no caller entry
  and no lifecycle events. `active_requests` excludes the poll. `query` and
  `cancel` stay audited but publish no lifecycle events.
- Admission pools are separate per class: 128 work, 16 `status`, 16 `query`,
  8 `cancel` and 32 for requests the GUI submits, at 256, 64, 64 and 16 per
  second for the first four. Every request handler has a hard deadline.
- `pam wait` and `pam subscribe` retry transient refusals and resume a dropped
  follow after the last event seen until `--timeout-ms`, then exit `1` with
  `follow_timeout`. Exit `3` now means the daemon refused and a retry will not
  help: a policy refusal, or a daemon of another build.
- A daemon started lazily by a client runs with a reduced environment (home,
  user, locale, temp and absolute `PATH` entries, plus `PAM_BASE_DIR`), in its
  own process group, with `/` as its directory. Flow steps no longer inherit
  the first caller's variables; add tool directories through the flow
  settings' `extra_path`.
- `pam service install` refuses binaries in temp directories, in cargo build
  output and ones writable by group or others; it writes the unit before it
  stops a loose daemon; and it pins `PAM_BASE_DIR` only when given
  `--base-dir`, ignoring the caller's variable.
- Model verification is recorded privately under `<base>/model-trust` and
  checked again whenever a model loads. A sidecar next to the weights no longer
  makes a model verified, so each existing model needs "Verify" once after
  upgrading. A model with a leftover sidecar says so. On Windows a model
  file's "verified" fingerprint is its size and modification time only, so a
  same-size replacement with the timestamp restored is not noticed there; the
  engine loads only PAM's private verified copy, so what runs is unaffected.
- Local summaries are bounded to two minutes in the engine and five minutes
  in all, and a cancelled flow step cancels its summary.
- The local engine's API key is passed as a private file, not on the command
  line.
- The curator runs agent CLIs only from trusted install directories, owned by
  root or the daemon's user and not writable by others, with a minimal
  environment. A CLI found only through `PATH` is listed as untrusted and never
  run. `admin.curator.list` gains `untrusted`.
- Connector credentials are trimmed when saved, and a value containing a line
  break is refused. Connector paths containing `.` or `..` are refused. A log
  redirect may only go to a public host on port 443.
- Model downloads run curl with a cleared environment that keeps only the
  proxy and certificate variables.
- A stateful flow step can no longer write Git hooks or Git configuration in
  the repository it runs in, so `git config`, `git remote add`, a tracking
  `git checkout -b`, `git submodule add` and `git init` fail in such steps.
- A state-changing step with no `needs` and the default `when` no longer runs
  after an earlier step failed; add `needs` or an explicit `when` to opt in.
- A supplied value that would become a command-line option blocks the step
  (`argument_option_refused`) unless a literal `--` precedes it.
- `${...}` in a step's `env:` values is now substituted, like in arguments.
- `${repo.origin}` resolves only for a remote whose host is exactly
  `github.com`.
- `echo` refuses a delay over 60 seconds or arguments over 64 KiB
  (`echo_limit_exceeded`).
- Retention prunes in bounded batches, treats a stored window outside 1 to
  3650 days as forever, and saves both windows in one write.
- The GUI asks for a typed confirmation, checked in Rust, before switching to
  the relaxed profile, adding a grant or approving with Remember. Approval
  cards show each argument as its own token and escape hidden characters.

### Removed

- ZeroMQ: the `zeromq` dependency, its vendored patch and its separate gate
  step are gone, and nothing on either plane speaks ZMTP.
- `events.sock`, the event broadcast socket, and the second socket
  `pam listen` bound for it. A stale one in the run directory or in a session
  directory is removed at the next start.
- The AWS CLI adapter, which was always refused, is removed. A flow that still
  names `connector: aws` fails validation as a removed connector; a stored `aws`
  connector row is ignored, and a keychain item left behind for it is harmless.

### Fixed

- The daemon no longer stops answering `status` and `cancel` when something
  behind it is slow: handlers have a hard deadline, `status` is a snapshot
  read and cancel has reserved capacity. The GUI's status polls no longer feed
  back into themselves, event refreshes are throttled and polling backs off
  while the daemon is busy or down.
- Requests whose final state could not be written are retried and then closed
  instead of staying "running" and filling the admission limit, and a failed
  write is never answered as success.
- A duplicate request attached to one that was refused is released at once
  instead of waiting for its own deadline.
- A store call cancelled inside a transaction no longer wedges the database;
  the abandoned transaction is rolled back before the next call.
- Grant changes, approvals and their audit rows are written in one
  transaction.
- A finished request can no longer be moved back to an in-flight state.
- Revoking a capability no longer makes unrelated older tickets' evidence
  unreadable.
- Noisy failing logs keep their evidence views; a ticket no longer turns
  `unavailable` because a provenance map was too detailed.
- Reading at the end of an evidence view returns an empty page marked `eof`
  instead of an error.
- Activity shows refused `admin.*` attempts even with probes hidden.
- The admin channel and `pam listen` survive transient accept errors on every
  platform; the relay caps concurrent connections at 64. A full admin listener
  answers `connection_capacity_exhausted` instead of dropping the connection.
- A killed flow step (timeout, cancel, output limit) takes its whole process
  group with it.
- Cancelling, or restarting the daemon, while a step waits for approval no
  longer reports `flow_effect_uncertain`.
- `guarded-land`: a new ticket finishes a landing whose pull request an
  earlier ticket already merged, and `sync` refuses `.git` directories swapped
  for symlinks.
- Compact flow results keep failed and blocked steps when they must drop
  observations.
- A lost `pam flow run` reply prints the request id and the `pam wait`
  recovery, also with `--json`.
- Lazy start waits for a booting daemon instead of racing it, and the version
  handshake waits for the replacement daemon before its single retry.
- The model engine's death is noticed and the next request reloads it, a
  leftover engine of a killed daemon is stopped, a stranger on the engine's
  loopback port is refused, and only a successful generation counts as use.
- The structured diagnosis dispatches an operation by its full target, and an
  authority tag counts only for a substantive quote.
- An unanswered keychain prompt no longer stalls every connector: reads give up
  after 20 seconds.
- `pam listen` starts. In 0.4.0 to 0.4.3 the installed binary panicked at
  startup ("Cannot start a runtime from within a runtime") before it bound
  anything, so the relay had only ever run inside tests. It now runs on the
  command's own runtime, and a test starts the compiled binary.

### Compatibility

- Schema version 12 adds indexes for Activity and retention and makes audit
  rows append-only and evidence views immutable. Version 13 adds the origin
  columns to request rows. A store upgraded by this version is refused by
  older binaries: a 0.4.3 daemon started on it exits `1` with "database schema
  version 13 is newer than this binary supports (max 11)", so there is no way
  back to an older daemon on the same base, and a login unit that still pins
  an old binary cannot start it.
- Upgrading from 0.4.x or 0.3.0 with a daemon still running: the old daemon
  speaks the previous protocol on the same socket, and a new client recognises
  it by its greeting. The first `pam` command run outside a sandbox, the GUI,
  or `pam listen` stops it the way `pam daemon stop` does and starts the new
  one. It prints nothing while it does, and it takes as long as the old
  daemon's drain: at once when that daemon is idle, up to ten seconds while
  it has work in flight. Work that finishes inside the drain keeps its result,
  readable through the new daemon; work still running after ten seconds is
  cancelled by the old daemon and reads as `failed` / `cancelled`. An old
  `pam wait` on such a ticket exits `3` with `daemon_shutting_down`.
- A first command that may not signal the old daemon (under an agent sandbox,
  or through `PAM_SOCKET_DIR`) exits `1` with the instruction to run
  `pam daemon stop` and then `pam status` outside the sandbox. Both are
  needed: a client that may not signal usually may not start a daemon either,
  so after the stop alone its retry fails ("did not become ready", or a
  transport failure through a relay). `pam status` alone, run outside the
  sandbox with the new binary, does both. On Windows the old daemon is not
  stopped automatically; the message names its process to end.
- An old `pam` binary cannot talk to the new daemon: it exits `1` with
  `cannot connect to ipc://<base>/run/pam.sock: Failed Greeting exchange`, and
  the daemon logs the stale client with its pid (at most once a minute, with a
  count of what it suppressed) without answering. With no daemon running, the
  old binary tries to start its own daemon, which the upgraded store refuses,
  and reports that the daemon did not become ready. A GUI left open across the
  upgrade is refused `client_outdated` and must be quit and reopened.
- Sandbox profiles need only `<base>/run/pam.sock` (or `<dir>/pam.sock` for a
  session relay). A rule that still allows `events.sock` is harmless and can
  be dropped.

## [0.4.3] - 2026-10-01

### Fixed

- Show the sidebar logo in installed builds. The release content security
  policy blocked it because the build embedded it as an inline `data:` image;
  it now ships as its own file.
- Let Home use the full window width. Wide windows place Ask Pam and its
  answers beside the task starters instead of keeping a narrow 960px column.

## [0.4.2] - 2026-09-18

### Fixed

- Make the original sidebar logo visible, with the version beneath it.
- Keep Activity lanes wide enough for request labels and timestamps, wrapping
  smaller groups instead of squeezing their contents.
- Use consistent button cursors and prevent hover effects on disabled actions.
- Keep model action menus outside scrolling containers, with keyboard navigation
  and reliable focus restoration.
- Disable accidental selection of interface labels while keeping inputs, logs,
  results and diagnostic text selectable.
- Keep Save and Discard changes visible above the flow editor. Saving updates
  custom flows; discarding restores the saved draft without writing it. Save uses
  the editor's latest validated draft, even while parent state is catching up.

### Changed

- Consolidate form controls and action menus into shared typed widgets.
- Remove manual log-compression controls and implementation-focused UI copy;
  compression remains part of the internal model pipeline.

## [0.4.1] - 2026-09-17

### Fixed

- Keep the desktop panel anchored while scrolling, with content scrolling
  inside its own pane. Remove entrance transforms that could leave content
  blank in the macOS webview after navigation.
- Keep the flow canvas, inspector and actions reachable in short windows,
  with a compact header and expandable flow descriptions.

### Changed

- Search the flow library by name, identifier or description without losing
  unsaved edits. Keyboard navigation stays usable while filtering.
- Show readable canvas action labels and the original PAM logo with the
  application version in both expanded and compact sidebars.

## [0.4.0] - 2026-09-17

### Changed

- A tier default now needs more than a verified digest: the model's exact
  SHA-256 must match a compiled-in qualification record for this engine build
  and platform (`pam_model::qualification`; today only gpt-oss-20b-MXFP4 on
  llama.cpp b10938, macOS arm64, under answer contract v2). `admin.models.
  defaults.set` refuses anything else with cause `unverified` or
  `unqualified`, and a default seeded past the admin op is refused at resolve
  time with the same cause, so a job never runs on unmeasured weights. Try
  still works on any installed model. The Models screen badges
  qualified / engine / test only with the reason, and the tier selects
  disable what cannot serve.
- `pam flow run` no longer accepts inputs the flow does not declare: an
  undeclared name refuses as `input_unknown` (the same cause `pam flow
  inspect` already reported), and an `inputs` value that is not a string or
  number refuses as `input_invalid`, both before a ticket exists. A typo
  against an input with a default used to run silently on that default, and
  the public projection does not echo inputs, so the run never showed which
  values it had used. The flow CLI contract records the two causes.
- The `after-merge-checks`, `pr-readiness` and `dependency-audit` recipes
  now say in their descriptions that their network-dependent steps (`git
  fetch`, the cargo-audit advisory database) fail under command containment
  instead of implying the remote refresh succeeds.

### Added

- `pam playbook`: the agent guide ships inside the binary. It prints the
  discover/run/read loop (`pam status` → `pam flow list` → `pam flow inspect`
  → `pam flow run --no-wait` → `pam wait` → `pam flow result` → `pam evidence
  read`), how to read refusals and exit codes, the sandbox-relay case
  (`PAM_SOCKET_DIR`, never started from inside the sandbox), and a drop-in
  snippet for a project's AGENTS.md — so an agent that only has the binary
  can still learn how to drive pam. `pam --help` and the `pam status` summary
  point at it, and it needs no daemon.
- `pam listen <dir>` (unix): a session socket relay for agents whose
  sandbox blocks the daemon's unix socket. It binds `pam.sock` and
  `events.sock` inside a directory the sandbox permits (created `0700`)
  and forwards bytes to the daemon's runtime sockets, so every client
  subcommand — `pam wait` and `pam subscribe` included — works through a
  path the sandbox already allows. Point sandboxed clients at it with
  `PAM_SOCKET_DIR=<dir>`: while set, the client dials the relay's sockets
  and never lazily spawns a daemon, so a dead relay is a clean error
  naming `pam listen` instead of a surprising spawn. The relay is a dumb
  byte pipe — admission, scope and budgets stay in the daemon — and it
  refuses to take over a directory where another relay already answers.
  Boundaries and placement trade-offs in `docs/session-socket-relay.md`.
- `pam subscribe` takes `--json` like `pam wait`, and with it a refused or
  timed-out follow is a `kind: refusal` object on stdout (the ticket as
  `id`, cause `follow_timeout` for an observation timeout) instead of a
  prose line on stderr; exit codes are unchanged. The README now carries a
  table of every subcommand and its exit codes.
- Windows builds can be administered: the GUI's private administration
  channel now exists on Windows as loopback TCP behind an owner-only nonce.
  The daemon writes the port and a fresh nonce to `<base>\admin\control.json`
  in the owner's private base, proves it holds the nonce before reading a
  byte, and admits only a client that presents it. Every `admin.*`
  operation the macOS and Linux GUI has works on Windows the same way;
  the threat model is unchanged and documented in `docs/admin-boundary.md`.
- `admin.models.status` reports one readiness record per tier: the first
  rung of configured → installed → verified → qualified → engine → ready
  that fails, the cause a job would be refused with, a recovery line, the
  qualification record, and whether the weights are in memory right now.
  The Models runtime tab opens with that verdict and one repair button per
  blocked tier; Settings → Models prints it under each tier; Home and the
  log-compression form say before submission why no model will answer.
- `docs/model-qualification-decisions.md`: the standing record of which
  artifacts qualified, which were screened and rejected, what was not
  measured, and the compression decision.
- A model summary now names its author: `pam flow result` observations
  that came from the heavy model carry `model` with the registry id and the
  qualification record that admitted it, the summary evidence identity
  carries the same block, and the log-compression report's `model` names
  the record. Identity only, never figures.
- `pam flow inspect` says before a run whether a summarize step will get
  its summary: the `model` block names the steps that ask the model, the
  heavy tier's stage, and the blocker with cause and recovery when the
  summary will be skipped. `pam status --json` carries the per-tier stage
  and cause under `model.readiness`.
- A straight answer to "can PAM reach the keychain?", in three places:
  `pam status` prints a `keyring:` line with the recovery sentence when it
  is blocked, Settings → Connectors carries a banner with a Re-check
  button, and Home flags a blocked keychain in the workspace overview. New
  admin op `admin.connectors.keyring { fresh? }`, and the daemon's `status`
  capability publishes a read-only `keyring` block. Reachability only — no
  capability can read a credential, and the probe reads an account nothing
  ever writes.
- Partial downloads can be thrown away from the Models screen: a preset
  card that has bytes on disk offers Resume and Start over, says how much
  is already here, and confirms before discarding. New admin op
  `admin.models.download.discard`, and `admin.models.catalog` now reports
  `partial_bytes` per preset — a part file is a dotfile a registry scan
  cannot see, so a resumable transfer no longer depends on a job row that
  may have aged out. This is also the way out of a checkpoint conflict,
  which previously needed a manual `rm`.

### Fixed

- `pam flow inspect` now reports each connector step's credential status
  under `auth_probe` instead of `credential`. The response redactor masks
  every value whose JSON key looks credential-shaped, so the honest
  `unknown_not_probed` sentinel never reached agents — they saw
  `[REDACTED]` and could not tell an unconfigured connector from a masked
  field. The field is a status, not a secret: credentials stay in the OS
  keychain and are set only from the GUI. Validation also refuses a flow
  input no step, environment value or correlation declaration reads, and an
  input name starting with `-` (unusable as a `key=value` CLI argument),
  both at `inputs.<name>` so a recipe fails before it is saved.
- Two Windows-only test flakes on loaded runners are hardened rather than
  retried: the curl mutation test's stand-in server now reports an early
  hang-up through the client assertion instead of panicking, with a 15 s
  curl deadline, and the lease-reaping test gives submission 4 s before
  its lease. Two Windows-only `unused_mut` warnings in the daemon are gone.
- `pam wait` no longer ends with "no readable result" while a flow is still
  running. A running request writes each evidence row a moment before its
  view, and a follower's `query` landing in that window was refused as if
  the ticket were not the caller's; the daemon now tells an unpublished
  view (pending, for a request that is not terminal) from a view published
  under another repository (never readable), and keeps the strict answer for
  finished requests.
- A download refused at the checkpoint check (foreign part file, wrong
  digest) now unlocks its transfer lock explicitly instead of merely
  closing the handle, so a curl process another task forked in that
  window can no longer hold the inherited lock past the next start. The
  same explicit release covers discarding a partial download.
- The store rolls back a transaction whose `COMMIT` fails instead of
  leaving it open on the shared connection, and refuses a terminal state
  handed to the non-terminal state update in release builds too, not only
  under `debug_assert`. An evidence range starting at the view's end is
  refused as invalid rather than charged against the read allowance.
- The client's readiness wait for a freshly spawned daemon no longer sleeps
  on a runtime worker; the GUI's event subscriber no longer creates or
  chmods the daemon's runtime directory; the daemon-log tail reads the last
  mebibyte of the file instead of the whole file; a systemd unit with a
  `PAM_BASE_DIR` override quotes and escapes the path; and `pam service
  status` on Windows reads the scheduled task's status column instead of
  reporting every registered task as loaded.

- Daemon review fixes: a cancel during a landing check, pack fetch or
  push now ends the run `cancelled` instead of blocked with a timeout or an
  internal error; a rejected `git push` whose remote ref did not move is a
  typed `landing_push_rejected` refusal, not an uncertain effect; sealed
  landing checktrees are removed when their ticket terminates; a flow
  checkpoint row is no longer orphaned by a journal conflict; the model
  runtime's busy flag clears when a generation future is dropped; an
  engine install cancelled by the admin deadline stops its transfer; the
  Windows admin channel admits a peer before it takes a served slot; a lease
  whose stored arguments cannot be parsed fails instead of running with
  empty arguments; a caller-supplied vendor is one plain path segment and
  the destination must stay inside the models directory; keyring errors log
  their kind only; credential patches carry a zeroing secret and print
  redacted; a diagnostic on a model the engine does not hold is refused
  rather than loading it; the status snapshot no longer touches the file
  system on the runtime thread.
- Model tooling: the download curl is the operating system's own, runs with
  `-q`, restricts protocols to https and http, and always passes the URL
  after `--`; a resume sends `If-Range` with the saved ETag so an origin
  change restarts the transfer; a completed download never overwrites a
  file that appeared meanwhile; a verification sidecar whose size or
  mtime no longer matches the weights counts as absent; the GGUF reader
  accepts every ggml type llama.cpp writes (MXFP4, the IQ and TQ families,
  integer and F64 tensors) and no longer preallocates a header-declared
  string length; the engine's API key comes from a process-seeded CSPRNG on
  every platform and the health check confirms the server's model path
  before a load is accepted; the curated catalog carries the qualified
  gpt-oss-20b preset; a flow that names the `aws` connector fails
  validation with a named blocker until containment lands.
- GUI: a running flow can be cancelled; the expanded request row shows its
  audit trail; approving with a note keeps the note; a run that finishes
  before the event stream attaches no longer sticks on queued; renaming an
  input onto an existing key is refused; the daemon card shows the real base
  directory and restart asks for confirmation; the beacon reports
  connecting and needs two missed polls before offline; independent steps
  lay out in declaration order; the installed-models table folds its
  actions into a menu and fits 1100x700; every chip, checkbox and radio has
  at least a 24 px hit area; the palette returns focus to its opener; the
  flow library is a keyboard listbox; faint ink, strong lines and a real
  amber warning pair are tokens that meet WCAG contrast in all four
  palettes; copy uses one phrase for a request awaiting review and one
  casing for labels.

- Review remainder: a rejected push keeps its `landing_push_rejected`
  cause when the run resumes; the Activity tide shows `admin.log.compress`
  rows under `hide_probes`; `admin.approvals.pending` entries carry `args`,
  `repository` and `effect`, so the Approvals card shows what will run and
  where without a second query; the engine manifest is read off the runtime
  thread; repository authorisation in flow, recovery, result and landing
  paths runs on the blocking lane; a startup sweep removes landing
  workspaces whose ticket died with the daemon. The GUI speaks in a system
  voice, Home is full-bleed like every other screen, Activity lanes size by
  row share, the built-in watch flows are named "Watch GitHub run", "Watch
  Jenkins build" and "Watch Sonar analysis", and the fake llama server can
  serve a loopback port for the Windows engine path.

## [0.3.1] - 2026-09-09

### Fixed

- Model downloads no longer hang on a dead connection: curl now carries a
  connect deadline and a minimum sustained rate, so a stalled transfer fails
  with a cause instead of a progress bar that never moves. The partial file
  is kept, so the next attempt resumes.
- Download failures say what actually broke. curl's exit code becomes a named
  cause — `dns_failed`, `connect_failed`, `network_timeout`, `http_error`,
  `tls_error`, `transfer_interrupted`, `resume_unsupported`, `disk_error` —
  each with its own recovery sentence, written to the job row and logged at
  WARN with curl's own complaint.
- The Models screen shows failed and cancelled downloads instead of silently
  dropping them, with cause, detail and recovery, and a Resume button when a
  partial file is waiting.

## [0.3.0] - 2026-09-04

### Added

- Discoverable New, Duplicate, Rename and Delete actions in the flow library,
  blank and template creation, unsaved-change guards, and session undo for
  deletion. Built-in flows remain recoverable after custom overrides.
- A PAM-specific PR readiness flow that runs the complete local quality gate.

### Fixed

- Quantized Qwen3 MoE generation on CPU and Metal, with cancellation and
  error recovery. Known unsupported tensor/backend combinations are refused
  before weight mapping with actionable errors.
- Clean-tree checks now fail on dirty tracked, untracked and submodule state.
- Connector verification now checks explicit passing statuses instead of
  treating successful retrieval as a passing check.
- Unread event subscribers no longer block daemon request replies or shutdown.
- Settings reject invalid input and protect against concurrent save races.
  Connector tests use the current saved configuration and retire stale readiness.
- Flow canvas connections have clearer contrast and zoom-independent targets.
  The canvas fits the available space, refits after resizing, and keeps the
  inspector independently scrollable.

### Compatibility

- Custom connector steps using `role: verify` must declare `expect_status`;
  otherwise execution refuses verification. Use `role: observe` when the step
  only retrieves data. Built-in verification flows include explicit predicates.
- Flow saves now reject duplicate display names, including names reserved by
  built-in flows. Existing flow IDs remain stable when renamed.
- Real dense and MoE Q8_0 generation and recovery were verified on CPU and
  Metal on a 64 GB host. This is compatibility evidence, not qualification of
  approximately 16 GB models on the 32 GB hardware baseline; that evaluation
  remains outstanding.

## [0.2.1] - 2026-09-04

### Changed

- Standardized Home, Flows, Activity, Approvals and Models on the Settings
  page structure, with fixed page headers and one bounded scroll region per
  active pane.
- Split dense tasks into keyboard-accessible tabs: flow canvas, YAML,
  execution and history; activity requests and compression; and model
  runtime, installation, downloads and testing.
- Kept Home answers beside the composer and preserved compression and flow-run
  results when filters or task views change.

### Compatibility

- No CLI, protocol or stored-data changes.

## [0.2.0] - 2026-09-04

### Added

- Navigation command palette with Cmd/Ctrl+K for pages, Settings categories,
  models and flows. Selecting a flow opens it without executing it.
- Monitor, Build and Focus workspace presets, compact navigation, and up to
  eight saved workspace layouts with their current route.
- Adjustable glass opacity and ambient background motion, with continuous
  speed and movement-intensity controls. Reduced-motion, reduced-transparency
  and forced-color preferences take priority.
- Expanded flow-canvas mode with toolbar and Escape restoration, preserving
  viewport, selected steps and unsaved edits.

### Changed

- Applied the Costa design across the desktop app: four appearance palettes,
  native typography, clearer controls and a soft, theme-tinted wave backdrop.
- Organized Settings into eight keyboard-accessible tabs with retained drafts,
  tab transitions and denser layouts that use wide desktop windows.
- Added translucent Appearance cards and removed opaque page-title strips
  from Models, Activity, Approvals and Flows.
- Improved Home hierarchy and kept workspace scrolling stable when navigating
  or expanding the flow canvas.

### Compatibility

- No CLI or protocol changes. Flows remain executable actions available from
  the CLI; appearance and workspace preferences are local to the desktop app.

## [0.1.0] - 2026-09-03

First packaged release of pam v2: the spine (daemon, CLI, GUI shell), the
model layer, log compression, flows and connectors, the flow designer,
retention, packaging, and Ask Pam.

### Added

- Packages on every first-class target: a signed, notarized macOS dmg
  (arm64), Linux AppImage and deb (amd64, arm64), and a per-user Windows
  NSIS installer (amd64, arm64), built by CI and published by the release
  workflow on `v*` tags.
- `pam service install | uninstall | status`: start the daemon at login
  through a macOS LaunchAgent, a systemd user unit, or a per-user Windows
  scheduled task. Settings › Daemon shows the same state with Install and
  Remove.
- Double-clicking `pam.app` opens the control center; the Linux desktop
  entry and the Windows shortcuts run `pam gui`.
- Home screen at `/` with Ask Pam: questions about pam itself answered
  from live daemon state with deep links (approvals, refusals, today's
  activity, the model, settings, the daemon, login, flows, tokens saved);
  the light model may rephrase answers behind an off-by-default switch.
- `admin.audit.request` returns one request's audit trail so refusals can
  be quoted.
- Activity reads as swimlanes per agent with agent and repo chips and live
  settle; the GUI's own polling stays out of the tide.

### Changed

- `crates/pam` owns the Tauri app configuration; `pam_gui` is a plain
  library behind it.
- The shell lays out like P-TRACK: a full-height sidebar with the brand
  under the traffic lights and the work panel from the top edge with its
  own toolbar row; the window-wide top strip is gone.
