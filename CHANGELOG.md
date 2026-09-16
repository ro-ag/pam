# Changelog

All notable changes to pam are documented in this file. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and pam adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

### Added

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
