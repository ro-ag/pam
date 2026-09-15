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

### Added

- A straight answer to "can PAM reach the keychain?", in three places:
  `pam status` prints a `keyring:` line with the recovery sentence when it
  is blocked, Settings → Connectors carries a banner with a Re-check
  button, and Home flags a blocked keychain in the workspace overview. New
  admin op `admin.connectors.keyring { fresh? }`, and the daemon's `status`
  capability publishes a read-only `keyring` block. Reachability only — no
  capability can read a credential, and the probe reads an account nothing
  ever writes.

### Added

- Partial downloads can be thrown away from the Models screen: a preset
  card that has bytes on disk offers Resume and Start over, says how much
  is already here, and confirms before discarding. New admin op
  `admin.models.download.discard`, and `admin.models.catalog` now reports
  `partial_bytes` per preset — a part file is a dotfile a registry scan
  cannot see, so a resumable transfer no longer depends on a job row that
  may have aged out. This is also the way out of a checkpoint conflict,
  which previously needed a manual `rm`.

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
