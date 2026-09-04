# Changelog

All notable changes to pam are documented in this file. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and pam adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
