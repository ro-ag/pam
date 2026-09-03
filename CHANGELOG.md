# Changelog

All notable changes to pam are documented in this file. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and pam adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
