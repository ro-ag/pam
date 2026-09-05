<p align="center">
  <img src="docs/assets/pam-mark.svg" width="160" alt="Pam mark: a lifeguard tower against a coral sun">
</p>

<h1 align="center">pam</h1>

<p align="center"><strong>A local lifeguard for developers and AI agents.</strong></p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-Apache--2.0-1d7893.svg" alt="License: Apache-2.0"></a>
  <a href="https://github.com/ro-ag/pam/releases/latest"><img src="https://img.shields.io/github/v/release/ro-ag/pam" alt="Latest release"></a>
  <a href="https://github.com/ro-ag/pam/actions/workflows/ci.yml"><img src="https://github.com/ro-ag/pam/actions/workflows/ci.yml/badge.svg?branch=main" alt="CI"></a>
</p>

---

pam is a single-binary local companion — CLI, daemon, and GUI in one
executable — that gives sandboxed AI agents (and the humans running them)
controlled, audited access to real capabilities: local models first, then
flows and connectors. Security administration (grants, approvals, profiles)
lives in the GUI only; agents see a fixed set of static subcommands, never a
raw-protocol escape hatch.

```text
pam status                  # client mode (default): talk to the daemon
pam daemon                  # the local background service (started lazily by any command)
pam gui                     # the desktop control center
pam flow run pr-readiness   # Rust-only starter; use pam-pr-readiness for PAM
```

## Install

Grab the latest packaged build from the
[releases page](https://github.com/ro-ag/pam/releases/latest).

| Platform | Architecture | Package | CLI location |
| --- | --- | --- | --- |
| macOS 12+ | arm64 | signed, notarized `.dmg` | drag `pam.app` to Applications; the CLI is `/Applications/pam.app/Contents/MacOS/pam` — symlink it into your `PATH` |
| Linux | amd64, arm64 | AppImage or `.deb` | `/usr/bin/pam` |
| Windows | amd64, arm64 | NSIS per-user installer | `%LOCALAPPDATA%\pam\pam.exe`; the Start-menu shortcut opens the GUI (a console window behind it is expected) |

## Quickstart

```sh
pam status              # daemon health snapshot
pam flow list           # flows this machine has
pam flow run <id>       # run one and print its verdict
pam gui                 # open the desktop control center
```

Grants, approvals, and profiles are managed in the GUI (Settings › Security),
not on the command line.

## Desktop workspace

- Use Cmd/Ctrl+K to jump to pages, Settings categories, models or flows.
  Navigation never runs a flow automatically.
- Choose Monitor, Build or Focus from Workspace, or save a layout and route
  for later. Expand a flow canvas and press Escape to restore the workspace.
- Settings uses eight tabs with retained drafts and wide-screen layouts.
  Appearance offers four Costa palettes, surface opacity, and background
  motion speed and intensity. System accessibility preferences take priority.
- Home, Flows, Activity, Approvals and Models keep their page controls fixed
  while the active task pane scrolls. Keyboard-accessible tabs separate flow
  editing and runs, activity compression, and model operations.

## Start at login

```sh
pam service install     # register the unit and start the managed daemon now
pam service status      # show whether the unit exists and is loaded
pam service uninstall   # unregister and remove the unit; the manager stops the managed daemon, the next pam command starts one lazily
```

Each platform gets one user-scope unit, never sudo or admin:

| Platform | Unit |
| --- | --- |
| macOS | LaunchAgent at `~/Library/LaunchAgents/com.github.ro-ag.pam.daemon.plist` |
| Linux | systemd user unit at `~/.config/systemd/user/pam-daemon.service` |
| Windows | scheduled task `pam\daemon` |

Settings › Daemon in the GUI shows the same state with Install and Remove.

## Build from source

```sh
rustup show                          # picks up rust-toolchain.toml
npm --prefix frontend ci             # Node 22
tools/check.sh                       # the whole local gate: fmt, clippy, tests, eslint, tsc + vite build, vitest
npm --prefix frontend run gui:build  # embedded-frontend binary
npm --prefix frontend run tauri -- build   # platform bundles (dmg, AppImage/deb, NSIS)
```

For PAM contributors, `pam flow run pam-pr-readiness` from this repository
runs a clean-tree assertion followed by all six gates in `tools/check.sh`.
The same flow is listed as **PAM PR readiness** in the GUI. Install frontend
dependencies first with `npm --prefix frontend ci`. Failed gates remain
unresolved and stop dependent gates. The generic **Rust PR readiness** starter
covers Rust checks only; customize it for another project's required gates.
Both flows retain the configured program allowlist and approval policy.

## Releasing

1. Bump the version in `Cargo.toml` (`[workspace.package]`),
   `crates/pam/tauri.conf.json`, and `frontend/package.json`.
2. Move the changelog's `## [Unreleased]` entries under
   `## [X.Y.Z] - YYYY-MM-DD`.
3. Merge, and wait for the `main` CI run to finish green.
4. `git tag -a vX.Y.Z -m "vX.Y.Z" && git push origin vX.Y.Z`.

`release.yml` validates, signs, notarizes, and publishes the packages.
Releases are cut only from CI on a tag push — never locally.

## License

[Apache-2.0](LICENSE).
