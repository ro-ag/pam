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

## CLI surface

Every subcommand the binary has; there is no raw-protocol escape hatch and no
security command. `--json` prints the daemon's response unchanged, and every
subcommand maps its outcome to the same exit codes: `0` success (or a ticket
handed off), `1` transport/client failure or observation timeout, `2` usage
error, `3` refused, `4` unresolved, `5` blocked.

| Subcommand | What it does |
| --- | --- |
| `pam playbook` | The agent guide as static text: the discover/run/read loop, refusal handling, exit codes, and the sandbox case. No daemon needed. |
| `pam status [--json]` | The daemon's health snapshot (starts the daemon lazily, like every client command). |
| `pam echo [args-json] [--wait\|--no-wait] [--deadline-ms N] [--json]` | Diagnostic: mirrors a JSON object back through the daemon. `--no-wait` prints a ticket instead; the last of `--wait`/`--no-wait` wins. |
| `pam cancel <ticket> [--json]` | Cancels a queued or running request. |
| `pam wait <ticket> [--timeout-ms N] [--json]` | Blocks quietly until the ticket's terminal event, then prints its durable result. Past the timeout (default 10 minutes) it exits `1` and keeps the request running; with `--json` the refusal or timeout is a `kind: refusal` object on stdout. |
| `pam subscribe <ticket> [--timeout-ms N] [--json]` | Like `wait`, but prints each event as it streams. |
| `pam evidence read <evidence-id> --request <ticket> [--offset N] [--length N] [--view ID --digest SHA] [--json]` | Reads one byte range of retained evidence; continue with the returned view, digest and `next_offset`. |
| `pam flow list [--offset N] [--limit 1..=50] [--json]` | The flows this machine has: id, source, steps, name. |
| `pam flow show <id>` | One flow's canonical YAML. |
| `pam flow inspect <id> [key=value…] [--json]` | Inputs and readiness (including whether a model summary will be available) without running. |
| `pam flow run <id> [key=value…] [--no-wait] [--deadline-ms N] [--json]` | Runs one flow and prints its verdict (default deadline 30 minutes); `--no-wait` prints a ticket to `subscribe` to. |
| `pam flow result <ticket> [--json]` | The durable result of a finished flow ticket. |
| `pam service install\|uninstall\|status [--json]` | The login-start unit (see [Start at login](#start-at-login)). |
| `pam listen <dir>` (unix) | Serves a session socket relay: binds `pam.sock`/`events.sock` in `<dir>` and forwards to the daemon, for clients under an agent sandbox that blocks the daemon's own socket — point them at it with `PAM_SOCKET_DIR=<dir>` (see [Session socket relay](docs/session-socket-relay.md)). |
| `pam daemon` | Runs the daemon in the foreground. |
| `pam daemon stop` | Signals the running daemon to drain and exit. |
| `pam gui` | Opens the desktop control center. |

## Desktop workspace

- Manage flows with the visible New, Duplicate, Rename and Delete actions.
  Unsaved edits are guarded; deleted flows can be restored with session undo.
  Canvas connections stay visible when zooming, and Fit uses the available pane.
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
npm --prefix frontend ci             # Node 22.22.2+, 24.15+, or 26+
tools/check.sh                       # the whole local gate: fmt, clippy, rustdoc, tests, eslint, tsc + vite build, vitest
npm --prefix frontend run gui:build  # embedded-frontend binary
npm --prefix frontend run tauri -- build   # platform bundles (dmg, AppImage/deb, NSIS)
```

The frontend builds with TypeScript 7 (`tsc`). Its `@typescript/native` npm alias
provides the native compiler; the `typescript` alias provides Microsoft's
`@typescript/typescript6` compatibility API for ESLint, which does not yet
support the TypeScript 7 API. Keep both aliases when updating dependencies.

For PAM contributors, `pam flow run pam-pr-readiness` from this repository
runs a clean-tree assertion followed by the gates in `tools/check.sh`.
The same flow is listed as **PAM PR readiness** in the GUI. Install frontend
dependencies first with `npm --prefix frontend ci`. Failed gates remain
unresolved and stop dependent gates. The generic **Rust PR readiness** starter
covers Rust checks only; customize it for another project's required gates.
Both flows retain the configured program allowlist and approval policy.

## Agent-companion roadmap

[Scoped admission and budgets](docs/scoped-admission-and-budgets.md) explains GUI repository approvals, target scopes, restart behavior and enforced limits.

The [delivery roadmap](docs/agent-companion-roadmap.md) maps remaining work to
ptrack plans and acceptance gates. The [agent workflow contract](docs/agent-workflow-contract.md)
defines what PAM should do for a sandboxed caller, what works today, and how to
continue implementation.

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
