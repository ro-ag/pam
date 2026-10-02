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
| macOS 12+ | arm64 (Apple Silicon) | signed, notarized `.dmg` | drag `pam.app` to Applications; the CLI is `/Applications/pam.app/Contents/MacOS/pam` — symlink it into your `PATH` |
| Windows | amd64, arm64 | NSIS per-user installer | `%LOCALAPPDATA%\pam\pam.exe`; the Start-menu shortcut opens the GUI (a console window behind it is expected) |

### Supported platforms

macOS 12+ on Apple Silicon, and Windows 10/11 on amd64 and arm64. Linux and
Intel Macs are not supported.

## Quickstart

```sh
pam status              # daemon health snapshot
pam flow list           # flows this machine has
pam flow run <id>       # run one and print its verdict
pam gui                 # open the desktop control center
```

Grants, approvals, and profiles are managed in the GUI (Settings › Security),
not on the command line. The sidebar shows the PAM logo and installed version;
Flows provides a searchable library and a canvas that stays usable in compact
windows. Save and Discard changes stay visible above the flow editor; built-in
flows can be duplicated to create editable copies. Home spreads Ask Pam and the
task starters across wide windows. Activity shows requests and results; log
compression runs internally.

## CLI surface

Every subcommand the binary has; there is no raw-protocol escape hatch and no
security command. `--json` prints the daemon's response unchanged, and every
subcommand maps its outcome to the same exit codes: `0` success (or a ticket
handed off), `1` transport/client failure or observation timeout, `2` usage
error, `3` refused, `4` unresolved, `5` blocked. A daemon started from another
build refuses the command (`client_version_mismatch`, exit `3`) and keeps
running; a daemon of version 0.4 or older that this process may not stop is a
client failure (exit `1`) with the instruction to run `pam daemon stop` and
then `pam status` outside the sandbox.

| Subcommand | What it does |
| --- | --- |
| `pam playbook` | The agent guide as static text: the discover/run/read loop, refusal handling, exit codes, and the sandbox case. No daemon needed. |
| `pam status [--json]` | The daemon's health snapshot (starts the daemon lazily, like every client command). It is served from a snapshot refreshed in the background: `snapshot.stale` says when a part is out of date, `active_requests` does not count the poll itself, and a poll leaves no request or audit row. |
| `pam echo [args-json] [--wait\|--no-wait] [--deadline-ms N] [--json]` | Diagnostic: mirrors a JSON object back through the daemon. `--no-wait` prints a ticket instead; the last of `--wait`/`--no-wait` wins. A delay over 60 s or arguments over 64 KiB are refused. |
| `pam cancel <ticket> [--json]` | Cancels a queued or running request. Run it from the repository the ticket was submitted from: another repository's ticket answers `not_found`. |
| `pam wait <ticket> [--timeout-ms N] [--json]` | Follows the ticket on one connection and blocks quietly until it ends, then prints the durable result the stream ended with; a ticket that already finished is answered at once. Transient daemon refusals are retried and a dropped connection is resumed after the last event seen, until the timeout (default 10 minutes), when it exits `1` and keeps the request running; exit `3` means the daemon refused (policy, or a daemon of another build). With `--json` the refusal or timeout is a `kind: refusal` object on stdout. Run it from the repository the ticket was submitted from. |
| `pam subscribe <ticket> [--timeout-ms N] [--json]` | Like `wait`, but prints each event as it arrives. A late subscriber is shown the earlier events of a running ticket the daemon still holds (`queued`, `started`). Events carry no detail: a progress note is fixed generic text. |
| `pam evidence read <evidence-id> --request <ticket> [--offset N] [--length N] [--view ID --digest SHA] [--json]` | Reads one byte range of retained evidence; continue with the returned view, digest and `next_offset`. |
| `pam flow list [--offset N] [--limit 1..=50] [--json]` | The flows this machine has: id, source, steps, name. |
| `pam flow show <id>` | One flow's canonical YAML. |
| `pam flow inspect <id> [key=value…] [--json]` | Inputs and readiness (including whether a model summary will be available) without running. The first line carries the flow's digest. |
| `pam flow run <id> [key=value…] [--no-wait] [--deadline-ms N] [--digest <sha256>] [--json]` | Runs one flow and prints its verdict (default deadline 30 minutes); `--no-wait` prints a ticket to `subscribe` to. `--digest` runs it only if the flow still has the digest `pam flow inspect` printed; otherwise it refuses as `flow_changed`. If the reply is lost, the request id and the `pam wait` recovery are printed. |
| `pam flow result <ticket> [--json]` | The durable result of a finished flow ticket, including the state-changing steps that ran (`effects`). Local-model summaries are labelled `[untrusted local-model summary]`. |
| `pam service install [--base-dir DIR]\|uninstall\|status [--json]` | The login-start unit (see [Start at login](#start-at-login)). |
| `pam listen <dir>` (unix) | Serves a session socket relay: binds one socket, `pam.sock`, in `<dir>` and forwards to the daemon, for clients under an agent sandbox that blocks the daemon's own socket — point them at it with `PAM_SOCKET_DIR=<dir>` (see [Session socket relay](docs/session-socket-relay.md)). It refuses a `<dir>` that is a link or is shared, and replaces a daemon of version 0.4 or older when it starts. |
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
pam service status      # show whether the unit exists and is loaded, and whether it pins this binary
pam service uninstall   # unregister and remove the unit; the manager stops the managed daemon, the next pam command starts one lazily
```

On Windows a lazy start goes through the system PowerShell so the daemon does
not hold the calling program's output pipe. Where policy blocks PowerShell,
install the login unit: a managed daemon needs no lazy start.

Each platform gets one user-scope unit, never sudo or admin:

| Platform | Unit |
| --- | --- |
| macOS | LaunchAgent at `~/Library/LaunchAgents/com.github.ro-ag.pam.daemon.plist` |
| Windows | scheduled task `pam\daemon` |

`install` writes the unit first and then stops a loose daemon so the managed one
takes over. It refuses a binary in a temporary directory, in cargo build output
or writable by group or others, because the unit pins that binary's path. It
uses `~/.pam` unless given `--base-dir`; `$PAM_BASE_DIR` is not carried over.
`status` reports the pinned binary and whether it is stale.

Settings › Daemon in the GUI shows the same state with Install, Remove and
"Repoint to this binary".

A daemon that a command starts lazily runs with a reduced environment, in its
own process group, and does not inherit the caller's variables; add tool
directories for flows through the flow settings, not the shell.

## Build from source

Building needs a C compiler on every target, because the store links SQLite
compiled from the amalgamation bundled in the `libsqlite3-sys` crate: the Xcode
command line tools on macOS (`xcode-select --install`), the MSVC build tools
("Desktop development with C++", with the ARM64 toolset on Windows arm64) on
Windows. Nothing else is downloaded at build time. See
[native build dependencies](docs/native-build-dependencies.md).

```sh
rustup show                          # picks up rust-toolchain.toml
npm --prefix frontend ci             # Node 22.22.2+, 24.15+, or 26+
tools/check.sh                       # the whole local gate: fmt, clippy, rustdoc, tests, eslint, tsc + vite build, vitest
npm --prefix frontend run gui:build  # embedded-frontend binary
npm --prefix frontend run tauri -- build   # platform bundles (dmg, NSIS)
```

A binary built without the embedded frontend (any plain `cargo build`) opens
its window on the Vite development server and therefore refuses to start
`pam gui` unless `PAM_GUI_DEV=1` is set; `npm --prefix frontend run dev:desktop`
sets it and starts both, on macOS and Windows alike.

The frontend builds with TypeScript 7 (`tsc`). Its `@typescript/native` npm alias
provides the native compiler; the `typescript` alias provides Microsoft's
`@typescript/typescript6` compatibility API for ESLint, which does not yet
support the TypeScript 7 API. Keep both aliases when updating dependencies.

For PAM contributors, `pam flow run pam-pr-readiness` from this repository
runs a clean-tree assertion followed by the gates in `tools/check.sh`.
The same flow is listed as **PAM PR readiness** in the GUI. Install frontend
dependencies first with `npm --prefix frontend ci`. Failed gates remain
unresolved and stop dependent gates, and a state-changing step that names no
`needs` does not run after any earlier failure. The generic **Rust PR readiness** starter
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
