# GitHub Copilot CLI on macOS: PAM boundary profile

- **Harness:** GitHub Copilot CLI, local sandbox (Seatbelt backend on macOS).
- **Status:** no configuration file format to ship. The sandbox is
  experimental and is configured through the `/sandbox config` dialog, which
  stores its choices under the `sandbox` key of `settings.json` in the Copilot
  CLI configuration directory; the key names inside it are not documented, so
  none are invented here. This page lists the dialog choices, and the
  `sandbox-exec` fallback (`pam doctor --profile sandbox-exec`) is the file to
  use when the dialog cannot express the boundary.
- **Sources:**
  <https://docs.github.com/en/copilot/concepts/security-governance-and-network-settings/about-cloud-and-local-sandboxes>,
  <https://docs.github.com/en/copilot/how-tos/cloud-and-local-sandboxes/configuring-local-sandbox-settings>,
  <https://docs.github.com/en/copilot/how-tos/cloud-and-local-sandboxes/using-local-sandboxing>
- **Verified:** 2026-10-02 (the first two pages read on that date; the third is
  the one the plan cites and was not re-read for this file).
- **Base:** `<base>` is PAM's base directory, default `~/.pam` (or
  `$PAM_BASE_DIR`); `pam doctor --profile copilot-cli [--base DIR]` prints this
  page with it substituted. Use the real path (`realpath ~/.pam`).
- **Allow:** the public socket `<base>/run/pam.sock` and the read of
  `<base>/run/daemon.lock`. No dialog item for a Unix socket is documented;
  see "The public socket" below.
- **Deny:** in the dialog's Filesystem tab, a Denied path rule for each of the
  paths listed below, including the engine runtime `<base>/run/engine.sock` and
  `<base>/run/engine/`; in the Auth tab, "Allow keychain access" off.
- **Prove:** from a command Copilot runs in the sandbox, `pam doctor` must print
  `boundary: established` and exit `0`.

## Dialog settings

Start Copilot CLI with `--experimental`, then `/sandbox enable` and
`/sandbox config` (the invocation the plan recorded from the "using local
sandboxing" page; the sandbox is described as experimental).

Filesystem tab, path rules, permission Denied (one rule each):

- `<base>`
- `<base>/admin`
- `<base>/state.sqlite3`
- `<base>/state.sqlite3-wal`
- `<base>/state.sqlite3-shm`
- `<base>/backup`
- `<base>/model-trust`
- `<base>/engine`
- `<base>/flows`
- `<base>/log`
- `<base>/run/engine`
- `<base>/run/engine.sock`

The rule on `<base>` also covers `<base>/run/daemon.lock`, which the client
reads to decide whether to start the daemon. Add `<base>/run/daemon.lock` as a
Read-Only rule if you want lazy start to work; the documentation lists the three
permissions (Read/Write, Read-Only, Denied) and does not say how overlapping
rules resolve, so check the informational `run.lock_probe` row of `pam doctor`
and, when it is not `allowed`, rely on the relay below. Add
`/Applications/PAM.app` as a Read-Only rule.

Auth tab: "Allow keychain access" **off** (the documented default).

Network tab: "Allow outbound connections" and "Allow local network" are the
only documented network choices.

## The public socket

The documentation lists no Unix-socket setting, and does not say whether "Allow
local network" admits a connection to a Unix socket path. So whether a sandboxed
`pam` can reach the daemon here is not established by this page: run
`pam doctor`. If `public.reach` is not `allowed` (exit `1`, `cannot_probe`),
take one of the two documented-compatible routes:

1. **Session relay.** Run `pam listen <dir>` outside the sandbox with `<dir>`
   inside the working directory (Copilot's "Include working directory" is the
   documented way to give the sandbox that directory), export
   `PAM_SOCKET_DIR=<dir>` into the session, and keep `<base>` denied. The relay
   is the only door; see `docs/session-socket-relay.md`.
2. **The `sandbox-exec` wrapper.** Launch Copilot under
   `pam-agent.sb` (`pam doctor --profile sandbox-exec`), which allows exactly
   the public socket and carries the keychain, signal and broker denials the
   dialog has no setting for.

## What the documentation does not cover

Nothing in the pages above says what the profile does about Mach lookups,
signals, AppleEvents, or LaunchServices, and the sandbox is experimental. That is
what `pam doctor` is for: an `established` verdict from inside Copilot's
sandbox is evidence for that configuration and that Copilot version on that day.

## Windows

Copilot's local sandbox on Windows uses the BaseContainer tier of the
ProcessContainer backend and needs a Windows Insiders build. No claim is made
about it here: see `../windows/README.md`.
