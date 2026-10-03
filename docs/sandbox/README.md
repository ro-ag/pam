# Reference sandbox profiles

PAM's administration boundary rests on one assumption: the agent's OS sandbox
keeps the agent away from everything PAM owns except one public socket (see
[admin-boundary.md](../admin-boundary.md)). PAM does not install, edit or lock
that sandbox. These profiles are the text you put in the harness's own
configuration, and `pam doctor` is how you check the harness enforced it.

A profile is **not** a PAM feature and not a guarantee: it is a starting point
that the harness enforces, and the proof is a `pam doctor` run from inside it.

## The invariant every profile keeps

With `<base>` the PAM base directory (default `~/.pam`, or `$PAM_BASE_DIR`):

1. **Allow** exactly one door: the Unix socket `<base>/run/pam.sock`, and the
   read of `<base>/run/daemon.lock` (the client's readiness probe). Under the
   [session relay](../session-socket-relay.md), allow exactly
   `<dir>/pam.sock` (the directory `pam listen <dir>` serves) and nothing under
   `<base>` at all.
2. **Deny** the rest of `<base>`: `admin/` and its socket, `state.sqlite3` with
   `-wal` and `-shm`, `backup/`, `model-trust/`, `engine/`, `flows/`, `log/`.
   The engine's private socket and its transient API key live under
   `<base>/engine/run`, inside the denied `engine/` tree; nothing but
   `pam.sock` and `daemon.lock` is under `run/`, and each profile allows the
   literal `pam.sock` rather than `run/` by subpath.
3. **Deny** the keychain, process control of the daemon (signals), and the GUI
   launch brokers (LaunchServices, AppleEvents on macOS).
4. **Deny** writes to the trusted `pam` executable and to the `.app` bundle.

Where a harness has no setting for one of these, the profile says so and
`pam doctor` reports it; it does not pretend.

## The files

| Harness | File | Format | Status (verified 2026-10-02) |
| --- | --- | --- | --- |
| Claude Code | [`macos/claude-code.md`](macos/claude-code.md), [`claude-code.settings.json`](macos/claude-code.settings.json), [`claude-code.managed-settings.json`](macos/claude-code.managed-settings.json) | `settings.json` `sandbox` and `permissions` keys | documented format, cited; format verified by syntax only (both variants parse, every path substituted) — the harness enforces it, `pam doctor` from inside is the evidence |
| Codex | [`macos/codex.config.toml`](macos/codex.config.toml) | `config.toml` permission profile | documented keys, cited; Beta page; format verified by syntax only — `pam doctor` from inside is the evidence |
| Gemini CLI | [`macos/gemini-cli.sandbox-macos-pam.sb`](macos/gemini-cli.sandbox-macos-pam.sb) | custom Seatbelt profile file | documented mechanism, source read; `pam doctor` under `sandbox-exec` with the launcher's `-D` names: **`established`** (`doctor_macos.rs`, macOS 26) |
| Copilot CLI | [`macos/copilot-cli.md`](macos/copilot-cli.md) | `/sandbox config` dialog choices | no file format; dialog choices verified by reading only; the `pam-agent.sb` wrapper it falls back to is `established` (below) |
| anything else (Cursor, Aider, a shell, a wrapper) | [`macos/pam-agent.sb`](macos/pam-agent.sb) | `sandbox-exec` profile | fallback; the strongest; `pam doctor` under it: **`established`**, exit 0, report recorded (`doctor_macos.rs`, macOS 26). Relay variant as commented (no read under `<base>`): **`established`** too — the daemon's pid comes from the hello acknowledgement, so `daemon.signal` is judged without the lock file; keeping the `daemon.lock` read line changes only the informational lock probe |
| Windows | [`windows/README.md`](windows/README.md) | none | no supported configuration |

`pam doctor --profile <name> [--base DIR]` prints the profile with `<base>`
replaced by the real path (names: `claude-code`, `codex`, `gemini-cli`,
`copilot-cli`, `sandbox-exec`; add `--managed` for the Claude Code managed
variant). The files here are the sources of what the binary embeds.

Use the real path: Seatbelt and the harnesses match resolved paths, so
`realpath ~/.pam` (a symbolic link in the base defeats a literal rule).

## How to apply

- **Claude Code:** merge `claude-code.settings.json` into
  `~/.claude/settings.json`, or deploy the managed variant to
  `/Library/Application Support/ClaudeCode/managed-settings.d/`. Read the
  limits in `claude-code.md` first: the sandbox covers Bash only.
- **Codex:** merge `codex.config.toml` into `~/.codex/config.toml`.
- **Gemini CLI:** `pam doctor --profile gemini-cli > ~/.gemini/sandbox-macos-pam.sb`,
  then start Gemini with `GEMINI_SANDBOX=sandbox-exec SEATBELT_PROFILE=pam`.
- **Copilot CLI:** apply the dialog choices in `copilot-cli.md`, or wrap Copilot
  in `pam-agent.sb` (below).
- **Anything else:** `pam doctor --profile sandbox-exec > pam-agent.sb`, then
  `sandbox-exec -D HOME="$HOME" -D WORKSPACE="$PWD" -D PAM_EXE="$(command -v pam)" -f pam-agent.sb <harness>`.
  The profile is deny-by-default with no Mach lookup and no network beyond
  `pam.sock`, so a harness that must reach its model API or system services
  needs narrow allowances added in the marked section; never remove or reorder
  the PAM block, which must stay last.

## How to verify

From inside the sandboxed harness (a command the harness runs, with its sandbox
applied), run:

```sh
pam doctor
```

It must print `boundary: established` and exit `0`. `pam doctor --json` is the
same for scripts (exit `6` is `not_established`, `1` is `cannot_probe`).
The daemon records the run; `pam status` then shows it.

What the other answers mean for a profile:

- `not_established`, **`failed`** lists probes that were *allowed* where denial
  is required: the profile (or the harness's enforcement of it) does not hold
  for that path. `admin.*`, `store.*`, `engine.*` are file rules in the profile
  or the harness ignoring them; `keychain.search`, `daemon.signal` and
  `broker.*` are things most harness sandboxes document nothing about, so this is
  where a harness profile typically falls short: wrap it in `pam-agent.sb`, or
  accept and record the finding.
- **`unverified`** lists probes that could not be classified (timeout, a helper
  that could not run). An unknown fails the verdict; re-run, and report one that
  persists.
- **`skipped`** lists probes that were absent (`absent`: nothing exists there,
  for example no engine is installed) or not probed on this platform. They do
  not count either way.
- `cannot_probe` (exit `1`): the public socket was not reachable. The profile
  closes the one door it must leave open, or the daemon is not running, or `<base>`
  is not the resolved path. Use the relay in
  [session-socket-relay.md](../session-socket-relay.md) when the harness cannot
  carry a socket path.
- A `doctor` run **outside** any sandbox says `not_established` on every
  correctly working machine; it proves installation and reachability, not the
  boundary.

An `established` verdict is a statement about the command that ran: if the
harness can run commands outside its sandbox (a retry escape hatch, a hook, an
MCP server, a file tool), those are not covered by it. Each file says what its
harness leaves outside.

## Windows

No supported harness configuration establishes the boundary on Windows. `pam
doctor` reports `not_established` there. The real options are a VM or a separate
machine per agent with PAM inside it, or accepting and recording the
convention. See [windows/README.md](windows/README.md) for the statement, the
evidence from each harness's documentation, and the reasons.

## Keeping these current

Each file carries its sources and the date it was verified against; harness
sandboxes change quickly (Codex's permission profiles and Copilot's local
sandbox are marked beta or experimental). Re-verify before relying on a file
after a harness upgrade, and run `pam doctor` again: the file is a claim, the
run is the evidence.
