# Claude Code on macOS: PAM boundary profile

- **Harness:** Claude Code, the sandboxed Bash tool (Seatbelt on macOS).
- **Status:** verified format. The `sandbox` and `permissions` keys below are
  the documented ones; what the documentation does not say is listed under
  "What the documentation does not cover" and is left to `pam doctor`.
- **Sources:** <https://code.claude.com/docs/en/sandboxing>,
  <https://code.claude.com/docs/en/settings-reference>,
  <https://code.claude.com/docs/en/managed-settings>
- **Verified:** 2026-10-02 (the three pages above read on that date; the JSON
  files parse; the rendered `<base>` paths are absolute as the pages require).
- **Base:** `<base>` is PAM's base directory, default `~/.pam` (or
  `$PAM_BASE_DIR`). `pam doctor --profile claude-code [--base DIR]` prints the
  fragment with it substituted; use the real path (`realpath ~/.pam`).
- **Allow:** `sandbox.network.allowUnixSockets` lists exactly one socket,
  `<base>/run/pam.sock`; `sandbox.filesystem.allowRead` re-opens exactly one
  file inside the denied base, `<base>/run/daemon.lock` (the client's readiness
  probe).
- **Deny:** `sandbox.filesystem.denyRead` names the base and every private path
  under it (the engine's socket and API key live under `<base>/engine/run`,
  covered by the `<base>/engine` rule); `denyWrite` names the base and
  `/Applications/PAM.app`; `permissions.deny` stops Claude's own file tools.
- **Prove:** from a Bash tool call inside a Claude Code session run
  `pam doctor`; it must print `boundary: established` and exit `0`.

## Files

| File | Use |
| --- | --- |
| `claude-code.settings.json` | merge into `~/.claude/settings.json` (a user's own settings) |
| `claude-code.managed-settings.json` | the same plus the admin-required locks; deliver as `/Library/Application Support/ClaudeCode/managed-settings.d/20-pam-boundary.json`, or through the `com.anthropic.claudecode` managed preferences domain (`pam doctor --profile claude-code --managed`) |

Merge, do not replace: keep your other keys. Array keys such as `denyRead`
merge across settings scopes; the managed variant's `allowManagedReadPathsOnly`
makes only managed `allowRead` entries count, so a developer cannot re-open
`<base>`.

## What the profile does not do (read this)

- **The sandbox covers shell commands only.** Claude's Read, Edit and Write
  tools, MCP servers and hooks run outside it; the documentation says "a
  `denyRead` entry doesn't stop the Read tool". The `permissions.deny` lines in
  the fragment (`Read(//…/**)`, `Edit(//…/**)`; `//` is an absolute path in
  permission rules, unlike sandbox paths) cover the file tools. A local MCP
  server or hook runs with your full access: `pam doctor` run from a Bash call
  says nothing about them.
- **The unsandboxed retry.** Without `allowUnsandboxedCommands: false` the
  model can retry a blocked command outside the sandbox; an `established`
  verdict is then a statement about one command, not the session. Only the
  managed variant sets it. A command you type at the `!` prompt also runs
  unsandboxed in most sessions.
- **Native Windows is not sandboxed by Claude Code at all** ("On native Windows,
  Claude Code runs commands unsandboxed"): see `../windows/README.md`.
- **Repository settings** cannot widen an admin-required sandbox, but until the
  managed variant is in place a repository's `.claude/settings.json` can add
  `allowRead`/`allowUnixSockets` entries. Use the managed variant on any machine
  where that matters.
- The `pam` executable is not named: Claude's default write set is the working
  directory and temporary directories, so an installed `pam` is not writable.
  `pam doctor` probes `exe.write`; if you run a `pam` built inside the working
  directory, it will say `allowed`.

## What the documentation does not cover

The sandbox page does not say whether Claude Code's Seatbelt profile refuses the
keychain service, signals to other processes, Mach lookups, LaunchServices or
AppleEvents (it lists `allowAppleEvents` and `allowMachLookup` as settings,
which suggests a default of off, but gives no guarantee). `pam doctor` reports
each as a probe. If one of `keychain.search`, `daemon.signal`,
`broker.launchservices` or `broker.appleevents` is `allowed`, this file cannot
close it: wrap the session in `pam-agent.sb` (`sandbox-exec` profile, see
`pam-agent.sb`) or accept and record the finding.

## If `public.reach` is not allowed

Claude Code says `allowUnixSockets` lists "Unix socket paths sandboxed commands
can use on macOS". If `pam doctor` reports `cannot_probe` with the public socket
refused, check that `<base>` is the resolved path (a symbolic link in `~/.pam`
defeats a literal match), that the daemon is running, and, when the policy
cannot carry the socket path, use the session relay instead
(`docs/session-socket-relay.md`): run `pam listen <dir>` outside the sandbox,
export `PAM_SOCKET_DIR=<dir>`, and list `<dir>/pam.sock` in `allowUnixSockets`
instead of the public socket, keeping `<base>` fully denied.
