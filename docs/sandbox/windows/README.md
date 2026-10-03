# Windows: no supported configuration establishes the boundary

**On Windows no supported configuration establishes the boundary today. `pam
doctor` reports `not_established` and lists every private path as reachable.
GUI-only administration there is a convention enforced by the harness's
permission prompts and by the absence of a hostile same-user process, not by the
OS. The enterprise choices are: a dedicated machine or VM per agent with PAM
inside it; or accept the convention and collect the `doctor` record so the fact
is visible.**

There is therefore no Windows profile to apply and `pam doctor --profile` has
no Windows output. This page says what each harness offers on Windows, from its
public documentation, so the statement above can be checked rather than taken.
Nothing here is a measured result unless a dated run is recorded below.

## What the harnesses offer on Windows (read 2026-10-02)

| Harness | What its documentation says | Source |
| --- | --- | --- |
| Claude Code | "On native Windows, Claude Code runs commands unsandboxed." The sandbox runs on macOS, Linux and WSL2. With `failIfUnavailable` set, it exits at startup on native Windows. | <https://code.claude.com/docs/en/sandboxing> |
| Codex | `windows.sandbox` takes `unelevated`, `elevated` or `mxc`. `elevated` "can use dedicated lower-privilege sandbox users, filesystem permission boundaries, and firewall rules"; `unelevated` is a fallback that "cannot enforce every split read/write carveout". | <https://learn.chatgpt.com/docs/config-file/config-reference>, <https://learn.chatgpt.com/docs/permissions> |
| Gemini CLI | the native sandbox uses `icacls` to set a Low mandatory integrity level on files and directories it needs to write to. That is a write restriction; the page does not claim a read restriction. | <https://github.com/google-gemini/gemini-cli/blob/main/docs/cli/sandbox.md> |
| Copilot CLI | local sandboxing on Windows uses the BaseContainer tier of the ProcessContainer backend and needs a Windows Insiders build. | <https://docs.github.com/en/copilot/concepts/security-governance-and-network-settings/about-cloud-and-local-sandboxes> |

## Why none of these is a profile

- PAM's Windows public endpoint is a loopback port whose nonce is in
  `<base>\run\public.json`, readable by its owner only. A process under a
  different account cannot read it, so a PAM client there cannot connect at all
  (`pam doctor` exits `1`, `cannot_probe`): that bounds the agent and also
  excludes it. A process of the same user (a restricted token, Low integrity,
  a harness's own prompts) can read `public.json` and, unless the ACLs of the
  harness say otherwise, the private files beside it.
- Windows Sandbox and a VM isolate a whole desktop, not a process beside PAM.
- There is no AppContainer or restricted-token launcher a harness offers for
  this purpose, and PAM has no Windows session channel (the loopback
  equivalent of `pam listen`) to give a differently-identified process a door.

## What to do

1. Run the agent in a VM or on a separate machine, with PAM installed there. The
   boundary is then the hypervisor or the machine, not the OS user.
2. Or accept the convention and record it: run `pam doctor` from the agent's
   position (it will exit `6`, `not_established`) and keep the report. The
   daemon stores it, and `pam status` shows that the check was made and what it
   found.

A Windows session channel plus a low-privilege-account mode is the future that
would change this; it is not planned here.

## Measured runs

### Measured 2026-10-02

Windows 11 ARM64 (10.0.26200) in the Parallels VM, a debug build of
`feat/boundary-doctor` at `56eb5c5` (`pam 0.4.3`), a scratch base per run, the
daemon started by the CLI's lazy start. Two contexts, with identical results
apart from timings: the VM's SYSTEM context (`prlctl exec`) and its interactive
user (`prlctl exec --current-user`), each against a daemon of its own context.
Neither is a restricted token, so each is the unsandboxed case.

- `pam doctor --json` prints one document and exits `6`; `verdict` is
  `not_established`, `unverified` is empty, and `pam doctor --no-report` exits
  `6` too. The report is recorded (`daemon_reply.accepted` is `true`) and `pam
  status --json` then carries `boundary.last_report` (verdict
  `not_established`, `reports.not_established` counting each reported run).
- `failed` (14): `run.lock_write`, `admin.control_read`, `admin.dir`,
  `store.read`, `store.write`, `store.wal_read`, `store.wal_write`,
  `store.shm_read`, `store.shm_write`, `log.read`, `keychain.search`,
  `daemon.process_query`, `broker.shellexecute`, `exe.write`.
- `skipped` (13): `public.unlink` (side effect); `backup.read`,
  `model_trust.read`, `engine.read`, `engine.runtime_read`, `flows.read`
  (`absent`: nothing there on a fresh base); and, not probed on Windows,
  `admin.endpoint`, `admin.endpoint_alias`, `engine.socket`, `daemon.signal`,
  `broker.launchservices`, `broker.appleevents`, `bundle.write`.
- `admin.control_read` is `allowed`: the control file opens for read (closed
  without reading a byte), so a same-user process can open the file that holds
  the admin plane's nonce. `daemon.process_query` is `allowed` ("query only":
  `Get-Process` returned the daemon's executable path). `broker.shellexecute` is
  `allowed` (`where.exe` was created). `exe.write` is `allowed` through
  `ERROR_SHARING_VIOLATION` (32): the ACL granted the write and only the running
  image's share mode refused it. `keychain.search` is `allowed` (Credential
  Manager answered for the absent account).
- The daemon's view of the caller is thin by design: no pid, uid or executable
  (the public plane admits by nonce), `peer_identity` is `none`, `harness_agrees`
  is `null`, and `claimed_harness` is the client's own nearest ancestor
  (`powershell.exe`; chain `powershell.exe`, `prl_tools_service.exe`,
  `services.exe`, `wininit.exe`).
- Nothing under the base changes. A recursive listing (path, size, timestamp,
  attributes) taken after the daemon started is identical after a `--no-report`
  run; after a reported run only `state.sqlite3-wal` differs (the daemon
  recording the report: 24,752 to 135,992 bytes). `pam.exe --version` still
  answers afterwards.
- `pam doctor --profile <harness>` exits `0` and prints the Windows statement
  (no profile exists here; the text names the options and this page) for every
  harness, and ignores `--base` and `--managed`. Before this was fixed the
  measured run exited `2` with a misleading "not an absolute path" refusal,
  because the macOS profiles name POSIX paths.

Not yet run: the second local user (expected `cannot_probe`, exit `1`) and the
Basic User token of the same SID (`runas /trustlevel:0x20000`, expected exit
`6` with the full list). They are recorded here, with their dates, when made.
