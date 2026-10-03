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

None recorded yet. The Windows acceptance runs (the owner's account, a second
local user, and a Basic User token of the same SID) are recorded here, with
their dates, when they are made.
