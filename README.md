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
error, `3` refused, `4` unresolved, `5` blocked, `6` sandbox boundary not
established (`pam doctor` only), and for `pam policy check` only `11` not
trusted (`--trust`), `12` the policy file is invalid as a whole, `13` valid
with rejected leaves. A daemon started from another
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
| `pam subscribe <ticket> [--timeout-ms N] [--json]` | Like `wait`, but prints each event as it arrives. A late subscriber is shown the earlier events of a running ticket the daemon still holds (`queued`, `started`). Events carry no detail: a progress note is fixed generic text. With `--json`, stdout is JSON only: one compact object per event, then the terminal response. |
| `pam evidence read <evidence-id> --request <ticket> [--offset N] [--length N] [--view ID --digest SHA] [--json]` | Reads one byte range of retained evidence; continue with the returned view, digest and `next_offset`. |
| `pam flow list [--offset N] [--limit 1..=50] [--json]` | The flows this machine has: id, source, steps, name. |
| `pam flow show <id>` | One flow's canonical YAML. |
| `pam flow inspect <id> [key=value…] [--json]` | Inputs and readiness (including whether a model summary will be available) without running. The first line carries the flow's digest. |
| `pam flow run <id> [key=value…] [--no-wait] [--deadline-ms N] [--digest <sha256>] [--json]` | Runs one flow and prints its verdict (default deadline 30 minutes); `--no-wait` prints a ticket to `subscribe` to. `--digest` runs it only if the flow still has the digest `pam flow inspect` printed; otherwise it refuses as `flow_changed`. If the reply is lost, the request id and the `pam wait` recovery are printed. |
| `pam flow result <ticket> [--json]` | The durable result of a finished flow ticket, including the state-changing steps that ran (`effects`). Local-model summaries are labelled `[untrusted local-model summary]`. |
| `pam doctor [--json] [--no-report] [--timeout-ms N]` | Checks the caller's own sandbox boundary: from where it runs, it probes PAM's private paths, endpoints and brokers (writing, creating and sending nothing), prints the verdict and sends the document to the daemon as `doctor.report` (`--no-report` skips that; the exit code never depends on it). Exit `0` `established`, `6` `not_established` (the failed probes are listed), `1` `cannot_probe` (the daemon did not answer the hello; nothing is started). With `--json` the document is the only thing on stdout; when the daemon answered, its reply is the top-level `daemon_reply` member. See [Verifying your agent's sandbox](#verifying-your-agents-sandbox). |
| `pam doctor --profile <claude-code\|codex\|gemini-cli\|copilot-cli\|sandbox-exec> [--base DIR] [--managed]` | Prints the reference sandbox profile for that harness with the base directory filled in (default: the resolved base; `--base` is made absolute and resolved) and exits `0` without probing or dialing; `--managed` prints the locked variant where one exists (Claude Code). The sources, with the per-harness guides, live under [docs/sandbox/](docs/sandbox/README.md). |
| `pam policy check <file> [--platform macos\|windows] [--trust] [--json]` | Validates a managed policy file (the organization's, delivered by MDM) exactly as the daemon would read it, with no daemon and no write: one line per key with its tier, modes, what each mode means and the value or the reason it was rejected, then the digest and what the file locks. `--platform` (or `--for`) checks path syntax for the target platform (default: this machine's); `--trust` also runs this machine's production trust check on the file where it sits and reports each rule. Exit `0` valid, `13` valid with rejected leaves, `12` invalid as a whole, `11` not trusted (`--trust`), `1` unreadable. A file over 64 KiB is refused unread. Delivery guide and samples: [docs/policy/](docs/policy/README.md). |
| `pam service install [--base-dir DIR]\|uninstall\|status [--json]` | The login-start unit (see [Start at login](#start-at-login)). |
| `pam listen <dir>` (unix) | Serves a session socket relay: binds one socket, `pam.sock`, in `<dir>` and forwards to the daemon, for clients under an agent sandbox that blocks the daemon's own socket — point them at it with `PAM_SOCKET_DIR=<dir>` (see [Session socket relay](docs/session-socket-relay.md)). It refuses a `<dir>` that is a link or is shared, and replaces a daemon of version 0.4 or older when it starts. |
| `pam daemon` | Runs the daemon in the foreground. |
| `pam daemon stop` | Signals the running daemon to drain and exit. |
| `pam gui` | Opens the desktop control center. |

### Verifying your agent's sandbox

PAM's administration boundary rests on the agent's OS sandbox keeping it away
from everything PAM owns except one public socket; PAM does not install that
sandbox, it checks it. Apply the harness's profile (`pam doctor --profile
<harness>` prints it; [docs/sandbox/](docs/sandbox/README.md) explains where it
goes), then run `pam doctor` from where the agent runs — by the agent, or by you
in the same terminal with the sandbox applied. `established` means the sandbox
holds that process to the public socket; `not_established` names what it could
reach, which is yours to fix, never the agent's to work around. The daemon keeps
the last report and its own observations of its private plane: `pam status`
prints them on the `boundary:` line, and the desktop app shows them under
Settings › Daemon and on Home. A report changes no authority: authority is per
operating-system user, so every process that can reach the public socket as that
user holds the whole approved set. Caller labels, pids and executable paths are
attribution; agents that need different authority run as different users, and
`pam doctor` proves each one's sandbox (see
[Administration boundary](docs/admin-boundary.md#verifying-the-boundary)).

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

## Local models and the inference engine

PAM can summarize logs with a language model that runs on your own computer.
This is optional and off until you turn it on in Models. It needs two things
PAM does not ship in the app: the llama.cpp inference engine and the model
weights. Neither is downloaded until you press a button, and the Models page
says what the button will fetch, from where, and what it will be checked
against before you press it.

**What is fetched, and from where**

| What | From | Checked against |
| --- | --- | --- |
| The llama.cpp engine, build b10938, one archive for your platform | `github.com/ggml-org/llama.cpp/releases/download/b10938/`, or the engine mirror you set in Settings › Network | the SHA-256 and size below, built into PAM |
| A model you choose in Models › Downloads | `huggingface.co` (the exact address and host are shown before you confirm), or the models mirror you set | the size and SHA-256 listed in PAM's catalog |

| Platform | Archive | Size | SHA-256 |
| --- | --- | --- | --- |
| macOS arm64 | `llama-b10938-bin-macos-arm64.tar.gz` | 11.1 MB | `69f236c8aa148eb32bfd76774a0a449e2f9b754c595e8f6d90b12cf7fecb8399` |
| Windows x64 | `llama-b10938-bin-win-cpu-x64.zip` | 18.4 MB | `ba39502946f4c0e966e5e93393618953dc4c005a252fbaf8c9786c33a9f8b60d` |
| Windows arm64 | `llama-b10938-bin-win-cpu-arm64.zip` | 12.0 MB | `85bc7b14a62092e17beca76295a0e1cbe88510f02623c3b18707ca470c06faeb` |

A file whose size or SHA-256 differs is deleted and not installed, wherever it
came from: GitHub, a mirror or a file on disk. After unpacking, PAM runs the
server once with `--version` and requires it to report build 10938. Only
`https://` addresses are fetched, for the engine, for catalog models and for
pasted model addresses alike. The installed engine's card shows the archive,
its digest, where it came from and the server's version line.

**What runs on your machine.** The engine is an ordinary program started by
the PAM daemon under your user account, only while a model is loaded. It is
installed under `~/.pam/engine` (`%USERPROFILE%\.pam\engine` on Windows). PAM
talks to it over a private socket (a loopback port protected by a per-load key
on Windows), starts it with a model path and an almost empty environment, and
does not give it your connector credentials or any network setting. Models are
stored under the models directory you choose in Settings › Models, not in the
engine folder.

**Model downloads and imports.** Download on a catalog model opens a
confirmation naming the file, its size, the host and address it will be
fetched from (your mirror, or the catalog source), its SHA-256, where it will
be saved and its licence; the transfer starts only when you confirm, and a
transfer that stops resumes where it was. A pasted address has no expected
SHA-256: the file is kept as an unverified, test-only model until you verify
it. Models › Downloads › "Import weights from a file" copies a `.gguf` you
already have into the models directory and hashes it as it copies. A file
whose size matches a catalog model is held to that model's SHA-256 and
recorded as verified; any other file is imported unverified unless you give
its SHA-256, and must pass Verify before it can serve jobs. The original file
is never changed, moved or deleted.

**Corporate networks.** See [Network settings](#network-settings) below:
a proxy, a no-proxy list, a CA bundle and internal mirrors for the engine and
for models, all set in the GUI and applied to connector requests and to
downloads alike.

**No network at all.** On another machine, download the archive for your
platform from the address above (and any model files you want), check the
SHA-256 against the table, and copy them to this one. Then use Models ›
Inference engine › "Install from a file" with the path of the archive, or of a
folder that contains it under its exact name, and Models › Downloads › "Import
weights from a file" for each model. PAM copies the files, checks them against
the same SHA-256 values, and never changes the originals. An unpacked engine
tree is refused: PAM pins the archive's digest, so only the archive can be
checked. Nothing in these steps uses the network or starts curl.

**Removing it.** Models › Inference engine › Remove engine (refused while a
model is loaded; unload it first), or stop the daemon and delete the `engine`
folder named above. That removes the engine, its manifest and the private
verified copies of model weights, so a model shows as needing Verify again.
Model files are deleted from Models; they are not in the engine folder.

### Network settings

Settings › Network is how PAM reaches connector services and download hosts.
Nothing is read from environment variables: `HTTPS_PROXY`, `HTTP_PROXY`,
`ALL_PROXY`, `NO_PROXY`, `CURL_CA_BUNDLE`, `SSL_CERT_FILE`, `SSL_CERT_DIR` and
their lowercase spellings are ignored by the daemon and by every curl it
starts, and the page lists which of them are present so you know they do
nothing. Only what you save on the page is used, and it is read again for
every request, so a change applies to the next one. Saving a proxy address, a
proxy password or a CA bundle asks for the typed word `network`, because a
proxy that inspects TLS can read the credentials PAM sends to connectors.

- **Proxy.** An `http://` or `https://` address with an explicit port, for
  example `http://proxy.corp.example:3128`. SOCKS, PAC and WPAD are not
  supported; a user name or password inside the address is refused. Sign-in
  is `none`, `basic`, or `anyauth` (curl picks Basic, Digest or NTLM from the
  proxy's challenge; NTLM takes `DOMAIN\user` as the user name). The user
  name is stored in the settings; the password goes into the operating
  system's keychain and is never written to the settings, a log line, an
  audit row, a reply or a command line. It reaches curl only on its standard
  input, for one request at a time. With an `http://` proxy and Basic
  sign-in the password crosses your network to the proxy unencrypted; the page
  says so beside the field.
- **No-proxy list.** Host names (matching the host and its subdomains, with or
  without a leading dot), IP addresses, and CIDR ranges such as `10.0.0.0/8`
  when the system curl is 7.86 or newer. No ports, no wildcards inside names.
  Loopback targets never go through the proxy, whatever the list says.
- **CA bundle.** Leave it empty when the root your organization uses is
  already trusted by this computer (an MDM profile on macOS; Group Policy or
  Intune on Windows). On Windows a CA bundle file cannot be imported: install
  the CA in the Windows certificate store (machine or user), which PAM's curl
  trusts, and the page shows the field read-only. On macOS, give the path of a
  PEM file: PAM reads it once, keeps only its certificate blocks (a file
  holding a private key is refused whole), writes a private copy under
  `~/.pam/net`, records the copy's SHA-256 and checks it again before every
  request; a copy that no longer matches refuses the request rather than
  running without it. The source file must be owned by you or by root and not
  writable by other users, and so must its directory. The bundle is handed to
  curl as its `cacert`, so for PAM's requests it is expected to stand in for
  the system trust: include every root the services and download hosts need.
  What has been measured on macOS: a private test issuer is untrusted until
  its root is imported and trusted afterwards; whether the system roots still
  apply beside the bundle is not measured, and the page warns about it when
  you save. A Windows `cacert` replaces the store's trust and a private CA
  with no http CRL fails revocation, which is why Windows uses the store; that
  failure shows as `tls_revocation_unavailable`. PAM offers no "do not verify"
  option anywhere, and never writes to the operating system's certificate
  store.
- **Mirrors.** The engine mirror is a directory address; PAM appends the
  archive name from the table above unchanged. The models mirror replaces the
  `https://huggingface.co/` prefix of a catalog address and keeps the rest;
  a pasted address is never rewritten. Mirrors must be `https://`, may use a
  host name or an internal IP address with a port, and may not be loopback,
  link-local or `localhost`. The bytes a mirror serves are checked against
  the same sizes and digests as the originals.
- **Test network settings.** Sends a credential-free `HEAD` to each place PAM
  actually goes — every enabled connector's base address, the engine archive
  address when the engine is not installed or a mirror is set, and the models
  host when a models mirror is set or a model is not installed — at most
  twelve targets, four at a time, within twenty seconds. Any HTTP status
  means the path works; a failure says the route (`direct`, `bypass`, or
  `proxy`), the stage it reached (`connect`, `proxy`, `tunnel`, `tls`,
  `http`) and a cause with a recovery line: the proxy name did not resolve,
  the proxy wants a sign-in (naming the schemes it offers), the certificate
  issuer is not trusted (naming it where this curl prints it), the name did
  not resolve, and so on. It never takes a free-form address.

Administration of all of this stays in the GUI; there is no CLI command for
network settings, mirrors, imports or the engine.

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

## Managed deployment

An organization can manage PAM on its machines with one read-only JSON file
delivered by its MDM (Jamf, Kandji, Intune, a GPO startup script). It can
lock a setting, set a default the human may change, bound or allowlist it,
and add constraints only an organization states, such as capabilities that
are never granted or the repository roots agents may work in. Settings shows
every managed value and why; the human's own settings are never rewritten and
come back when the file is removed.

| Platform | Fixed path (no flag or variable moves it) | Must be |
| --- | --- | --- |
| macOS | `/Library/Application Support/PAM/policy.json` | owned by root, with every folder above it, and writable by nobody else |
| Windows | `%ProgramData%\PAM\policy.json` | unwritable by the user's token: SYSTEM and Administrators full control, Users read |

A file that fails this trust check, or is damaged, never loosens anything:
the last good copy stays in force. Validate a file before the push, and check
what an endpoint holds:

```sh
pam policy check policy.json --platform windows          # 0 valid, 13 rejected leaves, 12 invalid
pam policy check "/Library/Application Support/PAM/policy.json" --trust --json   # 11 not trusted
```

The delivery guide, the scripts, every key and three sample files are in
[docs/policy/](docs/policy/README.md); the design is in
[the managed policy spec](docs/specs/2026-10-02-managed-policy-file.md).

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
