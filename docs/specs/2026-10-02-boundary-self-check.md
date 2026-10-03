# Boundary self-check: `pam doctor`, a status field and reference sandbox profiles — design and implementation plan

Status: implemented (T1–T6, T8); T7/T9 acceptance in progress. Built on
`feat/boundary-doctor`, 2026-10-02. What was built, where it departs from the
design below, is in [As built](#as-built-2026-10-02); where the two disagree, As
built is the behavior. The statement the docs now carry on authority is in
[the administration boundary](../admin-boundary.md#global-target-authority) and
the verification section after it.

ptrack plan 53; closes the first half of issue 41 and records the position on
the second half (per-agent authority). Written 2026-10-02 against branch
`feat/enterprise-network` (head `2708857`), read-only; line references are to
that tree.

PAM's administration boundary rests on an assumption it never checks: that the
agent's OS sandbox keeps the agent away from everything but the public socket
(`docs/admin-boundary.md:83-96`, `:115-117` "PAM does not automatically install
or verify the agent's sandbox policy"). The design review called this the central
gap — "GUI-only administration is ceremony unless the sandbox is right" — and
issue 41 proposes the remedy this spec designs: a probe run from the caller's
position (`pam doctor`), a daemon-side record of what it observed (a `boundary`
block in `status`), and reference sandbox profiles per agent harness with the
`doctor` run that proves each one.

The owner's directive applies: best for the product, easy for enterprise
environments; supported platforms are macOS arm64 and Windows amd64/arm64 only.

## Goal and non-goals

Goal. A human, an MDM script, or the agent itself can answer, with evidence,
"is this agent held to the public socket, or can it reach PAM's private state?"
— and the daemon shows, on its own side, whether anyone has ever answered it
and whether anything it saw contradicts the answer. PAM stays honest where the
answer is "no": `not_established` is the expected state of an unsandboxed
developer Mac and of every supported Windows configuration today, and the docs
say what that means.

Non-goals.

- PAM does not install, edit or lock the harness's sandbox policy. The
  reference profiles are text the human (or MDM) puts in the harness's own
  configuration; the harness enforces them.
- `doctor` never changes authority. No gate reads its verdict; a
  `not_established` machine is served exactly as before (see
  "Refusal-free semantics").
- No per-agent grant model. Section "Per-agent authority" recommends against
  it and says what the docs must state instead.
- No Windows session channel (the loopback equivalent of `pam listen`), no
  AppContainer launcher, no Linux. Each is named where it would matter.
- No change to the wire protocol beyond one new public capability
  (`doctor.report`) and one new `status` block.

## Current state

### The trust model and what is unverified

`docs/admin-boundary.md:85-90` lists what the agent sandbox must exclude: the
private endpoint and its directory, PAM's private state including
authorization data and credential access, modification of the trusted
executable and frontend assets, and control of trusted process memory and
execution. `:98-108` extends it to indirect routes: LaunchServices and other
process brokers, AppleEvents/UI automation, task ports, debugging, inherited
descriptors, replacement of frontend assets, and a writable development server.
`:110-113` adds the keychain service, not just its files. `:115-117` says
nothing verifies any of it.

The fixture that comes closest is `crates/pam/tests/sandbox_macos.rs`: a
default-deny `sandbox-exec` profile (`crates/pam/tests/support/broker-macos.sb:4-20`)
that allows `file-read*`, `process-exec`, `process-fork`, `sysctl-read`,
`process-info*`, writes to `/dev/null`, and one `network-outbound` to the
literal public socket, and denies data reads and writes under `<base>/admin`,
the three SQLite files, writes to a trusted asset, the keychain directory,
`mach-lookup` and `signal`. Its probe child (`sandbox_macos.rs:17-84`) is the
seed of `doctor`'s probe list: admin socket connect (direct and through a
`run/../admin` alias), lock open-for-write, socket unlink, store read and
write, asset and executable open-for-write, `/bin/kill -0` against an outside
pid, and `/usr/bin/security find-generic-password` on a nonexistent item
requiring the `SecKeychainSearchCreateFromAttributes:` initialization error
(`:66-83`; `docs/macos-sandbox-acceptance.md:37-43` explains why exit 44 is not
evidence). What the fixture does not cover is listed at
`docs/macos-sandbox-acceptance.md:45-52`: process control, task ports,
AppleEvents, LaunchServices, and it "never launches the PAM GUI".

### The base layout, and what an agent must and must not reach

The default base is `~/.pam` (`crates/pam_daemon/src/runtime_dir.rs:3`), or
`$PAM_BASE_DIR` (`crates/pam/src/main.rs:410-415`, `pam::default_base_dir`).
Everything `doctor` probes is derived from the resolved base, so the table is
the probe inventory.

| Path | Who creates it | Agent must | Evidence |
| --- | --- | --- | --- |
| `<base>/run/pam.sock` (unix) | daemon, `0600` in `0700` `run` | **connect** | `runtime_dir.rs:55`, `framed_unix.rs:3-7` |
| `<base>/run/public.json` (Windows: port + nonce) | daemon | **read** | `runtime_dir.rs:58`, spec `2026-10-02-framed-public-transport.md:609-631` |
| `<base>/run/daemon.lock` | daemon | read + shared-lock probe (the client's readiness test, `crates/pam_client/src/client.rs:545-575`, `:1545-1555`); **not write** | `lifecycle.rs:36`, `:141-166` |
| `<base>/engine/run/engine.sock` (relocated by T10; was `<base>/run/engine.sock`) | engine supervisor | **not connect** | `crates/pam_model/src/engine_server.rs`, `EngineLayout::runtime_dir` |
| `<base>/engine/run/api.key`, `engine.pid` (relocated by T10; was `<base>/run/engine/`) | engine supervisor (`0600` in `0700`, transient) | **not read** | `engine_server.rs`, `pam_model/src/engine.rs` |
| `<base>/admin/` and `control.sock` (macOS, `0700`/`0600`) | daemon | **not connect, not list** | `admin_transport_unix.rs:142-157` |
| `<base>/admin/control.json` (Windows) | daemon | **not open for read** | `admin_transport_windows.rs:6-13`, `:116-127` |
| `<base>/state.sqlite3`, `-wal`, `-shm` | store | **not read, not write** | `broker-macos.sb:14-16` |
| `<base>/backup/pre-sqlite-engine/` | store upgrade | **not read** | spec `2026-10-02-sqlite-store.md:409-411` |
| `<base>/model-trust/` | model service | **not read, not write** | `model_service.rs:793-798` |
| `<base>/engine/`, `engine/weights/` | engine install | **not read, not write** | `model_service.rs:783-789`, `pam_model/src/engine.rs:271` |
| `<base>/flows/` | flow library | **not read, not write** | `flow_service.rs:516` |
| `<base>/log/` | daemon logging | **not read** | `lifecycle.rs:39-43` |
| keychain service `dev.pam.connector` | secret store | **not initialize a search** | `secrets.rs:24`, `:32-34` |
| the daemon process | — | **not signal** (macOS); query rights are attribution (Windows) | `broker-macos.sb:20`, `sandbox_macos.rs:60-65` |
| the `pam` executable, the `.app` bundle, embedded frontend | installer | **not write** | `admin-boundary.md:88`, `:98-108` |
| LaunchServices / AppleEvents brokers (macOS), ShellExecute (Windows) | OS | **not reach** | `admin-boundary.md:98-108`, `broker_windows.rs:9-13` |

Finding (not previously recorded; **resolved by T10 on this branch**). The
engine's private socket and its transient API key lived **inside the run
directory** the agent must traverse: `<base>/run/engine.sock` and
`<base>/run/engine/api.key`. A profile that allows reads under `<base>/run` so
that the client can probe the lock (or read `public.json` on Windows) therefore
also exposed the engine key for the moments it exists, and a profile that
allows unix-socket connects under `<base>/run` by subpath exposed the engine's
OpenAI-compatible endpoint. T10 moved the runtime to `<base>/engine/run`
(`0700`, inside the `engine` tree every profile denies as a whole); `run/` now
holds `pam.sock`, `daemon.lock` and (Windows) `public.json` only, and the
reference profiles name no path under `run` but those. `doctor` still probes the
engine runtime at its new place (`engine.runtime_read`, `engine.socket`). An
older daemon's leftovers inside `run` are removed at daemon start. Relocating the engine
runtime under `<base>/engine/run` is the structural fix and is filed as an
issue in the implementation plan rather than done here.

### How the client finds the daemon and who it says it is

- Base: `$PAM_BASE_DIR` else `~/.pam` (`main.rs:410-415`).
- Session relay: `$PAM_SOCKET_DIR` makes the client dial `pam.sock` directly
  inside that directory, switches lazy start off, and sends `via: relay` in the
  hello (`client.rs:69-99`, `:102-112`; `pam_proto/src/wire.rs:81-87`;
  `docs/session-socket-relay.md:68-79`). Through the relay the daemon's kernel
  peer is `pam listen`, not the agent (`:81-92`).
- Lazy start: without the override the client probes the lock and spawns
  `pam daemon` with an environment allowlist (`client.rs:580-605`, `:616-650`),
  its own process group, `/` as cwd and null stdio (`:662-697`). A sandboxed
  client that cannot read the lock fails before dialing
  (`lock_is_held` returns `ClientError::Probe` on anything but `NotFound`,
  `:545-575`) — which is why the reference profiles keep
  `<base>/run/daemon.lock` readable, or use the relay.
- Identity: the envelope's `caller` is self-reported — a bounded parent-process
  walk matched by prefix against `KNOWN_AGENTS` (`claude`, `github-copilot`,
  `copilot`, `codex`, `cursor`, `gemini`, `aider`; `crates/pam_client/src/caller.rs:25-33`,
  `:87-115`), the repository from the cwd, and the client's own pid (`:1-12`).

### What the daemon records today

Every request row carries `ingress`, `peer_uid`, `peer_pid` and `relayed`
(`crates/pam_store/src/migrations.rs:119-122`); the peer is the kernel's view
on macOS (`framed_unix.rs:10-14`, `ingress.rs:94-107`) and `OwnerNonce` with no
uid or pid on Windows (`framed_windows.rs:24-25`). The executor sees it as
`ExecContext::peer` (`executor.rs:80`) and `ExecContext::origin` (`:71`).
Audit rows join to a request (`migrations.rs:286-296`: `action`, `decision`,
`actor ∈ {policy, human, system}`, `detail`). The `caller` table is an
agent+repo registry with first/last seen (`:327-333`), surfaced by
`admin.callers.list` (`admin.rs:959-975`). The admin plane admits by uid and the
presence of a kernel pid (`admin_transport_unix.rs:69-88`) — it does not look at
the peer's executable, and nothing counts a connection that was admitted and
then sent nothing.

`status` is answered from a snapshot with no row (`daemon.rs:28-31`):
`daemon_version`, `protocol`, `uptime_s`, `active_requests`, `blocking_jobs`,
`model`, `keyring`, `snapshot` (`status_cache.rs:252-266`); the CLI renders it
at `render.rs:263-276`; the GUI polls it through `daemon_status`
(`pam_gui/src/bridge.rs:373-385`) for the beacon (`Beacon.tsx:8-15`,
`useDaemonStatus.ts:9-16`) and the Settings › Daemon card (`Settings.tsx:384-392`,
`:488`). `query` and `cancel` are Control-class but audited requests with rows
(`daemon.rs:30-31`; `policy.rs:179-190` is the class registry).

### Exit codes and the CLI surface

`0` success, `1` transport/client failure, `2` usage, `3` refused, `4`
unresolved, `5` blocked (`crates/pam/src/lib.rs:12-13`; `render.rs:30-36`;
README "CLI surface"). The playbook already tells agents that `pam status
--json` is "also the sandbox probe" (`docs/pam-playbook.md:13`) and what to do
when the socket is blocked (`:72-87`). That sentence becomes true with this plan.

### What the harnesses offer (verified 2026-10-02)

The harnesses the owner uses are the four the curator runs (`claude`, `codex`,
`copilot`, `gemini`; `docs/command-containment.md:15`) and that `caller.rs`
recognises. What each provides, from its public documentation:

- **Claude Code** — [Configure the sandboxed Bash tool](https://code.claude.com/docs/en/sandboxing),
  [settings reference](https://code.claude.com/docs/en/settings-reference).
  macOS uses Seatbelt; Linux/WSL2 bubblewrap; "On native Windows, Claude Code
  runs commands unsandboxed." Keys (verbatim): `sandbox.enabled`,
  `sandbox.failIfUnavailable`, `sandbox.allowUnsandboxedCommands`,
  `sandbox.filesystem.denyRead` / `allowRead` / `denyWrite` / `allowWrite`,
  `sandbox.network.allowUnixSockets` ("List Unix socket paths sandboxed commands
  can use on macOS"), `allowAllUnixSockets`, `allowLocalBinding`,
  `excludedCommands`. Reads cover "most of the machine" by default; a narrower
  `allowRead` re-opens a path inside a `denyRead` region. Managed settings can
  make the sandbox admin-required (`allowUnsandboxedCommands: false`) and lock
  read paths (`allowManagedReadPathsOnly`). The sandbox covers shell commands
  only; file tools, MCP servers and hooks run outside it.
- **Codex** — [config reference](https://learn.chatgpt.com/docs/config-file/config-reference),
  [permissions](https://learn.chatgpt.com/docs/permissions).
  `sandbox_mode = "read-only" | "workspace-write" | "danger-full-access"`;
  `[sandbox_workspace_write]` with `writable_roots`, `network_access`,
  `exclude_tmpdir_env_var`, `exclude_slash_tmp`; custom profiles under
  `[permissions.<name>]` with filesystem rules mapping paths to `read`, `write`
  or `deny` (deny wins) and `network.enabled`, selected by
  `default_permissions`; `windows.sandbox = "unelevated" | "elevated" | "mxc"`.
  macOS is Seatbelt, Linux bubblewrap + seccomp, Windows "elevated sandboxing
  with dedicated low-privilege accounts". A per-socket allowance exists as a
  CLI option (`codex sandbox macos --allow-unix-socket <path>`,
  [PR 17654](https://github.com/openai/codex/pull/17654)); a config.toml
  spelling for it was not found in the documentation read and is not invented
  below.
- **Gemini CLI** — [sandboxing](https://github.com/google-gemini/gemini-cli/blob/main/docs/cli/sandbox.md),
  [`sandbox.ts`](https://github.com/google-gemini/gemini-cli/blob/main/packages/cli/src/utils/sandbox.ts).
  `GEMINI_SANDBOX=sandbox-exec` (or `-s`, or `"sandbox": true` under `tools`);
  `SEATBELT_PROFILE` names a built-in (`permissive-open` default,
  `permissive-proxied`, `restrictive-open`, `restrictive-proxied`,
  `strict-open`, `strict-proxied`) or a custom file
  `sandbox-macos-${profile}.sb` looked up in `~/.gemini` then project
  `.gemini`; the profile is run with `-D TARGET_DIR`, `TMP_DIR`, `HOME_DIR`,
  `CACHE_DIR` and `INCLUDE_DIR_0..4`. `permissive-open` is deny-default with
  unrestricted reads and `(allow network-outbound)`. The Windows native sandbox
  sets a persistent Low integrity level with `icacls` on writable paths — a
  write restriction, not a read one.
- **Copilot CLI** — [about sandboxes](https://docs.github.com/en/copilot/concepts/security-governance-and-network-settings/about-cloud-and-local-sandboxes),
  [using local sandboxing](https://docs.github.com/en/copilot/how-tos/cloud-and-local-sandboxes/using-local-sandboxing),
  [configuring](https://docs.github.com/en/copilot/how-tos/cloud-and-local-sandboxes/configuring-local-sandbox-settings).
  Experimental (`--experimental`, `/sandbox enable`, `sandbox.enabled` in
  `~/.copilot/settings.json`). macOS 15+ Seatbelt with a process-scoped profile
  per command; Linux bubblewrap; Windows "BaseContainer tier of the
  ProcessContainer backend", Insiders builds only. Configuration is through the
  `/sandbox config` dialog: path rules (read/write, read-only, denied), "Allow
  outbound connections", "Allow local network", and "Allow keychain access"
  (macOS, off by default). No unix-socket key is documented.

None of the four documents what happens to Mach lookups, signals or
AppleEvents inside its macOS profile. That is exactly why the profiles ship
with a `doctor` run instead of a claim.

## `pam doctor`

### Synopsis

```
pam doctor [--json] [--no-report] [--timeout-ms N]
pam doctor --profile <claude-code|codex|gemini-cli|copilot-cli|sandbox-exec> [--base DIR] [--managed]
```

Run from where the agent runs — by the agent, or by a human in the same
terminal the harness starts from with the harness's sandbox applied (each
harness has a way to run one command sandboxed; the profile docs name it).
It probes, prints, reports to the daemon (unless `--no-report`) and exits.
`--profile` prints a reference fragment and probes nothing (see "Reference
sandbox profiles"). The whole run is bounded: each probe has its own bound
(2 s for a file or socket operation, 5 s for a spawned helper), the public
hello uses the client's existing 5 s connect bound, and `--timeout-ms`
(default 30 000) caps the run; a probe that overruns is `unknown(timeout)`.

### Probe inventory

Each probe is one row with a stable `id`, a `class`, a `result` and the OS
error it saw. Classes: `must_allow` (the agent needs it), `must_deny` (the
boundary requires it denied), `info` (reported, never judged). Results:
`allowed`, `denied`, `absent` (the path does not exist — reported, not judged),
`unknown` (could not classify: timeout, an unexpected error, a helper that
could not run).

Rules for classifying an `io::Error`: `PermissionDenied` (EPERM/EACCES,
`ERROR_ACCESS_DENIED`) → `denied`; `NotFound` → `absent`; success → `allowed`;
on Windows `ERROR_SHARING_VIOLATION` on an open-for-write → `allowed` (the
ACL granted the access; only the share mode refused it — the access check
precedes the share check in `CreateFile`); anything else → `unknown` with the
error's kind and raw code. Every classification is a pure function over an
injected error, unit-tested per platform.

macOS (`must_allow` first; `<base>` is the resolved base; `<ep>` the resolved
public endpoint, which is `<dir>/pam.sock` under `PAM_SOCKET_DIR`):

| id | class | method | notes |
| --- | --- | --- | --- |
| `public.reach` | must_allow | connect `<ep>`, hello only (`transport::hello_on`, `crates/pam_client/src/transport.rs:329-376`), drop | reports `daemon_version`, `proto`, `epoch`, `via`. A `Legacy` or `Refused` answer is reported as such; `Unreachable` fails the run (exit 1): there is nothing to report to. |
| `run.lock_probe` | info | `File::open` + `try_lock_shared` + `unlock` on `<base>/run/daemon.lock` (the client's own readiness test) | `allowed` is what lazy start needs; `denied` is fine under the relay and is noted as "lazy start unavailable here" otherwise. Never written. |
| `run.lock_write` | must_deny | `OpenOptions::new().write(true).create(false).truncate(false).open(lock)`; close | never writes a byte. |
| `public.unlink` | must_deny | — | **not probed**: the only test is `remove_file`, which has a side effect. `doctor` reports `not_probed` with that reason; the macOS fixture keeps covering it (`sandbox_macos.rs:39`). |
| `admin.endpoint` | must_deny | `UnixStream::connect("<base>/admin/control.sock")`; on success, hold 150 ms (As built, 2), then drop | sends nothing, reads nothing. The daemon sees an admitted peer that went away before a hello and records it (see "Admin contacts"). Also probed through the alias `<base>/run/../admin/control.sock` as `admin.endpoint_alias`, as the fixture does (`sandbox_macos.rs:28-32`). |
| `admin.dir` | must_deny | `read_dir("<base>/admin")`; take at most one entry | |
| `store.read`, `store.write` | must_deny | open `state.sqlite3` read-only / write (`create(false)`); close; same for `-wal` and `-shm` as `store.wal_*`, `store.shm_*` | reads no byte. |
| `backup.read` | must_deny | `read_dir("<base>/backup")` | usually `absent` |
| `model_trust.read` | must_deny | `read_dir("<base>/model-trust")` | |
| `engine.read` | must_deny | `read_dir("<base>/engine")` | |
| `engine.runtime_read` | must_deny | `read_dir("<base>/engine/run")` | the key-file directory (finding above; relocated by T10) |
| `engine.socket` | must_deny | connect `<base>/engine/run/engine.sock`; drop | `absent` when no engine runs |
| `flows.read` | must_deny | `read_dir("<base>/flows")` | |
| `log.read` | must_deny | `read_dir("<base>/log")` | |
| `keychain.search` | must_deny | spawn `/usr/bin/security find-generic-password -s dev.pam.connector -a pam.doctor.absent.<pid>.<random>` with a cleared environment, null stdin, 5 s | `denied` on `SecKeychainSearchCreateFromAttributes:` in stderr; `allowed` on exit 44 / "could not be found" (the keychain answered); `unknown` otherwise. No item is created, read or changed; a search for an absent item never prompts. Same method and same evidence rule as the fixture (`sandbox_macos.rs:66-83`). |
| `daemon.signal` | must_deny | spawn `/bin/kill -0 <pid>` where `<pid>` is the daemon's pid **as the hello acknowledgement names it** (As built, 22; designed as the lock file's content) | `denied` on "Operation not permitted"; `allowed` on exit 0; `unknown` when the pid is gone; `not_probed` when no daemon acknowledged the hello (the run is `cannot_probe` then). Signal 0 delivers nothing (`sandbox_macos.rs:60-65`). The lock file is never read for it, so the probe is judged through the relay too, where nothing under the base is readable. |
| `broker.launchservices` | must_deny | **superseded (As built, 1):** `/usr/bin/lsappinfo find bundleid=com.apple.loginwindow`. Designed as: spawn `/usr/bin/open -b dev.pam.doctor.absent.<random>` | the bundle id does not exist, so nothing can launch; `allowed` when LaunchServices answered "Unable to find application"; `denied` when the lookup itself failed (the Mach bootstrap was refused). The exact strings are pinned by the acceptance test on the real OS, never guessed: until pinned, an unrecognised message is `unknown`, which is fail-closed. |
| `broker.appleevents` | must_deny | **superseded (As built, 1):** `/usr/bin/osascript -e 'id of application "Finder"'`. Designed as: spawn `/usr/bin/osascript -e 'tell application id "dev.pam.doctor.absent.<random>" to activate'` | same shape: an absent application id cannot be launched and does not trigger an automation consent prompt (prompts arise when targeting a running application). `allowed` when the AppleEvent runtime resolved the id and reported it absent; `denied` when the runtime could not start. Strings pinned by the acceptance test. |
| `exe.write` | must_deny | `/bin/test -w <std::env::current_exe()>` through the helper runner (absolute path, cleared environment, bounded) — `access(2)` with `W_OK`; the executable is **never opened** | exit 0 → `allowed`; exit 1 → `denied` with the note `access(W_OK) refused` (no errno to carry; `test -e` then tells a refused path from a missing one, which is `absent`); spawn failure, timeout or any other status → `unknown`. Never an open-for-write: on macOS, opening a Mach-O that another process is mapped from (the daemon, always, in production) for write invalidates the kernel's cached code signature for that inode, and every later exec of the file is `SIGKILL`ed until the file is replaced — one unsandboxed run would have left `pam` and `PAM.app` unrunnable until reinstalled. |
| `bundle.write` | must_deny | when the exe sits under a `.app`: `/bin/test -w <bundle>/Contents/Info.plist`, the same shape — nothing in the bundle is ever opened for write | `absent` outside a bundle, or when the plist is gone |
| `frontend` | info | the binary's own build: `embedded` (`gui-embed`) or `development_server` | a dev build is not a trusted surface (`admin-boundary.md:100-107`) and is reported as such; the daemon's build is what matters and is the same binary in production. |
| `env.socket_dir`, `env.base_dir`, `env.resolved_base`, `env.resolved_endpoint`, `env.client_version`, `env.exe`, `env.cwd_repo`, `env.harness_chain` | info | the facts the client already computes (`client.rs:69-99`, `caller.rs:41-46`, `:87-115`) | the harness chain is self-reported; the daemon walks its own (below). |

Windows differs where the mechanism differs:

| id | class | method | notes |
| --- | --- | --- | --- |
| `public.reach` | must_allow | read `<base>\run\public.json`, connect `127.0.0.1:<port>`, server proof, nonce, hello (`framed::connect_public`); drop | the public nonce is read because the client needs it; it confers nothing on the admin plane (spec `:635-637`). |
| `admin.control_read` | must_deny | `File::open("<base>\admin\control.json")` for read; close **without reading a byte** | **Decision**: open-then-close, not metadata. The ACL is evaluated at `CreateFile`; `metadata()` goes through `GetFileAttributesEx`, which needs only list rights on the parent, so it would answer a different question. Not reading the bytes is what keeps the probe from being the capability: the nonce never enters the doctor's memory and the admin port is never dialled. |
| `admin.dir` | must_deny | `read_dir("<base>\admin")` | |
| `store.*`, `backup.read`, `model_trust.read`, `engine.read`, `engine.runtime_read`, `flows.read`, `log.read`, `run.lock_write` | as macOS | | `engine.socket` is `not_probed` on Windows (the engine binds loopback there). |
| `exe.write` | must_deny | open `std::env::current_exe()` for write through the seam (`create(false)`, `truncate(false)`, no byte written); close | **Decision**: the open stays on Windows. The image section of a running executable makes `CreateFile` refuse write access at the share check — after the ACL's access check, so `ERROR_SHARING_VIOLATION` is `allowed` and `ERROR_ACCESS_DENIED` is `denied` — before any handle exists, and Windows keeps no code-signature cache the attempt could invalidate (the macOS hazard above). The non-opening alternatives answer a different question: the read-only attribute is not the ACL, and a directory opened for write is always `ERROR_ACCESS_DENIED`, which would read `denied` unsandboxed — a false pass. |
| `keychain.search` | must_deny | `keyring_core` read of service `dev.pam.connector`, account `pam.doctor.absent.<pid>.<random>` | `NoEntry` → `allowed` (Credential Manager answered); an access error → `denied`; else `unknown`. No entry is created. |
| `daemon.process_query` | must_deny | (as built, a PowerShell `Get-Process` of the pid the hello acknowledged, As built 4 and 22) `sysinfo` refresh of the lock file's pid and read of its exe path | `allowed` when the process is visible with its executable (query rights were granted); `denied` when the query yields nothing for the pid the daemon named. Query rights are attribution, not control: a termination-rights probe needs `OpenProcess` through FFI, which the workspace forbids, and is **not** done. The report says "query only". |
| `broker.shellexecute` | must_deny | spawn `%SystemRoot%\System32\where.exe` with a cleared environment | process creation is the broker (`broker_windows.rs:9-13`): if `doctor` itself was created, this is `allowed`. It exists so the Windows verdict lists the right reason. |
| `bundle.write`, `broker.launchservices`, `broker.appleevents` | — | `not_probed` on Windows | |

Safety invariants, enforced by code and by test:

- No probe writes, creates, truncates, unlinks, renames, sends a frame, reads
  private bytes, or changes a lock. The only bytes `doctor` reads from the base
  are (Windows) `public.json`, which the ordinary client already reads; the
  daemon's pid comes from the hello acknowledgement, not from the lock file
  (As built, 22).
- Spawned helpers are named by absolute path, run with a cleared environment,
  null stdin, captured output capped at 64 KiB, and a 5 s bound; a helper that
  cannot start is `unknown(spawn: <error>)`.
- The admin connect sends nothing. On macOS the daemon's admin listener sees
  accept → EOF; its hello read fails and the connection is dropped before any
  policy runs (`admin_transport.rs:9-13` describes the admission order).
- Nothing prompts: no keychain item is read, no running application is
  targeted, no file is created.

### Verdict

```
established      ⇔ public.reach = allowed
                   ∧ ∀ p ∈ must_deny : result(p) ∈ {denied, absent, not_probed}
not_established  ⇔ public.reach = allowed ∧ ∃ p ∈ must_deny : result(p) ∈ {allowed, unknown}
cannot_probe     ⇔ public.reach ≠ allowed, or the base cannot be resolved
```

`unknown` on a must-deny probe fails the verdict: the boundary is claimed only
from evidence. The JSON separates `failed` (allowed where denial was required)
from `unverified` (unknown) so a reader sees which is which. `absent` and
`not_probed` are listed under `skipped` with the reason; they do not count
either way, and the human output says so in one line.

A same-user agent with no sandbox sees every must-deny probe `allowed`. That is
the honest answer, and the human output states what it means:

```
boundary: not_established
  this process can reach PAM's private state; GUI-only administration is a
  convention on this machine, not a boundary. Apply a sandbox profile to the
  agent (pam doctor --profile <harness>) and run pam doctor again from inside it.
  failed: admin.endpoint admin.dir store.read store.write run.lock_write ...
```

### Exit codes

| code | meaning |
| --- | --- |
| `0` | `established` |
| `6` | `not_established` (new, distinct; `EXIT_BOUNDARY`) |
| `1` | `cannot_probe`: the daemon is unreachable, legacy, refusing the hello, or the base cannot be resolved; and every client failure the other subcommands map to `1` |
| `2` | usage |

`3`, `4` and `5` keep their meanings and are not used by `doctor`. `--no-report`
does not change the code. A failure to deliver the report (the daemon refused
or dropped the `doctor.report` request) is a stderr line and does not change
the verdict's code: the verdict is the client's, the record is best-effort.

### Output

Human (default): one header line with the verdict, then one line per probe in
inventory order (`id`, result, OS error when not `allowed`), then the env facts,
then `report: recorded as <request id>` or `report: not sent (<reason>)`.

`--json`: one document on stdout, nothing else:

```json
{
  "schema_version": 1,
  "verdict": "not_established",
  "platform": "macos",
  "ts": 1759400000,
  "daemon": { "version": "0.5.0", "proto": 2, "epoch": "01JB…", "via": "direct" },
  "probes": [
    { "id": "public.reach", "class": "must_allow", "result": "allowed", "elapsed_ms": 3 },
    { "id": "admin.endpoint", "class": "must_deny", "result": "allowed", "elapsed_ms": 151 },
    { "id": "store.read", "class": "must_deny", "result": "denied",
      "os_error": { "kind": "PermissionDenied", "code": 1 }, "elapsed_ms": 0 },
    { "id": "backup.read", "class": "must_deny", "result": "absent",
      "os_error": { "kind": "NotFound", "code": 2 }, "elapsed_ms": 0 },
    { "id": "daemon.signal", "class": "must_deny", "result": "denied",
      "os_error": { "kind": "PermissionDenied", "code": 1,
                    "detail": "kill: 4711: Operation not permitted" }, "elapsed_ms": 12 }
  ],
  "failed": ["admin.endpoint"],
  "unverified": [],
  "skipped": [{ "id": "backup.read", "why": "absent" },
              { "id": "public.unlink", "why": "not_probed: side effect" }],
  "env": {
    "socket_dir": null, "base_dir_override": null,
    "resolved_base": "/Users/me/.pam", "resolved_endpoint": "/Users/me/.pam/run/pam.sock",
    "client_version": "0.5.0", "exe": "/Applications/PAM.app/Contents/MacOS/pam",
    "cwd_repo": "/work/app", "frontend": "embedded",
    "harness_chain": ["pam", "zsh", "claude", "launchd"]
  },
  "report": { "recorded": true, "request_id": "req_01JB…" },
  "daemon_reply": {
    "accepted": true, "report_id": 7, "request_id": "req_01JB…", "verdict": "not_established",
    "peer": { "uid": 501, "pid": 48122, "exe": "/Applications/PAM.app/Contents/MacOS/pam",
              "harness": "claude", "relayed": false },
    "claimed_harness": "claude", "harness_agrees": true, "attributed_admin_contacts": 1
  }
}
```

The schema is versioned and additive; MDM scripts key on `verdict`, `failed`
and the exit code. `daemon_reply` is not part of the report the daemon stores
(the client sends the document with `report: null`); it is the daemon's answer,
added by the CLI as a sibling of `daemon`, which stays the hello's facts. It is
absent with `--no-report`, with `cannot_probe`, and when the daemon refused or
did not answer, in which case `report` is `{"recorded": false, "reason": …}`.

### The report: `doctor.report`

After probing, `doctor` opens one more public connection and sends a request
for the new capability `doctor.report` with the JSON document above as `args`
(bounded to 16 KiB at ingress like any public args). It is registered in
`policy::classify` as `CapabilityClass::Control` (`policy.rs:179-190`) — never
granted, never approved, admitted in the control pool with the control deadline
cap (`daemon.rs:1455-1460`), and, unlike `status` but like `query` and `cancel`
(`daemon.rs:30-31`), it is a real request: a `request` row with `ingress`,
`peer_uid`, `peer_pid`, `relayed`, and the self-reported `caller`; a terminal
state; and one audit row `action = "doctor.report"`, `decision = "allow"`,
`actor = "system"`, `detail = {"verdict": …, "failed": […], "unverified": […]}`.
Dispatch is one more arm in `BuiltinCapability` (`executor.rs:179-199`,
`:205-216`, `:239-250`).

The executor validates the schema, trims it to the stored shape, and inserts a
`boundary_report` row (see "What the daemon stores"). A document that fails
validation is refused `invalid_args` and nothing is stored; a refusal is
audited like any other. The capability has no effect on any gate, grant,
profile or approval.

## The `boundary` status block

### What the daemon stores

One migration adds:

```sql
CREATE TABLE boundary_report (
    id            INTEGER PRIMARY KEY,
    request_id    TEXT NOT NULL REFERENCES request (id),
    ts            INTEGER NOT NULL,
    verdict       TEXT NOT NULL CHECK (verdict IN ('established','not_established')),
    failed_json   TEXT NOT NULL,       -- ids, as sent
    unverified_json TEXT NOT NULL,
    agent         TEXT NOT NULL,       -- self-reported caller.agent
    repo          TEXT NOT NULL,       -- self-reported caller.repo
    peer_uid      INTEGER,             -- kernel view at receipt
    peer_pid      INTEGER,
    peer_exe      TEXT,                -- daemon-resolved executable of peer_pid
    peer_harness  TEXT,                -- daemon-resolved ancestor classification
    relayed       INTEGER NOT NULL,
    client_version TEXT NOT NULL,
    report_json   TEXT NOT NULL        -- the full document, ≤ 16 KiB
);
CREATE TABLE boundary_observation (
    id        INTEGER PRIMARY KEY,
    ts        INTEGER NOT NULL,
    kind      TEXT NOT NULL CHECK (kind IN ('admin_contact','admin_handshake_failed','public_unknown_harness')),
    peer_pid  INTEGER,
    peer_exe  TEXT,
    detail    TEXT,
    attributed TEXT                     -- NULL, or the doctor request_id that explains it
);
```

Bounds: `boundary_report` keeps the newest 64 rows (the insert prunes), so at
most 1 MiB of report text; `boundary_observation` keeps the newest 256 rows
plus lifetime counters in the `setting` table
(`boundary.admin_contacts_total`, `boundary.public_unknown_total`), so a
flood neither grows the store nor erases the history that the first contact
happened. The request row's `peer_exe` and `peer_harness` are added as two
nullable columns in the same migration so `admin.activity.list` can show them;
they are attribution, like `peer_pid` (`admin-boundary.md:38-41`).

Peer executable resolution is the daemon's own observation: at receipt of any
public request on macOS, the pipeline resolves `peer_pid`'s executable path
and walks its ancestors (bounded, cycle-safe, the same shape as
`caller.rs:87-115`) with `sysinfo`, classifying with the shared table. The
client process is alive for the whole exchange (one request per connection;
the reply is awaited), so the walk is not racing an exit. `classify_chain` and
`KNOWN_AGENTS` move to `pam_proto::caller` (the leaf crate that already owns
`Caller`) because `pam_client` depends on `pam_daemon` and the daemon cannot
depend back. Through the relay the peer is `pam listen`; `peer_harness` is
then `relay`, and the report's self-reported `harness_chain` is what the GUI
shows beside it, labelled as self-reported. On Windows both are null.

### Admin contacts

`admin_transport_unix.rs` gains one observation point: a connection that
passes `verify_peer` (uid and pid, `:82-88`) and then (a) ends before a valid
hello, or (b) presents a hello from a pid whose executable is not the daemon's
own image path (`image.rs` records it at boot; the GUI is the same binary), is
recorded as `admin_contact` with the pid and the executable. The Windows
adapter records `admin_handshake_failed` (a connection that failed the nonce
proof or sent none; no pid) — a doctor run never produces one there, by design.

Attribution: when a `doctor.report` arrives from the same kernel `peer_pid`
within 60 s of an `admin_contact`, the observation's `attributed` is set to the
report's request id and it is not counted as unattributed. This is the daemon
matching two things it saw itself (an admin accept and a public request from
one pid); the client's document plays no part in it. An admin contact nobody
explains stays unattributed forever and is the headline of the block.

Public unknown harness: a public request whose daemon-resolved `peer_harness`
is neither a known agent nor `relay` nor the GUI's own path is counted as
`public_unknown_harness` with the executable (attribution only; nothing is
refused).

### The block

`status` gains:

```json
"boundary": {
  "last_report": {
    "verdict": "established", "ts": 1759400000, "age_s": 420,
    "agent": "claude", "repo": "/work/app", "relayed": false,
    "peer_pid": 48122, "peer_exe": "/Applications/PAM.app/Contents/MacOS/pam", "peer_harness": "claude",
    "failed": [], "unverified": [], "request_id": "01JB…"
  },
  "reports": { "retained": 7, "established": 5, "not_established": 2 },
  "admin_contacts": { "unattributed": 0, "total": 3, "last": null },
  "public_unknown_harness": { "total": 1, "last": { "ts": 1759399000, "peer_exe": "/usr/local/bin/pam" } }
}
```

`last_report` is null before the first run. It is part of the `StatusCache`
snapshot (refreshed with the other slow parts; `status_cache.rs:127-131`,
`:252-266`) so a poll stays row-free. The CLI's `render_status`
(`render.rs:263-276`) adds one line:

```
  boundary:        established 7 min ago by claude (pid 48122, direct); admin contacts unattributed: 0
```

or `boundary:        never checked — run pam doctor from the agent`. The GUI's
Settings › Daemon card (`Settings.tsx:384-392`) gets a "Boundary" row group
with the same facts and a copyable `pam doctor` command; Home's daemon card
shows the one-line form. The beacon's four states (`Beacon.tsx:8-15`) are
unchanged: liveness and the boundary are different questions, and a red beacon
for an unsandboxed developer machine would train people to ignore red.

### Refusal-free semantics

`doctor` and its record change no authority: the gate (`policy.rs`), grants,
approvals, scopes and the profile never read `boundary_*`. A
`not_established` machine is served exactly as today. The block is a fact for
the human and for fleet tooling. Two consequences the docs state: the field can
only ever understate the risk (a report is a point in time from one position),
and the daemon's own observations (`admin_contacts`, `public_unknown_harness`)
are the only part it can vouch for.

## Reference sandbox profiles

Shipped in `docs/sandbox/` and embedded in the binary (`include_str!`) so
`pam doctor --profile <harness> [--base DIR]` prints the fragment with the base
path substituted (default `~/.pam`; `--base` for a pinned
`pam service install --base-dir`). Each file carries the same preamble: what it
allows, what it denies, the harness documentation it was written against and
the date, and the `pam doctor` run that proves it. Every profile holds the same
invariants:

1. Allow exactly the literal public socket (`<base>/run/pam.sock`) and the
   read of `<base>/run/daemon.lock`; or, under the relay, the literal
   `<dir>/pam.sock` and nothing under the base at all.
2. Deny everything else under `<base>`: `admin`, `state.sqlite3*`, `backup`,
   `model-trust`, `engine`, `flows`, `log`, and inside `run`: `engine.sock`
   and `engine/`.
3. Deny writes to the installed `pam` executable and the `.app` bundle.
4. Deny the keychain where the harness has a knob; otherwise rely on `doctor`
   to say.

Files:

- `docs/sandbox/macos/pam-agent.sb` — harness-independent SBPL, the fixture
  generalised with `(param "BASE")`, `(param "HOME")`, `(param "WORKSPACE")`,
  `(param "PAM_EXE")`; usable as a wrapper around any harness:
  `sandbox-exec -D BASE=$HOME/.pam -D HOME=$HOME -D WORKSPACE=$PWD -D PAM_EXE=$(command -v pam) -f pam-agent.sb <harness>`.
  Deny-default like `broker-macos.sb`, plus workspace writes, temp writes, and
  the common toolchain reads a harness needs; keeps `(deny mach-lookup)` and
  `(deny signal)` from the fixture, which is why it is the strongest profile
  and the one the enterprise doc recommends where the harness's own sandbox is
  weak or absent (Copilot CLI) — and why it will break tools that need Mach
  services; the preamble says to loosen by adding specific `(allow mach-lookup
  (global-name …))` lines, never by removing the PAM block. `sandbox-exec` is
  deprecated by Apple and still what every harness above uses.
- `docs/sandbox/macos/claude-code.settings.json` — a `sandbox` fragment for
  `~/.claude/settings.json` (or managed settings with `--managed`, which adds
  `failIfUnavailable: true`, `allowUnsandboxedCommands: false` and
  `allowManagedReadPathsOnly: true`):

  ```json
  {
    "sandbox": {
      "enabled": true,
      "filesystem": {
        "denyRead": ["~/.pam"],
        "allowRead": ["~/.pam/run/daemon.lock"],
        "denyWrite": ["~/.pam", "/Applications/PAM.app"]
      },
      "network": {
        "allowUnixSockets": ["~/.pam/run/pam.sock"]
      }
    }
  }
  ```

  Keys and semantics as documented (narrower `allowRead` inside a `denyRead`
  region re-opens that path). The preamble states what the documentation does
  not: whether Claude Code's Seatbelt profile denies the keychain service,
  signals and Mach lookups is not documented; `doctor` reports it. It also
  states that the sandbox covers Bash only — Claude Code's own file tools run
  outside it and are governed by permission rules, so `denyRead` here does not
  stop the Read tool; the `permissions.deny` rules for `Read(~/.pam/**)` and
  `Edit(~/.pam/**)` are printed alongside. And that without
  `allowUnsandboxedCommands: false` the model can retry a blocked command
  outside the sandbox, which makes any `established` verdict a statement about
  one command, not the session.
- `docs/sandbox/macos/codex.config.toml` — the documented keys:

  ```toml
  sandbox_mode = "workspace-write"
  [sandbox_workspace_write]
  network_access = false
  ```

  plus a `[permissions.pam]` profile denying `~/.pam` with `default_permissions
  = "pam"`, whose exact rule shape the implementer pins against the live
  permissions page before shipping (the page documents `read`/`write`/`deny`
  path rules and `network.enabled`; the TOML spelling was not reproduced in
  what was read and is not guessed here). The unix-socket allowance is the
  `codex sandbox macos --allow-unix-socket ~/.pam/run/pam.sock` option; the
  preamble says that until a config key for it is confirmed, the portable path
  is the relay in the workspace: `pam listen .pam-session` outside Codex and
  `PAM_SOCKET_DIR` exported into the session, with `~/.pam` denied outright.
- `docs/sandbox/macos/gemini-cli.sandbox-macos-pam.sb` — installed as
  `~/.gemini/sandbox-macos-pam.sb` and selected with `GEMINI_SANDBOX=sandbox-exec
  SEATBELT_PROFILE=pam`. It is a complete SBPL profile: a copy of Gemini's
  `permissive-open` (unrestricted reads, writes to `TARGET_DIR`/`TMP_DIR`/
  `CACHE_DIR`/`INCLUDE_DIR_n`, `(allow network-outbound)`) followed by the PAM
  block, which works because in SBPL the last matching rule wins:

  ```scheme
  ; --- pam boundary (append after the harness's own rules) ---
  (deny file-read-data file-write* (subpath (string-append (param "HOME_DIR") "/.pam")))
  (allow file-read-data (literal (string-append (param "HOME_DIR") "/.pam/run/daemon.lock")))
  (deny network-outbound (remote unix-socket (subpath (string-append (param "HOME_DIR") "/.pam"))))
  (allow network-outbound (remote unix-socket (literal (string-append (param "HOME_DIR") "/.pam/run/pam.sock"))))
  (deny file-write* (subpath "/Applications/PAM.app"))
  (deny file-read-data file-write* (subpath (string-append (param "HOME_DIR") "/Library/Keychains")))
  ```

  The permissive base keeps Mach lookup and network open, so `keychain.search`,
  `broker.*` and `daemon.signal` are expected `allowed` under it and the
  verdict is `not_established`; the file says so and offers the
  `restrictive`-based variant and `pam-agent.sb` as the next steps. The
  acceptance test runs this file with the same `-D` parameters Gemini passes.
- `docs/sandbox/macos/copilot-cli.md` — no file format exists; the page lists
  the `/sandbox config` choices (deny `~/.pam`; keychain access off, its
  default; local network on) and says that, with no unix-socket knob
  documented, `public.reach` may be `denied`, in which case the relay in the
  working directory is the path (the working directory is read/write by
  default). Windows: Insiders only; `doctor` says what it finds.
- `docs/sandbox/windows/README.md` — the honesty statement (next section) and
  the one configuration that does bound a same-user agent on Windows today:
  running the harness as a **different local user** — which also makes PAM
  unreachable (`public.json` is owner-ACL'd; spec `:625-631`), so it is a
  statement, not a profile.

### Windows

What exists: Claude Code runs commands unsandboxed on native Windows (WSL2
only); Codex's `windows.sandbox` modes run commands under "dedicated
low-privilege accounts" — a different SID cannot read the owner's `public.json`,
so a PAM client inside it cannot connect at all; Gemini's native sandbox lowers
the integrity level of writable paths, which blocks writes but not reads of
`~/.pam`; Copilot's Windows backend needs an Insiders build. Windows Sandbox and
a VM isolate a whole desktop, not a process on the user's desktop beside PAM.
There is no AppContainer or restricted-token launcher a harness offers for this
purpose, and PAM has no Windows session channel to give a differently-identified
process a door.

The statement, verbatim for the docs: **On Windows no supported configuration
establishes the boundary today. `pam doctor` reports `not_established` and lists
every private path as reachable. GUI-only administration there is a convention
enforced by the harness's permission prompts and by the absence of a hostile
same-user process, not by the OS. The enterprise choices are: a dedicated
machine or VM per agent with PAM inside it; or accept the convention and
collect the `doctor` record so the fact is visible.** A Windows loopback
session channel (the relay's design, `session-socket-relay.md:119-121`) plus a
low-privilege-account mode is the future that would change this and is an
owner decision outside this plan.

## Per-agent authority

Recommendation: **do not build a per-caller grant model.** State "one user,
one authority set; `doctor` proves the sandbox" and make it true in the docs.

Reasons, from what the daemon can verify:

- The only kernel-attested facts are `peer_uid` and `peer_pid` (`ingress.rs:94-107`),
  and on Windows neither (`framed_windows.rs:24-25`; spec `:638-641`). The uid is
  always the daemon's own. The pid names a short-lived `pam` process and is
  reused (`admin-boundary.md:38-41`); its executable path and ancestry are
  attribution — a copied binary or a renamed parent defeats them, and the
  relay collapses every client to `pam listen` (`session-socket-relay.md:81-92`).
  A grant bound to any of these would be the kind of label-keyed authority the
  review flagged, now with a GUI that implies otherwise.
- Harnesses do not give PAM anything stronger: none of the four injects a
  per-session credential the daemon could verify against the harness.
- The honest unit of isolation is the OS user: a separate user has a separate
  base, daemon, keychain and authority set, already supported. Where two agents
  need different authority on one machine, that is the answer (on Windows it is
  also the reason PAM then becomes unreachable, see above).
- What per-agent authority was meant to buy is partly delivered by scoping that
  does not depend on identity: approved repository roots, the ticket's canonical
  repository binding, flow digests on approvals (`admin-boundary.md:137-141`),
  and the pending "bind a grant to a flow digest, step and effect class" fix
  (`design-review-2026-10-02.md`, fix reports list).

What the docs must state (`admin-boundary.md` "Global target authority",
README, playbook): authority is per OS user; every process that can reach the
public socket as that user holds the whole approved set; `caller.agent`,
`caller.repo`, `caller.pid`, `peer_pid`, `peer_exe` and `peer_harness` are
attribution and filters, never a boundary; to give two agents different
authority, run them as different users; `pam doctor` proves the sandbox of
each. Issue 41's second half is closed by that statement, not by code.

If a harness ever offers a verifiable per-session identity (a token the daemon
can check with the harness, or a kernel-attested sandbox identity), the
`boundary_report` keyed by peer facts is the place a future grant model would
hang from; nothing here forecloses it.

## Enterprise fit

- **Fleet verification** is two commands, both `--json`, both exit-code driven:
  1. From the agent's position (a harness hook, a wrapper script, or the
     human once per setup): `pam doctor --json`; exit `6` is the compliance
     signal, `failed` is the remediation list. An MDM script that runs
     `doctor` **outside** any sandbox will see `not_established` — correctly;
     the doc says that such a run proves installation and reachability, not
     the boundary.
  2. From the host (the MDM script, any time): `pam status --json` and read
     `.boundary.last_report.verdict`, `.boundary.last_report.age_s`,
     `.boundary.admin_contacts.unattributed`. This is the daemon's record of
     the last in-position run and its own observations since; a non-zero
     unattributed count or a stale/missing report is the alert.
- **Harness policy delivery** is the harness's own: Claude Code managed
  settings (`--managed` prints the admin-required fragment), Codex `config.toml`
  under MDM, Gemini's `~/.gemini` profile file. PAM prints the fragments; it
  does not deliver them.
- **Plan 54's managed policy file** locks three PAM-side knobs that this plan
  introduces as settings with the `effective: { source, locked }` shape the
  network settings already use (spec `2026-10-02-enterprise-network-and-engine-delivery.md:184-190`,
  `:960`): `boundary.expected_harnesses` (which `peer_harness` values are
  expected; others count as `public_unknown_harness`), `boundary.report_max_age_s`
  (when `last_report` is shown stale), and `boundary.require_relay` (status
  flags direct dials as unexpected on machines whose policy mandates the relay).
  None of them refuses a request; a lock that did would re-introduce authority
  keyed on unverifiable identity.

## Threats

- **An agent lying about `doctor`.** The report is the client's claim; the
  daemon stores it as such, under the kernel's peer facts it recorded itself.
  What the daemon vouches for is only what it observed: that a request with
  those peer facts arrived, the executable and ancestry it resolved, the admin
  contacts it accepted, and whether a contact was followed by a report from the
  same pid. The two views are shown together and labelled; a fabricated
  `established` with an unattributed admin contact beside it is visibly
  inconsistent, and a fabricated report never changes authority anyway.
- **Probes as an oracle.** `absent` vs `denied` reveals whether a private path
  exists; the layout is documented, so nothing new is learned. No probe reads
  private bytes; the nonce files are never read by the admin probe. The admin
  connect is observable by the daemon and is counted, which is the point.
- **Probes as a capability.** The admin connect sends nothing; the Windows
  admin probe never dials; the keychain search targets an absent item; `kill -0`
  delivers nothing; `open -b`/`osascript` target an absent id. The code is
  structured so that a probe cannot be given a payload.
- **Time of check vs time of use.** A verdict is one process, one moment. The
  daemon shows the age; plan 54 lets policy define "stale". What makes the
  verdict carry to later commands is the harness applying one profile to every
  command and not letting the model opt out — Claude Code's
  `allowUnsandboxedCommands: false` and `excludedCommands` locks, Codex's
  `sandbox_mode` — which PAM cannot see; the profile preambles say so.
- **Denial of service through `doctor`.** The report is a Control-class request
  under the control pool and deadline cap; admin contacts are rate-limited by
  the admin listener's existing connection cap and handshake timeout
  (`admin-boundary.md:225-245`); observation tables are bounded.
- **A harness running `doctor` unsandboxed by exclusion.** A `doctor` listed in
  `excludedCommands` reports `not_established` — the honest result; the docs
  tell the human never to exclude it.

## Test strategy

macOS (the fixture style of `sandbox_macos.rs`; every test seeds the relaxed
profile explicitly and asserts no unix-only detail off macOS, per the memento
rule):

1. `crates/pam/tests/doctor_macos.rs`: start a daemon on a temporary base,
   render `broker-macos.sb`, run `pam doctor --json` under it → exit `0`,
   `verdict = established`, `public.reach = allowed`, every must-deny probe
   `denied` or `absent` with the exact set asserted, the admin socket and lock
   inodes and the lock bytes unchanged, the trusted asset unchanged, and a
   `doctor.report` request row with `ingress = public`, the sandboxed child's
   pid and `peer_exe` = the test binary's path; one `admin_contact` observation
   attributed to that request id and `admin_contacts.unattributed = 0` in the
   next `status`.
2. Same file, unsandboxed: exit `6`, `verdict = not_established`, `failed`
   equals the exact list `[admin.endpoint, admin.endpoint_alias, admin.dir,
   run.lock_write, store.read, store.write, store.wal_read, …, engine.runtime_read,
   flows.read, log.read, keychain.search, daemon.signal, broker.launchservices,
   broker.appleevents, exe.write]` minus whatever is `absent` on the fixture
   base (asserted explicitly), `unverified` empty; the unattributed admin
   contact count is `0` because the report attributes it.
3. `pam-agent.sb` and the Gemini `.sb` (with Gemini's `-D` parameters) run
   under `sandbox-exec` with `doctor` → `established` for the first, and for
   the second the exact expected `failed` set (`keychain.search`, `broker.*`,
   `daemon.signal`) with the verdict `not_established` — proving the doc's
   claim about the permissive base.
4. The helper-output classifiers (`security`, `kill`, `open`, `osascript`) are
   unit-tested against strings captured from the real OS during task T7 and
   recorded in the test as fixtures, with the capture date in a comment, the
   way `macos-sandbox-acceptance.md:30-34` records an observed behaviour.
5. `crates/pam/tests/cli.rs`: `--profile` for each harness renders with a given
   `--base`, is valid JSON/TOML/SBPL (`sandbox-exec -f <file> /usr/bin/true`
   for the `.sb` files), and names every must-deny path from the inventory
   (one test iterates the inventory against the rendered text).
6. Daemon unit tests: `doctor.report` validation and pruning (65 inserts keep
   64); admin contact recording for accept-then-EOF and for a foreign-exe hello
   (`admin_transport_unix_test.rs`, which already drives the real socket); the
   `status` block from an empty store and after reports; `public_unknown_harness`
   counting with an injected resolver.

Windows (the Parallels VM, driven as in the memento; CI's Windows job runs the
unit tests and the unsandboxed run):

- Unsandboxed as the owner: `pam doctor --json` → exit `6`, `failed` is the
  Windows list (`admin.control_read`, `admin.dir`, `store.*`, `run.lock_write`,
  `engine.*`, `flows.read`, `log.read`, `keychain.search`, `daemon.process_query`,
  `broker.shellexecute`, `exe.write` — the last `allowed` via sharing
  violation), `control.json` unread (the test wraps the file with an audit ACE
  or simply asserts the doctor never opened the port: the admin listener's
  pending count is unchanged).
- As a second local standard user created for the run (`net user pamprobe …`
  via `prlctl exec` as SYSTEM, then a scheduled task `schtasks /RU pamprobe`
  running `pam doctor --json` against the owner's base): exit `1`,
  `cannot_probe`, because `public.json` is unreadable — recorded in the doc as
  the proof that "different user" bounds the agent and also excludes it.
- `runas /trustlevel:0x20000` (Basic User, same SID): exit `6` with the full
  list — recorded as the proof that a restricted token of the same user does
  not bound file access; this is the Windows statement's evidence.
- Classification unit tests with injected `ERROR_ACCESS_DENIED`,
  `ERROR_SHARING_VIOLATION`, `ERROR_FILE_NOT_FOUND`.
- Documentation only: Codex low-privilege accounts, Gemini Low integrity,
  Copilot Insiders — each gets one sentence in `docs/sandbox/windows/README.md`
  with the source, no claim of a measured result.

## Implementation plan

Ordered; each task names its file-ownership set so agents can run in parallel
where the sets are disjoint. Clippy on the touched crate before the full gate
(memento). Branch `feat/boundary-doctor`; commits reference the ptrack task.

| # | Task | Owns | Acceptance |
| --- | --- | --- | --- |
| T1 | Shared types: move `KNOWN_AGENTS` and `classify_chain` to `pam_proto::caller`; add `pam_proto::doctor` (`DoctorReport`, `Probe`, `ProbeResult`, `Verdict`, `SCHEMA_VERSION = 1`, serde, validation with bounds) | `crates/pam_proto/src/{lib.rs,caller.rs,caller_test.rs,doctor.rs,doctor_test.rs}`, `crates/pam_client/src/caller.rs` (re-export) | unit tests; `cargo clippy -p pam_proto -p pam_client --all-targets -- -D warnings` |
| T2 | Probe engine: inventory, per-platform probes, pure classifiers over injected errors and helper outputs, bounded helper runner, env facts, JSON and human rendering | `crates/pam/src/doctor/{mod.rs,inventory.rs,classify.rs,classify_test.rs,helpers.rs,helpers_test.rs,probes_macos.rs,probes_windows.rs,render.rs,render_test.rs}` | every probe documented in the inventory table; classifier tests per platform; a test asserting no probe uses `write`, `create`, `truncate`, `remove_file`, `rename` (grep-style over the module) |
| T3 | CLI: `Cmd::Doctor { json, no_report, timeout_ms, profile, base, managed }`; `render::EXIT_BOUNDARY = 6`; README CLI table and exit codes; `lib.rs` exit table; playbook text (`pam::PLAYBOOK`, `docs/pam-playbook.md`) | `crates/pam/src/main.rs`, `crates/pam/src/render.rs`, `crates/pam/src/lib.rs`, `README.md`, `docs/pam-playbook.md` | `cli.rs`: unsandboxed run against a test daemon exits `6` with the list; `--json` prints one document; `--profile` prints and exits `0` without dialing |
| T4 | Daemon: `doctor.report` capability (Control class), store migration (`boundary_report`, `boundary_observation`, `request.peer_exe`, `request.peer_harness`), peer executable/ancestry resolution at public ingress, admin contact observation and attribution, `status` block in `StatusCache`, `admin.activity.list` columns | `crates/pam_daemon/src/{executor.rs,policy.rs,daemon.rs,ingress.rs,ingress_test.rs,boundary.rs,boundary_test.rs,admin_transport_unix.rs,admin_transport_unix_test.rs,admin_transport_windows.rs,status_cache.rs,admin.rs}`, `crates/pam_store/src/{migrations.rs,migrations_test.rs,store.rs,boundary.rs,boundary_test.rs}` | tests listed under "Test strategy" item 6; `status` from an empty store has `boundary.last_report = null`; a public `doctor.report` writes exactly one request row and one audit row |
| T5 | Status rendering and GUI: `render_status` line; `DaemonStatusReply` unchanged (the block rides in `status`); Settings › Daemon "Boundary" rows with a copyable command; Home card line; ipc types; vitest | `crates/pam/src/render.rs` (the `boundary` line only, after T3), `frontend/src/screens/Settings.tsx`, `Settings.test.tsx`, `Home.tsx`, `Home.test.tsx`, `frontend/src/lib/ipc.ts` | vitest renders never-checked, established, not_established, and unattributed-contact states; `npm run lint` and `build` |
| T6 | Reference profiles: the five files under `docs/sandbox/`, embedded and rendered by `--profile`; preambles with sources and dates; `docs/sandbox/README.md` | `docs/sandbox/**`, `crates/pam/src/doctor/profiles.rs`, `profiles_test.rs` | item 5 of the test strategy; each `.sb` loads under `sandbox-exec` |
| T7 | macOS acceptance: `doctor_macos.rs` (items 1–4), helper string capture recorded in the test and in `docs/macos-sandbox-acceptance.md` | `crates/pam/tests/doctor_macos.rs`, `crates/pam/tests/support/pam-agent.sb` (generated from `docs/sandbox`), `docs/macos-sandbox-acceptance.md` | both verdict paths pass under `cargo test -p pam --test doctor_macos` |
| T8 | Docs: `docs/admin-boundary.md` (new "Verifying the boundary" section; per-user authority statement replacing "Per-agent repository authentication is not implemented"; the engine-runtime finding), `docs/session-socket-relay.md` (doctor through the relay), `CHANGELOG.md`, `docs/reviews/design-review-2026-10-02.md` decision 4 pointer to this spec | those files | docs-only PR rule applies only if split out; otherwise part of the branch |
| T9 | Windows: `crates/pam/tests/doctor_windows.rs` (unsandboxed list; classification), the Parallels VM runs recorded in `docs/sandbox/windows/README.md` with dates; `bash tools/check.sh` green; CI green | `crates/pam/tests/doctor_windows.rs`, `docs/sandbox/windows/README.md` | the three VM runs recorded; `tools/check.sh` passes locally |
| T10 | Relocate the engine runtime (`engine.sock`, `engine/api.key`, `engine/engine.pid`) out of `<base>/run` into `<base>/engine/run` with the 0700 mode the base has (ptrack issue 44) — **done on this branch**: `EngineLayout::runtime_dir`, migration of an older daemon's leftovers at start, probes and profiles follow | `crates/pam_model/src/{engine.rs,engine_server.rs}`, `crates/pam_daemon/src/model_service.rs`, `crates/pam/src/doctor/{inventory.rs,probe_unix.rs}`, `docs/sandbox/**` | `pam_model` and `pam_daemon` tests; `doctor_macos` re-run |
| T11 | Integrate and verify (ptrack 217): rerun T7 and T9, `ptrack summary set`, `plan done` | — | checkpoint block acted on |

Parallelism: T1 first; then T2 ‖ T4 ‖ T6; then T3 (needs T1, T2) ‖ T5 (needs T4); then T7, T8, T9; then T10, T11.

## Decisions

1. Exit code `6` for `not_established`. Reusing `5` (blocked) or `3` (refused)
   would make a sandbox finding indistinguishable from a daemon decision in
   scripts; `6` is new and documented in every exit table.
2. The Windows admin probe opens `control.json` for read and closes it without
   reading. Metadata asks a different question; reading would make the probe
   the capability. The admin port is never dialled on Windows.
3. `public.unlink` is not probed: no side-effect-free test exists; the fixture
   keeps it.
4. `unknown` fails the verdict. A boundary is claimed from evidence only.
5. The report is a Control-class public request with a row and an audit entry,
   not a snapshot path: the record must be attributable to a kernel peer.
6. Admin-contact attribution is by kernel pid and a 60 s window — the daemon's
   own two observations, never the client's document.
7. The beacon does not change colour on the boundary; Settings › Daemon and
   Home carry it. Liveness and the boundary are different questions.
8. No per-agent grant model (section above); the docs state per-user authority.
9. The engine runtime's placement under `<base>/run` was filed as issue 44 and
   closed operationally by the profiles and `doctor`; T10 then moved it to
   `<base>/engine/run` on this branch (As built, T10 row), and the profiles no
   longer name any engine path under `run`.
10. `KNOWN_AGENTS`/`classify_chain` live in `pam_proto`; the daemon walks the
    peer's ancestry itself on macOS.

## Open questions (owner's)

1. Should the GUI add an onboarding step — "Verify your agent's sandbox" — that
   shows the `pam doctor --profile <harness>` fragment and the command to run,
   and shows the result arriving in the Daemon card? It is product surface, not
   a security change; this plan ships the data and the Settings rows only.
2. Is a Windows session channel (loopback relay with its own nonce) plus a
   low-privilege-account mode worth a plan of its own, given Codex's Windows
   sandbox runs commands as a different account and PAM is unreachable from it?
3. Should `pam status` for agents carry the full `boundary` block, or only the
   `last_report.verdict` and age? The block names private paths, which are
   documented anyway; the spec includes the block. Say if the agent-facing
   `status` should be trimmed.

## As built (2026-10-02)

What shipped on `feat/boundary-doctor` for T1 to T8 and T10, and where it
departs from the design above. Where this section and an earlier one disagree,
this one is the behavior; the sections above stay as the reasoning. T7 (macOS
acceptance under `sandbox-exec`) records its measurements in
`docs/macos-sandbox-acceptance.md`; T9 (Windows runs in the Parallels VM)
records them in `docs/sandbox/windows/README.md`. Line references in the design
sections are to the tree it was written against and have moved.

### Probes

1. **The broker probes are replaced, because the specified ones cannot tell
   allowed from denied.** `open -b <absent id>` and `osascript` against an absent
   application id print the same line inside the fixture's profile and outside
   it: the absent id is resolved in the calling process and the broker is never
   asked. As built, `broker.launchservices` runs `/usr/bin/lsappinfo find
   bundleid=com.apple.loginwindow` (a read-only query of the LaunchServices
   server: an `ASN:` line is `allowed`; exit 0 with no output, which is what a
   profile that denies the Mach lookup produces, is `denied`; anything else is
   `unknown`), and `broker.appleevents` runs `/usr/bin/osascript -e 'id of
   application "Finder"'` (a property read of the running Finder through the
   application-services broker, which sends no event, launches nothing and
   prompts for nothing: stdout exactly `com.apple.finder` is `allowed`; stderr
   containing `Connection Invalid` is `denied`; a bare `(-1728)` or anything else
   is `unknown`). Strings were pinned on macOS 26 (Darwin 27.0.0), 2026-10-02,
   outside and under both `crates/pam/tests/support/broker-macos.sb` and
   `docs/sandbox/macos/pam-agent.sb`, and T7 pins them again under
   `sandbox-exec`. Both need a login session with Finder and the login window
   registered to read `allowed`: in a headless session they read `denied` and
   `unknown`, never `allowed`. A profile that allow-lists Mach lookups must also
   deny `com.apple.hiservices-xpcservice`, or the AppleEvents probe reads
   `allowed` under it.
2. **The admin connect holds its socket for 150 ms.** `admin.endpoint`,
   `admin.endpoint_alias` and `engine.socket` connect, send and read nothing,
   hold the connection for 150 ms and drop it, instead of dropping at once. A
   peer that is already gone when the daemon's accept loop asks the kernel for
   its credentials cannot be identified, so the daemon could only record a
   contact with no pid, which no report could explain. With the hold, the daemon
   reads the pid and the report from that pid attributes the contact. A refused
   connect (`ECONNREFUSED` on a stale socket) is `allowed`: the sandbox let the
   connect reach the socket.
3. **`exe.write` and `bundle.write` never open their target.** The first version
   opened the running executable for write with `create(false)` and no byte
   written. On macOS an open-for-write of a Mach-O that another process is mapped
   from (the daemon, always, in production) invalidates the kernel's cached code
   signature for that inode, and every later exec of the file is killed
   (`Killed: 9`, exit 137) until the file is replaced; `codesign -vv` still says
   valid. One unsandboxed run would have left `pam` and `PAM.app` unrunnable
   until reinstalled. The probes now run `/bin/test -w <path>` through the helper
   runner, which is `access(2)` with `W_OK` and opens nothing (exit 0 is
   `allowed`; exit 1 is `denied` with the note `access(W_OK) refused`, unless
   `test -e` says the path is not there, which is `absent`). For `bundle.write`
   the path is `<bundle>/Contents/Info.plist`, and outside a bundle the row is
   `absent` ("not inside an application bundle"). `doctor_poisons_nothing_it_runs_from`
   in `crates/pam/tests/doctor_cli.rs` reproduces the failure on the old probe
   and passes on the new one. **Windows keeps the open**, through the seam:
   Windows has no signature cache, and the image section of a running executable
   makes `CreateFile` fail at the share check, after the ACL's access check, so
   `ERROR_SHARING_VIOLATION` is `allowed`, `ERROR_ACCESS_DENIED` is `denied`, and
   no handle ever exists. The non-opening alternatives answer another question or
   fail the wrong way (the read-only attribute is not the ACL; a directory opened
   for write is always `ERROR_ACCESS_DENIED`, a false pass).
4. **`daemon.process_query` on Windows is a PowerShell `Get-Process` of the
   lock's pid**, not `sysinfo`: the `pam` crate has no such dependency and none
   was approved. The evidence is the same (the executable path is visible if and
   only if query rights were granted) and the note still says "query only".
5. **The harness chain is read with `/bin/ps` (macOS) or one PowerShell
   `Win32_Process` walk (Windows)**, because the client's own walk is private. It
   includes the root (`launchd`) as a real ancestry walk does, and is empty when
   the helper cannot run, for example under a deny-default profile (`/bin/ps`
   cannot exec under either shipped profile). It is information only; the daemon
   walks its own.
6. **Helpers get a minimal environment, not an empty one**: an allowlist (home,
   user, locale, temp directory; on Windows the system and profile variables;
   never `PATH`), because `security` needs the session identity to find the login
   keychain. Absolute program, null stdin, both pipes drained and capped at
   64 KiB, killed at the bound, as designed.
7. **`unknown` on `public.reach`** (connection refused, a legacy build, a
   refusal, no acknowledgement) carries its reason as a note and yields
   `cannot_probe` with every other row still probed, instead of ending the run.
   `pam doctor` never starts a daemon, and with `cannot_probe` it does not send a
   report (the daemon would refuse it).

### The document and the verdict

8. **`ProbeId` is a closed enum** (`pam_proto::doctor`, 29 ids, one
   `INVENTORY` row each, in report order). An id the binary does not know fails
   to deserialize and the daemon refuses the document, instead of storing ids "as
   sent". Client and daemon ship as one binary and a version mismatch is refused
   at the hello, so a new probe is a new inventory row and additive. The
   `env.*` facts and `frontend` are `EnvFacts` members, not probe rows (a probe
   row means allowed or denied; `frontend: embedded` does not), and
   `run.lock_probe` is encoded for both platforms as an info row.
9. **`judge` outcomes.** Classes come from the inventory, never from a row's own
   `class`; info rows are never counted. `cannot_probe` is no `public.reach` row,
   or any must-allow row not `allowed`. Otherwise, over must-deny rows in order:
   `allowed` is `failed`, `unknown` is `unverified`, `absent` and `not_probed`
   are `skipped` with `why` equal to the state or `<state>: <note>`, and `denied`
   appears nowhere. Rows for a probe that does not exist on the platform are
   `not_probed` with the note `not probed on <platform>` and are listed under
   `skipped`. `established` is `failed` and `unverified` both empty. The daemon
   recomputes `judge` from the probe rows and refuses a document whose
   `verdict`, `failed`, `unverified` or `skipped` differ, and refuses a
   `cannot_probe` document (`NotRecordable`). Limits: 16 KiB, 64 rows, 256 bytes
   of text per note, 1,024 per path, 16 chain names, no control characters.
10. **`--json` is the document plus a top-level `daemon_reply`.** `daemon` stays
    the hello's facts (`version`, `proto`, `epoch`, `via`; `null` when the
    daemon was not reached); the `doctor.report` reply body is its own top-level
    member, present only when the daemon answered with a result. `report` is
    `{"recorded": true, "request_id": …}` or `{"recorded": false, "reason":
    …}` (`--no-report`, a refusal, a transport failure). Options serialize as
    `null`. The corrected example is under "Output" above.
11. **Delivery never changes the exit code.** `established` 0,
    `not_established` 6, `cannot_probe` and a run that cannot start 1, usage 2;
    a refusal or transport failure of the report is a stderr line and
    `report.recorded = false` with the cause. `--profile` answers before any
    runtime, base resolution or dial, and conflicts with `--json`, `--no-report`
    and `--timeout-ms`; `--base` and `--managed` require it.

### The daemon

12. **Two audit rows per report, not one.** The pipeline writes the terminal
    `execute` row for every request and cannot be replaced; the capability adds
    one non-terminal `doctor.report` / `allow` / `system` row (detail: verdict,
    `failed`, `unverified`, `peer_harness`) in the same transaction as the report
    row. A refused document leaves nothing stored and the pipeline's
    `execution_refused` row.
13. **Schema (migration 16)** differs from the DDL above: `boundary_report.request_id`
    is nullable with `ON DELETE SET NULL` (retention deletes request rows by an
    explicit child list); `report_ts` (the client's clock) sits beside `ts`
    (receipt); observations gain `expected`, `peer_uid` and `peer_harness`;
    `report_json` is checked at 16,384 bytes. Retention keeps the newest 64
    reports, the newest 256 unexpected observations and the newest 32 expected
    ones, with lifetime counters in `setting` (`boundary.admin_contacts_total`,
    `boundary.admin_contacts_expected_total`, `boundary.public_unknown_total`).
    Events per kernel pid are deduplicated in memory (5 s for unexpected, 1 h for
    expected) and still move the counters.
14. **Admin contacts.** Every connection the private listener accepts is
    observed; one that sends nothing, or that speaks from an executable other than
    the daemon's boot image, is recorded. A contact whose hello comes from the
    daemon's own image (the GUI) is `expected` and kept apart. A peer gone before
    its credentials could be read is recorded with no pid and stays unattributed.
    Attribution matches the same kernel pid within 60 s, a contact born after the
    report included. The unix and Windows adapters reach the observer through a
    registry keyed by the canonical base (`boundary::register_admin_sink`), because
    `admin_transport.rs` was outside T4's file set; threading a parameter through
    `AdminTransport::bind` would remove the registry.
15. **The block carries more than the design's.** Beyond the fields above:
    `peer_identity` (`kernel_pid`, or `none` on Windows), `received_ts` beside the
    report's `ts`, `unattributed_24h`, `expected_total`, `last_expected`, and a
    `summary` line the CLI prints verbatim. `pam status` prints a second line
    with the request id and age when a report exists. The Settings › Daemon rows
    also show the harness and the last foreign peer, with every daemon-supplied
    string escaped; Home shows one line linking to Settings.
16. **Windows peer facts are null.** `peer_uid`, `peer_pid`, `peer_exe` and
    `peer_harness` are null on every row and reply, `harness_agrees` is null,
    `public_unknown_harness` never counts, and admin observations are
    `admin_handshake_failed` only. The report is still stored and the block still
    served.
17. **Peer resolution** runs on the blocking pool under a 300 ms budget for every
    public request with a kernel pid (a miss is null), excludes the peer itself
    from the chain, and is skipped for attached duplicates and admin submissions.
18. **Not yet exposed:** `admin.activity.list` does not return `peer_exe` and
    `peer_harness` (`admin.rs` was outside T4's set); the store reads them
    through `request_peer_facts`.

### Profiles and documents

19. `profiles::render` returns a `Result` and fails closed on a base that cannot
    be written safely (not absolute, a `.` or `..` component, control
    characters, glob characters in a JSON or TOML path). `--profile --base` is
    made absolute and, on unix, canonicalised when it exists, because Seatbelt
    matches resolved paths.
20. Codex's permission profile does have a unix-socket key
    (`[permissions.<name>.network.unix_sockets]`), contrary to what the design
    could confirm, but it applies only with network access enabled, so the
    shipped file enables network and says egress is not restricted by it. The
    Gemini profile is our own, modelled on the permissive base, without the
    SecurityServer Mach lookup and with outbound limited to IP and the system
    resolver's socket; the PAM block is last.
21. The unverified-on-this-host list: every `cfg(windows)` line (the keyring
    read, the PowerShell helpers, `where.exe /?`, the loopback handshake hook)
    compiled and ran only through the code that builds on macOS; T9 runs them in
    the VM. The `established` exit-0 path through the binary is T7's, under
    `sandbox-exec`.
22. **`daemon.signal` and `daemon.process_query` take the daemon's pid from
    the hello acknowledgement**, not from `<base>/run/daemon.lock`. The
    `hello_ack` frame carries `pid` (`pam_proto::wire::HelloAck`; the admin
    plane's acknowledgement carries it too), the reach probe hands it to the
    probes that wait for it, and the lock file is never read: the seam reads no
    byte from under the base at all (a source test pins it). With no daemon
    acknowledged the two rows are `not_probed` ("no daemon reached: no pid to
    probe"), counted under `skipped`; the run is `cannot_probe` regardless.
    Consequence: through the session relay, under the documented relay
    variant of a profile (nothing under `<base>` readable), the verdict is
    `established` — T7 asserts it for both relay variants. The pid is public
    information (the lock holds it, `pam daemon stop` prints it) and the
    public socket is reachable by the same user only.
23. **`harness_agrees` is three-valued.** `false` only when both sides know
    and differ; `null` (printed `undetermined`) when the daemon has no
    resolution (Windows, a missed budget), when it sees the relay process in
    place of the client, or when the client's own chain is empty — under both
    shipped Seatbelt profiles `/bin/ps` cannot exec, so a correct sandboxed run
    claims `unknown` and must not read as a disagreement
    (`pam_daemon::boundary::harness_agreement`). The profiles do not allow
    `/bin/ps`: a process listing is information the sandbox should deny.

### Open at this status

Nothing: the two items recorded here earlier (the relayed `daemon.signal`
and the engine runtime inside `run`) closed with As built 22 and T10.
