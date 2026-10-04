# Changelog

All notable changes to pam are documented in this file. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and pam adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

- Nothing yet.

## [0.5.0] - 2026-10-03

### Upgrading from 0.4.x

Read [Compatibility](#compatibility) below before upgrading. In short:

- The store moves to SQLite on the first start, after a full copy into
  `<base>/backup/state-<UTC time>-pre-sqlite/`. There is no downgrade: older
  binaries refuse the upgraded database, and going back means restoring that
  copy and losing what was written since.
- Supported platforms are macOS on Apple Silicon and Windows amd64/arm64.
  Linux and Intel Mac builds are gone.
- The agent protocol on `run/pam.sock` changed. The first `pam` command run
  outside a sandbox, the GUI, or `pam listen` stops a running 0.4.x daemon and
  starts the new one, silently and for up to ten seconds if it has work in
  flight. On Windows end the old daemon's process yourself; a sandboxed client
  prints what to run instead.
- Quit and reopen a GUI left open across the upgrade. An old `pam` binary
  cannot talk to the new daemon.
- A login unit still pinned to the old binary cannot start the daemon:
  `pam service status` says whether it pins this binary, and
  `pam service install` registers the new one.
- Sandbox profiles need only `pam.sock`; `events.sock` is gone.
- Flows naming `connector: aws` fail validation; that adapter is removed.
- Building from source needs a C compiler, for the bundled SQLite.

### Added

- `status` carries a `containment` block saying whether this machine can
  contain command workloads, and `pam status` prints it on a `commands:` line.
  On Windows it reports that flow command steps and guarded landing refuse
  `command_containment_unavailable`; the desktop app says the same under
  Settings › Daemon, on Home, on the Flows screen and in the landing settings.
  README lists what runs on each platform.
- Refusals decided before a request row exists (capacity, rate, a malformed or
  oversized frame, a refused hello, an expired deadline at admission, the
  connection cap, the drain) are recorded in a new `refusal` table (schema 18)
  and shown in Activity under "Refused before admission": cause, how many
  attempts, who knocked (the kernel's view of the peer, and what the client
  claimed). Identical refusals within ten seconds are one row with a count, the
  write never delays the reply, and `status` reports `refusals.dropped` when a
  flood outruns the log. `admin.activity.list` takes `include_refusals`. See
  [the audit contract](docs/admin-boundary.md#the-audit-contract-request-rows-and-refusal-rows).
- `pam flow run --digest <sha256>` runs a flow only if it still has the digest
  `pam flow inspect` reported; a flow edited in between refuses as
  `flow_changed`. `pam flow inspect` now prints the digest on its first line.
  The GUI pins Run to the flow it shows in the same way.
- Flow results list `effects` (step, kind, `applied` or `possibly_applied`, and
  the landing operation for landing steps) beside the outcome. They are kept
  when the outcome is `unresolved` or `blocked`, where the handoff reason is
  `workflow_not_completed_after_state_change`. `pam flow result` and the GUI
  run card print them.
- Refusals carry a `retryable` flag for momentary daemon conditions. Clients
  retry on the flag and keep their own list of causes for older daemons.
- `admin.requests.cancel`: the GUI cancels a ticket over the private
  administration channel, and the audit records it as the human's act. The
  public `request_capability` bridge command is removed.
- `admin.flows.save` and `admin.flows.delete` replies list `grants_revoked`
  and `reapproval_required`, and the GUI tells the human which steps lost
  their remembered approval.
- Pending approvals for a flow step show the resolved command: program, one
  token per argument, directory and the names of the variables it sets.
  Approving is pinned to that snapshot (`expected_digest`); a flow edited
  while the approval waited refuses as `flow_changed` and stays pending.
- `pam status` gains `snapshot` (`stale`, `model_age_ms`, `keyring_age_ms`).
- The daemon checks the store's integrity at boot (files up to 256 MiB) and
  reports a damaged file with a cause and recovery line instead of an engine
  error.
- `pam service status` reports the binary the unit pins and whether it is
  stale; Settings offers "Repoint to this binary".
- `pam flow result` labels local-model summaries `[untrusted local-model
  summary]` and escapes control characters in them.
- Request rows record where a request entered the daemon and who connected:
  `ingress` (`public` or `admin`), the kernel's uid and pid of the peer
  (`peer_uid`, `peer_pid`; empty on Windows, which reports none) and whether
  the client said it came through `pam listen` (`relayed`).
  `admin.activity.list` returns them. They are attribution, never
  authorization.
- The GUI receives every lifecycle event over the private administration
  channel, with the ticket's capability, repository, agent label and the real
  progress note. Settings › Daemon explains a window and a daemon of different
  builds, and Models readiness says what a qualification covers.
- Settings › Network: an HTTPS proxy (`http://` or `https://` with an explicit
  port; `none`, `basic` or `anyauth` sign-in; the password kept in the OS
  keychain), a no-proxy list, a CA bundle imported as a private digest-checked
  copy, and mirror addresses for the engine and for models. "Test network
  settings" probes every enabled connector and the download hosts PAM would
  use and reports, per target, the route, the stage reached, a cause and a
  recovery line. Daemon ops `admin.network.get`, `admin.network.set` and
  `admin.network.test` (GUI-only), audit action `network.configure` with field
  names only, and the typed word `network` for a proxy, password or CA change.
  Fields a managed policy pins are reported locked and refuse the whole patch
  (`setting_locked`); the managed policy file below fills that layer.
- The engine card says, before the click, exactly what Install does:
  `admin.models.engine.status` discloses the asset, its size and SHA-256, the
  URL and host it would be fetched from, whether a mirror is in use, the
  install location, the installed engine's source, whether a model is loaded
  and whether the engine can be removed. Install uses the configured engine
  mirror when one is set. `admin.models.engine.import { path, confirm }`
  installs the pinned archive from a file, or a folder holding it by its
  exact name, copying and hashing in one pass with the original untouched;
  `admin.models.engine.remove { confirm }` deletes the engine directory and
  is refused while a model is loaded. The manifest records its `source`
  (`download`, `mirror` or `import`).
- Models: a download confirmation names the file, its size, the host and
  address, the SHA-256, the destination and the licence before a transfer
  starts, and says when a pasted address has no expected digest. "Import
  weights from a file" (`admin.models.import { path, confirm, vendor?,
  expected_sha256? }`) copies a GGUF into the models directory as a job of
  kind `import`; a file whose size matches a catalog model is held to that
  model's SHA-256 and recorded verified, any other file is unverified unless
  a digest is given. Catalog presets carry `fetch`, the exact address and
  host a download would use.
- The README gains "Local models and the inference engine": what is fetched
  and from where, the pinned archive table (held equal to the build's
  constants by a test), what runs on the machine, the mirror and
  install-from-file paths, the network settings, and how to remove it.
- `pam doctor` checks the caller's own sandbox boundary. Run from where the
  agent runs, it probes whether that position can reach what only the GUI may:
  the private administration endpoint, the store files, the lock file for
  writing, the model-trust, engine, flow and log directories, the engine's
  socket and key directory, the keychain service, a signal to the daemon, the
  LaunchServices and AppleEvents brokers, and writes to the `pam` executable and
  its bundle. It prints one verdict and exits `0` for `established`, **`6` for
  `not_established`** (a new code, distinct from refused and blocked; the
  `failed` probes are listed) and `1` for `cannot_probe` (no daemon answered
  the hello; nothing is started). `unknown` on a must-deny probe fails the
  verdict. `--json` prints one document and nothing else, with the daemon's
  reply as a top-level `daemon_reply`; `--no-report` skips recording and never
  changes the code. An unsandboxed developer machine is `not_established`, and
  so is every supported Windows configuration: no harness sandbox on Windows
  establishes the boundary today, and the documents say what to do instead.
- The daemon records each report (a control-class public request,
  `doctor.report`, with an audit row) and its own observations of the private
  plane: admin connections that sent nothing or came from another executable,
  and public requests from an unrecognised harness. `pam status` gains a
  `boundary` block (last report, retained counts, unattributed admin contacts,
  a `summary` line), printed as a `boundary:` line; Settings › Daemon shows it
  with a copyable `pam doctor` command, and Home shows one line. A report
  changes no authority; nothing reads it but the human and fleet scripts.
- `pam doctor --profile <claude-code|codex|gemini-cli|copilot-cli|sandbox-exec>
  [--base DIR] [--managed]` prints a reference sandbox profile for that harness
  with the base filled in and exits `0` without probing. The profiles live in
  `docs/sandbox/` (macOS profiles per harness, a harness-independent
  `sandbox-exec` profile, a Windows statement) and are embedded in the binary.
  Each allows the literal public socket and the lock-file read, denies the rest
  of the base, and says what its harness leaves outside.
- Request rows record the peer's executable and the harness the daemon found in
  its ancestry (`peer_exe`, `peer_harness`; `relay` through `pam listen`) beside
  `peer_uid` and `peer_pid`, on macOS. Attribution, never authorization.
- The administration boundary document gains "Verifying the boundary" and
  states that authority is per operating-system user: caller labels, pids and
  executable paths are attribution, and agents that need different authority
  run as different users. The playbook teaches `pam doctor --json` once per
  session, exit `6`, and stopping rather than working around a finding.
- A managed policy file: an organization delivers one read-only JSON document
  with its MDM to a fixed path, `/Library/Application Support/PAM/policy.json`
  on macOS or `%ProgramData%\PAM\policy.json` on Windows (no flag, environment
  variable or base directory can move it). The daemon reads it only after a
  trust check: on macOS the file and every folder above it owned by root and
  writable by nobody else, no symlink, one handle from check to read, and a
  write probe; on Windows the daemon's own token must be unable to write,
  delete or re-ACL the file or its folder. It can lock a setting, set an
  organization default the human may change, bound it (`floor`, `min`,
  `max`), allowlist it (`allow`), or add constraints only an organization
  states: never-grant capability patterns and classes, allowed repository
  roots, connector hosts, GitHub servers, model sources and curators, a
  landing ceiling, an engine source and a login-unit requirement. Proxy,
  no-proxy, CA bundle and mirrors are covered too. A damaged file follows a
  two-tier rule: a rejected authority key (security, scopes, connectors,
  programs, landing, retention, proxy) keeps the last good value or, with
  none, is held so nothing loosens, while a rejected convenience key (mirrors,
  models directory, idle unload) falls back to the human's value. The policy
  is re-read at boot, on a 60 s stat poll, on a 10 min re-verify and on
  "Check now"; it is an overlay computed at read, so the human's own settings
  are never rewritten and come back when the file is removed. Guide and
  samples: `docs/policy/`.
- `pam policy check <file> [--platform macos|windows] [--trust] [--json]`
  validates a policy file exactly as the daemon would, with no daemon and no
  write, and exits `0` valid, `13` valid with rejected leaves, `12` invalid as
  a whole, `11` not trusted (`--trust` runs this machine's trust check on the
  file where it sits), `1` unreadable. MDM compliance scripts run it against
  the fixed path with `--trust --json`.
- Settings shows managed values: a locked control is disabled with "Managed by
  your organization", the reason and the contact; a bounded or allowlisted
  control prints its constraint; an organization default says so. Security ›
  Managed policy shows the file's path and trust check, revision, digest,
  organization, contact, the last good copy, every key's state and a "Check
  now" button, and the Settings header carries a status line. Every settings
  `get` op returns an `effective` entry per field (`source`, `locked`, `mode`,
  `constraint`, `reason`, `state`).
- Daemon ops `admin.policy.get` and `admin.policy.reload` (GUI-only). Refused
  writes to a managed setting answer `setting_locked`, `policy_not_allowed` or
  `policy_frozen` and write a `policy.locked_write` audit row; loads write
  `policy.load`, `policy.reject` and `policy.clear` rows with the policy's
  digest. `pam status` gains a `policy` block (state, revision, a digest
  prefix, rejected-leaf count; never a rule or the organization) and a
  `policy:` line.

### Changed

- The daemon's first scheduled retention prune runs two minutes after boot
  instead of at once, so a large first prune does not hold the store during
  crash recovery and the first requests. Saving retention settings and Prune
  now still prune immediately.
- Guarded landing polls required checks with exponential backoff (about 5 s
  doubling to a 60 s cap, with jitter) until the request's own deadline,
  instead of a fixed 20 polls at 5 s: it never gives up while a poll fits, and
  the deadline bounds the count. A deadline with no room left refuses
  `request_deadline_exhausted`. See [guarded landing](docs/guarded-landing.md#durable-effects-and-bounded-waiting).
- The landing merge method is a setting (`merge_method`: `squash`, the default,
  `merge` or `rebase`) instead of a hard-coded squash. `merge` refuses
  `landing_merge_method_forbidden` before journalling when GitHub reports the
  repository forbids it. The managed policy can lock or default it
  (`landing.merge_method`).
- Required landing checks can be pinned to the GitHub App that reports them
  (`{ name, app_id }`, written `name @app-id` in the form); a same-named check
  from another app no longer satisfies a pinned check. Name-only checks still
  work and the form marks them "Unpinned app". A fully pinned list reads check
  runs only.
- GitHub refusing a landing PR creation or merge (405, 409, 422: a PR already
  exists, no commits, merge conflict, required status checks expected, method
  not allowed, head modified, not mergeable) blocks the step with a typed cause
  and recovery and settles the intent `rejected`; it no longer reads as an
  uncertain effect. A lost answer or a server error still does.
- Settings › Daemon: Stop now keeps the daemon stopped. The window's status polls
  and admin calls no longer start it behind the human's back; the beacon reads
  "Stopped by you" with a Start button beside it, Settings shows "stopped by you"
  with Start daemon, and Ask Pam says so. The stop holds until Start is pressed or
  the window is restarted. Restart is now Stop then Start. (A command-line `pam`
  still starts a stopped daemon lazily, as before.)
- `pam subscribe --json` writes only JSON to stdout: one compact object per event
  as it arrives, then the terminal response. Before, the human `[queued]` lines
  were printed first and made the output unparseable.
- The GUI saves a flow pinned to the digest it opened. A flow saved by someone
  else (another window, the CLI's library file) in between refuses
  `flow_changed` and writes nothing; the editor keeps the draft and offers
  "Reload the saved flow". `admin.flows.save` takes `expected_digest`.
- Ask Pam's optional rephrase is held to the template's shape: one plain line,
  bounded in length, no more sentences, no markdown, link, address or list marker
  it did not start with. Anything else shows the deterministic answer.
- Flow inputs take an optional `type:` (`string`, the default, `int`, `sha`,
  `ref`, `path` or `enum` with `values:`). A typed value that does not fit is
  refused with the input name, the type and the rule broken, before it reaches
  an argument, an environment value or a connector call; the value is never
  echoed. `ref` follows `git check-ref-format` (and refuses a leading `-`),
  `path` is relative and normalized, `sha` is 40 or 64 lowercase hex digits and
  `int` a decimal up to 2^53 - 1. An untyped input behaves as before. The
  starter flows type their revision, build, run, job, page and branch inputs,
  so their digests changed.
- A step's `env:` may no longer set `PATH`, `HOME`, `TMPDIR`/`TMP`/`TEMP`, any
  `GIT_*` name except `GIT_AUTHOR_*`, `GIT_COMMITTER_*` and `GIT_OPTIONAL_LOCKS`,
  `LD_*`, `DYLD_*`, `XDG_*`, `CARGO_HOME` and the other `CARGO_*`, `RUSTUP_*` and
  `RUSTC*` names that move or replace the toolchain, `PAM_ARTIFACTS`, or an
  interpreter hook such as `NODE_OPTIONS`. A stateful step that is not the first
  step and names neither `needs` nor `when` is refused at validation: add
  `needs: [...]` or `when: always`. **A flow in your library that does either
  needs an edit**: `pam flow inspect` and the GUI list show its refusal, and
  `pam flow run` refuses it as `flow_invalid` with the same message.

- A proxy locked by policy with `auth: none` (or pinned direct) also locks the
  proxy password; with `basic` or `anyauth` the password stays the human's to
  type in Settings › Network, because a policy file never carries a secret.
  A network setting the policy requires but cannot put in force refuses
  connector calls and downloads with the new cause `network_policy_invalid`,
  whose recovery sends the human to the administrator.
- On Windows `admin.network.set` refuses a CA bundle file (`network_ca_unsupported_on_windows`)
  and Settings › Network shows the field read-only: install the CA in the Windows
  certificate store, which PAM's curl trusts. On macOS saving a bundle warns that it is
  expected to replace system trust for every request (not measured there).
- The store runs on SQLite (bundled through `rusqlite`) instead of the Turso
  engine. Databases written by earlier versions are opened in place after a
  one-time backup. Building from source now needs a C compiler on every
  target: the Xcode command line tools on macOS, the MSVC build tools on
  Windows.
- The store refuses a call when 1,024 are already waiting for the same
  connection, instead of queueing without bound behind a disk that is not
  keeping up. A public request that meets the bound is refused with the new
  cause `store_overloaded`, marked retryable, with the store's own sentence as
  the detail and "Retry shortly." as the recovery; a `pam wait` or
  `pam subscribe` retries it with backoff. It used to be `internal_error`.
  The private admin plane shows the same sentence.
- A request that reaches the store after the daemon has closed it, at the
  very end of a shutdown, is refused `daemon_shutting_down` (retryable)
  instead of `internal_error`.
- The Activity list, a request's audit trail, evidence reads, the retention
  preview and the integrity check read through a second, read-only
  connection: they no longer wait behind writes, and writes no longer wait
  behind them.
- A model download or verification still running when the daemon stops is
  stopped and recorded as failed (`daemon_restart`) before the daemon exits,
  not at the next start. A download keeps its partial file and resumes.
- Supported platforms are macOS 12+ on Apple Silicon and Windows on amd64 and
  arm64. Linux and Intel Macs are not supported, and CI no longer builds or
  tests for them.
- The public transport is PAM's own framed protocol on the same socket,
  `<base>/run/pam.sock`: length-prefixed JSON, a `hello`, then one request per
  connection. On Windows it is a loopback port behind an owner nonce published
  in `<base>\run\public.json`. The daemon closes a connection after its
  answer, tells a connection over its 256-connection cap why
  (`connection_capacity_exhausted`), and keeps answering with a refusal frame
  while it drains instead of refusing the connect.
- Events are no longer broadcast. `pam wait` and `pam subscribe` follow one
  ticket on one connection, authorized like a result read, and the stream ends
  with the durable result: a follow costs one `query` request, a finished
  ticket is answered at once, and a late `pam subscribe` is shown the earlier
  events of a running ticket. At most 16 followers per ticket and 96 in total.
- `pam listen` binds one socket. It refuses a session directory that is a
  link, is owned by someone else or is writable by group or others, and a
  socket entry that is a link or not a socket. The daemon records the relay
  process as the peer of a relayed request.
- A `pam gui` built without the embedded frontend refuses to start unless
  `PAM_GUI_DEV=1` is set, because its window would load the development server
  with full control of the daemon. `npm run gui:dev` and `npm run dev:desktop`
  set it, on Windows too.
- `pam daemon stop` reports what `kill` said inside its own error line.

- `pam cancel` only acts on a ticket submitted from the caller's own
  repository; another repository's ticket answers `not_found`, like a missing
  one. Run it from the repository the ticket was submitted from. A public
  cancel is always recorded as `system`, whatever the caller's label says.
- Saving an edited flow removes the remembered approvals of every step whose
  definition changed, and deleting a flow removes those of its steps. The
  changed steps ask again.
- `admin.profile.set` applies immediately; the reply says `"applies": "now"`.
  It used to apply at the next daemon start.
- A client of a different version no longer restarts the daemon. The daemon
  restarts only when its own binary was replaced on disk; otherwise it
  refuses with `client_version_mismatch`, naming its version and path; the
  CLI prints one sentence with both versions and exits `3`. The version is
  judged on each connection's hello, on both planes. While it restarts, every
  request is answered `daemon_outdated`.
- `status` is served from a snapshot refreshed in the background, and a poll
  is no longer a request: it leaves no request or audit row, no caller entry
  and no lifecycle events. `active_requests` excludes the poll. `query` and
  `cancel` stay audited but publish no lifecycle events.
- Admission pools are separate per class: 128 work, 16 `status`, 16 `query`,
  8 `cancel` and 32 for requests the GUI submits, at 256, 64, 64 and 16 per
  second for the first four. Every request handler has a hard deadline.
- `pam wait` and `pam subscribe` retry transient refusals and resume a dropped
  follow after the last event seen until `--timeout-ms`, then exit `1` with
  `follow_timeout`. Exit `3` now means the daemon refused and a retry will not
  help: a policy refusal, or a daemon of another build.
- A daemon started lazily by a client runs with a reduced environment (home,
  user, locale, temp and absolute `PATH` entries, plus `PAM_BASE_DIR`), in its
  own process group, with `/` as its directory. Flow steps no longer inherit
  the first caller's variables; add tool directories through the flow
  settings' `extra_path`.
- `pam service install` refuses binaries in temp directories, in cargo build
  output and ones writable by group or others; it writes the unit before it
  stops a loose daemon; and it pins `PAM_BASE_DIR` only when given
  `--base-dir`, ignoring the caller's variable.
- Model verification is recorded privately under `<base>/model-trust` and
  checked again whenever a model loads. A sidecar next to the weights no longer
  makes a model verified, so each existing model needs "Verify" once after
  upgrading. A model with a leftover sidecar says so. On Windows a model
  file's "verified" fingerprint is its size and modification time only, so a
  same-size replacement with the timestamp restored is not noticed there; the
  engine loads only PAM's private verified copy, so what runs is unaffected.
- Local summaries are bounded to two minutes in the engine and five minutes
  in all, and a cancelled flow step cancels its summary.
- The local engine's API key is passed as a private file, not on the command
  line.
- The curator runs agent CLIs only from trusted install directories, owned by
  root or the daemon's user and not writable by others, with a minimal
  environment. A CLI found only through `PATH` is listed as untrusted and never
  run. `admin.curator.list` gains `untrusted`.
- Connector credentials are trimmed when saved, and a value containing a line
  break is refused. Connector paths containing `.` or `..` are refused. A log
  redirect may only go to a public host on port 443.
- Connector requests, model downloads and the engine archive all go through
  one hardened curl launcher (`pam_net`) over the trusted system curl: a
  constant argument vector `-q --config -`, every value on standard input, a
  cleared environment, a fixed working directory, `https://` only. Model
  downloads no longer honour `HTTPS_PROXY`, `HTTP_PROXY`, `ALL_PROXY`,
  `NO_PROXY`, `CURL_CA_BUNDLE`, `SSL_CERT_FILE`, `SSL_CERT_DIR` or any other
  variable; the proxy and CA bundle come only from Settings › Network. Plain
  `http://` download addresses, pasted ones included, are refused.
- Network failures carry a cause (`proxy_dns_failed`, `proxy_unreachable`,
  `proxy_auth_required` with the schemes offered, `proxy_denied`,
  `dns_failed`, `connect_failed`, `tls_untrusted_issuer` naming the issuer
  where curl prints it, `tls_hostname_mismatch`, `tls_expired`,
  `tls_revocation_unavailable`, `ca_bundle_unreadable`, …) with a sentence and
  a recovery, the same in connector refusals, download failures and the
  network test. A download that cannot start because the network settings are
  unusable is refused by that cause instead of `internal_error`; corrupt
  settings never fall back to a direct connection.
- Catalog downloads use the models mirror when one is set; pasted addresses
  are never rewritten.
- Store schema 15: `model_job.kind` admits `import`. The upgrade rebuilds the
  table in place and, like every schema upgrade, keeps a `pre-v15` copy of
  the database first.
- A stateful flow step can no longer write Git hooks or Git configuration in
  the repository it runs in, so `git config`, `git remote add`, a tracking
  `git checkout -b`, `git submodule add` and `git init` fail in such steps.
- A state-changing step with no `needs` and the default `when` no longer runs
  after an earlier step failed; add `needs` or an explicit `when` to opt in.
- A supplied value that would become a command-line option blocks the step
  (`argument_option_refused`) unless a literal `--` precedes it.
- `${...}` in a step's `env:` values is now substituted, like in arguments.
- `${repo.origin}` resolves only for a remote whose host is exactly
  `github.com`.
- `echo` refuses a delay over 60 seconds or arguments over 64 KiB
  (`echo_limit_exceeded`).
- Retention prunes in bounded batches, treats a stored window outside 1 to
  3650 days as forever, and saves both windows in one write.
- The GUI asks for a typed confirmation, checked in Rust, before switching to
  the relaxed profile, adding a grant or approving with Remember. Approval
  cards show each argument as its own token and escape hidden characters.

### Security

- The GUI's authority-expanding admin operations (relaxing the profile, adding
  a grant, approving with Remember, setting a proxy, its password or a CA
  bundle) now need a native confirmation drawn by the bridge in Rust after the
  typed phrase: a "Confirm in PAM" dialog whose sentence the bridge builds from
  the operation's own arguments and the daemon's pending entry, sent only on
  Allow and refused `confirmation_declined` on Cancel. The webview is granted
  no dialog permission, so a compromised page can neither skip it nor draw a
  look-alike. New dependency: `tauri-plugin-dialog` 2.7.3 (owner-approved), with
  `tauri-plugin-fs` and `rfd` under it. See
  [the administration boundary](docs/admin-boundary.md#confirmation-in-the-gui-bridge).
- The credentialed landing Git is no longer resolved through `PATH` and the
  flow search path. It is the explicitly configured Git path (Settings → Flows →
  Landing, or the managed policy's `landing.git_path`) or the first qualifying
  entry of a fixed allowlist (the active Xcode or Command Line Tools Git, never
  the `xcrun` shim, then Homebrew's; Git for Windows under Program Files), and
  every candidate and the directories above it must be owned by root or the
  daemon's user and writable by no group or other user. None qualifying refuses
  `landing_git_untrusted`. The freeze records the path and `git --version` in
  the landing session, a later stage that resolves another Git refuses
  `landing_git_changed`, and the Git broker re-checks it before each process.
- A remembered flow step approval is bound to what the step runs: the step's
  effect digest (computed from the normalized step, so reformatting or comments
  change nothing), its gate class and the canonical repository it was approved
  for. A flow file edited by hand or restored from a backup, or the same step
  run in another repository, asks a human again on every profile, and the
  approval card and the step's refusal say what changed. Remembering it again
  re-points that repository's grant. A flow step granted by hand in Settings is
  bound to the library's step for every repository (or a named one); a step the
  library does not hold is refused `flow_step_unknown`. `admin.grants.list`
  shows each binding (flow, step, repository, digest prefix) or `legacy`, and
  the approval card says Remember keeps the step for this repository and this
  exact step. Never-grant and manual-grant policy rules still apply first.
- Revoking one flow's step grant ends only that flow's tickets (the flow id is
  recorded on the request at admission), not every `flow.run` ticket; a parked
  watch of another flow keeps its authorization stamp.

- The curl launcher cannot render any option that weakens TLS verification:
  no `insecure`, `proxy-insecure`, `ssl-no-revoke`, `ssl-revoke-best-effort`
  or an outside `capath`, for a target or for a proxy, in production or in
  the test; a test scans the crate's source for those spellings.
- The proxy password never leaves the keychain except on curl's standard
  input for one request. It is absent from the command line, the environment,
  the settings document, log lines, audit rows and replies, and a failed
  proxied call never shows it. The CA bundle's private copy is re-hashed
  before every use; a copy that no longer matches its recorded digest refuses
  the request (`network_ca_tampered`) rather than running without it.
- The pinned engine digest, size, tag and build cannot be changed by any
  setting, argument or file: the install and import entry points build the
  pinned release themselves (`install_release` is test-only), the engine and
  import ops refuse unknown arguments, and a mirror or a file that serves
  other bytes is refused before anything is unpacked.
- The `pam doctor` write probes never open the binary. On macOS, opening for
  write a binary that the daemon is mapped from invalidates the kernel's cached
  code signature, and every later exec of `pam` and `PAM.app` is killed until
  reinstalled, so `exe.write` and `bundle.write` ask `access(2)` through
  `/bin/test -w` and open nothing (a regression test pins it). No probe writes,
  creates, truncates, unlinks, renames, sends a frame or reads a private byte,
  and `pam doctor` starts no daemon.
- The admin-endpoint probe connects and sends nothing: it holds the socket for
  150 ms so the daemon can read the peer's pid, then drops it; the daemon counts
  the connection as an admin contact and attributes it to the report from the
  same pid. The Windows probe opens `control.json` for read and closes it
  without reading a byte, and never dials the admin port; the keychain probe
  searches for an account that does not exist.
- The engine's private socket and transient API key no longer live inside the
  run directory that a sandboxed agent must traverse to reach `pam.sock`
  (ptrack issue 44): the engine runtime moved to `<base>/engine/run` (`0700`,
  inside the `engine` tree every profile denies), `run/` holds the public plane
  only, and a daemon removes an older daemon's leftovers inside `run` at
  start. The reference profiles name no engine path under `run` any more, and
  `pam doctor` probes the runtime where it is.
- `pam doctor` reads no byte from under the base. The daemon's pid, which the
  `daemon.signal` and `daemon.process_query` probes need, comes from the hello
  acknowledgement (`hello_ack` now carries `pid`) instead of the lock file, so
  the probe is judged through the session relay too: a run through
  `pam listen` under a profile that allows nothing under the base is
  `established`. `harness_agrees` in the `doctor.report` reply is three-valued:
  `false` only when both the daemon's resolution and the client's own chain are
  known and differ; `null` (undetermined) when either is unknown, as under a
  profile that denies `/bin/ps`.
- A corrupt, oversized or untrusted policy file never loosens security: it is
  never read for its content, the last good copy stays in force, and with no
  copy the authority keys are frozen (writes to them are refused
  `policy_frozen`, except a stricter profile and revoking a grant). A trusted file that loosens (for example a
  locked `relaxed` profile) is honoured only because it passed the same check.
  The public `status` and agent refusals say that a policy exists and that a
  capability is not available, never which rule refused it.
- Control requests (`status`, `query`, `cancel`, `doctor.report`) stay
  available under any never-grant rule, so a policy such as `never: ["*"]`
  cannot take down the control plane; every work and admin capability can be
  denied.
- A policy that pins a CA bundle on Windows has that leaf rejected
  (`network_ca_unsupported_on_windows`) and has no effect: install the CA in
  the Windows certificate store through MDM. A bundle file would replace the
  store's trust and break public hosts, so the network stays on store trust
  and `pam policy check --platform windows` reports the leaf.
- On Windows the daemon refuses to start when `<base>\run` is a symlink or
  junction, as it already did for `<base>\admin`. The run directory takes its
  ACL by inheritance from the base, so a link would let it come from elsewhere.

### Removed

- The Turso engine and its vendored sources (`vendor/turso_core`,
  `vendor/aegis`, and their patches); no `vendor/` directory remains.
- ZeroMQ: the `zeromq` dependency, its vendored patch and its separate gate
  step are gone, and nothing on either plane speaks ZMTP.
- `events.sock`, the event broadcast socket, and the second socket
  `pam listen` bound for it. A stale one in the run directory or in a session
  directory is removed at the next start.
- The AWS CLI adapter, which was always refused, is removed. A flow that still
  names `connector: aws` fails validation as a removed connector; a stored `aws`
  connector row is ignored, and a keychain item left behind for it is harmless.
- Linux support: the AppImage and `.deb` packages, the systemd user login unit
  (`pam service install` on Linux), the Secret Service credential backend and
  the Linux llama.cpp engine builds (`ubuntu-x64`, `ubuntu-arm64`).
- Intel Mac support: the `macos-x64` engine build. Apple Silicon Macs are
  unaffected.

### Fixed

- Evidence pages are served from the 64 KiB chunks they cover instead of
  the whole stored view, and every byte served is checked against its
  chunk's recorded SHA-256 first: a page of a 32 MiB view went from 3.8 ms
  to 0.17 ms (release build), and bytes changed on disk are refused as
  `evidence_corrupt` rather than returned under the view's digest. A view
  now references its evidence row, so it cannot point at evidence that is
  missing; at most one terminal audit row per request is enforced by the
  schema; and a flow's protected checkpoint is written in one transaction
  with the journal row that names it, so a crash can no longer leave a
  journal without its checkpoint or a checkpoint without its journal. Boot
  recovery closes checkpoints an older daemon left without a journal, with a
  `flow.checkpoint_orphaned` audit row each (schemas 19 and 20).
- The client detects its own identity (process ancestry, working directory) once
  per process instead of on every request, so the GUI's status polls stop
  re-walking the process tree.
- The client's `kill` was already the absolute `/bin/kill`; the test helper that
  stops a daemon now uses it too.
- On Windows a daemon started lazily by a command no longer inherits that
  command's output pipe, so a program capturing `pam`'s output (an agent
  harness) gets its answer instead of waiting until the daemon exits. The
  daemon is started through the system PowerShell's `Start-Process`, loaded
  from its module under `System32` by path, so the start takes the same
  fraction of a second however many PowerShell modules the machine has; where
  policy blocks PowerShell the command says so, quotes PowerShell's reason and
  names `pam service install`, which runs the daemon at login without a lazy
  start. A `pam.exe` that still carries a browser's downloaded-file mark is
  not started in the background by Windows; the error names the mark and how
  to remove it.
- On Windows a crashed daemon's stale control file is refused in 0.3 s instead
  of being mistaken for a busy daemon.
- `pam listen` no longer panics at startup (it did in 0.4.0 to 0.4.3).

- The daemon no longer stops answering `status` and `cancel` when something
  behind it is slow: handlers have a hard deadline, `status` is a snapshot
  read and cancel has reserved capacity. The GUI's status polls no longer feed
  back into themselves, event refreshes are throttled and polling backs off
  while the daemon is busy or down.
- Requests whose final state could not be written are retried and then closed
  instead of staying "running" and filling the admission limit, and a failed
  write is never answered as success.
- A duplicate request attached to one that was refused is released at once
  instead of waiting for its own deadline.
- A store call cancelled inside a transaction no longer wedges the database;
  the abandoned transaction is rolled back before the next call.
- Grant changes, approvals and their audit rows are written in one
  transaction.
- A finished request can no longer be moved back to an in-flight state.
- Revoking a capability no longer makes unrelated older tickets' evidence
  unreadable.
- Noisy failing logs keep their evidence views; a ticket no longer turns
  `unavailable` because a provenance map was too detailed.
- Reading at the end of an evidence view returns an empty page marked `eof`
  instead of an error.
- Activity shows refused `admin.*` attempts even with probes hidden.
- The admin channel and `pam listen` survive transient accept errors on every
  platform; the relay caps concurrent connections at 64. A full admin listener
  answers `connection_capacity_exhausted` instead of dropping the connection.
- A killed flow step (timeout, cancel, output limit) takes its whole process
  group with it.
- Cancelling, or restarting the daemon, while a step waits for approval no
  longer reports `flow_effect_uncertain`.
- `guarded-land`: a new ticket finishes a landing whose pull request an
  earlier ticket already merged, and `sync` refuses `.git` directories swapped
  for symlinks.
- Compact flow results keep failed and blocked steps when they must drop
  observations.
- A lost `pam flow run` reply prints the request id and the `pam wait`
  recovery, also with `--json`.
- Lazy start waits for a booting daemon instead of racing it, and the version
  handshake waits for the replacement daemon before its single retry.
- The model engine's death is noticed and the next request reloads it, a
  leftover engine of a killed daemon is stopped, a stranger on the engine's
  loopback port is refused, and only a successful generation counts as use.
- The structured diagnosis dispatches an operation by its full target, and an
  authority tag counts only for a substantive quote.
- An unanswered keychain prompt no longer stalls every connector: reads give up
  after 20 seconds.
- `pam listen` starts. In 0.4.0 to 0.4.3 the installed binary panicked at
  startup ("Cannot start a runtime from within a runtime") before it bound
  anything, so the relay had only ever run inside tests. It now runs on the
  command's own runtime, and a test starts the compiled binary.

### Compatibility

- Schemas 19 and 20 flag each request's terminal audit row and move every
  evidence view into chunks. The upgrade checks each view against its
  digest as it moves it: a view whose evidence row is missing becomes a
  retention tombstone and one whose bytes do not match is kept but refuses
  reads as `evidence_corrupt`; each is reported in an `evidence.view_orphaned`
  or `evidence.view_corrupt` audit row on its request. The upgrade copies the
  database first, as every migration does.
- Schema 17 adds the grant binding columns and `request.flow_id`. Flow step
  grants made before the upgrade are unbound legacy grants: they keep
  authorizing, and the first run that uses one binds it to the step as it runs
  then, in that run's repository, with a `grant_bound` audit row, so upgrading
  never stops a working flow and the binding applies from that first use. A
  `flow.run` ticket admitted before the upgrade names no flow and is still ended
  by a step revocation of any flow.

- The first start after upgrading copies the state database, its write-ahead
  log and its `-shm` file (those that exist) into
  `<base>/backup/state-<UTC time>-pre-sqlite/` before anything is written,
  checks the database in full once, and only then migrates it. The copy takes
  as much disk as the database, holds audit data (mode `0600` inside the
  base) and is never deleted by PAM. On a large database this start is slower
  by the copy and the check.
- If that copy cannot be written, or the check fails, the daemon refuses to
  start, leaves every database file untouched and says what to do: free the
  space or fix the `backup` directory's permissions; for a damaged database,
  run the release that wrote it against the copy, salvage with
  `sqlite3 <copy> .recover`, or move the state file and its `-wal` and `-shm`
  out of the base to start empty. There is no override. A restart loop gets
  the same refusal and makes no second copy.
- Later schema migrations copy the database first as well, into
  `backup/state-<UTC time>-pre-v<N>/`. The newest three of those copies are
  kept.
- There is no downgrade. Opening a database stamps it schema version 14 and
  marks it as PAM's; an older binary refuses it (see the next entry). To go
  back, stop the daemon, copy the files of the `pre-sqlite` backup over
  `state.sqlite3` and its `-wal`, and start the old release; what was written
  since the upgrade is lost.
- A power cut or an operating-system crash can lose the last committed
  transactions, never the database's consistency: a request acknowledged in
  that moment is back in its earlier state and boot recovery closes it. A
  full flush to the drive on every commit measured about 5 ms against 0.2 ms
  on macOS and is left off; checkpoints are fully synced there. A daemon that
  crashes or is killed loses nothing.
- A clean stop leaves `state.sqlite3` as a complete copy of the database: the
  write-ahead log is folded into it, so copying that one file is a full
  backup. A daemon that was killed leaves a `-wal` beside it, replayed at the
  next start; until then the main file alone is an older database.
- A state file that is missing or empty while its `-wal` has content is
  refused instead of being restarted empty. An empty state file with no log
  is refused too in a base PAM has used before (a `backup` directory, a log,
  the daemon's lock, flows or model records): restore the newest backup, or
  move the empty file aside to start fresh.

- `pam service status --json` no longer reports `"platform": "linux"`; on a
  platform with no login-start integration it reports the `unsupported` state
  with its reason.
- Schema version 12 adds indexes for Activity and retention and makes audit
  rows append-only and evidence views immutable. Version 13 adds the origin
  columns to request rows. Version 14 changes no table: it is the mark that
  the database has been opened by the SQLite engine. A store upgraded by this
  version is refused by older binaries: a 0.4.3 daemon started on it exits `1`
  with "database schema version 14 is newer than this binary supports (max
  11)", so there is no way back to an older daemon on the same base, and a
  login unit that still pins an old binary cannot start it.
- Upgrading from 0.4.x or 0.3.0 with a daemon still running: the old daemon
  speaks the previous protocol on the same socket, and a new client recognises
  it by its greeting. The first `pam` command run outside a sandbox, the GUI,
  or `pam listen` stops it the way `pam daemon stop` does and starts the new
  one. It prints nothing while it does, and it takes as long as the old
  daemon's drain: at once when that daemon is idle, up to ten seconds while
  it has work in flight. Work that finishes inside the drain keeps its result,
  readable through the new daemon; work still running after ten seconds is
  cancelled by the old daemon and reads as `failed` / `cancelled`. An old
  `pam wait` on such a ticket exits `3` with `daemon_shutting_down`.
- A first command that may not signal the old daemon (under an agent sandbox,
  or through `PAM_SOCKET_DIR`) exits `1` with the instruction to run
  `pam daemon stop` and then `pam status` outside the sandbox. Both are
  needed: a client that may not signal usually may not start a daemon either,
  so after the stop alone its retry fails ("did not become ready", or a
  transport failure through a relay). `pam status` alone, run outside the
  sandbox with the new binary, does both. On Windows the old daemon is not
  stopped automatically; the message names its process to end.
- An old `pam` binary cannot talk to the new daemon: it exits `1` with
  `cannot connect to ipc://<base>/run/pam.sock: Failed Greeting exchange`, and
  the daemon logs the stale client with its pid (at most once a minute, with a
  count of what it suppressed) without answering. With no daemon running, the
  old binary tries to start its own daemon, which the upgraded store refuses,
  and reports that the daemon did not become ready. A GUI left open across the
  upgrade is refused `client_outdated` and must be quit and reopened.
- Sandbox profiles need only `<base>/run/pam.sock` (or `<dir>/pam.sock` for a
  session relay). A rule that still allows `events.sock` is harmless and can
  be dropped.

## [0.4.3] - 2026-10-01

### Fixed

- Show the sidebar logo in installed builds. The release content security
  policy blocked it because the build embedded it as an inline `data:` image;
  it now ships as its own file.
- Let Home use the full window width. Wide windows place Ask Pam and its
  answers beside the task starters instead of keeping a narrow 960px column.

## [0.4.2] - 2026-09-18

### Fixed

- Make the original sidebar logo visible, with the version beneath it.
- Keep Activity lanes wide enough for request labels and timestamps, wrapping
  smaller groups instead of squeezing their contents.
- Use consistent button cursors and prevent hover effects on disabled actions.
- Keep model action menus outside scrolling containers, with keyboard navigation
  and reliable focus restoration.
- Disable accidental selection of interface labels while keeping inputs, logs,
  results and diagnostic text selectable.
- Keep Save and Discard changes visible above the flow editor. Saving updates
  custom flows; discarding restores the saved draft without writing it. Save uses
  the editor's latest validated draft, even while parent state is catching up.

### Changed

- Consolidate form controls and action menus into shared typed widgets.
- Remove manual log-compression controls and implementation-focused UI copy;
  compression remains part of the internal model pipeline.

## [0.4.1] - 2026-09-17

### Fixed

- Keep the desktop panel anchored while scrolling, with content scrolling
  inside its own pane. Remove entrance transforms that could leave content
  blank in the macOS webview after navigation.
- Keep the flow canvas, inspector and actions reachable in short windows,
  with a compact header and expandable flow descriptions.

### Changed

- Search the flow library by name, identifier or description without losing
  unsaved edits. Keyboard navigation stays usable while filtering.
- Show readable canvas action labels and the original PAM logo with the
  application version in both expanded and compact sidebars.

## [0.4.0] - 2026-09-17

### Changed

- A tier default now needs more than a verified digest: the model's exact
  SHA-256 must match a compiled-in qualification record for this engine build
  and platform (`pam_model::qualification`; today only gpt-oss-20b-MXFP4 on
  llama.cpp b10938, macOS arm64, under answer contract v2). `admin.models.
  defaults.set` refuses anything else with cause `unverified` or
  `unqualified`, and a default seeded past the admin op is refused at resolve
  time with the same cause, so a job never runs on unmeasured weights. Try
  still works on any installed model. The Models screen badges
  qualified / engine / test only with the reason, and the tier selects
  disable what cannot serve.
- `pam flow run` no longer accepts inputs the flow does not declare: an
  undeclared name refuses as `input_unknown` (the same cause `pam flow
  inspect` already reported), and an `inputs` value that is not a string or
  number refuses as `input_invalid`, both before a ticket exists. A typo
  against an input with a default used to run silently on that default, and
  the public projection does not echo inputs, so the run never showed which
  values it had used. The flow CLI contract records the two causes.
- The `after-merge-checks`, `pr-readiness` and `dependency-audit` recipes
  now say in their descriptions that their network-dependent steps (`git
  fetch`, the cargo-audit advisory database) fail under command containment
  instead of implying the remote refresh succeeds.

### Added

- `pam playbook`: the agent guide ships inside the binary. It prints the
  discover/run/read loop (`pam status` → `pam flow list` → `pam flow inspect`
  → `pam flow run --no-wait` → `pam wait` → `pam flow result` → `pam evidence
  read`), how to read refusals and exit codes, the sandbox-relay case
  (`PAM_SOCKET_DIR`, never started from inside the sandbox), and a drop-in
  snippet for a project's AGENTS.md — so an agent that only has the binary
  can still learn how to drive pam. `pam --help` and the `pam status` summary
  point at it, and it needs no daemon.
- `pam listen <dir>` (unix): a session socket relay for agents whose
  sandbox blocks the daemon's unix socket. It binds `pam.sock` and
  `events.sock` inside a directory the sandbox permits (created `0700`)
  and forwards bytes to the daemon's runtime sockets, so every client
  subcommand — `pam wait` and `pam subscribe` included — works through a
  path the sandbox already allows. Point sandboxed clients at it with
  `PAM_SOCKET_DIR=<dir>`: while set, the client dials the relay's sockets
  and never lazily spawns a daemon, so a dead relay is a clean error
  naming `pam listen` instead of a surprising spawn. The relay is a dumb
  byte pipe — admission, scope and budgets stay in the daemon — and it
  refuses to take over a directory where another relay already answers.
  Boundaries and placement trade-offs in `docs/session-socket-relay.md`.
- `pam subscribe` takes `--json` like `pam wait`, and with it a refused or
  timed-out follow is a `kind: refusal` object on stdout (the ticket as
  `id`, cause `follow_timeout` for an observation timeout) instead of a
  prose line on stderr; exit codes are unchanged. The README now carries a
  table of every subcommand and its exit codes.
- Windows builds can be administered: the GUI's private administration
  channel now exists on Windows as loopback TCP behind an owner-only nonce.
  The daemon writes the port and a fresh nonce to `<base>\admin\control.json`
  in the owner's private base, proves it holds the nonce before reading a
  byte, and admits only a client that presents it. Every `admin.*`
  operation the macOS and Linux GUI has works on Windows the same way;
  the threat model is unchanged and documented in `docs/admin-boundary.md`.
- `admin.models.status` reports one readiness record per tier: the first
  rung of configured → installed → verified → qualified → engine → ready
  that fails, the cause a job would be refused with, a recovery line, the
  qualification record, and whether the weights are in memory right now.
  The Models runtime tab opens with that verdict and one repair button per
  blocked tier; Settings → Models prints it under each tier; Home and the
  log-compression form say before submission why no model will answer.
- `docs/model-qualification-decisions.md`: the standing record of which
  artifacts qualified, which were screened and rejected, what was not
  measured, and the compression decision.
- A model summary now names its author: `pam flow result` observations
  that came from the heavy model carry `model` with the registry id and the
  qualification record that admitted it, the summary evidence identity
  carries the same block, and the log-compression report's `model` names
  the record. Identity only, never figures.
- `pam flow inspect` says before a run whether a summarize step will get
  its summary: the `model` block names the steps that ask the model, the
  heavy tier's stage, and the blocker with cause and recovery when the
  summary will be skipped. `pam status --json` carries the per-tier stage
  and cause under `model.readiness`.
- A straight answer to "can PAM reach the keychain?", in three places:
  `pam status` prints a `keyring:` line with the recovery sentence when it
  is blocked, Settings → Connectors carries a banner with a Re-check
  button, and Home flags a blocked keychain in the workspace overview. New
  admin op `admin.connectors.keyring { fresh? }`, and the daemon's `status`
  capability publishes a read-only `keyring` block. Reachability only — no
  capability can read a credential, and the probe reads an account nothing
  ever writes.
- Partial downloads can be thrown away from the Models screen: a preset
  card that has bytes on disk offers Resume and Start over, says how much
  is already here, and confirms before discarding. New admin op
  `admin.models.download.discard`, and `admin.models.catalog` now reports
  `partial_bytes` per preset — a part file is a dotfile a registry scan
  cannot see, so a resumable transfer no longer depends on a job row that
  may have aged out. This is also the way out of a checkpoint conflict,
  which previously needed a manual `rm`.

### Fixed

- `pam flow inspect` now reports each connector step's credential status
  under `auth_probe` instead of `credential`. The response redactor masks
  every value whose JSON key looks credential-shaped, so the honest
  `unknown_not_probed` sentinel never reached agents — they saw
  `[REDACTED]` and could not tell an unconfigured connector from a masked
  field. The field is a status, not a secret: credentials stay in the OS
  keychain and are set only from the GUI. Validation also refuses a flow
  input no step, environment value or correlation declaration reads, and an
  input name starting with `-` (unusable as a `key=value` CLI argument),
  both at `inputs.<name>` so a recipe fails before it is saved.
- Two Windows-only test flakes on loaded runners are hardened rather than
  retried: the curl mutation test's stand-in server now reports an early
  hang-up through the client assertion instead of panicking, with a 15 s
  curl deadline, and the lease-reaping test gives submission 4 s before
  its lease. Two Windows-only `unused_mut` warnings in the daemon are gone.
- `pam wait` no longer ends with "no readable result" while a flow is still
  running. A running request writes each evidence row a moment before its
  view, and a follower's `query` landing in that window was refused as if
  the ticket were not the caller's; the daemon now tells an unpublished
  view (pending, for a request that is not terminal) from a view published
  under another repository (never readable), and keeps the strict answer for
  finished requests.
- A download refused at the checkpoint check (foreign part file, wrong
  digest) now unlocks its transfer lock explicitly instead of merely
  closing the handle, so a curl process another task forked in that
  window can no longer hold the inherited lock past the next start. The
  same explicit release covers discarding a partial download.
- The store rolls back a transaction whose `COMMIT` fails instead of
  leaving it open on the shared connection, and refuses a terminal state
  handed to the non-terminal state update in release builds too, not only
  under `debug_assert`. An evidence range starting at the view's end is
  refused as invalid rather than charged against the read allowance.
- The client's readiness wait for a freshly spawned daemon no longer sleeps
  on a runtime worker; the GUI's event subscriber no longer creates or
  chmods the daemon's runtime directory; the daemon-log tail reads the last
  mebibyte of the file instead of the whole file; a systemd unit with a
  `PAM_BASE_DIR` override quotes and escapes the path; and `pam service
  status` on Windows reads the scheduled task's status column instead of
  reporting every registered task as loaded.

- Daemon review fixes: a cancel during a landing check, pack fetch or
  push now ends the run `cancelled` instead of blocked with a timeout or an
  internal error; a rejected `git push` whose remote ref did not move is a
  typed `landing_push_rejected` refusal, not an uncertain effect; sealed
  landing checktrees are removed when their ticket terminates; a flow
  checkpoint row is no longer orphaned by a journal conflict; the model
  runtime's busy flag clears when a generation future is dropped; an
  engine install cancelled by the admin deadline stops its transfer; the
  Windows admin channel admits a peer before it takes a served slot; a lease
  whose stored arguments cannot be parsed fails instead of running with
  empty arguments; a caller-supplied vendor is one plain path segment and
  the destination must stay inside the models directory; keyring errors log
  their kind only; credential patches carry a zeroing secret and print
  redacted; a diagnostic on a model the engine does not hold is refused
  rather than loading it; the status snapshot no longer touches the file
  system on the runtime thread.
- Model tooling: the download curl is the operating system's own, runs with
  `-q`, restricts protocols to https and http, and always passes the URL
  after `--`; a resume sends `If-Range` with the saved ETag so an origin
  change restarts the transfer; a completed download never overwrites a
  file that appeared meanwhile; a verification sidecar whose size or
  mtime no longer matches the weights counts as absent; the GGUF reader
  accepts every ggml type llama.cpp writes (MXFP4, the IQ and TQ families,
  integer and F64 tensors) and no longer preallocates a header-declared
  string length; the engine's API key comes from a process-seeded CSPRNG on
  every platform and the health check confirms the server's model path
  before a load is accepted; the curated catalog carries the qualified
  gpt-oss-20b preset; a flow that names the `aws` connector fails
  validation with a named blocker until containment lands.
- GUI: a running flow can be cancelled; the expanded request row shows its
  audit trail; approving with a note keeps the note; a run that finishes
  before the event stream attaches no longer sticks on queued; renaming an
  input onto an existing key is refused; the daemon card shows the real base
  directory and restart asks for confirmation; the beacon reports
  connecting and needs two missed polls before offline; independent steps
  lay out in declaration order; the installed-models table folds its
  actions into a menu and fits 1100x700; every chip, checkbox and radio has
  at least a 24 px hit area; the palette returns focus to its opener; the
  flow library is a keyboard listbox; faint ink, strong lines and a real
  amber warning pair are tokens that meet WCAG contrast in all four
  palettes; copy uses one phrase for a request awaiting review and one
  casing for labels.

- Review remainder: a rejected push keeps its `landing_push_rejected`
  cause when the run resumes; the Activity tide shows `admin.log.compress`
  rows under `hide_probes`; `admin.approvals.pending` entries carry `args`,
  `repository` and `effect`, so the Approvals card shows what will run and
  where without a second query; the engine manifest is read off the runtime
  thread; repository authorisation in flow, recovery, result and landing
  paths runs on the blocking lane; a startup sweep removes landing
  workspaces whose ticket died with the daemon. The GUI speaks in a system
  voice, Home is full-bleed like every other screen, Activity lanes size by
  row share, the built-in watch flows are named "Watch GitHub run", "Watch
  Jenkins build" and "Watch Sonar analysis", and the fake llama server can
  serve a loopback port for the Windows engine path.

## [0.3.1] - 2026-09-09

### Fixed

- Model downloads no longer hang on a dead connection: curl now carries a
  connect deadline and a minimum sustained rate, so a stalled transfer fails
  with a cause instead of a progress bar that never moves. The partial file
  is kept, so the next attempt resumes.
- Download failures say what actually broke. curl's exit code becomes a named
  cause — `dns_failed`, `connect_failed`, `network_timeout`, `http_error`,
  `tls_error`, `transfer_interrupted`, `resume_unsupported`, `disk_error` —
  each with its own recovery sentence, written to the job row and logged at
  WARN with curl's own complaint.
- The Models screen shows failed and cancelled downloads instead of silently
  dropping them, with cause, detail and recovery, and a Resume button when a
  partial file is waiting.

## [0.3.0] - 2026-09-04

### Added

- Discoverable New, Duplicate, Rename and Delete actions in the flow library,
  blank and template creation, unsaved-change guards, and session undo for
  deletion. Built-in flows remain recoverable after custom overrides.
- A PAM-specific PR readiness flow that runs the complete local quality gate.

### Fixed

- Quantized Qwen3 MoE generation on CPU and Metal, with cancellation and
  error recovery. Known unsupported tensor/backend combinations are refused
  before weight mapping with actionable errors.
- Clean-tree checks now fail on dirty tracked, untracked and submodule state.
- Connector verification now checks explicit passing statuses instead of
  treating successful retrieval as a passing check.
- Unread event subscribers no longer block daemon request replies or shutdown.
- Settings reject invalid input and protect against concurrent save races.
  Connector tests use the current saved configuration and retire stale readiness.
- Flow canvas connections have clearer contrast and zoom-independent targets.
  The canvas fits the available space, refits after resizing, and keeps the
  inspector independently scrollable.

### Compatibility

- Custom connector steps using `role: verify` must declare `expect_status`;
  otherwise execution refuses verification. Use `role: observe` when the step
  only retrieves data. Built-in verification flows include explicit predicates.
- Flow saves now reject duplicate display names, including names reserved by
  built-in flows. Existing flow IDs remain stable when renamed.
- Real dense and MoE Q8_0 generation and recovery were verified on CPU and
  Metal on a 64 GB host. This is compatibility evidence, not qualification of
  approximately 16 GB models on the 32 GB hardware baseline; that evaluation
  remains outstanding.

## [0.2.1] - 2026-09-04

### Changed

- Standardized Home, Flows, Activity, Approvals and Models on the Settings
  page structure, with fixed page headers and one bounded scroll region per
  active pane.
- Split dense tasks into keyboard-accessible tabs: flow canvas, YAML,
  execution and history; activity requests and compression; and model
  runtime, installation, downloads and testing.
- Kept Home answers beside the composer and preserved compression and flow-run
  results when filters or task views change.

### Compatibility

- No CLI, protocol or stored-data changes.

## [0.2.0] - 2026-09-04

### Added

- Navigation command palette with Cmd/Ctrl+K for pages, Settings categories,
  models and flows. Selecting a flow opens it without executing it.
- Monitor, Build and Focus workspace presets, compact navigation, and up to
  eight saved workspace layouts with their current route.
- Adjustable glass opacity and ambient background motion, with continuous
  speed and movement-intensity controls. Reduced-motion, reduced-transparency
  and forced-color preferences take priority.
- Expanded flow-canvas mode with toolbar and Escape restoration, preserving
  viewport, selected steps and unsaved edits.

### Changed

- Applied the Costa design across the desktop app: four appearance palettes,
  native typography, clearer controls and a soft, theme-tinted wave backdrop.
- Organized Settings into eight keyboard-accessible tabs with retained drafts,
  tab transitions and denser layouts that use wide desktop windows.
- Added translucent Appearance cards and removed opaque page-title strips
  from Models, Activity, Approvals and Flows.
- Improved Home hierarchy and kept workspace scrolling stable when navigating
  or expanding the flow canvas.

### Compatibility

- No CLI or protocol changes. Flows remain executable actions available from
  the CLI; appearance and workspace preferences are local to the desktop app.

## [0.1.0] - 2026-09-03

First packaged release of pam v2: the spine (daemon, CLI, GUI shell), the
model layer, log compression, flows and connectors, the flow designer,
retention, packaging, and Ask Pam.

### Added

- Packages on every first-class target: a signed, notarized macOS dmg
  (arm64), Linux AppImage and deb (amd64, arm64), and a per-user Windows
  NSIS installer (amd64, arm64), built by CI and published by the release
  workflow on `v*` tags.
- `pam service install | uninstall | status`: start the daemon at login
  through a macOS LaunchAgent, a systemd user unit, or a per-user Windows
  scheduled task. Settings › Daemon shows the same state with Install and
  Remove.
- Double-clicking `pam.app` opens the control center; the Linux desktop
  entry and the Windows shortcuts run `pam gui`.
- Home screen at `/` with Ask Pam: questions about pam itself answered
  from live daemon state with deep links (approvals, refusals, today's
  activity, the model, settings, the daemon, login, flows, tokens saved);
  the light model may rephrase answers behind an off-by-default switch.
- `admin.audit.request` returns one request's audit trail so refusals can
  be quoted.
- Activity reads as swimlanes per agent with agent and repo chips and live
  settle; the GUI's own polling stays out of the tide.

### Changed

- `crates/pam` owns the Tauri app configuration; `pam_gui` is a plain
  library behind it.
- The shell lays out like P-TRACK: a full-height sidebar with the brand
  under the traffic lights and the work panel from the top edge with its
  own toolbar row; the window-wide top strip is gone.
