# Administration boundary

PAM separates ordinary agent requests from administration. The public endpoint
rejects every `admin.*` operation before any row is written, including
envelopes claiming `caller.agent = "pam-gui"`. Caller labels, repository names,
and caller-supplied PIDs do not authorize administration.

The GUI cancels a ticket through `admin.requests.cancel` on the private
channel, which the audit records as the human's act. The bridge has no
`request_capability` command and so no public request at all. A public `cancel`
is recorded as `system` whatever `caller.agent` says, and it acts only on a
ticket admitted under the caller's own canonical repository; a foreign ticket
answers `not_found`, like a missing one.

## The two endpoints

Both planes speak one protocol: length-prefixed JSON frames, a `hello` first,
then exactly one request per connection (wire protocol 2; see the
[transport specification](specs/2026-10-02-framed-public-transport.md)).

The **public endpoint** is what agents reach. On macOS it is one stream socket,
`<base>/run/pam.sock`, mode `0600` in the `0700` run directory; who may connect
is decided by those filesystem modes and by the agent's sandbox, not by the
daemon. On Windows the daemon listens on an ephemeral `127.0.0.1` port and
writes `<base>\run\public.json` (the port and a fresh 32-byte nonce); the
handshake is the administration one described below with its own label
(`pam-public-server`) and its own nonce, which confers nothing on the
administration plane. A sandboxed Windows client needs read access to
`<base>\run` and an outbound loopback connection, and must not be given
`<base>\admin` or the state database.

The daemon **records** the kernel's view of every public connection and never
authorizes by it: each request row carries the plane it arrived on (`ingress`:
`public` or `admin`), the peer's uid and pid as the kernel reports them
(`peer_uid`, `peer_pid`), and whether the client said it came through a session
relay (`relayed`). `admin.activity.list` returns them. On macOS the daemon also
resolves, at receipt, the executable of that pid and the harness it can find in
the pid's ancestry (`peer_exe`, `peer_harness`; `relay` when the peer is `pam
listen`), and keeps both on the row. On Windows there is no kernel peer identity
on a loopback connection, so all of these are empty there: the recorded standing
is "could read the owner's control file". A peer whose uid is not the daemon's
is served and logged. The pid names a short-lived `pam` process and can be
reused; the executable path and the ancestry are what a copied binary or a
renamed parent defeats. All of it is attribution, like `caller.agent`, and the
audit actor is decided by the plane alone.

There is no event broadcast and no second public socket. A public client
receives events only as the follow of one ticket (see
[Global target authority](#global-target-authority)).

## The private endpoint

On macOS, the native GUI client uses a separate Unix socket at
`<base>/admin/control.sock`. The transport obtains the connected peer's UID and
PID from the kernel rather than trusting the request envelope. These credentials
authenticate the peer's operating-system owner and process identity; they do
**not** prove that the process is in GUI mode or that a human requested the
operation. Executable-path checks, where applied, likewise do not prove code
integrity or GUI mode.

On Windows (2026-09-15), safe Rust gets no kernel peer credentials on a named pipe
and the workspace forbids the raw FFI that would, so the adapter proves ownership
by possession instead: the daemon listens on an ephemeral `127.0.0.1` port and
writes `<base>\admin\control.json` — the port and a fresh 32-byte nonce — into
the owner's private base, whose NTFS ACL is inherited from the profile directory
(owner, SYSTEM, Administrators). The handshake is server-first: the daemon sends
`sha256("pam-admin-server" ‖ nonce)` before reading a byte, so a client never
hands the nonce to a process that merely reused the port after a stale control
file; the client then presents the raw nonce, compared in constant time, and only
then is the hello read. Reading that file is the same standing a Unix peer
proves through its uid: another local user cannot; an administrator or an
unrestricted same-user process can, exactly as root or a same-uid process can on
Unix. The connection is loopback-only and the same frame budgets, header timeout
and connection cap apply. This proves no more than the Unix path does: not GUI
mode, not code integrity, not that a human asked.

The GUI also receives every lifecycle event over this endpoint: an admitted
connection that sends `events` becomes a stream of each published event with
its ticket, capability, repository, agent label, plane and the real progress
note. At most four such subscribers are attached at once, each holding one of
the 32 connections; a subscriber that falls more than 1,024 events behind is
closed with `subscriber_lagged` and reconnects. Requests the daemon publishes
nothing for (`status`, `query`, `cancel`, `doctor.report`) never appear on it. This richer view
is acceptable here because the peer has already proved it is the daemon's
owner; it is the reason the stream is not offered on the public endpoint.

## Deployment assumption

The security boundary depends on the agent's OS sandbox excluding:

- The private administration endpoint and its parent directory.
- PAM's private state, including its authorization data and credential access.
- Modification of the trusted PAM executable and frontend assets.
- Access to or control of trusted PAM process memory and execution.

Granting access to the public socket must not also grant access to these
resources. A private pathname or owner-only filesystem permissions alone cannot
exclude an unrestricted process running as the same user. Unrestricted same-user
code execution, debugger/process injection access, and replacement of trusted
program files are outside this boundary's protection.

The exclusions must also cover indirect control: launching the trusted GUI through
LaunchServices or other process brokers, AppleEvents/UI automation, task ports,
debugging, inherited private descriptors and replacement of trusted frontend
assets. A writable development server serving the GUI is part of the trusted
execution surface. Production verification must use the embedded frontend or
separately protect that server. A plain build of `pam gui` (without the
`gui-embed` feature) would load the Vite development URL,
`http://127.0.0.1:1420`, with the full admin bridge, so such a build refuses to
start unless `PAM_GUI_DEV=1` is set; with it, that is a development
configuration only, and the caveat stands. Blocking a direct child process is not proof that
a system broker cannot launch an unsandboxed process on its behalf.

OS keychain isolation requires restricting the credential service as well as
keychain files. A fake credential backend verifies PAM behavior, not OS credential
isolation. Negative deployment tests must establish absence of privileged effects,
not merely a nonzero client exit code.

PAM does not install, edit or lock the agent's sandbox policy: the harness
enforces it, and the [reference profiles](sandbox/README.md) are text you put in
the harness's own configuration. PAM does check it, from the agent's position,
with `pam doctor` (see [Verifying the boundary](#verifying-the-boundary)). The
deployment must establish and maintain these exclusions. An executable name,
argv value, or self-reported PID is not a substitute for that isolation.

**The engine's runtime files live under the engine directory.** The model
engine's private socket, `<base>/engine/run/engine.sock`, and its transient API
key and pid file beside it, sit inside `<base>/engine`, a directory the agent is
never granted; `<base>/run` holds `pam.sock`, `daemon.lock` and (Windows)
`public.json` only. They used to live inside `run`, the directory the agent must
traverse to reach `pam.sock`, where a rule allowing `<base>/run` by subpath
exposed the key for the moments it exists and, as a unix-socket allowance, the
engine's OpenAI-compatible endpoint (found while designing the boundary check,
ptrack issue 44; relocated by plan 53, task T10). Every reference profile allows
the literal `pam.sock` and the read of `daemon.lock` only and denies the rest of
the base, and `pam doctor` probes the engine runtime at its place
(`engine.socket`, `engine.runtime_read`). A daemon that finds an older daemon's
engine runtime inside `run` removes it at start.

A daemon that a client starts lazily is started with an environment allowlist
(home, user, locale, temp directory, absolute `PATH` entries, `PAM_LOG`, an
explicit `PAM_BASE_DIR`), in its own
process group, with `/` as its directory and null standard streams. It does not
inherit the caller's environment, descriptors or process group. Flow steps build
their environment from the daemon's, so they no longer see the first caller's
variables either.

## Verifying the boundary

The deployment assumption above is checkable. `pam doctor` runs from where the
agent runs, probes what that position can reach, and reports to the daemon,
which keeps the report next to what it saw on its own side. The design and its
rationale are in the [boundary self-check spec](specs/2026-10-02-boundary-self-check.md);
this section is what the shipped behavior establishes and what it does not.

A report changes no authority. No gate, grant, approval, scope or profile reads
it; a machine whose verdict is `not_established` is served exactly as before.
The record is a fact for the human and for fleet tooling.

### What `pam doctor` probes

From the caller's position, with the caller's own base (`$PAM_BASE_DIR` or
`~/.pam`) and endpoint (`$PAM_SOCKET_DIR` under the relay). One row per probe,
each with a class: `must_allow` (the agent needs it), `must_deny` (the boundary
requires it denied) or `info` (reported, never judged); each result is
`allowed`, `denied`, `absent` (the path does not exist) or `unknown` (it could
not be classified).

- **The one door, must be allowed.** `public.reach`: the same `hello` the client
  sends, on the public endpoint, then the connection is dropped. It reports the
  daemon's version, protocol, epoch and whether it came `direct` or through the
  relay. `run.lock_probe` (info) is the client's own readiness test: open and
  try a shared lock on `<base>/run/daemon.lock`, never written.
- **Must be denied, by file operation.** Connecting to the private endpoint
  (`admin.endpoint`, and through the `run/../admin` alias); listing `admin/`;
  opening `state.sqlite3`, `-wal` and `-shm` for read and for write; opening
  `daemon.lock` for write; listing `backup/`, `model-trust/`, `engine/`,
  `flows/`, `log/` and `<base>/engine/run`; connecting to
  `<base>/engine/run/engine.sock`. No probe writes, creates, truncates,
  unlinks, renames, sends a frame or reads a private byte. The admin connect
  holds the socket for 150 ms, sending and reading nothing, so the daemon can
  read the peer's pid before it drops, and then drops it. Nothing is read from
  under the base but, on Windows, `public.json`, which the ordinary client
  reads too; the daemon's pid, for the signal probe, comes from the hello
  acknowledgement.
- **Must be denied, by helper.** Each runs by absolute path with a cleared
  environment, no stdin and a five-second bound: a keychain search for the
  `dev.pam.connector` service with an account that does not exist (nothing is
  created, read or prompted for); `kill -0` of the daemon's pid as the hello
  acknowledgement names it, which delivers no signal (and works through the
  relay, where nothing under the base is readable); a read-only LaunchServices query and a property read through the
  AppleEvents broker, which launch and send nothing; and the writability of the
  `pam` executable and of the `.app` bundle's `Info.plist`, asked with
  `/bin/test -w`, which is `access(2)`. **Neither the executable nor anything
  in the bundle is ever opened.** (On macOS, opening a mapped Mach-O for write
  invalidates the kernel's cached code signature, and every later exec of that
  file is killed until it is replaced. A first version of the probe did exactly
  that, and a regression test now pins it.)
- **Not probed.** Unlinking `pam.sock` has no side-effect-free test and is left
  to the [macOS sandbox fixture](macos-sandbox-acceptance.md). Rows that do not
  apply to the platform are `not_applicable`.

The human output lists every row; `--json` prints one document (the
probes, `failed`, `unverified`, `skipped`, the environment facts and whether the
report was recorded) and nothing else.

### What the daemon records

The report goes to the daemon as `doctor.report`, an ordinary public request in
the control class: a request row with the plane, the kernel's peer uid and pid,
`relayed` and the self-reported caller, plus the daemon-resolved `peer_exe` and
`peer_harness`; the pipeline's terminal audit row; and one `doctor.report`
audit row (so two rows per report, both `system`). The document is validated
(size, members, bounds, and that the verdict and the failed list follow from the
probe rows); a forged or malformed one is refused `invalid_args` and nothing is
stored. The daemon keeps the newest 64 reports.

Separately, the daemon records what it saw itself, and the report plays no part
in those rows:

- **Admin contacts.** Every connection the private listener accepts is
  observed. One that sends nothing, or that speaks from an executable other than
  the daemon's own boot image, is an `admin_contact` with the kernel pid and the
  executable. The GUI is the same image and its contacts are counted as expected
  and kept apart so they cannot push an unexplained one out. On Windows the
  adapter records `admin_handshake_failed` for a loopback peer that failed the
  nonce proof (no pid; a doctor run never produces one).
- **Public requests from an unrecognised harness.** A request whose resolved
  harness is neither a known agent, nor `relay`, nor the GUI's own image is
  counted as `public_unknown_harness` with the executable. Nothing is refused.

Observations are bounded (the newest 256 unexpected, 32 expected) and lifetime
counters outlive the rows, so a flood neither grows the store nor erases the
fact that a contact happened. `pam status` serves the result from memory as a
`boundary` block (`last_report`, `reports`, `admin_contacts`,
`public_unknown_harness`, a one-line `summary`); the CLI's `pam status` prints the line,
Settings › Daemon shows the rows with a copyable `pam doctor` command, and Home
shows one line. The beacon does not change colour: liveness and the boundary
are different questions, and a red beacon on an unsandboxed developer machine
would train people to ignore red.

### How the two views combine

The report is the client's claim, stored as such under the kernel's peer facts
the daemon recorded itself. What the daemon vouches for is only what it
observed: that a request with those peer facts arrived, the executable and
ancestry it resolved, the admin contacts it accepted, and whether a contact was
followed by a report from the same kernel pid.

That last match is the daemon joining two things it saw: a `doctor.report` from
a pid within 60 seconds of an unexplained admin contact from that pid sets the
contact's `attributed` to the report's request and removes it from the
unattributed count. The client's document plays no part in it. The reply to the
report also says whether the harness the client claimed (`claimed_harness`)
agrees with the one the daemon resolved (`harness_agrees`: `false` only when
both sides know and differ; `null`, printed `undetermined`, where either does
not — the daemon on Windows or through the relay, the client under a profile
that denies `/bin/ps` and so claims `unknown`).

An admin contact nobody explains stays unattributed and is the headline of the
block. A fabricated `established` beside an unattributed admin contact is
visibly inconsistent, and a fabricated report never changes authority anyway.
Two limits follow, and the docs state them rather than hide them: the field can
only understate the risk (a report is one process at one moment, and a harness
that lets the model retry a blocked command outside its sandbox makes
`established` a statement about one command, not the session), and the daemon's
own observations are the only part it can vouch for.

### The verdict and exit code 6

```
established      public.reach allowed, and every must_deny probe is denied,
                 absent or not probed
not_established  public.reach allowed, and some must_deny probe is allowed
                 or unknown
cannot_probe     public.reach is not allowed, or the base cannot be resolved
```

`unknown` on a must-deny probe fails the verdict: the boundary is claimed only
from evidence. The JSON separates `failed` (allowed where denial was required)
from `unverified` (unknown); `absent`, `not_probed` and rows that do not apply to
the platform are listed under `skipped` with their reason and count neither way.

| Exit | Meaning |
| --- | --- |
| `0` | `established` |
| `6` | `not_established` (new, distinct from `3` refused and `5` blocked: a sandbox finding must not look like a daemon decision) |
| `1` | `cannot_probe`: the daemon is unreachable, a legacy build, or refused the hello; `pam doctor` never starts a daemon |
| `2` | usage |

Failing to deliver the report to the daemon is a line on stderr and leaves the
code alone: the verdict is the client's, the record is best-effort.
`--no-report` skips the record and does not change the code either.

### On an unsandboxed machine

On a developer machine where nothing confines the agent, every must-deny probe
is `allowed` and the verdict is `not_established`. That is correct, and it is
the expected state until a profile is applied; the human output says what it
means: this process can reach PAM's private state, so GUI-only administration is
a convention on this machine, not a boundary. A run outside any sandbox proves
installation and reachability, not the boundary. An MDM script that runs
`pam doctor` unsandboxed will therefore always read `not_established`; the
signal is the run from inside the harness's sandbox. Never list `pam doctor`
among a harness's sandbox exclusions: an excluded run reports the honest
result for the wrong position.

### On Windows

**On Windows no supported configuration establishes the boundary today. `pam
doctor` reports `not_established` and lists every private path as reachable.
GUI-only administration there is a convention enforced by the harness's
permission prompts and by the absence of a hostile same-user process, not by
the OS. The enterprise choices are: a dedicated machine or VM per agent with PAM
inside it; or accept the convention and collect the `doctor` record so the fact
is visible.**

Windows differs in mechanism, not in rule. The probes open `control.json` for
read and close it without reading a byte (the nonce never enters the doctor's
memory and the admin port is never dialled), list the private directories, open
the state files and the running executable for write (a sharing violation counts
as `allowed`: the ACL granted it, only the share mode refused), search the
credential store for an absent account, query the daemon's process (query rights
are attribution, not control) and check that process creation, the broker, is
reachable. Windows has no kernel peer identity on the public plane, so the
daemon's `peer_*` columns, `harness_agrees` and `public_unknown_harness` are
empty there, and the `boundary` block's `peer_identity` says `none`. A
differently-identified account cannot read the owner's `public.json`, so a
harness that runs commands as another local user cannot reach PAM at all: that
bounds the agent and also excludes it, which is a statement, not a profile. See
[sandbox/windows/README.md](sandbox/windows/README.md) for each harness's
position, with sources.

### Reference profiles

[`docs/sandbox/`](sandbox/README.md) holds a reference profile per harness
(Claude Code, Codex, Gemini CLI, Copilot CLI) and a harness-independent
`sandbox-exec` profile, each embedded in the binary: `pam doctor --profile
<claude-code|codex|gemini-cli|copilot-cli|sandbox-exec> [--base DIR]
[--managed]` prints it with the base filled in and exits `0` without probing or
dialing. Every profile allows the literal public socket and the read of the lock
file, denies the rest of the base (including the engine's runtime paths named
above), denies writes to the trusted executable and bundle, and says what its
harness leaves outside. A profile is a claim; the proof is a `pam doctor` run
from inside it.

### Fleet signal

Two commands, both machine-readable:

1. From the agent's position (a harness hook, a wrapper, or the human once per
   setup): `pam doctor --json`. Exit `6` is the compliance signal and `failed`
   is the remediation list. The document's `report` member says whether the
   daemon recorded it, and `daemon_reply` (a top-level member, present when the
   daemon answered) carries the daemon's view of the caller.
2. From the host, any time: `pam status --json`, reading
   `.boundary.last_report.verdict`, `.boundary.last_report.age_s` and
   `.boundary.admin_contacts.unattributed`. A non-zero unattributed count, a
   `not_established` verdict, or a stale or missing report is the alert.

Harness policy delivery is the harness's own (Claude Code managed settings, Codex
`config.toml` under MDM, Gemini's `~/.gemini` profile file); PAM prints the
fragments and does not deliver them.

## Confirmation in the GUI bridge

The bridge forwards only the admin operations the frontend names. Three of them
expand what agents may do, and the bridge refuses them with
`confirmation_required` unless the call carries a typed phrase that Rust
checks before the operation reaches the socket: `relaxed` for
`admin.profile.set` to anything but `standard` or `strict`, and `grant` for
`admin.grants.add` and for `admin.approvals.resolve` with `remember` on an
approval. A compromised webview can supply the phrase itself, so this is a
second wall against blind one-click flows and mistakes, not against a hostile
frontend; a wall against that would need a native dialog drawn by Rust, which
this binary does not have. Approving a flow step is also pinned to the
resolved command shown on the card (`expected_digest`); a flow edited while the
approval waited refuses as `flow_changed` and the approval stays pending.

## Global target authority

**Authority is per operating-system user.** GUI grants, approvals, profiles and
repository/product scopes apply to every process that can reach the public
socket as that user: all of them hold the whole approved set, and clients may
select any approved repository. `caller.agent`, `caller.repo`, `caller.pid`,
the kernel's `peer_pid`, and the daemon-resolved `peer_exe` and `peer_harness`
are attribution and filters in the audit and the GUI, never a boundary. The only
facts the kernel attests are the peer's uid and pid; the uid is always the
daemon's own, the pid names a short-lived `pam` process that can be reused, its
executable and ancestry are defeated by a copied binary or a renamed parent, the
session relay collapses every client to `pam listen`, and on Windows there is
no peer identity at all. No harness hands PAM a per-session credential it could
verify. A grant keyed to any of these would be label-keyed authority with a GUI
that implies otherwise, so PAM has none.

Binding a ticket to its original canonical repository prevents relabeling that
ticket under another root. It does not isolate agents or keep evidence
confidential from another public client authorized through the same global
policy.

Two agents that need different authority on one machine run as different
operating-system users: a separate user has a separate base, daemon, keychain
and approved set, which PAM already supports (on Windows the same separation
also makes PAM unreachable from the other account, see
[Windows](#on-windows)). What `pam doctor` proves is the other half: that each
agent's sandbox holds it to the public socket. If a harness ever offers an
identity the daemon can verify with the harness, the recorded peer facts are
where a per-agent grant model would hang from; nothing here forecloses it.

Events are per follow, not broadcast. A public client that wants a ticket's
events opens a follow for that one ticket; the daemon authorizes it by the same
rule as a scoped result read (the caller's repository must be an approved root
and the ticket's own canonical repository, and the ticket's grant revision must
still hold), re-checks that rule while the follow lasts, and ends the stream
with the durable result. A ticket the caller may not read and one that does not
exist answer alike (`result_unavailable`). At most 16 followers attach to one
ticket and 96 in total; a follow lasts at most one hour and is then reconnected
by the client.

What a follower is sent is deliberately small: lifecycle states, a per-ticket
sequence number and progress percentages. Events do not carry step names,
repository/product details or diagnostic text; progress notes are fixed generic
text even though the follower passed the check that lets it read the result.
Use scoped result/evidence reads for details. Because target authority is
global, any public client working under the same approved repository can follow
that repository's tickets; the follow is scoped, not private to one agent. The
stream that carries every ticket with its real notes exists only on the private
endpoint, for the GUI.

## Failure behavior

Administration uses no bearer secret carried through the public protocol and
never falls back to the public socket. The Windows nonce travels only over the
private loopback connection, after the server has proved it holds the same nonce,
and never through the public endpoint. On a platform with no adapter at all
PAM reports that limitation rather than use a weaker identity check or silently
restore public administration.

The client sends an administrative operation once. A lost connection, timeout,
or lost reply can occur after a change has taken effect, so the client does not
automatically retry the operation. Inspect the resulting state before manually
trying again. Public request retry behavior does not authorize replaying admin
operations.

`admin.profile.set` persists the profile and swaps the running gate, so it
applies at once (the reply says `"applies": "now"`); the gate, the profile the
GUI shows and the authorization stamps of parked watch and landing runs all read
that one value. Revoking a grant or editing a flow can still end tickets that
were admitted before it.

A client whose version differs from the daemon's never restarts the daemon by
what it says. The daemon re-reads its own executable's file facts (cached for
one second): only a replaced image answers `daemon_outdated` and restarts, and
it respawns from the path it recorded at boot. A different version with an
unchanged image is refused `client_version_mismatch`, naming the daemon's
version and path, on both planes, and the phase does not move. The version is
judged on each connection's hello, before the request frame is read; nothing in
a request envelope decides it.

A GUI left open across an upgrade from 0.4.x still sends that version's bare
request frame. The private endpoint recognises it and answers in the old shape
with a `client_outdated` refusal telling the human to quit and reopen PAM; the
operation is not run.

## What verification establishes

Transport and integration tests can verify that forged public admin requests
are rejected, private requests use kernel peer credentials, missing or unsupported
private transport fails closed, and the client does not use public fallback or
automatic replay. Test fixtures representing a trusted native client are not
proof that an arbitrary same-user process is isolated.

The [macOS sandbox fixture](macos-sandbox-acceptance.md) exercises a real
default-deny profile with the compiled CLI and temporary daemon. It records
precisely which positive and negative operations are tested.

Those tests do not establish the deployed sandbox's filesystem, process, or
credential restrictions. Deployment verification must separately confirm that
an agent can reach its permitted public operations while it cannot reach or
modify the private resources listed above; `pam doctor` is that confirmation,
run from the agent's position (next section).

## Resource and recovery limits

Native frames are capped before allocation: 1 MiB requests and 16 MiB replies.
At most 32 native connections are served at once (an event subscriber holds one
for its lifetime), the hello and the request frame together must arrive within
five seconds, and request deadlines are between one millisecond and five
minutes. A connection over the cap is told `connection_capacity_exhausted`
rather than dropped. The request
clock starts before ledger insertion; waiting for bookkeeping cannot grant a
fresh execution deadline. A terminal write that fails is retried, then parked in
a bounded queue that the maintenance loop retries every second and once more
while draining, and the caller is answered `internal_error` rather than success
when the row is not durable; admin rows have no expiry, so a parked admin verdict
that never lands is closed by the next boot's crash recovery. Interrupted admin
rows enter crash recovery, never the work queue.

The admin listener logs and retries accept errors with backoff (10 ms doubling
to one second) instead of ending, and the requests the GUI submits (such as
`admin.flows.run`) have their own 32-slot dispatcher pool, so a public flood
cannot refuse them. On Windows, a local process can still hold the adapter's
pending-handshake slots (eight on the private endpoint, 32 on the public one)
for the five-second handshake timeout; they sit outside the served-connection
caps and that bound is by design.

While the daemon drains, both listeners keep accepting and answer each request
with a `daemon_shutting_down` refusal frame instead of refusing the connect;
followers and event subscribers are ended by name. When the drain is done each
listener stops accepting, removes its socket file (`control.sock`, `pam.sock`)
or control file while the instance lock is still held, and gives owned
asynchronous handlers five seconds. This is not a cancellation guarantee for already-started blocking work
(such as an OS keychain call or weight-file deletion): Rust cannot abort that
work. Its effects can remain uncertain after a timeout, and runtime shutdown may
wait longer. A separate process-owned runner now bounds accounted blocking work to eight
executing jobs and 128 outstanding admissions. Permits remain inside the actual
closures, including after caller cancellation. Native keychain/model filesystem
work is serialized by resource lane; existing asynchronous downloads retain their
own lifecycle. See [scoped admission and budgets](scoped-admission-and-budgets.md).

The daemon validates the canonical base and its ancestor ownership/write modes
before opening state. Root-owned sticky temporary directories are allowed;
the base must be owned and non-symlink, and the private admin directory/socket
must have modes 0700/0600. These checks supplement the OS sandbox exclusions;
they do not isolate mutually hostile processes sharing an unrestricted user.
