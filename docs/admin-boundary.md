# Administration boundary

PAM separates ordinary agent requests from administration. The public ZeroMQ
endpoint rejects every `admin.*` operation, including envelopes claiming
`caller.agent = "pam-gui"`. Caller labels, repository names, and caller-supplied
PIDs do not authorize administration.

The GUI cancels a ticket through `admin.requests.cancel` on the private
channel, which the audit records as the human's act. The bridge has no
`request_capability` command and so no public request at all. A public `cancel`
is recorded as `system` whatever `caller.agent` says, and it acts only on a
ticket admitted under the caller's own canonical repository; a foreign ticket
answers `not_found`, like a missing one.

On macOS and Linux, the native GUI client uses a separate Unix socket at
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
then is a request frame read. Reading that file is the same standing a Unix peer
proves through its uid: another local user cannot; an administrator or an
unrestricted same-user process can, exactly as root or a same-uid process can on
Unix. The connection is loopback-only and the same frame budgets, header timeout
and connection cap apply. This proves no more than the Unix path does: not GUI
mode, not code integrity, not that a human asked.

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
`gui-embed` feature) loads the Vite development URL, `http://127.0.0.1:1420`,
with the full admin bridge: that is a development configuration only, and the
caveat stands. Blocking a direct child process is not proof that
a system broker cannot launch an unsandboxed process on its behalf.

OS keychain isolation requires restricting the credential service as well as
keychain files. A fake credential backend verifies PAM behavior, not OS credential
isolation. Negative deployment tests must establish absence of privileged effects,
not merely a nonzero client exit code.

PAM does not automatically install or verify the agent's sandbox policy. The
deployment must establish and maintain these exclusions. An executable name,
argv value, or self-reported PID is not a substitute for that isolation.

A daemon that a client starts lazily is started with an environment allowlist
(home, user, locale, temp directory, absolute `PATH` entries, `PAM_LOG`, an
explicit `PAM_BASE_DIR`, and on Linux the keyring session variables), in its own
process group, with `/` as its directory and null standard streams. It does not
inherit the caller's environment, descriptors or process group. Flow steps build
their environment from the daemon's, so they no longer see the first caller's
variables either.

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

GUI grants and repository/product scopes apply globally to public PAM clients.
Caller labels and PIDs provide attribution; clients may select any approved
repository. Binding a ticket to its original canonical repository prevents
relabeling that ticket under another root. It does not isolate agents or keep
evidence confidential from another public client authorized through the same
global policy. Per-agent repository authentication is not implemented.

Public events expose lifecycle timing, opaque request IDs and progress percentages.
They do not carry step names, repository/product details or diagnostic text;
progress notes are fixed generic text. Raw subscribers can observe all these
public events. Topic filtering and CLI authorization are not event access control.
Use scoped result/evidence reads for details.

## Failure behavior

Administration uses no bearer secret carried through the public protocol and
never falls back to the public socket. The Windows nonce travels only over the
private loopback connection, after the server has proved it holds the same nonce,
and never through the public ZeroMQ endpoint. On a platform with no adapter at all
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
version and path, on both planes, and the phase does not move.

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
modify the private resources listed above.

## Resource and recovery limits

Native frames are capped before allocation: 1 MiB requests and 16 MiB replies.
At most 32 native connection handlers are active, with a five-second frame-read
limit and request deadlines between one millisecond and five minutes. The request
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
pending-handshake slots for the five-second handshake timeout; that limit
remains until the listener is replaced.

Shutdown stops acceptance and gives owned asynchronous handlers five seconds to
drain. This is not a cancellation guarantee for already-started blocking work
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
