# Administration boundary

PAM separates ordinary agent requests from administration. The public ZeroMQ
endpoint rejects every `admin.*` operation, including envelopes claiming
`caller.agent = "pam-gui"`. Caller labels, repository names, and caller-supplied
PIDs do not authorize administration.

On macOS and Linux, the native GUI client uses a separate Unix socket at
`<base>/admin/control.sock`. The transport obtains the connected peer's UID and
PID from the kernel rather than trusting the request envelope. These credentials
authenticate the peer's operating-system owner and process identity; they do
**not** prove that the process is in GUI mode or that a human requested the
operation. Executable-path checks, where applied, likewise do not prove code
integrity or GUI mode.

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
separately protect that server. Blocking a direct child process is not proof that
a system broker cannot launch an unsandboxed process on its behalf.

OS keychain isolation requires restricting the credential service as well as
keychain files. A fake credential backend verifies PAM behavior, not OS credential
isolation. Negative deployment tests must establish absence of privileged effects,
not merely a nonzero client exit code.

PAM does not automatically install or verify the agent's sandbox policy. The
deployment must establish and maintain these exclusions. An executable name,
argv value, or self-reported PID is not a substitute for that isolation.

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
never falls back to the public socket. Windows native administration is currently
unsupported; PAM must report that limitation rather than use a weaker identity
check or silently restore public administration.

The client sends an administrative operation once. A lost connection, timeout,
or lost reply can occur after a change has taken effect, so the client does not
automatically retry the operation. Inspect the resulting state before manually
trying again. Public request retry behavior does not authorize replaying admin
operations.

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
fresh execution deadline. Terminal audit persistence remains tracked after that
clock expires. Interrupted admin rows enter crash recovery, never the work queue.

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
