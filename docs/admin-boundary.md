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

PAM does not automatically install or verify the agent's sandbox policy. The
deployment must establish and maintain these exclusions. An executable name,
argv value, or self-reported PID is not a substitute for that isolation.

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

Those tests do not establish the deployed sandbox's filesystem, process, or
credential restrictions. Deployment verification must separately confirm that
an agent can reach its permitted public operations while it cannot reach or
modify the private resources listed above.
