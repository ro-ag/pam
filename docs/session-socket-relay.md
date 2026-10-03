# Session socket relay (unix)

An agent harness runs its tool commands under a sandbox that is deny-by-default
on networking, and that denial covers unix domain sockets too — including the
daemon's own `pam.sock`, which is the only door a `pam` client has. When the
sandbox's policy can be edited, the narrow fix is a path-scoped allowance for
the daemon's socket under the PAM base (`~/.pam/run/pam.sock`); that grant
confers no network reach and is the configuration the rest of the contracts
assume ("Host policy must permit PAM execution and IPC"). When the policy
cannot be edited, `pam listen` provides a relay through a path the sandbox
already permits — typically the workspace.

## Using it

```sh
# in the terminal the agent session starts from, outside the sandbox:
pam listen .pam-session
# it prints, among the startup lines:
#   sandboxed clients: export PAM_SOCKET_DIR=/absolute/path/to/.pam-session

export PAM_SOCKET_DIR=/absolute/path/to/.pam-session
claude …   # or any agent harness; start it normally
```

`pam listen` binds one socket, `pam.sock`, directly inside `<dir>` (created
`0700`) and forwards bytes to the daemon's public socket,
`<base>/run/pam.sock`. Every client subcommand then works unchanged, including
`pam wait` and `pam subscribe`: a follow is a long-lived connection through the
same pipe, so there is no second socket and a sandbox policy needs to allow only
`<dir>/pam.sock`. Stop the relay with ctrl-c; it removes its socket file on the
way out, and a daemon the relay started keeps running. A stale socket file
nobody answers is replaced on the next start; a socket that still answers
belongs to a running relay and is refused, never taken over. A stale
`events.sock` in `<dir>` is removed at start when it is a socket you own;
nothing dials it any more. (No released relay can have left one: `pam listen`
of 0.4.0 to 0.4.3 panicked at startup before it bound anything.)

## What the relay checks before it starts

**The directory and the socket entry.** The relay refuses, with the cause and
what to do, rather than repair:

- a `<dir>` that is a symbolic link (also when given with a trailing slash), or
  is not a directory;
- a `<dir>` owned by another user, or writable by group or others;
- a `pam.sock` entry in it that is a symbolic link, is not a socket, or is owned
  by another user. A regular file of that name is left where it is.

A missing `<dir>` is created `0700`; an existing one you own is tightened to
`0700`. The directory is opened once and its identity (device and inode) is
compared before and after the bind, and the socket is bound through the
directory's canonical path and set to `0600`, so a link swapped in between the
checks and the bind is noticed.

**The daemon behind it.** The relay dials the daemon's public socket once with a
hello. A daemon of version 0.4 or older answers in its own protocol; the relay
runs outside the sandbox, where its clients cannot act, so it stops that daemon
the way `pam daemon stop` does, starts the current one and then serves. If it
cannot (the lock file names no process, signalling is refused, the old daemon is
still draining after 20 seconds, or the new one does not start) the relay
removes the socket it bound and exits with the instruction, instead of
forwarding to a daemon its clients cannot talk to. A daemon that is not running
is reported as "not reachable yet" and the relay serves anyway. The startup
lines say which of these it found.

## What the override changes for clients

With `$PAM_SOCKET_DIR` set, the client dials `pam.sock` directly inside that
directory instead of `<base>/run`, and lazy daemon auto-start is off: the
relay is the transport, so a missing relay is a clean error naming
`pam listen` — never a spawned daemon. A client that dials through the relay
never signals anything either: if what answers is a daemon of version 0.4 or
older, it fails with the instruction to run `pam daemon stop` and then
`pam status` outside the sandbox. The second command matters: with the old
daemon stopped and nothing started, the relay has no daemon to forward to and
the client gets a bare transport failure (`Broken pipe` or `early eof`), not a
message naming the cause. The override affects only the public dial path
(`send_request`, `follow_ticket`); `pam daemon stop` and the login service
still target the real base.

## What the daemon records for a relayed request

The daemon records, on every request row, the plane it arrived on and the
kernel's view of the connection (`ingress`, `peer_uid`, `peer_pid`, `relayed`).
For a relayed connection the kernel's peer is the **relay process**, not the
sandboxed client: `peer_uid` and `peer_pid` name `pam listen`. `relayed` is the
client's own statement, sent in its hello because `$PAM_SOCKET_DIR` is set; the
envelope's `caller` (agent label, repository, pid) is self-reported as always.
None of this authorizes anything. The uid is the same owner on both paths, the
relay's pid identifies the grant of reach the human made by starting it, and a
relayed client that omitted the marker would still be recorded with a pid that
resolves to a `pam listen` process. The daemon's resolution of that pid
(`peer_exe`, `peer_harness`) therefore names the relay: `peer_harness` is
`relay`, and the harness the agent actually runs under is known only from the
client's own statement.

## `pam doctor` through the relay

`pam doctor` works through the relay and says so. With `$PAM_SOCKET_DIR` set it
dials `<dir>/pam.sock`, the hello carries `via: relay`, and the report's
`daemon.via` reads `relay`. It never starts a relay or a daemon: with no relay
the verdict is `cannot_probe` (exit `1`).

What the daemon records is the relay's peer, not the agent's. The
`doctor.report` request row has `relayed` set and the kernel's uid and pid of
`pam listen`, with `peer_harness = relay`; the status block's `last_report`
shows `relay` for it. The harness chain of the client (`env.harness_chain`, and
the `claimed_harness` the reply derives from it) is carried in the report as a
self-report, never as the daemon's own finding; `harness_agrees` is `null`
(printed `undetermined`) because the daemon sees the relay process, not the
client's harness, and cannot say the two disagree.

Two consequences for reading a relayed report:

- **Nothing under `<base>` is expected to be reachable, and the verdict is
  still computed.** The relay profile allows `<dir>/pam.sock` and no path under
  the base, so the lock-file probe is `denied` ("unreadable under the relay;
  lazy start is not needed here"), which is informational, and every private
  path should read `denied` or `absent`. `daemon.signal` takes the daemon's pid
  from the hello acknowledgement (the daemon answers the hello through the
  relay, so the pid is the daemon's, not the relay's) and never reads the lock
  file, so it is probed and refused like every other must-deny row. A run
  through the relay under the documented relay variant of `pam-agent.sb` is
  `established` (`doctor_macos.rs`, macOS 26); keeping the `daemon.lock` read
  line changes only the informational lock probe.
- **A relayed run cannot attribute its own admin contact.** The daemon matches
  an unexplained admin contact to a report by kernel pid. The contact, if the
  sandbox lets the client reach the private endpoint at all, comes from the
  client's pid; the report arrives from the relay's pid. The two never match, so
  such a contact stays unattributed and shows on `pam status` as one — which is
  the right outcome: the sandbox let a process reach the private endpoint.

The relay is still a byte pipe: it does not know a doctor report from any other
request, and a `doctor.report` through it is admitted, validated and recorded
like one from a direct client. See
[Verifying the boundary](admin-boundary.md#verifying-the-boundary).

## Boundaries

- **The relay is a dumb byte pipe.** It holds no credential, makes no decision
  and never inspects frames; the daemon sees ordinary connections and applies
  the same admission, repository scope, grant revision and budgets. A ticket
  or a relayed connection is a reference, not authority.
- **A transient accept error does not end the relay.** Any accept error
  (descriptor exhaustion, an aborted connection) is retried with backoff,
  10 ms doubling to one second. The relay serves at most 64 concurrent
  connections, a follow included for as long as it lasts; an excess connection
  is closed at once, and the dial to the daemon is bounded to five seconds.
- **Placement is the trade.** A listening socket inside a writable directory
  can be unlinked and rebound by another process of the same user, which lets
  it impersonate the daemon to the agent — deception, not escalation, since a
  same-user process could talk to the real daemon anyway. The checks above
  narrow this and do not close it: std offers no way to bind relative to an
  open directory, so between the last check and the bind another process **of
  the same user** can still swap the path. The directory is `0700` and the
  socket `0600`; prefer a session directory outside every writable repository
  if the sandbox permits one, and treat the workspace variant as a bench
  configuration.
- **The prerequisite is unchanged.** The sandbox must still permit unix-socket
  connects under the relay's directory. The relay relocates a grant; it does
  not remove the need for one. If the policy is editable, allowing the daemon's
  socket path directly is simpler and needs no relay.
- **Windows is out of scope.** The relay needs unix domain sockets; a Windows
  session channel would follow the admin transport's loopback-plus-nonce
  design instead.
