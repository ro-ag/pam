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

`pam listen` binds `pam.sock` and `events.sock` directly inside `<dir>` (created
`0700`) and forwards bytes to the daemon's runtime sockets under the PAM base.
Every client subcommand then works unchanged, including `pam wait` and
`pam subscribe` (the events socket is relayed too). Stop the relay with ctrl-c;
it removes its socket files on the way out. A stale socket file nobody answers
is replaced on the next start; a socket that still answers belongs to a running
relay and is refused, never taken over.

## What the override changes for clients

With `$PAM_SOCKET_DIR` set, the client dials the two sockets directly inside
that directory instead of `<base>/run`, and lazy daemon auto-start is off: the
relay is the transport, so a missing relay is a clean error naming
`pam listen` — never a spawned daemon. The override affects only the public
dial path (`send_request`, `follow_ticket`); `pam daemon stop` and the login
service still target the real base.

## Boundaries

- **The relay is a dumb byte pipe.** It holds no credential, makes no decision
  and never inspects frames; the daemon sees ordinary connections and applies
  the same admission, repository scope, grant revision and budgets. A ticket
  or a relayed connection is a reference, not authority.
- **Placement is the trade.** A listening socket inside a writable directory
  can be unlinked and rebound by another process of the same user, which lets
  it impersonate the daemon to the agent — deception, not escalation, since a
  same-user process could talk to the real daemon anyway. The directory is
  created `0700` and sockets `0600`; prefer a session directory outside every
  writable repository if the sandbox permits one, and treat the workspace
  variant as a bench configuration.
- **The prerequisite is unchanged.** The sandbox must still permit unix-socket
  connects under the relay's directory. The relay relocates a grant; it does
  not remove the need for one. If the policy is editable, allowing the daemon's
  socket path directly is simpler and needs no relay.
- **Windows is out of scope.** The relay needs unix domain sockets; a Windows
  session channel would follow the admin transport's loopback-plus-nonce
  design instead.
