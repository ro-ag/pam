# macOS broker isolation acceptance fixture

`cargo test -p pam --test sandbox_macos` runs the compiled PAM CLI inside
`/usr/bin/sandbox-exec`, against a temporary daemon outside that profile. The
profile is [broker-macos.sb](../crates/pam/tests/support/broker-macos.sb); the
harness escapes quoted SBPL path contents and substitutes canonical temporary and home paths. This does not install or verify
an enterprise agent's actual host policy.

The default-deny profile allows executable/library reads, child execution,
caller process metadata, and only PAM's one public Unix endpoint,
`<base>/run/pam.sock`. It does not allow
Mach service lookup, signal operations, arbitrary network access, private admin
access, SQLite state access, keychain files, or writes to trusted assets. Its
broad filesystem-read allowance is deliberately a fixture convenience, not a
claim of general document confidentiality.

The real CLI must complete an approved echo and read exactly two retained
evidence bytes. A child of the same sandbox must get permission errors opening
the private admin socket (including a `run/../admin` alias), reading/writing the database, opening the existing daemon lock for writing, unlinking the public socket, and opening trusted
fixture assets and the PAM executable for writing. A harmless `kill -0` against
the outside test process must fail with permission denied; no signal that kills
or changes the target is sent. The parent verifies the socket and lock inodes and lock bytes remain unchanged, then repeats a successful public echo. The profile grants no runtime-directory writes. Dropping the acceptance deadline kills an outstanding direct child. Removing repository approval must make the same
evidence request unavailable while its protected source remains in the store.

A second case puts a fake daemon of version 0.4 or older behind the same
profile: it holds the real instance lock, names a stand-in process in it and
answers on `pam.sock` with that version's greeting. The sandboxed CLI must exit
`1`, print nothing on stdout under `--json`, name the pid and the instruction
(`pam daemon stop` outside the sandbox) on stderr, and leave the stand-in
process alive and the lock unchanged: a sandboxed client cannot stop a daemon,
and does not start one beside it. The unsandboxed takeover is proved separately
by `cargo test -p pam --test legacy_takeover`.

The keychain probe asks only for a nonexistent service/account. It requires a
keychain search initialization error, not merely exit 44 or item-not-found,
which occur outside a sandbox too. This proves the tested command cannot
initialize that lookup under this profile; it does not validate every keychain
API, access group, or enterprise credential deployment. No credential is seeded,
exported, or changed.

Deployment acceptance must additionally establish that trusted process control,
Mach task ports, inherited privileged descriptors, AppleEvents/UI automation,
and indirect launch routes (including LaunchServices) cannot escape the actual
agent profile. This fixture grants no Mach lookup, but does not exercise those
routes using real privileged applications. It never launches the PAM GUI.
Trusted installed binaries and frontend assets must be outside agent write
access; a writable development frontend is not equivalent to a trusted embedded
production frontend.

Repository/connector scopes are global daemon approvals, not authenticated
per-agent identities. A caller-supplied repository name cannot establish tenant
isolation. Events are no longer broadcast: a public client receives the events
of one ticket, on a follow the daemon authorised by the same scoped rule as a
result read, and they carry no detail. That is the same global approval, not a
per-agent boundary. The fixture must not be cited as proving either property.
