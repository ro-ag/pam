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
(`pam daemon stop` and then `pam status`, outside the sandbox) on stderr, and
leave the stand-in process alive and the lock unchanged: a sandboxed client
cannot stop a daemon, and does not start one beside it. Under this profile it
cannot start one at all: with no daemon running, the sandboxed CLI exits `1`
after six seconds with "the pam daemon did not become ready" (seen with the
real binaries on 2026-10-02; no test pins it), which is why the instruction
names the second command. The unsandboxed takeover is proved separately by
`cargo test -p pam --test legacy_takeover`.

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

## Boundary self-check acceptance (`pam doctor`)

`cargo test -p pam --test doctor_macos` runs the compiled `pam doctor` under
real `sandbox-exec` profiles against a daemon on a scratch base
(`pam_testkit::TestDaemon`, in-process, relaxed profile seeded, plus the
`log` directory a daemon started from the binary creates), from a fresh APFS
clone of the binary warmed with `--version` before anything is timed, with
every path a profile names resolved (`/private/tmp/…`). The profiles are
rendered at test time through `pam::doctor::profiles::render`, so what runs
is what `pam doctor --profile` prints. Observed on macOS 26 (Darwin 27.0.0),
2026-10-02, in a GUI login session; each statement below is asserted by the
test named.

**Established** (`under_pam_agent_sb_the_boundary_is_established_and_recorded`).
Under `docs/sandbox/macos/pam-agent.sb` with `-D HOME -D WORKSPACE -D PAM_EXE`
the verdict is `established`, exit `0`, `failed` and `unverified` empty.
Every must-deny probe whose target exists on the base is `denied`
(`run.lock_write`, `admin.endpoint`, `admin.endpoint_alias`, `admin.dir`,
`store.read`, `store.write`, `store.wal_read`, `store.wal_write`,
`store.shm_read`, `store.shm_write`, `log.read`, `keychain.search`,
`daemon.signal`, `broker.launchservices`, `broker.appleevents`,
`exe.write`); the targets that do not exist on a fresh base are `absent`
(`backup.read`, `model_trust.read`, `engine.read`, `engine.runtime_read`,
`engine.socket`, `flows.read`, and `bundle.write` outside a `.app`);
`public.unlink` is `not_probed`. `public.reach` is `allowed`, `via: direct`;
`run.lock_probe` stays `allowed` (`held: a daemon is running`). The daemon
accepts the report (`daemon_reply.accepted`, the sandboxed clone as `peer.exe`),
`pam status --json` then shows `boundary.last_report.verdict = established`
with `admin_contacts.unattributed_24h = 0` and `admin_contacts.total = 0`:
the sandbox refuses the admin connect before it reaches the socket, so there
is no contact to attribute. The public socket and lock inodes and the lock
bytes are unchanged. The harness chain is empty under the profile because
`/bin/ps` cannot exec there (`sandbox-exec: execvp() of '/bin/ps' failed:
Operation not permitted`), so the daemon reports `claimed_harness: unknown`,
`harness_agrees: false` while its own view of the peer names the real harness.

**Not established, unsandboxed**
(`unsandboxed_is_not_established_and_its_admin_contact_is_attributed`). The
same clone without `sandbox-exec` exits `6`, `not_established`, `unverified`
empty, and `failed` is exactly the must-deny probes whose target exists on
the base, in inventory order — on a fresh base: `run.lock_write`,
`admin.endpoint`, `admin.endpoint_alias`, `admin.dir`, `store.read`,
`store.write`, `store.wal_read`, `store.wal_write`, `store.shm_read`,
`store.shm_write`, `log.read`, `keychain.search`, `daemon.signal`,
`broker.launchservices`, `broker.appleevents`, `exe.write` (the test derives
the list from the inventory's path constants and the base, never from a
literal). The two admin connects reach the daemon; the 150 ms hold lets the
accept loop read the pid, so `daemon_reply.attributed_admin_contacts ≥ 1`
and the next `status` has `admin_contacts.unattributed = 0`,
`unattributed_24h = 0`, `total ≥ 1`, `last.attributed` = this report's
request id and `last.peer_pid` = the doctor's pid.

**Per profile** (`every_harness_profile_yields_its_recorded_verdict`; the
table in [sandbox/README.md](sandbox/README.md) records the same):
`pam-agent.sb` → `established`; the Gemini CLI profile, run with the
launcher's `-D TARGET_DIR TMP_DIR HOME_DIR CACHE_DIR INCLUDE_DIR_0..4` →
`established` (the spec expected it to fall short on the keychain, signal
and brokers; the shipped profile denies those, unlike upstream's
`permissive-open`). The Claude Code JSON (standard and managed), Codex TOML
and Copilot Markdown are consumed by their harness, carry no Seatbelt
fragment, and are checked for syntax only (the JSON parses, every
`<base>` is substituted, the public socket is named): a `pam doctor` from
inside the harness is the only evidence for those.

**The broker fixture is not a boundary profile**
(`the_broker_fixture_profile_leaves_the_log_directory_listable`). Under
`broker-macos.sb` (above) the doctor says `not_established` on exactly
`log.read`: the fixture allows `file-read*` broadly and denies only the admin
directory, the store files and the keychain by name, so the `log` directory
a daemon creates stays listable. Everything else it denies the way
`pam-agent.sb` does. The fixture proves broker isolation; `pam-agent.sb` is
the profile that establishes the boundary.

**Through the relay**
(`through_the_relay_the_verdict_is_computed_and_the_lock_decides_daemon_signal`).
With `pam listen <dir>` running outside the sandbox and `PAM_SOCKET_DIR=<dir>`
in the sandboxed run, the hello goes through the relay (`daemon.via: relay`,
`env.socket_dir` and `env.resolved_endpoint` name `<dir>`), the admin, store
and log probes stay `denied`, and the daemon records the report with the
relay as its peer (`peer.relayed = true`, `peer.harness = "relay"`,
`peer.pid` = the relay's). With the relay variant the profile's own comment
describes — the `pam.sock` and `daemon.lock` allow lines replaced by one
allow of `<dir>/pam.sock`, nothing under `<base>` readable — the verdict is
`not_established` with `failed = []` and `unverified = [daemon.signal]`:
the daemon's pid lives in `<base>/run/daemon.lock`, which is now unreadable
(`run.lock_probe`: `unreadable under the relay; lazy start is not needed
here`), so the signal probe is `unknown` (`lock file unreadable: no pid to
probe`) and an unknown fails the verdict. The same profile with the
`daemon.lock` read line kept is `established` through the relay. Until the
relay guidance or the probe changes, a relay deployment that wants
`established` keeps the lock readable.

**Helper strings re-pinned under `sandbox-exec`**
(`keychain_signal_access_and_ps_helpers_under_pam_agent_sb_match_the_pinned_strings`,
`broker_helpers_under_pam_agent_sb_match_the_pinned_strings`), with the
rows' `os_error` as the engine folds them: `security find-generic-password
-s dev.pam.connector -a <absent>` → exit 44, first line
`security: SecKeychainSearchCreateFromAttributes: One or more parameters
passed to a function were not valid.` (outside: exit 44,
`SecKeychainSearchCopyNext: The specified item could not be found`);
`kill -0 <pid>` → exit 1, `kill: <pid>: Operation not permitted` (outside:
exit 0); `lsappinfo find bundleid=com.apple.loginwindow` → exit 0, nothing
on either stream (outside: `ASN:0x0-0x1001-"loginwindow":`);
`osascript -e 'id of application "Finder"'` → exit 1, stderr `Connection
Invalid error for service com.apple.hiservices-xpcservice.` then `… Can’t
get application "Finder". (-1728)` (outside: `com.apple.finder`); `test -w
<exe>` → 1 (outside 0), `test -e <exe>` → 0; `/bin/ps` → exit 71, `execvp()
of '/bin/ps' failed: Operation not permitted`. The broker readings `allowed`
outside a sandbox need a GUI login session (Finder and loginwindow
registered); in a headless session they read `denied` and `unknown`, never
`allowed`.

Repository/connector scopes are global daemon approvals, not authenticated
per-agent identities. A caller-supplied repository name cannot establish tenant
isolation. Events are no longer broadcast: a public client receives the events
of one ticket, on a follow the daemon authorised by the same scoped rule as a
result read, and they carry no detail. That is the same global approval, not a
per-agent boundary. The fixture must not be cited as proving either property.
