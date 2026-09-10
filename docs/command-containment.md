# Broker command containment

PAM executes repository-controlled programs outside the calling agent's sandbox. The daemon must install a separate OS boundary before executing those programs; an approved program name, cleared environment, process group, or GUI approval does not establish that boundary.

## Current contract

Every flow command, including preliminary Git inspection, carries a mandatory containment configuration. On macOS, the system sandbox launcher installs a default-deny profile before an environment trampoline starts the canonical executable. Descendants inherit the profile. Validation consumes the original command deadline. There is no uncontained retry.

The profile permits explicit repository and toolchain reads. Repository writes require a declared stateful step and its normal approval gate. It denies network access (including PAM sockets), Mach service lookup, AppleEvents, access to PAM's private base and keychain files, new hardlinks, and control of unrelated processes. Trusted executable/toolchain roots cannot overlap a writable repository. Configuration failures return `command_containment_unavailable` before the workload starts. An OS launcher rejection can instead appear as a nonzero command result; this does not trigger fallback.

Linux and Windows command containment is not implemented and commands are refused. Rust/HTTP connector operations remain independently available where their transport is supported. The AWS CLI adapter is refused before credential lookup or spawning because its credential helpers do not yet have qualified containment.

HTTP transport uses the trusted system curl on macOS/Linux with `-q` first, an empty environment, and a fixed working directory. Credentials remain in its stdin configuration. Caller PATH, curl configuration, and inherited proxy settings do not select or configure this transport. Windows transport qualification remains outstanding.

## Deliberate execution limits

Network commands such as `git fetch`, push, and publishing cannot run inside this profile. Existing network command recipes are not thereby qualified for landing. Future remote operations require a separately scoped broker implementation and acceptance tests; granting a program cannot loosen containment.

There are no implicit HOME, cache, temporary-directory, or build-output write allowances. A read-only step that runs a tool which writes artifacts can fail. A later build capability must declare and validate artifact roots explicitly. Stateful execution in a checkout containing the running PAM executable is refused: install trusted PAM assets outside the writable repository.

Deployment must exclude pre-existing aliases or hardlinks to protected files from writable roots and keep trusted binaries, toolchains, profiles, and the GUI frontend immutable to the agent. This profile is not protection against an otherwise unrestricted process of the same user changing those assets. Process-group cleanup is not a claim that all independently daemonized descendants are reaped.

## Verification

`crates/pam_daemon/tests/flow_containment.rs` invokes a granted real flow whose child and grandchild attempt private socket, database, trusted asset, keychain initialization, and process-control access. Host-side assertions verify absent effects and successful allowed repository markers. Keychain tests use nonexistent test items; process-control probes use signal zero. The unsupported-platform path requires refusal without the child-started marker.

`crates/pam/tests/sandbox_macos.rs` separately verifies the calling CLI's public/private boundary. Both boundaries are necessary. Neither fixture attests the policy of every enterprise agent sandbox.

Track implementation and runtime qualification under ptrack task #143; the complete broker checkpoint remains #120.
