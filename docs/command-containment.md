# Broker command containment

PAM executes repository-controlled programs outside the calling agent's sandbox. The daemon must install a separate OS boundary before executing those programs; an approved program name, cleared environment, process group, or GUI approval does not establish that boundary.

## Current contract

Every flow command, including preliminary Git inspection, carries a mandatory containment configuration. On macOS, the system sandbox launcher installs a default-deny profile before an environment trampoline starts the canonical executable. Descendants inherit the profile. Validation consumes the original command deadline. There is no uncontained retry.

The profile permits explicit repository and toolchain reads. Repository writes require a declared stateful step and its normal approval gate. It denies network access (including PAM sockets), Mach service lookup, AppleEvents, access to PAM's private base and keychain files, new hardlinks, and control of unrelated processes. Trusted executable/toolchain roots cannot overlap a writable repository. Configuration failures return `command_containment_unavailable` before the workload starts. An OS launcher rejection can instead appear as a nonzero command result; this does not trigger fallback.

Linux and Windows command containment is not implemented and commands are refused. Rust/HTTP connector operations remain independently available where their transport is supported. The AWS CLI adapter is refused before credential lookup or spawning because its credential helpers do not yet have qualified containment.

HTTP transport uses the trusted system curl on macOS/Linux with `-q` first, an empty environment, and a fixed working directory. Credentials remain in its stdin configuration. Caller PATH, curl configuration, and inherited proxy settings do not select or configure this transport. Windows transport qualification remains outstanding.

## Deliberate execution limits

Network commands such as `git fetch`, push, and publishing cannot run inside this profile. Existing network command recipes are not thereby qualified for landing. [Guarded landing](guarded-landing.md) uses separate typed brokers with exact remote/ref policy; granting a program cannot loosen containment. That flow remains under end-to-end qualification.

Command environments default Git global/system configuration and personal ignore/attribute files to `/dev/null`; repository configuration remains subject to repository access and helper containment. Typed landing network operations use isolated Git metadata and the scoped broker credential. Local checks read sealed source and may write only separately declared private artifact roots; approved caches remain read-only.

There are no implicit HOME, cache, temporary-directory, or build-output write allowances. The only build-output write a flow step gets is the **build output directory** named in Settings → Flows (`flows.artifacts_root`): under it the daemon keeps one private tree per repository (`home`, `cargo`, `target`, `tmp`, `npm`, mode 700, owned by PAM's user) and links the approved read-only caches (`flows.read_cache_roots`, by default `~/.cargo/registry` and `~/.cargo/git`) under `cargo/`. Every command step then runs with `HOME`, `CARGO_HOME`, `CARGO_TARGET_DIR`, `TMPDIR` and the npm cache pointed into that tree and `PAM_ARTIFACTS` naming it, so a read-only cargo or npm step never touches the repository or the user's home. While no directory is named, a step whose program keeps state in a home directory (cargo, rustc, rustup, npm, npx, pnpm, yarn) is blocked before spawn with `artifacts_root_unset` and `pam flow inspect` lists the same blocker; a directory inside the repository or PAM's private base, or one readable by other users, is refused with `artifacts_root_invalid`. Landing checks lay out the same tree under their sealed workspace. Stateful execution in a checkout containing the running PAM executable is refused: install trusted PAM assets outside the writable repository.

Deployment must exclude pre-existing aliases or hardlinks to protected files from writable roots and keep trusted binaries, toolchains, profiles, and the GUI frontend immutable to the agent. This profile is not protection against an otherwise unrestricted process of the same user changing those assets. Process-group cleanup is not a claim that all independently daemonized descendants are reaped.

## Verification

`crates/pam_daemon/tests/flow_containment.rs` invokes a granted real flow whose child and grandchild attempt private socket, database, trusted asset, keychain initialization, and process-control access. Host-side assertions verify absent effects and successful allowed repository markers. Keychain tests use nonexistent test items; process-control probes use signal zero. The unsupported-platform path requires refusal without the child-started marker.

`crates/pam/tests/sandbox_macos.rs` separately verifies the calling CLI's public/private boundary. Both boundaries are necessary. Neither fixture attests the policy of every enterprise agent sandbox.

Track implementation and runtime qualification under ptrack task #143; the complete broker checkpoint remains #120.
