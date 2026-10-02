# PAM: drop Linux and Intel macOS — exact removal plan

Scope (owner decision): supported targets are macOS arm64 and Windows amd64/arm64.
Everything that exists only for Linux or only for Intel macOS goes. Nothing needs to
compile or pass on Linux afterwards. `cfg(unix)` code is shared with macOS and STAYS.
Read-only inventory; line numbers are from the working tree on `feat/framed-public-transport`
(files the in-flight framed-transport work has modified are marked **[dirty]**).

## 0. Findings that change how this must be sequenced

1. **Branch protection.** Per the repo's own plan and memory, `main` requires the contexts
   `gate`, `targets (ubuntu-24.04-arm)`, `targets (macos-15)`, `targets (windows-2025)`,
   `targets (windows-11-arm)` (docs/plans/2026-09-03-packaging.md:2455-2458). Removing the
   Ubuntu ARM row makes `targets (ubuntu-24.04-arm)` never report, so the CI PR cannot be
   plain-merged. Plan: land the CI PR with `--admin` (same as docs-only PRs), then remove
   that one context from the ruleset (repo setting, not a file; coordinator action). Keeping
   `gate`, `targets (macos-15)`, `targets (windows-2025)`, `targets (windows-11-arm)` as
   names avoids touching the other four.
2. **Dirty files.** `admin_transport.rs`, `daemon.rs`, `framed_unix.rs` (untracked) belong to
   the in-flight branch. Their Linux edits are tiny (one cfg swap in `admin_transport.rs`,
   comments elsewhere). Land Set A after that branch merges, or do those three files last.
   `docs/specs/2026-10-02-framed-public-transport.md:800,1415` mention Linux; it is that
   branch's spec, leave it.
3. **Cargo.lock cannot shed the Linux GUI stack.** `gtk`, `webkit2gtk`, `soup3`, `glib`,
   `cairo`, `pango`, `atk`, `gdk*`, `javascriptcore-rs` (~45 crates) are target-conditional
   dependencies of `tao`/`wry`/`tauri-runtime`; Cargo.lock is resolved for all targets and
   they stay for as long as Tauri is used. They never compile on macOS/Windows. Only the
   Secret Service tree and the `x11` feature crates leave the lock (section 1).
4. **No Linux branch exists in command containment.** `command_containment.rs` is
   macOS-only (`sandbox-exec`, line 71) with a `not(target_os = "macos")` refusal at line 106
   (`command_containment_unavailable`). Nothing to remove; `any(target_os = "macos", test)`
   gates there are for tests, not Linux. `docs/command-containment.md:11` already says so.
5. **Compile-time vs runtime refusal, per item.** Every Linux arm sits next to an
   existing legible runtime refusal. Recommendation for all items: keep the runtime refusal
   (cleaner: `cargo check`/rust-analyzer still work on any dev box, and a half-way
   `compile_error!` would not stop the many `cfg(unix)` modules compiling anyway). No
   `compile_error!` is proposed. The GUI crate will in practice stop building on Linux
   (no `x11`, no system libs): acceptable and expected.

| Item | Behaviour on an unsupported OS after removal | Mechanism (already present) |
| --- | --- | --- |
| Credential store | `SecretError::Unavailable`, warn "no native credential store is implemented for this platform" | `secrets.rs:280-285` fallback arm |
| Login-start service | `ServiceState::Unsupported`, reason "linux has no login-start integration" | `Platform::Other` + `unsupported()` at `service.rs:686` |
| Engine asset | `EngineStatus.cause = "unsupported_target"`; install returns `EngineError::UnsupportedTarget` -> `engine_unsupported_target` | `engine.rs:357,392`, `admin_engine.rs:33` |
| Admin transport | `admin_transport_unsupported: this platform has no validated private administration adapter` | `admin_transport.rs` not-supported arms |
| Trusted curl | `trusted_curl_unavailable` (fail closed, no process started) | `curl.rs:52`, `download.rs:1160` fallbacks |
| Command containment | `command_containment_unavailable` | unchanged |
| Flow default PATH | no Linux list; non-Windows falls to the macOS list | see 2.7 |

## 1. Dependencies and features

| # | File:line | Action |
| --- | --- | --- |
| 1.1 | `crates/pam_daemon/Cargo.toml:61-63` `[target.'cfg(target_os = "linux")'.dependencies] zbus-secret-service-keyring-store = { version = "=1.0.1", features = ["rt-tokio-crypto-rust"] }` | Delete the whole table (3 lines + comment). Only Linux-gated dependency in the workspace. |
| 1.2 | `crates/pam_daemon/Cargo.toml:29-32` comment on `keyring-core` ("per-OS backend crate below is the only one actually built") | Keep; optionally reword. `keyring-core = "=1.0.0"` stays (macOS/Windows stores need it). |
| 1.3 | `Cargo.toml:76` `tauri = { version = "2", default-features = false, features = ["wry", "x11"] }` and its comment ("`x11` keeps Linux building") | Change to `features = ["wry"]`; delete the `x11` clause from the comment. `x11` is inert on macOS/Windows. Verify with `cargo tree -p pam_gui -e features` after the edit. |
| 1.4 | `crates/pam/Cargo.toml`, `crates/pam_gui/Cargo.toml` | No Linux items (`tauri.workspace = true`). No change. |
| 1.5 | `crates/pam_daemon/Cargo.toml` `[target.'cfg(target_os = "macos")']` (apple keyring), `[target.'cfg(target_os = "windows")']` (windows keyring), `[target.'cfg(windows)'] getrandom` | Untouched. |
| 1.6 | `vendor/{zeromq,turso_core,aegis}` | Upstream code with their own Linux cfgs; leave. |
| 1.7 | `.cargo/config.toml:3-12` `[target.aarch64-unknown-linux-gnu] rustflags = ["-C","target-feature=+fp16"]` plus the comment paragraph | Delete the Linux table; reword the comment to name only `aarch64-pc-windows-msvc`. (The whole fp16 rationale cites candle, removed 2026-09-13; separate cleanup, not Linux-driven.) Line 17-18 comment "macOS and Linux give it 8 MiB" -> "macOS gives". |
| 1.8 | `frontend/package-lock.json` (144 lines mention linux; 36 `"os": ["linux"]` optional entries for esbuild/rollup/lightningcss/@tauri-apps/cli etc.) | Leave untouched. npm lists every platform's optional binary by design; regenerating would not drop them. |
| 1.9 | `.github/dependabot.yml` | github-actions only; no change. |

**What leaves Cargo.lock** (computed from the lock graph, not by building):

- 46 packages via removing the `pam_daemon -> zbus-secret-service-keyring-store` edge: `zbus-secret-service-keyring-store`, `secret-service`, `zbus`, `zbus_macros`, `zbus_names`, `zvariant`, `zvariant_derive`, `zvariant_utils`, `uds_windows`, `endi`, `enumflags2`, `enumflags2_derive`, `ordered-stream`, `zcheapstr`, `async-broadcast`, `async-channel`, `async-executor`, `async-lock`, `async-process`, `async-recursion`, `async-signal`, `async-task`, `blocking`, `event-listener`, `event-listener-strategy`, `piper`, `num`, `num-complex`, `num-iter`, `num-rational`, plus the RustCrypto 0.11-generation duplicate set only the Secret Service used: `aes`, `cbc`, `cipher`, `inout`, `block-buffer`, `block-padding`, `crypto-common`, `hybrid-array`, `digest 0.11.3`, `sha2 0.11.0`, `hmac 0.13`, `hkdf 0.13`, `const-oid 0.10`, `cmov`, `cpubits`, `ctutils`. (Side effect: `sha2` collapses to a single version, so dependents' `"sha2 0.10.9"` entries become `"sha2"`.)
- ~4 packages via dropping `x11` (estimate; confirm after `cargo update -w`/`cargo check`): `x11-dl`, `x11`, `gdkx11`, `gdkx11-sys`.
- Total ~50 packages, roughly 620 lock lines. Direct dependencies dropped: 1. Features dropped: 1 (`tauri/x11`).
- After the edit confirm each crate still builds alone (`cargo check -p pam_daemon`, `-p pam_store`): the Secret Service feature `rt-tokio-crypto-rust` pulled tokio features transitively; every crate here already requests its own, but a per-crate check proves it.

## 2. Source (`crates/`)

### 2.1 Systemd user unit — `crates/pam_client/src/service.rs`

Remove (all line numbers current):

- 1-2, 15: module docs mentioning systemd / "macOS and Linux" (reword to macOS + Windows).
- 33-34 `pub const SYSTEMD_UNIT`.
- 40 doc "on macOS and Linux" for `MANAGED_STOPPED_NOTE` (reword; value unchanged).
- 49-51 `Platform::Linux` variant; 64-65 `else if cfg!(target_os = "linux")` in `current()`; 78 `Self::Linux => "linux"` in `as_str()`. Linux hosts then report `Platform::Other`.
- 342-391 `render_systemd_unit`, `systemd_quote`, `systemd_exec_quote` (~50 lines).
- 523-545 `pinned_exe_from_systemd` (~23 lines).
- 581 `Platform::Linux => ...config/systemd/user` in `unit_path` (the arm `Windows | Other` stays).
- 670 `Platform::Linux => pinned_exe_from_systemd(text)`.
- 734-748 `Platform::Linux` status arm (`systemctl --user is-active`).
- 837-858 `write_linux_unit`, `register_linux`.
- 907, 913 install arms; 925 `matches!(env.platform, Platform::Macos | Platform::Linux)` -> `== Platform::Macos`; 945 `Platform::Macos | Platform::Linux` note arm -> `Platform::Macos`; 958-966 uninstall arm (`systemctl disable --now`, `daemon-reload`).
- Behaviour afterwards: on Linux `Platform::current()` is `Other`, `unsupported()` returns "linux has no login-start integration" (`service.rs:686`), `install`/`uninstall`/`status` return `ServiceState::Unsupported`. Legible, never silent.
- JSON contract: `Platform` serializes lowercase; `"linux"` disappears from the value set (frontend only displays it).

Tests, `crates/pam_client/src/service_test.rs`:

- Delete: `systemd_unit_restarts_on_failure_and_wants_default_target` (45), `systemd_unit_quotes_and_escapes...` (56), `linux_install_reloads_then_enables_now` (237), `linux_status_asks_is_active` (264), `linux_uninstall_disables_removes_reloads` (285), `systemd_specifiers_and_expansions_in_the_exe_path_stay_literal` (608); the systemd half of `the_pinned_executable_is_read_back_from_each_unit_format` (589-606); imports at 11-13 (`SYSTEMD_UNIT`, `pinned_exe_from_systemd`, `render_systemd_unit`).
- Retarget from `Platform::Linux` to `Platform::Macos` (generic behaviour tests that only borrowed Linux as a stand-in; unit path becomes `Library/LaunchAgents/com.github.ro-ag.pam.daemon.plist`, runner commands become `launchctl ...`): lines 412, 425, 436, 506, 532, 544, 626, 661, and the `.config/systemd` assertions at 517, 527, 545, 627. These need a careful rewrite, not a sed. (~140 lines removed, ~40 edited.)
- `crates/pam/src/render_test.rs:525-547`: two `ServiceReport { platform: "linux", unit: ".../systemd/user/pam-daemon.service" }` literals -> `platform: "macos"`, unit `/Users/me/Library/LaunchAgents/com.github.ro-ag.pam.daemon.plist`.
- Doc/help text: `crates/pam/src/main.rs:136-137` ("launch agent, systemd user unit, or scheduled task" -> "launch agent or scheduled task"; this is `--help` output), `main.rs:173` ("On macOS and Linux the manager stops..." -> "On macOS"), `crates/pam/src/lib.rs:12`, `crates/pam_gui/src/service.rs:68`. No test asserts the help text (grepped `crates/pam/tests`).

### 2.2 Keychain / Secret Service — `crates/pam_daemon/src/secrets.rs`

- 277-279 `#[cfg(target_os = "linux")] let store = zbus_secret_service_keyring_store::Store::new()...` delete.
- 280, 287 `not(any(macos, windows, linux))` -> `not(any(macos, windows))` (two places; same fallback body: warn + `SecretError::Unavailable`).
- Docs: 6 ("Secret Service on Linux"), 566-570 (the "Linux Secret Service client spins up its own runtime ... session bus ... stall" paragraph is the zbus/runtime workaround rationale; trim to the macOS-warm explanation), `crates/pam_daemon/src/daemon.rs:739` "or the Secret Service bus" **[dirty]**.
- `secrets_test.rs:169` `warm_on_non_macos_returns_immediately...` is generic non-macOS (Windows); keep.
- No Linux-specific code in `secrets_test.rs`.

### 2.3 Engine asset mapping — `crates/pam_model/src/engine.rs`

Linux:
- 47-50 `Target::UbuntuX64`, `Target::UbuntuArm64` (+ docs).
- 70-71 `("linux","x86_64")`, `("linux","aarch64")` in `for_platform`.
- 93-94 names `"ubuntu-x64"`, `"ubuntu-arm64"`.
- 135-146 the two `EngineAsset` rows (`llama-b10938-bin-ubuntu-x64.tar.gz` sha256 `adbd216b...`, 16_820_989 bytes; `...ubuntu-arm64.tar.gz` sha256 `647e257d...`, 13_449_176 bytes).
- 676-679 `#[cfg(target_os = "linux")] command.env("LD_LIBRARY_PATH", dir)` in `verify_build`; `engine_server.rs:729-732` same in the launcher (the Linux-only `LD_LIBRARY_PATH` for shipped `.so` files; macOS ships `.dylib` next to the binary).
- `ENGINE_ASSETS: [EngineAsset; 6]` (line 122) -> length after both removals (see 7 below: 4, or 3 if macOS x64 also goes).
- Tests: `engine_test.rs:26-27` rows, `engine_test.rs:58` `layout.server_path("b1", Target::UbuntuX64)` -> use `Target::MacosArm64`; `qualification_test.rs:157` `find_in(RECORDS,"abc",Target::UbuntuX64).is_none()` ("Metal figures do not qualify a CPU build") -> `Target::WinCpuX64`, assertion message unchanged.
- Unsupported-OS behaviour: `Target::current()` -> `None` -> `unsupported_target` (see table).

Other engine-adjacent strings:
- `crates/pam_model/tests/engine_live.rs:6` doc "macOS/Linux" -> "macOS". `crates/pam_model/src/engine_test.rs` name `every_ci_runner_maps_to_exactly_one_pinned_asset` can stay.

### 2.4 Admin transport, curl trust, other `target_os` gates (cfg swaps)

Mechanical rewrite rules: `any(target_os = "macos", target_os = "linux")` -> `target_os = "macos"`; `any(target_os = "macos", target_os = "linux", windows)` -> `any(target_os = "macos", windows)`; `not(any(... "linux" ...))` -> drop "linux" from the list. Sites:

- `crates/pam_daemon/src/admin_transport.rs` **[dirty]** lines 28, 40, 47 (`supported()`), 53, 76, 83, 91, 99, 103, 115, 119. `admin_transport_unix.rs:1` doc "macOS/Linux" -> "macOS". The Unix adapter module stays; it is gated on macOS rather than `unix`, so Linux gets the `admin_transport_unsupported` refusal. (Alternative: gate on `unix`; rejected, it keeps Linux admin alive.)
- `crates/pam_connectors/src/curl.rs:32, 52`; `curl_test.rs:94, 161, 173, 199, 236`.
- `crates/pam_model/src/download.rs:454` doc (`On macOS and Linux that is /usr/bin/curl` -> macOS), `1125, 1160`; `download_test.rs:389`.
- `crates/pam_testkit/tests/admin.rs:314, 344, 370, 421` and doc line 3; `crates/pam_gui/tests/bridge.rs:21, 68, 90, 117`; `crates/pam_gui/tests/model_checkpoint.rs:15` (and doc 12); `crates/pam/tests/cli.rs:1098, 1106` (+ comment 1095, 103); `crates/pam/tests/live_subscribe.rs:192` doc; `crates/pam_testkit/src/lib.rs:112` doc; `crates/pam_daemon/tests/daemon.rs:202` doc.
- Net effect on the Ubuntu runner: these gates now compile out; irrelevant because no Linux runner remains.

### 2.5 Lazy-daemon environment allowlist and spawn path — `crates/pam_client/src/client.rs`

- 413-415: `// Secret Service / keyring access on Linux.` + `"XDG_RUNTIME_DIR"`, `"DBUS_SESSION_BUS_ADDRESS"` — delete the three lines. Doc text above (the const's doc, "few platform variables the OS credential stores ... need") stays true for macOS/Windows.
- 104-124: `daemon_exe()` strips the Linux ` (deleted)` suffix (`cfg!(target_os = "linux")`). Delete the Linux branch; the function reduces to `std::env::current_exe()` and, as its only caller is `real_spawner` at line 102, inline it and delete the `pub fn daemon_exe` (no tests or other callers; grep-verified). Fix the doc on `real_spawner` accordingly.
- `docs`/comments of the same Linux `(deleted)` fact: `crates/pam_daemon/src/image.rs:32` and `daemon.rs:406` **[dirty]** ("names a deleted file on Linux"). The boot-image-path design is still right on macOS (rename-into-place install changes the inode but `current_exe()` stays valid); reword the comments to drop the Linux claim, keep the behaviour.
- `crates/pam_daemon/src/framed_unix.rs:11` **[dirty, untracked]**: comment "`SO_PEERCRED` on Linux" -> macOS only (`LOCAL_PEERCRED`).

### 2.6 Trusted-directory and curl path lists

- `crates/pam_model/src/curator.rs:206` `"/home/linuxbrew/.linuxbrew/bin"` — delete the entry. Keep `/usr/bin`, `/bin`, `/usr/local/bin`, `/opt/homebrew/bin` (all exist on macOS) and every `$HOME/...` entry (cross-platform).
- `curl` paths: `/usr/bin/curl` is the macOS path; no Linux-only path lists exist in `curl.rs` or `download.rs`.
- `crates/pam_daemon/src/flow_exec.rs:709` doc "launchd or systemd" -> "launchd"; `flow_service.rs:274` doc "launchd or systemd" -> "launchd".

### 2.7 Default flow PATH — `crates/pam_daemon/src/flow_service.rs:279-285`

The `else` arm is the Linux/other default `["~/.cargo/bin", "~/.local/bin", "/usr/local/bin"]`. Replace the three-way chain with `if windows { [%USERPROFILE%\.cargo\bin] } else { macOS list }` so the macOS list is the Unix default and `~/.local/bin` leaves with Linux. Unit tests (`flow_service_test.rs:99-112, 161, 412-420`) assert only non-emptiness and the cargo caches; no change needed.

### 2.8 Runtime dir, socket path, other items checked and found Linux-free

- `runtime_dir.rs`, `ingress.rs`, `public_transport.rs`, `framed*.rs`, `transport.rs`: no `target_os = "linux"` cfg; only the doc line above. Tests under `/tmp` for the 104-byte `sun_path` cap (`tests/transport.rs:15-22`, `tests/daemon.rs:36-43`, `engine_live.rs:30`) are the macOS limit (Linux's is 108); keep.
- `crates/pam_daemon/tests/transport_stress.rs:337-340` is the one genuinely Linux-only test code: `#[cfg(not(target_os = "macos"))] let thread_count = read_dir("/proc/{pid}/task")`. On Windows it silently yields `None`. Replace with `#[cfg(not(target_os = "macos"))] let thread_count: Option<usize> = None;`.
- `crates/pam_daemon/tests/flow_containment.rs`, `command_containment*.rs`, `landing_checkout_test.rs:276`: `not(target_os = "macos")` arms = Windows after this change; leave.
- `crates/pam/gen/schemas/*.json`: generated, git-ignored; ignore.
- No Linux code in `pam_flow`, `pam_compact`, `pam_proto`, `pam_store`.

## 3. Tests: Linux-only vs harmless

| Item | Where | Class | Action |
| --- | --- | --- | --- |
| systemd render/status/install tests | `service_test.rs` (see 2.1) | Linux-only | delete |
| Generic service tests using `Platform::Linux` as stand-in | `service_test.rs` 412-661 | Linux-coupled | retarget to macOS |
| `ServiceReport` fixtures `platform:"linux"` | `render_test.rs:525-547` | Linux-coupled | retarget to macOS |
| Ubuntu engine rows | `engine_test.rs:26-27,58`; `qualification_test.rs:157` | Linux-only | delete/retarget |
| ETXTBSY retry wrappers `invoke_fresh`/`detect_fresh` | `crates/pam_model/src/curator_test.rs:80-124` (10 call sites: 147, 239, 252, 270, 287, 313, 530, 557) | Linux-observed harness race (comments say "On Linux ...") | remove wrappers, call `invoke`/`detect_in` directly |
| ETXTBSY retry wrappers `cli`/`verify_aws` | `crates/pam_connectors/src/aws_test.rs:373-410` (10 call sites) | same | remove wrappers, call `call_once`-equivalents directly |
| `/proc/{pid}/task` thread probe | `transport_stress.rs:337-340` | Linux-only | see 2.8 |
| `any(macos,linux)` gated tests/helpers | see 2.4 | shared | cfg swap, not deleted |
| `cfg(unix)`/`not(unix)` tests and `/tmp` short paths | many | shared with macOS | keep |
| `download_test.rs:911` `LD_PRELOAD=/tmp/evil.so` env-scrub test | `download_test.rs:911` | generic Unix hygiene | keep |
| zbus runtime workaround | only in `secrets.rs` doc 566-570 | prose only | trim (2.2) |

ETXTBSY risk note (flag, not blocking): the race (a forked-but-not-yet-exec'd child holding the script's `O_CLOEXEC` write fd) is POSIX, not Linux-specific; it was *observed* on Linux CI per the comments, and the macOS test runs here did not need it. Per the owner's instruction these are removed. If a macOS flake with "Text file busy" ever appears, reinstate the wrappers (they are 35 lines each).

## 4. Packaging and release

### 4.1 Tauri bundle config and assets

- `crates/pam/tauri.linux.conf.json` (9 lines, `targets: ["appimage","deb"]`, `linux.deb.desktopTemplate`) — delete the file.
- `crates/pam/linux/pam.desktop` (12-line Handlebars desktop-entry template) — delete the file and the `linux/` directory.
- `crates/pam/src/config_test.rs` (assign to the packaging set; compile-coupled to the two deletions): remove line 10 `const LINUX_CONF = include_str!("../tauri.linux.conf.json")`, line 12 `const DESKTOP_TEMPLATE = include_str!("../linux/pam.desktop")`, lines 124-127 (the Linux assertion in `platform_overlays_name_pam_olds_targets`), and the first assertion in `desktop_entry_and_shortcuts_open_the_gui` (line 140 `DESKTOP_TEMPLATE.lines().any(...)`; keep the NSIS hook assertions). Test names stay.
- `crates/pam/tauri.conf.json`: no Linux keys (`bundle.icon` carries `icon.png` used by Linux and the macOS/Windows icons; `icon.png` is also the source for the others—keep). `tauri.macos.conf.json`, `tauri.windows.conf.json`, `capabilities/main-window.json`, `nsis/`: untouched.
- `tools/`: contains no Linux packaging: `check.sh`, `package-macos-dmg.sh`, `dmg/*`, `screen-model.py` (macOS-only). Nothing to remove. (`check.sh` header says "CI does not duplicate it"; stale since plan #3, not a Linux item.)
- `.cargo/config.toml`: see 1.7.

### 4.2 Workflow inventory (as-is)

`.github/workflows/ci.yml` (jobs):

| Job | Runner | What it does | Class |
| --- | --- | --- | --- |
| `gate` (22-60) | `ubuntu-24.04` | apt Tauri deps, rust+cache, node, `tools/check.sh` (fmt, clippy, doc, vendor zeromq tests, `cargo test --workspace`, eslint, tsc+vite, vitest); emits the desktop-package matrix | the cheap gate |
| `targets` (62-91) | matrix `ubuntu-24.04-arm, macos-15, windows-2025, windows-11-arm` | apt deps (Linux rows), `cargo test --workspace` with `PAM_ENGINE_LIVE=1`; macOS row also builds `--features gui-embed` | per-target tests |
| `desktop-packages` (92-242) | matrix from `gate` output: PR = `linux_amd64` only; non-PR = linux amd64, linux arm64, windows amd64, windows arm64 | `tauri build`, then "Verify Linux package contract" (121-172) or "Verify Windows package contract" (173-221), tars Linux bundles (230-235), uploads `pam-linux-*`/`pam-windows-*` | Linux product jobs (2 of 4 rows) + Windows |
| `macos-package` (243-298) | `macos-15` | unsigned dmg preview, non-PR only | macOS product |

`.github/workflows/release.yml` (jobs): `validate` (16-86, ubuntu-24.04), `build` (88-168, matrix: Linux amd64, Linux arm64 on ubuntu runners + Windows amd64/arm64: download CI artifact, repackage), `macos` (170-302, macos-15, sign+notarize), `release` (304-end, ubuntu-24.04: download all, `sha256sum * > checksums.txt`, changelog extract, `gh release create`).

### 4.3 CI restructure (no Linux runner anywhere)

Decisions: the cheap gate moves to the macOS arm64 runner; Windows jobs stay gated behind it with `needs:`; concurrency-cancel, path filters (`paths-ignore`), `cancel-in-progress`, rust-cache and node caching are unchanged. Runner label `macos-15` (arm64) is already used by the repo.

`ci.yml` line-by-line:

| Line(s) | Change |
| --- | --- |
| 23 `runs-on: ubuntu-24.04` | `runs-on: macos-15` |
| 24 `timeout-minutes: 30` | raise to 45 (full `check.sh` incl. macOS-only sandbox tests on a hosted arm64 runner; matches `targets`) |
| 29-32 "Tauri system deps" apt step (gate) | delete |
| 33-35 comment + `dtolnay/rust-toolchain`, 36-37 rust-cache, 38-43 node, 44-45 `npm ci`, `tools/check.sh` | keep as is |
| 46-60 "Choose the desktop packages" | delete vars `linux_amd64` (51), `linux_arm64` (52); line 58 PR matrix -> `[$windows_amd64]`; line 60 -> `[$windows_amd64,$windows_arm64]`. Comment 55-56 stays accurate ("cheapest package only" on PRs). Shell is `bash` 3.2 on macOS; the script uses no bash-4 features. |
| 68 `os: [ubuntu-24.04-arm, macos-15, windows-2025, windows-11-arm]` | `os: [macos-15, windows-2025, windows-11-arm]` |
| 72-75 `if: startsWith(matrix.os, 'ubuntu')` apt step (targets) | delete |
| 80-83 `cargo test --workspace` with `PAM_ENGINE_LIVE: "1"` | add `if: runner.os == 'Windows'` (macOS already runs the full workspace test inside `gate`); add a macOS-only step `if: runner.os == 'macOS'`: `cargo test -p pam_model --test engine_live` with `env: PAM_ENGINE_LIVE: "1"` (keeps the live llama.cpp proof on arm64). Simpler alternative if the owner prefers zero logic: leave the step unconditional (macOS tests run twice; minutes are not billed). |
| 84-91 macOS `gui-embed` build steps | keep |
| 102-107 "Tauri system deps" (`matrix.family == 'linux'`) in `desktop-packages` | delete |
| 121-172 "Verify Linux package contract" | delete (52 lines: readelf/dpkg-deb/AppImage extraction) |
| 173-174 `if: ${{ matrix.family == 'windows' }}` on the Windows contract | may stay (family is always windows now) or drop the condition |
| 222-236 "Record package output": the `if [[ "$RUNNER_OS" == "Linux" ]]` branch (230-235) | delete branch; keep `echo "path=$bundle" >> "$GITHUB_OUTPUT"` |
| 239 `name: ${{ matrix.artifact }}` upload | keep (now only `pam-windows-amd64/arm64`) |
| `macos-package` (243-298) | unchanged; `needs: [gate, targets]` stays. Its `gate` dependency now means the macOS gate. |

`release.yml` line-by-line:

| Line(s) | Change |
| --- | --- |
| 18 `validate: runs-on: ubuntu-24.04` | `macos-15` (uses only checkout, bash, awk, `node -p`, `git`, `gh`; all present on macOS runners; the version regex and `awk` section parser are POSIX-safe on BSD awk) |
| 80 `for artifact in pam-linux-amd64 pam-linux-arm64 pam-windows-amd64 pam-windows-arm64 pam-macos-arm64` | drop the two `pam-linux-*` names |
| 96-107 Linux matrix rows (two entries) | delete |
| 135-151 "Assemble Linux release archive" step | delete (the `.tar.gz` of AppImage + deb) |
| 153 `if: ${{ matrix.family == 'windows' }}` | optional drop |
| 165 `name: pam-${{ matrix.family }}-${{ matrix.arch }}` | keep (windows-amd64/arm64) |
| 307 `release: runs-on: ubuntu-24.04` | `macos-15` |
| 326 `sha256sum * > checksums.txt` | `shasum -a 256 * > checksums.txt` (macOS has no `sha256sum`; output format is identical, two spaces, so `sha256sum -c` still verifies for users) |
| rest of `release` (download-artifact, awk release notes, `gh release create dist/*`) | keep; `dist/*` now holds one dmg + two Windows zips + `checksums.txt` |

Required-check implication: only `targets (ubuntu-24.04-arm)` disappears from the required set (section 0.1); `Linux amd64 package` / `Linux arm64 package` are not required contexts.

## 5. Frontend

- `frontend/src/screens/Settings.tsx:383` doc comment "LaunchAgent, systemd user unit, scheduled task" -> drop "systemd user unit". No behaviour: the card renders `status.state.unit` and `platform` as received.
- `frontend/src/screens/Settings.test.tsx:750, 788, 812` fixtures `platform: "linux"`, `exe: "/usr/bin/pam"`, `unit: "/home/me/.config/systemd/user/pam-daemon.service"`, error text "systemctl --user disable --now refused" (754, 792, 819, plus the assertion on the same string) -> `platform: "macos"`, exe `/Applications/pam.app/Contents/MacOS/pam`, unit `/Users/me/Library/LaunchAgents/com.github.ro-ag.pam.daemon.plist`, `launchctl bootout refused`.
- `frontend/src/components/shell/shell.test.tsx:51-54` `stubTrafficLights(false)` uses UA `"Mozilla/5.0 (X11; Linux x86_64)"` as the "not a Mac" stand-in -> use a Windows UA (`"Mozilla/5.0 (Windows NT 10.0; Win64; x64)"`). `Sidebar.tsx:67 navigator.userAgent.includes("Mac")` is the macOS-vs-everything-else switch Windows needs; keep.
- No platform switches, install copy or AppImage text anywhere else in `frontend/src` (grepped). `frontend/dist` is git-ignored.
- `frontend/src/screens/EngineCard.test.tsx` uses `aarch64-apple-darwin`: arm64 macOS, keep.

## 6. Docs

README.md:
- 39 table row `| Linux | amd64, arm64 | AppImage or .deb | /usr/bin/pam |` — delete the row. Add one sentence under "## Install" (line ~34): "Supported platforms: macOS (Apple Silicon) and Windows (amd64, arm64)."
- 116 "Start at login" row `| Linux | systemd user unit at ~/.config/systemd/user/pam-daemon.service |` — delete.
- 139 comment `# platform bundles (dmg, AppImage/deb, NSIS)` -> `(dmg, NSIS)`.
- The CI badge/other text: no Linux claims.

docs/ (current, non-historical) sentences to change:
- `docs/admin-boundary.md:15` "On macOS and Linux, the native GUI client uses a separate Unix socket..." -> "On macOS ...". `:76` "(... `PAM_BASE_DIR`, and on Linux the keyring session variables)" -> delete the clause.
- `docs/command-containment.md:11` "Linux and Windows command containment is not implemented" -> "Windows command containment ...". `:13` "uses the trusted system curl on macOS/Linux" -> "macOS". `:15` list of curator directories: remove "linuxbrew".
- `docs/model-qualification-decisions.md:17` table row label "`ubuntu-*`, `macos-x64`, `win-cpu-*`" -> "`win-cpu-*`"; `:93` "adding `ubuntu-x64` to the record without a run on that backend is not permitted" -> reword to a generic "adding a target"; `:146` "Linux and Windows measurements" -> "Windows measurements".
- `docs/agent-companion-roadmap.md:50` ("qualification on Linux/Windows targets" in the Models row) -> "Windows".
- `docs/enterprise-evidence-checkpoint.md:54` (history: "gate, macOS, Ubuntu ARM and both Windows targets", run id) — dated record; leave.
- `docs/native-build-dependencies.md`, `docs/macos-sandbox-acceptance.md`, `docs/session-socket-relay.md`, `docs/guarded-landing.md`, `docs/pam-playbook.md`: no Linux claims.

Historical (leave; do not edit; for awareness): `docs/vision.md:47-48` (Linux Secret Service), `:215` (the only "Target platforms (owner decision): darwin arm64 · linux amd64/arm64 · windows ..." statement, **this is the supported-platform line**; README's Install sentence above supersedes it, optionally add a one-line superseded note there), `:439`; every file under `docs/plans/` and `docs/specs/` (`2026-09-01-model-layer.md:145,167,186,190`, `2026-09-03-packaging.md:19,2115-2116,2457`, `2026-09-01-spine-design.md:36,129,194`, `2026-09-02-flows-connectors-design.md:27,278,299,305`, `2026-09-03-packaging-design.md:9,268,286`, `2026-09-09-local-model-triage.md:24`, `2026-09-10-model-admission-and-qualification.md:155`, `2026-09-13-llama-cpp-engine.md:29,74`, `2026-10-02-framed-public-transport.md:800,1415` — the last is the in-flight branch's spec); `docs/benchmarks/**` (a fixture log with `target=linux-x86_64`, data); `fixtures/incidents/**/source.log:12` (fixture bytes pinned by SHA-256; never touch).

CHANGELOG.md — under `## [Unreleased]` (heading at line 7; sections Added 9, Changed 41, Fixed 110, Compatibility 159) add a new `### Removed` section before `### Compatibility`:

```
### Removed

- Linux is no longer a supported platform. pam now ships for macOS (Apple
  Silicon) and Windows (amd64, arm64). The AppImage and deb packages, the
  systemd user unit behind `pam service`, the Secret Service credential
  store and the Ubuntu llama.cpp engine assets are gone; on Linux, `pam
  service` reports that login-start is unsupported, connector secrets report
  the credential store as unavailable, and the engine reports
  `unsupported_target`.
- Intel Macs (x86_64) are no longer supported; the macOS x64 llama.cpp engine
  asset is removed and `pam engine` reports `unsupported_target` there.
```
and one `### Compatibility` bullet: "`pam service status --json` no longer reports `\"platform\": \"linux\"`." Released history (CHANGELOG 272, 348, 518-525) stays.

Agent rule files (list only, no edits proposed beyond a note to the coordinator): `CLAUDE.md:101,104-105` and `AGENTS.md:101,104` ("lint and portable unit tests on Linux only ... `needs:` the cheap Linux checks first"; CLAUDE.md also "ci.yml runs the Linux gate"). These now contradict the CI shape (macOS gate). The same wording exists in `~/.claude/CLAUDE.md` and `~/dev/ai` rules (outside the repo, not read here).

## 7. ptrack / roadmap references (no edits; for the coordinator)

- Docs that cite Linux qualification gates / measurements: `docs/model-qualification-decisions.md:17,93,146`; `docs/agent-companion-roadmap.md:50` (open-items cell); `docs/specs/2026-09-10-model-admission-and-qualification.md:155` ("Linux and Windows builds stay unqualified until measured there").
- `docs/plans/2026-09-01-model-layer.md:145` and `docs/plans/2026-09-03-packaging.md:2455-2458` record the required-check names (`targets (ubuntu-24.04-arm)` ...).
- `.ptrack/agent-handoff.md:9` mentions "gate, ubuntu-24.04-arm, macos-15 ..." (git-ignored state).
- `MEMENTO.md`: no Linux lines. Memory file `docs-only-prs-need-admin-merge` states the five required contexts and will need updating after protection changes.

## 8. Intel Mac (x86_64-apple-darwin) inventory

Everything Intel-specific is small; CI/release/tauri were already arm64-only.

| File:line | What | Action |
| --- | --- | --- |
| `crates/pam_model/src/engine.rs:45-46` | `Target::MacosX64` variant, doc "Intel macOS." | delete |
| `engine.rs:69` | `("macos","x86_64") => Some(Self::MacosX64)` | delete; `("macos","x86_64")` then falls to `_ => None` -> `unsupported_target` |
| `engine.rs:92` | name `"macos-x64"` | delete |
| `engine.rs:129-134` | `EngineAsset` `llama-b10938-bin-macos-x64.tar.gz`, sha256 `13179741dd10cc0642cc5d09a69a08b6e3f59af40e70d4803c9f6f0b5a0bc10a`, 11_194_750 bytes | delete |
| `engine.rs:122` | `ENGINE_ASSETS: [EngineAsset; 6]` | `[EngineAsset; 3]` (MacosArm64, WinCpuX64, WinCpuArm64) once Ubuntu x2 and macOS x64 are all removed |
| `engine.rs:100-105` `server_file_name` | `_ => "llama-server"` | unchanged |
| `engine_test.rs:25` | `("macos","x86_64", Target::MacosX64)` row | delete; add `assert_eq!(Target::for_platform("macos","x86_64"), None)` and `("linux","x86_64")` -> `None` next to the existing freebsd assertion |
| `docs/model-qualification-decisions.md:17` | `macos-x64` in the "not qualified" row | drop the target (see 6) |
| `docs/specs/2026-09-13-llama-cpp-engine.md:29` | asset list names macos-x64 | historical spec; leave |
| `frontend/src/components/shell/shell.test.tsx:52` | `"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"` | this is the standard macOS user agent string even on Apple Silicon; keep |
| `crates/pam_client/src/service_test.rs:453`, `frontend/.../EngineCard.test.tsx:30,44,91` | `aarch64-apple-darwin` | arm64; keep |
| `tauri.macos.conf.json`, `.github/workflows/*.yml`, `tools/package-macos-dmg.sh` | already `aarch64-apple-darwin`/`macos-15`/`arm64`; no `x86_64-apple-darwin`, no `universal-apple-darwin`, no `lipo` universal step, no `consts::ARCH` arm other than `engine.rs:61` | nothing to remove |
| `README.md:38` | macOS row already says `arm64` | no change |
| `crates/pam_daemon/tests/incident_support/mod.rs:82`, `crates/pam_model/tests/engine_live.rs:107` | report `consts::ARCH` into JSON | not target arms; keep |
| `tools/screen-model.py:261` | `sys.platform != "darwin"` guard | not arch specific; keep |

CHANGELOG wording for Intel is in section 6. Windows amd64/arm64 untouched.

## 9. Ordered removal plan (three disjoint file-ownership sets)

Order: A and B and C are independent in files; apply A first (compiles/tests), B second (needs A merged only for the `config_test.rs` + deletion coupling, which is inside B itself), C last (docs describe the final state). Preferred: three separate PRs, merged A -> B -> C; or one PR if the coordinator wants it atomic. B's PR needs `--admin` (section 0.1), then update the ruleset.

### Set A — Rust source and Cargo (38 source/test files + 3 manifests)

Files: `Cargo.toml`, `Cargo.lock`, `crates/pam_daemon/Cargo.toml`;
`crates/pam_daemon/src/{secrets.rs, daemon.rs[dirty], admin_transport.rs[dirty], admin_transport_unix.rs, image.rs, flow_service.rs, flow_exec.rs, framed_unix.rs[dirty]}`, `crates/pam_daemon/tests/{transport_stress.rs, daemon.rs}`;
`crates/pam_testkit/src/lib.rs`, `crates/pam_testkit/tests/admin.rs`;
`crates/pam_model/src/{engine.rs, engine_server.rs, engine_test.rs, qualification_test.rs, curator.rs, curator_test.rs, download.rs, download_test.rs}`, `crates/pam_model/tests/engine_live.rs`;
`crates/pam_client/src/{service.rs, service_test.rs, client.rs}`;
`crates/pam_connectors/src/{curl.rs, curl_test.rs, aws_test.rs}`;
`crates/pam/src/{main.rs, lib.rs, render_test.rs}`, `crates/pam/tests/{cli.rs, live_subscribe.rs}`;
`crates/pam_gui/src/service.rs`, `crates/pam_gui/tests/{bridge.rs, model_checkpoint.rs}`.

Steps: (1) Cargo manifests + lock regen (`cargo update -w` style minimal; confirm lock diff is only removals). (2) secrets, engine (+ Intel), service, client, curl/download/admin_transport cfg swaps, curator, flow_service. (3) tests and retargets. (4) doc-comment rewording. (5) the three **[dirty]** files last or after the framed-transport branch merges.

Acceptance:
- macOS: `cargo clippy --workspace --all-targets -- -D warnings` on touched crates first (memento clippy-before-full-gate), then `bash tools/check.sh` green.
- Windows VM (Parallels, per owner directive): `cargo check --workspace --all-targets` clean on amd64 and, where available, arm64.
- Greps return nothing: `grep -rn 'target_os = "linux"\|zbus\|SYSTEMD_UNIT\|Platform::Linux\|UbuntuX64\|UbuntuArm64\|MacosX64\|XDG_RUNTIME_DIR\|DBUS_SESSION' crates Cargo.toml`.
- `git diff Cargo.lock` shows only deleted packages and `sha2` reference simplifications.

### Set B — CI, release, packaging (6 files)

Files: `.github/workflows/ci.yml`, `.github/workflows/release.yml`, `crates/pam/tauri.linux.conf.json` (delete), `crates/pam/linux/pam.desktop` (delete), `crates/pam/src/config_test.rs`, `.cargo/config.toml`.

Acceptance:
- macOS: `cargo test -p pam --lib config_test` (the `include_str!` set resolves) and `bash tools/check.sh`.
- `actionlint` (if available) or `gh workflow view` parse; no `ubuntu` or `linux` token left: `grep -n 'ubuntu\|linux\|apt-get\|appimage\|\.deb' .github/workflows/*.yml` empty.
- On the PR run: `gate` (macos-15) green, `targets (macos-15|windows-2025|windows-11-arm)` green, one `Windows amd64 package` job green. Confirm `release.yml` with a dry parse; it is only exercised on a tag, which the owner must request.
- After merge: ruleset required contexts reduced to `gate`, `targets (macos-15)`, `targets (windows-2025)`, `targets (windows-11-arm)` (coordinator).

### Set C — docs and frontend (9 files)

Files: `README.md`, `CHANGELOG.md`, `docs/admin-boundary.md`, `docs/command-containment.md`, `docs/model-qualification-decisions.md`, `docs/agent-companion-roadmap.md`, `frontend/src/screens/Settings.tsx`, `frontend/src/screens/Settings.test.tsx`, `frontend/src/components/shell/shell.test.tsx`.

Acceptance: `npm --prefix frontend run lint && npm --prefix frontend run build && npm --prefix frontend run test` (all inside `tools/check.sh`); `grep -rni 'linux\|systemd\|appimage' README.md CHANGELOG.md docs/*.md frontend/src` leaves only the CHANGELOG `Removed` text, released changelog history, and the deliberately-historical `docs/enterprise-evidence-checkpoint.md:54` / `docs/vision.md`.

Docs-only parts of Set C go through `--admin` merge if that PR touches only markdown (memory: docs-only PRs); the frontend test edits make it a normal PR.

### What the Linux situation is after the change

No Linux runner remains in either workflow. The workspace is not expected to build or pass on Linux: `pam_gui`/`pam` will not link without the GTK/webkit system libraries and the `x11` feature, and the admin transport, credential store, service manager, engine and curl trust all refuse at runtime with the causes in the table in section 0.

## 10. Totals

| | Files touched | Approx. lines removed | Notes |
| --- | --- | --- | --- |
| Set A (Rust + Cargo) | 41 (38 source/test + `Cargo.toml`, `Cargo.lock`, `pam_daemon/Cargo.toml`) | ~490 source/test, ~620 lock, 6 manifest | ~60 further lines edited (cfg swaps, retargeted tests) |
| Set B (CI/release/packaging) | 6 (2 deleted) | ~105 workflow, 21 deleted files' content, ~10 `.cargo`, ~14 `config_test.rs` | |
| Set C (docs + frontend) | 9 | ~25 prose, ~10 test fixture lines edited | CHANGELOG +~14 added |
| **Total** | **56 files (2 deleted)** | **~1,290 lines removed (about 620 of them Cargo.lock)** | |

Dependencies dropped: 1 direct crate (`zbus-secret-service-keyring-store`), ~50 lock packages (46 certain, ~4 `x11` estimate), 1 Tauri feature (`x11`), 1 `.cargo` target table, 2 workflow matrix rows (Ubuntu ARM tests, two Linux packages), 2 release matrix rows, 4 apt install steps.
