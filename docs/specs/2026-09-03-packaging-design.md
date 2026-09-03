# Packaging + OS integration — design

Plan #9. Owner decisions recorded 2026-09-03. Companion plan:
`docs/plans/2026-09-03-packaging.md`.

## Scope

Ship `pam` the way pam-old shipped, on the five first-class targets
(darwin arm64, linux amd64/arm64, windows amd64/arm64), and give the
daemon a user-scope login-start integration with a CLI and a GUI surface.
No tag is cut by this plan; it delivers the pipeline, the packages, and
the docs a first tag needs.

## Decisions (owner-approved)

- **Replicate pam-old's packaging and release.** "It is the only thing
  done well." The Tauri CLI owns the `pam` binary again, bundles are the
  same per platform (Linux `appimage` + `deb`, Windows `nsis` per-user,
  macOS `app` + a dmg built by `tools/package-macos-dmg.sh`), CI builds
  packages and verifies a package contract per platform, and a separate
  `release.yml` on `v*` tags reuses the artifacts of the green CI run on
  the tag commit: validate, repackage, sign + notarize macOS, checksums,
  release notes from the changelog, `gh release create --verify-tag`.
- **Signing is required, not optional.** Like pam-old (and the owner's
  `rust-multiplatform-ci` notes): the macOS release job fails closed when
  the Apple secrets are missing. The six secrets are pushed by the owner
  with `~/dev/apple-developer-signing/setup-github-secrets.sh ro-ag/pam`
  before the first tag; agents never handle credential material.
- **Windows keeps the console subsystem.** Deviation from pam-old
  (windowed in release): v2 agents drive the CLI on Windows, and a
  windowed binary prints nothing to a terminal. Cost accepted: launching
  the GUI from the Start menu shows a console window behind it. A
  console-attach fix is deferred.
- **CI: best of both.** This repo's `gate` (tools/check.sh) and `targets`
  jobs stay the test gate. From pam-old: pinned action SHAs with version
  comments, `permissions: contents: read`, `workflow_dispatch`, job
  timeouts, PR-only `cancel-in-progress`, the `desktop-packages` matrix
  and `macos-package` jobs with their contract checks, 7-day artifacts,
  and `dependabot.yml` for `github-actions` (weekly) to keep the pins
  fresh. Not ported: the `foundation` job's already-tested skip, the
  required-docs check (folded into the release validation), and
  `tools/ci/test-timeout-tolerance.sh` (this repo handles flakes at the
  harness level).
- **Package builds cost:** the full desktop matrix and the macOS package
  run on `main` pushes and `workflow_dispatch`; pull requests build only
  the Linux amd64 package (cheapest runner) to catch bundling and
  desktop-entry regressions before merge. The release reuses `main`
  artifacts only.
- **Login-start is user scope only** (spine spec): macOS LaunchAgent,
  systemd user unit, Windows per-user scheduled task. Never sudo, admin,
  or root. Surface: `pam service install | uninstall | status` and a
  "Start at login" row in Settings › Daemon (GUI-observatory law).
- **Docs:** README.md, CHANGELOG.md (Keep a Changelog), LICENSE
  (Apache-2.0, as Cargo.toml declares), in pam-old's format adapted to
  the v2 CLI. The pam-old mark (`docs/assets/pam-mark.svg`) is reused.
- **Repo settings copied from pam-old** where they differ: description,
  branch protection on `main` (required checks `gate` and the four
  `targets (...)` checks, force pushes and deletions blocked). Not
  copied: GitHub Pages and the `github-pages` environment (pam-old's help
  site is documentation work, not packaging; deferred).

## Deferred (recorded, not built now)

- Help site on GitHub Pages.
- Windows console-attach so a Start-menu launch shows no console.
- The already-tested main-run skip and the timeout-tolerance test runner.
- Homebrew tap / winget / apt repository.
- Auto-update.

## Crate layout: `crates/pam` becomes the Tauri app crate

Today `crates/pam_gui` holds `tauri.conf.json`, `build.rs` (tauri-build),
`icons/`, `capabilities/`, `permissions/`, `gen/`, and calls
`tauri::generate_context!()` inside a library. The Tauri CLI expects the
directory holding `tauri.conf.json` to be the crate that produces the
binary named `mainBinaryName`. pam-old solved this with `src-tauri`
owning the `pam` binary; v2 does the same with `crates/pam`:

- Move `tauri.conf.json`, `icons/`, `capabilities/`, `permissions/`,
  `build.rs`, and the gitignored `gen/` from `crates/pam_gui` to
  `crates/pam`. `frontendDist` stays `../../frontend/dist`, `devUrl`
  stays `http://127.0.0.1:1420`, `mainBinaryName` stays `pam`,
  `bundle.active` becomes `true` with pam-old's `category`, `publisher`,
  `copyright`, `shortDescription`, `longDescription`, and icons.
- Add per-platform overlays exactly as pam-old: `tauri.macos.conf.json`
  (`targets: ["app"]`, `minimumSystemVersion: "12.0"`),
  `tauri.linux.conf.json` (`targets: ["appimage", "deb"]`, plus a
  `desktopTemplate` whose `Exec` is `pam gui`), `tauri.windows.conf.json`
  (`targets: ["nsis"]`, `installMode: "currentUser"`,
  `allowDowngrades: false`, and an NSIS post-install hook that rewrites
  the Start-menu and desktop shortcuts to run `pam.exe gui`).
- `crates/pam/Cargo.toml` gains `tauri` (dependency) and `tauri-build`
  (build dependency); feature `gui-embed = ["tauri/custom-protocol",
  "pam_gui/embed"]` keeps the manual production path
  (`npm run gui:build`) working. `tauri build` enables
  `tauri/custom-protocol` itself.
- `pam_gui::run(context: tauri::Context)`: the context is generated by
  the app crate (`pam_gui::run(tauri::generate_context!())` in
  `main.rs`); the command list and the Tauri builder stay in `pam_gui`.
  `build.rs`'s `AppManifest::commands` list moves with it, so the ACL
  manifest is still generated from one list.
- The config-sanity tests in `crates/pam_gui/src/lib_test.rs` move to
  `crates/pam/src/config_test.rs` (declared from `lib.rs`), reading the
  moved files. The Rust rule stands: tests live in sibling files.
- `frontend/package.json` gains `@tauri-apps/cli` (dev dependency, exact
  version) and the scripts `"tauri": "cd ../crates/pam && tauri"` and
  `"dev:desktop": "cd ../crates/pam && tauri dev -- -- gui"`. Running the
  CLI from the app crate directory makes tauri-dir discovery
  deterministic. `.claude/launch.json` keeps `gui-dev`.
- Bare launch rule (pam-old's `main.rs`): no arguments and an executable
  path inside a `.app` bundle means `pam gui`; a bare terminal launch
  still prints help. Pure helper `launched_from_app_bundle(exe: &Path)`
  in `crates/pam/src/lib.rs` with a sibling test; the macOS-only gate
  wraps the call, not the helper.
- Windows: no `windows_subsystem` attribute (console stays).

## Login-start service

New module `crates/pam_client/src/service.rs` (+ `service_test.rs`),
shared by the CLI and the GUI bridge like `client.rs` is.

### API

```rust
pub enum ServiceState {
    Installed { unit: PathBuf, loaded: bool },
    NotInstalled { unit: PathBuf },
    Unsupported { reason: String },
}
#[derive(Serialize)]
pub struct ServiceReport { pub platform: &'static str, pub exe: PathBuf, pub state: ServiceState }
pub trait Runner { fn run(&self, program: &str, args: &[OsString]) -> io::Result<Output>; }
pub struct CommandRunner;           // std::process::Command
pub fn status(env: &ServiceEnv, runner: &dyn Runner) -> Result<ServiceReport, ServiceError>;
pub fn install(env: &ServiceEnv, runner: &dyn Runner) -> Result<ServiceReport, ServiceError>;
pub fn uninstall(env: &ServiceEnv, runner: &dyn Runner) -> Result<ServiceReport, ServiceError>;
```

`ServiceEnv { platform, exe, home, base_override: Option<PathBuf> }` is
resolved once by the caller (`std::env::current_exe`,
`std::env::home_dir`, `$PAM_BASE_DIR`), so every branch is testable
without touching the process environment (the workspace denies
`unsafe`). The three platform managers are compiled on every host and
selected by `platform`; only the constructor of the default `ServiceEnv`
is `cfg`-gated. Errors are legible: `ServiceError` carries the command
that failed, its exit status, and the trimmed stderr, plus a recovery
line.

### Units

- **macOS**: `~/Library/LaunchAgents/com.github.ro-ag.pam.daemon.plist`.
  `ProgramArguments [exe, "daemon"]`, `RunAtLoad true`,
  `KeepAlive { SuccessfulExit = false }` (crash restarts, clean exits and
  `already running` exits stay down), `ProcessType Background`,
  `StandardOutPath`/`StandardErrorPath` `<base>/log/launchd.log`,
  `EnvironmentVariables { PAM_BASE_DIR }` only when overridden.
  Commands: install = `launchctl bootout gui/<uid>/<label>` (ignored
  when absent), write plist, `launchctl bootstrap gui/<uid> <plist>`;
  status = plist exists → installed, `launchctl print gui/<uid>/<label>`
  exit 0 → loaded; uninstall = bootout, remove plist. `<uid>` comes from
  `id -u` through the runner.
- **Linux**: `~/.config/systemd/user/pam-daemon.service`. `[Service]
  ExecStart=<exe> daemon`, `Restart=on-failure`, `RestartSec=2`,
  optional `Environment=PAM_BASE_DIR=…`; `[Install]
  WantedBy=default.target`. install = write, `systemctl --user
  daemon-reload`, `systemctl --user enable --now pam-daemon.service`;
  status = file exists → installed, `is-active` exit 0 → loaded;
  uninstall = `disable --now`, remove, `daemon-reload`.
- **Windows**: scheduled task `pam\daemon`, trigger at logon of the
  current user, action `conhost.exe --headless "<exe>" daemon` (no
  console window), `/RL LIMITED`, `/F`. install = `schtasks /Create …`
  then `schtasks /Run /TN pam\daemon`; status = `schtasks /Query /TN`
  exit 0 → installed and loaded (the task has no separate loaded state);
  uninstall = `schtasks /Delete /TN pam\daemon /F`. A `PAM_BASE_DIR`
  override is refused with a legible `Unsupported` (scheduled tasks
  carry no environment); the `unit` path reported is the task name.

Install semantics on every platform: if a loose daemon holds the
instance lock, stop it first (`client::stop_daemon`, bounded) so the
managed instance takes over; on Windows, where stopping is not supported
yet, the loose daemon keeps running and the task starts at the next
logon (the report says so). Uninstall never stops the daemon. `pam
daemon` exits 0 on `already running`, so a manager never restart-loops
against a loose instance.

### CLI

`pam service install | uninstall | status [--json]`. Human output: one
line per fact (`platform`, `state`, `unit`, `exe`) and a closing
sentence; `--json` prints the `ServiceReport`. Exit codes: 0 success,
1 failure, 2 usage. Documented in `crates/pam/src/lib.rs`'s subcommand
list and in README.

### GUI

Settings › Daemon gets a "start at login" row under the existing facts:
a `Badge` (`installed` success / `not installed` neutral / `unsupported`
muted), the unit path in `font-data`, and either `Install` (`Button`)
or `Remove` (`ConfirmButton`, "remove it?"). The result line reuses the
panel's `note` slot; failures render as `FailureNote`. Three new Tauri
commands in `crates/pam_gui/src/service.rs` (`service_status`,
`service_install`, `service_uninstall`, each `spawn_blocking` over the
shared module, errors mapped to `BridgeError` cause `service_failed`),
listed in `build.rs`, granted in `capabilities/main-window.json`,
wrapped in `ipc.ts` (`serviceStatus`, `serviceInstall`,
`serviceUninstall`, `ServiceReport` type). Vitest covers the four states
and both actions; the fixture shim answers `service_status`.

## CI (`.github/workflows/ci.yml`)

- Triggers: `pull_request` and `push` to `main` with the existing
  `paths-ignore`, `push` tags `v*` (unchanged), plus `workflow_dispatch`.
  `permissions: contents: read`. `concurrency` cancels in progress only
  for pull requests. Every job has `timeout-minutes`. Actions are pinned
  by commit SHA with a `# vN` comment.
- `gate` and `targets`: unchanged steps. `gate` additionally emits a
  `packages` output: the JSON matrix of desktop packages to build in this
  run (full four-entry list on `main`/dispatch/tags, `Linux amd64` only
  on pull requests).
- `desktop-packages` (needs `gate`, `targets`; `strategy.matrix:
  ${{ fromJSON(needs.gate.outputs.packages) }}`, `fail-fast: false`,
  timeout 40): pam-old's job — Linux deps, Node 22, toolchain with
  target, rust-cache keyed `desktop-<target>`, `npm ci`, `npm --prefix
  frontend run tauri -- build --target <t> --bundles <b>`, then the
  contract check and a 7-day artifact `pam-linux-amd64` /
  `pam-linux-arm64` / `pam-windows-amd64` / `pam-windows-arm64`
  (Linux: `pam-<target>-bundle.tar.gz` of the bundle dir; Windows: the
  `bundle` dir).
- Linux contract (bash): exactly one AppImage and one deb; ELF machine of
  the binary and the AppImage; deb `Architecture`; `pam --version` equals
  `pam <workspace version>`; `--help` matches `^Usage: pam`; deb and
  AppImage payloads carry `pam` (AppImage also `xdg-open`) and nothing
  else; the `.desktop` `Exec` line runs `pam gui`.
- Windows contract (pwsh): exactly one NSIS installer; PE machine of the
  binary and the packaged `pam.exe`; PE subsystem `3` (console); the
  installer's `pam.exe` differs from the build output only by Tauri's
  same-length bundle marker (pam-old's check); `pam.exe --version`
  prints `pam <version>` (possible only because the console stays);
  silent install (`/S`) into the runner's user profile, the Start-menu
  shortcut's `Arguments` is `gui`, then silent uninstall.
- `macos-package` (needs `gate`, `targets`; `main`, dispatch, and tags,
  never pull requests; macos-15; timeout 45): `MACOSX_DEPLOYMENT_TARGET=12.0`, `tauri build
  --target aarch64-apple-darwin --bundles app`, dmg via
  `tools/package-macos-dmg.sh` (ported with `tools/dmg/` art, the icns
  path updated to `crates/pam/icons/icon.icns`), contract: exactly one
  executable `pam` in `Contents/MacOS`, `lipo -archs` arm64, `minos`
  12.0, `pam --version` from inside the bundle prints `pam <version>`;
  artifact `pam-macos-arm64` = `pam-macos-arm64-bundle.tar.gz` holding
  `macos/pam.app` and `dmg/<name>.dmg`.
- Tag pushes run `gate`, `targets`, the full `desktop-packages` matrix
  and `macos-package` too, so a tag on a commit that never reached
  `main` still has artifacts; `release.yml` looks the run up by commit
  (`gh run list --commit <sha>`), not by branch.

## Release (`.github/workflows/release.yml`)

pam-old's workflow, adapted:

- `validate` (ubuntu, 5 min): canonical `vX.Y.Z` tag; version equality
  across `Cargo.toml` `[workspace.package]`, `crates/pam/tauri.conf.json`,
  `frontend/package.json`, and a `## [X.Y.Z]` heading in `CHANGELOG.md`;
  `README.md`, `LICENSE`, `CHANGELOG.md` non-empty; a `success` CI run
  for the tag's peeled commit with all five artifacts unexpired
  (otherwise a legible `::error` naming the rerun to do). Outputs
  `version` and `run_id`.
- `build` (matrix of the four Linux/Windows packages, 10 min each): `gh
  run download --repo "$GITHUB_REPOSITORY"` (no checkout), Linux →
  `pam_<ver>_linux_<arch>.tar.gz`, Windows → `pam_<ver>_windows_<arch>.zip`.
- `macos` (macos-15, 45 min): checkout (for the dmg tool), download,
  ephemeral keychain from the secrets, `codesign --force --timestamp
  --options runtime --deep` on `pam.app`, rebuild the dmg around the
  signed app, sign the dmg, `notarytool submit --wait` with `notarytool
  log` on any non-Accepted status, `stapler staple` + `validate`,
  `spctl --assess --type open --context context:primary-signature`,
  contract re-check, `pam_<ver>_darwin_arm64.dmg`, keychain cleanup in
  an `always()` step. Missing secrets fail this job.
- `release` (ubuntu, 15 min, `contents: write`): download all,
  `sha256sum * > checksums.txt`, notes = the tag's CHANGELOG section,
  `gh release create "$TAG" dist/* --title "pam $TAG" --notes-file
  --verify-tag`.
- `concurrency: release-<ref>`, no cancel. Pinned actions.

## Docs

- `README.md`: mark, one-line pitch (vision north star), badges
  (license, release, CI), the three modes block, "Why", the control
  center, Install (table: macOS 12+ arm64 signed+notarized dmg; Linux
  amd64/arm64 AppImage + deb; Windows amd64/arm64 NSIS per-user
  installer), Quickstart (`pam status`, `pam flow list`, `pam flow run`,
  `pam gui`), Start at login (`pam service`), Build from source
  (`tools/check.sh`, `npm run gui:build`, `npm run tauri -- build`),
  Releasing (bump the three versions + changelog heading, merge, wait
  for main CI, tag, watch `release.yml`), License.
- `CHANGELOG.md`: Keep a Changelog header; `## [Unreleased]` with this
  plan's Added/Changed entries. The first tag moves it under its heading.
- `LICENSE`: Apache-2.0 text.
- `docs/assets/pam-mark.svg` copied from pam-old.

## Testing

- Rust: `service_test.rs` — unit rendering per platform (label, exe
  path quoting, RunAtLoad/KeepAlive, Restart=on-failure, WantedBy,
  conhost action, base-dir env only when overridden), install/uninstall/
  status command sequences through a recording fake runner for all three
  platforms, error mapping (non-zero exit → `ServiceError` with stderr),
  the Windows base-dir refusal, and the "stop loose daemon first" branch
  through the existing lock probe on a temp base. `config_test.rs` in
  `crates/pam` — the moved config-sanity tests plus: bundle active, the
  three overlay files parse and name the expected targets, the desktop
  template's `Exec` runs `pam gui`, the NSIS hook file exists, and every
  bridge command (now six + three) is listed in `build.rs` and granted in
  the capability. `lib_test` for `launched_from_app_bundle`. Bridge
  mapping test for the three service commands' error shape.
- Frontend: `Settings.test.tsx` daemon block — badge per state, Install
  calls `serviceInstall`, Remove asks then calls `serviceUninstall`,
  unsupported hides the buttons and shows the reason; `ipc` wrappers
  reject with `BridgeUnavailable` outside the shell.
- Local gates: `tools/check.sh`; `npm run tauri -- build --bundles app`
  on the bench producing `pam.app`, the dmg script producing a mounting
  dmg, `open pam.app` bringing up the GUI (bare-launch rule), `pam
  service install/status/uninstall` against the real LaunchAgent with
  `launchctl print` as witness, and the Settings row eyeballed through
  the fixture proxy in both theme families.
- CI: the PR run green (gate, targets, Linux amd64 package); the main
  run green with all five package artifacts, downloaded and inspected.
- Release: proven by the owner's first tag; this plan stops at a green
  `main` with artifacts.

## Risks

- Tauri CLI tauri-dir discovery from a `crates/pam` layout: pinned by
  running the CLI from the app crate directory; the first implementation
  step is `tauri info` from there.
- `conhost.exe --headless` is undocumented; if a runner-side check fails
  the task falls back to a visible console and the README says so.
- NSIS shortcut rewrite depends on Tauri's installer hook names
  (`NSIS_HOOK_POSTINSTALL`); the Windows contract step proves the
  shortcut arguments on a real silent install.
