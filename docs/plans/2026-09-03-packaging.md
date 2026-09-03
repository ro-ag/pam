# Packaging + OS Integration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship `pam` the way pam-old shipped (Tauri CLI bundles, CI package
contracts, a tag-triggered signed release) and give the daemon a user-scope
login-start integration with a CLI and a Settings surface.

**Architecture:** `crates/pam` becomes the Tauri app crate (config, icons,
capabilities, build script) so `tauri build` can own the single `pam`
binary; `pam_gui::run` takes the generated context. A new
`pam_client::service` module renders and manages one login-start unit per
platform behind an injected `Runner`, shared by `pam service …` and three
Tauri commands. CI keeps `gate` + `targets` and gains pam-old's package
jobs; `release.yml` reuses the green run's artifacts.

**Tech Stack:** Rust 1.97 (edition 2024, `unsafe` denied), clap 4, tauri
2.11.5 / tauri-build 2.6.3, `@tauri-apps/cli` 2.11.4, Vite + vitest,
GitHub Actions (ubuntu-24.04, ubuntu-24.04-arm, macos-15, windows-2025,
windows-11-arm), NSIS, hdiutil, codesign/notarytool.

Spec: `docs/specs/2026-09-03-packaging-design.md`.

## Global Constraints

- Branch per task, PR + squash merge, conventional title, no AI attribution
  anywhere (commits, PRs). Reference the ptrack task id as `#<id>` in the
  squash title's body only if known; otherwise the coordinator links it.
- Rust tests live in sibling files (`module.rs` + `module_test.rs`,
  declared with `#[cfg(test)] mod module_test;`). Never `mod tests` inline.
- No new Rust dependencies. The only new npm dependency is
  `@tauri-apps/cli` pinned to `2.11.4` (matches tauri 2.11.5).
- No `unsafe`. Environment is read, never mutated, in library code and
  tests; inject it instead.
- `tools/check.sh` is the local gate (fmt, clippy `-D warnings`, cargo
  test, eslint, tsc + vite build, vitest). Every task runs it before its
  PR. Foreground only: no background waits.
- Tailwind v4 tokens only in the frontend; no arbitrary values (ESLint
  enforces). Reuse `Badge`, `Button`, `ConfirmButton`, `FailureNote`,
  `Panel`.
- Copy in the GUI is first person, lowercase labels in `font-data`, as the
  existing Daemon panel does.
- Version strings stay `0.1.0` in `Cargo.toml`, `crates/pam/tauri.conf.json`
  and `frontend/package.json`. No tag is cut by this plan.
- Actions in workflows are pinned by full commit SHA with a `# vN`
  comment. Resolve a tag's SHA with
  `gh api repos/<owner>/<repo>/git/ref/tags/<tag> --jq .object.sha`; if
  `.object.type` is `tag` (annotated), dereference with
  `gh api repos/<owner>/<repo>/git/tags/<sha> --jq .object.sha`.
- Subagents work in isolated worktrees on disjoint file sets. Wave 1 tasks
  (1, 2, 3) are independent; Wave 2 tasks (4, 5, 6) need 1 and 2 merged;
  Task 7 needs 6 merged; Task 8 is the coordinator's checkpoint.

---

## File map

| Path | Responsibility | Task |
| --- | --- | --- |
| `crates/pam/tauri.conf.json`, `tauri.{macos,linux,windows}.conf.json` | Tauri app config + per-platform bundle overlays | 1 |
| `crates/pam/build.rs`, `icons/`, `capabilities/`, `permissions/` | moved from `crates/pam_gui` | 1 |
| `crates/pam/linux/pam.desktop`, `crates/pam/nsis/hooks.nsh` | desktop entry template (`Exec=pam gui`), NSIS shortcut hook | 1 |
| `crates/pam/src/lib.rs`, `lib_test.rs`, `config_test.rs` | `launched_from_app_bundle`, config-sanity tests | 1 |
| `crates/pam/src/main.rs` | bare-launch rule, `pam_gui::run(generate_context!())`, `pam service` | 1, 4 |
| `crates/pam_gui/src/lib.rs` | `run(context)`; docs | 1, 5 |
| `crates/pam_client/src/service.rs`, `service_test.rs` | login-start module | 2 |
| `crates/pam/src/render.rs`, `render_test.rs` | `render_service_report` | 4 |
| `crates/pam_gui/src/service.rs`, `service_test.rs` | Tauri commands | 5 |
| `frontend/src/lib/ipc.ts`, `screens/Settings.tsx`, `Settings.test.tsx` | wrappers + Start-at-login row | 5 |
| `README.md`, `CHANGELOG.md`, `LICENSE`, `docs/assets/pam-mark.svg` | docs | 3 |
| `.github/workflows/ci.yml`, `.github/dependabot.yml` | package jobs, pins, dispatch | 6 |
| `tools/package-macos-dmg.sh`, `tools/dmg/*` | dmg tooling ported from pam-old | 6 |
| `.github/workflows/release.yml` | tag release | 7 |

---

### Task 1: `crates/pam` becomes the Tauri app crate; bundles; bare-launch rule

**Files:**
- Move (git mv): `crates/pam_gui/tauri.conf.json` → `crates/pam/tauri.conf.json`; `crates/pam_gui/build.rs` → `crates/pam/build.rs`; `crates/pam_gui/icons/` → `crates/pam/icons/`; `crates/pam_gui/capabilities/` → `crates/pam/capabilities/`; `crates/pam_gui/permissions/` → `crates/pam/permissions/`
- Create: `crates/pam/tauri.macos.conf.json`, `crates/pam/tauri.linux.conf.json`, `crates/pam/tauri.windows.conf.json`, `crates/pam/linux/pam.desktop`, `crates/pam/nsis/hooks.nsh`, `crates/pam/src/config_test.rs`, `crates/pam/src/lib_test.rs`
- Modify: `crates/pam/Cargo.toml`, `crates/pam/src/lib.rs`, `crates/pam/src/main.rs`, `crates/pam_gui/Cargo.toml`, `crates/pam_gui/src/lib.rs`, `.gitignore`, `frontend/package.json` (+ `package-lock.json`), `crates/pam_gui/tests/bridge.rs` only if it references moved files (it does not today)
- Delete: `crates/pam_gui/src/lib_test.rs` (its tests move to `crates/pam/src/config_test.rs`)

**Interfaces:**
- Produces: `pam_gui::run(context: tauri::Context) -> tauri::Result<()>`; `pam::launched_from_app_bundle(exe: &Path) -> bool`; `tauri.conf.json` at `crates/pam/`; npm scripts `tauri` and `dev:desktop`; `.gitignore` entry `crates/pam/gen/`.
- Consumed by: Task 5 (adds commands to `crates/pam/build.rs` and `capabilities/main-window.json`), Task 6 (`npm --prefix frontend run tauri -- build`).

- [ ] **Step 1: Move the Tauri files**

```bash
git mv crates/pam_gui/tauri.conf.json crates/pam/tauri.conf.json
git mv crates/pam_gui/build.rs crates/pam/build.rs
git mv crates/pam_gui/icons crates/pam/icons
git mv crates/pam_gui/capabilities crates/pam/capabilities
git mv crates/pam_gui/permissions crates/pam/permissions
rm -rf crates/pam_gui/gen
sed -i '' 's#^crates/pam_gui/gen/$#crates/pam/gen/#' .gitignore
```

`capabilities/main-window.json` keeps `"$schema": "../gen/schemas/desktop-schema.json"` (still one level up from the capability dir).

- [ ] **Step 2: Cargo wiring**

`crates/pam/Cargo.toml` — replace the `[features]` block and add tauri:

```toml
[features]
# Production GUI build: embed frontend/dist into the binary instead of the
# dev-server context. `npm --prefix frontend run build` must run first.
# `tauri build` turns tauri/custom-protocol on by itself; this feature is
# the manual equivalent for `npm run gui:build` and local proofs.
gui-embed = ["tauri/custom-protocol", "pam_gui/embed"]

[dependencies]
clap.workspace = true
pam_client.workspace = true
pam_daemon.workspace = true
pam_gui.workspace = true
pam_proto.workspace = true
serde_json.workspace = true
tauri.workspace = true
tokio = { workspace = true, features = ["signal"] }

[build-dependencies]
tauri-build.workspace = true
```

`crates/pam_gui/Cargo.toml` — delete the `[build-dependencies]` table; keep
the `embed` feature exactly as it is.

- [ ] **Step 3: `pam_gui::run` takes the context**

In `crates/pam_gui/src/lib.rs` change the signature and the last line:

```rust
/// Opens the pam desktop window and runs the Tauri event loop until the
/// window closes. `context` is generated by the app crate
/// (`crates/pam`), which owns `tauri.conf.json` — see the crate docs.
pub fn run(context: tauri::Context) -> tauri::Result<()> {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            bridge::daemon_status,
            bridge::admin_call,
            bridge::request_capability,
            bridge::daemon_stop,
            events::events_subscribe,
            logs::read_daemon_log
        ])
        .run(context)
}
```

Remove `#[cfg(test)] mod lib_test;` from that file, delete
`crates/pam_gui/src/lib_test.rs`, and rewrite the crate header comment:
the app crate (`crates/pam`) now owns `tauri.conf.json`, `build.rs`,
icons, and capabilities; the Tauri CLI is part of the flow
(`npm --prefix frontend run tauri -- build` bundles; `npm run gui:build`
remains the manual embed path); the "white window law" paragraph stays.

- [ ] **Step 4: Bare-launch helper with a failing test**

`crates/pam/src/lib_test.rs`:

```rust
use std::path::Path;

use crate::launched_from_app_bundle;

#[test]
fn a_binary_inside_an_app_bundle_wants_the_gui() {
    assert!(launched_from_app_bundle(Path::new(
        "/Applications/pam.app/Contents/MacOS/pam"
    )));
}

#[test]
fn a_plain_binary_stays_a_cli() {
    assert!(!launched_from_app_bundle(Path::new("/usr/local/bin/pam")));
    assert!(!launched_from_app_bundle(Path::new("/tmp/pam.app.backup/pam")));
    assert!(!launched_from_app_bundle(Path::new("/tmp/pam.application/pam")));
}
```

Add to `crates/pam/src/lib.rs` (after the `pub mod render;` line):

```rust
/// True when `exe` sits inside a macOS application bundle
/// (`…/Something.app/Contents/MacOS/pam`): a bare double-click launch,
/// which should open the GUI. A bare terminal launch prints help.
#[must_use]
pub fn launched_from_app_bundle(exe: &Path) -> bool {
    exe.components().any(|part| {
        part.as_os_str()
            .to_str()
            .is_some_and(|name| name.ends_with(".app"))
    })
}

#[cfg(test)]
mod config_test;
#[cfg(test)]
mod lib_test;
```

with `use std::path::Path;` at the top. Run
`cargo test -p pam --lib lib_test` — expect the two tests to fail to
compile first (function missing), then pass after the addition.

- [ ] **Step 5: `main.rs` dispatch**

Replace `fn main` and `gui_mode`:

```rust
fn main() -> ExitCode {
    if bare_bundle_launch() {
        return gui_mode();
    }
    match Cli::parse().command {
        Cmd::Daemon { action: None } => daemon_mode(),
        Cmd::Daemon {
            action: Some(DaemonCmd::Stop),
        } => daemon_stop(),
        Cmd::Gui => gui_mode(),
        command => client_mode(command),
    }
}

/// A bare launch (no arguments) from inside a macOS `.app` bundle is a
/// double-click: open the GUI instead of printing help. Every other
/// platform, and any bare terminal launch, stays in client mode.
fn bare_bundle_launch() -> bool {
    cfg!(target_os = "macos")
        && std::env::args_os().nth(1).is_none()
        && std::env::current_exe().is_ok_and(|exe| pam::launched_from_app_bundle(&exe))
}

/// `pam gui`: hands the process to the Tauri event loop (must run on the
/// main thread, before any async runtime exists) until the window closes.
///
/// The context (config, icons, capabilities) is generated from this
/// crate's `tauri.conf.json`; which frontend the window loads is a
/// compile-time property of the binary (`tauri build`, or
/// `--features gui-embed`, embed `frontend/dist`; plain builds load the
/// Vite dev server). See the [`pam_gui`] crate docs.
fn gui_mode() -> ExitCode {
    match pam_gui::run(tauri::generate_context!()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("pam gui: {err}");
            ExitCode::FAILURE
        }
    }
}
```

- [ ] **Step 6: Tauri config + overlays**

`crates/pam/tauri.conf.json` — change `build` and `bundle`, keep `app` verbatim:

```json
  "build": {
    "beforeDevCommand": { "script": "npm run dev", "cwd": "../../frontend" },
    "devUrl": "http://127.0.0.1:1420",
    "beforeBuildCommand": { "script": "npm run build", "cwd": "../../frontend" },
    "frontendDist": "../../frontend/dist"
  },
```

```json
  "bundle": {
    "active": true,
    "category": "DeveloperTool",
    "publisher": "ro-ag",
    "copyright": "Copyright © 2026 pam contributors",
    "shortDescription": "A local lifeguard for developers and AI agents",
    "longDescription": "pam gives sandboxed agents controlled, audited access to real capabilities: local models, flows, connectors, and a desktop control center.",
    "icon": ["icons/icon.png", "icons/icon.ico", "icons/icon.icns"]
  }
```

`crates/pam/tauri.macos.conf.json`:

```json
{
  "$schema": "https://schema.tauri.app/config/2",
  "bundle": {
    "targets": ["app"],
    "macOS": { "minimumSystemVersion": "12.0" }
  }
}
```

`crates/pam/tauri.linux.conf.json`:

```json
{
  "$schema": "https://schema.tauri.app/config/2",
  "bundle": {
    "targets": ["appimage", "deb"],
    "linux": {
      "deb": { "desktopTemplate": "./linux/pam.desktop" }
    }
  }
}
```

`crates/pam/linux/pam.desktop` (Tauri's default template with `gui` on Exec):

```
[Desktop Entry]
Categories={{categories}}
{{#if comment}}
Comment={{comment}}
{{/if}}
Exec={{exec}} gui
Icon={{icon}}
Name={{name}}
Terminal=false
Type=Application
{{#if mime_type}}
MimeType={{mime_type}}
{{/if}}
```

`crates/pam/tauri.windows.conf.json`:

```json
{
  "$schema": "https://schema.tauri.app/config/2",
  "bundle": {
    "targets": ["nsis"],
    "windows": {
      "allowDowngrades": false,
      "nsis": {
        "installMode": "currentUser",
        "installerHooks": "./nsis/hooks.nsh"
      }
    }
  }
}
```

`crates/pam/nsis/hooks.nsh` — Tauri creates both shortcuts without
arguments; a bare `pam.exe` prints help. Recreate them to open the GUI:

```nsis
; pam ships one console binary; the shortcuts must pass `gui`.
!macro NSIS_HOOK_POSTINSTALL
  CreateShortcut "$SMPROGRAMS\${PRODUCTNAME}.lnk" "$INSTDIR\${MAINBINARYNAME}.exe" "gui" "$INSTDIR\${MAINBINARYNAME}.exe" 0
  IfFileExists "$DESKTOP\${PRODUCTNAME}.lnk" 0 +2
    CreateShortcut "$DESKTOP\${PRODUCTNAME}.lnk" "$INSTDIR\${MAINBINARYNAME}.exe" "gui" "$INSTDIR\${MAINBINARYNAME}.exe" 0
!macroend
```

- [ ] **Step 7: Config-sanity tests move and grow**

`crates/pam/src/config_test.rs` — port every test from the old
`crates/pam_gui/src/lib_test.rs` (same assertions, paths now
`../tauri.conf.json`, `../capabilities/main-window.json`, `../build.rs`)
and add:

```rust
const MACOS_CONF: &str = include_str!("../tauri.macos.conf.json");
const LINUX_CONF: &str = include_str!("../tauri.linux.conf.json");
const WINDOWS_CONF: &str = include_str!("../tauri.windows.conf.json");
const DESKTOP_TEMPLATE: &str = include_str!("../linux/pam.desktop");
const NSIS_HOOKS: &str = include_str!("../nsis/hooks.nsh");

/// Every bridge command the frontend may invoke: `build.rs` mints its
/// `allow-<command>` permission and the main-window capability grants it.
const BRIDGE_COMMANDS: [&str; 6] = [
    "daemon_status",
    "admin_call",
    "request_capability",
    "daemon_stop",
    "events_subscribe",
    "read_daemon_log",
];

#[test]
fn bundling_is_on_with_pam_olds_metadata() {
    let conf = tauri_conf();
    assert_eq!(conf["bundle"]["active"], true);
    assert_eq!(conf["bundle"]["category"], "DeveloperTool");
    assert_eq!(conf["mainBinaryName"], "pam");
    assert_eq!(conf["build"]["beforeBuildCommand"]["cwd"], "../../frontend");
}

#[test]
fn platform_overlays_name_pam_olds_targets() {
    let parse = |s: &str| serde_json::from_str::<serde_json::Value>(s).expect("overlay parses");
    assert_eq!(parse(MACOS_CONF)["bundle"]["targets"], serde_json::json!(["app"]));
    assert_eq!(parse(MACOS_CONF)["bundle"]["macOS"]["minimumSystemVersion"], "12.0");
    assert_eq!(parse(LINUX_CONF)["bundle"]["targets"], serde_json::json!(["appimage", "deb"]));
    assert_eq!(parse(WINDOWS_CONF)["bundle"]["targets"], serde_json::json!(["nsis"]));
    assert_eq!(parse(WINDOWS_CONF)["bundle"]["windows"]["nsis"]["installMode"], "currentUser");
}

#[test]
fn desktop_entry_and_shortcuts_open_the_gui() {
    assert!(DESKTOP_TEMPLATE.lines().any(|l| l == "Exec={{exec}} gui"));
    assert!(NSIS_HOOKS.contains("NSIS_HOOK_POSTINSTALL"));
    assert_eq!(NSIS_HOOKS.matches("\"gui\"").count(), 2);
}

#[test]
fn every_bridge_command_is_built_and_granted() {
    let capability: serde_json::Value =
        serde_json::from_str(MAIN_WINDOW_CAPABILITY).expect("capability parses");
    let granted = capability["permissions"].as_array().expect("permissions array");
    for command in BRIDGE_COMMANDS {
        assert!(BUILD_SCRIPT.contains(&format!("\"{command}\"")), "{command} missing from build.rs");
        let permission = format!("allow-{}", command.replace('_', "-"));
        assert!(granted.iter().any(|p| p == permission.as_str()), "{permission} not granted");
    }
}
```

`serde_json` is already a dependency of `crates/pam`. Run
`cargo test -p pam --lib config_test` — expect PASS.

- [ ] **Step 8: Tauri CLI in the frontend**

```bash
npm --prefix frontend install --save-dev --save-exact @tauri-apps/cli@2.11.4
```

Add to `frontend/package.json` `scripts`:

```json
    "tauri": "cd ../crates/pam && tauri",
    "dev:desktop": "cd ../crates/pam && tauri dev -- -- gui"
```

Verify discovery: `npm --prefix frontend run tauri -- info` must print the
`crates/pam` config path and tauri 2.11.5. Then on the bench:

```bash
npm --prefix frontend run tauri -- build --bundles app
ls target/release/bundle/macos/pam.app/Contents/MacOS/
target/release/bundle/macos/pam.app/Contents/MacOS/pam --version
```

Expected: exactly `pam`; version `pam 0.1.0`. Then `open
target/release/bundle/macos/pam.app` opens the control center window
(bare-launch rule) — confirm with `pgrep -fl 'pam.app/Contents/MacOS/pam'`
and close it. If `tauri build` refuses because the CLI cannot find the
crate's binary target, add `[[bin]] name = "pam" path = "src/main.rs"` to
`crates/pam/Cargo.toml` and retry; record whichever was needed in the PR.

- [ ] **Step 9: Gate and commit**

```bash
tools/check.sh
git add -A
git commit -m "build(tauri): crates/pam owns the Tauri app — bundles, overlays, bare-launch rule"
```

Open the PR with title `build(tauri): crates/pam owns the Tauri app; bundles; bare-launch rule`.

---

### Task 2: `pam_client::service` — login-start units behind an injected runner

**Files:**
- Create: `crates/pam_client/src/service.rs`, `crates/pam_client/src/service_test.rs`
- Modify: `crates/pam_client/src/lib.rs` (add `pub mod service;` and `#[cfg(test)] mod service_test;`), `crates/pam_client/Cargo.toml` (add `serde.workspace = true`)

**Interfaces:**
- Produces (all `pub` in `pam_client::service`):
  - `enum Platform { Macos, Linux, Windows, Other }` with `fn current() -> Self`, `fn as_str(self) -> &'static str`
  - `enum ServiceState { Installed { unit: String, loaded: bool }, NotInstalled { unit: String }, Unsupported { reason: String } }` (`Serialize`, `#[serde(tag = "kind", rename_all = "snake_case")]`)
  - `struct ServiceReport { platform: &'static str, exe: PathBuf, state: ServiceState, note: Option<String> }` (`Serialize`)
  - `struct ServiceEnv { platform: Platform, exe: PathBuf, home: PathBuf, base: PathBuf, base_override: Option<PathBuf> }` with `fn detect(base: &Path) -> Result<Self, ServiceError>`
  - `trait Runner { fn run(&self, program: &str, args: &[OsString]) -> io::Result<Output>; }`, `struct CommandRunner;`
  - `type StopFn<'a> = &'a dyn Fn(&Path) -> Result<StopOutcome, StopError>;`
  - `fn status(env: &ServiceEnv, runner: &dyn Runner) -> Result<ServiceReport, ServiceError>`
  - `fn install(env: &ServiceEnv, runner: &dyn Runner) -> Result<ServiceReport, ServiceError>` (calls `install_with` with `client::stop_daemon(base, STOP_WAIT)`)
  - `fn install_with(env: &ServiceEnv, runner: &dyn Runner, stop: StopFn<'_>) -> Result<ServiceReport, ServiceError>`
  - `fn uninstall(env: &ServiceEnv, runner: &dyn Runner) -> Result<ServiceReport, ServiceError>`
  - `enum ServiceError` (`thiserror`) with `fn recovery(&self) -> &'static str`
  - `fn render_launch_agent(exe: &Path, log_dir: &Path, base_override: Option<&Path>) -> String`, `fn render_systemd_unit(exe: &Path, base_override: Option<&Path>) -> String`, `fn windows_task_action(exe: &Path) -> String`
  - consts `LAUNCHD_LABEL = "com.github.ro-ag.pam.daemon"`, `SYSTEMD_UNIT = "pam-daemon.service"`, `WINDOWS_TASK = r"pam\daemon"`, `STOP_WAIT = Duration::from_secs(15)`
- Consumes: `client::stop_daemon`, `client::StopOutcome`, `client::StopError` (existing).

- [ ] **Step 1: Failing tests — rendering**

`crates/pam_client/src/service_test.rs` (start with these; the file grows in later steps):

```rust
use std::cell::RefCell;
use std::ffi::OsString;
use std::io;
use std::os::unix::process::ExitStatusExt as _;
use std::path::{Path, PathBuf};
use std::process::{ExitStatus, Output};

use tempfile::TempDir;

use crate::client::{StopError, StopOutcome};
use crate::service::{
    LAUNCHD_LABEL, Platform, Runner, ServiceEnv, ServiceError, ServiceState, SYSTEMD_UNIT,
    WINDOWS_TASK, install_with, render_launch_agent, render_systemd_unit, status, uninstall,
    windows_task_action,
};

#[test]
fn launch_agent_runs_the_daemon_at_load_and_restarts_only_on_crash() {
    let plist = render_launch_agent(
        Path::new("/Applications/pam.app/Contents/MacOS/pam"),
        Path::new("/Users/me/.pam/log"),
        None,
    );
    assert!(plist.contains(&format!("<string>{LAUNCHD_LABEL}</string>")));
    assert!(plist.contains("<string>/Applications/pam.app/Contents/MacOS/pam</string>"));
    assert!(plist.contains("<string>daemon</string>"));
    assert!(plist.contains("<key>RunAtLoad</key>\n\t<true/>"));
    assert!(plist.contains("<key>SuccessfulExit</key>\n\t\t<false/>"));
    assert!(plist.contains("<string>/Users/me/.pam/log/launchd.log</string>"));
    assert!(!plist.contains("PAM_BASE_DIR"));
}

#[test]
fn launch_agent_carries_the_base_override_and_escapes_xml() {
    let plist = render_launch_agent(
        Path::new("/tmp/a&b/pam"),
        Path::new("/tmp/x/log"),
        Some(Path::new("/tmp/x")),
    );
    assert!(plist.contains("<string>/tmp/a&amp;b/pam</string>"));
    assert!(plist.contains("<key>PAM_BASE_DIR</key>\n\t\t<string>/tmp/x</string>"));
}

#[test]
fn systemd_unit_restarts_on_failure_and_wants_default_target() {
    let unit = render_systemd_unit(Path::new("/home/me/.local/bin/pam"), None);
    assert!(unit.contains("ExecStart=\"/home/me/.local/bin/pam\" daemon\n"));
    assert!(unit.contains("Restart=on-failure\n"));
    assert!(unit.contains("WantedBy=default.target\n"));
    assert!(!unit.contains("Environment="));
    let with_base = render_systemd_unit(Path::new("/opt/pam"), Some(Path::new("/srv/pam")));
    assert!(with_base.contains("Environment=PAM_BASE_DIR=/srv/pam\n"));
}

#[test]
fn windows_task_runs_headless() {
    assert_eq!(
        windows_task_action(Path::new(r"C:\Users\me\AppData\Local\pam\pam.exe")),
        r#"conhost.exe --headless "C:\Users\me\AppData\Local\pam\pam.exe" daemon"#
    );
}
```

Run `cargo test -p pam_client --lib service_test` — expect a compile error
(module missing).

- [ ] **Step 2: The module skeleton and renderers**

`crates/pam_client/src/service.rs`:

```rust
//! Login-start integration for the daemon: one user-scope unit per
//! platform (macOS LaunchAgent, systemd user unit, Windows per-user
//! scheduled task), rendered and managed here, shared by
//! `pam service …` and the GUI bridge.
//!
//! Every OS call goes through [`Runner`], so tests drive all three
//! platforms on any host with a fake; the platform managers are compiled
//! everywhere and selected by [`ServiceEnv::platform`]. Never sudo,
//! admin, or root (spine spec: user scope only).
//!
//! Install semantics: stop a loose daemon first (bounded, through
//! [`crate::client::stop_daemon`]) so the managed instance takes over,
//! write the unit, register and start it. Uninstall unregisters and
//! removes the unit; it never stops the daemon. `pam daemon` exits 0 on
//! `already running`, so a manager never restart-loops against a loose
//! instance.

use std::ffi::OsString;
use std::fmt::Write as _;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::Duration;

use serde::Serialize;
use thiserror::Error;

use crate::client::{self, StopError, StopOutcome};

/// launchd label and plist file stem.
pub const LAUNCHD_LABEL: &str = "com.github.ro-ag.pam.daemon";
/// systemd user unit file name.
pub const SYSTEMD_UNIT: &str = "pam-daemon.service";
/// Windows Task Scheduler task path.
pub const WINDOWS_TASK: &str = r"pam\daemon";
/// How long `install` waits for a loose daemon to drain before the
/// managed instance is started.
pub const STOP_WAIT: Duration = Duration::from_secs(15);

/// The platforms with a login-start manager.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Platform {
    Macos,
    Linux,
    Windows,
    Other,
}

impl Platform {
    /// The platform this binary was built for.
    #[must_use]
    pub fn current() -> Self {
        if cfg!(target_os = "macos") {
            Self::Macos
        } else if cfg!(target_os = "linux") {
            Self::Linux
        } else if cfg!(windows) {
            Self::Windows
        } else {
            Self::Other
        }
    }

    /// Lowercase name, as the report prints it.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Macos => "macos",
            Self::Linux => "linux",
            Self::Windows => "windows",
            Self::Other => "other",
        }
    }
}

/// Whether the unit exists and whether its manager reports it loaded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ServiceState {
    /// The unit is registered; `loaded` is the manager's own verdict
    /// (launchd print / systemctl is-active / task exists).
    Installed { unit: String, loaded: bool },
    /// No unit at the path (or task name) the platform uses.
    NotInstalled { unit: String },
    /// This platform or configuration has no login-start integration.
    Unsupported { reason: String },
}

/// What every service command answers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ServiceReport {
    pub platform: &'static str,
    pub exe: PathBuf,
    pub state: ServiceState,
    /// Something the human should know (a loose daemon was stopped, or
    /// could not be), never an error.
    pub note: Option<String>,
}

/// Everything the managers need from the process, resolved once by the
/// caller so the module never reads the environment itself.
#[derive(Debug, Clone)]
pub struct ServiceEnv {
    pub platform: Platform,
    /// Absolute path of the `pam` binary the unit will run.
    pub exe: PathBuf,
    pub home: PathBuf,
    /// The base dir in use (`~/.pam` or `$PAM_BASE_DIR`).
    pub base: PathBuf,
    /// Set only when `$PAM_BASE_DIR` overrides the default.
    pub base_override: Option<PathBuf>,
}

impl ServiceEnv {
    /// Resolves the current process: platform, `current_exe`, home, and
    /// whether `base` is an override of `~/.pam`.
    ///
    /// # Errors
    ///
    /// [`ServiceError::NoHome`] when the home directory is unknown,
    /// [`ServiceError::NoExe`] when `current_exe` fails.
    pub fn detect(base: &Path) -> Result<Self, ServiceError> {
        let home = std::env::home_dir().ok_or(ServiceError::NoHome)?;
        let exe = std::env::current_exe().map_err(ServiceError::NoExe)?;
        let base_override = (base != home.join(".pam")).then(|| base.to_path_buf());
        Ok(Self {
            platform: Platform::current(),
            exe,
            home,
            base: base.to_path_buf(),
            base_override,
        })
    }
}

/// Runs one external command and returns its output. The real one is
/// [`CommandRunner`]; tests inject a fake.
pub trait Runner {
    /// # Errors
    ///
    /// Whatever spawning the program produced.
    fn run(&self, program: &str, args: &[OsString]) -> io::Result<Output>;
}

/// [`Runner`] over `std::process::Command`.
#[derive(Debug, Default, Clone, Copy)]
pub struct CommandRunner;

impl Runner for CommandRunner {
    fn run(&self, program: &str, args: &[OsString]) -> io::Result<Output> {
        Command::new(program).args(args).output()
    }
}

/// How `install` stops a loose daemon; injected so tests need no daemon.
pub type StopFn<'a> = &'a dyn Fn(&Path) -> Result<StopOutcome, StopError>;

/// Why a service command failed. Every variant names its recovery.
#[derive(Debug, Error)]
pub enum ServiceError {
    #[error("cannot resolve the home directory")]
    NoHome,
    #[error("cannot resolve the pam executable path: {0}")]
    NoExe(#[source] io::Error),
    #[error("cannot write {path}: {source}")]
    Write {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("cannot remove {path}: {source}")]
    Remove {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("cannot run {program}: {source}")]
    Spawn {
        program: String,
        #[source]
        source: io::Error,
    },
    #[error("`{program} {args}` failed ({status}): {stderr}")]
    Command {
        program: String,
        args: String,
        status: String,
        stderr: String,
    },
    #[error("{platform} has no login-start integration")]
    Unsupported { platform: &'static str },
    #[error("stopping the running daemon failed: {0}")]
    Stop(#[from] StopError),
}

impl ServiceError {
    /// One recovery line per failure family, for the CLI and the GUI.
    #[must_use]
    pub fn recovery(&self) -> &'static str {
        match self {
            Self::NoHome => "Set $HOME and retry.",
            Self::NoExe(_) => "Run pam from an installed location and retry.",
            Self::Write { .. } | Self::Remove { .. } => {
                "Check the permissions of the unit directory and retry."
            }
            Self::Spawn { .. } => "Install the platform's service manager tools and retry.",
            Self::Command { .. } => "Read the manager's message above; fix it and retry.",
            Self::Unsupported { .. } => "Start the daemon lazily instead: any pam command does.",
            Self::Stop(_) => "Stop the daemon with `pam daemon stop`, then retry.",
        }
    }
}

// --- unit rendering ---------------------------------------------------------

fn xml_escape(text: &str) -> String {
    text.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
}

/// The LaunchAgent plist: run `exe daemon` at load, restart only on a
/// crash (a clean exit — `pam daemon stop`, or `already running` —
/// stays down), log launchd's own capture to `log_dir/launchd.log`.
#[must_use]
pub fn render_launch_agent(exe: &Path, log_dir: &Path, base_override: Option<&Path>) -> String {
    let exe = xml_escape(&exe.display().to_string());
    let log = xml_escape(&log_dir.join("launchd.log").display().to_string());
    let mut plist = String::new();
    plist.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    plist.push_str("<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n");
    plist.push_str("<plist version=\"1.0\">\n<dict>\n");
    let _ = writeln!(plist, "\t<key>Label</key>\n\t<string>{LAUNCHD_LABEL}</string>");
    let _ = writeln!(
        plist,
        "\t<key>ProgramArguments</key>\n\t<array>\n\t\t<string>{exe}</string>\n\t\t<string>daemon</string>\n\t</array>"
    );
    plist.push_str("\t<key>RunAtLoad</key>\n\t<true/>\n");
    plist.push_str("\t<key>KeepAlive</key>\n\t<dict>\n\t\t<key>SuccessfulExit</key>\n\t\t<false/>\n\t</dict>\n");
    plist.push_str("\t<key>ProcessType</key>\n\t<string>Background</string>\n");
    let _ = writeln!(plist, "\t<key>StandardOutPath</key>\n\t<string>{log}</string>");
    let _ = writeln!(plist, "\t<key>StandardErrorPath</key>\n\t<string>{log}</string>");
    if let Some(base) = base_override {
        let base = xml_escape(&base.display().to_string());
        let _ = writeln!(
            plist,
            "\t<key>EnvironmentVariables</key>\n\t<dict>\n\t\t<key>PAM_BASE_DIR</key>\n\t\t<string>{base}</string>\n\t</dict>"
        );
    }
    plist.push_str("</dict>\n</plist>\n");
    plist
}

/// The systemd user unit: restart on failure only, part of the user's
/// default target.
#[must_use]
pub fn render_systemd_unit(exe: &Path, base_override: Option<&Path>) -> String {
    let mut unit = String::new();
    unit.push_str("[Unit]\nDescription=pam daemon (local lifeguard for developers and AI agents)\n\n");
    unit.push_str("[Service]\n");
    let _ = writeln!(unit, "ExecStart=\"{}\" daemon", exe.display());
    unit.push_str("Restart=on-failure\nRestartSec=2\n");
    if let Some(base) = base_override {
        let _ = writeln!(unit, "Environment=PAM_BASE_DIR={}", base.display());
    }
    unit.push_str("\n[Install]\nWantedBy=default.target\n");
    unit
}

/// The scheduled task's action: `conhost.exe --headless` runs the console
/// binary without a window.
#[must_use]
pub fn windows_task_action(exe: &Path) -> String {
    format!("conhost.exe --headless \"{}\" daemon", exe.display())
}
```

Run `cargo test -p pam_client --lib service_test` — the four rendering
tests pass (the manager tests come next).

- [ ] **Step 3: Failing tests — the managers through a fake runner**

Append to `service_test.rs`:

```rust
/// Records every call and answers from a table keyed by
/// `"<program> <first arg>"`; unknown calls succeed with empty output.
#[derive(Default)]
struct FakeRunner {
    calls: RefCell<Vec<String>>,
    answers: Vec<(&'static str, i32, &'static str, &'static str)>, // key, code, stdout, stderr
}

impl FakeRunner {
    fn answer(mut self, key: &'static str, code: i32, stdout: &'static str, stderr: &'static str) -> Self {
        self.answers.push((key, code, stdout, stderr));
        self
    }
    fn calls(&self) -> Vec<String> {
        self.calls.borrow().clone()
    }
}

impl Runner for FakeRunner {
    fn run(&self, program: &str, args: &[OsString]) -> io::Result<Output> {
        let rendered: Vec<String> = args.iter().map(|a| a.to_string_lossy().into_owned()).collect();
        let line = format!("{program} {}", rendered.join(" "));
        self.calls.borrow_mut().push(line.clone());
        let key = format!("{program} {}", rendered.first().map_or("", String::as_str));
        let (code, out, err) = self
            .answers
            .iter()
            .find(|(k, ..)| *k == key)
            .map_or((0, "", ""), |(_, c, o, e)| (*c, *o, *e));
        Ok(Output {
            status: ExitStatus::from_raw(code << 8),
            stdout: out.as_bytes().to_vec(),
            stderr: err.as_bytes().to_vec(),
        })
    }
}

fn env(platform: Platform, home: &Path) -> ServiceEnv {
    ServiceEnv {
        platform,
        exe: PathBuf::from("/opt/pam/pam"),
        home: home.to_path_buf(),
        base: home.join(".pam"),
        base_override: None,
    }
}

fn not_running(_: &Path) -> Result<StopOutcome, StopError> {
    Ok(StopOutcome::NotRunning)
}

#[test]
fn macos_install_writes_the_plist_then_bootstraps_it() {
    let home = TempDir::new().unwrap();
    let runner = FakeRunner::default().answer("id -u", 0, "501\n", "");
    let report = install_with(&env(Platform::Macos, home.path()), &runner, &not_running).unwrap();
    let plist = home.path().join("Library/LaunchAgents").join(format!("{LAUNCHD_LABEL}.plist"));
    assert!(plist.is_file());
    assert_eq!(report.state, ServiceState::Installed { unit: plist.display().to_string(), loaded: true });
    assert_eq!(
        runner.calls(),
        vec![
            "id -u".to_owned(),
            format!("launchctl bootout gui/501/{LAUNCHD_LABEL}"),
            format!("launchctl bootstrap gui/501 {}", plist.display()),
        ]
    );
}

#[test]
fn macos_status_reads_the_plist_and_asks_launchctl() {
    let home = TempDir::new().unwrap();
    let e = env(Platform::Macos, home.path());
    let absent = FakeRunner::default().answer("id -u", 0, "501\n", "");
    let plist = home.path().join("Library/LaunchAgents").join(format!("{LAUNCHD_LABEL}.plist"));
    assert_eq!(
        status(&e, &absent).unwrap().state,
        ServiceState::NotInstalled { unit: plist.display().to_string() }
    );
    std::fs::create_dir_all(plist.parent().unwrap()).unwrap();
    std::fs::write(&plist, "x").unwrap();
    let unloaded = FakeRunner::default().answer("id -u", 0, "501\n", "").answer("launchctl print", 3, "", "Could not find service");
    assert_eq!(
        status(&e, &unloaded).unwrap().state,
        ServiceState::Installed { unit: plist.display().to_string(), loaded: false }
    );
}

#[test]
fn macos_uninstall_boots_out_and_removes_the_plist() {
    let home = TempDir::new().unwrap();
    let e = env(Platform::Macos, home.path());
    let plist = home.path().join("Library/LaunchAgents").join(format!("{LAUNCHD_LABEL}.plist"));
    std::fs::create_dir_all(plist.parent().unwrap()).unwrap();
    std::fs::write(&plist, "x").unwrap();
    let runner = FakeRunner::default().answer("id -u", 0, "501\n", "");
    let report = uninstall(&e, &runner).unwrap();
    assert!(!plist.exists());
    assert_eq!(report.state, ServiceState::NotInstalled { unit: plist.display().to_string() });
    assert_eq!(runner.calls()[1], format!("launchctl bootout gui/501/{LAUNCHD_LABEL}"));
}

#[test]
fn linux_install_reloads_then_enables_now() {
    let home = TempDir::new().unwrap();
    let runner = FakeRunner::default();
    let report = install_with(&env(Platform::Linux, home.path()), &runner, &not_running).unwrap();
    let unit = home.path().join(".config/systemd/user").join(SYSTEMD_UNIT);
    assert!(std::fs::read_to_string(&unit).unwrap().contains("ExecStart=\"/opt/pam/pam\" daemon"));
    assert_eq!(report.state, ServiceState::Installed { unit: unit.display().to_string(), loaded: true });
    assert_eq!(
        runner.calls(),
        vec![
            "systemctl --user daemon-reload".to_owned(),
            format!("systemctl --user enable --now {SYSTEMD_UNIT}"),
        ]
    );
}

#[test]
fn linux_status_asks_is_active() {
    let home = TempDir::new().unwrap();
    let e = env(Platform::Linux, home.path());
    let unit = home.path().join(".config/systemd/user").join(SYSTEMD_UNIT);
    std::fs::create_dir_all(unit.parent().unwrap()).unwrap();
    std::fs::write(&unit, "x").unwrap();
    let inactive = FakeRunner::default().answer("systemctl --user", 3, "inactive\n", "");
    assert_eq!(
        status(&e, &inactive).unwrap().state,
        ServiceState::Installed { unit: unit.display().to_string(), loaded: false }
    );
    assert_eq!(inactive.calls(), vec![format!("systemctl --user is-active {SYSTEMD_UNIT}")]);
}

#[test]
fn linux_uninstall_disables_removes_reloads() {
    let home = TempDir::new().unwrap();
    let e = env(Platform::Linux, home.path());
    let unit = home.path().join(".config/systemd/user").join(SYSTEMD_UNIT);
    std::fs::create_dir_all(unit.parent().unwrap()).unwrap();
    std::fs::write(&unit, "x").unwrap();
    let runner = FakeRunner::default();
    uninstall(&e, &runner).unwrap();
    assert!(!unit.exists());
    assert_eq!(
        runner.calls(),
        vec![
            format!("systemctl --user disable --now {SYSTEMD_UNIT}"),
            "systemctl --user daemon-reload".to_owned(),
        ]
    );
}

#[test]
fn windows_install_creates_the_logon_task_and_runs_it() {
    let home = TempDir::new().unwrap();
    let mut e = env(Platform::Windows, home.path());
    e.exe = PathBuf::from(r"C:\pam\pam.exe");
    let runner = FakeRunner::default();
    let report = install_with(&e, &runner, &not_running).unwrap();
    assert_eq!(report.state, ServiceState::Installed { unit: WINDOWS_TASK.to_owned(), loaded: true });
    assert_eq!(
        runner.calls(),
        vec![
            format!(
                r#"schtasks /Create /F /SC ONLOGON /RL LIMITED /TN {WINDOWS_TASK} /TR conhost.exe --headless "C:\pam\pam.exe" daemon"#
            ),
            format!("schtasks /Run /TN {WINDOWS_TASK}"),
        ]
    );
}

#[test]
fn windows_refuses_a_base_override() {
    let home = TempDir::new().unwrap();
    let mut e = env(Platform::Windows, home.path());
    e.base_override = Some(PathBuf::from(r"D:\pam"));
    let report = status(&e, &FakeRunner::default()).unwrap();
    assert!(matches!(report.state, ServiceState::Unsupported { ref reason } if reason.contains("PAM_BASE_DIR")));
    let report = install_with(&e, &FakeRunner::default(), &not_running).unwrap();
    assert!(matches!(report.state, ServiceState::Unsupported { .. }));
}

#[test]
fn other_platforms_are_unsupported() {
    let home = TempDir::new().unwrap();
    let report = status(&env(Platform::Other, home.path()), &FakeRunner::default()).unwrap();
    assert!(matches!(report.state, ServiceState::Unsupported { .. }));
}

#[test]
fn a_failing_manager_command_is_legible() {
    let home = TempDir::new().unwrap();
    let runner = FakeRunner::default().answer("systemctl --user", 1, "", "Failed to connect to bus\n");
    let err = install_with(&env(Platform::Linux, home.path()), &runner, &not_running).unwrap_err();
    let text = err.to_string();
    assert!(text.contains("systemctl --user daemon-reload"), "{text}");
    assert!(text.contains("Failed to connect to bus"), "{text}");
    assert!(matches!(err, ServiceError::Command { .. }));
}

#[test]
fn install_stops_a_loose_daemon_first_and_says_so() {
    let home = TempDir::new().unwrap();
    let stopped = |_: &Path| -> Result<StopOutcome, StopError> { Ok(StopOutcome::Stopped { pid: 4242 }) };
    let report = install_with(&env(Platform::Linux, home.path()), &FakeRunner::default(), &stopped).unwrap();
    assert_eq!(report.note.as_deref(), Some("stopped the running daemon (pid 4242) so the managed one takes over"));
    let unsupported = |_: &Path| -> Result<StopOutcome, StopError> { Err(StopError::Unsupported) };
    let report = install_with(&env(Platform::Linux, home.path()), &FakeRunner::default(), &unsupported).unwrap();
    assert!(report.note.as_deref().unwrap().contains("keeps running"));
}
```

`std::os::unix::process::ExitStatusExt` makes this test file unix-only;
gate the whole file with `#![cfg(unix)]` at its top and, on Windows,
provide `ExitStatus` through `std::os::windows::process::ExitStatusExt::from_raw(code as u32)`
behind `#[cfg(windows)]` in a tiny helper `fn exit(code: i32) -> ExitStatus`
instead if you prefer both hosts to run it; either is acceptable, the
CI Windows targets must compile the crate's tests.

Run `cargo test -p pam_client --lib service_test` — expect the new tests
to fail (functions missing).

- [ ] **Step 4: The managers**

Append to `service.rs`:

```rust
// --- managers ---------------------------------------------------------------

/// Where the unit lives, per platform.
fn unit_path(env: &ServiceEnv) -> PathBuf {
    match env.platform {
        Platform::Macos => env
            .home
            .join("Library/LaunchAgents")
            .join(format!("{LAUNCHD_LABEL}.plist")),
        Platform::Linux => env.home.join(".config/systemd/user").join(SYSTEMD_UNIT),
        Platform::Windows | Platform::Other => PathBuf::from(WINDOWS_TASK),
    }
}

fn args(parts: &[&str]) -> Vec<OsString> {
    parts.iter().map(OsString::from).collect()
}

/// Runs a command that must succeed; a non-zero exit is a legible
/// [`ServiceError::Command`].
fn must(runner: &dyn Runner, program: &str, argv: &[OsString]) -> Result<Output, ServiceError> {
    let output = runner.run(program, argv).map_err(|source| ServiceError::Spawn {
        program: program.to_owned(),
        source,
    })?;
    if output.status.success() {
        return Ok(output);
    }
    Err(ServiceError::Command {
        program: program.to_owned(),
        args: argv
            .iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect::<Vec<_>>()
            .join(" "),
        status: output.status.to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).trim().to_owned(),
    })
}

/// Runs a command whose failure is informational (a `bootout` of a unit
/// that is not loaded, an `is-active` that answers inactive).
fn probe(runner: &dyn Runner, program: &str, argv: &[OsString]) -> Result<bool, ServiceError> {
    runner
        .run(program, argv)
        .map(|output| output.status.success())
        .map_err(|source| ServiceError::Spawn {
            program: program.to_owned(),
            source,
        })
}

fn write_unit(path: &Path, body: &str) -> Result<(), ServiceError> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|source| ServiceError::Write {
            path: dir.to_path_buf(),
            source,
        })?;
    }
    std::fs::write(path, body).map_err(|source| ServiceError::Write {
        path: path.to_path_buf(),
        source,
    })
}

fn remove_unit(path: &Path) -> Result<(), ServiceError> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(ServiceError::Remove {
            path: path.to_path_buf(),
            source,
        }),
    }
}

fn report(env: &ServiceEnv, state: ServiceState, note: Option<String>) -> ServiceReport {
    ServiceReport {
        platform: env.platform.as_str(),
        exe: env.exe.clone(),
        state,
        note,
    }
}

/// The reason a configuration cannot be managed, or `None`.
fn unsupported(env: &ServiceEnv) -> Option<String> {
    match env.platform {
        Platform::Other => Some(format!(
            "{} has no login-start integration",
            std::env::consts::OS
        )),
        Platform::Windows if env.base_override.is_some() => Some(
            "scheduled tasks carry no environment, so PAM_BASE_DIR cannot be honoured; \
             unset it to install the login task"
                .to_owned(),
        ),
        _ => None,
    }
}

fn macos_uid(runner: &dyn Runner) -> Result<String, ServiceError> {
    let output = must(runner, "id", &args(&["-u"]))?;
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

/// Reports whether the unit is registered and loaded.
///
/// # Errors
///
/// Manager tools that cannot be spawned; a manager saying "no" is a state,
/// not an error.
pub fn status(env: &ServiceEnv, runner: &dyn Runner) -> Result<ServiceReport, ServiceError> {
    if let Some(reason) = unsupported(env) {
        return Ok(report(env, ServiceState::Unsupported { reason }, None));
    }
    let unit = unit_path(env);
    let unit_name = unit.display().to_string();
    let state = match env.platform {
        Platform::Macos => {
            if unit.is_file() {
                let uid = macos_uid(runner)?;
                let loaded = probe(
                    runner,
                    "launchctl",
                    &args(&["print", &format!("gui/{uid}/{LAUNCHD_LABEL}")]),
                )?;
                ServiceState::Installed { unit: unit_name, loaded }
            } else {
                ServiceState::NotInstalled { unit: unit_name }
            }
        }
        Platform::Linux => {
            if unit.is_file() {
                let loaded = probe(runner, "systemctl", &args(&["--user", "is-active", SYSTEMD_UNIT]))?;
                ServiceState::Installed { unit: unit_name, loaded }
            } else {
                ServiceState::NotInstalled { unit: unit_name }
            }
        }
        Platform::Windows => {
            if probe(runner, "schtasks", &args(&["/Query", "/TN", WINDOWS_TASK]))? {
                ServiceState::Installed { unit: WINDOWS_TASK.to_owned(), loaded: true }
            } else {
                ServiceState::NotInstalled { unit: WINDOWS_TASK.to_owned() }
            }
        }
        Platform::Other => unreachable!("filtered by unsupported()"),
    };
    Ok(report(env, state, None))
}

/// Registers the login-start unit and starts it now, stopping a loose
/// daemon first (bounded) so the managed instance takes over.
///
/// # Errors
///
/// Unit write failures, manager command failures, or a stop that failed
/// for a reason other than "not supported here".
pub fn install(env: &ServiceEnv, runner: &dyn Runner) -> Result<ServiceReport, ServiceError> {
    install_with(env, runner, &|base| client::stop_daemon(base, STOP_WAIT))
}

/// [`install`] with the stop step injected.
///
/// # Errors
///
/// See [`install`].
pub fn install_with(
    env: &ServiceEnv,
    runner: &dyn Runner,
    stop: StopFn<'_>,
) -> Result<ServiceReport, ServiceError> {
    if let Some(reason) = unsupported(env) {
        return Ok(report(env, ServiceState::Unsupported { reason }, None));
    }
    let note = match stop(&env.base) {
        Ok(StopOutcome::NotRunning) => None,
        Ok(StopOutcome::Stopped { pid }) => Some(format!(
            "stopped the running daemon (pid {pid}) so the managed one takes over"
        )),
        Ok(StopOutcome::StillDraining { pid }) => Some(format!(
            "the running daemon (pid {pid}) is still draining; the managed one takes over when it exits"
        )),
        Err(StopError::Unsupported) => Some(
            "a daemon is already running and keeps running; the login task takes over at the next logon"
                .to_owned(),
        ),
        Err(err) => return Err(ServiceError::Stop(err)),
    };
    let unit = unit_path(env);
    let unit_name = unit.display().to_string();
    match env.platform {
        Platform::Macos => {
            let uid = macos_uid(runner)?;
            let log_dir = env.base.join("log");
            write_unit(&unit, &render_launch_agent(&env.exe, &log_dir, env.base_override.as_deref()))?;
            // A previous registration must go before bootstrap accepts the file again.
            let _ = probe(runner, "launchctl", &args(&["bootout", &format!("gui/{uid}/{LAUNCHD_LABEL}")]))?;
            must(runner, "launchctl", &args(&["bootstrap", &format!("gui/{uid}"), &unit_name]))?;
        }
        Platform::Linux => {
            write_unit(&unit, &render_systemd_unit(&env.exe, env.base_override.as_deref()))?;
            must(runner, "systemctl", &args(&["--user", "daemon-reload"]))?;
            must(runner, "systemctl", &args(&["--user", "enable", "--now", SYSTEMD_UNIT]))?;
        }
        Platform::Windows => {
            let action = windows_task_action(&env.exe);
            must(
                runner,
                "schtasks",
                &args(&["/Create", "/F", "/SC", "ONLOGON", "/RL", "LIMITED", "/TN", WINDOWS_TASK, "/TR", &action]),
            )?;
            let _ = probe(runner, "schtasks", &args(&["/Run", "/TN", WINDOWS_TASK]))?;
        }
        Platform::Other => unreachable!("filtered by unsupported()"),
    }
    Ok(report(env, ServiceState::Installed { unit: unit_name, loaded: true }, note))
}

/// Unregisters and removes the unit. Never stops a running daemon.
///
/// # Errors
///
/// Unit removal failures or manager tools that cannot be spawned.
pub fn uninstall(env: &ServiceEnv, runner: &dyn Runner) -> Result<ServiceReport, ServiceError> {
    if let Some(reason) = unsupported(env) {
        return Ok(report(env, ServiceState::Unsupported { reason }, None));
    }
    let unit = unit_path(env);
    let unit_name = unit.display().to_string();
    match env.platform {
        Platform::Macos => {
            let uid = macos_uid(runner)?;
            let _ = probe(runner, "launchctl", &args(&["bootout", &format!("gui/{uid}/{LAUNCHD_LABEL}")]))?;
            remove_unit(&unit)?;
        }
        Platform::Linux => {
            let _ = probe(runner, "systemctl", &args(&["--user", "disable", "--now", SYSTEMD_UNIT]))?;
            remove_unit(&unit)?;
            let _ = probe(runner, "systemctl", &args(&["--user", "daemon-reload"]))?;
        }
        Platform::Windows => {
            let _ = probe(runner, "schtasks", &args(&["/Delete", "/TN", WINDOWS_TASK, "/F"]))?;
        }
        Platform::Other => unreachable!("filtered by unsupported()"),
    }
    Ok(report(env, ServiceState::NotInstalled { unit: unit_name }, None))
}
```

Add `pub mod service;` and `#[cfg(test)] mod service_test;` to
`crates/pam_client/src/lib.rs` and `serde.workspace = true` to its
`[dependencies]`. Run `cargo test -p pam_client --lib service_test` —
expect all tests PASS. Clippy may ask for `#[allow(clippy::too_many_lines)]`
on `install_with`; split the platform arms into `install_macos` /
`install_linux` / `install_windows` helpers instead.

- [ ] **Step 5: Gate and commit**

```bash
tools/check.sh
git add crates/pam_client
git commit -m "feat(client): login-start service module — LaunchAgent, systemd user unit, scheduled task"
```

PR title: `feat(client): login-start service module (LaunchAgent, systemd --user, scheduled task)`.

---

### Task 3: README, CHANGELOG, LICENSE, mark

**Files:**
- Create: `README.md`, `CHANGELOG.md`, `LICENSE`, `docs/assets/pam-mark.svg`

**Interfaces:**
- Produces: `CHANGELOG.md` with a `## [Unreleased]` section (Task 7's
  release validation greps `## [X.Y.Z]` headings); README sections the
  later tasks link to (`## Start at login`, `## Releasing`).

- [ ] **Step 1: Copy the license and the mark**

```bash
cp ~/dev/rs/pam-old/LICENSE LICENSE
mkdir -p docs/assets && cp ~/dev/rs/pam-old/docs/assets/pam-mark.svg docs/assets/pam-mark.svg
head -3 LICENSE   # expect the Apache License 2.0 header
```

- [ ] **Step 2: CHANGELOG.md**

```markdown
# Changelog

All notable changes to pam are documented in this file. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and pam adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Packages on every first-class target: a signed, notarized macOS dmg
  (arm64), Linux AppImage and deb (amd64, arm64), and a per-user Windows
  NSIS installer (amd64, arm64), built by CI and published by the release
  workflow on `v*` tags.
- `pam service install | uninstall | status`: start the daemon at login
  through a macOS LaunchAgent, a systemd user unit, or a per-user Windows
  scheduled task. Settings › Daemon shows the same state with Install and
  Remove.
- Double-clicking `pam.app` opens the control center; the Linux desktop
  entry and the Windows shortcuts run `pam gui`.

### Changed

- `crates/pam` owns the Tauri app configuration; `pam_gui` is a plain
  library behind it.
```

- [ ] **Step 3: README.md**

Write it in pam-old's shape with v2 content. Required sections and their
substance (prose is yours; facts are these):

- Header: the mark (`docs/assets/pam-mark.svg`, width 160), `<h1>pam</h1>`,
  tagline **A local lifeguard for developers and AI agents.**, badges for
  License (Apache-2.0), latest release
  (`https://img.shields.io/github/v/release/ro-ag/pam`), and CI
  (`https://github.com/ro-ag/pam/actions/workflows/ci.yml/badge.svg?branch=main`).
- One paragraph from the north star: a single-binary local companion
  (CLI, daemon, GUI) that gives sandboxed agents controlled, audited
  access to real capabilities — local models first, flows, connectors —
  with security administration in the GUI only.
- The modes block:

  ```text
  pam status                  # client mode (default): talk to the daemon
  pam daemon                  # the local background service (started lazily by any command)
  pam gui                     # the desktop control center
  pam flow run pr-readiness   # run one flow and print its verdict
  ```

- `## Install` — table: macOS 12+ arm64 → signed, notarized dmg (drag
  `pam.app` to Applications; the CLI is
  `/Applications/pam.app/Contents/MacOS/pam`, symlink it into your PATH);
  Linux amd64/arm64 → AppImage or deb (`/usr/bin/pam`); Windows
  amd64/arm64 → NSIS per-user installer (`%LOCALAPPDATA%\pam\pam.exe`,
  Start-menu shortcut opens the GUI; the console window behind the GUI is
  expected). Link `https://github.com/ro-ag/pam/releases/latest`.
- `## Quickstart` — `pam status`, `pam flow list`, `pam flow run <id>`,
  `pam gui`; grants, approvals, and profiles live in the GUI (Settings ›
  Security).
- `## Start at login` — `pam service install`, `pam service status`,
  `pam service uninstall`; what each platform writes (LaunchAgent
  `~/Library/LaunchAgents/com.github.ro-ag.pam.daemon.plist`, systemd
  `~/.config/systemd/user/pam-daemon.service`, scheduled task `pam\daemon`);
  user scope only; Settings › Daemon has the same row.
- `## Build from source` — toolchain from `rust-toolchain.toml`, Node 22,
  `npm --prefix frontend ci`, `tools/check.sh` (the whole gate),
  `npm --prefix frontend run gui:build` (embedded-frontend binary),
  `npm --prefix frontend run tauri -- build` (platform bundles).
- `## Releasing` — bump the version in `Cargo.toml` (`[workspace.package]`),
  `crates/pam/tauri.conf.json`, `frontend/package.json`; move the
  changelog's Unreleased entries under `## [X.Y.Z] - YYYY-MM-DD`; merge;
  wait for the `main` CI run to finish green; `git tag vX.Y.Z && git push
  origin vX.Y.Z`; `release.yml` validates, signs, notarizes, and publishes.
  Releases are cut only from CI on a tag push.
- `## License` — Apache-2.0.

- [ ] **Step 4: Gate and commit**

`tools/check.sh` (docs only; still run it). Commit:

```bash
git add README.md CHANGELOG.md LICENSE docs/assets/pam-mark.svg
git commit -m "docs: README, CHANGELOG, LICENSE, mark"
```

PR title: `docs: README, CHANGELOG, LICENSE`.

---

### Task 4: `pam service install | uninstall | status [--json]`

Needs Tasks 1 and 2 merged.

**Files:**
- Modify: `crates/pam/src/main.rs` (new `Cmd::Service`, `ServiceCmd`, dispatch), `crates/pam/src/lib.rs` (subcommand docs), `crates/pam/src/render.rs`, `crates/pam/src/render_test.rs`

**Interfaces:**
- Consumes: `pam_client::service::{ServiceEnv, CommandRunner, ServiceReport, ServiceState, ServiceError, status, install, uninstall}` (Task 2).
- Produces: `pam::render::render_service_report(report: &ServiceReport) -> String`.

- [ ] **Step 1: Failing renderer test**

Append to `crates/pam/src/render_test.rs`:

```rust
#[test]
fn service_report_prints_one_fact_per_line() {
    use pam_client::service::{ServiceReport, ServiceState};
    let installed = ServiceReport {
        platform: "macos",
        exe: "/Applications/pam.app/Contents/MacOS/pam".into(),
        state: ServiceState::Installed {
            unit: "/Users/me/Library/LaunchAgents/com.github.ro-ag.pam.daemon.plist".to_owned(),
            loaded: true,
        },
        note: Some("stopped the running daemon (pid 7) so the managed one takes over".to_owned()),
    };
    let text = render::render_service_report(&installed);
    assert_eq!(
        text,
        "platform  macos\n\
         state     installed, loaded\n\
         unit      /Users/me/Library/LaunchAgents/com.github.ro-ag.pam.daemon.plist\n\
         exe       /Applications/pam.app/Contents/MacOS/pam\n\
         note      stopped the running daemon (pid 7) so the managed one takes over\n"
    );
    let unsupported = ServiceReport {
        platform: "other",
        exe: "/x/pam".into(),
        state: ServiceState::Unsupported { reason: "freebsd has no login-start integration".to_owned() },
        note: None,
    };
    assert!(render::render_service_report(&unsupported).contains("state     unsupported: freebsd has no login-start integration\n"));
    let absent = ServiceReport {
        platform: "linux",
        exe: "/usr/bin/pam".into(),
        state: ServiceState::NotInstalled { unit: "/home/me/.config/systemd/user/pam-daemon.service".to_owned() },
        note: None,
    };
    assert!(render::render_service_report(&absent).contains("state     not installed\n"));
}
```

Run `cargo test -p pam --lib render_test::service_report_prints_one_fact_per_line` — expect a compile failure.

- [ ] **Step 2: Renderer**

Append to `crates/pam/src/render.rs`:

```rust
/// `pam service …` human output: one fact per line, aligned like the
/// rest of the CLI's summaries.
#[must_use]
pub fn render_service_report(report: &pam_client::service::ServiceReport) -> String {
    use pam_client::service::ServiceState;
    let mut out = String::new();
    out.push_str(&format!("platform  {}\n", report.platform));
    match &report.state {
        ServiceState::Installed { unit, loaded } => {
            out.push_str(&format!(
                "state     installed, {}\n",
                if *loaded { "loaded" } else { "not loaded" }
            ));
            out.push_str(&format!("unit      {unit}\n"));
        }
        ServiceState::NotInstalled { unit } => {
            out.push_str("state     not installed\n");
            out.push_str(&format!("unit      {unit}\n"));
        }
        ServiceState::Unsupported { reason } => {
            out.push_str(&format!("state     unsupported: {reason}\n"));
        }
    }
    out.push_str(&format!("exe       {}\n", report.exe.display()));
    if let Some(note) = &report.note {
        out.push_str(&format!("note      {note}\n"));
    }
    out
}
```

(`format!` pushes are fine here; if clippy asks, switch to `writeln!` on
the `String` with `use std::fmt::Write as _;`.) Run the test — PASS.

- [ ] **Step 3: Subcommand**

In `crates/pam/src/main.rs` add to `enum Cmd` (after `Flow`):

```rust
    /// Start the daemon at login: a user-scope LaunchAgent, systemd user
    /// unit, or scheduled task. Never sudo or admin.
    Service {
        #[command(subcommand)]
        action: ServiceCmd,
    },
```

and the enum:

```rust
/// `pam service`: the login-start unit for the daemon.
#[derive(Subcommand)]
enum ServiceCmd {
    /// Register the unit and start the managed daemon now (a loose
    /// daemon is stopped first so the managed one takes over).
    Install {
        /// Print the report as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Unregister and remove the unit. The running daemon is left alone.
    Uninstall {
        /// Print the report as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Show whether the unit exists and whether the manager has it loaded.
    Status {
        /// Print the report as JSON.
        #[arg(long)]
        json: bool,
    },
}
```

In `main()` route it before `client_mode` (it needs no async runtime):

```rust
        Cmd::Service { action } => service_command(action),
```

and add:

```rust
/// `pam service …`: the shared mechanics live in
/// [`pam_client::service`]; this prints the report and maps failures.
fn service_command(action: ServiceCmd) -> ExitCode {
    use pam_client::service::{self, CommandRunner, ServiceEnv};
    let Some(base) = base_dir() else {
        eprintln!("pam service: cannot resolve the home directory; set $HOME");
        return ExitCode::FAILURE;
    };
    let env = match ServiceEnv::detect(&base) {
        Ok(env) => env,
        Err(err) => {
            eprintln!("pam service: {err}\n  {}", err.recovery());
            return ExitCode::FAILURE;
        }
    };
    let runner = CommandRunner;
    let (result, json) = match action {
        ServiceCmd::Install { json } => (service::install(&env, &runner), json),
        ServiceCmd::Uninstall { json } => (service::uninstall(&env, &runner), json),
        ServiceCmd::Status { json } => (service::status(&env, &runner), json),
    };
    match result {
        Ok(report) if json => {
            println!("{}", serde_json::to_string_pretty(&report).unwrap_or_default());
            ExitCode::SUCCESS
        }
        Ok(report) => {
            print!("{}", render::render_service_report(&report));
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("pam service: {err}\n  {}", err.recovery());
            ExitCode::FAILURE
        }
    }
}
```

Also extend the `Cmd::Daemon { .. } | Cmd::Gui => unreachable!(...)` arm in
`run_client_command` to include `Cmd::Service { .. }`.

- [ ] **Step 4: Docs**

In `crates/pam/src/lib.rs`'s subcommand list add, before the `pam daemon`
bullet:

```
//! - `pam service install | uninstall | status [--json]` — start the
//!   daemon at login through a user-scope unit (macOS LaunchAgent, systemd
//!   user unit, Windows scheduled task). `install` stops a loose daemon
//!   first so the managed one takes over; `uninstall` never stops it.
```

- [ ] **Step 5: Bench smoke (macOS), gate, commit**

```bash
cargo build -p pam
target/debug/pam service status
target/debug/pam service install
launchctl print gui/$(id -u)/com.github.ro-ag.pam.daemon | head -5
target/debug/pam status
target/debug/pam service uninstall
target/debug/pam service status --json
```

Expected: `not installed` → `installed, loaded` with the plist path;
`launchctl print` shows the service with `state = running`; `pam status`
answers; after uninstall, `not installed` and the plist is gone. Then:

```bash
tools/check.sh
git add crates/pam
git commit -m "feat(cli): pam service install|uninstall|status"
```

PR title: `feat(cli): pam service install|uninstall|status`.

---

### Task 5: Settings › Daemon "start at login" row

Needs Tasks 1 and 2 merged. Disjoint from Task 4 (no `main.rs`, no
`render.rs`).

**Files:**
- Create: `crates/pam_gui/src/service.rs`, `crates/pam_gui/src/service_test.rs`
- Modify: `crates/pam_gui/src/lib.rs` (mod + handler), `crates/pam/build.rs` (three commands), `crates/pam/capabilities/main-window.json` (three grants), `crates/pam/src/config_test.rs` (`BRIDGE_COMMANDS` grows to 9), `frontend/src/lib/ipc.ts`, `frontend/src/screens/Settings.tsx`, `frontend/src/screens/Settings.test.tsx`

**Interfaces:**
- Consumes: `pam_client::service::*` (Task 2).
- Produces: Tauri commands `service_status`, `service_install`, `service_uninstall` → `ServiceReport`; `ipc.ts` `serviceStatus()`, `serviceInstall()`, `serviceUninstall()` → `Promise<ServiceReport>` with

  ```ts
  export type ServiceState =
    | { kind: "installed"; unit: string; loaded: boolean }
    | { kind: "not_installed"; unit: string }
    | { kind: "unsupported"; reason: string };
  export interface ServiceReport { platform: string; exe: string; state: ServiceState; note: string | null; }
  ```

- [ ] **Step 1: Failing Rust test for the error mapping**

`crates/pam_gui/src/service_test.rs`:

```rust
use pam_client::service::ServiceError;

use crate::service::bridge_error;

#[test]
fn service_failures_keep_the_module_recovery_line() {
    let err = ServiceError::Unsupported { platform: "other" };
    let mapped = bridge_error(&err);
    assert_eq!(mapped.cause, "service_failed");
    assert_eq!(mapped.detail, "other has no login-start integration");
    assert_eq!(mapped.recovery, err.recovery());
}
```

- [ ] **Step 2: The commands**

`crates/pam_gui/src/service.rs`:

```rust
//! Login-start commands for Settings › Daemon: thin, blocking-pool
//! wrappers over [`pam_client::service`], the module `pam service …`
//! uses. The report is the module's, serialized as is.

use pam_client::service::{self, CommandRunner, ServiceEnv, ServiceError, ServiceReport};

use crate::bridge::BridgeError;

/// Maps a module failure onto the bridge's refusal shape.
#[must_use]
pub fn bridge_error(err: &ServiceError) -> BridgeError {
    BridgeError::new("service_failed", err.to_string(), err.recovery())
}

enum Op {
    Status,
    Install,
    Uninstall,
}

async fn run(op: Op) -> Result<ServiceReport, BridgeError> {
    let base = crate::bridge::resolve_base_dir()?;
    tauri::async_runtime::spawn_blocking(move || {
        let env = ServiceEnv::detect(&base).map_err(|err| bridge_error(&err))?;
        let runner = CommandRunner;
        let result = match op {
            Op::Status => service::status(&env, &runner),
            Op::Install => service::install(&env, &runner),
            Op::Uninstall => service::uninstall(&env, &runner),
        };
        result.map_err(|err| bridge_error(&err))
    })
    .await
    .map_err(|err| {
        BridgeError::new(
            "internal_error",
            format!("the service task failed: {err}"),
            "Retry; report this if it persists.",
        )
    })?
}

/// Whether the login-start unit exists and is loaded.
#[tauri::command]
pub async fn service_status() -> Result<ServiceReport, BridgeError> {
    run(Op::Status).await
}

/// Registers the unit and starts the managed daemon.
#[tauri::command]
pub async fn service_install() -> Result<ServiceReport, BridgeError> {
    run(Op::Install).await
}

/// Unregisters and removes the unit; the daemon keeps running.
#[tauri::command]
pub async fn service_uninstall() -> Result<ServiceReport, BridgeError> {
    run(Op::Uninstall).await
}
```

`resolve_base_dir` in `bridge.rs` is private today: make it `pub(crate)`.
`BridgeError::new` is already `pub(crate)`. In `lib.rs` add `pub mod
service;`, `#[cfg(test)] mod service_test;`, and the three commands to
`generate_handler!`. In `crates/pam/build.rs` append `"service_status",
"service_install", "service_uninstall"` to the commands list; in
`capabilities/main-window.json` add `"allow-service-status"`,
`"allow-service-install"`, `"allow-service-uninstall"`; in
`config_test.rs` grow `BRIDGE_COMMANDS` to nine entries. Run
`cargo test -p pam_gui --lib service_test` and `cargo test -p pam --lib
config_test` — PASS.

- [ ] **Step 3: Failing vitest**

Add to the `mocks` object in `Settings.test.tsx`: `serviceStatus: vi.fn()`,
`serviceInstall: vi.fn()`, `serviceUninstall: vi.fn()`; in `beforeEach`:

```ts
  mocks.serviceStatus.mockResolvedValue({
    platform: "macos",
    exe: "/Applications/pam.app/Contents/MacOS/pam",
    state: { kind: "not_installed", unit: "/Users/me/Library/LaunchAgents/com.github.ro-ag.pam.daemon.plist" },
    note: null,
  });
  mocks.serviceInstall.mockResolvedValue({
    platform: "macos",
    exe: "/Applications/pam.app/Contents/MacOS/pam",
    state: { kind: "installed", unit: "/Users/me/Library/LaunchAgents/com.github.ro-ag.pam.daemon.plist", loaded: true },
    note: "stopped the running daemon (pid 7) so the managed one takes over",
  });
  mocks.serviceUninstall.mockResolvedValue({
    platform: "macos",
    exe: "/Applications/pam.app/Contents/MacOS/pam",
    state: { kind: "not_installed", unit: "/Users/me/Library/LaunchAgents/com.github.ro-ag.pam.daemon.plist" },
    note: null,
  });
```

New tests inside `describe("daemon", …)`:

```ts
  it("offers to install the login unit when none exists", async () => {
    renderSettings();
    const card = within(await screen.findByRole("region", { name: "Daemon" }));
    expect(await card.findByText("not installed")).toBeInTheDocument();
    expect(card.getByText(/com\.github\.ro-ag\.pam\.daemon\.plist/)).toBeInTheDocument();
    fireEvent.click(card.getByRole("button", { name: "Install" }));
    await waitFor(() => expect(mocks.serviceInstall).toHaveBeenCalledTimes(1));
    expect(await card.findByText(/stopped the running daemon \(pid 7\)/)).toBeInTheDocument();
  });

  it("removes the login unit only after the two-tap confirm", async () => {
    mocks.serviceStatus.mockResolvedValue({
      platform: "linux",
      exe: "/usr/bin/pam",
      state: { kind: "installed", unit: "/home/me/.config/systemd/user/pam-daemon.service", loaded: false },
      note: null,
    });
    renderSettings();
    const card = within(await screen.findByRole("region", { name: "Daemon" }));
    expect(await card.findByText("installed, not loaded")).toBeInTheDocument();
    fireEvent.click(card.getByRole("button", { name: "Remove" }));
    expect(mocks.serviceUninstall).not.toHaveBeenCalled();
    fireEvent.click(card.getByRole("button", { name: "remove it?" }));
    await waitFor(() => expect(mocks.serviceUninstall).toHaveBeenCalledTimes(1));
    expect(await card.findByText(/removed · the daemon keeps running/)).toBeInTheDocument();
  });

  it("explains an unsupported platform instead of offering buttons", async () => {
    mocks.serviceStatus.mockResolvedValue({
      platform: "windows",
      exe: "C:\\pam\\pam.exe",
      state: { kind: "unsupported", reason: "scheduled tasks carry no environment, so PAM_BASE_DIR cannot be honoured; unset it to install the login task" },
      note: null,
    });
    renderSettings();
    const card = within(await screen.findByRole("region", { name: "Daemon" }));
    expect(await card.findByText("unsupported")).toBeInTheDocument();
    expect(card.getByText(/PAM_BASE_DIR cannot be honoured/)).toBeInTheDocument();
    expect(card.queryByRole("button", { name: "Install" })).toBeNull();
    expect(card.queryByRole("button", { name: "Remove" })).toBeNull();
  });
```

Run `npm --prefix frontend run test -- Settings` — expect failures.

- [ ] **Step 4: ipc wrappers**

Append to `ipc.ts` after the daemon section:

```ts
// --- login-start service ---------------------------------------------------

export type ServiceState =
  | { kind: "installed"; unit: string; loaded: boolean }
  | { kind: "not_installed"; unit: string }
  | { kind: "unsupported"; reason: string };

/** What `pam service …` and the three service commands answer. */
export interface ServiceReport {
  platform: string;
  exe: string;
  state: ServiceState;
  note: string | null;
}

/** Whether the login-start unit exists and is loaded. */
export function serviceStatus(): Promise<ServiceReport> {
  return bridged<ServiceReport>("service_status");
}

/** Registers the unit and starts the managed daemon (a loose one is stopped first). */
export function serviceInstall(): Promise<ServiceReport> {
  return bridged<ServiceReport>("service_install");
}

/** Unregisters and removes the unit; the daemon keeps running. */
export function serviceUninstall(): Promise<ServiceReport> {
  return bridged<ServiceReport>("service_uninstall");
}
```

- [ ] **Step 5: The row in `DaemonPanel`**

Import `serviceInstall, serviceStatus, serviceUninstall, type ServiceReport`
in `Settings.tsx`. Inside `DaemonPanel`, after the `stop` mutation:

```tsx
  const service = useQuery({ queryKey: ["daemon", "service"], queryFn: serviceStatus });
  const [serviceNote, setServiceNote] = useState<string | null>(null);
  const [serviceFailure, setServiceFailure] = useState<BridgeFailure | null>(null);
  const applyService = (reply: ServiceReport, fallback: string) => {
    queryClient.setQueryData(["daemon", "service"], reply);
    setServiceNote(reply.note ?? fallback);
  };
  const install = useMutation({
    mutationFn: () => serviceInstall(),
    onMutate: () => {
      setServiceFailure(null);
      setServiceNote(null);
    },
    onSuccess: (reply) => applyService(reply, "installed · the daemon now starts at login"),
    onError: (error) => setServiceFailure(toBridgeFailure(error)),
    onSettled: refreshSoon,
  });
  const remove = useMutation({
    mutationFn: () => serviceUninstall(),
    onMutate: () => {
      setServiceFailure(null);
      setServiceNote(null);
    },
    onSuccess: (reply) => applyService(reply, "removed · the daemon keeps running until it exits"),
    onError: (error) => setServiceFailure(toBridgeFailure(error)),
  });
  const serviceState = service.data?.state;
  const serviceLabel =
    serviceState === undefined
      ? "—"
      : serviceState.kind === "installed"
        ? `installed, ${serviceState.loaded ? "loaded" : "not loaded"}`
        : serviceState.kind === "not_installed"
          ? "not installed"
          : "unsupported";
  const serviceTone =
    serviceState?.kind === "installed"
      ? serviceState.loaded
        ? "success"
        : "warning"
      : "neutral";
  const serviceDetail =
    serviceState === undefined
      ? ""
      : serviceState.kind === "unsupported"
        ? serviceState.reason
        : serviceState.unit;
```

Render it between the facts `<dl>` and the "not answering" paragraph:

```tsx
      {!bridgeDown && (
        <div className="flex flex-wrap items-center gap-3 border-t border-line pt-4">
          <div className="min-w-0 flex-1 space-y-0.5">
            <p className="font-data text-xs text-ink-faint">start at login</p>
            <p className="truncate font-data text-xs text-ink-muted" title={serviceDetail}>
              {serviceDetail || "—"}
            </p>
          </div>
          <Badge tone={serviceTone}>{serviceLabel}</Badge>
          {serviceState?.kind === "not_installed" && (
            <Button size="sm" disabled={install.isPending} onClick={() => install.mutate()}>
              Install
            </Button>
          )}
          {serviceState?.kind === "installed" && (
            <ConfirmButton
              label="Remove"
              confirmLabel="remove it?"
              busy={remove.isPending}
              onConfirm={() => remove.mutate()}
            />
          )}
        </div>
      )}
      {serviceNote && <p className="font-data text-xs text-ink-muted">{serviceNote}</p>}
      {serviceFailure && <FailureNote failure={serviceFailure} label="start at login" />}
```

A `service.isError` (bridge unavailable in the browser) renders no row
error of its own: the panel's existing `bridgeDown` note already covers
it, and the badge shows `—`. Update the panel's doc comment: the daemon
card now also owns the login-start row.

- [ ] **Step 6: Gate, fixture eyeball, commit**

```bash
npm --prefix frontend run test -- Settings
tools/check.sh
```

Eyeball in the fixture browser (memory `gui-fixture-live-proxy`: the
proxy must answer `service_status` — add a `/service/<op>` route that
calls `pam_client::service::{status,install,uninstall}` with
`CommandRunner`, or map the shim's `invoke("service_status")` to a
canned report) in one light and one dark theme; confirm the badge, the
unit path, Install, and the note. Then:

```bash
npm --prefix frontend run build && cargo build --release -p pam --features gui-embed
strings target/release/pam | grep -c 'service_install'
```

Expected: a non-zero count. Commit:

```bash
git add crates/pam crates/pam_gui frontend/src
git commit -m "feat(gui): Settings › Daemon start-at-login row"
```

PR title: `feat(gui): Settings › Daemon start-at-login row`.

---

### Task 6: CI package jobs, dmg tooling, dependabot

Needs Task 1 merged (the `tauri` npm script and `crates/pam` config).

**Files:**
- Modify: `.github/workflows/ci.yml`
- Create: `.github/dependabot.yml`, `tools/package-macos-dmg.sh`, `tools/dmg/` (copied from pam-old: `DS_Store`, `author-layout.sh`, `background.png`, `background.svg`, `background@2x.png`, `render-background.sh`)

**Interfaces:**
- Produces: artifacts `pam-linux-amd64`, `pam-linux-arm64`, `pam-windows-amd64`, `pam-windows-arm64` (each a `pam-<target>-bundle.tar.gz` on Linux / the `bundle` dir on Windows) and `pam-macos-arm64` (`pam-macos-arm64-bundle.tar.gz` with `macos/pam.app` and `dmg/<name>.dmg`); the `gate` job output `packages`.
- Consumed by: Task 7 (`release.yml` downloads these by name).

- [ ] **Step 1: Port the dmg tooling**

```bash
mkdir -p tools/dmg
cp ~/dev/rs/pam-old/tools/dmg/{DS_Store,author-layout.sh,background.png,background.svg,background@2x.png,render-background.sh} tools/dmg/
cp ~/dev/rs/pam-old/tools/package-macos-dmg.sh tools/package-macos-dmg.sh
sed -i '' 's#readonly volume_icon="\$repository/src-tauri/icons/icon.icns"#readonly volume_icon="$repository/crates/pam/icons/icon.icns"#' tools/package-macos-dmg.sh
grep -n 'volume_icon=' tools/package-macos-dmg.sh
```

Keep the volume name `Pam` (the committed `.DS_Store` layout was authored
against it). Verify on the bench after a `tauri build --bundles app`:

```bash
tools/package-macos-dmg.sh "$PWD/target/release/bundle/macos/pam.app" "$PWD/target/release/bundle/dmg"
hdiutil attach target/release/bundle/dmg/pam_0.1.0_aarch64.dmg -nobrowse -mountpoint /tmp/pamdmg && ls /tmp/pamdmg && hdiutil detach /tmp/pamdmg
```

Expected: `Applications pam.app` listed.

- [ ] **Step 2: Dependabot**

`.github/dependabot.yml`:

```yaml
version: 2
updates:
  - package-ecosystem: github-actions
    directory: /
    schedule:
      interval: weekly
```

- [ ] **Step 3: ci.yml — header, pins, gate output**

Resolve SHAs for `actions/checkout@v4`, `actions/setup-node@v4`,
`Swatinem/rust-cache@v2`, `dtolnay/rust-toolchain@stable`,
`actions/upload-artifact@v4` (the commands are in Global Constraints) and
pin every `uses:`. Rewrite the top of the file:

```yaml
name: CI
on:
  pull_request:
    branches: [main]
    paths-ignore: ["docs/**", "**/*.md"]
  push:
    branches: [main]
    tags: ["v*"]
    paths-ignore: ["docs/**", "**/*.md"]
  workflow_dispatch:
permissions:
  contents: read
concurrency:
  group: ci-${{ github.ref }}
  # Superseded PR runs are waste; a main run must finish so release.yml
  # can reuse its artifacts.
  cancel-in-progress: ${{ github.event_name == 'pull_request' }}
env:
  CARGO_TERM_COLOR: always
  CARGO_INCREMENTAL: "0"
```

`gate` gains `timeout-minutes: 30`, an `outputs:` block, and a last step:

```yaml
    outputs:
      packages: ${{ steps.packages.outputs.matrix }}
    steps:
      # …existing steps unchanged…
      - name: Choose the desktop packages this run builds
        id: packages
        shell: bash
        run: |
          set -euo pipefail
          linux_amd64='{"name":"Linux amd64 package","runner":"ubuntu-24.04","target":"x86_64-unknown-linux-gnu","bundles":"appimage,deb","family":"linux","artifact":"pam-linux-amd64"}'
          linux_arm64='{"name":"Linux arm64 package","runner":"ubuntu-24.04-arm","target":"aarch64-unknown-linux-gnu","bundles":"appimage,deb","family":"linux","artifact":"pam-linux-arm64"}'
          windows_amd64='{"name":"Windows amd64 package","runner":"windows-2025","target":"x86_64-pc-windows-msvc","bundles":"nsis","family":"windows","artifact":"pam-windows-amd64"}'
          windows_arm64='{"name":"Windows arm64 package","runner":"windows-11-arm","target":"aarch64-pc-windows-msvc","bundles":"nsis","family":"windows","artifact":"pam-windows-arm64"}'
          # Pull requests build the cheapest package only; main, tags and
          # dispatch build the four that release.yml reuses.
          if [[ "$GITHUB_EVENT_NAME" == "pull_request" ]]; then
            echo "matrix={\"include\":[$linux_amd64]}" >> "$GITHUB_OUTPUT"
          else
            echo "matrix={\"include\":[$linux_amd64,$linux_arm64,$windows_amd64,$windows_arm64]}" >> "$GITHUB_OUTPUT"
          fi
```

`targets` gains `timeout-minutes: 45`; its steps stay as they are.

- [ ] **Step 4: ci.yml — `desktop-packages`**

```yaml
  desktop-packages:
    name: ${{ matrix.name }}
    needs: [gate, targets]
    timeout-minutes: 40
    strategy:
      fail-fast: false
      matrix: ${{ fromJSON(needs.gate.outputs.packages) }}
    runs-on: ${{ matrix.runner }}
    steps:
      - uses: actions/checkout@<sha> # v4
      - name: Tauri system deps
        if: ${{ matrix.family == 'linux' }}
        run: |
          sudo apt-get update
          sudo apt-get install -y --no-install-recommends libwebkit2gtk-4.1-dev libgtk-3-dev librsvg2-dev libsoup-3.0-dev libjavascriptcoregtk-4.1-dev libappindicator3-dev patchelf xdg-utils
      - uses: actions/setup-node@<sha> # v4
        with:
          node-version: 22
          cache: npm
          cache-dependency-path: frontend/package-lock.json
      - uses: dtolnay/rust-toolchain@<sha> # stable
        with:
          targets: ${{ matrix.target }}
      - uses: Swatinem/rust-cache@<sha> # v2
        with:
          shared-key: desktop-${{ matrix.target }}
      - run: npm --prefix frontend ci
      - name: Build desktop packages
        run: npm --prefix frontend run tauri -- build --target ${{ matrix.target }} --bundles ${{ matrix.bundles }}
      - name: Verify Linux package contract
        if: ${{ matrix.family == 'linux' }}
        shell: bash
        env:
          TARGET: ${{ matrix.target }}
        run: |
          set -euo pipefail
          bundle="target/$TARGET/release/bundle"
          binary="target/$TARGET/release/pam"
          mapfile -t appimages < <(find "$bundle/appimage" -maxdepth 1 -type f -name '*.AppImage' -print)
          mapfile -t debs < <(find "$bundle/deb" -maxdepth 1 -type f -name '*.deb' -print)
          (( ${#appimages[@]} == 1 ))
          (( ${#debs[@]} == 1 ))
          case "$TARGET" in
            x86_64-unknown-linux-gnu) expected_machine="Advanced Micro Devices X86-64"; expected_deb_arch="amd64" ;;
            aarch64-unknown-linux-gnu) expected_machine="AArch64"; expected_deb_arch="arm64" ;;
            *) echo "unsupported Linux verification target: $TARGET" >&2; exit 2 ;;
          esac
          for candidate in "$binary" "${appimages[0]}"; do
            machine="$(readelf -h "$candidate" | awk -F: '/Machine:/ { sub(/^[[:space:]]+/, "", $2); print $2 }')"
            [[ "$machine" == "$expected_machine" ]]
          done
          [[ "$(dpkg-deb --field "${debs[0]}" Architecture)" == "$expected_deb_arch" ]]
          expected_version="$(cargo metadata --no-deps --format-version 1 | node -e '
            let input = ""; process.stdin.on("data", c => input += c);
            process.stdin.on("end", () => { const m = JSON.parse(input); process.stdout.write(m.packages.find(p => p.name === "pam").version); });')"
          verify_cli_contract() {
            local candidate="$1"
            [[ "$("$candidate" --version)" == "pam $expected_version" ]]
            "$candidate" --help > "$RUNNER_TEMP/pam-help.txt"
            grep -Fq "A local lifeguard for developers and AI agents." "$RUNNER_TEMP/pam-help.txt"
            grep -Eq '^Usage: pam( |$)' "$RUNNER_TEMP/pam-help.txt"
          }
          verify_cli_contract "$binary"
          deb_root="$RUNNER_TEMP/pam-deb-payload"; appimage_root="$RUNNER_TEMP/pam-appimage-payload"
          mkdir -p "$deb_root" "$appimage_root"
          dpkg-deb --extract "${debs[0]}" "$deb_root"
          ( cd "$appimage_root" && "$GITHUB_WORKSPACE/${appimages[0]}" --appimage-extract >/dev/null )
          verify_payload() {
            local root="$1"
            # Single-binary product; the AppImage additionally carries the
            # xdg-open helper linuxdeploy bundles. Nothing else belongs here.
            mapfile -t binaries < <(find "$root/usr/bin" -maxdepth 1 -type f -printf '%f\n' | sort)
            [[ "${binaries[*]}" == "pam" || "${binaries[*]}" == "pam xdg-open" ]]
            machine="$(readelf -h "$root/usr/bin/pam" | awk -F: '/Machine:/ { sub(/^[[:space:]]+/, "", $2); print $2 }')"
            [[ "$machine" == "$expected_machine" ]]
            verify_cli_contract "$root/usr/bin/pam"
            # The desktop entry opens the GUI, not the help text.
            grep -Eq '^Exec=.*pam gui' "$root/usr/share/applications/pam.desktop"
          }
          verify_payload "$deb_root"
          verify_payload "$appimage_root/squashfs-root"
      - name: Verify Windows package contract
        if: ${{ matrix.family == 'windows' }}
        shell: pwsh
        env:
          TARGET: ${{ matrix.target }}
        run: |
          $ErrorActionPreference = "Stop"
          $bundle = "target/$env:TARGET/release/bundle"
          $binary = (Resolve-Path "target/$env:TARGET/release/pam.exe").Path
          $installers = @(Get-ChildItem "$bundle/nsis" -File -Filter '*.exe')
          if ($installers.Count -ne 1) { throw "expected exactly one NSIS installer" }
          function Get-PeHeader([string] $Path) {
            $bytes = [System.IO.File]::ReadAllBytes($Path)
            if ($bytes.Length -lt 64 -or $bytes[0] -ne 0x4d -or $bytes[1] -ne 0x5a) { throw "$Path is not a PE executable" }
            $peOffset = [BitConverter]::ToInt32($bytes, 0x3c)
            if ([Text.Encoding]::ASCII.GetString($bytes, $peOffset, 4) -ne "PE`0`0") { throw "$Path has no PE signature" }
            @{ Bytes = $bytes; Machine = [BitConverter]::ToUInt16($bytes, $peOffset + 4); Subsystem = [BitConverter]::ToUInt16($bytes, $peOffset + 24 + 68) }
          }
          $expectedMachine = switch ($env:TARGET) {
            'x86_64-pc-windows-msvc' { [UInt16] 0x8664 }
            'aarch64-pc-windows-msvc' { [UInt16] 0xaa64 }
            default { throw "unsupported Windows verification target: $env:TARGET" }
          }
          $header = Get-PeHeader $binary
          if ($header.Machine -ne $expectedMachine) { throw ("PE machine 0x{0:x4} != 0x{1:x4}" -f $header.Machine, $expectedMachine) }
          # Console subsystem (3): agents read pam's output on Windows too.
          if ($header.Subsystem -ne 3) { throw "pam.exe must keep the console subsystem, found $($header.Subsystem)" }
          $expectedVersion = (cargo metadata --no-deps --format-version 1 | ConvertFrom-Json).packages | Where-Object name -eq 'pam' | Select-Object -ExpandProperty version
          $version = & $binary --version
          if ($version -ne "pam $expectedVersion") { throw "pam --version printed '$version'" }
          $sevenZip = (Get-Command 7z.exe -ErrorAction SilentlyContinue).Source
          if (-not $sevenZip) { $sevenZip = "$env:ProgramFiles/7-Zip/7z.exe" }
          if (-not (Test-Path $sevenZip)) { throw "7-Zip is required to inspect the NSIS payload" }
          $extract = Join-Path $env:RUNNER_TEMP 'pam-nsis'
          New-Item -ItemType Directory -Force -Path $extract | Out-Null
          & $sevenZip x '-y' "-o$extract" $installers[0].FullName | Out-Null
          if ($LASTEXITCODE -ne 0) { throw "failed to extract NSIS installer" }
          $pamExecutables = @(Get-ChildItem $extract -Recurse -File -Filter 'pam*.exe')
          if ((@($pamExecutables.Name | Sort-Object) -join ' ') -ne 'pam.exe') { throw "unexpected NSIS pam executable inventory" }
          if ((Get-PeHeader $pamExecutables[0].FullName).Machine -ne $expectedMachine) { throw "packaged pam.exe has the wrong machine" }
          # Silent per-user install: the Start-menu shortcut must open the GUI.
          Start-Process -Wait -FilePath $installers[0].FullName -ArgumentList '/S'
          $lnk = Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs\pam.lnk'
          if (-not (Test-Path $lnk)) { throw "no Start-menu shortcut at $lnk" }
          $shortcut = (New-Object -ComObject WScript.Shell).CreateShortcut($lnk)
          if ($shortcut.Arguments -ne 'gui') { throw "shortcut arguments are '$($shortcut.Arguments)', expected 'gui'" }
          $installed = Join-Path $env:LOCALAPPDATA 'pam\pam.exe'
          if ((& $installed --version) -ne "pam $expectedVersion") { throw "installed pam.exe --version failed" }
          Start-Process -Wait -FilePath (Join-Path $env:LOCALAPPDATA 'pam\uninstall.exe') -ArgumentList '/S'
      - name: Record package output
        id: package
        shell: bash
        env:
          TARGET: ${{ matrix.target }}
        run: |
          set -euo pipefail
          bundle="target/$TARGET/release/bundle"
          if [[ "$RUNNER_OS" == "Linux" ]]; then
            archive="target/$TARGET/release/pam-$TARGET-bundle.tar.gz"
            tar -C "$bundle" -czf "$PWD/$archive" .
            echo "path=$archive" >> "$GITHUB_OUTPUT"
          else
            echo "path=$bundle" >> "$GITHUB_OUTPUT"
          fi
      - uses: actions/upload-artifact@<sha> # v4
        with:
          name: ${{ matrix.artifact }}
          path: ${{ steps.package.outputs.path }}
          if-no-files-found: error
          retention-days: 7
```

If the silent install's uninstaller lives elsewhere (Tauri names it
`uninstall.exe` in the install dir), read the path from
`HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\pam`'s
`QuietUninstallString` instead and keep the step. If the Start-menu
shortcut path differs, list `$env:APPDATA\Microsoft\Windows\Start
Menu\Programs` in the failure message so the next run fixes the path
with evidence.

- [ ] **Step 5: ci.yml — `macos-package`**

```yaml
  macos-package:
    name: macOS arm64 package
    needs: [gate, targets]
    # Unsigned preview; signing + notarization happen in release.yml on
    # tags, which reuses this artifact. Never on pull requests.
    if: ${{ github.event_name != 'pull_request' }}
    runs-on: macos-15
    timeout-minutes: 45
    steps:
      - uses: actions/checkout@<sha> # v4
      - uses: actions/setup-node@<sha> # v4
        with:
          node-version: 22
          cache: npm
          cache-dependency-path: frontend/package-lock.json
      - uses: dtolnay/rust-toolchain@<sha> # stable
        with:
          targets: aarch64-apple-darwin
      - uses: Swatinem/rust-cache@<sha> # v2
        with:
          shared-key: desktop-aarch64-apple-darwin
      - run: npm --prefix frontend ci
      - name: Build application
        env:
          MACOSX_DEPLOYMENT_TARGET: "12.0"
        run: npm --prefix frontend run tauri -- build --target aarch64-apple-darwin --bundles app
      - name: Build disk image
        shell: bash
        run: |
          set -euo pipefail
          tools/package-macos-dmg.sh "$PWD/target/aarch64-apple-darwin/release/bundle/macos/pam.app" "$PWD/target/aarch64-apple-darwin/release/bundle/dmg"
      - name: Verify macOS package contract
        id: package
        shell: bash
        run: |
          set -euo pipefail
          bundle="target/aarch64-apple-darwin/release/bundle"
          app="$bundle/macos/pam.app"
          dmg="$(find "$bundle/dmg" -maxdepth 1 -type f -name '*.dmg' -print -quit)"
          [[ -n "$dmg" ]]
          mapfile -t bundle_binaries < <(find "$app/Contents/MacOS" -maxdepth 1 -type f -exec basename {} \; | sort)
          [[ "${bundle_binaries[*]}" == "pam" ]]
          [[ "$(lipo -archs "$app/Contents/MacOS/pam")" == arm64 ]]
          [[ "$(otool -l "$app/Contents/MacOS/pam" | awk '/cmd LC_BUILD_VERSION/ { seen=1 } seen && /minos/ { print $2; exit }')" == 12.0 ]]
          expected_version="$(cargo metadata --no-deps --format-version 1 | node -e '
            let input = ""; process.stdin.on("data", c => input += c);
            process.stdin.on("end", () => { const m = JSON.parse(input); process.stdout.write(m.packages.find(p => p.name === "pam").version); });')"
          [[ "$("$app/Contents/MacOS/pam" --version)" == "pam $expected_version" ]]
          archive="target/aarch64-apple-darwin/release/pam-macos-arm64-bundle.tar.gz"
          tar -C "$bundle" -czf "$PWD/$archive" "macos/pam.app" "dmg/$(basename "$dmg")"
          echo "path=$archive" >> "$GITHUB_OUTPUT"
      - uses: actions/upload-artifact@<sha> # v4
        with:
          name: pam-macos-arm64
          path: ${{ steps.package.outputs.path }}
          if-no-files-found: error
          retention-days: 7
```

Note `pam --version` from inside the bundle with an argument is a CLI
launch (the bare-launch rule needs zero arguments), so it prints and
exits.

- [ ] **Step 6: Validate and commit**

```bash
python3 -c "import yaml,sys; yaml.safe_load(open('.github/workflows/ci.yml')); print('ci.yml parses')" 2>/dev/null || npx --yes yaml-lint .github/workflows/ci.yml
tools/check.sh
git add .github tools
git commit -m "ci: desktop and macOS package jobs, pinned actions, dmg tooling, dependabot"
```

PR title: `ci: desktop + macOS package jobs, pinned actions, dmg tooling`.
The PR run itself proves the Linux amd64 package job; after the squash
merge the `main` run must show all five package artifacts (`gh run view
<id>` lists them).

---

### Task 7: `release.yml`

Needs Task 6 merged (artifact names) and Task 3 (CHANGELOG, README,
LICENSE) merged.

**Files:**
- Create: `.github/workflows/release.yml`

**Interfaces:**
- Consumes: CI artifacts from Task 6; repository secrets
  `APPLE_CERTIFICATE_BASE64`, `APPLE_CERTIFICATE_PASSWORD`,
  `KEYCHAIN_PASSWORD`, `APPLE_API_KEY`, `APPLE_API_KEY_ID`,
  `APPLE_API_ISSUER` (owner-provided; the job fails legibly without them).

- [ ] **Step 1: Copy pam-old's workflow**

```bash
cp ~/dev/rs/pam-old/.github/workflows/release.yml .github/workflows/release.yml
```

- [ ] **Step 2: Apply these exact edits**

1. `Verify version consistency`: replace the three `check` lines with

   ```bash
   check Cargo.toml "$(awk -F'"' 'in_section && /^version = /{print $2; exit} /^\[workspace\.package\]$/{in_section=1}' Cargo.toml)"
   check crates/pam/tauri.conf.json "$(node -p 'require("./crates/pam/tauri.conf.json").version')"
   check frontend/package.json "$(node -p 'require("./frontend/package.json").version')"
   for path in README.md LICENSE CHANGELOG.md; do
     test -s "$path" || { echo "::error::$path is missing or empty."; exit 1; }
   done
   ```

   keeping the `CHANGELOG.md` heading check that follows.
2. `Verify green CI run on the tag commit`: drop `--branch main` from the
   `gh run list` call (the run is looked up by commit), keep
   `--workflow ci.yml --commit "$sha" --status success`.
3. `Prepare Apple signing and notarization`: add a first guard so a
   missing secret fails with one line instead of a `base64` stack:

   ```bash
   for name in APPLE_API_KEY_ID_SECRET APPLE_API_KEY_MATERIAL APPLE_CERTIFICATE_BASE64_SECRET APPLE_CERTIFICATE_PASSWORD_SECRET KEYCHAIN_PASSWORD_SECRET; do
     [[ -n "${!name:-}" ]] || { echo "::error::Apple signing secret ${name%_SECRET} is not set on this repository; run ~/dev/apple-developer-signing/setup-github-secrets.sh ro-ag/pam and retry the tag."; exit 1; }
   done
   ```

   and the same one-line guard for `APPLE_API_ISSUER` at the top of
   `Sign and notarize disk image`.
4. `Sign and notarize disk image`: after `xcrun stapler validate "$dmg"`
   add `spctl --assess --type open --context context:primary-signature -v "$dmg"`.
5. `Publish GitHub release`: title `"pam ${GITHUB_REF_NAME}"`.
6. Re-pin every `uses:` to the SHAs Task 6 used for the same actions;
   `actions/download-artifact` gets its own resolved SHA (v4).
7. Leave the artifact names, archive names
   (`pam_<ver>_linux_<arch>.tar.gz`, `pam_<ver>_windows_<arch>.zip`,
   `pam_<ver>_darwin_arm64.dmg`), the `--deep --options runtime
   --timestamp` signing, the dmg rebuild via `tools/package-macos-dmg.sh`,
   the `notarytool log` on rejection, checksums, and the changelog notes
   extraction as they are.

- [ ] **Step 3: Dry validation and commit**

```bash
npx --yes yaml-lint .github/workflows/release.yml
grep -n 'crates/pam/tauri.conf.json\|spctl\|setup-github-secrets' .github/workflows/release.yml
tools/check.sh
git add .github/workflows/release.yml
git commit -m "ci(release): tag-triggered release reusing the green main run's artifacts"
```

PR title: `ci(release): tag-triggered release reusing main artifacts`.
The workflow itself is exercised by the owner's first tag; this task ends
with the merged file and a green `main` run.

---

### Task 8: Coordinator checkpoint (ptrack #22)

- [ ] Repo settings via `gh api`: description
  `A local lifeguard for developers and AI agents.`; branch protection on
  `main` with required status checks `gate`,
  `targets (ubuntu-24.04-arm)`, `targets (macos-15)`,
  `targets (windows-2025)`, `targets (windows-11-arm)` (strict false),
  `enforce_admins: false`, `allow_force_pushes: false`,
  `allow_deletions: false`, no required reviews.
- [ ] On the settled `main`: `tools/check.sh` green; `npm --prefix
  frontend run tauri -- build --bundles app` produces `pam.app`; the dmg
  script produces a dmg that mounts; `open pam.app` opens the control
  center; `pam service install/status/uninstall` round-trips against the
  real LaunchAgent with `launchctl print` as witness; the Settings row
  eyeballed through the fixture proxy in both theme families; gui-embed
  release binary carries `service_install` (strings).
- [ ] `main` CI run for the final merge green by id with the literal
  `success` conclusion; the run lists five package artifacts; download
  `pam-linux-amd64` and `pam-macos-arm64` and list their contents.
- [ ] Tell the owner the one command that pushes the Apple secrets; no tag.
- [ ] `ptrack task done 22 --summary …`, `ptrack plan done 9`, act on the
  checkpoint block, `ptrack summary set …`.
