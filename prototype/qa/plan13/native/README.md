# Plan 13 native UI evidence

Captured 2026-08-20 from fresh production-mode builds of the current working
tree. The deterministic state matrix remains in Vitest and Playwright; these
images prove native renderer/package execution without presenting a temporary
project or recovery state as production data.

| Renderer | Artifact | SHA-256 | Evidence |
| --- | --- | --- | --- |
| macOS 26.5.2 arm64, WKWebView 21624 | `PAM.app/Contents/MacOS/pam-gui` | `ba2dbd68175fe3c86fba797074e59cb3e88053b3d93600b90dec071163f0a28e` | `macos-recovery.jpeg`, `macos-queue-drawer.jpeg` |
| Ubuntu 24.04.3 arm64, WebKitGTK 2.52.3 | `pam-gui` with Tauri `custom-protocol` | `b9a2f6b80e8c4779dbe0a0181d3fac8945e2ecb003c28f5722f5d84967fc7a62` | `ubuntu-shell.png`, `ubuntu-command.png`, `ubuntu-queue-drawer.png`, `ubuntu-focus-return.png`, `ubuntu-shell-780.png`, `ubuntu-shell-320.png` |

The macOS app ran from the generated `.app` bundle against the real PAM repo
and p-track catalog. The Ubuntu binary ran under Xvfb from a real temporary Git
repository initialized with p-track 0.30.0 and the production Tauri bridge. In
both cases the missing GUI caller credential is the truthful backend state.

Observed checks:

- packaged PAM mark, horizon asset, Manrope, Cormorant, and JetBrains Mono
  render from self-hosted resources;
- the 248px desktop shell, 5px separator, 8px workspace inset, 44px toolbar,
  68px compact rail, and bounded workspace remain visually intact;
- command search autofocus, keyboard filtering, queue selection, the 430px
  drawer, Escape dismissal, inert backdrop, and opener focus restoration work
  in WKWebView and WebKitGTK;
- the Ubuntu production window accepts 780x800 and 320x800, keeps primary
  recovery actions visible, and shows no horizontal document overflow;
- production startup reports unavailable credentials/project context instead
  of fixture success.

The local macOS bundle is unsigned acceptance evidence. Signing, notarization,
and the five-target package-build matrix are separate distribution checks.
