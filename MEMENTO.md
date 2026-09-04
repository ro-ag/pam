# Memento ledger (project)

Managed by memento.py — log with `memento hit`, do not hand-edit entry fields.

## vitest-css-raw-stubbed
- kind: habit
- scope: project
- rule: vitest stubs every css module import to an empty string by default — including ?raw imports a test wants to parse — and the tailwind v4 vite plugin also swallows css in test mode
- fix: Set test.css: true in vite/vitest config AND gate @tailwindcss/vite out of the plugin list when mode === 'test' (defineConfig(({mode}) => ...)); avoid process.env in vite.config.ts when @types/node is absent — use the mode argument
- hits: 2026-09-01
- cost: 0
- status: watching

## pam-tests-never-ran-off-macos
- kind: project-way
- scope: project
- rule: PAM test harnesses must seed the relaxed policy profile explicitly and must not assert unix-only lock/signal details; Profile::platform_default is standard off macOS, Windows byte-range locks hide the holder pid, and Windows has no SIGTERM
- fix: pam_testkit::TestDaemon and the crate-level harnesses call seed_relaxed(base) before the daemon opens the store; assert pid == if cfg!(unix) { Some(pid) } else { None }; stop via taskkill /T /F off unix
- hits: 2026-09-01
- cost: 60
- status: enforced -> /Users/rodox/dev/rs/pam/AGENTS.md

## turso-connection-concurrent-use
- kind: trick
- scope: project
- rule: A turso (Limbo) Connection must never run statements from two tasks at once: it fails with Misuse("concurrent use forbidden"), and a swallowed failure on a terminal write leaves rows stuck forever (looked like a PUB/SUB or follow-timeout flake). Serialize every statement behind one async mutex and hold it across explicit BEGIN..COMMIT
- fix: pam_store::Store conn_lock (tokio Mutex) taken at the top of every method; regression test store_test::concurrent_inserts_and_finishes_never_fail; daemon logs failed terminal writes (log_terminal_failure). Diagnosis path: dump the daemon log on test failure and read the statement timeline (BEGIN with no COMMIT).
- hits: 2026-09-01
- cost: 120
- status: enforced -> /Users/rodox/dev/rs/pam/AGENTS.md

## stage-only-task-files
- kind: habit
- scope: project
- rule: Stage only task-owned tracked changes or explicit new files; never stage a whole source directory when untracked user data is present.
- fix: Use git add -u for existing tracked edits, inspect git diff --cached --stat before committing, and stage intended new files by exact path.
- hits: 2026-09-03
- cost: 0
- status: watching

## costa-glass-fidelity
- kind: habit
- scope: project
- rule: Use Costa typography, palettes and complete materials for requested screen redesigns, while preserving the user-approved ZCode/p-track outer frame.
- fix: Use the Costa native UI and mono stacks; keep PAM full-height sidebar, inset rounded main panel and quiet toolbar. Redesign screen contents within that frame, and verify the native Tauri app before finishing.
- hits: 2026-09-03, 2026-09-03, 2026-09-03
- cost: 0
- status: watching

## pam-textures-are-alternatives
- kind: project-way
- scope: project
- rule: Treat PAM texture references as alternatives, not stacked surface decoration; a wave backdrop must be heavily blurred until individual lines are unreadable.
- fix: Use one preblurred alpha wave field only behind the frame; remove photograph and command-surface texture overlays. Keep controls and cards clean.
- hits: 2026-09-04
- cost: 8
- status: watching

## pam-backdrop-visible-bounds
- kind: project-way
- scope: project
- rule: When stretching the PAM wave backdrop across the window, trim transparent margins in the derived mask and size it to 100% 100%; keep the supplied source unchanged.
- fix: Extract alpha, trim +repage, blur at sigma 5, normalize and copy alpha; use CSS mask-size 100% 100% instead of cover.
- hits: 2026-09-04
- cost: 0
- status: watching

## pam-bounded-desktop-controls
- kind: project-way
- scope: project
- rule: PAM appearance controls must stay in bounded, grouped panels on large monitors instead of stretching sliders across the full workspace.
- fix: Cap Appearance at1240px, use two responsive control cards with custom native range tracks/readouts and compact switches; stack below760px.
- hits: 2026-09-04
- cost: 0
- status: watching

## pam-liquid-glass-safari
- kind: habit
- scope: project
- rule: Do not equate a liquid-glass library's Playwright WebKit support claim or mocked wiring tests with actual Safari/WKWebView rendering compatibility.
- fix: Use a matched-settings minimal reproduction in real Safari before claiming optical portability. Keep the user's confirmed Chrome-versus-Safari screenshots as failure evidence; distinguish integration failure from universal library incompatibility.
- hits: 2026-09-04
- cost: 0
- status: watching

## pam-preserve-transparency-without-glass-library
- kind: habit
- scope: project
- rule: Removing a rejected optical-effect library must not silently discard independently desired translucent surfaces.
- fix: Separate plain CSS surface opacity from refraction and glow. Inventory visual behaviors before removal and preserve user-approved transparency without the dependency.
- hits: 2026-09-04
- cost: 0
- status: watching

