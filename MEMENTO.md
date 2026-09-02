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

