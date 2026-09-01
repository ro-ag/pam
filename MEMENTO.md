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

