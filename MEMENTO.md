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

## no-codex-branch-prefix
- kind: habit
- scope: project
- rule: Never use the codex/ prefix for branches in Rodox repositories; use the repository's conventional feat/, fix/, chore/, or docs/ prefix.
- fix: Rename any local codex/* branch before push or PR creation, and choose the scope-appropriate conventional prefix from the start.
- hits: 2026-09-04
- cost: 0
- status: enforced -> /Users/rodox/dev/rs/pam/AGENTS.md

## pam-old-evidence-before-redesign
- kind: habit
- scope: project
- rule: Before reassessing PAM local-model value, inspect pam-old model quality investigations and product-specific diagnosis code; do not reduce its intended role to generic log summaries.
- fix: Read pam-old docs/model-memory.md, docs/benchmarks/llama-cpp-macos.md, ptrack tasks 24/25, and Jenkins/Sonar research modules; distinguish measured quality smoke tests, production wiring, and unproven end-to-end workflow accuracy.
- hits: 2026-09-09
- cost: 0
- status: watching

## pam-blocking-work-outlives-timeout
- kind: habit
- scope: project
- rule: Keep resource permits inside actual blocking closures, bound pending admission separately, and preserve overload as a typed capacity refusal rather than missing models or unavailable credentials.
- fix: Track closure lifetime after caller cancellation, serialize conflicting mutations, retain finite waiting slots and do not cache capacity pressure as backend health.
- hits: 2026-09-10
- cost: 0
- status: watching

## large-async-fixture-stack
- kind: habit
- scope: project
- rule: Keep large nested daemon test fixture futures heap-pinned instead of accumulating them on the test thread stack.
- fix: Box::pin the outer deadline future and nested fixture constructor; preserve the normal thread stack and real deadlines. Sonar integration fixture overflowed before boxing and passed all five cases after.
- hits: 2026-09-10
- cost: 0
- status: watching

## child-stdin-eof-before-output-wait
- kind: habit
- scope: project
- rule: Drop a child stdin handle after writing the complete input, before awaiting output EOF; AsyncWrite shutdown alone may leave the pipe open.
- fix: Move stdin into the writer future so it is dropped when the write completes, and keep a real child-process regression that finishes under the original deadline.
- hits: 2026-09-10
- cost: 0
- status: watching

## typescript7-eslint-compat
- kind: habit
- scope: project
- rule: When upgrading all JS dependencies to latest, use TypeScript 7 for builds and Microsofts documented side-by-side TypeScript 6 compatibility API for typescript-eslint; do not hold the compiler back solely because of the linter peer range.
- fix: Use @typescript/native alias npm:typescript@^7.0.2 and typescript alias npm:@typescript/typescript6@^6.0.2; verify tsc --version, clean npm ci, npm ls, lint, build and tests.
- hits: 2026-09-12
- cost: 0
- status: watching

## clippy-before-full-gate
- kind: project-way
- scope: project
- rule: Run cargo clippy --all-targets -- -D warnings on the touched crate before launching tools/check.sh; the full gate costs ten minutes per clippy nit
- fix: cargo clippy -p <crate> --all-targets -- -D warnings (about 1 min) then ./tools/check.sh; this session lost four gate runs to must_use, absurd_extreme_comparisons, match_same_arms and needless_pass_by_value
- hits: 2026-09-15
- cost: 40
- status: enforced -> /Users/rodox/dev/rs/pam/AGENTS.md

## pam-ui-shell-scroll-containment
- kind: habit
- scope: project
- rule: Keep animated desktop backgrounds clipped inside a viewport-fixed shell; overflow hidden alone can still allow focus or keyboard scrolling of decorative overflow.
- fix: Verify actual shell scrollTop and panel coordinates after keyboard and wheel scrolling at the minimum window size. PAM uses fixed inset-0 h-dvh overflow-clip and explicit pane scroll ownership.
- hits: 2026-09-17
- cost: 0
- status: watching

## pam-original-brand-artwork
- kind: habit
- scope: project
- rule: Use the original PAM brand SVG for in-app branding rather than the packaged application icon.
- fix: Import docs/assets/pam-mark.svg, the artwork used by the README, in Sidebar.tsx.
- hits: 2026-09-17
- cost: 0
- status: watching

## pam-deadline-audit-scheduling
- kind: habit
- scope: project
- rule: A short-deadline audit test must account for expiry before leasing as well as expiry of a running lease; do not assume the executor wins the scheduler race.
- fix: Require failed/lease_expired and exactly deadline_refusal plus either recovery_refusal from take_next or lease_reaped from the reaper.
- hits: 2026-09-17
- cost: 0
- status: watching

## pam-logo-painted-bounds
- kind: habit
- scope: project
- rule: Size and position brand artwork from its painted bounds, not its SVG viewBox; inspect the native window and both sidebar modes before declaring it visible.
- fix: Framed the original PAM SVG in a 2:1 image box and increased expanded artwork to 118 by 59 painted pixels; verified native and light/dark screenshots.
- hits: 2026-09-17
- cost: 0
- status: watching

## pam-model-menu-scroll-clipping
- kind: habit
- scope: project
- rule: Inspect menus on the final row of an overflow container; position popups outside the scrolling ancestor and verify focus and disabled hover behavior.
- fix: Portaled Models More menu to the body with viewport bounds, resize/scroll repositioning, outside dismissal, arrow navigation and Escape focus restoration.
- hits: 2026-09-17
- cost: 0
- status: watching

## pam-frontend-format-gate
- kind: habit
- scope: project
- rule: When asked to clear frontend validation failures, fix baseline formatting failures too and provide saved evidence for the complete formatting, lint, build and test runs.
- fix: Formatted all seven reported files and reran the full frontend checks with logs saved beside the visual review.
- hits: 2026-09-17
- cost: 0
- status: watching

## pam-desktop-label-selection
- kind: habit
- scope: project
- rule: PAM interface labels should be nonselectable by default; explicitly preserve selection for inputs and copyable output, including WebKit.
- fix: Set body user-select none with WebKit prefix and opt text controls, evidence, logs, answers and diagnostics back in; verify real heading and input selection.
- hits: 2026-09-17
- cost: 0
- status: watching

## pam-ui-copy-implementation-details
- kind: habit
- scope: project
- rule: Keep GUI-only and only-this-app implementation restrictions out of normal PAM labels and descriptions; describe the user action and retain only actionable permission explanations.
- fix: Removed redundant Settings restriction copy and simplified Models and Approvals descriptions; kept internal security comments and enforcement unchanged.
- hits: 2026-09-18
- cost: 0
- status: watching

## pam-compression-is-internal
- kind: habit
- scope: project
- rule: Log compression is an internal model-input optimization, not a PAM user workflow; do not expose compression forms or unsolicited implementation status in the UI.
- fix: Removed Activity compression tab/form and its dead component, plus Models compression-status prose; preserved internal IPC and backend processing.
- hits: 2026-09-18
- cost: 0
- status: watching

## pam-activity-lane-minimum
- kind: habit
- scope: project
- rule: Do not pair a CSS minimum-width layout guarantee with min-w-0 on the same Activity lane; utility-layer precedence defeats the floor and crushes labels.
- fix: Removed lane min-w-0, kept 360px wrapping floor and nonwrapping timestamps, and inspected native Activity with uneven lane counts.
- hits: 2026-09-18
- cost: 0
- status: watching

