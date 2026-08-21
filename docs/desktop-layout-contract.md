# PAM desktop layout contract

Status: normative for Plan 13, tasks 77–84. PAM's identity is unchanged: keep
the approved midnight navy, sunset coral, Pacific aqua, warm sand, editorial
type, timeline, provenance, and Current/Flows/Access hierarchy. Execution follows
p-track's compact desktop shell; p-track's mint brand, board semantics, and copy
do not cross into PAM.

## Authorities

- PAM visual and content authority: `prototype/reference/pam-project-current-approved.png`,
  `prototype/AGENTS.md`, `frontend/src/selectors.ts`, and `prototype/design-qa.md`.
- Cross-repository shell authority:
  `/Users/rodox/dev/rs/ptrack/frontend/src/workspace/layout.ts`,
  `/Users/rodox/dev/rs/ptrack/frontend/src/style.css`,
  `/Users/rodox/dev/rs/ptrack/frontend/src/app.js`, and
  `/Users/rodox/dev/rs/ptrack/frontend/src/workspace/application-overlay.ts`.
- Visual checks for the shipped spatial grammar:
  `/Users/rodox/dev/rs/ptrack/docs/help/assets/screenshots/overview-dark.png`,
  `/Users/rodox/dev/rs/ptrack/docs/help/assets/screenshots/board-dark.png`,
  `/Users/rodox/dev/rs/ptrack/docs/help/assets/screenshots/task-drawer-dark.png`,
  and `/Users/rodox/dev/rs/ptrack/docs/help/assets/screenshots/project-switch-dark.png`.

When the approved PAM image and p-track differ, PAM owns identity, visible
product concepts, and narrative hierarchy; p-track owns shell geometry,
density, overflow, interaction, and responsive execution. Typed PAM responses
own every displayed fact.

## Shell geometry and density

The desktop root fills the native viewport and uses three columns:
`sidebar | 5px separator | minmax(0, 1fr) workspace`. The sidebar defaults to
248px and clamps to `180px..min(420px, 45vw)`. Hiding it collapses both the
sidebar and separator columns to zero; the toolbar toggle remains available.

The workspace contains one inset canvas. At default density it has an 8px
inset on the top, right, and bottom, with its left edge beginning immediately
after the separator. The canvas has a 1px boundary, 10px radius, clipped outer
overflow, and a fixed first row for the toolbar; only the canvas body scrolls.
Desktop body scrolling and horizontal shell scrolling are failures. Recovery
and empty-state content is bounded to 660px.

Default (comfortable) spacing tokens are `4 / 8 / 12 / 16 / 20 / 24 / 32px`.
Compact density is a real alternate scale, not another name for default:
`3 / 6 / 9 / 12 / 14 / 17 / 22px`. Components must consume tokens so the
whole surface tightens together. The measured 8px desktop and 4px mobile
canvas insets are default-density values; explicit compact density substitutes
6px and 3px without changing the shell structure.

## Sidebar, toolbar, and canvas anatomy

The sidebar order is PAM identity, active-project switcher, Current/Flows/Access
navigation, then bottom utilities and daemon control. Active state, labels,
counts, and full project names must not depend on hover. Long names truncate in
the shell but expose their full accessible name. PAM's compact state is a 68px
icon rail; opening full navigation at compact widths places it above a scrim,
makes the workspace inert and `aria-hidden`, moves focus into navigation, and
returns focus to the toolbar toggle on close.

The 5px separator is a focusable vertical `role="separator"` with current,
minimum, and responsive maximum ARIA values. Primary-pointer drag uses pointer
capture, updates the clamped width continuously, and commits once on
`pointerup`, `pointercancel`, or lost capture. Keyboard behavior is exact:
Left/Right changes 16px, Page Down/Page Up changes -64/+64px, Home selects
180px, and End selects the responsive maximum. Resize is unavailable while the
sidebar is hidden or while a modal onboarding state owns the shell.

Width and desktop collapsed state persist under named, PAM-specific
frontend storage keys. PAM has no typed native layout DTO, so this preference
must not invent a parallel backend command; a future typed native record may
supersede the frontend store. Invalid or stale widths are clamped on read,
storage failure never breaks the live layout, and transient responsive
drawer/rail openness is not persisted.

The toolbar is the canvas's 44px top row. Its controls are 28px high and remain
quiet and compact. The left group holds the sidebar toggle and project context;
the right group holds bounded queue, refresh, and project actions. Empty toolbar
space may be a native drag region, while all interactive controls are explicitly
non-draggable. Beneath it, keep the approved project title, timeline, expanded
outcome, provenance, and handoff actions. At low height, the canvas scrolls so
Copy outcome brief, Open evidence, and Continue flow all remain reachable.

## Drawers, dialogs, and overlays

Evidence, queue, and approval details use a right drawer no wider than
`min(430px, 94vw)`, full height, with a fixed header and independently
scrollable body. Centered dialogs use `min(440px, 100%)` and a viewport-bounded
height. At narrow widths, dialogs align to the top and action rows stack.

Only the most recently opened application overlay is active. Earlier visible
overlays and the workspace become inert and `aria-hidden`; layering must be
deterministic. Dialogs and drawers trap Tab/Shift+Tab, Escape closes only the
active overlay, backdrop dismissal is available where the action is safe, and
focus returns to the exact opener. Loading, empty, failure, binary, truncated,
and retry states render inside the same bounded surface without changing its
geometry. Toasts are status announcements, never the only evidence of success
or failure.

## Responsive and accessibility rules

p-track has exactly three shell breakpoints; PAM inherits their intent:

- At 1180px and below, compact broad content and low-value toolbar/status
  labels before constraining primary content.
- At 960px and below, compound grids become one column, action groups wrap,
  and controls use `min-width: 0`; no card may force horizontal overflow.
- At 600px and below, reflow the shell to one column, remove the separator,
  place the compact navigation row above the workspace, allow document-height
  scrolling, use a default 4px canvas inset, wrap the 44px-minimum toolbar, and
  top-align dialogs and recovery cards.

780px is a required PAM native acceptance width, not a p-track breakpoint and
must not be described as one. Its icon-rail/overlay navigation is PAM-specific.
Effective 320 CSS-pixel acceptance comes from the 600px reflow rules under 400%
zoom, not from a new 320px breakpoint. It must have no horizontal document
scroll, long identifiers must wrap or elide accessibly, and every handoff action
must remain reachable.

Every interactive element has a visible `:focus-visible` treatment using PAM
aqua; clipped controls use a 2px inward outline. Focus order follows visual
order, current navigation uses `aria-current`, toggle state is named, and status
changes use appropriate polite status or assertive alert regions. Reduced-motion
`always` and the system `prefers-reduced-motion` path reduce transitions and
animations to 0.01ms and disable smooth scrolling; an explicit `never` setting
may opt out of the media query. In forced colors, focus uses `Highlight`,
disabled controls use `GrayText`, structural boundaries use system colors, and
meaning is never communicated by color alone.

## Truth and content constraints

The approved image is a composition reference, not permission to invent live
facts. Production UI obeys these rules:

- Timeline ordering is labelled `Sequence 1` through `Sequence N`. Do not
  synthesize wall-clock times, relative ages, or a current timestamp.
- Daemon identity may show only the returned daemon version and an accurate
  lifecycle phrase. Never display a mock Qwen name, model memory, token/latency
  telemetry, or model availability that the protocol did not report.
- Project branch, request status, outcome sections, evidence handles, queue
  counts, approvals, and access facts come only from the typed active-project
  response. Do not infer grants from configuration or turn unavailable data
  into optimistic copy.
- Access distinguishes observed, policy-gated, disabled, and unavailable facts.
  Approval copy states the exact bounded effect, project, capability/policy,
  expiry, and opaque handle supplied by the protocol.
- Solved, unresolved, blocked, cancelled, loading, offline, credential-recovery,
  and stale-project states retain their truthful terminal meaning. A decorative
  or fixture success must never leak into production.

## Plan 13 acceptance gate

Task 84 requires current-run UI evidence on the locally available native
renderers in scope: the macOS arm64 host and Parallels Ubuntu 24.04.3 arm64.
Duplicate amd64/arm64 validation and Windows UI validation are not part of this
UI gate; the existing five-target package-build matrix remains separate
distribution and portability coverage.

The deterministic Vitest and Playwright suites own the complete typed state and
interaction matrix: Current lifecycle states, Access available/blocked,
evidence loading/text/binary/truncated/failure, Flows valid/invalid,
drawers/dialogs, keyboard navigation, reduced motion, forced colors, 780px,
and effective-320px reflow. Each native renderer must additionally launch the
production-mode Tauri application with the shipped frontend assets and pass a
bounded package/render smoke covering startup, shell geometry, asset and font
loading, viewport containment, and representative keyboard/overlay behavior.
Native smoke must not be described as proof that every backend state is
deterministically reachable through the production daemon on every platform.

Acceptance requires every P0 and P1 mismatch to be closed, the three core
handoff actions to remain reachable, zero horizontal document overflow, correct
focus/inert restoration, a current screenshot/measurement set, and current
native evidence from each available renderer. Fixture-only, browser-only,
stale, or fabricated results do not satisfy the gate by themselves.
