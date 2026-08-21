# Plan 13 desktop UI design QA

## Evidence and normalization

- PAM identity and content source: `prototype/reference/pam-project-current-approved.png`
  (1487 x 1058 px).
- p-track spatial sources:
  `/Users/rodox/dev/rs/ptrack/docs/help/assets/screenshots/board-dark.png`,
  `task-drawer-dark.png`, and `project-search-dark.png` (1552 x 1012 px;
  the app frame is the exact 1440 x 900 crop at `+56+39`).
- Browser-rendered implementation:
  `prototype/qa/plan13/production-current-1487x1058.png` at a 1487 x 1058
  CSS-pixel Chromium viewport, device scale factor 1, dark color scheme,
  `en-US`, UTC, and reduced motion.
- Exact PAM full-view comparison:
  `prototype/qa/plan13/pam-approved-vs-production.png` (source left,
  production right; both 1487 x 1058, no crop or stretch).
- Exact p-track shell comparison:
  `prototype/qa/plan13/ptrack-shell-vs-pam-production.png` (p-track left,
  PAM right; both 1440 x 900).
- Focused comparisons:
  `prototype/qa/plan13/handoff-approved-vs-production.png`,
  `prototype/qa/plan13/ptrack-drawer-vs-pam-queue.png`, and
  `prototype/qa/plan13/ptrack-command-vs-pam-command.png`.
  Handoff regions were independently scaled to 900 px wide without changing
  aspect ratio. Drawer crops retain 200 px of dimmed underlay plus the exact
  430 px drawer. Command crops retain the 520 px dialog and backdrop context.
- Responsive evidence:
  `prototype/qa/plan13/responsive-contact-sheet.png` plus the individual
  Playwright baselines under
  `frontend/e2e/__screenshots__/pam.spec.ts/` at 1180, 960, 780, 600, and
  320 CSS px, all 800 px tall. The direct 320 px viewport is the effective
  reflow target for 400% zoom, not a separate breakpoint.
- Interaction evidence:
  `prototype/qa/plan13/interaction-contact-sheet.png` covers the project menu,
  command palette, queue drawer, evidence drawer, and validated Flows view.
- State: deterministic `payments-api` solved fixture; Current active; daemon
  running; terminal result expanded; no live timestamps, model identity, or
  other invented protocol facts.

The approved PAM image owns palette, imagery, editorial hierarchy, timeline,
and handoff identity. p-track owns shell density, the 5 px separator, 8 px
workspace inset, 44 px toolbar, bounded canvas, 430 px drawer, and 520 px
search-dialog execution. p-track's mint/purple palette, Kanban content,
terminal, and copy are deliberately not copied.

## Findings

No actionable P0, P1, or P2 visual or interaction differences remain in the
current comparisons.

- Fonts and typography: bundled Cormorant, Manrope, and JetBrains Mono preserve
  PAM's editorial/UI/code hierarchy without platform-font drift. The production
  typography is intentionally denser than the approved presentation mock so it
  matches p-track's working desktop scale; headings, small labels, identifiers,
  wrapping, and truncation remain legible at every captured width.
- Spacing and layout rhythm: the live shell matches p-track's 248 px desktop
  sidebar, 68 px compact rail, 5 px separator, 8 px/4 px workspace insets, and
  growable 44 px toolbar. Timeline, terminal result, provenance, and actions
  retain the approved PAM order. Flows becomes one column at 960 px. At 320 px,
  the document reflows without horizontal overflow and all three handoff actions
  remain reachable.
- Colors and tokens: midnight navy, sunset coral, Pacific aqua, and warm sand
  remain the only product palette. Coral continues to denote action/attention,
  aqua denotes verified/focus state, and sand carries body copy. p-track's
  colors were used only as spatial reference.
- Image quality and asset fidelity: the transparent PAM mark and Pacific sunset
  are real project-local raster assets with correct transparency, crop, and
  sharpness. No logo, background, or non-standard visible asset is replaced by
  CSS art, emoji, a text glyph, or handcrafted SVG. Interface icons use the
  existing Phosphor family consistently.
- Copy and content: the UI keeps PAM's approved narrative anatomy while using
  only production-shaped protocol truth. `Sequence 1` through `Sequence 4`
  replace invented clock times, and the terminal report does not claim a model
  name or memory size that the daemon does not supply.
- Interaction and accessibility: React Aria owns menu, tabs, modal, drawer,
  listbox, search, focus containment, outside dismissal, and Escape behavior.
  The project menu supports Arrow keys, Home, End, Enter/Space, and exact focus
  return. Drawers and the command palette keep one active layer, make older
  layers inert, and restore the exact opener. Visible focus, forced colors,
  reduced-motion `always`/system/`never`, and compact-sidebar focus containment
  are covered by automated assertions.

## Comparison history

### Interaction pre-pass — blocked

- [P1] Replacing the command palette with the queue drawer allowed the browser's
  modal cleanup to overwrite focus restoration, leaving focus on the document.
  `Drawer` now restores the explicit opener immediately and once more on the
  next animation frame, after React Aria finishes its cleanup. Vitest and real
  Chromium both prove toolbar-opener restoration.
- [P1] The compact sidebar's original document-level Tab trap could intercept
  an active modal. Focus containment now lives on the sidebar itself, so
  portalled menus and dialogs retain their own authority. A regression test
  opens an approval while the compact sidebar is expanded and proves focus
  remains inside the active dialog.

### Current visual pass — passed

- `pam-approved-vs-production.png` confirms that PAM's brand, timeline,
  terminal-result hierarchy, provenance, and three actions remain intact while
  using the denser p-track shell.
- `ptrack-shell-vs-pam-production.png` confirms sidebar density, workspace
  boundary, toolbar height, and scroll ownership at the same 1440 x 900 frame.
- Focused handoff, drawer, and command comparisons confirm action order,
  independent drawer scrolling, fixed headers, dimmed underlay, and bounded
  dialog geometry. No visual fix was required after this current-run pass.
- The Playwright suite runs 12 production-shaped Chromium checks and rejects
  console errors or page exceptions. It also asserts zero document overflow,
  exact shell measurements, reachable actions, keyboard navigation, focus
  return, forced-color focus, and reduced motion.
- Fresh production-mode native evidence now covers macOS arm64 WKWebView and
  Parallels Ubuntu arm64 WebKitGTK. Both render packaged assets/fonts and the
  truthful credential-recovery state; command search, queue drawer geometry,
  Escape dismissal, and opener focus recovery pass on both. Ubuntu additionally
  passes real 780x800 and 320x800 window captures without visible horizontal
  overflow. See [the native evidence manifest](prototype/qa/plan13/native/README.md).

## Open questions and residual scope

- The checked-in baselines in this pass are Darwin-specific by filename.
  Plan 13 task 84 records separate current-run evidence on the macOS host and
  the available Parallels Ubuntu guest; raster output is never compared across
  operating systems with a permissive shared baseline.
- Browser fixture evidence owns the deterministic full state matrix but does
  not substitute for task 84's bounded production-mode native WebView smoke on
  macOS and Linux.

## Implementation checklist

- Preserve the approved PAM identity/content authority and p-track spatial
  authority as separate constraints.
- Keep platform-specific screenshot baselines locked to the bundled Chromium
  revision.
- Keep the current macOS and Parallels Ubuntu native-smoke evidence manifest
  synchronized when Plan 13 UI sources change. Windows and duplicate CPU
  architecture variants remain package-distribution scope, not this UI gate.

## Follow-up polish

- [P3] A future native-only capture can document the separator's aqua hover
  rail beside its default transparent state; the keyboard focus state is already
  asserted and does not block this pass.

final result: passed
