# PAM two-layer shell and theme implementation QA

Date: 2026-08-21

## Result

PAM now uses the shared composition visible in ZCode and p-track: the sidebar
belongs to the application background and the main working area is one inset,
floating canvas. PAM's identity remains its own. Ventisquero Mist/Bedrock and
Viña del Mar Dawn/Night retain their existing palette, typography, imagery,
copy, and interaction language.

No P0, P1, or P2 visual or interaction findings remain.

## Source truth and capture conditions

- Repository-owned reference board:
  `qa/ui-modernization/reference-board-1280x800.png`.
- Reproducible ZCode/PAM composition comparison:
  `qa/ui-modernization/zcode-reference-vs-pam-canvas-2360x800.png`.
- Canonical Ventisquero and Viña del Mar assets:
  `frontend/public/assets/ventisquero-yelcho.png` and
  `frontend/public/assets/vina-sunset.png`; their semantic token maps live in
  `frontend/src/styles.css`.
- Browser implementation capture:
  `qa/ui-modernization/after-canvas-composition-1180x800.png` at exactly
  1180×800 CSS pixels and 1× scale.
- Light-shell implementation capture:
  `frontend/e2e/__screenshots__/pam.spec.ts/access-audit-evaluated-1180x1000-darwin.png`
  at exactly 1180×1000 CSS pixels and 1× scale.
- Native implementation capture:
  `qa/ui-modernization/native-tauri-canvas-composition.jpeg` from the running
  macOS Tauri application.
- Responsive evidence: current Playwright snapshots at 1180, 960, 780, 600,
  and 320 CSS pixels.

The 1152×768 ZCode capture was padded, not scaled, to 1180×800 before the
side-by-side shell comparison. The comparison tests the shared spatial rule,
not a pixel clone. PAM content, tokens, and identity remain intentionally
different. The theme board compares all four PAM appearances at the same
1180×800 viewport.

## Combined visual evidence

- ZCode composition beside PAM:
  `qa/ui-modernization/zcode-reference-vs-pam-canvas-2360x800.png`.
- PAM baseline beside the final composition:
  `qa/ui-modernization/canvas-composition-before-after-2360x800.png`.
- All four final appearances:
  `qa/ui-modernization/four-theme-canvas-composition-1180x800.jpg`.
- User-reported light shell beside the corrected implementation crop:
  `qa/ui-modernization/light-shell-seam-reference-vs-fix.png`. Both halves are
  452×1000 crops at 1× scale, aligned on the sidebar/workspace boundary.
- Original-size full views were inspected in addition to the combined boards;
  no focused crop was needed because type, icons, boundaries, and imagery were
  legible in the originals.

## Fidelity review

### Composition, spacing, and elevation

- The application root and sidebar share the theme chrome. There is no detached
  sidebar card or separate sidebar background layer.
- The 5px desktop resize gutter is painted with that same chrome token. This
  masks the workspace's left shadow inside the gutter while preserving the
  workspace border, its elevation on the other three sides, and the resize
  hit target.
- The workspace is the only large floating surface: 10px desktop inset, 18px
  radius, 1px theme boundary, clipped content, and the only large shell shadow.
- Its toolbar is 52px high; controls are 34px. Content begins directly below
  the toolbar inside the same canvas.
- The hero is a flat section with a divider rather than a nested 24px card.
  Its existing image is retained in a compact 104px slot.
- The three status summaries read as one 10px-radius strip with internal
  dividers. Individual summary cards have no shadow, lift, or competing radius.
- Timeline, outcome, panel, and state surfaces use radii no larger than 12px
  and no large elevation. Hierarchy comes from grouping and whitespace.
- At 600px and below the same two-layer concept reflows vertically: compact
  navigation remains part of the root and the workspace remains the single
  inset canvas. There is no horizontal document overflow at 320px.

### Typography

- Existing theme type roles are unchanged. Ventisquero uses Archivo/Inter with
  IBM Plex Mono for data; Viña uses Space Grotesk/Inter with JetBrains Mono for
  data.
- Display size is capped at 38px in the compact hero. Monospace remains limited
  to code and metadata; general UI copy does not regress to terminal styling.

### Colors and variants

- The implementation does not introduce a new palette. Root/sidebar chrome,
  workspace page, borders, states, and accents all use the existing semantic
  tokens.
- Ventisquero Mist and Bedrock remain independent light/dark variants of one
  family. Viña del Mar Dawn and Night remain independent light/dark variants
  of the other family.
- Family and variant apply at the document root, so Radix menus, dialogs,
  drawers, tooltips, and toasts inherit the active appearance.

### Imagery, icons, and copy

- The exact supplied glacier and Pacific assets are retained; no generated,
  approximate, SVG, or CSS-drawn replacement was introduced.
- Phosphor remains the single icon family. Radix remains the primitive layer
  for menus, dialogs, drawers, tooltips, and selection behavior.
- Product copy and truthful typed fixture content are unchanged.

### Motion, interaction, and accessibility

- Existing Motion route/overlay transitions remain, with the reduced-motion
  path preserving immediate state changes.
- Browser verification covered the command palette, sidebar collapse/restore,
  and the family/variant theme menu. Focus returned correctly and browser error
  logs were empty.
- Native verification launched the actual macOS Tauri app. The overlay titlebar
  contract is configured and also enforced at runtime; dedicated drag regions
  avoid turning interactive controls into window drag targets.
- Forced-colors, focus-visible, keyboard navigation, responsive containment,
  and reduced-motion assertions remain in the automated suite.

## Iteration history

1. Baseline: nested 24px hero, individually elevated 74px status cards,
   24px timeline/outcome cards, and 60px toolbar produced a P1 hierarchy
   mismatch. Fixed by making the workspace the only major floating canvas and
   flattening the inner content.
2. First responsive pass: at 960px the redundant status phrase truncated to
   `PAM is a…`, a P2 responsive defect. Fixed by hiding redundant state pills
   from 601–1100px and restoring them in the mobile reflow.
3. Theme regression check: the former test expected the hero to have its own
   opaque card color. The intentional transparent hero invalidated that old
   assertion, so the contract now checks the unified overview surface. All four
   theme snapshots then passed.
4. Native pass: configuration and runtime titlebar styles were aligned, native
   drag regions were added, and the running Tauri window was captured after the
   final rebuild.
5. Light-shell regression: the transparent desktop resize gutter exposed the
   workspace's left shadow as a gray strip, a P2 composition defect that made
   the sidebar appear detached. The base gutter background now resolves to
   `--pam-chrome`; the focused post-fix comparison shows one uninterrupted
   shell. At y=400, pixels x=247 through x=252 are all `rgb(253,252,249)` in
   Viña del Mar Dawn, with the workspace boundary beginning at x=253.
   The four-appearance visual contract now also asserts that the computed
   separator background exactly equals the computed sidebar chrome, so the
   narrow defect cannot slip under screenshot-diff tolerance again.
6. Pre-merge audit: semantic success and danger text used decorative accent
   colors below the 4.5:1 small-text threshold, an active run without an
   outcome occupied only the first desktop grid track, and native chrome was
   fixed to dark. State pill text now uses the high-contrast content token,
   the only timeline child spans both tracks, and document theme changes call
   Tauri's bounded app-theme command. Automated contrast, geometry, capability,
   and default-light configuration checks cover all three corrections.

## Automated evidence

- TypeScript typecheck: passed.
- Vitest: 13 files, 124 tests passed.
- Vite production build: passed; only the existing chunk-size advisory remains.
- Playwright visual/interaction suite: 23 tests passed, including four theme
  appearances, an outcome-free active timeline, and the 1180/960/780/600/320
  responsive set.
- Rust formatting: passed.
- Rust workspace check: passed.
- Clippy with warnings denied: passed.
- Rust workspace tests: passed; two live connector tests remain intentionally
  ignored.
- Tauri security contract: passed, including the native window configuration
  and narrowly scoped app-theme permission.

final result: passed
