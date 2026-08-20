# PAM Project Current and Flow Editor design QA

## Evidence

- Source visual truth: `reference/pam-project-current-approved.png`
- Implementation pass 1: `qa/implementation-1280x720-pass1.png`
- Final implementation: `qa/implementation-1280x720-pass2.png`
- Full-view comparison: `qa/full-comparison-pass2.png`
- Focused handoff comparison: `qa/handoff-comparison-pass2.png`
- Flow editor implementation: `qa/flow-editor-implementation.png`
- Flow editor responsive implementation: `qa/flow-editor-responsive.png`
- Flow editor visual-system comparison: `qa/flow-editor-comparison.png`
- Browser viewport: 1280 x 720 CSS px
- Browser density: device pixel ratio 2; the Browser capture is normalized to
  1280 x 720 output pixels.
- Source pixels: 1487 x 1058
- Final implementation pixels: 1280 x 720
- Flow editor implementation pixels: 1280 x 720
- Flow editor responsive pixels: 1024 x 768
- Normalization: the source was proportionally scaled to 1012 x 720 and placed
  beside the 1280 x 720 responsive implementation. The source was not cropped
  or stretched. The focused handoff comparison uses the corresponding source
  and implementation regions at a common width of 900 px.
- State: `payments-api` selected, Current active, daemon on, Verification passed
  expanded, no drawer or toast open.
- Flow editor state: `payments-api` selected, Flows active,
  `after-merge-checks.toml` selected, valid schema v2, Dry run selected, no toast
  open.

The available in-app Browser viewport is wider and shorter than the approved
1487 x 1058 frame. The comparison therefore evaluates the same information and
interaction state in PAM's intentional low-height responsive layout rather than
pretending the canvases are identical.

## Findings

No actionable P0, P1, or P2 differences remain in the final comparisons.

- Fonts and typography: the serif PAM wordmark and project title preserve the
  approved editorial character; the remaining UI uses a native system sans and
  monospace evidence handles. The low-height state uses a tighter optical scale
  so the handoff remains usable without scrolling.
- Spacing and layout rhythm: sidebar, project header, four-step timeline,
  expanded verification boundary, handoff rows, provenance, and action grouping
  follow the approved hierarchy. Separators and modest radii match the target.
- Colors and visual tokens: midnight navy, sunset coral, Pacific aqua, and warm
  sand map directly to the approved visual. The generated ocean background
  preserves the warm right-side horizon while keeping the working surface dark.
- Image quality and asset fidelity: the background and transparent PAM mark are
  project-local generated assets derived from the approved art direction. No
  raster placeholder, CSS illustration, handcrafted SVG, or emoji substitutes
  a visible source asset. Interface icons use Phosphor consistently.
- Copy and content: approved labels, developer scenario, evidence handles, and
  handoff fields are preserved. The absolute date is updated to August 18, 2026
  while retaining the same chronology.

The new Flow editor is not depicted in the approved Current reference, so its
QA checks visual-system continuity rather than claiming a pixel-identical
screen. `qa/flow-editor-comparison.png` places the source and editor together:
the sidebar anatomy, editorial serif heading, native sans UI, midnight working
surface, coral selection/validation emphasis, aqua verified state, warm sand
copy, modest radii, fine rules, ocean horizon, and Phosphor icon language carry
across without introducing a second design system.

- Fonts and typography: the editor preserves the established display/UI split
  and adds a legible monospace source surface. Labels, filenames, and authority
  metadata have distinct hierarchy without relying on raw color alone.
- Spacing and layout rhythm: catalog, source, and inspection panels form a
  stable three-column workbench at 1280 x 720. At 1024 x 768, core controls stay
  visible and the page reports no horizontal body overflow; long secondary
  labels truncate instead of displacing controls.
- Colors and visual tokens: validation, active navigation, semantic roles, and
  authority status use the approved coral/aqua/sand tokens over midnight navy.
- Image quality and asset fidelity: the editor reuses the approved project-local
  PAM mark and ocean background. All interface symbols use the existing
  Phosphor library; there are no placeholder assets, emoji, CSS illustrations,
  or handcrafted SVGs.
- Copy and content: the editor uses the checked `after-merge-checks` definition,
  names dry run as non-executing, identifies the supported read-only Git
  boundary, and distinguishes Observe from Verify truthfully.

## Comparison history

### Pass 1 — blocked

- [P2] Core handoff actions were below the fold at 1280 x 720.
  - Evidence: `qa/implementation-1280x720-pass1.png` showed the handoff clipped
    after the Next row; Copy agent brief, Open evidence, and Continue flow were
    not visible without scrolling.
  - Fix: added a low-height layout that tightens timeline rows, handoff spacing,
    typography, provenance, and controls while retaining the approved order.

### Pass 2 — passed

- Evidence: `qa/full-comparison-pass2.png` shows the approved source and final
  implementation together. All four handoff rows, both evidence handles, and
  all three actions are visible. The timeline reports `scrollHeight: 618` and
  `clientHeight: 618`, so no core control is hidden.
- Focused evidence: `qa/handoff-comparison-pass2.png` confirms matching field
  order, color semantics, provenance treatment, and action hierarchy.

### Pass 3 — flow editor extension passed

- Evidence: `qa/flow-editor-comparison.png` shows the approved source and the
  final Flow editor together at a common 720 px height. The new workbench keeps
  the existing shell and visual tokens while making catalog, editor, dry run,
  version diff, validation, and save status readable in one view.
- Responsive evidence: `qa/flow-editor-responsive.png` shows the editor at
  1024 x 768 with all three workbench regions, tabs, save/validation status, and
  authority result visible. `body.scrollWidth` and `body.clientWidth` were both
  1024 px.
- A separate focused crop was not needed for the editor because the full
  1280 x 720 capture retains readable source, step, role, and authority detail;
  the prior handoff comparison remains the focused evidence for the unchanged
  Current state.

## Interaction and runtime checks

- Project switcher changed to `ledger-web` and restored `payments-api`.
- Current, Flows, and Access navigation states rendered and returned correctly.
- Verification passed collapsed and expanded.
- Copy agent brief reached the Brief copied success state.
- Open evidence opened a modal drawer and its close control dismissed it.
- Daemon control switched between PAM is on watch and Start PAM.
- Continue flow produced the expected status feedback.
- Flow catalog selection switched between the checked definition and the draft.
- Invalid TOML produced a visible validation alert and disabled save.
- A valid edit without a revision advance produced the exact revision error.
- Advancing the revision enabled save and reset the version diff after saving.
- Version diff reported deterministic added/removed revision lines.
- Dry run exposed three ordered steps, their Observe/Verify roles, dependencies,
  attempts, approvals, exact Git commands, and a no-execution authority result.
- No application console warning or error surfaced during the final Flow editor
  interaction pass; the Vite development session remained free of page/runtime
  errors.

## Follow-up polish

- [P3] At 720 px height, the handoff's secondary text is intentionally denser
  than the approved 1058 px-tall source. The Tauri desktop uses the roomier
  source scale whenever the window height permits it.
- [P3] The bottom daemon label wraps in the compact browser frame. The native
  control can use an icon-only status with an accessible tooltip at this size.
- [P3] At 1024 px, long catalog names and Git commands intentionally ellipsize.
  A future native editor can expose full values in accessible hover/focus
  affordances while keeping the three-pane inspection context intact.

## Implementation checklist

- Keep the approved expanded Current state as the primary Tauri desktop target.
- Preserve low-height visibility of the three core handoff actions.
- Carry project switching, daemon control, evidence inspection, and handoff
  success states into the production interaction contract.
- Preserve the Flow editor's validation-first save rule, explicit version
  advance, non-executing dry run, deterministic diff, and visible authority
  boundary in the native control center.

final result: passed
