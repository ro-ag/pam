# Flow designer canvas — design

Status: approved by owner (brainstorming session, 2026-09-02)
Umbrella vision: `docs/vision.md` §3 "Graphical flow designer,
first-class", GUI principles 3 ("flow DAG editor/viewer (xyflow)") and
"Flow runs breathe" (`--xy-*` theming, status rims, animated edges).
Depends on: flows + connectors spec (`pam_flow` schema, validation,
`to_normalized_yaml`, `admin.flows.*`, the Flows screen and its YAML
tab, `FlowRunCard` ticket subscription and verdict loading).

## Scope and owner decisions (2026-09-02)

- **Plan #6 delivers all four designer features** the vision names:
  canvas + YAML round-trip + inspector editing, live validation on the
  nodes, auto-layout + minimap + snap grid, and animated run edges.
- **YAML stays the single source of truth.** The canvas is a second
  reading of the same file. Every canvas edit is turned into canonical
  YAML by the daemon (`pam_flow::to_normalized_yaml`), never by a
  frontend YAML writer, so the diff a canvas edit produces is exactly
  the diff a hand edit of the same fields would produce.
- **Positions are GUI-local.** Hand-arranged node positions live in the
  GUI's localStorage, keyed by flow id and step id, never in the YAML.
  Missing positions get an automatic layout; "Tidy" relays everything.
- **Dependencies**: `@xyflow/react` 12 (canvas) and `elkjs` (layered
  auto-layout, port-aware). Nothing else. ELK is loaded through a
  literal dynamic import so the first paint of the app does not pay for
  it; the production bundle proof greps the emitted chunk.
- **One new GUI-only daemon op**, `admin.flows.normalize`, joins
  `FLOW_ADMIN_OPS`. It never becomes a capability and touches no disk.
- **One daemon progress note per finished step** so status rims settle
  live; the event vocabulary (`Progress { pct, note }`) is unchanged.

Out of scope (deferral notes on plan #6): a model step as its own node
kind (the schema has none — `output: summarize` is a chip on the step),
a template gallery inside the canvas (the library column already lists
starters and Clone exists), a density switch, YAML comment preservation
(normalization drops comments today, on every path), free reordering of
steps by dragging along the x axis.

## Graph model

The canvas draws one node per step, in file order, plus two fixed frame
nodes. Its model is the resolved `Flow` JSON the daemon already returns
from `admin.flows.get` (and now from `admin.flows.normalize`).

### Nodes

| node | source | shape |
| --- | --- | --- |
| step, `command` | `steps[i].action.kind == "command"` | raised card, `Terminal` glyph, argv preview |
| step, `connector` | `steps[i].action.kind == "connector"` | raised card, `Plug` glyph, `connector · call` |
| Inputs frame | `inputs` | surface panel listing declared inputs, opens the inputs inspector |
| Verdict frame | fixed | surface panel with the five outcome chips (solved / changed / verified / unresolved / blocked), grey until a run paints one |

Step modifiers are chips on the card, not separate nodes, because the
schema has no standalone condition, retry, approval, or model step:

| modifier | chip |
| --- | --- |
| `approval: required` | warning tone, `Hand` glyph, amber rim on the card |
| `effect: stateful` | copper tone, "changes" |
| `output: summarize` | accent tone, `Sparkles` glyph |
| `output: discard` | neutral tone, "discard" |
| `retry` non-default | neutral tone, `×<attempts> / <backoff>` |
| `timeout` non-default | neutral tone, `Clock` glyph + value |
| `role` | small label under the id (`observe` / `verify` / `change`) |
| `when: always` | neutral tone, "always" (no edge) |

Every card shows an order chip `1…N` (its index in `steps`).

### Edges

| edge | source | look |
| --- | --- | --- |
| `needs` | `steps[i].needs[]` → step `i` | smoothstep, `line` stroke, no label |
| `when: { succeeded: x }` | step `x` → step `i` | success tint, pill label `succeeded` |
| `when: { failed: x }` | step `x` → step `i` | danger tint, pill label `failed` |
| implicit terminal | every step with no outgoing edge → Verdict | faint, not persisted, not selectable |

A step has one target handle and one source handle. A new connection
drawn by hand is a `needs` edge; the inspector flips a selected edge to
`succeeded` / `failed` (which replaces the step's `when`) or back to
`needs`. Deleting an edge removes the `needs` entry or resets `when` to
`needs_succeeded`.

### Order

Steps execute in file order and `needs` / `when` may only reference
earlier steps (flows spec). The canvas keeps the array as the truth:

- Connecting `A → B` where `B` precedes `A` moves `B` and its transitive
  dependents to sit right after `A`, in their existing relative order.
  The order chips update; the YAML diff is the moved blocks.
- A connection that would close a cycle is refused on the canvas with a
  cause + fix note ("`B` already runs before `A` through `C`; remove
  that edge first"). Nothing is sent to the daemon.
- Reordering without edges: the inspector's step list has up / down
  buttons. Node x position never changes file order.

## Editing

Layout of the canvas tab (inside the existing right column of the Flows
screen): a toolbar row, then the canvas (fills the column, min height
520 px), then the inspector as a 320 px raised panel on the right at
`lg` and above, stacked below the canvas under it.

Toolbar: left `Add command`, `Add connector` (ghost, `sm`); right
`Tidy`, `Fit` (ghost), `Remove` (ConfirmButton, danger, enabled with a
selected step or edge; removes that step and its edges, or that edge).
Save / Clone / Delete of the whole flow stay in FlowEditor's row, which
now renders under both tabs.

Inspector, per selected node:

- step: `id` (validated locally for `[a-z0-9-]{1,64}` and uniqueness),
  kind toggle (`command` / `connector`), for a command one argv line
  split on whitespace with double-quoted tokens kept whole, for a
  connector the connector select (`ConnectorId::ALL` order) and the call
  select fed by the connector's call table, `with` arguments as
  name/value rows (required ones pre-listed), `timeout`, `effect`,
  `role`, `output`, `retry` (attempts 1–5, backoff), `approval`, `env`
  rows (command only), plus the step list with up / down buttons.
- Inputs frame: rows of name / description / default with add / remove.
- an edge: kind radio `needs` / `succeeded` / `failed`.
- nothing selected: flow `name` and `description`.

Every edit mutates the flow JSON and, after 150 ms of quiet, calls
`admin.flows.normalize { flow }`. The reply's `yaml` replaces the
textarea text (the YAML tab shows the same dirty state), the reply's
`flow` replaces the model (defaults resolved), and the reply's `error`
paints the marker (below). Typing in the YAML textarea goes the other
way after 400 ms of quiet, or immediately when switching to the canvas
tab: `admin.flows.normalize { yaml }`; a parse failure leaves the last
good graph on screen with the marker on the toolbar note. Save stays
disabled while the last normalize reply was invalid.

The two tabs share one lifted state in `Flows.tsx`:
`{ yaml, flow, error, dirty }` per selected flow; switching flows resets
it from `admin.flows.get`.

### Layout

- Positions: `localStorage["pam.flow.layout.<flowId>"]` =
  `{ [stepId]: { x, y } }` plus the two frames. Stored on drag end.
  Reads and writes are wrapped in try/catch; a missing or unreadable
  store means "auto".
- Auto-layout: ELK `layered` algorithm, direction `RIGHT`, node spacing
  48, layer spacing 96, ports fixed on the west (target) and east
  (source) sides. Applied to nodes without a stored position on open,
  and to every node on `Tidy` (which also clears the stored positions).
- Snap grid 16 px; minimap bottom-right (nodes filled by kind);
  xyflow's Controls and attribution hidden; the toolbar's `Fit` covers
  fit-to-view and no keyboard shortcut is added in this plan.

## Daemon

### `admin.flows.normalize`

GUI-only, listed in `FLOW_ADMIN_OPS`, never grantable, no disk access.

Args: exactly one of

- `yaml: string` — a flow file's text, or
- `flow: object` — the file's shape as JSON (`schema`, `id`, `name`,
  `description`, `inputs`, `steps[]` with `run` / `connector` / `call` /
  `with` / `timeout` / `effect` / `role` / `output` / `needs` / `when` /
  `retry` / `approval` / `env`). It deserializes into the crate's
  `RawFlow`, so `deny_unknown_fields` and every existing rule apply.
  `pam_flow` gains `parse_value(serde_json::Value) -> Result<Flow,
  FlowError>` next to `parse(&str)`; both run the same resolve step.

Both or neither → `invalid_args` refusal, like the other ops.

Reply, valid:

```json
{ "valid": true, "yaml": "<to_normalized_yaml>", "flow": { ...Flow JSON... }, "digest": "<64 hex>" }
```

Reply, invalid (a normal reply, not a refusal, so the canvas keeps
drawing):

```json
{ "valid": false, "error": { "path": "steps[2].run[0]", "message": "…" } }
```

`TooLarge` and `Io` map to `path: "yaml"`. The audit line is
`{ op, valid, bytes }`.

### Progress notes

`FlowService` already publishes `"{step}: running (i/total)"` before a
step. After each step it also publishes `"{step}: {status}"` with the
`StepStatus` wire word (`succeeded` / `failed` / `skipped` / `blocked` /
`cancelled`), same `pct`. FlowRunCard keeps showing the latest note.

## Live validation and run animation

Marker placement from the `error.path`:

- `^steps\[(\d+)\]` → that node: danger rim + marker chip; hovering or
  selecting shows cause (the message) and fix (the field, from the rest
  of the path) in FailureNote style.
- `^inputs\.` → the Inputs frame, same treatment.
- anything else → the FailureNote above the canvas.

Validation is fail-fast, so at most one marker shows. Two checks never
leave the GUI: cycle on connect and duplicate / malformed step id in the
inspector.

Run animation reuses FlowRunCard's ticket subscription (the card is
rendered under the canvas tab too). Notes are parsed with
`^(\S+): (running \((\d+)/(\d+)\)|succeeded|failed|skipped|blocked|cancelled)$`:

- running → accent rim + `animate-breathe` on the node, incoming edges
  dashed and marching in accent;
- a status word → rim by `STEP_TONES` (success / danger / neutral /
  danger / warning);
- `done` / `refused` → the verdict is loaded from evidence as today and
  paints the final rims and the Verdict frame's outcome chip;
- any edit to the flow clears every rim.

## Visual language and tokens

The frontend-design skill governs the implementation. Nodes reuse the
Panel raised recipe (`rounded-card border-edge bg-surface-raised
shadow-raise`), 220 px wide: header = glyph + step id in the display
font + order chip; body = argv or `connector · call` in the data font,
two lines, ellipsis; footer = modifier chips (Badge tones). Rims are a
2 px ring: selected accent, running accent + breathe, succeeded
success, failed / blocked danger, skipped ink-faint, cancelled warning,
invalid danger + marker chip. Handles are 10 px pills in `line`, accent
on hover and while connecting. Edges are smoothstep, `line`, 1.5 px;
`when` edges tinted success / danger with a pill label; running edges
dashed in accent. Canvas ground is `chrome` with a dot grid in
`separator`; the minimap sits on `surface`.

Acceptance bar (measurable): side by side with the YAML tab the canvas
reads as a designed product within 2 s; every rim, chip, and edge kind
above is distinguishable in all four theme × mode palettes.

Tokens: no new palette primitives. `tokens.css` gains one `--xy-*`
block scoped to `.flow-canvas .react-flow` binding xyflow's variables
(background, edge stroke, handle, selection, minimap, node colors) to
semantic tokens with `var()`. xyflow's stylesheet is unlayered, so the
variables are the only clean theming hook; layered utility overrides
are not used. `design.test.ts` gains one assertion: every `--xy-*`
value is `var()`-bound.

ESLint's arbitrary-value ban applies to every class string, including
those handed to xyflow.

## Frontend structure

```
frontend/src/screens/flow-canvas/
  graph.ts            flow JSON ⇄ nodes/edges, connect with order repair, cycle check, delete, when flip  (pure)
  layout.ts           localStorage positions, ELK layout (literal dynamic import)                          (pure + async)
  notes.ts            progress-note parser → step status map                                               (pure)
  FlowCanvas.tsx      ReactFlow host, toolbar, minimap, selection state
  StepNode.tsx        step card (command / connector), rims, chips, marker
  FrameNode.tsx       Inputs and Verdict frames
  FlowEdge.tsx        needs / when edges, labels, running dash
  Inspector.tsx       selected-thing editor
  flow-canvas.css     --xy-* bindings (imported once)
```

`Flows.tsx` gains the `canvas` tab (first of three: canvas, yaml, runs),
the lifted `{ yaml, flow, error, dirty }` state, and passes it to both
`FlowCanvas` and `FlowEditor`. `ipc.ts` gains `FlowSpec` types (the
resolved `Flow` JSON), `flowsNormalize`, and the `FlowNormalizeReply`
type.

## Testing

Rust:

- `pam_flow` `validate_test`: `parse_value` accepts a raw JSON flow,
  refuses an unknown field, reports the same paths as `parse`.
- `pam_daemon` `admin_flows_test`: normalize with `yaml`, with `flow`,
  invalid reply shape and path, both / neither args refused, op present
  in `FLOW_ADMIN_OPS`, never grantable.
- `pam_daemon` flow service test: the per-step settle note follows the
  running note, with the status word.

Frontend (vitest, jsdom with a ResizeObserver stub in `vitest.setup.ts`):

- `graph.test.ts`: flow → nodes/edges for every starter (counts, kinds,
  chips), connect forward / backward with order repair, cycle refusal,
  delete cascades, when flip, add step ids.
- `layout.test.ts`: localStorage round-trip and failure tolerance; ELK
  mocked, layout applied only to unpositioned nodes; Tidy clears.
- `notes.test.ts`: every note form, unmatched notes ignored.
- `FlowCanvas.test.tsx`: renders a starter, selection opens the
  inspector, an inspector edit calls `flowsNormalize` with the mutated
  flow, an error path paints the node marker, progress notes paint rims,
  a verdict paints final rims.
- `Flows.test.tsx`: canvas tab present and first, shared dirty state
  between tabs, Save disabled while invalid.
- `design.test.ts`: `--xy-*` bindings are `var()`-bound.

## Verification before merge

1. `tools/check.sh` green on the settled tree.
2. Fixture browser eyeballing with real daemon replies (scratch
   `send_admin` dump + `frontend/public/fixture.js` shim, deleted
   after): library + canvas for every starter, an inspector edit and
   the YAML it produces, the marker, the run animation and verdict, in
   all four theme × mode palettes.
3. Production proof: `npm run build` then `rg admin.flows.normalize
   frontend/dist/assets` and an `elk` chunk present; gui-embed binary
   `strings` finds `admin.flows.normalize`.
4. PR checks green, squash-merge, main run for the merge commit green
   by id with conclusion `success`.
