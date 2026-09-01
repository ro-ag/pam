# PAM v2 — rewrite plan (new repository)

Status: draft. Repo: `ro-ag/pam` (fresh). The old codebase lives archived at
`ro-ag/pam-old`.

## North star

A single command-line tool, backed by a local daemon with first-class local
models, that lets sandboxed AI agents (and their humans) act on a project
safely: durable continuity, compressed evidence, repeatable flows, and a full
audit trail — all local, no hosted control plane.

## Scoping model — what is global, what is per-project

Ground rule from the owner: PAM is a machine-level companion. Nothing below
is "installed into" a repo; repos are just callers.

**Global, never per-project:**
- **Models** — one machine-wide registry and runtime.
- **Flows** — one library of named flows, runnable from any repo.
- **Connectors** — SonarQube, Jenkins, GitHub, etc.: one machine-wide set,
  enabled/credentialed once, dormant until switched on.

**Hybrid (global inventory, per-project localization):**
- **Skills, MCP servers, rules, agent boilerplate** — one global catalog;
  a project view selects/overrides what applies locally.
- The catalog is curated with intelligence via the **agent CLIs already
  installed on the machine** (claude, copilot, codex, gemini, …): PAM
  shells out to them in non-interactive mode and rides the user's
  existing subscription/auth. **No API keys held or managed by PAM.**
  Catalog maintenance is sporadic and quality-sensitive, so a frontier
  vendor agent beats burning local compute on it.
- PAM's intelligence layer therefore has two tiers: **local runtime**
  (llama.cpp — high-volume cheap work like log summarization) and
  **vendor agent CLI** (catalog curation/maintenance). An adapter
  detects which agent CLIs exist and lets the user pick the curator.

**Credentials (owner decision):**
- All secrets (connector tokens, certs) live in the OS-native store —
  macOS Keychain, Windows Credential Manager, Linux Secret Service
  (libsecret: gnome-keyring / KWallet). Never in SQLite, config files,
  or env vars. Rust `keyring` crate fronts all three.
- PAM stores only references/metadata; the secret itself never crosses
  the socket — callers get brokered results, never the credential.

**Activity (timeline / audit):**
- Global by default; filterable per caller (repo). One machine-wide story
  with a per-project lens, not per-project silos.

## Goals, ranked

### 1. Local models first-class (top priority)
- llama.cpp (or candle / mistral.rs) behind a runtime adapter, inside the daemon.
- Uses: log summarization after deterministic reduction, failure
  classification, retry-path selection in flows, project-brief generation.
- Model management: assisted GGUF download, `~/llm/<vendor>/<model>` layout,
  weight verification. No weights ever shipped.
- Everything degrades gracefully without a model (deterministic paths keep
  working); with a model, everything gets smarter.
- **Hardware floor: 32 GB RAM** — model catalog and defaults sized to it.
- **Test bench = owner's machine**: Apple M4 Max, 64 GB, llama.cpp already
  installed (homebrew: `llama-server`/`llama-cli`), model dir `~/llm/`
  (currently only an empty `qwen/`). Candidate evaluation runs here:
  anything up to ~48 GB weights is testable, but a model only enters the
  *supported* catalog if a quant of it runs inside the 32 GB floor
  alongside the developer's normal workload (~≤20 GB weights).
- Candidate shortlist to test for the summarize/classify tier:
  Qwen3 4B/8B/14B, Qwen3-30B-A3B (MoE — fast on Apple Silicon),
  Gemma 3 12B/27B, Phi-4 14B, Mistral Small 24B. Bigger dense models
  (70B Q4) fit the 64 GB bench for comparison but are out of catalog.
- Token economy: the model lives in the daemon, summarizes once, and every
  caller reuses the result from the durable store.
- Second tier (see Scoping model): installed vendor agent CLIs (claude,
  copilot, codex, …) invoked non-interactively for sporadic
  quality-sensitive work like catalog curation — user's subscription,
  no API keys in PAM.

### 2. Controlled sandbox escape
- Agent inside a sandbox runs `pam <cmd>`; the CLI reaches the daemon outside
  the sandbox; the daemon holds all real authority.
- Every capability is named, granted per-project, revocable.
- Approval at the meaningful boundary (human confirms destructive/external).
- One audit row per operation — including refused and failed operations
  (v1 lesson, issue #49: the audit trail under-reported exactly the
  operations most worth auditing).
- Fail-closed, but every refusal names its cause and a recovery path
  (v1 lessons, issues #44 and #52: opaque refusals are a product failure).
- **Security administration is GUI-only** (owner decision): grants,
  approvals, revocations live exclusively in the desktop control center.
  The CLI exposes NO security commands — an agent holding the CLI can
  request, never self-authorize. A refusal's recovery line points the
  human at the GUI ("open Pam → Access → approve …"), not at a command
  the agent could run itself.

### 3. Local workflows kill boilerplate
- `pam flow run <name>`: versioned, inspectable recipes with conditions,
  retries, approvals, and compact output contracts.
- **Format: YAML** (owner decision — matches infra convention), stored in
  the global flow library (flows are global; see Scoping model).
- The agent receives a compact verdict, never raw command chatter.
- **Graphical flow designer, first-class** (owner decision): a beautiful
  visual editor in the GUI — not a viewer bolted on later.
  - xyflow-based canvas with modern node/edge language: raised rounded
    node cards (same component system), typed ports, smooth bezier /
    smoothstep connectors, animated edges on running flows, edge labels
    for conditions, snap grid, minimap, auto-layout (elk/dagre) so
    hand-arranged mess is one click from tidy.
  - Node types match flow semantics: command, connector call, condition,
    approval gate (hand icon — amber rim), retry wrapper, model step
    (summarize/classify), verdict/output contract.
  - **YAML is the source of truth, designer round-trips it**: open a
    flow file → canvas; edit canvas → clean YAML diff (stable key
    order, no churn). Both views live side by side (canvas / YAML tab).
  - Validation live on canvas: unwired ports, unreachable nodes,
    missing approval on destructive steps — flagged on the node itself
    with the refusal-legibility style (cause + fix).
- **Predefined flow library ships with PAM**: curated starter flows,
  visible in the designer as templates — e.g. after-merge-checks,
  release-readiness, ci-failure-triage, summarize-build-log,
  sonar-gate-check, pr-readiness, dependency-audit. Each is a normal
  YAML file the user can clone and edit; quick-action pills on the main
  screen surface the favorites.

### 4. Log compression
- Deterministic reduction first (dedupe repeats, collapse progress spam, keep
  error lines with provenance), local-model summarization second.
- Original evidence always addressable by handle. Compression is reversible.
- Success metric: input tokens avoided per diagnosis.

### 5. Single command-line tool
- One `pam` binary is the interface for both humans and agents. Not a proxy.
- Client mode is thin: parse, send request, print compact result.
- All state, policy, models, and execution live in the daemon.
- Small, stable command set — no subcommand sprawl.

### 6. Transport: ZeroMQ (or similar)
- CLI/agent <-> daemon over zmq using **`ipc://` (unix domain sockets)** —
  owner decision: no TCP listener, nothing reachable off-machine.
- REQ/REP for requests, PUB/SUB for streamed progress events.
- **One single unix socket, no more** (owner decision): every caller —
  agent CLI invocations, GUI, humans — goes through the same endpoint.
  No per-caller sockets, no secondary channels.
- Unix socket = filesystem permissions as the auth baseline (0700 runtime
  dir, user-only).
- **Caller identity = who invoked the CLI**: the `pam` client identifies
  its invoker (parent process chain — claude/codex/copilot/shell —
  plus cwd repo) and stamps that identity on the request. Identity is
  for attribution, filtering, and per-caller grants — resolved at the
  CLI edge, carried in the envelope, recorded in every audit row.
- **Queue manager in the daemon**: all requests from the single socket
  land in a managed queue — ordering, dedupe of identical in-flight
  work, per-caller fairness, backpressure. Callers never race each
  other; expensive work (model runs, connector calls) is done once and
  shared.
- The 104-byte sockaddr path limit applies (v1 issue #52): fixed short
  runtime dir (e.g. `~/.pam/run/`), validate path length at startup with
  a legible error naming the limit and the offending path.
- Sandbox note: the sandbox profile must whitelist the socket path — that
  single allowed path IS the controlled escape hatch.
- Alternatives if zmq disappoints: nng, gRPC over UDS.

## Themes: kept from v1 verbatim (owner decision — "they are pretty")

The two v1 theme families port to v2 as the seed of the design system:

- **Ventisquero Mist** (default) — light + dark variants.
- **Viña del Mar Dawn** — light + dark variants.

Source material to carry from `ro-ag/pam-old`:

- `frontend/src/styles.css` — the `@layer tokens` block (lines ~12–226):
  four `:root[data-theme="…"][data-mode="…"]` token sets (`--pam-*` custom
  properties: page/paper/surface/line/text/muted, accent ramps, fonts),
  plus the density scale (`data-density="compact"`) and spacing tokens.
- `frontend/src/theme.ts` — theme registry, default theme, persistence.
- Font stack: Inter Variable (UI), Archivo Variable (display), Newsreader
  Variable (editorial), IBM Plex Mono / JetBrains Mono (mono) — via
  fontsource packages.

The v1 token scheme (`--pam-*` vars switched by `data-theme` + `data-mode`
attributes, density as a multiplier) is already the "theme = token set"
model v2 wants — adopt it as the design-system foundation rather than
inventing a new one, then extend it with the chart/diagram token tier.

## Kept from v1 (still true)

- **One binary, modes as subcommands** (owner decision): the same `pam`
  executable selects its mode by subcommand — `pam daemon` for the
  background service, `pam gui` for the desktop control center, every
  other subcommand runs as the thin client. One artifact to install,
  sign, and version — no drift between client and daemon.
- Local-first: no hosted control plane, no bundled weights.
- One project = one ordered story (durable queue serializes conflicting work).
- Truth reporting: solved / changed / verified / unresolved / blocked.
- GUI is the human observatory: every daemon capability is visible in the GUI
  or explicitly deferred with an owner-approved note (memento law — v1 kept
  shipping features the GUI never surfaced).
- Destructive actions always confirm, fail legibly, and report (v1 PR #153).

## Dropped / demoted from v1

- Connector zoo (Jira, Confluence, SharePoint, AWS) — later, behind the same
  capability boundary.
- Skills inventory — later.

## Stack

Target platforms (owner decision): **darwin arm64 · linux amd64/arm64 ·
windows amd64/arm64** — all first-class release targets. Hardware floor for
local inference: 32 GB RAM.

| Layer | Choice |
| --- | --- |
| Core / daemon / CLI | Rust |
| Transport | ZeroMQ (REQ/REP + PUB/SUB), auth layer on top |
| Durable store | SQLite (embedded, zero setup) |
| Local inference | llama.cpp binding behind a runtime adapter |
| Desktop shell | Tauri (one binary embeds the GUI: `pam gui`) |
| Frontend build | Vite |
| Frontend data/UI | TanStack (Router, Query, Table) |
| Styling | Tailwind on design tokens |
| Animation | Motion |

## UI goals — design system from day zero, not retrofit

1. **Design system before the first screen.** Tokens (color, spacing, type
   scale, radius, elevation) defined first; every component consumes tokens
   only. No hardcoded hex, ever.
2. **Themes are first-class citizens.** A theme is a token set. Light and dark
   per theme family, runtime switching, user-installable themes possible.
   Keep v1's Ventisquero / Viña del Mar families, re-expressed as tokens.
3. **Charts and diagrams native.** Queue timelines, token-savings charts, flow
   DAG editor/viewer (xyflow), model memory/throughput gauges, audit activity
   heatmap. One chart library, themed by the same tokens.
4. **Owned component library.** Buttons, cards, tables, status badges, confirm
   dialogs — built once, documented, reused everywhere.
5. **GUI = full observatory.** Every daemon capability surfaces in the GUI or
   carries an explicit deferral note.
6. **Streaming UI.** PUB/SUB events animate live: flow progress, queue
   movement, model tokens/sec. This is where Motion earns its place.
7. **Settings are complete, day one.** Every configurable thing surfaces
   in Settings — models (registry, default per job tier, download,
   verify, delete), logs (retention, compaction thresholds, verbosity),
   themes/density, daemon (runtime dir, socket, autostart), connectors,
   catalog curator choice, approvals defaults. No hidden config-file-only
   knobs; the file and the UI stay in sync.
8. **Primary layout paradigm: ZCode-style** (owner reference, loved —
   screenshot on file). Traits to reproduce:
   - **Two-pane shell**: slim persistent left sidebar + one calm main
     pane. Sidebar top = global actions with shortcut hints (New task
     ⌘N, Search ⌘K, …); middle = scope filter chips (Group/Project
     toggle) over a Projects tree with per-item age badges; bottom =
     Tasks section and a user footer row (avatar, name, settings gear).
   - **Main pane centered focus card**: a single prominent composer
     card — context pickers inline at its top (project ▾, branch ▾),
     large input with placeholder affordances ("@ to add context,
     / for commands"), left mode control ("Ask before changes ▾"),
     right utility ("Manage models ▾") and one round submit button.
   - **Inline dismissible banner** above the card for system notices,
     with its actions right-aligned (e.g. "No model available —
     Upgrade / Set / ×").
   - **Quick-action pills** under the composer (icon + label, e.g.
     Weekly Summary, Error Fix) for canned tasks — PAM equivalent:
     flow shortcuts.
   - **Core structural idea (the thing the owner loves): the sidebar is
     part of the window background** — no border, no fill of its own,
     it lives on the chrome — while **the working area floats on top of
     it** as a raised rounded surface (elevated panel, own background
     token, soft shadow, larger corner radius). One elevation step
     separates "chrome" (sidebar, window) from "work" (main panel).
     In tokens: `--chrome` (window + sidebar ground) vs `--surface`
     (floating work panel) vs `--surface-raised` (cards on the panel).
   - **Feel**: dark-first, generous whitespace, rounded cards, subtle
     hairline borders, muted grays with one accent, oversized friendly
     greeting text in the empty state.
   Settings follow the same paradigm: sidebar groups, searchable, one
   scrollable detail pane — never a bolted-on dialog.
9. **"Ask Pam" composer is self-aware** (owner decision): the centered
   composer in the GUI is Pam's own voice — it answers about the app
   itself and its status, not code. "Why was that flow refused?",
   "what's waiting for my approval?", "what ran today in repo X?",
   "which model is loaded and how much memory?", "where do I change
   log retention?" — answered from daemon state + audit + settings
   schema, with deep links that navigate the UI to the right screen.
   Local model tier answers these; degrades to structured status
   rendering when no model is present.
   **Short memory, stated clearly**: Ask Pam keeps only a small rolling
   context (current screen + last few exchanges) — it is a status
   assistant, not a chat with history. The UI says so up front
   (placeholder/hint), so nobody expects it to remember yesterday's
   conversation; durable truth lives in the activity/audit views it
   links to, never in the chat transcript.

## Design vision — brainstorm (pre-plan ideas)

Concept: **the lifeguard tower at night**. The chrome is the dark water —
deep, calm, atmospheric. The floating work panel is the lit tower deck —
clean, bright-edged, where everything legible happens. Pam watches; the UI
should feel like being watched *over*, not watched.

### Typography with a point of view
Three voices, three faces (all already in the v1 stack — sharpened roles):
- **Archivo (display)** — big numbers, greetings, stat tiles, section
  heroes. Wide, confident, slightly industrial: the tower's signage.
- **Newsreader (editorial serif) — Pam's voice.** Every sentence Pam
  "says" (Ask Pam answers, refusal explanations, brief narratives,
  empty-state greetings) renders in the serif. Data never does. This one
  rule gives the app a memorable split personality: machine facts in
  sans/mono, the companion's voice in warm serif.
- **IBM Plex Mono** — evidence, hashes, paths, audit rows, log excerpts.
  UI sans (Inter) stays for controls and labels only — furniture, not
  personality.

### Signature moments (pick the memorable ones, execute precisely)
1. **The beacon.** Daemon state lives in the sidebar footer as a small
   lighthouse dot: slow breathing glow when idle, quick pulse while
   working, amber hold when an approval waits, red flash on refusal.
   Whole-app status readable from the corner of the eye, no text.
2. **Refusals are beautiful.** The product thesis made visible. A refusal
   card has fixed anatomy: cause line (serif, plain language) → evidence
   handle (mono chip) → one recovery button that deep-links into the GUI
   (Access screen, Settings row). Never a toast, never a stack trace.
3. **Approval = raised hand.** A pending approval slides a banner from
   the top edge of the work panel (hand icon, requester identity, exact
   capability, blast radius). Approve/deny only there. The panel edge
   glows amber while any hand is raised.
4. **Tokens-saved odometer.** The compression story as a rolling
   odometer stat tile: "tokens avoided this week", digits rolling on
   each new compaction event. The one number that sells PAM.
5. **Activity as tide.** Global timeline reads as swimlanes per caller;
   events arrive live over PUB/SUB and slide-settle into place. Filter
   chips (per repo/caller) narrow lanes with a layout animation, not a
   reload.
6. **Flow runs breathe.** Flow DAG (xyflow, themed via `--xy-*` vars):
   nodes are raised cards with a status rim; the active edge runs an
   animated dash; a finished run settles into a compact verdict card
   with solved/changed/verified/unresolved/blocked chips.

### Atmosphere & depth (no flat solid-color slop)
- Chrome carries the mood: a very subtle radial gradient wash + fine
  noise grain (v1's `.atmosphere` layer, kept). The floating panel stays
  perfectly clean — contrast of texture, not just of color.
- Elevation is disciplined: exactly three grounds (`--chrome`,
  `--surface`, `--surface-raised`) + one overlay tier. No ad-hoc
  shadows; two shadow tokens total (float, raise).
- The one theme-independent warm hairline (v1's chrome separator) stays
  as a brand signature.
- Custom titlebar on all three OSes (Tauri decorations off): the sidebar
  IS the titlebar region (traffic lights / window buttons sit in it),
  so chrome truly reaches the window edge — the ZCode trick.

### Micro-interactions (few, orchestrated, token-driven)
- One well-staged app-open: sidebar items stagger-fade in (60ms steps),
  panel floats up 8px with the greeting; nothing else animates on load.
- Composer submit morphs the round button into a progress ring fed by
  PUB/SUB progress events; result card replaces the ring in place.
- Quick-action pills (global flows) lift 2px on hover, press 1px down.
- Sidebar project age badges fade toward muted as they stale.
- All durations/easings are motion tokens; `prefers-reduced-motion`
  collapses everything to opacity fades.

### Data visualization language
- One chart system, themed by chart role tokens (`--chart-1..n`,
  `--chart-grid`, `--chart-ref`): sparklines inside stat tiles, area
  chart for queue depth over time, calendar heatmap for audit activity,
  compact gauges for model memory/tokens-per-second.
- Numbers use Archivo with tabular figures; every chart readable in all
  four theme×mode combinations (contrast-checked at token level).

### Structure & navigation extras
- **⌘K command palette** searches everything: screens, settings rows,
  flows, activity, models. Same index that powers Ask Pam's deep links.
- **Density toggle** (v1 multiplier) surfaced in Settings; compact mode
  tightens spacing tokens only — no component forks.
- **First run = tower setup**: a card-stack checklist on the empty panel
  (start daemon → pick theme → add a model → try `pam brief`), each card
  collapsing as Pam detects completion — onboarding by observation, in
  Pam's serif voice.

### Anti-slop guardrails
- No purple-gradient-on-white, no glassmorphism-everywhere, no emoji-as-
  icons, no five competing accents. One accent per theme + status colors.
- Every screen must survive the squint test: chrome recedes, one floating
  panel, one focal action.

## Styling architecture — Tailwind, done right from the ground

Single source of truth, enforced, no drift:

1. **Tokens live in CSS, Tailwind v4 CSS-first.** One `tokens.css`:
   `@theme` maps semantic tokens (`--color-surface`, `--color-accent`,
   `--spacing-*`, `--font-*`, `--radius-*`) so Tailwind generates real
   utilities (`bg-surface`, `text-muted`) from them. No
   `tailwind.config.js` theme sprawl, no second source.
2. **Themes = CSS variable swaps only.** `:root[data-theme][data-mode]`
   blocks redefine the same semantic variables (v1's proven scheme).
   Components never know which theme is active — they consume semantic
   utilities only. Adding a theme = adding one CSS block, zero component
   edits.
3. **Semantic layer over raw palette.** Raw ramps (`--ice-500`) exist
   only inside theme blocks; components use role tokens (`surface`,
   `line`, `text`, `muted`, `accent`, `danger`, `success`). Charts get
   their own role tier (`--chart-1..n`, `--gauge-*`) themed the same way.
4. **Component variants via CVA + `tailwind-merge`.** Every owned
   component (Button, Card, Badge, Dialog, Table) defines variants with
   `class-variance-authority`; `cn()` helper (clsx + tailwind-merge)
   everywhere. No string-concatenated class soup.
5. **Enforcement, not discipline.** ESLint + Tailwind plugin: forbid
   arbitrary values (`bg-[#hex]`, `p-[13px]`), forbid raw palette
   classes outside the design-system folder, class ordering via
   `prettier-plugin-tailwindcss`. CI-cheap: runs in the normal lint job.
6. **Density and motion as tokens too.** Density multiplier (v1 scheme)
   and motion durations/easings are variables — Motion reads them, so
   animation speed respects reduced-motion and density settings.
7. **Living style reference.** A `pam gui` hidden route (or Ladle/
   Storybook-lite) renders every component in every theme × mode — the
   design system is visible, testable, and screenshot-diffable.

## Architecture in one line

agent → `pam` CLI → ZeroMQ → daemon (policy + queue + local model + executor)
→ audited compact result back.

## v1 lessons to bake in from day one

- Error legibility: every refusal names cause + recovery (issues #44, #51, #52).
- Audit completeness: every capability writes its own outcome row, refusals
  included (issue #49); previews/dry-runs leave a trace too (issue #50).
- CLI vocabulary == capability vocabulary (issue #51): the grant and the
  command are spellable the same way.
- Release discipline: tag only after the main-push CI run completes; CI stays
  cheap (Linux-first gates, path filters, superseded-run cancellation).
