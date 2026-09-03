# Ask Pam + tide activity — design

Plan #7. Owner decisions recorded 2026-09-03. Companion plan:
`docs/plans/2026-09-03-ask-pam-tide.md`.

## Scope

Two subsystems, one spec and one plan (owner's call):

- **Part A — Ask Pam.** A Home screen at `/` with the self-aware composer:
  questions about pam itself, answered from live daemon state with deep
  links into the GUI. Pam's own voice (serif), short memory, honest about
  what it cannot answer.
- **Part B — the tide.** The Activity screen becomes swimlanes per agent,
  live events slide-settle into their lane, filter chips narrow lanes with
  a layout animation instead of a reload.

## Decisions (owner-approved)

- **Home at `/`.** New default route with an oversized serif greeting, the
  centered composer, quick-action pills, and the last three exchanges.
  Activity moves one click away (sidebar order: Home, Activity, Approvals,
  Flows, Models, Settings).
- **Deterministic router; the model only phrases.** The owner's base local
  model is 18 GB and "really limited" (note #122). A fixed intent table
  matched by patterns answers every question from structured state with a
  templated sentence, data facts, and deep links. The light-tier model may
  only *rephrase* that sentence, bounded and guarded, and is skipped when
  it is unavailable, slow, or drops a number or a name. Default off; a
  toggle in Settings › Models turns it on.
- **Nine intents plus an honest fallback** (table below). Nothing outside
  the table is attempted: an unmatched question answers "I can answer
  about pam itself" with the pill list.
- **Short memory, stated up front:** the current screen and the last three
  exchanges, in memory only; the composer placeholder says so. Durable
  truth lives in the screens the answers link to.
- **Lanes are agents** (`claude`, `codex`, `gemini`, `copilot`, `gui`,
  `cli`, …); the repo is a chip on the row. Filter chips: agents and repos.
- **Vertical lanes side by side**, newest row on top, Motion layout
  animations for settle and for chip toggles; one column on narrow panels.
- **Never runs anything.** "Run flow X" answers with a deep link to the
  Flows screen; approvals are decided only on the Approvals screen.

## Deviation to flag (recorded here for the owner's review)

The approved option text said "daemon-side intent router". The router
lives in the **GUI** (TypeScript, pure functions, unit-tested) instead:

- every fact source already crosses the bridge as a read op
  (`daemon_status`, `admin.approvals.pending`, `admin.activity.list`,
  `admin.models.status`, `admin.retention.get`, `admin.evidence.stats`,
  `admin.flows.list`) and `service_status` exists only bridge-side — the
  daemon cannot see the login unit at all (`pam_client` depends on
  `pam_daemon`, not the reverse);
- the composer is a GUI-only surface by design (no `pam ask` for agents in
  v0), so a daemon op would add IPC and audit surface for one caller;
- the model rephrase reuses `admin.models.try`.

One daemon addition is still needed: **`admin.audit.request { request_id }`**
(GUI-only, read-only) returning that request's audit rows, so "why was that
refused" can quote the cause, detail, and recovery the daemon recorded
(`Store::audit_for_request` exists; no bridge op exposes it — the same gap
`Activity.tsx` already lists as its follow-up).

## Deferred (recorded, not built now)

- ⌘K command palette over the same deep-link index.
- `pam ask` on the CLI / a daemon-side router.
- Model-based intent classification for unmatched questions.
- Persisting exchanges; any memory beyond the last three.
- Horizontal (time-axis) tide; per-lane virtualization.
- First-run "tower setup" card stack.

## Part A — Ask Pam

### Home screen

Route `/` renders `Home` (the index redirect goes away). Layout inside the
work panel, top to bottom:

1. **Greeting** — `font-display` time-of-day word ("Good evening") over one
   `font-voice` line that changes with state: quiet ("The water is calm:
   nothing waits for you."), raised hand ("Two requests wait for your
   hand."), daemon down ("The daemon is not answering; the next question
   starts it."). Computed from `daemon_status` and
   `admin.approvals.pending`, the same queries the beacon uses.
2. **Composer** — one text input, `font-voice` placeholder "Ask about pam
   itself — I keep only this screen and the last three exchanges", Enter
   asks, Escape clears, disabled while an answer is loading. A ghost
   button "Ask" for pointer users.
3. **Quick-action pills** — one per intent (label below), clicking asks
   the canonical question.
4. **Exchanges** — newest first, at most three; each: the question in
   `font-data`, then the **answer card**: sentence in `font-voice`, a facts
   grid (`font-data` label/value, up to eight), and deep-link buttons.
   Failures render as `FailureNote` (the daemon's refusal shape).
5. **Model line** — only when the rephrase toggle is on: "rephrased by
   `<model id>`" under an answer that was, or "answers stay in my own
   words: no light model is set" with a link to Models when
   `defaults.light` is null (this is the "no model" composer banner
   deferred from plan 3, sized down to one line).

Sidebar gets a `Home` entry (lucide `MessageCircleQuestion`) at the top.

### Router (`frontend/src/lib/ask/`)

- `intents.ts` — the ordered table: `{ id, label, canonical, patterns:
  RegExp[], capture?: (question) => Args, answer: (args, sources) =>
  Promise<Answer> }`. First matching intent wins; `fallback` when none.
- `sources.ts` — `Sources` interface over the ipc wrappers
  (`daemonStatus`, `approvalsPending`, `activityList`, `callersList`,
  `modelsStatus`, `retentionGet`, `serviceStatus`, `evidenceStats`,
  `flowsList`, `auditRequest`, `modelsTry`) so tests inject fakes; the
  real one is a thin object over `../ipc`.
- `answer.ts` — `Answer { intent, sentence, facts: [label, value][],
  links: { label, to, search?, hash? }[], rephrased?: { model } }` plus the
  sentence templates. Numbers and names in the sentence come from the
  facts, so the rephrase guard can check them.
- `rephrase.ts` — `maybeRephrase(answer, sources, enabled)`: when the
  toggle is on and `modelsStatus.defaults.light` is set, call
  `modelsTry(prompt, 96)` with an 8 s client timeout where the prompt is
  "Rewrite in one sentence, first person, warm and plain, keeping every
  number and name exactly as written: <sentence>". Accept only when the
  reply is one non-empty line containing every fact value that appears in
  the template sentence; otherwise keep the template. Never throws.
- `router.ts` — `ask(question, ctx: { screen }, sources, options) ->
  Promise<Answer>`.
- Tests `ask.test.ts`: every pattern matches its canonical question and at
  least two paraphrases; three negatives per intent; capture of repo
  names, ticket ids (26-char Crockford ULID), capability tokens, setting
  topics; fallback; rephrase accept/reject/timeout.

### Intent table

| id | canonical question | patterns (case-insensitive) | sources | sentence + facts | links |
| --- | --- | --- | --- | --- | --- |
| `approvals_waiting` | what's waiting for my approval? | `approv`, `waiting for (me|my)`, `pending`, `raised hand` | approvalsPending | "Nothing waits for you." / "N requests wait for your hand." facts: capability, agent, repo, age per pending (≤8) | Approvals |
| `why_refused` | why was that refused? | `refus`, `denied`, `why (did|was).*(not|n't)`, optional ticket id or capability token, optional "flow" | activityList(state refused[, capability]) newest, auditRequest(id) | "I refused `<capability>` from `<agent>`: <cause> — <detail>. <recovery>" facts: ticket, when, cause | Activity (state=refused), Settings › Security when the cause is a grant/profile cause |
| `what_ran` | what ran today? | `what (ran|happened|did)`, `today`, `recent`, `in <repo>` | activityList(limit 100)[, repo] since local midnight | "Today N requests ran (in <repo>): a solved, b changed, c verified, d unresolved, e blocked, f refused, g still running." facts: top capabilities, agents | Activity (repo) |
| `model_status` | which model is loaded? | `model`, `loaded`, `memory`, `ram`, `gpu` | modelsStatus | idle: "No model is loaded; the light default is <id or unset>." loaded: "<id> is loaded on <device>: <weight GB> of <host GB> RAM, context <n>." facts: quant, arch, last used, defaults | Models |
| `where_change` | where do I change log retention? | `where (do|can) i`, `how do i (change|set|turn)`, `setting`, + topic map: retention → `#retention`; login/startup/launch → `#daemon`; profile/approval mode → `#security`; grant → `#security`; models dir/model folder → `#models`; connector → `#connectors`; allowed programs/flow settings → `#flows`; theme/mode → `#appearance`; daemon/stop/restart → `#daemon` | none (retentionGet only for the retention topic, to quote the current windows) | "<Topic> lives in Settings › <Panel>." facts: current value when known | Settings (hash) |
| `daemon_status` | is the daemon running? | `daemon`, `running`, `uptime`, `alive`, `status`, `version` | daemonStatus | "The daemon answers: version v, up for d, n active requests." / down sentence | Settings › Daemon |
| `login_start` | does pam start at login? | `login`, `startup`, `boot`, `start at` | serviceStatus | "Yes: the <platform> unit is installed and loaded." / "No: nothing starts me at login." / unsupported reason | Settings › Daemon |
| `flows` | which flows do I have? / run pr-readiness | `flow`, `run <id>` | flowsList | "You have N flows: a, b, c." run form: "I do not run flows from here; open <id> on the Flows screen." | Flows (`?flow=<id>` when named) |
| `tokens_saved` | how many tokens did I save? | `token`, `saved`, `compress`, `odometer` | evidenceStats(since 7 days) | "This week I avoided about N tokens across c compressions (x → y)." | Activity (the odometer band) |
| `fallback` | — | none matched | — | "I can answer about pam itself: approvals, refusals, today's activity, the model, settings, the daemon, login, flows, tokens saved." | pills |

Ordering resolves overlaps: `why_refused` before `what_ran`,
`where_change` before `daemon_status`, `login_start` before
`daemon_status`, `tokens_saved` before `what_ran`.

### Deep links

- Settings panels get stable anchors: `Section` takes an `id` (slug of the
  title: `appearance`, `security`, `models`, `flows`, `connectors`,
  `daemon`, `retention`, `logs`) and Settings scrolls the hash target into
  view on mount and on hash change.
- Flows accepts `?flow=<id>` (route `validateSearch`) and preselects that
  flow; unknown ids fall back to the current behaviour.
- Activity already accepts `?repo=&agent=&state=`.

### Rephrase toggle

Settings › Models gains "Ask Pam may rephrase answers with the light
model" (a `Button`-styled switch like the theme mode toggle), stored in
`localStorage` key `pam.ask.rephrase` (GUI-only preference, like the
theme). Off by default. The Home model line explains the state.

### New daemon op

`admin.audit.request { request_id }` → `{ rows: [{ id, action, decision,
actor, detail, ts }] }` in `pam_daemon::admin` (GUI-only, read-only,
whitelisted in the bridge and in `ipc.ts` as `auditRequest(requestId)`).
Unknown ids answer `{ rows: [] }`. Tests: admin_test (existing request
with two rows; unknown id), bridge whitelist, ipc wrapper.

## Part B — the tide

### Layout

`Activity.tsx` keeps its data plumbing (queries, event-driven refetch with
the 300 ms debounce, state lens, URL search, EvidenceBand, EvidenceStrip,
row detail) and changes its body:

- **Chip bar** under the state lens: agent chips (from `callersList`,
  plus any agent present in the rows) and repo chips (tail of the path,
  full path on hover); a chip toggles the matching URL search param;
  active chips are `accent-soft`. "all" clears.
- **Lanes**: a CSS grid `repeat(auto-fit, minmax(20rem, 1fr))`; one lane
  per agent present after the repo/state filters, alphabetical so lanes
  never trade places. Lane header: agent chip, row count, last-seen
  relative time. Rows reuse the existing row component, newest on top, at
  most 50 per lane (the daemon clamps to 100 overall).
- **Motion**: lanes and rows are `motion.section`/`motion.li` with
  `layout`; `AnimatePresence` on rows: enter `{ opacity: 0, y: -8 }` →
  `{ opacity: 1, y: 0 }` over 240 ms, exit fades over 160 ms; an agent
  chip toggle removes or restores a whole lane with the same layout
  transition. Reduced motion follows the pattern `EvidenceBand.tsx` already
  uses (`useReducedMotion` from `motion/react`): no slide, instant
  layout.
- **Empty states**: no rows → the existing calm empty copy; filters that
  hide everything → "No requests match these chips" with a clear action.

### Acceptance (measurable)

- With two agents in the seed, a before/after screenshot pair shows two
  side-by-side lanes headed by the agent names, obvious in two seconds.
- A new request appears in its lane within 1 s of its event and visibly
  slides (8 px, 240 ms); this is proven live through the fixture proxy.
- Toggling an agent chip removes its lane with a layout transition and
  updates the URL (`?agent=`); a repo chip narrows every lane.
- `Activity.test.tsx`: rows group under `region`s named by agent; chip
  clicks change the search params; the filtered-empty copy renders; the
  existing lens, detail, and evidence tests still pass.

## Testing

- Rust: `admin_test` for `admin.audit.request`; bridge whitelist test;
  `config_test` unchanged (no new Tauri command).
- Frontend: `ask.test.ts` (router, captures, fallback, rephrase guard),
  `Home.test.tsx` (greeting by state, pills ask, exchange list capped at
  three, links navigate, model line states), `Settings.test.tsx` (anchors,
  rephrase toggle), `Flows.test.tsx` (`?flow=` preselect),
  `Activity.test.tsx` (lanes, chips, empty), `shell.test.tsx` (Home entry,
  `/` renders Home).
- Local: `tools/check.sh`; the fixture proxy drives both screens against a
  real daemon with two agents: the CLI reports the nearest
  agent-named ancestor process, so `pam echo` run under a shell copied to
  `/tmp/agents/claude` lands in the `claude` lane and requests sent
  through the proxy land under the proxy's own name — two lanes with no
  code changes; in both theme families; production proof by `strings` on the gui-embed binary for
  `admin.audit.request` and a Home marker.

## Risks

- Pattern tables drift toward false positives; the ordered table and the
  negative tests hold the line, and the fallback is honest rather than
  wrong.
- The 0.6 B wiring model rephrases badly; the guard (numbers and names
  intact, one line) rejects most of it, which is the intended behaviour,
  and the default stays off.
- Motion layout animations over many rows can jank; lanes cap at 50 rows
  and the grid uses `layout="position"` on rows.
