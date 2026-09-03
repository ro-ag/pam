# Ask Pam + Tide Activity Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A Home screen at `/` where Pam answers questions about herself from
live daemon state (deterministic intent router, deep links, optional light-model
rephrase), and an Activity screen that reads as swimlanes per agent with live
settle and chip filters.

**Architecture:** The intent router is a pure TypeScript library
(`frontend/src/lib/ask/`) over an injected `Sources` object that wraps the
existing bridge reads; the daemon gains one read-only op
(`admin.audit.request`) so refusals can be quoted. Home composes the router,
the greeting, pills, and the last three exchanges. Activity keeps its data
plumbing and regroups rows into lanes with Motion layout animations.

**Tech Stack:** Rust (pam_daemon admin surface, pam_store), TypeScript/React 19,
TanStack Router + Query, Motion 13, Tailwind v4 tokens, vitest + Testing Library.

Spec: `docs/specs/2026-09-03-ask-pam-tide-design.md`.

## Global Constraints

- Branch per task, PR + squash merge with the ptrack task id first in the
  squash subject (`<title> #<task> (#<pr>)`), no AI attribution anywhere.
- Rust tests only in sibling files. No `unsafe`, no new dependencies (Rust or
  npm). No `#[allow]`; fix clippy pedantic at the root.
- Frontend: Tailwind v4 tokens only (no arbitrary values; ESLint enforces),
  reuse `Badge`, `Button`, `ConfirmButton`, `FailureNote`, `Panel`, `Section`.
  Pam's sentences render in `font-voice`; facts in `font-data`; controls in
  the UI sans. First person, lowercase `font-data` labels.
- The router never runs anything: no flow runs, no approvals, no writes.
- Model use is rephrase-only, off by default (`localStorage` key
  `pam.ask.rephrase`), guarded (one line, every fact value present, 8 s).
- Memory: last three exchanges + current screen, in React state only.
- `tools/check.sh` green before every PR (fmt, clippy `-D warnings`, cargo
  test, eslint, tsc + vite build, vitest). Foreground only.
- Wave 1 (Tasks 1, 2, 3, 5) touch disjoint files and run in parallel
  worktrees; Task 4 needs 1, 2 and 3 merged; Task 6 is the coordinator's
  checkpoint (ptrack #20).

---

## File map

| Path | Responsibility | Task |
| --- | --- | --- |
| `crates/pam_daemon/src/admin.rs`, `admin_test.rs` | `admin.audit.request` | 1 |
| `crates/pam_gui/src/bridge.rs` | whitelist entry (core ops 9 → 10) | 1 |
| `frontend/src/lib/ipc.ts` | `AuditRow`, `auditRequest`, `AdminOp` | 1 |
| `frontend/src/lib/ask/answer.ts`, `intents.ts`, `router.ts`, `rephrase.ts`, `sources.ts`, `ask.test.ts` | the router library | 2 |
| `frontend/src/components/ui/Section.tsx` | `id` anchors | 3 |
| `frontend/src/screens/Settings.tsx`, `Settings.test.tsx` | anchors + hash scroll | 3 |
| `frontend/src/screens/SettingsModels.tsx`, `SettingsModels.test.tsx`, `frontend/src/lib/ask/prefs.ts` | rephrase toggle | 3 |
| `frontend/src/router.tsx`, `frontend/src/screens/Flows.tsx`, `Flows.test.tsx` | `?flow=` preselect | 3 |
| `frontend/src/screens/Home.tsx`, `Home.test.tsx`, `frontend/src/router.tsx`, `components/shell/Sidebar.tsx`, `shell.test.tsx` | Home screen | 4 |
| `frontend/src/screens/Activity.tsx`, `Activity.test.tsx` | the tide | 5 |

---

### Task 1: `admin.audit.request` (daemon op, bridge whitelist, ipc wrapper)

**Files:**
- Modify: `crates/pam_daemon/src/admin.rs` (new const, dispatch arm, handler), `crates/pam_daemon/src/admin_test.rs`, `crates/pam_gui/src/bridge.rs` (`CORE_ADMIN_OPS` grows to 10), `frontend/src/lib/ipc.ts`

**Interfaces:**
- Produces: op `admin.audit.request { request_id }` → `{ request_id, rows: [{ id, action, decision, actor, detail, ts }] }` with `detail` parsed to JSON when it is JSON, else the raw string or null; unknown ids → `rows: []`. Frontend: `interface AuditRow { id: number; action: string; decision: string; actor: string; detail: unknown; ts: number }`, `auditRequest(requestId: string): Promise<{ request_id: string; rows: AuditRow[] }>`, `AdminOp` gains `"admin.audit.request"`.
- Consumes: `Store::audit_for_request` (exists).

- [ ] **Step 1: Failing daemon tests**

Append to `crates/pam_daemon/src/admin_test.rs` (imports: add `OP_AUDIT_REQUEST` to the `crate::admin` import list):

```rust
#[tokio::test]
async fn audit_request_lists_a_requests_rows_oldest_first() {
    timeout(DEADLINE, async {
        let (store, admin, _events) = service().await;
        store
            .insert_request("req_a1", "repo.push", "/repo/a", "claude", "{}", None)
            .await
            .unwrap();
        // The enqueue row exists from insert_request; a refusal adds a second.
        store
            .finish_request(
                "req_a1",
                RequestState::Refused,
                Some("not_granted"),
                AuditEntry {
                    action: "execute",
                    decision: Decision::Refuse,
                    actor: Actor::Policy,
                    detail: Some(r#"{"cause":"not_granted","detail":"repo.push is not granted","recovery":"Grant it in Settings › Security."}"#),
                },
            )
            .await
            .unwrap();

        let response = admin
            .handle(&admin_envelope(
                "req_q1",
                OP_AUDIT_REQUEST,
                serde_json::json!({ "request_id": "req_a1" }),
            ))
            .await;

        let body = expect_result(response, Outcome::Verified);
        assert_eq!(body["request_id"], "req_a1");
        let rows = body["rows"].as_array().unwrap();
        assert!(rows.len() >= 2, "{rows:?}");
        let last = rows.last().unwrap();
        assert_eq!(last["action"], "execute");
        assert_eq!(last["decision"], "refuse");
        assert_eq!(last["actor"], "policy");
        assert_eq!(last["detail"]["cause"], "not_granted");
        assert!(last["ts"].as_i64().unwrap() > 0);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn audit_request_answers_empty_for_an_unknown_id_and_refuses_a_missing_one() {
    timeout(DEADLINE, async {
        let (_store, admin, _events) = service().await;
        let response = admin
            .handle(&admin_envelope(
                "req_q2",
                OP_AUDIT_REQUEST,
                serde_json::json!({ "request_id": "req_nope" }),
            ))
            .await;
        let body = expect_result(response, Outcome::Verified);
        assert_eq!(body["rows"].as_array().unwrap().len(), 0);

        let response = admin
            .handle(&admin_envelope("req_q3", OP_AUDIT_REQUEST, serde_json::json!({})))
            .await;
        expect_refusal(response, CAUSE_INVALID_ADMIN_ARGS);
    })
    .await
    .unwrap();
}
```

Check the exact names of `AuditEntry`'s fields and `RequestState`,
`Decision`, `Actor` imports in `pam_store` (`crates/pam_store/src/store.rs`,
`AuditEntry` is what `finish_request` takes) and import them in the test.
Run `cargo test -p pam_daemon --lib admin_test::audit_request` — expect a
compile error (`OP_AUDIT_REQUEST` missing).

- [ ] **Step 2: The op**

In `crates/pam_daemon/src/admin.rs` after `OP_CALLERS_LIST`:

```rust
/// `admin.audit.request { request_id }` — every audit row the daemon wrote
/// for one request, oldest first. Read-only; the GUI quotes refusals with
/// it ("why was that refused").
pub const OP_AUDIT_REQUEST: &str = "admin.audit.request";
```

Dispatch arm next to `OP_CALLERS_LIST => self.callers_list().await,`:

```rust
            OP_AUDIT_REQUEST => self.audit_request(args).await,
```

Handler next to `callers_list`:

```rust
    /// The audit trail of one request. Unknown ids answer an empty list:
    /// pruned or mistyped ids are a state to render, not a refusal.
    async fn audit_request(&self, args: &serde_json::Value) -> Result<AdminOk, AdminRefusal> {
        let request_id = args
            .get("request_id")
            .and_then(serde_json::Value::as_str)
            .filter(|id| !id.is_empty())
            .ok_or(AdminRefusal {
                cause: CAUSE_INVALID_ADMIN_ARGS,
                detail: "request_id (string) is required".to_owned(),
                recovery: RECOVERY_FIX_ARGS,
            })?;
        let rows: Vec<serde_json::Value> = self
            .store
            .audit_for_request(request_id)
            .await?
            .into_iter()
            .map(|row| {
                let detail = row.detail.map(|raw| {
                    serde_json::from_str::<serde_json::Value>(&raw)
                        .unwrap_or(serde_json::Value::String(raw))
                });
                json!({
                    "id": row.id,
                    "action": row.action,
                    "decision": row.decision.as_str(),
                    "actor": row.actor.as_str(),
                    "detail": detail,
                    "ts": row.ts,
                })
            })
            .collect();
        let count = rows.len();
        Ok(AdminOk {
            outcome: Outcome::Verified,
            body: json!({ "request_id": request_id, "rows": rows }),
            audit: json!({ "op": OP_AUDIT_REQUEST, "request_id": request_id, "rows": count }),
        })
    }
```

Match the `AdminOk.audit` shape the neighbouring handlers use (read
`callers_list`). Run the two tests — PASS.

- [ ] **Step 3: Bridge whitelist and ipc**

`crates/pam_gui/src/bridge.rs`: import `OP_AUDIT_REQUEST` with the other
core ops and make `CORE_ADMIN_OPS: [&str; 10]` end with it. The existing
bridge test that checks the whitelist composition (`tests/bridge.rs` /
`bridge_test.rs`) keeps passing because the length is computed.

`frontend/src/lib/ipc.ts`: add `| "admin.audit.request"` to `AdminOp`
(after `"admin.callers.list"`), and after `callersList`:

```ts
/** One audit row; `detail` is the daemon's JSON when it was JSON. */
export interface AuditRow {
  id: number;
  action: string;
  decision: string;
  actor: string;
  detail: unknown;
  ts: number;
}

/** The audit trail of one request, oldest first; unknown ids answer []. */
export function auditRequest(requestId: string): Promise<{ request_id: string; rows: AuditRow[] }> {
  return adminCall("admin.audit.request", { request_id: requestId });
}
```

- [ ] **Step 4: Gate and PR**

```bash
tools/check.sh
git add crates/pam_daemon crates/pam_gui frontend/src/lib/ipc.ts
git commit -m "feat(daemon): admin.audit.request — one request's audit trail for the GUI"
```

PR title: `feat(daemon): admin.audit.request`.

---

### Task 2: The Ask router library (`frontend/src/lib/ask/`)

Pure TypeScript, no React, no ipc import: everything the intents read comes
through the `Sources` interface, so this task has no dependency on Task 1
beyond the `AuditRow` shape, which it re-declares structurally.

**Files:**
- Create: `frontend/src/lib/ask/answer.ts`, `sources.ts`, `intents.ts`, `rephrase.ts`, `router.ts`, `ask.test.ts`

**Interfaces (produced, used by Task 4):**

```ts
// answer.ts
export interface AskLink { label: string; to: "/" | "/activity" | "/approvals" | "/flows" | "/models" | "/settings"; search?: Record<string, string>; hash?: string; }
export interface Answer { intent: IntentId; sentence: string; facts: Array<[string, string]>; links: AskLink[]; rephrased?: { model: string }; }
export type IntentId = "approvals_waiting" | "why_refused" | "what_ran" | "model_status" | "where_change" | "daemon_status" | "login_start" | "flows" | "tokens_saved" | "fallback";
// sources.ts
export interface Sources {
  daemonStatus(): Promise<{ connected: boolean; status: Record<string, unknown> | null }>;
  approvalsPending(): Promise<{ pending: Array<{ request_id: string; capability: string; repo: string; agent: string; requested_ts: number }> }>;
  activityList(f: { limit?: number; repo?: string; agent?: string; state?: string; capability?: string }): Promise<{ requests: Array<{ id: string; capability: string; repo: string; agent: string; state: string; outcome: string | null; created_ts: number }> }>;
  modelsStatus(): Promise<{ runtime: { state: { state: string; id?: string; device?: string; weight_bytes?: number; context_length?: number; quant?: string; last_used_at?: number } ; busy: boolean }; defaults: { light: string | null; heavy: string | null }; host_ram_bytes: number; models_dir: string }>;
  retentionGet(): Promise<{ evidence_days: number | null; audit_days: number | null }>;
  serviceStatus(): Promise<{ platform: string; state: { kind: "installed"; unit: string; loaded: boolean } | { kind: "not_installed"; unit: string } | { kind: "unsupported"; reason: string } }>;
  evidenceStats(sinceTs: number): Promise<{ compressions: number; source_bytes: number; compact_bytes: number; tokens_avoided_est: number }>;
  flowsList(): Promise<{ flows: Array<{ id: string; name: string; valid: boolean }> }>;
  auditRequest(id: string): Promise<{ rows: Array<{ action: string; decision: string; actor: string; detail: unknown; ts: number }> }>;
  modelsTry(prompt: string, maxTokens: number): Promise<{ text: string }>;
}
// router.ts
export interface AskContext { screen: string; now: number; }
export interface AskOptions { rephrase: boolean; }
export function ask(question: string, ctx: AskContext, sources: Sources, options: AskOptions): Promise<Answer>;
export function matchIntent(question: string): { id: IntentId; args: Args };
export const INTENTS: ReadonlyArray<{ id: IntentId; label: string; canonical: string }>; // pills, in table order, without fallback
```

`Args = { ticket?: string; capability?: string; repo?: string; flow?: string; topic?: SettingsTopic }`;
`SettingsTopic = "retention" | "daemon" | "security" | "models" | "connectors" | "flows" | "appearance"`.

- [ ] **Step 1: Failing router tests**

`ask.test.ts` — write these first (they define the contract; add the
sentence assertions from the table in Step 3 as you implement):

```ts
import { describe, expect, it } from "vitest";
import { INTENTS, ask, matchIntent } from "./router";
import type { Sources } from "./sources";

const NOW = 1_800_000_000; // unix seconds, a Wednesday afternoon
function fakeSources(overrides: Partial<Sources> = {}): Sources {
  return {
    daemonStatus: async () => ({ connected: true, status: { daemon_version: "0.1.0", uptime_s: 3_723, active_requests: 1 } }),
    approvalsPending: async () => ({ pending: [] }),
    activityList: async () => ({ requests: [] }),
    modelsStatus: async () => ({ runtime: { state: { state: "idle" }, busy: false }, defaults: { light: null, heavy: null }, host_ram_bytes: 64e9, models_dir: "/Users/me/llm" }),
    retentionGet: async () => ({ evidence_days: 90, audit_days: null }),
    serviceStatus: async () => ({ platform: "macos", state: { kind: "not_installed", unit: "/Users/me/Library/LaunchAgents/com.github.ro-ag.pam.daemon.plist" } }),
    evidenceStats: async () => ({ compressions: 3, source_bytes: 300_000, compact_bytes: 30_000, tokens_avoided_est: 67_500 }),
    flowsList: async () => ({ flows: [{ id: "pr-readiness", name: "PR readiness", valid: true }, { id: "after-merge-checks", name: "After-merge checks", valid: true }] }),
    auditRequest: async () => ({ rows: [] }),
    modelsTry: async () => ({ text: "" }),
    ...overrides,
  };
}
const ctx = { screen: "/", now: NOW * 1000 };
const off = { rephrase: false };

describe("matchIntent", () => {
  it.each([
    ["what's waiting for my approval?", "approvals_waiting"],
    ["anything pending for me", "approvals_waiting"],
    ["why was that refused?", "why_refused"],
    ["why did repo.push get denied", "why_refused"],
    ["what ran today?", "what_ran"],
    ["what happened in pam recently", "what_ran"],
    ["which model is loaded?", "model_status"],
    ["how much memory is the model using", "model_status"],
    ["where do I change log retention?", "where_change"],
    ["how do I set the approval profile", "where_change"],
    ["is the daemon running?", "daemon_status"],
    ["what version is the daemon", "daemon_status"],
    ["does pam start at login?", "login_start"],
    ["which flows do I have?", "flows"],
    ["run pr-readiness", "flows"],
    ["how many tokens did I save?", "tokens_saved"],
    ["tell me a joke", "fallback"],
    ["", "fallback"],
  ])("%s → %s", (question, id) => {
    expect(matchIntent(question).id).toBe(id);
  });

  it("captures a ticket id, a capability, a repo, a flow id and a settings topic", () => {
    expect(matchIntent("why was 01J9Z8K2M3N4P5Q6R7S8T9V0WX refused").args.ticket).toBe("01J9Z8K2M3N4P5Q6R7S8T9V0WX");
    expect(matchIntent("why was repo.push refused").args.capability).toBe("repo.push");
    expect(matchIntent("what ran today in pam").args.repo).toBe("pam");
    expect(matchIntent("run after-merge-checks").args.flow).toBe("after-merge-checks");
    expect(matchIntent("where do I change start at login").args.topic).toBe("daemon");
    expect(matchIntent("where is the models dir setting").args.topic).toBe("models");
  });

  it("orders overlapping intents: refusals before today, login before daemon, tokens before today", () => {
    expect(matchIntent("what was refused today").id).toBe("why_refused");
    expect(matchIntent("is the daemon starting at login").id).toBe("login_start");
    expect(matchIntent("tokens saved today").id).toBe("tokens_saved");
  });

  it("exposes the nine pills in table order", () => {
    expect(INTENTS.map((i) => i.id)).toEqual(["approvals_waiting", "why_refused", "what_ran", "model_status", "where_change", "daemon_status", "login_start", "flows", "tokens_saved"]);
  });
});

describe("ask", () => {
  it("says nothing waits, then lists raised hands with facts and the Approvals link", async () => {
    const quiet = await ask("what's waiting for my approval?", ctx, fakeSources(), off);
    expect(quiet.sentence).toBe("Nothing waits for you.");
    expect(quiet.links[0]).toMatchObject({ to: "/approvals" });
    const busy = await ask("approvals?", ctx, fakeSources({ approvalsPending: async () => ({ pending: [{ request_id: "r1", capability: "repo.push", repo: "/Users/me/pam", agent: "claude", requested_ts: NOW - 60 }] }) }), off);
    expect(busy.sentence).toBe("1 request waits for your hand.");
    expect(busy.facts).toContainEqual(["repo.push", "claude · pam · 1m ago"]);
  });

  it("quotes the newest refusal from its audit row", async () => {
    const sources = fakeSources({
      activityList: async () => ({ requests: [{ id: "r9", capability: "repo.push", repo: "/Users/me/pam", agent: "codex", state: "refused", outcome: "not_granted", created_ts: NOW - 300 }] }),
      auditRequest: async () => ({ rows: [{ action: "execute", decision: "refuse", actor: "policy", detail: { cause: "not_granted", detail: "repo.push is not granted", recovery: "Grant it in Settings › Security." }, ts: NOW - 300 }] }),
    });
    const answer = await ask("why was that refused?", ctx, sources, off);
    expect(answer.sentence).toBe("I refused repo.push from codex: not_granted — repo.push is not granted. Grant it in Settings › Security.");
    expect(answer.facts).toContainEqual(["ticket", "r9"]);
    expect(answer.links.map((l) => l.to)).toEqual(["/activity", "/settings"]);
  });

  it("counts today's requests by verdict, narrowed to a repo when named", async () => {
    const sources = fakeSources({
      activityList: async ({ repo }) => ({ requests: [
        { id: "a", capability: "echo", repo: "/Users/me/pam", agent: "claude", state: "done", outcome: "solved", created_ts: NOW - 60 },
        { id: "b", capability: "flow.run", repo: "/Users/me/other", agent: "codex", state: "refused", outcome: "not_granted", created_ts: NOW - 120 },
        { id: "c", capability: "echo", repo: "/Users/me/pam", agent: "claude", state: "done", outcome: "solved", created_ts: NOW - 90_000 },
      ].filter((r) => !repo || r.repo.includes(repo)) }),
    });
    const all = await ask("what ran today?", ctx, sources, off);
    expect(all.sentence).toBe("Today 2 requests ran: 1 solved, 1 refused.");
    const pam = await ask("what ran today in pam", ctx, sources, off);
    expect(pam.sentence).toBe("Today 1 request ran in pam: 1 solved.");
    expect(pam.links[0]).toMatchObject({ to: "/activity", search: { repo: "pam" } });
  });

  it("describes the loaded model or the idle default", async () => {
    const idle = await ask("which model is loaded?", ctx, fakeSources(), off);
    expect(idle.sentence).toBe("No model is loaded; no light default is set.");
    const loaded = await ask("model?", ctx, fakeSources({ modelsStatus: async () => ({ runtime: { state: { state: "loaded", id: "qwen/qwen3-0.6b-q8_0", device: "metal", weight_bytes: 639e6, context_length: 8192, quant: "Q8_0", last_used_at: NOW - 10 }, busy: false }, defaults: { light: "qwen/qwen3-0.6b-q8_0", heavy: null }, host_ram_bytes: 64e9, models_dir: "/x" }) }), off);
    expect(loaded.sentence).toBe("qwen/qwen3-0.6b-q8_0 is loaded on metal: 0.6 GB of 64.0 GB RAM, context 8192.");
  });

  it("points settings questions at their panel with the current value when known", async () => {
    const answer = await ask("where do I change log retention?", ctx, fakeSources(), off);
    expect(answer.sentence).toBe("Retention lives in Settings › Retention.");
    expect(answer.facts).toContainEqual(["evidence", "90 days"]);
    expect(answer.facts).toContainEqual(["audit", "forever"]);
    expect(answer.links[0]).toMatchObject({ to: "/settings", hash: "retention" });
  });

  it("reports the daemon, login start, flows, and tokens saved", async () => {
    expect((await ask("is the daemon running?", ctx, fakeSources(), off)).sentence).toBe("The daemon answers: version 0.1.0, up for 1h 02m, 1 active request.");
    expect((await ask("does pam start at login?", ctx, fakeSources(), off)).sentence).toBe("No: nothing starts me at login.");
    expect((await ask("which flows do I have?", ctx, fakeSources(), off)).sentence).toBe("You have 2 flows: pr-readiness, after-merge-checks.");
    const run = await ask("run pr-readiness", ctx, fakeSources(), off);
    expect(run.sentence).toBe("I do not run flows from here; open pr-readiness on the Flows screen.");
    expect(run.links[0]).toMatchObject({ to: "/flows", search: { flow: "pr-readiness" } });
    expect((await ask("how many tokens did I save?", ctx, fakeSources(), off)).sentence).toBe("This week I avoided about 67,500 tokens across 3 compressions (293 KB → 29 KB).");
  });

  it("answers honestly when nothing matches, and when the daemon is down", async () => {
    const none = await ask("tell me a joke", ctx, fakeSources(), off);
    expect(none.intent).toBe("fallback");
    expect(none.sentence).toMatch(/^I can answer about pam itself:/);
    const down = await ask("is the daemon running?", ctx, fakeSources({ daemonStatus: async () => ({ connected: false, status: null }) }), off);
    expect(down.sentence).toBe("The daemon is not answering; the next question starts it.");
  });

  it("rephrases only when enabled, one line, every fact intact; otherwise keeps the template", async () => {
    const good = fakeSources({ modelsStatus: async () => ({ runtime: { state: { state: "idle" }, busy: false }, defaults: { light: "m", heavy: null }, host_ram_bytes: 1, models_dir: "/x" }), modelsTry: async () => ({ text: "Right now nothing waits for you." }) });
    const on = await ask("approvals?", ctx, good, { rephrase: true });
    expect(on.sentence).toBe("Right now nothing waits for you.");
    expect(on.rephrased).toEqual({ model: "m" });
    const bad = fakeSources({ modelsStatus: good.modelsStatus, modelsTry: async () => ({ text: "Two things\nwait" }) });
    expect((await ask("approvals?", ctx, bad, { rephrase: true })).rephrased).toBeUndefined();
    const slow = fakeSources({ modelsStatus: good.modelsStatus, modelsTry: () => new Promise(() => {}) });
    const answer = await ask("approvals?", ctx, slow, { rephrase: true, timeoutMs: 20 } as never);
    expect(answer.sentence).toBe("Nothing waits for you.");
    expect((await ask("approvals?", ctx, good, off)).rephrased).toBeUndefined();
  });
});
```

(`AskOptions` carries an optional `timeoutMs` for tests; default 8000.)
Run `npm --prefix frontend run test -- ask` — expect module-not-found.

- [ ] **Step 2: `answer.ts`, `sources.ts`**

`sources.ts` holds the `Sources` interface exactly as in Interfaces (no
implementation here). `answer.ts` holds `Answer`, `AskLink`, `IntentId`,
and small formatters shared by intents:

```ts
export function plural(n: number, one: string, many = `${one}s`): string { return `${n} ${n === 1 ? one : many}`; }
export function repoTail(repo: string): string { const s = repo.split("/").filter(Boolean); return s[s.length - 1] ?? repo; }
export function ago(ts: number, nowMs: number): string  // "1m ago", "2h ago", "3d ago" (reuse ../time relativeTime if its signature fits: relativeTime(ts, nowMs))
export function gb(bytes: number): string { return `${(bytes / 1e9).toFixed(1)} GB`; }
export function kb(bytes: number): string { return `${Math.round(bytes / 1024)} KB`; }
export function duration(seconds: number): string  // reuse ../time formatDuration
```

Reuse `frontend/src/lib/time.ts` (`relativeTime`, `formatDuration`) and
`frontend/src/lib/bytes.ts` where their output matches the expected strings
in the tests; otherwise implement locally and keep the tests' strings.

- [ ] **Step 3: `intents.ts`**

The ordered table. Sketch (fill every branch; the tests pin the strings):

```ts
const ULID = /\b[0-9A-HJKMNP-TV-Z]{26}\b/;
const CAPABILITY = /\b([a-z]+(?:\.[a-z_]+)+)\b/;          // repo.push, flow.run, compress.log
const IN_REPO = /\bin\s+([\w.-]+)\b/i;
const RUN_FLOW = /\brun\s+([a-z0-9][a-z0-9-]*)/i;
const TOPICS: Array<[RegExp, SettingsTopic, string]> = [
  [/retention|prune|how long .*keep/i, "retention", "Retention"],
  [/login|startup|start at|launch/i, "daemon", "Daemon"],
  [/daemon|stop|restart/i, "daemon", "Daemon"],
  [/profile|approval mode|relaxed|strict/i, "security", "Security"],
  [/grant|capabilit/i, "security", "Security"],
  [/models? (dir|folder|directory)|weights|tier|curator/i, "models", "Models"],
  [/connector|jira|github|sonar|confluence|sharepoint|aws/i, "connectors", "Connectors"],
  [/allowed program|flow setting|flows? (dir|folder)/i, "flows", "Flows"],
  [/theme|mode|dark|light|appearance/i, "appearance", "Appearance"],
];

export const INTENT_TABLE: Intent[] = [
  { id: "approvals_waiting", label: "waiting for me", canonical: "what's waiting for my approval?", patterns: [/approv/i, /waiting for (me|my)/i, /pending/i, /raised hand/i], answer: approvalsWaiting },
  { id: "why_refused", label: "why refused", canonical: "why was that refused?", patterns: [/refus/i, /denied/i, /why (did|was).*(not|n't|never)/i], capture: (q) => ({ ticket: q.match(ULID)?.[0], capability: q.match(CAPABILITY)?.[1] }), answer: whyRefused },
  { id: "tokens_saved", ... patterns: [/token/i, /saved/i, /compress/i, /odometer/i] },
  { id: "login_start", ... patterns: [/login/i, /startup/i, /boot/i, /start at/i] },
  { id: "where_change", ... patterns: [/where (do|can|would) i/i, /how do i (change|set|turn|switch)/i, /setting/i, /where is/i], capture: (q) => ({ topic: TOPICS.find(([re]) => re.test(q))?.[1] }) },
  { id: "what_ran", ... patterns: [/what (ran|happened|did)/i, /today/i, /recent/i, /this (morning|afternoon|week)/i], capture: (q) => ({ repo: q.match(IN_REPO)?.[1] }) },
  { id: "model_status", ... patterns: [/model/i, /loaded/i, /memory/i, /\bram\b/i, /\bgpu\b/i, /metal/i] },
  { id: "daemon_status", ... patterns: [/daemon/i, /running/i, /uptime/i, /alive/i, /status/i, /version/i] },
  { id: "flows", ... patterns: [/flow/i, RUN_FLOW], capture: (q) => ({ flow: q.match(RUN_FLOW)?.[1] }) },
];
```

Table order in `INTENTS` (pills) follows the spec order; **matching order**
is: why_refused, tokens_saved, login_start, where_change, what_ran,
approvals_waiting, model_status, daemon_status, flows (the tests pin the
overlaps). Keep the two orders as two arrays derived from one table.

Answer functions (each `async (args, sources, ctx) => Answer`):

- `approvalsWaiting`: sentence `Nothing waits for you.` or
  `${plural(n, "request")} wait${n === 1 ? "s" : ""} for your hand.`;
  facts per pending: `[capability, \`${agent} · ${repoTail(repo)} · ${ago(requested_ts, now)}\`]`
  (≤8); link `{ label: "Open Approvals", to: "/approvals" }`.
- `whyRefused`: `activityList({ state: "refused", limit: 20, capability? })`,
  pick the row whose id equals `args.ticket` else the first; none →
  `I have refused nothing lately.`; else `auditRequest(id)`, take the last
  row whose `decision === "refuse"` (else the last row); read
  `detail.{cause,detail,recovery}` when `detail` is an object, else use
  `row.outcome` as cause and empty detail; sentence
  `I refused ${capability} from ${agent}: ${cause} — ${detail}. ${recovery}`
  (drop the ` — ${detail}` part when empty, drop the trailing recovery when
  empty); facts `ticket`, `when` (ago), `cause`; links Activity
  (`search: { state: "refused" }`) and, when cause matches
  `/grant|profile|approval/`, Settings `hash: "security"`.
- `whatRan`: `activityList({ limit: 100, repo: args.repo })`, keep rows with
  `created_ts * 1000 >= localMidnight(ctx.now)`; counts by
  `outcome` for done rows (solved/changed/verified/unresolved/blocked),
  `refused`, `failed`, and `running` (queued+running+waiting_approval →
  "still running"); sentence
  `Today ${plural(n, "request")} ran${repo ? ` in ${repo}` : ""}: ${parts.join(", ")}.`
  with parts only for non-zero counts, in the order solved, changed,
  verified, unresolved, blocked, refused, failed, still running; zero rows →
  `Nothing has run today${repo ? ` in ${repo}` : ""}.`; facts: top three
  capabilities with counts, agents seen; link Activity with `search.repo`
  when named.
- `modelStatus`: idle → `No model is loaded; ${light ? `the light default is ${light}` : "no light default is set"}.`;
  loading → `${id} is loading (${phase}).`; loaded →
  `${id} is loaded on ${device}: ${gb(weight)} of ${gb(host)} RAM, context ${context_length}.`;
  facts quant, architecture, last used, defaults; link Models.
- `whereChange`: topic missing → sentence
  `Tell me which setting: retention, start at login, the approval profile, grants, the models directory, connectors, flow programs, or the theme.`
  with link Settings; else `${Topic} lives in Settings › ${Panel}.` with
  the retention topic adding facts from `retentionGet` (`evidence`,
  `audit`; null → `forever`, n → `${n} days`); link Settings with the hash.
  Topic → sentence subject: retention → "Retention", daemon (login words) →
  "Start at login", daemon (daemon words) → "The daemon", security →
  "The approval profile and grants", models → "The models directory and
  tier defaults", connectors → "Connectors", flows → "Flow programs",
  appearance → "Theme and mode".
- `daemonStatus`: down → `The daemon is not answering; the next question starts it.`;
  up → `The daemon answers: version ${v}, up for ${duration(uptime_s)}, ${plural(active, "active request")}.`;
  link Settings `hash: "daemon"`.
- `loginStart`: installed → `Yes: the ${platform} unit is installed${loaded ? " and loaded" : " but not loaded"}.`;
  not installed → `No: nothing starts me at login.`; unsupported →
  `Not here: ${reason}.`; fact `unit`; link Settings `hash: "daemon"`.
- `flows`: with `args.flow` → `I do not run flows from here; open ${flow} on the Flows screen.`
  link Flows `search: { flow }`; else `You have ${plural(n, "flow")}: ${ids.join(", ")}.`
  (`You have no flows yet.` when empty; invalid ones get ` (invalid)`), link Flows.
- `tokensSaved`: `evidenceStats(ctx.now/1000 - 7*86400)` →
  `This week I avoided about ${tokens.toLocaleString("en-US")} tokens across ${plural(c, "compression")} (${kb(source)} → ${kb(compact)}).`;
  zero compressions → `Nothing has been compressed this week.`; link Activity.
- `fallback`: `I can answer about pam itself: approvals, refusals, today's activity, the model, settings, the daemon, login, flows, tokens saved.`;
  no links.

Every answer function catches a rejected source and returns a sentence in
Pam's voice naming the failure (`I could not read ${what}: ${detail}`) with
the refusal detail from `toBridgeFailure`-shaped errors, so the Home screen
never sees a throw from `ask`.

- [ ] **Step 4: `rephrase.ts` and `router.ts`**

```ts
// rephrase.ts
export async function maybeRephrase(answer: Answer, sources: Sources, options: AskOptions): Promise<Answer> {
  if (!options.rephrase || answer.intent === "fallback") return answer;
  const status = await sources.modelsStatus().catch(() => null);
  const model = status?.defaults.light ?? null;
  if (!model) return answer;
  const prompt = `Rewrite in one sentence, first person, warm and plain, keeping every number and name exactly as written: ${answer.sentence}`;
  const timeoutMs = options.timeoutMs ?? 8_000;
  const reply = await Promise.race([
    sources.modelsTry(prompt, 96).then((r) => r.text).catch(() => ""),
    new Promise<string>((resolve) => setTimeout(() => resolve(""), timeoutMs)),
  ]);
  const line = reply.trim();
  if (!line || line.includes("\n")) return answer;
  const values = answer.facts.map(([, v]) => v).filter((v) => answer.sentence.includes(v));
  const numbers = answer.sentence.match(/\d[\d,.]*/g) ?? [];
  if (![...values, ...numbers].every((needle) => line.includes(needle))) return answer;
  return { ...answer, sentence: line, rephrased: { model } };
}
// router.ts
export function matchIntent(question: string): { id: IntentId; args: Args } { const q = question.trim(); if (!q) return { id: "fallback", args: {} }; for (const intent of MATCH_ORDER) if (intent.patterns.some((p) => p.test(q))) return { id: intent.id, args: intent.capture?.(q) ?? {} }; return { id: "fallback", args: {} }; }
export async function ask(question, ctx, sources, options) { const { id, args } = matchIntent(question); const intent = TABLE_BY_ID[id]; const answer = await intent.answer(args, sources, ctx); return maybeRephrase(answer, sources, options); }
export const INTENTS = SPEC_ORDER.map(({ id, label, canonical }) => ({ id, label, canonical }));
```

Run `npm --prefix frontend run test -- ask` until green; `npm --prefix
frontend run lint`; `npx prettier --check src/lib/ask`.

- [ ] **Step 5: Gate and PR**

```bash
tools/check.sh
git add frontend/src/lib/ask
git commit -m "feat(gui): Ask router — nine intents over live state, honest fallback, guarded rephrase"
```

PR title: `feat(gui): Ask router library`.

---

### Task 3: Deep-link plumbing — Settings anchors, `?flow=` preselect, rephrase toggle

**Files:**
- Modify: `frontend/src/components/ui/Section.tsx`, `frontend/src/screens/Settings.tsx`, `Settings.test.tsx`, `frontend/src/screens/SettingsModels.tsx`, `SettingsModels.test.tsx`, `frontend/src/router.tsx` (flows route only), `frontend/src/screens/Flows.tsx`, `Flows.test.tsx`
- Create: `frontend/src/lib/ask/prefs.ts`

**Interfaces:**
- Produces: `Section` prop `id?: string` (rendered as the `<section id>`); Settings sections carry ids `appearance`, `security`, `models`, `flows`, `connectors`, `daemon`, `retention`, `logs` and scroll to `location.hash` on mount and on change; Flows route `validateSearch` → `{ flow?: string }`, `FlowsScreen({ initialFlow?: string })` preselects it; `prefs.ts`: `readRephrase(): boolean`, `writeRephrase(on: boolean): void`, `subscribeRephrase(listener): () => void`, `useRephrasePref(): [boolean, (on: boolean) => void]` (via `useSyncExternalStore`, `localStorage` key `pam.ask.rephrase`, same try/catch style as `theme.ts`).

- [ ] **Step 1: Failing tests**

`Settings.test.tsx`, new `describe("deep links")`:

```ts
  it("gives every section a stable anchor and scrolls to the hash", async () => {
    const router = createAppRouter(createMemoryHistory({ initialEntries: ["/settings#retention"] }));
    const scrolled: string[] = [];
    Element.prototype.scrollIntoView = function () { scrolled.push((this as HTMLElement).id); };
    render(<App router={router} />);
    await screen.findByRole("region", { name: "Retention" });
    for (const id of ["appearance", "security", "models", "flows", "connectors", "daemon", "retention", "logs"]) {
      expect(document.getElementById(id)).not.toBeNull();
    }
    await waitFor(() => expect(scrolled).toContain("retention"));
  });
```

`SettingsModels.test.tsx` (read its existing render helper first):

```ts
  it("keeps the Ask Pam rephrase toggle off by default and remembers a flip", async () => {
    window.localStorage.removeItem("pam.ask.rephrase");
    renderModels();
    const toggle = await screen.findByRole("switch", { name: /rephrase answers with the light model/i });
    expect(toggle).toHaveAttribute("aria-checked", "false");
    fireEvent.click(toggle);
    expect(toggle).toHaveAttribute("aria-checked", "true");
    expect(window.localStorage.getItem("pam.ask.rephrase")).toBe("on");
  });
```

`Flows.test.tsx`:

```ts
  it("preselects the flow named by the route search", async () => {
    render(<QueryClientProvider client={createAppQueryClient()}><FlowsScreen initialFlow="after-merge-checks" /></QueryClientProvider>);
    expect(await screen.findByRole("region", { name: "flow after-merge-checks" })).toBeInTheDocument();
  });
```

(Use the flow ids the existing Flows test fixtures list.) Run the three
files — expect failures.

- [ ] **Step 2: Implement**

`Section.tsx`: add `id?: string` and render `<section id={id} …>`.

`Settings.tsx`: pass `id` to each `Section` (slug of the eyebrow), and in
`SettingsScreen`:

```tsx
  const hash = useRouterState({ select: (s) => s.location.hash });
  useEffect(() => {
    if (!hash) return;
    document.getElementById(hash.replace(/^#/, ""))?.scrollIntoView({ block: "start" });
  }, [hash]);
```

(import `useRouterState` from `@tanstack/react-router`, `useEffect` from react.)

`prefs.ts`:

```ts
const KEY = "pam.ask.rephrase";
const listeners = new Set<() => void>();
export function readRephrase(): boolean { try { return window.localStorage.getItem(KEY) === "on"; } catch { return false; } }
export function writeRephrase(on: boolean): void { try { window.localStorage.setItem(KEY, on ? "on" : "off"); } catch { /* optional */ } for (const l of listeners) l(); }
export function subscribeRephrase(listener: () => void): () => void { listeners.add(listener); return () => listeners.delete(listener); }
export function useRephrasePref(): [boolean, (on: boolean) => void] { const on = useSyncExternalStore(subscribeRephrase, readRephrase, () => false); return [on, writeRephrase]; }
```

`SettingsModels.tsx`: a new small `AskPamPanel` after `TierDefaultsPanel`
(same `Panel ground="raised" … p-5` shape, eyebrow `ask pam`), one row:
`font-data` label "rephrase answers with the light model", a `Button`
`role="switch" aria-checked` that flips `useRephrasePref`, and a
`font-voice` line: on → "I keep every number and name; if the model drops
one, my own sentence stands." off → "My answers are my own sentences from
live state; turn this on to let the light model soften them."

`router.tsx`: `flowsRoute` gets

```ts
  validateSearch: (search: Record<string, unknown>): { flow?: string } =>
    typeof search.flow === "string" && search.flow !== "" ? { flow: search.flow } : {},
  component: FlowsRoute,
```

with `function FlowsRoute() { const { flow } = flowsRoute.useSearch(); return <FlowsScreen initialFlow={flow} />; }`
(declare after the route; TanStack allows `Route.useSearch()` on the route
object). `FlowsScreen({ initialFlow }: { initialFlow?: string } = {})`:
`useState<string | null>(initialFlow ?? null)` for `picked`, plus an
effect that re-picks when `initialFlow` changes.

- [ ] **Step 3: Gate and PR**

```bash
npm --prefix frontend run test -- Settings Flows
tools/check.sh
git add frontend/src
git commit -m "feat(gui): settings anchors, ?flow= preselect, Ask Pam rephrase toggle"
```

PR title: `feat(gui): deep-link plumbing for Ask Pam`.

---

### Task 4: Home screen

Needs Tasks 1, 2 and 3 merged.

**Files:**
- Create: `frontend/src/screens/Home.tsx`, `frontend/src/screens/Home.test.tsx`, `frontend/src/lib/ask/live.ts` (the real `Sources` over ipc)
- Modify: `frontend/src/router.tsx` (index route renders Home), `frontend/src/components/shell/Sidebar.tsx` (Home entry), `frontend/src/components/shell/shell.test.tsx`

**Interfaces:**
- Consumes: `ask`, `INTENTS`, `Answer` (Task 2); `useRephrasePref` (Task 3); ipc wrappers incl. `auditRequest` (Task 1), `serviceStatus`, `modelsTry`.
- Produces: `liveSources(): Sources` in `live.ts`; route `/` → `HomeScreen`.

- [ ] **Step 1: Failing tests**

`Home.test.tsx` mounts the whole `App` with a memory history at `/` and
mocks `../lib/ipc` like `Settings.test.tsx` (copy its `mocks` pattern; stub
`daemonStatus`, `approvalsPending`, `activityList`, `callersList`,
`modelsStatus`, `retentionGet`, `serviceStatus`, `evidenceStats`,
`flowsList`, `auditRequest`, `modelsTry`, `subscribeEvents`). Tests:

```ts
  it("greets in Pam's voice from the daemon and approvals state", …)      // "Good <part of day>" heading + "The water is calm: nothing waits for you." ; with one pending → "One request waits for your hand."
  it("answers a typed question and keeps only the last three exchanges", …) // type 4 questions, Enter each; expect 3 answer cards, newest first
  it("asks the canonical question when a pill is clicked", …)              // click pill "waiting for me" → question text shows, answer sentence "Nothing waits for you."
  it("renders facts and deep links, and the link navigates", …)            // ask "does pam start at login?" → link "Open Settings › Daemon" → router pathname "/settings", hash "#daemon"
  it("explains the placeholder memory rule and disables the input while asking", …)
  it("shows the model line only when rephrase is on", …)                   // localStorage on + defaults.light null → "answers stay in my own words: no light model is set" with a Models link
  it("renders a source failure as Pam's sentence, not a crash", …)         // approvalsPending rejects with {cause,detail,recovery} → sentence starts with "I could not read"
```

`shell.test.tsx`: add a test that `/` renders the Home heading and the
sidebar has a `Home` link first.

- [ ] **Step 2: `live.ts`**

```ts
import * as ipc from "../ipc";
import type { Sources } from "./sources";
export function liveSources(): Sources {
  return {
    daemonStatus: () => ipc.daemonStatus(),
    approvalsPending: () => ipc.approvalsPending(),
    activityList: (f) => ipc.activityList(f as Parameters<typeof ipc.activityList>[0]),
    modelsStatus: () => ipc.modelsStatus(),
    retentionGet: () => ipc.retentionGet(),
    serviceStatus: () => ipc.serviceStatus(),
    evidenceStats: (since) => ipc.evidenceStats(since),
    flowsList: () => ipc.flowsList(),
    auditRequest: (id) => ipc.auditRequest(id),
    modelsTry: (prompt, max) => ipc.modelsTry(prompt, max),
  };
}
```

(Adjust return shapes with thin maps where ipc's types are wider than
`Sources`; never widen `Sources`.)

- [ ] **Step 3: `Home.tsx`**

Structure (see the spec's Home section for copy):

```tsx
export function HomeScreen() {
  const status = useQuery({ queryKey: ["daemon", "status"], queryFn: daemonStatus, refetchInterval: 5_000 });
  const pending = useQuery({ queryKey: ["approvals", "pending"], queryFn: approvalsPending, refetchInterval: 5_000 });
  const [rephrase] = useRephrasePref();
  const models = useQuery({ queryKey: ["models", "status"], queryFn: modelsStatus, enabled: rephrase });
  const pathname = useRouterState({ select: (s) => s.location.pathname });
  const navigate = useNavigate();
  const [question, setQuestion] = useState("");
  const [exchanges, setExchanges] = useState<Exchange[]>([]);   // { id, question, answer | null, failure | null }
  const [asking, setAsking] = useState(false);
  const sources = useMemo(liveSources, []);

  const submit = async (text: string) => { const q = text.trim(); if (!q || asking) return; setAsking(true); setQuestion(""); const id = crypto.randomUUID(); setExchanges((prev) => [{ id, question: q, answer: null }, ...prev].slice(0, 3)); try { const answer = await ask(q, { screen: pathname, now: Date.now() }, sources, { rephrase }); setExchanges((prev) => prev.map((e) => (e.id === id ? { ...e, answer } : e))); } finally { setAsking(false); } };
  …
}
```

Render: eyebrow `home · ask pam`, `<h1 className="font-display text-title …">{partOfDay(now)}</h1>` ("Good morning" < 12h, "Good afternoon" < 18h, else "Good evening"), the greeting sentence in `font-voice text-lg italic`, the composer (`<input aria-label="ask pam" placeholder="Ask about pam itself — I keep only this screen and the last three exchanges" …>` inside a `Panel ground="raised"`, Enter submits, Escape clears, disabled while `asking`; a ghost `Button` "Ask"), pills (`Button size="sm" variant="ghost"` per `INTENTS`, `aria-label={\`ask: ${canonical}\`}`), the exchange list (`<ol aria-label="exchanges">`; each `<li>`: question in `font-data text-xs text-ink-faint`, then the answer card `Panel` with the sentence `font-voice text-base`, a `<dl>` facts grid like the Daemon panel's, and link `Button`s that call `navigate({ to, search, hash })`; while `answer === null` a `font-data` "thinking…" line; `rephrased` → `font-data text-xs` "rephrased by {model}"), and the model line when `rephrase` is on and `models.data?.defaults.light` is null: "answers stay in my own words: no light model is set" + `Button` "Open Models".

`Sidebar.tsx`: add `"/"` to `NavLink`'s `to` union, first entry
`<NavLink to="/" label="Home" icon={MessageCircleQuestion} />` (import from
lucide-react); active state for `/` uses exact match (already `pathname === to`).

`router.tsx`: `indexRoute` becomes `{ path: "/", component: HomeScreen }`
(drop the redirect and the `redirect` import); update the file comment.

- [ ] **Step 4: Gate, fixture eyeball, PR**

```bash
npm --prefix frontend run test -- Home shell
tools/check.sh
npm --prefix frontend run build && cargo build --release -p pam --features gui-embed
strings target/release/pam | grep -c "I keep only this screen"
```

Commit `feat(gui): Home — the self-aware Ask Pam composer`; PR title the same.

---

### Task 5: The tide — lanes per agent, chips, live settle

**Files:**
- Modify: `frontend/src/screens/Activity.tsx`, `frontend/src/screens/Activity.test.tsx`

**Interfaces:** none new; URL search params unchanged (`repo`, `agent`, `state`).

- [ ] **Step 1: Failing tests**

Add to `Activity.test.tsx` (keep every existing test; the row/detail/lens
tests must still pass unchanged):

```ts
describe("lanes", () => {
  it("groups rows into one lane per agent, alphabetical, newest on top", async () => {
    renderActivity();
    const claude = within(await screen.findByRole("region", { name: "claude" }));
    const codex = within(screen.getByRole("region", { name: "codex" }));
    expect(claude.getAllByRole("listitem")).toHaveLength(2);
    expect(codex.getAllByRole("listitem")).toHaveLength(1);
    const lanes = screen.getAllByRole("region").filter((r) => ["claude", "codex"].includes(r.getAttribute("aria-label") ?? ""));
    expect(lanes.map((l) => l.getAttribute("aria-label"))).toEqual(["claude", "codex"]);
  });
  it("shows agent and repo chips; an agent chip narrows to one lane and writes the URL", async () => {
    const router = renderActivity();
    fireEvent.click(await screen.findByRole("button", { name: "agent codex" }));
    await waitFor(() => expect(router.state.location.search).toMatchObject({ agent: "codex" }));
    expect(screen.queryByRole("region", { name: "claude" })).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "repo other" }));
    await waitFor(() => expect(router.state.location.search).toMatchObject({ repo: "/Users/dev/other" }));
  });
  it("says so when the chips leave nothing, and clears them", …);  // "No requests match these chips." + "Clear chips" button resets search
});
```

(Adapt the render helper name and the `TIDE` fixture already in the file.)

- [ ] **Step 2: Implement**

In `Activity.tsx`:

- Replace the two `FilterSelect`s with a `ChipBar` under the state
  segments: `<div role="group" aria-label="chips">` with one `button`
  per agent (`aria-label="agent <name>"`, `aria-pressed`) and one per repo
  (`aria-label="repo <tail>"`, `title` full path); options come from
  `callersList` plus the agents/repos present in `requests` (so a lane
  never lacks its chip); the active chip uses `bg-accent-soft text-ink`,
  idle `text-ink-faint hover:text-ink`, same classes as the segments.
  Clicking an active chip clears it. Keep `setFilters`.
- Group: `const lanes = useMemo(() => groupBy(rows, (r) => r.agent) sorted by agent, each lane's rows newest first and capped at 50, …)`.
- Render the lanes in `<div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">`
  (an auto-fit `minmax` column template would be an arbitrary value, which
  ESLint bans; the breakpoints give one column below `md`). Each lane:

```tsx
<motion.section layout key={lane.agent} aria-label={lane.agent} className="min-w-0 rounded-card border border-line bg-surface-raised/40 p-2">
  <header className="flex items-center gap-2 px-2 pb-2">
    <Badge tone="accent">{lane.agent}</Badge>
    <span className="font-data text-xs text-ink-faint">{lane.rows.length}</span>
    <span className="ml-auto font-data text-xs text-ink-faint">{relativeTime(lane.latest, now)}</span>
  </header>
  <ul className="divide-y divide-line">
    <AnimatePresence initial={false}>
      {lane.rows.map((row) => (
        <motion.li key={row.id} layout="position" initial={reduced ? false : { opacity: 0, y: -8 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, transition: { duration: 0.16 } }} transition={{ duration: 0.24, ease: "easeOut" }}>
          <TideRow … />   // TideRow's outer element becomes a <div>; the <li> moves here
        </motion.li>
      ))}
    </AnimatePresence>
  </ul>
</motion.section>
```

  wrapped in `<AnimatePresence>` at the grid level so a lane removed by an
  agent chip exits with the same fade; `const reduced = useReducedMotion();`
  from `motion/react`. The tests already pin `useReducedMotion` to true.
- Hide the agent `Badge` inside `TideRow` (the lane header carries it) and
  keep the repo tail.
- Empty-after-chips copy: `No requests match these chips.` with a ghost
  `Button` "Clear chips" that resets `repo`, `agent`, `state`.
- Footer line: `${rows.length} request(s) · ${lanes.length} lane(s) · newest first`.

- [ ] **Step 3: Gate, fixture eyeball, PR**

```bash
npm --prefix frontend run test -- Activity
tools/check.sh
```

Eyeball through the fixture proxy with two agents (spec "Testing": a shell
copied to `/tmp/agents/claude` running `pam echo` against the scratch
daemon, and requests through the proxy), in both theme families; capture
before/after screenshots and a screenshot mid-settle. Commit
`feat(gui): Activity as tide — lanes per agent, chips, live settle`; PR
title `feat(gui): Activity tide lanes`.

---

### Task 6: Coordinator checkpoint (ptrack #20)

- [ ] On the settled `main`: `tools/check.sh` green; gui-embed strings for
  `admin.audit.request` and the composer placeholder; live eyeball of Home
  (greeting, pills, two answers with links that navigate, model line) and
  the tide (two lanes, chip toggle, a request arriving live) through the
  fixture proxy in both theme families; final `main` run green by id with
  the literal `success`.
- [ ] `ptrack task done 20 --summary …`, `ptrack plan done 7`, act on the
  checkpoint block, `ptrack summary set …`.
