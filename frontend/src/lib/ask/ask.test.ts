import { describe, expect, it, vi } from "vitest";
import { INTENTS, ask, matchIntent } from "./router";
import type { Sources } from "./sources";

// "Today" is a local-calendar window, so the fixtures below (60s and 120s
// before `NOW`, versus 25h before) only read as "today" while the clock is
// not sitting on a local midnight. `NOW` is 08:00 UTC — midnight sharp in
// America/Los_Angeles — so the timezone is pinned here and the suite reads
// the same on a laptop as it does in CI.
vi.stubEnv("TZ", "UTC");

const NOW = 1_800_000_000; // unix seconds, a Wednesday afternoon
function fakeSources(overrides: Partial<Sources> = {}): Sources {
  return {
    daemonStatus: async () => ({
      connected: true,
      status: { daemon_version: "0.1.0", uptime_s: 3_723, active_requests: 1 },
    }),
    approvalsPending: async () => ({ pending: [] }),
    activityList: async () => ({ requests: [] }),
    modelsStatus: async () => ({
      runtime: { state: { state: "idle" }, busy: false },
      defaults: { light: null, heavy: null },
      host_ram_bytes: 64e9,
      models_dir: "/Users/me/llm",
    }),
    retentionGet: async () => ({ evidence_days: 90, audit_days: null }),
    serviceStatus: async () => ({
      platform: "macos",
      state: {
        kind: "not_installed",
        unit: "/Users/me/Library/LaunchAgents/com.github.ro-ag.pam.daemon.plist",
      },
    }),
    evidenceStats: async () => ({
      compressions: 3,
      source_bytes: 300_000,
      compact_bytes: 30_000,
      tokens_avoided_est: 67_500,
    }),
    flowsList: async () => ({
      flows: [
        { id: "pr-readiness", name: "PR readiness", valid: true },
        { id: "after-merge-checks", name: "After-merge checks", valid: true },
      ],
    }),
    auditRequest: async () => ({ rows: [] }),
    modelsTry: async () => ({ text: "", model: { id: "m" } }),
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
    ["Summarize a build log", "start_task"],
    ["triage the CI failure", "start_task"],
    ["check PR readiness", "start_task"],
    ["watch this GitHub run", "start_task"],
    ["how many tokens did I save?", "tokens_saved"],
    ["tell me a joke", "fallback"],
    ["", "fallback"],
  ])("%s → %s", (question, id) => {
    expect(matchIntent(question).id).toBe(id);
  });

  it("captures a ticket id, a capability, a repo, a flow id and a settings topic", () => {
    expect(matchIntent("why was 01J9Z8K2M3N4P5Q6R7S8T9V0WX refused").args.ticket).toBe(
      "01J9Z8K2M3N4P5Q6R7S8T9V0WX",
    );
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

  it("exposes the ten pills in table order", () => {
    expect(INTENTS.map((i) => i.id)).toEqual([
      "approvals_waiting",
      "why_refused",
      "what_ran",
      "model_status",
      "where_change",
      "daemon_status",
      "login_start",
      "flows",
      "start_task",
      "tokens_saved",
    ]);
  });
});

describe("ask", () => {
  it("says nothing waits, then lists raised hands with facts and the Approvals link", async () => {
    const quiet = await ask("what's waiting for my approval?", ctx, fakeSources(), off);
    expect(quiet.sentence).toBe("Nothing waits for you.");
    expect(quiet.links[0]).toMatchObject({ to: "/approvals" });
    const busy = await ask(
      "approvals?",
      ctx,
      fakeSources({
        approvalsPending: async () => ({
          pending: [
            {
              request_id: "r1",
              capability: "repo.push",
              repo: "/Users/me/pam",
              agent: "claude",
              requested_ts: NOW - 60,
            },
          ],
        }),
      }),
      off,
    );
    expect(busy.sentence).toBe("1 request waits for your hand.");
    expect(busy.facts).toContainEqual(["repo.push", "claude · pam · 1m ago"]);
  });

  it("quotes the newest refusal from its audit row", async () => {
    const sources = fakeSources({
      activityList: async () => ({
        requests: [
          {
            id: "r9",
            capability: "repo.push",
            repo: "/Users/me/pam",
            agent: "codex",
            state: "refused",
            outcome: "not_granted",
            created_ts: NOW - 300,
          },
        ],
      }),
      auditRequest: async () => ({
        rows: [
          {
            action: "execute",
            decision: "refuse",
            actor: "policy",
            detail: {
              cause: "not_granted",
              detail: "repo.push is not granted",
              recovery: "Grant it in Settings › Security.",
            },
            ts: NOW - 300,
          },
        ],
      }),
    });
    const answer = await ask("why was that refused?", ctx, sources, off);
    expect(answer.sentence).toBe(
      "PAM refused repo.push from codex: not_granted — repo.push is not granted. Grant it in Settings › Security.",
    );
    expect(answer.facts).toContainEqual(["ticket", "r9"]);
    expect(answer.links.map((l) => l.to)).toEqual(["/activity", "/settings"]);
  });

  it("counts today's requests by verdict, narrowed to a repo when named", async () => {
    const filters: Array<{ hide_probes?: boolean }> = [];
    const sources = fakeSources({
      activityList: async (f) => (
        filters.push(f),
        {
          requests: [
            {
              id: "a",
              capability: "echo",
              repo: "/Users/me/pam",
              agent: "claude",
              state: "done",
              outcome: "solved",
              created_ts: NOW - 60,
            },
            {
              id: "b",
              capability: "flow.run",
              repo: "/Users/me/other",
              agent: "codex",
              state: "refused",
              outcome: "not_granted",
              created_ts: NOW - 120,
            },
            {
              id: "c",
              capability: "echo",
              repo: "/Users/me/pam",
              agent: "claude",
              state: "done",
              outcome: "solved",
              created_ts: NOW - 90_000,
            },
          ].filter((r) => !f.repo || r.repo.includes(f.repo)),
        }
      ),
    });
    const all = await ask("what ran today?", ctx, sources, off);
    expect(all.sentence).toBe("Today 2 requests ran: 1 solved, 1 refused.");
    const pam = await ask("what ran today in pam", ctx, sources, off);
    expect(pam.sentence).toBe("Today 1 request ran in pam: 1 solved.");
    expect(pam.links[0]).toMatchObject({ to: "/activity", search: { repo: "pam" } });
    // The day's count is agent work, not the GUI polling itself.
    expect(filters.every((f) => f.hide_probes === true)).toBe(true);
  });

  it("describes the loaded model or the idle default", async () => {
    const idle = await ask("which model is loaded?", ctx, fakeSources(), off);
    expect(idle.sentence).toBe("No model is loaded; no light default is set.");
    const loaded = await ask(
      "model?",
      ctx,
      fakeSources({
        modelsStatus: async () => ({
          runtime: {
            state: {
              state: "loaded",
              id: "qwen/qwen3-0.6b-q8_0",
              device: "metal",
              weight_bytes: 639e6,
              context_length: 8192,
              quant: "Q8_0",
              last_used_at: NOW - 10,
            },
            busy: false,
          },
          defaults: { light: "qwen/qwen3-0.6b-q8_0", heavy: null },
          host_ram_bytes: 64e9,
          models_dir: "/x",
        }),
      }),
      off,
    );
    expect(loaded.sentence).toBe(
      "qwen/qwen3-0.6b-q8_0 is loaded on metal: 0.6 GB of 64.0 GB RAM, context 8192.",
    );
  });

  it("points settings questions at their panel with the current value when known", async () => {
    const answer = await ask("where do I change log retention?", ctx, fakeSources(), off);
    expect(answer.sentence).toBe("Retention lives in Settings › Retention.");
    expect(answer.facts).toContainEqual(["evidence", "90 days"]);
    expect(answer.facts).toContainEqual(["audit", "forever"]);
    expect(answer.links[0]).toMatchObject({ to: "/settings", hash: "retention" });
  });

  it("reports the daemon, login start, flows, and tokens saved", async () => {
    expect((await ask("is the daemon running?", ctx, fakeSources(), off)).sentence).toBe(
      "The daemon answers: version 0.1.0, up for 1h 02m, 1 active request.",
    );
    expect((await ask("does pam start at login?", ctx, fakeSources(), off)).sentence).toBe(
      "No: PAM does not start at login.",
    );
    expect((await ask("which flows do I have?", ctx, fakeSources(), off)).sentence).toBe(
      "You have 2 flows: pr-readiness, after-merge-checks.",
    );
    const run = await ask("run pr-readiness", ctx, fakeSources(), off);
    expect(run.sentence).toBe(
      "Flows do not run from here; open pr-readiness on the Flows screen.",
    );
    expect(run.links[0]).toMatchObject({ to: "/flows", search: { flow: "pr-readiness" } });
    expect((await ask("how many tokens did I save?", ctx, fakeSources(), off)).sentence).toBe(
      "This week PAM avoided about 67,500 tokens across 3 compressions (293 KB → 29 KB).",
    );
  });

  it("points a bounded task request at the starter flow's run overview, not the flow list", async () => {
    const log = await ask("Summarize a build log", ctx, fakeSources(), off);
    expect(log.intent).toBe("start_task");
    expect(log.sentence).toMatch(/^Summarize a build log starts from its own card/);
    expect(log.links).toEqual([
      {
        label: "Open Summarize a build log",
        to: "/flows",
        search: { flow: "summarize-build-log", tab: "run" },
      },
    ]);

    const triage = await ask("triage the CI failure", ctx, fakeSources(), off);
    expect(triage.intent).toBe("start_task");
    expect(triage.sentence).toMatch(/^Triage a CI failure starts from its own card/);
    expect(triage.links).toEqual([
      {
        label: "Open Triage a CI failure",
        to: "/flows",
        search: { flow: "ci-failure-triage", tab: "run" },
      },
    ]);
  });

  it("answers honestly when nothing matches, and when the daemon is down", async () => {
    const none = await ask("tell me a joke", ctx, fakeSources(), off);
    expect(none.intent).toBe("fallback");
    expect(none.sentence).toMatch(/^Ask about PAM itself:/);
    const down = await ask(
      "is the daemon running?",
      ctx,
      fakeSources({ daemonStatus: async () => ({ connected: false, status: null }) }),
      off,
    );
    expect(down.sentence).toBe("The daemon is not answering; the next question starts it.");
  });

  it("rephrases only when enabled, one line, every fact intact; otherwise keeps the template", async () => {
    const good = fakeSources({
      modelsStatus: async () => ({
        runtime: { state: { state: "loaded", id: "m" }, busy: false },
        defaults: { light: "m", heavy: null },
        host_ram_bytes: 1,
        models_dir: "/x",
      }),
      modelsTry: async () => ({ text: "Right now nothing waits for you.", model: { id: "m" } }),
    });
    const on = await ask("approvals?", ctx, good, { rephrase: true });
    expect(on.sentence).toBe("Right now nothing waits for you.");
    expect(on.rephrased).toEqual({ model: "m" });
    const bad = fakeSources({
      modelsStatus: good.modelsStatus,
      modelsTry: async () => ({ text: "Two things\nwait", model: { id: "m" } }),
    });
    expect((await ask("approvals?", ctx, bad, { rephrase: true })).rephrased).toBeUndefined();
    const slow = fakeSources({
      modelsStatus: good.modelsStatus,
      modelsTry: () => new Promise(() => {}),
    });
    const answer = await ask("approvals?", ctx, slow, { rephrase: true, timeoutMs: 20 });
    expect(answer.sentence).toBe("Nothing waits for you.");
    expect((await ask("approvals?", ctx, good, off)).rephrased).toBeUndefined();
  });
});

describe("rephrase worker identity", () => {
  function ready(loaded = "light", busy = false): Sources["modelsStatus"] {
    return async () => ({
      runtime: { state: { state: "loaded", id: loaded }, busy },
      defaults: { light: "light", heavy: "heavy" },
      host_ram_bytes: 1,
      models_dir: "/x",
    });
  }

  it("requests the explicit light identity and never attributes a different worker", async () => {
    const generate = vi.fn(async () => ({
      text: "Right now nothing waits for you.",
      model: { id: "heavy" },
    }));
    const sources = fakeSources({ modelsStatus: ready(), modelsTry: generate });
    const answer = await ask("approvals?", ctx, sources, { rephrase: true });
    expect(generate).toHaveBeenCalledWith(
      "light",
      expect.stringContaining("Nothing waits for you."),
      96,
      8000,
    );
    expect(answer.sentence).toBe("Nothing waits for you.");
    expect(answer.rephrased).toBeUndefined();
  });

  it.each(["heavy", "idle", "busy", "disabled"])("does no inference when %s", async (state) => {
    const generate = vi.fn(async () => ({
      text: "Right now nothing waits for you.",
      model: { id: "light" },
    }));
    const status = vi.fn(ready(state === "heavy" ? "heavy" : "light", state === "busy"));
    if (state === "idle")
      status.mockImplementation(async () => ({
        ...(await ready()()),
        runtime: { state: { state: "idle" }, busy: false },
      }));
    const answer = await ask(
      "approvals?",
      ctx,
      fakeSources({ modelsStatus: status, modelsTry: generate }),
      { rephrase: state !== "disabled" },
    );
    expect(generate).not.toHaveBeenCalled();
    if (state === "disabled") expect(status).not.toHaveBeenCalled();
    expect(answer.sentence).toBe("Nothing waits for you.");
    expect(answer.rephrased).toBeUndefined();
  });

  it("sends the same short deadline that bounds local waiting", async () => {
    const generate = vi.fn(
      () => new Promise<{ text: string; model: { id: string } }>(() => {}),
    );
    const answer = await ask(
      "approvals?",
      ctx,
      fakeSources({ modelsStatus: ready(), modelsTry: generate }),
      { rephrase: true, timeoutMs: 20 },
    );
    expect(generate).toHaveBeenCalledWith("light", expect.any(String), 96, 20);
    expect(answer.sentence).toBe("Nothing waits for you.");
    expect(answer.rephrased).toBeUndefined();
  });

  it("keeps the template after a worker refusal", async () => {
    const generate = vi.fn(async () => {
      throw { cause: "model_mismatch" };
    });
    const answer = await ask(
      "approvals?",
      ctx,
      fakeSources({ modelsStatus: ready(), modelsTry: generate }),
      { rephrase: true },
    );
    expect(generate).toHaveBeenCalledTimes(1);
    expect(answer.sentence).toBe("Nothing waits for you.");
    expect(answer.rephrased).toBeUndefined();
  });
});

// --- additions beyond the plan's contract -----------------------------------

describe("matchIntent negatives", () => {
  it.each([
    ["what is the weather", "fallback"],
    ["make me a sandwich", "fallback"],
    ["hello pam", "fallback"],
  ])("%s → %s", (question, id) => {
    expect(matchIntent(question).id).toBe(id);
  });
});

describe("ask failure paths", () => {
  it("names the read it could not do instead of throwing", async () => {
    const answer = await ask(
      "what's waiting for my approval?",
      ctx,
      fakeSources({
        approvalsPending: async () => {
          throw { cause: "daemon_unreachable", detail: "no socket", recovery: "Start it." };
        },
      }),
      off,
    );
    expect(answer.sentence).toBe("PAM could not read the approval queue: no socket.");
    expect(answer.facts).toEqual([]);
  });

  it("says so when nothing has been refused lately", async () => {
    const answer = await ask("why was that refused?", ctx, fakeSources(), off);
    expect(answer.sentence).toBe("Nothing has been refused lately.");
  });

  it("asks which setting when no topic is recognisable", async () => {
    const answer = await ask("where do I change it", ctx, fakeSources(), off);
    expect(answer.sentence).toMatch(/^Name the setting: /);
    expect(answer.links[0]).toMatchObject({ to: "/settings" });
  });

  it("reports an empty day and an empty week", async () => {
    expect((await ask("what ran today?", ctx, fakeSources(), off)).sentence).toBe(
      "Nothing has run today.",
    );
    expect(
      (
        await ask(
          "how many tokens did I save?",
          ctx,
          fakeSources({
            evidenceStats: async () => ({
              compressions: 0,
              source_bytes: 0,
              compact_bytes: 0,
              tokens_avoided_est: 0,
            }),
          }),
          off,
        )
      ).sentence,
    ).toBe("Nothing has been compressed this week.");
  });

  it("confirms an installed login unit", async () => {
    const answer = await ask(
      "does pam start at login?",
      ctx,
      fakeSources({
        serviceStatus: async () => ({
          platform: "macos",
          state: { kind: "installed", unit: "com.github.ro-ag.pam.daemon", loaded: true },
        }),
      }),
      off,
    );
    expect(answer.sentence).toBe("Yes: the macos unit is installed and loaded.");
    expect(answer.facts).toContainEqual(["unit", "com.github.ro-ag.pam.daemon"]);
  });

  it("keeps the template when the rephrase drops a number", async () => {
    const sources = fakeSources({
      approvalsPending: async () => ({
        pending: [
          {
            request_id: "r1",
            capability: "repo.push",
            repo: "/Users/me/pam",
            agent: "claude",
            requested_ts: NOW - 60,
          },
        ],
      }),
      modelsStatus: async () => ({
        runtime: { state: { state: "loaded", id: "m" }, busy: false },
        defaults: { light: "m", heavy: null },
        host_ram_bytes: 1,
        models_dir: "/x",
      }),
      modelsTry: async () => ({
        text: "Someone is waiting for your hand.",
        model: { id: "m" },
      }),
    });
    const answer = await ask("approvals?", ctx, sources, { rephrase: true });
    expect(answer.sentence).toBe("1 request waits for your hand.");
    expect(answer.rephrased).toBeUndefined();
  });

  it("never rephrases the fallback", async () => {
    const answer = await ask("tell me a joke", ctx, fakeSources(), { rephrase: true });
    expect(answer.rephrased).toBeUndefined();
  });
});
