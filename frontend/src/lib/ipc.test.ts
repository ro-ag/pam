import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  BridgeUnavailable,
  activityList,
  adminCall,
  approvalsPending,
  connectorsConfigure,
  connectorsList,
  connectorsTest,
  curatorList,
  curatorSet,
  curatorTest,
  daemonStatus,
  daemonStop,
  evidenceGet,
  evidenceList,
  evidenceStats,
  flowsDelete,
  flowsGet,
  flowsList,
  flowsRun,
  flowsSave,
  flowsSettingsGet,
  flowsSettingsSet,
  grantsList,
  logCompress,
  modelsCatalog,
  modelsDefaultsSet,
  modelsDelete,
  modelsDownload,
  modelsDownloadCancel,
  modelsList,
  modelsLoad,
  modelsSettingsSet,
  modelsStatus,
  modelsTry,
  modelsUnload,
  modelsVerify,
  requestCapability,
  subscribeEvents,
  toBridgeFailure,
} from "./ipc";

/**
 * The bridge itself is mocked so the wrappers' op names and arg shapes
 * can be asserted against `pam_daemon::admin_models` — a renamed arg is
 * a silent refusal at runtime, so it is worth a test. `inShell` flips
 * the bridge on only for the block that needs it; every other test in
 * this file keeps jsdom's honest "no Tauri here".
 */
const bridge = vi.hoisted(() => ({ inShell: false, invoke: vi.fn() }));

vi.mock("@tauri-apps/api/core", () => ({
  isTauri: () => bridge.inShell,
  invoke: (command: string, args?: Record<string, unknown>) => bridge.invoke(command, args),
}));

/**
 * jsdom has no Tauri bridge, exactly like plain-browser Vite dev — every
 * wrapper must reject with the typed BridgeUnavailable failure instead of
 * throwing something the UI cannot render.
 */
describe("ipc without the app shell", () => {
  it.each([
    ["daemonStatus", () => daemonStatus()],
    ["daemonStop", () => daemonStop()],
    ["adminCall", () => adminCall("admin.profile.get")],
    ["approvalsPending", () => approvalsPending()],
    ["activityList", () => activityList()],
    ["grantsList", () => grantsList()],
    ["evidenceStats", () => evidenceStats()],
    ["requestCapability", () => requestCapability("echo", { hello: "pam" })],
    ["subscribeEvents", () => subscribeEvents(() => {})],
  ] as const)("%s rejects with BridgeUnavailable", async (_name, call) => {
    await expect(call()).rejects.toBeInstanceOf(BridgeUnavailable);
  });

  it("BridgeUnavailable carries the uniform failure shape", () => {
    const failure = new BridgeUnavailable();
    expect(failure.cause).toBe("bridge_unavailable");
    expect(failure.detail).toMatch(/outside the app shell/);
    expect(failure.recovery).toMatch(/pam -- gui/);
    // It narrows through the same helper as bridge rejections.
    expect(toBridgeFailure(failure)).toEqual({
      cause: failure.cause,
      detail: failure.detail,
      recovery: failure.recovery,
    });
  });
});

describe("toBridgeFailure", () => {
  it("passes a Rust BridgeError shape through verbatim", () => {
    const shaped = {
      cause: "unknown_admin_op",
      detail: "no such op",
      recovery: "pick a real one",
    };
    expect(toBridgeFailure(shaped)).toEqual(shaped);
  });

  it("wraps junk rejections into the same shape", () => {
    const failure = toBridgeFailure("socket exploded");
    expect(failure.cause).toBe("unknown_failure");
    expect(failure.detail).toContain("socket exploded");
    expect(failure.recovery).not.toHaveLength(0);
  });

  it("wraps partially-shaped objects instead of trusting them", () => {
    const failure = toBridgeFailure({ cause: 42, detail: "x", recovery: "y" });
    expect(failure.cause).toBe("unknown_failure");
  });
});

describe("log and evidence wrappers speak the daemon's op names and arg shapes", () => {
  beforeEach(() => {
    bridge.inShell = true;
    bridge.invoke.mockResolvedValue({});
  });

  afterEach(() => {
    bridge.inShell = false;
  });

  /** The op and args the wrapper handed the bridge on its one call. */
  function sent(): { op: string; args: Record<string, unknown> } {
    expect(bridge.invoke).toHaveBeenCalledTimes(1);
    const [command, payload] = bridge.invoke.mock.calls[0] as [
      string,
      { op: string; args: Record<string, unknown> },
    ];
    expect(command).toBe("admin_call");
    return payload;
  }

  it.each([
    [
      "logCompress",
      () => logCompress({ path: "/tmp/build.log", exit_status: 1, model: true }),
      "admin.log.compress",
      { path: "/tmp/build.log", exit_status: 1, model: true },
    ],
    [
      "logCompress (deterministic only)",
      () => logCompress({ path: "/tmp/build.log", model: false }),
      "admin.log.compress",
      { path: "/tmp/build.log", model: false },
    ],
    [
      "evidenceList",
      () => evidenceList("req_7"),
      "admin.evidence.list",
      { request_id: "req_7" },
    ],
    [
      "evidenceGet (bounded)",
      () => evidenceGet("ev_1", 10),
      "admin.evidence.get",
      { id: "ev_1", max_bytes: 10 },
    ],
    [
      "evidenceStats (window named)",
      () => evidenceStats(1_700_000_000),
      "admin.evidence.stats",
      { since_ts: 1_700_000_000 },
    ],
  ] as const)("%s", async (_name, call, op, args) => {
    await call();
    expect(sent()).toEqual({ op, args });
  });

  it("lets the daemon own both defaults when the caller names neither", async () => {
    await evidenceGet("ev_1");
    expect(sent()).toEqual({ op: "admin.evidence.get", args: { id: "ev_1" } });
    bridge.invoke.mockClear();
    await evidenceStats();
    expect(sent()).toEqual({ op: "admin.evidence.stats", args: {} });
  });
});

describe("model wrappers speak the daemon's op names and arg shapes", () => {
  beforeEach(() => {
    bridge.inShell = true;
    bridge.invoke.mockResolvedValue({});
  });

  afterEach(() => {
    bridge.inShell = false;
  });

  /** The op and args the wrapper handed the bridge on its one call. */
  function sent(): { op: string; args: Record<string, unknown> } {
    expect(bridge.invoke).toHaveBeenCalledTimes(1);
    const [command, payload] = bridge.invoke.mock.calls[0] as [
      string,
      { op: string; args: Record<string, unknown> },
    ];
    expect(command).toBe("admin_call");
    return payload;
  }

  it.each([
    ["modelsList", () => modelsList(), "admin.models.list", {}],
    ["modelsCatalog", () => modelsCatalog(), "admin.models.catalog", {}],
    ["modelsStatus", () => modelsStatus(), "admin.models.status", {}],
    ["modelsUnload", () => modelsUnload(), "admin.models.unload", {}],
    ["curatorList", () => curatorList(), "admin.curator.list", {}],
    ["curatorTest", () => curatorTest(), "admin.curator.test", {}],
    [
      "modelsLoad",
      () => modelsLoad("qwen/Qwen3-0.6B-Q8_0"),
      "admin.models.load",
      { model_id: "qwen/Qwen3-0.6B-Q8_0" },
    ],
    [
      "modelsDelete",
      () => modelsDelete("qwen/Qwen3-0.6B-Q8_0"),
      "admin.models.delete",
      { model_id: "qwen/Qwen3-0.6B-Q8_0" },
    ],
    [
      "modelsVerify",
      () => modelsVerify("qwen/Qwen3-0.6B-Q8_0"),
      "admin.models.verify",
      { model_id: "qwen/Qwen3-0.6B-Q8_0" },
    ],
    [
      "modelsDownload (preset)",
      () => modelsDownload({ preset_id: "qwen3-coder-30b-a3b-q4_k_m" }),
      "admin.models.download",
      { preset_id: "qwen3-coder-30b-a3b-q4_k_m" },
    ],
    [
      "modelsDownload (pasted url)",
      () => modelsDownload({ url: "https://example.test/m.gguf", vendor: "qwen" }),
      "admin.models.download",
      { url: "https://example.test/m.gguf", vendor: "qwen" },
    ],
    [
      "modelsDownloadCancel",
      () => modelsDownloadCancel("job_01"),
      "admin.models.download.cancel",
      { job_id: "job_01" },
    ],
    [
      "modelsDefaultsSet",
      () => modelsDefaultsSet("heavy", "qwen/big"),
      "admin.models.defaults.set",
      { tier: "heavy", model_id: "qwen/big" },
    ],
    [
      "modelsDefaultsSet (cleared)",
      () => modelsDefaultsSet("light", null),
      "admin.models.defaults.set",
      { tier: "light", model_id: null },
    ],
    [
      "modelsSettingsSet",
      () => modelsSettingsSet({ models_dir: "/Users/dev/llm", idle_unload_min: 20 }),
      "admin.models.settings.set",
      { models_dir: "/Users/dev/llm", idle_unload_min: 20 },
    ],
    [
      "modelsTry",
      () => modelsTry("Say hello.", 64),
      "admin.models.try",
      { prompt: "Say hello.", max_tokens: 64 },
    ],
    ["curatorSet", () => curatorSet("codex"), "admin.curator.set", { agent: "codex" }],
    ["curatorSet (cleared)", () => curatorSet(null), "admin.curator.set", { agent: null }],
  ] as const)("%s", async (_name, call, op, args) => {
    await call();
    expect(sent()).toEqual({ op, args });
  });

  it("omits max_tokens entirely when the caller names no budget", async () => {
    await modelsTry("Say hello.");
    expect(sent().args).toEqual({ prompt: "Say hello." });
  });
});

describe("flow and connector wrappers speak the daemon's op names and arg shapes", () => {
  beforeEach(() => {
    bridge.inShell = true;
    bridge.invoke.mockResolvedValue({});
  });

  afterEach(() => {
    bridge.inShell = false;
  });

  /** The op and args the wrapper handed the bridge on its one call. */
  function sent(): { op: string; args: Record<string, unknown> } {
    expect(bridge.invoke).toHaveBeenCalledTimes(1);
    const [command, payload] = bridge.invoke.mock.calls[0] as [
      string,
      { op: string; args: Record<string, unknown> },
    ];
    expect(command).toBe("admin_call");
    return payload;
  }

  it.each([
    ["flowsList", () => flowsList(), "admin.flows.list", {}],
    ["flowsGet", () => flowsGet("pr-readiness"), "admin.flows.get", { id: "pr-readiness" }],
    [
      "flowsSave",
      () => flowsSave("mine", "id: mine\n"),
      "admin.flows.save",
      { id: "mine", yaml: "id: mine\n" },
    ],
    ["flowsDelete", () => flowsDelete("mine"), "admin.flows.delete", { id: "mine" }],
    [
      "flowsRun",
      () => flowsRun("pr-readiness", "/work/pam", { base: "main" }),
      "admin.flows.run",
      { id: "pr-readiness", repo: "/work/pam", inputs: { base: "main" } },
    ],
    [
      "flowsRun (nothing declared)",
      () => flowsRun("pr-readiness", "/work/pam"),
      "admin.flows.run",
      { id: "pr-readiness", repo: "/work/pam", inputs: {} },
    ],
    ["flowsSettingsGet", () => flowsSettingsGet(), "admin.flows.settings.get", {}],
    [
      "flowsSettingsSet (one list at a time)",
      () => flowsSettingsSet({ allowed_programs: ["git", "cargo"] }),
      "admin.flows.settings.set",
      { allowed_programs: ["git", "cargo"] },
    ],
    ["connectorsList", () => connectorsList(), "admin.connectors.list", {}],
    [
      "connectorsConfigure (enable + base url)",
      () => connectorsConfigure("jenkins", { enabled: true, base_url: "https://ci.test" }),
      "admin.connectors.configure",
      { id: "jenkins", enabled: true, base_url: "https://ci.test" },
    ],
    [
      "connectorsConfigure (set credential)",
      () => connectorsConfigure("github", { credential: { set: "ghp_x" } }),
      "admin.connectors.configure",
      { id: "github", credential: { set: "ghp_x" } },
    ],
    [
      "connectorsConfigure (clear credential)",
      () => connectorsConfigure("github", { credential: { clear: true } }),
      "admin.connectors.configure",
      { id: "github", credential: { clear: true } },
    ],
    [
      "connectorsConfigure (clear a text field)",
      () => connectorsConfigure("jira", { username: null }),
      "admin.connectors.configure",
      { id: "jira", username: null },
    ],
    [
      "connectorsTest",
      () => connectorsTest("github"),
      "admin.connectors.test",
      { id: "github" },
    ],
  ] as const)("%s", async (_name, call, op, args) => {
    await call();
    expect(sent()).toEqual({ op, args });
  });

  it("narrows the tide to one capability for the run history", async () => {
    await activityList({ capability: "flow.run", limit: 50 });
    expect(sent()).toEqual({
      op: "admin.activity.list",
      args: { capability: "flow.run", limit: 50 },
    });
  });

  it("sends an untouched connector field as an absent key, not an empty string", async () => {
    await connectorsConfigure("github", { enabled: false });
    expect(sent().args).toEqual({ id: "github", enabled: false });
  });
});
