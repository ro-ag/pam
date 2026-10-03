import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  BRIDGE_TIMEOUT_MS,
  BridgeUnavailable,
  HARNESS_PROFILES,
  boundaryStatus,
  harnessProfileFor,
  CONFIRM_GRANT,
  CONFIRM_NETWORK,
  CONFIRM_RELAXED,
  STATUS_TIMEOUT_MS,
  approvalsResolve,
  grantsAdd,
  profileSet,
  FLOW_CONNECTORS,
  FLOW_CONNECTOR_CALLS,
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
  engineInstall,
  engineImport,
  engineRemove,
  engineStatus,
  evidenceGet,
  evidenceList,
  evidenceStats,
  flowsDelete,
  flowsGet,
  flowsList,
  flowsNormalize,
  flowsRun,
  flowsSave,
  flowsSettingsGet,
  flowsSettingsSet,
  grantsList,
  logCompress,
  networkGet,
  networkSet,
  networkTest,
  modelsCatalog,
  modelsDefaultsSet,
  modelsDelete,
  modelsDownload,
  modelsImport,
  modelsDownloadCancel,
  modelsList,
  modelsLoad,
  modelsSettingsSet,
  modelsStatus,
  modelsTry,
  modelsUnload,
  modelsVerify,
  revokedStepCount,
  snapshotDigest,
  type PendingApproval,
  subscribeEvents,
  toBridgeFailure,
  versionMismatchNote,
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

/**
 * An `invoke` cannot be aborted, so a bridge call that never answers would hold its caller (and
 * the daemon-side permit behind it) forever. Every wrapper therefore rejects with the uniform
 * `reply_timeout` failure once its bound passes.
 */
describe("bridge calls have a client-side timeout", () => {
  beforeEach(() => {
    bridge.inShell = true;
    vi.useFakeTimers();
  });

  afterEach(() => {
    bridge.inShell = false;
    vi.useRealTimers();
  });

  it("gives up on a status poll the bridge never answers", async () => {
    bridge.invoke.mockImplementation(() => new Promise(() => {}));
    const outcome = daemonStatus().then(
      () => "answered",
      (error: unknown) => toBridgeFailure(error).cause,
    );
    await vi.advanceTimersByTimeAsync(STATUS_TIMEOUT_MS - 1);
    await vi.advanceTimersByTimeAsync(2);
    expect(await outcome).toBe("reply_timeout");
  });

  it("gives an admin read the ordinary bound, and a model run far longer", async () => {
    bridge.invoke.mockImplementation(() => new Promise(() => {}));
    let listed = "pending";
    void approvalsPending().catch(() => {
      listed = "timed out";
    });
    let tried = "pending";
    void modelsTry("m", "hi").catch(() => {
      tried = "timed out";
    });
    await vi.advanceTimersByTimeAsync(BRIDGE_TIMEOUT_MS + 1);
    expect(listed).toBe("timed out");
    expect(tried).toBe("pending");
    await vi.advanceTimersByTimeAsync(110_000);
    expect(tried).toBe("timed out");
  });

  it("does not time out an answer that arrives in time", async () => {
    bridge.invoke.mockResolvedValue({ connected: true, status: {} });
    await expect(daemonStatus()).resolves.toEqual({ connected: true, status: {} });
    await vi.advanceTimersByTimeAsync(BRIDGE_TIMEOUT_MS * 4);
  });
});

describe("authority-expanding wrappers pass the typed confirmation to the bridge", () => {
  beforeEach(() => {
    bridge.inShell = true;
    bridge.invoke.mockResolvedValue({});
  });

  afterEach(() => {
    bridge.inShell = false;
  });

  it("sends the phrase beside the op, not inside its args", async () => {
    await profileSet("relaxed", CONFIRM_RELAXED);
    expect(bridge.invoke).toHaveBeenLastCalledWith("admin_call", {
      op: "admin.profile.set",
      args: { profile: "relaxed" },
      confirmation: "relaxed",
    });
    await grantsAdd("fs.write", CONFIRM_GRANT);
    expect(bridge.invoke).toHaveBeenLastCalledWith("admin_call", {
      op: "admin.grants.add",
      args: { capability: "fs.write" },
      confirmation: "grant",
    });
    await approvalsResolve("req_1", "approved", {
      remember: true,
      note: "ok",
      confirmation: CONFIRM_GRANT,
    });
    expect(bridge.invoke).toHaveBeenLastCalledWith("admin_call", {
      op: "admin.approvals.resolve",
      args: { request_id: "req_1", resolution: "approved", remember: true, note: "ok" },
      confirmation: "grant",
    });
  });

  it("sends the network phrase beside the op, and the password only inside the patch", async () => {
    await networkSet(
      {
        proxy: { url: "http://proxy.corp.example:3128", auth: "basic", username: "svc" },
        credential: { set: "hunter2" },
      },
      CONFIRM_NETWORK,
    );
    expect(bridge.invoke).toHaveBeenLastCalledWith("admin_call", {
      op: "admin.network.set",
      args: {
        proxy: { url: "http://proxy.corp.example:3128", auth: "basic", username: "svc" },
        credential: { set: "hunter2" },
      },
      confirmation: "network",
    });
    await networkSet({ ca_bundle: null });
    expect(bridge.invoke).toHaveBeenLastCalledWith("admin_call", {
      op: "admin.network.set",
      args: { ca_bundle: null },
      confirmation: undefined,
    });
  });

  it("pins an approval to the flow digest the card showed, only when it has one", async () => {
    await approvalsResolve("req_1", "approved", { expectedDigest: "ab".repeat(32) });
    expect(bridge.invoke).toHaveBeenLastCalledWith("admin_call", {
      op: "admin.approvals.resolve",
      args: { request_id: "req_1", resolution: "approved", expected_digest: "ab".repeat(32) },
      confirmation: undefined,
    });
    await approvalsResolve("req_1", "denied");
    const calls = bridge.invoke.mock.calls;
    const [, payload] = calls[calls.length - 1] as [string, { args: object }];
    expect(payload.args).not.toHaveProperty("expected_digest");
  });

  it("reads the digest from either name the daemon snapshot may use", () => {
    const base = { request_id: "r" } as PendingApproval;
    const resolved = { program: "git", argv: [] };
    expect(snapshotDigest({ ...base, resolved: { ...resolved, digest: "d1" } })).toBe("d1");
    expect(snapshotDigest({ ...base, resolved: { ...resolved, flow_digest: "d2" } })).toBe(
      "d2",
    );
    expect(snapshotDigest({ ...base, resolved })).toBeNull();
    expect(snapshotDigest({ ...base, resolved: null })).toBeNull();
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

describe("versionMismatchNote", () => {
  const refusal = {
    cause: "client_version_mismatch",
    detail:
      "client version 0.4.3 does not match daemon version 0.5.0 running from /opt/pam/bin/pam; " +
      "that binary has not changed on disk, so the daemon keeps running",
    recovery: "Use the pam binary this daemon was started from.",
  };

  it("lifts the daemon's version and path out of the refusal and keeps its recovery line", () => {
    expect(versionMismatchNote(refusal)).toEqual({
      cause: "client_version_mismatch",
      detail:
        "This window is not the build the running daemon was started from; the daemon is " +
        "version 0.5.0, running from /opt/pam/bin/pam",
      recovery: "Use the pam binary this daemon was started from.",
    });
  });

  it("keeps a path with spaces and still reads a refusal whose detail it cannot parse", () => {
    const spaced = versionMismatchNote({
      ...refusal,
      detail: refusal.detail.replace("/opt/pam/bin/pam", "/Users/Jo Doe/My Apps/pam"),
    });
    expect(spaced?.detail).toContain("running from /Users/Jo Doe/My Apps/pam");

    const opaque = versionMismatchNote({ ...refusal, detail: "different builds" });
    expect(opaque?.detail).toBe(
      "This window is not the build the running daemon was started from",
    );
    expect(opaque?.recovery).toBe(refusal.recovery);
  });

  it("is only for client_version_mismatch", () => {
    for (const cause of [
      "daemon_outdated",
      "client_outdated",
      "reply_timeout",
      "unknown_failure",
    ]) {
      expect(versionMismatchNote({ ...refusal, cause })).toBeNull();
    }
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
    ["engineStatus", () => engineStatus(), "admin.models.engine.status", {}],
    ["engineInstall", () => engineInstall(), "admin.models.engine.install", { confirm: true }],
    [
      "engineImport",
      () => engineImport("/opt/pam/llama.tar.gz"),
      "admin.models.engine.import",
      { path: "/opt/pam/llama.tar.gz", confirm: true },
    ],
    ["engineRemove", () => engineRemove(), "admin.models.engine.remove", { confirm: true }],
    [
      "modelsImport (path only)",
      () => modelsImport({ path: "/srv/m.gguf" }),
      "admin.models.import",
      { path: "/srv/m.gguf", confirm: true },
    ],
    [
      "modelsImport (vendor and digest)",
      () =>
        modelsImport({ path: "/srv/x.gguf", vendor: "qwen", expected_sha256: "ab".repeat(32) }),
      "admin.models.import",
      { path: "/srv/x.gguf", vendor: "qwen", expected_sha256: "ab".repeat(32), confirm: true },
    ],
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
      () => modelsTry("fixture-model", "Say hello.", 64),
      "admin.models.try",
      { model_id: "fixture-model", prompt: "Say hello.", max_tokens: 64 },
    ],
    ["curatorSet", () => curatorSet("codex"), "admin.curator.set", { agent: "codex" }],
    ["curatorSet (cleared)", () => curatorSet(null), "admin.curator.set", { agent: null }],
  ] as const)("%s", async (_name, call, op, args) => {
    await call();
    expect(sent()).toEqual({ op, args });
  });

  it("sends an explicit generation deadline when supplied", async () => {
    await modelsTry("fixture-model", "Say hello.", 96, 8000);
    expect(sent().args).toEqual({
      model_id: "fixture-model",
      prompt: "Say hello.",
      max_tokens: 96,
      timeout_ms: 8000,
    });
  });

  it("omits max_tokens entirely when the caller names no budget", async () => {
    await modelsTry("fixture-model", "Say hello.");
    expect(sent().args).toEqual({ model_id: "fixture-model", prompt: "Say hello." });
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
      "flowsRun (pinned to the shown digest)",
      () => flowsRun("pr-readiness", "/work/pam", {}, "cd".repeat(32)),
      "admin.flows.run",
      { id: "pr-readiness", repo: "/work/pam", inputs: {}, expected_digest: "cd".repeat(32) },
    ],
    [
      "cancel (private channel)",
      () => adminCall("admin.requests.cancel", { ticket: "req_run" }),
      "admin.requests.cancel",
      { ticket: "req_run" },
    ],
    [
      "flowsRun (nothing declared)",
      () => flowsRun("pr-readiness", "/work/pam"),
      "admin.flows.run",
      { id: "pr-readiness", repo: "/work/pam", inputs: {} },
    ],
    [
      "flowsNormalize (yaml)",
      () => flowsNormalize({ yaml: "schema: 1\n" }),
      "admin.flows.normalize",
      { yaml: "schema: 1\n" },
    ],
    [
      "flowsNormalize (flow)",
      () =>
        flowsNormalize({
          flow: { schema: 1, id: "mine", name: "Mine", steps: [{ id: "a", run: ["git"] }] },
        }),
      "admin.flows.normalize",
      { flow: { schema: 1, id: "mine", name: "Mine", steps: [{ id: "a", run: ["git"] }] } },
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
    ["networkGet", () => networkGet(), "admin.network.get", {}],
    [
      "networkSet (a patch: absent keeps, null clears)",
      () => networkSet({ proxy: null, no_proxy: ["corp.example"], engine_mirror: null }),
      "admin.network.set",
      { proxy: null, no_proxy: ["corp.example"], engine_mirror: null },
    ],
    [
      "networkTest (one connector)",
      () => networkTest("jenkins"),
      "admin.network.test",
      { target: "jenkins" },
    ],
    ["networkTest (everything configured)", () => networkTest(), "admin.network.test", {}],
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

  it("mirrors pam_flow::connector_calls for every connector, required args first", () => {
    expect(Object.keys(FLOW_CONNECTOR_CALLS).sort()).toEqual([...FLOW_CONNECTORS].sort());
    for (const calls of Object.values(FLOW_CONNECTOR_CALLS)) {
      expect(calls.length).toBeGreaterThan(0);
    }
    expect(FLOW_CONNECTOR_CALLS.github.map((call) => call.name)).toEqual([
      "runs",
      "run",
      "job_log",
    ]);
    expect(FLOW_CONNECTOR_CALLS.jenkins.find((call) => call.name === "investigate")).toEqual({
      name: "investigate",
      args: [
        { name: "job", required: true },
        { name: "build", required: true },
      ],
    });
    expect(FLOW_CONNECTORS).not.toContain("aws");
    expect(FLOW_CONNECTOR_CALLS).not.toHaveProperty("aws");
    expect(FLOW_CONNECTOR_CALLS.sharepoint[0].args.map((arg) => arg.name)).toEqual([
      "site",
      "query",
      "limit",
    ]);
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

  it("counts the steps a save or delete took the remembered approval from", () => {
    expect(revokedStepCount({})).toBeNull();
    expect(revokedStepCount(undefined)).toBeNull();
    expect(revokedStepCount({ grants_revoked: [] })).toBeNull();
    expect(
      revokedStepCount({ grants_revoked: ["flow.step:a/build", "flow.step:a/push"] }),
    ).toBe(2);
    // The daemon said approval is needed again without listing which steps.
    expect(revokedStepCount({ reapproval_required: true })).toBe(1);
  });
});

describe("boundaryStatus", () => {
  it("is null without a block, and never invents a report from a bad verdict", () => {
    expect(boundaryStatus(null)).toBeNull();
    expect(boundaryStatus({})).toBeNull();
    expect(boundaryStatus({ boundary: "yes" })).toBeNull();
    const odd = boundaryStatus({ boundary: { last_report: { verdict: "fine" } } });
    expect(odd?.last_report).toBeNull();
    expect(odd?.summary).toBe("never checked — run pam doctor from the agent");
    expect(odd?.admin_contacts.unattributed_24h).toBe(0);
    expect(odd?.peer_identity).toBe("none");
  });

  it("reads the block as the daemon serves it", () => {
    const block = boundaryStatus({
      boundary: {
        peer_identity: "kernel_pid",
        last_report: {
          verdict: "not_established",
          ts: 10,
          received_ts: 11,
          age_s: 420,
          agent: "claude",
          repo: "/work/app",
          relayed: false,
          peer_pid: 48122,
          peer_exe: "/Applications/PAM.app/Contents/MacOS/pam",
          peer_harness: "claude",
          failed: ["admin.dir", 7],
          unverified: [],
          request_id: "req_abc",
        },
        reports: { retained: 7, established: 5, not_established: 2 },
        admin_contacts: {
          unattributed: 1,
          unattributed_24h: 1,
          total: 3,
          expected_total: 120,
          last: {
            ts: 5,
            kind: "admin_contact",
            peer_pid: 4711,
            peer_exe: "/usr/local/bin/pam",
            peer_harness: "zsh",
            attributed: null,
          },
          last_expected: null,
        },
        public_unknown_harness: { total: 1, last: { ts: 4, peer_pid: 5, peer_exe: null } },
        summary: "not_established 7 min ago by claude (pid 48122, direct); admin contacts unattributed: 1",
      },
    });
    expect(block).not.toBeNull();
    expect(block?.peer_identity).toBe("kernel_pid");
    expect(block?.last_report?.verdict).toBe("not_established");
    expect(block?.last_report?.failed).toEqual(["admin.dir"]);
    expect(block?.last_report?.request_id).toBe("req_abc");
    expect(block?.reports).toEqual({ retained: 7, established: 5, not_established: 2 });
    expect(block?.admin_contacts.last?.peer_exe).toBe("/usr/local/bin/pam");
    expect(block?.admin_contacts.last?.attributed).toBeNull();
    expect(block?.admin_contacts.last_expected).toBeNull();
    expect(block?.public_unknown_harness.last?.peer_pid).toBe(5);
    expect(block?.summary).toMatch(/^not_established 7 min ago/);
  });

  it("maps a report's agent to the profile the CLI takes, falling back to sandbox-exec", () => {
    expect(harnessProfileFor("claude")).toBe("claude-code");
    expect(harnessProfileFor("Codex")).toBe("codex");
    expect(harnessProfileFor("gemini")).toBe("gemini-cli");
    expect(harnessProfileFor("copilot")).toBe("copilot-cli");
    expect(harnessProfileFor("github-copilot")).toBe("copilot-cli");
    expect(harnessProfileFor("cursor")).toBe("sandbox-exec");
    expect(harnessProfileFor(null)).toBe("sandbox-exec");
    expect(harnessProfileFor(undefined)).toBe("sandbox-exec");
    for (const name of HARNESS_PROFILES) expect(harnessProfileFor(name)).toBe(name);
  });
});
