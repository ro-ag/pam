import { createMemoryHistory } from "@tanstack/react-router";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import App from "../App";
import type { GrantRow, PolicyBody } from "../lib/ipc";
import {
  applyTheme,
  applyMaterial,
  materialStorageKey,
  applyBackgroundMotion,
  backgroundMotionStorageKey,
  applyBackgroundSpeed,
  backgroundSpeedStorageKey,
  applyBackgroundIntensity,
  backgroundIntensityStorageKey,
  applyGlassOpacity,
  glassOpacityStorageKey,
} from "../lib/theme";
import { createAppRouter } from "../router";
import {
  AUDIT_CHOICES,
  EVIDENCE_CHOICES,
  KNOWN_CAPABILITIES,
  LOG_LINE_CHOICES,
  PROFILE_SENTENCES,
  GRANT_BLOCKED_NOTE,
  GRANT_MANUAL_BLOCKED_NOTE,
  boundaryVerdictLine,
  logTone,
  profileBlocker,
} from "./Settings";

/**
 * The Settings screen against a mocked bridge: profile round-trip with
 * the applies-next-start note, the grants table's two-tap revoke and add
 * flow, the theme selector, the retention windows and prune button, the
 * log viewer, and the daemon card. The whole App mounts (shell included)
 * so the query provider and the screen run exactly as shipped.
 */

const mocks = vi.hoisted(() => ({
  activityList: vi.fn(),
  callersList: vi.fn(),
  subscribeEvents: vi.fn(),
  daemonStatus: vi.fn(),
  daemonStop: vi.fn(),
  approvalsPending: vi.fn(),
  profileGet: vi.fn(),
  profileSet: vi.fn(),
  grantsList: vi.fn(),
  grantsAdd: vi.fn(),
  grantsRevoke: vi.fn(),
  readDaemonLog: vi.fn(),
  // The Models section mounts between Security and Daemon; its three
  // reads are stubbed so this file keeps asserting Settings' own copy
  // instead of three bridge-unavailable notes from a neighbour section.
  modelsStatus: vi.fn(),
  modelsList: vi.fn(),
  curatorList: vi.fn(),
  // Same for the Flows and Connectors sections between Models and
  // Daemon: stubbed so their honest bridge-unavailable notes do not
  // drown out the copy this file is here to assert.
  flowsSettingsGet: vi.fn(),
  connectorsList: vi.fn(),
  // The Network section mounts between Connectors and Daemon.
  networkGet: vi.fn(),
  retentionGet: vi.fn(),
  retentionSet: vi.fn(),
  retentionPrune: vi.fn(),
  serviceStatus: vi.fn(),
  serviceInstall: vi.fn(),
  serviceUninstall: vi.fn(),
  // The Security tab mounts the managed-policy panel; the header reads it on every tab.
  policyGet: vi.fn(),
  policyReload: vi.fn(),
}));

vi.mock("../lib/ipc", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../lib/ipc")>();
  return { ...actual, ...mocks };
});

const nowSec = Math.floor(Date.now() / 1000);

function grant(overrides: Partial<GrantRow>): GrantRow {
  return {
    id: 1,
    capability: "echo",
    scope: "global",
    granted_ts: nowSec - 3_600,
    revoked_ts: null,
    ...overrides,
  };
}

/** What `admin.policy.get` answers on a machine with no managed policy. */
function unmanagedPolicy(overrides: Partial<PolicyBody> = {}): PolicyBody {
  return {
    state: "none",
    reason_code: null,
    reason_detail: null,
    origin: { path: null, platform: "macos", trust: { verdict: "absent", code: null, recovery: null } },
    digest: null,
    file_digest: null,
    revision: null,
    organization: null,
    contact: null,
    loaded_ts: null,
    checked_ts: null,
    last_good: null,
    rejected_leaves: 0,
    keys: [],
    diagnostics: [],
    compliance: { login_unit: { required: false, present: null } },
    ...overrides,
  };
}

beforeEach(() => {
  // Deterministic theme regardless of what an earlier test applied.
  applyTheme("ventisquero", "dark", { persist: false });
  applyMaterial("glass", { persist: false });
  applyBackgroundMotion("slow");
  applyBackgroundSpeed(1);
  applyBackgroundIntensity(70);
  applyGlassOpacity(84);

  mocks.subscribeEvents.mockResolvedValue(() => {});
  mocks.daemonStatus.mockResolvedValue({
    connected: true,
    status: { daemon_version: "0.10.1", protocol: 1, uptime_s: 3_723, active_requests: 2 },
    base_dir: "/Users/me/.pam",
  });
  mocks.daemonStop.mockResolvedValue({ outcome: "stopped", pid: 42 });
  mocks.serviceStatus.mockResolvedValue({
    platform: "macos",
    exe: "/Applications/pam.app/Contents/MacOS/pam",
    state: {
      kind: "not_installed",
      unit: "/Users/me/Library/LaunchAgents/com.github.ro-ag.pam.daemon.plist",
    },
    note: null,
  });
  mocks.serviceInstall.mockResolvedValue({
    platform: "macos",
    exe: "/Applications/pam.app/Contents/MacOS/pam",
    state: {
      kind: "installed",
      unit: "/Users/me/Library/LaunchAgents/com.github.ro-ag.pam.daemon.plist",
      loaded: true,
    },
    note: "stopped the running daemon (pid 7) so the managed one takes over",
  });
  mocks.serviceUninstall.mockResolvedValue({
    platform: "macos",
    exe: "/Applications/pam.app/Contents/MacOS/pam",
    state: {
      kind: "not_installed",
      unit: "/Users/me/Library/LaunchAgents/com.github.ro-ag.pam.daemon.plist",
    },
    note: "the manager stopped the managed daemon along with its unit; the next pam command starts one lazily",
  });
  mocks.policyGet.mockResolvedValue(unmanagedPolicy());
  mocks.policyReload.mockResolvedValue(unmanagedPolicy());
  mocks.approvalsPending.mockResolvedValue({ pending: [] });
  mocks.activityList.mockResolvedValue({ requests: [] });
  mocks.callersList.mockResolvedValue({ callers: [] });
  mocks.profileGet.mockResolvedValue({ profile: "standard" });
  mocks.profileSet.mockResolvedValue({ profile: "strict", applies: "now" });
  mocks.grantsList.mockResolvedValue({
    grants: [
      grant({ id: 1, capability: "echo" }),
      grant({ id: 2, capability: "status", revoked_ts: nowSec - 60 }),
    ],
  });
  mocks.grantsAdd.mockResolvedValue({ capability: "query", granted: true });
  mocks.grantsRevoke.mockResolvedValue({ capability: "echo", revoked: true });
  mocks.readDaemonLog.mockResolvedValue({
    file: "/Users/dev/.pam/log/daemon.log.2026-09-01",
    lines: ["INFO daemon listening", "WARN queue is deep", "ERROR store unreachable"],
  });
  mocks.modelsStatus.mockResolvedValue({
    runtime: { state: { state: "idle" }, busy: false },
    jobs: [],
    defaults: { light: null, heavy: null },
    idle_unload_min: 10,
    models_dir: "/Users/dev/llm",
    host_ram_bytes: 64_000_000_000,
  });
  mocks.modelsList.mockResolvedValue({ models: [], models_dir: "/Users/dev/llm" });
  mocks.curatorList.mockResolvedValue({ detected: [], selected: null });
  mocks.flowsSettingsGet.mockResolvedValue({ allowed_programs: ["git"], extra_path: [] });
  mocks.connectorsList.mockResolvedValue({ connectors: [] });
  mocks.networkGet.mockResolvedValue({
    settings: {
      proxy: null,
      no_proxy: [],
      ca_bundle: null,
      engine_mirror: null,
      models_mirror: null,
      credential: { present: false, store_available: true },
    },
  });
  mocks.retentionGet.mockResolvedValue({
    evidence_days: 90,
    audit_days: 365,
    last_run: {
      ts: nowSec - 720,
      evidence_rows: 41,
      evidence_bytes: 2_100_000,
      requests: 3,
      audit_rows: 5,
    },
  });
  mocks.retentionSet.mockImplementation(async (patch) => ({
    evidence_days: 90,
    audit_days: 365,
    last_run: null,
    ...patch,
  }));
  mocks.retentionPrune.mockResolvedValue({
    ts: nowSec,
    evidence_rows: 2,
    evidence_bytes: 512,
    requests: 0,
    audit_rows: 0,
  });
});

afterEach(() => {
  vi.clearAllMocks();
  window.localStorage.clear();
  delete document.documentElement.dataset.theme;
  delete document.documentElement.dataset.mode;
  delete document.documentElement.dataset.backgroundMotion;
  delete document.documentElement.dataset.backgroundSpeed;
  delete document.documentElement.dataset.backgroundIntensity;
  delete document.documentElement.dataset.glassOpacity;
  document.documentElement.style.removeProperty("--glass-opacity");
  document.documentElement.style.removeProperty("--background-intensity");
  document.documentElement.style.removeProperty("--background-drift-duration");
});

function renderSettings(hash = "") {
  const router = createAppRouter(
    createMemoryHistory({ initialEntries: [`/settings${hash ? `#${hash}` : ""}`] }),
  );
  render(<App router={router} />);
  return router;
}

const categoryNames = [
  "Appearance",
  "Security",
  "Models",
  "Flows",
  "Connectors",
  "Network",
  "Daemon",
  "Retention",
  "Logs",
] as const;

function expectActiveCategory(name: (typeof categoryNames)[number]) {
  const tabs = within(screen.getByRole("tablist", { name: "Settings categories" }));
  expect(tabs.getAllByRole("tab", { selected: true })).toHaveLength(1);
  expect(tabs.getByRole("tab", { name })).toHaveAttribute("aria-selected", "true");
  expect(screen.getAllByRole("tabpanel")).toHaveLength(1);
  expect(screen.getByRole("tabpanel", { name })).toHaveAttribute("id", name.toLowerCase());
}

describe("settings navigation", () => {
  it("defaults to Appearance and exposes one labeled category panel", async () => {
    renderSettings();
    const categories = await screen.findByRole("tablist", { name: "Settings categories" });
    expect(
      within(categories)
        .getAllByRole("tab")
        .map((tab) => tab.textContent),
    ).toEqual(categoryNames);
    expectActiveCategory("Appearance");
    expect(screen.getAllByRole("tabpanel", { hidden: true })).toHaveLength(9);
    for (const name of categoryNames) {
      const id = name.toLowerCase();
      const tab = within(categories).getByRole("tab", { name });
      const panel = document.getElementById(id);
      expect(tab).toHaveAttribute("id", `settings-tab-${id}`);
      expect(tab).toHaveAttribute("aria-controls", id);
      expect(panel).toHaveAttribute("aria-labelledby", `settings-tab-${id}`);
      if (name === "Appearance") {
        expect(panel).not.toHaveAttribute("hidden");
      } else {
        expect(panel).toHaveAttribute("hidden");
      }
    }
  });

  it.each(categoryNames)("opens the %s hash directly", async (name) => {
    renderSettings(name.toLowerCase());
    await screen.findByRole("tabpanel", { name });
    expectActiveCategory(name);
  });

  it("changes the hash and exposes only the selected panel when switching", async () => {
    const router = renderSettings();
    await screen.findByRole("tablist", { name: "Settings categories" });
    for (const name of categoryNames.slice(1)) {
      fireEvent.click(screen.getByRole("tab", { name }));
      await waitFor(() => expect(router.state.location.hash).toBe(name.toLowerCase()));
      expectActiveCategory(name);
    }
  });

  it("follows back and forward navigation between category hashes", async () => {
    const router = renderSettings("security");
    await screen.findByRole("tabpanel", { name: "Security" });
    fireEvent.click(screen.getByRole("tab", { name: "Models" }));
    await waitFor(() => expectActiveCategory("Models"));
    fireEvent.click(screen.getByRole("tab", { name: "Retention" }));
    await waitFor(() => expectActiveCategory("Retention"));
    router.history.back();
    await waitFor(() => expectActiveCategory("Models"));
    expect(router.state.location.hash).toBe("models");
    router.history.back();
    await waitFor(() => expectActiveCategory("Security"));
    expect(router.state.location.hash).toBe("security");
    router.history.forward();
    await waitFor(() => expectActiveCategory("Models"));
    expect(router.state.location.hash).toBe("models");
  });

  it("falls back to Appearance for an unknown hash", async () => {
    renderSettings("missing-category");
    await screen.findByRole("tabpanel", { name: "Appearance" });
    expectActiveCategory("Appearance");
  });

  it("wraps arrow navigation and activates Home and End targets with focus", async () => {
    const router = renderSettings();
    const appearance = await screen.findByRole("tab", { name: "Appearance" });
    appearance.focus();
    for (const [key, name] of [
      ["ArrowLeft", "Logs"],
      ["ArrowRight", "Appearance"],
      ["ArrowRight", "Security"],
      ["End", "Logs"],
      ["Home", "Appearance"],
    ] as const) {
      fireEvent.keyDown(document.activeElement!, { key });
      await waitFor(() => expectActiveCategory(name));
      expect(screen.getByRole("tab", { name })).toHaveFocus();
      expect(router.state.location.hash).toBe(name.toLowerCase());
    }
  });

  it("keeps only the selected tab and active panel in the sequential tab order", async () => {
    renderSettings("security");
    await screen.findByRole("tabpanel", { name: "Security" });
    for (const name of categoryNames) {
      expect(screen.getByRole("tab", { name })).toHaveAttribute(
        "tabindex",
        name === "Security" ? "0" : "-1",
      );
    }
    expect(screen.getByRole("tabpanel", { name: "Security" })).toHaveAttribute("tabindex", "0");
  });

  it("preserves a Models directory draft across category switches", async () => {
    renderSettings("models");
    const field = await screen.findByRole("textbox", { name: "models directory" });
    await waitFor(() => expect(field).toHaveValue("/Users/dev/llm"));
    fireEvent.change(field, { target: { value: "/tmp/unsaved-models" } });
    fireEvent.click(screen.getByRole("tab", { name: "Retention" }));
    await waitFor(() => expectActiveCategory("Retention"));
    expect(screen.queryByRole("textbox", { name: "models directory" })).toBeNull();
    fireEvent.click(screen.getByRole("tab", { name: "Models" }));
    expect(await screen.findByRole("textbox", { name: "models directory" })).toHaveValue(
      "/tmp/unsaved-models",
    );
  });

  it("does not mount or fetch unvisited categories", async () => {
    renderSettings();
    await screen.findByRole("tabpanel", { name: "Appearance" });
    const categoryReads = [
      mocks.profileGet,
      mocks.grantsList,
      mocks.modelsStatus,
      mocks.modelsList,
      mocks.curatorList,
      mocks.flowsSettingsGet,
      mocks.connectorsList,
      mocks.networkGet,
      mocks.serviceStatus,
      mocks.retentionGet,
      mocks.readDaemonLog,
    ];
    for (const read of categoryReads) expect(read).not.toHaveBeenCalled();
    for (const name of categoryNames.slice(1)) {
      expect(document.getElementById(name.toLowerCase())).toBeEmptyDOMElement();
    }
    fireEvent.click(screen.getByRole("tab", { name: "Security" }));
    await waitFor(() => expect(mocks.profileGet).toHaveBeenCalledTimes(1));
    expect(mocks.grantsList).toHaveBeenCalledTimes(1);
    for (const read of categoryReads.slice(2)) expect(read).not.toHaveBeenCalled();
  });
});

describe("profile", () => {
  it("renders the daemon's current profile checked, with a sentence each", async () => {
    renderSettings("security");
    await waitFor(() => expect(screen.getByRole("radio", { name: /standard/ })).toBeChecked());
    expect(screen.getByRole("radio", { name: /relaxed/ })).not.toBeChecked();
    for (const sentence of Object.values(PROFILE_SENTENCES)) {
      expect(screen.getByText(sentence)).toBeInTheDocument();
    }
  });

  it("sets a new profile with no restart note when the daemon applies it now", async () => {
    renderSettings("security");
    await waitFor(() => expect(screen.getByRole("radio", { name: /strict/ })).toBeEnabled());
    mocks.profileGet.mockResolvedValue({ profile: "strict" });
    fireEvent.click(screen.getByRole("radio", { name: /strict/ }));
    await waitFor(() => expect(mocks.profileSet).toHaveBeenCalledWith("strict", undefined));
    await waitFor(() => expect(screen.getByRole("radio", { name: /strict/ })).toBeChecked());
    expect(screen.queryByText(/applies at next daemon start/)).not.toBeInTheDocument();
  });

  it("surfaces the applies-next-start note from a daemon that defers the change", async () => {
    mocks.profileSet.mockResolvedValue({ profile: "strict", applies: "next_daemon_start" });
    renderSettings("security");
    // The radios enable once profileGet answers.
    await waitFor(() => expect(screen.getByRole("radio", { name: /strict/ })).toBeEnabled());
    // After the set, the daemon reports the new profile on refetch.
    mocks.profileGet.mockResolvedValue({ profile: "strict" });
    fireEvent.click(screen.getByRole("radio", { name: /strict/ }));
    // Narrowing the profile is one click: no confirmation phrase.
    await waitFor(() => expect(mocks.profileSet).toHaveBeenCalledWith("strict", undefined));
    expect(await screen.findByText(/applies at next daemon start/)).toBeInTheDocument();
    expect(screen.getByRole("radio", { name: /strict/ })).toBeChecked();
  });

  it("does not relax the profile on one click: it takes a typed confirmation", async () => {
    renderSettings("security");
    await waitFor(() => expect(screen.getByRole("radio", { name: /relaxed/ })).toBeEnabled());
    fireEvent.click(screen.getByRole("radio", { name: /relaxed/ }));

    // Nothing was sent, and the radio did not move.
    expect(mocks.profileSet).not.toHaveBeenCalled();
    expect(screen.getByRole("radio", { name: /relaxed/ })).not.toBeChecked();
    const prompt = within(
      screen.getByRole("group", { name: "Switch to the relaxed profile?" }),
    );
    expect(prompt.getByRole("button", { name: "Cancel" })).toHaveFocus();
    const confirm = prompt.getByRole("button", { name: "Switch to relaxed" });
    expect(confirm).toBeDisabled();
    fireEvent.change(prompt.getByRole("textbox", { name: "type relaxed to confirm" }), {
      target: { value: "relaxed" },
    });
    fireEvent.click(confirm);
    await waitFor(() => expect(mocks.profileSet).toHaveBeenCalledWith("relaxed", "relaxed"));
  });

  it("cancelling the relax prompt changes nothing", async () => {
    renderSettings("security");
    await waitFor(() => expect(screen.getByRole("radio", { name: /relaxed/ })).toBeEnabled());
    fireEvent.click(screen.getByRole("radio", { name: /relaxed/ }));
    fireEvent.click(screen.getByRole("button", { name: "Cancel" }));
    expect(screen.queryByRole("group", { name: "Switch to the relaxed profile?" })).toBeNull();
    expect(mocks.profileSet).not.toHaveBeenCalled();
  });
});

describe("grants", () => {
  it("renders every grant row with state badges, revoke only on active ones", async () => {
    renderSettings("security");
    expect(await screen.findByText("echo")).toBeInTheDocument();
    expect(screen.getByText("status")).toBeInTheDocument();
    expect(screen.getByText("active")).toBeInTheDocument();
    expect(screen.getByText("revoked")).toBeInTheDocument();
    // Only the active row offers Revoke.
    expect(screen.getAllByRole("button", { name: "Revoke" })).toHaveLength(1);
  });

  it("revokes in two taps: first arms the confirm, second fires", async () => {
    renderSettings("security");
    const revoke = await screen.findByRole("button", { name: "Revoke" });
    fireEvent.click(revoke);
    // Armed, not fired: the button now asks, the bridge stays untouched.
    expect(mocks.grantsRevoke).not.toHaveBeenCalled();
    const armed = screen.getByRole("button", { name: "revoke?" });
    fireEvent.click(armed);
    await waitFor(() => expect(mocks.grantsRevoke).toHaveBeenCalledWith("echo"));
  });

  it("disarms the confirm when focus leaves the button", async () => {
    renderSettings("security");
    const revoke = await screen.findByRole("button", { name: "Revoke" });
    fireEvent.click(revoke);
    fireEvent.blur(screen.getByRole("button", { name: "revoke?" }));
    expect(screen.getByRole("button", { name: "Revoke" })).toBeInTheDocument();
    expect(mocks.grantsRevoke).not.toHaveBeenCalled();
  });

  it("adds a grant from the mono input and clears it on success", async () => {
    renderSettings("security");
    const input = await screen.findByLabelText("capability to grant");
    fireEvent.change(input, { target: { value: "query" } });
    fireEvent.click(screen.getByRole("button", { name: "Grant" }));
    // A grant is global: the form opens a typed confirmation instead of sending.
    expect(mocks.grantsAdd).not.toHaveBeenCalled();
    const prompt = within(
      screen.getByRole("group", { name: "Grant query to every repository?" }),
    );
    fireEvent.change(prompt.getByRole("textbox", { name: "type grant to confirm" }), {
      target: { value: "grant" },
    });
    fireEvent.click(prompt.getByRole("button", { name: "Grant" }));
    await waitFor(() => expect(mocks.grantsAdd).toHaveBeenCalledWith("query", "grant"));
    await waitFor(() => expect(input).toHaveValue(""));
  });

  it("offers the known capabilities as datalist suggestions", async () => {
    renderSettings("security");
    await screen.findByLabelText("capability to grant");
    const options = document.querySelectorAll("#known-capabilities option");
    expect([...options].map((option) => option.getAttribute("value"))).toEqual([
      ...KNOWN_CAPABILITIES,
    ]);
  });
});

describe("appearance", () => {
  it("adjusts opacity while preserving the reduced-transparency override", async () => {
    renderSettings();
    const opacity = await screen.findByRole("slider", { name: "Glass opacity" });
    expect(opacity).toHaveValue("84");
    fireEvent.change(opacity, { target: { value: "72" } });
    expect(window.localStorage.getItem(glassOpacityStorageKey)).toBe("72");
    expect(document.documentElement.style.getPropertyValue("--glass-opacity")).toBe("72%");
    const reduce = screen.getByRole("checkbox", { name: "Reduce transparency" });
    fireEvent.click(reduce);
    expect(opacity).toBeDisabled();
    fireEvent.click(reduce);
    expect(opacity).toHaveValue("72");
    expect(opacity).toBeEnabled();
  });
  it("adjusts movement intensity independently from speed and retains it when off", async () => {
    renderSettings();
    const intensity = await screen.findByRole("slider", { name: "Movement intensity" });
    expect(intensity).toHaveValue("70");
    fireEvent.change(intensity, { target: { value: "95" } });
    expect(window.localStorage.getItem(backgroundIntensityStorageKey)).toBe("95");
    expect(document.documentElement.style.getPropertyValue("--background-intensity")).toBe(
      "0.95",
    );
    expect(screen.getByRole("slider", { name: "Background animation speed" })).toHaveValue("1");
    const enabled = screen.getByRole("checkbox", { name: "Animate background" });
    fireEvent.click(enabled);
    expect(intensity).toBeDisabled();
    fireEvent.click(enabled);
    expect(intensity).toBeEnabled();
    expect(intensity).toHaveValue("95");
  });
  it("switches background speed and off, retaining the choice through material and tab changes", async () => {
    renderSettings();
    const group = await screen.findByRole("group", { name: "Background motion" });
    const slider = within(group).getByRole("slider", { name: "Background animation speed" });
    const enabled = within(group).getByRole("checkbox", { name: "Animate background" });
    expect(enabled).toBeChecked();
    expect(slider).toHaveValue("1");
    fireEvent.change(slider, { target: { value: "6.3" } });
    expect(window.localStorage.getItem(backgroundSpeedStorageKey)).toBe("6.3");
    expect(slider).toHaveAttribute("aria-valuetext", "6.3 times speed, 38 seconds per loop");
    expect(screen.getByText("6.3× · 38s loop")).toBeInTheDocument();
    const transparency = screen.getByRole("checkbox", { name: "Reduce transparency" });
    fireEvent.click(transparency);
    expect(screen.getByText(/Hidden while transparency is reduced/)).toBeInTheDocument();
    expect(slider).toHaveValue("6.3");
    fireEvent.click(transparency);
    fireEvent.click(enabled);
    expect(document.documentElement.dataset.backgroundMotion).toBe("off");
    expect(window.localStorage.getItem(backgroundMotionStorageKey)).toBe("off");
    expect(slider).toBeDisabled();
    expect(screen.getByText(/The background stays still/)).toBeInTheDocument();
    fireEvent.click(screen.getByRole("tab", { name: "Security" }));
    await screen.findByRole("tabpanel", { name: "Security" });
    fireEvent.click(screen.getByRole("tab", { name: "Appearance" }));
    await screen.findByRole("tabpanel", { name: "Appearance" });
    expect(enabled).not.toBeChecked();
    fireEvent.click(enabled);
    expect(document.documentElement.dataset.backgroundMotion).toBe("slow");
    expect(slider).toBeEnabled();
    expect(slider).toHaveValue("6.3");
  });

  it("applies a theme family from its swatch card", async () => {
    renderSettings();
    const vina = await screen.findByRole("button", { name: "Viña del Mar dark" });
    expect(vina).toHaveAttribute("aria-pressed", "false");
    fireEvent.click(vina);
    expect(document.documentElement.dataset.theme).toBe("vina");
    expect(vina).toHaveAttribute("aria-pressed", "true");
    // Mode untouched by a family switch.
    expect(document.documentElement.dataset.mode).toBe("dark");
  });

  it("switches mode with the light/dark buttons", async () => {
    renderSettings();
    // Exact names: the chrome strip's own toggle says "switch to light mode".
    const light = await screen.findByRole("button", { name: "light" });
    fireEvent.click(light);
    expect(document.documentElement.dataset.mode).toBe("light");
    expect(document.documentElement.dataset.theme).toBe("ventisquero");
    fireEvent.click(screen.getByRole("button", { name: "dark" }));
    expect(document.documentElement.dataset.mode).toBe("dark");
  });

  it("previews all four Costa appearances with their own palette scope", async () => {
    renderSettings();
    for (const [label, family, mode] of [
      ["Ventisquero dark", "ventisquero", "dark"],
      ["Ventisquero light", "ventisquero", "light"],
      ["Viña del Mar dark", "vina", "dark"],
      ["Viña del Mar light", "vina", "light"],
    ]) {
      const card = await screen.findByRole("button", { name: label });
      expect(card.querySelector(`[data-theme='${family}']`)).toHaveAttribute("data-mode", mode);
    }
  });

  it("uses the material control without resetting a form draft", async () => {
    renderSettings("security");
    const input = await screen.findByLabelText("capability to grant");
    fireEvent.change(input, { target: { value: "echo" } });
    fireEvent.click(screen.getByRole("tab", { name: "Appearance" }));
    const material = await screen.findByRole("checkbox", { name: "Reduce transparency" });
    expect(material).not.toBeChecked();
    fireEvent.click(material);
    expect(material).toBeChecked();
    expect(document.documentElement.dataset.material).toBe("opaque");
    expect(window.localStorage.getItem(materialStorageKey)).toBe("opaque");
    fireEvent.click(screen.getByRole("button", { name: "Viña del Mar light" }));
    expect(document.documentElement.dataset.material).toBe("opaque");
    fireEvent.click(material);
    expect(document.documentElement.dataset.material).toBe("glass");
    fireEvent.click(screen.getByRole("tab", { name: "Security" }));
    await waitFor(() => expectActiveCategory("Security"));
    expect(screen.getByRole("combobox", { name: "capability to grant" })).toHaveValue("echo");
  });
});

describe("retention", () => {
  it("renders the stored windows and the last run", async () => {
    renderSettings("retention");
    const evidence = (await screen.findByLabelText("evidence age")) as HTMLSelectElement;
    await waitFor(() => expect(evidence.value).toBe("90"));
    expect((screen.getByLabelText("audit age") as HTMLSelectElement).value).toBe("365");
    expect(
      screen.getByText(/pruned 41 evidence rows \(2 MB\) and 3 requests · 12m ago/),
    ).toBeInTheDocument();
    expect(screen.queryByText("arrives with retention")).not.toBeInTheDocument();
    expect(EVIDENCE_CHOICES).toEqual([30, 90, 365, null]);
    expect(AUDIT_CHOICES).toEqual([90, 365, null]);
  });

  it("saves a changed window through the daemon", async () => {
    renderSettings("retention");
    const evidence = await screen.findByLabelText("evidence age");
    await waitFor(() => expect((evidence as HTMLSelectElement).value).toBe("90"));
    fireEvent.change(evidence, { target: { value: "forever" } });
    await waitFor(() =>
      expect(mocks.retentionSet).toHaveBeenCalledWith({ evidence_days: null }),
    );
    fireEvent.change(screen.getByLabelText("audit age"), { target: { value: "90" } });
    await waitFor(() => expect(mocks.retentionSet).toHaveBeenCalledWith({ audit_days: 90 }));
  });

  it("shows the daemon's refusal and snaps the select back", async () => {
    mocks.retentionSet.mockRejectedValue({
      cause: "retention_invalid",
      detail: "evidence window (1 year) exceeds audit window (90 days)",
      recovery:
        "Keep evidence no longer than audit rows: shorten the evidence window or lengthen the audit one.",
    });
    renderSettings("retention");
    const evidence = (await screen.findByLabelText("evidence age")) as HTMLSelectElement;
    await waitFor(() => expect(evidence.value).toBe("90"));
    fireEvent.change(evidence, { target: { value: "365" } });
    expect(await screen.findByText(/exceeds audit window/)).toBeInTheDocument();
    await waitFor(() => expect(evidence.value).toBe("90"));
  });

  it("prunes on demand and reports the counts", async () => {
    renderSettings("retention");
    const prune = await screen.findByRole("button", { name: "Prune now" });
    fireEvent.click(prune);
    await waitFor(() => expect(mocks.retentionPrune).toHaveBeenCalledTimes(1));
    expect(
      await screen.findByText(/pruned 2 evidence rows \(512 B\) and 0 requests/),
    ).toBeInTheDocument();
  });

  it("never pruned yet reads honestly", async () => {
    mocks.retentionGet.mockResolvedValue({
      evidence_days: null,
      audit_days: null,
      last_run: null,
    });
    renderSettings("retention");
    expect(await screen.findByText("never pruned yet")).toBeInTheDocument();
    expect(((await screen.findByLabelText("evidence age")) as HTMLSelectElement).value).toBe(
      "forever",
    );
  });
});

describe("daemon", () => {
  it("shows version, protocol, uptime, and active requests", async () => {
    renderSettings("daemon");
    const card = within(await screen.findByRole("region", { name: "Daemon" }));
    expect(await card.findByText("0.10.1")).toBeInTheDocument();
    expect(card.getByText("1h 02m")).toBeInTheDocument();
    expect(card.getByText("2")).toBeInTheDocument();
    expect(card.getByText("running")).toBeInTheDocument();
    // The live base dir the bridge resolved, not the documented rule.
    expect(card.getByText(/base dir: \/Users\/me\/\.pam/)).toBeInTheDocument();
  });

  it("stops the daemon only after the two-tap confirm", async () => {
    renderSettings("daemon");
    const stop = await screen.findByRole("button", { name: "Stop daemon" });
    await waitFor(() => expect(stop).toBeEnabled());
    fireEvent.click(stop);
    expect(mocks.daemonStop).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole("button", { name: "stop it?" }));
    await waitFor(() => expect(mocks.daemonStop).toHaveBeenCalledTimes(1));
    expect(await screen.findByText(/stopped · pid 42/)).toBeInTheDocument();
  });

  it("restarts only after the two-tap confirm, and says what stop answered", async () => {
    renderSettings("daemon");
    const restart = await screen.findByRole("button", { name: "Restart" });
    await waitFor(() => expect(restart).toBeEnabled());
    fireEvent.click(restart);
    expect(mocks.daemonStop).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole("button", { name: "restart it?" }));
    await waitFor(() => expect(mocks.daemonStop).toHaveBeenCalledTimes(1));
    expect(
      await screen.findByText(/stopped · pid 42 · the next status poll starts it again/),
    ).toBeInTheDocument();
    // The sentence under the buttons says what a restart is.
    expect(
      screen.getByText(/Restart stops the daemon; the next status poll/),
    ).toBeInTheDocument();
  });

  it("keeps Stop and Restart closed while the daemon is unreachable", async () => {
    mocks.daemonStatus.mockResolvedValue({ connected: false, status: null, base_dir: "/x" });
    renderSettings("daemon");
    const card = within(await screen.findByRole("region", { name: "Daemon" }));
    expect(await card.findByText("unreachable")).toBeInTheDocument();
    expect(card.getByRole("button", { name: "Stop daemon" })).toBeDisabled();
    const restart = card.getByRole("button", { name: "Restart" });
    expect(restart).toBeDisabled();
    expect(restart).toHaveAttribute("title", "The daemon is not running");
  });

  describe("a window that is not the daemon's build", () => {
    const mismatch = {
      cause: "client_version_mismatch",
      detail:
        "client version 0.4.3 does not match daemon version 0.5.0 running from " +
        "/Applications/pam.app/Contents/MacOS/pam; that binary has not changed on disk, so the " +
        "daemon keeps running",
      recovery:
        "Use the pam binary this daemon was started from, or stop the daemon from the PAM GUI " +
        "and start it with the build you intend to use.",
    };

    it("says so plainly, with the daemon's version and path and the way out", async () => {
      mocks.daemonStatus.mockRejectedValue(mismatch);
      renderSettings("daemon");
      const card = within(await screen.findByRole("region", { name: "Daemon" }));
      expect(await card.findByText(/daemon · client_version_mismatch/)).toBeInTheDocument();
      expect(
        card.getByText(
          "This window is not the build the running daemon was started from; the daemon is " +
            "version 0.5.0, running from /Applications/pam.app/Contents/MacOS/pam.",
        ),
      ).toBeInTheDocument();
      expect(card.getByText(mismatch.recovery)).toBeInTheDocument();
      // The recovery names stopping from here, so stopping stays possible: it is a signal, not
      // a request the daemon would refuse.
      expect(card.getByRole("button", { name: "Stop daemon" })).toBeEnabled();
      expect(card.getByRole("button", { name: "Restart" })).toBeEnabled();
    });

    it("leaves every other bridge failure as it was, with Stop closed", async () => {
      mocks.daemonStatus.mockRejectedValue({
        cause: "daemon_outdated",
        detail: "the daemon is restarting on a newer build",
        recovery: "Wait a moment and retry.",
      });
      renderSettings("daemon");
      const card = within(await screen.findByRole("region", { name: "Daemon" }));
      expect(await card.findByText(/daemon · daemon_outdated/)).toBeInTheDocument();
      expect(card.getByText(/the daemon is restarting on a newer build/)).toBeInTheDocument();
      expect(card.queryByText(/not the build the running daemon/)).not.toBeInTheDocument();
      expect(card.getByRole("button", { name: "Stop daemon" })).toBeDisabled();
    });
  });

  it.each([
    ["not_running", null, /was not running/],
    ["still_draining", 42, /still draining · pid 42 · finishing in-flight work/],
  ] as const)("reports a %s stop outcome in words", async (outcome, pid, expected) => {
    mocks.daemonStop.mockResolvedValue({ outcome, pid });
    renderSettings("daemon");
    const stop = await screen.findByRole("button", { name: "Stop daemon" });
    await waitFor(() => expect(stop).toBeEnabled());
    fireEvent.click(stop);
    fireEvent.click(screen.getByRole("button", { name: "stop it?" }));
    expect(await screen.findByText(expected)).toBeInTheDocument();
  });

  it("reports a restart of a daemon that was not running", async () => {
    mocks.daemonStop.mockResolvedValue({ outcome: "not_running", pid: null });
    renderSettings("daemon");
    const restart = await screen.findByRole("button", { name: "Restart" });
    await waitFor(() => expect(restart).toBeEnabled());
    fireEvent.click(restart);
    fireEvent.click(screen.getByRole("button", { name: "restart it?" }));
    expect(
      await screen.findByText(/was not running · the next status poll starts it/),
    ).toBeInTheDocument();
  });

  it("renders the daemon's refusal when removing the login unit fails", async () => {
    mocks.serviceStatus.mockResolvedValue({
      platform: "macos",
      exe: "/Applications/pam.app/Contents/MacOS/pam",
      state: {
        kind: "installed",
        unit: "/Users/me/Library/LaunchAgents/com.github.ro-ag.pam.daemon.plist",
        loaded: true,
      },
      note: null,
    });
    mocks.serviceUninstall.mockRejectedValue({
      cause: "service_manager_failed",
      detail: "launchctl bootout refused",
      recovery: "Run `pam service uninstall` from a shell to see the manager's own output.",
    });
    renderSettings("daemon");
    const card = within(await screen.findByRole("region", { name: "Daemon" }));
    fireEvent.click(await card.findByRole("button", { name: "Remove" }));
    fireEvent.click(card.getByRole("button", { name: "remove it?" }));
    expect(
      await card.findByText(/start at login · service_manager_failed/),
    ).toBeInTheDocument();
    expect(card.getByText(/launchctl bootout refused/)).toBeInTheDocument();
    // The unit is still installed: Remove is offered again.
    expect(card.getByRole("button", { name: "Remove" })).toBeInTheDocument();
  });

  it("offers to install the login unit when none exists", async () => {
    renderSettings("daemon");
    const card = within(await screen.findByRole("region", { name: "Daemon" }));
    expect(await card.findByText("not installed")).toBeInTheDocument();
    expect(card.getByText(/com\.github\.ro-ag\.pam\.daemon\.plist/)).toBeInTheDocument();
    fireEvent.click(card.getByRole("button", { name: "Install" }));
    await waitFor(() => expect(mocks.serviceInstall).toHaveBeenCalledTimes(1));
    expect(await card.findByText(/stopped the running daemon \(pid 7\)/)).toBeInTheDocument();
  });

  it("removes the login unit only after the two-tap confirm", async () => {
    mocks.serviceStatus.mockResolvedValue({
      platform: "macos",
      exe: "/Applications/pam.app/Contents/MacOS/pam",
      state: {
        kind: "installed",
        unit: "/Users/me/Library/LaunchAgents/com.github.ro-ag.pam.daemon.plist",
        loaded: false,
      },
      note: null,
    });
    renderSettings("daemon");
    const card = within(await screen.findByRole("region", { name: "Daemon" }));
    expect(await card.findByText("installed, not loaded")).toBeInTheDocument();
    fireEvent.click(card.getByRole("button", { name: "Remove" }));
    expect(mocks.serviceUninstall).not.toHaveBeenCalled();
    fireEvent.click(card.getByRole("button", { name: "remove it?" }));
    await waitFor(() => expect(mocks.serviceUninstall).toHaveBeenCalledTimes(1));
    // The module's own note wins over the panel's fallback line.
    expect(
      await card.findByText(/the manager stopped the managed daemon along with its unit/),
    ).toBeInTheDocument();
  });

  it("warns when the login unit pins a binary that is gone, and offers to repoint it", async () => {
    mocks.serviceStatus.mockResolvedValue({
      platform: "macos",
      exe: "/Applications/pam.app/Contents/MacOS/pam",
      pinned_exe: "/tmp/old/pam",
      stale:
        "the unit runs /tmp/old/pam, which no longer exists; run `pam service install` from the current binary",
      state: {
        kind: "installed",
        unit: "/Users/me/Library/LaunchAgents/com.github.ro-ag.pam.daemon.plist",
        loaded: false,
      },
      note: null,
    });
    renderSettings("daemon");
    const card = within(await screen.findByRole("region", { name: "Daemon" }));
    expect(await card.findByText(/which no longer exists/)).toBeInTheDocument();
    fireEvent.click(card.getByRole("button", { name: "Repoint to this binary" }));
    await waitFor(() => expect(mocks.serviceInstall).toHaveBeenCalledTimes(1));
  });

  it("explains an unsupported platform instead of offering buttons", async () => {
    mocks.serviceStatus.mockResolvedValue({
      platform: "windows",
      exe: "C:\\pam\\pam.exe",
      state: {
        kind: "unsupported",
        reason:
          "scheduled tasks carry no environment, so PAM_BASE_DIR cannot be honoured; unset it to install the login task",
      },
      note: null,
    });
    renderSettings("daemon");
    const card = within(await screen.findByRole("region", { name: "Daemon" }));
    expect(await card.findByText("unsupported")).toBeInTheDocument();
    expect(card.getByText(/PAM_BASE_DIR cannot be honoured/)).toBeInTheDocument();
    expect(card.queryByRole("button", { name: "Install" })).toBeNull();
    expect(card.queryByRole("button", { name: "Remove" })).toBeNull();
  });
});

/** A `status.boundary` block as the daemon serves it, with overrides. */
function boundaryBlock(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    peer_identity: "kernel_pid",
    last_report: null,
    reports: { retained: 0, established: 0, not_established: 0 },
    admin_contacts: {
      unattributed: 0,
      unattributed_24h: 0,
      total: 0,
      expected_total: 0,
      last: null,
      last_expected: null,
    },
    public_unknown_harness: { total: 0, last: null },
    summary: "never checked — run pam doctor from the agent",
    ...overrides,
  };
}

/** A recorded report, received `ageS` seconds ago. */
function lastReport(verdict: string, ageS: number, overrides: Record<string, unknown> = {}) {
  return {
    verdict,
    ts: nowSec - ageS - 1,
    received_ts: nowSec - ageS,
    age_s: ageS,
    agent: "claude",
    repo: "/work/app",
    relayed: false,
    peer_pid: 48122,
    peer_exe: "/Applications/PAM.app/Contents/MacOS/pam",
    peer_harness: "claude",
    failed: [],
    unverified: [],
    request_id: "req_abc",
    ...overrides,
  };
}

function statusWithBoundary(boundary: Record<string, unknown> | undefined) {
  mocks.daemonStatus.mockResolvedValue({
    connected: true,
    status: {
      daemon_version: "0.10.1",
      protocol: 1,
      uptime_s: 3_723,
      active_requests: 2,
      ...(boundary === undefined ? {} : { boundary }),
    },
    base_dir: "/Users/me/.pam",
  });
}

describe("boundary", () => {
  it("shows nothing for a daemon that publishes no block", async () => {
    statusWithBoundary(undefined);
    renderSettings("daemon");
    const card = within(await screen.findByRole("region", { name: "Daemon" }));
    expect(await card.findByText("0.10.1")).toBeInTheDocument();
    expect(card.queryByRole("group", { name: "Boundary" })).not.toBeInTheDocument();
  });

  it("reads not verified before any report, with the command preselected on the fallback", async () => {
    statusWithBoundary(boundaryBlock());
    renderSettings("daemon");
    const rows = within(await screen.findByRole("group", { name: "Boundary" }));
    expect(rows.getByText("not verified")).toBeInTheDocument();
    expect(rows.getByText("not verified — run pam doctor from the agent")).toBeInTheDocument();
    expect(rows.getByText("0")).toBeInTheDocument();
    expect(rows.getByRole("combobox", { name: "harness" })).toHaveValue("sandbox-exec");
    expect(rows.getByText("pam doctor --profile sandbox-exec")).toBeInTheDocument();
    expect(rows.getByRole("button", { name: "copy doctor command" })).toBeEnabled();
  });

  it("shows an established boundary with its age, sender and the harness it came from", async () => {
    statusWithBoundary(
      boundaryBlock({
        last_report: lastReport("established", 7_200),
        reports: { retained: 1, established: 1, not_established: 0 },
        summary: "established 2 h ago by claude (pid 48122, direct); admin contacts unattributed: 0",
      }),
    );
    renderSettings("daemon");
    const rows = within(await screen.findByRole("group", { name: "Boundary" }));
    expect(rows.getByText("established")).toBeInTheDocument();
    expect(rows.getByText("established · 2h ago · by claude (direct)")).toBeInTheDocument();
    expect(rows.getByText("claude")).toBeInTheDocument();
    expect(rows.getByText(/pid 48122/)).toBeInTheDocument();
    expect(rows.queryByText("reached (must be denied)")).not.toBeInTheDocument();
    // The harness of the last report picks the profile to copy.
    expect(rows.getByRole("combobox", { name: "harness" })).toHaveValue("claude-code");
    expect(rows.getByText("pam doctor --profile claude-code")).toBeInTheDocument();
  });

  it("names what a not-established run reached and the unexplained admin contacts", async () => {
    statusWithBoundary(
      boundaryBlock({
        last_report: lastReport("not_established", 120, {
          agent: "codex",
          relayed: true,
          peer_pid: null,
          peer_harness: null,
          failed: ["admin.dir", "store.read"],
          unverified: ["daemon.signal"],
        }),
        reports: { retained: 1, established: 0, not_established: 1 },
        admin_contacts: {
          unattributed: 2,
          unattributed_24h: 2,
          total: 3,
          expected_total: 10,
          last: {
            ts: nowSec - 60,
            kind: "admin_contact",
            peer_pid: 4711,
            peer_exe: "/usr/local/bin/pam\u202e",
            peer_harness: "zsh",
            attributed: null,
          },
          last_expected: null,
        },
        summary: "not_established 2 min ago by codex (no pid, relay); admin contacts unattributed: 2",
      }),
    );
    renderSettings("daemon");
    const rows = within(await screen.findByRole("group", { name: "Boundary" }));
    expect(rows.getByText("not established")).toBeInTheDocument();
    expect(rows.getByText("not established · 2m ago · by codex (relay)")).toBeInTheDocument();
    expect(rows.getByText("reached (must be denied)")).toBeInTheDocument();
    expect(rows.getByText("admin.dir store.read")).toBeInTheDocument();
    expect(rows.getByText("unverified")).toBeInTheDocument();
    expect(rows.getByText("daemon.signal")).toBeInTheDocument();
    expect(rows.getByText("2")).toBeInTheDocument();
    // The peer executable is agent-influenced text: its hidden character is shown as an escape.
    expect(rows.getByText(/last from/)).toBeInTheDocument();
    expect(rows.getByText("\\u{202E}")).toBeInTheDocument();
    expect(rows.getByRole("combobox", { name: "harness" })).toHaveValue("codex");
  });

  it("keeps a cannot-probe report honest and lets the human pick another harness", async () => {
    statusWithBoundary(
      boundaryBlock({
        last_report: lastReport("cannot_probe", 600, { agent: "gemini" }),
      }),
    );
    renderSettings("daemon");
    const rows = within(await screen.findByRole("group", { name: "Boundary" }));
    expect(rows.getByText("not probed")).toBeInTheDocument();
    expect(rows.getByText("could not be probed · 10m ago · by gemini (direct)")).toBeInTheDocument();
    const select = rows.getByRole("combobox", { name: "harness" });
    expect(select).toHaveValue("gemini-cli");
    fireEvent.change(select, { target: { value: "copilot-cli" } });
    expect(rows.getByText("pam doctor --profile copilot-cli")).toBeInTheDocument();
  });

  it("copies the command and says so", async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, "clipboard", { value: { writeText }, configurable: true });
    statusWithBoundary(boundaryBlock());
    renderSettings("daemon");
    const rows = within(await screen.findByRole("group", { name: "Boundary" }));
    fireEvent.click(rows.getByRole("button", { name: "copy doctor command" }));
    await waitFor(() => expect(writeText).toHaveBeenCalledWith("pam doctor --profile sandbox-exec"));
    expect(await rows.findByText("Copied")).toBeInTheDocument();
  });

  it("phrases every verdict as one line", () => {
    const now = nowSec * 1000;
    const block = (last_report: unknown) =>
      ({ ...boundaryBlock(), last_report }) as unknown as Parameters<typeof boundaryVerdictLine>[0];
    expect(boundaryVerdictLine(block(null), now)).toBe(
      "not verified — run pam doctor from the agent",
    );
    expect(
      boundaryVerdictLine(block(lastReport("established", 3_600 * 5)), now),
    ).toBe("established · 5h ago · by claude (direct)");
    expect(
      boundaryVerdictLine(block(lastReport("not_established", 0, { relayed: true })), now),
    ).toBe("not established · now · by claude (relay)");
  });
});

describe("logs", () => {
  it("renders the tail with level colorization", async () => {
    renderSettings("logs");
    const viewer = within(await screen.findByLabelText("daemon log lines"));
    expect(viewer.getByText("INFO daemon listening")).toBeInTheDocument();
    expect(viewer.getByText("WARN queue is deep").className).toContain("text-warning");
    expect(viewer.getByText("ERROR store unreachable").className).toContain("text-danger");
    expect(viewer.getByText("INFO daemon listening").className).toContain("text-ink-muted");
    // The file the tail came from is named.
    expect(screen.getByText("/Users/dev/.pam/log/daemon.log.2026-09-01")).toBeInTheDocument();
  });

  it("classifies lines by their level token", () => {
    expect(logTone("2026-09-01T10:00:00Z ERROR pam_daemon: boom")).toBe("danger");
    expect(logTone("2026-09-01T10:00:00Z  WARN pam_daemon: deep")).toBe("warning");
    expect(logTone("2026-09-01T10:00:00Z  INFO pam_daemon: fine")).toBeNull();
    expect(logTone("no level at all")).toBeNull();
  });

  it("asks for 500 lines by default and refetches when the count changes", async () => {
    renderSettings("logs");
    await waitFor(() => expect(mocks.readDaemonLog).toHaveBeenCalledWith(500));
    fireEvent.change(screen.getByLabelText("lines to show"), { target: { value: "1000" } });
    await waitFor(() => expect(mocks.readDaemonLog).toHaveBeenCalledWith(1000));
    expect(LOG_LINE_CHOICES).toEqual([100, 500, 1000]);
  });

  it("offers refresh, auto-refresh, and copy controls", async () => {
    renderSettings("logs");
    // Copy enables once the tail has lines to copy.
    await screen.findByLabelText("daemon log lines");
    expect(screen.getByRole("button", { name: "refresh log" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "copy log lines" })).toBeEnabled();
    expect(screen.getByRole("checkbox", { name: "Refresh every 5 s" })).not.toBeChecked();
  });

  it("renders the uniform failure shape when the bridge is unavailable", async () => {
    mocks.readDaemonLog.mockRejectedValue({
      cause: "bridge_unavailable",
      detail: "running outside the app shell; no Tauri bridge exists",
      recovery: "Open the desktop app (`cargo run -p pam -- gui`) to talk to the daemon.",
    });
    renderSettings("logs");
    expect(await screen.findByText(/log · bridge_unavailable/)).toBeInTheDocument();
    expect(screen.getByText(/no Tauri bridge exists/)).toBeInTheDocument();
  });
});

it("opens and focuses an exact connector from a recovery link", async () => {
  mocks.connectorsList.mockResolvedValue({
    connectors: [
      {
        id: "sonarqube",
        name: "SonarQube",
        auth: "token_as_user",
        needs_base_url: true,
        enabled: false,
        credential_present: false,
        store_available: true,
      },
    ],
  });
  renderSettings("connectors/sonarqube");
  const target = await screen.findByLabelText("connector SonarQube");
  expect(screen.getByRole("tab", { name: "Connectors" })).toHaveAttribute(
    "aria-selected",
    "true",
  );
  await waitFor(() => expect(target).toHaveFocus());
});

describe("managed policy in Settings", () => {
  const managed = (overrides: Partial<PolicyBody> = {}) =>
    unmanagedPolicy({
      state: "active",
      organization: "Example Corp",
      digest: "ab12cd34ef56".padEnd(64, "0"),
      revision: "r1",
      ...overrides,
    });

  it("shows the policy panel in Security and the status line on every tab", async () => {
    mocks.policyGet.mockResolvedValue(managed());
    renderSettings("security");
    expect(await screen.findByRole("region", { name: "managed policy" })).toBeInTheDocument();
    const line = await screen.findByRole("status", { name: "managed policy status" });
    expect(line).toHaveTextContent("Managed by your organization's policy.");
    fireEvent.click(screen.getByRole("tab", { name: "Daemon" }));
    expect(screen.getByRole("status", { name: "managed policy status" })).toBeInTheDocument();
  });

  it("the status line opens the Security tab", async () => {
    mocks.policyGet.mockResolvedValue(managed({ state: "frozen" }));
    renderSettings("daemon");
    const line = await screen.findByRole("status", { name: "managed policy status" });
    expect(line).toHaveTextContent(/paused until it is fixed/);
    fireEvent.click(within(line).getByRole("button", { name: "View policy" }));
    await waitFor(() => expectActiveCategory("Security"));
  });

  it("shows no status line when there is no policy", async () => {
    renderSettings("security");
    expect(
      await screen.findByText("No managed policy is installed on this computer."),
    ).toBeInTheDocument();
    expect(screen.queryByRole("status", { name: "managed policy status" })).toBeNull();
  });

  it("Check now re-reads the policy and refreshes what the other panels show", async () => {
    mocks.policyGet.mockResolvedValue(managed());
    renderSettings("security");
    await screen.findByText("Managed by Example Corp.");
    const profileReads = mocks.profileGet.mock.calls.length;
    fireEvent.click(screen.getByRole("button", { name: /Check now/ }));
    await waitFor(() => expect(mocks.policyReload).toHaveBeenCalledTimes(1));
    await waitFor(() => expect(mocks.profileGet.mock.calls.length).toBeGreaterThan(profileReads));
  });

  describe("profile", () => {
    it("disables every profile and says who owns it when the policy locks it", async () => {
      mocks.profileGet.mockResolvedValue({
        profile: "strict",
        effective: { profile: { source: "policy", locked: true, mode: "locked", reason: "SEC-114" } },
      });
      renderSettings("security");
      await waitFor(() => expect(screen.getByRole("radio", { name: /strict/ })).toBeChecked());
      for (const name of [/relaxed/, /standard/, /strict/]) {
        expect(screen.getByRole("radio", { name })).toBeDisabled();
      }
      expect(screen.getAllByText("Managed by your organization").length).toBeGreaterThan(0);
      expect(screen.getByText("SEC-114")).toBeInTheDocument();
    });

    it("disables only the profiles below a floor and prints the floor", async () => {
      mocks.profileGet.mockResolvedValue({
        profile: "standard",
        effective: {
          profile: {
            source: "policy",
            locked: false,
            mode: "floor",
            constraint: { floor: "standard" },
            clamped: true,
          },
        },
      });
      renderSettings("security");
      await waitFor(() => expect(screen.getByRole("radio", { name: /standard/ })).toBeChecked());
      expect(screen.getByRole("radio", { name: /relaxed/ })).toBeDisabled();
      expect(screen.getByRole("radio", { name: /standard/ })).toBeEnabled();
      expect(screen.getByRole("radio", { name: /strict/ })).toBeEnabled();
      expect(screen.getByText("lowest allowed: standard")).toBeInTheDocument();
    });

    it("names why a profile is blocked", () => {
      expect(profileBlocker(undefined, "relaxed")).toBeUndefined();
      expect(profileBlocker({ source: "policy", locked: true }, "strict")).toBe(
        "Managed by your organization",
      );
      expect(
        profileBlocker(
          { source: "policy", locked: false, mode: "floor", constraint: { floor: "strict" } },
          "standard",
        ),
      ).toBe("Your organization does not allow a profile below strict");
    });

    it.each([
      ["setting_locked", "the profile is managed by your organisation's policy"],
      ["policy_frozen", "the policy file cannot be trusted, so widening changes are paused"],
      ["policy_not_allowed", "relaxed is below the floor your organisation set"],
    ])("renders a %s refusal's detail and recovery through the failure note", async (cause, detail) => {
      mocks.profileSet.mockRejectedValue({
        cause,
        detail,
        recovery: "Managed by your organisation's policy; ask your administrator.",
      });
      renderSettings("security");
      await waitFor(() => expect(screen.getByRole("radio", { name: /strict/ })).toBeEnabled());
      fireEvent.click(screen.getByRole("radio", { name: /strict/ }));
      expect(await screen.findByText(new RegExp(`profile · ${cause}`))).toBeInTheDocument();
      expect(screen.getByText(`${detail}.`)).toBeInTheDocument();
      expect(screen.getByText(/ask your administrator/)).toBeInTheDocument();
    });
  });

  describe("grants", () => {
    it("badges a row the policy blocks and explains that the grant is kept", async () => {
      mocks.grantsList.mockResolvedValue({
        grants: [grant({ id: 1, capability: "echo", blocked_by_policy: true })],
      });
      renderSettings("security");
      expect(await screen.findByText("blocked by policy")).toBeInTheDocument();
      expect(screen.getByText(GRANT_BLOCKED_NOTE)).toBeInTheDocument();
      expect(screen.queryByText("active")).toBeNull();
      // Revoke stays: the row is the human's, and revoking is never refused.
      expect(screen.getByRole("button", { name: "Revoke" })).toBeInTheDocument();
    });

    it("lists what the policy never allows", async () => {
      mocks.grantsList.mockResolvedValue({
        grants: [],
        policy: { manual: null, remember: null, never: ["flow.step:prod/*"], never_classes: ["destructive"] },
      });
      renderSettings("security");
      const note = await screen.findByLabelText("capabilities the policy never allows");
      expect(note).toHaveTextContent("never allows flow.step:prod/* and the classes destructive");
    });

    it("disables Add with the reason when the policy forbids manual grants", async () => {
      mocks.grantsList.mockResolvedValue({
        grants: [],
        policy: { manual: "deny", remember: null, never: null, never_classes: null },
        effective: { manual: { source: "policy", locked: true, mode: "forbid" } },
      });
      renderSettings("security");
      expect(await screen.findByText(GRANT_MANUAL_BLOCKED_NOTE)).toBeInTheDocument();
      expect(screen.getByLabelText("capability to grant")).toBeDisabled();
      expect(screen.getByRole("button", { name: "Grant" })).toBeDisabled();
      expect(screen.getByRole("button", { name: "Grant" })).toHaveAttribute(
        "title",
        GRANT_MANUAL_BLOCKED_NOTE,
      );
    });

    it("renders a refused add through the failure note", async () => {
      mocks.grantsAdd.mockRejectedValue({
        cause: "policy_not_allowed",
        detail: "capability \"echo\" is not allowed by your organisation",
        recovery: "Managed by your organisation's policy; ask your administrator.",
      });
      renderSettings("security");
      const input = await screen.findByLabelText("capability to grant");
      fireEvent.change(input, { target: { value: "echo" } });
      fireEvent.click(screen.getByRole("button", { name: "Grant" }));
      const prompt = within(
        screen.getByRole("group", { name: "Grant echo to every repository?" }),
      );
      fireEvent.change(prompt.getByRole("textbox", { name: "type grant to confirm" }), {
        target: { value: "grant" },
      });
      fireEvent.click(prompt.getByRole("button", { name: "Grant" }));
      expect(await screen.findByText(/grants · policy_not_allowed/)).toBeInTheDocument();
      expect(screen.getByText(/is not allowed by your organisation/)).toBeInTheDocument();
    });
  });

  describe("retention", () => {
    it("disables a window the policy locks and keeps the other editable", async () => {
      mocks.retentionGet.mockResolvedValue({
        evidence_days: 90,
        audit_days: 365,
        last_run: null,
        effective: {
          evidence_days: { source: "policy", locked: true, mode: "locked" },
          audit_days: { source: "user", locked: false },
        },
      });
      renderSettings("retention");
      const evidence = (await screen.findByLabelText("evidence age")) as HTMLSelectElement;
      await waitFor(() => expect(evidence.value).toBe("90"));
      expect(evidence).toBeDisabled();
      expect(screen.getByLabelText("audit age")).toBeEnabled();
      expect(screen.getAllByText("Managed by your organization")).toHaveLength(1);
    });

    it("hints a policy default and leaves the window editable", async () => {
      mocks.retentionGet.mockResolvedValue({
        evidence_days: 90,
        audit_days: 365,
        last_run: null,
        effective: {
          evidence_days: { source: "policy", locked: false, mode: "default" },
          audit_days: { source: "user", locked: false },
        },
      });
      renderSettings("retention");
      expect(await screen.findByText("organization default")).toBeInTheDocument();
      expect(screen.getByLabelText("evidence age")).toBeEnabled();
    });

    it("renders a window the policy clamps with its limit", async () => {
      mocks.retentionGet.mockResolvedValue({
        evidence_days: 30,
        audit_days: 90,
        last_run: null,
        effective: {
          evidence_days: {
            source: "policy",
            locked: false,
            mode: "max",
            constraint: { max: 30 },
            clamped: true,
          },
          audit_days: { source: "user", locked: false },
        },
      });
      renderSettings("retention");
      expect(await screen.findByText("at most: 30")).toBeInTheDocument();
      expect(screen.getByText("Limited by your organization")).toBeInTheDocument();
    });

    it("renders a refused window through the failure note", async () => {
      mocks.retentionSet.mockRejectedValue({
        cause: "setting_locked",
        detail: "evidence_days is managed by your organisation's policy",
        recovery: "Managed by your organisation's policy; ask your administrator.",
      });
      renderSettings("retention");
      const evidence = (await screen.findByLabelText("evidence age")) as HTMLSelectElement;
      await waitFor(() => expect(evidence.value).toBe("90"));
      fireEvent.change(evidence, { target: { value: "365" } });
      expect(await screen.findByText(/retention · setting_locked/)).toBeInTheDocument();
      expect(screen.getByText(/ask your administrator/)).toBeInTheDocument();
    });
  });
});
