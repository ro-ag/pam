import { createMemoryHistory } from "@tanstack/react-router";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import App from "../App";
import type { GrantRow } from "../lib/ipc";
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
} from "../lib/theme";
import { createAppRouter } from "../router";
import {
  AUDIT_CHOICES,
  EVIDENCE_CHOICES,
  KNOWN_CAPABILITIES,
  LOG_LINE_CHOICES,
  PROFILE_SENTENCES,
  logTone,
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
  retentionGet: vi.fn(),
  retentionSet: vi.fn(),
  retentionPrune: vi.fn(),
  serviceStatus: vi.fn(),
  serviceInstall: vi.fn(),
  serviceUninstall: vi.fn(),
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

beforeEach(() => {
  // Deterministic theme regardless of what an earlier test applied.
  applyTheme("ventisquero", "dark", { persist: false });
  applyMaterial("glass", { persist: false });
  applyBackgroundMotion("slow");
  applyBackgroundSpeed(1);
  applyBackgroundIntensity(70);

  mocks.subscribeEvents.mockResolvedValue(() => {});
  mocks.daemonStatus.mockResolvedValue({
    connected: true,
    status: { daemon_version: "0.10.1", protocol: 1, uptime_s: 3_723, active_requests: 2 },
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
  mocks.approvalsPending.mockResolvedValue({ pending: [] });
  mocks.activityList.mockResolvedValue({ requests: [] });
  mocks.callersList.mockResolvedValue({ callers: [] });
  mocks.profileGet.mockResolvedValue({ profile: "standard" });
  mocks.profileSet.mockResolvedValue({ profile: "strict", applies: "next_daemon_start" });
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
    expect(screen.getAllByRole("tabpanel", { hidden: true })).toHaveLength(8);
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

  it("sets a new profile and surfaces the applies-next-start note", async () => {
    renderSettings("security");
    // The radios enable once profileGet answers.
    await waitFor(() => expect(screen.getByRole("radio", { name: /strict/ })).toBeEnabled());
    // After the set, the daemon reports the new profile on refetch.
    mocks.profileGet.mockResolvedValue({ profile: "strict" });
    fireEvent.click(screen.getByRole("radio", { name: /strict/ }));
    await waitFor(() => expect(mocks.profileSet).toHaveBeenCalledWith("strict"));
    expect(await screen.findByText(/applies at next daemon start/)).toBeInTheDocument();
    expect(screen.getByRole("radio", { name: /strict/ })).toBeChecked();
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
    await waitFor(() => expect(mocks.grantsAdd).toHaveBeenCalledWith("query"));
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
    const vina = await screen.findByRole("button", { name: "Viña del Mar Night" });
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
      ["Ventisquero Bedrock", "ventisquero", "dark"],
      ["Ventisquero Mist", "ventisquero", "light"],
      ["Viña del Mar Night", "vina", "dark"],
      ["Viña del Mar Dawn", "vina", "light"],
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
    fireEvent.click(screen.getByRole("button", { name: "Viña del Mar Dawn" }));
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
      screen.getByText(/last pruned 12m ago · 41 evidence rows \(2 MB\) · 3 requests/),
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
      await screen.findByText(/2 evidence rows \(512 B\) · 0 requests/),
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
    expect(card.getByText(/base dir: ~\/\.pam/)).toBeInTheDocument();
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

  it("labels restart honestly as stop + lazy start", async () => {
    renderSettings("daemon");
    const restart = await screen.findByRole("button", {
      name: "Restart (stop + lazy start)",
    });
    fireEvent.click(restart);
    await waitFor(() => expect(mocks.daemonStop).toHaveBeenCalledTimes(1));
    expect(await screen.findByText(/starting it again/)).toBeInTheDocument();
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
      platform: "linux",
      exe: "/usr/bin/pam",
      state: {
        kind: "installed",
        unit: "/home/me/.config/systemd/user/pam-daemon.service",
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
    expect(screen.getByRole("checkbox", { name: "auto 5s" })).not.toBeChecked();
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
