import { createMemoryHistory } from "@tanstack/react-router";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import App from "../App";
import { rephraseStorageKey } from "../lib/ask/prefs";
import { applyTheme } from "../lib/theme";
import { createAppRouter } from "../router";

/**
 * The Home screen against a mocked bridge: the greeting reads the daemon
 * and the raised hands, the composer asks the real router, the pills ask
 * the canonical questions, an answer's deep link actually navigates, the
 * memory is three exchanges deep and says so, the model line appears only
 * when the rephrase toggle is on, and a source that refuses becomes one
 * of Pam's sentences rather than a crash.
 *
 * The whole App mounts (shell included) so the route, the query provider
 * and the screen run exactly as shipped.
 */

const mocks = vi.hoisted(() => ({
  daemonStatus: vi.fn(),
  approvalsPending: vi.fn(),
  activityList: vi.fn(),
  callersList: vi.fn(),
  modelsStatus: vi.fn(),
  retentionGet: vi.fn(),
  serviceStatus: vi.fn(),
  evidenceStats: vi.fn(),
  flowsList: vi.fn(),
  auditRequest: vi.fn(),
  modelsTry: vi.fn(),
  subscribeEvents: vi.fn(),
  // Settings mounts when an answer's deep link navigates there; its own
  // reads are stubbed so this file keeps asserting Home's copy.
  profileGet: vi.fn(),
  grantsList: vi.fn(),
  modelsList: vi.fn(),
  curatorList: vi.fn(),
  flowsSettingsGet: vi.fn(),
  connectorsList: vi.fn(),
  readDaemonLog: vi.fn(),
}));

vi.mock("../lib/ipc", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../lib/ipc")>();
  return { ...actual, ...mocks };
});

const UNIT = "/Users/me/Library/LaunchAgents/com.github.ro-ag.pam.daemon.plist";

beforeEach(() => {
  applyTheme("ventisquero", "dark", { persist: false });
  window.localStorage.removeItem(rephraseStorageKey);
  // jsdom has no layout, so Settings' hash-scroll effect would throw when
  // an answer's deep link lands there.
  Element.prototype.scrollIntoView = () => {};

  mocks.subscribeEvents.mockResolvedValue(() => {});
  mocks.daemonStatus.mockResolvedValue({
    connected: true,
    status: { daemon_version: "0.1.0", protocol: 1, uptime_s: 3_723, active_requests: 1 },
  });
  mocks.approvalsPending.mockResolvedValue({ pending: [] });
  mocks.activityList.mockResolvedValue({ requests: [] });
  mocks.callersList.mockResolvedValue({ callers: [] });
  mocks.modelsStatus.mockResolvedValue({
    runtime: { state: { state: "idle" }, busy: false },
    jobs: [],
    defaults: { light: null, heavy: null },
    idle_unload_min: 10,
    models_dir: "/Users/me/.pam/models",
    host_ram_bytes: 64e9,
  });
  mocks.retentionGet.mockResolvedValue({
    evidence_days: 90,
    audit_days: null,
    last_run: null,
  });
  mocks.serviceStatus.mockResolvedValue({
    platform: "macos",
    exe: "/usr/local/bin/pam",
    state: { kind: "not_installed", unit: UNIT },
    note: null,
  });
  mocks.evidenceStats.mockResolvedValue({
    since_ts: 0,
    compressions: 0,
    source_bytes: 0,
    compact_bytes: 0,
    tokens_avoided_est: 0,
  });
  mocks.flowsList.mockResolvedValue({
    flows: [
      { id: "pr-readiness", name: "PR readiness", valid: true },
      { id: "after-merge-checks", name: "After-merge checks", valid: true },
    ],
  });
  mocks.auditRequest.mockResolvedValue({ request_id: "", rows: [] });
  mocks.modelsTry.mockResolvedValue({ text: "" });

  mocks.profileGet.mockResolvedValue({ profile: "standard" });
  mocks.grantsList.mockResolvedValue({ grants: [] });
  mocks.modelsList.mockResolvedValue({ models: [], models_dir: "/Users/me/.pam/models" });
  mocks.curatorList.mockResolvedValue({ detected: [], selected: null });
  mocks.flowsSettingsGet.mockResolvedValue({
    allowed_programs: [],
    flows_dir: "/Users/me/.pam/flows",
  });
  mocks.connectorsList.mockResolvedValue({ connectors: [] });
  mocks.readDaemonLog.mockResolvedValue({ path: "/tmp/pam.log", lines: [], truncated: false });
});

afterEach(() => {
  vi.clearAllMocks();
});

function renderHome() {
  const router = createAppRouter(createMemoryHistory({ initialEntries: ["/"] }));
  render(<App router={router} />);
  return router;
}

/** Type a question into the composer and press Enter, as a human does. */
async function askQuestion(question: string) {
  const input = await screen.findByRole("textbox", { name: "ask pam" });
  await waitFor(() => expect(input).toBeEnabled());
  fireEvent.change(input, { target: { value: question } });
  fireEvent.submit(screen.getByRole("form", { name: "Ask PAM" }));
}

describe("Home shell", () => {
  it("greets in Pam's voice from the daemon and approvals state", async () => {
    renderHome();
    expect(await screen.findByRole("heading", { name: "Home" })).toBeInTheDocument();
    expect(await screen.findByText("No requests need your approval.")).toBeInTheDocument();
  });

  it("greets a raised hand, and says so when the daemon is silent", async () => {
    mocks.approvalsPending.mockResolvedValue({
      pending: [
        {
          request_id: "r1",
          capability: "repo.push",
          repo: "/Users/me/pam",
          agent: "claude",
          requested_ts: Math.floor(Date.now() / 1000) - 60,
        },
      ],
    });
    const { unmount } = render(
      <App router={createAppRouter(createMemoryHistory({ initialEntries: ["/"] }))} />,
    );
    expect(await screen.findByText("One request awaiting your approval.")).toBeInTheDocument();
    unmount();

    mocks.daemonStatus.mockResolvedValue({ connected: false, status: null });
    renderHome();
    expect(await screen.findByText("Active requests: Unavailable")).toBeInTheDocument();
  });

  it("shows unavailable state instead of inventing zero counts and keeps workspace links usable", async () => {
    mocks.daemonStatus.mockResolvedValue({ connected: false, status: null });
    mocks.approvalsPending.mockRejectedValue(new Error("unavailable"));
    const router = renderHome();
    const overview = await screen.findByRole("complementary", { name: "Workspace overview" });
    await waitFor(() =>
      expect(within(overview).getByText("Approval queue unavailable.")).toBeInTheDocument(),
    );
    expect(within(overview).getByText("Active requests: Unavailable")).toBeInTheDocument();
    expect(within(overview).queryByText("0")).not.toBeInTheDocument();
    fireEvent.click(within(overview).getByRole("link", { name: /Active requests/ }));
    await waitFor(() => expect(router.state.location.pathname).toBe("/activity"));
  });

  it("answers a typed question and keeps only the last three exchanges", async () => {
    renderHome();
    await askQuestion("what's waiting for my approval?");
    expect(await screen.findByText("Nothing waits for you.")).toBeInTheDocument();
    await askQuestion("is the daemon running?");
    expect(
      await screen.findByText(
        "The daemon answers: version 0.1.0, up for 1h 02m, 1 active request.",
      ),
    ).toBeInTheDocument();
    await askQuestion("does pam start at login?");
    expect(await screen.findByText("No: nothing starts me at login.")).toBeInTheDocument();
    await askQuestion("which flows do I have?");
    expect(
      await screen.findByText("You have 2 flows: pr-readiness, after-merge-checks."),
    ).toBeInTheDocument();

    const exchanges = within(screen.getByRole("list", { name: "exchanges" })).getAllByRole(
      "listitem",
    );
    expect(exchanges).toHaveLength(3);
    // Newest first, and the fourth question pushed the first one out.
    expect(within(exchanges[0]).getByText("which flows do I have?")).toBeInTheDocument();
    expect(screen.queryByText("what's waiting for my approval?")).toBeNull();
  });

  it("asks the canonical question when a pill is clicked", async () => {
    renderHome();
    fireEvent.click(await screen.findByText("Suggested questions"));
    const pill = await screen.findByRole("button", {
      name: "ask: what's waiting for my approval?",
    });
    fireEvent.click(pill);
    const exchange = await screen.findByRole("listitem");
    expect(within(exchange).getByText("what's waiting for my approval?")).toBeInTheDocument();
    expect(await screen.findByText("Nothing waits for you.")).toBeInTheDocument();
  });

  it("renders facts and deep links, and the link navigates", async () => {
    const router = renderHome();
    await askQuestion("does pam start at login?");
    expect(await screen.findByText("No: nothing starts me at login.")).toBeInTheDocument();
    const exchange = screen.getByRole("listitem");
    expect(within(exchange).getByText("unit")).toBeInTheDocument();
    expect(within(exchange).getByText(UNIT)).toBeInTheDocument();

    fireEvent.click(within(exchange).getByRole("button", { name: "Settings › Daemon" }));
    await waitFor(() => expect(router.state.location.pathname).toBe("/settings"));
    expect(router.state.location.hash.replace(/^#/, "")).toBe("daemon");
  });

  it("keeps the memory rule visible and exposes pending state while asking", async () => {
    let release: (value: { pending: never[] }) => void = () => {};
    mocks.approvalsPending.mockImplementation(
      () =>
        new Promise((resolve) => {
          release = resolve;
        }),
    );
    renderHome();
    const input = await screen.findByRole("textbox", { name: "ask pam" });
    expect(input).toHaveAccessibleDescription(
      "Ask about PAM itself. I keep only this screen and the last three exchanges.",
    );
    expect(screen.getByText("Ask PAM", { selector: "label" })).toHaveAttribute("for", input.id);
    fireEvent.change(input, { target: { value: "what's waiting for my approval?" } });
    fireEvent.submit(screen.getByRole("form", { name: "Ask PAM" }));
    await waitFor(() => expect(input).toBeDisabled());
    expect(screen.getByRole("button", { name: "Ask" })).toHaveAttribute("aria-busy", "true");
    release({ pending: [] });
    await waitFor(() => expect(input).toBeEnabled());
    expect(await screen.findByText("Nothing waits for you.")).toBeInTheDocument();
  });

  it("shows the model line only when rephrase is on", async () => {
    const { unmount } = render(
      <App router={createAppRouter(createMemoryHistory({ initialEntries: ["/"] }))} />,
    );
    expect(await screen.findByText("No requests need your approval.")).toBeInTheDocument();
    expect(
      screen.queryByText("answers stay in my own words: no light model is set"),
    ).toBeNull();
    unmount();

    window.localStorage.setItem(rephraseStorageKey, "on");
    renderHome();
    expect(
      await screen.findByText("answers stay in my own words: no light model is set"),
    ).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Open Models" })).toBeInTheDocument();
  });

  it("renders a source failure as Pam's sentence, not a crash", async () => {
    mocks.approvalsPending.mockRejectedValue({
      cause: "bridge_unavailable",
      detail: "the daemon socket refused the connection",
      recovery: "Start the daemon and ask again.",
    });
    renderHome();
    await askQuestion("what's waiting for my approval?");
    expect(
      await screen.findByText(
        "I could not read the approval queue: the daemon socket refused the connection.",
      ),
    ).toBeInTheDocument();
  });
});
