import { QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { createAppQueryClient } from "../App";
import type { PolicyBody } from "../lib/ipc";
import { PolicyPanel, PolicyStatusLine, policySentence } from "./SettingsPolicy";

/**
 * The managed-policy view against a mocked bridge: one rendering per state, the digest as a
 * prefix, every diagnostic through SafeText, Check now as `admin.policy.reload`, the login-unit
 * compliance row, and the one status line Settings shows on every tab.
 */

const mocks = vi.hoisted(() => ({
  policyGet: vi.fn(),
  policyReload: vi.fn(),
  serviceInstall: vi.fn(),
}));

vi.mock("../lib/ipc", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../lib/ipc")>();
  return { ...actual, ...mocks };
});

const DIGEST = "ab12cd34ef56".padEnd(64, "0");
const NOW = Math.floor(Date.now() / 1000);

function body(overrides: Partial<PolicyBody> = {}): PolicyBody {
  return {
    state: "active",
    reason_code: null,
    reason_detail: null,
    origin: {
      path: "/Library/Application Support/pam/policy.json",
      platform: "macos",
      trust: {
        verdict: "trusted",
        code: null,
        recovery: null,
        owner: "root",
        writable_by_user: false,
        symlink: false,
        parents: "ok",
      },
    },
    digest: DIGEST,
    file_digest: DIGEST,
    revision: "2026-10-02.1",
    organization: "Example Corp",
    contact: "it@example.com",
    loaded_ts: NOW - 120,
    checked_ts: NOW - 30,
    last_good: null,
    rejected_leaves: 0,
    keys: [],
    diagnostics: [],
    compliance: { login_unit: { required: false, present: null } },
    ...overrides,
  };
}

function renderPanel() {
  render(
    <QueryClientProvider client={createAppQueryClient()}>
      <PolicyPanel />
    </QueryClientProvider>,
  );
}

beforeEach(() => {
  vi.clearAllMocks();
  mocks.policyGet.mockResolvedValue(body());
  mocks.policyReload.mockResolvedValue(body());
  mocks.serviceInstall.mockResolvedValue({});
});

describe("policy panel states", () => {
  it("none: says no policy is installed and shows no details", async () => {
    mocks.policyGet.mockResolvedValue(
      body({
        state: "none",
        origin: {
          path: null,
          platform: "macos",
          trust: { verdict: "absent", code: null, recovery: null },
        },
        digest: null,
        organization: null,
        contact: null,
        revision: null,
        loaded_ts: null,
        checked_ts: null,
      }),
    );
    renderPanel();
    expect(
      await screen.findByText("No managed policy is installed on this computer."),
    ).toBeInTheDocument();
    expect(screen.getByText("no policy")).toBeInTheDocument();
    expect(screen.queryByText("digest")).toBeNull();
    expect(screen.getByRole("button", { name: /Check now/ })).toBeEnabled();
  });

  it("active: names the organization, shows presence, digest prefix, times, path and trust", async () => {
    renderPanel();
    expect(await screen.findByText("Managed by Example Corp.")).toBeInTheDocument();
    expect(screen.getByText("active")).toBeInTheDocument();
    expect(screen.getByText("ab12cd34ef56")).toBeInTheDocument();
    expect(screen.queryByText(DIGEST)).toBeNull();
    expect(screen.getByText("2026-10-02.1")).toBeInTheDocument();
    expect(screen.getByText("it@example.com")).toBeInTheDocument();
    expect(screen.getByText("2m ago")).toBeInTheDocument();
    expect(screen.getByText("30s ago")).toBeInTheDocument();
    expect(
      screen.getByText("/Library/Application Support/pam/policy.json"),
    ).toBeInTheDocument();
    expect(screen.getByText("trusted · owner root")).toBeInTheDocument();
  });

  it("degraded: counts the problems, lists each diagnostic and the per-key states", async () => {
    mocks.policyGet.mockResolvedValue(
      body({
        state: "degraded",
        rejected_leaves: 1,
        diagnostics: [
          {
            code: "policy_bad_host",
            key: "network.engine_mirror",
            detail: 'host "mirror.exmaple" is not on the allowed list',
          },
        ],
        keys: [
          { key: "security.profile", tier: "A", mode: ["locked"], state: "applied" },
          {
            key: "network.engine_mirror",
            tier: "B",
            mode: ["default"],
            state: "rejected",
            code: "policy_bad_host",
            detail: "the mirror host is mistyped",
          },
        ],
      }),
    );
    renderPanel();
    expect(
      await screen.findByText(
        "Your organization's policy has 1 problem; the settings affected are listed below. Contact it@example.com.",
      ),
    ).toBeInTheDocument();
    const problems = within(screen.getByRole("group", { name: "policy diagnostics" }));
    expect(problems.getByText(/policy_bad_host/)).toBeInTheDocument();
    expect(problems.getByText(/is not on the allowed list/)).toBeInTheDocument();
    const keys = within(screen.getByRole("group", { name: "policy keys" }));
    expect(keys.getByText("security.profile")).toBeInTheDocument();
    expect(keys.getByText("applied")).toBeInTheDocument();
    expect(keys.getByText("rejected")).toBeInTheDocument();
    expect(keys.getByText("the mirror host is mistyped")).toBeInTheDocument();
  });

  it("last good: says the last good copy governs and which revision", async () => {
    mocks.policyGet.mockResolvedValue(
      body({
        state: "last_good",
        last_good: { digest: "99aabbccddee".padEnd(64, "1"), loaded_ts: NOW - 3_600 },
        reason_code: "policy_not_json",
        reason_detail: "the policy file is not valid JSON",
      }),
    );
    renderPanel();
    expect(
      await screen.findByText(/using the last good copy \(revision 2026-10-02.1\)/),
    ).toBeInTheDocument();
    expect(screen.getByText("last good copy", { selector: "span" })).toBeInTheDocument();
    expect(screen.getByText("the policy file is not valid JSON")).toBeInTheDocument();
    expect(screen.getByText(/99aabbccddee/)).toBeInTheDocument();
  });

  it("frozen: says widening changes are paused, and shows an untrusted file's recovery", async () => {
    mocks.policyGet.mockResolvedValue(
      body({
        state: "frozen",
        origin: {
          path: "/Library/Application Support/pam/policy.json",
          platform: "macos",
          trust: {
            verdict: "untrusted",
            code: "policy_writable_by_user",
            recovery: "Ask your administrator to make the file root-owned.",
            writable_by_user: true,
          },
        },
      }),
    );
    renderPanel();
    expect(
      await screen.findByText(/Changes that would widen what agents can do are paused/),
    ).toBeInTheDocument();
    expect(
      screen.getByText("untrusted · policy_writable_by_user · writable by you"),
    ).toBeInTheDocument();
    expect(
      screen.getByText("Ask your administrator to make the file root-owned."),
    ).toBeInTheDocument();
  });

  it("shows hidden characters in a diagnostic instead of hiding them", async () => {
    mocks.policyGet.mockResolvedValue(
      body({
        state: "degraded",
        rejected_leaves: 1,
        diagnostics: [{ code: "x", key: "k", detail: "bad‮value" }],
      }),
    );
    renderPanel();
    expect(
      await screen.findByTitle("a hidden character, shown as its escape"),
    ).toBeInTheDocument();
  });

  it("renders a failed read through the failure note", async () => {
    mocks.policyGet.mockRejectedValue({
      cause: "daemon_unreachable",
      detail: "the daemon did not answer",
      recovery: "Start the daemon.",
    });
    renderPanel();
    expect(await screen.findByText(/policy · daemon_unreachable/)).toBeInTheDocument();
    expect(screen.getByText("Start the daemon.")).toBeInTheDocument();
  });
});

describe("check now", () => {
  it("calls admin.policy.reload and shows the fresh body", async () => {
    mocks.policyReload.mockResolvedValue(body({ state: "degraded", rejected_leaves: 2 }));
    renderPanel();
    await screen.findByText("Managed by Example Corp.");
    fireEvent.click(screen.getByRole("button", { name: /Check now/ }));
    await waitFor(() => expect(mocks.policyReload).toHaveBeenCalledTimes(1));
    expect(await screen.findByText(/has 2 problems/)).toBeInTheDocument();
  });

  it("renders a refused reload through the failure note", async () => {
    mocks.policyReload.mockRejectedValue({
      cause: "invalid_admin_args",
      detail: "reload takes no arguments",
      recovery: "Send an empty object.",
    });
    renderPanel();
    await screen.findByText("Managed by Example Corp.");
    fireEvent.click(screen.getByRole("button", { name: /Check now/ }));
    expect(await screen.findByText(/policy · invalid_admin_args/)).toBeInTheDocument();
  });
});

describe("login unit compliance", () => {
  it("asks for the one-click install when the policy requires it and it is missing", async () => {
    mocks.policyGet.mockResolvedValue(
      body({ compliance: { login_unit: { required: true, present: false } } }),
    );
    renderPanel();
    expect(
      await screen.findByText("Your organization requires PAM to start at login."),
    ).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Install" }));
    await waitFor(() => expect(mocks.serviceInstall).toHaveBeenCalledTimes(1));
  });

  it("stays quiet when it is present or cannot be told", async () => {
    mocks.policyGet.mockResolvedValue(
      body({ compliance: { login_unit: { required: true, present: null } } }),
    );
    renderPanel();
    await screen.findByText("Managed by Example Corp.");
    expect(screen.queryByText(/requires PAM to start at login/)).toBeNull();
  });
});

describe("policy status line", () => {
  function renderLine(onOpen = vi.fn()) {
    render(
      <QueryClientProvider client={createAppQueryClient()}>
        <PolicyStatusLine onOpen={onOpen} />
      </QueryClientProvider>,
    );
    return onOpen;
  }

  it("says managed when active, and opens the policy view", async () => {
    const onOpen = renderLine();
    const line = await screen.findByRole("status", { name: "managed policy status" });
    expect(line).toHaveTextContent("Managed by your organization's policy.");
    fireEvent.click(within(line).getByRole("button", { name: "View policy" }));
    expect(onOpen).toHaveBeenCalledTimes(1);
  });

  it.each(["degraded", "last_good", "frozen"] as const)("warns when %s", async (state) => {
    mocks.policyGet.mockResolvedValue(body({ state, rejected_leaves: 1 }));
    renderLine();
    const line = await screen.findByRole("status", { name: "managed policy status" });
    expect(line).toHaveTextContent(policySentence(body({ state, rejected_leaves: 1 })));
    expect(within(line).queryByText("managed")).toBeNull();
  });

  it("shows nothing without a policy or when the read fails", async () => {
    mocks.policyGet.mockResolvedValue(body({ state: "none" }));
    const { unmount } = render(
      <QueryClientProvider client={createAppQueryClient()}>
        <PolicyStatusLine onOpen={vi.fn()} />
      </QueryClientProvider>,
    );
    await waitFor(() => expect(mocks.policyGet).toHaveBeenCalled());
    expect(screen.queryByRole("status", { name: "managed policy status" })).toBeNull();
    unmount();

    mocks.policyGet.mockRejectedValue(new Error("down"));
    renderLine();
    await waitFor(() => expect(mocks.policyGet).toHaveBeenCalledTimes(2));
    expect(screen.queryByRole("status", { name: "managed policy status" })).toBeNull();
  });
});
