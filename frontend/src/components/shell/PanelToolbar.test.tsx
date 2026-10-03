import { createMemoryHistory } from "@tanstack/react-router";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  daemonStatus: vi.fn(),
  daemonStart: vi.fn(),
  approvalsPending: vi.fn(),
  subscribeEvents: vi.fn(),
}));

vi.mock("../../lib/ipc", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../lib/ipc")>();
  return { ...actual, ...mocks };
});

import App from "../../App";
import { createAppRouter } from "../../router";
import { initWorkspace } from "../../lib/workspace";

function mount() {
  render(<App router={createAppRouter(createMemoryHistory({ initialEntries: ["/"] }))} />);
}

const stopped = { connected: false, status: null, base_dir: "/x", stopped_by_you: true };
const up = { connected: true, status: {}, base_dir: "/x", stopped_by_you: false };

beforeEach(() => {
  vi.clearAllMocks();
  window.localStorage.clear();
  initWorkspace();
  mocks.subscribeEvents.mockRejectedValue(new Error("no bridge"));
  mocks.approvalsPending.mockResolvedValue({ pending: [] });
});

describe("the toolbar beacon after the human's Stop", () => {
  it("says stopped by you and offers Start, which starts the daemon and nothing else does", async () => {
    mocks.daemonStatus.mockResolvedValue(stopped);
    // What the bridge does: lowers its flag, so the polls that follow find the daemon running.
    mocks.daemonStart.mockImplementation(async () => {
      mocks.daemonStatus.mockResolvedValue(up);
      return up;
    });
    mount();
    expect(
      await screen.findByRole("status", { name: "daemon stopped by you" }),
    ).toHaveTextContent("Stopped by you");
    expect(mocks.daemonStart).not.toHaveBeenCalled();

    fireEvent.click(screen.getByRole("button", { name: "Start" }));
    await waitFor(() => expect(mocks.daemonStart).toHaveBeenCalledTimes(1));
    expect(await screen.findByRole("status", { name: "daemon connected" })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Start" })).not.toBeInTheDocument();
  });

  it("offers no Start for a daemon that is just down", async () => {
    mocks.daemonStatus.mockResolvedValue({ connected: false, status: null, base_dir: "/x" });
    mount();
    expect(
      await screen.findByRole("status", { name: "daemon unreachable" }),
    ).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Start" })).not.toBeInTheDocument();
  });
});
