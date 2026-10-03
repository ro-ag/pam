import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { ContainmentNotice } from "./ContainmentNotice";

/**
 * The notice reads the daemon's `status.containment` and speaks only when
 * this machine cannot contain command workloads: never while the daemon is
 * unreachable, never on an older daemon without the block, never when
 * containment is available.
 */

const mocks = vi.hoisted(() => ({ daemonStatus: vi.fn() }));

vi.mock("../lib/ipc", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../lib/ipc")>();
  return { ...actual, ...mocks };
});

const UNAVAILABLE = {
  available: false,
  cause: "command_containment_unavailable",
  detail: "command containment is supported only on macOS",
  affects: ["flow command steps", "guarded landing"],
};

function renderNotice(subject: "flows" | "landing") {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <p>page</p>
      <ContainmentNotice subject={subject} />
    </QueryClientProvider>,
  );
}

beforeEach(() => {
  mocks.daemonStatus.mockReset();
});

describe("ContainmentNotice", () => {
  it("tells the flows screen that command steps are refused here", async () => {
    mocks.daemonStatus.mockResolvedValue({
      connected: true,
      status: { containment: UNAVAILABLE },
    });
    renderNotice("flows");
    const note = await screen.findByRole("note", { name: "command steps unavailable" });
    expect(note).toHaveTextContent("Command steps cannot run on this machine.");
    expect(note).toHaveTextContent("Flows that use only connectors and models still run");
    expect(note).toHaveTextContent(
      "command_containment_unavailable · command containment is supported only on macOS",
    );
  });

  it("tells the landing settings that a landing is refused here", async () => {
    mocks.daemonStatus.mockResolvedValue({
      connected: true,
      status: { containment: UNAVAILABLE },
    });
    renderNotice("landing");
    const note = await screen.findByRole("note", { name: "guarded landing unavailable" });
    expect(note).toHaveTextContent("Guarded landing cannot run on this machine.");
  });

  it.each([
    [
      "containment is available",
      {
        connected: true,
        status: { containment: { ...UNAVAILABLE, available: true, cause: null } },
      },
    ],
    ["the daemon predates the block", { connected: true, status: { daemon_version: "0.4.3" } }],
    ["the daemon is unreachable", { connected: false, status: { containment: UNAVAILABLE } }],
  ])("stays silent when %s", async (_label, reply) => {
    mocks.daemonStatus.mockResolvedValue(reply);
    renderNotice("flows");
    await screen.findByText("page");
    await vi.waitFor(() => expect(mocks.daemonStatus).toHaveBeenCalled());
    // Let the query settle before asserting absence.
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(screen.queryByRole("note")).not.toBeInTheDocument();
  });
});
