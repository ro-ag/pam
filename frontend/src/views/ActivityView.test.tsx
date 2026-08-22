import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { fixtureBridge, type FixtureScenario } from "../fixtures";
import { selectControlCenter } from "../selectors";
import { ActivityView } from "./ActivityView";

async function activityProps(scenario: FixtureScenario = "solved") {
  const bridge = fixtureBridge(scenario);
  const snapshot = await bridge.bootstrap();
  const catalog = await bridge.catalog();
  return {
    bridge,
    fence: snapshot.fence,
    data: selectControlCenter(snapshot.data, catalog, true),
    pending: false,
    onStartDaemon: vi.fn(),
  };
}

describe("ActivityView", () => {
  it("renders daemon health and the bounded activity feed", async () => {
    const props = await activityProps();
    render(<ActivityView {...props} />);

    expect(screen.getByRole("heading", { name: "Activity" })).toBeInTheDocument();
    expect(screen.getByText("PAM is on watch")).toBeInTheDocument();
    expect(screen.getByText("Daemon fixture-0.1.0")).toBeInTheDocument();
    expect(screen.getByText("Queue depth")).toBeInTheDocument();

    expect(await screen.findByText("project.current")).toBeInTheDocument();
    expect(screen.getByText(/gui:pam-desktop · payments-api · served/)).toBeInTheDocument();
    expect(screen.getByText(/cli:release-agent · ledger-web/)).toBeInTheDocument();
    expect(screen.getAllByText("allowed")).toHaveLength(3);
    expect(screen.getByText("approval required")).toBeInTheDocument();
  });

  it("refreshes the feed on demand", async () => {
    const user = userEvent.setup();
    const props = await activityProps();
    const spy = vi.spyOn(props.bridge, "daemonActivity");
    render(<ActivityView {...props} />);
    await screen.findByText("project.current");
    expect(spy).toHaveBeenCalledTimes(1);

    await user.click(screen.getByRole("button", { name: "Refresh activity" }));
    await waitFor(() => expect(spy).toHaveBeenCalledTimes(2));
  });

  it("renders the exact empty feed without inventing events", async () => {
    const props = await activityProps("empty");
    render(<ActivityView {...props} />);

    expect(await screen.findByText(/No recent activity/)).toBeInTheDocument();
  });

  it("renders a calm unavailable feed with its recovery guidance", async () => {
    const props = await activityProps();
    props.bridge.daemonActivity = vi.fn().mockResolvedValue({
      status: "unavailable",
      failure: { code: "feed_unavailable", detail: "The activity feed is not being served.", recovery: "Retry shortly." },
    });
    render(<ActivityView {...props} />);

    expect(await screen.findByText("The activity feed is not being served. Retry shortly.")).toBeInTheDocument();
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });

  it("keeps a transport failure retryable inside the feed panel", async () => {
    const props = await activityProps();
    props.bridge.daemonActivity = vi.fn().mockRejectedValue(new Error("daemon socket unavailable"));
    render(<ActivityView {...props} />);

    expect(await screen.findByRole("alert")).toHaveTextContent("daemon socket unavailable");
    expect(screen.getByRole("button", { name: "Refresh activity" })).toBeEnabled();
  });

  it("shows a calm paused state offline and wires the start control", async () => {
    const user = userEvent.setup();
    const props = await activityProps("offline");
    const spy = vi.spyOn(props.bridge, "daemonActivity");
    render(<ActivityView {...props} />);

    expect(screen.getByRole("heading", { name: "PAM is paused" })).toBeInTheDocument();
    expect(screen.getByText(/pick up where it left off/)).toBeInTheDocument();
    expect(spy).not.toHaveBeenCalled();
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Start PAM" }));
    expect(props.onStartDaemon).toHaveBeenCalledTimes(1);
  });
});
