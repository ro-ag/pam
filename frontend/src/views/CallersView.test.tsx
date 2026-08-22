import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { useState } from "react";
import { describe, expect, it, vi } from "vitest";
import { fixtureBridge, type FixtureScenario } from "../fixtures";
import { selectControlCenter } from "../selectors";
import { CallersView, type CallersViewProps } from "./CallersView";

async function callersProps(scenario: FixtureScenario = "solved") {
  const bridge = fixtureBridge(scenario);
  const snapshot = await bridge.bootstrap();
  const catalog = await bridge.catalog();
  return {
    bridge,
    fence: snapshot.fence,
    data: selectControlCenter(snapshot.data, catalog, true),
    onSelectProject: vi.fn(),
    onCopy: vi.fn(),
    onEvidence: vi.fn(),
    onContinue: vi.fn(),
    onOpenQueue: vi.fn(),
    onOpenApproval: vi.fn(),
    onRecoverDaemon: vi.fn(),
    onRefresh: vi.fn(),
    onRegisterCaller: vi.fn(),
    registrationBusy: false,
  };
}

function Harness(props: Omit<CallersViewProps, "projectMenuOpen" | "onProjectMenuOpenChange">) {
  const [open, setOpen] = useState(false);
  return (
    <CallersView
      {...props}
      projectMenuOpen={open}
      onProjectMenuOpenChange={setOpen}
    />
  );
}

describe("CallersView", () => {
  it("lists registered callers with registration dates and revoked badges", async () => {
    const props = await callersProps();
    render(<Harness {...props} />);

    expect(screen.getByRole("heading", { name: "Callers" })).toBeInTheDocument();
    expect(await screen.findByText("gui:pam-desktop")).toBeInTheDocument();
    expect(screen.getByText("cli:release-agent")).toBeInTheDocument();
    const revokedRow = screen.getByText("cli:retired-agent").closest("article");
    expect(revokedRow).not.toBeNull();
    expect(within(revokedRow!).getByText("revoked")).toBeInTheDocument();
    expect(screen.getAllByText("active")).toHaveLength(2);
    expect(screen.getAllByText(/^Registered .*\d{4}$/)).toHaveLength(3);
  });

  it("refreshes the caller registry on demand", async () => {
    const user = userEvent.setup();
    const props = await callersProps();
    const spy = vi.spyOn(props.bridge, "callerRegistry");
    render(<Harness {...props} />);
    await screen.findByText("gui:pam-desktop");
    expect(spy).toHaveBeenCalledTimes(1);

    await user.click(screen.getByRole("button", { name: "Refresh callers" }));
    await waitFor(() => expect(spy).toHaveBeenCalledTimes(2));
  });

  it("drills into the active project through Current and Access sub-tabs", async () => {
    const user = userEvent.setup();
    const props = await callersProps();
    render(<Harness {...props} />);

    expect(screen.getByRole("tab", { name: "Current" })).toHaveAttribute("aria-selected", "true");
    expect(await screen.findByRole("heading", { name: "Ready for the next agent" })).toBeInTheDocument();

    await user.click(screen.getByRole("tab", { name: "Access" }));
    expect(await screen.findByRole("heading", { name: "Authorized capabilities" })).toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: "Ready for the next agent" })).not.toBeInTheDocument();
  });

  it("keeps project browsing available while the daemon is offline", async () => {
    const user = userEvent.setup();
    const props = await callersProps("offline");
    render(<Harness {...props} />);

    expect(await screen.findByText(/caller registry is not being served/)).toBeInTheDocument();
    expect(screen.getByText(/Start PAM to read the registered callers/)).toBeInTheDocument();

    const switcher = screen.getByRole("button", { name: "payments-api" });
    switcher.focus();
    await user.keyboard("{ArrowDown}");
    const menu = await screen.findByRole("menu");
    expect(menu).toHaveAttribute("aria-label", "Registered projects");
    expect(within(menu).getAllByRole("menuitemradio")).toHaveLength(3);
    await user.click(within(menu).getByRole("menuitemradio", { name: /ledger-web/ }));
    expect(props.onSelectProject).toHaveBeenCalledWith(expect.objectContaining({ name: "ledger-web" }));
  });
});
