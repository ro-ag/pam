import { fireEvent, render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { initWorkspace, workspaceSnapshot } from "../../lib/workspace";
import { WorkspaceMenu } from "./WorkspaceMenu";

const navigate = vi.hoisted(() => vi.fn());
vi.mock("@tanstack/react-router", () => ({
  useRouter: () => ({ navigate }),
  useRouterState: ({ select }: { select: (state: { location: { href: string } }) => string }) =>
    select({ location: { href: "/settings#models" } }),
}));

beforeEach(() => {
  navigate.mockReset();
  window.localStorage.clear();
  initWorkspace();
  HTMLDialogElement.prototype.showModal = function () {
    this.setAttribute("open", "");
  };
  HTMLDialogElement.prototype.close = function () {
    this.removeAttribute("open");
  };
});

function openMenu() {
  render(<WorkspaceMenu />);
  const trigger = screen.getByRole("button", { name: "Workspace" });
  fireEvent.click(trigger);
  return trigger;
}

describe("workspace controls", () => {
  it("opens a labelled native dialog and restores focus on Escape", () => {
    const trigger = openMenu();
    expect(screen.getByRole("dialog", { name: "Workspace" })).toHaveAttribute("open");
    fireEvent(screen.getByRole("dialog"), new Event("cancel", { bubbles: false }));
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(trigger).toHaveFocus();
  });
  it.each([
    ["Monitor", "/activity", "compact"],
    ["Build", "/flows", "expanded"],
  ])("%s only navigates and updates layout", (label, href, sidebar) => {
    openMenu();
    fireEvent.click(screen.getByRole("button", { name: label }));
    expect(navigate).toHaveBeenCalledExactlyOnceWith({ href });
    expect(workspaceSnapshot()).toMatchObject({ sidebar, width: "full" });
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });
  it("focuses the current screen without navigating", () => {
    openMenu();
    fireEvent.click(screen.getByRole("button", { name: "Focus" }));
    expect(navigate).not.toHaveBeenCalled();
    expect(workspaceSnapshot().width).toBe("focused");
  });
  it("changes controls, saves, restores, and deletes a named layout", () => {
    openMenu();
    fireEvent.click(screen.getByRole("button", { name: "Compact" }));
    fireEvent.click(screen.getByRole("button", { name: "Focused" }));
    expect(screen.getByRole("button", { name: "Compact" })).toHaveAttribute(
      "aria-pressed",
      "true",
    );
    fireEvent.change(screen.getByLabelText("Layout name"), {
      target: { value: "Models desk" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Save" }));
    expect(screen.getByRole("status")).toHaveTextContent("Layout saved.");
    fireEvent.click(screen.getByRole("button", { name: "Expanded" }));
    fireEvent.click(screen.getByRole("button", { name: "Models desk" }));
    expect(navigate).toHaveBeenCalledWith({ href: "/settings#models" });
    expect(workspaceSnapshot()).toMatchObject({ sidebar: "compact", width: "focused" });
    fireEvent.click(screen.getByRole("button", { name: "Workspace" }));
    fireEvent.click(screen.getByRole("button", { name: "Delete layout Models desk" }));
    expect(screen.queryByRole("button", { name: "Models desk" })).not.toBeInTheDocument();
  });
});
