import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { useState } from "react";
import { describe, expect, it, vi } from "vitest";

import type { ProjectView } from "../selectors";
import { ProjectMenu, ResizeSeparator } from "./Shell";

const projects: ProjectView[] = [
  { handle: "payments", name: "payments-api", rootLabel: "/work/payments-api", branch: "main", health: "ready", queuedCount: 0 },
  { handle: "ledger", name: "ledger-web", rootLabel: "/work/ledger-web", branch: "feature/ledger", health: "busy", queuedCount: 1 },
  { handle: "docs", name: "docs", rootLabel: "/work/docs", branch: null, health: "attention", queuedCount: null },
];

function ControlledProjectMenu({
  onOpenChange = vi.fn(),
  onSelect = vi.fn(),
}: {
  onOpenChange?: (open: boolean) => void;
  onSelect?: (project: ProjectView) => void;
}) {
  const [open, setOpen] = useState(false);
  return (
    <ProjectMenu
      active={projects[0]}
      projects={projects}
      open={open}
      onOpenChange={(nextOpen) => {
        onOpenChange(nextOpen);
        setOpen(nextOpen);
      }}
      onSelect={onSelect}
    />
  );
}

interface CaptureStubs {
  captured: Set<number>;
  setPointerCapture: ReturnType<typeof vi.fn>;
  hasPointerCapture: ReturnType<typeof vi.fn>;
  releasePointerCapture: ReturnType<typeof vi.fn>;
}

function installPointerCaptureStubs(element: HTMLElement): CaptureStubs {
  const captured = new Set<number>();
  const setPointerCapture = vi.fn((pointerId: number) => captured.add(pointerId));
  const hasPointerCapture = vi.fn((pointerId: number) => captured.has(pointerId));
  const releasePointerCapture = vi.fn((pointerId: number) => captured.delete(pointerId));
  Object.assign(element, { setPointerCapture, hasPointerCapture, releasePointerCapture });
  return { captured, setPointerCapture, hasPointerCapture, releasePointerCapture };
}

function dispatchPointer(
  element: HTMLElement,
  type: string,
  properties: Record<string, number | boolean>,
): void {
  const event = new Event(type, { bubbles: true, cancelable: true });
  Object.defineProperties(event, Object.fromEntries(
    Object.entries(properties).map(([key, value]) => [key, { value }]),
  ));
  fireEvent(element, event);
}

function renderSeparator({
  collapsed = false,
  width = 248,
  viewportWidth = 1_400,
  onResizePreview = vi.fn(),
  onResizeCommit = vi.fn(),
  onToggle = vi.fn(),
}: Partial<React.ComponentProps<typeof ResizeSeparator>> = {}) {
  render(
    <ResizeSeparator
      collapsed={collapsed}
      width={width}
      viewportWidth={viewportWidth}
      onResizePreview={onResizePreview}
      onResizeCommit={onResizeCommit}
      onToggle={onToggle}
    />,
  );
  return screen.getByRole("separator", { name: "Resize project sidebar" });
}

describe("ProjectMenu", () => {
  it("uses controlled state and restores trigger focus after keyboard dismissal", async () => {
    const user = userEvent.setup();
    const onOpenChange = vi.fn();
    render(<ControlledProjectMenu onOpenChange={onOpenChange} />);

    const switcher = screen.getByRole("button", { name: "payments-api" });
    switcher.focus();
    await user.keyboard("{ArrowDown}");

    const menu = await screen.findByRole("menu");
    expect(menu).toHaveClass("project-menu");
    expect(menu).toHaveAttribute("aria-label", "Registered projects");
    expect(menu.closest(".project-menu-popover")).toBeInTheDocument();
    expect(menu.closest(".project-menu-wrap")).toBeNull();
    expect(onOpenChange).toHaveBeenCalledWith(true);

    const payments = screen.getByRole("menuitemradio", { name: /payments-api/ });
    const ledger = screen.getByRole("menuitemradio", { name: /ledger-web/ });
    const docs = screen.getByRole("menuitemradio", { name: /^docs/ });
    expect(payments).toHaveClass("project-menu-item");
    expect(payments).toHaveAttribute("aria-checked", "true");
    expect(payments).toHaveAccessibleName(/Health: ready/i);
    expect(ledger).toHaveAccessibleName(/Health: busy/i);
    expect(docs).toHaveAccessibleName(/Health: attention/i);
    await waitFor(() => expect(payments).toHaveFocus());

    await user.keyboard("{ArrowDown}");
    await waitFor(() => expect(ledger).toHaveFocus());
    await user.keyboard("{End}");
    await waitFor(() => expect(docs).toHaveFocus());
    await user.keyboard("{Home}");
    await waitFor(() => expect(payments).toHaveFocus());
    await user.keyboard("{Escape}");

    await waitFor(() => expect(screen.queryByRole("menu")).not.toBeInTheDocument());
    expect(onOpenChange).toHaveBeenLastCalledWith(false);
    await waitFor(() => expect(switcher).toHaveFocus());
  });

  it("closes after keyboard selection and restores the exact opener", async () => {
    const user = userEvent.setup();
    const onSelect = vi.fn();
    render(<ControlledProjectMenu onSelect={onSelect} />);

    const switcher = screen.getByRole("button", { name: "payments-api" });
    switcher.focus();
    await user.keyboard("{ArrowDown}");
    await waitFor(() => expect(screen.getByRole("menuitemradio", { name: /payments-api/ })).toHaveFocus());
    await user.keyboard("{ArrowDown}{Enter}");

    await waitFor(() => expect(onSelect).toHaveBeenCalledWith(projects[1]));
    await waitFor(() => expect(screen.queryByRole("menu")).not.toBeInTheDocument());
    await waitFor(() => expect(switcher).toHaveFocus());
  });
});

describe("ResizeSeparator", () => {
  it("reports responsive minimum, maximum, and clamped current widths", () => {
    const { rerender } = render(
      <ResizeSeparator
        collapsed={false}
        width={500}
        viewportWidth={1_400}
        onResizePreview={vi.fn()}
        onResizeCommit={vi.fn()}
        onToggle={vi.fn()}
      />,
    );
    const separator = screen.getByRole("separator", { name: "Resize project sidebar" });
    expect(separator).toHaveAttribute("aria-valuemin", "180");
    expect(separator).toHaveAttribute("aria-valuemax", "420");
    expect(separator).toHaveAttribute("aria-valuenow", "420");

    rerender(
      <ResizeSeparator
        collapsed={false}
        width={400}
        viewportWidth={640}
        onResizePreview={vi.fn()}
        onResizeCommit={vi.fn()}
        onToggle={vi.fn()}
      />,
    );
    expect(separator).toHaveAttribute("aria-valuemin", "180");
    expect(separator).toHaveAttribute("aria-valuemax", "288");
    expect(separator).toHaveAttribute("aria-valuenow", "288");
  });

  it("commits exact fine, coarse, and boundary keyboard widths", () => {
    const onResizeCommit = vi.fn();
    const separator = renderSeparator({ onResizeCommit });

    for (const key of ["ArrowLeft", "ArrowRight", "PageDown", "PageUp", "Home", "End"]) {
      fireEvent.keyDown(separator, { key });
    }

    expect(onResizeCommit.mock.calls).toEqual([
      [232],
      [264],
      [184],
      [312],
      [180],
      [420],
    ]);
  });

  it("is disabled and removed from tab order while collapsed", () => {
    const onResizeCommit = vi.fn();
    const separator = renderSeparator({ collapsed: true, onResizeCommit });

    expect(separator).toHaveAttribute("aria-disabled", "true");
    expect(separator).toHaveAttribute("tabindex", "-1");
    fireEvent.keyDown(separator, { key: "ArrowRight" });
    expect(onResizeCommit).not.toHaveBeenCalled();
  });

  it("captures only a primary pointer, previews clamped width, and commits once on pointerup", () => {
    const onResizePreview = vi.fn();
    const onResizeCommit = vi.fn();
    const separator = renderSeparator({ onResizePreview, onResizeCommit });
    const capture = installPointerCaptureStubs(separator);

    dispatchPointer(separator, "pointerdown", { pointerId: 4, isPrimary: false, button: 0, clientX: 248 });
    dispatchPointer(separator, "pointerdown", { pointerId: 5, isPrimary: true, button: 1, clientX: 248 });
    expect(capture.setPointerCapture).not.toHaveBeenCalled();

    dispatchPointer(separator, "pointerdown", { pointerId: 7, isPrimary: true, button: 0, clientX: 248 });
    expect(capture.setPointerCapture).toHaveBeenCalledOnce();
    expect(capture.setPointerCapture).toHaveBeenCalledWith(7);

    dispatchPointer(separator, "pointermove", { pointerId: 7, clientX: -1_000 });
    dispatchPointer(separator, "pointermove", { pointerId: 7, clientX: 1_000 });
    expect(onResizePreview.mock.calls).toEqual([[180], [420]]);

    dispatchPointer(separator, "pointerup", { pointerId: 7 });
    dispatchPointer(separator, "lostpointercapture", { pointerId: 7 });
    dispatchPointer(separator, "pointerup", { pointerId: 7 });
    expect(onResizeCommit).toHaveBeenCalledOnce();
    expect(onResizeCommit).toHaveBeenCalledWith(420);
    expect(capture.releasePointerCapture).toHaveBeenCalledOnce();
    expect(capture.releasePointerCapture).toHaveBeenCalledWith(7);
  });

  it("cleans up pointer cancellation without double commit", () => {
    const onResizeCommit = vi.fn();
    const separator = renderSeparator({ onResizeCommit });
    const capture = installPointerCaptureStubs(separator);

    dispatchPointer(separator, "pointerdown", { pointerId: 8, isPrimary: true, button: 0, clientX: 248 });
    dispatchPointer(separator, "pointermove", { pointerId: 8, clientX: 300 });
    dispatchPointer(separator, "pointercancel", { pointerId: 8 });
    dispatchPointer(separator, "lostpointercapture", { pointerId: 8 });
    dispatchPointer(separator, "pointerup", { pointerId: 8 });

    expect(onResizeCommit).toHaveBeenCalledOnce();
    expect(onResizeCommit).toHaveBeenCalledWith(300);
    expect(capture.releasePointerCapture).toHaveBeenCalledOnce();
    expect(capture.captured).not.toContain(8);
  });

  it("commits lost capture once without trying to release missing capture", () => {
    const onResizeCommit = vi.fn();
    const separator = renderSeparator({ onResizeCommit });
    const capture = installPointerCaptureStubs(separator);

    dispatchPointer(separator, "pointerdown", { pointerId: 9, isPrimary: true, button: 0, clientX: 248 });
    dispatchPointer(separator, "pointermove", { pointerId: 9, clientX: 280 });
    capture.captured.delete(9);
    dispatchPointer(separator, "lostpointercapture", { pointerId: 9 });
    dispatchPointer(separator, "pointercancel", { pointerId: 9 });

    expect(onResizeCommit).toHaveBeenCalledOnce();
    expect(onResizeCommit).toHaveBeenCalledWith(280);
    expect(capture.hasPointerCapture).toHaveBeenCalledWith(9);
    expect(capture.releasePointerCapture).not.toHaveBeenCalled();
  });
});
