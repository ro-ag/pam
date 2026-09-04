import { fireEvent, render, screen } from "@testing-library/react";
import { useState } from "react";
import { describe, expect, it } from "vitest";
import { PagePane, PageTabs } from "./PageTabs";

const tabs = [
  { id: "first", label: "First" },
  { id: "second", label: "Second" },
] as const;

function Workspace() {
  const [selected, setSelected] = useState<"first" | "second">("first");
  return (
    <>
      <PageTabs
        id="example"
        label="Tasks"
        tabs={tabs}
        selected={selected}
        onSelect={setSelected}
      />
      {tabs.map((tab) => (
        <PagePane key={tab.id} id="example" tab={tab.id} active={selected === tab.id}>
          <input aria-label={`${tab.label} draft`} defaultValue="" />
        </PagePane>
      ))}
    </>
  );
}

describe("workspace tabs", () => {
  it("supports arrows, Home and End with roving focus and associated panels", () => {
    render(<Workspace />);
    const first = screen.getByRole("tab", { name: "First" });
    const second = screen.getByRole("tab", { name: "Second" });
    expect(first).toHaveAttribute("tabindex", "0");
    expect(second).toHaveAttribute("tabindex", "-1");
    fireEvent.keyDown(first, { key: "ArrowLeft" });
    expect(second).toHaveFocus();
    expect(second).toHaveAttribute("aria-selected", "true");
    expect(screen.getByRole("tabpanel", { name: "Second" }).id).toBe(
      second.getAttribute("aria-controls"),
    );
    fireEvent.keyDown(second, { key: "ArrowRight" });
    expect(first).toHaveFocus();
    fireEvent.keyDown(first, { key: "End" });
    expect(second).toHaveFocus();
    fireEvent.keyDown(second, { key: "Home" });
    expect(first).toHaveFocus();
  });

  it("mounts panes on first visit and preserves their drafts and scroll positions", () => {
    render(<Workspace />);
    expect(screen.queryByLabelText("Second draft")).not.toBeInTheDocument();
    const pane = screen.getByRole("tabpanel", { name: "First" });
    pane.scrollTop = 150;
    fireEvent.change(screen.getByLabelText("First draft"), { target: { value: "keep this" } });
    fireEvent.click(screen.getByRole("tab", { name: "Second" }));
    expect(screen.getAllByRole("tabpanel")).toHaveLength(1);
    expect(screen.getByRole("textbox", { name: "Second draft" })).toBeInTheDocument();
    fireEvent.click(screen.getByRole("tab", { name: "First" }));
    expect(screen.getByLabelText("First draft")).toHaveValue("keep this");
    expect(screen.getByRole("tabpanel", { name: "First" })).toBe(pane);
    expect(pane.scrollTop).toBe(150);
  });
});
