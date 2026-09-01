import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { Beacon } from "./Beacon";
import { TopStrip } from "./TopStrip";

describe("Beacon", () => {
  it("defaults to the down state", () => {
    render(<Beacon />);
    const beacon = screen.getByRole("status", { name: "daemon unreachable" });
    expect(beacon.innerHTML).toContain("bg-beacon-red");
  });

  it.each([
    ["connected", "daemon connected", "bg-beacon-green"],
    ["pending", "daemon approval pending", "bg-beacon-amber"],
    ["down", "daemon unreachable", "bg-beacon-red"],
  ] as const)("renders the %s state", (state, label, tokenClass) => {
    render(<Beacon state={state} />);
    const beacon = screen.getByRole("status", { name: label });
    expect(beacon.innerHTML).toContain(tokenClass);
  });

  it("breathes — the glow layer uses the breathe motion token", () => {
    render(<Beacon state="connected" />);
    const beacon = screen.getByRole("status", { name: "daemon connected" });
    expect(beacon.innerHTML).toContain("animate-breathe");
  });
});

describe("TopStrip", () => {
  it("is a drag region on the strip and its non-interactive children", () => {
    render(<TopStrip />);
    const strip = document.querySelector("header[data-tauri-drag-region]");
    expect(strip).not.toBeNull();
    // Tauri honors the attribute per element, so the wordmark carries it too.
    expect(screen.getByText("PAM")).toHaveAttribute("data-tauri-drag-region");
    // …while the theme and mode controls stay clickable.
    for (const control of screen.getAllByRole("button")) {
      expect(control).not.toHaveAttribute("data-tauri-drag-region");
    }
    expect(screen.getAllByRole("button")).toHaveLength(2);
  });
});
