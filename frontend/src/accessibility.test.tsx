import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { App } from "./App";
import { fixtureBridge } from "./fixtures";

describe("DOM accessibility contract", () => {
  it("exposes landmarks, named controls, current navigation, and a skip target", async () => {
    render(<App bridge={fixtureBridge()} />);
    await screen.findByRole("heading", { name: "payments-api" });

    expect(screen.getByRole("complementary", { name: "Project navigation" })).toBeInTheDocument();
    expect(screen.getByRole("navigation", { name: "Primary" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Current" })).toHaveAttribute("aria-current", "page");
    expect(screen.getByRole("button", { name: "Collapse sidebar" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Refresh project" })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Skip to content" })).toHaveAttribute("href", "#main-content");
    expect(document.querySelectorAll("button:not([aria-label]):empty")).toHaveLength(0);
  });
});
