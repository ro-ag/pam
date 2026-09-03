import { createMemoryHistory } from "@tanstack/react-router";
import { fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import App from "./App";
import { createAppRouter } from "./router";

/** Mount the shell at a path on a fresh, isolated memory history. */
function renderShell(path = "/") {
  const router = createAppRouter(createMemoryHistory({ initialEntries: [path] }));
  render(<App router={router} />);
  return router;
}

afterEach(() => {
  window.localStorage.clear();
  delete document.documentElement.dataset.theme;
  delete document.documentElement.dataset.mode;
});

describe("shell routing", () => {
  it("redirects / to the Activity screen, the default view", async () => {
    const router = renderShell("/");
    expect(await screen.findByRole("heading", { name: "Activity" })).toBeInTheDocument();
    expect(router.state.location.pathname).toBe("/activity");
  });

  it("switches the work panel content when a sidebar link is clicked", async () => {
    renderShell("/");
    await screen.findByRole("heading", { name: "Activity" });
    fireEvent.click(screen.getByRole("link", { name: "Approvals" }));
    expect(await screen.findByRole("heading", { name: "Approvals" })).toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: "Activity" })).not.toBeInTheDocument();
  });

  it("marks only the current screen's nav item as active", async () => {
    renderShell("/approvals");
    await screen.findByRole("heading", { name: "Approvals" });
    expect(screen.getByRole("link", { name: "Approvals" })).toHaveAttribute(
      "aria-current",
      "page",
    );
    expect(screen.getByRole("link", { name: "Activity" })).not.toHaveAttribute("aria-current");
  });

  it("renders all five nav entries, every one of them a real link", async () => {
    renderShell("/");
    await screen.findByRole("heading", { name: "Activity" });
    for (const entry of ["Activity", "Approvals", "Flows", "Models", "Settings"]) {
      expect(screen.getByRole("link", { name: entry })).toBeInTheDocument();
    }
    // The last placeholder went when the Flows screen landed.
    expect(screen.queryByText("soon")).not.toBeInTheDocument();
    expect(document.querySelector("[aria-disabled='true']")).toBeNull();
  });

  it("routes /flows to the Flows screen", async () => {
    renderShell("/flows");
    expect(await screen.findByRole("heading", { name: "Flows" })).toBeInTheDocument();
  });

  it("routes /models to the Models screen", async () => {
    renderShell("/models");
    expect(await screen.findByRole("heading", { name: "Models" })).toBeInTheDocument();
    for (const section of ["Runtime", "Library", "Catalog", "Try box"]) {
      expect(screen.getByRole("heading", { name: section })).toBeInTheDocument();
    }
  });

  it("hosts the real Settings sections (the style proof is retired)", async () => {
    renderShell("/settings");
    expect(await screen.findByRole("heading", { name: "Settings" })).toBeInTheDocument();
    for (const section of [
      "Appearance",
      "Security",
      "Models",
      "Flows",
      "Connectors",
      "Daemon",
      "Retention",
      "Logs",
    ]) {
      expect(screen.getByRole("heading", { name: section })).toBeInTheDocument();
    }
    // The design system's living proof moved out with task #30.
    expect(screen.queryByText(/tokens avoided this week/)).not.toBeInTheDocument();
  });
});

describe("shell chrome", () => {
  it("keeps the whole top strip a window drag region", async () => {
    renderShell("/");
    await screen.findByRole("heading", { name: "Activity" });
    const strip = document.querySelector("header[data-tauri-drag-region]");
    expect(strip).not.toBeNull();
    // Interactive chrome must NOT drag the window.
    const toggle = screen.getByRole("button", { name: /Ventisquero/ });
    expect(toggle).not.toHaveAttribute("data-tauri-drag-region");
    const modeToggle = screen.getByRole("button", { name: /switch to light mode/ });
    expect(modeToggle).not.toHaveAttribute("data-tauri-drag-region");
  });

  it("shows the beacon red while no daemon answers (jsdom has no bridge)", async () => {
    renderShell("/");
    await screen.findByRole("heading", { name: "Activity" });
    expect(screen.getByRole("status", { name: "daemon unreachable" })).toBeInTheDocument();
  });

  it("cycles theme families by token redefinition on the root element", async () => {
    renderShell("/");
    await screen.findByRole("heading", { name: "Activity" });
    fireEvent.click(screen.getByRole("button", { name: /Ventisquero/ }));
    expect(document.documentElement.dataset.theme).toBe("vina");
    expect(window.localStorage.getItem("pam-theme")).toBe("vina");
    fireEvent.click(screen.getByRole("button", { name: /Viña del Mar/ }));
    expect(document.documentElement.dataset.theme).toBe("ventisquero");
  });

  it("toggles the mode axis independently of the family", async () => {
    renderShell("/");
    await screen.findByRole("heading", { name: "Activity" });
    // No stamped attributes in jsdom, so the strip assumes dark-first.
    fireEvent.click(screen.getByRole("button", { name: /switch to light mode/ }));
    expect(document.documentElement.dataset.mode).toBe("light");
    expect(document.documentElement.dataset.theme).toBe("ventisquero");
    expect(window.localStorage.getItem("pam-theme-mode")).toBe("light");
    fireEvent.click(screen.getByRole("button", { name: /switch to dark mode/ }));
    expect(document.documentElement.dataset.mode).toBe("dark");
  });
});
