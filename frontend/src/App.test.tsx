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

  it("renders all five nav entries; Flows and Models are disabled non-links", async () => {
    renderShell("/");
    await screen.findByRole("heading", { name: "Activity" });
    for (const entry of ["Activity", "Approvals", "Settings"]) {
      expect(screen.getByRole("link", { name: entry })).toBeInTheDocument();
    }
    for (const entry of ["Flows", "Models"]) {
      const item = screen.getByText(entry);
      expect(item.closest("a")).toBeNull();
      expect(item.closest("[aria-disabled='true']")).not.toBeNull();
    }
    expect(screen.getAllByText("soon")).toHaveLength(2);
  });

  it("hosts the migrated style proof on the Settings screen", async () => {
    renderShell("/settings");
    expect(await screen.findByRole("heading", { name: "Settings" })).toBeInTheDocument();
    for (const verdict of ["verified", "changed", "queued", "refused"]) {
      expect(screen.getByText(verdict)).toBeInTheDocument();
    }
    expect(screen.getByText(/tokens avoided this week/)).toBeInTheDocument();
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
