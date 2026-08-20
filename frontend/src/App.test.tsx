import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { App } from "./App";
import { fixtureBridge } from "./fixtures";

describe("control center", () => {
  it("renders the p-track spatial grammar and provenance-backed current outcome", async () => {
    render(<App bridge={fixtureBridge()} />);

    expect(await screen.findByRole("heading", { name: "payments-api" })).toBeInTheDocument();
    expect(screen.getByRole("navigation", { name: "Primary" })).toBeInTheDocument();
    expect(screen.getByRole("separator", { name: "Resize project sidebar" })).toHaveAttribute("aria-valuenow", "248");
    expect(screen.getByRole("heading", { name: "Ready for the next agent" })).toBeInTheDocument();
    expect(screen.getByText("Goal")).toBeInTheDocument();
    expect(screen.getByText("Decisions")).toBeInTheDocument();
    expect(screen.getByText("Verified")).toBeInTheDocument();
    expect(screen.getByText("Next")).toBeInTheDocument();
    expect(screen.getByText("Design fixture")).toBeInTheDocument();
  });

  it("supports keyboard resizing, view shortcuts, and Escape drawer recovery", async () => {
    const user = userEvent.setup();
    render(<App bridge={fixtureBridge()} />);
    await screen.findByRole("heading", { name: "payments-api" });

    const separator = screen.getByRole("separator", { name: "Resize project sidebar" });
    fireEvent.keyDown(separator, { key: "ArrowRight" });
    expect(separator).toHaveAttribute("aria-valuenow", "256");

    fireEvent.keyDown(window, { key: "3", metaKey: true });
    expect(await screen.findByRole("heading", { name: "Access" })).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Open queue" }));
    expect(screen.getByRole("dialog", { name: "Project queue" })).toBeInTheDocument();
    fireEvent.keyDown(window, { key: "Escape" });
    await waitFor(() => expect(screen.queryByRole("dialog", { name: "Project queue" })).not.toBeInTheDocument());
  });

  it("loads bounded evidence as escaped text", async () => {
    const user = userEvent.setup();
    render(<App bridge={fixtureBridge()} />);
    await screen.findByRole("heading", { name: "payments-api" });

    await user.click(screen.getByRole("button", { name: "44444444-4444-4444-8444-444444444444" }));
    expect(await screen.findByRole("dialog", { name: "Evidence" })).toBeInTheDocument();
    expect(await screen.findByText(/Null currency in fixture/)).toBeInTheDocument();
    expect(document.querySelector(".evidence-document pre script")).toBeNull();
  });

  it("opens, validates, and durably saves a bounded flow document", async () => {
    const user = userEvent.setup();
    render(<App bridge={fixtureBridge()} />);
    await screen.findByRole("heading", { name: "payments-api" });

    await user.click(screen.getByRole("button", { name: "Flows" }));
    expect(await screen.findByRole("region", { name: "Flow workspace" })).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: /after-merge-checks/ }));
    expect((await screen.findByRole("textbox", { name: "Flow TOML source" }) as HTMLTextAreaElement).value).toContain("schema_version = 2");
    await waitFor(() => expect(screen.getByRole("button", { name: "Validate" })).toBeEnabled());
    await user.click(screen.getByRole("button", { name: "Validate" }));
    expect(await screen.findByText(/Valid · 1 dry-run steps/)).toBeInTheDocument();
    await waitFor(() => expect(screen.getByRole("button", { name: "Save" })).toBeEnabled());
    await user.click(screen.getByRole("button", { name: "Save" }));
    expect(await screen.findByText(/saved durably/i)).toBeInTheDocument();
  });

  it("never substitutes fixture data after a production bridge failure", async () => {
    const bridge = fixtureBridge();
    bridge.bootstrap = vi.fn().mockRejectedValue(new Error("daemon socket unavailable"));
    render(<App bridge={bridge} />);

    expect(await screen.findByRole("heading", { name: "PAM needs a moment" })).toBeInTheDocument();
    expect(screen.getByText("daemon socket unavailable")).toBeInTheDocument();
    expect(screen.queryByText("payments-api")).not.toBeInTheDocument();
  });
});
