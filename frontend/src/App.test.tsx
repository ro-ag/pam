import { act, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { App } from "./App";
import { MAX_EVIDENCE_TEXT } from "./domain";
import { fixtureBridge } from "./fixtures";

function memoryStorage(): Storage {
  const values = new Map<string, string>();
  return {
    get length() { return values.size; },
    clear: () => values.clear(),
    getItem: (key) => values.get(key) ?? null,
    key: (index) => [...values.keys()][index] ?? null,
    removeItem: (key) => values.delete(key),
    setItem: (key, value) => values.set(key, value),
  };
}

Object.defineProperty(window, "localStorage", {
  configurable: true,
  value: memoryStorage(),
});

function deferred() {
  let resolve!: () => void;
  let reject!: (reason?: unknown) => void;
  const promise = new Promise<void>((onResolve, onReject) => {
    resolve = onResolve;
    reject = onReject;
  });
  return { promise, resolve, reject };
}

describe("control center", () => {
  beforeEach(() => window.localStorage.clear());

  it("renders the p-track spatial grammar and provenance-backed current outcome", async () => {
    render(<App bridge={fixtureBridge()} />);

    expect(await screen.findByRole("heading", { name: "payments-api" })).toBeInTheDocument();
    expect(screen.getByRole("navigation", { name: "Primary" })).toBeInTheDocument();
    expect(screen.getByRole("separator", { name: "Resize project sidebar" })).toHaveAttribute("aria-valuenow", "248");
    expect(screen.getByRole("heading", { name: "Ready for the next agent" })).toBeInTheDocument();
    expect(screen.getByText("SOLVED")).toBeInTheDocument();
    expect(screen.getByText("CHANGED")).toBeInTheDocument();
    expect(screen.getByText("VERIFIED")).toBeInTheDocument();
    expect(screen.getByText("UNRESOLVED")).toBeInTheDocument();
    expect(screen.getByText("BLOCKED")).toBeInTheDocument();
    expect(screen.getByText("Design fixture")).toBeInTheDocument();
  });

  it("renders an active request even before replay facts arrive", async () => {
    const bridge = fixtureBridge("active");
    const originalBootstrap = bridge.bootstrap.bind(bridge);
    bridge.bootstrap = vi.fn(async () => {
      const response = await originalBootstrap();
      if (response.data.current.status === "available" && response.data.current.run) {
        response.data.current.run.timeline = [];
      }
      return response;
    });

    render(<App bridge={bridge} />);

    expect(await screen.findByText("Active durable request")).toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: "No current activity" })).not.toBeInTheDocument();
  });

  it("keeps loading inside the shared shell without project claims", () => {
    render(<App bridge={fixtureBridge("loading")} />);

    expect(screen.getByRole("status")).toHaveTextContent("Finding the last registered project…");
    expect(screen.queryByText("payments-api")).not.toBeInTheDocument();
  });

  it("renders the exact empty current state", async () => {
    render(<App bridge={fixtureBridge("empty")} />);

    expect(await screen.findByRole("heading", { name: "No current activity" })).toBeInTheDocument();
    expect(screen.queryByText("Ready for the next agent")).not.toBeInTheDocument();
  });

  it("renders offline current recovery without an available-state claim", async () => {
    render(<App bridge={fixtureBridge("offline")} />);

    expect(await screen.findByRole("heading", { name: "Authenticated project state is unavailable" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Start PAM" })).toBeEnabled();
    expect(screen.getByRole("alert")).toHaveTextContent("The authenticated daemon is unavailable for this project.");
    expect(screen.queryByRole("heading", { name: "Ready for the next agent" })).not.toBeInTheDocument();
  });

  it("renders a queued-only current state before durable work starts", async () => {
    render(<App bridge={fixtureBridge("queued")} />);

    expect(await screen.findByRole("heading", { name: "2 project requests are queued" })).toBeInTheDocument();
    expect(screen.getByText("Next: after-merge-checks. PAM remains on watch while durable work waits.")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Open project queue" })).toBeEnabled();
    expect(screen.queryByRole("heading", { name: "No current activity" })).not.toBeInTheDocument();
  });

  it("keeps a policy-blocked current response distinct from a blocked terminal report", async () => {
    render(<App bridge={fixtureBridge("current-blocked")} />);

    expect(await screen.findByText(/Project policy blocked access to the bounded current state\./)).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Authenticated project state is unavailable" })).toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: "Run is blocked" })).not.toBeInTheDocument();
  });

  it("renders unresolved terminal truth without a solved claim", async () => {
    render(<App bridge={fixtureBridge("unresolved")} />);

    expect(await screen.findByRole("heading", { name: "Run needs follow-up" })).toBeInTheDocument();
    expect(screen.getByText("Terminal result · follow-up required")).toBeInTheDocument();
    expect(screen.queryByText("Terminal result · solved")).not.toBeInTheDocument();
  });

  it("renders cancelled terminal truth without a solved claim", async () => {
    render(<App bridge={fixtureBridge("cancelled")} />);

    expect(await screen.findByRole("heading", { name: "Run was cancelled" })).toBeInTheDocument();
    expect(screen.getByText("Terminal result · follow-up required")).toBeInTheDocument();
    expect(screen.queryByText("Terminal result · solved")).not.toBeInTheDocument();
  });

  it("renders startup transport failure in the bounded recovery shell", async () => {
    render(<App bridge={fixtureBridge("startup-error")} />);

    expect(await screen.findByRole("heading", { name: "PAM needs a moment" })).toBeInTheDocument();
    expect(screen.getByText("The PAM daemon fixture is unavailable.")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Retry safely" })).toBeEnabled();
  });

  it("supports keyboard resizing, view shortcuts, and Escape drawer recovery", async () => {
    const user = userEvent.setup();
    render(<App bridge={fixtureBridge()} />);
    await screen.findByRole("heading", { name: "payments-api" });

    const separator = screen.getByRole("separator", { name: "Resize project sidebar" });
    fireEvent.keyDown(separator, { key: "ArrowRight" });
    expect(separator).toHaveAttribute("aria-valuenow", "264");
    expect(window.localStorage.getItem("pam-sidebar-width")).toBe("264");

    fireEvent.keyDown(window, { key: "3", metaKey: true });
    expect(await screen.findByRole("heading", { name: "Access" })).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Open queue" }));
    expect(screen.getByRole("dialog", { name: "Project queue" })).toBeInTheDocument();
    await user.keyboard("{Escape}");
    await waitFor(() => expect(screen.queryByRole("dialog", { name: "Project queue" })).not.toBeInTheDocument());
  });

  it("renders the available Access facts supplied by the active project", async () => {
    render(<App bridge={fixtureBridge("access-available")} initialView="access" />);

    expect(await screen.findByRole("heading", { name: "Access" })).toBeInTheDocument();
    expect(screen.getByText("Model access")).toBeInTheDocument();
    expect(screen.getByText("Access policy")).toBeInTheDocument();
    expect(screen.getByText("Certificates")).toBeInTheDocument();
    expect(screen.getByText("Network configuration")).toBeInTheDocument();
    expect(screen.getByText(/Operating-system certificate verifier enabled/)).toBeInTheDocument();
  });

  it("renders policy-blocked Access without available diagnostics", async () => {
    render(<App bridge={fixtureBridge("access-blocked")} initialView="access" />);

    expect(await screen.findByRole("heading", { name: "Access" })).toBeInTheDocument();
    expect(screen.getByText("Access policy")).toBeInTheDocument();
    expect(screen.getByText("policy-gated")).toBeInTheDocument();
    expect(screen.getByText(/Network diagnostics are blocked by the selected project's policy/)).toBeInTheDocument();
    expect(screen.queryByText("Certificates")).not.toBeInTheDocument();
  });

  it("activates only the newest overlay and restores its underlay and exact openers", async () => {
    const user = userEvent.setup();
    const bridge = fixtureBridge();
    const approvalSnapshot = await fixtureBridge("approval").bootstrap();
    const refreshGate = deferred();
    bridge.refreshProject = vi.fn(async (fence) => {
      await refreshGate.promise;
      return { fence: structuredClone(fence), data: structuredClone(approvalSnapshot.data) };
    });
    render(<App bridge={bridge} />);
    await screen.findByRole("heading", { name: "payments-api" });

    await user.click(screen.getByRole("button", { name: "Refresh project" }));
    const queueOpener = screen.getByRole("button", { name: "Open queue" });
    await user.click(queueOpener);
    expect(await screen.findByRole("dialog", { name: "Project queue" })).toBeInTheDocument();

    await act(async () => { refreshGate.resolve(); });
    const approval = await screen.findByRole("dialog", { name: "Approval required" });
    const queueUnderlay = screen.getByRole("dialog", { name: "Project queue", hidden: true });
    const approvalLayer = approval.closest<HTMLElement>("[data-application-overlay-layer]");
    const queueLayer = queueUnderlay.closest<HTMLElement>("[data-application-overlay-layer]");
    const appShell = document.querySelector<HTMLElement>(".app-shell");

    expect(screen.getAllByRole("dialog")).toEqual([approval]);
    expect(document.querySelectorAll('[data-application-overlay-layer="active"]')).toHaveLength(1);
    expect(approvalLayer).toHaveAttribute("data-application-overlay-layer", "active");
    expect(queueLayer).toHaveAttribute("data-application-overlay-layer", "underlay");
    expect(queueLayer).toHaveAttribute("aria-hidden", "true");
    expect(queueLayer).toHaveAttribute("inert");
    expect(appShell).toHaveAttribute("aria-hidden", "true");
    expect(appShell).toHaveAttribute("inert");

    await user.keyboard("{Escape}");
    const restoredQueue = await screen.findByRole("dialog", { name: "Project queue" });
    await waitFor(() => expect(within(restoredQueue).getByRole("button", { name: "Close Project queue" })).toHaveFocus());
    expect(screen.queryByRole("dialog", { name: "Approval required" })).not.toBeInTheDocument();
    expect(appShell).toHaveAttribute("aria-hidden", "true");
    expect(appShell).toHaveAttribute("inert");

    await user.keyboard("{Escape}");
    await waitFor(() => expect(screen.queryByRole("dialog", { name: "Project queue" })).not.toBeInTheDocument());
    expect(queueOpener).toHaveFocus();
    expect(appShell).not.toHaveAttribute("aria-hidden");
    expect(appShell).not.toHaveAttribute("inert");
  });

  it("moves focus into and out of the compact sidebar while the workspace is inert", async () => {
    window.localStorage.setItem("pam-sidebar-collapsed", "false");
    const originalMatchMedia = window.matchMedia;
    Object.defineProperty(window, "matchMedia", {
      configurable: true,
      value: (query: string) => ({
        matches: query.includes("max-width: 780px"),
        media: query,
        onchange: null,
        addListener: () => undefined,
        removeListener: () => undefined,
        addEventListener: () => undefined,
        removeEventListener: () => undefined,
        dispatchEvent: () => false,
      }),
    });
    try {
      const user = userEvent.setup();
      render(<App bridge={fixtureBridge()} />);
      await screen.findByRole("heading", { name: "payments-api" });
      const trigger = screen.getByRole("button", { name: "Expand sidebar" });
      await user.click(trigger);

      const workspace = document.querySelector<HTMLElement>(".workspace");
      const sidebar = screen.getByRole("complementary", { name: "Project navigation" });
      const switcher = within(sidebar).getByRole("button", { name: "payments-api" });
      await waitFor(() => expect(switcher).toHaveFocus());
      expect(workspace).toHaveAttribute("inert");
      expect(workspace).toHaveAttribute("aria-hidden", "true");
      expect(screen.getByText("Skip to content")).toHaveAttribute("tabindex", "-1");
      expect(screen.getByRole("button", { name: "Close project sidebar" })).toHaveAttribute("tabindex", "-1");
      expect(screen.getByRole("separator", { name: "Resize project sidebar" })).toHaveAttribute("tabindex", "-1");

      const enabledSidebarButtons = within(sidebar).getAllByRole("button").filter((button) => !button.hasAttribute("disabled"));
      const lastSidebarButton = enabledSidebarButtons[enabledSidebarButtons.length - 1];
      await user.tab({ shift: true });
      expect(lastSidebarButton).toHaveFocus();
      await user.tab();
      expect(switcher).toHaveFocus();

      await user.keyboard("{ArrowDown}");
      await waitFor(() => expect(screen.getByRole("menuitemradio", { name: /payments-api/ })).toHaveFocus());
      await user.keyboard("{Escape}");
      await waitFor(() => expect(screen.queryByRole("menu")).not.toBeInTheDocument());
      expect(screen.getByRole("button", { name: "Close project sidebar" })).toBeInTheDocument();
      expect(switcher).toHaveFocus();

      await user.keyboard("{Escape}");
      await waitFor(() => expect(screen.getByRole("button", { name: "Expand sidebar" })).toHaveFocus());
      expect(workspace).not.toHaveAttribute("inert");
      expect(workspace).not.toHaveAttribute("aria-hidden");
      expect(window.localStorage.getItem("pam-sidebar-collapsed")).toBe("false");
    } finally {
      Object.defineProperty(window, "matchMedia", { configurable: true, value: originalMatchMedia });
    }
  });

  it("yields compact-sidebar focus containment to an active application overlay", async () => {
    const originalMatchMedia = window.matchMedia;
    Object.defineProperty(window, "matchMedia", {
      configurable: true,
      value: (query: string) => ({
        matches: query.includes("max-width: 780px"),
        media: query,
        onchange: null,
        addListener: () => undefined,
        removeListener: () => undefined,
        addEventListener: () => undefined,
        removeEventListener: () => undefined,
        dispatchEvent: () => false,
      }),
    });
    try {
      const user = userEvent.setup();
      const bridge = fixtureBridge();
      const approvalSnapshot = await fixtureBridge("approval").bootstrap();
      const refreshGate = deferred();
      bridge.refreshProject = vi.fn(async (fence) => {
        await refreshGate.promise;
        return { fence: structuredClone(fence), data: structuredClone(approvalSnapshot.data) };
      });
      render(<App bridge={bridge} />);
      await screen.findByRole("heading", { name: "payments-api" });

      await user.click(screen.getByRole("button", { name: "Refresh project" }));
      await user.click(screen.getByRole("button", { name: "Expand sidebar" }));
      const sidebar = screen.getByRole("complementary", { name: "Project navigation" });
      await waitFor(() => expect(within(sidebar).getByRole("button", { name: "payments-api" })).toHaveFocus());

      await act(async () => { refreshGate.resolve(); });
      const dialog = await screen.findByRole("dialog", { name: "Approval required" });
      await waitFor(() => expect(within(dialog).getByRole("button", { name: "Close Approval required" })).toHaveFocus());
      await user.tab();
      expect(dialog).toContainElement(document.activeElement as HTMLElement);
      expect(sidebar).not.toContainElement(document.activeElement as HTMLElement);
    } finally {
      Object.defineProperty(window, "matchMedia", { configurable: true, value: originalMatchMedia });
    }
  });

  it("supports the complete keyboard project-menu contract", async () => {
    const user = userEvent.setup();
    render(<App bridge={fixtureBridge()} />);
    await screen.findByRole("heading", { name: "payments-api" });

    const switcher = screen.getByRole("button", { name: "payments-api" });
    switcher.focus();
    await user.keyboard("{ArrowDown}");
    const payments = await screen.findByRole("menuitemradio", { name: /payments-api/ });
    const ledger = screen.getByRole("menuitemradio", { name: /ledger-web/ });
    const docs = screen.getByRole("menuitemradio", { name: /^docs/ });
    await waitFor(() => expect(payments).toHaveFocus());
    expect(payments).toHaveAttribute("tabindex", "0");
    expect(ledger).toHaveAttribute("tabindex", "-1");

    await user.keyboard("{ArrowDown}");
    await waitFor(() => expect(ledger).toHaveFocus());
    expect(ledger).toHaveAttribute("tabindex", "0");
    expect(payments).toHaveAttribute("tabindex", "-1");
    await user.keyboard("{End}");
    await waitFor(() => expect(docs).toHaveFocus());
    await user.keyboard("{Home}");
    await waitFor(() => expect(payments).toHaveFocus());
    await user.keyboard("{Escape}");
    expect(screen.queryByRole("menu")).not.toBeInTheDocument();
    expect(switcher).toHaveFocus();

    await user.keyboard("{ArrowDown}");
    await waitFor(() => expect(screen.getByRole("menuitemradio", { name: /payments-api/ })).toHaveFocus());
    await user.keyboard("{ArrowDown}");
    await waitFor(() => expect(screen.getByRole("menuitemradio", { name: /ledger-web/ })).toHaveFocus());
    await user.keyboard("{Enter}");
    expect(await screen.findByRole("heading", { name: "ledger-web" })).toBeInTheDocument();
    const ledgerSwitcher = screen.getByRole("button", { name: "ledger-web" });
    ledgerSwitcher.focus();
    await user.keyboard("{ArrowDown}");
    await waitFor(() => expect(screen.getByRole("menuitemradio", { name: /ledger-web/ })).toHaveFocus());
    await user.keyboard("{End}");
    await waitFor(() => expect(screen.getByRole("menuitemradio", { name: /^docs/ })).toHaveFocus());
    await user.keyboard(" ");
    expect(await screen.findByRole("heading", { name: "docs" })).toBeInTheDocument();
  });

  it("filters and runs command-palette actions with keyboard focus restoration", async () => {
    const user = userEvent.setup();
    render(<App bridge={fixtureBridge()} />);
    await screen.findByRole("heading", { name: "payments-api" });
    const commandOpener = screen.getByRole("button", { name: "Open command palette (⌘K)" });
    commandOpener.focus();

    await user.keyboard("{Control>}k{/Control}");
    let palette = await screen.findByRole("dialog", { name: "Command palette" });
    let search = within(palette).getByRole("searchbox", { name: "Search commands" });
    await waitFor(() => expect(search).toHaveFocus());
    await user.type(search, "access");
    expect(within(palette).getAllByRole("option")).toHaveLength(1);
    const accessCommand = within(palette).getByRole("option", { name: /Open Access/ });
    await user.keyboard("{ArrowDown}");
    await waitFor(() => expect(accessCommand).toHaveFocus());
    await user.keyboard("{Enter}");

    expect(await screen.findByRole("heading", { name: "Access" })).toBeInTheDocument();
    expect(screen.queryByRole("dialog", { name: "Command palette" })).not.toBeInTheDocument();
    await waitFor(() => expect(commandOpener).toHaveFocus());

    await user.keyboard("{Meta>}k{/Meta}");
    palette = await screen.findByRole("dialog", { name: "Command palette" });
    search = within(palette).getByRole("searchbox", { name: "Search commands" });
    await user.type(search, "queue");
    const queueCommand = within(palette).getByRole("option", { name: /Open project queue/ });
    await user.keyboard("{ArrowUp}");
    await waitFor(() => expect(queueCommand).toHaveFocus());
    await user.keyboard("{Enter}");

    expect(await screen.findByRole("dialog", { name: "Project queue" })).toBeInTheDocument();
    expect(screen.queryByRole("dialog", { name: "Command palette", hidden: true })).not.toBeInTheDocument();
    expect(document.querySelectorAll('[data-application-overlay-layer="underlay"]')).toHaveLength(0);
    expect(screen.getAllByRole("dialog")).toHaveLength(1);
  });

  it("loads bounded evidence as escaped text", async () => {
    const user = userEvent.setup();
    render(<App bridge={fixtureBridge()} />);
    await screen.findByRole("heading", { name: "payments-api" });

    const opener = screen.getByRole("button", { name: "Open Evidence 1" });
    expect(opener).toHaveAccessibleDescription("44444444-4444-4444-8444-444444444444");
    await user.click(opener);
    expect(await screen.findByRole("dialog", { name: "Evidence" })).toBeInTheDocument();
    expect(await screen.findByText(/Null currency in fixture/)).toBeInTheDocument();
    expect(document.querySelector(".evidence-document pre script")).toBeNull();
    await user.click(screen.getByRole("button", { name: "Close Evidence" }));
    await waitFor(() => expect(opener).toHaveFocus());
  });

  it("keeps retryable evidence failure inside the bounded drawer", async () => {
    const user = userEvent.setup();
    render(<App bridge={fixtureBridge("evidence-failed")} />);
    await screen.findByRole("heading", { name: "payments-api" });

    await user.click(screen.getByRole("button", { name: "Open Evidence 1" }));
    const drawer = await screen.findByRole("dialog", { name: "Evidence" });
    expect(within(drawer).getByRole("alert")).toHaveTextContent("The bounded evidence preview could not be loaded.");
    expect(within(drawer).getByRole("button", { name: "Retry evidence" })).toBeEnabled();
  });

  it("renders binary evidence metadata without inventing a text preview", async () => {
    const user = userEvent.setup();
    render(<App bridge={fixtureBridge("evidence-binary")} />);
    await screen.findByRole("heading", { name: "payments-api" });

    await user.click(screen.getByRole("button", { name: "Open Evidence 1" }));
    const drawer = await screen.findByRole("dialog", { name: "Evidence" });
    expect(within(drawer).getByRole("heading", { name: "Binary evidence metadata" })).toBeInTheDocument();
    expect(within(drawer).getByText(/application\/octet-stream/)).toBeInTheDocument();
    expect(within(drawer).getByText("This evidence has no text preview.")).toBeInTheDocument();
  });

  it("bounds truncated evidence text and labels the preview", async () => {
    const user = userEvent.setup();
    render(<App bridge={fixtureBridge("evidence-truncated")} />);
    await screen.findByRole("heading", { name: "payments-api" });

    await user.click(screen.getByRole("button", { name: "Open Evidence 1" }));
    const drawer = await screen.findByRole("dialog", { name: "Evidence" });
    expect(within(drawer).getByText(/bounded preview/)).toBeInTheDocument();
    const preview = drawer.querySelector(".evidence-document pre");
    expect(preview).not.toBeNull();
    expect(preview).toHaveTextContent("retained evidence line");
    expect(preview?.textContent).toHaveLength(MAX_EVIDENCE_TEXT);
    expect(preview).not.toHaveTextContent("preview stops at the bounded read limit");
  });

  it("hides evidence retry when a mismatched response invalidates the handle", async () => {
    const user = userEvent.setup();
    const bridge = fixtureBridge();
    const originalLoadEvidence = bridge.loadEvidence.bind(bridge);
    bridge.loadEvidence = vi.fn(async (fence, handle) => {
      const response = await originalLoadEvidence(fence, handle);
      return { ...response, fence: { ...response.fence, operationId: "99999999-9999-4999-8999-999999999999" } };
    });
    render(<App bridge={bridge} />);
    await screen.findByRole("heading", { name: "payments-api" });

    await user.click(screen.getByRole("button", { name: "Open Evidence 1" }));
    expect(await screen.findByText(/active project changed/i)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Retry evidence" })).not.toBeInTheDocument();
  });

  it("shows the exact bounded approval effect without protocol request identifiers", async () => {
    render(<App bridge={fixtureBridge("approval")} />);

    const dialog = await screen.findByRole("dialog", { name: "Approval required" });
    expect(within(dialog).getByText("Read the selected project's bounded current queue and latest run")).toBeInTheDocument();
    expect(within(dialog).getByText("payments-api")).toBeInTheDocument();
    expect(within(dialog).getByText("project.current · exact project policy")).toBeInTheDocument();
    expect(within(dialog).getByText("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee")).toBeInTheDocument();
    expect(within(dialog).queryByText(/fixture-request/)).not.toBeInTheDocument();
  });

  it("keeps auto approval dismissed until explicit reopen, then restores focus", async () => {
    const user = userEvent.setup();
    render(<App bridge={fixtureBridge("approval")} />);
    const initialDialog = await screen.findByRole("dialog", { name: "Approval required" });
    await user.click(within(initialDialog).getByRole("button", { name: "Close Approval required" }));
    await waitFor(() => expect(screen.queryByRole("dialog", { name: "Approval required" })).not.toBeInTheDocument());
    await act(async () => { await Promise.resolve(); });
    expect(screen.queryByRole("dialog", { name: "Approval required" })).not.toBeInTheDocument();
    const opener = screen.getByRole("button", { name: "Review exact effect" });
    await user.click(opener);
    const dialog = await screen.findByRole("dialog", { name: "Approval required" });
    const close = within(dialog).getByRole("button", { name: "Close Approval required" });
    const approve = within(dialog).getByRole("button", { name: "Approve exact request" });
    await waitFor(() => expect(close).toHaveFocus());

    await user.tab({ shift: true });
    expect(approve).toHaveFocus();
    await user.tab();
    expect(close).toHaveFocus();
    await user.click(close);
    expect(opener).toHaveFocus();
  });

  it("keeps the approval handle actionable after an ambiguous decision failure", async () => {
    const user = userEvent.setup();
    const bridge = fixtureBridge("approval");
    const decideApproval = bridge.decideApproval.bind(bridge);
    let attempts = 0;
    bridge.decideApproval = vi.fn(async (fence, handle, decision) => {
      attempts += 1;
      if (attempts === 1) throw new Error("Approval response was not observed; retry the same decision safely.");
      return decideApproval(fence, handle, decision);
    });
    render(<App bridge={bridge} />);
    const dialog = await screen.findByRole("dialog", { name: "Approval required" });
    await user.click(within(dialog).getByRole("button", { name: "Approve exact request" }));

    expect(await within(dialog).findByRole("alert")).toHaveTextContent("Approval response was not observed");
    expect(screen.getByRole("dialog", { name: "Approval required" })).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Approve exact request" }));
    expect(await screen.findByRole("heading", { name: "Ready for the next agent" })).toBeInTheDocument();
    expect(bridge.decideApproval).toHaveBeenCalledTimes(2);
  });

  it("surfaces an explicit expired approval without a success claim", async () => {
    const user = userEvent.setup();
    const bridge = fixtureBridge("approval");
    const decideApproval = bridge.decideApproval.bind(bridge);
    bridge.decideApproval = vi.fn(async (fence, handle, decision) => {
      const response = await decideApproval(fence, handle, decision);
      response.disposition = "expired";
      response.snapshot.data.current = {
        status: "unavailable",
        failure: {
          kind: "unavailable",
          code: "approval_expired",
          detail: "This approval expired before the decision was applied.",
          recovery: "Retry project current to receive a new challenge.",
        },
      };
      return response;
    });
    render(<App bridge={bridge} />);
    await user.click(within(await screen.findByRole("dialog", { name: "Approval required" })).getByRole("button", { name: "Approve exact request" }));

    expect(await screen.findByRole("status")).toHaveTextContent("Approval expired; request a new challenge");
    expect(screen.getByRole("alert")).toHaveTextContent("This approval expired before the decision was applied.");
    expect(screen.queryByText("Exact request approved")).not.toBeInTheDocument();
  });

  it("renders non-solved terminal reports without a solved or provenance overclaim", async () => {
    const bridge = fixtureBridge();
    const originalBootstrap = bridge.bootstrap.bind(bridge);
    bridge.bootstrap = vi.fn(async () => {
      const response = await originalBootstrap();
      if (response.data.current.status === "available" && response.data.current.run?.outcome) {
        response.data.current.run.outcome.heading = "Run is blocked";
        response.data.current.run.outcome.solved = false;
        response.data.current.run.outcome.evidence = [];
        response.data.current.run.outcome.sections = [
          { label: "SOLVED", summary: "The request did not complete.", satisfied: false },
          { label: "BLOCKED", summary: "Project policy blocked the write.", satisfied: true },
        ];
      }
      return response;
    });
    render(<App bridge={bridge} />);

    expect(await screen.findByRole("heading", { name: "Run is blocked" })).toBeInTheDocument();
    expect(screen.getByText("Terminal result · follow-up required")).toBeInTheDocument();
    expect(screen.getByText("The terminal result reported no evidence handles.")).toBeInTheDocument();
    expect(screen.queryByText(/Every statement/)).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Open evidence/ })).toBeDisabled();
  });

  it("discards stale command success and its toast when project responses reverse", async () => {
    const user = userEvent.setup();
    const bridge = fixtureBridge();
    const activate = bridge.activateProject.bind(bridge);
    const ledgerGate = deferred();
    const docsGate = deferred();
    bridge.activateProject = vi.fn(async (handle, operationId) => {
      if (handle.includes("2222")) await ledgerGate.promise;
      if (handle.includes("3333")) await docsGate.promise;
      return activate(handle, operationId);
    });
    render(<App bridge={bridge} />);
    await screen.findByRole("heading", { name: "payments-api" });

    await user.click(screen.getByRole("button", { name: "payments-api" }));
    await user.click(screen.getByRole("menuitemradio", { name: /ledger-web/ }));
    await user.click(screen.getByRole("button", { name: "payments-api" }));
    await user.click(screen.getByRole("menuitemradio", { name: /^docs/ }));
    await act(async () => { docsGate.resolve(); });
    expect(await screen.findByRole("heading", { name: "docs" })).toBeInTheDocument();
    expect(await screen.findByRole("status")).toHaveTextContent("Now watching docs");

    await act(async () => { ledgerGate.resolve(); });
    expect(screen.getByRole("heading", { name: "docs" })).toBeInTheDocument();
    expect(screen.queryByText("Now watching ledger-web")).not.toBeInTheDocument();
  });

  it("does not reopen evidence after it is closed while loading", async () => {
    const user = userEvent.setup();
    const bridge = fixtureBridge();
    const originalLoadEvidence = bridge.loadEvidence.bind(bridge);
    const gate = deferred();
    bridge.loadEvidence = vi.fn(async (fence, handle) => {
      await gate.promise;
      return originalLoadEvidence(fence, handle);
    });
    render(<App bridge={bridge} />);
    await screen.findByRole("heading", { name: "payments-api" });

    await user.click(screen.getByRole("button", { name: "Open Evidence 1" }));
    expect(screen.getByText("Loading retained evidence…")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Close Evidence" }));
    expect(screen.queryByRole("dialog", { name: "Evidence" })).not.toBeInTheDocument();

    await act(async () => { gate.resolve(); });
    expect(screen.queryByRole("dialog", { name: "Evidence" })).not.toBeInTheDocument();
  });

  it("discards evidence from the previous project authority", async () => {
    const user = userEvent.setup();
    const bridge = fixtureBridge();
    const originalLoadEvidence = bridge.loadEvidence.bind(bridge);
    const loadGate = deferred();
    const activateGate = deferred();
    bridge.loadEvidence = vi.fn(async (fence, handle) => {
      await loadGate.promise;
      return originalLoadEvidence(fence, handle);
    });
    const originalActivateProject = bridge.activateProject.bind(bridge);
    bridge.activateProject = vi.fn(async (handle, operationId) => {
      await activateGate.promise;
      return originalActivateProject(handle, operationId);
    });
    render(<App bridge={bridge} />);
    await screen.findByRole("heading", { name: "payments-api" });

    await user.click(screen.getByRole("button", { name: "payments-api" }));
    await user.click(screen.getByRole("menuitemradio", { name: /ledger-web/ }));
    await user.click(screen.getByRole("button", { name: "Open Evidence 1" }));
    await act(async () => { activateGate.resolve(); });
    expect(await screen.findByRole("heading", { name: "ledger-web" })).toBeInTheDocument();

    await act(async () => { loadGate.resolve(); });
    expect(screen.queryByRole("dialog", { name: "Evidence" })).not.toBeInTheDocument();
    expect(screen.queryByText(/Null currency in fixture/)).not.toBeInTheDocument();
  });

  it("opens, validates, and durably saves a bounded flow document", async () => {
    const user = userEvent.setup();
    const bridge = fixtureBridge();
    const saveFlow = bridge.saveFlow.bind(bridge);
    bridge.saveFlow = vi.fn(saveFlow);
    render(<App bridge={bridge} />);
    await screen.findByRole("heading", { name: "payments-api" });

    await user.click(screen.getByRole("button", { name: "Flows" }));
    expect(await screen.findByRole("region", { name: "Flow workspace" })).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: /after-merge-checks/ }));
    const source = await screen.findByRole("textbox", { name: "Flow TOML source" }) as HTMLTextAreaElement;
    expect(source.value).toContain("schema_version = 2");
    fireEvent.change(source, { target: { value: `${source.value.replace("revision = 4", "revision = 5")}\n\n` } });
    await waitFor(() => expect(screen.getByRole("button", { name: "Validate" })).toBeEnabled());
    await user.click(screen.getByRole("button", { name: "Validate" }));
    expect(await screen.findByText(/Valid · 1 dry-run steps/)).toBeInTheDocument();
    const dryRunTab = screen.getByRole("tab", { name: "Dry run" });
    const diffTab = screen.getByRole("tab", { name: /Version diff · changed/ });
    dryRunTab.focus();
    await user.keyboard("{ArrowRight}");
    expect(diffTab).toHaveAttribute("aria-selected", "true");
    await user.keyboard("{ArrowLeft}");
    expect(dryRunTab).toHaveAttribute("aria-selected", "true");
    await user.keyboard("{End}");
    expect(diffTab).toHaveAttribute("aria-selected", "true");
    await user.keyboard("{Home}");
    expect(dryRunTab).toHaveAttribute("aria-selected", "true");
    await user.keyboard("{End}");
    expect(screen.getByRole("tabpanel", { name: /Version diff · changed/ })).toHaveTextContent("revision = 4");
    await waitFor(() => expect(screen.getByRole("button", { name: "Save" })).toBeEnabled());
    await user.click(screen.getByRole("button", { name: "Save" }));
    expect(await screen.findByText(/saved durably/i)).toBeInTheDocument();
    expect((screen.getByRole("textbox", { name: "Flow TOML source" }) as HTMLTextAreaElement).value.endsWith("\n\n")).toBe(false);
    expect(bridge.saveFlow).toHaveBeenCalledWith(expect.anything(), expect.any(String), expect.not.stringMatching(/\n\n$/));
  });

  it("keeps validation errors beside the flow source until the user edits", async () => {
    const user = userEvent.setup();
    const bridge = fixtureBridge();
    bridge.validateFlow = vi.fn().mockRejectedValue(new Error("Line 4: expected a TOML value"));
    render(<App bridge={bridge} />);
    await screen.findByRole("heading", { name: "payments-api" });
    await user.click(screen.getByRole("button", { name: "Flows" }));
    await user.click(await screen.findByRole("button", { name: /after-merge-checks/ }));

    const source = await screen.findByRole("textbox", { name: "Flow TOML source" });
    await user.click(screen.getByRole("button", { name: "Validate" }));
    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("Line 4: expected a TOML value");
    expect(source).toHaveAttribute("aria-invalid", "true");
    expect(source).toHaveAttribute("aria-describedby", alert.id);

    fireEvent.change(source, { target: { value: "schema_version = 2\n" } });
    expect(screen.queryByText("Line 4: expected a TOML value")).not.toBeInTheDocument();
    expect(source).not.toHaveAttribute("aria-invalid");
  });

  it("keeps Save disabled when the source changes during validation", async () => {
    const user = userEvent.setup();
    const bridge = fixtureBridge();
    const originalValidate = bridge.validateFlow.bind(bridge);
    const gate = deferred();
    bridge.validateFlow = vi.fn(async (fence, documentHandle, source) => {
      await gate.promise;
      return originalValidate(fence, documentHandle, source);
    });
    render(<App bridge={bridge} />);
    await screen.findByRole("heading", { name: "payments-api" });
    await user.click(screen.getByRole("button", { name: "Flows" }));
    await screen.findByRole("region", { name: "Flow workspace" });
    await user.click(screen.getByRole("button", { name: /after-merge-checks/ }));
    const source = await screen.findByRole("textbox", { name: "Flow TOML source" });

    await user.click(screen.getByRole("button", { name: "Validate" }));
    fireEvent.change(source, { target: { value: `${(source as HTMLTextAreaElement).value}\n# edited while validating` } });
    await act(async () => { gate.resolve(); });

    expect(screen.getByRole("button", { name: "Save" })).toBeDisabled();
    expect(screen.queryByText(/Valid ·/)).not.toBeInTheDocument();
  });

  it("accepts only the newest validation when responses arrive in reverse", async () => {
    const user = userEvent.setup();
    const bridge = fixtureBridge();
    const originalValidate = bridge.validateFlow.bind(bridge);
    const gates = [deferred(), deferred()];
    let call = 0;
    bridge.validateFlow = vi.fn(async (fence, documentHandle, source) => {
      const gate = gates[call++];
      await gate.promise;
      return originalValidate(fence, documentHandle, source);
    });
    render(<App bridge={bridge} />);
    await screen.findByRole("heading", { name: "payments-api" });
    await user.click(screen.getByRole("button", { name: "Flows" }));
    await screen.findByRole("region", { name: "Flow workspace" });
    await user.click(screen.getByRole("button", { name: /after-merge-checks/ }));
    const source = await screen.findByRole("textbox", { name: "Flow TOML source" }) as HTMLTextAreaElement;

    await user.click(screen.getByRole("button", { name: "Validate" }));
    fireEvent.change(source, { target: { value: `${source.value}\n# newest source` } });
    await user.click(screen.getByRole("button", { name: "Validate" }));
    await act(async () => { gates[1].resolve(); });
    await waitFor(() => expect(screen.getByRole("button", { name: "Save" })).toBeEnabled());

    await act(async () => { gates[0].resolve(); });
    expect(screen.getByRole("button", { name: "Save" })).toBeEnabled();
    expect(screen.getByText(/Valid · 1 dry-run steps/)).toBeInTheDocument();
  });

  it("discards a flow document opened under the previous project authority", async () => {
    const user = userEvent.setup();
    const bridge = fixtureBridge();
    const originalOpenFlow = bridge.openFlow.bind(bridge);
    const gate = deferred();
    bridge.openFlow = vi.fn(async (fence, flowHandle) => {
      await gate.promise;
      return originalOpenFlow(fence, flowHandle);
    });
    render(<App bridge={bridge} />);
    await screen.findByRole("heading", { name: "payments-api" });
    await user.click(screen.getByRole("button", { name: "Flows" }));
    await screen.findByRole("region", { name: "Flow workspace" });
    await user.click(screen.getByRole("button", { name: /after-merge-checks/ }));

    await user.click(screen.getByRole("button", { name: "payments-api" }));
    await user.click(screen.getByRole("menuitemradio", { name: /ledger-web/ }));
    await screen.findByRole("button", { name: "ledger-web" });
    await screen.findByRole("region", { name: "Flow workspace" });
    expect(await screen.findByRole("heading", { name: "Select a definition" })).toBeInTheDocument();

    await act(async () => { gate.resolve(); });
    const source = screen.getByRole("textbox", { name: "Flow TOML source" }) as HTMLTextAreaElement;
    expect(source).toBeDisabled();
    expect(source.value).toBe("");
  });

  it("shows an inline retry when the flow workspace load fails", async () => {
    const user = userEvent.setup();
    const bridge = fixtureBridge();
    const originalLoadWorkspace = bridge.loadFlowWorkspace.bind(bridge);
    let attempts = 0;
    bridge.loadFlowWorkspace = vi.fn(async (fence) => {
      attempts += 1;
      if (attempts === 1) throw new Error("flow catalog temporarily unavailable");
      return originalLoadWorkspace(fence);
    });
    render(<App bridge={bridge} />);
    await screen.findByRole("heading", { name: "payments-api" });
    await user.click(screen.getByRole("button", { name: "Flows" }));

    expect(await screen.findByRole("alert")).toHaveTextContent("flow catalog temporarily unavailable");
    await user.click(screen.getByRole("button", { name: "Retry flows" }));
    expect(await screen.findByRole("region", { name: "Flow workspace" })).toBeInTheDocument();
  });

  it("registers a missing GUI caller through the fenced native recovery action", async () => {
    const user = userEvent.setup();
    const bridge = fixtureBridge("missing-credential");
    const originalRegister = bridge.registerGuiCaller.bind(bridge);
    const gate = deferred();
    bridge.registerGuiCaller = vi.fn(async (fence) => {
      await gate.promise;
      return originalRegister(fence);
    });
    render(<App bridge={bridge} />);

    const register = await screen.findByRole("button", { name: "Register GUI caller" });
    expect(screen.queryByText(/pam caller register|\/usr\/|\\\\/i)).not.toBeInTheDocument();
    await user.click(register);
    expect(screen.getByRole("button", { name: "Registering…" })).toBeDisabled();

    await act(async () => { gate.resolve(); });
    expect(await screen.findByRole("heading", { name: "Ready for the next agent" })).toBeInTheDocument();
    expect(await screen.findByRole("status")).toHaveTextContent("GUI caller registered");
    expect(bridge.registerGuiCaller).toHaveBeenCalledTimes(1);
  });

  it("keeps missing-credential recovery actionable after registration fails", async () => {
    const user = userEvent.setup();
    const bridge = fixtureBridge("missing-credential");
    bridge.registerGuiCaller = vi.fn().mockRejectedValue(new Error("/usr/local/bin/pam rejected secret-token"));
    render(<App bridge={bridge} />);

    await user.click(await screen.findByRole("button", { name: "Register GUI caller" }));

    expect(await screen.findByText("GUI caller registration could not be completed. Retry from this screen.")).toBeInTheDocument();
    expect(screen.queryByText(/\/usr\/local|secret-token/)).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Register GUI caller" })).toBeEnabled();
    expect(bridge.registerGuiCaller).toHaveBeenCalledTimes(1);
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
