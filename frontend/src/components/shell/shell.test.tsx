import { createMemoryHistory } from "@tanstack/react-router";
import { fireEvent, render, screen, within } from "@testing-library/react";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from "vitest";
import App from "../../App";
import { createAppRouter } from "../../router";
import { Beacon } from "./Beacon";
import { initWorkspace } from "../../lib/workspace";

/** Mount the whole shell on a fresh, isolated memory history. */
function renderShell(path = "/") {
  render(<App router={createAppRouter(createMemoryHistory({ initialEntries: [path] }))} />);
}

/**
 * The shell reads `navigator.userAgent` to decide whether macOS floats the
 * traffic lights over our sidebar head, so stubbing it is how we mock
 * `hasTrafficLights()` from the outside.
 */
const realUserAgent = navigator.userAgent;
const realShowModal = Object.getOwnPropertyDescriptor(HTMLDialogElement.prototype, "showModal");
const realClose = Object.getOwnPropertyDescriptor(HTMLDialogElement.prototype, "close");
beforeAll(() => {
  Object.defineProperty(HTMLDialogElement.prototype, "showModal", {
    configurable: true,
    value(this: HTMLDialogElement) {
      this.open = true;
    },
  });
  Object.defineProperty(HTMLDialogElement.prototype, "close", {
    configurable: true,
    value(this: HTMLDialogElement) {
      this.open = false;
    },
  });
});
afterAll(() => {
  if (realShowModal)
    Object.defineProperty(HTMLDialogElement.prototype, "showModal", realShowModal);
  else Reflect.deleteProperty(HTMLDialogElement.prototype, "showModal");
  if (realClose) Object.defineProperty(HTMLDialogElement.prototype, "close", realClose);
  else Reflect.deleteProperty(HTMLDialogElement.prototype, "close");
});
beforeEach(() => {
  window.localStorage.clear();
  initWorkspace();
});

function stubTrafficLights(present: boolean) {
  Object.defineProperty(window.navigator, "userAgent", {
    value: present
      ? "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"
      : "Mozilla/5.0 (X11; Linux x86_64)",
    configurable: true,
  });
}

afterEach(() => {
  Object.defineProperty(window.navigator, "userAgent", {
    value: realUserAgent,
    configurable: true,
  });
});

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

  it("keeps the idle beacon still and labels its state", () => {
    render(<Beacon state="connected" />);
    const beacon = screen.getByRole("status", { name: "daemon connected" });
    expect(beacon.innerHTML).not.toContain("animate-breathe");
    expect(beacon).toHaveTextContent("Connected");
  });
});

describe("PanelToolbar", () => {
  it("is a labelled toolbar whose row drags the window but whose controls do not", async () => {
    renderShell();
    const toolbar = await screen.findByRole("toolbar", { name: "panel controls" });
    expect(toolbar).toHaveAttribute("data-tauri-drag-region");
    expect(within(toolbar).getByRole("status")).toBeInTheDocument();
    const controls = within(toolbar).getAllByRole("button");
    expect(controls).toHaveLength(4);
    for (const control of controls) {
      expect(control).not.toHaveAttribute("data-tauri-drag-region");
    }
  });
});

describe("shell layout", () => {
  it("wires palette navigation and restores a saved screen with its workspace layout", async () => {
    renderShell("/settings");
    await screen.findByRole("heading", { name: "Settings" });
    fireEvent.keyDown(document, { key: "k", ctrlKey: true });
    const search = screen.getByRole("combobox", {
      name: "Search pages, settings, flows, and models",
    });
    fireEvent.change(search, { target: { value: "retention" } });
    fireEvent.keyDown(search, { key: "Enter" });
    await screen.findByRole("tabpanel", { name: "Retention" });
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Workspace" }));
    fireEvent.click(screen.getByRole("button", { name: "Compact" }));
    fireEvent.click(screen.getByRole("button", { name: "Focused" }));
    fireEvent.change(screen.getByLabelText("Layout name"), { target: { value: "My desk" } });
    fireEvent.click(screen.getByRole("button", { name: "Save" }));
    fireEvent.click(screen.getByRole("button", { name: "Monitor" }));
    await screen.findByRole("heading", { name: "Activity" });
    fireEvent.click(screen.getByRole("button", { name: "Workspace" }));
    fireEvent.click(screen.getByRole("button", { name: "My desk" }));
    await screen.findByRole("tabpanel", { name: "Retention" });
    expect(document.documentElement.dataset.workspaceSidebar).toBe("compact");
    expect(document.documentElement.dataset.workspaceWidth).toBe("focused");
    expect(screen.getByRole("link", { name: "Settings" })).toHaveAttribute("title", "Settings");
  });
  it("starts a new screen at the top of its workspace", async () => {
    renderShell("/activity");
    await screen.findByRole("heading", { name: "Activity" });
    const workspace = document.querySelector<HTMLElement>(".workspace-scroll")!;
    workspace.scrollTop = 480;
    fireEvent.click(screen.getByRole("link", { name: "Home" }));
    await screen.findByRole("heading", { name: "Home" });
    expect(document.querySelector(".workspace-scroll")?.scrollTop).toBe(0);
  });

  it("has no window-wide top strip above the sidebar and the panel", async () => {
    renderShell("/activity");
    await screen.findByRole("heading", { name: "Activity" });
    expect(document.querySelector("header[data-tauri-drag-region]")).toBeNull();
  });

  it("puts the brand block in the sidebar column, as a drag region", async () => {
    renderShell("/activity");
    await screen.findByRole("heading", { name: "Activity" });
    const nav = screen.getByRole("navigation", { name: "Primary" });
    const column = nav.parentElement as HTMLElement;
    expect(column).not.toBeNull();
    const wordmark = screen.getByText("PAM");
    expect(column).toContainElement(wordmark);
    expect(wordmark).toHaveAttribute("data-tauri-drag-region");
    expect(within(column).getByText("personal agent machine")).toHaveAttribute(
      "data-tauri-drag-region",
    );
  });

  it("keeps the draggable toolbar above the scrolling workspace", async () => {
    renderShell("/activity");
    await screen.findByRole("heading", { name: "Activity" });
    const panel = document.querySelector("main section");
    expect(panel).not.toBeNull();
    const toolbar = screen.getByRole("toolbar", { name: "panel controls" });
    expect(panel?.firstElementChild).toBe(toolbar);
    expect(
      within(toolbar).getByRole("status", { name: "daemon unreachable" }),
    ).toBeInTheDocument();
    const controls = within(toolbar).getAllByRole("button");
    expect(controls).toHaveLength(4);
    for (const control of controls) {
      expect(control).not.toHaveAttribute("data-tauri-drag-region");
    }
  });

  it("drops the sidebar head below the macOS traffic lights when they overlay it", async () => {
    stubTrafficLights(true);
    renderShell("/activity");
    await screen.findByRole("heading", { name: "Activity" });
    const head = screen.getByText("PAM").parentElement as HTMLElement;
    expect(head.className).toContain("pt-10");
    expect(head.className).not.toContain("pt-4");
  });

  it("keeps the head tight to the top when there are no traffic lights", async () => {
    stubTrafficLights(false);
    renderShell("/activity");
    await screen.findByRole("heading", { name: "Activity" });
    const head = screen.getByText("PAM").parentElement as HTMLElement;
    expect(head.className).toContain("pt-4");
    expect(head.className).not.toContain("pt-10");
  });
});

describe("Sidebar", () => {
  it("puts Home first and renders the Home screen at /", async () => {
    const router = createAppRouter(createMemoryHistory({ initialEntries: ["/"] }));
    render(<App router={router} />);
    const nav = await screen.findByRole("navigation", { name: "Primary" });
    const links = within(nav).getAllByRole("link");
    expect(links.map((link) => link.textContent)).toEqual([
      "Home",
      "Activity",
      "Approvals",
      "Flows",
      "Models",
      "Settings",
    ]);
    expect(links[0]).toHaveAttribute("aria-current", "page");
    expect(await screen.findByRole("heading", { name: "Home" })).toBeInTheDocument();
  });
});
