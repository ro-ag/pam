import { createMemoryHistory } from "@tanstack/react-router";
import { render, screen, within } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import App from "../../App";
import { createAppRouter } from "../../router";
import { Beacon } from "./Beacon";
import { PanelToolbar } from "./PanelToolbar";

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
  it("is a labelled toolbar whose row drags the window but whose controls do not", () => {
    render(<PanelToolbar />);
    const toolbar = screen.getByRole("toolbar", { name: "panel controls" });
    expect(toolbar).toHaveAttribute("data-tauri-drag-region");
    expect(within(toolbar).getByRole("status")).toBeInTheDocument();
    const controls = within(toolbar).getAllByRole("button");
    expect(controls).toHaveLength(2);
    for (const control of controls) {
      expect(control).not.toHaveAttribute("data-tauri-drag-region");
    }
  });
});

describe("shell layout", () => {
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

  it("makes the toolbar the panel's first child, inside the panel", async () => {
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
    expect(controls).toHaveLength(2);
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
    expect(
      await screen.findByRole("heading", { name: /^Good (morning|afternoon|evening)$/ }),
    ).toBeInTheDocument();
  });
});
