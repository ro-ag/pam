import { act, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { GlassProps } from "@samasante/liquid-glass";
import { LiquidGlassBackdrop } from "./LiquidGlassBackdrop";
import { applyBackgroundMotion, applyMaterial, initTheme } from "../../lib/theme";
import { applyWorkspace, initWorkspace } from "../../lib/workspace";
import tauriConfig from "../../../../crates/pam/tauri.conf.json";

const glass = vi.hoisted(() => ({ fail: false }));
vi.mock("@samasante/liquid-glass", () => ({
  Glass: ({ refract, live, filterResolution, pixelUnits }: GlassProps) => {
    if (glass.fail) throw new Error("Canvas unavailable");
    return (
      <div
        data-testid="lens"
        data-live={live}
        data-resolution={filterResolution}
        data-pixels={pixelUnits}
      >
        {refract}
      </div>
    );
  },
}));

let intersect: (entries: { isIntersecting: boolean }[]) => void;
let resize: () => void;
let width = 480;
let height = 320;
let left = 300;
const media = new Map<string, { matches: boolean; listeners: Set<() => void> }>();
const copyAnimation = { currentTime: 0 };
const sourceAnimation = { animationName: "background-drift", currentTime: 37_000 };
const disconnect = vi.fn();

beforeEach(() => {
  glass.fail = false;
  width = 480;
  height = 320;
  left = 300;
  media.clear();
  disconnect.mockClear();
  vi.stubGlobal("CSS", { supports: () => true });
  vi.stubGlobal(
    "IntersectionObserver",
    class {
      constructor(callback: typeof intersect) {
        intersect = callback;
      }
      observe() {}
      disconnect = disconnect;
    },
  );
  vi.stubGlobal(
    "ResizeObserver",
    class {
      constructor(callback: () => void) {
        resize = callback;
      }
      observe() {}
      disconnect = disconnect;
    },
  );
  vi.stubGlobal("matchMedia", (query: string) => {
    if (!media.has(query)) media.set(query, { matches: false, listeners: new Set() });
    const item = media.get(query)!;
    return {
      get matches() {
        return item.matches;
      },
      addEventListener: (_: string, listener: () => void) => item.listeners.add(listener),
      removeEventListener: (_: string, listener: () => void) => item.listeners.delete(listener),
    };
  });
  vi.spyOn(document, "hidden", "get").mockReturnValue(false);
  vi.spyOn(Element.prototype, "getBoundingClientRect").mockImplementation(function (
    this: Element,
  ) {
    return this.classList.contains("desktop-shell")
      ? new DOMRect(0, 0, 1920, 1080)
      : new DOMRect(left, 200, width, height);
  });
  Object.defineProperty(Element.prototype, "getAnimations", {
    configurable: true,
    value: function (this: Element) {
      return this.classList.contains("desktop-shell") ? [sourceAnimation] : [copyAnimation];
    },
  });
  window.localStorage.clear();
  initTheme();
  initWorkspace();
});

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  Reflect.deleteProperty(Element.prototype, "getAnimations");
});

function mount() {
  const result = render(
    <div className="desktop-shell">
      <section className="liquid-glass-panel">
        <LiquidGlassBackdrop />
        <button>Real control</button>
      </section>
    </div>,
  );
  act(() => intersect([{ isIntersecting: true }]));
  return result;
}

function preference(query: string, matches: boolean) {
  act(() => {
    const item = media.get(query)!;
    item.matches = matches;
    item.listeners.forEach((listener) => listener());
  });
}

describe("bounded liquid glass", () => {
  it("refracts only a hidden decorative crop, aligned and synchronized with the shell", () => {
    const { container } = mount();
    const lens = screen.getByTestId("lens");
    expect(lens).toHaveAttribute("data-resolution", "1");
    expect(lens).toHaveAttribute("data-pixels", "true");
    expect(lens).toHaveAttribute("data-live", "true");
    expect(lens).not.toContainElement(screen.getByRole("button", { name: "Real control" }));
    const backdrop = container.querySelector<HTMLElement>(".liquid-glass-backdrop")!;
    expect(backdrop).toHaveAttribute("aria-hidden", "true");
    expect(backdrop).toHaveAttribute("inert");
    expect(backdrop.style.getPropertyValue("--glass-scene-left")).toBe("-300px");
    expect(backdrop.style.getPropertyValue("--glass-scene-width")).toBe("1920px");
    expect(copyAnimation.currentTime).toBe(sourceAnimation.currentTime);
  });

  it("disables live work for motion off or system reduced motion without removing controls", () => {
    mount();
    act(() => applyBackgroundMotion("off"));
    expect(screen.getByTestId("lens")).toHaveAttribute("data-live", "false");
    act(() => applyBackgroundMotion("slow"));
    preference("(prefers-reduced-motion: reduce)", true);
    expect(screen.getByTestId("lens")).toHaveAttribute("data-live", "false");
    preference("(prefers-reduced-motion: reduce)", false);
    expect(screen.getByTestId("lens")).toHaveAttribute("data-live", "true");
  });

  it.each(["(prefers-reduced-transparency: reduce)", "(forced-colors: active)"])(
    "unmounts the renderer for %s",
    (query) => {
      mount();
      preference(query, true);
      expect(screen.queryByTestId("lens")).not.toBeInTheDocument();
      expect(screen.getByRole("button")).toBeEnabled();
      preference(query, false);
      expect(screen.getByTestId("lens")).toBeInTheDocument();
    },
  );

  it("unmounts for opaque material, hidden panes and background windows", () => {
    mount();
    act(() => applyMaterial("opaque"));
    expect(screen.queryByTestId("lens")).not.toBeInTheDocument();
    act(() => applyMaterial("glass"));
    act(() => intersect([{ isIntersecting: false }]));
    expect(screen.queryByTestId("lens")).not.toBeInTheDocument();
    act(() => intersect([{ isIntersecting: true }]));
    expect(screen.getByTestId("lens")).toBeInTheDocument();
    vi.spyOn(document, "hidden", "get").mockReturnValue(true);
    fireEvent(document, new Event("visibilitychange"));
    expect(screen.queryByTestId("lens")).not.toBeInTheDocument();
  });

  it("falls back outside the filter size budget and restores after resizing", () => {
    mount();
    width = 1200;
    act(() => resize());
    expect(screen.queryByTestId("lens")).not.toBeInTheDocument();
    width = 480;
    height = 700;
    act(() => resize());
    expect(screen.queryByTestId("lens")).not.toBeInTheDocument();
    height = 320;
    act(() => resize());
    expect(screen.getByTestId("lens")).toBeInTheDocument();
  });

  it("realigns a position-only layout change and the end of a pane entrance", () => {
    const { container } = mount();
    const backdrop = container.querySelector<HTMLElement>(".liquid-glass-backdrop")!;
    left = 180;
    act(() => applyWorkspace({ sidebar: "compact", width: "full" }));
    expect(backdrop.style.getPropertyValue("--glass-scene-left")).toBe("-180px");
    left = 200;
    fireEvent.animationEnd(backdrop.parentElement!);
    expect(backdrop.style.getPropertyValue("--glass-scene-left")).toBe("-200px");
  });

  it("tolerates missing animation inspection and legacy media-query listeners", () => {
    Reflect.deleteProperty(Element.prototype, "getAnimations");
    const add = vi.fn();
    const remove = vi.fn();
    vi.stubGlobal("matchMedia", () => ({
      matches: false,
      addListener: add,
      removeListener: remove,
    }));
    const view = mount();
    expect(screen.getByTestId("lens")).toBeInTheDocument();
    expect(add).toHaveBeenCalledTimes(3);
    view.unmount();
    expect(remove).toHaveBeenCalledTimes(3);
  });

  it("keeps the UI usable when filters are unsupported or the library throws", () => {
    vi.stubGlobal("CSS", { supports: () => false });
    const first = mount();
    expect(screen.queryByTestId("lens")).not.toBeInTheDocument();
    first.unmount();
    vi.stubGlobal("CSS", { supports: () => true });
    glass.fail = true;
    vi.spyOn(console, "error").mockImplementation(() => {});
    const second = mount();
    expect(screen.queryByTestId("lens")).not.toBeInTheDocument();
    expect(screen.getByRole("button")).toBeEnabled();
    second.unmount();
    expect(disconnect).toHaveBeenCalled();
    expect([...media.values()].every((entry) => entry.listeners.size === 0)).toBe(true);
  });
});

it("permits generated image maps in production without expanding script or network sources", () => {
  const csp = tauriConfig.app.security.csp;
  expect(csp).toContain("img-src 'self' data:");
  expect(csp).toContain("script-src 'self';");
  expect(csp).toContain("connect-src ipc: http://ipc.localhost;");
  expect(csp).not.toContain("unsafe-eval");
});
