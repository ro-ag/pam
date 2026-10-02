import { describe, expect, it } from "vitest";
import { app } from "../../crates/pam/tauri.conf.json";
import viteConfig from "../vite.config";

/** The CSP source list a release window grants one directive, e.g. `img-src`. */
function cspSources(csp: string, directive: string): string[] {
  const entry = csp
    .split(";")
    .map((part) => part.trim().split(/\s+/))
    .find(([name]) => name === directive);
  return entry?.slice(1) ?? [];
}

describe("release bundle against the release CSP", () => {
  it("never inlines assets as data: URIs the release CSP would block", () => {
    const csp = app.security.csp;
    // The release window forbids data: images and fonts; if that ever
    // loosens, this pairing can be revisited, not silently relied on.
    expect(cspSources(csp, "img-src")).not.toContain("data:");
    expect(cspSources(csp, "font-src")).not.toContain("data:");

    const config =
      typeof viteConfig === "function"
        ? viteConfig({ mode: "production", command: "build" })
        : viteConfig;
    expect(config).not.toBeInstanceOf(Promise);
    expect(
      (config as { build?: { assetsInlineLimit?: unknown } }).build?.assetsInlineLimit,
    ).toBe(0);
  });
});
