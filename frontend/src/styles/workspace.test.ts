import { describe, expect, it } from "vitest";
import styles from "../styles.css?raw";

describe("desktop workspace materials", () => {
  it("uses one preblurred backdrop without surface textures or remote requests", () => {
    expect(styles).not.toContain("glass-droplets");
    expect(styles).toContain('url("./assets/materials/chaos-soft.webp")');
    expect(styles).not.toMatch(/url\(["']?https?:/);
    expect(styles).not.toMatch(/(?:backdrop-)?filter:\s*blur/);
    expect(styles).not.toContain(".command-surface::before");
    expect(styles).not.toContain(".command-surface::after");
    expect(styles).toMatch(/\.desktop-shell::before\s*\{[^}]*pointer-events: none/);
  });

  it("keeps the desktop material above default utility precedence", () => {
    const material = styles.indexOf("/* Material overrides must win");
    expect(material).toBeGreaterThan(styles.lastIndexOf("@layer"));
    expect(styles.slice(material)).toMatch(/\.desktop-panel\s*\{\s*background: color-mix/);
  });

  it("stretches the wave mask to both window dimensions without tiling", () => {
    for (const property of ["mask", "-webkit-mask"]) {
      expect(styles).toContain(
        `${property}: url("./assets/materials/chaos-soft.webp") center / 100% 100% no-repeat`,
      );
    }
  });

  it("offers reversible slow drift, an off switch and reduced-motion protection", () => {
    expect(styles).toContain(
      "animation: background-drift var(--background-drift-duration, 120s)",
    );
    expect(styles).toContain("ease-in-out infinite");
    expect(styles).toContain("alternate;");
    expect(styles).toMatch(
      /\[data-background-motion="off"\] .desktop-shell::before\s*\{\s*animation: none/,
    );
    const keyframes = styles.slice(
      styles.indexOf("@keyframes background-drift"),
      styles.indexOf(".desktop-sidebar"),
    );
    expect(keyframes).toContain("transform: scale(1) rotate(0deg)");
    expect(keyframes).toContain("transform: scale(1.2) rotate(2deg)");
    expect(keyframes.match(/\b[\w-]+:/g)).toEqual(["transform:", "transform:"]);
    const reduced = styles.slice(styles.indexOf("@media (prefers-reduced-motion: reduce)"));
    expect(reduced).toContain("*::before");
    expect(reduced).toContain("animation: none !important");
  });

  it("removes textures for opaque, reduced transparency and forced colors", () => {
    const opaque = styles.slice(styles.indexOf('[data-material="opaque"]'));
    expect(opaque).toMatch(/\.desktop-shell::before\s*\{\s*display: none/);
    for (const preference of [
      "prefers-reduced-transparency: reduce",
      "forced-colors: active",
    ]) {
      const media = styles.slice(styles.indexOf(`@media (${preference})`));
      expect(media).toMatch(/\.desktop-shell::before\s*\{\s*display: none/);
      expect(media).toContain(".desktop-shell::before");
    }
  });
});

describe("Settings layout contract", () => {
  it("scrolls the active pane while keeping the workspace and tabs fixed", () => {
    expect(styles).toMatch(/\.workspace-scroll\[data-settings\]\s*\{\s*overflow: hidden/);
    expect(styles).toMatch(/\.settings-pane\s*\{[^}]*overflow: auto/);
    expect(styles).toMatch(/\.settings-pane\[hidden\]\s*\{\s*display: none/);
    expect(styles).toMatch(/\.settings-tabs\s*\{[^}]*flex-shrink: 0/);
  });

  it("uses content-width breakpoints and additional columns on wide windows", () => {
    expect(styles).toContain("@container (min-width: 960px)");
    expect(styles).toContain("@container (min-width: 1400px)");
    expect(styles).toMatch(/\.appearance-grid\s*\{\s*grid-template-columns: repeat\(4,/);
    expect(styles).toMatch(/\.connector-grid\s*\{\s*grid-template-columns: repeat\(3,/);
    expect(styles).toContain("max-width: 1440px");
  });

  it("keeps selected tabs identifiable when decorative colors are unavailable", () => {
    const forced = styles.slice(styles.indexOf("@media (forced-colors: active)"));
    expect(forced).toContain('[role="tab"][aria-selected="true"]');
    expect(forced).toContain("outline: 2px solid Highlight");
  });
});
