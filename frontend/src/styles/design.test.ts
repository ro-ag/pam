import { describe, expect, it } from "vitest";
import { badgeVariants } from "../components/ui/Badge";
import { buttonVariants } from "../components/ui/Button";
import { panelVariants } from "../components/ui/Panel";
import themesCss from "./themes.css?raw";
import tokensCss from "./tokens.css?raw";

/**
 * Design-system contract tests.
 *
 * The token layer (`tokens.css` + `themes.css`) is the ONE place style
 * decisions live; components consume semantic utilities only. These tests
 * make that contract executable:
 *
 *  1. every semantic role components rely on exists in `tokens.css`;
 *  2. the stock Tailwind namespaces stay wiped (no `bg-neutral-950` ever);
 *  3. all four theme blocks define the same primitive set, every primitive
 *     `tokens.css` references resolves in every theme, and the bare-`:root`
 *     dark fallback stays verbatim in sync with Ventisquero dark;
 *  4. the cva exemplars (Panel/Badge/Button) keep their variant maps total,
 *     distinct, and token-backed — no variant may smuggle in a class the
 *     token set does not answer for.
 */

/* ------------------------------------------------------------------ *
 * The semantic surface — the names components are allowed to use.
 * ------------------------------------------------------------------ */

const SEMANTIC_COLORS = [
  // grounds
  "chrome",
  "surface",
  "surface-raised",
  // ink
  "ink",
  "ink-muted",
  "ink-faint",
  // hairlines
  "line",
  "edge",
  "control-line",
  "flow-edge",
  "inset",
  "selection-ink",
  "separator",
  // accent ramp
  "accent",
  "accent-strong",
  "accent-hover",
  "accent-pressed",
  "accent-soft",
  "on-accent",
  // status + warmth
  "success",
  "success-soft",
  "warning",
  "warning-soft",
  "danger",
  "danger-soft",
  "copper",
  // the beacon
  "beacon-green",
  "beacon-amber",
  "beacon-red",
  // refusals are beautiful
  "refusal",
  "refusal-soft",
  // interaction furniture
  "focus",
  "overlay",
] as const;

const SEMANTIC_SHADOWS = ["raise", "float"] as const;
const SEMANTIC_RADII = ["control", "card", "panel", "badge", "overlay", "pill"] as const;
const SEMANTIC_FONTS = ["display", "voice", "data", "sans"] as const;

/** Non-color `text-*` utilities that legitimately survive the wipe. */
const TEXT_SIZES = new Set(["xs", "sm", "base", "lg", "xl", "2xl", "hero", "title"]);

/** Non-family `font-*` utilities (weights are stock and kept). */
const FONT_WEIGHTS = new Set(["light", "normal", "medium", "semibold", "bold"]);

/* ------------------------------------------------------------------ *
 * CSS parsing helpers — regex over ?raw imports, no build step.
 * ------------------------------------------------------------------ */

function stripComments(css: string): string {
  return css.replace(/\/\*[\s\S]*?\*\//g, "");
}

/** The body of the first block whose selector contains `selector`. */
function blockOf(css: string, selector: string): string {
  const at = css.indexOf(selector);
  expect(at, `themes.css must contain a ${selector} block`).toBeGreaterThanOrEqual(0);
  const open = css.indexOf("{", at);
  const close = css.indexOf("}", open);
  return css.slice(open + 1, close);
}

/** `--<prefix>-*` declarations of a block as name → normalized value. */
function declarationsOf(block: string, prefix = "pam"): Record<string, string> {
  const decls: Record<string, string> = {};
  for (const match of block.matchAll(
    new RegExp(`(--${prefix}-[a-z0-9-]+)\\s*:\\s*([^;]+);`, "g"),
  )) {
    decls[match[1]] = match[2]
      .replace(/\s+/g, " ")
      .replace(/\(\s+/g, "(")
      .replace(/\s+\)/g, ")")
      .trim();
  }
  return decls;
}

const themes = stripComments(themesCss);
const tokens = stripComments(tokensCss);

const THEME_COMBOS = [
  '[data-theme="ventisquero"][data-mode="light"]',
  '[data-theme="ventisquero"][data-mode="dark"]',
  '[data-theme="vina"][data-mode="light"]',
  '[data-theme="vina"][data-mode="dark"]',
] as const;

/* ------------------------------------------------------------------ *
 * 1 + 2 — tokens.css: the semantic namespace and the wipes.
 * ------------------------------------------------------------------ */

describe("tokens.css semantic namespace", () => {
  it("declares every color role components rely on", () => {
    for (const name of SEMANTIC_COLORS) {
      expect(tokens, `--color-${name} must be mapped in tokens.css`).toMatch(
        new RegExp(`--color-${name}\\s*:`),
      );
    }
  });

  it("declares exactly the two shadows, the compact radii, and the four voices", () => {
    for (const name of SEMANTIC_SHADOWS) {
      expect(tokens).toMatch(new RegExp(`--shadow-${name}\\s*:`));
    }
    for (const name of SEMANTIC_RADII) {
      expect(tokens).toMatch(new RegExp(`--radius-${name}\\s*:`));
    }
    for (const name of SEMANTIC_FONTS) {
      expect(tokens).toMatch(new RegExp(`--font-${name}\\s*:`));
    }
  });

  it("wipes the stock Tailwind namespaces so only semantic utilities exist", () => {
    for (const wipe of ["--color-*", "--shadow-*", "--radius-*", "--font-*"]) {
      expect(tokens, `${wipe}: initial keeps the stock scale out`).toContain(
        `${wipe}: initial`,
      );
    }
  });
});

/* ------------------------------------------------------------------ *
 * 3 — themes.css: four palettes, one primitive contract.
 * ------------------------------------------------------------------ */

describe("themes.css primitive contract", () => {
  const blocks = THEME_COMBOS.map((combo) => ({
    combo,
    decls: declarationsOf(blockOf(themes, combo)),
  }));

  it("defines a non-empty primitive set in every theme block", () => {
    for (const { combo, decls } of blocks) {
      expect(Object.keys(decls).length, `${combo} defines primitives`).toBeGreaterThan(0);
    }
  });

  it("defines the SAME primitive set in all four theme blocks", () => {
    const reference = Object.keys(blocks[0].decls).sort();
    for (const { combo, decls } of blocks.slice(1)) {
      expect(Object.keys(decls).sort(), `${combo} must match ${blocks[0].combo}`).toEqual(
        reference,
      );
    }
  });

  it("resolves every primitive tokens.css references, in every theme", () => {
    // The two deliberately theme-independent tokens live on bare :root.
    const rootDefined = new Set(["--pam-separator", "--pam-density"]);
    const referenced = [...tokens.matchAll(/var\((--pam-[a-z0-9-]+)\)/g)].map(
      (match) => match[1],
    );
    expect(referenced.length).toBeGreaterThan(0);
    for (const { combo, decls } of blocks) {
      for (const primitive of referenced) {
        if (rootDefined.has(primitive)) continue;
        expect(
          decls[primitive],
          `${combo} must define ${primitive} (referenced by tokens.css)`,
        ).toBeDefined();
      }
    }
  });

  it("keeps the bare-:root dark fallback verbatim in sync with Ventisquero dark", () => {
    const fallback = declarationsOf(blockOf(themes, ":root:not([data-mode])"));
    const ventisqueroDark = declarationsOf(
      blockOf(themes, '[data-theme="ventisquero"][data-mode="dark"]'),
    );
    expect(fallback).toEqual(ventisqueroDark);
  });
});

/* ------------------------------------------------------------------ *
 * 4 — cva exemplars: variant maps stay total, distinct, token-backed.
 * ------------------------------------------------------------------ */

/** Asserts every styling utility in a cva output resolves from the token set. */
function expectTokenBacked(classString: string, label: string): void {
  const colors = new Set<string>(SEMANTIC_COLORS);
  const shadows = new Set<string>(SEMANTIC_SHADOWS);
  const radii = new Set<string>(SEMANTIC_RADII);
  const fonts = new Set<string>(SEMANTIC_FONTS);
  for (const raw of classString.split(/\s+/).filter(Boolean)) {
    // Strip state prefixes (hover:, active:, disabled:) and opacity (/40).
    const utility = (raw.split(":").pop() ?? raw).split("/")[0];
    const claim = (ok: boolean, role: string) => {
      expect(ok, `${label}: ${raw} must resolve from the semantic ${role} tokens`).toBe(true);
    };
    if (utility.startsWith("bg-")) {
      claim(colors.has(utility.slice(3)), "color");
    } else if (utility.startsWith("text-")) {
      const rest = utility.slice(5);
      claim(colors.has(rest) || TEXT_SIZES.has(rest), "color/size");
    } else if (utility !== "border" && utility.startsWith("border-")) {
      claim(colors.has(utility.slice(7)), "color");
    } else if (utility.startsWith("shadow-")) {
      claim(shadows.has(utility.slice(7)), "shadow");
    } else if (utility.startsWith("rounded-")) {
      claim(radii.has(utility.slice(8)), "radius");
    } else if (utility.startsWith("font-")) {
      const rest = utility.slice(5);
      claim(fonts.has(rest) || FONT_WEIGHTS.has(rest), "font");
    }
    // Everything else (flex, gap, px, transition, …) is layout furniture.
  }
}

/** Asserts each declared variant yields a distinct, token-backed class string. */
function expectTotalAndDistinct(label: string, rendered: ReadonlyMap<string, string>): void {
  const outputs = [...rendered.values()];
  expect(new Set(outputs).size, `${label} variants must style distinctly`).toBe(outputs.length);
  for (const [variant, classes] of rendered) {
    expect(classes.trim().length, `${label}.${variant} renders classes`).toBeGreaterThan(0);
    expectTokenBacked(classes, `${label}.${variant}`);
  }
}

describe("cva exemplars", () => {
  it("Panel: all grounds render distinct token-backed elevations", () => {
    const grounds = ["surface", "raised", "command"] as const;
    expectTotalAndDistinct(
      "Panel",
      new Map(grounds.map((ground) => [ground, panelVariants({ ground })])),
    );
  });

  it("Badge: all five tones render distinct token-backed chips in the data voice", () => {
    const tones = ["neutral", "accent", "success", "warning", "danger"] as const;
    const rendered = new Map(tones.map((tone) => [tone, badgeVariants({ tone })]));
    expectTotalAndDistinct("Badge", rendered);
    for (const classes of rendered.values()) {
      expect(classes).toContain("font-data");
      expect(classes).toContain("rounded-badge");
    }
  });

  it("Button: every variant x size combination is distinct and token-backed", () => {
    const variants = ["primary", "ghost", "danger"] as const;
    const sizes = ["sm", "md"] as const;
    const rendered = new Map(
      variants.flatMap((variant) =>
        sizes.map((size) => [`${variant}-${size}`, buttonVariants({ variant, size })] as const),
      ),
    );
    expectTotalAndDistinct("Button", rendered);
  });
});

/* ------------------------------------------------------------------ *
 * 5 — xyflow: the canvas is themed only through the variables it reads.
 * ------------------------------------------------------------------ */

describe("xyflow bindings", () => {
  it("binds every --xy-* variable to a semantic token, never a raw value", () => {
    const declarations = declarationsOf(blockOf(tokens, ".flow-canvas .react-flow"), "xy");
    const names = Object.keys(declarations);
    expect(names.length).toBeGreaterThan(8);
    for (const name of names) {
      const value = declarations[name];
      const ok =
        /^var\(--(color|shadow)-[a-z-]+\)$/.test(value) ||
        value === "transparent" ||
        /^[0-9.]+$/.test(value) ||
        /^1px solid var\(--color-[a-z-]+\)$/.test(value);
      expect(ok, `${name}: ${value}`).toBe(true);
    }
  });

  it("gives running edges their dash: an --animate-dash token, its keyframes, and the class", () => {
    expect(tokens).toMatch(/--animate-dash\s*:\s*dash /);
    expect(tokens).toContain("@keyframes dash");
    expect(tokens).toMatch(
      /\.flow-canvas \.flow-edge-running\s*\{\s*stroke-dasharray:\s*6;?\s*\}/,
    );
  });
});

function luminance(hex: string): number {
  const channels = hex.match(/^#([a-f0-9]{2})([a-f0-9]{2})([a-f0-9]{2})$/i);
  if (!channels) throw new Error(`Expected opaque canvas color, got ${hex}`);
  const linear = channels.slice(1).map((channel) => {
    const value = parseInt(channel, 16) / 255;
    return value <= 0.04045 ? value / 12.92 : ((value + 0.055) / 1.055) ** 2.4;
  });
  return linear[0] * 0.2126 + linear[1] * 0.7152 + linear[2] * 0.0722;
}

it("keeps every semantic flow edge above 3:1 on the actual opaque canvas in all themes", () => {
  expect(tokensCss).toContain("--color-flow-edge: var(--pam-ink-muted)");
  expect(tokensCss).toContain("--xy-background-color: var(--color-chrome)");
  for (const theme of THEME_COMBOS) {
    const palette = declarationsOf(blockOf(themesCss, theme));
    const backdrop = luminance(palette["--pam-chrome"]);
    for (const role of ["ink-muted", "success", "danger", "accent"]) {
      const stroke = luminance(palette[`--pam-${role}`]);
      const contrast =
        (Math.max(stroke, backdrop) + 0.05) / (Math.min(stroke, backdrop) + 0.05);
      expect(contrast, `${theme} ${role} canvas contrast`).toBeGreaterThanOrEqual(3);
    }
  }
});
