import { describe, expect, it } from "vitest";
import {
  escapeCodePoint,
  escapeInvisible,
  hasHiddenCharacters,
  headAndTail,
  safeSegments,
} from "./safeText";

describe("safeSegments", () => {
  it("leaves ordinary text, spaces and non-latin letters exactly as they are", () => {
    expect(safeSegments("git push origin main")).toEqual([
      { text: "git push origin main", hidden: false },
    ]);
    expect(escapeInvisible("héllo wörld — 日本語 🚀")).toBe("héllo wörld — 日本語 🚀");
  });

  it("spells out bidi overrides, zero-width characters and controls where they sit", () => {
    expect(escapeInvisible("a‮b")).toBe("a\\u{202E}b");
    expect(escapeInvisible("x​y")).toBe("x\\u{200B}y");
    expect(escapeInvisible("a⁦b⁩")).toBe("a\\u{2066}b\\u{2069}");
    expect(escapeInvisible("line\nbreak\ttab\u0000nul")).toBe(
      "line\\u{000A}break\\u{0009}tab\\u{0000}nul",
    );
    expect(escapeInvisible("﻿bom")).toBe("\\u{FEFF}bom");
    expect(escapeInvisible("soft­hyphen")).toBe("soft\\u{00AD}hyphen");
    expect(escapeInvisible("sep here")).toBe("sep\\u{2028}here");
  });

  it("marks which segments stand in for a hidden character, losing nothing", () => {
    expect(safeSegments("ab‮cd")).toEqual([
      { text: "ab", hidden: false },
      { text: "\\u{202E}", hidden: true },
      { text: "cd", hidden: false },
    ]);
  });

  it("detects hidden characters", () => {
    expect(hasHiddenCharacters("plain")).toBe(false);
    expect(hasHiddenCharacters("pla‍in")).toBe(true);
  });

  it("formats code points with braces, uppercase hex and four digits at least", () => {
    expect(escapeCodePoint("‮")).toBe("\\u{202E}");
    expect(escapeCodePoint("\u0007")).toBe("\\u{0007}");
    expect(escapeCodePoint("\u{E0041}")).toBe("\\u{E0041}");
  });
});

describe("headAndTail", () => {
  it("returns nothing to split for text that fits", () => {
    expect(headAndTail("short", 10, 3)).toBeNull();
  });

  it("keeps the tail visible and counts what sits between", () => {
    const value = `${"a".repeat(50)}${"m".repeat(40)}${"z".repeat(10)}`;
    const split = headAndTail(value, 60, 10);
    expect(split).not.toBeNull();
    expect(split?.tail).toBe("z".repeat(10));
    expect(split?.head).toBe("a".repeat(50));
    expect(split?.omitted).toBe(40);
  });
});
