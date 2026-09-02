import { describe, expect, it } from "vitest";
import { formatBytes, percentOf } from "./bytes";

/**
 * The floor is written as 18 GB everywhere in the model layer, so the
 * formatter has to agree with it: decimal units, one decimal from GB up.
 */
describe("formatBytes", () => {
  it.each([
    [0, "0 B"],
    [1, "1 B"],
    [999, "999 B"],
    [1_000, "1 KB"],
    [639_000_000, "639 MB"],
    [18_556_689_568, "18.6 GB"],
    [18_000_000_000, "18.0 GB"],
    [32_483_935_392, "32.5 GB"],
    [1_500_000_000_000, "1.5 TB"],
  ])("renders %i as %s", (bytes, expected) => {
    expect(formatBytes(bytes)).toBe(expected);
  });

  it("refuses to invent a figure for nonsense input", () => {
    expect(formatBytes(-1)).toBe("—");
    expect(formatBytes(Number.NaN)).toBe("—");
  });
});

describe("percentOf", () => {
  it("rounds to whole percent", () => {
    expect(percentOf(9_278_344_784, 18_556_689_568)).toBe(50);
    expect(percentOf(1, 3)).toBe(33);
  });

  it("has no percentage without a known total", () => {
    expect(percentOf(100, null)).toBeNull();
    expect(percentOf(100, 0)).toBeNull();
  });

  it("clamps a server that overshoots its own total", () => {
    expect(percentOf(200, 100)).toBe(100);
  });
});
