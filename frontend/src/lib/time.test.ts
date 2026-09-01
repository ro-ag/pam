import { describe, expect, it } from "vitest";
import { exactTime, formatDuration, relativeTime } from "./time";

const NOW_MS = 1_756_000_000_000; // fixed "now" so ages are deterministic
const NOW_S = NOW_MS / 1000;

describe("relativeTime", () => {
  it.each([
    [0, "now"],
    [9, "now"],
    [10, "10s ago"],
    [42, "42s ago"],
    [59, "59s ago"],
    [60, "1m ago"],
    [185, "3m ago"],
    [3_599, "59m ago"],
    [3_600, "1h ago"],
    [5 * 3_600 + 40, "5h ago"],
    [86_400, "1d ago"],
    [2 * 86_400 + 3_600, "2d ago"],
    [604_800, "1w ago"],
    [3 * 604_800 + 86_400, "3w ago"],
  ] as const)("%ds elapsed reads %s", (elapsed, expected) => {
    expect(relativeTime(NOW_S - elapsed, NOW_MS)).toBe(expected);
  });

  it("treats a future timestamp (clock skew) as now", () => {
    expect(relativeTime(NOW_S + 120, NOW_MS)).toBe("now");
  });
});

describe("formatDuration", () => {
  it.each([
    [0, "0s"],
    [42, "42s"],
    [59, "59s"],
    [60, "1m 00s"],
    [185, "3m 05s"],
    [3_599, "59m 59s"],
    [3_600, "1h 00m"],
    [3_723, "1h 02m"],
    [86_399, "23h 59m"],
    [86_400, "1d 00h"],
    [2 * 86_400 + 11 * 3_600, "2d 11h"],
  ] as const)("%ds reads %s", (seconds, expected) => {
    expect(formatDuration(seconds)).toBe(expected);
  });

  it("treats a negative duration as zero", () => {
    expect(formatDuration(-5)).toBe("0s");
  });
});

describe("exactTime", () => {
  it("renders a full local stamp", () => {
    const stamp = exactTime(NOW_S);
    expect(stamp).toMatch(/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/);
    // Field values agree with the platform's own local rendering.
    const date = new Date(NOW_MS);
    expect(stamp.startsWith(String(date.getFullYear()))).toBe(true);
    expect(stamp.endsWith(`:${String(date.getSeconds()).padStart(2, "0")}`)).toBe(true);
  });
});
