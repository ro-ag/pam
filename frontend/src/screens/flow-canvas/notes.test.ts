import { describe, expect, it } from "vitest";
import { parseNote, statusesFrom } from "./notes";

describe("parseNote", () => {
  it("parses the running note", () => {
    expect(parseNote("clippy: running (3/6)")).toEqual({ step: "clippy", status: "running" });
  });

  it("parses every settle word", () => {
    for (const status of ["succeeded", "failed", "skipped", "blocked", "cancelled"] as const) {
      expect(parseNote(`fmt-check: ${status}`)).toEqual({ step: "fmt-check", status });
    }
  });

  it("ignores anything else", () => {
    for (const note of [
      "queued · waiting",
      "",
      "clippy: exploded",
      "clippy: running",
      "clippy running (1/2)",
      "Clippy: succeeded",
      "clippy: succeeded quickly",
      "solved: 3 of 3 steps",
    ]) {
      expect(parseNote(note), note).toBeNull();
    }
  });
});

describe("statusesFrom", () => {
  it("later notes win", () => {
    expect(statusesFrom(["a: running (1/2)", "a: succeeded", "b: running (2/2)"])).toEqual({
      a: "succeeded",
      b: "running",
    });
  });

  it("skips unmatched notes and is empty for none", () => {
    expect(statusesFrom([])).toEqual({});
    expect(statusesFrom(["queued", "a: running (1/1)", "done"])).toEqual({ a: "running" });
  });
});
