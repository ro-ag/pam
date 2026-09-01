import { describe, expect, it } from "vitest";
import { cn } from "./cn";

describe("cn", () => {
  it("joins classes and drops falsy conditionals", () => {
    expect(cn("bg-surface", false, undefined, "text-ink")).toBe("bg-surface text-ink");
  });

  it("lets the later conflicting utility win (tailwind-merge)", () => {
    expect(cn("px-4", "px-8")).toBe("px-8");
    expect(cn("bg-surface", "bg-chrome")).toBe("bg-chrome");
  });

  it("keeps non-conflicting utilities intact", () => {
    expect(cn("rounded-panel shadow-float", "p-10")).toBe("rounded-panel shadow-float p-10");
  });
});
