import { fireEvent, render, screen, within } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import type { ModelsStatus, TierReadiness } from "../lib/ipc";
import {
  NO_RECORD_SENTENCE,
  ReadinessCard,
  ReadinessLine,
  RUNGS,
  readinessSentence,
  repairFor,
  stopIndex,
} from "./Readiness";

/**
 * Readiness draws the daemon's verdict and nothing else: the chain stops
 * where the daemon says, the sentence is the daemon's own detail when
 * blocked, and the one repair button goes where that rung is fixed.
 */

function tier(overrides: Partial<TierReadiness> = {}): TierReadiness {
  return {
    tier: "heavy",
    configured: "candidates/gpt-oss-20b-MXFP4",
    model_id: "candidates/gpt-oss-20b-MXFP4",
    fallback: false,
    stage: "ready",
    resident: false,
    qualification: {
      artifact: "gpt-oss-20b-MXFP4",
      sha256: "27cd6c43",
      engine_tag: "b10938",
      targets: ["macos-arm64"],
      contract: "answer-contract-v2",
      case_set_sha256: "7796",
      record: "docs/benchmarks/2026-09-15-answer-contract-v2",
      host: "test host",
      accuracy: 0.98,
      false_passes: 0,
      warm_p95_ms: 593,
      decided: "2026-09-15",
    },
    blocker: null,
    ...overrides,
  };
}

function status(overrides: Partial<ModelsStatus> = {}): ModelsStatus {
  return {
    runtime: { state: { state: "idle" }, busy: false },
    jobs: [],
    defaults: { light: null, heavy: "candidates/gpt-oss-20b-MXFP4" },
    idle_unload_min: 10,
    models_dir: "/Users/dev/llm",
    host_ram_bytes: 64_000_000_000,
    readiness: {
      light: tier({
        tier: "light",
        configured: null,
        model_id: null,
        stage: "unconfigured",
        qualification: null,
        blocker: {
          cause: "no_default",
          detail: "no default model for tier light",
          recovery: "Point the tier at a qualified model under Settings > Models.",
        },
      }),
      heavy: tier(),
    },
    ...overrides,
  };
}

describe("the chain", () => {
  it("stops at the failing rung and runs to the end when ready", () => {
    expect(stopIndex("unconfigured")).toBe(0);
    expect(stopIndex("unqualified")).toBe(3);
    expect(stopIndex("engine_missing")).toBe(4);
    expect(stopIndex("ready")).toBe(RUNGS.length);
  });

  it("names one repair per blocked stage and none when ready", () => {
    expect(repairFor("unconfigured")).toEqual({ label: "Choose a model", target: "settings" });
    expect(repairFor("missing")?.target).toBe("catalog");
    expect(repairFor("unverified")?.target).toBe("library");
    expect(repairFor("unqualified")?.target).toBe("settings");
    expect(repairFor("engine_missing")).toEqual({ label: "Install engine", target: "catalog" });
    expect(repairFor("ready")).toBeNull();
  });

  it("speaks the daemon's detail when blocked and residency when ready", () => {
    expect(
      readinessSentence(
        tier({
          stage: "unqualified",
          blocker: { cause: "model_unqualified", detail: "it is not qualified", recovery: "" },
        }),
        10,
      ),
    ).toBe("it is not qualified");
    expect(readinessSentence(tier({ resident: true }), 10)).toBe("Ready and in memory.");
    expect(readinessSentence(tier(), 10)).toMatch(/leaves memory after 10 idle minutes/);
    expect(readinessSentence(tier(), 0)).toMatch(/stays in memory/);
  });
});

describe("ReadinessCard", () => {
  it("draws both tiers, marks the failing rung, and routes the repair", () => {
    const onRepair = vi.fn();
    render(<ReadinessCard status={status()} failure={null} onRepair={onRepair} />);

    const light = screen.getByRole("list", { name: "light readiness" });
    const rungs = within(light).getAllByRole("listitem");
    expect(rungs).toHaveLength(RUNGS.length);
    expect(rungs[0]).toHaveAttribute("aria-current", "step");
    expect(rungs[0]).toHaveAttribute("data-state", "stop");
    expect(rungs[1]).toHaveAttribute("data-state", "todo");
    expect(screen.getByText("no default model for tier light")).toBeInTheDocument();
    expect(
      screen.getByText("Point the tier at a qualified model under Settings > Models."),
    ).toBeInTheDocument();

    const heavy = screen.getByRole("list", { name: "heavy readiness" });
    for (const rung of within(heavy).getAllByRole("listitem")) {
      expect(rung).toHaveAttribute("data-state", "done");
      expect(rung).not.toHaveAttribute("aria-current");
    }
    expect(screen.getByText("ready", { selector: ".rounded-badge" })).toBeInTheDocument();
    expect(
      screen.getByText(/answer-contract-v2 · 98\.0% · 0 false passes · b10938/),
    ).toBeInTheDocument();
    expect(screen.queryByText(/Semantic compression/)).toBeNull();

    fireEvent.click(screen.getByRole("button", { name: "Choose a model" }));
    expect(onRepair).toHaveBeenCalledWith("settings");
    expect(screen.queryByRole("button", { name: /another model|Verify|Install/ })).toBeNull();
  });

  it("badges residency beside the verdict and names a borrowed model", () => {
    render(
      <ReadinessCard
        status={status({
          readiness: {
            light: tier({ tier: "light", resident: true }),
            heavy: tier({ configured: null, fallback: true, resident: true }),
          },
        })}
        failure={null}
        onRepair={vi.fn()}
      />,
    );
    expect(screen.getAllByText("in memory")).toHaveLength(2);
    expect(screen.getByText(/borrowed from light/)).toBeInTheDocument();
    expect(screen.getAllByText("Ready and in memory.")).toHaveLength(2);
  });

  it("says so, rather than guessing, when the daemon reports no record", () => {
    render(
      <ReadinessCard
        status={status({ readiness: undefined })}
        failure={null}
        onRepair={vi.fn()}
      />,
    );
    expect(screen.getByText(NO_RECORD_SENTENCE)).toBeInTheDocument();
    expect(screen.queryByRole("list")).toBeNull();
  });
});

describe("ReadinessLine", () => {
  it("is one warning sentence when blocked and nothing without a record", () => {
    const { rerender } = render(
      <ReadinessLine
        readiness={tier({
          stage: "engine_missing",
          blocker: { cause: "engine_not_installed", detail: "no engine", recovery: "" },
        })}
        idleUnloadMin={10}
      />,
    );
    expect(screen.getByText("no engine")).toHaveClass("text-warning");
    rerender(<ReadinessLine readiness={undefined} idleUnloadMin={10} />);
    expect(screen.queryByText("no engine")).toBeNull();
  });
});
