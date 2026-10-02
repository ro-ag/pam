import { render, screen, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import type { FlowStepReport } from "../lib/ipc";
import {
  isModelSummary,
  StepTable,
  summaryProvenance,
  UNTRUSTED_SUMMARY_LABEL,
} from "./FlowRunCard";

/**
 * The step table's summaries. A summary a local model wrote is text the step's own output
 * influenced; the CLI labels it `[untrusted local-model summary]` and escapes its control
 * characters, and the table must say and do the same.
 */

function step(overrides: Partial<FlowStepReport> & Record<string, unknown>): FlowStepReport {
  return {
    id: "build",
    kind: "command",
    status: "succeeded",
    attempts: 1,
    duration_ms: 1_200,
    exit_status: 0,
    evidence: [],
    ...overrides,
  } as FlowStepReport;
}

/** The daemon's marker for a model-written summary: the model and the record that admitted it. */
const SUMMARY_MODEL = {
  id: "openai/gpt-oss-20b-MXFP4",
  qualification: {
    artifact: "gpt-oss-20b-MXFP4",
    contract: "answer-contract-v2",
    record: "docs/benchmarks/2026-09-15-answer-contract-v2",
    engine_tag: "b10938",
  },
};

function row(id: string) {
  const cell = screen.getByText(id, { selector: "td" });
  return within(cell);
}

describe("a step's summary in the step table", () => {
  it("labels a summary a local model wrote, with the words the CLI prints", () => {
    render(
      <StepTable
        steps={[
          step({
            id: "summarize",
            summary: "The build failed in the link stage.\nExit status 1.",
            summary_model: SUMMARY_MODEL,
          }),
        ]}
      />,
    );
    expect(UNTRUSTED_SUMMARY_LABEL).toBe("[untrusted local-model summary]");
    const cell = row("summarize");
    const label = cell.getByText(UNTRUSTED_SUMMARY_LABEL);
    const first = cell.getByText("The build failed in the link stage.");
    // The label comes before the text it qualifies, and each line stays a line.
    expect(label.compareDocumentPosition(first) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    expect(cell.getByText("Exit status 1.")).toBeInTheDocument();
    expect(first.parentElement?.parentElement?.querySelectorAll("br")).toHaveLength(1);
    // And what stands behind it is said in plain words: the bench, not the summary, was measured.
    expect(
      cell.getByText(
        "Qualified on the capability bench (contract v2). Summaries are advisory and not separately measured.",
      ),
    ).toBeInTheDocument();
  });

  it("claims no qualification for a summary whose step carries no record", () => {
    expect(summaryProvenance(step({ summary: "x", summary_model: { id: "m" } }))).toBe(
      "Summaries are advisory and not separately measured.",
    );
    expect(
      summaryProvenance(step({ summary: "x", summary_model: { id: "m", qualification: null } })),
    ).toBe("Summaries are advisory and not separately measured.");
    expect(
      summaryProvenance(
        step({
          summary: "x",
          summary_model: { id: "m", qualification: { contract: "house-contract" } },
        }),
      ),
    ).toBe(
      "Qualified on the capability bench (house-contract). Summaries are advisory and not separately measured.",
    );
  });

  it("shows hidden characters in a model-written summary as visible escapes", () => {
    render(
      <StepTable
        steps={[
          step({
            id: "summarize",
            // A right-to-left override and an escape character: what a hostile log would echo.
            summary: "all checks passed‮gnp.exe\u001B[2J",
            summary_model: SUMMARY_MODEL,
          }),
        ]}
      />,
    );
    const cell = row("summarize");
    expect(cell.getByText("\\u{202E}")).toHaveAttribute(
      "title",
      "a hidden character, shown as its escape",
    );
    expect(cell.getByText("\\u{001B}")).toBeInTheDocument();
    expect(cell.getByText("all checks passed")).toBeInTheDocument();
  });

  it("leaves a summary the host composed unlabelled", () => {
    render(
      <StepTable
        steps={[step({ id: "compress", summary: "summary skipped: no default model" })]}
      />,
    );
    const cell = row("compress");
    expect(cell.getByText("summary skipped: no default model")).toBeInTheDocument();
    expect(cell.queryByText(UNTRUSTED_SUMMARY_LABEL)).toBeNull();
  });

  it("decides model authorship the way the CLI does, failing towards the label", () => {
    expect(isModelSummary(step({ summary: "x", summary_model: SUMMARY_MODEL }))).toBe(true);
    expect(isModelSummary(step({ summary: "x", summary_model: { id: "m" } }))).toBe(true);
    for (const key of ["model_summary", "untrusted", "summary_untrusted"]) {
      expect(isModelSummary(step({ summary: "x", [key]: true }))).toBe(true);
      expect(isModelSummary(step({ summary: "x", [key]: "true" }))).toBe(false);
    }
    expect(isModelSummary(step({ summary: "x" }))).toBe(false);
    expect(isModelSummary(step({ summary: "x", summary_model: null }))).toBe(false);
    expect(isModelSummary(step({ summary: "x", summary_model: "gpt" }))).toBe(false);
  });
});
