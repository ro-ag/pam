import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import type { CommandFence, SkillAuditDataDto, SkillAuditDto } from "../domain";
import { fixtureBridge } from "../fixtures";
import { SkillAuditReportPanel } from "./SkillAuditReportPanel";

const firstFence: CommandFence = {
  projectHandle: "11111111-1111-4111-8111-111111111111",
  generation: "99999999-9999-4999-8999-999999999999",
  operationId: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
};

const secondFence: CommandFence = {
  projectHandle: "22222222-2222-4222-8222-222222222222",
  generation: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
  operationId: "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
};

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((done) => { resolve = done; });
  return { promise, resolve };
}

async function evaluatedData(): Promise<SkillAuditDataDto> {
  const response = await fixtureBridge().loadSkillAudit(firstFence);
  if (!response.data) throw new Error("evaluated fixture report is missing");
  return response.data;
}

describe("SkillAuditReportPanel", () => {
  it("loads the latest report on mount without running an audit", async () => {
    const bridge = fixtureBridge();
    bridge.loadSkillAudit = vi.fn(bridge.loadSkillAudit.bind(bridge));
    bridge.runSkillAudit = vi.fn(bridge.runSkillAudit.bind(bridge));

    render(<SkillAuditReportPanel bridge={bridge} fence={firstFence} />);

    expect(screen.getByRole("status")).toHaveTextContent("Loading latest skill audit");
    expect(await screen.findByRole("heading", { name: "Evaluator verdict" })).toBeInTheDocument();
    expect(bridge.loadSkillAudit).toHaveBeenCalledTimes(1);
    expect(bridge.runSkillAudit).not.toHaveBeenCalled();
    const requestFence = vi.mocked(bridge.loadSkillAudit).mock.calls[0][0];
    expect(requestFence).toMatchObject({ projectHandle: firstFence.projectHandle, generation: firstFence.generation });
    expect(requestFence.operationId).not.toBe(firstFence.operationId);
  });

  it("renders the exact evaluated footprint, top row, evaluator, grade, and all verdict categories", async () => {
    render(<SkillAuditReportPanel bridge={fixtureBridge()} fence={firstFence} />);

    expect(await screen.findByText("3,584")).toBeInTheDocument();
    expect(screen.getByText("2")).toBeInTheDocument();
    expect(screen.getByText("Project instructions")).toBeInTheDocument();
    expect(screen.getByText("AGENTS.md")).toBeInTheDocument();
    expect(screen.getByText("2,048 tokens")).toBeInTheDocument();
    expect(screen.getByText("codex", { selector: "dd" })).toBeInTheDocument();
    expect(screen.getAllByText("elevated")).toHaveLength(2);
    expect(screen.getByRole("heading", { name: "Overlaps" })).toBeInTheDocument();
    expect(screen.getByText("Two review instructions cover the same change-verification responsibility.")).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Conflicts" })).toBeInTheDocument();
    expect(screen.getByText("The project instructions and review skill disagree about when local checks may be skipped.")).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Stale candidates" })).toBeInTheDocument();
    expect(screen.getByText("This review skill references a command no longer present in the project.")).toBeInTheDocument();
    expect(screen.getByText("ID: artifact:sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc")).toBeInTheDocument();
  });

  it("shows deterministic-only fallback without inventing an evaluator verdict", async () => {
    render(<SkillAuditReportPanel bridge={fixtureBridge("skill-audit-no-evaluator")} fence={firstFence} />);

    expect(await screen.findByText(
      "Deterministic footprint only — no supported evaluator was available, so PAM did not produce a qualitative verdict.",
    )).toBeInTheDocument();
    expect(screen.getByText("deterministic only")).toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: "Evaluator verdict" })).not.toBeInTheDocument();
    expect(screen.queryByText("Saturation grade")).not.toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: "Overlaps" })).not.toBeInTheDocument();
  });

  it("renders unavailable observation time without throwing for an out-of-range timestamp", async () => {
    const bridge = fixtureBridge();
    const data = await evaluatedData();
    bridge.loadSkillAudit = vi.fn(async (fence) => ({
      fence,
      data: { ...data, observedAtMs: Number.MAX_SAFE_INTEGER },
    }));

    render(<SkillAuditReportPanel bridge={bridge} fence={firstFence} />);

    expect(await screen.findByText("Observation time unavailable")).toBeInTheDocument();
    expect(screen.getByText("Observation time unavailable")).not.toHaveAttribute("datetime");
  });

  it("shows closed evaluator and failure labels without a verdict when evaluation fails", async () => {
    render(<SkillAuditReportPanel bridge={fixtureBridge("skill-audit-failed")} fence={firstFence} />);

    expect(await screen.findByRole("heading", { name: "Evaluation status" })).toBeInTheDocument();
    expect(screen.getByText("Evaluator")).toBeInTheDocument();
    expect(screen.getByText("cursor agent")).toBeInTheDocument();
    expect(screen.getByText("Failure")).toBeInTheDocument();
    expect(screen.getByText("invalid verdict")).toBeInTheDocument();
    expect(screen.queryByText("Saturation grade")).not.toBeInTheDocument();
  });

  it("runs only from the explicit empty-state action with a fresh operation fence", async () => {
    const user = userEvent.setup();
    const bridge = fixtureBridge("skill-audit-empty");
    bridge.loadSkillAudit = vi.fn(bridge.loadSkillAudit.bind(bridge));
    bridge.runSkillAudit = vi.fn(bridge.runSkillAudit.bind(bridge));
    render(<SkillAuditReportPanel bridge={bridge} fence={firstFence} />);

    expect(await screen.findByText("No saved skill audit")).toBeInTheDocument();
    expect(bridge.runSkillAudit).not.toHaveBeenCalled();
    await user.click(screen.getByRole("button", { name: "Run audit" }));

    expect(await screen.findByRole("heading", { name: "Evaluator verdict" })).toBeInTheDocument();
    expect(bridge.runSkillAudit).toHaveBeenCalledTimes(1);
    const loadFence = vi.mocked(bridge.loadSkillAudit).mock.calls[0][0];
    const runFence = vi.mocked(bridge.runSkillAudit).mock.calls[0][0];
    expect(runFence).toMatchObject({ projectHandle: firstFence.projectHandle, generation: firstFence.generation });
    expect(runFence.operationId).not.toBe(firstFence.operationId);
    expect(runFence.operationId).not.toBe(loadFence.operationId);
  });

  it("keeps load failure inside the panel and retries the failed action", async () => {
    const user = userEvent.setup();
    const bridge = fixtureBridge();
    const data = await evaluatedData();
    let attempts = 0;
    bridge.loadSkillAudit = vi.fn(async (fence) => {
      attempts += 1;
      if (attempts === 1) throw new Error("bounded audit load unavailable");
      return { fence, data };
    });
    bridge.runSkillAudit = vi.fn(bridge.runSkillAudit.bind(bridge));
    render(<SkillAuditReportPanel bridge={bridge} fence={firstFence} />);

    expect(await screen.findByRole("alert")).toHaveTextContent("bounded audit load unavailable");
    await user.click(screen.getByRole("button", { name: "Retry audit" }));

    expect(await screen.findByRole("heading", { name: "Evaluator verdict" })).toBeInTheDocument();
    expect(bridge.loadSkillAudit).toHaveBeenCalledTimes(2);
    expect(bridge.runSkillAudit).not.toHaveBeenCalled();
  });

  it("rejects a response whose complete fence does not match the request", async () => {
    const bridge = fixtureBridge();
    const data = await evaluatedData();
    bridge.loadSkillAudit = vi.fn(async (fence) => ({
      fence: { ...fence, operationId: "dddddddd-dddd-4ddd-8ddd-dddddddddddd" },
      data,
    }));
    render(<SkillAuditReportPanel bridge={bridge} fence={firstFence} />);

    expect(await screen.findByRole("alert")).toHaveTextContent(
      "The skill audit response did not match the active project request",
    );
    expect(screen.queryByText("Project instructions")).not.toBeInTheDocument();
  });

  it("discards a report from the previous project authority", async () => {
    const bridge = fixtureBridge();
    const first = deferred<SkillAuditDto>();
    const second = deferred<SkillAuditDto>();
    const data = await evaluatedData();
    bridge.loadSkillAudit = vi
      .fn()
      .mockImplementationOnce(() => first.promise)
      .mockImplementationOnce(() => second.promise);
    const rendered = render(<SkillAuditReportPanel bridge={bridge} fence={firstFence} />);
    rendered.rerender(<SkillAuditReportPanel bridge={bridge} fence={secondFence} />);
    await waitFor(() => expect(bridge.loadSkillAudit).toHaveBeenCalledTimes(2));

    await act(async () => {
      const requestFence = vi.mocked(bridge.loadSkillAudit).mock.calls[1][0];
      second.resolve({
        fence: requestFence,
        data: { ...structuredClone(data), footprint: { ...structuredClone(data.footprint), estimator: "new_project_estimator" } },
      });
    });
    expect(await screen.findByText("Estimator: new project estimator")).toBeInTheDocument();

    await act(async () => {
      const requestFence = vi.mocked(bridge.loadSkillAudit).mock.calls[0][0];
      first.resolve({
        fence: requestFence,
        data: { ...structuredClone(data), footprint: { ...structuredClone(data.footprint), estimator: "stale_project_estimator" } },
      });
    });
    expect(screen.queryByText("Estimator: stale project estimator")).not.toBeInTheDocument();
    expect(screen.getByText("Estimator: new project estimator")).toBeInTheDocument();
  });
});
