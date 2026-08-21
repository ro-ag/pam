import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import type { CommandFence, SkillInventoryDataDto, SkillInventoryDto } from "../domain";
import { fixtureBridge } from "../fixtures";
import { SkillInventoryPanel } from "./SkillInventoryPanel";

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

function artifact(name: string, id: string) {
  return {
    id: `artifact:sha256:${id.repeat(64)}`,
    name,
    logicalPath: `.claude/skills/${name}/SKILL.md`,
    kind: "skill",
    scope: "project",
    origin: "claude_code",
    loadSemantics: "model_selected",
    contentHash: `sha256:${id.repeat(64)}`,
    firstSeenAtMs: 10,
    lastChangedAtMs: 20,
  };
}

function inventory(overrides: Partial<SkillInventoryDataDto> = {}): SkillInventoryDataDto {
  const artifacts = [artifact("review", "a")];
  return {
    artifacts,
    total: artifacts.length,
    truncated: false,
    drift: { added: 1, changed: 2, removed: 3, resurrected: 4 },
    cursorGlobalRulesStatus: "not_locally_discoverable",
    ...overrides,
  };
}

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((done) => { resolve = done; });
  return { promise, resolve };
}

describe("SkillInventoryPanel", () => {
  it("renders loading, drift, artifacts, and bounded truncation metadata", async () => {
    const bridge = fixtureBridge();
    const gate = deferred<SkillInventoryDto>();
    bridge.loadSkillInventory = vi.fn(() => gate.promise);
    render(<SkillInventoryPanel bridge={bridge} fence={firstFence} />);

    expect(screen.getByRole("status")).toHaveTextContent("Scanning bounded local agent configuration");
    await act(async () => {
      const requestFence = vi.mocked(bridge.loadSkillInventory).mock.calls[0][0];
      gate.resolve({
        fence: requestFence,
        data: inventory({ total: 300, truncated: true }),
      });
    });

    expect(await screen.findByText("review")).toBeInTheDocument();
    expect(screen.getByRole("status")).toHaveTextContent("1 added, 2 changed, 3 removed, 4 restored");
    expect(screen.getByText("Showing 1 of 300 artifacts. The native response is bounded.")).toBeInTheDocument();
  });

  it("renders the explicit empty state", async () => {
    const bridge = fixtureBridge();
    bridge.loadSkillInventory = vi.fn(async (fence) => ({
      fence,
      data: inventory({ artifacts: [], total: 0, drift: { added: 0, changed: 0, removed: 0, resurrected: 0 } }),
    }));
    render(<SkillInventoryPanel bridge={bridge} fence={firstFence} />);

    expect(await screen.findByText("No supported agent artifacts were found for this project.")).toBeInTheDocument();
    expect(screen.getByRole("status")).toHaveTextContent("No inventory drift detected");
  });

  it("keeps scan failure in the panel and retries", async () => {
    const user = userEvent.setup();
    const bridge = fixtureBridge();
    let attempts = 0;
    bridge.loadSkillInventory = vi.fn(async (fence) => {
      attempts += 1;
      if (attempts === 1) throw new Error("bounded inventory unavailable");
      return { fence, data: inventory() };
    });
    render(<SkillInventoryPanel bridge={bridge} fence={firstFence} />);

    expect(await screen.findByRole("alert")).toHaveTextContent("bounded inventory unavailable");
    await user.click(screen.getByRole("button", { name: "Retry inventory" }));

    expect(await screen.findByText("review")).toBeInTheDocument();
    expect(bridge.loadSkillInventory).toHaveBeenCalledTimes(2);
  });

  it("rejects a response whose complete fence does not match the request", async () => {
    const bridge = fixtureBridge();
    bridge.loadSkillInventory = vi.fn(async (fence) => ({
      fence: { ...fence, operationId: "dddddddd-dddd-4ddd-8ddd-dddddddddddd" },
      data: inventory(),
    }));
    render(<SkillInventoryPanel bridge={bridge} fence={firstFence} />);

    expect(await screen.findByRole("alert")).toHaveTextContent(
      "The skill inventory response did not match the active project request",
    );
    expect(screen.queryByText("review")).not.toBeInTheDocument();
  });

  it("discards a response from the previous project authority", async () => {
    const bridge = fixtureBridge();
    const first = deferred<SkillInventoryDto>();
    const second = deferred<SkillInventoryDto>();
    bridge.loadSkillInventory = vi
      .fn()
      .mockImplementationOnce(() => first.promise)
      .mockImplementationOnce(() => second.promise);
    const rendered = render(<SkillInventoryPanel bridge={bridge} fence={firstFence} />);
    rendered.rerender(<SkillInventoryPanel bridge={bridge} fence={secondFence} />);
    await waitFor(() => expect(bridge.loadSkillInventory).toHaveBeenCalledTimes(2));

    await act(async () => {
      const requestFence = vi.mocked(bridge.loadSkillInventory).mock.calls[1][0];
      second.resolve({ fence: requestFence, data: inventory({ artifacts: [artifact("new-project", "b")] }) });
    });
    expect(await screen.findByText("new-project")).toBeInTheDocument();

    await act(async () => {
      const requestFence = vi.mocked(bridge.loadSkillInventory).mock.calls[0][0];
      first.resolve({ fence: requestFence, data: inventory({ artifacts: [artifact("stale-project", "c")] }) });
    });
    expect(screen.queryByText("stale-project")).not.toBeInTheDocument();
    expect(screen.getByText("new-project")).toBeInTheDocument();
  });
});
