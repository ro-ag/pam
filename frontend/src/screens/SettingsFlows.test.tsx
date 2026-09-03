import { QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { createAppQueryClient } from "../App";
import { SettingsFlowsSection } from "./SettingsFlows";

/**
 * Settings → Flows against a mocked bridge: the allowlist chips, the
 * extra-PATH rows, and the one refusal this panel exists to teach — a
 * shell is not a program pam will run.
 */

const mocks = vi.hoisted(() => ({
  flowsSettingsGet: vi.fn(),
  flowsSettingsSet: vi.fn(),
}));

vi.mock("../lib/ipc", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../lib/ipc")>();
  return { ...actual, ...mocks };
});

const SETTINGS = {
  allowed_programs: ["git", "cargo"],
  extra_path: ["/opt/homebrew/bin"],
};

beforeEach(() => {
  mocks.flowsSettingsGet.mockResolvedValue(SETTINGS);
  mocks.flowsSettingsSet.mockImplementation((patch: Record<string, string[]>) =>
    Promise.resolve({ ...SETTINGS, ...patch }),
  );
});

async function renderSection() {
  render(
    <QueryClientProvider client={createAppQueryClient()}>
      <SettingsFlowsSection />
    </QueryClientProvider>,
  );
  await screen.findByText("git");
}

describe("allowed programs", () => {
  it("shows one chip per allowed program", async () => {
    await renderSection();
    for (const program of SETTINGS.allowed_programs) {
      expect(screen.getByText(program)).toBeInTheDocument();
      expect(screen.getByLabelText(`remove program ${program}`)).toBeInTheDocument();
    }
  });

  it("adds a program through the daemon, not just on screen", async () => {
    await renderSection();
    fireEvent.change(screen.getByLabelText("program to allow"), { target: { value: "gh" } });
    fireEvent.click(within(screen.getByLabelText("program to allow").closest("form") as HTMLFormElement).getByRole("button", { name: "Add" }));
    await waitFor(() =>
      expect(mocks.flowsSettingsSet).toHaveBeenCalledWith({
        allowed_programs: ["git", "cargo", "gh"],
      }),
    );
  });

  it("removes a program by sending the list without it", async () => {
    await renderSection();
    fireEvent.click(screen.getByLabelText("remove program cargo"));
    await waitFor(() =>
      expect(mocks.flowsSettingsSet).toHaveBeenCalledWith({ allowed_programs: ["git"] }),
    );
  });

  it("renders the daemon's shell refusal instead of pretending it saved", async () => {
    mocks.flowsSettingsSet.mockRejectedValue({
      cause: "program_not_allowed",
      detail: '"bash" is a shell: allowing it would allow every program',
      recovery: "Name the program the step actually runs, not a shell.",
    });
    await renderSection();
    fireEvent.change(screen.getByLabelText("program to allow"), { target: { value: "bash" } });
    fireEvent.click(within(screen.getByLabelText("program to allow").closest("form") as HTMLFormElement).getByRole("button", { name: "Add" }));
    expect(
      await screen.findByText(/flow settings · program_not_allowed/),
    ).toBeInTheDocument();
    expect(screen.getByText(/allowing it would allow every program/)).toBeInTheDocument();
  });
});

describe("extra PATH", () => {
  it("adds and removes a directory through the same op", async () => {
    await renderSection();
    fireEvent.change(screen.getByLabelText("directory to add to PATH"), {
      target: { value: "/usr/local/bin" },
    });
    fireEvent.click(
      within(
        screen.getByLabelText("directory to add to PATH").closest("form") as HTMLFormElement,
      ).getByRole("button", { name: "Add" }),
    );
    await waitFor(() =>
      expect(mocks.flowsSettingsSet).toHaveBeenCalledWith({
        extra_path: ["/opt/homebrew/bin", "/usr/local/bin"],
      }),
    );

    fireEvent.click(screen.getByLabelText("remove directory /opt/homebrew/bin"));
    await waitFor(() =>
      expect(mocks.flowsSettingsSet).toHaveBeenCalledWith({ extra_path: [] }),
    );
  });
});
