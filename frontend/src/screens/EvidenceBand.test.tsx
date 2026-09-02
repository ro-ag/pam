import { QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { createAppQueryClient } from "../App";
import type { CompressReport } from "../lib/ipc";
import { EvidenceBand, isAbsolutePath } from "./EvidenceBand";

/**
 * The evidence band against a mocked bridge. `useReducedMotion` is
 * pinned true so the odometer lands on its figure synchronously — the
 * rolling digits are the animation, the number is the contract.
 */

const mocks = vi.hoisted(() => ({
  evidenceStats: vi.fn(),
  logCompress: vi.fn(),
}));

vi.mock("../lib/ipc", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../lib/ipc")>();
  return { ...actual, ...mocks };
});

vi.mock("motion/react", async (importOriginal) => {
  const actual = await importOriginal<typeof import("motion/react")>();
  return { ...actual, useReducedMotion: () => true };
});

function report(overrides: Partial<CompressReport> = {}): CompressReport {
  return {
    source: { id: "ev_s", bytes: 90_000 },
    compact: { id: "ev_c", bytes: 5_000 },
    summary: null,
    compact_text: "cargo build\nerror[E0308]",
    summary_text: null,
    stats: {
      source_bytes: 88_000,
      compact_bytes: 4_000,
      source_records: 1_204,
      retained_records: 61,
      tokens_source_est: 22_000,
      tokens_compact_est: 1_000,
      tokens_avoided_est: 21_000,
    },
    model: null,
    model_skipped: null,
    ...overrides,
  };
}

const onCompressed = vi.fn();

beforeEach(() => {
  onCompressed.mockClear();
  mocks.evidenceStats.mockResolvedValue({
    since_ts: 1_700_000_000,
    compressions: 3,
    source_bytes: 88_000,
    compact_bytes: 4_000,
    tokens_avoided_est: 21_450,
  });
  mocks.logCompress.mockResolvedValue(report());
});

function renderBand() {
  render(
    <QueryClientProvider client={createAppQueryClient()}>
      <EvidenceBand onCompressed={onCompressed} />
    </QueryClientProvider>,
  );
}

describe("the odometer tile", () => {
  it("holds an em dash until the first answer lands", () => {
    mocks.evidenceStats.mockReturnValue(new Promise(() => {}));
    renderBand();
    expect(screen.getByText("—")).toBeInTheDocument();
    expect(screen.queryByText(/compressions/)).not.toBeInTheDocument();
  });

  it("renders the window's figures once the stats land", async () => {
    renderBand();
    expect(await screen.findByText("21,450")).toBeInTheDocument();
    expect(screen.getByText(/3 compressions/)).toBeInTheDocument();
    expect(screen.getByText(/88 KB → 4 KB/)).toBeInTheDocument();
    expect(mocks.evidenceStats).toHaveBeenCalledWith();
  });

  it("renders a stats failure as a failure note instead of a number", async () => {
    mocks.evidenceStats.mockRejectedValue({
      cause: "daemon_unreachable",
      detail: "no daemon is answering",
      recovery: "Check that the pam daemon can start.",
    });
    renderBand();
    expect(await screen.findByText(/evidence stats · daemon_unreachable/)).toBeInTheDocument();
    expect(screen.getByText("no daemon is answering.")).toBeInTheDocument();
    expect(screen.queryByText("21,450")).not.toBeInTheDocument();
  });
});

describe("the compress box", () => {
  it("stays closed until the path is one the daemon can resolve", async () => {
    renderBand();
    await screen.findByText("21,450");
    const button = screen.getByRole("button", { name: "Compress" });
    expect(button).toBeDisabled();
    fireEvent.change(screen.getByLabelText("log path"), { target: { value: "build.log" } });
    expect(button).toBeDisabled();
    fireEvent.change(screen.getByLabelText("log path"), { target: { value: "/tmp/build.log" } });
    expect(button).toBeEnabled();
  });

  it("sends the path, the exit status, and the model toggle, then reports the saving", async () => {
    renderBand();
    await screen.findByText("21,450");
    fireEvent.change(screen.getByLabelText("log path"), { target: { value: "/tmp/build.log" } });
    fireEvent.change(screen.getByLabelText("exit status"), { target: { value: "1" } });
    fireEvent.click(screen.getByRole("button", { name: "Compress" }));
    await waitFor(() =>
      expect(mocks.logCompress).toHaveBeenCalledWith({
        path: "/tmp/build.log",
        exit_status: 1,
        model: true,
      }),
    );
    expect(await screen.findByText(/88 KB → 4 KB · ~21,000 tokens avoided/)).toBeInTheDocument();
    expect(onCompressed).toHaveBeenCalledTimes(1);
  });

  it("drops the model toggle and the exit status when neither is offered", async () => {
    renderBand();
    await screen.findByText("21,450");
    fireEvent.change(screen.getByLabelText("log path"), { target: { value: "/tmp/build.log" } });
    fireEvent.click(screen.getByLabelText("use model"));
    fireEvent.click(screen.getByRole("button", { name: "Compress" }));
    await waitFor(() =>
      expect(mocks.logCompress).toHaveBeenCalledWith({
        path: "/tmp/build.log",
        model: false,
      }),
    );
  });

  it("says why there is no summary when the model layer stood aside", async () => {
    mocks.logCompress.mockResolvedValue(
      report({
        model_skipped: { cause: "no_default", detail: "no heavy model is configured" },
      }),
    );
    renderBand();
    await screen.findByText("21,450");
    fireEvent.change(screen.getByLabelText("log path"), { target: { value: "/tmp/build.log" } });
    fireEvent.click(screen.getByRole("button", { name: "Compress" }));
    expect(
      await screen.findByText(/No summary this time — no heavy model is configured/),
    ).toBeInTheDocument();
  });

  it("renders a refusal as a failure note in the uniform shape", async () => {
    mocks.logCompress.mockRejectedValue({
      cause: "source_unreadable",
      detail: "cannot read /tmp/gone.log: No such file or directory",
      recovery: "Check the path and that the daemon's user can read it.",
    });
    renderBand();
    await screen.findByText("21,450");
    fireEvent.change(screen.getByLabelText("log path"), { target: { value: "/tmp/gone.log" } });
    fireEvent.click(screen.getByRole("button", { name: "Compress" }));
    expect(await screen.findByText(/compress · source_unreadable/)).toBeInTheDocument();
    expect(screen.getByText(/cannot read \/tmp\/gone.log/)).toBeInTheDocument();
    expect(onCompressed).not.toHaveBeenCalled();
  });
});

describe("isAbsolutePath", () => {
  it("accepts what the daemon accepts and nothing else", () => {
    for (const path of ["/tmp/build.log", "  /tmp/build.log  ", "C:\\logs\\build.log", "D:/b.log"])
      expect(isAbsolutePath(path), path).toBe(true);
    for (const path of ["", "build.log", "./build.log", "~/build.log", "C:build.log"])
      expect(isAbsolutePath(path), path).toBe(false);
  });
});
