import { QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { createAppQueryClient } from "../App";
import type { EvidenceContent, EvidenceMeta } from "../lib/ipc";
import { EvidenceStrip } from "./EvidenceStrip";

/**
 * The evidence strip against a mocked bridge: the chips a request's rows
 * become, and the viewer each one opens into.
 */

const mocks = vi.hoisted(() => ({
  evidenceList: vi.fn(),
  evidenceGet: vi.fn(),
}));

vi.mock("../lib/ipc", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../lib/ipc")>();
  return { ...actual, ...mocks };
});

const COMPACT_META = {
  name: "build.log",
  source_bytes: 88_000,
  compact_bytes: 4_000,
  source_records: 1_204,
  retained_records: 61,
  tokens_avoided_est: 21_000,
};

function meta(overrides: Partial<EvidenceMeta>): EvidenceMeta {
  return {
    id: "ev_s",
    request_id: "req_1",
    kind: "log.source",
    bytes: 88_000,
    sha256: "abc",
    meta: null,
    ts: 1_700_000_000,
    ...overrides,
  };
}

function content(overrides: Partial<EvidenceContent>): EvidenceContent {
  return {
    ...meta({}),
    text: "cargo build\nerror[E0308]",
    text_bytes: 24,
    truncated: false,
    ...overrides,
  };
}

const ROWS: EvidenceMeta[] = [
  meta({ id: "ev_s", kind: "log.source", bytes: 88_000 }),
  meta({ id: "ev_c", kind: "log.compact", bytes: 6_000, meta: COMPACT_META }),
];

beforeEach(() => {
  mocks.evidenceList.mockResolvedValue({ evidence: ROWS });
  mocks.evidenceGet.mockResolvedValue(content({}));
});

function renderStrip(requestId = "req_1") {
  render(
    <QueryClientProvider client={createAppQueryClient()}>
      <EvidenceStrip requestId={requestId} />
    </QueryClientProvider>,
  );
}

describe("the strip", () => {
  it("renders nothing for a request that left no evidence", async () => {
    mocks.evidenceList.mockResolvedValue({ evidence: [] });
    const { container } = render(
      <QueryClientProvider client={createAppQueryClient()}>
        <EvidenceStrip requestId="req_quiet" />
      </QueryClientProvider>,
    );
    await waitFor(() => expect(mocks.evidenceList).toHaveBeenCalledWith("req_quiet"));
    expect(container).toBeEmptyDOMElement();
    expect(mocks.evidenceGet).not.toHaveBeenCalled();
  });

  it("renders one chip per row with its kind, its blob size, and its id", async () => {
    renderStrip();
    const source = await screen.findByRole("button", { name: "log.source · 88 KB" });
    expect(source).toHaveAttribute("title", "ev_s");
    expect(source).toHaveAttribute("aria-pressed", "false");
    expect(screen.getByRole("button", { name: "log.compact · 6 KB" })).toHaveAttribute(
      "title",
      "ev_c",
    );
  });
});

describe("the viewer", () => {
  it("opens a compact row on its stats line above the reduced text", async () => {
    mocks.evidenceGet.mockResolvedValue(
      content({
        id: "ev_c",
        kind: "log.compact",
        bytes: 6_000,
        meta: COMPACT_META,
        text: "cargo build\nerror[E0308]: mismatched types",
      }),
    );
    renderStrip();
    fireEvent.click(await screen.findByRole("button", { name: "log.compact · 6 KB" }));
    await waitFor(() => expect(mocks.evidenceGet).toHaveBeenCalledWith("ev_c"));
    expect(
      await screen.findByText("1,204 → 61 records · 88 KB → 4 KB · ~21,000 tokens avoided"),
    ).toBeInTheDocument();
    expect(screen.getByText(/mismatched types/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "log.compact · 6 KB" })).toHaveAttribute(
      "aria-pressed",
      "true",
    );
  });

  it("gives a summary the UI font and no stats line", async () => {
    mocks.evidenceList.mockResolvedValue({
      evidence: [meta({ id: "ev_m", kind: "log.summary", bytes: 300 })],
    });
    mocks.evidenceGet.mockResolvedValue(
      content({
        id: "ev_m",
        kind: "log.summary",
        bytes: 300,
        text: "The build failed on one type mismatch.",
      }),
    );
    renderStrip();
    fireEvent.click(await screen.findByRole("button", { name: "log.summary · 300 B" }));
    const prose = await screen.findByText("The build failed on one type mismatch.");
    expect(prose.className).toContain("font-sans");
    expect(screen.queryByText(/records ·/)).not.toBeInTheDocument();
  });

  it("says how much of a truncated body it is showing", async () => {
    mocks.evidenceGet.mockResolvedValue(
      content({ text: "x".repeat(2_000), text_bytes: 900_000, truncated: true }),
    );
    renderStrip();
    fireEvent.click(await screen.findByRole("button", { name: "log.source · 88 KB" }));
    expect(await screen.findByText("showing the first 2 KB of 900 KB")).toBeInTheDocument();
  });

  it("renders a refusal on the row it could not read", async () => {
    mocks.evidenceGet.mockRejectedValue({
      cause: "not_found",
      detail: 'no evidence row carries the id "ev_s"',
      recovery: "Pick an evidence handle from the request's row.",
    });
    renderStrip();
    fireEvent.click(await screen.findByRole("button", { name: "log.source · 88 KB" }));
    expect(await screen.findByText(/evidence · not_found/)).toBeInTheDocument();
  });
});
