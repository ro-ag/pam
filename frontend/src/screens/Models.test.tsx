import { createMemoryHistory } from "@tanstack/react-router";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import App from "../App";
import type { CatalogPreset, ModelEntry, ModelJob, ModelsStatus } from "../lib/ipc";
import { applyTheme } from "../lib/theme";
import { createAppRouter } from "../router";
import {
  EMPTY_LIBRARY_SENTENCE,
  FLOOR_SENTENCE,
  IDLE_RUNTIME_SENTENCE,
  POLL_BUSY_MS,
  POLL_IDLE_MS,
  pollInterval,
  presetModelId,
  runningDownload,
} from "./Models";

/**
 * The Models screen against a mocked bridge. The whole App mounts so the
 * query provider, the router, and the screen run exactly as shipped.
 */

const mocks = vi.hoisted(() => ({
  modelsStatus: vi.fn(),
  modelsList: vi.fn(),
  modelsCatalog: vi.fn(),
  modelsLoad: vi.fn(),
  modelsUnload: vi.fn(),
  modelsDownload: vi.fn(),
  modelsDownloadCancel: vi.fn(),
  modelsDelete: vi.fn(),
  modelsVerify: vi.fn(),
  modelsDefaultsSet: vi.fn(),
  modelsTry: vi.fn(),
  daemonStatus: vi.fn(),
  subscribeEvents: vi.fn(),
}));

vi.mock("../lib/ipc", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../lib/ipc")>();
  return { ...actual, ...mocks };
});

const nowSec = Math.floor(Date.now() / 1000);

function idleStatus(overrides: Partial<ModelsStatus> = {}): ModelsStatus {
  return {
    runtime: { state: { state: "idle" }, busy: false },
    jobs: [],
    defaults: { light: null, heavy: null },
    idle_unload_min: 10,
    models_dir: "/Users/dev/llm",
    host_ram_bytes: 64_000_000_000,
    ...overrides,
  };
}

function loadedStatus(): ModelsStatus {
  return idleStatus({
    runtime: {
      state: {
        state: "loaded",
        id: "qwen/Qwen3-Coder-30B-A3B-Instruct-Q4_K_M",
        quant: "Q4_K_M",
        architecture: "qwen3moe",
        context_length: 8192,
        weight_bytes: 18_556_689_568,
        device: "metal",
        loaded_at: nowSec - 60,
        last_used_at: nowSec - 5,
        last_tokens_per_sec: 42.5,
      },
      busy: false,
    },
  });
}

function entry(overrides: Partial<ModelEntry> = {}): ModelEntry {
  return {
    id: "qwen/Qwen3-Coder-30B-A3B-Instruct-Q4_K_M",
    vendor: "qwen",
    file_name: "Qwen3-Coder-30B-A3B-Instruct-Q4_K_M.gguf",
    path: "/Users/dev/llm/qwen/Qwen3-Coder-30B-A3B-Instruct-Q4_K_M.gguf",
    size_bytes: 18_556_689_568,
    info: {
      architecture: "qwen3moe",
      name: "Qwen3 Coder 30B",
      quant_label: "Q4_K_M",
      parameter_count: 30_000_000_000,
      context_length: 262_144,
      expert_count: 128,
      tensor_count: 579,
      version: 3,
    },
    info_error: null,
    class: "engine",
    verified: {
      sha256: "fadc3e5f",
      size_bytes: 18_556_689_568,
      verified_ts: nowSec - 600,
      matches_catalog: true,
    },
    catalog_id: "qwen3-coder-30b-a3b-q4_k_m",
    ...overrides,
  };
}

function testOnlyEntry(): ModelEntry {
  return entry({
    id: "qwen/Qwen3-0.6B-Q8_0",
    file_name: "Qwen3-0.6B-Q8_0.gguf",
    path: "/Users/dev/llm/qwen/Qwen3-0.6B-Q8_0.gguf",
    size_bytes: 639_000_000,
    class: "test_only",
    verified: null,
    catalog_id: null,
    info: {
      architecture: "qwen3",
      name: "Qwen3 0.6B",
      quant_label: "Q8_0",
      parameter_count: 600_000_000,
      context_length: 32_768,
      expert_count: null,
      tensor_count: 311,
      version: 3,
    },
  });
}

function preset(overrides: Partial<CatalogPreset> = {}): CatalogPreset {
  return {
    id: "qwen3-coder-30b-a3b-q4_k_m",
    label: "Qwen3-Coder-30B-A3B Q4_K_M",
    vendor: "qwen",
    file_name: "Qwen3-Coder-30B-A3B-Instruct-Q4_K_M.gguf",
    url: "https://huggingface.test/Q4_K_M.gguf",
    size_bytes: 18_556_689_568,
    sha256: "fadc3e5f",
    license_id: "Apache-2.0",
    license_url: "https://spdx.org/licenses/Apache-2.0.html",
    quant: "Q4_K_M",
    params_label: "30B-A3B",
    min_host_ram_bytes: 32_000_000_000,
    fits_host: true,
    installed: false,
    ...overrides,
  };
}

function job(overrides: Partial<ModelJob> = {}): ModelJob {
  return {
    id: "job_01",
    kind: "download",
    model_id: "qwen/Qwen3-Coder-30B-A3B-Instruct-Q4_K_M",
    source: "https://huggingface.test/Q4_K_M.gguf",
    state: "running",
    bytes_done: 9_278_344_784,
    bytes_total: 18_556_689_568,
    detail: null,
    created_ts: nowSec - 120,
    updated_ts: nowSec,
    ...overrides,
  };
}

beforeEach(() => {
  applyTheme("ventisquero", "dark", { persist: false });
  mocks.subscribeEvents.mockResolvedValue(() => {});
  mocks.daemonStatus.mockResolvedValue({ connected: false, status: null });
  mocks.modelsStatus.mockResolvedValue(idleStatus());
  mocks.modelsList.mockResolvedValue({ models: [], models_dir: "/Users/dev/llm" });
  mocks.modelsCatalog.mockResolvedValue({
    presets: [preset()],
    host_ram_bytes: 64_000_000_000,
    floor_bytes: 18_000_000_000,
  });
  mocks.modelsLoad.mockResolvedValue({ state: { state: "idle" } });
  mocks.modelsUnload.mockResolvedValue({ state: { state: "idle" } });
  mocks.modelsDownload.mockResolvedValue({ job_id: "job_01" });
  mocks.modelsDownloadCancel.mockResolvedValue({ job_id: "job_01", cancelled: true });
  mocks.modelsDelete.mockResolvedValue({ deleted: true });
  mocks.modelsVerify.mockResolvedValue({ job_id: "job_02" });
  mocks.modelsDefaultsSet.mockResolvedValue({ tier: "heavy", model_id: null });
});

function renderModels() {
  const router = createAppRouter(createMemoryHistory({ initialEntries: ["/models"] }));
  render(<App router={router} />);
  return router;
}

describe("polling cadence", () => {
  it("ticks fast while work is in flight and slow otherwise", () => {
    expect(pollInterval(undefined)).toBe(POLL_IDLE_MS);
    expect(pollInterval(idleStatus())).toBe(POLL_IDLE_MS);
    expect(pollInterval(idleStatus({ jobs: [job()] }))).toBe(POLL_BUSY_MS);
    expect(pollInterval(idleStatus({ jobs: [job({ state: "done" })] }))).toBe(POLL_IDLE_MS);
    expect(
      pollInterval(
        idleStatus({
          runtime: {
            state: { state: "loading", phase: "mapping_tensors", id: "x" },
            busy: true,
          },
        }),
      ),
    ).toBe(POLL_BUSY_MS);
  });
});

describe("runtime card", () => {
  it("says Pam's idle sentence and closes the try box with a reason", async () => {
    renderModels();
    expect(await screen.findByText(IDLE_RUNTIME_SENTENCE)).toBeInTheDocument();
    expect(screen.getByLabelText("prompt")).toBeDisabled();
    expect(screen.getByRole("button", { name: "Run" })).toBeDisabled();
    expect(screen.getByText(/Load a model first/)).toBeInTheDocument();
    expect(screen.getByText("idle unload after 10 min")).toBeInTheDocument();
  });

  it("shows the loaded model's id, quant and tokens/sec in the display face", async () => {
    mocks.modelsStatus.mockResolvedValue(loadedStatus());
    renderModels();
    const card = within(await screen.findByRole("region", { name: "Runtime" }));
    expect(
      await card.findByText("qwen/Qwen3-Coder-30B-A3B-Instruct-Q4_K_M"),
    ).toBeInTheDocument();
    expect(card.getByText("Q4_K_M")).toBeInTheDocument();
    expect(card.getByText("18.6 GB")).toBeInTheDocument();
    expect(card.getByText("metal")).toBeInTheDocument();
    const rate = card.getByText("42.5");
    expect(rate.className).toContain("font-display");
    expect(card.getByText("loaded")).toBeInTheDocument();
  });

  it("loads the model chosen in the select", async () => {
    mocks.modelsList.mockResolvedValue({
      models: [entry(), testOnlyEntry()],
      models_dir: "/Users/dev/llm",
    });
    renderModels();
    const card = within(await screen.findByRole("region", { name: "Runtime" }));
    const select = await card.findByLabelText("model to load");
    fireEvent.change(select, { target: { value: "qwen/Qwen3-0.6B-Q8_0" } });
    fireEvent.click(card.getByRole("button", { name: "Load" }));
    await waitFor(() => expect(mocks.modelsLoad).toHaveBeenCalledWith("qwen/Qwen3-0.6B-Q8_0"));
  });
});

describe("library", () => {
  it("renders Pam's empty-shelf sentence when nothing is installed", async () => {
    renderModels();
    expect(await screen.findByText(EMPTY_LIBRARY_SENTENCE)).toBeInTheDocument();
  });

  it("badges a test-only row and refuses it as a tier default, with the reason", async () => {
    mocks.modelsList.mockResolvedValue({
      models: [testOnlyEntry()],
      models_dir: "/Users/dev/llm",
    });
    renderModels();
    const table = within(await screen.findByRole("region", { name: "Library" }));
    expect(await table.findByText("test only")).toBeInTheDocument();
    expect(table.getByText(FLOOR_SENTENCE)).toBeInTheDocument();
    expect(table.getByRole("button", { name: "Set light" })).toBeDisabled();
    expect(table.getByRole("button", { name: "Set heavy" })).toBeDisabled();
    // The digest is unknown until Verify runs, and the row says so.
    expect(table.getByText("unverified")).toBeInTheDocument();
    // Loading a test-only model is allowed — that is what it is for.
    expect(table.getByRole("button", { name: "Load" })).toBeEnabled();
  });

  it("offers a verified engine row its defaults, its size and its digest verdict", async () => {
    mocks.modelsList.mockResolvedValue({ models: [entry()], models_dir: "/Users/dev/llm" });
    renderModels();
    const table = within(await screen.findByRole("region", { name: "Library" }));
    expect(await table.findByText("engine")).toBeInTheDocument();
    expect(table.getByText("verified")).toBeInTheDocument();
    expect(table.getByText("18.6 GB")).toBeInTheDocument();
    fireEvent.click(table.getByRole("button", { name: "Set heavy" }));
    await waitFor(() =>
      expect(mocks.modelsDefaultsSet).toHaveBeenCalledWith(
        "heavy",
        "qwen/Qwen3-Coder-30B-A3B-Instruct-Q4_K_M",
      ),
    );
  });

  it("reports an unreadable header in the danger tone instead of a blank quant", async () => {
    mocks.modelsList.mockResolvedValue({
      models: [entry({ info: null, info_error: "bad magic" })],
      models_dir: "/Users/dev/llm",
    });
    renderModels();
    const table = within(await screen.findByRole("region", { name: "Library" }));
    const cell = await table.findByText("bad magic");
    expect(cell.className).toContain("text-danger");
  });

  it("deletes in two taps", async () => {
    mocks.modelsList.mockResolvedValue({ models: [entry()], models_dir: "/Users/dev/llm" });
    renderModels();
    const table = within(await screen.findByRole("region", { name: "Library" }));
    fireEvent.click(await table.findByRole("button", { name: "Delete" }));
    expect(mocks.modelsDelete).not.toHaveBeenCalled();
    fireEvent.click(table.getByRole("button", { name: "delete it?" }));
    await waitFor(() =>
      expect(mocks.modelsDelete).toHaveBeenCalledWith(
        "qwen/Qwen3-Coder-30B-A3B-Instruct-Q4_K_M",
      ),
    );
  });
});

describe("catalog", () => {
  it("hides presets this host cannot hold and checks off the installed ones", async () => {
    mocks.modelsCatalog.mockResolvedValue({
      presets: [
        preset(),
        preset({ id: "too-big", label: "Too big for this host", fits_host: false }),
        preset({ id: "already-here", label: "Already here", installed: true }),
      ],
      host_ram_bytes: 64_000_000_000,
      floor_bytes: 18_000_000_000,
    });
    renderModels();
    const catalog = within(await screen.findByRole("region", { name: "Catalog" }));
    expect(await catalog.findByText("Qwen3-Coder-30B-A3B Q4_K_M")).toBeInTheDocument();
    expect(catalog.queryByText("Too big for this host")).not.toBeInTheDocument();
    expect(catalog.getByText("Already here")).toBeInTheDocument();
    expect(catalog.getByText("installed")).toBeInTheDocument();
    // One Download button: the installed card offers a check instead.
    expect(catalog.getAllByRole("button", { name: "Download" })).toHaveLength(1);
  });

  it("starts a preset download and names the license", async () => {
    renderModels();
    const catalog = within(await screen.findByRole("region", { name: "Catalog" }));
    fireEvent.click(await catalog.findByRole("button", { name: "Download" }));
    await waitFor(() =>
      expect(mocks.modelsDownload).toHaveBeenCalledWith({
        preset_id: "qwen3-coder-30b-a3b-q4_k_m",
      }),
    );
    expect(catalog.getByRole("link", { name: "Apache-2.0 license" })).toHaveAttribute(
      "href",
      "https://spdx.org/licenses/Apache-2.0.html",
    );
  });

  it("renders a running download's percentage and cancels that job", async () => {
    mocks.modelsStatus.mockResolvedValue(idleStatus({ jobs: [job()] }));
    renderModels();
    const catalog = within(await screen.findByRole("region", { name: "Catalog" }));
    expect(await catalog.findByText("50%")).toBeInTheDocument();
    expect(catalog.getByLabelText("download progress")).toBeInTheDocument();
    expect(catalog.queryByRole("button", { name: "Download" })).not.toBeInTheDocument();
    fireEvent.click(catalog.getByRole("button", { name: "Cancel" }));
    await waitFor(() => expect(mocks.modelsDownloadCancel).toHaveBeenCalledWith("job_01"));
  });

  it("matches a job to its preset by the id the download installs as", () => {
    expect(presetModelId(preset())).toBe("qwen/Qwen3-Coder-30B-A3B-Instruct-Q4_K_M");
    expect(runningDownload([job()], presetModelId(preset()))?.id).toBe("job_01");
    expect(runningDownload([job({ state: "done" })], presetModelId(preset()))).toBeUndefined();
    expect(runningDownload([job()], "qwen/other")).toBeUndefined();
  });

  it("sends a pasted URL with its vendor, and says pasted files stay unverified", async () => {
    renderModels();
    const catalog = within(await screen.findByRole("region", { name: "Catalog" }));
    fireEvent.change(await catalog.findByLabelText("gguf url"), {
      target: { value: "https://example.test/model.gguf" },
    });
    fireEvent.change(catalog.getByLabelText("vendor"), { target: { value: "qwen" } });
    fireEvent.click(catalog.getByRole("button", { name: "Fetch" }));
    await waitFor(() =>
      expect(mocks.modelsDownload).toHaveBeenCalledWith({
        url: "https://example.test/model.gguf",
        vendor: "qwen",
      }),
    );
    expect(catalog.getByText(/stays unverified until you run Verify/)).toBeInTheDocument();
    expect(catalog.getByText(/under 18 GB load only as test-only/)).toBeInTheDocument();
  });
});

describe("try box", () => {
  it("renders the reply and its rate on success", async () => {
    mocks.modelsStatus.mockResolvedValue(loadedStatus());
    mocks.modelsTry.mockResolvedValue({
      text: "Hello there, friend of mine.",
      prompt_tokens: 21,
      completion_tokens: 7,
      prompt_ms: 90,
      decode_ms: 300,
      tokens_per_sec: 23.33,
    });
    renderModels();
    const box = within(await screen.findByRole("region", { name: "Try box" }));
    const prompt = await box.findByLabelText("prompt");
    await waitFor(() => expect(prompt).toBeEnabled());
    fireEvent.change(prompt, { target: { value: "Say hello in five words." } });
    fireEvent.click(box.getByRole("button", { name: "Run" }));
    await waitFor(() =>
      expect(mocks.modelsTry).toHaveBeenCalledWith("Say hello in five words.", 64),
    );
    expect(await box.findByText("Hello there, friend of mine.")).toBeInTheDocument();
    expect(box.getByText(/23.3 tokens\/sec/)).toBeInTheDocument();
    expect(box.getByText(/21 prompt · 7 completion/)).toBeInTheDocument();
  });

  it("renders a refusal through the uniform failure note", async () => {
    mocks.modelsStatus.mockResolvedValue(loadedStatus());
    mocks.modelsTry.mockRejectedValue({
      cause: "prompt_too_long",
      detail: "prompt is 9001 tokens; the context allows 8192",
      recovery: "Shorten the prompt; the context holds 8192 tokens.",
    });
    renderModels();
    const box = within(await screen.findByRole("region", { name: "Try box" }));
    const prompt = await box.findByLabelText("prompt");
    await waitFor(() => expect(prompt).toBeEnabled());
    fireEvent.change(prompt, { target: { value: "war and peace" } });
    fireEvent.click(box.getByRole("button", { name: "Run" }));
    expect(await box.findByText(/try · prompt_too_long/)).toBeInTheDocument();
    expect(box.getByText(/the context allows 8192/)).toBeInTheDocument();
    expect(box.getByText(/Shorten the prompt/)).toBeInTheDocument();
  });
});
