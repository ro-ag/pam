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
  UNQUALIFIED_SENTENCE,
  IDLE_RUNTIME_SENTENCE,
  POLL_BUSY_MS,
  POLL_IDLE_MS,
  downloadFailure,
  latestDownload,
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
  modelsDownloadDiscard: vi.fn(),
  modelsImport: vi.fn(),
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
    qualification: {
      artifact: "Qwen3-Coder-30B-A3B-Instruct-Q4_K_M",
      sha256: "fadc3e5f",
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
    qualification: null,
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
    partial_bytes: null,
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
  });
  mocks.modelsLoad.mockResolvedValue({ state: { state: "idle" } });
  mocks.modelsUnload.mockResolvedValue({ state: { state: "idle" } });
  mocks.modelsDownload.mockResolvedValue({ job_id: "job_01" });
  mocks.modelsDownloadCancel.mockResolvedValue({ job_id: "job_01", cancelled: true });
  mocks.modelsDownloadDiscard.mockResolvedValue({
    model_id: "qwen/Qwen3-Coder-30B-A3B-Instruct-Q4_K_M",
    discarded_bytes: 9_278_344_784,
  });
  mocks.modelsDelete.mockResolvedValue({ deleted: true });
  mocks.modelsVerify.mockResolvedValue({ job_id: "job_02" });
  mocks.modelsDefaultsSet.mockResolvedValue({ tier: "heavy", model_id: null });
});

function renderModels() {
  const router = createAppRouter(createMemoryHistory({ initialEntries: ["/models"] }));
  render(<App router={router} />);
  return router;
}

describe("library refresh", () => {
  it("re-reads the library when a running job settles", async () => {
    mocks.modelsStatus
      .mockResolvedValueOnce(
        idleStatus({ jobs: [job({ id: "job_02", kind: "verify", state: "running" })] }),
      )
      .mockResolvedValue(
        idleStatus({ jobs: [job({ id: "job_02", kind: "verify", state: "done" })] }),
      );
    renderModels();
    await waitFor(() => expect(mocks.modelsList).toHaveBeenCalled());
    const before = mocks.modelsList.mock.calls.length;
    // The busy poll (2 s) delivers the settled job; the library must follow.
    await waitFor(() => expect(mocks.modelsList.mock.calls.length).toBeGreaterThan(before), {
      timeout: 5_000,
    });
  });
});

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
            state: { state: "loading", phase: "reading_tensors", id: "x" },
            busy: true,
          },
        }),
      ),
    ).toBe(POLL_BUSY_MS);
  });
});

describe("readiness card", () => {
  it("draws the daemon's verdict per tier and the repair opens the right tab", async () => {
    mocks.modelsStatus.mockResolvedValue(
      idleStatus({
        defaults: { light: null, heavy: "qwen/Qwen3-Coder-30B-A3B-Instruct-Q4_K_M" },
        readiness: {
          light: {
            tier: "light",
            configured: null,
            model_id: null,
            fallback: false,
            stage: "unconfigured",
            resident: false,
            qualification: null,
            blocker: {
              cause: "no_default",
              detail: "no default model for tier light",
              recovery: "",
            },
          },
          heavy: {
            tier: "heavy",
            configured: "qwen/Qwen3-Coder-30B-A3B-Instruct-Q4_K_M",
            model_id: "qwen/Qwen3-Coder-30B-A3B-Instruct-Q4_K_M",
            fallback: false,
            stage: "engine_missing",
            resident: false,
            qualification: null,
            blocker: {
              cause: "engine_not_installed",
              detail: "the llama.cpp engine b10938 is not installed (not_installed)",
              recovery:
                "Install the llama.cpp engine from Models > Runtime; the model itself is ready.",
            },
          },
        },
      }),
    );
    renderModels();
    const heavy = await screen.findByRole("list", { name: "heavy readiness" });
    expect(within(heavy).getAllByRole("listitem")[4]).toHaveAttribute("aria-current", "step");
    expect(
      screen.getByText("the llama.cpp engine b10938 is not installed (not_installed)"),
    ).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Install engine" }));
    expect(
      await screen.findByRole("tab", { name: "Downloads", selected: true }),
    ).toBeInTheDocument();
  });
});

describe("runtime card", () => {
  it("says Pam's idle sentence and closes the try box with a reason", async () => {
    renderModels();
    expect(await screen.findByText(IDLE_RUNTIME_SENTENCE)).toBeInTheDocument();
    expect(screen.getByText("idle unload after 10 min")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("tab", { name: "Test model" }));
    expect(screen.getByLabelText("prompt")).toBeDisabled();
    expect(screen.getByRole("button", { name: "Run" })).toBeDisabled();
    expect(screen.getByText(/Load a model first/)).toBeInTheDocument();
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

  it("shows which model the engine holds, badged, when the engine is installed and loaded", async () => {
    mocks.modelsStatus.mockResolvedValue(
      idleStatus({
        engine: {
          installed: true,
          expected_tag: "b1234",
          cause: null,
          loaded: {
            id: "qwen/Qwen3-Coder-30B-A3B-engine",
            path: "/Users/dev/llm/qwen/Qwen3-Coder-30B-A3B-engine.gguf",
            context_length: 8192,
            build_info: "b1234",
            loaded_at_ms: Date.now(),
            pid: 4242,
          },
        },
      }),
    );
    renderModels();
    const card = within(await screen.findByRole("region", { name: "Runtime" }));
    expect(await card.findAllByText("engine")).toHaveLength(2);
    expect(card.getByText("qwen/Qwen3-Coder-30B-A3B-engine")).toBeInTheDocument();
    expect(card.getByText("8192 tokens")).toBeInTheDocument();
    expect(card.getByText("b1234")).toBeInTheDocument();
  });

  it("says the engine is ready but idle when installed with nothing loaded", async () => {
    mocks.modelsStatus.mockResolvedValue(
      idleStatus({
        engine: { installed: true, expected_tag: "b1234", cause: null, loaded: null },
      }),
    );
    renderModels();
    expect(await screen.findByText("Engine ready, nothing loaded")).toBeInTheDocument();
  });
});

/** Opens a row's More menu and scopes queries to it. */
function openMenu(table: ReturnType<typeof within>, modelId: string) {
  fireEvent.click(table.getByRole("button", { name: `More actions for ${modelId}` }));
  return within(screen.getByRole("menu", { name: `Actions for ${modelId}` }));
}

describe("library", () => {
  it("renders Pam's empty-shelf sentence when nothing is installed", async () => {
    renderModels();
    fireEvent.click(await screen.findByRole("tab", { name: "Installed" }));
    expect(await screen.findByText(EMPTY_LIBRARY_SENTENCE)).toBeInTheDocument();
  });

  it("badges a test-only row and refuses it as a tier default, with the reason", async () => {
    mocks.modelsList.mockResolvedValue({
      models: [testOnlyEntry()],
      models_dir: "/Users/dev/llm",
    });
    renderModels();
    fireEvent.click(await screen.findByRole("tab", { name: "Installed" }));
    const table = within(await screen.findByRole("region", { name: "Installed models" }));
    expect(await table.findByText("test only")).toBeInTheDocument();
    expect(table.getByText(FLOOR_SENTENCE)).toBeInTheDocument();
    const menu = openMenu(table, "qwen/Qwen3-0.6B-Q8_0");
    expect(menu.getByRole("menuitem", { name: "Set light" })).toBeDisabled();
    expect(menu.getByRole("menuitem", { name: "Set heavy" })).toBeDisabled();
    // The popup escapes the table's scroll clipping and skips unavailable actions.
    expect(table.queryByRole("menu")).toBeNull();
    expect(menu.getByRole("menuitem", { name: "Verify" })).toHaveFocus();
    fireEvent.keyDown(document.activeElement!, { key: "ArrowDown" });
    expect(menu.getByRole("menuitem", { name: "Delete" })).toHaveFocus();
    fireEvent.keyDown(document.activeElement!, { key: "ArrowDown" });
    expect(menu.getByRole("menuitem", { name: "Verify" })).toHaveFocus();

    expect(menu.getByRole("menuitem", { name: "Set light" })).toHaveAttribute(
      "title",
      FLOOR_SENTENCE,
    );
    // The digest is unknown until Verify runs, and the row says so.
    expect(table.getByText("unverified")).toBeInTheDocument();
    // Loading a test-only model is allowed — that is what it is for.
    expect(table.getByRole("button", { name: "Load" })).toBeEnabled();
    fireEvent.pointerDown(document.body);
    expect(screen.queryByRole("menu")).toBeNull();
  });

  it("badges a verified but unqualified row and refuses it as a tier default, with the reason", async () => {
    mocks.modelsList.mockResolvedValue({
      models: [entry({ qualification: null })],
      models_dir: "/Users/dev/llm",
    });
    renderModels();
    fireEvent.click(await screen.findByRole("tab", { name: "Installed" }));
    const table = within(await screen.findByRole("region", { name: "Installed models" }));
    expect(await table.findByText("engine")).toBeInTheDocument();
    expect(table.getByText(UNQUALIFIED_SENTENCE)).toBeInTheDocument();
    expect(table.getByText("verified")).toBeInTheDocument();
    const menu = openMenu(table, "qwen/Qwen3-Coder-30B-A3B-Instruct-Q4_K_M");
    expect(menu.getByRole("menuitem", { name: "Set light" })).toBeDisabled();
    expect(menu.getByRole("menuitem", { name: "Set heavy" })).toBeDisabled();
    expect(table.getByRole("button", { name: "Load" })).toBeEnabled();
  });

  it("offers a qualified row its defaults, its evidence, its size and its digest verdict", async () => {
    mocks.modelsList.mockResolvedValue({ models: [entry()], models_dir: "/Users/dev/llm" });
    renderModels();
    fireEvent.click(await screen.findByRole("tab", { name: "Installed" }));
    const table = within(await screen.findByRole("region", { name: "Installed models" }));
    expect(await table.findByText("qualified")).toBeInTheDocument();
    expect(table.getByText(/answer-contract-v2 · 98\.0% · 0 false passes/)).toBeInTheDocument();
    expect(table.getByText("verified")).toBeInTheDocument();
    expect(table.getByText("18.6 GB")).toBeInTheDocument();
    // The header names what the column answers.
    expect(table.getByRole("columnheader", { name: "verification" })).toBeInTheDocument();
    const menu = openMenu(table, "qwen/Qwen3-Coder-30B-A3B-Instruct-Q4_K_M");
    fireEvent.click(menu.getByRole("menuitem", { name: "Set heavy" }));
    // Choosing closes the menu.
    expect(screen.queryByRole("menu")).toBeNull();
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
    fireEvent.click(await screen.findByRole("tab", { name: "Installed" }));
    const table = within(await screen.findByRole("region", { name: "Installed models" }));
    // "unknown" in the danger tone, the parser's own words beneath it.
    const cell = await table.findByText("unknown");
    expect(cell.className).toContain("text-danger");
    expect(table.getByText("bad magic")).toBeInTheDocument();
  });

  it("keeps every row on one line: Load plus one More menu, six rows at once", async () => {
    mocks.modelsList.mockResolvedValue({
      models: Array.from({ length: 6 }, (_, index) =>
        entry({ id: `qwen/model-${index}`, file_name: `model-${index}.gguf` }),
      ),
      models_dir: "/Users/dev/llm",
    });
    renderModels();
    fireEvent.click(await screen.findByRole("tab", { name: "Installed" }));
    const table = within(await screen.findByRole("region", { name: "Installed models" }));
    await table.findByText("qwen/model-5");
    const rows = table.getAllByRole("row").slice(1);
    expect(rows).toHaveLength(6);
    for (const row of rows) {
      const buttons = within(row).getAllByRole("button");
      expect(buttons.map((button) => button.textContent?.trim())).toEqual(["Load", "More"]);
      expect(within(row).getByRole("cell", { name: "18.6 GB" }).className).toContain(
        "whitespace-nowrap",
      );
    }
    // Escape closes an open menu and hands focus back to its button.
    const menu = openMenu(table, "qwen/model-0");
    fireEvent.keyDown(menu.getByRole("menuitem", { name: "Verify" }), { key: "Escape" });
    expect(screen.queryByRole("menu")).toBeNull();
    expect(table.getByRole("button", { name: "More actions for qwen/model-0" })).toHaveFocus();
  });

  it("deletes in two taps", async () => {
    mocks.modelsList.mockResolvedValue({ models: [entry()], models_dir: "/Users/dev/llm" });
    renderModels();
    fireEvent.click(await screen.findByRole("tab", { name: "Installed" }));
    const table = within(await screen.findByRole("region", { name: "Installed models" }));
    await table.findByText("qwen/Qwen3-Coder-30B-A3B-Instruct-Q4_K_M");
    const menu = openMenu(table, "qwen/Qwen3-Coder-30B-A3B-Instruct-Q4_K_M");
    fireEvent.click(menu.getByRole("menuitem", { name: "Delete" }));
    expect(mocks.modelsDelete).not.toHaveBeenCalled();
    fireEvent.click(menu.getByRole("menuitem", { name: "delete it?" }));
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
    });
    renderModels();
    fireEvent.click(await screen.findByRole("tab", { name: "Downloads" }));
    const catalog = within(await screen.findByRole("region", { name: "Downloads" }));
    expect(await catalog.findByText("Qwen3-Coder-30B-A3B Q4_K_M")).toBeInTheDocument();
    expect(catalog.queryByText("Too big for this host")).not.toBeInTheDocument();
    expect(catalog.getByText("Already here")).toBeInTheDocument();
    expect(catalog.getByText("installed")).toBeInTheDocument();
    // One Download button: the installed card offers a check instead.
    expect(catalog.getAllByRole("button", { name: "Download" })).toHaveLength(1);
  });

  it("starts a preset download and names the license", async () => {
    renderModels();
    fireEvent.click(await screen.findByRole("tab", { name: "Downloads" }));
    const catalog = within(await screen.findByRole("region", { name: "Downloads" }));
    fireEvent.click(await catalog.findByRole("button", { name: "Download" }));
    // Pressing Download only opens the confirmation; nothing is fetched yet.
    expect(mocks.modelsDownload).not.toHaveBeenCalled();
    expect(
      catalog.getByRole("link", { name: "https://spdx.org/licenses/Apache-2.0.html" }),
    ).toHaveAttribute("href", "https://spdx.org/licenses/Apache-2.0.html");
    fireEvent.click(catalog.getByRole("button", { name: "Start download" }));
    await waitFor(() =>
      expect(mocks.modelsDownload).toHaveBeenCalledWith({
        preset_id: "qwen3-coder-30b-a3b-q4_k_m",
      }),
    );
  });

  it("renders a running download's percentage and cancels that job", async () => {
    mocks.modelsStatus.mockResolvedValue(idleStatus({ jobs: [job()] }));
    renderModels();
    fireEvent.click(await screen.findByRole("tab", { name: "Downloads" }));
    const catalog = within(await screen.findByRole("region", { name: "Downloads" }));
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

  it("shows why a download failed, with its recovery, and offers a resume", async () => {
    // A failed transfer leaves its part file behind, and that is what the
    // catalog reports back.
    mocks.modelsCatalog.mockResolvedValue({
      presets: [preset({ partial_bytes: 9_278_344_784 })],
      host_ram_bytes: 64_000_000_000,
    });
    mocks.modelsStatus.mockResolvedValue(
      idleStatus({
        jobs: [
          job({
            state: "failed",
            detail: JSON.stringify({
              cause: "network_timeout",
              detail: "curl exited 28: Operation too slow",
              recovery: "The transfer stopped moving; download again to resume.",
            }),
          }),
        ],
      }),
    );
    renderModels();
    fireEvent.click(await screen.findByRole("tab", { name: "Downloads" }));
    const catalog = within(await screen.findByRole("region", { name: "Downloads" }));
    expect(await catalog.findByText("download · network_timeout")).toBeInTheDocument();
    expect(catalog.getByText(/Operation too slow/)).toBeInTheDocument();
    expect(catalog.getByText(/download again to resume/)).toBeInTheDocument();
    // A failed transfer left its part file: the button says what it does.
    expect(catalog.getByRole("button", { name: "Resume" })).toBeInTheDocument();
    expect(catalog.queryByLabelText("download progress")).not.toBeInTheDocument();
  });

  it("reads a failure body, and still says something when the row is old or broken", () => {
    expect(downloadFailure(job())).toBeNull();
    expect(downloadFailure(job({ state: "done" }))).toBeNull();
    expect(
      downloadFailure(
        job({
          state: "failed",
          detail: JSON.stringify({
            cause: "tls_error",
            detail: "bad cert",
            recovery: "Fix it.",
          }),
        }),
      ),
    ).toEqual({ cause: "tls_error", detail: "bad cert", recovery: "Fix it." });

    const legacy = downloadFailure(job({ state: "failed", detail: "daemon_restart" }));
    expect(legacy?.cause).toBe("download_failed");
    expect(legacy?.detail).toBe("daemon_restart");
    expect(legacy?.recovery).not.toBe("");

    const empty = downloadFailure(job({ state: "failed", detail: null }));
    expect(empty?.detail).toBe("the transfer ended without saying why");
  });

  it("follows a model's latest download whatever state it reached", () => {
    expect(latestDownload([job({ state: "failed" })], presetModelId(preset()))?.id).toBe(
      "job_01",
    );
    expect(latestDownload([job()], "qwen/other")).toBeUndefined();
    expect(
      latestDownload([job({ kind: "verify", state: "failed" })], presetModelId(preset())),
    ).toBeUndefined();
  });

  it("offers Resume and Start over when a partial is on disk, and discards on confirm", async () => {
    mocks.modelsCatalog.mockResolvedValue({
      presets: [preset({ partial_bytes: 9_278_344_784 })],
      host_ram_bytes: 64_000_000_000,
    });
    renderModels();
    fireEvent.click(await screen.findByRole("tab", { name: "Downloads" }));
    const catalog = within(await screen.findByRole("region", { name: "Downloads" }));

    expect(await catalog.findByRole("button", { name: "Resume" })).toBeInTheDocument();
    expect(catalog.queryByRole("button", { name: "Download" })).not.toBeInTheDocument();
    expect(catalog.getByText(/9\.3 GB of 18\.6 GB already here/)).toBeInTheDocument();

    // Destructive, so it arms first (memento law).
    fireEvent.click(catalog.getByRole("button", { name: "Start over" }));
    expect(mocks.modelsDownloadDiscard).not.toHaveBeenCalled();
    fireEvent.click(catalog.getByRole("button", { name: "Discard and start over?" }));
    await waitFor(() =>
      expect(mocks.modelsDownloadDiscard).toHaveBeenCalledWith({
        preset_id: "qwen3-coder-30b-a3b-q4_k_m",
      }),
    );
  });

  it("offers a plain Download when nothing partial is on disk", async () => {
    renderModels();
    fireEvent.click(await screen.findByRole("tab", { name: "Downloads" }));
    const catalog = within(await screen.findByRole("region", { name: "Downloads" }));
    expect(await catalog.findByRole("button", { name: "Download" })).toBeInTheDocument();
    expect(catalog.queryByRole("button", { name: "Start over" })).not.toBeInTheDocument();
  });

  it("sends a pasted URL with its vendor, and says pasted files stay unverified", async () => {
    renderModels();
    fireEvent.click(await screen.findByRole("tab", { name: "Downloads" }));
    const catalog = within(await screen.findByRole("region", { name: "Downloads" }));
    fireEvent.change(await catalog.findByLabelText("gguf url"), {
      target: { value: "https://example.test/model.gguf" },
    });
    fireEvent.change(catalog.getByLabelText("vendor"), { target: { value: "qwen" } });
    fireEvent.click(catalog.getByRole("button", { name: "Fetch" }));
    // The pasted address waits for a confirmation that says what it means.
    expect(mocks.modelsDownload).not.toHaveBeenCalled();
    const confirm = within(catalog.getByRole("group", { name: "confirm unverified download" }));
    expect(
      confirm.getByText(/PAM has no expected SHA-256 for this address/),
    ).toBeInTheDocument();
    expect(confirm.getByText(/Mirrors do not apply to pasted addresses/)).toBeInTheDocument();
    expect(confirm.getByText("example.test")).toBeInTheDocument();
    fireEvent.click(confirm.getByRole("button", { name: "Start download" }));
    await waitFor(() =>
      expect(mocks.modelsDownload).toHaveBeenCalledWith({
        url: "https://example.test/model.gguf",
        vendor: "qwen",
      }),
    );
    expect(catalog.getByText(/stays unverified until you run Verify/)).toBeInTheDocument();
    expect(catalog.getByText(/Unverified models load only as test-only/)).toBeInTheDocument();
  });
});

describe("download confirmation", () => {
  async function openCatalog() {
    renderModels();
    fireEvent.click(await screen.findByRole("tab", { name: "Downloads" }));
    return within(await screen.findByRole("region", { name: "Downloads" }));
  }

  it("names the file, host, size, digest, location and licence before anything is fetched", async () => {
    mocks.modelsCatalog.mockResolvedValue({
      presets: [
        preset({
          sha256: "fadc3e5f0123456789abcdef0123456789abcdef0123456789abcdef01234567",
          fetch: {
            url: "https://huggingface.co/qwen/x/resolve/main/Q4_K_M.gguf",
            host: "huggingface.co",
            source: "upstream",
          },
        }),
      ],
      host_ram_bytes: 64_000_000_000,
    });
    const catalog = await openCatalog();
    fireEvent.click(await catalog.findByRole("button", { name: "Download" }));
    const confirm = within(
      catalog.getByRole("group", { name: "confirm download Qwen3-Coder-30B-A3B Q4_K_M" }),
    );
    expect(confirm.getByText("Download Qwen3-Coder-30B-A3B Q4_K_M?")).toBeInTheDocument();
    expect(confirm.getByText("18.6 GB")).toBeInTheDocument();
    expect(confirm.getByText("huggingface.co")).toBeInTheDocument();
    expect(
      confirm.getByText("https://huggingface.co/qwen/x/resolve/main/Q4_K_M.gguf"),
    ).toBeInTheDocument();
    expect(confirm.getByText(/the catalog source/)).toBeInTheDocument();
    expect(confirm.getByText("fadc3e5f0123…234567")).toBeInTheDocument();
    expect(confirm.getByText(/a file that differs is deleted/)).toBeInTheDocument();
    expect(
      confirm.getByText("/Users/dev/llm/qwen/Qwen3-Coder-30B-A3B-Instruct-Q4_K_M.gguf"),
    ).toBeInTheDocument();
    expect(confirm.getByText(/This is model data, not a program/)).toBeInTheDocument();
    expect(mocks.modelsDownload).not.toHaveBeenCalled();
  });

  it("says when the models mirror is the host, and names the catalog source", async () => {
    mocks.modelsCatalog.mockResolvedValue({
      presets: [
        preset({
          fetch: {
            url: "https://artifacts.corp.example/hf/qwen/x/resolve/main/Q4_K_M.gguf",
            host: "artifacts.corp.example",
            source: "mirror",
          },
        }),
      ],
      host_ram_bytes: 64_000_000_000,
    });
    const catalog = await openCatalog();
    fireEvent.click(await catalog.findByRole("button", { name: "Download" }));
    const confirm = within(catalog.getByRole("group", { name: /confirm download/ }));
    expect(confirm.getByText("artifacts.corp.example")).toBeInTheDocument();
    expect(confirm.getByText(/your configured mirror/)).toBeInTheDocument();
    expect(confirm.getByText(/the catalog source is huggingface.co/)).toBeInTheDocument();
  });

  it("falls back to the catalog address when the daemon sent no resolved fetch", async () => {
    const catalog = await openCatalog();
    fireEvent.click(await catalog.findByRole("button", { name: "Download" }));
    const confirm = within(catalog.getByRole("group", { name: /confirm download/ }));
    expect(confirm.getByText("huggingface.test")).toBeInTheDocument();
    expect(confirm.queryByText(/your configured mirror/)).not.toBeInTheDocument();
  });

  it("Cancel closes it without fetching and brings the Download button back", async () => {
    const catalog = await openCatalog();
    fireEvent.click(await catalog.findByRole("button", { name: "Download" }));
    expect(catalog.queryByRole("button", { name: "Download" })).not.toBeInTheDocument();
    fireEvent.click(
      within(catalog.getByRole("group", { name: /confirm download/ })).getByRole("button", {
        name: "Cancel",
      }),
    );
    expect(catalog.queryByRole("group", { name: /confirm download/ })).not.toBeInTheDocument();
    expect(catalog.getByRole("button", { name: "Download" })).toBeInTheDocument();
    expect(mocks.modelsDownload).not.toHaveBeenCalled();
  });

  it("asks before a Resume too, and says it is a resume", async () => {
    mocks.modelsCatalog.mockResolvedValue({
      presets: [preset({ partial_bytes: 9_278_344_784 })],
      host_ram_bytes: 64_000_000_000,
    });
    const catalog = await openCatalog();
    fireEvent.click(await catalog.findByRole("button", { name: "Resume" }));
    expect(mocks.modelsDownload).not.toHaveBeenCalled();
    expect(
      within(catalog.getByRole("group", { name: /confirm download/ })).getByText(
        "Resume Qwen3-Coder-30B-A3B Q4_K_M?",
      ),
    ).toBeInTheDocument();
  });

  it("points at Settings › Network when the catalog could not read the network settings", async () => {
    mocks.modelsCatalog.mockResolvedValue({
      presets: [preset()],
      host_ram_bytes: 64_000_000_000,
      network_issue: {
        cause: "network_settings_invalid",
        detail: "The stored network settings could not be read",
        recovery: "Re-save them in Settings › Network.",
      },
    });
    const catalog = await openCatalog();
    expect(
      await catalog.findByText(/network settings · network_settings_invalid/),
    ).toBeInTheDocument();
    expect(
      catalog.getAllByRole("button", { name: "Open Settings › Network" }).length,
    ).toBeGreaterThan(0);
  });
});

describe("import weights from a file", () => {
  async function openImport() {
    renderModels();
    fireEvent.click(await screen.findByRole("tab", { name: "Downloads" }));
    const catalog = within(await screen.findByRole("region", { name: "Downloads" }));
    fireEvent.click(await catalog.findByRole("button", { name: "Import weights from file…" }));
    return catalog;
  }

  it("says plainly that an unknown digest lands unverified and needs Verify, and that no file picker exists", async () => {
    const catalog = await openImport();
    expect(catalog.getByText(/this app has no file picker/)).toBeInTheDocument();
    expect(catalog.getByText(/saved as an\s+unverified, test-only model/)).toBeInTheDocument();
    expect(catalog.getByText(/it needs Verify/)).toBeInTheDocument();
    expect(catalog.getByText(/no network is\s+used/)).toBeInTheDocument();
  });

  it("needs a path, then a two-tap confirm, then sends the path with confirm", async () => {
    mocks.modelsImport.mockResolvedValue({
      job_id: "job_imp",
      model_id: "imported/model",
      dest: "/Users/dev/llm/imported/model.gguf",
      source: "/srv/model.gguf",
      size_bytes: 10,
      catalog: null,
      expected_sha256: null,
      verified_on_completion: false,
      note: "PAM has no expected SHA-256 for this file: it is imported as an unverified, test-only model. Run Verify on it before it can serve jobs.",
    });
    const catalog = await openImport();
    const importGroup = within(
      catalog.getByRole("group", { name: "import weights from a file" }),
    );
    expect(importGroup.getByRole("button", { name: "Import" })).toBeDisabled();
    fireEvent.change(importGroup.getByLabelText("weights file path"), {
      target: { value: "/srv/model.gguf" },
    });
    fireEvent.click(importGroup.getByRole("button", { name: "Import" }));
    expect(mocks.modelsImport).not.toHaveBeenCalled();
    fireEvent.click(importGroup.getByRole("button", { name: "Copy this file in?" }));
    await waitFor(() =>
      expect(mocks.modelsImport).toHaveBeenCalledWith({ path: "/srv/model.gguf" }),
    );
    // The daemon's own note about what will be trusted is shown as it answered.
    expect(
      await catalog.findByText(/imported as an unverified, test-only model. Run Verify/),
    ).toBeInTheDocument();
    expect(catalog.getByText("/Users/dev/llm/imported/model.gguf")).toBeInTheDocument();
  });

  it("sends the vendor and the digest to expect when they are given", async () => {
    mocks.modelsImport.mockResolvedValue({
      job_id: "job_imp",
      model_id: "qwen/m",
      dest: "/Users/dev/llm/qwen/m.gguf",
      source: "/srv/m.gguf",
      size_bytes: 10,
      catalog: null,
      expected_sha256: "ab".repeat(32),
      verified_on_completion: true,
      note: "PAM copies the file and checks its SHA-256.",
    });
    const catalog = await openImport();
    const importGroup = within(
      catalog.getByRole("group", { name: "import weights from a file" }),
    );
    fireEvent.change(importGroup.getByLabelText("weights file path"), {
      target: { value: "/srv/m.gguf" },
    });
    fireEvent.change(importGroup.getByLabelText("import vendor"), {
      target: { value: "qwen" },
    });
    fireEvent.change(importGroup.getByLabelText("expected sha256"), {
      target: { value: "AB".repeat(32) },
    });
    fireEvent.click(importGroup.getByRole("button", { name: "Import" }));
    fireEvent.click(importGroup.getByRole("button", { name: "Copy this file in?" }));
    await waitFor(() =>
      expect(mocks.modelsImport).toHaveBeenCalledWith({
        path: "/srv/m.gguf",
        vendor: "qwen",
        expected_sha256: "ab".repeat(32),
      }),
    );
  });

  it.each([
    ["import_source_refused", "The path is a symbolic link", "Give the real file, not a link."],
    ["import_source_missing", "No such file: /srv/nope.gguf", "Check the path and try again."],
    ["already_installed", "A model already exists at that destination", "Delete it first."],
    ["no_space", "12 GB needed, 3 GB free", "Free space on the models volume."],
  ])("renders the refusal %s through the failure note", async (cause, detail, recovery) => {
    mocks.modelsImport.mockRejectedValue({ cause, detail, recovery });
    const catalog = await openImport();
    const importGroup = within(
      catalog.getByRole("group", { name: "import weights from a file" }),
    );
    fireEvent.change(importGroup.getByLabelText("weights file path"), {
      target: { value: "/srv/nope.gguf" },
    });
    fireEvent.click(importGroup.getByRole("button", { name: "Import" }));
    fireEvent.click(importGroup.getByRole("button", { name: "Copy this file in?" }));
    expect(await catalog.findByText(new RegExp(`catalog · ${cause}`))).toBeInTheDocument();
    expect(catalog.getByText(new RegExp(detail))).toBeInTheDocument();
    expect(catalog.getByText(recovery)).toBeInTheDocument();
  });

  it("shows a running import's progress and cancels that job", async () => {
    mocks.modelsStatus.mockResolvedValue(
      idleStatus({ jobs: [job({ id: "job_imp", kind: "import", source: "/srv/m.gguf" })] }),
    );
    renderModels();
    fireEvent.click(await screen.findByRole("tab", { name: "Downloads" }));
    const catalog = within(await screen.findByRole("region", { name: "Downloads" }));
    expect(await catalog.findByLabelText("import progress")).toBeInTheDocument();
    fireEvent.click(catalog.getByRole("button", { name: "Cancel" }));
    await waitFor(() => expect(mocks.modelsDownloadCancel).toHaveBeenCalledWith("job_imp"));
  });

  it("renders a failed import job's cause, sentence and recovery", async () => {
    mocks.modelsStatus.mockResolvedValue(
      idleStatus({
        jobs: [
          job({
            id: "job_imp",
            kind: "import",
            state: "failed",
            detail: JSON.stringify({
              cause: "digest_mismatch",
              detail: "the copy hashes to 1234, the catalog expects fadc",
              recovery: "The file is not that model; the copy was deleted.",
            }),
          }),
        ],
      }),
    );
    renderModels();
    fireEvent.click(await screen.findByRole("tab", { name: "Downloads" }));
    const catalog = within(await screen.findByRole("region", { name: "Downloads" }));
    expect(await catalog.findByText(/import · digest_mismatch/)).toBeInTheDocument();
    expect(catalog.getByText(/the catalog expects fadc/)).toBeInTheDocument();
    expect(catalog.getByText(/the copy was deleted/)).toBeInTheDocument();
  });
});

describe("try box", () => {
  it("renders the reply and its rate on success", async () => {
    mocks.modelsStatus.mockResolvedValue(loadedStatus());
    mocks.modelsTry.mockResolvedValue({
      text: "Hello there, friend of mine.",
      model: { id: entry().id, quant: "Q4_K_M", device: "cpu" },
      prompt_tokens: 21,
      completion_tokens: 7,
      prompt_ms: 90,
      decode_ms: 300,
      tokens_per_sec: 23.33,
    });
    renderModels();
    fireEvent.click(await screen.findByRole("tab", { name: "Test model" }));
    const box = within(await screen.findByRole("region", { name: "Test model" }));
    const prompt = await box.findByLabelText("prompt");
    await waitFor(() => expect(prompt).toBeEnabled());
    fireEvent.change(prompt, { target: { value: "Say hello in five words." } });
    fireEvent.click(box.getByRole("button", { name: "Run" }));
    await waitFor(() =>
      expect(mocks.modelsTry).toHaveBeenCalledWith(entry().id, "Say hello in five words.", 64),
    );
    expect(await box.findByText("Hello there, friend of mine.")).toBeInTheDocument();
    expect(box.getByText(/23.3 tokens\/sec/)).toBeInTheDocument();
    expect(box.getByText(/21 prompt · 7 completion/)).toBeInTheDocument();
  });

  it("rejects text from a worker other than the requested loaded model", async () => {
    mocks.modelsStatus.mockResolvedValue(loadedStatus());
    mocks.modelsTry.mockResolvedValue({
      text: "Unexpected worker output",
      model: { id: "different-model" },
    });
    renderModels();
    fireEvent.click(await screen.findByRole("tab", { name: "Test model" }));
    const box = within(await screen.findByRole("region", { name: "Test model" }));
    const prompt = box.getByLabelText("prompt");
    await waitFor(() => expect(prompt).toBeEnabled());
    fireEvent.change(prompt, { target: { value: "Hello" } });
    fireEvent.click(box.getByRole("button", { name: "Run" }));
    expect(
      await box.findByText("The worker did not confirm the requested model identity."),
    ).toBeInTheDocument();
    expect(box.queryByText("Unexpected worker output")).not.toBeInTheDocument();
    expect(mocks.modelsTry).toHaveBeenCalledWith(entry().id, "Hello", 64);
  });

  it("renders a refusal through the uniform failure note", async () => {
    mocks.modelsStatus.mockResolvedValue(loadedStatus());
    mocks.modelsTry.mockRejectedValue({
      cause: "prompt_too_long",
      detail: "prompt is 9001 tokens; the context allows 8192",
      recovery: "Shorten the prompt; the context holds 8192 tokens.",
    });
    renderModels();
    fireEvent.click(await screen.findByRole("tab", { name: "Test model" }));
    const box = within(await screen.findByRole("region", { name: "Test model" }));
    const prompt = await box.findByLabelText("prompt");
    await waitFor(() => expect(prompt).toBeEnabled());
    fireEvent.change(prompt, { target: { value: "war and peace" } });
    fireEvent.click(box.getByRole("button", { name: "Run" }));
    expect(await box.findByText(/try · prompt_too_long/)).toBeInTheDocument();
    expect(box.getByText(/the context allows 8192/)).toBeInTheDocument();
    expect(box.getByText(/Shorten the prompt/)).toBeInTheDocument();
  });
});

describe("catalog under a managed policy", () => {
  function allow(sources: string[]) {
    mocks.modelsCatalog.mockResolvedValue({
      presets: [preset()],
      host_ram_bytes: 64_000_000_000,
      effective: {
        allowed_sources: {
          source: "policy",
          locked: false,
          mode: "forbid",
          constraint: { allow: sources },
          clamped: false,
          state: "applied",
        },
      },
    });
  }

  async function openDownloads() {
    renderModels();
    fireEvent.click(await screen.findByRole("tab", { name: "Downloads" }));
    return within(await screen.findByRole("region", { name: "Downloads" }));
  }

  it("closes the sources the policy leaves out and prints what it allows", async () => {
    allow(["catalog"]);
    const catalog = await openDownloads();
    expect(await catalog.findByText("allowed: catalog")).toBeInTheDocument();
    expect(catalog.getByRole("button", { name: "Download" })).toBeEnabled();
    expect(catalog.getByRole("button", { name: "Fetch" })).toBeDisabled();
    expect(catalog.getByRole("button", { name: "Fetch" })).toHaveAttribute(
      "title",
      "Your organization's policy does not allow this source",
    );
    expect(catalog.getByRole("button", { name: "Import weights from file…" })).toBeDisabled();
  });

  it("closes catalog downloads when only a file import is allowed", async () => {
    allow(["import"]);
    const catalog = await openDownloads();
    await waitFor(() =>
      expect(catalog.getByRole("button", { name: "Download" })).toBeDisabled(),
    );
    expect(catalog.getByRole("button", { name: "Import weights from file…" })).toBeEnabled();
  });

  it("an empty allowlist closes every source", async () => {
    allow([]);
    const catalog = await openDownloads();
    await waitFor(() =>
      expect(catalog.getByRole("button", { name: "Download" })).toBeDisabled(),
    );
    expect(catalog.getByRole("button", { name: "Fetch" })).toBeDisabled();
    expect(catalog.getByRole("button", { name: "Import weights from file…" })).toBeDisabled();
  });

  it("renders a refused download with the policy's cause, detail and recovery", async () => {
    mocks.modelsDownload.mockRejectedValue({
      cause: "policy_not_allowed",
      detail: "downloading catalog models is not allowed on this machine",
      recovery: "Managed by your organization's policy; ask your administrator.",
    });
    const catalog = await openDownloads();
    fireEvent.click(await catalog.findByRole("button", { name: "Download" }));
    fireEvent.click(catalog.getByRole("button", { name: "Start download" }));
    expect(await catalog.findByText(/catalog · policy_not_allowed/)).toBeInTheDocument();
    expect(catalog.getByText(/ask your administrator/)).toBeInTheDocument();
  });
});
