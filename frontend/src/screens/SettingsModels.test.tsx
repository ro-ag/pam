import { QueryClientProvider } from "@tanstack/react-query";
import { createMemoryHistory } from "@tanstack/react-router";
import { act, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import App, { createAppQueryClient } from "../App";
import type { AgentCli, ModelEntry, ModelsStatus } from "../lib/ipc";
import { applyTheme } from "../lib/theme";
import { createAppRouter } from "../router";
import { FLOOR_SENTENCE } from "./Models";
import { CURATOR_AGENTS, SettingsModelsSection } from "./SettingsModels";

/**
 * Settings → Models against a mocked bridge: the tier defaults (with the
 * engine floor visible in the disabled options), the curator radio list
 * and its round-trip test, and the storage knobs.
 */

const mocks = vi.hoisted(() => ({
  modelsStatus: vi.fn(),
  modelsList: vi.fn(),
  modelsDefaultsSet: vi.fn(),
  modelsSettingsSet: vi.fn(),
  curatorList: vi.fn(),
  curatorSet: vi.fn(),
  curatorTest: vi.fn(),
  daemonStatus: vi.fn(),
  daemonStop: vi.fn(),
  subscribeEvents: vi.fn(),
  profileGet: vi.fn(),
  grantsList: vi.fn(),
  readDaemonLog: vi.fn(),
}));

vi.mock("../lib/ipc", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../lib/ipc")>();
  return { ...actual, ...mocks };
});

function status(overrides: Partial<ModelsStatus> = {}): ModelsStatus {
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

function engineEntry(): ModelEntry {
  return {
    id: "qwen/Qwen3-Coder-30B-A3B-Instruct-Q4_K_M",
    vendor: "qwen",
    file_name: "Qwen3-Coder-30B-A3B-Instruct-Q4_K_M.gguf",
    path: "/Users/dev/llm/qwen/Qwen3-Coder-30B-A3B-Instruct-Q4_K_M.gguf",
    size_bytes: 18_556_689_568,
    info: null,
    info_error: null,
    class: "engine",
    verified: null,
    catalog_id: "qwen3-coder-30b-a3b-q4_k_m",
  };
}

function testOnlyEntry(): ModelEntry {
  return {
    ...engineEntry(),
    id: "qwen/Qwen3-0.6B-Q8_0",
    size_bytes: 639_000_000,
    class: "test_only",
  };
}

function cli(overrides: Partial<AgentCli> = {}): AgentCli {
  return { id: "claude", path: "/opt/homebrew/bin/claude", version: "2.1.0", ...overrides };
}

beforeEach(() => {
  applyTheme("ventisquero", "dark", { persist: false });
  window.localStorage.removeItem("pam.ask.rephrase");
  mocks.subscribeEvents.mockResolvedValue(() => {});
  mocks.daemonStatus.mockResolvedValue({ connected: false, status: null });
  mocks.daemonStop.mockResolvedValue({ outcome: "not_running", pid: null });
  mocks.profileGet.mockResolvedValue({ profile: "standard" });
  mocks.grantsList.mockResolvedValue({ grants: [] });
  mocks.readDaemonLog.mockResolvedValue({ file: "/tmp/daemon.log", lines: [] });
  mocks.modelsStatus.mockResolvedValue(status());
  mocks.modelsList.mockResolvedValue({
    models: [engineEntry(), testOnlyEntry()],
    models_dir: "/Users/dev/llm",
  });
  mocks.modelsDefaultsSet.mockResolvedValue({ tier: "heavy", model_id: null });
  mocks.modelsSettingsSet.mockResolvedValue({
    models_dir: "/Users/dev/llm",
    idle_unload_min: 10,
  });
  mocks.curatorList.mockResolvedValue({ detected: [], selected: null });
  mocks.curatorSet.mockResolvedValue({ selected: null });
  mocks.curatorTest.mockResolvedValue({ reply: "OK", ms: 812 });
});

async function renderModelsSection() {
  const router = createAppRouter(createMemoryHistory({ initialEntries: ["/settings#models"] }));
  render(<App router={router} />);
  return within(await screen.findByRole("region", { name: "Models" }));
}

describe("tier defaults", () => {
  it("points a tier at an engine-class model", async () => {
    const section = await renderModelsSection();
    const heavy = await section.findByLabelText("heavy tier default");
    await waitFor(() => expect(heavy).toBeEnabled());
    fireEvent.change(heavy, {
      target: { value: "qwen/Qwen3-Coder-30B-A3B-Instruct-Q4_K_M" },
    });
    await waitFor(() =>
      expect(mocks.modelsDefaultsSet).toHaveBeenCalledWith(
        "heavy",
        "qwen/Qwen3-Coder-30B-A3B-Instruct-Q4_K_M",
      ),
    );
  });

  it("clears a tier back to the deterministic path", async () => {
    mocks.modelsStatus.mockResolvedValue(
      status({ defaults: { light: "qwen/Qwen3-Coder-30B-A3B-Instruct-Q4_K_M", heavy: null } }),
    );
    const section = await renderModelsSection();
    const light = await section.findByLabelText("light tier default");
    await waitFor(() =>
      expect((light as HTMLSelectElement).value).toBe(
        "qwen/Qwen3-Coder-30B-A3B-Instruct-Q4_K_M",
      ),
    );
    fireEvent.change(light, { target: { value: "" } });
    await waitFor(() => expect(mocks.modelsDefaultsSet).toHaveBeenCalledWith("light", null));
  });

  it("offers a test-only model disabled, with the floor sentence in its label", async () => {
    const section = await renderModelsSection();
    const heavy = await section.findByLabelText("heavy tier default");
    const option = await within(heavy).findByRole("option", {
      name: `qwen/Qwen3-0.6B-Q8_0 — ${FLOOR_SENTENCE}`,
    });
    expect(option).toBeDisabled();
    expect(
      within(heavy).getByRole("option", {
        name: "qwen/Qwen3-Coder-30B-A3B-Instruct-Q4_K_M",
      }),
    ).toBeEnabled();
    expect(within(heavy).getByRole("option", { name: "none (deterministic)" })).toBeEnabled();
  });
});

describe("curator", () => {
  it("names the four CLIs it looks for when none is installed", async () => {
    const section = await renderModelsSection();
    const empty = await section.findByText(/None found on the daemon's PATH/);
    for (const agent of CURATOR_AGENTS) {
      expect(empty.textContent).toContain(agent);
    }
    expect(CURATOR_AGENTS).toEqual(["claude", "codex", "copilot", "gemini"]);
    // Nothing to test against, so the button stays shut.
    expect(section.getByRole("button", { name: "Test" })).toBeDisabled();
  });

  it("picks a detected CLI, version and path shown", async () => {
    mocks.curatorList.mockResolvedValue({
      detected: [cli(), cli({ id: "codex", path: "/usr/local/bin/codex", version: null })],
      selected: null,
    });
    const section = await renderModelsSection();
    const codex = await section.findByRole("radio", { name: /codex/ });
    expect(section.getByText(/2\.1\.0/)).toBeInTheDocument();
    expect(section.getByText(/version unknown/)).toBeInTheDocument();
    fireEvent.click(codex);
    await waitFor(() => expect(mocks.curatorSet).toHaveBeenCalledWith("codex"));
  });

  it("clears the pick with the none option", async () => {
    mocks.curatorList.mockResolvedValue({ detected: [cli()], selected: "claude" });
    const section = await renderModelsSection();
    fireEvent.click(await section.findByRole("radio", { name: "none" }));
    await waitFor(() => expect(mocks.curatorSet).toHaveBeenCalledWith(null));
  });

  it("tests the pick and shows the reply with its round-trip time", async () => {
    mocks.curatorList.mockResolvedValue({ detected: [cli()], selected: "claude" });
    const section = await renderModelsSection();
    const test = await section.findByRole("button", { name: "Test" });
    await waitFor(() => expect(test).toBeEnabled());
    fireEvent.click(test);
    await waitFor(() => expect(mocks.curatorTest).toHaveBeenCalledTimes(1));
    expect(await section.findByText("OK")).toBeInTheDocument();
    expect(section.getByText("812 ms")).toBeInTheDocument();
  });

  it("renders a failed test through the uniform failure note", async () => {
    mocks.curatorList.mockResolvedValue({ detected: [cli()], selected: "claude" });
    mocks.curatorTest.mockRejectedValue({
      cause: "curator_failed",
      detail: "claude exited with 1: not logged in",
      recovery: "Check that the CLI runs non-interactively (sign in, or update it).",
    });
    const section = await renderModelsSection();
    const test = await section.findByRole("button", { name: "Test" });
    await waitFor(() => expect(test).toBeEnabled());
    fireEvent.click(test);
    expect(await section.findByText(/curator · curator_failed/)).toBeInTheDocument();
    expect(section.getByText(/not logged in/)).toBeInTheDocument();
  });
});

describe("storage", () => {
  it("starts from the daemon's own values and applies a new directory", async () => {
    const section = await renderModelsSection();
    const dir = await section.findByLabelText("models directory");
    await waitFor(() => expect((dir as HTMLInputElement).value).toBe("/Users/dev/llm"));
    fireEvent.change(dir, { target: { value: "/Volumes/weights" } });
    fireEvent.click(section.getAllByRole("button", { name: "Apply" })[0]);
    await waitFor(() =>
      expect(mocks.modelsSettingsSet).toHaveBeenCalledWith({ models_dir: "/Volumes/weights" }),
    );
  });

  it("applies the idle-unload window", async () => {
    const section = await renderModelsSection();
    const minutes = await section.findByLabelText("idle unload minutes");
    await waitFor(() => expect((minutes as HTMLInputElement).value).toBe("10"));
    fireEvent.change(minutes, { target: { value: "0" } });
    fireEvent.click(section.getAllByRole("button", { name: "Apply" })[1]);
    await waitFor(() =>
      expect(mocks.modelsSettingsSet).toHaveBeenCalledWith({ idle_unload_min: 0 }),
    );
    expect(section.getByText(/0 keeps the weights resident/)).toBeInTheDocument();
  });
});

describe("ask pam", () => {
  it("keeps the Ask Pam rephrase toggle off by default and remembers a flip", async () => {
    window.localStorage.removeItem("pam.ask.rephrase");
    const section = await renderModelsSection();
    const toggle = await section.findByRole("switch", {
      name: /rephrase answers with the light model/i,
    });
    expect(toggle).toHaveAttribute("aria-checked", "false");
    fireEvent.click(toggle);
    expect(toggle).toHaveAttribute("aria-checked", "true");
    expect(window.localStorage.getItem("pam.ask.rephrase")).toBe("on");
    fireEvent.click(toggle);
    expect(toggle).toHaveAttribute("aria-checked", "false");
    expect(window.localStorage.getItem("pam.ask.rephrase")).toBe("off");
  });
});

it("opens Models as the only visible Settings category", async () => {
  const router = createAppRouter(createMemoryHistory({ initialEntries: ["/settings#models"] }));
  render(<App router={router} />);
  await screen.findByRole("region", { name: "Models" });
  const headings = screen
    .getAllByRole("heading", { level: 2 })
    .map((heading) => heading.textContent);
  expect(headings).toEqual(["Models"]);
  expect(screen.getByRole("tab", { name: "Models" })).toHaveAttribute("aria-selected", "true");
});

it("rejects a blank idle window even through form submission", async () => {
  const section = await renderModelsSection();
  const minutes = await section.findByLabelText("idle unload minutes");
  await waitFor(() => expect(minutes).toHaveValue(10));
  fireEvent.change(minutes, { target: { value: "" } });
  expect(section.getAllByRole("button", { name: "Apply" })[1]).toBeDisabled();
  fireEvent.submit(minutes.closest("form")!);
  expect(mocks.modelsSettingsSet).not.toHaveBeenCalled();
});

it("preserves dirty storage drafts across refresh and locks rapid saves", async () => {
  const client = createAppQueryClient();
  render(
    <QueryClientProvider client={client}>
      <SettingsModelsSection />
    </QueryClientProvider>,
  );
  const minutes = screen.getByLabelText("idle unload minutes");
  const dir = screen.getByLabelText("models directory");
  await waitFor(() => expect(minutes).toHaveValue(10));
  fireEvent.change(minutes, { target: { value: "20" } });
  fireEvent.change(dir, { target: { value: "/Volumes/draft" } });
  mocks.modelsStatus.mockResolvedValue(
    status({ idle_unload_min: 5, models_dir: "/Volumes/remote" }),
  );
  await act(async () => {
    await client.invalidateQueries({ queryKey: ["models", "status"] });
  });
  await waitFor(() => expect(minutes).toBeEnabled());
  expect(minutes).toHaveValue(20);
  expect(dir).toHaveValue("/Volumes/draft");
  let finish!: (value: { models_dir: string; idle_unload_min: number }) => void;
  mocks.modelsSettingsSet.mockReturnValue(
    new Promise((resolve) => {
      finish = resolve;
    }),
  );
  act(() => {
    fireEvent.submit(minutes.closest("form")!);
    fireEvent.submit(minutes.closest("form")!);
    fireEvent.submit(dir.closest("form")!);
  });
  await waitFor(() => expect(mocks.modelsSettingsSet).toHaveBeenCalledTimes(1));
  expect(mocks.modelsSettingsSet).toHaveBeenCalledWith({ idle_unload_min: 20 });
  expect(dir).toBeDisabled();
  fireEvent.change(dir, { target: { value: "/Volumes/lost" } });
  expect(dir).toHaveValue("/Volumes/draft");
  mocks.modelsStatus.mockResolvedValue(
    status({ idle_unload_min: 20, models_dir: "/Volumes/remote" }),
  );
  await act(async () => finish({ idle_unload_min: 20, models_dir: "/Volumes/remote" }));
  await waitFor(() => expect(dir).toBeEnabled());
  expect(dir).toHaveValue("/Volumes/draft");
  expect(minutes).toHaveValue(20);
});
