import { useState } from "react";
import { QueryClientProvider } from "@tanstack/react-query";
import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, expect, it, vi } from "vitest";
import { createAppQueryClient } from "../App";
import { useFlowLibraryControls, type LibraryDraft } from "./FlowLibraryControls";
import { defaultStep } from "./flow-canvas/graph";
import type { FlowListEntry } from "../lib/ipc";
const mocks = vi.hoisted(() => ({
  flowsSave: vi.fn(),
  flowsGet: vi.fn(),
  flowsDelete: vi.fn(),
  flowsNormalize: vi.fn(),
}));
vi.mock("../lib/ipc", async (original) => ({
  ...(await original<typeof import("../lib/ipc")>()),
  ...mocks,
}));
const entry: FlowListEntry = {
  id: "mine",
  name: "My checks",
  description: "",
  source: "library",
  valid: true,
  digest: "old",
  steps: 1,
  inputs: [],
};
const builtin: FlowListEntry = { ...entry, id: "starter", name: "Starter", source: "builtin" };
const yaml = "id: mine\nname: My checks\nsteps:\n  - id: first\n    run: [git, status]\n";
const selected = vi.fn(),
  discarded = vi.fn(),
  navigated = vi.fn();
beforeEach(() => {
  mocks.flowsGet.mockImplementation(async (id) => ({
    ...entry,
    id,
    yaml,
    normalized_yaml: yaml,
    flow: {
      id,
      name: entry.name,
      description: "",
      inputs: {},
      steps: [
        {
          ...defaultStep("first", "command"),
          action: { kind: "command", argv: ["git", "status"] },
        },
      ],
    },
  }));
  mocks.flowsNormalize.mockImplementation(async ({ flow, yaml: inputYaml }) => {
    if (inputYaml) {
      expect(inputYaml).toMatch(/^schema: 1\n/);
      return { valid: true, yaml: inputYaml, flow: {} };
    }
    expect(flow.schema).toBe(1);
    return {
      valid: true,
      yaml: `schema: 1\nid: ${flow.id}\nname: ${JSON.stringify(flow.name)}\nsteps:\n  - id: first\n    run: [git, status]\n`,
      flow,
    };
  });
  mocks.flowsSave.mockResolvedValue(entry);
  mocks.flowsDelete.mockResolvedValue({ id: entry.id, revealed_builtin: false });
});
function Harness({ draft, chosen = entry }: { draft?: LibraryDraft; chosen?: FlowListEntry }) {
  const [localDraft, setLocalDraft] = useState(draft);
  const controls = useFlowLibraryControls({
    entries: [entry, builtin],
    selected: chosen,
    draft: localDraft ?? null,
    ready: true,
    onSelected: selected,
    onDiscard: discarded,
  });
  return (
    <>
      {controls.toolbar}
      {controls.dialogs}
      <button onClick={() => controls.requestNavigation(navigated)}>Go elsewhere</button>
      <button onClick={() => setLocalDraft({ id: chosen.id, yaml, dirty: true })}>
        Edit fallback
      </button>
    </>
  );
}
function setup(draft?: LibraryDraft, chosen?: FlowListEntry) {
  render(
    <QueryClientProvider client={createAppQueryClient()}>
      <Harness draft={draft} chosen={chosen} />
    </QueryClientProvider>,
  );
}
function change(label: string, value: string) {
  fireEvent.change(screen.getByLabelText(label), { target: { value } });
}
it("creates a new command without running it and atomically refuses replacement", async () => {
  setup();
  fireEvent.click(screen.getByRole("button", { name: "New flow" }));
  change("Flow name", "Quick status");
  change("Flow ID", "quick-status");
  expect(screen.getByRole("button", { name: "Create flow" })).toBeDisabled();
  change("First program", "git");
  change("Arguments (one per line)", "status\n--short");
  fireEvent.click(screen.getByRole("button", { name: "Create flow" }));
  await waitFor(() =>
    expect(mocks.flowsSave).toHaveBeenCalledWith(
      "quick-status",
      expect.stringContaining('run: ["git", "status", "--short"]'),
      { create_only: true },
    ),
  );
  expect(selected).toHaveBeenCalledWith("quick-status");
});
it("creates from a template and duplicates a custom flow with a unique ID and name", async () => {
  setup();
  fireEvent.click(screen.getByRole("button", { name: "New flow" }));
  change("Starting point", "starter");
  change("Flow ID", "copied-starter");
  change("Flow name", "Copied starter");
  fireEvent.click(screen.getByRole("button", { name: "Create flow" }));
  await waitFor(() =>
    expect(mocks.flowsSave).toHaveBeenCalledWith(
      "copied-starter",
      expect.stringContaining('name: "Copied starter"'),
      { create_only: true },
    ),
  );
  await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
  fireEvent.click(screen.getByRole("button", { name: "Duplicate" }));
  fireEvent.click(screen.getByRole("button", { name: "Create flow" }));
  await waitFor(() =>
    expect(mocks.flowsSave).toHaveBeenCalledWith(
      "mine-copy",
      expect.stringContaining('name: "My checks copy"'),
      { create_only: true },
    ),
  );
});
it("renames display name while preserving stable ID", async () => {
  setup();
  fireEvent.click(screen.getByRole("button", { name: "Rename" }));
  expect(screen.getByLabelText("Flow ID")).toBeDisabled();
  change("Flow name", "Renamed checks");
  fireEvent.click(screen.getByRole("button", { name: "Save name" }));
  await waitFor(() =>
    expect(mocks.flowsSave).toHaveBeenCalledWith(
      "mine",
      expect.stringContaining('name: "Renamed checks"'),
      {},
    ),
  );
});
it("blocks visible collisions and leaves concurrent backend refusal recoverable", async () => {
  setup();
  fireEvent.click(screen.getByRole("button", { name: "Duplicate" }));
  change("Flow name", "Starter");
  expect(screen.getByRole("alert")).toHaveTextContent("already exists");
  expect(screen.getByRole("button", { name: "Create flow" })).toBeDisabled();
  change("Flow name", "Different");
  mocks.flowsSave.mockRejectedValue({
    cause: "id_mismatch",
    detail: "ID was created by another writer",
    recovery: "Choose another ID",
  });
  fireEvent.click(screen.getByRole("button", { name: "Create flow" }));
  expect(await screen.findByText(/ID was created by another writer/)).toBeInTheDocument();
  expect(screen.getByLabelText("Flow name")).toHaveValue("Different");
  expect(selected).not.toHaveBeenCalled();
});
it.each([false, true])(
  "confirms deletion and conditionally restores without overwriting (%s)",
  async (revealed) => {
    mocks.flowsDelete.mockResolvedValue({ id: "mine", revealed_builtin: revealed });
    setup();
    fireEvent.click(screen.getByRole("button", { name: "Delete" }));
    expect(mocks.flowsDelete).not.toHaveBeenCalled();
    expect(screen.getByText(/Undo remains available/)).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Confirm delete" }));
    const undo = await screen.findByRole("button", { name: "Undo delete" });
    await waitFor(() => expect(undo).toBeEnabled());
    fireEvent.click(undo);
    await waitFor(() =>
      expect(mocks.flowsSave).toHaveBeenCalledWith("mine", yaml, {
        create_only: true,
        ...(revealed ? { allow_builtin_override: true } : {}),
      }),
    );
  },
);
it("protects built-in originals from deletion", () => {
  setup(undefined, builtin);
  expect(screen.getByRole("button", { name: "Delete" })).toBeDisabled();
});
it("offers Save, Discard and Cancel when navigation would lose a draft", async () => {
  setup({ id: "mine", yaml, dirty: true });
  fireEvent.click(screen.getByText("Go elsewhere"));
  expect(screen.getByRole("dialog", { name: "Unsaved flow changes" })).toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", { name: "Cancel" }));
  expect(navigated).not.toHaveBeenCalled();
  fireEvent.click(screen.getByText("Go elsewhere"));
  fireEvent.click(screen.getByRole("button", { name: "Save" }));
  await waitFor(() => expect(navigated).toHaveBeenCalledTimes(1));
  expect(mocks.flowsSave).toHaveBeenCalledWith("mine", yaml);
  fireEvent.click(screen.getByText("Go elsewhere"));
  fireEvent.click(screen.getByRole("button", { name: "Discard" }));
  expect(navigated).toHaveBeenCalledTimes(2);
  expect(discarded).toHaveBeenCalled();
});
it("keeps failed draft saves in place and serializes rapid save events", async () => {
  let reject!: (value: unknown) => void;
  mocks.flowsSave.mockReturnValue(
    new Promise((_, no) => {
      reject = no;
    }),
  );
  setup({ id: "mine", yaml, dirty: true });
  fireEvent.click(screen.getByText("Go elsewhere"));
  act(() => {
    fireEvent.click(screen.getByRole("button", { name: "Save" }));
    fireEvent.click(screen.getByRole("button", { name: "Save" }));
  });
  await waitFor(() => expect(mocks.flowsSave).toHaveBeenCalledTimes(1));
  await act(async () =>
    reject({ cause: "flow_invalid", detail: "steps invalid", recovery: "Fix the step" }),
  );
  expect(await screen.findByText(/steps invalid/)).toBeInTheDocument();
  expect(navigated).not.toHaveBeenCalled();
  expect(discarded).not.toHaveBeenCalled();
});

it("guards Undo against losing a new draft", async () => {
  setup();
  fireEvent.click(screen.getByRole("button", { name: "Delete" }));
  fireEvent.click(screen.getByRole("button", { name: "Confirm delete" }));
  const undo = await screen.findByRole("button", { name: "Undo delete" });
  await waitFor(() => expect(undo).toBeEnabled());
  fireEvent.click(screen.getByText("Edit fallback"));
  fireEvent.click(undo);
  expect(screen.getByRole("dialog", { name: "Unsaved flow changes" })).toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", { name: "Cancel" }));
  expect(mocks.flowsSave).not.toHaveBeenCalled();
  fireEvent.click(undo);
  fireEvent.click(screen.getByRole("button", { name: "Discard" }));
  await waitFor(() =>
    expect(mocks.flowsSave).toHaveBeenCalledWith("mine", yaml, { create_only: true }),
  );
});
it("cannot save an old YAML snapshot while normalization is pending", () => {
  setup({ id: "mine", yaml, dirty: true, saveDisabled: true });
  fireEvent.click(screen.getByText("Go elsewhere"));
  expect(screen.getByRole("button", { name: "Save" })).toBeDisabled();
  fireEvent.click(screen.getByRole("button", { name: "Save" }));
  expect(mocks.flowsSave).not.toHaveBeenCalled();
});

it("finishes Save before starting the queued Undo restoration", async () => {
  setup();
  fireEvent.click(screen.getByRole("button", { name: "Delete" }));
  fireEvent.click(screen.getByRole("button", { name: "Confirm delete" }));
  const undo = await screen.findByRole("button", { name: "Undo delete" });
  await waitFor(() => expect(undo).toBeEnabled());
  fireEvent.click(screen.getByText("Edit fallback"));
  fireEvent.click(undo);
  fireEvent.click(screen.getByRole("button", { name: "Save" }));
  await waitFor(() => expect(mocks.flowsSave).toHaveBeenCalledTimes(2));
  expect(mocks.flowsSave).toHaveBeenNthCalledWith(1, "mine", yaml);
  expect(mocks.flowsSave).toHaveBeenNthCalledWith(2, "mine", yaml, { create_only: true });
  await waitFor(() =>
    expect(screen.queryByRole("button", { name: "Undo delete" })).not.toBeInTheDocument(),
  );
});
