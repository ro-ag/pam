import { act, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import type { CommandFence, SkillLibraryDto } from "../domain";
import { fixtureBridge } from "../fixtures";
import { SkillLibraryPanel } from "./SkillLibraryPanel";

const fence: CommandFence = {
  projectHandle: "project:one",
  generation: "11111111-1111-4111-8111-111111111111",
  operationId: "22222222-2222-4222-8222-222222222222",
};

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((onResolve) => { resolve = onResolve; });
  return { promise, resolve };
}

describe("SkillLibraryPanel", () => {
  it("renders retained versions, metadata-only provenance, and distinct target truth", async () => {
    render(<SkillLibraryPanel bridge={fixtureBridge()} fence={fence} />);

    expect(await screen.findByRole("heading", { name: "Skill library" })).toBeInTheDocument();
    expect(screen.getByLabelText("Library state definitions")).toHaveTextContent("ObservedShown in inventory above; detection alone grants no management.");
    expect(screen.getByLabelText("Library state definitions")).toHaveTextContent("EnabledSelected for this exact project and agent.");
    expect(within(screen.getByLabelText("Canonical library entries")).getByText("review-changes")).toBeInTheDocument();
    expect(screen.getByText(/Git install · commit/)).toBeInTheDocument();
    expect(screen.getByText("Local install · source path not retained")).toBeInTheDocument();
    expect(screen.getAllByText("not inspected").length).toBeGreaterThan(0);
    expect(screen.getAllByText("yes").length).toBeGreaterThan(0);
    expect(screen.getAllByText("no").length).toBeGreaterThan(0);

    expect(screen.getByLabelText("Library entry ID", { selector: 'input[name="adopt-entry-id"]' })).toBeInTheDocument();
    expect(screen.getByLabelText("Observed inventory artifact")).toBeInTheDocument();
    expect(screen.getByLabelText("Source type")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Adopt into library" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Install into library" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Enable target" })).toBeEnabled();
    expect(screen.getByRole("button", { name: "Disable target" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Preview materialization" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Inspect drift" })).toBeEnabled();
    expect(screen.getByRole("button", { name: "Preview resync" })).toBeDisabled();
  });

  it("waits for mutation and verified refresh before claiming success", async () => {
    const user = userEvent.setup();
    const bridge = fixtureBridge();
    const nativeManage = bridge.manageSkillLibrary.bind(bridge);
    const enableGate = deferred<void>();
    const calls: Array<{ fence: CommandFence; action: string }> = [];
    bridge.manageSkillLibrary = vi.fn(async (requestFence, action) => {
      calls.push({ fence: structuredClone(requestFence), action: action.action });
      if (action.action === "enable") await enableGate.promise;
      return nativeManage(requestFence, action);
    });
    render(<SkillLibraryPanel bridge={bridge} fence={fence} />);

    const enable = await screen.findByRole("button", { name: "Enable target" });
    await user.click(enable);
    expect(screen.getByText("Waiting for verified enable result…")).toBeInTheDocument();
    expect(screen.queryByText(/Enablement verified/)).not.toBeInTheDocument();
    expect(screen.getByRole("combobox", { name: "Library entry" })).toBeDisabled();
    expect(screen.getByRole("combobox", { name: "Library version" })).toBeDisabled();
    expect(screen.getByRole("combobox", { name: "Library agent" })).toBeDisabled();

    await act(async () => { enableGate.resolve(); });
    expect(await screen.findByText("Enablement verified against refreshed library state.")).toBeInTheDocument();
    const verifiedResult = screen.getByRole("region", { name: "Verified operation result" });
    expect(verifiedResult).toHaveTextContent("Enabledyes");
    expect(verifiedResult).toHaveTextContent("State changedyes");
    expect(screen.getByRole("combobox", { name: "Library entry" })).toBeEnabled();
    expect(calls.map((call) => call.action)).toEqual(["load", "enable", "load"]);
    expect(new Set(calls.map((call) => call.fence.operationId)).size).toBe(3);
  });

  it("submits local and Git installs explicitly and clears sensitive source fields after refresh", async () => {
    const user = userEvent.setup();
    const bridge = fixtureBridge();
    const nativeManage = bridge.manageSkillLibrary.bind(bridge);
    const actions: unknown[] = [];
    bridge.manageSkillLibrary = vi.fn(async (requestFence, action) => {
      actions.push(structuredClone(action));
      return nativeManage(requestFence, action);
    });
    render(<SkillLibraryPanel bridge={bridge} fence={fence} />);

    const entry = await screen.findByLabelText("Library entry ID", { selector: 'input[name="install-entry-id"]' });
    const localPath = screen.getByLabelText("Local source path");
    await user.type(entry, "local-review");
    await user.type(localPath, "/private/team/review.md");
    await user.click(screen.getByRole("button", { name: "Install into library" }));
    expect(await screen.findByText("Local installation verified against refreshed library state.")).toBeInTheDocument();
    expect(entry).toHaveValue("");
    expect(localPath).toHaveValue("");

    await user.selectOptions(screen.getByLabelText("Source type"), "git");
    await user.type(entry, "git-review");
    const gitUrl = screen.getByLabelText("Git URL");
    const artifactPath = screen.getByLabelText("Artifact path");
    await user.type(gitUrl, "https://example.com/team/skills.git");
    await user.type(artifactPath, "skills/review/SKILL.md");
    await user.click(screen.getByRole("button", { name: "Install into library" }));
    expect(await screen.findByText("Git installation verified against refreshed library state.")).toBeInTheDocument();
    expect(screen.getByRole("region", { name: "Verified operation result" })).toHaveTextContent("Dispositioninserted");
    expect(entry).toHaveValue("");
    expect(gitUrl).toHaveValue("");
    expect(artifactPath).toHaveValue("");
    expect(actions).toContainEqual({ action: "install_local", entryId: "local-review", sourcePath: "/private/team/review.md" });
    expect(actions).toContainEqual({ action: "install_git", entryId: "git-review", url: "https://example.com/team/skills.git", artifactPath: "skills/review/SKILL.md" });
  });

  it("keeps preview identity exact through apply and reload", async () => {
    const user = userEvent.setup();
    const bridge = fixtureBridge();
    const nativeManage = bridge.manageSkillLibrary.bind(bridge);
    const actions: string[] = [];
    bridge.manageSkillLibrary = vi.fn(async (requestFence, action) => {
      actions.push(action.action);
      return nativeManage(requestFence, action);
    });
    render(<SkillLibraryPanel bridge={bridge} fence={fence} />);

    await user.selectOptions(await screen.findByRole("combobox", { name: "Library entry" }), "review-changes");
    await user.selectOptions(screen.getByRole("combobox", { name: "Library agent" }), "cursor");
    await user.click(screen.getByRole("button", { name: "Preview materialization" }));

    const preview = await screen.findByRole("heading", { name: "Verified materialization preview" });
    const previewRegion = preview.closest("section");
    expect(previewRegion).not.toBeNull();
    expect(within(previewRegion!).getByText("replace")).toBeInTheDocument();
    expect(within(previewRegion!).getByText("cursor fixed destination")).toBeInTheDocument();
    await user.click(within(previewRegion!).getByRole("button", { name: "Apply exact materialization" }));

    expect(await screen.findByText("Materialization verified against refreshed library state.")).toBeInTheDocument();
    const verifiedResult = screen.getByRole("region", { name: "Verified operation result" });
    expect(verifiedResult).toHaveTextContent("replace");
    expect(verifiedResult).toHaveTextContent("Ownership recorded: yes");
    expect(verifiedResult).toHaveTextContent("Backup: 1024 bytes");
    expect(actions).toEqual(["load", "preview_materialization", "apply_materialization", "load"]);
    expect(screen.queryByRole("heading", { name: "Verified materialization preview" })).not.toBeInTheDocument();
  });

  it("does not claim success when refreshed durable state contradicts a mutation", async () => {
    const user = userEvent.setup();
    const bridge = fixtureBridge();
    const nativeManage = bridge.manageSkillLibrary.bind(bridge);
    let enabled = false;
    bridge.manageSkillLibrary = vi.fn(async (requestFence, action) => {
      const response = await nativeManage(requestFence, action);
      if (action.action === "enable") enabled = true;
      if (enabled && response.data.action === "load") {
        const version = response.data.entries
          .find((entry) => entry.entryId === "release-confidence")
          ?.versions.find((candidate) => candidate.version.startsWith("sha256:1111"));
        if (version) version.enabledAgents = version.enabledAgents.filter((agent) => agent !== "claude");
      }
      return response;
    });
    render(<SkillLibraryPanel bridge={bridge} fence={fence} />);

    await user.click(await screen.findByRole("button", { name: "Enable target" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("did not match refreshed durable library state");
    expect(screen.queryByText(/Enablement verified/)).not.toBeInTheDocument();
  });

  it("retains the observed adoption selection when durable verification contradicts it", async () => {
    const user = userEvent.setup();
    const bridge = fixtureBridge();
    const nativeManage = bridge.manageSkillLibrary.bind(bridge);
    let adopted = false;
    bridge.manageSkillLibrary = vi.fn(async (requestFence, action) => {
      const response = await nativeManage(requestFence, action);
      if (action.action === "adopt") adopted = true;
      if (adopted && response.data.action === "load") {
        response.data.entries = response.data.entries.filter((entry) => entry.entryId !== "retry-adoption");
      }
      return response;
    });
    render(<SkillLibraryPanel bridge={bridge} fence={fence} />);

    const entry = await screen.findByLabelText("Library entry ID", { selector: 'input[name="adopt-entry-id"]' });
    const artifact = screen.getByRole("combobox", { name: "Observed inventory artifact" });
    const artifactId = "artifact:sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    await user.type(entry, "retry-adoption");
    await user.selectOptions(artifact, artifactId);
    await user.click(screen.getByRole("button", { name: "Adopt into library" }));

    expect(await screen.findByRole("alert")).toHaveTextContent("did not match refreshed durable library state");
    expect(entry).toHaveValue("retry-adoption");
    expect(artifact).toHaveValue(artifactId);
  });

  it("retains local and Git install inputs when durable verification contradicts them", async () => {
    const user = userEvent.setup();
    const bridge = fixtureBridge();
    const nativeManage = bridge.manageSkillLibrary.bind(bridge);
    let contradictedEntry: string | null = null;
    bridge.manageSkillLibrary = vi.fn(async (requestFence, action) => {
      const response = await nativeManage(requestFence, action);
      if (action.action === "install_local" || action.action === "install_git") {
        contradictedEntry = action.entryId;
      } else if (contradictedEntry && response.data.action === "load") {
        response.data.entries = response.data.entries.filter((entry) => entry.entryId !== contradictedEntry);
      }
      return response;
    });
    render(<SkillLibraryPanel bridge={bridge} fence={fence} />);

    const entry = await screen.findByLabelText("Library entry ID", { selector: 'input[name="install-entry-id"]' });
    const localPath = screen.getByLabelText("Local source path");
    await user.type(entry, "retry-local");
    await user.type(localPath, "/private/retry/SKILL.md");
    await user.click(screen.getByRole("button", { name: "Install into library" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("did not match refreshed durable library state");
    expect(entry).toHaveValue("retry-local");
    expect(localPath).toHaveValue("/private/retry/SKILL.md");

    await user.clear(entry);
    await user.selectOptions(screen.getByLabelText("Source type"), "git");
    await user.type(entry, "retry-git");
    const gitUrl = screen.getByLabelText("Git URL");
    const artifactPath = screen.getByLabelText("Artifact path");
    await user.type(gitUrl, "https://example.com/team/skills.git");
    await user.type(artifactPath, "skills/retry/SKILL.md");
    await user.click(screen.getByRole("button", { name: "Install into library" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("did not match refreshed durable library state");
    expect(entry).toHaveValue("retry-git");
    expect(gitUrl).toHaveValue("https://example.com/team/skills.git");
    expect(artifactPath).toHaveValue("skills/retry/SKILL.md");
  });

  it("requires the exact entry and version to remain present when verifying disable", async () => {
    const user = userEvent.setup();
    const bridge = fixtureBridge();
    const nativeManage = bridge.manageSkillLibrary.bind(bridge);
    let disabled = false;
    bridge.manageSkillLibrary = vi.fn(async (requestFence, action) => {
      const response = await nativeManage(requestFence, action);
      if (action.action === "disable") disabled = true;
      if (disabled && response.data.action === "load") {
        response.data.entries = response.data.entries.filter((entry) => entry.entryId !== "review-changes");
      }
      return response;
    });
    render(<SkillLibraryPanel bridge={bridge} fence={fence} />);

    await user.selectOptions(await screen.findByRole("combobox", { name: "Library entry" }), "review-changes");
    await user.selectOptions(screen.getByRole("combobox", { name: "Library agent" }), "cursor");
    await user.click(screen.getByRole("button", { name: "Disable target" }));

    expect(await screen.findByRole("alert")).toHaveTextContent("did not match refreshed durable library state");
    expect(screen.queryByRole("region", { name: "Verified operation result" })).not.toBeInTheDocument();
  });

  it("adopts only a selected artifact surfaced by the observed inventory", async () => {
    const user = userEvent.setup();
    const bridge = fixtureBridge();
    const nativeManage = bridge.manageSkillLibrary.bind(bridge);
    const actions: unknown[] = [];
    bridge.manageSkillLibrary = vi.fn(async (requestFence, action) => {
      actions.push(structuredClone(action));
      return nativeManage(requestFence, action);
    });
    render(<SkillLibraryPanel bridge={bridge} fence={fence} />);

    const artifact = await screen.findByRole("combobox", { name: "Observed inventory artifact" });
    expect(within(artifact).getByRole("option", { name: "Review changes · claude code" })).toHaveValue(
      "artifact:sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    );
    expect(within(artifact).getByRole("option", { name: "Project instructions · codex" })).toHaveValue(
      "artifact:sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
    );
    await user.type(screen.getByLabelText("Library entry ID", { selector: 'input[name="adopt-entry-id"]' }), "adopted-review");
    await user.selectOptions(artifact, "artifact:sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    expect(screen.getByText(/Exact observed ID/)).toHaveTextContent("artifact:sha256:aaaaaaaa");
    await user.click(screen.getByRole("button", { name: "Adopt into library" }));

    expect(await screen.findByText("Adoption verified against refreshed library state.")).toBeInTheDocument();
    expect(screen.getByRole("region", { name: "Verified operation result" })).toHaveTextContent("Dispositioninserted");
    expect(actions).toContainEqual({
      action: "adopt",
      entryId: "adopted-review",
      artifactId: "artifact:sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    });
  });

  it("rejects an adoption result for a substituted observed artifact", async () => {
    const user = userEvent.setup();
    const bridge = fixtureBridge();
    const nativeManage = bridge.manageSkillLibrary.bind(bridge);
    bridge.manageSkillLibrary = vi.fn(async (requestFence, action) => {
      const response = await nativeManage(requestFence, action);
      if (response.data.action === "adopt") {
        response.data.artifactId = "artifact:sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
      }
      return response;
    });
    render(<SkillLibraryPanel bridge={bridge} fence={fence} />);

    await user.type(
      await screen.findByLabelText("Library entry ID", { selector: 'input[name="adopt-entry-id"]' }),
      "substituted-adoption",
    );
    await user.selectOptions(
      screen.getByRole("combobox", { name: "Observed inventory artifact" }),
      "artifact:sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    );
    await user.click(screen.getByRole("button", { name: "Adopt into library" }));

    expect(await screen.findByRole("alert")).toHaveTextContent(
      "did not match the exact project request and selection",
    );
    expect(screen.queryByText(/Adoption verified/)).not.toBeInTheDocument();
  });

  it("accepts an exact unowned no-op without claiming ownership was recorded", async () => {
    const user = userEvent.setup();
    const bridge = fixtureBridge();
    const nativeManage = bridge.manageSkillLibrary.bind(bridge);
    bridge.manageSkillLibrary = vi.fn(async (requestFence, action) => {
      const response = await nativeManage(requestFence, action);
      if (response.data.action === "apply_materialization") {
        response.data.outcomes[0].ownershipRecorded = false;
      }
      if (response.data.action === "load") {
        const version = response.data.entries
          .find((entry) => entry.entryId === "review-changes")
          ?.versions[0];
        if (version) version.managedAgents = version.managedAgents.filter((agent) => agent !== "claude");
      }
      return response;
    });
    render(<SkillLibraryPanel bridge={bridge} fence={fence} />);

    await user.selectOptions(await screen.findByRole("combobox", { name: "Library entry" }), "review-changes");
    await user.selectOptions(screen.getByRole("combobox", { name: "Library agent" }), "claude");
    await user.click(screen.getByRole("button", { name: "Preview materialization" }));
    const preview = await screen.findByRole("region", { name: "Verified materialization preview" });
    expect(within(preview).getByText("no op")).toBeInTheDocument();
    await user.click(within(preview).getByRole("button", { name: "Apply exact materialization" }));

    expect(await screen.findByText("Materialization verified against refreshed library state.")).toBeInTheDocument();
    expect(screen.getByRole("region", { name: "Verified operation result" })).toHaveTextContent(
      "Ownership recorded: no",
    );
  });

  it("accepts an already-managed no-op with durable ownership truth", async () => {
    const user = userEvent.setup();
    render(<SkillLibraryPanel bridge={fixtureBridge()} fence={fence} />);

    await user.selectOptions(await screen.findByRole("combobox", { name: "Library entry" }), "review-changes");
    await user.selectOptions(screen.getByRole("combobox", { name: "Library agent" }), "claude");
    await user.click(screen.getByRole("button", { name: "Preview materialization" }));
    const preview = await screen.findByRole("region", { name: "Verified materialization preview" });
    await user.click(within(preview).getByRole("button", { name: "Apply exact materialization" }));

    expect(await screen.findByText("Materialization verified against refreshed library state.")).toBeInTheDocument();
    expect(screen.getByRole("region", { name: "Verified operation result" })).toHaveTextContent(
      "Ownership recorded: yes",
    );
  });

  it("rejects a write outcome whose ownership was not recorded", async () => {
    const user = userEvent.setup();
    const bridge = fixtureBridge();
    const nativeManage = bridge.manageSkillLibrary.bind(bridge);
    bridge.manageSkillLibrary = vi.fn(async (requestFence, action) => {
      const response = await nativeManage(requestFence, action);
      if (response.data.action === "apply_materialization") {
        response.data.outcomes[0].ownershipRecorded = false;
      }
      return response;
    });
    render(<SkillLibraryPanel bridge={bridge} fence={fence} />);

    await user.selectOptions(await screen.findByRole("combobox", { name: "Library agent" }), "codex");
    await user.click(screen.getByRole("button", { name: "Preview materialization" }));
    const preview = await screen.findByRole("region", { name: "Verified materialization preview" });
    await user.click(within(preview).getByRole("button", { name: "Apply exact materialization" }));

    expect(await screen.findByRole("alert")).toHaveTextContent(
      "did not match refreshed durable library state",
    );
    expect(screen.queryByText(/Materialization verified/)).not.toBeInTheDocument();
  });

  it("rejects a result whose target identity does not match the request", async () => {
    const user = userEvent.setup();
    const bridge = fixtureBridge();
    const nativeManage = bridge.manageSkillLibrary.bind(bridge);
    bridge.manageSkillLibrary = vi.fn(async (requestFence, action) => {
      const response = await nativeManage(requestFence, action);
      if (response.data.action === "inspect_drift") {
        response.data.inspection.key.entryId = "substituted-entry";
      }
      return response;
    });
    render(<SkillLibraryPanel bridge={bridge} fence={fence} />);

    await user.click(await screen.findByRole("button", { name: "Inspect drift" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("did not match the exact project request and selection");
    expect(screen.queryByRole("heading", { name: "Verified drift inspection" })).not.toBeInTheDocument();
  });

  it("drops an old-generation response after remount authority changes", async () => {
    const bridge = fixtureBridge();
    const nativeManage = bridge.manageSkillLibrary.bind(bridge);
    const oldLoad = deferred<SkillLibraryDto>();
    let oldRequestFence: CommandFence | null = null;
    bridge.manageSkillLibrary = vi.fn(async (requestFence, action) => {
      if (action.action === "load" && requestFence.generation === fence.generation) {
        oldRequestFence = structuredClone(requestFence);
        return oldLoad.promise;
      }
      const response = await nativeManage(requestFence, action);
      if (response.data.action === "load") response.data.entries = response.data.entries.filter((entry) => entry.entryId === "review-changes");
      return response;
    });
    const { rerender } = render(<SkillLibraryPanel bridge={bridge} fence={fence} />);
    expect(screen.getByText("Loading bounded library metadata…")).toBeInTheDocument();

    const nextFence = { ...fence, generation: "33333333-3333-4333-8333-333333333333" };
    rerender(<SkillLibraryPanel bridge={bridge} fence={nextFence} />);
    const entries = await screen.findByLabelText("Canonical library entries");
    expect(within(entries).getByText("review-changes")).toBeInTheDocument();
    expect(within(entries).queryByText("release-confidence")).not.toBeInTheDocument();

    await act(async () => {
      oldLoad.resolve({
        fence: oldRequestFence!,
        data: { schemaVersion: 1, action: "load", entries: [{ entryId: "old-project-entry", versions: [] }] },
      });
    });
    await waitFor(() => expect(screen.queryByText("old-project-entry")).not.toBeInTheDocument());
    expect(within(screen.getByLabelText("Canonical library entries")).getByText("review-changes")).toBeInTheDocument();
  });
});
