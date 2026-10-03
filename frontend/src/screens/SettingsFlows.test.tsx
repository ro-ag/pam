import { QueryClientProvider } from "@tanstack/react-query";
import { act, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { createAppQueryClient } from "../App";
import type { FlowSettings } from "../lib/ipc";
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

async function addScopeDraft() {
  fireEvent.change(screen.getByLabelText("repository root"), { target: { value: "/repo" } });
  fireEvent.click(screen.getByRole("button", { name: "Add repository" }));
  fireEvent.change(screen.getByLabelText("service URL for /repo"), {
    target: { value: "https://jenkins.example/" },
  });
  fireEvent.change(screen.getByLabelText("exact targets for /repo"), {
    target: { value: "platform/nightly" },
  });
  fireEvent.click(screen.getByRole("button", { name: "Add connector scope" }));
}

describe("repository scopes", () => {
  it("saves exact connector targets and removes grants explicitly", async () => {
    await renderSection();
    await addScopeDraft();
    expect(mocks.flowsSettingsSet).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole("button", { name: "Save scopes" }));
    await waitFor(() =>
      expect(mocks.flowsSettingsSet).toHaveBeenCalledWith({
        scope_policy: {
          version: 1,
          repositories: [
            {
              root: "/repo",
              connectors: [
                {
                  connector: "jenkins",
                  base_url: "https://jenkins.example/",
                  access: "targets",
                  targets: ["platform/nightly"],
                },
              ],
            },
          ],
        },
      }),
    );
    await waitFor(() =>
      expect(screen.queryByText("Unsaved scope changes")).not.toBeInTheDocument(),
    );
    await waitFor(() => expect(screen.getByLabelText("remove repository /repo")).toBeEnabled());
    fireEvent.click(screen.getByLabelText(/remove connector scope jenkins/));
    fireEvent.click(screen.getByRole("button", { name: "Save scopes" }));
    await waitFor(() =>
      expect(mocks.flowsSettingsSet).toHaveBeenLastCalledWith({
        scope_policy: {
          version: 1,
          repositories: [{ root: "/repo", connectors: [] }],
        },
      }),
    );
    await waitFor(() => expect(screen.getByLabelText("remove repository /repo")).toBeEnabled());
    fireEvent.click(screen.getByLabelText("remove repository /repo"));
    fireEvent.click(screen.getByRole("button", { name: "Save scopes" }));
    await waitFor(() =>
      expect(mocks.flowsSettingsSet).toHaveBeenLastCalledWith({
        scope_policy: { version: 1, repositories: [] },
      }),
    );
  });

  it("requires explicit connector-wide access and saves no targets for it", async () => {
    await renderSection();
    fireEvent.change(screen.getByLabelText("repository root"), { target: { value: "/repo" } });
    fireEvent.click(screen.getByRole("button", { name: "Add repository" }));
    fireEvent.change(screen.getByLabelText("service URL for /repo"), {
      target: { value: "https://jenkins.example/" },
    });
    expect(screen.getByRole("button", { name: "Add connector scope" })).toBeDisabled();
    fireEvent.click(
      screen.getByLabelText("Allow all connector targets and searches for /repo"),
    );
    fireEvent.click(screen.getByRole("button", { name: "Add connector scope" }));
    fireEvent.click(screen.getByRole("button", { name: "Save scopes" }));
    await waitFor(() =>
      expect(mocks.flowsSettingsSet).toHaveBeenCalledWith({
        scope_policy: {
          version: 1,
          repositories: [
            {
              root: "/repo",
              connectors: [
                {
                  connector: "jenkins",
                  base_url: "https://jenkins.example/",
                  access: "connector_wide",
                  targets: [],
                },
              ],
            },
          ],
        },
      }),
    );
  });

  it("keeps a rejected draft and displays the daemon refusal", async () => {
    await renderSection();
    await addScopeDraft();
    mocks.flowsSettingsSet.mockRejectedValueOnce({
      cause: "invalid_scope",
      detail: "Repository does not exist",
      recovery: "Choose an existing repository.",
    });
    fireEvent.click(screen.getByRole("button", { name: "Save scopes" }));
    await screen.findByText(/Repository does not exist/);
    expect(screen.getByText("Unsaved scope changes")).toBeInTheDocument();
    expect(screen.getByLabelText("remove repository /repo")).toBeInTheDocument();
  });

  it("retains dirty drafts on refresh and blocks overwriting changed scopes", async () => {
    const client = await renderSection();
    await addScopeDraft();
    await act(async () => {
      await client.invalidateQueries({ queryKey: ["flow-settings"] });
    });
    expect(screen.getByText("Unsaved scope changes")).toBeInTheDocument();
    act(() =>
      client.setQueryData(["flow-settings"], {
        ...SETTINGS,
        scope_policy: { version: 1, repositories: [{ root: "/elsewhere", connectors: [] }] },
      }),
    );
    await waitFor(() =>
      expect(screen.getByRole("button", { name: "Save scopes" })).toBeDisabled(),
    );
    expect(screen.getByText(/Saved scopes changed/)).toBeInTheDocument();
    expect(screen.getByLabelText("remove repository /repo")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Discard scope changes" }));
    expect(screen.getByLabelText("remove repository /elsewhere")).toBeInTheDocument();
    expect(mocks.flowsSettingsSet).not.toHaveBeenCalled();
  });
});

beforeEach(() => {
  let current = { ...SETTINGS };
  mocks.flowsSettingsGet.mockImplementation(async () => current);
  mocks.flowsSettingsSet.mockImplementation(async (patch: Partial<FlowSettings>) => {
    current = { ...current, ...patch };
    return current;
  });
});

async function renderSection() {
  const client = createAppQueryClient();
  render(
    <QueryClientProvider client={client}>
      <SettingsFlowsSection />
    </QueryClientProvider>,
  );
  await screen.findByText("git");
  await waitFor(() => expect(screen.getByLabelText("Program to allow")).toBeEnabled());
  return client;
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
    fireEvent.change(screen.getByLabelText("Program to allow"), { target: { value: "gh" } });
    fireEvent.click(
      within(
        screen.getByLabelText("Program to allow").closest("form") as HTMLFormElement,
      ).getByRole("button", { name: "Add" }),
    );
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
    fireEvent.change(screen.getByLabelText("Program to allow"), { target: { value: "bash" } });
    fireEvent.click(
      within(
        screen.getByLabelText("Program to allow").closest("form") as HTMLFormElement,
      ).getByRole("button", { name: "Add" }),
    );
    expect(await screen.findByText(/flow settings · program_not_allowed/)).toBeInTheDocument();
    expect(screen.getByText(/allowing it would allow every program/)).toBeInTheDocument();
  });
});

describe("extra PATH", () => {
  it("adds and removes a directory through the same op", async () => {
    await renderSection();
    fireEvent.change(screen.getByLabelText("Directory to add to PATH"), {
      target: { value: "/usr/local/bin" },
    });
    fireEvent.click(
      within(
        screen.getByLabelText("Directory to add to PATH").closest("form") as HTMLFormElement,
      ).getByRole("button", { name: "Add" }),
    );
    await waitFor(() =>
      expect(mocks.flowsSettingsSet).toHaveBeenCalledWith({
        extra_path: ["/opt/homebrew/bin", "/usr/local/bin"],
      }),
    );

    await waitFor(() =>
      expect(screen.getByLabelText("remove directory /opt/homebrew/bin")).toBeEnabled(),
    );
    fireEvent.click(screen.getByLabelText("remove directory /opt/homebrew/bin"));
    await waitFor(() =>
      expect(mocks.flowsSettingsSet).toHaveBeenCalledWith({ extra_path: ["/usr/local/bin"] }),
    );
  });
});

describe("build output directory", () => {
  it("shows the unset state and saves the directory a human types", async () => {
    await renderSection();
    expect(screen.getByText(/no build output directory/i)).toBeInTheDocument();
    const input = screen.getByLabelText("build output directory");
    fireEvent.change(input, { target: { value: " ~/pam-builds " } });
    fireEvent.click(screen.getByRole("button", { name: "Save directory" }));
    await waitFor(() =>
      expect(mocks.flowsSettingsSet).toHaveBeenCalledWith({ artifacts_root: "~/pam-builds" }),
    );
  });

  it("shows the configured directory and clears it with an explicit null", async () => {
    mocks.flowsSettingsGet.mockResolvedValue({
      ...SETTINGS,
      artifacts_root: "/private/builds",
    });
    await renderSection();
    expect(screen.getByLabelText("build output directory")).toHaveValue("/private/builds");
    fireEvent.click(screen.getByRole("button", { name: "Clear directory" }));
    await waitFor(() =>
      expect(mocks.flowsSettingsSet).toHaveBeenCalledWith({ artifacts_root: null }),
    );
  });
});

describe("read-only caches", () => {
  it("adds and removes a cache directory through the same op", async () => {
    let current: FlowSettings = { ...SETTINGS, read_cache_roots: ["~/.cargo/registry"] };
    mocks.flowsSettingsGet.mockImplementation(async () => current);
    mocks.flowsSettingsSet.mockImplementation(async (patch: Partial<FlowSettings>) => {
      current = { ...current, ...patch };
      return current;
    });
    await renderSection();
    fireEvent.change(screen.getByLabelText("Cache directory to add"), {
      target: { value: "~/.cargo/git" },
    });
    fireEvent.click(
      within(
        screen.getByLabelText("Cache directory to add").closest("form") as HTMLFormElement,
      ).getByRole("button", { name: "Add" }),
    );
    await waitFor(() =>
      expect(mocks.flowsSettingsSet).toHaveBeenCalledWith({
        read_cache_roots: ["~/.cargo/registry", "~/.cargo/git"],
      }),
    );
    await waitFor(() =>
      expect(screen.getByLabelText("remove cache directory ~/.cargo/registry")).toBeEnabled(),
    );
    fireEvent.click(screen.getByLabelText("remove cache directory ~/.cargo/registry"));
    await waitFor(() =>
      expect(mocks.flowsSettingsSet).toHaveBeenCalledWith({
        read_cache_roots: ["~/.cargo/git"],
      }),
    );
  });
});

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (reason: unknown) => void;
  const promise = new Promise<T>((yes, no) => {
    resolve = yes;
    reject = no;
  });
  return { promise, resolve, reject };
}

it("blocks initial and failed reads until a successful retry", async () => {
  const read = deferred<FlowSettings>();
  mocks.flowsSettingsGet.mockReturnValue(read.promise);
  render(
    <QueryClientProvider client={createAppQueryClient()}>
      <SettingsFlowsSection />
    </QueryClientProvider>,
  );
  const input = screen.getByLabelText("Program to allow");
  expect(input).toBeDisabled();
  fireEvent.change(input, { target: { value: "gh" } });
  fireEvent.submit(input.closest("form")!);
  expect(mocks.flowsSettingsSet).not.toHaveBeenCalled();
  await act(async () =>
    read.reject({ cause: "offline", detail: "read failed", recovery: "Retry" }),
  );
  expect(await screen.findByText(/flow settings · offline/)).toBeInTheDocument();
  fireEvent.submit(input.closest("form")!);
  expect(mocks.flowsSettingsSet).not.toHaveBeenCalled();
  mocks.flowsSettingsGet.mockResolvedValue(SETTINGS);
  fireEvent.click(screen.getByRole("button", { name: "Retry reading settings" }));
  await waitFor(() => expect(input).toBeEnabled());
  fireEvent.change(input, { target: { value: "gh" } });
  fireEvent.submit(input.closest("form")!);
  await waitFor(() =>
    expect(mocks.flowsSettingsSet).toHaveBeenCalledWith({
      allowed_programs: ["git", "cargo", "gh"],
    }),
  );
});

it("serializes double submits, chip removal and the post-save refresh", async () => {
  const save = deferred<FlowSettings>();
  mocks.flowsSettingsSet.mockReturnValue(save.promise);
  const client = await renderSection();
  const input = screen.getByLabelText("Program to allow");
  fireEvent.change(input, { target: { value: "gh" } });
  act(() => {
    fireEvent.submit(input.closest("form")!);
    fireEvent.submit(input.closest("form")!);
    fireEvent.click(screen.getByLabelText("remove program git"));
  });
  await waitFor(() => expect(mocks.flowsSettingsSet).toHaveBeenCalledTimes(1));
  expect(screen.getByLabelText("remove program git")).toBeDisabled();
  expect(screen.getByLabelText("Directory to add to PATH")).toBeDisabled();
  const refresh = deferred<FlowSettings>();
  mocks.flowsSettingsGet.mockReturnValue(refresh.promise);
  await act(async () =>
    save.resolve({ ...SETTINGS, allowed_programs: ["git", "cargo", "gh"] }),
  );
  await waitFor(() => expect(client.isFetching()).toBe(1));
  fireEvent.click(screen.getByLabelText("remove program git"));
  fireEvent.submit(input.closest("form")!);
  expect(mocks.flowsSettingsSet).toHaveBeenCalledTimes(1);
  await act(async () =>
    refresh.resolve({ ...SETTINGS, allowed_programs: ["git", "cargo", "gh", "rg"] }),
  );
  await waitFor(() => expect(input).toBeEnabled());
  fireEvent.click(screen.getByLabelText("remove program git"));
  await waitFor(() =>
    expect(mocks.flowsSettingsSet).toHaveBeenLastCalledWith({
      allowed_programs: ["cargo", "gh", "rg"],
    }),
  );
});

it("blocks a failed background refresh even when cached chips remain", async () => {
  const client = await renderSection();
  mocks.flowsSettingsGet.mockRejectedValue({
    cause: "offline",
    detail: "refresh failed",
    recovery: "Retry",
  });
  await act(async () => {
    await client.invalidateQueries({ queryKey: ["flow-settings"] });
  });
  expect(await screen.findByText(/flow settings · offline/)).toBeInTheDocument();
  expect(screen.getByLabelText("remove program git")).toBeDisabled();
  fireEvent.click(screen.getByLabelText("remove program git"));
  fireEvent.submit(screen.getByLabelText("Program to allow").closest("form")!);
  expect(mocks.flowsSettingsSet).not.toHaveBeenCalled();
});

describe("managed policy", () => {
  function managed(extra: Partial<FlowSettings>) {
    mocks.flowsSettingsGet.mockResolvedValue({ ...SETTINGS, ...extra });
  }

  it("disables a locked list and shows the policy's list in force, not the saved one", async () => {
    managed({
      allowed_programs: ["git", "cargo"],
      effective: {
        allowed_programs: {
          source: "policy",
          locked: true,
          mode: "locked",
          reason: "SEC-114",
          value: ["git"],
        },
      },
    });
    render(
      <QueryClientProvider client={createAppQueryClient()}>
        <SettingsFlowsSection />
      </QueryClientProvider>,
    );
    await screen.findByText("SEC-114");
    expect(screen.getByText("Managed by your organization")).toBeInTheDocument();
    expect(screen.getByLabelText("Program to allow")).toBeDisabled();
    expect(screen.getByLabelText("remove program git")).toBeDisabled();
    expect(screen.queryByLabelText("remove program cargo")).toBeNull();
    // The other lists stay editable.
    expect(screen.getByLabelText("Directory to add to PATH")).toBeEnabled();
  });

  it("locks the build output directory and the read-only caches too", async () => {
    managed({
      artifacts_root: "/home/me/saved",
      read_cache_roots: ["/home/me/cache"],
      effective: {
        artifacts_root: { source: "policy", locked: true, value: "/managed/builds" },
        read_cache_roots: { source: "policy", locked: true, value: ["/managed/cache"] },
      },
    });
    await renderSection();
    const directory = await screen.findByLabelText("build output directory");
    expect(directory).toHaveValue("/managed/builds");
    expect(directory).toBeDisabled();
    expect(screen.getByRole("button", { name: "Clear directory" })).toBeDisabled();
    expect(screen.getByLabelText("Cache directory to add")).toBeDisabled();
    expect(screen.getByLabelText("remove cache directory /managed/cache")).toBeDisabled();
    expect(screen.queryByLabelText("remove cache directory /home/me/cache")).toBeNull();
  });

  it("prints an allowlist beside a list that stays editable", async () => {
    managed({
      effective: {
        extra_path: {
          source: "policy",
          locked: false,
          mode: "allow",
          constraint: { allow: ["/opt/homebrew"] },
          clamped: true,
        },
      },
    });
    await renderSection();
    expect(await screen.findByText("allowed: /opt/homebrew")).toBeInTheDocument();
    expect(screen.getByLabelText("Directory to add to PATH")).toBeEnabled();
  });

  it("lists the scope entries the policy is not using, with the reason", async () => {
    managed({
      scope_policy: {
        version: 1,
        repositories: [{ root: "/work/app", connectors: [] }],
      },
      scope_policy_dropped: [
        {
          root: "/work/app",
          connector: "jenkins",
          key: "connectors.disabled",
          reason: "your organization's policy disables this connector",
        },
      ],
    });
    await renderSection();
    const note = await screen.findByRole("note", {
      name: "scope entries the policy is not using",
    });
    expect(note).toHaveTextContent("/work/app · jenkins");
    expect(note).toHaveTextContent("your organization's policy disables this connector");
    expect(note).toHaveTextContent("kept, and nothing is deleted");
  });

  it("freezes the scope editor when the policy holds the scope keys", async () => {
    managed({
      effective: {
        scope_policy: { source: "default", locked: true, state: "held" },
      },
    });
    await renderSection();
    expect(
      await screen.findByText(/paused until the policy file is fixed/),
    ).toBeInTheDocument();
    expect(screen.getByLabelText("repository root")).toBeDisabled();
    expect(screen.getByRole("button", { name: "Add repository" })).toBeDisabled();
  });

  it.each([
    ["setting_locked", "allowed_programs is managed by your organization's policy"],
    ["policy_not_allowed", '"make" is not on the list your organization allows'],
    ["policy_frozen", "the policy file cannot be trusted, so widening changes are paused"],
  ])("renders a %s refusal's detail and recovery", async (cause, detail) => {
    mocks.flowsSettingsSet.mockRejectedValue({
      cause,
      detail,
      recovery: "Managed by your organization's policy; ask your administrator.",
    });
    await renderSection();
    fireEvent.change(screen.getByLabelText("Program to allow"), { target: { value: "make" } });
    fireEvent.submit(screen.getByLabelText("Program to allow").closest("form")!);
    expect(await screen.findByText(new RegExp(`flow settings · ${cause}`))).toBeInTheDocument();
    expect(screen.getByText(`${detail}.`)).toBeInTheDocument();
    expect(screen.getByText(/ask your administrator/)).toBeInTheDocument();
  });
});
