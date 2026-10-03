import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, expect, it, vi } from "vitest";
import {
  LandingSettings,
  formatRequiredCheck,
  parseRequiredCheck,
  parseTimeout,
  unpinnedChecks,
} from "./LandingSettings";
import type { LandingPolicy, LandingRepository } from "../lib/landing";
const mocks = vi.hoisted(() => ({ landingGet: vi.fn(), landingSet: vi.fn() }));
vi.mock("../lib/landing", async (original) => ({
  ...(await original<typeof import("../lib/landing")>()),
  ...mocks,
}));
const repository: LandingRepository = {
  root: "/repo",
  repository: "https://github.com/org/repo",
  github_server: "https://api.github.com/",
  github_repository: "org/repo",
  base: "main",
  branches: ["feature/work"],
  workspace_root: "/private/landing",
  read_cache_roots: [],
  checks: [{ name: "unit", argv: ["cargo", "test"], timeout_seconds: 300 }],
  required_checks: ["ci"],
  main_checks: ["ci"],
  permissions: { push: false, create_pr: false, merge: false, sync: false },
};
const saved: LandingPolicy = { revision: "revision-a", repositories: [repository] };
beforeEach(() => {
  vi.clearAllMocks();
  mocks.landingGet.mockResolvedValue(saved);
  mocks.landingSet.mockImplementation(async (_revision, repositories, git_path) => ({
    revision: "revision-b",
    git_path,
    repositories,
  }));
});
async function setup() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={client}>
      <LandingSettings />
    </QueryClientProvider>,
  );
  await screen.findByDisplayValue("/repo");
  return client;
}
it("loads saved fields and new entries grant nothing before explicit save", async () => {
  await setup();
  expect(screen.getByLabelText("Landing repository 1 check 1 program")).toHaveValue("cargo");
  expect(screen.getAllByRole("checkbox")).toHaveLength(4);
  for (const checkbox of screen.getAllByRole("checkbox")) expect(checkbox).not.toBeChecked();
  fireEvent.click(screen.getByRole("button", { name: "Add landing repository" }));
  for (const checkbox of screen.getAllByRole("checkbox")) expect(checkbox).not.toBeChecked();
  expect(mocks.landingSet).not.toHaveBeenCalled();
});
it("saves a structured revision-bound recipe and only selected permission", async () => {
  await setup();
  fireEvent.change(
    screen.getByLabelText("Landing repository 1 check 1 arguments (one per line)"),
    { target: { value: "test\n--workspace" } },
  );
  fireEvent.click(screen.getByLabelText("Landing repository 1: Push branch"));
  fireEvent.click(screen.getByRole("button", { name: "Save landing policy" }));
  await waitFor(() => expect(mocks.landingSet).toHaveBeenCalledTimes(1));
  expect(mocks.landingSet).toHaveBeenCalledWith(
    "revision-a",
    [
      {
        ...repository,
        checks: [{ ...repository.checks[0], argv: ["cargo", "test", "--workspace"] }],
        permissions: { push: true, create_pr: false, merge: false, sync: false },
      },
    ],
    null,
  );
  await waitFor(() =>
    expect(screen.queryByText(/Unsaved landing changes/)).not.toBeInTheDocument(),
  );
});
it("removal is draft-only until saving the empty deny policy", async () => {
  await setup();
  fireEvent.click(screen.getByRole("button", { name: "Remove landing repository 1" }));
  expect(mocks.landingSet).not.toHaveBeenCalled();
  fireEvent.click(screen.getByRole("button", { name: "Save landing policy" }));
  await waitFor(() => expect(mocks.landingSet).toHaveBeenCalledWith("revision-a", [], null));
});
it("pending saves block duplicate submission and edits", async () => {
  let resolve!: (value: LandingPolicy) => void;
  mocks.landingSet.mockImplementation(
    () =>
      new Promise((done) => {
        resolve = done;
      }),
  );
  await setup();
  fireEvent.click(screen.getByLabelText("Landing repository 1: Push branch"));
  const save = screen.getByRole("button", { name: "Save landing policy" });
  fireEvent.click(save);
  fireEvent.click(save);
  expect(save).toBeDisabled();
  expect(screen.getByLabelText("Landing repository 1: Merge pull request")).toBeDisabled();
  expect(screen.getByRole("button", { name: "Reload landing policy" })).toBeDisabled();
  expect(mocks.landingSet).toHaveBeenCalledTimes(1);
  await act(async () =>
    resolve({
      revision: "revision-b",
      repositories: [{ ...repository, permissions: { ...repository.permissions, push: true } }],
    }),
  );
  expect(screen.getByLabelText("Landing repository 1: Merge pull request")).not.toBeChecked();
});
it("background revisions preserve the draft and require explicit reload", async () => {
  const client = await setup();
  fireEvent.click(screen.getByLabelText("Landing repository 1: Push branch"));
  act(() => client.setQueryData(["landing-policy"], { revision: "newer", repositories: [] }));
  await screen.findByRole("alert");
  expect(screen.getByLabelText("Landing repository 1: Push branch")).toBeChecked();
  expect(screen.getByRole("button", { name: "Save landing policy" })).toBeDisabled();
  mocks.landingGet.mockResolvedValue({ revision: "newer", repositories: [] });
  fireEvent.click(screen.getByRole("button", { name: "Reload landing policy" }));
  await waitFor(() => expect(screen.queryByRole("alert")).not.toBeInTheDocument());
  expect(screen.queryByLabelText("Landing repository 1: Push branch")).not.toBeInTheDocument();
  expect(mocks.landingSet).not.toHaveBeenCalled();
});
it("CAS rejection requires reload and does not silently retry authority", async () => {
  mocks.landingSet.mockRejectedValue({
    cause: "landing_policy_changed",
    detail: "Policy changed",
    recovery: "Reload",
  });
  await setup();
  fireEvent.click(screen.getByLabelText("Landing repository 1: Merge pull request"));
  fireEvent.click(screen.getByRole("button", { name: "Save landing policy" }));
  await screen.findByRole("alert");
  expect(screen.getByRole("button", { name: "Save landing policy" })).toBeDisabled();
  expect(screen.getByLabelText("Landing repository 1: Merge pull request")).toBeChecked();
  expect(mocks.landingSet).toHaveBeenCalledTimes(1);
});

it("cache access requires explicit exact directories in the saved recipe", async () => {
  await setup();
  const label = "Landing repository 1 read-only cache directories (maximum 8) (one per line)";
  expect(screen.getByLabelText(label)).toHaveValue("");
  fireEvent.change(screen.getByLabelText(label), {
    target: { value: "/home/dev/.cargo/registry\n/home/dev/.npm/_cacache" },
  });
  expect(mocks.landingSet).not.toHaveBeenCalled();
  fireEvent.click(screen.getByRole("button", { name: "Save landing policy" }));
  await waitFor(() =>
    expect(mocks.landingSet).toHaveBeenCalledWith(
      "revision-a",
      [
        {
          ...repository,
          read_cache_roots: ["/home/dev/.cargo/registry", "/home/dev/.npm/_cacache"],
        },
      ],
      null,
    ),
  );
});
it("keeps the saved timeout while the field is blank or out of range", async () => {
  await setup();
  const timeout = await screen.findByLabelText(/check 1 timeout/);
  expect(timeout).toHaveValue("300");
  fireEvent.change(timeout, { target: { value: "" } });
  expect(timeout).toHaveAttribute("aria-invalid", "true");
  expect(screen.getByText(/Whole seconds between 1 and 600/)).toBeInTheDocument();
  fireEvent.change(timeout, { target: { value: "601" } });
  expect(timeout).toHaveAttribute("aria-invalid", "true");
  fireEvent.change(timeout, { target: { value: "45" } });
  expect(timeout).not.toHaveAttribute("aria-invalid");
  fireEvent.click(screen.getByRole("button", { name: "Save landing policy" }));
  await waitFor(() => expect(mocks.landingSet).toHaveBeenCalled());
  const saved = mocks.landingSet.mock.calls[0][1][0];
  expect(saved.checks[0].timeout_seconds).toBe(45);
  expect(parseTimeout(" 12 ")).toBe(12);
  expect(parseTimeout("0")).toBeNull();
  expect(parseTimeout("1.5")).toBeNull();
});

it("refuses more than eight cache roots before an admin save", async () => {
  await setup();
  fireEvent.change(
    screen.getByLabelText(
      "Landing repository 1 read-only cache directories (maximum 8) (one per line)",
    ),
    { target: { value: Array.from({ length: 9 }, (_, i) => `/cache/${i}`).join("\n") } },
  );
  expect(screen.getByRole("button", { name: "Save landing policy" })).toBeDisabled();
  fireEvent.click(screen.getByRole("button", { name: "Save landing policy" }));
  expect(mocks.landingSet).not.toHaveBeenCalled();
});

it("disables a permission the policy ceiling forbids and says so", async () => {
  mocks.landingGet.mockResolvedValue({
    ...saved,
    effective: {
      max_permissions: {
        source: "policy",
        locked: false,
        mode: "forbid",
        constraint: { "landing.max_permissions": { create_pr: false } },
        clamped: true,
        value: { push: true, create_pr: false, merge: true, sync: true },
      },
    },
  });
  await setup();
  expect(screen.getByLabelText(/Landing repository 1: Create pull request/)).toBeDisabled();
  expect(screen.getByLabelText(/Landing repository 1: Push branch/)).toBeEnabled();
  expect(screen.getByText("not allowed by your organization")).toBeInTheDocument();
  expect(screen.getByText("Limited by your organization")).toBeInTheDocument();
});

it("lists the allowed GitHub servers", async () => {
  mocks.landingGet.mockResolvedValue({
    ...saved,
    effective: {
      allowed_github_servers: {
        source: "policy",
        locked: false,
        mode: "forbid",
        constraint: { "landing.allowed_github_servers": ["https://ghe.corp.example/api/v3/"] },
        value: ["https://ghe.corp.example/api/v3/"],
      },
    },
  });
  await setup();
  expect(screen.getByLabelText("allowed GitHub servers")).toHaveTextContent(
    "https://ghe.corp.example/api/v3/",
  );
});

it("reports the landing recipes the policy is not using", async () => {
  mocks.landingGet.mockResolvedValue({
    ...saved,
    landing_policy_dropped: [
      {
        root: "/repo",
        key: "landing.allowed_github_servers",
        reason: "this repository's GitHub server is not one your organization allows",
      },
    ],
  });
  await setup();
  const note = screen.getByRole("note", { name: "landing recipes the policy is not using" });
  expect(note).toHaveTextContent("/repo");
  expect(note).toHaveTextContent("not one your organization allows");
});

it("freezes the whole editor when the policy holds a landing key", async () => {
  mocks.landingGet.mockResolvedValue({
    ...saved,
    effective: { max_permissions: { source: "default", locked: true, state: "held" } },
  });
  await setup();
  expect(screen.getByLabelText("Landing repository 1: Push branch")).toBeDisabled();
  expect(screen.getByRole("button", { name: "Add landing repository" })).toBeDisabled();
  expect(screen.getByText(/paused until the policy file is fixed/)).toBeInTheDocument();
});

it("renders a refused save with the daemon's cause, detail and recovery", async () => {
  mocks.landingSet.mockRejectedValue({
    cause: "policy_not_allowed",
    detail: "landing.max_permissions does not allow create_pr",
    recovery: "Managed by your organization's policy; ask your administrator.",
  });
  await setup();
  fireEvent.click(screen.getByLabelText("Landing repository 1: Push branch"));
  fireEvent.click(screen.getByRole("button", { name: "Save landing policy" }));
  expect(await screen.findByText(/landing policy · policy_not_allowed/)).toBeInTheDocument();
  expect(screen.getByText(/ask your administrator/)).toBeInTheDocument();
});

it("pins a required check to its GitHub App and flags the unpinned ones", async () => {
  expect(parseRequiredCheck("ci / build @15368")).toEqual({
    name: "ci / build",
    app_id: 15368,
  });
  expect(parseRequiredCheck("ci")).toBe("ci");
  expect(parseRequiredCheck("ci @0")).toBe("ci @0");
  expect(parseRequiredCheck("@15368")).toBe("@15368");
  expect(formatRequiredCheck({ name: "ci", app_id: 15368 })).toBe("ci @15368");
  expect(unpinnedChecks({ ...repository, main_checks: [{ name: "ci", app_id: 1 }] })).toEqual([
    "ci",
  ]);
  await setup();
  expect(screen.getByLabelText("Landing repository 1 unpinned checks")).toHaveTextContent(
    "Unpinned app: ci.",
  );
  for (const label of ["required PR checks", "required main checks"]) {
    fireEvent.change(screen.getByLabelText(`Landing repository 1 ${label} (one per line)`), {
      target: { value: "ci @15368\n" },
    });
  }
  expect(
    screen.queryByLabelText("Landing repository 1 unpinned checks"),
  ).not.toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", { name: "Save landing policy" }));
  await waitFor(() => expect(mocks.landingSet).toHaveBeenCalled());
  const sent = mocks.landingSet.mock.calls[0][1][0];
  expect(sent.required_checks).toEqual([{ name: "ci", app_id: 15368 }]);
  expect(sent.main_checks).toEqual([{ name: "ci", app_id: 15368 }]);
});

it("saves the merge method and the Git path", async () => {
  await setup();
  const method = screen.getByLabelText("Landing repository 1 merge method");
  expect(method).toHaveValue("squash");
  fireEvent.change(method, { target: { value: "rebase" } });
  fireEvent.change(screen.getByLabelText(/Git for landing/), {
    target: { value: " /Library/Developer/CommandLineTools/usr/bin/git " },
  });
  fireEvent.click(screen.getByRole("button", { name: "Save landing policy" }));
  await waitFor(() => expect(mocks.landingSet).toHaveBeenCalled());
  const [, repositories, gitPath] = mocks.landingSet.mock.calls[0];
  expect(repositories[0].merge_method).toBe("rebase");
  expect(gitPath).toBe("/Library/Developer/CommandLineTools/usr/bin/git");
});

it("shows a Git path and merge method the policy locks as read-only", async () => {
  mocks.landingGet.mockResolvedValue({
    ...saved,
    git_path: "/opt/homebrew/bin/git",
    effective: {
      git_path: {
        source: "policy",
        locked: true,
        mode: "locked",
        reason: "SEC-7",
        value: "/Library/Developer/CommandLineTools/usr/bin/git",
      },
      merge_method: { source: "policy", locked: true, mode: "locked", value: "merge" },
    },
  });
  await setup();
  const git = screen.getByLabelText(/Git for landing/);
  expect(git).toBeDisabled();
  expect(git).toHaveValue("/Library/Developer/CommandLineTools/usr/bin/git");
  const method = screen.getByLabelText("Landing repository 1 merge method");
  expect(method).toBeDisabled();
  expect(method).toHaveValue("merge");
  expect(screen.getByText("SEC-7")).toBeInTheDocument();
  expect(screen.getAllByText("Managed by your organization")).toHaveLength(2);
});
