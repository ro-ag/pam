import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, expect, it, vi } from "vitest";
import { LandingSettings } from "./LandingSettings";
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
  mocks.landingSet.mockImplementation(async (_revision, repositories) => ({
    revision: "revision-b",
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
  expect(mocks.landingSet).toHaveBeenCalledWith("revision-a", [
    {
      ...repository,
      checks: [{ ...repository.checks[0], argv: ["cargo", "test", "--workspace"] }],
      permissions: { push: true, create_pr: false, merge: false, sync: false },
    },
  ]);
  await waitFor(() =>
    expect(screen.queryByText(/Unsaved landing changes/)).not.toBeInTheDocument(),
  );
});
it("removal is draft-only until saving the empty deny policy", async () => {
  await setup();
  fireEvent.click(screen.getByRole("button", { name: "Remove landing repository 1" }));
  expect(mocks.landingSet).not.toHaveBeenCalled();
  fireEvent.click(screen.getByRole("button", { name: "Save landing policy" }));
  await waitFor(() => expect(mocks.landingSet).toHaveBeenCalledWith("revision-a", []));
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
  expect(screen.getByLabelText("Landing repository 1: Squash merge")).toBeDisabled();
  expect(screen.getByRole("button", { name: "Reload landing policy" })).toBeDisabled();
  expect(mocks.landingSet).toHaveBeenCalledTimes(1);
  await act(async () =>
    resolve({
      revision: "revision-b",
      repositories: [{ ...repository, permissions: { ...repository.permissions, push: true } }],
    }),
  );
  expect(screen.getByLabelText("Landing repository 1: Squash merge")).not.toBeChecked();
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
  fireEvent.click(screen.getByLabelText("Landing repository 1: Squash merge"));
  fireEvent.click(screen.getByRole("button", { name: "Save landing policy" }));
  await screen.findByRole("alert");
  expect(screen.getByRole("button", { name: "Save landing policy" })).toBeDisabled();
  expect(screen.getByLabelText("Landing repository 1: Squash merge")).toBeChecked();
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
    expect(mocks.landingSet).toHaveBeenCalledWith("revision-a", [
      {
        ...repository,
        read_cache_roots: ["/home/dev/.cargo/registry", "/home/dev/.npm/_cacache"],
      },
    ]),
  );
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
