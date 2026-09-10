import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen } from "@testing-library/react";
import { beforeEach, expect, it, vi } from "vitest";
import { SonarRepositoryMappingsEditor } from "./SonarRepositoryMappings";
const mocks = vi.hoisted(() => ({ sonarMappingsGet: vi.fn(), sonarMappingsSet: vi.fn() }));
vi.mock("../lib/ipc", async (original) => ({
  ...(await original<typeof import("../lib/ipc")>()),
  ...mocks,
}));
const row = {
  server: "https://sonar.example",
  project: "app",
  repository: "https://git.example/team/app.git",
};
beforeEach(() => {
  vi.resetAllMocks();
  mocks.sonarMappingsGet.mockResolvedValue({ revision: "r1", mappings: [row] });
});
function mount() {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  render(
    <QueryClientProvider client={client}>
      <SonarRepositoryMappingsEditor />
    </QueryClientProvider>,
  );
}
it("does not auto-write and saves explicit edits against the loaded revision", async () => {
  mocks.sonarMappingsSet.mockResolvedValue({
    revision: "r2",
    mappings: [{ ...row, project: "changed" }],
  });
  mount();
  expect(await screen.findByLabelText("Mapping 1 project")).toHaveValue("app");
  expect(mocks.sonarMappingsSet).not.toHaveBeenCalled();
  expect(screen.getByRole("button", { name: "Save mappings" })).toBeDisabled();
  fireEvent.change(screen.getByLabelText("Mapping 1 project"), {
    target: { value: "changed" },
  });
  fireEvent.click(screen.getByRole("button", { name: "Save mappings" }));
  await screen.findByText("Mappings saved.");
  expect(mocks.sonarMappingsSet.mock.calls[0][0]).toEqual({
    revision: "r1",
    mappings: [{ ...row, project: "changed" }],
  });
});
it("refresh preserves dirty edits until deliberate reload after concurrent change", async () => {
  mount();
  await screen.findByLabelText("Mapping 1 project");
  fireEvent.change(screen.getByLabelText("Mapping 1 project"), {
    target: { value: "local edit" },
  });
  mocks.sonarMappingsGet.mockResolvedValue({
    revision: "r2",
    mappings: [{ ...row, project: "remote edit" }],
  });
  fireEvent.click(screen.getByRole("button", { name: "Refresh mappings" }));
  await screen.findByText(/Saved mappings changed elsewhere/);
  expect(screen.getByLabelText("Mapping 1 project")).toHaveValue("local edit");
  expect(screen.getByRole("button", { name: "Save mappings" })).toBeDisabled();
  fireEvent.click(
    screen.getByRole("button", { name: "Reload saved mappings (discard edits)" }),
  );
  expect(screen.getByLabelText("Mapping 1 project")).toHaveValue("remote edit");
  expect(mocks.sonarMappingsSet).not.toHaveBeenCalled();
});
it.each(["sonar_mapping_invalid", "sonar_mapping_conflict"])(
  "retains edits and reports %s",
  async (cause) => {
    mocks.sonarMappingsSet.mockRejectedValue({
      cause,
      detail: "Mapping rejected",
      recovery: "Review the current mapping.",
    });
    mount();
    await screen.findByLabelText("Mapping 1 repository");
    fireEvent.change(screen.getByLabelText("Mapping 1 repository"), {
      target: { value: "https://git.example/local.git" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Save mappings" }));
    await screen.findByText(new RegExp(cause));
    expect(screen.getByLabelText("Mapping 1 repository")).toHaveValue(
      "https://git.example/local.git",
    );
    expect(await screen.findByText("Review the current mapping.")).toBeInTheDocument();
  },
);
