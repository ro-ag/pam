import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, expect, it, vi } from "vitest";
import { CompressorCard } from "./CompressorCard";

const call = vi.hoisted(() => vi.fn());
vi.mock("../lib/ipc", () => ({
  adminCall: call,
  toBridgeFailure: (error: Error) => ({ detail: error.message }),
}));

beforeEach(() => {
  call.mockReset();
});
function mount() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={client}>
      <CompressorCard />
    </QueryClientProvider>,
  );
}

it("requires installation before opt-in and starts GUI download jobs", async () => {
  call.mockImplementation(async (op: string) =>
    op.endsWith("status") ? { installed: false, enabled: false } : { jobs: ["download-1"] },
  );
  mount();
  const install = await screen.findByRole("button", { name: "Install compressor" });
  await waitFor(() => expect(install).toBeEnabled());
  expect(screen.getByRole("button", { name: "Enable for summaries" })).toBeDisabled();
  expect(screen.getByRole("button", { name: "Reinstall assets" })).toBeEnabled();
  fireEvent.click(install);
  await waitFor(() =>
    expect(call).toHaveBeenCalledWith("admin.models.compressor.install", { repair: false }),
  );
});

it("offers explicit reinstall and reports refused opt-in", async () => {
  call.mockImplementation(async (op: string) => {
    if (op.endsWith("status")) return { installed: true, enabled: false };
    if (op.endsWith("set")) throw new Error("Assets failed validation");
    return { jobs: [] };
  });
  mount();
  const repair = await screen.findByRole("button", { name: "Reinstall assets" });
  await waitFor(() => expect(repair).toBeEnabled());
  fireEvent.click(repair);
  await waitFor(() =>
    expect(call).toHaveBeenCalledWith("admin.models.compressor.install", { repair: true }),
  );
  fireEvent.click(screen.getByRole("button", { name: "Enable for summaries" }));
  expect(await screen.findByRole("alert")).toHaveTextContent("Assets failed validation");
});
