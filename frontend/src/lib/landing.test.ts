import { beforeEach, expect, it, vi } from "vitest";
import { emptyLandingRepository, landingGet, landingSet } from "./landing";
const admin = vi.hoisted(() => vi.fn());
vi.mock("./ipc", () => ({ adminCall: admin }));
beforeEach(() => admin.mockReset());
it("uses only GUI admin operations with the exact expected revision", async () => {
  admin.mockResolvedValue({ revision: "r", repositories: [] });
  await landingGet();
  expect(admin).toHaveBeenCalledWith("admin.flows.landing.get");
  await landingSet("r", []);
  expect(admin).toHaveBeenLastCalledWith("admin.flows.landing.set", {
    expected_revision: "r",
    repositories: [],
  });
});
it("new recipes deny every mutation and do not share mutable defaults", () => {
  const first = emptyLandingRepository();
  first.permissions.merge = true;
  first.checks[0].argv.push("test");
  const second = emptyLandingRepository();
  expect(Object.values(second.permissions)).toEqual([false, false, false, false]);
  expect(second.checks[0].argv).toEqual([""]);
});
