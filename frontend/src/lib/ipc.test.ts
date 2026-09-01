import { describe, expect, it } from "vitest";
import {
  BridgeUnavailable,
  activityList,
  adminCall,
  approvalsPending,
  daemonStatus,
  daemonStop,
  grantsList,
  requestCapability,
  subscribeEvents,
  toBridgeFailure,
} from "./ipc";

/**
 * jsdom has no Tauri bridge, exactly like plain-browser Vite dev — every
 * wrapper must reject with the typed BridgeUnavailable failure instead of
 * throwing something the UI cannot render.
 */
describe("ipc without the app shell", () => {
  it.each([
    ["daemonStatus", () => daemonStatus()],
    ["daemonStop", () => daemonStop()],
    ["adminCall", () => adminCall("admin.profile.get")],
    ["approvalsPending", () => approvalsPending()],
    ["activityList", () => activityList()],
    ["grantsList", () => grantsList()],
    ["requestCapability", () => requestCapability("echo", { hello: "pam" })],
    ["subscribeEvents", () => subscribeEvents(() => {})],
  ] as const)("%s rejects with BridgeUnavailable", async (_name, call) => {
    await expect(call()).rejects.toBeInstanceOf(BridgeUnavailable);
  });

  it("BridgeUnavailable carries the uniform failure shape", () => {
    const failure = new BridgeUnavailable();
    expect(failure.cause).toBe("bridge_unavailable");
    expect(failure.detail).toMatch(/outside the app shell/);
    expect(failure.recovery).toMatch(/pam -- gui/);
    // It narrows through the same helper as bridge rejections.
    expect(toBridgeFailure(failure)).toEqual({
      cause: failure.cause,
      detail: failure.detail,
      recovery: failure.recovery,
    });
  });
});

describe("toBridgeFailure", () => {
  it("passes a Rust BridgeError shape through verbatim", () => {
    const shaped = {
      cause: "unknown_admin_op",
      detail: "no such op",
      recovery: "pick a real one",
    };
    expect(toBridgeFailure(shaped)).toEqual(shaped);
  });

  it("wraps junk rejections into the same shape", () => {
    const failure = toBridgeFailure("socket exploded");
    expect(failure.cause).toBe("unknown_failure");
    expect(failure.detail).toContain("socket exploded");
    expect(failure.recovery).not.toHaveLength(0);
  });

  it("wraps partially-shaped objects instead of trusting them", () => {
    const failure = toBridgeFailure({ cause: 42, detail: "x", recovery: "y" });
    expect(failure.cause).toBe("unknown_failure");
  });
});
