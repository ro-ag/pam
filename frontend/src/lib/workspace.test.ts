import { beforeEach, describe, expect, it, vi } from "vitest";
import {
  applyWorkspace,
  deleteWorkspace,
  initWorkspace,
  isWorkspaceHref,
  saveWorkspace,
  subscribeWorkspace,
  workspaceSnapshot,
  workspaceStorageKey,
} from "./workspace";

beforeEach(() => {
  window.localStorage.clear();
  initWorkspace();
});

describe("workspace preferences", () => {
  it("defaults to an expanded full-width workspace and stamps CSS attributes", () => {
    expect(workspaceSnapshot()).toEqual({ sidebar: "expanded", width: "full", saved: [] });
    expect(document.documentElement.dataset.workspaceSidebar).toBe("expanded");
    expect(document.documentElement.dataset.workspaceWidth).toBe("full");
  });
  it("persists layout changes and restores them at startup", () => {
    applyWorkspace({ sidebar: "compact", width: "focused" });
    initWorkspace();
    expect(workspaceSnapshot()).toMatchObject({ sidebar: "compact", width: "focused" });
  });
  it("publishes a stable snapshot only when changed", () => {
    const original = workspaceSnapshot();
    expect(workspaceSnapshot()).toBe(original);
    const changed = vi.fn();
    const unsubscribe = subscribeWorkspace(changed);
    applyWorkspace({ sidebar: "compact", width: "full" });
    expect(changed).toHaveBeenCalledOnce();
    unsubscribe();
    applyWorkspace({ sidebar: "expanded", width: "full" });
    expect(changed).toHaveBeenCalledOnce();
  });
  it("saves screen, query and settings category without changing them", () => {
    applyWorkspace({ sidebar: "compact", width: "focused" });
    expect(saveWorkspace("  Models setup  ", "/settings?view=local#models")).toBeNull();
    initWorkspace();
    expect(workspaceSnapshot().saved[0]).toMatchObject({
      name: "Models setup",
      href: "/settings?view=local#models",
      sidebar: "compact",
      width: "focused",
    });
    deleteWorkspace(workspaceSnapshot().saved[0].id);
    expect(workspaceSnapshot().saved).toEqual([]);
  });
  it("rejects duplicate names, empty names and more than eight saves", () => {
    expect(saveWorkspace(" ", "/")).toMatch(/name/);
    expect(saveWorkspace("Monitor", "/activity")).toBeNull();
    expect(saveWorkspace("MONITOR", "/")).toMatch(/already exists/);
    for (let i = 1; i < 8; i++) expect(saveWorkspace(`Layout ${i}`, "/")).toBeNull();
    expect(saveWorkspace("Ninth", "/")).toMatch(/maximum 8/);
  });
  it.each([
    "https://example.com",
    "//example.com",
    "javascript:alert(1)",
    "/settings\\evil",
    "/unknown",
    "/settings\n",
    " /flows",
  ])("rejects unsafe or unknown route %s", (href) => {
    expect(isWorkspaceHref(href)).toBe(false);
    expect(saveWorkspace("Bad", href)).toMatch(/cannot be saved/);
  });
  it("ignores corrupt storage and filters invalid saved records", () => {
    window.localStorage.setItem(workspaceStorageKey, "not json");
    initWorkspace();
    expect(workspaceSnapshot().sidebar).toBe("expanded");
    const valid = { id: "one", name: "One", href: "/flows", sidebar: "compact", width: "full" };
    window.localStorage.setItem(
      workspaceStorageKey,
      JSON.stringify({
        sidebar: "compact",
        width: "full",
        saved: [valid, valid, { ...valid, id: "two", href: "https://evil.test" }, null],
      }),
    );
    initWorkspace();
    expect(workspaceSnapshot().saved).toEqual([valid]);
  });
  it("keeps live controls usable when persistence fails", () => {
    const store = vi.spyOn(window.localStorage, "setItem").mockImplementation(() => {
      throw new Error("unavailable");
    });
    expect(() => applyWorkspace({ sidebar: "compact", width: "focused" })).not.toThrow();
    expect(workspaceSnapshot().sidebar).toBe("compact");
    store.mockRestore();
  });
});
