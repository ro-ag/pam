import { describe, expect, it } from "vitest";

import {
  clampSidebarWidth,
  defaultSidebarCollapsed,
  defaultSidebarWidth,
  maximumSidebarWidth,
  minimumSidebarWidth,
  readPersistedSidebarCollapsed,
  readPersistedSidebarWidth,
  sidebarCollapsedStorageKey,
  sidebarMaximumWidth,
  sidebarWidthFromKey,
  sidebarWidthStorageKey,
  storedSidebarCollapsed,
  storedSidebarWidth,
  writePersistedSidebarCollapsed,
  writePersistedSidebarWidth,
  type LayoutStorage,
} from "./layout";

class MemoryStorage implements LayoutStorage {
  readonly values = new Map<string, string>();

  getItem(key: string): string | null {
    return this.values.get(key) ?? null;
  }

  setItem(key: string, value: string): void {
    this.values.set(key, value);
  }
}

const throwingStorage: LayoutStorage = {
  getItem: () => {
    throw new Error("storage read failed");
  },
  setItem: () => {
    throw new Error("storage write failed");
  },
};

describe("sidebar layout policy", () => {
  it("uses the verified desktop and responsive bounds", () => {
    expect(sidebarMaximumWidth(1_400)).toBe(maximumSidebarWidth);
    expect(clampSidebarWidth(80, 1_400)).toBe(minimumSidebarWidth);
    expect(clampSidebarWidth(360, 1_400)).toBe(360);
    expect(clampSidebarWidth(900, 1_400)).toBe(maximumSidebarWidth);

    expect(sidebarMaximumWidth(640)).toBe(288);
    expect(clampSidebarWidth(420, 640)).toBe(288);
    expect(clampSidebarWidth(179, 640)).toBe(minimumSidebarWidth);
  });

  it("rounds to integer pixels and falls back for invalid widths", () => {
    expect(clampSidebarWidth(280.6, 1_400)).toBe(281);
    expect(clampSidebarWidth(Number.NaN, 1_400)).toBe(defaultSidebarWidth);
    expect(clampSidebarWidth(Number.POSITIVE_INFINITY, 1_400)).toBe(defaultSidebarWidth);
    expect(storedSidebarWidth(null, 1_400)).toBe(defaultSidebarWidth);
    expect(storedSidebarWidth("", 1_400)).toBe(defaultSidebarWidth);
    expect(storedSidebarWidth("not-a-number", 1_400)).toBe(defaultSidebarWidth);
    expect(storedSidebarWidth("350", 1_400)).toBe(350);
  });

  it("uses the exact fine, coarse, and boundary keyboard steps", () => {
    expect(sidebarWidthFromKey(248, "ArrowLeft", 1_400)).toBe(232);
    expect(sidebarWidthFromKey(248, "ArrowRight", 1_400)).toBe(264);
    expect(sidebarWidthFromKey(248, "PageDown", 1_400)).toBe(184);
    expect(sidebarWidthFromKey(248, "PageUp", 1_400)).toBe(312);
    expect(sidebarWidthFromKey(248, "Home", 1_400)).toBe(minimumSidebarWidth);
    expect(sidebarWidthFromKey(248, "End", 1_400)).toBe(maximumSidebarWidth);
    expect(sidebarWidthFromKey(248, "End", 640)).toBe(288);
    expect(sidebarWidthFromKey(248, "Escape", 1_400)).toBeNull();
  });
});

describe("sidebar layout persistence", () => {
  it("uses PAM-specific keys", () => {
    expect(sidebarWidthStorageKey).toBe("pam-sidebar-width");
    expect(sidebarCollapsedStorageKey).toBe("pam-sidebar-collapsed");
  });

  it("falls back for missing and invalid persisted values", () => {
    const storage = new MemoryStorage();

    expect(readPersistedSidebarWidth(storage, 1_400)).toBe(defaultSidebarWidth);
    expect(readPersistedSidebarCollapsed(storage)).toBe(defaultSidebarCollapsed);

    storage.values.set(sidebarWidthStorageKey, "wide");
    storage.values.set(sidebarCollapsedStorageKey, "sometimes");
    expect(readPersistedSidebarWidth(storage, 1_400)).toBe(defaultSidebarWidth);
    expect(readPersistedSidebarCollapsed(storage)).toBe(defaultSidebarCollapsed);
    expect(storedSidebarCollapsed("true")).toBe(true);
    expect(storedSidebarCollapsed("false")).toBe(false);
  });

  it("reads and writes width and collapsed state independently", () => {
    const storage = new MemoryStorage();

    writePersistedSidebarWidth(storage, 700, 640);
    expect(storage.values.get(sidebarWidthStorageKey)).toBe("288");
    expect(storage.values.has(sidebarCollapsedStorageKey)).toBe(false);

    writePersistedSidebarCollapsed(storage, true);
    expect(storage.values.get(sidebarCollapsedStorageKey)).toBe("true");
    expect(readPersistedSidebarWidth(storage, 640)).toBe(288);
    expect(readPersistedSidebarCollapsed(storage)).toBe(true);
  });

  it("never throws when storage reads or writes fail", () => {
    expect(readPersistedSidebarWidth(throwingStorage, 1_400)).toBe(defaultSidebarWidth);
    expect(readPersistedSidebarCollapsed(throwingStorage)).toBe(defaultSidebarCollapsed);
    expect(readPersistedSidebarWidth(undefined, 1_400)).toBe(defaultSidebarWidth);
    expect(readPersistedSidebarCollapsed(null)).toBe(defaultSidebarCollapsed);

    expect(() => writePersistedSidebarWidth(throwingStorage, 320, 1_400)).not.toThrow();
    expect(() => writePersistedSidebarCollapsed(throwingStorage, true)).not.toThrow();
    expect(() => writePersistedSidebarWidth(undefined, 320, 1_400)).not.toThrow();
    expect(() => writePersistedSidebarCollapsed(null, false)).not.toThrow();
  });
});
