import { afterEach, describe, expect, it } from "vitest";
import {
  applyTheme,
  defaultTheme,
  initTheme,
  isThemeId,
  nextTheme,
  themeDefinition,
  themes,
  themeStorageKey,
} from "./theme";

afterEach(() => {
  window.localStorage.clear();
  delete document.documentElement.dataset.theme;
  document.documentElement.style.colorScheme = "";
});

describe("theme registry", () => {
  it("registers both kept v1 families with schemes", () => {
    expect(themes.map((theme) => theme.id)).toEqual(["ventisquero-mist", "vina-del-mar-dawn"]);
    expect(themeDefinition("ventisquero-mist").scheme).toBe("dark");
    expect(themeDefinition("vina-del-mar-dawn").scheme).toBe("light");
  });

  it("validates ids", () => {
    expect(isThemeId("vina-del-mar-dawn")).toBe(true);
    expect(isThemeId("solarized")).toBe(false);
    expect(isThemeId(null)).toBe(false);
  });

  it("cycles through the registry", () => {
    expect(nextTheme("ventisquero-mist")).toBe("vina-del-mar-dawn");
    expect(nextTheme("vina-del-mar-dawn")).toBe("ventisquero-mist");
  });
});

describe("applyTheme", () => {
  it("sets data-theme, color-scheme, and persists", () => {
    applyTheme("vina-del-mar-dawn");
    expect(document.documentElement.dataset.theme).toBe("vina-del-mar-dawn");
    expect(document.documentElement.style.colorScheme).toBe("light");
    expect(window.localStorage.getItem(themeStorageKey)).toBe("vina-del-mar-dawn");
  });

  it("can apply without persisting", () => {
    applyTheme("ventisquero-mist", { persist: false });
    expect(document.documentElement.dataset.theme).toBe("ventisquero-mist");
    expect(window.localStorage.getItem(themeStorageKey)).toBeNull();
  });
});

describe("initTheme", () => {
  it("prefers a valid stored theme", () => {
    window.localStorage.setItem(themeStorageKey, "vina-del-mar-dawn");
    expect(initTheme()).toBe("vina-del-mar-dawn");
    expect(document.documentElement.dataset.theme).toBe("vina-del-mar-dawn");
  });

  it("falls back to the default on garbage storage", () => {
    window.localStorage.setItem(themeStorageKey, "hotdog-stand");
    expect(initTheme()).toBe(defaultTheme);
    expect(document.documentElement.dataset.theme).toBe(defaultTheme);
  });

  it("does not persist the fallback choice", () => {
    window.localStorage.clear();
    initTheme();
    expect(window.localStorage.getItem(themeStorageKey)).toBeNull();
  });
});
