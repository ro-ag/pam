import { afterEach, describe, expect, it } from "vitest";
import {
  applyTheme,
  applyMaterial,
  materialStorageKey,
  defaultTheme,
  initTheme,
  isModeId,
  isThemeId,
  modeStorageKey,
  nextMode,
  nextTheme,
  subscribeTheme,
  themeDefinition,
  themes,
  themeSnapshot,
  themeStorageKey,
} from "./theme";

afterEach(() => {
  window.localStorage.clear();
  delete document.documentElement.dataset.theme;
  delete document.documentElement.dataset.mode;
  delete document.documentElement.dataset.material;
  document.documentElement.style.colorScheme = "";
});

describe("theme registry", () => {
  it("registers both kept v1 families", () => {
    expect(themes.map((theme) => theme.id)).toEqual(["ventisquero", "vina"]);
    expect(themeDefinition("ventisquero").label).toBe("Ventisquero");
    expect(themeDefinition("vina").label).toBe("Viña del Mar");
  });

  it("validates theme and mode ids", () => {
    expect(isThemeId("vina")).toBe(true);
    expect(isThemeId("vina-del-mar-dawn")).toBe(false);
    expect(isThemeId(null)).toBe(false);
    expect(isModeId("dark")).toBe(true);
    expect(isModeId("dim")).toBe(false);
  });

  it("cycles families and toggles modes", () => {
    expect(nextTheme("ventisquero")).toBe("vina");
    expect(nextTheme("vina")).toBe("ventisquero");
    expect(nextMode("light")).toBe("dark");
    expect(nextMode("dark")).toBe("light");
  });
});

describe("the shared theme store", () => {
  it("keeps the snapshot referentially stable between applies", () => {
    applyTheme("vina", "dark", { persist: false });
    expect(themeSnapshot()).toBe(themeSnapshot());
    expect(themeSnapshot()).toEqual({ theme: "vina", mode: "dark", material: "glass" });
  });

  it("notifies subscribers on every apply, until they unsubscribe", () => {
    let seen = 0;
    const unsubscribe = subscribeTheme(() => {
      seen += 1;
    });
    applyTheme("ventisquero", "light", { persist: false });
    applyTheme("vina", "light", { persist: false });
    expect(seen).toBe(2);
    expect(themeSnapshot()).toEqual({ theme: "vina", mode: "light", material: "glass" });
    unsubscribe();
    applyTheme("vina", "dark", { persist: false });
    expect(seen).toBe(2);
  });
});

describe("applyTheme", () => {
  it("sets both attributes, color-scheme, and persists both keys", () => {
    applyTheme("vina", "dark");
    expect(document.documentElement.dataset.theme).toBe("vina");
    expect(document.documentElement.dataset.mode).toBe("dark");
    expect(document.documentElement.style.colorScheme).toBe("dark");
    expect(window.localStorage.getItem(themeStorageKey)).toBe("vina");
    expect(window.localStorage.getItem(modeStorageKey)).toBe("dark");
  });

  it("changes one axis without disturbing the other", () => {
    applyTheme("ventisquero", "dark");
    applyTheme("vina", "dark");
    expect(document.documentElement.dataset.theme).toBe("vina");
    expect(document.documentElement.dataset.mode).toBe("dark");
    applyTheme("vina", "light");
    expect(document.documentElement.dataset.theme).toBe("vina");
    expect(document.documentElement.dataset.mode).toBe("light");
  });

  it("can apply without persisting", () => {
    applyTheme("ventisquero", "light", { persist: false });
    expect(document.documentElement.dataset.theme).toBe("ventisquero");
    expect(window.localStorage.getItem(themeStorageKey)).toBeNull();
    expect(window.localStorage.getItem(modeStorageKey)).toBeNull();
  });
});

describe("initTheme", () => {
  it("prefers valid stored values on both axes", () => {
    window.localStorage.setItem(themeStorageKey, "vina");
    window.localStorage.setItem(modeStorageKey, "light");
    expect(initTheme()).toEqual({ theme: "vina", mode: "light" });
    expect(document.documentElement.dataset.theme).toBe("vina");
    expect(document.documentElement.dataset.mode).toBe("light");
  });

  it("falls back per axis on garbage storage", () => {
    window.localStorage.setItem(themeStorageKey, "hotdog-stand");
    window.localStorage.setItem(modeStorageKey, "light");
    expect(initTheme()).toEqual({ theme: defaultTheme, mode: "light" });
  });

  it("resolves mode from the system when unstored (jsdom has none → dark-first)", () => {
    window.localStorage.setItem(themeStorageKey, "ventisquero");
    expect(initTheme().mode).toBe("dark");
  });

  it("does not persist fallback choices", () => {
    window.localStorage.clear();
    initTheme();
    expect(window.localStorage.getItem(themeStorageKey)).toBeNull();
    expect(window.localStorage.getItem(modeStorageKey)).toBeNull();
  });
});

describe("Costa material preference", () => {
  it("persists and restores material without changing the selected theme", () => {
    applyTheme("vina", "light");
    applyMaterial("opaque");
    expect(themeSnapshot()).toEqual({ theme: "vina", mode: "light", material: "opaque" });
    expect(window.localStorage.getItem(materialStorageKey)).toBe("opaque");
    delete document.documentElement.dataset.material;
    initTheme();
    expect(document.documentElement.dataset.material).toBe("opaque");
    applyTheme("ventisquero", "dark");
    expect(themeSnapshot().material).toBe("opaque");
  });

  it("notifies subscribers and does not persist an implicit mode choice", () => {
    initTheme();
    let seen = 0;
    const unsubscribe = subscribeTheme(() => {
      seen += 1;
    });
    applyMaterial("opaque");
    expect(seen).toBe(1);
    expect(window.localStorage.getItem(modeStorageKey)).toBeNull();
    expect(window.localStorage.getItem(themeStorageKey)).toBeNull();
    unsubscribe();
    applyMaterial("glass");
    expect(seen).toBe(1);
  });

  it("defaults to glass for missing or invalid stored material", () => {
    window.localStorage.setItem(materialStorageKey, "clear");
    initTheme();
    expect(themeSnapshot().material).toBe("glass");
    expect(document.documentElement.dataset.material).toBe("glass");
    expect(window.localStorage.getItem(materialStorageKey)).toBe("clear");
  });
});
