import { afterEach, describe, expect, it, vi } from "vitest";
import {
  applyTheme,
  applyMaterial,
  applyBackgroundMotion,
  backgroundMotionStorageKey,
  applyBackgroundSpeed,
  backgroundSpeedStorageKey,
  isBackgroundSpeed,
  applyBackgroundIntensity,
  backgroundIntensityStorageKey,
  isBackgroundMotionId,
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
  delete document.documentElement.dataset.backgroundMotion;
  delete document.documentElement.dataset.backgroundSpeed;
  delete document.documentElement.dataset.backgroundIntensity;
  document.documentElement.style.removeProperty("--background-intensity");
  document.documentElement.style.removeProperty("--background-drift-duration");
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
    expect(themeSnapshot()).toEqual({
      theme: "vina",
      mode: "dark",
      material: "glass",
      backgroundMotion: "slow",
      backgroundSpeed: 1,
      backgroundIntensity: 70,
    });
  });

  it("notifies subscribers on every apply, until they unsubscribe", () => {
    let seen = 0;
    const unsubscribe = subscribeTheme(() => {
      seen += 1;
    });
    applyTheme("ventisquero", "light", { persist: false });
    applyTheme("vina", "light", { persist: false });
    expect(seen).toBe(2);
    expect(themeSnapshot()).toEqual({
      theme: "vina",
      mode: "light",
      material: "glass",
      backgroundMotion: "slow",
      backgroundSpeed: 1,
      backgroundIntensity: 70,
    });
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
    expect(themeSnapshot()).toEqual({
      theme: "vina",
      mode: "light",
      material: "opaque",
      backgroundMotion: "slow",
      backgroundSpeed: 1,
      backgroundIntensity: 70,
    });
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

describe("background motion preference", () => {
  it("defaults intensity to70, persists zero and preserves intensity across other choices", () => {
    initTheme();
    expect(themeSnapshot().backgroundIntensity).toBe(70);
    expect(window.localStorage.getItem(backgroundIntensityStorageKey)).toBeNull();
    applyBackgroundIntensity(0);
    initTheme();
    expect(themeSnapshot().backgroundIntensity).toBe(0);
    expect(document.documentElement.style.getPropertyValue("--background-intensity")).toBe("0");
    applyBackgroundIntensity(92);
    applyBackgroundMotion("off");
    applyTheme("vina", "dark");
    applyMaterial("opaque");
    applyBackgroundSpeed(12);
    initTheme();
    expect(themeSnapshot().backgroundIntensity).toBe(92);
    expect(document.documentElement.style.getPropertyValue("--background-intensity")).toBe(
      "0.92",
    );
  });

  it("rejects invalid intensity and restores safe defaults from invalid storage", () => {
    initTheme();
    for (const value of [-1, 101, NaN, Infinity]) {
      applyBackgroundIntensity(value);
      expect(themeSnapshot().backgroundIntensity).toBe(70);
    }
    for (const stored of ["", "garbage", "101", "-1"]) {
      window.localStorage.setItem(backgroundIntensityStorageKey, stored);
      initTheme();
      expect(themeSnapshot().backgroundIntensity).toBe(70);
    }
  });
  it.each([5_000, 15_000])("preserves loop phase when changing speed at %sms", (time) => {
    initTheme();
    const drift = {
      animationName: "background-drift",
      currentTime: time,
      effect: { getComputedTiming: () => ({ duration: 10_000 }) },
    };
    const original = Object.getOwnPropertyDescriptor(document, "getAnimations");
    Object.defineProperty(document, "getAnimations", {
      configurable: true,
      value: () => [drift],
    });
    try {
      applyBackgroundSpeed(6);
      expect(drift.currentTime).toBe(time * 4);
      expect(
        document.documentElement.style.getPropertyValue("--background-drift-duration"),
      ).toBe("40s");
    } finally {
      if (original) Object.defineProperty(document, "getAnimations", original);
      else Reflect.deleteProperty(document, "getAnimations");
    }
  });

  it("persists arbitrary slider speed and remembers it while disabled", () => {
    initTheme();
    applyBackgroundSpeed(6.3);
    expect(window.localStorage.getItem(backgroundSpeedStorageKey)).toBe("6.3");
    applyBackgroundMotion("off");
    initTheme();
    expect(themeSnapshot().backgroundMotion).toBe("off");
    expect(themeSnapshot().backgroundSpeed).toBe(6.3);
    applyBackgroundMotion("slow");
    applyTheme("vina", "light");
    applyMaterial("opaque");
    expect(themeSnapshot().backgroundSpeed).toBe(6.3);
    expect(document.documentElement.style.getPropertyValue("--background-drift-duration")).toBe(
      `${240 / 6.3}s`,
    );
  });

  it.each([
    ["slow", 1],
    ["slower", 0.5],
    ["off", 1],
  ])("preserves old %s preset timing", (preset, speed) => {
    window.localStorage.setItem(backgroundMotionStorageKey, String(preset));
    initTheme();
    expect(themeSnapshot().backgroundSpeed).toBe(speed);
    expect(window.localStorage.getItem(backgroundSpeedStorageKey)).toBeNull();
  });

  it("validates speed boundaries and ignores invalid updates", () => {
    initTheme();
    for (const speed of [0, -1, 0.4, 12.1, Infinity, NaN]) {
      expect(isBackgroundSpeed(speed)).toBe(false);
      applyBackgroundSpeed(speed);
      expect(themeSnapshot().backgroundSpeed).toBe(1);
    }
    applyBackgroundSpeed(0.5);
    expect(document.documentElement.style.getPropertyValue("--background-drift-duration")).toBe(
      "480s",
    );
    applyBackgroundSpeed(12);
    expect(document.documentElement.style.getPropertyValue("--background-drift-duration")).toBe(
      "20s",
    );
    window.localStorage.setItem(backgroundSpeedStorageKey, "garbage");
    initTheme();
    expect(themeSnapshot().backgroundSpeed).toBe(1);
  });

  it("defaults to slow without persisting a fallback", () => {
    initTheme();
    expect(themeSnapshot().backgroundMotion).toBe("slow");
    expect(document.documentElement.dataset.backgroundMotion).toBe("slow");
    expect(window.localStorage.getItem(backgroundMotionStorageKey)).toBeNull();
    window.localStorage.setItem(backgroundMotionStorageKey, "fast");
    initTheme();
    expect(themeSnapshot().backgroundMotion).toBe("slow");
    expect(isBackgroundMotionId("fast")).toBe(false);
  });

  it.each(["off", "slow", "slower"] as const)("persists and restores %s", (speed) => {
    initTheme();
    applyBackgroundMotion(speed);
    expect(window.localStorage.getItem(backgroundMotionStorageKey)).toBe(speed);
    delete document.documentElement.dataset.backgroundMotion;
    initTheme();
    expect(themeSnapshot().backgroundMotion).toBe(speed);
    expect(document.documentElement.dataset.backgroundMotion).toBe(speed);
    expect(themeSnapshot()).toBe(themeSnapshot());
  });

  it("retains speed across palette and material changes and notifies subscribers", () => {
    initTheme();
    const listener = vi.fn();
    const unsubscribe = subscribeTheme(listener);
    applyBackgroundMotion("slower");
    expect(listener).toHaveBeenCalledTimes(1);
    applyMaterial("opaque");
    applyTheme("vina", "dark");
    expect(themeSnapshot().backgroundMotion).toBe("slower");
    applyMaterial("glass");
    expect(themeSnapshot().backgroundMotion).toBe("slower");
    unsubscribe();
    listener.mockClear();
    applyBackgroundMotion("off");
    expect(listener).not.toHaveBeenCalled();
  });

  it("still switches for this session when persistence is unavailable", () => {
    initTheme();
    vi.spyOn(window.localStorage, "setItem").mockImplementation(() => {
      throw new Error("storage denied");
    });
    expect(() => applyBackgroundMotion("off")).not.toThrow();
    expect(themeSnapshot().backgroundMotion).toBe("off");
    expect(document.documentElement.dataset.backgroundMotion).toBe("off");
  });
});
