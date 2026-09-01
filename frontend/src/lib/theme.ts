import { setTheme as setNativeTheme } from "@tauri-apps/api/app";

/**
 * Theme switching — token redefinition only.
 *
 * A PAM theme is one CSS block in `src/styles/themes.css` selected by the
 * `data-theme` attribute on <html>. Applying a theme swaps CSS variables;
 * no component re-renders, no component ever knows which theme is active.
 */

export interface ThemeDefinition {
  id: ThemeId;
  label: string;
  /** Which native color scheme the theme belongs to. */
  scheme: "dark" | "light";
}

export const themeIds = ["ventisquero-mist", "vina-del-mar-dawn"] as const;
export type ThemeId = (typeof themeIds)[number];

export const themes: readonly ThemeDefinition[] = [
  { id: "ventisquero-mist", label: "Ventisquero Mist", scheme: "dark" },
  { id: "vina-del-mar-dawn", label: "Viña del Mar Dawn", scheme: "light" },
];

export const defaultTheme: ThemeId = "ventisquero-mist";
export const themeStorageKey = "pam-theme";

export function isThemeId(value: unknown): value is ThemeId {
  return themeIds.includes(value as ThemeId);
}

export function themeDefinition(id: ThemeId): ThemeDefinition {
  const found = themes.find((theme) => theme.id === id);
  if (!found) throw new Error(`unregistered theme: ${id}`);
  return found;
}

/** The next theme in registry order — powers the cycle toggle. */
export function nextTheme(current: ThemeId): ThemeId {
  const index = themeIds.indexOf(current);
  return themeIds[(index + 1) % themeIds.length];
}

function persistTheme(id: ThemeId): void {
  try {
    window.localStorage.setItem(themeStorageKey, id);
  } catch {
    // Persistence is optional; switching the live UI must still work.
  }
}

function syncNativeWindow(scheme: "dark" | "light"): void {
  if (!("__TAURI_INTERNALS__" in window)) return;
  void Promise.resolve(setNativeTheme(scheme)).catch(() => {
    // Titlebar tint is cosmetic; never let it break theme switching.
  });
}

/** Apply a theme now and remember it for the next launch. */
export function applyTheme(id: ThemeId, options?: { persist?: boolean }): void {
  document.documentElement.dataset.theme = id;
  const { scheme } = themeDefinition(id);
  document.documentElement.style.colorScheme = scheme;
  if (options?.persist !== false) persistTheme(id);
  syncNativeWindow(scheme);
}

function storedTheme(): ThemeId | null {
  try {
    const value = window.localStorage.getItem(themeStorageKey);
    return isThemeId(value) ? value : null;
  } catch {
    return null;
  }
}

function systemTheme(): ThemeId {
  try {
    if (window.matchMedia("(prefers-color-scheme: light)").matches) {
      return "vina-del-mar-dawn";
    }
  } catch {
    // jsdom and stripped-down webviews may lack matchMedia; fall through.
  }
  return defaultTheme;
}

/**
 * Resolve and apply the boot theme: the user's stored choice, else the OS
 * scheme (dark → Ventisquero Mist, light → Viña del Mar Dawn). Called from
 * main.tsx before the first render so no frame paints unthemed. Does not
 * persist — only an explicit user choice is remembered.
 */
export function initTheme(): ThemeId {
  const id = storedTheme() ?? systemTheme();
  applyTheme(id, { persist: false });
  return id;
}
