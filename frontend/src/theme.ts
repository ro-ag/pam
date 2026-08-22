import { setTheme as setNativeTheme } from "@tauri-apps/api/app";

export const pamThemes = ["ventisquero", "vina"] as const;
export const pamThemeModes = ["light", "dark"] as const;

export type PamTheme = typeof pamThemes[number];
export type PamThemeMode = typeof pamThemeModes[number];

export const defaultPamTheme: PamTheme = "ventisquero";
export const defaultPamThemeMode: PamThemeMode = "light";
export const pamThemeStorageKey = "pam-theme";
export const pamThemeModeStorageKey = "pam-theme-mode";

let lastNativeThemeMode: PamThemeMode | null = null;

export interface ThemeStorage {
  getItem(key: string): string | null;
  setItem(key: string, value: string): void;
}

export function storedPamTheme(value: unknown): PamTheme {
  return pamThemes.includes(value as PamTheme) ? value as PamTheme : defaultPamTheme;
}

export function storedPamThemeMode(value: unknown): PamThemeMode {
  return pamThemeModes.includes(value as PamThemeMode) ? value as PamThemeMode : defaultPamThemeMode;
}

export function readPersistedPamTheme(storage: ThemeStorage | null | undefined): PamTheme {
  try {
    return storedPamTheme(storage?.getItem(pamThemeStorageKey) ?? null);
  } catch {
    return defaultPamTheme;
  }
}

export function readPersistedPamThemeMode(storage: ThemeStorage | null | undefined): PamThemeMode {
  try {
    return storedPamThemeMode(storage?.getItem(pamThemeModeStorageKey) ?? null);
  } catch {
    return defaultPamThemeMode;
  }
}

export function writePersistedPamTheme(
  storage: ThemeStorage | null | undefined,
  theme: PamTheme,
): void {
  try {
    storage?.setItem(pamThemeStorageKey, theme);
  } catch {
    // Theme persistence is optional; switching the live UI must still work.
  }
}

export function writePersistedPamThemeMode(
  storage: ThemeStorage | null | undefined,
  mode: PamThemeMode,
): void {
  try {
    storage?.setItem(pamThemeModeStorageKey, mode);
  } catch {
    // Theme persistence is optional; switching the live UI must still work.
  }
}

export function applyPamTheme(theme: PamTheme, mode: PamThemeMode): void {
  document.documentElement.dataset.theme = theme;
  document.documentElement.dataset.mode = mode;
  document.documentElement.style.colorScheme = mode;

  if (!("__TAURI_INTERNALS__" in window) || lastNativeThemeMode === mode) return;

  lastNativeThemeMode = mode;
  void Promise.resolve(setNativeTheme(mode)).catch(() => {
    if (lastNativeThemeMode === mode) lastNativeThemeMode = null;
  });
}
