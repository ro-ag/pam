import { setTheme as setNativeTheme } from "@tauri-apps/api/app";

/**
 * Theme switching — token redefinition only, on two axes (v1's model):
 *
 *   data-theme  the family   ventisquero | vina
 *   data-mode   the variant  light | dark
 *
 * Four palettes total, each one CSS block in `src/styles/themes.css`
 * selected by the two attributes on <html>. Applying a theme or mode swaps
 * CSS variables; no component re-renders, no component ever knows which
 * combination is active.
 */

export const themeIds = ["ventisquero", "vina"] as const;
export type ThemeId = (typeof themeIds)[number];

export const modeIds = ["light", "dark"] as const;
export type ModeId = (typeof modeIds)[number];

export interface ThemeDefinition {
  id: ThemeId;
  label: string;
}

export const themes: readonly ThemeDefinition[] = [
  { id: "ventisquero", label: "Ventisquero" },
  { id: "vina", label: "Viña del Mar" },
];

export const defaultTheme: ThemeId = "ventisquero";
export const themeStorageKey = "pam-theme";
export const modeStorageKey = "pam-theme-mode";

export function isThemeId(value: unknown): value is ThemeId {
  return themeIds.includes(value as ThemeId);
}

export function isModeId(value: unknown): value is ModeId {
  return modeIds.includes(value as ModeId);
}

export function themeDefinition(id: ThemeId): ThemeDefinition {
  const found = themes.find((theme) => theme.id === id);
  if (!found) throw new Error(`unregistered theme: ${id}`);
  return found;
}

/** The next family in registry order — powers the cycle control. */
export function nextTheme(current: ThemeId): ThemeId {
  const index = themeIds.indexOf(current);
  return themeIds[(index + 1) % themeIds.length];
}

/** The other variant — powers the sun/moon toggle. */
export function nextMode(current: ModeId): ModeId {
  return current === "light" ? "dark" : "light";
}

// --- shared live state -----------------------------------------------------
//
// Two views change themes (the chrome strip and Settings > Appearance), so
// the applied combination is a tiny external store: `applyTheme` is the one
// writer, `themeSnapshot`/`subscribeTheme` feed `useSyncExternalStore` in
// whichever components render controls. No context, no prop drilling — the
// DOM attributes stay the source of truth and this cache only exists so
// React gets a referentially stable snapshot.

/** The applied combination, as one immutable snapshot object. */
export interface ThemeState {
  theme: ThemeId;
  mode: ModeId;
}

let snapshot: ThemeState | null = null;
const listeners = new Set<() => void>();

/** Subscribe to theme/mode changes; returns the unsubscribe function. */
export function subscribeTheme(listener: () => void): () => void {
  listeners.add(listener);
  return () => {
    listeners.delete(listener);
  };
}

/**
 * The currently applied combination — stable between `applyTheme` calls
 * (required by `useSyncExternalStore`). First read falls back to the DOM
 * attributes `initTheme()` stamped, then to the defaults.
 */
export function themeSnapshot(): ThemeState {
  if (snapshot === null) {
    const theme = document.documentElement.dataset.theme;
    const mode = document.documentElement.dataset.mode;
    snapshot = {
      theme: isThemeId(theme) ? theme : defaultTheme,
      mode: isModeId(mode) ? mode : systemMode(),
    };
  }
  return snapshot;
}

function persist(key: string, value: string): void {
  try {
    window.localStorage.setItem(key, value);
  } catch {
    // Persistence is optional; switching the live UI must still work.
  }
}

function syncNativeWindow(mode: ModeId): void {
  if (!("__TAURI_INTERNALS__" in window)) return;
  void Promise.resolve(setNativeTheme(mode)).catch(() => {
    // Titlebar tint is cosmetic; never let it break theme switching.
  });
}

/** Apply a theme + mode now and remember both for the next launch. */
export function applyTheme(
  theme: ThemeId,
  mode: ModeId,
  options?: { persist?: boolean },
): void {
  document.documentElement.dataset.theme = theme;
  document.documentElement.dataset.mode = mode;
  document.documentElement.style.colorScheme = mode;
  if (options?.persist !== false) {
    persist(themeStorageKey, theme);
    persist(modeStorageKey, mode);
  }
  syncNativeWindow(mode);
  snapshot = { theme, mode };
  for (const listener of listeners) listener();
}

function stored<T>(key: string, guard: (value: unknown) => value is T): T | null {
  try {
    const value = window.localStorage.getItem(key);
    return guard(value) ? value : null;
  } catch {
    return null;
  }
}

function systemMode(): ModeId {
  try {
    if (window.matchMedia("(prefers-color-scheme: light)").matches) {
      return "light";
    }
  } catch {
    // jsdom and stripped-down webviews may lack matchMedia; fall through.
  }
  return "dark"; // dark-first, per the design vision
}

/**
 * Resolve and apply the boot combination: the stored family (else
 * Ventisquero) in the stored mode (else the system's preferred scheme).
 * Called from main.tsx before the first render so no frame paints
 * unthemed. Does not persist — only an explicit user choice is remembered.
 */
export function initTheme(): { theme: ThemeId; mode: ModeId } {
  const theme = stored(themeStorageKey, isThemeId) ?? defaultTheme;
  const mode = stored(modeStorageKey, isModeId) ?? systemMode();
  applyTheme(theme, mode, { persist: false });
  return { theme, mode };
}
