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

export type MaterialId = "glass" | "opaque";
export const materialStorageKey = "pam-material";

export const backgroundMotionIds = ["off", "slow", "slower"] as const;
export type BackgroundMotionId = (typeof backgroundMotionIds)[number];
export const backgroundMotionStorageKey = "pam-background-motion";
export const backgroundSpeedStorageKey = "pam-background-speed";

export function isBackgroundSpeed(value: unknown): value is number {
  return typeof value === "number" && Number.isFinite(value) && value >= 0.5 && value <= 12;
}

export function isBackgroundMotionId(value: unknown): value is BackgroundMotionId {
  return backgroundMotionIds.includes(value as BackgroundMotionId);
}

export function isMaterialId(value: unknown): value is MaterialId {
  return value === "glass" || value === "opaque";
}

export interface ThemeDefinition {
  id: ThemeId;
  label: string;
  appearances: Record<ModeId, string>;
}

export const themes: readonly ThemeDefinition[] = [
  { id: "ventisquero", label: "Ventisquero", appearances: { dark: "Bedrock", light: "Mist" } },
  { id: "vina", label: "Viña del Mar", appearances: { dark: "Night", light: "Dawn" } },
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
  material: MaterialId;
  backgroundMotion: BackgroundMotionId;
  backgroundSpeed: number;
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
    const material = document.documentElement.dataset.material;
    snapshot = {
      theme: isThemeId(theme) ? theme : defaultTheme,
      mode: isModeId(mode) ? mode : systemMode(),
      material: isMaterialId(material) ? material : "glass",
      backgroundMotion: readBackgroundMotion(),
      backgroundSpeed: readBackgroundSpeed(),
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
  const material = document.documentElement.dataset.material;
  snapshot = {
    theme,
    mode,
    material: isMaterialId(material) ? material : "glass",
    backgroundMotion: readBackgroundMotion(),
    backgroundSpeed: readBackgroundSpeed(),
  };
  for (const listener of listeners) listener();
}

/** Costa material preference is independent of the palette and native tint. */
export function applyMaterial(material: MaterialId, options?: { persist?: boolean }): void {
  document.documentElement.dataset.material = material;
  if (options?.persist !== false) persist(materialStorageKey, material);
  snapshot = { ...themeSnapshot(), material };
  for (const listener of listeners) listener();
}

function readBackgroundMotion(): BackgroundMotionId {
  const value = document.documentElement.dataset.backgroundMotion;
  return isBackgroundMotionId(value) ? value : "slow";
}

function readBackgroundSpeed(): number {
  const speed = Number(document.documentElement.dataset.backgroundSpeed);
  return isBackgroundSpeed(speed) ? speed : readBackgroundMotion() === "slower" ? 0.5 : 1;
}

function stampBackgroundSpeed(speed: number): void {
  // Preserve the current phase while dragging, rather than jumping to the
  // position implied by a new CSS duration. No animation exists while off.
  const drift = document
    .getAnimations?.()
    .find(
      (animation) =>
        "animationName" in animation && animation.animationName === "background-drift",
    );
  const duration = drift?.effect?.getComputedTiming().duration;
  const phase =
    drift &&
    typeof drift.currentTime === "number" &&
    typeof duration === "number" &&
    duration > 0
      ? drift.currentTime / duration
      : null;
  document.documentElement.dataset.backgroundSpeed = String(speed);
  document.documentElement.style.setProperty("--background-drift-duration", `${120 / speed}s`);
  if (drift && phase !== null) drift.currentTime = phase * (120_000 / speed);
}

/** Multiples of the original four-minute cycle; keep the chosen speed while off. */
export function applyBackgroundSpeed(speed: number): void {
  if (!isBackgroundSpeed(speed)) return;
  stampBackgroundSpeed(speed);
  persist(backgroundSpeedStorageKey, String(speed));
  snapshot = { ...themeSnapshot(), backgroundSpeed: speed };
  for (const listener of listeners) listener();
}

/** Store the chosen speed; CSS honors accessibility overrides independently. */
export function applyBackgroundMotion(backgroundMotion: BackgroundMotionId): void {
  document.documentElement.dataset.backgroundMotion = backgroundMotion;
  persist(backgroundMotionStorageKey, backgroundMotion);
  snapshot = { ...themeSnapshot(), backgroundMotion };
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
  document.documentElement.dataset.material =
    stored(materialStorageKey, isMaterialId) ?? "glass";
  document.documentElement.dataset.backgroundMotion =
    stored(backgroundMotionStorageKey, isBackgroundMotionId) ?? "slow";
  const savedSpeed = Number(
    stored(backgroundSpeedStorageKey, (value): value is string => typeof value === "string"),
  );
  stampBackgroundSpeed(
    isBackgroundSpeed(savedSpeed) ? savedSpeed : readBackgroundMotion() === "slower" ? 0.5 : 1,
  );
  applyTheme(theme, mode, { persist: false });
  return { theme, mode };
}
