import { useSyncExternalStore } from "react";

/**
 * Ask Pam's GUI-only preferences.
 *
 * The rephrase switch is a local taste, not daemon state: whether Pam may
 * hand her finished sentence to the light model for a softer wording. It
 * lives in `localStorage` beside the theme, and follows the same shape —
 * one writer, a listener set, `useSyncExternalStore` for whichever
 * components render the control. Off by default: an answer Pam wrote
 * herself is the one she can defend.
 *
 * Every storage access is guarded. A stripped-down webview without
 * `localStorage` must still render the switch and honour a flip for the
 * session's lifetime rather than throwing on mount.
 */

export const rephraseStorageKey = "pam.ask.rephrase";

const listeners = new Set<() => void>();

/** Whether Pam may rephrase — false unless the human said otherwise. */
export function readRephrase(): boolean {
  try {
    return window.localStorage.getItem(rephraseStorageKey) === "on";
  } catch {
    return false;
  }
}

/** Remember the choice and wake every subscribed control. */
export function writeRephrase(on: boolean): void {
  try {
    window.localStorage.setItem(rephraseStorageKey, on ? "on" : "off");
  } catch {
    // Persistence is optional; the live UI must still switch.
  }
  for (const listener of listeners) listener();
}

/** Subscribe to rephrase changes; returns the unsubscribe function. */
export function subscribeRephrase(listener: () => void): () => void {
  listeners.add(listener);
  return () => {
    listeners.delete(listener);
  };
}

/** `useState`-shaped view of the preference, live across every control. */
export function useRephrasePref(): [boolean, (on: boolean) => void] {
  const on = useSyncExternalStore(subscribeRephrase, readRephrase, () => false);
  return [on, writeRephrase];
}
