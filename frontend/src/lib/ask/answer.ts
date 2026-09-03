/**
 * What an answer is made of, and the handful of formatters its sentences
 * share.
 *
 * An `Answer` is a template sentence in Pam's voice, the facts that
 * sentence was built from, and where to go to see or change the thing.
 * Every number and name in the sentence also appears in `facts`, which is
 * what lets the rephrase guard check that a model rewrite kept them.
 */

import { formatDuration, relativeTime } from "../time";

/** The nine intents plus the honest "I don't know that" answer. */
export type IntentId =
  | "approvals_waiting"
  | "why_refused"
  | "what_ran"
  | "model_status"
  | "where_change"
  | "daemon_status"
  | "login_start"
  | "flows"
  | "tokens_saved"
  | "fallback";

/** Screens an answer may point at; the router never navigates itself. */
export type AskRoute = "/" | "/activity" | "/approvals" | "/flows" | "/models" | "/settings";

/** Settings panels, by the anchor slug `Section` renders. */
export type SettingsTopic =
  "retention" | "daemon" | "security" | "models" | "connectors" | "flows" | "appearance";

/** What a question carried besides its intent. */
export interface Args {
  ticket?: string;
  capability?: string;
  repo?: string;
  flow?: string;
  topic?: SettingsTopic;
}

export interface AskLink {
  label: string;
  to: AskRoute;
  search?: Record<string, string>;
  hash?: string;
}

export interface Answer {
  intent: IntentId;
  sentence: string;
  facts: Array<[string, string]>;
  links: AskLink[];
  rephrased?: { model: string };
}

/** What the caller knows that the question does not say. */
export interface AskContext {
  /** The route the question was asked from, e.g. `/activity`. */
  screen: string;
  /** Milliseconds, so tests can pin the clock. */
  now: number;
}

export interface AskOptions {
  /** The `pam.ask.rephrase` preference; off by default. */
  rephrase: boolean;
  /** Client-side ceiling on the rephrase call; 8 s when unset. */
  timeoutMs?: number;
}

/** `1 request`, `2 requests` — the count and its noun, agreeing. */
export function plural(n: number, one: string, many = `${one}s`): string {
  return `${n} ${n === 1 ? one : many}`;
}

/** The last segment of a repo path: `/Users/me/pam` → `pam`. */
export function repoTail(repo: string): string {
  const segments = repo.split("/").filter(Boolean);
  return segments[segments.length - 1] ?? repo;
}

/** `1m ago`, `2h ago` — the same age the tide shows. */
export function ago(unixSeconds: number, nowMs: number): string {
  return relativeTime(unixSeconds, nowMs);
}

/**
 * Gigabytes with one decimal — weights and host RAM sit side by side in
 * one sentence ("0.6 GB of 64.0 GB RAM"), so both wear the same unit
 * rather than `formatBytes`'s per-value ladder, which would print the
 * weight in MB and lose the comparison.
 */
export function gb(bytes: number): string {
  return `${(bytes / 1e9).toFixed(1)} GB`;
}

/** Kilobytes, whole: the odometer's before/after pair. */
export function kb(bytes: number): string {
  return `${Math.round(bytes / 1024)} KB`;
}

/** `1h 02m` — daemon uptime, as the status card writes it. */
export function duration(seconds: number): string {
  return formatDuration(seconds);
}

/** Midnight of `nowMs`'s local day, in ms — the start of "today". */
export function localMidnight(nowMs: number): number {
  const date = new Date(nowMs);
  date.setHours(0, 0, 0, 0);
  return date.getTime();
}

/**
 * The human half of a rejected read. Bridge failures are
 * `{ cause, detail, recovery }`; anything else is stringified rather than
 * swallowed, because an unnamed failure is worse than an ugly one.
 */
export function failureDetail(error: unknown): string {
  if (typeof error === "object" && error !== null && "detail" in error) {
    const detail = (error as { detail: unknown }).detail;
    if (typeof detail === "string" && detail.length > 0) return detail;
  }
  return String(error);
}

/**
 * The answer for a read that did not come back. Pam names what she could
 * not read instead of inventing a number, and `ask` never throws.
 */
export function failedRead(intent: IntentId, what: string, error: unknown): Answer {
  return {
    intent,
    sentence: `I could not read ${what}: ${failureDetail(error)}.`,
    facts: [],
    links: [],
  };
}
