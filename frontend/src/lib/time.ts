/**
 * Tiny time helpers for the activity tide — no date library, the daemon
 * hands us unix seconds and the UI only ever needs "how long ago" plus a
 * precise stamp for detail views.
 */

/** Steps, largest first: [threshold in seconds, divisor, unit suffix]. */
const STEPS: ReadonlyArray<readonly [number, number, string]> = [
  [604_800, 604_800, "w"],
  [86_400, 86_400, "d"],
  [3_600, 3_600, "h"],
  [60, 60, "m"],
];

/**
 * Compact relative age: "now" under 10s, then "42s ago", "3m ago",
 * "5h ago", "2d ago", "3w ago". Clock skew (a future timestamp) reads
 * as "now" rather than a negative age.
 */
export function relativeTime(unixSeconds: number, nowMs: number = Date.now()): string {
  const elapsed = Math.floor(nowMs / 1000) - unixSeconds;
  if (elapsed < 10) return "now";
  for (const [threshold, divisor, unit] of STEPS) {
    if (elapsed >= threshold) return `${Math.floor(elapsed / divisor)}${unit} ago`;
  }
  return `${elapsed}s ago`;
}

/** Full precise stamp for detail views: "2026-09-01 14:03:27" (local). */
export function exactTime(unixSeconds: number): string {
  const date = new Date(unixSeconds * 1000);
  const pad = (n: number) => String(n).padStart(2, "0");
  return (
    `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())} ` +
    `${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}`
  );
}
