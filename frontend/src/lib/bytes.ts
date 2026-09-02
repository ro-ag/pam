/**
 * Byte sizes, spoken the way the model layer speaks them.
 *
 * Decimal units on purpose: the engine floor is written as 18 GB
 * (`MODEL_FLOOR_BYTES = 18_000_000_000`) and the catalog quotes 18.56 GB
 * for the smallest preset. Binary units would render the same file as
 * "17.3 GiB" and put the number on the wrong side of the floor the
 * sentence next to it names — so the screen and the rule agree here, and
 * PAM never argues with itself about a size.
 */

/** Decimal ladder; anything past the top just keeps counting in TB. */
const UNITS = ["B", "KB", "MB", "GB", "TB"] as const;

/**
 * Formats `bytes` in decimal units: `0 B`, `639 MB`, `18.6 GB`.
 *
 * One decimal from GB up (where the difference between two quants is
 * worth seeing), none below (nobody needs 638.9 MB). Negative or
 * non-finite input reads as `—`, never as a lie.
 */
export function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes < 0) return "—";
  let value = bytes;
  let unit = 0;
  while (value >= 1000 && unit < UNITS.length - 1) {
    value /= 1000;
    unit += 1;
  }
  const decimals = unit >= 3 ? 1 : 0;
  return `${value.toFixed(decimals)} ${UNITS[unit]}`;
}

/**
 * Percentage of `total` that `done` covers, clamped to 0..100 and
 * rounded to a whole number — progress bars do not need decimals, and a
 * server that reports more bytes than it promised must not render 103%.
 */
export function percentOf(done: number, total: number | null | undefined): number | null {
  if (typeof total !== "number" || !Number.isFinite(total) || total <= 0) return null;
  return Math.min(100, Math.max(0, Math.round((done / total) * 100)));
}
