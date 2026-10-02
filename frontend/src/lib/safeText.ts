/**
 * Text an agent influenced, made safe to read.
 *
 * The approval card shows strings the agent chose: a repository path, a flow or step name, the
 * arguments of a command. A right-to-left override or a zero-width character makes such a string
 * *look* like something else (`gpj.exe` rendered as `exe.jpg`; two tokens that look like one), so a
 * human approving what they read could be approving something different. Every character that
 * renders as nothing, or that changes how its neighbours render, is shown as a visible escape
 * instead — `\u{202E}` — and the rest of the text is left exactly as it is.
 */

/** Controls (including tab and newline), format characters (bidi marks and overrides, zero-width
 * space/joiners, soft hyphen, word joiner, BOM, language tags) and the line/paragraph separators. */
const INVISIBLE = /[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/u;

/** One stretch of a string: ordinary text, or a single hidden character shown as its escape. */
export interface SafeSegment {
  /** What to render: the text itself, or the visible escape. */
  text: string;
  /** True when `text` stands in for a hidden character. */
  hidden: boolean;
}

/** `\u{202E}` for one code point: always braces, uppercase hex, at least four digits. */
export function escapeCodePoint(char: string): string {
  const code = char.codePointAt(0) ?? 0;
  return `\\u{${code.toString(16).toUpperCase().padStart(4, "0")}}`;
}

/** Splits `value` into plain runs and visible escapes, in order, losing nothing. */
export function safeSegments(value: string): SafeSegment[] {
  const segments: SafeSegment[] = [];
  let run = "";
  for (const char of value) {
    if (INVISIBLE.test(char)) {
      if (run) segments.push({ text: run, hidden: false });
      run = "";
      segments.push({ text: escapeCodePoint(char), hidden: true });
    } else {
      run += char;
    }
  }
  if (run) segments.push({ text: run, hidden: false });
  return segments;
}

/** `value` as one plain string with every hidden character spelled out (tooltips, labels). */
export function escapeInvisible(value: string): string {
  return safeSegments(value)
    .map((segment) => segment.text)
    .join("");
}

/** True when `value` carries at least one character that [`safeSegments`] would escape. */
export function hasHiddenCharacters(value: string): boolean {
  return INVISIBLE.test(value);
}

/**
 * Splits a long string for display without ever hiding its tail: the head and the tail stay
 * visible around a marker saying how many characters sit between them.
 */
export function headAndTail(
  value: string,
  limit: number,
  tail: number,
): { head: string; omitted: number; tail: string } | null {
  const chars = Array.from(value);
  if (chars.length <= limit) return null;
  const head = chars.slice(0, limit - tail).join("");
  const end = chars.slice(chars.length - tail).join("");
  return { head, omitted: chars.length - limit, tail: end };
}
