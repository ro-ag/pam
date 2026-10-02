import { useState } from "react";
import { cn } from "../../lib/cn";
import { headAndTail, safeSegments } from "../../lib/safeText";

/** Longest string shown whole; past it the head and tail stay visible around a marker. */
export const SAFE_TEXT_LIMIT = 600;

/** How much of the end of a long string always stays visible. */
const TAIL = 200;

/**
 * Agent-influenced text, shown faithfully: every hidden character (bidi override, zero-width,
 * control) appears as a highlighted `\u{…}` escape, long text wraps instead of truncating, and a
 * string past [`SAFE_TEXT_LIMIT`] shows its head **and tail** around a visible "N more
 * characters" marker with the full text one click away. Nothing is ever cut off silently.
 */
export function SafeText({ value, className }: { value: string; className?: string }) {
  const [expanded, setExpanded] = useState(false);
  const split = headAndTail(value, SAFE_TEXT_LIMIT, TAIL);
  const shown = split === null || expanded;
  return (
    <span className={cn("break-all", className)}>
      {shown ? (
        <Segments value={value} />
      ) : (
        <>
          <Segments value={split.head} />
          <button
            type="button"
            onClick={() => setExpanded(true)}
            className="mx-1 rounded-badge border border-line bg-inset px-1.5 py-0.5 font-data text-xs text-warning"
          >
            {split.omitted} more characters — show all
          </button>
          <Segments value={split.tail} />
        </>
      )}
    </span>
  );
}

function Segments({ value }: { value: string }) {
  return (
    <>
      {safeSegments(value).map((segment, index) =>
        segment.hidden ? (
          <span
            key={index}
            title="a hidden character, shown as its escape"
            className="rounded-badge bg-danger-soft px-0.5 text-danger"
          >
            {segment.text}
          </span>
        ) : (
          <span key={index}>{segment.text}</span>
        ),
      )}
    </>
  );
}
