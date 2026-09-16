import type { ReactNode } from "react";

/**
 * Compact Costa section heading; stable anchors preserve settings deep
 * links. The eyebrow is the one place a small label sits above a title:
 * it says what kind of thing the section governs ("Local preference",
 * "Daemon policy"), in the data voice, sentence case.
 */
export function Section({
  id,
  eyebrow,
  eyebrowExtra,
  title,
  blurb,
  children,
}: {
  id?: string;
  eyebrow: string;
  eyebrowExtra?: ReactNode;
  title: string;
  blurb: string;
  children: ReactNode;
}) {
  return (
    <section id={id} aria-label={title} className="min-w-0 scroll-mt-28 space-y-3">
      <header className="space-y-1">
        <p className="font-data text-xs text-ink-faint">{eyebrow}</p>
        <div className="flex items-center gap-2">
          <h2 className="font-sans text-lg font-semibold text-ink">{title}</h2>
          {eyebrowExtra}
        </div>
        <p className="font-sans text-sm text-ink-muted">{blurb}</p>
      </header>
      {children}
    </section>
  );
}
