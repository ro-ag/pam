import type { ReactNode } from "react";

/** Compact Costa section heading; stable anchors preserve settings deep links. */
export function Section({
  id,
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
