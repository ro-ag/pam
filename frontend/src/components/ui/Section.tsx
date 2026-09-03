import type { ReactNode } from "react";

/**
 * Section — the grouping rhythm every settings-shaped screen keeps:
 * a mono eyebrow (what this is), a display title (its name), one serif
 * sentence in Pam's voice (why it exists), then the panels.
 *
 * Shared by Settings and Models so the two read as the same product
 * rather than two takes on the same idea.
 *
 * `id` is the section's stable anchor: Ask Pam deep-links to a panel by
 * hash (`/settings#retention`), so the slug has to live on the element
 * the browser scrolls to, not on a wrapper.
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
    <section id={id} aria-label={title} className="max-w-2xl space-y-4">
      <header className="space-y-1.5">
        <div className="flex items-center gap-2">
          <p className="font-data text-xs tracking-widest text-ink-faint uppercase">
            {eyebrow}
          </p>
          {eyebrowExtra}
        </div>
        <h2 className="font-display text-lg font-semibold text-ink">{title}</h2>
        <p className="font-voice text-base text-ink-muted italic">{blurb}</p>
      </header>
      {children}
    </section>
  );
}
