import type { HTMLAttributes } from "react";
import { cn, cva, type VariantProps } from "../../lib/cn";

/**
 * Badge — status chips for truth reporting (solved / changed / verified /
 * unresolved / blocked) and daemon states. Badges carry data, so they speak
 * in the data voice (Plex Mono), never in Pam's serif.
 */
export const badgeVariants = cva(
  "inline-flex items-center gap-1.5 rounded-badge px-2 py-0.5 font-data text-xs",
  {
    variants: {
      tone: {
        neutral: "border border-line bg-surface-raised text-ink-muted",
        accent: "bg-accent-soft text-accent",
        success: "bg-success-soft text-success",
        warning: "warm-badge bg-warning-soft text-warning",
        danger: "bg-danger-soft text-danger",
      },
    },
    defaultVariants: {
      tone: "neutral",
    },
  },
);

export type BadgeProps = HTMLAttributes<HTMLSpanElement> & VariantProps<typeof badgeVariants>;

export function Badge({ tone, className, ...props }: BadgeProps) {
  return <span className={cn(badgeVariants({ tone }), className)} {...props} />;
}
