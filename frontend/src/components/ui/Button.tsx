import type { ButtonHTMLAttributes, Ref } from "react";
import { cn, cva, type VariantProps } from "../../lib/cn";

/**
 * Button — one accent per theme, so one primary per view. The rule for
 * picking a variant: `primary` is the one main action of a card or form,
 * `secondary` (outlined) is any other action with an effect, `ghost` is
 * inline low-emphasis furniture (toolbars, links-as-buttons), and
 * `danger` stays quiet (soft fill, firm ink) because PAM's destructive
 * actions confirm and explain rather than shout.
 *
 * Disabled states keep at least 3:1: a disabled primary drops its
 * gradient for a muted solid fill (ink-muted on inset, 5:1 in every
 * palette) and the others fade to 70%, which the measured palettes keep
 * above 3:1. Pair a disabled button with a `title` saying why.
 */
export const buttonVariants = cva(
  "inline-flex shrink-0 select-none items-center justify-center gap-2 rounded-control font-sans font-medium transition-colors disabled:cursor-not-allowed disabled:opacity-70",
  {
    variants: {
      variant: {
        primary:
          "action-control border border-control-line bg-accent-strong text-on-accent enabled:hover:bg-accent-hover enabled:active:bg-accent-pressed disabled:border-line-strong disabled:bg-inset disabled:text-ink-muted disabled:opacity-100",
        secondary:
          "field-control border border-control-line bg-surface-raised text-ink enabled:hover:bg-accent-soft",
        ghost:
          "text-ink-muted enabled:hover:bg-accent-soft enabled:hover:text-ink enabled:active:bg-accent-soft",
        danger:
          "border border-danger/40 bg-danger-soft text-danger enabled:hover:border-danger enabled:active:border-danger",
      },
      size: {
        sm: "h-8 px-2.5 text-xs",
        md: "h-8 px-3 text-sm",
      },
    },
    defaultVariants: {
      variant: "primary",
      size: "md",
    },
  },
);

type ButtonProps = ButtonHTMLAttributes<HTMLButtonElement> &
  VariantProps<typeof buttonVariants> & { ref?: Ref<HTMLButtonElement> };

export function Button({ variant, size, className, type, ref, ...props }: ButtonProps) {
  return (
    <button
      ref={ref}
      type={type ?? "button"}
      className={cn(buttonVariants({ variant, size }), className)}
      {...props}
    />
  );
}
