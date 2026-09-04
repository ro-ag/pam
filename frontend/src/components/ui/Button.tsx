import type { ButtonHTMLAttributes } from "react";
import { cn, cva, type VariantProps } from "../../lib/cn";

/**
 * Button — one accent per theme, so one primary per view. Ghost buttons are
 * furniture; danger buttons stay quiet (soft fill, firm ink) because PAM's
 * destructive actions confirm and explain rather than shout.
 */
export const buttonVariants = cva(
  "inline-flex shrink-0 select-none items-center justify-center gap-2 rounded-control font-sans font-medium transition-colors disabled:cursor-not-allowed disabled:opacity-50",
  {
    variants: {
      variant: {
        primary:
          "action-control border border-control-line bg-accent-strong text-on-accent hover:bg-accent-hover active:bg-accent-pressed",
        secondary:
          "field-control border border-control-line bg-surface-raised text-ink hover:bg-accent-soft",
        ghost: "text-ink-muted hover:bg-accent-soft hover:text-ink active:bg-accent-soft",
        danger:
          "border border-danger/40 bg-danger-soft text-danger hover:border-danger active:border-danger",
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

export type ButtonProps = ButtonHTMLAttributes<HTMLButtonElement> &
  VariantProps<typeof buttonVariants>;

export function Button({ variant, size, className, type, ...props }: ButtonProps) {
  return (
    <button
      type={type ?? "button"}
      className={cn(buttonVariants({ variant, size }), className)}
      {...props}
    />
  );
}
