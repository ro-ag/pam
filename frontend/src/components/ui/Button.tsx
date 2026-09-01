import type { ButtonHTMLAttributes } from "react";
import { cn, cva, type VariantProps } from "../../lib/cn";

/**
 * Button — one accent per theme, so one primary per view. Ghost buttons are
 * furniture; danger buttons stay quiet (soft fill, firm ink) because PAM's
 * destructive actions confirm and explain rather than shout.
 */
export const buttonVariants = cva(
  "inline-flex select-none items-center justify-center gap-2 rounded-control font-sans font-medium transition-colors duration-150 disabled:cursor-not-allowed disabled:opacity-50",
  {
    variants: {
      variant: {
        primary:
          "bg-accent-strong text-on-accent hover:bg-accent-hover active:bg-accent-pressed",
        ghost: "text-ink-muted hover:bg-accent-soft hover:text-ink active:bg-accent-soft",
        danger:
          "border border-danger/40 bg-danger-soft text-danger hover:border-danger active:border-danger",
      },
      size: {
        sm: "h-8 px-3 text-xs",
        md: "h-10 px-4 text-sm",
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
