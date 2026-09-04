import type { HTMLAttributes } from "react";
import { cn } from "../../lib/cn";

/** Titles share the page material; scroll normally so content cannot overlap them. */
export function PageHeader({ className, ...props }: HTMLAttributes<HTMLElement>) {
  return (
    <header
      className={cn("shrink-0 space-y-1 border-b border-line py-5", className)}
      {...props}
    />
  );
}
