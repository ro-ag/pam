import type { HTMLAttributes } from "react";
import { cn } from "../../lib/cn";

/** Settings-sized header, outside each workspace's scrolling content. */
export function PageHeader({ className, ...props }: HTMLAttributes<HTMLElement>) {
  return (
    <header
      className={cn("page-header shrink-0 space-y-1 border-b border-line", className)}
      {...props}
    />
  );
}
