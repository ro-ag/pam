import type { HTMLAttributes } from "react";
import { cn, cva, type VariantProps } from "../../lib/cn";

/** Flat work surfaces and a bounded Costa glass command or decision pane. */
export const panelVariants = cva("border", {
  variants: {
    ground: {
      /** Opaque working surface. */
      surface: "rounded-panel border-edge bg-surface",
      /** A flat working card: as many as the layout needs. */
      raised: "rounded-card border-edge bg-surface-raised",
      /** Plain translucency; no blur, glow, refraction or copied backgrounds. */
      translucent:
        "rounded-card border-edge bg-surface-translucent material-opaque:bg-surface-raised transparency-reduce:bg-surface-raised forced-colors:bg-system-canvas",
      /** Opaque reflected material for a command or decision surface. */
      command: "command-surface rounded-overlay",
    },
  },
  defaultVariants: {
    ground: "surface",
  },
});

export type PanelProps = HTMLAttributes<HTMLElement> & VariantProps<typeof panelVariants>;

export function Panel({ ground, className, ...props }: PanelProps) {
  return <section className={cn(panelVariants({ ground }), className)} {...props} />;
}
