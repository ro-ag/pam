import type { HTMLAttributes } from "react";
import { cn, cva, type VariantProps } from "../../lib/cn";

/**
 * Panel — the elevation system made visible. PAM has exactly three grounds:
 * chrome (window + sidebar, the dark water), surface (the floating work
 * panel, the lit tower deck), and surface-raised (cards on the deck). Panel
 * renders working surfaces and an opaque command material; chrome is the page itself.
 *
 * The pattern every PAM component follows: variants declared with cva,
 * consumer overrides merged through cn(), semantic tokens only.
 */
export const panelVariants = cva("border", {
  variants: {
    ground: {
      /** The floating work panel: one per screen, floats over chrome. */
      surface: "rounded-panel border-edge bg-surface shadow-float",
      /** A flat working card: as many as the layout needs. */
      raised: "rounded-card border-edge bg-surface-raised",
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
