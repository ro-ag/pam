import type { HTMLAttributes } from "react";
import { cn, cva, type VariantProps } from "../../lib/cn";

/**
 * Panel — the elevation system made visible. PAM has exactly three grounds:
 * chrome (window + sidebar, the dark water), surface (the floating work
 * panel, the lit tower deck), and surface-raised (cards on the deck). Panel
 * renders the two elevated ones; chrome is the page itself, never a Panel.
 *
 * The pattern every PAM component follows: variants declared with cva,
 * consumer overrides merged through cn(), semantic tokens only.
 */
export const panelVariants = cva("border", {
  variants: {
    ground: {
      /** The floating work panel: one per screen, floats over chrome. */
      surface: "rounded-panel border-edge bg-surface shadow-float",
      /** A card standing on the panel: as many as the layout needs. */
      raised: "rounded-card border-edge bg-surface-raised shadow-raise",
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
