import { cn, cva, type VariantProps } from "../../lib/cn";

/**
 * The beacon — daemon state readable from the corner of the eye, no text.
 * A small lighthouse dot with a breathing glow: green when the daemon
 * answers, amber while an approval waits (wired by the approvals task),
 * red when the daemon is unreachable. Colors come from the beacon token
 * aliases so a theme can retune them without touching this component.
 */
export type BeaconState = "connected" | "pending" | "down";

const beaconLabels: Record<BeaconState, string> = {
  connected: "daemon connected",
  pending: "daemon approval pending",
  down: "daemon unreachable",
};

export const beaconVariants = cva("rounded-pill", {
  variants: {
    state: {
      connected: "bg-beacon-green",
      pending: "bg-beacon-amber",
      down: "bg-beacon-red",
    },
  },
  defaultVariants: {
    state: "down",
  },
});

export type BeaconProps = VariantProps<typeof beaconVariants> & { className?: string };

export function Beacon({ state, className }: BeaconProps) {
  const resolved: BeaconState = state ?? "down";
  return (
    <span
      role="status"
      aria-label={beaconLabels[resolved]}
      className={cn("relative flex size-2", className)}
    >
      <span
        aria-hidden="true"
        className={cn(
          beaconVariants({ state: resolved }),
          "absolute inset-0 animate-breathe blur-xs",
        )}
      />
      <span className={cn(beaconVariants({ state: resolved }), "relative size-2")} />
    </span>
  );
}
