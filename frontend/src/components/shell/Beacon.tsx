import { cn, cva, type VariantProps } from "../../lib/cn";

/** Static daemon indicator with a visible state label and a material pending marker. */
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
      pending: "warm-marker bg-beacon-amber",
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
      className={cn("flex items-center gap-2 font-sans text-xs text-ink-muted", className)}
    >
      <span
        aria-hidden="true"
        className={cn(beaconVariants({ state: resolved }), "size-2 shrink-0")}
      />
      <span>
        {resolved === "connected"
          ? "Connected"
          : resolved === "pending"
            ? "Awaiting review"
            : "Offline"}
      </span>
    </span>
  );
}
