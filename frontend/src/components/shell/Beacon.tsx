import { cn, cva, type VariantProps } from "../../lib/cn";

/**
 * Static daemon indicator with a visible state label and a material
 * pending marker. "connecting" is the honest first frame: nothing has
 * answered yet, so the beacon neither claims a daemon nor mourns one.
 */
export type BeaconState = "connecting" | "connected" | "pending" | "down";

const beaconLabels: Record<BeaconState, string> = {
  connecting: "daemon connecting",
  connected: "daemon connected",
  pending: "daemon approval pending",
  down: "daemon unreachable",
};

const beaconWords: Record<BeaconState, string> = {
  connecting: "Connecting",
  connected: "Connected",
  pending: "Awaiting review",
  down: "Offline",
};

const beaconVariants = cva("rounded-pill", {
  variants: {
    state: {
      connecting: "bg-line-strong",
      connected: "bg-beacon-green",
      pending: "warm-marker bg-beacon-amber",
      down: "bg-beacon-red",
    },
  },
  defaultVariants: {
    state: "connecting",
  },
});

type BeaconProps = VariantProps<typeof beaconVariants> & { className?: string };

export function Beacon({ state, className }: BeaconProps) {
  const resolved: BeaconState = state ?? "connecting";
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
      <span>{beaconWords[resolved]}</span>
    </span>
  );
}
