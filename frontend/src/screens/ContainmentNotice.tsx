import { useQuery } from "@tanstack/react-query";
import { DAEMON_STATUS_KEY, statusRefetchInterval } from "../components/shell/useDaemonStatus";
import { SafeText } from "../components/ui/SafeText";
import { containmentStatus, daemonStatus } from "../lib/ipc";

const SENTENCES = {
  flows: {
    label: "command steps unavailable",
    lead: "Command steps cannot run on this machine.",
    rest: "Flows that use only connectors and models still run; a command step is refused.",
  },
  landing: {
    label: "guarded landing unavailable",
    lead: "Guarded landing cannot run on this machine.",
    rest: "Its local Git runs inside the same containment as flow command steps, so a landing is refused.",
  },
} as const;

/**
 * Says, before anything is run, that this machine cannot contain command
 * workloads (the daemon's `status.containment`). Renders nothing while the
 * daemon is unreachable, on an older daemon that publishes no block, and
 * wherever containment is available. Shares the beacon's status query, so it
 * adds no polling of its own.
 */
export function ContainmentNotice({ subject }: { subject: keyof typeof SENTENCES }) {
  const status = useQuery({
    queryKey: DAEMON_STATUS_KEY,
    queryFn: daemonStatus,
    refetchInterval: statusRefetchInterval,
  });
  const containment =
    status.data?.connected === true ? containmentStatus(status.data.status) : null;
  if (!containment || containment.available) return null;
  const sentences = SENTENCES[subject];
  return (
    <div
      role="note"
      aria-label={sentences.label}
      className="max-w-content space-y-1 rounded-card border border-warning/40 bg-warning-soft p-3"
    >
      <p className="font-sans text-sm text-ink">
        {sentences.lead} {sentences.rest}
      </p>
      <p className="select-text font-data text-xs text-ink-muted">
        <SafeText
          value={`${containment.cause ?? "command_containment_unavailable"} · ${containment.detail}`}
        />
      </p>
    </div>
  );
}
