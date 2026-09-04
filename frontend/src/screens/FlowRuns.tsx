import { useQuery } from "@tanstack/react-query";
import { ChevronRight } from "lucide-react";
import { useState } from "react";
import { Badge, type BadgeProps } from "../components/ui/Badge";
import { FailureNote } from "../components/ui/FailureNote";
import { cn } from "../lib/cn";
import { activityList, toBridgeFailure, type ActivityRow, type OutcomeName } from "../lib/ipc";
import { exactTime, relativeTime } from "../lib/time";
import { EvidenceStrip } from "./EvidenceStrip";
import { FlowVerdictPanel, OUTCOME_TONES } from "./FlowRunCard";

/**
 * Runs — this flow's history, which is nothing but the tide narrowed.
 *
 * A run IS a request: `flow.run`, with the flow id in its args. So the
 * history asks `admin.activity.list` for that one capability and keeps
 * the rows whose args name this flow — no second store, no parallel
 * bookkeeping that could disagree with the audit trail.
 *
 * Expanding a row shows the same verdict the run card shows, plus the
 * request's whole evidence strip: every log, compact and summary the run
 * left behind, exactly where Activity already looks for them.
 */

/** How many `flow.run` rows the history asks for. */
export const RUNS_LIMIT = 50;

/** The capability every run is filed under. */
export const RUN_CAPABILITY = "flow.run";

/** The flow id out of a request's parsed args, or null. */
export function flowIdOf(args: unknown): string | null {
  if (typeof args !== "object" || args === null) return null;
  const id = (args as { id?: unknown }).id;
  return typeof id === "string" ? id : null;
}

/** Last path segment; the full path rides on the title attribute. */
function repoTail(repo: string): string {
  const segments = repo.split("/").filter(Boolean);
  return segments[segments.length - 1] ?? repo;
}

/** The verdict badge for a row: the outcome when there is one, else state. */
function runBadge(row: ActivityRow): { label: string; tone: BadgeProps["tone"] } {
  if (row.state === "queued") return { label: "queued", tone: "neutral" };
  if (row.state === "running") return { label: "running", tone: "accent" };
  if (row.state === "waiting_approval") return { label: "approval held", tone: "warning" };
  if (!row.outcome) {
    return { label: row.state === "done" ? "done" : row.state, tone: "neutral" };
  }
  return {
    label: row.outcome,
    tone: OUTCOME_TONES[row.outcome as OutcomeName] ?? "danger",
  };
}

function RunRow({
  row,
  expanded,
  onToggle,
}: {
  row: ActivityRow;
  expanded: boolean;
  onToggle: () => void;
}) {
  const badge = runBadge(row);
  return (
    <li>
      <button
        type="button"
        aria-expanded={expanded}
        onClick={onToggle}
        className="group flex h-11 w-full items-center gap-3 rounded-control px-2 text-left transition-colors duration-150 hover:bg-accent-soft/40"
      >
        <ChevronRight
          aria-hidden="true"
          className={cn(
            "size-3.5 shrink-0 text-ink-faint transition-transform duration-150",
            expanded && "rotate-90",
          )}
        />
        <Badge tone={badge.tone} className="shrink-0">
          {badge.label}
        </Badge>
        <span
          className="min-w-0 flex-1 truncate font-data text-xs text-ink-muted"
          title={row.repo}
        >
          {repoTail(row.repo)}
        </span>
        <time
          dateTime={new Date(row.created_ts * 1000).toISOString()}
          title={exactTime(row.created_ts)}
          className="w-16 shrink-0 text-right font-data text-xs text-ink-faint tabular-nums"
        >
          {relativeTime(row.created_ts)}
        </time>
      </button>
      {expanded && (
        <div className="mt-1 mb-3 ml-9 space-y-3 border-l border-line pl-4">
          <p className="font-data text-xs text-ink-faint">{row.id}</p>
          <FlowVerdictPanel requestId={row.id} />
          <EvidenceStrip requestId={row.id} />
        </div>
      )}
    </li>
  );
}

export function FlowRuns({ flowId }: { flowId: string }) {
  const [expanded, setExpanded] = useState<string | null>(null);
  const runs = useQuery({
    queryKey: ["flow-runs"],
    queryFn: () => activityList({ capability: RUN_CAPABILITY, limit: RUNS_LIMIT }),
  });

  const failure = runs.isError ? toBridgeFailure(runs.error) : null;
  if (failure) return <FailureNote failure={failure} label="runs" />;

  const rows = (runs.data?.requests ?? [])
    .filter((row) => flowIdOf(row.args) === flowId)
    .sort((left, right) => right.created_ts - left.created_ts);

  if (runs.isPending) {
    return <p className="font-data text-xs text-ink-faint">reading the tide…</p>;
  }

  if (rows.length === 0) {
    return (
      <p className="max-w-md font-sans text-sm text-ink-muted">
        This flow has not run yet. Every run — yours or an agent&rsquo;s — lands here with its
        verdict and everything it left behind.
      </p>
    );
  }

  return (
    <ul aria-label="runs" className="divide-y divide-line">
      {rows.map((row) => (
        <RunRow
          key={row.id}
          row={row}
          expanded={expanded === row.id}
          onToggle={() => setExpanded(expanded === row.id ? null : row.id)}
        />
      ))}
    </ul>
  );
}
