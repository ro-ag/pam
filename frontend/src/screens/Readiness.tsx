import { Badge } from "../components/ui/Badge";
import { Button } from "../components/ui/Button";
import { FailureNote } from "../components/ui/FailureNote";
import { Panel } from "../components/ui/Panel";
import { cn } from "../lib/cn";
import type { BridgeFailure, ModelsStatus, ReadinessStage, TierReadiness } from "../lib/ipc";

/**
 * Readiness — what a job tier will actually do, as the daemon computed it.
 *
 * The daemon's `readiness` record is the single verdict: the first rung of
 * configured → installed → verified → qualified → engine → ready that fails,
 * with the same cause a job would be refused with. This file only draws it
 * and points at the one repair that unblocks the rung. Residency (weights in
 * memory right now) is transient and shown beside the verdict, never as a
 * rung of it. Nothing here invents a state the daemon did not report: an
 * older daemon without the record gets a plain sentence, not a guess.
 */

/** The chain, in order; each stage names the rung that failed. */
export const RUNGS: readonly { stage: ReadinessStage; label: string }[] = [
  { stage: "unconfigured", label: "configured" },
  { stage: "missing", label: "installed" },
  { stage: "unverified", label: "verified" },
  { stage: "unqualified", label: "qualified" },
  { stage: "engine_missing", label: "engine" },
  { stage: "ready", label: "ready" },
];

/** What the badge says when the chain stops at a stage. */
export const BLOCK_LABELS: Record<ReadinessStage, string> = {
  unconfigured: "not configured",
  missing: "not installed",
  unverified: "unverified",
  unqualified: "unqualified",
  engine_missing: "no engine",
  ready: "ready",
};

/** Where the chain stops: the index of the rung that failed, or the length when ready. */
export function stopIndex(stage: ReadinessStage): number {
  const index = RUNGS.findIndex((rung) => rung.stage === stage);
  return stage === "ready" ? RUNGS.length : index;
}

/** Where a repair happens: a Models tab, or the tier settings. */
export type RepairTarget = "settings" | "library" | "catalog";

/** The one action that unblocks a stage, or null when nothing is blocked. */
export function repairFor(
  stage: ReadinessStage,
): { label: string; target: RepairTarget } | null {
  switch (stage) {
    case "unconfigured":
      return { label: "Choose a model", target: "settings" };
    case "missing":
      return { label: "Open Downloads", target: "catalog" };
    case "unverified":
      return { label: "Verify it", target: "library" };
    case "unqualified":
      return { label: "Choose another model", target: "settings" };
    case "engine_missing":
      return { label: "Install engine", target: "catalog" };
    case "ready":
      return null;
  }
}

/** The sentence for a tier, in Pam's voice; the daemon's own words when blocked. */
export function readinessSentence(readiness: TierReadiness, idleUnloadMin: number): string {
  if (readiness.stage !== "ready") {
    return readiness.blocker?.detail ?? "not ready";
  }
  if (readiness.resident) return "Ready and in memory.";
  if (idleUnloadMin === 0) return "Ready — loads on the first job and stays in memory.";
  return `Ready — loads on the first job, leaves memory after ${idleUnloadMin} idle minutes.`;
}

/** The sentence for an older daemon that reports no readiness record. */
export const NO_RECORD_SENTENCE =
  "This daemon does not report readiness; restart it on the current build to see it.";

/** What persists and what does not, said once. */
export const PERSISTENCE_SENTENCE =
  "A tier default is a saved setting. Residency is not: weights leave memory when idle and come back on the next job.";

/** The compression fact, so nobody looks for a knob that is not there. */
export const COMPRESSION_SENTENCE =
  "Semantic compression is off: evidence is reduced deterministically, and summaries come from the heavy tier only.";

function Chain({ readiness }: { readiness: TierReadiness }) {
  const stop = stopIndex(readiness.stage);
  return (
    <ol aria-label={`${readiness.tier} readiness`} className="flex flex-wrap gap-x-3 gap-y-1">
      {RUNGS.map((rung, index) => {
        const state = index < stop ? "done" : index === stop ? "stop" : "todo";
        return (
          <li
            key={rung.stage}
            aria-current={state === "stop" ? "step" : undefined}
            data-state={state}
            className={cn(
              "flex items-center gap-1.5 font-data text-xs",
              state === "done" && "text-ink-muted",
              state === "stop" && "text-warning",
              state === "todo" && "text-ink-faint",
            )}
          >
            <span
              aria-hidden="true"
              className={cn(
                "size-2 shrink-0 rounded-full border",
                state === "done" && "border-success bg-success",
                state === "stop" && "border-warning bg-warning-soft",
                state === "todo" && "border-line bg-transparent",
              )}
            />
            {rung.label}
          </li>
        );
      })}
    </ol>
  );
}

/** One tier: name, model, the chain, the sentence, and the one repair. */
export function TierRow({
  readiness,
  idleUnloadMin,
  onRepair,
}: {
  readiness: TierReadiness;
  idleUnloadMin: number;
  onRepair?: (target: RepairTarget) => void;
}) {
  const repair = repairFor(readiness.stage);
  const record = readiness.qualification;
  return (
    <div className="space-y-3 rounded-card border border-line p-3">
      <div className="flex flex-wrap items-baseline justify-between gap-x-4 gap-y-1">
        <div className="flex min-w-0 flex-wrap items-baseline gap-x-3 gap-y-1">
          <span className="font-sans text-sm font-semibold text-ink">{readiness.tier}</span>
          <span className="truncate font-data text-xs text-ink-muted">
            {readiness.model_id ?? "no model"}
            {readiness.fallback && readiness.model_id && " · borrowed from light"}
          </span>
        </div>
        <span className="flex items-center gap-1.5">
          {readiness.stage === "ready" ? (
            <Badge tone="success">ready</Badge>
          ) : (
            <Badge tone="warning">{BLOCK_LABELS[readiness.stage]}</Badge>
          )}
          {readiness.resident && <Badge tone="accent">in memory</Badge>}
        </span>
      </div>

      <Chain readiness={readiness} />

      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="min-w-0 flex-1 space-y-0.5">
          <p className="font-sans text-sm text-ink">
            {readinessSentence(readiness, idleUnloadMin)}
          </p>
          {readiness.blocker && (
            <p className="font-sans text-xs text-ink-muted">{readiness.blocker.recovery}</p>
          )}
          {record && (
            <p className="font-data text-xs text-ink-faint">
              {record.contract} · {(record.accuracy * 100).toFixed(1)}% · {record.false_passes}{" "}
              false passes · {record.engine_tag} · {record.decided}
            </p>
          )}
        </div>
        {repair && onRepair && (
          <Button size="sm" variant="secondary" onClick={() => onRepair(repair.target)}>
            {repair.label}
          </Button>
        )}
      </div>
    </div>
  );
}

/** The compact form for the Settings tier selects: one sentence, no chain. */
export function ReadinessLine({
  readiness,
  idleUnloadMin,
}: {
  readiness: TierReadiness | undefined;
  idleUnloadMin: number;
}) {
  if (!readiness) return null;
  const blocked = readiness.stage !== "ready";
  return (
    <span
      className={cn("block font-sans text-xs", blocked ? "text-warning" : "text-ink-muted")}
    >
      {readinessSentence(readiness, idleUnloadMin)}
    </span>
  );
}

/** Both tiers, the persistence sentence, and the compression fact. */
export function ReadinessCard({
  status,
  failure,
  onRepair,
}: {
  status: ModelsStatus | undefined;
  failure: BridgeFailure | null;
  onRepair: (target: RepairTarget) => void;
}) {
  const readiness = status?.readiness;
  return (
    <Panel ground="raised" className="space-y-4 p-5">
      <p className="font-data text-xs text-ink-faint">what a job gets</p>

      {failure && <FailureNote failure={failure} label="readiness" />}

      {!failure && status && !readiness && (
        <p className="font-sans text-sm text-ink-muted">{NO_RECORD_SENTENCE}</p>
      )}

      {readiness && (
        <div className="grid grid-cols-1 gap-3 lg:grid-cols-2">
          <TierRow
            readiness={readiness.light}
            idleUnloadMin={status?.idle_unload_min ?? 0}
            onRepair={onRepair}
          />
          <TierRow
            readiness={readiness.heavy}
            idleUnloadMin={status?.idle_unload_min ?? 0}
            onRepair={onRepair}
          />
        </div>
      )}

      <div className="space-y-1 border-t border-line pt-3">
        <p className="font-sans text-xs text-ink-muted">{PERSISTENCE_SENTENCE}</p>
        <p className="font-sans text-xs text-ink-muted">{COMPRESSION_SENTENCE}</p>
      </div>
    </Panel>
  );
}
