import { useQuery } from "@tanstack/react-query";
import { LoaderCircle, Play } from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";
import { Badge, type BadgeProps } from "../components/ui/Badge";
import { Button } from "../components/ui/Button";
import { FailureNote } from "../components/ui/FailureNote";
import { fieldClasses } from "../components/ui/field";
import { Panel } from "../components/ui/Panel";
import { cn } from "../lib/cn";
import {
  callersList,
  evidenceGet,
  evidenceList,
  flowsRun,
  subscribeEvents,
  toBridgeFailure,
  type BridgeFailure,
  type FlowListEntry,
  type FlowResult,
  type FlowStepReport,
  type FlowStepStatus,
  type OutcomeName,
} from "../lib/ipc";
import { formatDuration } from "../lib/time";

/**
 * The run card — the one place a human starts a flow, and the verdict
 * that lands when it finishes.
 *
 * Starting a flow from here is deliberately unprivileged: the daemon
 * turns `admin.flows.run` into a genuine `flow.run` envelope and pushes
 * it through its own pipeline, so it is classified, gated, laned and
 * audited exactly like an agent's. The GUI gets a ticket back and does
 * what any subscriber does — follows that ticket's events, then reads
 * the verdict out of evidence.
 *
 * The verdict is never invented here. It is the `flow.result` evidence
 * row, parsed: the same JSON the CLI prints and the audit trail keeps.
 * That is why the run card and the run history render through the same
 * two components below — one truth, two places to read it.
 */

/** The evidence kind carrying a run's whole verdict. */
export const FLOW_RESULT_KIND = "flow.result";

/** Truth vocabulary → badge tone; the same mapping the tide uses. */
export const OUTCOME_TONES: Record<OutcomeName, BadgeProps["tone"]> = {
  solved: "accent",
  changed: "accent",
  verified: "accent",
  unresolved: "warning",
  blocked: "danger",
};

/** Step status → badge tone: only success is quiet, only failure shouts. */
const STEP_TONES: Record<FlowStepStatus, BadgeProps["tone"]> = {
  succeeded: "success",
  failed: "danger",
  skipped: "neutral",
  blocked: "danger",
  cancelled: "warning",
};

/** Milliseconds as the shortest honest reading a human wants. */
export function stepDuration(ms: number): string {
  if (ms < 1_000) return `${ms}ms`;
  return formatDuration(Math.round(ms / 1_000));
}

// --- the verdict -----------------------------------------------------------

/**
 * One run's steps, in order. Every column is machine fact, so the whole
 * table speaks in the data voice; the only prose is a step's own summary
 * or the reason it did not succeed.
 */
export function StepTable({ steps }: { steps: FlowStepReport[] }) {
  if (steps.length === 0) {
    return (
      <p className="font-voice text-sm text-ink-muted italic">This run took no steps at all.</p>
    );
  }
  return (
    <div className="overflow-x-auto">
      <table className="w-full border-collapse">
        <thead>
          <tr className="text-left font-data text-xs tracking-widest text-ink-faint uppercase">
            <th className="pb-2 pr-3 font-medium">step</th>
            <th className="pb-2 pr-3 font-medium">kind</th>
            <th className="pb-2 pr-3 font-medium">status</th>
            <th className="pb-2 pr-3 font-medium">tries</th>
            <th className="pb-2 pr-3 font-medium">took</th>
            <th className="pb-2 font-medium">exit</th>
          </tr>
        </thead>
        <tbody>
          {steps.map((step) => (
            <tr key={step.id} className="border-t border-line align-top">
              <td className="py-2.5 pr-3 font-data text-sm text-ink">
                {step.id}
                {step.summary && (
                  <span className="mt-1 block max-w-md font-voice text-sm text-ink-muted italic">
                    {step.summary}
                  </span>
                )}
                {step.error && (
                  <span className="mt-1 block max-w-md font-data text-xs text-danger">
                    {step.error.cause} · {step.error.detail}
                  </span>
                )}
              </td>
              <td className="py-2.5 pr-3 font-data text-xs text-ink-muted">{step.kind}</td>
              <td className="py-2.5 pr-3">
                <Badge tone={STEP_TONES[step.status]}>{step.status}</Badge>
              </td>
              <td className="py-2.5 pr-3 font-data text-xs text-ink-muted tabular-nums">
                {step.attempts}
              </td>
              <td className="py-2.5 pr-3 font-data text-xs text-ink-muted tabular-nums">
                {stepDuration(step.duration_ms)}
              </td>
              <td className="py-2.5 font-data text-xs text-ink-muted tabular-nums">
                {step.exit_status ?? "—"}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

/** The verdict card: outcome chip, Pam's sentence, then the step table. */
export function FlowVerdict({ result }: { result: FlowResult }) {
  return (
    <div aria-label="run verdict" className="space-y-3">
      <div className="flex flex-wrap items-center gap-2">
        <Badge tone={OUTCOME_TONES[result.outcome] ?? "neutral"}>{result.outcome}</Badge>
        <span className="font-data text-xs text-ink-faint" title={result.repo}>
          {result.flow.id} · {result.repo}
        </span>
      </div>
      <p className="max-w-xl font-voice text-base text-ink italic">{result.summary}</p>
      <StepTable steps={result.steps} />
    </div>
  );
}

/** Reads one request's `flow.result` row and parses it into the verdict. */
async function loadVerdict(requestId: string): Promise<FlowResult | null> {
  const { evidence } = await evidenceList(requestId);
  const row = evidence.find((entry) => entry.kind === FLOW_RESULT_KIND);
  if (!row) return null;
  const content = await evidenceGet(row.id);
  return JSON.parse(content.text) as FlowResult;
}

/**
 * The verdict of one finished run, loaded from its evidence. A request
 * with no `flow.result` row (still running, or refused before its first
 * step) resolves to null rather than erroring — there is simply nothing
 * to show yet.
 */
export function useFlowVerdict(requestId: string | null) {
  return useQuery({
    queryKey: ["flow-verdict", requestId],
    queryFn: () => loadVerdict(requestId as string),
    enabled: requestId !== null,
  });
}

/** The verdict, wherever a request id is already known. */
export function FlowVerdictPanel({ requestId }: { requestId: string }) {
  const verdict = useFlowVerdict(requestId);
  const failure = verdict.isError ? toBridgeFailure(verdict.error) : null;
  if (failure) return <FailureNote failure={failure} label="verdict" />;
  if (verdict.isPending) {
    return <p className="font-data text-xs text-ink-faint">reading the verdict…</p>;
  }
  if (!verdict.data) {
    return (
      <p className="font-voice text-sm text-ink-muted italic">
        This run left no verdict — it never reached its first step.
      </p>
    );
  }
  return <FlowVerdict result={verdict.data} />;
}

// --- starting a run --------------------------------------------------------

/** The refusal shape a mid-run `refused` event stands for. */
const REFUSED_MID_RUN: BridgeFailure = {
  cause: "refused",
  detail: "the daemon stopped this run before it finished",
  recovery: "Open Activity and expand this request to read the refusal it recorded.",
};

/**
 * What the card knows about its run, for whoever wants to paint it: the
 * ticket, every progress note it has heard for that ticket in order, the
 * settled request id once `done` / `refused` arrived, and whether it was
 * a refusal. The canvas turns the notes into rims.
 */
export interface FlowRunState {
  ticket: string | null;
  notes: string[];
  settled: string | null;
  refused: boolean;
}

export function FlowRunCard({
  flow,
  onRun,
}: {
  flow: FlowListEntry;
  /** Called whenever the run state changes; notes accumulate per ticket. */
  onRun?: (run: FlowRunState) => void;
}) {
  const callers = useQuery({ queryKey: ["callers"], queryFn: callersList });
  const [repo, setRepo] = useState("");
  const [values, setValues] = useState<Record<string, string>>({});
  const [ticket, setTicket] = useState<string | null>(null);
  const [notes, setNotes] = useState<string[]>([]);
  const [settled, setSettled] = useState<string | null>(null);
  const [refused, setRefused] = useState(false);
  const [failure, setFailure] = useState<BridgeFailure | null>(null);
  const [starting, setStarting] = useState(false);

  // Every flow declares its own inputs; switching flows resets the card
  // to that flow's defaults rather than carrying a neighbour's answers.
  useEffect(() => {
    const defaults: Record<string, string> = {};
    for (const input of flow.inputs) defaults[input.name] = input.default ?? "";
    setValues(defaults);
    setTicket(null);
    setNotes([]);
    setSettled(null);
    setRefused(false);
    setFailure(null);
  }, [flow.id, flow.inputs]);

  // Whoever listens gets every change, through a ref so a new callback
  // identity never re-announces an unchanged run.
  const onRunRef = useRef(onRun);
  onRunRef.current = onRun;
  useEffect(() => {
    onRunRef.current?.({ ticket, notes, settled, refused });
  }, [ticket, notes, settled, refused]);

  // The ticket's own events drive the progress line. Kept in a ref so the
  // subscription is opened once per run, not once per re-render.
  const ticketRef = useRef<string | null>(null);
  ticketRef.current = ticket;
  useEffect(() => {
    if (ticket === null) return;
    let cancelled = false;
    let unlisten: (() => void) | undefined;
    subscribeEvents((payload) => {
      if (payload.ticket !== ticketRef.current) return;
      if (payload.event.kind === "progress") {
        const note = payload.event.note;
        setNotes((prev) => [...prev, note]);
        return;
      }
      if (payload.event.kind === "done" || payload.event.kind === "refused") {
        setRefused(payload.event.kind === "refused");
        setSettled(payload.ticket);
      }
    })
      .then((stop) => {
        if (cancelled) stop();
        else unlisten = stop;
      })
      .catch(() => {
        // No bridge (browser dev) or no stream: the run still happens,
        // the card just cannot narrate it.
      });
    return () => {
      cancelled = true;
      unlisten?.();
    };
  }, [ticket]);

  const repos = useMemo(() => {
    const seen = new Set((callers.data?.callers ?? []).map((caller) => caller.repo));
    return [...seen].filter(Boolean).sort();
  }, [callers.data]);

  const progress = notes.length > 0 ? notes[notes.length - 1] : null;

  const start = () => {
    setStarting(true);
    setFailure(null);
    setNotes([]);
    setSettled(null);
    setRefused(false);
    flowsRun(flow.id, repo.trim(), values)
      .then((reply) => setTicket(reply.ticket))
      .catch((error) => setFailure(toBridgeFailure(error)))
      .finally(() => setStarting(false));
  };

  return (
    <Panel ground="raised" aria-label="run this flow" className="space-y-4 p-4">
      <p className="font-data text-xs tracking-widest text-ink-faint uppercase">run</p>

      <div className="space-y-1.5">
        <span className="block font-data text-xs text-ink-faint">repo</span>
        {repos.length > 0 && (
          <select
            aria-label="known repo"
            value={repos.includes(repo) ? repo : ""}
            onChange={(event) => setRepo(event.target.value)}
            className="h-8 w-full rounded-control border border-line bg-surface px-2 font-data text-xs text-ink"
          >
            <option value="">pick a repo pam has seen</option>
            {repos.map((known) => (
              <option key={known} value={known}>
                {known}
              </option>
            ))}
          </select>
        )}
        <input
          aria-label="repo path"
          value={repo}
          onChange={(event) => setRepo(event.target.value)}
          placeholder="or type an absolute path"
          className={fieldClasses}
        />
      </div>

      {flow.inputs.length > 0 && (
        <div className="space-y-3 border-t border-line pt-3">
          {flow.inputs.map((input) => (
            <label key={input.name} className="block space-y-1">
              <span className="block font-data text-xs text-ink-faint">{input.name}</span>
              <input
                aria-label={input.name}
                value={values[input.name] ?? ""}
                onChange={(event) =>
                  setValues((prev) => ({ ...prev, [input.name]: event.target.value }))
                }
                className={fieldClasses}
              />
              {input.description && (
                <span className="block font-voice text-sm text-ink-muted italic">
                  {input.description}
                </span>
              )}
            </label>
          ))}
        </div>
      )}

      <div className="flex flex-wrap items-center gap-3 border-t border-line pt-3">
        <Button size="sm" disabled={starting || !repo.trim()} onClick={start}>
          {starting ? (
            <LoaderCircle aria-hidden="true" className="size-3.5 animate-spin" />
          ) : (
            <Play size={14} aria-hidden="true" />
          )}
          Run
        </Button>
        {ticket && <span className="font-data text-xs text-ink-faint">{ticket}</span>}
      </div>

      {failure && <FailureNote failure={failure} label="run" />}

      {ticket && settled === null && (
        <p
          aria-label="run progress"
          className={cn("font-data text-xs", progress ? "text-ink-muted" : "text-ink-faint")}
        >
          {progress ?? "queued · waiting for the first step"}
        </p>
      )}

      {refused && <FailureNote failure={REFUSED_MID_RUN} label="run" />}

      {settled !== null && <FlowVerdictPanel requestId={settled} />}
    </Panel>
  );
}
