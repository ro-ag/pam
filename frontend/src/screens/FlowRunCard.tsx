import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { LoaderCircle, Play } from "lucide-react";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Badge, type BadgeProps } from "../components/ui/Badge";
import { Button } from "../components/ui/Button";
import { ConfirmButton } from "../components/ui/ConfirmButton";
import { FailureNote } from "../components/ui/FailureNote";
import { fieldClasses, fieldLabelClasses } from "../components/ui/field";
import { Panel } from "../components/ui/Panel";
import { cn } from "../lib/cn";
import {
  callersList,
  evidenceGet,
  evidenceList,
  flowsInspect,
  flowsRun,
  requestCapability,
  subscribeEvents,
  toBridgeFailure,
  type BridgeFailure,
  type FlowInspectBlocker,
  type FlowInspection,
  type FlowListEntry,
  type FlowResult,
  type FlowStepReport,
  type FlowStepStatus,
  type OutcomeName,
  type PamEventPayload,
} from "../lib/ipc";
import { outcomeLabel } from "../lib/outcome";
import { formatDuration } from "../lib/time";

/**
 * The run card — where a human starts a flow and sees its verdict.
 *
 * Starting a flow here is deliberately unprivileged: the daemon turns
 * `admin.flows.run` into a genuine `flow.run` envelope, so it is
 * classified, gated, laned, and audited exactly like an agent's. The
 * verdict is never invented here — it is the `flow.result` evidence
 * row (same JSON as the CLI and audit trail), rendered through the
 * same components as run history below.
 * `admin.flows.run` answers with a ticket; the card follows that ticket's events rather than receiving the verdict directly.
 */

/** The evidence kind carrying a run's whole verdict. */
const FLOW_RESULT_KIND = "flow.result";

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
function stepDuration(ms: number): string {
  if (ms < 1_000) return `${ms}ms`;
  return formatDuration(Math.round(ms / 1_000));
}

/** A summary longer than this many characters is clamped to three lines until opened. */
const SUMMARY_CLAMP_CHARS = 240;

/**
 * A step's own words. A model observation can run to a paragraph; the
 * table shows three lines of it and a way to read the rest, so the step
 * column never dwarfs the columns of fact beside it.
 */
function StepSummary({ text }: { text: string }) {
  const [open, setOpen] = useState(false);
  const long = text.length > SUMMARY_CLAMP_CHARS;
  return (
    <span className="mt-1 block max-w-md">
      <span
        className={cn(
          "block font-sans text-sm text-ink-muted",
          long && !open && "line-clamp-3",
        )}
      >
        {text}
      </span>
      {long && (
        <button
          type="button"
          aria-expanded={open}
          onClick={() => setOpen((value) => !value)}
          className="mt-1 min-h-8 rounded-control font-sans text-xs text-accent-strong underline"
        >
          {open ? "Show less" : "Show more"}
        </button>
      )}
    </span>
  );
}

// --- the verdict -----------------------------------------------------------

/**
 * One run's steps, in order. Every column is machine fact, so the whole
 * table speaks in the data voice; the only prose is a step's own summary
 * or the reason it did not succeed.
 */
function StepTable({ steps }: { steps: FlowStepReport[] }) {
  if (steps.length === 0) {
    return <p className="font-sans text-sm text-ink-muted">This run took no steps at all.</p>;
  }
  return (
    <div className="overflow-x-auto">
      <table className="w-full border-collapse">
        <thead>
          <tr className="text-left font-data text-xs text-ink-faint">
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
                {step.summary && <StepSummary text={step.summary} />}
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
function FlowVerdict({ result }: { result: FlowResult }) {
  return (
    <div aria-label="run verdict" className="space-y-3">
      <div className="flex flex-wrap items-center gap-2">
        <Badge tone={OUTCOME_TONES[result.outcome] ?? "neutral"}>
          {outcomeLabel(result.outcome)}
        </Badge>
        <span className="font-data text-xs text-ink-faint" title={result.repo}>
          {result.flow.id} · {result.repo}
        </span>
      </div>
      <p className="max-w-xl font-sans text-sm text-ink">{result.summary}</p>
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
      <p className="font-sans text-sm text-ink-muted">
        This run left no verdict — it never reached its first step.
      </p>
    );
  }
  return <FlowVerdict result={verdict.data} />;
}

// --- readiness ---------------------------------------------------------------

/** Where a blocker's cause is best fixed, read off the cause's own wording. */
function destinationFor(cause: string): { to: "/settings" | "/models"; hash?: string } | null {
  if (cause.includes("connector")) return { to: "/settings", hash: "connectors" };
  if (cause === "landing_permission_missing" || cause.startsWith("landing_"))
    return { to: "/settings", hash: "flows" };
  if (
    cause === "program_missing" ||
    cause === "program_not_allowed" ||
    cause.startsWith("program") ||
    cause.startsWith("scope_")
  )
    return { to: "/settings", hash: "flows" };
  if (cause.includes("model")) return { to: "/models" };
  return null;
}

/** One reason this run would not be admitted, and the way to fix it. */
function BlockerRow({
  blocker,
  onFocusInput,
}: {
  blocker: FlowInspectBlocker;
  onFocusInput: (name: string) => void;
}) {
  const focusInput = blocker.cause === "input_unavailable" ? blocker.input : undefined;
  const destination = focusInput ? null : destinationFor(blocker.cause);
  const text = [blocker.detail, blocker.recovery].filter(Boolean).join(" — ");
  return (
    <li className="space-y-1.5 rounded-card border border-line bg-surface-raised p-3">
      <div className="flex flex-wrap items-center gap-2">
        {blocker.step && <Badge tone="neutral">{blocker.step}</Badge>}
        <span className="font-data text-xs text-ink">{blocker.cause}</span>
      </div>
      {text && <p className="font-sans text-sm text-ink-muted">{text}</p>}
      {focusInput && (
        <Button size="sm" variant="ghost" onClick={() => onFocusInput(focusInput)}>
          Go to {focusInput}
        </Button>
      )}
      {destination && (
        <Link
          to={destination.to}
          hash={destination.hash}
          className="block font-sans text-sm text-accent-strong underline"
        >
          {destination.to === "/models" ? "Open Models" : "Open Settings"}
        </Link>
      )}
    </li>
  );
}

/** The dry-run verdict: ready or blocked, why, and the declared inputs. */
function ReadinessPanel({
  inspection,
  onFocusInput,
}: {
  inspection: FlowInspection;
  onFocusInput: (name: string) => void;
}) {
  const ready = inspection.readiness === "admission_required";
  return (
    <div aria-label="flow readiness" className="space-y-3">
      <Badge tone={ready ? "success" : "danger"}>{ready ? "Ready to run" : "Blocked"}</Badge>
      {inspection.blockers.length > 0 && (
        <ul aria-label="readiness blockers" className="space-y-2">
          {inspection.blockers.map((blocker, index) => (
            <BlockerRow
              key={`${blocker.cause}-${index}`}
              blocker={blocker}
              onFocusInput={onFocusInput}
            />
          ))}
        </ul>
      )}
      {inspection.inputs.length > 0 && (
        <dl className="flex flex-wrap gap-x-4 gap-y-1 border-t border-line pt-2">
          {inspection.inputs.map((input) => (
            <div key={input.name} className="font-data text-xs text-ink-muted">
              <dt className="inline">
                {input.name}
                {input.required ? " (required)" : ""}
              </dt>
              <dd className="inline text-ink-faint"> · {input.type}</dd>
            </div>
          ))}
        </dl>
      )}
    </div>
  );
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

/** How many events the card keeps while its ticket is still unknown. */
const EARLY_EVENT_CAP = 64;

/** Why Run and Check readiness stay closed without a repository. */
const REPO_HINT = "Enter a repository path first";

export function FlowRunCard({
  flow,
  onRun,
}: {
  flow: FlowListEntry;
  /** Called whenever the run state changes; notes accumulate per ticket. */
  onRun?: (run: FlowRunState) => void;
}) {
  const queryClient = useQueryClient();
  const callers = useQuery({ queryKey: ["callers"], queryFn: callersList });
  const [repo, setRepo] = useState("");
  const [values, setValues] = useState<Record<string, string>>({});
  const [ticket, setTicket] = useState<string | null>(null);
  const [notes, setNotes] = useState<string[]>([]);
  const [settled, setSettled] = useState<string | null>(null);
  const [refused, setRefused] = useState(false);
  const [failure, setFailure] = useState<BridgeFailure | null>(null);
  const [starting, setStarting] = useState(false);
  const [cancelling, setCancelling] = useState(false);
  const [inspection, setInspection] = useState<FlowInspection | null>(null);
  const [inspecting, setInspecting] = useState(false);
  const [inspectFailure, setInspectFailure] = useState<BridgeFailure | null>(null);
  const inputRefs = useRef<Record<string, HTMLInputElement | null>>({});

  // Read wherever an effect fires without wanting `repo` itself as a
  // trigger — the auto-check below cares whether one is already there,
  // not about every keystroke that changes it.
  const repoRef = useRef(repo);
  repoRef.current = repo;

  // The ticket the event stream filters on, and the events that arrived
  // before it was known (see the subscription below).
  const ticketRef = useRef<string | null>(null);
  const early = useRef<PamEventPayload[]>([]);

  // Only the newest check may answer: the auto-check on a flow switch and
  // a manual one can otherwise land out of order.
  const inspectionRun = useRef(0);
  const runInspection = useCallback(
    (repoValue: string, inputValues: Record<string, string>) => {
      const trimmed = repoValue.trim();
      if (!trimmed) return;
      const run = ++inspectionRun.current;
      setInspecting(true);
      setInspectFailure(null);
      flowsInspect(flow.id, trimmed, inputValues)
        .then((reply) => {
          if (run !== inspectionRun.current) return;
          setInspection(reply);
        })
        .catch((error) => {
          if (run !== inspectionRun.current) return;
          setInspectFailure(toBridgeFailure(error));
        })
        .finally(() => {
          if (run === inspectionRun.current) setInspecting(false);
        });
    },
    [flow.id],
  );

  // Every flow declares its own inputs; switching flows resets the card
  // to that flow's defaults rather than carrying a neighbour's answers.
  // A repo the human already typed survives the switch, so this is also
  // where the readiness check re-runs for the newly selected flow — once,
  // not on every keystroke that follows. The inputs are keyed by value:
  // every `["flows"]` refetch hands the card a fresh array for the same
  // flow, and that must not reset a run in progress.
  const inputsKey = JSON.stringify(flow.inputs);
  useEffect(() => {
    const declared = JSON.parse(inputsKey) as FlowListEntry["inputs"];
    const defaults: Record<string, string> = {};
    for (const input of declared) defaults[input.name] = input.default ?? "";
    setValues(defaults);
    setTicket(null);
    ticketRef.current = null;
    early.current = [];
    setNotes([]);
    setSettled(null);
    setRefused(false);
    setFailure(null);
    setInspection(null);
    setInspectFailure(null);
    runInspection(repoRef.current, defaults);
  }, [flow.id, inputsKey, runInspection]);

  // Whoever listens gets every change, through a ref so a new callback
  // identity never re-announces an unchanged run.
  const onRunRef = useRef(onRun);
  onRunRef.current = onRun;
  useEffect(() => {
    onRunRef.current?.({ ticket, notes, settled, refused });
  }, [ticket, notes, settled, refused]);

  // The ticket's own events drive the progress line. The stream is open
  // from mount, because a short flow can finish before `admin.flows.run`
  // even answers with its ticket: events that arrive while the ticket is
  // still unknown wait in `early` and replay the moment it is.
  const apply = useCallback(
    (payload: PamEventPayload) => {
      if (payload.event.kind === "progress") {
        const note = payload.event.note;
        setNotes((prev) => [...prev, note]);
        return;
      }
      if (payload.event.kind === "done" || payload.event.kind === "refused") {
        setRefused(payload.event.kind === "refused");
        setSettled(payload.ticket);
        // The history tab reads the tide; a settled run is a new row there.
        void queryClient.invalidateQueries({ queryKey: ["flow-runs"] });
      }
    },
    [queryClient],
  );
  useEffect(() => {
    let cancelled = false;
    let unlisten: (() => void) | undefined;
    subscribeEvents((payload) => {
      const current = ticketRef.current;
      if (current === null) {
        early.current = [...early.current.slice(-(EARLY_EVENT_CAP - 1)), payload];
        return;
      }
      if (payload.ticket !== current) return;
      apply(payload);
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
  }, [apply]);

  const repos = useMemo(() => {
    const seen = new Set((callers.data?.callers ?? []).map((caller) => caller.repo));
    return [...seen].filter(Boolean).sort();
  }, [callers.data]);

  const progress = notes.length > 0 ? notes[notes.length - 1] : null;
  const running = ticket !== null && settled === null;

  const start = () => {
    setStarting(true);
    setFailure(null);
    setNotes([]);
    setSettled(null);
    setRefused(false);
    setTicket(null);
    ticketRef.current = null;
    early.current = [];
    flowsRun(flow.id, repo.trim(), values)
      .then((reply) => {
        ticketRef.current = reply.ticket;
        setTicket(reply.ticket);
        const waiting = early.current.filter((payload) => payload.ticket === reply.ticket);
        early.current = [];
        for (const payload of waiting) apply(payload);
      })
      .catch((error) => setFailure(toBridgeFailure(error)))
      .finally(() => setStarting(false));
  };

  // `cancel` is an ordinary capability the daemon exposes to anyone who
  // holds the ticket; the GUI asks as itself and the audit names a human.
  const cancel = () => {
    if (ticket === null) return;
    setCancelling(true);
    setFailure(null);
    requestCapability("cancel", { ticket })
      .catch((error) => setFailure(toBridgeFailure(error)))
      .finally(() => setCancelling(false));
  };

  return (
    <Panel ground="raised" aria-label="run this flow" className="space-y-4 p-4">
      <p className="font-data text-xs text-ink-faint">Run</p>

      <div className="space-y-2">
        {repos.length > 0 && (
          <label className="block space-y-1">
            <span className={fieldLabelClasses}>Known repository</span>
            <select
              aria-label="known repo"
              value={repos.includes(repo) ? repo : ""}
              onChange={(event) => setRepo(event.target.value)}
              className={cn(fieldClasses, "px-2")}
            >
              <option value="">Choose a repository pam has seen</option>
              {repos.map((known) => (
                <option key={known} value={known}>
                  {known}
                </option>
              ))}
            </select>
          </label>
        )}
        <label className="block space-y-1">
          <span className={fieldLabelClasses}>Repository path</span>
          <input
            aria-label="repo path"
            value={repo}
            onChange={(event) => setRepo(event.target.value)}
            placeholder="/absolute/path/to/repository"
            className={fieldClasses}
          />
          <span className="block font-sans text-xs text-ink-muted">
            An absolute path to the repository the flow runs in.
          </span>
        </label>
      </div>

      {flow.inputs.length > 0 && (
        <div className="space-y-3 border-t border-line pt-3">
          {flow.inputs.map((input) => (
            <label key={input.name} className="block space-y-1">
              <span className={fieldLabelClasses}>{input.name}</span>
              <input
                aria-label={input.name}
                ref={(el) => {
                  inputRefs.current[input.name] = el;
                }}
                value={values[input.name] ?? ""}
                onChange={(event) =>
                  setValues((prev) => ({ ...prev, [input.name]: event.target.value }))
                }
                className={fieldClasses}
              />
              {input.description && (
                <span className="block font-sans text-sm text-ink-muted">
                  {input.description}
                </span>
              )}
            </label>
          ))}
        </div>
      )}

      <div className="space-y-3 border-t border-line pt-3">
        <Button
          size="sm"
          variant="secondary"
          disabled={inspecting || !repo.trim()}
          title={!repo.trim() ? REPO_HINT : undefined}
          onClick={() => runInspection(repo, values)}
        >
          {inspecting && <LoaderCircle aria-hidden="true" className="size-3.5 animate-spin" />}
          Check readiness
        </Button>
        {inspectFailure && <FailureNote failure={inspectFailure} label="readiness" />}
        {inspection && (
          <ReadinessPanel
            inspection={inspection}
            onFocusInput={(name) => inputRefs.current[name]?.focus()}
          />
        )}
      </div>

      <div className="flex flex-wrap items-center gap-3 border-t border-line pt-3">
        <Button
          size="sm"
          disabled={starting || running || !repo.trim()}
          title={
            !repo.trim() ? REPO_HINT : running ? "This flow is already running" : undefined
          }
          onClick={start}
        >
          {starting ? (
            <LoaderCircle aria-hidden="true" className="size-3.5 animate-spin" />
          ) : (
            <Play size={14} aria-hidden="true" />
          )}
          Run
        </Button>
        {running && (
          <ConfirmButton
            label="Cancel run"
            confirmLabel="cancel it?"
            variant="secondary"
            busy={cancelling}
            onConfirm={cancel}
          />
        )}
        {ticket && <span className="font-data text-xs text-ink-faint">{ticket}</span>}
      </div>

      {failure && <FailureNote failure={failure} label="run" />}

      {running && (
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
