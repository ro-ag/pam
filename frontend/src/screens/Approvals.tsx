import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Hand } from "lucide-react";
import { AnimatePresence, motion } from "motion/react";
import { useEffect, useRef, useState } from "react";
import { APPROVALS_PENDING_KEY } from "../components/shell/useDaemonStatus";
import { Badge } from "../components/ui/Badge";
import { Button } from "../components/ui/Button";
import { FailureNote } from "../components/ui/FailureNote";
import { fieldClasses } from "../components/ui/field";
import { Panel } from "../components/ui/Panel";
import { PageHeader } from "../components/ui/PageHeader";
import { cn } from "../lib/cn";
import {
  activityList,
  approvalsPending,
  approvalsResolve,
  subscribeEvents,
  toBridgeFailure,
  type ActivityRow,
  type BridgeFailure,
  type PendingApproval,
} from "../lib/ipc";
import { repoTail } from "../lib/repo";
import { exactTime, relativeTime, useNow } from "../lib/time";

/**
 * Approvals — the raised hand: each pending approval renders as a full card (never a table row).
 * Approve is primary; Deny is the outlined secondary — refusing is legitimate, not shouted.
 * The pending list names the capability but not what will run; the card joins the request's
 * own row from the tide (`admin.activity.list`, state `waiting_approval`) to show its args.
 * Live-ness mirrors Activity: a ~300ms trailing debounce on the daemon event stream surfaces a
 * card under a second after `approval_pending`. Resolution is optimistic — it exits on answer and
 * returns with the uniform failure shape on a bridge failure.
 * The daemon auto-refuses an unanswered hand after 15 minutes (`DEFAULT_APPROVAL_TIMEOUT`); from
 * minute 10 the clock switches to the warning token and counts down.
 */

/** Trailing debounce for event-driven refetches: bursts coalesce. */
export const EVENT_REFRESH_MS = 300;

/** Daemon default before an unanswered hand times out (approval.rs). */
export const APPROVAL_TIMEOUT_S = 15 * 60;

/** Waiting time at which the card's clock turns to the warning token. */
export const WARNING_AFTER_S = 10 * 60;

/** How often waiting durations re-render. */
const CLOCK_TICK_MS = 10_000;

/** How many waiting requests the card join reads from the tide. */
const WAITING_LIMIT = 100;

// --- what approving means --------------------------------------------------

/** How a gated flow step names itself: `flow.step:<flow>/<step>`. */
const FLOW_STEP_PREFIX = "flow.step:";

/**
 * What the sentence renders in the data voice. Almost always the
 * capability verbatim — except a gated flow step, whose name carries two
 * facts a human reads separately: which flow, and which step of it.
 */
export function capabilityLabel(capability: string): string {
  if (!capability.startsWith(FLOW_STEP_PREFIX)) return capability;
  const [flow, ...rest] = capability.slice(FLOW_STEP_PREFIX.length).split("/");
  return rest.length > 0 ? `${flow} / ${rest.join("/")}` : flow;
}

/**
 * The serif sentence per capability family, split around the capability
 * so it can render in the data voice mid-sentence. The daemon registry
 * is still small, so the family read is a prefix heuristic with the
 * generic fallback the spec names.
 */
export function approvalMeaning(capability: string): { before: string; after: string } {
  // A gated flow step is its own family: the asker is the flow, not the
  // agent, and a yes is scoped to that one step of that one flow.
  if (capability.startsWith(FLOW_STEP_PREFIX)) {
    return {
      before: "The flow asks to run a gated step, ",
      after: ". Approving runs that step this once; remember keeps it for this flow.",
    };
  }
  switch (capability.split(".")[0]) {
    case "repo":
    case "git":
      return {
        before: "The agent asks to change this repository through ",
        after: ". Approving lets it alter shared history this once.",
      };
    case "fs":
    case "file":
    case "files":
      return {
        before: "The agent asks to touch files through ",
        after: ". Approving lets it write beyond its sandbox this once.",
      };
    case "net":
    case "http":
    case "web":
      return {
        before: "The agent asks to reach beyond this machine with ",
        after: ". Approving lets that traffic leave this once.",
      };
    case "shell":
    case "exec":
    case "proc":
      return {
        before: "The agent asks to run a command through ",
        after: ". Approving lets it execute this once.",
      };
    default:
      return {
        before: "The agent asks to run ",
        after: ". Approving lets it continue this once.",
      };
  }
}

// --- the waiting clock -----------------------------------------------------

/**
 * The card's clock. Calm ("raised 3m ago") until the hand has waited
 * 10 of its 15 minutes; from exactly `WARNING_AFTER_S` it turns urgent
 * and counts what's left before the daemon refuses on the human's
 * behalf.
 */
export function waitingClock(
  requestedTs: number,
  nowMs: number,
): { label: string; urgent: boolean } {
  const elapsed = Math.max(0, Math.floor(nowMs / 1000) - requestedTs);
  const rel = relativeTime(requestedTs, nowMs);
  const raised = rel === "now" ? "raised just now" : `raised ${rel}`;
  if (elapsed < WARNING_AFTER_S) return { label: raised, urgent: false };
  const remaining = APPROVAL_TIMEOUT_S - elapsed;
  if (remaining <= 0) return { label: `${raised} · timing out now`, urgent: true };
  return { label: `${raised} · times out in ${Math.ceil(remaining / 60)}m`, urgent: true };
}

/**
 * What the request will actually run, read off its recorded args: an
 * `argv` array joins into the command line; anything else renders as one
 * compact JSON line so the human sees the exact payload, not a paraphrase.
 */
export function commandLine(args: unknown): string | null {
  if (typeof args !== "object" || args === null) return null;
  const body = args as Record<string, unknown>;
  const argv = body.argv ?? body.run ?? body.command;
  if (Array.isArray(argv) && argv.every((part) => typeof part === "string")) {
    return argv.join(" ");
  }
  if (typeof argv === "string") return argv;
  const line = JSON.stringify(args);
  return line === "{}" ? null : line;
}

// --- one raised hand -------------------------------------------------------

function ApprovalCard({
  approval,
  request,
  now,
  busy,
  failure,
  onResolve,
}: {
  approval: PendingApproval;
  /** The request's own tide row, when the join found it. */
  request: ActivityRow | undefined;
  now: number;
  busy: boolean;
  failure: BridgeFailure | undefined;
  onResolve: (
    resolution: "approved" | "denied",
    options: { remember?: boolean; note?: string },
  ) => void;
}) {
  const [remember, setRemember] = useState(false);
  const [noteOpen, setNoteOpen] = useState(false);
  const [note, setNote] = useState("");
  const meaning = approvalMeaning(approval.capability);
  const clock = waitingClock(approval.requested_ts, now);
  const command = commandLine(request?.args);
  const options = () => ({ remember, ...(note.trim() ? { note: note.trim() } : {}) });

  return (
    <Panel
      ground="command"
      aria-label={`approval ${approval.capability}`}
      className="space-y-4 p-5"
    >
      <div className="flex items-start gap-3">
        <span
          aria-hidden="true"
          className="warm-badge flex size-8 shrink-0 items-center justify-center rounded-control text-warning"
        >
          <Hand className="size-4 text-warning" />
        </span>
        <div className="min-w-0 flex-1 space-y-1.5">
          <p className="truncate font-data text-base font-medium text-ink">
            {approval.capability}
          </p>
          <div className="flex min-w-0 flex-wrap items-center gap-2">
            <Badge tone="neutral">{approval.agent}</Badge>
            <span className="truncate font-data text-xs text-ink-faint" title={approval.repo}>
              {repoTail(approval.repo)}
            </span>
          </div>
        </div>
        <time
          dateTime={new Date(approval.requested_ts * 1000).toISOString()}
          title={exactTime(approval.requested_ts)}
          className={cn(
            "shrink-0 font-data text-xs tabular-nums",
            clock.urgent ? "text-warning" : "text-ink-faint",
          )}
        >
          {clock.label}
        </time>
      </div>

      <p className="max-w-md font-sans text-sm text-ink-muted">
        {meaning.before}
        <span className="font-data text-sm text-ink not-italic">
          {capabilityLabel(approval.capability)}
        </span>
        {meaning.after}
      </p>

      <dl aria-label="what will run" className="space-y-1 font-data text-xs text-ink-muted">
        <div className="flex gap-3">
          <dt className="w-20 shrink-0 text-ink-faint">Command</dt>
          <dd className="min-w-0 break-all text-ink">
            {command ?? (request ? "no arguments recorded" : "not in the tide yet")}
          </dd>
        </div>
        <div className="flex gap-3">
          <dt className="w-20 shrink-0 text-ink-faint">Repository</dt>
          <dd className="min-w-0 break-all">{approval.repo}</dd>
        </div>
      </dl>

      {failure && <FailureNote failure={failure} label="resolve failed" />}

      <div className="flex flex-wrap items-center gap-x-4 gap-y-2 border-t border-line pt-4">
        <Button size="sm" disabled={busy} onClick={() => onResolve("approved", options())}>
          Approve
        </Button>
        <Button
          size="sm"
          variant="secondary"
          disabled={busy}
          onClick={() => onResolve("denied", options())}
        >
          Deny
        </Button>
        <label className="flex min-h-8 cursor-pointer items-center gap-2 font-sans text-xs text-ink-muted">
          <input
            type="checkbox"
            checked={remember}
            onChange={(event) => setRemember(event.target.checked)}
            className="size-4.5 accent-accent-strong"
          />
          Remember this capability
        </label>
        {!noteOpen && (
          <Button
            size="sm"
            variant="ghost"
            className="ml-auto"
            onClick={() => setNoteOpen(true)}
          >
            Add note
          </Button>
        )}
      </div>

      {noteOpen && (
        <label className="block space-y-1">
          <span className="block font-sans text-xs text-ink-muted">
            Note — travels with the audit trail
          </span>
          <input
            aria-label="resolution note"
            // The ghost button just unmounted under the pointer; the field
            // it revealed inherits the keyboard.
            autoFocus
            value={note}
            onChange={(event) => setNote(event.target.value)}
            placeholder="Why you approved or denied"
            className={fieldClasses}
          />
        </label>
      )}
    </Panel>
  );
}

/** Skeleton hands while the first answer is on its way — tokens only. */
function RaisedSkeleton() {
  return (
    <div aria-hidden="true" className="max-w-2xl animate-pulse space-y-4 pt-4">
      {Array.from({ length: 2 }, (_, index) => (
        <div
          key={index}
          className="space-y-4 rounded-card border border-edge bg-surface-raised p-5"
        >
          <div className="flex items-center gap-3">
            <span className="size-8 rounded-pill bg-line" />
            <span className="h-3 w-40 rounded-pill bg-line" />
            <span className="ml-auto h-3 w-20 rounded-pill bg-line" />
          </div>
          <span className="block h-3 w-64 rounded-pill bg-line" />
          <div className="flex gap-3 border-t border-line pt-4">
            <span className="h-8 w-24 rounded-control bg-line" />
            <span className="h-8 w-20 rounded-control bg-line" />
          </div>
        </div>
      ))}
    </div>
  );
}

// --- the screen ------------------------------------------------------------

interface ResolveVars {
  requestId: string;
  resolution: "approved" | "denied";
  options: { remember?: boolean; note?: string };
}

export function ApprovalsScreen() {
  const queryClient = useQueryClient();
  const now = useNow(CLOCK_TICK_MS);
  const [resolving, setResolving] = useState<Record<string, "approved" | "denied">>({});
  const [failures, setFailures] = useState<Record<string, BridgeFailure>>({});

  const approvals = useQuery({ queryKey: APPROVALS_PENDING_KEY, queryFn: approvalsPending });
  // The waiting requests' own rows, for what each hand will run.
  const waiting = useQuery({
    queryKey: ["activity", "waiting"],
    queryFn: () => activityList({ state: "waiting_approval", limit: WAITING_LIMIT }),
    enabled: (approvals.data?.pending.length ?? 0) > 0,
  });

  // Stagger the entrance only for the first load; a hand raised later
  // slides in alone, undelayed.
  const firstPaintDone = useRef(false);
  const stagger = !firstPaintDone.current;
  useEffect(() => {
    if (approvals.data) firstPaintDone.current = true;
  }, [approvals.data]);

  // The event stream nudges the query: one trailing ~300ms window per
  // burst, then a single refetch (same contract as Activity's tide).
  useEffect(() => {
    let timer: number | undefined;
    let cancelled = false;
    let unlisten: (() => void) | undefined;
    subscribeEvents(() => {
      if (timer !== undefined) return;
      timer = window.setTimeout(() => {
        timer = undefined;
        void queryClient.invalidateQueries({ queryKey: ["approvals"] });
        void queryClient.invalidateQueries({ queryKey: ["activity", "waiting"] });
      }, EVENT_REFRESH_MS);
    })
      .then((stop) => {
        if (cancelled) stop();
        else unlisten = stop;
      })
      .catch(() => {
        // No bridge (browser dev) or no stream: nothing to keep live.
      });
    return () => {
      cancelled = true;
      if (timer !== undefined) clearTimeout(timer);
      unlisten?.();
    };
  }, [queryClient]);

  const resolve = useMutation({
    mutationFn: ({ requestId, resolution, options }: ResolveVars) =>
      approvalsResolve(requestId, resolution, options),
    onMutate: async ({ requestId, resolution }) => {
      // Optimistic exit: the card leaves the moment the human answers.
      setResolving((prev) => ({ ...prev, [requestId]: resolution }));
      setFailures((prev) => {
        const next = { ...prev };
        delete next[requestId];
        return next;
      });
      await queryClient.cancelQueries({ queryKey: APPROVALS_PENDING_KEY });
      const previous = queryClient.getQueryData<{ pending: PendingApproval[] }>(
        APPROVALS_PENDING_KEY,
      );
      queryClient.setQueryData<{ pending: PendingApproval[] }>(
        APPROVALS_PENDING_KEY,
        (old) =>
          old && { pending: old.pending.filter((hand) => hand.request_id !== requestId) },
      );
      return { previous };
    },
    onError: (error, { requestId }, context) => {
      // The hand comes back, carrying the uniform failure shape inline.
      if (context?.previous) queryClient.setQueryData(APPROVALS_PENDING_KEY, context.previous);
      setFailures((prev) => ({ ...prev, [requestId]: toBridgeFailure(error) }));
    },
    onSettled: (_reply, _error, { requestId }) => {
      setResolving((prev) => {
        const next = { ...prev };
        delete next[requestId];
        return next;
      });
      void queryClient.invalidateQueries({ queryKey: ["approvals"] });
      void queryClient.invalidateQueries({ queryKey: ["activity"] });
    },
  });

  const pending = approvals.data?.pending ?? [];
  const count = approvals.data?.pending.length;
  const failure = approvals.isError ? toBridgeFailure(approvals.error) : null;

  return (
    <div className="page-workspace">
      <PageHeader>
        <h1 className="font-sans text-title font-semibold text-ink">Approvals</h1>
        <p className="text-sm text-ink-muted">
          {count === undefined
            ? "Review agent requests before they run."
            : `${count} request${count === 1 ? "" : "s"} awaiting review`}
        </p>
        {pending.length > 0 && (
          <p className="text-xs text-ink-muted">
            Oldest first · unanswered requests time out in 15 minutes.
          </p>
        )}
      </PageHeader>
      <div className="page-content" role="region" aria-label="Approval queue" tabIndex={0}>
        {failure && (
          <div className="mt-2">
            <FailureNote failure={failure} label="disconnected">
              <Button
                size="sm"
                variant="secondary"
                disabled={approvals.isFetching}
                onClick={() => void approvals.refetch()}
              >
                Retry
              </Button>
            </FailureNote>
          </div>
        )}

        {!failure && approvals.isPending && <RaisedSkeleton />}

        {!failure && !approvals.isPending && pending.length === 0 && (
          <div className="flex flex-1 flex-col items-start justify-center gap-4 py-16">
            <span
              aria-hidden="true"
              className="flex size-10 items-center justify-center rounded-pill border border-line bg-surface-raised"
            >
              <Hand className="size-5 text-ink-faint" />
            </span>
            <p className="max-w-md font-sans text-lg text-ink-muted">
              No requests are waiting for review.
            </p>
            <p className="max-w-md font-sans text-sm text-ink-muted">
              When an agent needs a yes, its request appears here; only this app can answer it.
            </p>
          </div>
        )}

        {!failure && pending.length > 0 && (
          <>
            <ul className="max-w-content space-y-4">
              <AnimatePresence>
                {pending.map((hand, index) => (
                  <motion.li
                    key={hand.request_id}
                    initial={{ opacity: 0, y: 8 }}
                    animate={{
                      opacity: 1,
                      y: 0,
                      transition: {
                        duration: 0.18,
                        ease: "easeOut",
                        delay: stagger ? Math.min(index, 8) * 0.05 : 0,
                      },
                    }}
                    exit={{ opacity: 0, transition: { duration: 0.15, ease: "easeOut" } }}
                  >
                    <ApprovalCard
                      approval={hand}
                      request={waiting.data?.requests.find((row) => row.id === hand.request_id)}
                      now={now}
                      busy={resolving[hand.request_id] !== undefined}
                      failure={failures[hand.request_id]}
                      onResolve={(resolution, options) =>
                        resolve.mutate({ requestId: hand.request_id, resolution, options })
                      }
                    />
                  </motion.li>
                ))}
              </AnimatePresence>
            </ul>
          </>
        )}
      </div>
    </div>
  );
}
