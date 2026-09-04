import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Hand, LoaderCircle } from "lucide-react";
import { AnimatePresence, motion } from "motion/react";
import { useEffect, useRef, useState } from "react";
import { Badge } from "../components/ui/Badge";
import { Button } from "../components/ui/Button";
import { Panel } from "../components/ui/Panel";
import { PageHeader } from "../components/ui/PageHeader";
import { cn } from "../lib/cn";
import {
  approvalsPending,
  approvalsResolve,
  subscribeEvents,
  toBridgeFailure,
  type BridgeFailure,
  type PendingApproval,
} from "../lib/ipc";
import { exactTime, relativeTime } from "../lib/time";

/**
 * Approvals — the raised hand. Each pending approval is Pam holding a
 * request still until the human answers, so every one gets a raised card
 * (never a table row): capability in the data voice, requester identity,
 * a serif sentence saying what a yes means, and the two answers. Approve
 * is the view's one primary; Deny stays quiet furniture until hovered —
 * refusing is legitimate, so it never has to shout.
 *
 * Live-ness mirrors Activity: the daemon event stream nudges the query
 * through one ~300ms trailing debounce, so a raised hand surfaces well
 * under a second after its `approval_pending` event.
 *
 * Resolution is optimistic: the card leaves the list the moment the
 * human answers (spinner riding the exit), and on a bridge failure it
 * returns carrying the uniform failure shape inline.
 *
 * The daemon auto-refuses an unanswered hand after 15 minutes
 * (`DEFAULT_APPROVAL_TIMEOUT`); from minute 10 the card's clock shifts
 * to the warning token and starts counting the time left.
 */

/** Trailing debounce for event-driven refetches: bursts coalesce. */
export const EVENT_REFRESH_MS = 300;

/** Daemon default before an unanswered hand times out (approval.rs). */
export const APPROVAL_TIMEOUT_S = 15 * 60;

/** Waiting time at which the card's clock turns to the warning token. */
export const WARNING_AFTER_S = 10 * 60;

/** How often waiting durations re-render. */
const CLOCK_TICK_MS = 10_000;

/** A ticking now, for live waiting durations without per-card timers. */
function useNow(intervalMs: number): number {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const timer = setInterval(() => setNow(Date.now()), intervalMs);
    return () => clearInterval(timer);
  }, [intervalMs]);
  return now;
}

// --- what approving means --------------------------------------------------

/** How a gated flow step names itself: `flow.step:<flow>/<step>`. */
export const FLOW_STEP_PREFIX = "flow.step:";

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

/** Last path segment; the full path rides on the title attribute. */
function repoTail(repo: string): string {
  const segments = repo.split("/").filter(Boolean);
  return segments[segments.length - 1] ?? repo;
}

// --- one raised hand -------------------------------------------------------

function ApprovalCard({
  approval,
  now,
  resolving,
  failure,
  onResolve,
}: {
  approval: PendingApproval;
  now: number;
  resolving: "approved" | "denied" | undefined;
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
  const busy = resolving !== undefined;

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

      {failure && (
        <div className="space-y-1 rounded-card border border-danger/40 bg-danger-soft p-3">
          <p className="font-data text-xs text-danger">resolve failed · {failure.cause}</p>
          <p className="font-sans text-sm text-ink">{failure.detail}.</p>
          <p className="font-data text-xs text-ink-muted">{failure.recovery}</p>
        </div>
      )}

      <div className="flex flex-wrap items-center gap-x-4 gap-y-2 border-t border-line pt-4">
        <Button size="sm" disabled={busy} onClick={() => onResolve("approved", { remember })}>
          {resolving === "approved" && (
            <LoaderCircle aria-hidden="true" className="size-3.5 animate-spin" />
          )}
          Approve
        </Button>
        <Button
          size="sm"
          variant="ghost"
          disabled={busy}
          onClick={() => onResolve("denied", note.trim() ? { note: note.trim() } : {})}
          className="hover:bg-danger-soft hover:text-danger active:bg-danger-soft"
        >
          {resolving === "denied" && (
            <LoaderCircle aria-hidden="true" className="size-3.5 animate-spin" />
          )}
          Deny
        </Button>
        <label className="flex cursor-pointer items-center gap-2 font-data text-xs text-ink-muted">
          <input
            type="checkbox"
            checked={remember}
            onChange={(event) => setRemember(event.target.checked)}
            className="size-3.5 accent-accent-strong"
          />
          remember this capability
        </label>
        {!noteOpen && (
          <button
            type="button"
            onClick={() => setNoteOpen(true)}
            className="ml-auto font-data text-xs text-ink-faint transition-colors duration-150 hover:text-ink"
          >
            add note
          </button>
        )}
      </div>

      {noteOpen && (
        <input
          aria-label="resolution note"
          // The ghost button just unmounted under the pointer; the field
          // it revealed inherits the keyboard.
          autoFocus
          value={note}
          onChange={(event) => setNote(event.target.value)}
          placeholder="why — this line travels with the audit trail"
          className="h-8 w-full rounded-control field-control border border-control-line bg-inset px-2.5 font-data text-xs text-ink placeholder:text-ink-faint"
        />
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

  const approvals = useQuery({ queryKey: ["approvals"], queryFn: approvalsPending });

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
      await queryClient.cancelQueries({ queryKey: ["approvals"] });
      const previous = queryClient.getQueryData<{ pending: PendingApproval[] }>(["approvals"]);
      queryClient.setQueryData<{ pending: PendingApproval[] }>(
        ["approvals"],
        (old) =>
          old && { pending: old.pending.filter((hand) => hand.request_id !== requestId) },
      );
      return { previous };
    },
    onError: (error, { requestId }, context) => {
      // The hand comes back, carrying the uniform failure shape inline.
      if (context?.previous) queryClient.setQueryData(["approvals"], context.previous);
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
    <div className="flex min-h-full flex-col px-6 pb-6">
      <PageHeader>
        <h1 className="font-sans text-title font-semibold text-ink">Approvals</h1>
        <p className="text-sm text-ink-muted">
          {count === undefined
            ? "Review agent requests before they run."
            : `${count} request${count === 1 ? "" : "s"} awaiting review`}
        </p>
      </PageHeader>

      {failure && (
        <section className="mt-2 max-w-xl space-y-2 rounded-card border border-danger/40 bg-danger-soft p-4">
          <p className="font-data text-xs text-danger">disconnected · {failure.cause}</p>
          <p className="font-sans text-sm text-ink">{failure.detail}.</p>
          <p className="font-data text-xs text-ink-muted">{failure.recovery}</p>
        </section>
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
            No hands raised. When an agent needs your yes, it appears here first.
          </p>
          <p className="font-data text-xs text-ink-faint">
            approvals resolve only in this app — no agent or CLI can answer for you
          </p>
        </div>
      )}

      {!failure && pending.length > 0 && (
        <>
          <ul className="max-w-4xl space-y-4 pt-5">
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
                    now={now}
                    resolving={resolving[hand.request_id]}
                    failure={failures[hand.request_id]}
                    onResolve={(resolution, options) =>
                      resolve.mutate({ requestId: hand.request_id, resolution, options })
                    }
                  />
                </motion.li>
              ))}
            </AnimatePresence>
          </ul>
          <p className="mt-4 font-data text-xs text-ink-faint">
            {pending.length} waiting · oldest first · unanswered hands time out in 15m
          </p>
        </>
      )}
    </div>
  );
}
