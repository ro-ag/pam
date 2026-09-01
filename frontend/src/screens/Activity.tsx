import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useNavigate, useSearch } from "@tanstack/react-router";
import { ChevronRight } from "lucide-react";
import { useEffect, useMemo, useState, type ReactNode } from "react";
import { Badge, type BadgeProps } from "../components/ui/Badge";
import { Button } from "../components/ui/Button";
import { cn, cva } from "../lib/cn";
import {
  activityList,
  callersList,
  subscribeEvents,
  toBridgeFailure,
  type ActivityRow,
} from "../lib/ipc";
import { exactTime, relativeTime } from "../lib/time";
import {
  STATE_FILTERS,
  matchesStateFilter,
  serverStateFor,
  type StateFilter,
} from "./activitySearch";

/**
 * Activity — the default screen: the tide. The owner watches the water
 * from here; every request the daemon has seen rolls in newest-first as a
 * compact row (~44px): state dot, capability in the data voice, agent
 * chip, repo tail, truth-vocabulary badge, live relative age. A row opens
 * into its detail (args JSON, id, exact stamps) in place.
 *
 * Live-ness: the daemon event stream invalidates the queries through one
 * ~300ms trailing debounce, so a burst of events becomes one refetch and
 * a new request is visible well under a second after its event.
 *
 * Plain list, no virtualization: the daemon clamps the reply to 100 rows
 * (v0 volumes) and the panel already scrolls.
 *
 * Follow-up (blocked on IPC surface): per-request audit trail in the
 * detail view — there is no `admin.audit.*` op on the bridge yet.
 */

/** Rows requested per fetch; the store clamps to the same bound. */
const LIST_LIMIT = 100;

/** Trailing debounce for event-driven refetches: bursts coalesce. */
export const EVENT_REFRESH_MS = 300;

/** How often the "3m ago" column re-renders. */
const CLOCK_TICK_MS = 30_000;

/** A ticking now, for live relative ages without a per-row timer. */
function useNow(intervalMs: number): number {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const timer = setInterval(() => setNow(Date.now()), intervalMs);
    return () => clearInterval(timer);
  }, [intervalMs]);
  return now;
}

// --- state → visuals -------------------------------------------------------

/**
 * The state dot. Breathing is reserved for the two states where the water
 * is actually moving — running and a raised hand — everything settled sits
 * still. A refusal is a hollow ring (the beautiful refusal keeps its own
 * silhouette); a failure is solid danger.
 */
const stateDot = cva("size-2 shrink-0 rounded-pill", {
  variants: {
    state: {
      queued: "bg-ink-faint",
      running: "animate-breathe bg-accent",
      waiting_approval: "animate-breathe bg-warning",
      done: "bg-success",
      refused: "border border-danger bg-transparent",
      failed: "bg-danger",
    },
  },
});

/** Truth vocabulary → badge tone (mirrors the Settings style proof). */
const OUTCOME_TONES: Record<string, BadgeProps["tone"]> = {
  solved: "success",
  verified: "success",
  changed: "accent",
  unresolved: "warning",
  blocked: "danger",
};

/** The one badge per row: verdict when terminal, state otherwise. */
function rowBadge(row: ActivityRow): { label: string; tone: BadgeProps["tone"] } {
  switch (row.state) {
    case "queued":
      return { label: "queued", tone: "neutral" };
    case "running":
      return { label: "running", tone: "accent" };
    case "waiting_approval":
      return { label: "approval held", tone: "warning" };
    case "refused":
      return { label: row.outcome ?? "refused", tone: "danger" };
    case "failed":
      return { label: row.outcome ?? "failed", tone: "danger" };
    case "done":
      return row.outcome
        ? { label: row.outcome, tone: OUTCOME_TONES[row.outcome] ?? "neutral" }
        : { label: "done", tone: "success" };
  }
}

/** Last path segment; the full path rides on the title attribute. */
function repoTail(repo: string): string {
  const segments = repo.split("/").filter(Boolean);
  return segments[segments.length - 1] ?? repo;
}

// --- filter controls -------------------------------------------------------

const selectClasses =
  "h-8 max-w-40 truncate rounded-control border border-line bg-surface-raised px-2 " +
  "font-data text-xs text-ink-muted";

function FilterSelect({
  label,
  value,
  options,
  allLabel,
  onChange,
}: {
  label: string;
  value: string;
  options: string[];
  allLabel: string;
  onChange: (next: string) => void;
}) {
  // A value carried in from a shared URL stays selectable even when the
  // caller registry doesn't (or can't) list it.
  const listed = value === "" || options.includes(value) ? options : [value, ...options];
  return (
    <select
      aria-label={label}
      value={value}
      onChange={(event) => onChange(event.target.value)}
      className={selectClasses}
    >
      <option value="">{allLabel}</option>
      {listed.map((option) => (
        <option key={option} value={option}>
          {option}
        </option>
      ))}
    </select>
  );
}

function StateSegments({
  value,
  onChange,
}: {
  value: StateFilter;
  onChange: (next: StateFilter) => void;
}) {
  return (
    <div
      role="group"
      aria-label="state filter"
      className="flex h-8 items-center gap-0.5 rounded-control border border-line bg-surface-raised p-0.5"
    >
      {STATE_FILTERS.map((filter) => (
        <button
          key={filter}
          type="button"
          aria-pressed={filter === value}
          onClick={() => onChange(filter)}
          className={cn(
            "h-full rounded-control px-2.5 font-data text-xs transition-colors duration-150",
            filter === value ? "bg-accent-soft text-ink" : "text-ink-faint hover:text-ink",
          )}
        >
          {filter}
        </button>
      ))}
    </div>
  );
}

// --- tide rows -------------------------------------------------------------

function TideRow({
  row,
  now,
  expanded,
  onToggle,
}: {
  row: ActivityRow;
  now: number;
  expanded: boolean;
  onToggle: () => void;
}) {
  const badge = rowBadge(row);
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
        <span aria-hidden="true" className={stateDot({ state: row.state })} />
        <span className="min-w-0 flex-1 truncate font-data text-sm text-ink">
          {row.capability}
        </span>
        <Badge tone="neutral" className="hidden shrink-0 sm:inline-flex">
          {row.agent}
        </Badge>
        <span
          className="hidden w-28 truncate font-data text-xs text-ink-faint md:block"
          title={row.repo}
        >
          {repoTail(row.repo)}
        </span>
        <Badge tone={badge.tone} className="shrink-0">
          {badge.label}
        </Badge>
        <time
          dateTime={new Date(row.created_ts * 1000).toISOString()}
          title={exactTime(row.created_ts)}
          className="w-16 shrink-0 text-right font-data text-xs tabular-nums text-ink-faint"
        >
          {relativeTime(row.created_ts, now)}
        </time>
      </button>
      {expanded && (
        <div className="mt-1 mb-3 ml-9 space-y-3 border-l border-line pl-4">
          <dl className="flex flex-wrap gap-x-6 gap-y-1 font-data text-xs text-ink-muted">
            <div className="flex gap-1.5">
              <dt className="text-ink-faint">id</dt>
              <dd>{row.id}</dd>
            </div>
            <div className="flex gap-1.5">
              <dt className="text-ink-faint">created</dt>
              <dd>{exactTime(row.created_ts)}</dd>
            </div>
            <div className="flex gap-1.5">
              <dt className="text-ink-faint">updated</dt>
              <dd>{exactTime(row.updated_ts)}</dd>
            </div>
            <div className="flex gap-1.5">
              <dt className="text-ink-faint">repo</dt>
              <dd>{row.repo}</dd>
            </div>
          </dl>
          {row.args != null ? (
            <pre className="overflow-x-auto rounded-card border border-line bg-chrome p-3 font-data text-xs leading-relaxed text-ink-muted">
              {JSON.stringify(row.args, null, 2)}
            </pre>
          ) : (
            <p className="font-data text-xs text-ink-faint">no args recorded</p>
          )}
        </div>
      )}
    </li>
  );
}

/** Skeleton tide while the first answer is on its way — tokens only. */
function TideSkeleton() {
  return (
    <ul aria-hidden="true" className="animate-pulse divide-y divide-line">
      {Array.from({ length: 8 }, (_, index) => (
        <li key={index} className="flex h-11 items-center gap-3 px-2">
          <span className="size-2 shrink-0 rounded-pill bg-line" />
          <span className="h-3 w-40 rounded-pill bg-line" />
          <span className="ml-auto h-3 w-24 rounded-pill bg-line" />
          <span className="h-3 w-12 rounded-pill bg-line" />
        </li>
      ))}
    </ul>
  );
}

/** Pam speaks in the serif; machine facts never do. */
function PamMoment({ children, aside }: { children: ReactNode; aside?: ReactNode }) {
  return (
    <div className="flex flex-1 flex-col items-start justify-center gap-4 py-16">
      <p className="max-w-md font-voice text-lg text-ink-muted italic">{children}</p>
      {aside}
    </div>
  );
}

// --- the screen ------------------------------------------------------------

export function ActivityScreen() {
  const search = useSearch({ from: "/activity" });
  const navigate = useNavigate({ from: "/activity" });
  const queryClient = useQueryClient();
  const now = useNow(CLOCK_TICK_MS);
  const [expandedId, setExpandedId] = useState<string | null>(null);

  const stateFilter: StateFilter = search.state ?? "all";
  const serverState = serverStateFor(stateFilter);

  const activity = useQuery({
    queryKey: ["activity", search.repo ?? null, search.agent ?? null, serverState ?? null],
    queryFn: () =>
      activityList({
        limit: LIST_LIMIT,
        repo: search.repo,
        agent: search.agent,
        state: serverState,
      }),
    // Keep the previous tide on screen while a narrower lens loads.
    placeholderData: (previous) => previous,
  });

  const callers = useQuery({ queryKey: ["callers"], queryFn: callersList });

  // The event stream nudges the queries: one trailing ~300ms window per
  // burst, then a single refetch. No per-row surgery.
  useEffect(() => {
    let timer: number | undefined;
    let cancelled = false;
    let unlisten: (() => void) | undefined;
    subscribeEvents(() => {
      if (timer !== undefined) return;
      timer = window.setTimeout(() => {
        timer = undefined;
        void queryClient.invalidateQueries({ queryKey: ["activity"] });
        void queryClient.invalidateQueries({ queryKey: ["callers"] });
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

  const repoOptions = useMemo(() => {
    const repos = new Set((callers.data?.callers ?? []).map((caller) => caller.repo));
    return [...repos].sort();
  }, [callers.data]);
  const agentOptions = useMemo(() => {
    const agents = new Set((callers.data?.callers ?? []).map((caller) => caller.agent));
    return [...agents].sort();
  }, [callers.data]);

  const setFilters = (patch: {
    repo?: string | undefined;
    agent?: string | undefined;
    state?: StateFilter;
  }) => {
    void navigate({
      replace: true,
      search: (previous) => ({
        ...previous,
        ...("repo" in patch ? { repo: patch.repo || undefined } : {}),
        ...("agent" in patch ? { agent: patch.agent || undefined } : {}),
        ...(patch.state !== undefined
          ? { state: patch.state === "all" ? undefined : patch.state }
          : {}),
      }),
    });
  };

  const rows = (activity.data?.requests ?? []).filter((row) =>
    matchesStateFilter(row.state, stateFilter),
  );
  const filtered =
    search.repo !== undefined || search.agent !== undefined || stateFilter !== "all";
  const failure = activity.isError ? toBridgeFailure(activity.error) : null;

  return (
    <div className="flex min-h-full flex-col px-8 pb-6">
      <header className="sticky top-0 z-10 space-y-3 bg-surface pt-8 pb-3">
        <p className="font-data text-xs tracking-widest text-ink-faint uppercase">
          lifeguard tower · watching
        </p>
        <div className="flex flex-wrap items-center gap-3">
          <h1 className="mr-auto font-display text-title font-semibold text-ink">Activity</h1>
          <FilterSelect
            label="repo filter"
            value={search.repo ?? ""}
            options={repoOptions}
            allLabel="all repos"
            onChange={(repo) => setFilters({ repo })}
          />
          <FilterSelect
            label="agent filter"
            value={search.agent ?? ""}
            options={agentOptions}
            allLabel="all agents"
            onChange={(agent) => setFilters({ agent })}
          />
          <StateSegments value={stateFilter} onChange={(state) => setFilters({ state })} />
        </div>
        <div className="border-b border-line" />
      </header>

      {failure && (
        <section className="mt-2 max-w-xl space-y-2 rounded-card border border-danger/40 bg-danger-soft p-4">
          <p className="font-data text-xs tracking-widest text-danger uppercase">
            disconnected · {failure.cause}
          </p>
          <p className="font-voice text-base text-ink italic">{failure.detail}.</p>
          <p className="font-data text-xs text-ink-muted">{failure.recovery}</p>
        </section>
      )}

      {!failure && activity.isPending && <TideSkeleton />}

      {!failure && !activity.isPending && rows.length === 0 && (
        <PamMoment
          aside={
            filtered && (
              <Button
                variant="ghost"
                size="sm"
                onClick={() => setFilters({ repo: undefined, agent: undefined, state: "all" })}
              >
                Clear filters
              </Button>
            )
          }
        >
          {filtered
            ? "Nothing in the water matches this lens. Widen it, or let it go."
            : "I’m watching the water. Nothing needs your hand right now — when something does, I’ll raise mine first."}
        </PamMoment>
      )}

      {!failure && rows.length > 0 && (
        <>
          <ul className="divide-y divide-line">
            {rows.map((row) => (
              <TideRow
                key={row.id}
                row={row}
                now={now}
                expanded={expandedId === row.id}
                onToggle={() => setExpandedId(expandedId === row.id ? null : row.id)}
              />
            ))}
          </ul>
          <p className="mt-3 font-data text-xs text-ink-faint">
            {rows.length} request{rows.length === 1 ? "" : "s"} · newest first
          </p>
        </>
      )}
    </div>
  );
}
