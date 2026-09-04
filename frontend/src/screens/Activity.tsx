import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useNavigate, useSearch } from "@tanstack/react-router";
import { ChevronRight } from "lucide-react";
import { AnimatePresence, motion, useReducedMotion } from "motion/react";
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
import { COMPRESS_CAPABILITY, EvidenceBand } from "./EvidenceBand";
import { EvidenceStrip } from "./EvidenceStrip";
import {
  STATE_FILTERS,
  matchesStateFilter,
  serverStateFor,
  type StateFilter,
} from "./activitySearch";

/**
 * Activity — the default screen: the tide. The owner watches the water
 * from here; every request the daemon has seen rolls in as a compact row
 * (~44px): state dot, capability in the data voice, repo tail,
 * truth-vocabulary badge, live relative age. A row opens into its detail
 * (args JSON, id, exact stamps) in place.
 *
 * Rows run in lanes, one per agent, alphabetical so lanes never trade
 * places, newest on top within a lane: two agents working at once read as
 * two currents rather than one interleaved list. Chips under the state
 * lens narrow to an agent or a repo (the same `?agent=` / `?repo=` params
 * a shared URL carries).
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
      waiting_approval: "warm-marker bg-warning",
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

/** Sorted, de-duplicated chip values: registry ∪ the rows ∪ the lens. */
function chipOptions(
  registry: string[],
  present: string[],
  active: string | undefined,
): string[] {
  const values = new Set([...registry, ...present]);
  if (active !== undefined) values.add(active);
  return [...values].sort();
}

/** One toggle in the chip bar; pressed reads as the active lens. */
function Chip({
  label,
  text,
  title,
  active,
  onToggle,
}: {
  label: string;
  text: string;
  title?: string;
  active: boolean;
  onToggle: () => void;
}) {
  return (
    <button
      type="button"
      aria-label={label}
      aria-pressed={active}
      title={title}
      onClick={onToggle}
      className={cn(
        "h-7 max-w-40 truncate rounded-control px-2.5 font-data text-xs transition-colors duration-100",
        active ? "bg-accent-soft text-ink" : "text-ink-faint hover:text-ink",
      )}
    >
      {text}
    </button>
  );
}

/**
 * Agents then repos, one chip each. Clicking a pressed chip clears it, so
 * the bar is its own "all". Options include whatever the rows and the URL
 * carry, not just the caller registry: a lane never lacks its chip, and a
 * lens shared from another machine stays visible and clearable.
 */
function ChipBar({
  agents,
  repos,
  agent,
  repo,
  onAgent,
  onRepo,
}: {
  agents: string[];
  repos: string[];
  agent: string | undefined;
  repo: string | undefined;
  onAgent: (next: string | undefined) => void;
  onRepo: (next: string | undefined) => void;
}) {
  if (agents.length === 0 && repos.length === 0) return null;
  return (
    <div role="group" aria-label="chips" className="flex flex-wrap items-center gap-1">
      {agents.map((option) => (
        <Chip
          key={`agent:${option}`}
          label={`agent ${option}`}
          text={option}
          active={option === agent}
          onToggle={() => onAgent(option === agent ? undefined : option)}
        />
      ))}
      {agents.length > 0 && repos.length > 0 && (
        <span aria-hidden="true" className="mx-1 h-4 w-px bg-line" />
      )}
      {repos.map((option) => (
        <Chip
          key={`repo:${option}`}
          label={`repo ${repoTail(option)}`}
          text={repoTail(option)}
          title={option}
          active={option === repo}
          onToggle={() => onRepo(option === repo ? undefined : option)}
        />
      ))}
    </div>
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
            "h-full rounded-control px-2.5 font-data text-xs transition-colors duration-100",
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
    <>
      <button
        type="button"
        aria-expanded={expanded}
        onClick={onToggle}
        className="group flex h-9 w-full items-center gap-2 rounded-control px-2 text-left transition-colors duration-100 hover:bg-accent-soft/40"
      >
        <ChevronRight
          aria-hidden="true"
          className={cn(
            "size-3.5 shrink-0 text-ink-faint transition-transform duration-100",
            expanded && "rotate-90",
          )}
        />
        <span aria-hidden="true" className={stateDot({ state: row.state })} />
        <span className="min-w-0 flex-1 truncate font-data text-sm text-ink">
          {row.capability}
        </span>
        <span
          className="lane-repo w-28 shrink-0 truncate font-data text-xs text-ink-faint"
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
          <dl className="activity-details flex flex-wrap gap-x-6 gap-y-1 font-data text-xs text-ink-muted">
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
          <EvidenceStrip requestId={row.id} />
        </div>
      )}
    </>
  );
}

// --- lanes -----------------------------------------------------------------

/** At most this many rows per lane; the daemon clamps the tide to 100. */
const LANE_ROW_CAP = 50;

/** One agent's current: its rows newest first, and when it last moved. */
interface Lane {
  agent: string;
  rows: ActivityRow[];
  latest: number;
}

/**
 * Rows into lanes: one per agent present, alphabetical so a lane never
 * trades places with its neighbour while the owner is reading it.
 */
function toLanes(rows: ActivityRow[]): Lane[] {
  const byAgent = new Map<string, ActivityRow[]>();
  for (const row of rows) {
    const lane = byAgent.get(row.agent);
    if (lane) lane.push(row);
    else byAgent.set(row.agent, [row]);
  }
  return [...byAgent.entries()]
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([agent, laneRows]) => {
      const newestFirst = [...laneRows].sort(
        (left, right) => right.created_ts - left.created_ts,
      );
      return {
        agent,
        rows: newestFirst.slice(0, LANE_ROW_CAP),
        latest: newestFirst[0]?.created_ts ?? 0,
      };
    });
}

/**
 * A row's enter frame: it slides 4px down into its lane. Reduced motion
 * answers `false`, which mounts the row at rest — the arrival still
 * happens, it just doesn't travel.
 */
export function rowEnter(reduced: boolean | null): false | { opacity: number; y: number } {
  return reduced ? false : { opacity: 0, y: -4 };
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
  // The settle: a row lands in 180ms, a lane (or a row a chip hides)
  // leaves in 120ms. Reduced motion keeps the arrivals but drops the
  // travel — nothing slides, nothing lingers on its way out.
  const reduced = useReducedMotion();
  const enter = rowEnter(reduced);
  const settle = { duration: reduced ? 0 : 0.18, ease: "easeOut" } as const;
  const fade = { opacity: 0, transition: { duration: reduced ? 0 : 0.12 } };
  const [expandedId, setExpandedId] = useState<string | null>(null);
  // A compression answers with its report, not with the request id it
  // was filed under. So the band raises this flag, and the next tide to
  // land opens the newest compress row — which is where its evidence is.
  const [pendingExpand, setPendingExpand] = useState(false);

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
        // The observatory polls this op (and `status`) every few
        // seconds; without this the newest-N window fills with the GUI
        // watching itself and the real lanes wash out.
        hide_probes: true,
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

  const requests = activity.data?.requests;
  useEffect(() => {
    if (!pendingExpand || !requests) return;
    const compressed = requests.find((row) => row.capability === COMPRESS_CAPABILITY);
    if (!compressed) return;
    setExpandedId(compressed.id);
    setPendingExpand(false);
  }, [pendingExpand, requests]);

  const rows = useMemo(
    () => (requests ?? []).filter((row) => matchesStateFilter(row.state, stateFilter)),
    [requests, stateFilter],
  );
  const lanes = useMemo(() => toLanes(rows), [rows]);

  const repoOptions = useMemo(
    () =>
      chipOptions(
        (callers.data?.callers ?? []).map((caller) => caller.repo),
        rows.map((row) => row.repo),
        search.repo,
      ),
    [callers.data, rows, search.repo],
  );
  const agentOptions = useMemo(
    () =>
      chipOptions(
        (callers.data?.callers ?? []).map((caller) => caller.agent),
        rows.map((row) => row.agent),
        search.agent,
      ),
    [callers.data, rows, search.agent],
  );

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

  const filtered =
    search.repo !== undefined || search.agent !== undefined || stateFilter !== "all";
  const failure = activity.isError ? toBridgeFailure(activity.error) : null;

  return (
    <div className="flex min-h-full flex-col px-6 pb-6">
      <header className="sticky top-0 z-10 space-y-3 bg-surface pt-6 pb-3">
        <p className="font-data text-xs tracking-widest text-ink-faint uppercase">
          lifeguard tower · watching
        </p>
        <div className="flex flex-wrap items-center gap-3">
          <h1 className="mr-auto font-display text-title font-semibold text-ink">Activity</h1>
          <StateSegments value={stateFilter} onChange={(state) => setFilters({ state })} />
        </div>
        <ChipBar
          agents={agentOptions}
          repos={repoOptions}
          agent={search.agent}
          repo={search.repo}
          onAgent={(agent) => setFilters({ agent })}
          onRepo={(repo) => setFilters({ repo })}
        />
        <div className="border-b border-line" />
      </header>

      <EvidenceBand onCompressed={() => setPendingExpand(true)} />

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
          <div role="group" aria-label="lanes" className="activity-lanes grid gap-4">
            <AnimatePresence initial={false}>
              {lanes.map((lane) => (
                <motion.section
                  key={lane.agent}
                  layout
                  aria-label={lane.agent}
                  exit={fade}
                  transition={settle}
                  className="activity-lane min-w-0 rounded-card border border-line bg-surface-raised p-2"
                >
                  <header className="flex items-center gap-2 px-2 pb-2">
                    <Badge tone="accent">{lane.agent}</Badge>
                    <span className="font-data text-xs text-ink-faint">{lane.rows.length}</span>
                    <span className="ml-auto font-data text-xs text-ink-faint">
                      {relativeTime(lane.latest, now)}
                    </span>
                  </header>
                  <ul className="divide-y divide-line">
                    <AnimatePresence initial={false}>
                      {lane.rows.map((row) => (
                        <motion.li
                          key={row.id}
                          layout="position"
                          initial={enter}
                          animate={{ opacity: 1, y: 0 }}
                          exit={fade}
                          transition={settle}
                        >
                          <TideRow
                            row={row}
                            now={now}
                            expanded={expandedId === row.id}
                            onToggle={() =>
                              setExpandedId(expandedId === row.id ? null : row.id)
                            }
                          />
                        </motion.li>
                      ))}
                    </AnimatePresence>
                  </ul>
                </motion.section>
              ))}
            </AnimatePresence>
          </div>
          <p className="mt-3 font-data text-xs text-ink-faint">
            {rows.length} request{rows.length === 1 ? "" : "s"} · {lanes.length} lane
            {lanes.length === 1 ? "" : "s"} · newest first · own probes hidden
          </p>
        </>
      )}
    </div>
  );
}
