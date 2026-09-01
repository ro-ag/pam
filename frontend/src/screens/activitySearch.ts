import type { RequestStateName } from "../lib/ipc";

/**
 * The Activity screen's filter model, shared by the route (URL search
 * validation) and the screen (controls + query args). Lives in its own
 * module because the router imports the screen — importing the router
 * back from the screen would be a cycle.
 *
 * The state segments collapse the store's six states into five lenses:
 * `active` groups `queued` + `running` (both mean "the water is moving";
 * a separate queued lens earns nothing at v0 volumes), `waiting` is the
 * raised-hand state `waiting_approval`, and the three terminal lenses map
 * 1:1. `all` is the default and stays out of the URL.
 */
export const STATE_FILTERS = ["all", "active", "waiting", "done", "refused", "failed"] as const;

export type StateFilter = (typeof STATE_FILTERS)[number];

/** URL search params for `/activity`; absent means "all". */
export interface ActivitySearch {
  repo?: string;
  agent?: string;
  state?: Exclude<StateFilter, "all">;
}

/** Narrows raw URL search into the filter model, dropping junk silently. */
export function parseActivitySearch(search: Record<string, unknown>): ActivitySearch {
  const parsed: ActivitySearch = {};
  if (typeof search.repo === "string" && search.repo !== "") parsed.repo = search.repo;
  if (typeof search.agent === "string" && search.agent !== "") parsed.agent = search.agent;
  if (
    typeof search.state === "string" &&
    search.state !== "all" &&
    (STATE_FILTERS as readonly string[]).includes(search.state)
  ) {
    parsed.state = search.state as Exclude<StateFilter, "all">;
  }
  return parsed;
}

/**
 * The server-side `state` arg for a lens, or undefined when the lens
 * needs more than one store state (`active`) — that lens fetches
 * unfiltered and narrows client-side via `matchesStateFilter`.
 */
export function serverStateFor(filter: StateFilter): RequestStateName | undefined {
  switch (filter) {
    case "waiting":
      return "waiting_approval";
    case "done":
    case "refused":
    case "failed":
      return filter;
    default:
      return undefined;
  }
}

/** Client-side narrowing; only `active` actually filters anything. */
export function matchesStateFilter(state: RequestStateName, filter: StateFilter): boolean {
  if (filter === "active") return state === "queued" || state === "running";
  const server = serverStateFor(filter);
  return server === undefined || state === server;
}
