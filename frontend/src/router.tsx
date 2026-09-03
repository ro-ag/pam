import {
  createRootRoute,
  createRoute,
  createRouter,
  type RouterHistory,
} from "@tanstack/react-router";
import { Shell } from "./components/shell/Shell";
import { ActivityScreen } from "./screens/Activity";
import { parseActivitySearch } from "./screens/activitySearch";
import { ApprovalsScreen } from "./screens/Approvals";
import { FlowsScreen } from "./screens/Flows";
import { HomeScreen } from "./screens/Home";
import { ModelsScreen } from "./screens/Models";
import { SettingsScreen } from "./screens/Settings";

/**
 * Code-based route table — small app, no file-based magic. The root route is
 * the ZCode shell (chrome strip + sidebar + floating work panel); every child
 * renders inside the panel. `/` is Home, where Pam answers questions about
 * herself — the app opens on a question, not on a list. Every sidebar entry
 * is a real route.
 */
const rootRoute = createRootRoute({ component: Shell });

const indexRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/",
  component: HomeScreen,
});

const activityRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/activity",
  component: ActivityScreen,
  // Filters live in the URL so a filtered view is shareable/restorable;
  // junk params are dropped rather than refused.
  validateSearch: parseActivitySearch,
});

const approvalsRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/approvals",
  component: ApprovalsScreen,
});

const flowsRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/flows",
  // `?flow=<id>` preselects a flow so Ask Pam (and any shared link) can
  // land on one; an empty or non-string value is dropped rather than
  // refused, and an unknown id falls back to the top of the shelf.
  validateSearch: (search: Record<string, unknown>): { flow?: string } =>
    typeof search.flow === "string" && search.flow !== "" ? { flow: search.flow } : {},
  component: FlowsRoute,
});

function FlowsRoute() {
  const { flow } = flowsRoute.useSearch();
  return <FlowsScreen initialFlow={flow} />;
}

const modelsRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/models",
  component: ModelsScreen,
});

const settingsRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/settings",
  component: SettingsScreen,
});

const routeTree = rootRoute.addChildren([
  indexRoute,
  activityRoute,
  approvalsRoute,
  flowsRoute,
  modelsRoute,
  settingsRoute,
]);

/** Build a router; tests pass a memory history, the app uses the default. */
export function createAppRouter(history?: RouterHistory) {
  return createRouter({ routeTree, history });
}

export type AppRouter = ReturnType<typeof createAppRouter>;

declare module "@tanstack/react-router" {
  interface Register {
    router: AppRouter;
  }
}
