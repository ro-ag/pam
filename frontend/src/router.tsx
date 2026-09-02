import {
  createRootRoute,
  createRoute,
  createRouter,
  redirect,
  type RouterHistory,
} from "@tanstack/react-router";
import { Shell } from "./components/shell/Shell";
import { ActivityScreen } from "./screens/Activity";
import { parseActivitySearch } from "./screens/activitySearch";
import { ApprovalsScreen } from "./screens/Approvals";
import { ModelsScreen } from "./screens/Models";
import { SettingsScreen } from "./screens/Settings";

/**
 * Code-based route table — small app, no file-based magic. The root route is
 * the ZCode shell (chrome strip + sidebar + floating work panel); every child
 * renders inside the panel. `/` redirects to the Activity screen, the app's
 * default view. Flows is the last sidebar placeholder — it gains a route
 * when its screen lands.
 */
const rootRoute = createRootRoute({ component: Shell });

const indexRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/",
  beforeLoad: () => {
    throw redirect({ to: "/activity" });
  },
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
