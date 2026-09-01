import {
  createRootRoute,
  createRoute,
  createRouter,
  redirect,
  type RouterHistory,
} from "@tanstack/react-router";
import { Shell } from "./components/shell/Shell";
import { ActivityScreen } from "./screens/Activity";
import { ApprovalsScreen } from "./screens/Approvals";
import { SettingsScreen } from "./screens/Settings";

/**
 * Code-based route table — small app, no file-based magic. The root route is
 * the ZCode shell (chrome strip + sidebar + floating work panel); every child
 * renders inside the panel. `/` redirects to the Activity screen, the app's
 * default view. Flows and Models are sidebar placeholders only — they gain
 * routes when their screens land (tasks #28–#30 wire the real views).
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
});

const approvalsRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/approvals",
  component: ApprovalsScreen,
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
