import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { RouterProvider } from "@tanstack/react-router";
import { MotionConfig } from "motion/react";
import { useState } from "react";
import { createAppRouter, type AppRouter } from "./router";

/**
 * App — the router mounted inside one MotionConfig and one QueryClient.
 * `reducedMotion="user"` makes every transform animation in the shell
 * (panel rise, sidebar stagger) collapse to plain opacity fades when the
 * OS asks for reduced motion. Tests inject a fresh memory-history router;
 * the app itself uses the default browser history.
 *
 * Query defaults: the daemon is local, so a failed call is a state to
 * render (the disconnected banner), not something to retry into working —
 * `retry: false`. Freshness comes from event-driven invalidation
 * (`subscribeEvents` → invalidate), not window-focus refetching.
 */
export function createAppQueryClient(): QueryClient {
  return new QueryClient({
    defaultOptions: {
      queries: {
        retry: false,
        refetchOnWindowFocus: false,
        staleTime: 5_000,
      },
    },
  });
}

const defaultRouter = createAppRouter();

export default function App({ router = defaultRouter }: { router?: AppRouter }) {
  // One client per mounted App: the app mounts once, and every test render
  // gets an isolated cache without plumbing.
  const [queryClient] = useState(createAppQueryClient);
  return (
    <QueryClientProvider client={queryClient}>
      <MotionConfig reducedMotion="user">
        <RouterProvider router={router} />
      </MotionConfig>
    </QueryClientProvider>
  );
}
