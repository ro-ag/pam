import { RouterProvider } from "@tanstack/react-router";
import { MotionConfig } from "motion/react";
import { createAppRouter, type AppRouter } from "./router";

/**
 * App — the router mounted inside one MotionConfig. `reducedMotion="user"`
 * makes every transform animation in the shell (panel rise, sidebar stagger)
 * collapse to plain opacity fades when the OS asks for reduced motion.
 * Tests inject a fresh memory-history router; the app itself uses the
 * default browser history.
 */
const defaultRouter = createAppRouter();

export default function App({ router = defaultRouter }: { router?: AppRouter }) {
  return (
    <MotionConfig reducedMotion="user">
      <RouterProvider router={router} />
    </MotionConfig>
  );
}
