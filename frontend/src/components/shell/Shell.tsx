import { Outlet, useRouterState } from "@tanstack/react-router";
import { motion } from "motion/react";
import { Panel } from "../ui/Panel";
import { Sidebar } from "./Sidebar";
import { TopStrip } from "./TopStrip";

/**
 * The ZCode shell — the signature layout. The window background IS the
 * chrome ground: the strip and sidebar live directly on it, borderless.
 * The working area is the one floating panel per screen — inset 12px from
 * every visible edge (strip, sidebar, window), lifted by shadow-float,
 * rounded with radius-panel: a lit sheet over dark water.
 *
 * Route content re-mounts inside the panel with a keyed fade-and-rise
 * (~180ms); MotionConfig in App.tsx collapses it to an opacity fade under
 * prefers-reduced-motion.
 */
export function Shell() {
  const pathname = useRouterState({ select: (state) => state.location.pathname });

  return (
    <div className="relative flex h-screen flex-col overflow-hidden bg-chrome text-ink">
      <div className="atmosphere" aria-hidden="true" />
      <TopStrip />
      <div className="flex min-h-0 flex-1 gap-3 p-3">
        <Sidebar />
        <main className="min-w-0 flex-1">
          <Panel className="flex h-full flex-col overflow-hidden">
            <motion.div
              key={pathname}
              initial={{ opacity: 0, y: 6 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.18, ease: "easeOut" }}
              className="min-h-0 flex-1 overflow-y-auto"
            >
              <Outlet />
            </motion.div>
          </Panel>
        </main>
      </div>
    </div>
  );
}
