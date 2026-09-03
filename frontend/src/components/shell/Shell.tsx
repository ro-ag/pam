import { Outlet, useRouterState } from "@tanstack/react-router";
import { motion } from "motion/react";
import { Panel } from "../ui/Panel";
import { PanelToolbar } from "./PanelToolbar";
import { Sidebar } from "./Sidebar";

/**
 * The ZCode shell — the signature layout. The window background IS the
 * chrome ground: the sidebar lives directly on it, borderless, running the
 * full window height with the brand block at its head. Nothing bands across
 * the top any more.
 *
 * The working area is the one floating panel per screen — inset 12px from
 * every window edge and from the sidebar, lifted by shadow-float, rounded
 * with radius-panel: a lit sheet over dark water. Its first row is the
 * panel toolbar (beacon, theme family, light/dark); the routed screen
 * renders beneath it.
 *
 * Route content re-mounts inside the panel with a keyed fade-and-rise
 * (~180ms); MotionConfig in App.tsx collapses it to an opacity fade under
 * prefers-reduced-motion.
 */
export function Shell() {
  const pathname = useRouterState({ select: (state) => state.location.pathname });

  return (
    <div className="relative flex h-screen overflow-hidden bg-chrome text-ink">
      <div className="atmosphere" aria-hidden="true" />
      <Sidebar />
      <main className="min-w-0 flex-1 p-3">
        <Panel className="flex h-full flex-col overflow-hidden">
          <PanelToolbar />
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
  );
}
