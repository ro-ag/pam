import { Outlet, useRouterState } from "@tanstack/react-router";
import { Panel } from "../ui/Panel";
import { PanelToolbar } from "./PanelToolbar";
import { Sidebar } from "./Sidebar";

/** Keep PAM’s sidebar and inset work panel; Costa supplies the visual language within it. */
export function Shell() {
  const pathname = useRouterState({ select: (state) => state.location.pathname });
  return (
    <div className="desktop-shell fixed inset-0 flex h-dvh overflow-clip bg-chrome text-ink">
      <Sidebar />
      <main className="flex min-h-0 min-w-0 flex-1 p-3">
        <Panel className="desktop-panel flex min-h-0 min-w-0 flex-1 flex-col overflow-hidden shadow-float">
          <PanelToolbar />
          <div
            key={pathname}
            className="workspace-scroll min-h-0 flex-1 overflow-hidden"
            data-settings={pathname === "/settings" || undefined}
          >
            <Outlet />
          </div>
        </Panel>
      </main>
    </div>
  );
}
