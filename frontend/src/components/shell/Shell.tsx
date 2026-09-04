import { Outlet, useRouterState } from "@tanstack/react-router";
import { Panel } from "../ui/Panel";
import { PanelToolbar } from "./PanelToolbar";
import { Sidebar } from "./Sidebar";

/** Keep PAM’s sidebar and inset work panel; Costa supplies the visual language within it. */
export function Shell() {
  const pathname = useRouterState({ select: (state) => state.location.pathname });
  return (
    <div className="relative flex h-screen overflow-hidden bg-chrome text-ink">
      <Sidebar />
      <main className="min-w-0 flex-1 p-3">
        <Panel className="flex h-full flex-col overflow-hidden shadow-float">
          <PanelToolbar />
          <div key={pathname} className="workspace-scroll min-h-0 flex-1 overflow-y-auto">
            <Outlet />
          </div>
        </Panel>
      </main>
    </div>
  );
}
