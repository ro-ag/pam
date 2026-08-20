import type { CatalogDto, CommandFence, SnapshotDataDto, SnapshotDto, ViewId } from "./domain";
import { sameFence } from "./bridge";

export type LoadState = "loading" | "ready" | "recovering";

export interface AppState {
  loadState: LoadState;
  data: SnapshotDataDto | null;
  catalog: CatalogDto | null;
  activeFence: CommandFence | null;
  pendingFence: CommandFence | null;
  activeView: ViewId;
  sidebarWidth: number;
  sidebarCollapsed: boolean;
  error: string | null;
}

export type AppAction =
  | { type: "bootstrapSucceeded"; response: SnapshotDto; catalog: CatalogDto }
  | { type: "commandStarted"; fence: CommandFence }
  | { type: "commandSucceeded"; response: SnapshotDto }
  | { type: "commandFailed"; fence: CommandFence; message: string }
  | { type: "navigate"; view: ViewId }
  | { type: "resizeSidebar"; width: number }
  | { type: "toggleSidebar" }
  | { type: "retry" };

export const initialState: AppState = {
  loadState: "loading",
  data: null,
  catalog: null,
  activeFence: null,
  pendingFence: null,
  activeView: "current",
  sidebarWidth: 248,
  sidebarCollapsed: false,
  error: null,
};

export function clampSidebarWidth(width: number): number {
  return Math.min(368, Math.max(208, Math.round(width / 8) * 8));
}

export function appReducer(state: AppState, action: AppAction): AppState {
  switch (action.type) {
    case "bootstrapSucceeded":
      return {
        ...state,
        loadState: "ready",
        data: action.response.data,
        catalog: action.catalog,
        activeFence: action.response.fence,
        pendingFence: null,
        error: null,
      };
    case "commandStarted":
      return { ...state, pendingFence: action.fence, error: null };
    case "commandSucceeded":
      if (
        !sameFence(state.pendingFence, action.response.fence) &&
        !(
          state.pendingFence?.generation === "" &&
          state.pendingFence.projectHandle === action.response.fence.projectHandle &&
          state.pendingFence.operationId === action.response.fence.operationId
        )
      ) return state;
      return {
        ...state,
        loadState: "ready",
        data: action.response.data,
        activeFence: action.response.fence,
        pendingFence: null,
        error: null,
      };
    case "commandFailed":
      if (!sameFence(state.pendingFence, action.fence)) return state;
      return { ...state, loadState: "recovering", pendingFence: null, error: action.message };
    case "navigate":
      return { ...state, activeView: action.view };
    case "resizeSidebar":
      return { ...state, sidebarWidth: clampSidebarWidth(action.width), sidebarCollapsed: false };
    case "toggleSidebar":
      return { ...state, sidebarCollapsed: !state.sidebarCollapsed };
    case "retry":
      return { ...state, loadState: "loading", error: null };
  }
}

export function presentError(error: unknown): string {
  const record = typeof error === "object" && error !== null ? error as Record<string, unknown> : null;
  const message = typeof record?.message === "string" ? record.message : null;
  const recovery = typeof record?.recovery === "string" ? record.recovery : null;
  const raw = error instanceof Error
    ? error.message
    : typeof error === "string"
      ? error
      : [message, recovery].filter(Boolean).join(" ") || "PAM could not complete the request.";
  const collapsed = raw.replace(/[\u0000-\u001f\u007f]+/g, " ").replace(/\s+/g, " ").trim();
  return collapsed.slice(0, 280) || "PAM could not complete the request.";
}
