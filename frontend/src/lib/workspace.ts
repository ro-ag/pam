export type SidebarMode = "expanded" | "compact";
export type WorkspaceWidth = "full" | "focused";
export interface WorkspaceLayout {
  sidebar: SidebarMode;
  width: WorkspaceWidth;
}
export interface SavedWorkspace extends WorkspaceLayout {
  id: string;
  name: string;
  href: string;
}
export interface WorkspaceState extends WorkspaceLayout {
  saved: SavedWorkspace[];
}

export const workspaceStorageKey = "pam-workspace";
export const maxSavedWorkspaces = 8;
const defaults: WorkspaceState = { sidebar: "expanded", width: "full", saved: [] };
let snapshot: WorkspaceState = defaults;
const listeners = new Set<() => void>();
const routes = new Set(["/", "/activity", "/approvals", "/flows", "/models", "/settings"]);

/** Layouts may select a local screen, never execute a command or open an external URL. */
export function isWorkspaceHref(value: unknown): value is string {
  if (typeof value !== "string" || value.length > 4096 || /[\\\s]/.test(value)) return false;
  return routes.has(value.split(/[?#]/, 1)[0]);
}

function isLayout(value: unknown): value is WorkspaceLayout {
  if (!value || typeof value !== "object") return false;
  const layout = value as WorkspaceLayout;
  return (
    (layout.sidebar === "expanded" || layout.sidebar === "compact") &&
    (layout.width === "full" || layout.width === "focused")
  );
}

function isSaved(value: unknown): value is SavedWorkspace {
  if (!isLayout(value)) return false;
  const saved = value as SavedWorkspace;
  return (
    typeof saved.id === "string" &&
    saved.id.length > 0 &&
    saved.id.length <= 100 &&
    typeof saved.name === "string" &&
    saved.name.trim().length > 0 &&
    saved.name.length <= 40 &&
    isWorkspaceHref(saved.href)
  );
}

function update(next: WorkspaceState, persist = true): void {
  snapshot = next;
  document.documentElement.dataset.workspaceSidebar = next.sidebar;
  document.documentElement.dataset.workspaceWidth = next.width;
  if (persist) {
    try {
      window.localStorage.setItem(workspaceStorageKey, JSON.stringify(next));
    } catch {
      /* Storage is optional; layout changes still apply in this session. */
    }
  }
  for (const listener of listeners) listener();
}

export function initWorkspace(): void {
  let next = defaults;
  try {
    const stored: unknown = JSON.parse(
      window.localStorage.getItem(workspaceStorageKey) ?? "null",
    );
    if (isLayout(stored)) {
      const saved = (stored as WorkspaceState).saved;
      const valid = Array.isArray(saved) ? saved.filter(isSaved) : [];
      next = {
        sidebar: stored.sidebar,
        width: stored.width,
        saved: valid
          .filter((item, index) => valid.findIndex((other) => other.id === item.id) === index)
          .slice(0, maxSavedWorkspaces),
      };
    }
  } catch {
    /* Invalid or unavailable storage falls back to the default workspace. */
  }
  update(next, false);
}

export function workspaceSnapshot(): WorkspaceState {
  return snapshot;
}
export function subscribeWorkspace(listener: () => void): () => void {
  listeners.add(listener);
  return () => {
    listeners.delete(listener);
  };
}
export function applyWorkspace(layout: WorkspaceLayout): void {
  if (isLayout(layout)) update({ ...snapshot, sidebar: layout.sidebar, width: layout.width });
}

/** Returns a useful validation message, or null after saving. */
export function saveWorkspace(name: string, href: string): string | null {
  const trimmed = name.trim();
  if (!trimmed || trimmed.length > 40) return "Choose a name between 1 and 40 characters.";
  if (!isWorkspaceHref(href)) return "This screen cannot be saved as a workspace.";
  if (snapshot.saved.length >= maxSavedWorkspaces)
    return "Delete a saved workspace before adding another (maximum 8).";
  if (snapshot.saved.some((saved) => saved.name.toLowerCase() === trimmed.toLowerCase()))
    return "A workspace with this name already exists.";
  const saved: SavedWorkspace = {
    id: crypto.randomUUID(),
    name: trimmed,
    href,
    sidebar: snapshot.sidebar,
    width: snapshot.width,
  };
  update({ ...snapshot, saved: [...snapshot.saved, saved] });
  return null;
}
export function deleteWorkspace(id: string): void {
  update({ ...snapshot, saved: snapshot.saved.filter((saved) => saved.id !== id) });
}
