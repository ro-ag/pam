export const defaultSidebarWidth = 248;
export const minimumSidebarWidth = 180;
export const maximumSidebarWidth = 420;
export const defaultSidebarCollapsed = false;
export const sidebarWidthStorageKey = "pam-sidebar-width";
export const sidebarCollapsedStorageKey = "pam-sidebar-collapsed";

export interface LayoutStorage {
  getItem(key: string): string | null;
  setItem(key: string, value: string): void;
}

export function sidebarMaximumWidth(viewportWidth: number): number {
  return Math.max(
    minimumSidebarWidth,
    Math.min(maximumSidebarWidth, Math.floor(viewportWidth * 0.45)),
  );
}

export function clampSidebarWidth(width: number, viewportWidth: number): number {
  const responsiveMaximum = sidebarMaximumWidth(viewportWidth);
  const finiteWidth = Number.isFinite(width) ? width : defaultSidebarWidth;
  return Math.round(
    Math.max(minimumSidebarWidth, Math.min(finiteWidth, responsiveMaximum)),
  );
}

export function storedSidebarWidth(
  value: unknown,
  viewportWidth: number,
): number {
  if (typeof value !== "string" || value.trim() === "") {
    return clampSidebarWidth(defaultSidebarWidth, viewportWidth);
  }
  return clampSidebarWidth(Number(value), viewportWidth);
}

export function storedSidebarCollapsed(value: unknown): boolean {
  if (value === "true") return true;
  if (value === "false") return false;
  return defaultSidebarCollapsed;
}

export function sidebarWidthFromKey(
  currentWidth: number,
  key: string,
  viewportWidth: number,
): number | null {
  if (key === "ArrowLeft") return clampSidebarWidth(currentWidth - 16, viewportWidth);
  if (key === "ArrowRight") return clampSidebarWidth(currentWidth + 16, viewportWidth);
  if (key === "PageDown") return clampSidebarWidth(currentWidth - 64, viewportWidth);
  if (key === "PageUp") return clampSidebarWidth(currentWidth + 64, viewportWidth);
  if (key === "Home") return minimumSidebarWidth;
  if (key === "End") return clampSidebarWidth(maximumSidebarWidth, viewportWidth);
  return null;
}

export function readPersistedSidebarWidth(
  storage: LayoutStorage | null | undefined,
  viewportWidth: number,
): number {
  try {
    return storedSidebarWidth(
      storage?.getItem(sidebarWidthStorageKey) ?? null,
      viewportWidth,
    );
  } catch {
    return clampSidebarWidth(defaultSidebarWidth, viewportWidth);
  }
}

export function readPersistedSidebarCollapsed(
  storage: LayoutStorage | null | undefined,
): boolean {
  try {
    return storedSidebarCollapsed(
      storage?.getItem(sidebarCollapsedStorageKey) ?? null,
    );
  } catch {
    return defaultSidebarCollapsed;
  }
}

export function writePersistedSidebarWidth(
  storage: LayoutStorage | null | undefined,
  width: number,
  viewportWidth: number,
): void {
  try {
    storage?.setItem(
      sidebarWidthStorageKey,
      String(clampSidebarWidth(width, viewportWidth)),
    );
  } catch {
    // Storage is a startup optimization, never a requirement for live layout.
  }
}

export function writePersistedSidebarCollapsed(
  storage: LayoutStorage | null | undefined,
  collapsed: boolean,
): void {
  try {
    storage?.setItem(sidebarCollapsedStorageKey, String(collapsed));
  } catch {
    // Storage is a startup optimization, never a requirement for live layout.
  }
}
