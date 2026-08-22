import {
  ArrowClockwise,
  BookOpen,
  CaretDown,
  CaretRight,
  Check,
  Circle,
  Gear,
  GitBranch,
  LockSimple,
  MagnifyingGlass,
  MoonStars,
  Power,
  Pulse,
  Queue,
  SidebarSimple,
  SunHorizon,
} from "@phosphor-icons/react";
import { DropdownMenu, Tooltip, VisuallyHidden } from "radix-ui";
import {
  type KeyboardEvent as ReactKeyboardEvent,
  type PointerEvent as ReactPointerEvent,
  type ReactNode,
  type RefObject,
  useEffect,
  useRef,
} from "react";
import type { ViewId } from "../domain";
import {
  clampSidebarWidth,
  minimumSidebarWidth,
  sidebarMaximumWidth,
  sidebarWidthFromKey,
} from "../layout";
import type { ControlCenterView, ProjectView } from "../selectors";
import type { PamTheme, PamThemeMode } from "../theme";

export const navItems: ReadonlyArray<{ id: ViewId; label: string; icon: typeof Pulse }> = [
  { id: "current", label: "Current", icon: Pulse },
  { id: "flows", label: "Flows", icon: GitBranch },
  { id: "access", label: "Access", icon: LockSimple },
];

export function StatusDot({ state = "coral" }: { state?: "coral" | "aqua" | "muted" }) {
  return <Circle className={`status-dot status-dot--${state}`} size={12} weight="fill" aria-hidden="true" />;
}

function IconTooltip({ label, children }: { label: string; children: ReactNode }) {
  return (
    <Tooltip.Root>
      <Tooltip.Trigger asChild>{children}</Tooltip.Trigger>
      <Tooltip.Portal>
        <Tooltip.Content className="tooltip-content" sideOffset={8}>
          {label}
          <Tooltip.Arrow className="tooltip-arrow" />
        </Tooltip.Content>
      </Tooltip.Portal>
    </Tooltip.Root>
  );
}

export function ProjectMenu({
  active,
  projects,
  open,
  onOpenChange,
  onSelect,
}: {
  active: ProjectView;
  projects: ProjectView[];
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onSelect: (project: ProjectView) => void;
}) {
  const triggerRef = useRef<HTMLButtonElement>(null);
  const menuRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (open) {
      window.requestAnimationFrame(() => menuRef.current?.querySelector<HTMLElement>('[data-state="checked"]')?.focus());
    }
  }, [open]);

  return (
    <div className="project-menu-wrap">
      <DropdownMenu.Root open={open} onOpenChange={onOpenChange}>
        <DropdownMenu.Trigger asChild>
          <button
          ref={triggerRef}
          type="button"
          className="project-switcher"
          >
            <GitBranch size={19} aria-hidden="true" />
            <span>{active.name}</span>
            <CaretDown size={16} weight="bold" aria-hidden="true" />
          </button>
        </DropdownMenu.Trigger>
        <DropdownMenu.Portal>
          <DropdownMenu.Content
            ref={menuRef}
            className="project-menu-popover project-menu"
            aria-label="Registered projects"
            align="start"
            sideOffset={8}
            onCloseAutoFocus={(event) => {
              event.preventDefault();
              triggerRef.current?.focus();
            }}
          >
            <DropdownMenu.RadioGroup value={active.handle}>
            {projects.map((project) => (
              <DropdownMenu.RadioItem
                className="project-menu-item"
                key={project.handle}
                textValue={project.name}
                value={project.handle}
                onSelect={() => onSelect(project)}
              >
                <span className={`health-dot health-dot--${project.health}`} aria-hidden="true" />
                <span>
                  <strong>{project.name}</strong>
                  <small>{project.branch ?? project.rootLabel}</small>
                  <VisuallyHidden.Root>Health: {project.health}</VisuallyHidden.Root>
                </span>
                <DropdownMenu.ItemIndicator><Check size={15} weight="bold" aria-hidden="true" /></DropdownMenu.ItemIndicator>
              </DropdownMenu.RadioItem>
            ))}
            </DropdownMenu.RadioGroup>
          </DropdownMenu.Content>
        </DropdownMenu.Portal>
      </DropdownMenu.Root>
    </div>
  );
}

export function Sidebar({
  data,
  activeView,
  collapsed,
  pending,
  projectMenuOpen,
  trapFocus,
  onNavigate,
  onProjectMenuOpenChange,
  onSelectProject,
  onToggleDaemon,
  onRestartDaemon,
  onDismiss,
  containerRef,
}: {
  data: ControlCenterView;
  activeView: ViewId;
  collapsed: boolean;
  pending: boolean;
  projectMenuOpen: boolean;
  trapFocus: boolean;
  onNavigate: (view: ViewId) => void;
  onProjectMenuOpenChange: (open: boolean) => void;
  onSelectProject: (project: ProjectView) => void;
  onToggleDaemon: () => void;
  onRestartDaemon: () => void;
  onDismiss: () => void;
  containerRef: RefObject<HTMLElement | null>;
}) {
  const trapTabFocus = (event: ReactKeyboardEvent<HTMLElement>) => {
    if (trapFocus && !projectMenuOpen && event.key === "Escape") {
      event.preventDefault();
      event.stopPropagation();
      onDismiss();
      return;
    }
    if (!trapFocus || event.key !== "Tab") return;
    const sidebar = event.currentTarget;
    const focusable = Array.from(sidebar.querySelectorAll<HTMLElement>([
      "a[href]",
      "button:not(:disabled)",
      "input:not(:disabled)",
      "select:not(:disabled)",
      "textarea:not(:disabled)",
      '[tabindex]:not([tabindex="-1"])',
    ].join(","))).filter((element) => !element.hidden && element.getAttribute("aria-hidden") !== "true");
    if (focusable.length === 0) return;
    const first = focusable[0];
    const last = focusable[focusable.length - 1];
    if ((event.shiftKey && document.activeElement === first) || (!event.shiftKey && document.activeElement === last)) {
      event.preventDefault();
      (event.shiftKey ? last : first).focus();
    }
  };
  return (
    <aside ref={containerRef} className={`sidebar ${collapsed ? "is-collapsed" : ""}`} aria-label="Project navigation" onKeyDownCapture={trapTabFocus}>
      <div className="brand" aria-label="PAM" data-tauri-drag-region>
        <img src="/assets/pam-mark.png" alt="" />
        {!collapsed && <span>PAM</span>}
      </div>
      {!collapsed ? (
        <ProjectMenu
          active={data.project}
          projects={data.catalog}
          open={projectMenuOpen}
          onOpenChange={onProjectMenuOpenChange}
          onSelect={onSelectProject}
        />
      ) : (
        <div className="project-monogram" title={data.project.name} aria-label={`Project ${data.project.name}`}>
          {data.project.name.slice(0, 1).toUpperCase()}
        </div>
      )}
      <nav className="primary-nav" aria-label="Primary">
        {navItems.map(({ id, label, icon: Icon }) => (
          <button
            type="button"
            className={`nav-item ${activeView === id ? "is-active" : ""}`}
            aria-current={activeView === id ? "page" : undefined}
            aria-label={label}
            title={collapsed ? label : undefined}
            key={id}
            onClick={() => onNavigate(id)}
          >
            <Icon size={21} weight={activeView === id ? "bold" : "regular"} aria-hidden="true" />
            {!collapsed && <span>{label}</span>}
            {!collapsed && id === "current" && data.current.queue.length > 0 && (
              <span className="nav-count" aria-label={`${data.current.queue.length} queued`}>
                {data.current.queue.length}
              </span>
            )}
          </button>
        ))}
      </nav>
      <div className="sidebar-footer">
        <div className="daemon-row">
          <button
            type="button"
            className="daemon-control"
            aria-pressed={data.daemon.state === "running"}
            aria-label={collapsed ? data.daemon.detail : undefined}
            title={collapsed ? data.daemon.detail : undefined}
            disabled={pending || ["starting", "stopping", "unavailable"].includes(data.daemon.state)}
            onClick={onToggleDaemon}
          >
            {data.daemon.state === "running" ? <StatusDot /> : <Power size={18} weight="bold" aria-hidden="true" />}
            {!collapsed && <span>{data.daemon.detail}</span>}
          </button>
          {!collapsed && data.daemon.state === "running" && (
            <button
              type="button"
              className="daemon-restart"
              aria-label="Restart PAM"
              title="Restart PAM"
              disabled={pending}
              onClick={onRestartDaemon}
            >
              <ArrowClockwise size={16} weight="bold" aria-hidden="true" />
            </button>
          )}
        </div>
        <div className="utility-nav">
          <button type="button" aria-label="Settings unavailable in this preview" title="Settings unavailable in this preview" disabled><Gear size={19} /></button>
          <button type="button" aria-label="Documentation unavailable in this preview" title="Documentation unavailable in this preview" disabled><BookOpen size={19} /></button>
        </div>
      </div>
    </aside>
  );
}

export function ResizeSeparator({
  collapsed,
  width,
  viewportWidth,
  onResizePreview,
  onResizeCommit,
  onToggle,
}: {
  collapsed: boolean;
  width: number;
  viewportWidth: number;
  onResizePreview: (width: number) => void;
  onResizeCommit: (width: number) => void;
  onToggle: () => void;
}) {
  const start = useRef<{ pointerId: number; x: number; width: number; latestWidth: number } | null>(null);
  const onPointerDown = (event: ReactPointerEvent<HTMLDivElement>) => {
    if (collapsed || !event.isPrimary || event.button !== 0 || start.current) return;
    event.preventDefault();
    start.current = { pointerId: event.pointerId, x: event.clientX, width, latestWidth: width };
    event.currentTarget.setPointerCapture(event.pointerId);
  };
  const onPointerMove = (event: ReactPointerEvent<HTMLDivElement>) => {
    const active = start.current;
    if (!active || active.pointerId !== event.pointerId || collapsed) return;
    const nextWidth = clampSidebarWidth(active.width + event.clientX - active.x, viewportWidth);
    active.latestWidth = nextWidth;
    onResizePreview(nextWidth);
  };
  const finishPointer = (event: ReactPointerEvent<HTMLDivElement>) => {
    const active = start.current;
    if (!active || active.pointerId !== event.pointerId) return;
    start.current = null;
    if (event.currentTarget.hasPointerCapture(active.pointerId)) {
      event.currentTarget.releasePointerCapture(active.pointerId);
    }
    onResizeCommit(active.latestWidth);
  };
  const onKeyDown = (event: ReactKeyboardEvent<HTMLDivElement>) => {
    if (collapsed) return;
    if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      onToggle();
      return;
    }
    const nextWidth = sidebarWidthFromKey(width, event.key, viewportWidth);
    if (nextWidth !== null) {
      event.preventDefault();
      onResizeCommit(nextWidth);
    }
  };
  const maximumWidth = sidebarMaximumWidth(viewportWidth);
  const currentWidth = clampSidebarWidth(width, viewportWidth);
  return (
    <div
      className="resize-separator"
      role="separator"
      aria-orientation="vertical"
      aria-valuemin={minimumSidebarWidth}
      aria-valuemax={maximumWidth}
      aria-valuenow={currentWidth}
      aria-disabled={collapsed}
      aria-label="Resize project sidebar"
      tabIndex={collapsed ? -1 : 0}
      onDoubleClick={collapsed ? undefined : onToggle}
      onKeyDown={onKeyDown}
      onPointerDown={onPointerDown}
      onPointerMove={onPointerMove}
      onPointerUp={finishPointer}
      onPointerCancel={finishPointer}
      onLostPointerCapture={finishPointer}
    />
  );
}

export function Toolbar({
  data,
  theme,
  themeMode,
  collapsed,
  pending,
  onToggleSidebar,
  onRefresh,
  onOpenCommand,
  onOpenQueue,
  onThemeChange,
  onThemeModeChange,
  toggleButtonRef,
  commandButtonRef,
  queueButtonRef,
}: {
  data: ControlCenterView;
  theme: PamTheme;
  themeMode: PamThemeMode;
  collapsed: boolean;
  pending: boolean;
  onToggleSidebar: () => void;
  onRefresh: () => void;
  onOpenCommand: (returnFocusTarget?: HTMLElement) => void;
  onOpenQueue: (returnFocusTarget?: HTMLElement) => void;
  onThemeChange: (theme: PamTheme) => void;
  onThemeModeChange: (mode: PamThemeMode) => void;
  toggleButtonRef: RefObject<HTMLButtonElement | null>;
  commandButtonRef: RefObject<HTMLButtonElement | null>;
  queueButtonRef: RefObject<HTMLButtonElement | null>;
}) {
  return (
    <header className="toolbar">
      <button ref={toggleButtonRef} type="button" aria-label={collapsed ? "Expand sidebar" : "Collapse sidebar"} onClick={onToggleSidebar}>
        <SidebarSimple size={19} weight="bold" />
      </button>
      <div className="breadcrumb" data-tauri-drag-region>
        <span>{data.project.name}</span>
        <CaretRight size={12} aria-hidden="true" />
        <strong>Control center</strong>
      </div>
      {import.meta.env.DEV && data.fixture && <span className="fixture-badge">Design fixture</span>}
      <div className="toolbar-actions">
        <DropdownMenu.Root>
          <DropdownMenu.Trigger asChild>
            <button
              type="button"
              className="theme-trigger"
              aria-label={`Theme: ${theme === "ventisquero" ? "Ventisquero" : "Viña del Mar"} · ${themeMode}`}
              title="Choose appearance theme"
            >
              {themeMode === "light"
                ? <SunHorizon size={19} weight="bold" aria-hidden="true" />
                : <MoonStars size={19} weight="bold" aria-hidden="true" />}
            </button>
          </DropdownMenu.Trigger>
          <DropdownMenu.Portal>
            <DropdownMenu.Content className="theme-menu-popover" align="end" sideOffset={8}>
              <DropdownMenu.Label className="theme-menu-label">Theme</DropdownMenu.Label>
              <DropdownMenu.RadioGroup value={theme} onValueChange={(value) => onThemeChange(value as PamTheme)}>
                <DropdownMenu.RadioItem className="theme-menu-item" value="ventisquero" textValue="Ventisquero">
                  <span className="theme-swatch theme-swatch--ventisquero" aria-hidden="true" />
                  <span><strong>Ventisquero</strong><small>Rock · Ice · Copper · Mist</small></span>
                  <DropdownMenu.ItemIndicator><Check size={15} weight="bold" aria-hidden="true" /></DropdownMenu.ItemIndicator>
                </DropdownMenu.RadioItem>
                <DropdownMenu.RadioItem className="theme-menu-item" value="vina" textValue="Viña del Mar">
                  <span className="theme-swatch theme-swatch--vina" aria-hidden="true" />
                  <span><strong>Viña del Mar</strong><small>Night · Violet · Coral · Surf</small></span>
                  <DropdownMenu.ItemIndicator><Check size={15} weight="bold" aria-hidden="true" /></DropdownMenu.ItemIndicator>
                </DropdownMenu.RadioItem>
              </DropdownMenu.RadioGroup>
              <DropdownMenu.Separator className="theme-menu-separator" />
              <DropdownMenu.Label className="theme-menu-label">Variant</DropdownMenu.Label>
              <DropdownMenu.RadioGroup value={themeMode} onValueChange={(value) => onThemeModeChange(value as PamThemeMode)}>
                <DropdownMenu.RadioItem className="theme-menu-item theme-menu-item--compact" value="light" textValue="Light variant">
                  <SunHorizon size={19} aria-hidden="true" />
                  <span><strong>Light</strong><small>{theme === "ventisquero" ? "Mist" : "Dawn"}</small></span>
                  <DropdownMenu.ItemIndicator><Check size={15} weight="bold" aria-hidden="true" /></DropdownMenu.ItemIndicator>
                </DropdownMenu.RadioItem>
                <DropdownMenu.RadioItem className="theme-menu-item theme-menu-item--compact" value="dark" textValue="Dark variant">
                  <MoonStars size={19} aria-hidden="true" />
                  <span><strong>Dark</strong><small>{theme === "ventisquero" ? "Bedrock" : "Night"}</small></span>
                  <DropdownMenu.ItemIndicator><Check size={15} weight="bold" aria-hidden="true" /></DropdownMenu.ItemIndicator>
                </DropdownMenu.RadioItem>
              </DropdownMenu.RadioGroup>
            </DropdownMenu.Content>
          </DropdownMenu.Portal>
        </DropdownMenu.Root>
        <IconTooltip label="Search commands · ⌘K">
          <button ref={commandButtonRef} type="button" aria-label="Open command palette (⌘K)" onClick={(event) => onOpenCommand(event.currentTarget)}>
            <MagnifyingGlass size={18} />
          </button>
        </IconTooltip>
        <IconTooltip label="Open project queue">
          <button ref={queueButtonRef} type="button" aria-label="Open queue" onClick={(event) => onOpenQueue(event.currentTarget)}>
            <Queue size={19} />
            {data.current.queue.length > 0 && <span>{data.current.queue.length}</span>}
          </button>
        </IconTooltip>
        <IconTooltip label="Refresh project · ⌘R">
          <button type="button" aria-label="Refresh project" disabled={pending} onClick={onRefresh}>
            <ArrowClockwise className={pending ? "is-spinning" : ""} size={18} weight="bold" />
          </button>
        </IconTooltip>
      </div>
    </header>
  );
}
