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
  Power,
  Pulse,
  Queue,
  SidebarSimple,
} from "@phosphor-icons/react";
import {
  type KeyboardEvent as ReactKeyboardEvent,
  type PointerEvent as ReactPointerEvent,
  type RefObject,
  useEffect,
  useRef,
} from "react";
import {
  Button,
  Menu,
  MenuItem,
  MenuTrigger,
  Popover,
  VisuallyHidden,
} from "react-aria-components";
import type { ViewId } from "../domain";
import {
  clampSidebarWidth,
  minimumSidebarWidth,
  sidebarMaximumWidth,
  sidebarWidthFromKey,
} from "../layout";
import type { ControlCenterView, ProjectView } from "../selectors";

export const navItems: ReadonlyArray<{ id: ViewId; label: string; icon: typeof Pulse }> = [
  { id: "current", label: "Current", icon: Pulse },
  { id: "flows", label: "Flows", icon: GitBranch },
  { id: "access", label: "Access", icon: LockSimple },
];

export function StatusDot({ state = "coral" }: { state?: "coral" | "aqua" | "muted" }) {
  return <Circle className={`status-dot status-dot--${state}`} size={12} weight="fill" aria-hidden="true" />;
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
  const wasOpen = useRef(open);

  useEffect(() => {
    if (wasOpen.current && !open) triggerRef.current?.focus();
    wasOpen.current = open;
  }, [open]);

  return (
    <div className="project-menu-wrap">
      <MenuTrigger
        isOpen={open}
        onOpenChange={onOpenChange}
      >
        <Button
          ref={triggerRef}
          type="button"
          className="project-switcher"
        >
          <GitBranch size={19} aria-hidden="true" />
          <span>{active.name}</span>
          <CaretDown size={16} weight="bold" aria-hidden="true" />
        </Button>
        <Popover className="project-menu-popover" placement="bottom start">
          <Menu
            className="project-menu"
            aria-label="Registered projects"
            selectionMode="single"
            selectedKeys={new Set([active.handle])}
          >
            {projects.map((project) => (
              <MenuItem
                className="project-menu-item"
                id={project.handle}
                key={project.handle}
                textValue={project.name}
                onAction={() => onSelect(project)}
              >
                <span className={`health-dot health-dot--${project.health}`} aria-hidden="true" />
                <span>
                  <strong>{project.name}</strong>
                  <small>{project.branch ?? project.rootLabel}</small>
                  <VisuallyHidden>Health: {project.health}</VisuallyHidden>
                </span>
                {project.handle === active.handle && <Check size={15} weight="bold" aria-hidden="true" />}
              </MenuItem>
            ))}
          </Menu>
        </Popover>
      </MenuTrigger>
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
      <div className="brand" aria-label="PAM">
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
  collapsed,
  pending,
  onToggleSidebar,
  onRefresh,
  onOpenCommand,
  onOpenQueue,
  toggleButtonRef,
  commandButtonRef,
  queueButtonRef,
}: {
  data: ControlCenterView;
  collapsed: boolean;
  pending: boolean;
  onToggleSidebar: () => void;
  onRefresh: () => void;
  onOpenCommand: (returnFocusTarget?: HTMLElement) => void;
  onOpenQueue: (returnFocusTarget?: HTMLElement) => void;
  toggleButtonRef: RefObject<HTMLButtonElement | null>;
  commandButtonRef: RefObject<HTMLButtonElement | null>;
  queueButtonRef: RefObject<HTMLButtonElement | null>;
}) {
  return (
    <header className="toolbar">
      <button ref={toggleButtonRef} type="button" aria-label={collapsed ? "Expand sidebar" : "Collapse sidebar"} onClick={onToggleSidebar}>
        <SidebarSimple size={19} weight="bold" />
      </button>
      <div className="breadcrumb">
        <span>{data.project.name}</span>
        <CaretRight size={12} aria-hidden="true" />
        <strong>Control center</strong>
      </div>
      {import.meta.env.DEV && data.fixture && <span className="fixture-badge">Design fixture</span>}
      <div className="toolbar-actions">
        <button ref={commandButtonRef} type="button" aria-label="Open command palette (⌘K)" title="Open command palette (⌘K)" onClick={(event) => onOpenCommand(event.currentTarget)}>
          <MagnifyingGlass size={18} />
        </button>
        <button ref={queueButtonRef} type="button" aria-label="Open queue" title="Open queue" onClick={(event) => onOpenQueue(event.currentTarget)}>
          <Queue size={19} />
          {data.current.queue.length > 0 && <span>{data.current.queue.length}</span>}
        </button>
        <button type="button" aria-label="Refresh project" title="Refresh project (⌘R)" disabled={pending} onClick={onRefresh}>
          <ArrowClockwise className={pending ? "is-spinning" : ""} size={18} weight="bold" />
        </button>
      </div>
    </header>
  );
}
