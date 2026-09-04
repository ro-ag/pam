import { Link, useRouterState } from "@tanstack/react-router";
import {
  Activity,
  Cpu,
  Hand,
  MessageCircleQuestion,
  Settings,
  Workflow,
  type LucideIcon,
} from "lucide-react";
import { cn, cva, type VariantProps } from "../../lib/cn";

/** Desktop navigation stays available immediately; selection has a fixed inset marker.
 * The full-height column keeps its brand below native macOS traffic lights.
 */
export const navItemVariants = cva(
  "flex h-9 w-full items-center gap-2.5 rounded-control px-3 font-sans text-sm font-medium transition-colors duration-100",
  {
    variants: {
      state: {
        idle: "text-ink-muted hover:bg-accent-soft/60 hover:text-ink",
        active: "nav-current bg-accent-soft text-selection-ink",
      },
    },
    defaultVariants: {
      state: "idle",
    },
  },
);

export type NavItemState = NonNullable<VariantProps<typeof navItemVariants>["state"]>;

function NavLink({
  to,
  label,
  icon: Icon,
}: {
  to: "/" | "/activity" | "/approvals" | "/flows" | "/models" | "/settings";
  label: string;
  icon: LucideIcon;
}) {
  const pathname = useRouterState({ select: (state) => state.location.pathname });
  const active = pathname === to;
  return (
    <Link
      to={to}
      aria-current={active ? "page" : undefined}
      className={navItemVariants({ state: active ? "active" : "idle" })}
    >
      <Icon aria-hidden="true" className={cn("size-4 shrink-0", active && "text-accent")} />
      {label}
    </Link>
  );
}

/** macOS overlay mode floats the traffic lights over our top-left; clear them. */
function hasTrafficLights(): boolean {
  return navigator.userAgent.includes("Mac");
}

/**
 * The brand block at the head of the column. It is a drag region — and so
 * are its non-interactive children, because Tauri honors the attribute on
 * the exact element under the pointer. With `titleBarStyle: "Overlay"` the
 * macOS traffic lights sit at x 16 / y 17, so the head drops below them.
 */
function SidebarHead() {
  return (
    <div
      data-tauri-drag-region=""
      className={cn(
        "flex w-full shrink-0 flex-col gap-0.5 px-3 pb-5",
        hasTrafficLights() ? "pt-10" : "pt-4",
      )}
    >
      <span
        data-tauri-drag-region=""
        className="font-display text-sm font-semibold tracking-widest text-ink"
      >
        PAM
      </span>
      <span data-tauri-drag-region="" className="font-data text-xs text-ink-faint">
        personal agent machine
      </span>
    </div>
  );
}

export function Sidebar() {
  return (
    <div className="desktop-sidebar flex h-full shrink-0 flex-col px-3">
      <SidebarHead />
      <nav aria-label="Primary" className="flex min-h-0 w-full flex-1 flex-col gap-1 pb-3">
        <div>
          <NavLink to="/" label="Home" icon={MessageCircleQuestion} />
        </div>
        <div>
          <NavLink to="/activity" label="Activity" icon={Activity} />
        </div>
        <div>
          <NavLink to="/approvals" label="Approvals" icon={Hand} />
        </div>
        <div>
          <NavLink to="/flows" label="Flows" icon={Workflow} />
        </div>
        <div>
          <NavLink to="/models" label="Models" icon={Cpu} />
        </div>
        <div className="mt-auto">
          <NavLink to="/settings" label="Settings" icon={Settings} />
        </div>
      </nav>
    </div>
  );
}
