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
import { motion } from "motion/react";
import { cn, cva, type VariantProps } from "../../lib/cn";

/**
 * Sidebar — the ZCode trait the owner loves: it has NO ground of its own.
 * No card, no border, no fill; the items float directly on the chrome (the
 * dark water) while the work panel floats beside them. Active screen gets
 * the accent-soft pill. Every entry is a real screen now — the last
 * placeholder went when Flows landed.
 *
 * The column runs the full window height and carries the brand block at its
 * head; there is no strip across the window any more. The mount stagger is
 * one of exactly two orchestrated motions in the shell (the other is the
 * work panel's route transition) — nothing else animates, and the head
 * never does: it must be paintable the instant the window appears.
 */
export const navItemVariants = cva(
  "flex h-9 w-full items-center gap-2.5 rounded-control px-3 font-sans text-sm font-medium transition-colors duration-150",
  {
    variants: {
      state: {
        idle: "text-ink-muted hover:bg-accent-soft/60 hover:text-ink",
        active: "bg-accent-soft text-ink",
      },
    },
    defaultVariants: {
      state: "idle",
    },
  },
);

export type NavItemState = NonNullable<VariantProps<typeof navItemVariants>["state"]>;

const staggerList = {
  hidden: {},
  show: { transition: { staggerChildren: 0.06, delayChildren: 0.05 } },
};

const staggerItem = {
  hidden: { opacity: 0, y: 6 },
  show: { opacity: 1, y: 0, transition: { duration: 0.22, ease: "easeOut" as const } },
};

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
        "flex w-52 shrink-0 flex-col gap-0.5 px-3 pb-5",
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
    <div className="flex h-full shrink-0 flex-col pl-3">
      <SidebarHead />
      <motion.nav
        aria-label="Primary"
        variants={staggerList}
        initial="hidden"
        animate="show"
        className="flex min-h-0 w-52 flex-1 flex-col gap-1 pb-3"
      >
        <motion.div variants={staggerItem}>
          <NavLink to="/" label="Home" icon={MessageCircleQuestion} />
        </motion.div>
        <motion.div variants={staggerItem}>
          <NavLink to="/activity" label="Activity" icon={Activity} />
        </motion.div>
        <motion.div variants={staggerItem}>
          <NavLink to="/approvals" label="Approvals" icon={Hand} />
        </motion.div>
        <motion.div variants={staggerItem}>
          <NavLink to="/flows" label="Flows" icon={Workflow} />
        </motion.div>
        <motion.div variants={staggerItem}>
          <NavLink to="/models" label="Models" icon={Cpu} />
        </motion.div>
        <motion.div variants={staggerItem} className="mt-auto">
          <NavLink to="/settings" label="Settings" icon={Settings} />
        </motion.div>
      </motion.nav>
    </div>
  );
}
