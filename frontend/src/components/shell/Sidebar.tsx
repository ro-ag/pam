import { Link, useRouterState } from "@tanstack/react-router";
import { Activity, Cpu, Hand, Settings, Workflow, type LucideIcon } from "lucide-react";
import { motion } from "motion/react";
import { cn, cva, type VariantProps } from "../../lib/cn";

/**
 * Sidebar — the ZCode trait the owner loves: it has NO ground of its own.
 * No card, no border, no fill; the items float directly on the chrome (the
 * dark water) while the work panel floats beside them. Active screen gets
 * the accent-soft pill; future screens sit faint with a mono "soon" tag.
 *
 * The mount stagger is one of exactly two orchestrated motions in the shell
 * (the other is the work panel's route transition) — nothing else animates.
 */
export const navItemVariants = cva(
  "flex h-9 w-full items-center gap-2.5 rounded-control px-3 font-sans text-sm font-medium transition-colors duration-150",
  {
    variants: {
      state: {
        idle: "text-ink-muted hover:bg-accent-soft/60 hover:text-ink",
        active: "bg-accent-soft text-ink",
        soon: "text-ink-faint",
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
  to: "/activity" | "/approvals" | "/models" | "/settings";
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

function NavSoon({ label, icon: Icon }: { label: string; icon: LucideIcon }) {
  return (
    <span aria-disabled="true" className={navItemVariants({ state: "soon" })}>
      <Icon aria-hidden="true" className="size-4 shrink-0" />
      {label}
      <span className="ml-auto font-data text-xs tracking-wider">soon</span>
    </span>
  );
}

export function Sidebar() {
  return (
    <motion.nav
      aria-label="Primary"
      variants={staggerList}
      initial="hidden"
      animate="show"
      className="flex w-52 shrink-0 flex-col gap-1 pt-1"
    >
      <motion.div variants={staggerItem}>
        <NavLink to="/activity" label="Activity" icon={Activity} />
      </motion.div>
      <motion.div variants={staggerItem}>
        <NavLink to="/approvals" label="Approvals" icon={Hand} />
      </motion.div>
      <motion.div variants={staggerItem}>
        <NavSoon label="Flows" icon={Workflow} />
      </motion.div>
      <motion.div variants={staggerItem}>
        <NavLink to="/models" label="Models" icon={Cpu} />
      </motion.div>
      <motion.div variants={staggerItem} className="mt-auto">
        <NavLink to="/settings" label="Settings" icon={Settings} />
      </motion.div>
    </motion.nav>
  );
}
