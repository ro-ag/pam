import { Lock } from "lucide-react";
import type { ReactNode } from "react";
import { Badge } from "../components/ui/Badge";
import { SafeText } from "../components/ui/SafeText";
import { cn } from "../lib/cn";
import type { EffectiveEntry, PolicyDrop } from "../lib/ipc";

/**
 * ManagedField — the one way a settings control shows what a managed policy owns.
 *
 * Every get op that answers an `effective` entry per field feeds that entry here:
 *  - `locked`: the control is disabled and wears "Managed by your organization", with the
 *    policy's reason when it gave one;
 *  - a policy clamp or allowlist (`source: "policy"`, `locked: false`, a `mode` that is not
 *    `default`): the control stays editable inside the permitted set, and the constraint is
 *    printed beside it;
 *  - a policy default (`source: "policy"`, unlocked, no clamp): the control stays editable and a
 *    quiet "organization default" hint says where the starting value came from.
 * An entry with no policy in play (`source: "user"` or `"default"`) renders nothing at all.
 * Policy text (reason, constraint values) is administrator-authored file content, so it goes
 * through `SafeText`.
 */

export const MANAGED_LABEL = "Managed by your organization";
export const ORG_DEFAULT_LABEL = "organization default";
export const LIMITED_LABEL = "Limited by your organization";
export const HELD_NOTE =
  "paused until the policy file is fixed; changes that would widen what agents can do are held";

/** Whether the human cannot edit the field at all. */
export function isLocked(entry: EffectiveEntry | undefined): boolean {
  return entry?.locked === true;
}

/** Whether the entry carries a range or allowlist the human has to stay inside. */
export function isLimited(entry: EffectiveEntry | undefined): boolean {
  if (!entry || entry.locked || entry.source !== "policy") return false;
  return entry.clamped === true || (entry.mode !== undefined && entry.mode !== "default");
}

/** Whether the policy only supplied a starting value the human may replace. */
export function isOrgDefault(entry: EffectiveEntry | undefined): boolean {
  if (!entry || entry.locked || entry.source !== "policy") return false;
  return !isLimited(entry);
}

const CONSTRAINT_LABELS: Record<string, string> = {
  allow: "allowed",
  floor: "lowest allowed",
  min: "at least",
  max: "at most",
};

function formatValue(value: unknown): string {
  if (value === null || value === undefined) return "none";
  if (Array.isArray(value))
    return value.length === 0 ? "none" : value.map(formatValue).join(", ");
  if (typeof value === "object") {
    return Object.entries(value as Record<string, unknown>)
      .map(([key, inner]) => `${key} ${formatValue(inner)}`)
      .join("; ");
  }
  return String(value);
}

/** The permitted set or range in words, or null when the entry names none. */
export function describeConstraint(entry: EffectiveEntry | undefined): string | null {
  const constraint = entry?.constraint;
  if (!constraint) return null;
  const parts = Object.entries(constraint).map(([key, value]) => {
    const label = CONSTRAINT_LABELS[key] ?? key;
    return `${label}: ${formatValue(value)}`;
  });
  return parts.length === 0 ? null : parts.join(" · ");
}

/** The badge and hints for one entry; nothing when no policy owns it. */
export function ManagedNote({
  entry,
  className,
}: {
  entry: EffectiveEntry | undefined;
  className?: string;
}) {
  if (isLocked(entry)) {
    const held = entry?.state === "held";
    return (
      <div className={cn("flex flex-wrap items-center gap-x-2 gap-y-1", className)}>
        <Badge tone="warning">
          <Lock aria-hidden="true" className="size-3" />
          {MANAGED_LABEL}
        </Badge>
        {entry?.reason && (
          <span className="select-text font-sans text-xs text-ink-muted">
            <SafeText value={entry.reason} />
          </span>
        )}
        {held && <span className="font-sans text-xs text-warning">{HELD_NOTE}</span>}
      </div>
    );
  }
  if (isLimited(entry)) {
    const constraint = describeConstraint(entry);
    return (
      <div className={cn("flex flex-wrap items-center gap-x-2 gap-y-1", className)}>
        <Badge tone="neutral">{LIMITED_LABEL}</Badge>
        {constraint && (
          <span className="select-text font-data text-xs text-ink-muted">
            <SafeText value={constraint} />
          </span>
        )}
        {entry?.reason && (
          <span className="select-text font-sans text-xs text-ink-muted">
            <SafeText value={entry.reason} />
          </span>
        )}
      </div>
    );
  }
  if (isOrgDefault(entry)) {
    return (
      <span className={cn("font-data text-xs text-ink-faint", className)}>
        {ORG_DEFAULT_LABEL}
      </span>
    );
  }
  return null;
}

/**
 * Wraps one control. `children` receives whether the field is locked, so the control can set its
 * own `disabled`; the wrapper adds the note above it.
 */
export function ManagedField({
  entry,
  children,
  className,
}: {
  entry: EffectiveEntry | undefined;
  children: (locked: boolean) => ReactNode;
  className?: string;
}) {
  const locked = isLocked(entry);
  return (
    <div className={cn("space-y-2", className)} data-managed={locked ? "locked" : undefined}>
      <ManagedNote entry={entry} />
      {children(locked)}
    </div>
  );
}

/** A list value out of an effective entry, or `fallback` when the entry carries none. */
export function entryList(entry: EffectiveEntry | undefined, fallback: string[]): string[] {
  const value = entry?.value;
  return Array.isArray(value) && value.every((item) => typeof item === "string")
    ? (value as string[])
    : fallback;
}

/**
 * Stored entries the managed policy has stopped using: kept in the human's settings, reported
 * here with the daemon's reason, never used until the policy allows them again.
 */
export function PolicyDropNotice({
  drops,
  label,
}: {
  drops: PolicyDrop[] | undefined;
  label: string;
}) {
  if (!drops || drops.length === 0) return null;
  return (
    <div
      role="note"
      aria-label={label}
      className="space-y-1.5 rounded-card border border-warning/40 bg-warning-soft p-3"
    >
      <p className="font-sans text-sm text-ink">
        Your organization&apos;s policy is not using{" "}
        {drops.length === 1 ? "this entry" : "these entries"}.{" "}
        {drops.length === 1 ? "It is" : "They are"} kept, and nothing is deleted.
      </p>
      <ul className="space-y-1">
        {drops.map((drop, index) => (
          <li key={`${drop.root}-${drop.connector ?? ""}-${index}`} className="select-text">
            <p className="font-data text-xs text-ink">
              <SafeText
                value={drop.connector ? `${drop.root} · ${drop.connector}` : drop.root}
              />
            </p>
            <p className="font-sans text-xs text-ink-muted">
              <SafeText value={drop.reason} />
            </p>
          </li>
        ))}
      </ul>
    </div>
  );
}
