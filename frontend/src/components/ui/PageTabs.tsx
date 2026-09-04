import { useRef, useState, type ReactNode } from "react";
import { cn } from "../../lib/cn";

/** Settings' navigation pattern, shared by workspaces with distinct tasks. */
export function PageTabs<T extends string>({
  id,
  label,
  tabs,
  selected,
  onSelect,
}: {
  id: string;
  label: string;
  tabs: readonly { id: T; label: string }[];
  selected: T;
  onSelect: (id: T) => void;
}) {
  const buttons = useRef<(HTMLButtonElement | null)[]>([]);
  return (
    <div role="tablist" aria-label={label} className="settings-tabs page-tabs">
      {tabs.map((tab, index) => (
        <button
          key={tab.id}
          ref={(element) => {
            buttons.current[index] = element;
          }}
          type="button"
          role="tab"
          id={`${id}-tab-${tab.id}`}
          aria-controls={`${id}-pane-${tab.id}`}
          aria-selected={selected === tab.id}
          tabIndex={selected === tab.id ? 0 : -1}
          className="settings-tab"
          onClick={() => onSelect(tab.id)}
          onKeyDown={(event) => {
            const next =
              event.key === "ArrowRight"
                ? (index + 1) % tabs.length
                : event.key === "ArrowLeft"
                  ? (index + tabs.length - 1) % tabs.length
                  : event.key === "Home"
                    ? 0
                    : event.key === "End"
                      ? tabs.length - 1
                      : null;
            if (next === null) return;
            event.preventDefault();
            buttons.current[next]?.focus();
            onSelect(tabs[next].id);
          }}
        >
          {tab.label}
        </button>
      ))}
    </div>
  );
}

/** Preserve drafts, in-flight actions, and scroll offsets once a pane is visited. */
export function PagePane({
  id,
  tab,
  active,
  children,
  className,
}: {
  id: string;
  tab: string;
  active: boolean;
  children: ReactNode;
  className?: string;
}) {
  const [visited, setVisited] = useState(active);
  if (active && !visited) setVisited(true);
  return (
    <div
      id={`${id}-pane-${tab}`}
      role="tabpanel"
      aria-labelledby={`${id}-tab-${tab}`}
      hidden={!active}
      tabIndex={active ? 0 : -1}
      className={cn("page-content", className)}
    >
      {visited && children}
    </div>
  );
}
