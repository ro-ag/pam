import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { Badge } from "../components/ui/Badge";
import { FailureNote } from "../components/ui/FailureNote";
import { Panel } from "../components/ui/Panel";
import { cn, cva } from "../lib/cn";
import { flowsList, toBridgeFailure, type FlowListEntry } from "../lib/ipc";
import { FlowEditor } from "./FlowEditor";
import { FlowRunCard } from "./FlowRunCard";
import { FlowRuns } from "./FlowRuns";

/**
 * Flows — the workbench. Everything pam knows how to do on its own,
 * shelved on the left; on the right, the one you picked: its text, and
 * everything it has ever done.
 *
 * The screen is human-facing by construction. Agents reach flows through
 * `pam flow run`, never through this; what lives here is the part only a
 * human should hold — writing the list of commands pam is allowed to
 * run, and reading back what running it actually produced.
 *
 * Two tabs, no third. YAML is the flow; Runs is its history. (Plan #6
 * adds the canvas beside YAML — a second reading of the same file, never
 * a second source of truth.)
 */

/** The tabs of the detail pane. */
const TABS = ["yaml", "runs"] as const;

type Tab = (typeof TABS)[number];

const tabVariants = cva(
  "h-8 rounded-control px-3 font-data text-xs transition-colors duration-150",
  {
    variants: {
      state: {
        active: "bg-accent-soft text-ink",
        idle: "text-ink-faint hover:text-ink",
      },
    },
    defaultVariants: { state: "idle" },
  },
);

// --- the library rail ------------------------------------------------------

function LibraryEntry({
  entry,
  active,
  onSelect,
}: {
  entry: FlowListEntry;
  active: boolean;
  onSelect: () => void;
}) {
  return (
    <li>
      <button
        type="button"
        aria-current={active ? "true" : undefined}
        onClick={onSelect}
        className={cn(
          "w-full space-y-1 rounded-control px-2.5 py-2 text-left transition-colors duration-150",
          active ? "bg-accent-soft" : "hover:bg-accent-soft/40",
        )}
      >
        <span className="flex items-center gap-2">
          <span className="min-w-0 flex-1 truncate font-data text-sm text-ink">{entry.id}</span>
          <Badge tone={entry.source === "builtin" ? "neutral" : "accent"}>{entry.source}</Badge>
        </span>
        <span className="block truncate font-sans text-xs text-ink-muted">{entry.name}</span>
        {!entry.valid && (
          <>
            <Badge tone="danger" title={entry.error ?? "this flow will not parse"}>
              invalid
            </Badge>
            <span className="block font-data text-xs text-danger">
              {entry.error ?? "this flow will not parse"}
            </span>
          </>
        )}
      </button>
    </li>
  );
}

// --- the screen ------------------------------------------------------------

export function FlowsScreen() {
  const flows = useQuery({ queryKey: ["flows"], queryFn: flowsList });
  const [picked, setPicked] = useState<string | null>(null);
  const [tab, setTab] = useState<Tab>("yaml");

  const entries = flows.data?.flows ?? [];
  // Nothing picked yet means the top of the shelf; a flow that just went
  // away (deleted, or renamed by a clone) falls back the same way.
  const selected = entries.find((entry) => entry.id === picked) ?? entries[0] ?? null;
  const failure = flows.isError ? toBridgeFailure(flows.error) : null;

  return (
    <div className="flex min-h-full flex-col px-8 pb-6">
      <header className="sticky top-0 z-10 space-y-3 bg-surface pt-8 pb-3">
        <p className="font-data text-xs tracking-widest text-ink-faint uppercase">
          {entries.length > 0 ? `flows · ${entries.length} on the shelf` : "flows"}
        </p>
        <h1 className="font-display text-title font-semibold text-ink">Flows</h1>
        <div className="border-b border-line" />
      </header>

      {failure && (
        <div className="max-w-xl pt-4">
          <FailureNote failure={failure} label="flows" />
        </div>
      )}

      {!failure && flows.isPending && (
        <p className="pt-6 font-data text-xs text-ink-faint">reading the shelf…</p>
      )}

      {!failure && !flows.isPending && selected === null && (
        <p className="max-w-md pt-6 font-voice text-lg text-ink-muted italic">
          There are no flows installed at all — not even mine. Something is wrong with the flow
          library; the daemon log will say what.
        </p>
      )}

      {!failure && selected !== null && (
        <div className="flex flex-1 flex-col gap-5 pt-6 lg:flex-row">
          <Panel ground="raised" aria-label="flow library" className="w-full p-2 lg:w-64">
            <ul className="space-y-0.5">
              {entries.map((entry) => (
                <LibraryEntry
                  key={entry.id}
                  entry={entry}
                  active={entry.id === selected.id}
                  onSelect={() => setPicked(entry.id)}
                />
              ))}
            </ul>
          </Panel>

          <section aria-label={`flow ${selected.id}`} className="min-w-0 flex-1 space-y-4">
            <div className="space-y-1.5">
              <h2 className="font-display text-lg font-semibold text-ink">{selected.name}</h2>
              <p className="max-w-xl font-voice text-base text-ink-muted italic">
                {selected.description || "This flow describes itself in its own YAML."}
              </p>
              <p className="font-data text-xs text-ink-faint">
                {selected.id} · {selected.steps} step{selected.steps === 1 ? "" : "s"}
                {selected.digest ? ` · ${selected.digest}` : ""}
              </p>
            </div>

            <div
              role="group"
              aria-label="flow view"
              className="flex items-center gap-0.5 border-b border-line pb-2"
            >
              {TABS.map((candidate) => (
                <button
                  key={candidate}
                  type="button"
                  aria-pressed={tab === candidate}
                  onClick={() => setTab(candidate)}
                  className={tabVariants({ state: tab === candidate ? "active" : "idle" })}
                >
                  {candidate}
                </button>
              ))}
            </div>

            {tab === "yaml" ? (
              <div className="space-y-4">
                <FlowEditor
                  key={selected.id}
                  entry={selected}
                  onSaved={(id) => setPicked(id)}
                  onDeleted={() => setPicked(null)}
                />
                <FlowRunCard key={`run-${selected.id}`} flow={selected} />
              </div>
            ) : (
              <FlowRuns flowId={selected.id} />
            )}
          </section>
        </div>
      )}
    </div>
  );
}
