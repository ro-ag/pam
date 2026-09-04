import { useQuery } from "@tanstack/react-query";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Badge } from "../components/ui/Badge";
import { FailureNote } from "../components/ui/FailureNote";
import { cn, cva } from "../lib/cn";
import { PageHeader } from "../components/ui/PageHeader";
import {
  flowsGet,
  flowsList,
  flowsNormalize,
  toBridgeFailure,
  type FlowListEntry,
  type FlowSpec,
  type RawFlow,
} from "../lib/ipc";
import { FlowCanvas, type Selection } from "./flow-canvas/FlowCanvas";
import { markerFor, toRaw, type RunStatus } from "./flow-canvas/graph";
import { Inspector } from "./flow-canvas/Inspector";
import { statusesFrom } from "./flow-canvas/notes";
import { FlowEditor } from "./FlowEditor";
import { FlowRunCard, useFlowVerdict, type FlowRunState } from "./FlowRunCard";
import { FlowRuns } from "./FlowRuns";

/**
 * Flows — the workbench. Everything pam knows how to do on its own,
 * shelved on the left; on the right, the one you picked: its shape, its
 * text, and everything it has ever done.
 *
 * The screen is human-facing by construction. Agents reach flows through
 * `pam flow run`, never through this; what lives here is the part only a
 * human should hold — writing the list of commands pam is allowed to
 * run, and reading back what running it actually produced.
 *
 * Three tabs, one file. Canvas and YAML are two readings of the same
 * draft — one lifted `{ yaml, spec, error, dirty }` per selected flow,
 * owned here — and every edit on either side goes through the daemon's
 * normalizer so the other side shows exactly what will be saved. Runs is
 * the flow's history. The daemon stays the only validator: the live
 * check between keystrokes can disable Save, never bless a flow.
 */

/** The tabs of the detail pane; the canvas comes first. */
const TABS = ["canvas", "yaml", "runs"] as const;

type Tab = (typeof TABS)[number];

/** How long the canvas waits after an edit before asking the daemon. */
export const CANVAS_QUIET_MS = 150;

/** How long the textarea waits — typing is bursty, a canvas gesture is not. */
export const YAML_QUIET_MS = 400;

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

// --- the draft ---------------------------------------------------------------

/** The first rule a draft breaks, as the daemon names it. */
export interface FlowIssue {
  path: string;
  message: string;
}

/** One selected flow, as both tabs see it. */
export interface Draft {
  yaml: string;
  /** The last shape the daemon accepted, or the canvas's own edit while it checks. */
  spec: FlowSpec | null;
  error: FlowIssue | null;
  dirty: boolean;
}

const EMPTY_DRAFT: Draft = { yaml: "", spec: null, error: null, dirty: false };

/**
 * The lifted draft and its round trip through `admin.flows.normalize`.
 *
 * A canvas edit lands in the spec at once (the node moves now) and, after
 * a short quiet, goes to the daemon as the raw file shape; the reply's
 * canonical YAML becomes the textarea's text and its resolved flow the
 * spec, so defaults the human never typed are filled in. A YAML edit goes
 * the other way after a longer quiet and only ever updates the spec and
 * the error — the human's text stays as typed until Save writes it.
 *
 * Only the newest request may answer. Every edit and every flow change
 * bumps a sequence number; a reply that comes back under an older number
 * is dropped, so a slow answer to a stale draft can never overwrite a
 * newer one. `flush` fires a pending yaml check at once, for the moment
 * the human switches to the canvas and wants to see what they typed.
 */
function useFlowDraft(entry: FlowListEntry) {
  const detail = useQuery({ queryKey: ["flow", entry.id], queryFn: () => flowsGet(entry.id) });
  const [draft, setDraft] = useState<Draft>(EMPTY_DRAFT);
  const [normalizing, setNormalizing] = useState(false);

  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const pending = useRef<(() => void) | null>(null);
  const sequence = useRef(0);

  const cancel = useCallback(() => {
    if (timer.current !== null) clearTimeout(timer.current);
    timer.current = null;
    pending.current = null;
  }, []);

  // The selected flow (or its file) changed: the draft starts over from
  // what the daemon holds, and any answer still in flight is stale.
  const fileError = entry.error ?? null;
  useEffect(() => {
    cancel();
    sequence.current += 1;
    setNormalizing(false);
    const data = detail.data;
    if (!data) {
      setDraft(EMPTY_DRAFT);
      return;
    }
    const spec = data.flow ?? null;
    setDraft({
      yaml: data.yaml,
      spec,
      error: spec ? null : { path: "yaml", message: fileError ?? "this flow will not parse" },
      dirty: false,
    });
  }, [entry.id, fileError, detail.data, cancel]);

  useEffect(() => cancel, [cancel]);

  const normalize = useCallback((input: { yaml: string } | { flow: RawFlow }) => {
    const run = ++sequence.current;
    setNormalizing(true);
    flowsNormalize(input)
      .then((reply) => {
        if (run !== sequence.current) return;
        setNormalizing(false);
        setDraft((prev) =>
          reply.valid
            ? {
                yaml: "flow" in input ? reply.yaml : prev.yaml,
                spec: reply.flow,
                error: null,
                dirty: prev.dirty,
              }
            : { ...prev, error: reply.error },
        );
      })
      .catch((error: unknown) => {
        if (run !== sequence.current) return;
        setNormalizing(false);
        const failure = toBridgeFailure(error);
        setDraft((prev) => ({
          ...prev,
          error: { path: "daemon", message: `${failure.cause} · ${failure.detail}` },
        }));
      });
  }, []);

  const schedule = useCallback(
    (action: () => void, quiet: number) => {
      cancel();
      // An edit after a request makes that request's answer stale.
      sequence.current += 1;
      setNormalizing(true);
      pending.current = action;
      timer.current = setTimeout(() => {
        timer.current = null;
        pending.current = null;
        action();
      }, quiet);
    },
    [cancel],
  );

  const flush = useCallback(() => {
    const action = pending.current;
    cancel();
    action?.();
  }, [cancel]);

  const changeSpec = useCallback(
    (spec: FlowSpec) => {
      setDraft((prev) => ({ ...prev, spec, dirty: true }));
      schedule(() => normalize({ flow: toRaw(spec) }), CANVAS_QUIET_MS);
    },
    [schedule, normalize],
  );

  const changeYaml = useCallback(
    (yaml: string) => {
      setDraft((prev) => ({ ...prev, yaml, dirty: true }));
      schedule(() => normalize({ yaml }), YAML_QUIET_MS);
    },
    [schedule, normalize],
  );

  return { detail, draft, normalizing, changeSpec, changeYaml, flush };
}

// --- the run, as rims --------------------------------------------------------

const NO_NOTES: readonly string[] = [];

/**
 * The per-step statuses a run has produced so far, with a stable identity:
 * the canvas rebuilds its nodes whenever this object changes, so a note
 * that says nothing new (a queue position, a summary) must not hand it a
 * fresh object. Keyed on the content, not on the notes array.
 */
function useRunStatuses(run: FlowRunState | null) {
  const verdict = useFlowVerdict(run?.settled ?? null);
  const notes = run?.notes ?? NO_NOTES;
  const key = useMemo(() => {
    const entries = verdict.data
      ? verdict.data.steps.map((step) => [step.id, step.status] as const)
      : Object.entries(statusesFrom(notes));
    return entries.map(([id, status]) => `${id}=${status}`).join(",");
  }, [verdict.data, notes]);
  const statuses = useMemo<Record<string, RunStatus>>(
    () =>
      Object.fromEntries(
        key
          .split(",")
          .filter(Boolean)
          .map((pair) => pair.split("=") as [string, RunStatus]),
      ),
    [key],
  );
  return { statuses, outcome: verdict.data?.outcome ?? null };
}

/** The same identity for the same issue, so the canvas does not rebuild on a repeat. */
function useStableIssue(issue: FlowIssue | null): FlowIssue | null {
  const key = issue === null ? null : JSON.stringify(issue);
  return useMemo(() => (key === null ? null : (JSON.parse(key) as FlowIssue)), [key]);
}

// --- the detail pane ---------------------------------------------------------

function FlowDetailPane({
  entry,
  tab,
  onTab,
  onSaved,
  onDeleted,
}: {
  entry: FlowListEntry;
  tab: Tab;
  onTab: (tab: Tab) => void;
  onSaved: (id: string) => void;
  onDeleted: () => void;
}) {
  const { detail, draft, normalizing, changeSpec, changeYaml, flush } = useFlowDraft(entry);
  const [selection, setSelection] = useState<Selection>({ kind: "none" });
  const [run, setRun] = useState<FlowRunState | null>(null);
  const { statuses, outcome } = useRunStatuses(run);
  const error = useStableIssue(draft.error);

  // A new flow means a fresh selection; the run card resets itself.
  useEffect(() => {
    setSelection({ kind: "none" });
    setRun(null);
  }, [entry.id]);

  // Any edit says the flow the run was about no longer exists as drawn.
  const onCanvasChange = useCallback(
    (spec: FlowSpec) => {
      setRun(null);
      changeSpec(spec);
    },
    [changeSpec],
  );
  const onYamlChange = useCallback(
    (yaml: string) => {
      setRun(null);
      changeYaml(yaml);
    },
    [changeYaml],
  );

  const loadFailure = detail.isError ? toBridgeFailure(detail.error) : null;
  const saveDisabled = draft.error !== null || normalizing;
  // A marker the canvas cannot pin on a node (the flow's own `id`, `name`,
  // an unparseable file) is said above the canvas instead.
  const flowIssue =
    error !== null && (draft.spec === null || markerFor(error, draft.spec).node === null)
      ? error
      : null;

  return (
    <>
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
            onClick={() => {
              if (candidate === "canvas") flush();
              onTab(candidate);
            }}
            className={tabVariants({ state: tab === candidate ? "active" : "idle" })}
          >
            {candidate}
          </button>
        ))}
      </div>

      {tab === "runs" ? (
        <FlowRuns flowId={entry.id} />
      ) : (
        <div className="space-y-4">
          {loadFailure && <FailureNote failure={loadFailure} label="flow" />}

          {draft.dirty && (
            <p aria-label="draft status" className="flex items-center gap-2 font-data text-xs">
              <Badge tone="warning">unsaved</Badge>
              <span className="text-ink-faint">
                {normalizing
                  ? "checking the flow…"
                  : draft.error
                    ? "the flow will not run as written"
                    : "both tabs show this draft; Save writes it"}
              </span>
            </p>
          )}

          {tab === "canvas" && (
            <div className="flow-workbench flex gap-4">
              <div className="min-w-0 flex-1 space-y-3">
                {flowIssue && (
                  <FailureNote
                    label="flow"
                    failure={{
                      cause: flowIssue.message,
                      detail: `at \`${flowIssue.path}\``,
                      recovery:
                        draft.spec === null
                          ? "fix the YAML below; the canvas draws it as soon as it parses"
                          : "fix it in the inspector or the YAML below",
                    }}
                  />
                )}
                {draft.spec ? (
                  <FlowCanvas
                    flowId={entry.id}
                    spec={draft.spec}
                    statuses={statuses}
                    outcome={outcome}
                    error={error}
                    onChange={onCanvasChange}
                    selection={selection}
                    onSelect={setSelection}
                  />
                ) : detail.isPending ? (
                  <p className="font-data text-xs text-ink-faint">reading the flow…</p>
                ) : null}
              </div>
              {draft.spec && (
                <div className="flow-inspector shrink-0">
                  <Inspector
                    spec={draft.spec}
                    selection={selection}
                    onChange={onCanvasChange}
                    onSelect={setSelection}
                    error={error}
                  />
                </div>
              )}
            </div>
          )}

          <FlowEditor
            key={entry.id}
            entry={entry}
            yaml={draft.yaml}
            onYamlChange={onYamlChange}
            saveDisabled={saveDisabled}
            onSaved={onSaved}
            onDeleted={onDeleted}
          />
          <FlowRunCard key={`run-${entry.id}`} flow={entry} onRun={setRun} />
        </div>
      )}
    </>
  );
}

// --- the screen ------------------------------------------------------------

export function FlowsScreen({ initialFlow }: { initialFlow?: string } = {}) {
  const flows = useQuery({ queryKey: ["flows"], queryFn: flowsList });
  const [picked, setPicked] = useState<string | null>(initialFlow ?? null);
  const [tab, setTab] = useState<Tab>("canvas");

  // `?flow=<id>` is a deep link (Ask Pam answers "run pr-readiness" with
  // one), so a second link to a different flow while the screen is
  // already mounted has to move the selection too. An id nobody has
  // falls through to the shelf's own fallback below.
  useEffect(() => {
    if (initialFlow) setPicked(initialFlow);
  }, [initialFlow]);

  const entries = flows.data?.flows ?? [];
  // Nothing picked yet means the top of the shelf; a flow that just went
  // away (deleted, or renamed by a clone) falls back the same way.
  const selected = entries.find((entry) => entry.id === picked) ?? entries[0] ?? null;
  const failure = flows.isError ? toBridgeFailure(flows.error) : null;

  return (
    <div className="flex min-h-full flex-col px-6 pb-6">
      <PageHeader>
        <h1 className="font-sans text-title font-semibold text-ink">Flows</h1>
        <p className="text-sm text-ink-muted">Reusable workflows and execution history.</p>
      </PageHeader>

      {failure && (
        <div className="max-w-xl pt-4">
          <FailureNote failure={failure} label="flows" />
        </div>
      )}

      {!failure && flows.isPending && (
        <p className="pt-6 font-data text-xs text-ink-faint">reading the shelf…</p>
      )}

      {!failure && !flows.isPending && selected === null && (
        <p className="max-w-md pt-6 font-sans text-lg text-ink-muted">
          There are no flows installed at all — not even mine. Something is wrong with the flow
          library; the daemon log will say what.
        </p>
      )}

      {!failure && selected !== null && (
        <div className="flow-library-layout flex flex-1 gap-5 pt-5">
          <section aria-label="flow library" className="flow-library min-w-0 shrink-0 pb-3">
            <h2 className="mb-2 px-2 text-xs font-medium text-ink-muted">Flow library</h2>
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
          </section>

          <section
            aria-label={`flow ${selected.id}`}
            className="flow-detail min-w-0 flex-1 space-y-4"
          >
            <div className="space-y-1.5">
              <h2 className="font-display text-lg font-semibold text-ink">{selected.name}</h2>
              <p className="max-w-xl font-sans text-sm text-ink-muted">
                {selected.description || "This flow describes itself in its own YAML."}
              </p>
              <p className="font-data text-xs text-ink-faint">
                {selected.id} · {selected.steps} step{selected.steps === 1 ? "" : "s"}
                {selected.digest ? ` · ${selected.digest}` : ""}
              </p>
            </div>

            <FlowDetailPane
              entry={selected}
              tab={tab}
              onTab={setTab}
              onSaved={(id) => setPicked(id)}
              onDeleted={() => setPicked(null)}
            />
          </section>
        </div>
      )}
    </div>
  );
}
