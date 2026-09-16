import { Link } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import {
  useCallback,
  useEffect,
  useLayoutEffect,
  useMemo,
  useRef,
  useState,
  type KeyboardEvent,
} from "react";
import { Badge } from "../components/ui/Badge";
import { Button } from "../components/ui/Button";
import { FailureNote } from "../components/ui/FailureNote";
import { fieldClasses } from "../components/ui/field";
import { cn } from "../lib/cn";
import { PageTabs } from "../components/ui/PageTabs";
import { Panel } from "../components/ui/Panel";
import { PageHeader } from "../components/ui/PageHeader";
import {
  connectorsList,
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
import { useFlowLibraryControls, type LibraryDraft } from "./FlowLibraryControls";
import { FlowEditor } from "./FlowEditor";
import { FlowRunCard, useFlowVerdict, type FlowRunState } from "./FlowRunCard";
import { FlowRuns } from "./FlowRuns";

/**
 * Flows — the workbench: everything pam can do on the left, the selected flow's shape, text, and
 * history on the right. Human-facing by construction: agents reach flows only through
 * `pam flow run`, never through this screen.
 * Canvas and YAML are two readings of one lifted `{ yaml, spec, error, dirty }` draft per flow;
 * every edit on either side goes through the daemon's normalizer so the other side shows exactly
 * what will be saved. The daemon stays the only validator — the live check between keystrokes can
 * disable Save, never bless a flow.
 */

/** The tabs of the detail pane; the canvas comes first. */
export const TABS = ["canvas", "yaml", "run", "runs"] as const;

export type Tab = (typeof TABS)[number];

/** How long the canvas waits after an edit before asking the daemon. */
export const CANVAS_QUIET_MS = 150;

/** How long the textarea waits — typing is bursty, a canvas gesture is not. */
export const YAML_QUIET_MS = 400;

// --- the library rail ------------------------------------------------------

/**
 * One option of the library listbox. The list owns keyboard movement
 * (roving tabindex, arrows, Home/End); an option only reports a click or
 * an Enter/Space on itself.
 */
function LibraryEntry({
  entry,
  active,
  tabbable,
  focused,
  onSelect,
  onFocusOption,
  onKeyDown,
}: {
  entry: FlowListEntry;
  active: boolean;
  /** The one option in the tab order (roving tabindex). */
  tabbable: boolean;
  /** Whether the arrows just moved focus here. */
  focused: boolean;
  onSelect: () => void;
  onFocusOption: () => void;
  onKeyDown: (event: KeyboardEvent<HTMLLIElement>) => void;
}) {
  const option = useRef<HTMLLIElement>(null);
  useEffect(() => {
    if (focused && document.activeElement !== option.current) option.current?.focus();
  }, [focused]);
  return (
    <li
      ref={option}
      role="option"
      aria-selected={active}
      tabIndex={tabbable ? 0 : -1}
      title={entry.id}
      onClick={onSelect}
      onFocus={onFocusOption}
      onKeyDown={(event) => {
        if (event.key === "Enter" || event.key === " ") {
          event.preventDefault();
          onSelect();
          return;
        }
        onKeyDown(event);
      }}
      className={cn(
        "navigation-item w-full space-y-1 rounded-control px-2.5 py-2 text-left",
        active && "bg-accent-soft",
      )}
    >
      <span className="block font-sans text-sm font-medium text-ink">
        {entry.name || entry.id}
      </span>
      {entry.source !== "builtin" && <Badge tone="accent">Custom</Badge>}
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
    </li>
  );
}

/** The library rail: a listbox whose keyboard focus roves with the arrows. */
function LibraryList({
  entries,
  selectedId,
  onPick,
}: {
  entries: FlowListEntry[];
  selectedId: string;
  onPick: (id: string) => void;
}) {
  // Focus follows the arrows; it starts on the selected flow and stays
  // where the arrows left it until the selection moves.
  const [focusedId, setFocusedId] = useState<string | null>(null);
  const focused = focusedId ?? selectedId;
  const [armed, setArmed] = useState(false);
  const move = (event: KeyboardEvent<HTMLLIElement>) => {
    const index = entries.findIndex((entry) => entry.id === focused);
    const next =
      event.key === "ArrowDown"
        ? Math.min(entries.length - 1, index + 1)
        : event.key === "ArrowUp"
          ? Math.max(0, index - 1)
          : event.key === "Home"
            ? 0
            : event.key === "End"
              ? entries.length - 1
              : null;
    if (next === null) return;
    event.preventDefault();
    setArmed(true);
    setFocusedId(entries[next]?.id ?? null);
  };
  return (
    <ul role="listbox" aria-label="Flow library" className="space-y-0.5">
      {entries.map((entry) => (
        <LibraryEntry
          key={entry.id}
          entry={entry}
          active={entry.id === selectedId}
          tabbable={entry.id === focused}
          focused={armed && entry.id === focused}
          onSelect={() => onPick(entry.id)}
          onFocusOption={() => setFocusedId(entry.id)}
          onKeyDown={move}
        />
      ))}
    </ul>
  );
}

// --- the draft ---------------------------------------------------------------

/** The first rule a draft breaks, as the daemon names it. */
interface FlowIssue {
  path: string;
  message: string;
}

/** One selected flow, as both tabs see it. */
interface Draft {
  yaml: string;
  /** The last shape the daemon accepted, or the canvas's own edit while it checks. */
  spec: FlowSpec | null;
  error: FlowIssue | null;
  dirty: boolean;
}

const EMPTY_DRAFT: Draft = { yaml: "", spec: null, error: null, dirty: false };

/**
 * The lifted draft and its round trip through `admin.flows.normalize`.
 * A canvas edit lands in the spec at once (the node moves now), then after a short quiet goes to
 * the daemon; the reply's canonical YAML becomes the textarea text and its resolved flow the
 * spec, filling in defaults the human never typed. A YAML edit goes the other way after a longer
 * quiet and only updates spec and error — text stays as typed until Save.
 * Only the newest request may answer: every edit and flow change bumps a sequence number, and a
 * reply under an older number is dropped. `flush` fires a pending yaml check at once, for
 * switching to canvas.
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

function ConnectorPrerequisites({ ids }: { ids: string[] }) {
  const connectors = useQuery({
    queryKey: ["connectors"],
    queryFn: connectorsList,
    enabled: ids.length > 0,
  });
  if (ids.length === 0) return null;
  return (
    <Panel ground="raised" className="space-y-2 p-4">
      <p className="text-sm font-medium text-ink">Required connectors</p>
      {ids.map((id) => {
        const row = connectors.data?.connectors.find((item) => item.id === id);
        const state =
          !connectors.isSuccess || connectors.isFetching
            ? "Readiness unavailable"
            : !row
              ? "Not configured"
              : !row.enabled
                ? "Disabled"
                : row.needs_base_url && !row.base_url
                  ? "Needs URL"
                  : row.auth !== "aws_profile" && !row.store_available
                    ? "Store unavailable"
                    : row.auth !== "aws_profile" &&
                        (!row.credential_present ||
                          (row.auth === "basic_user_secret" && !row.username?.trim()))
                      ? "Needs credentials"
                      : row.last_test?.status === "passed"
                        ? "Ready"
                        : row.last_test?.status === "failed"
                          ? "Test failed"
                          : "Untested";
        return (
          <p key={id} className="text-sm text-ink-muted">
            {row?.name ?? id}: {state}
            {" · "}
            <Link
              to="/settings"
              hash={`connectors/${id}`}
              className="text-accent-strong underline"
            >
              Set up {row?.name ?? id}
            </Link>
          </p>
        );
      })}
      <p className="text-sm text-ink-muted">
        A connection test checks service access; the run still enforces each step's policy and
        permissions.
      </p>
    </Panel>
  );
}

function FlowDetailPane({
  entry,
  tab,
  onTab,
  onDraft,
  busy,
  onSave,
  isLocked,
}: {
  entry: FlowListEntry;
  tab: Tab;
  onTab: (tab: Tab) => void;
  onDraft: (draft: LibraryDraft) => void;
  busy: boolean;
  onSave: () => void;
  isLocked: () => boolean;
}) {
  const { detail, draft, normalizing, changeSpec, changeYaml, flush } = useFlowDraft(entry);
  useEffect(
    () =>
      onDraft({
        id: entry.id,
        yaml: draft.yaml,
        dirty: draft.dirty,
        saveDisabled: normalizing || draft.error !== null || draft.spec === null,
      }),
    [entry.id, draft.yaml, draft.dirty, draft.error, draft.spec, normalizing, onDraft],
  );
  const [selection, setSelection] = useState<Selection>({ kind: "none" });
  const [run, setRun] = useState<FlowRunState | null>(null);
  const { statuses, outcome } = useRunStatuses(run);
  const error = useStableIssue(draft.error);
  const pane = useRef<HTMLDivElement>(null);
  const scrollPositions = useRef<Record<Tab, number>>({ canvas: 0, yaml: 0, run: 0, runs: 0 });
  useLayoutEffect(() => {
    if (pane.current) pane.current.scrollTop = scrollPositions.current[tab];
  }, [tab]);

  // A new flow means a fresh selection; the run card resets itself.
  useEffect(() => {
    setSelection({ kind: "none" });
    setRun(null);
  }, [entry.id]);

  // Any edit says the flow the run was about no longer exists as drawn.
  const onCanvasChange = useCallback(
    (spec: FlowSpec) => {
      if (busy || isLocked()) return;
      setRun(null);
      changeSpec(spec);
    },
    [changeSpec, busy, isLocked],
  );
  const onYamlChange = useCallback(
    (yaml: string) => {
      if (busy || isLocked()) return;
      setRun(null);
      changeYaml(yaml);
    },
    [changeYaml, busy, isLocked],
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
      <PageTabs
        id="flow"
        label="flow view"
        tabs={TABS.map((id) => ({
          id,
          label:
            id === "yaml"
              ? "YAML"
              : id === "runs"
                ? "Run history"
                : id === "run"
                  ? "Run flow"
                  : "Canvas",
        }))}
        selected={tab}
        onSelect={(candidate) => {
          scrollPositions.current[tab] = pane.current?.scrollTop ?? 0;
          if (candidate === "canvas") flush();
          onTab(candidate);
        }}
      />
      {TABS.filter((candidate) => candidate !== tab).map((candidate) => (
        <div
          key={candidate}
          id={`flow-pane-${candidate}`}
          role="tabpanel"
          aria-labelledby={`flow-tab-${candidate}`}
          hidden
        />
      ))}
      <div
        ref={pane}
        id={`flow-pane-${tab}`}
        role="tabpanel"
        aria-labelledby={`flow-tab-${tab}`}
        tabIndex={0}
        className={cn("page-content", tab === "canvas" && "flow-canvas-pane")}
      >
        {tab === "runs" && <FlowRuns flowId={entry.id} />}
        <div className="flow-editor-pane space-y-4" hidden={tab === "run" || tab === "runs"}>
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
              <div className="flow-canvas-column min-w-0 flex-1 space-y-3">
                {flowIssue && (
                  <FailureNote
                    label="flow"
                    failure={{
                      cause: flowIssue.message,
                      detail: `at \`${flowIssue.path}\``,
                      recovery:
                        draft.spec === null
                          ? "Open YAML to fix the flow; the canvas returns once it parses"
                          : "Fix it in the inspector or open YAML",
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
                <div className="flow-inspector">
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
            showYaml={tab === "yaml"}
            onYamlChange={onYamlChange}
            saveDisabled={saveDisabled}
            onSave={onSave}
            busy={busy}
          />
        </div>
        <div hidden={tab !== "run"} className="max-w-content space-y-4">
          <p className="text-sm text-ink-muted">Choose a repository and run the saved flow.</p>
          {draft.dirty && (
            <p className="text-sm text-warning">
              You have unsaved changes. Save or clone them before running the updated flow.
            </p>
          )}
          <ConnectorPrerequisites
            ids={[
              ...new Set(
                (detail.data?.flow?.steps ?? []).flatMap((step) =>
                  step.action.kind === "connector" ? [step.action.connector] : [],
                ),
              ),
            ]}
          />
          <FlowRunCard key={`run-${entry.id}`} flow={entry} onRun={setRun} />
        </div>
      </div>
    </>
  );
}

// --- the screen ------------------------------------------------------------

export function FlowsScreen({
  initialFlow,
  initialTab,
  onDirtyChange,
  navigation,
}: {
  initialFlow?: string;
  /** The tab `?flow=<id>&tab=` names; canvas when absent. */
  initialTab?: Tab;
  onDirtyChange?: (dirty: boolean) => void;
  navigation?: { pending: boolean; proceed?: () => void; cancel?: () => void };
} = {}) {
  const flows = useQuery({ queryKey: ["flows"], queryFn: flowsList });
  const [picked, setPicked] = useState<string | null>(initialFlow ?? null);
  const [tab, setTab] = useState<Tab>(initialTab ?? "canvas");
  const [draft, setDraft] = useState<LibraryDraft | null>(null);
  const [revision, setRevision] = useState(0);
  const discard = useCallback(() => {
    setDraft(null);
    setRevision((value) => value + 1);
  }, []);
  useEffect(() => {
    onDirtyChange?.(draft?.dirty ?? false);
  }, [draft?.dirty, onDirtyChange]);

  // `?flow=<id>` is a deep link (Ask Pam answers "run pr-readiness" with
  // one), so a second link to a different flow while the screen is
  // already mounted has to move the selection too. An id nobody has
  // falls through to the shelf's own fallback below.

  const entries = flows.data?.flows ?? [];
  // Nothing picked yet means the top of the shelf; a flow that just went
  // away (deleted, or renamed by a clone) falls back the same way.
  const selected = entries.find((entry) => entry.id === picked) ?? entries[0] ?? null;
  const failure = flows.isError ? toBridgeFailure(flows.error) : null;
  const controls = useFlowLibraryControls({
    entries,
    selected,
    draft,
    ready: flows.isSuccess && !flows.isFetching,
    onSelected: setPicked,
    onDiscard: discard,
  });
  const { requestNavigation } = controls;
  const handledNavigation = useRef<(() => void) | undefined>(undefined);
  useEffect(() => {
    if (!navigation?.pending) {
      handledNavigation.current = undefined;
      return;
    }
    if (handledNavigation.current !== navigation.proceed && navigation.proceed) {
      handledNavigation.current = navigation.proceed;
      requestNavigation(navigation.proceed, navigation.cancel);
    }
  }, [navigation, requestNavigation]);
  const previousInitialFlow = useRef(initialFlow);
  useEffect(() => {
    if (initialFlow && initialFlow !== previousInitialFlow.current) {
      previousInitialFlow.current = initialFlow;
      requestNavigation(() => {
        setPicked(initialFlow);
        if (initialTab) setTab(initialTab);
      });
    }
  }, [initialFlow, initialTab, requestNavigation]);

  return (
    <div className="page-workspace">
      <PageHeader>
        <h1 className="font-sans text-title font-semibold text-ink">Flows</h1>
        <p className="text-sm text-ink-muted">Reusable workflows and execution history.</p>
        {controls.toolbar}
      </PageHeader>

      {controls.dialogs}
      {failure && (
        <div className="pt-4">
          <FailureNote failure={failure} label="flows">
            <Button size="sm" variant="secondary" onClick={() => void flows.refetch()}>
              Retry
            </Button>
          </FailureNote>
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
        <div className="flow-library-layout flex flex-1">
          <section aria-label="flow library" className="flow-library min-w-0 shrink-0">
            <h2 className="mb-2 px-2 text-xs font-medium text-ink-muted">Flow library</h2>
            <LibraryList
              entries={entries}
              selectedId={selected.id}
              onPick={(id) => {
                if (id !== selected.id) requestNavigation(() => setPicked(id));
              }}
            />
          </section>

          <section aria-label={`flow ${selected.id}`} className="flow-detail min-w-0 flex-1">
            <label className="flow-picker space-y-1">
              <span className="block text-xs font-medium text-ink-muted">Flow library</span>
              <select
                aria-label="Choose flow"
                value={selected.id}
                onChange={(event) => {
                  const next = event.target.value;
                  requestNavigation(() => setPicked(next));
                }}
                className={cn(fieldClasses, "px-2 font-sans text-sm")}
              >
                {entries.map((entry) => (
                  <option key={entry.id} value={entry.id}>
                    {entry.name || entry.id}
                    {entry.valid ? "" : " (invalid)"}
                  </option>
                ))}
              </select>
            </label>
            <div className="flow-detail-header shrink-0 space-y-1.5">
              <h2 className="font-display text-lg font-semibold text-ink">{selected.name}</h2>
              <p className="max-w-xl font-sans text-sm text-ink-muted">
                {selected.description || "This flow describes itself in its own YAML."}
              </p>
              <p className="font-data text-xs text-ink-faint">
                {selected.steps} step{selected.steps === 1 ? "" : "s"} ·{" "}
                {selected.source === "builtin" ? "Built-in flow" : "Custom flow"}
              </p>
            </div>

            <FlowDetailPane
              key={`${selected.id}-${revision}`}
              entry={selected}
              tab={tab}
              onTab={(next) => {
                if (
                  (tab === "canvas" || tab === "yaml") &&
                  (next === "canvas" || next === "yaml")
                )
                  setTab(next);
                else requestNavigation(() => setTab(next));
              }}
              onDraft={setDraft}
              busy={controls.busy}
              onSave={controls.saveDraft}
              isLocked={controls.isLocked}
            />
          </section>
        </div>
      )}
    </div>
  );
}
