import {
  ArrowClockwise,
  ArrowDown,
  BookOpen,
  CaretDown,
  CaretLeft,
  CaretRight,
  CaretUp,
  Check,
  CheckCircle,
  Circle,
  Copy,
  FileText,
  FloppyDisk,
  FolderOpen,
  Gear,
  GitBranch,
  ListChecks,
  LockSimple,
  MagnifyingGlass,
  Play,
  Power,
  Pulse,
  Queue,
  SidebarSimple,
  WarningCircle,
  Wrench,
  X,
} from "@phosphor-icons/react";
import {
  type KeyboardEvent as ReactKeyboardEvent,
  type PointerEvent as ReactPointerEvent,
  type RefObject,
  useCallback,
  useEffect,
  useReducer,
  useRef,
  useState,
  useId,
} from "react";
import { nextOperationId, sameFence, withOperation } from "./bridge";
import type {
  ApprovalDecision,
  CommandFence,
  EvidenceDataDto,
  FlowDocumentDataDto,
  FlowReviewDataDto,
  FlowWorkspaceDataDto,
  PamBridge,
  SnapshotDto,
  ViewId,
} from "./domain";
import { MAX_EVIDENCE_TEXT, MAX_FLOW_SOURCE } from "./domain";
import type { AgentBriefView, ControlCenterView, ProjectView, TimelineItemView } from "./selectors";
import { selectControlCenter } from "./selectors";
import { appReducer, initialState, presentError } from "./state";

interface AppProps {
  bridge: PamBridge;
  initialView?: ViewId;
}

const navItems: ReadonlyArray<{ id: ViewId; label: string; icon: typeof Pulse }> = [
  { id: "current", label: "Current", icon: Pulse },
  { id: "flows", label: "Flows", icon: GitBranch },
  { id: "access", label: "Access", icon: LockSimple },
];

function formatClock(iso: string): string {
  const date = new Date(iso);
  return Number.isNaN(date.valueOf())
    ? "Time unavailable"
    : new Intl.DateTimeFormat(undefined, { hour: "numeric", minute: "2-digit" }).format(date);
}

function formatDateTime(iso: string): string {
  const date = new Date(iso);
  return Number.isNaN(date.valueOf())
    ? "Time unavailable"
    : new Intl.DateTimeFormat(undefined, {
        month: "long",
        day: "numeric",
        year: "numeric",
        hour: "numeric",
        minute: "2-digit",
      }).format(date);
}

function briefText(brief: AgentBriefView): string {
  return [
    brief.title,
    ...brief.sections.map((section) => `${section.label}: ${section.summary}`),
  ].join("\n");
}

function acceptsResponseFence(requestFence: CommandFence, responseFence: CommandFence): boolean {
  return sameFence(requestFence, responseFence) || (
    requestFence.generation === "" &&
    requestFence.projectHandle === responseFence.projectHandle &&
    requestFence.operationId === responseFence.operationId
  );
}

function sameAuthority(left: CommandFence, right: CommandFence): boolean {
  return left.projectHandle === right.projectHandle && left.generation === right.generation;
}

function StatusDot({ state = "coral" }: { state?: "coral" | "aqua" | "muted" }) {
  return <Circle className={`status-dot status-dot--${state}`} size={12} weight="fill" aria-hidden="true" />;
}

function ProjectMenu({
  active,
  projects,
  onSelect,
}: {
  active: ProjectView;
  projects: ProjectView[];
  onSelect: (project: ProjectView) => void;
}) {
  const [open, setOpen] = useState(false);
  const [focusedIndex, setFocusedIndex] = useState(0);
  const wrap = useRef<HTMLDivElement>(null);
  const switcher = useRef<HTMLButtonElement>(null);
  const menuItems = useRef<Array<HTMLButtonElement | null>>([]);

  const focusMenuItem = (index: number) => {
    const bounded = Math.max(0, Math.min(projects.length - 1, index));
    setFocusedIndex(bounded);
    window.requestAnimationFrame(() => menuItems.current[bounded]?.focus());
  };

  const openMenu = (index = projects.findIndex((project) => project.handle === active.handle)) => {
    setOpen(true);
    focusMenuItem(index < 0 ? 0 : index);
  };

  useEffect(() => {
    if (!open) return;
    const close = (event: MouseEvent) => {
      if (!wrap.current?.contains(event.target as Node)) setOpen(false);
    };
    document.addEventListener("mousedown", close);
    return () => document.removeEventListener("mousedown", close);
  }, [open]);

  return (
    <div className="project-menu-wrap" ref={wrap}>
      <button
        type="button"
        ref={switcher}
        className="project-switcher"
        aria-haspopup="menu"
        aria-expanded={open}
        onClick={() => { if (open) setOpen(false); else openMenu(); }}
        onKeyDown={(event) => {
          if (event.key === "Escape") {
            event.preventDefault();
            setOpen(false);
          } else if (event.key === "ArrowDown") {
            event.preventDefault();
            openMenu();
          }
        }}
      >
        <GitBranch size={19} aria-hidden="true" />
        <span>{active.name}</span>
        <CaretDown size={16} weight="bold" aria-hidden="true" />
      </button>
      {open && (
        <div className="project-menu" role="menu" aria-label="Registered projects">
          {projects.map((project, index) => (
            <button
              type="button"
              ref={(element) => { menuItems.current[index] = element; }}
              role="menuitemradio"
              aria-checked={project.handle === active.handle}
              tabIndex={index === focusedIndex ? 0 : -1}
              key={project.handle}
              onClick={() => {
                onSelect(project);
                setOpen(false);
                switcher.current?.focus();
              }}
              onKeyDown={(event) => {
                if (event.key === "ArrowDown") { event.preventDefault(); focusMenuItem((index + 1) % projects.length); }
                else if (event.key === "ArrowUp") { event.preventDefault(); focusMenuItem((index - 1 + projects.length) % projects.length); }
                else if (event.key === "Home") { event.preventDefault(); focusMenuItem(0); }
                else if (event.key === "End") { event.preventDefault(); focusMenuItem(projects.length - 1); }
                else if (event.key === "Escape") { event.preventDefault(); setOpen(false); switcher.current?.focus(); }
              }}
            >
              <span className={`health-dot health-dot--${project.health}`} aria-hidden="true" />
              <span>
                <strong>{project.name}</strong>
                <small>{project.branch ?? project.rootLabel}</small>
              </span>
              {project.handle === active.handle && <Check size={15} weight="bold" aria-hidden="true" />}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}

function Sidebar({
  data,
  activeView,
  collapsed,
  pending,
  onNavigate,
  onSelectProject,
  onToggleDaemon,
  containerRef,
}: {
  data: ControlCenterView;
  activeView: ViewId;
  collapsed: boolean;
  pending: boolean;
  onNavigate: (view: ViewId) => void;
  onSelectProject: (project: ProjectView) => void;
  onToggleDaemon: () => void;
  containerRef: RefObject<HTMLElement | null>;
}) {
  return (
    <aside ref={containerRef} className={`sidebar ${collapsed ? "is-collapsed" : ""}`} aria-label="Project navigation">
      <div className="brand" aria-label="PAM">
        <img src="/assets/pam-mark.png" alt="" />
        {!collapsed && <span>PAM</span>}
      </div>
      {!collapsed ? (
        <ProjectMenu active={data.project} projects={data.catalog} onSelect={onSelectProject} />
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

function ResizeSeparator({
  collapsed,
  width,
  onResize,
  onToggle,
}: {
  collapsed: boolean;
  width: number;
  onResize: (width: number) => void;
  onToggle: () => void;
}) {
  const start = useRef<{ x: number; width: number } | null>(null);
  const onPointerDown = (event: ReactPointerEvent<HTMLDivElement>) => {
    start.current = { x: event.clientX, width };
    event.currentTarget.setPointerCapture(event.pointerId);
  };
  const onPointerMove = (event: ReactPointerEvent<HTMLDivElement>) => {
    if (!start.current || collapsed) return;
    onResize(start.current.width + event.clientX - start.current.x);
  };
  const onKeyDown = (event: ReactKeyboardEvent<HTMLDivElement>) => {
    if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      onToggle();
    } else if (event.key === "ArrowLeft") {
      event.preventDefault();
      if (collapsed) onToggle();
      else onResize(width - (event.shiftKey ? 32 : 8));
    } else if (event.key === "ArrowRight") {
      event.preventDefault();
      if (collapsed) onToggle();
      else onResize(width + (event.shiftKey ? 32 : 8));
    } else if (event.key === "Home") {
      event.preventDefault();
      onResize(208);
    } else if (event.key === "End") {
      event.preventDefault();
      onResize(368);
    }
  };
  return (
    <div
      className="resize-separator"
      role="separator"
      aria-orientation="vertical"
      aria-valuemin={collapsed ? 68 : 208}
      aria-valuemax={368}
      aria-valuenow={collapsed ? 68 : width}
      aria-label="Resize project sidebar"
      tabIndex={0}
      onDoubleClick={onToggle}
      onKeyDown={onKeyDown}
      onPointerDown={onPointerDown}
      onPointerMove={onPointerMove}
      onPointerUp={() => { start.current = null; }}
      onPointerCancel={() => { start.current = null; }}
    />
  );
}

function Toolbar({
  data,
  collapsed,
  pending,
  onToggleSidebar,
  onRefresh,
  onOpenQueue,
  toggleButtonRef,
}: {
  data: ControlCenterView;
  collapsed: boolean;
  pending: boolean;
  onToggleSidebar: () => void;
  onRefresh: () => void;
  onOpenQueue: () => void;
  toggleButtonRef: RefObject<HTMLButtonElement | null>;
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
        <button type="button" aria-label="Open queue" title="Open queue" onClick={onOpenQueue}>
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

const timelineIcons = {
  request: ArrowDown,
  evidence: MagnifyingGlass,
  change: Wrench,
  verification: Check,
  failure: WarningCircle,
};

function TimelineEventRow({ item, last }: { item: TimelineItemView; last: boolean }) {
  const Icon = timelineIcons[item.kind];
  return (
    <li className={`timeline-row timeline-row--${item.kind}`}>
      <div className="timeline-marker" aria-hidden="true">
        <span><Icon size={21} weight={item.kind === "verification" ? "bold" : "regular"} /></span>
        {!last && <i />}
      </div>
      <div className="timeline-copy">
        <strong>{item.title}</strong>
        <span>{item.description}</span>
      </div>
      {item.occurredAt ? (
        <time dateTime={item.occurredAt}>
          <span>{item.relativeLabel}</span>
          <span>{formatClock(item.occurredAt)}</span>
        </time>
      ) : <span className="timeline-sequence">{item.relativeLabel}</span>}
    </li>
  );
}

function HandoffPanel({
  brief,
  onCopy,
  onEvidence,
  onContinue,
}: {
  brief: AgentBriefView;
  onCopy: () => void;
  onEvidence: (handle: string) => void;
  onContinue: () => void;
}) {
  return (
    <section className="handoff-panel" aria-labelledby="handoff-title">
      <h2 id="handoff-title">{brief.title}</h2>
      <dl className="brief-grid">
        {brief.sections.map((section) => (
          <div key={section.label}>
            <dt>{section.label}</dt>
            <dd className="outcome-section-summary">
              <span className={`state-pill state-pill--${section.satisfied ? "observed" : "not-reported"}`}>
                {section.satisfied ? "yes" : "no"}
              </span>
              <span>{section.summary}</span>
            </dd>
          </div>
        ))}
      </dl>
      <div className="provenance">
        <div className="provenance-intro">
          <GitBranch size={19} weight="bold" aria-hidden="true" />
          <strong>Provenance</strong>
          <span>
            {brief.evidenceHandles.length > 0
              ? `${brief.evidenceHandles.length} evidence handle${brief.evidenceHandles.length === 1 ? "" : "s"} reported by the terminal result${brief.evidenceTruncated ? "; additional handles were truncated" : ""}.`
              : "The terminal result reported no evidence handles."}
          </span>
        </div>
        <div className="evidence-handles">
          {brief.evidenceHandles.map((handle, index) => (
            <button type="button" aria-label={`Open Evidence ${index + 1}`} key={handle} onClick={() => onEvidence(handle)}>
              <FileText size={17} aria-hidden="true" />
              <span>Evidence {index + 1}</span>
              <code>{handle.slice(0, 8)}…{handle.slice(-4)}</code>
            </button>
          ))}
        </div>
      </div>
      <div className="handoff-actions">
        <button type="button" className="button button--primary" onClick={onCopy}>
          <Copy size={19} weight="bold" /> Copy outcome brief
        </button>
        <div>
          <button type="button" className="button button--secondary" disabled={brief.evidenceHandles.length === 0} onClick={() => brief.evidenceHandles[0] && onEvidence(brief.evidenceHandles[0])}>
            <FolderOpen size={19} /> Open evidence
          </button>
          <button type="button" className="button button--secondary" onClick={onContinue}>
            <Play size={19} /> Continue flow
          </button>
        </div>
      </div>
    </section>
  );
}

function CurrentView({
  data,
  onCopy,
  onEvidence,
  onContinue,
  onOpenQueue,
  onOpenApproval,
  onRecoverDaemon,
  onRefresh,
  onRegisterCaller,
  registrationBusy,
}: {
  data: ControlCenterView;
  onCopy: (brief: AgentBriefView) => void;
  onEvidence: (handle: string) => void;
  onContinue: () => void;
  onOpenQueue: () => void;
  onOpenApproval: () => void;
  onRecoverDaemon: () => void;
  onRefresh: () => void;
  onRegisterCaller: () => void;
  registrationBusy: boolean;
}) {
  const [expanded, setExpanded] = useState(true);
  const outcome = data.current.latestOutcome;
  const timeline = data.current.activeRun?.timeline ?? outcome?.timeline ?? [];
  const missingCredential = data.current.recoveryAction === "register-caller";
  const canStartDaemon = data.current.recoveryAction === "start-daemon";
  return (
    <main className="canvas" id="main-content">
      <header className="project-header">
        <div>
          <h1>{data.project.name}</h1>
          <p>
            <StatusDot state={data.daemon.state === "running" ? "coral" : "muted"} />
            {data.daemon.detail}
            {data.daemon.model && <><span>·</span>{data.daemon.model}</>}
            {data.daemon.modelMemory && <><span>·</span>{data.daemon.modelMemory}</>}
          </p>
        </div>
        <time dateTime={data.nowIso}>{formatDateTime(data.nowIso)}</time>
      </header>
      {data.catalogWarning && <div className="surface-notice" role="status"><WarningCircle size={18} /><span>{data.catalogWarning}</span></div>}
      {data.current.failure && <div className="surface-notice is-error" role="alert"><WarningCircle size={18} /><span>{data.current.failure}</span></div>}
      {data.current.approval ? (
        <section className="empty-state state-card is-attention">
          <WarningCircle size={38} aria-hidden="true" />
          <h2>Approval required</h2>
          <p>The selected project's bounded current queue and latest run are waiting for your decision.</p>
          <button type="button" className="button button--primary" onClick={onOpenApproval}>Review exact effect</button>
        </section>
      ) : timeline.length === 0 && data.current.failure ? (
        <section className="empty-state state-card is-attention">
          <WarningCircle size={38} aria-hidden="true" />
          <h2>Authenticated project state is unavailable</h2>
          <p>{missingCredential
            ? "Register the GUI caller credential, then retry authenticated project loading."
            : canStartDaemon
              ? "Start PAM, then retry authenticated project loading."
              : "Use the recovery guidance above, then retry authenticated project loading."}</p>
          <div className="state-actions">
            {missingCredential
              ? <button type="button" className="button button--primary" disabled={registrationBusy} onClick={onRegisterCaller}><LockSimple size={18} /> {registrationBusy ? "Registering…" : "Register GUI caller"}</button>
              : canStartDaemon
                ? <button type="button" className="button button--primary" disabled={registrationBusy} onClick={onRecoverDaemon}><Power size={18} /> Start PAM</button>
                : null}
            <button type="button" className="button button--secondary" disabled={registrationBusy} onClick={onRefresh}><ArrowClockwise size={18} /> Retry</button>
          </div>
        </section>
      ) : timeline.length === 0 && !data.current.activeRun && data.current.queue.length > 0 ? (
        <section className="empty-state state-card">
          <Queue size={38} aria-hidden="true" />
          <h2>{data.current.queue.length} project request{data.current.queue.length === 1 ? " is" : "s are"} queued</h2>
          <p>Next: {data.current.queue[0]?.operationKind}. PAM remains on watch while durable work waits.</p>
          <button type="button" className="button button--secondary" onClick={onOpenQueue}>Open project queue</button>
        </section>
      ) : timeline.length === 0 && !data.current.activeRun ? (
        <section className="empty-state">
          <Pulse size={38} aria-hidden="true" />
          <h2>No current activity</h2>
          <p>PAM is watching this project. New requests and evidence will appear here.</p>
        </section>
      ) : (
        <section className="timeline-surface" aria-label={`${data.project.name} activity timeline`}>
          {data.current.activeRun && <div className="active-run-strip" role="status"><Pulse size={18} aria-hidden="true" /><strong>{data.current.activeRun.state === "cancelling" ? "Cancelling durable request" : "Active durable request"}</strong><span>{data.current.activeRun.operationKind}</span><span className={`state-pill state-pill--${data.current.activeRun.state}`}>{data.current.activeRun.state}</span></div>}
          <ol className="timeline-list">
            {timeline.map((item, index) => <TimelineEventRow item={item} last={index === timeline.length - 1} key={item.id} />)}
          </ol>
          {outcome?.brief && (
            <article className={`outcome-card ${outcome.state === "succeeded" ? "is-solved" : "is-attention"}`}>
              <button type="button" className="outcome-summary" aria-expanded={expanded} onClick={() => setExpanded((value) => !value)}>
                <span>{outcome.state === "succeeded"
                  ? <CheckCircle size={24} weight="regular" aria-hidden="true" />
                  : <WarningCircle size={24} weight="regular" aria-hidden="true" />}</span>
                <span><strong>{outcome.title}</strong><small>{outcome.state === "succeeded" ? "Terminal result · solved" : "Terminal result · follow-up required"}</small></span>
                {expanded ? <CaretUp size={18} weight="bold" /> : <CaretDown size={18} weight="bold" />}
              </button>
              {expanded && <HandoffPanel brief={outcome.brief} onCopy={() => onCopy(outcome.brief!)} onEvidence={onEvidence} onContinue={onContinue} />}
            </article>
          )}
        </section>
      )}
    </main>
  );
}

function AccessView({ data }: { data: ControlCenterView }) {
  const accessIcon = (id: string) => id === "model"
    ? Pulse
    : id === "policy"
      ? LockSimple
      : id === "certificates"
        ? FileText
        : id === "network"
          ? GitBranch
          : WarningCircle;
  return (
    <main className="canvas" id="main-content">
      <header className="project-header compact"><div><h1>Access</h1><p>Narrow capabilities, visible to the developer.</p></div></header>
      <section className="panel access-panel" aria-labelledby="access-heading">
        <div className="panel-title"><div><span className="eyebrow">Project boundary</span><h2 id="access-heading">Authorized capabilities</h2></div><LockSimple size={22} /></div>
        <div className="access-list">
          {data.access.length === 0 ? <p className="panel-empty">No access grants are configured for this project.</p> : data.access.map((grant) => {
              const Icon = accessIcon(grant.id);
              return <article key={grant.id}>
              <span className="access-icon"><Icon size={21} /></span>
              <div><strong>{grant.name}</strong><p>{grant.summary}</p></div>
              <span className={`state-pill state-pill--${grant.state}`}>{grant.state}</span>
            </article>;
          })}
        </div>
      </section>
    </main>
  );
}

function FlowsView({ bridge, fence, onError, onToast }: { bridge: PamBridge; fence: CommandFence; onError: (message: string) => void; onToast: (message: string) => void }) {
  const [workspace, setWorkspace] = useState<FlowWorkspaceDataDto | null>(null);
  const [selected, setSelected] = useState<FlowDocumentDataDto | null>(null);
  const [draft, setDraft] = useState("");
  const [review, setReview] = useState<FlowReviewDataDto | null>(null);
  const [reviewedSource, setReviewedSource] = useState<string | null>(null);
  const [reviewPanel, setReviewPanel] = useState<"dry-run" | "diff">("dry-run");
  const [loadError, setLoadError] = useState<string | null>(null);
  const [validationError, setValidationError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const validationErrorId = useId();
  const fenceRef = useRef(fence);
  const requestSequence = useRef(0);
  fenceRef.current = fence;

  const isCurrentRequest = useCallback((sequence: number, requestFence: CommandFence) => (
    sequence === requestSequence.current && sameAuthority(requestFence, fenceRef.current)
  ), []);

  const load = useCallback(async () => {
    const sequence = ++requestSequence.current;
    const requestFence = withOperation(fenceRef.current);
    setBusy(true);
    setLoadError(null);
    setWorkspace(null);
    setSelected(null);
    setDraft("");
    setReview(null);
    setReviewedSource(null);
    setReviewPanel("dry-run");
    setValidationError(null);
    try {
      const response = await bridge.loadFlowWorkspace(requestFence);
      if (!isCurrentRequest(sequence, requestFence)) return;
      if (!sameFence(requestFence, response.fence)) {
        setLoadError("The flow workspace response did not match the active project request. Retry flows.");
        return;
      }
      setWorkspace(response.data);
    } catch (error) {
      if (isCurrentRequest(sequence, requestFence)) setLoadError(presentError(error));
    } finally {
      if (isCurrentRequest(sequence, requestFence)) setBusy(false);
    }
  }, [bridge, isCurrentRequest]);

  useEffect(() => {
    void load();
    return () => { requestSequence.current += 1; };
  }, [load, fence.projectHandle, fence.generation]);

  const open = async (flowHandle: string) => {
    const sequence = ++requestSequence.current;
    const requestFence = withOperation(fenceRef.current);
    setBusy(true);
    setSelected(null);
    setDraft("");
    setReview(null);
    setReviewedSource(null);
    setReviewPanel("dry-run");
    setValidationError(null);
    try {
      const response = await bridge.openFlow(requestFence, flowHandle);
      if (!isCurrentRequest(sequence, requestFence)) return;
      if (!sameFence(requestFence, response.fence)) {
        onError("The flow document response did not match the active project request.");
        return;
      }
      setSelected(response.data);
      setDraft(response.data.source);
    } catch (error) {
      if (isCurrentRequest(sequence, requestFence)) onError(presentError(error));
    } finally {
      if (isCurrentRequest(sequence, requestFence)) setBusy(false);
    }
  };

  const validate = async () => {
    if (!selected) return;
    const source = draft.slice(0, MAX_FLOW_SOURCE);
    const documentHandle = selected.handle;
    const sequence = ++requestSequence.current;
    const requestFence = withOperation(fenceRef.current);
    setBusy(true);
    setReview(null);
    setReviewedSource(null);
    setValidationError(null);
    try {
      const response = await bridge.validateFlow(requestFence, documentHandle, source);
      if (!isCurrentRequest(sequence, requestFence)) return;
      if (!sameFence(requestFence, response.fence)) {
        setValidationError("The flow validation response did not match the active project request. Retry validation.");
        return;
      }
      setReview(response.data);
      setReviewedSource(source);
      setReviewPanel("dry-run");
      onToast(response.data.dryRun.daemonDefinitionEligible ? "Flow document is valid and daemon-eligible" : "Flow document is valid with authority limits");
    } catch (error) {
      if (isCurrentRequest(sequence, requestFence)) setValidationError(presentError(error));
    } finally {
      if (isCurrentRequest(sequence, requestFence)) setBusy(false);
    }
  };

  const save = async () => {
    const source = draft.slice(0, MAX_FLOW_SOURCE);
    if (!selected || !review || reviewedSource !== source || !review.diff.changed) return;
    const normalizedSource = review.normalizedToml.slice(0, MAX_FLOW_SOURCE);
    const documentHandle = selected.handle;
    const sequence = ++requestSequence.current;
    const requestFence = withOperation(fenceRef.current);
    setBusy(true);
    try {
      const response = await bridge.saveFlow(requestFence, documentHandle, normalizedSource);
      if (!isCurrentRequest(sequence, requestFence)) return;
      if (!sameFence(requestFence, response.fence)) {
        onError("The flow save response did not match the active project request.");
        return;
      }
      if (response.data.document !== documentHandle) {
        onError("The flow save response did not match the reviewed document. Reload flows before saving again.");
        return;
      }
      setSelected((current) => current?.handle === documentHandle ? { ...current, identity: response.data.identity, source: normalizedSource } : current);
      setDraft(normalizedSource);
      setWorkspace((current) => current && ({ definitions: current.definitions.map((definition) => definition.identity.id === response.data.identity.id ? { ...definition, identity: response.data.identity } : definition) }));
      setReview(null);
      setReviewedSource(null);
      onToast(response.data.durabilityConfirmed && response.data.cleanupComplete ? "Flow saved durably inside the project boundary" : "Flow saved; durability confirmation is incomplete");
    } catch (error) {
      if (isCurrentRequest(sequence, requestFence)) onError(presentError(error));
    } finally {
      if (isCurrentRequest(sequence, requestFence)) setBusy(false);
    }
  };

  const acceptedReview = reviewedSource === draft ? review : null;

  return (
    <main className="canvas" id="main-content">
      <header className="project-header compact"><div><h1>Flows</h1><p>Repeatable work, with meaningful feedback.</p></div></header>
      {loadError && !workspace ? (
        <section className="panel loading-panel is-error" role="alert">
          <WarningCircle size={25} />
          <div><strong>Flow workspace unavailable</strong><p>{loadError}</p></div>
          <button type="button" className="button button--secondary" onClick={() => void load()}><ArrowClockwise size={18} /> Retry flows</button>
        </section>
      ) : !workspace ? (
        <section className="panel loading-panel" aria-busy="true" aria-live="polite"><ArrowClockwise className={busy ? "is-spinning" : ""} size={25} /><p>Loading bounded flow workspace…</p></section>
      ) : (
        <section className="flow-workspace" aria-label="Flow workspace">
          <aside className="flow-catalog">
            <div className="panel-title"><div><span className="eyebrow">Project catalog</span><h2>Definitions</h2></div><FileText size={20} /></div>
            <div className="flow-list">
              {workspace.definitions.map((flow) => (
                <button type="button" className={selected?.identity?.id === flow.identity.id ? "is-active" : ""} aria-pressed={selected?.identity?.id === flow.identity.id} key={flow.handle} onClick={() => void open(flow.handle)}>
                  <GitBranch size={18} />
                  <span><strong>{flow.identity.id}</strong><small>{flow.identity.fileName}</small></span>
                  <span className="state-pill state-pill--ready">r{flow.identity.revision}</span>
                </button>
              ))}
            </div>
          </aside>
          <section className="flow-editor">
            <div className="panel-title editor-title">
              <div><span className="eyebrow">Editing</span><h2>{selected?.identity?.fileName ?? "Select a definition"}</h2></div>
              <div>
                <button type="button" className="button button--secondary button--small" disabled={busy || !selected} onClick={() => void validate()}><ListChecks size={17} /> Validate</button>
                <button type="button" className="button button--primary button--small" disabled={busy || !acceptedReview?.diff.changed} onClick={() => void save()}><FloppyDisk size={17} /> Save</button>
              </div>
            </div>
            <textarea
              aria-label="Flow TOML source"
              aria-invalid={validationError ? true : undefined}
              aria-describedby={validationError ? validationErrorId : undefined}
              spellCheck={false}
              value={draft}
              maxLength={MAX_FLOW_SOURCE}
              disabled={!selected}
              onChange={(event) => {
                requestSequence.current += 1;
                setBusy(false);
                setDraft(event.target.value);
                setReview(null);
                setReviewedSource(null);
                setValidationError(null);
              }}
            />
            {validationError && <div className="validation-errors" id={validationErrorId} role="alert"><p><WarningCircle size={16} aria-hidden="true" />{validationError}</p></div>}
            <div className="editor-status" role="status">
              <span>{draft.length.toLocaleString()} / {MAX_FLOW_SOURCE.toLocaleString()} characters</span>
              {acceptedReview && <span className={acceptedReview.dryRun.daemonDefinitionEligible ? "is-valid" : "is-invalid"}>{acceptedReview.dryRun.daemonDefinitionEligible ? `Valid · ${acceptedReview.dryRun.steps.length} dry-run steps` : "Valid · outside daemon authority"}</span>}
            </div>
            {acceptedReview && (
              <div className="flow-inspector">
                <div className="flow-inspector-tabs" role="tablist" aria-label="Flow review">
                  <button type="button" role="tab" aria-selected={reviewPanel === "dry-run"} onClick={() => setReviewPanel("dry-run")}>Dry run</button>
                  <button type="button" role="tab" aria-selected={reviewPanel === "diff"} onClick={() => setReviewPanel("diff")}>Version diff{acceptedReview.diff.changed ? " · changed" : " · clean"}</button>
                </div>
                {reviewPanel === "dry-run" ? (
                  <div className="flow-review" role="tabpanel" aria-label="Dry-run review">
                    {acceptedReview.dryRun.steps.slice(0, 5).map((step) => <p key={`${step.index}:${step.id}`}><span>{step.index + 1}</span><strong>{step.id}</strong><small>{step.semanticRole} · {step.daemonAuthority}</small></p>)}
                  </div>
                ) : (
                  <div className="flow-diff" role="tabpanel" aria-label="Version diff">
                    {acceptedReview.diff.lines.length === 0
                      ? <p>No versioned source changes were reported.</p>
                      : acceptedReview.diff.lines.map((line, index) => <pre className={`is-${line.kind}`} key={`${index}:${line.kind}`}>{line.kind === "added" ? "+" : line.kind === "removed" ? "−" : " "} {line.text}</pre>)}
                    {acceptedReview.diff.truncated && <p className="bounded-note">The bounded version diff was truncated.</p>}
                  </div>
                )}
              </div>
            )}
          </section>
        </section>
      )}
    </main>
  );
}

function Drawer({ title, eyebrow, onClose, children }: { title: string; eyebrow: string; onClose: () => void; children: React.ReactNode }) {
  const titleId = useId();
  const drawerRef = useRef<HTMLElement>(null);
  const previousFocus = useRef<HTMLElement | null>(document.activeElement instanceof HTMLElement ? document.activeElement : null);
  useEffect(() => {
    return () => { if (previousFocus.current?.isConnected) previousFocus.current.focus(); };
  }, []);
  const trapFocus = (event: ReactKeyboardEvent<HTMLElement>) => {
    if (event.key !== "Tab") return;
    const focusable = Array.from(drawerRef.current?.querySelectorAll<HTMLElement>("button:not(:disabled), a[href], textarea:not(:disabled), [tabindex]:not([tabindex='-1'])") ?? []);
    if (focusable.length === 0) return;
    const first = focusable[0];
    const last = focusable[focusable.length - 1];
    if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last.focus(); }
    else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first.focus(); }
  };
  return (
    <div className="drawer-backdrop" role="presentation" onMouseDown={onClose}>
      <aside ref={drawerRef} className="drawer" role="dialog" aria-modal="true" aria-labelledby={titleId} onKeyDown={trapFocus} onMouseDown={(event) => event.stopPropagation()}>
        <header><div><span className="eyebrow">{eyebrow}</span><h2 id={titleId}>{title}</h2></div><button type="button" autoFocus aria-label={`Close ${title}`} onClick={onClose}><X size={21} weight="bold" /></button></header>
        {children}
      </aside>
    </div>
  );
}

function EvidenceDrawer({ document, loading, error, onRetry, onClose }: { document: EvidenceDataDto | null; loading: boolean; error: string | null; onRetry?: () => void; onClose: () => void }) {
  return (
    <Drawer title="Evidence" eyebrow="Exact bounded source" onClose={onClose}>
      {loading && <div className="drawer-message" role="status" aria-live="polite"><ArrowClockwise className="is-spinning" size={23} /><p>Loading retained evidence…</p></div>}
      {error && <div className="drawer-message is-error" role="alert"><WarningCircle size={23} /><p>{error}</p>{onRetry && <button type="button" className="button button--secondary" onClick={onRetry}><ArrowClockwise size={18} /> Retry evidence</button>}</div>}
      {document && <article className="evidence-document"><code>{document.handle}</code><h3>{document.truth}</h3><p>{document.mediaType} · {document.sizeBytes.toLocaleString()} bytes · {document.digest}{document.truncated ? " · bounded preview" : ""}</p><pre>{(document.body ?? "This evidence has no text preview.").slice(0, MAX_EVIDENCE_TEXT)}</pre></article>}
    </Drawer>
  );
}

function QueueDrawer({ data, onClose }: { data: ControlCenterView; onClose: () => void }) {
  return (
    <Drawer title="Project queue" eyebrow={`${data.current.queue.length} retained request${data.current.queue.length === 1 ? "" : "s"}`} onClose={onClose}>
      <div className="queue-list">
        {data.current.queue.length === 0 ? <p className="panel-empty">Nothing is queued for this project.</p> : data.current.queue.map((item, index) => (
          <article key={item.requestId}><span>{index + 1}</span><div><strong>{item.operationKind}</strong><code>{item.requestId}</code></div><span className={`state-pill state-pill--${item.state}`}>{item.state}</span></article>
        ))}
        {data.current.queueTruncated && <p className="bounded-note">Only the bounded queue window is shown.</p>}
      </div>
    </Drawer>
  );
}

function ApprovalDrawer({ data, busy, onDecision, onClose }: { data: ControlCenterView; busy: boolean; onDecision: (decision: ApprovalDecision) => void; onClose: () => void }) {
  const approval = data.current.approval;
  if (!approval) return null;
  return (
    <Drawer title="Approval required" eyebrow="Bounded project effect" onClose={onClose}>
      <article className="approval-card" aria-busy={busy}><WarningCircle size={28} /><h3>{approval.title}</h3><p>{approval.reason}</p><dl><div><dt>Effect</dt><dd>{approval.effect}</dd></div><div><dt>Project</dt><dd>{approval.projectName}</dd></div><div><dt>Policy / capability</dt><dd>{approval.policyCapability}</dd></div><div><dt>Expires</dt><dd>{approval.expiresAt}</dd></div><div><dt>Request handle</dt><dd><code>{approval.approvalHandle}</code></dd></div></dl>{busy && <p role="status">Applying the exact decision…</p>}<div><button type="button" className="button button--secondary" disabled={busy} onClick={() => onDecision("deny")}>Deny</button><button type="button" className="button button--primary" disabled={busy} onClick={() => onDecision("approve")}>Approve exact request</button></div></article>
    </Drawer>
  );
}

function LoadingScreen() {
  return <main className="startup-screen" aria-live="polite"><img src="/assets/pam-mark.png" alt="" /><h1>PAM</h1><p>Finding the last registered project…</p></main>;
}

function RecoveryScreen({ message, onRetry }: { message: string; onRetry: () => void }) {
  return <main className="startup-screen recovery-screen" role="alert"><WarningCircle size={38} /><h1>PAM needs a moment</h1><p>{message}</p><button type="button" className="button button--primary" onClick={onRetry}><ArrowClockwise size={18} /> Retry safely</button></main>;
}

export function App({ bridge, initialView = "current" }: AppProps) {
  const [compactViewport, setCompactViewport] = useState(() => window.matchMedia("(max-width: 780px)").matches);
  const [state, dispatch] = useReducer(appReducer, {
    ...initialState,
    activeView: initialView,
    sidebarCollapsed: compactViewport,
  });
  const [toast, setToast] = useState("");
  const [queueOpen, setQueueOpen] = useState(false);
  const [approvalOpen, setApprovalOpen] = useState(false);
  const [evidence, setEvidence] = useState<{ open: boolean; loading: boolean; handle: string | null; document: EvidenceDataDto | null; error: string | null }>({ open: false, loading: false, handle: null, document: null, error: null });
  const toastTimer = useRef<number | null>(null);
  const evidenceRequestSequence = useRef(0);
  const dataCommandSequence = useRef(0);
  const bootstrapRequestSequence = useRef(0);
  const sidebarRef = useRef<HTMLElement>(null);
  const sidebarToggleRef = useRef<HTMLButtonElement>(null);
  const fenceRef = useRef(state.activeFence);
  fenceRef.current = state.activeFence;

  useEffect(() => {
    const query = window.matchMedia("(max-width: 780px)");
    const update = () => setCompactViewport(query.matches);
    query.addEventListener("change", update);
    return () => query.removeEventListener("change", update);
  }, []);

  const closeEvidence = useCallback(() => {
    evidenceRequestSequence.current += 1;
    setEvidence({ open: false, loading: false, handle: null, document: null, error: null });
  }, []);

  useEffect(() => {
    evidenceRequestSequence.current += 1;
    setEvidence({ open: false, loading: false, handle: null, document: null, error: null });
  }, [state.activeFence?.projectHandle, state.activeFence?.generation]);

  const showToast = useCallback((message: string) => {
    setToast(message);
    if (toastTimer.current) window.clearTimeout(toastTimer.current);
    toastTimer.current = window.setTimeout(() => setToast(""), 2600);
  }, []);

  const bootstrap = useCallback(async () => {
    const sequence = ++bootstrapRequestSequence.current;
    dataCommandSequence.current += 1;
    dispatch({ type: "retry" });
    try {
      const [response, catalog] = await Promise.all([bridge.bootstrap(), bridge.catalog()]);
      if (sequence !== bootstrapRequestSequence.current) return;
      dispatch({ type: "bootstrapSucceeded", response, catalog });
    } catch (error) {
      if (sequence !== bootstrapRequestSequence.current) return;
      const syntheticFence = { projectHandle: "bootstrap", generation: "", operationId: "bootstrap" };
      dispatch({ type: "commandStarted", fence: syntheticFence });
      dispatch({ type: "commandFailed", fence: syntheticFence, message: presentError(error) });
    }
  }, [bridge]);

  useEffect(() => { void bootstrap(); }, [bootstrap]);
  useEffect(() => { if (state.data?.current.status === "approval_required") setApprovalOpen(true); }, [state.data?.current]);

  const executeDataCommand = useCallback(async (
    fence: CommandFence,
    command: () => Promise<SnapshotDto>,
    successMessage?: string,
  ) => {
    const sequence = ++dataCommandSequence.current;
    dispatch({ type: "commandStarted", fence });
    try {
      const response = await command();
      if (sequence !== dataCommandSequence.current) return false;
      if (!acceptsResponseFence(fence, response.fence)) {
        dispatch({ type: "commandFailed", fence, message: "The command response did not match the latest project operation. Retry safely." });
        return false;
      }
      dispatch({ type: "commandSucceeded", response });
      if (successMessage) showToast(successMessage);
      return true;
    } catch (error) {
      if (sequence !== dataCommandSequence.current) return false;
      dispatch({ type: "commandFailed", fence, message: presentError(error) });
      return false;
    }
  }, [showToast]);

  const refresh = useCallback(() => {
    if (!fenceRef.current) return;
    const fence = withOperation(fenceRef.current);
    void executeDataCommand(fence, () => bridge.refreshProject(fence), "Project state refreshed");
  }, [bridge, executeDataCommand]);

  const mobileSidebarOpen = compactViewport && !state.sidebarCollapsed;
  const toggleSidebar = useCallback(() => {
    const opening = state.sidebarCollapsed;
    dispatch({ type: "toggleSidebar" });
    if (!compactViewport) return;
    window.requestAnimationFrame(() => {
      if (opening) sidebarRef.current?.querySelector<HTMLElement>("button:not(:disabled)")?.focus();
      else sidebarToggleRef.current?.focus();
    });
  }, [compactViewport, state.sidebarCollapsed]);

  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        closeEvidence();
        setQueueOpen(false);
        setApprovalOpen(false);
        if (mobileSidebarOpen) toggleSidebar();
      }
      if ((event.metaKey || event.ctrlKey) && !event.shiftKey && !event.altKey) {
        const view = event.key === "1" ? "current" : event.key === "2" ? "flows" : event.key === "3" ? "access" : null;
        if (view) { event.preventDefault(); dispatch({ type: "navigate", view }); }
        if (event.key.toLowerCase() === "r") { event.preventDefault(); refresh(); }
      }
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [closeEvidence, mobileSidebarOpen, refresh, toggleSidebar]);

  if (state.loadState === "loading" && !state.data) return <LoadingScreen />;
  if (!state.data || !state.catalog || !state.activeFence) return <RecoveryScreen message={state.error ?? "The project control center is unavailable."} onRetry={() => void bootstrap()} />;

  const data = selectControlCenter(state.data, state.catalog, bridge.mode === "fixture");
  const pending = state.pendingFence !== null;
  const selectProject = (project: ProjectView) => {
    if (project.handle === data.project.handle) return;
    const operationId = nextOperationId();
    const pendingFence = { projectHandle: project.handle, generation: "", operationId };
    void executeDataCommand(pendingFence, () => bridge.activateProject(project.handle, operationId), `Now watching ${project.name}`);
    if (mobileSidebarOpen) toggleSidebar();
  };
  const toggleDaemon = () => {
    const fence = withOperation(state.activeFence!);
    const stopping = data.daemon.state === "running";
    void executeDataCommand(fence, () => stopping ? bridge.stopDaemon(fence) : bridge.startDaemon(fence), stopping ? "PAM is paused" : "PAM is back on watch");
  };
  const registerGuiCaller = () => {
    const fence = withOperation(state.activeFence!);
    void executeDataCommand(
      fence,
      () => bridge.registerGuiCaller(fence).catch(() => {
        throw new Error("GUI caller registration could not be completed. Retry from this screen.");
      }),
      "GUI caller registered",
    );
  };
  const loadEvidence = async (handle: string) => {
    if (!fenceRef.current) return;
    const sequence = ++evidenceRequestSequence.current;
    const fence = withOperation(fenceRef.current);
    setEvidence({ open: true, loading: true, handle, document: null, error: null });
    try {
      const response = await bridge.loadEvidence(fence, handle);
      if (sequence !== evidenceRequestSequence.current || !fenceRef.current || !sameAuthority(fence, fenceRef.current)) return;
      if (!sameFence(fence, response.fence)) {
        setEvidence({ open: true, loading: false, handle: null, document: null, error: "The active project changed. Reopen this evidence from the refreshed outcome." });
        return;
      }
      setEvidence({ open: true, loading: false, handle, document: { ...response.data, body: response.data.body?.slice(0, MAX_EVIDENCE_TEXT) ?? null }, error: null });
    } catch (error) {
      if (sequence !== evidenceRequestSequence.current || !fenceRef.current || !sameAuthority(fence, fenceRef.current)) return;
      setEvidence({ open: true, loading: false, handle, document: null, error: presentError(error) });
    }
  };
  const copyBrief = async (brief: AgentBriefView) => {
    try {
      await navigator.clipboard.writeText(briefText(brief));
      showToast("Agent brief copied");
    } catch {
      showToast("Clipboard access is unavailable");
    }
  };
  const decide = async (decision: ApprovalDecision) => {
    const approval = data.current.approval;
    if (!approval) return;
    const fence = withOperation(state.activeFence!);
    const sequence = ++dataCommandSequence.current;
    dispatch({ type: "commandStarted", fence });
    try {
      const response = await bridge.decideApproval(fence, approval.approvalHandle, decision);
      if (sequence !== dataCommandSequence.current) return;
      if (!acceptsResponseFence(fence, response.snapshot.fence)) {
        dispatch({ type: "commandFailed", fence, message: "The approval response did not match the latest project operation. Retry safely." });
        return;
      }
      dispatch({ type: "commandSucceeded", response: response.snapshot });
      showToast(response.disposition === "approved"
        ? "Exact request approved"
        : response.disposition === "denied"
          ? "Request denied"
          : "Approval expired; request a new challenge");
      setApprovalOpen(false);
    } catch (error) {
      if (sequence !== dataCommandSequence.current) return;
      dispatch({ type: "commandFailed", fence, message: presentError(error) });
    }
  };

  const shellWidth = state.sidebarCollapsed ? 68 : state.sidebarWidth;
  return (
    <div className={`app-shell sidebar-width-${shellWidth}`}>
      <div className="atmosphere" aria-hidden="true" />
      <a className="skip-link" href="#main-content">Skip to content</a>
      <Sidebar containerRef={sidebarRef} data={data} activeView={state.activeView} collapsed={state.sidebarCollapsed} pending={pending} onNavigate={(view) => { dispatch({ type: "navigate", view }); if (mobileSidebarOpen) toggleSidebar(); }} onSelectProject={selectProject} onToggleDaemon={toggleDaemon} />
      {mobileSidebarOpen && <button type="button" className="sidebar-scrim" aria-label="Close project sidebar" onClick={toggleSidebar} />}
      <ResizeSeparator collapsed={state.sidebarCollapsed} width={state.sidebarWidth} onResize={(width) => dispatch({ type: "resizeSidebar", width })} onToggle={toggleSidebar} />
      <section className="workspace" inert={mobileSidebarOpen} aria-hidden={mobileSidebarOpen || undefined}>
        <Toolbar toggleButtonRef={sidebarToggleRef} data={data} collapsed={state.sidebarCollapsed} pending={pending} onToggleSidebar={toggleSidebar} onRefresh={refresh} onOpenQueue={() => setQueueOpen(true)} />
        <div className="canvas-inset">
          {state.loadState === "recovering" && state.error && <div className="inline-recovery" role="alert"><WarningCircle size={18} /><span>{state.error}</span><button type="button" onClick={refresh}>Retry</button></div>}
          {state.activeView === "current" && <CurrentView data={data} onCopy={(brief) => void copyBrief(brief)} onEvidence={(handle) => void loadEvidence(handle)} onContinue={() => { dispatch({ type: "navigate", view: "flows" }); showToast("Flow workspace opened"); }} onOpenQueue={() => setQueueOpen(true)} onOpenApproval={() => setApprovalOpen(true)} onRecoverDaemon={toggleDaemon} onRefresh={refresh} onRegisterCaller={registerGuiCaller} registrationBusy={pending} />}
          {state.activeView === "flows" && <FlowsView bridge={bridge} fence={state.activeFence} onError={showToast} onToast={showToast} />}
          {state.activeView === "access" && <AccessView data={data} />}
        </div>
      </section>
      {queueOpen && <QueueDrawer data={data} onClose={() => setQueueOpen(false)} />}
      {approvalOpen && data.current.approval && <ApprovalDrawer data={data} busy={pending} onDecision={(decision) => { void decide(decision); }} onClose={() => setApprovalOpen(false)} />}
      {evidence.open && <EvidenceDrawer document={evidence.document} loading={evidence.loading} error={evidence.error} onRetry={evidence.handle ? () => { void loadEvidence(evidence.handle!); } : undefined} onClose={closeEvidence} />}
      {toast && <div className="toast" role="status">{toast}</div>}
    </div>
  );
}
