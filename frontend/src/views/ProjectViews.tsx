import {
  ArrowClockwise,
  ArrowDown,
  CaretDown,
  CaretUp,
  Check,
  CheckCircle,
  Copy,
  FileText,
  FolderOpen,
  GitBranch,
  LockSimple,
  MagnifyingGlass,
  Play,
  Power,
  Pulse,
  Queue,
  WarningCircle,
  Wrench,
} from "@phosphor-icons/react";
import { useState } from "react";
import { StatusDot } from "../components/Shell";
import type { CommandFence, PamBridge } from "../domain";
import type { AgentBriefView, ControlCenterView, TimelineItemView } from "../selectors";
import { SkillInventoryPanel } from "./SkillInventoryPanel";

function formatClock(iso: string): string {
  const date = new Date(iso);
  return Number.isNaN(date.valueOf())
    ? "Time unavailable"
    : new Intl.DateTimeFormat(undefined, { hour: "numeric", minute: "2-digit" }).format(date);
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
            <button type="button" aria-label={`Open Evidence ${index + 1}`} aria-description={handle} title={handle} key={handle} onClick={() => onEvidence(handle)}>
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

export interface CurrentViewProps {
  data: ControlCenterView;
  onCopy: (brief: AgentBriefView) => void;
  onEvidence: (handle: string) => void;
  onContinue: () => void;
  onOpenQueue: (returnFocusTarget?: HTMLElement) => void;
  onOpenApproval: () => void;
  onRecoverDaemon: () => void;
  onRefresh: () => void;
  onRegisterCaller: () => void;
  registrationBusy: boolean;
}

export function CurrentView({
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
}: CurrentViewProps) {
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
          <button type="button" className="button button--secondary" onClick={(event) => onOpenQueue(event.currentTarget)}>Open project queue</button>
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

export interface AccessViewProps {
  data: ControlCenterView;
  bridge: PamBridge;
  fence: CommandFence;
}

export function AccessView({ data, bridge, fence }: AccessViewProps) {
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
      <SkillInventoryPanel bridge={bridge} fence={fence} />
    </main>
  );
}
