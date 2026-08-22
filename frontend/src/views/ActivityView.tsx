import {
  ArrowClockwise,
  CheckCircle,
  Power,
  Pulse,
  Queue,
  WarningCircle,
} from "@phosphor-icons/react";
import { useCallback, useEffect, useRef, useState } from "react";
import { withOperation } from "../bridge";
import type { ActivityDto, ActivityEventDto, CommandFence, PamBridge } from "../domain";
import type { ControlCenterView } from "../selectors";
import { presentError } from "../state";

function formatClock(occurredAtMs: number): string {
  const date = new Date(occurredAtMs);
  return Number.isNaN(date.valueOf())
    ? "Time unavailable"
    : new Intl.DateTimeFormat(undefined, { hour: "numeric", minute: "2-digit" }).format(date);
}

export interface ActivityViewProps {
  data: ControlCenterView;
  bridge: PamBridge;
  fence: CommandFence;
  pending: boolean;
  onStartDaemon: () => void;
}

export function ActivityView({ data, bridge, fence, pending, onStartDaemon }: ActivityViewProps) {
  const [activity, setActivity] = useState<ActivityDto | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const fenceRef = useRef(fence);
  const requestSequence = useRef(0);
  fenceRef.current = fence;
  const offline = data.daemon.state === "stopped";

  const load = useCallback(async () => {
    const sequence = ++requestSequence.current;
    setBusy(true);
    setLoadError(null);
    try {
      const response = await bridge.daemonActivity(withOperation(fenceRef.current));
      if (sequence !== requestSequence.current) return;
      setActivity(response);
    } catch (error) {
      if (sequence === requestSequence.current) setLoadError(presentError(error));
    } finally {
      if (sequence === requestSequence.current) setBusy(false);
    }
  }, [bridge]);

  useEffect(() => {
    if (offline) {
      setActivity(null);
      setLoadError(null);
      return;
    }
    void load();
    return () => { requestSequence.current += 1; };
  }, [load, offline]);

  const projectLabel = (projectId: string | null) => projectId === null
    ? "daemon"
    : data.catalog.find((project) => project.handle === projectId)?.name ?? `${projectId.slice(0, 8)}…`;

  const eventRow = (event: ActivityEventDto) => (
    <article key={event.sequence}>
      <span className="access-icon" aria-hidden="true">
        {event.decision === "allowed" ? <CheckCircle size={21} /> : <WarningCircle size={21} />}
      </span>
      <div>
        <strong>{event.action}</strong>
        <p>
          {formatClock(event.occurredAtMs)} · {event.callerId} · {projectLabel(event.projectId)}
          {event.outcome && ` · ${event.outcome}`}
        </p>
      </div>
      <span className={`state-pill state-pill--${event.decision === "allowed" ? "allowed" : "attention"}`}>
        {event.decision.replaceAll("_", " ")}
      </span>
    </article>
  );

  return (
    <main className="canvas" id="main-content">
      <header className="project-header compact">
        <div><h1>Activity</h1><p>What PAM has seen across the daemon.</p></div>
      </header>
      <section className="project-overview" aria-label="Daemon health">
        <article className="project-stat group flex items-center gap-3">
          <span className="project-stat-icon"><Pulse size={21} weight="bold" /></span>
          <div><small>Watch status</small><strong>{data.daemon.detail}</strong></div>
          <span className={`state-pill state-pill--${data.daemon.state === "running" ? "healthy" : "attention"}`}>{data.daemon.state}</span>
        </article>
        <article className="project-stat group flex items-center gap-3">
          <span className="project-stat-icon"><CheckCircle size={21} weight="bold" /></span>
          <div><small>Daemon version</small><strong>{data.daemon.model ?? "Not reported"}</strong></div>
        </article>
        <article className="project-stat group flex items-center gap-3">
          <span className="project-stat-icon"><Queue size={21} weight="bold" /></span>
          <div><small>Queue depth</small><strong>{data.daemon.queueDepth ?? "Not reported"}</strong></div>
          {data.daemon.queueDepth !== null && <span className="project-stat-value">{data.daemon.queueDepth}</span>}
        </article>
      </section>
      {offline ? (
        <section className="empty-state">
          <Power size={38} aria-hidden="true" />
          <h2>PAM is paused</h2>
          <p>The activity feed will pick up where it left off once PAM is back on watch.</p>
          <button type="button" className="button button--primary" disabled={pending} onClick={onStartDaemon}>
            <Power size={18} /> Start PAM
          </button>
        </section>
      ) : (
        <section className="panel" aria-labelledby="activity-heading">
          <div className="panel-title">
            <div><span className="eyebrow">Daemon feed</span><h2 id="activity-heading">Recent activity</h2></div>
            <button
              type="button"
              className="button button--secondary button--small"
              aria-label="Refresh activity"
              disabled={busy}
              onClick={() => void load()}
            >
              <ArrowClockwise className={busy ? "is-spinning" : ""} size={17} /> Refresh
            </button>
          </div>
          {loadError ? (
            <p className="panel-empty" role="alert">{loadError}</p>
          ) : !activity ? (
            <p className="panel-empty" aria-busy="true" aria-live="polite">Loading the recent daemon activity…</p>
          ) : activity.status !== "ok" ? (
            <p className="panel-empty">
              {[activity.failure.detail, activity.failure.recovery].filter(Boolean).join(" ")}
            </p>
          ) : activity.events.length === 0 ? (
            <p className="panel-empty">No recent activity. PAM is on watch and new events will appear here.</p>
          ) : (
            <div className="access-list">
              {activity.events.map(eventRow)}
              {activity.truncated && <p className="panel-empty">Older activity was truncated at the bounded feed limit.</p>}
            </div>
          )}
        </section>
      )}
    </main>
  );
}
