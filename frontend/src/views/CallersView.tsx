import {
  ArrowClockwise,
  FolderOpen,
  UserCircle,
} from "@phosphor-icons/react";
import { useCallback, useEffect, useRef, useState } from "react";
import { Tab, TabList, TabPanel, Tabs } from "react-aria-components";
import { withOperation } from "../bridge";
import { ProjectMenu } from "../components/Shell";
import type { CallersDto, CommandFence, PamBridge } from "../domain";
import type { AgentBriefView, ControlCenterView, ProjectView } from "../selectors";
import { presentError } from "../state";
import { AccessView, CurrentView } from "./ProjectViews";

function formatDate(registeredAtMs: number): string {
  const date = new Date(registeredAtMs);
  return Number.isNaN(date.valueOf())
    ? "Date unavailable"
    : new Intl.DateTimeFormat(undefined, { dateStyle: "medium" }).format(date);
}

export interface CallersViewProps {
  data: ControlCenterView;
  bridge: PamBridge;
  fence: CommandFence;
  projectMenuOpen: boolean;
  onProjectMenuOpenChange: (open: boolean) => void;
  onSelectProject: (project: ProjectView) => void;
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

export function CallersView({
  data,
  bridge,
  fence,
  projectMenuOpen,
  onProjectMenuOpenChange,
  onSelectProject,
  onCopy,
  onEvidence,
  onContinue,
  onOpenQueue,
  onOpenApproval,
  onRecoverDaemon,
  onRefresh,
  onRegisterCaller,
  registrationBusy,
}: CallersViewProps) {
  const [callers, setCallers] = useState<CallersDto | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const fenceRef = useRef(fence);
  const requestSequence = useRef(0);
  fenceRef.current = fence;

  const load = useCallback(async () => {
    const sequence = ++requestSequence.current;
    setBusy(true);
    setLoadError(null);
    try {
      const response = await bridge.callerRegistry(withOperation(fenceRef.current));
      if (sequence !== requestSequence.current) return;
      setCallers(response);
    } catch (error) {
      if (sequence === requestSequence.current) setLoadError(presentError(error));
    } finally {
      if (sequence === requestSequence.current) setBusy(false);
    }
  }, [bridge]);

  useEffect(() => {
    void load();
    return () => { requestSequence.current += 1; };
  }, [load]);

  return (
    <main className="canvas" id="main-content">
      <header className="project-header compact">
        <div><h1>Callers</h1><p>Who PAM listens to, and the projects they work in.</p></div>
      </header>
      <section className="panel" aria-labelledby="callers-heading">
        <div className="panel-title">
          <div><span className="eyebrow">Daemon registry</span><h2 id="callers-heading">Registered callers</h2></div>
          <button
            type="button"
            className="button button--secondary button--small"
            aria-label="Refresh callers"
            disabled={busy}
            onClick={() => void load()}
          >
            <ArrowClockwise className={busy ? "is-spinning" : ""} size={17} /> Refresh
          </button>
        </div>
        {loadError ? (
          <p className="panel-empty" role="alert">{loadError}</p>
        ) : !callers ? (
          <p className="panel-empty" aria-busy="true" aria-live="polite">Loading the registered callers…</p>
        ) : callers.status !== "ok" ? (
          <p className="panel-empty">
            {[callers.failure.detail, callers.failure.recovery].filter(Boolean).join(" ")}
          </p>
        ) : callers.callers.length === 0 ? (
          <p className="panel-empty">No callers are registered with the daemon yet.</p>
        ) : (
          <div className="access-list">
            {callers.callers.map((caller) => (
              <article key={caller.callerId}>
                <span className="access-icon" aria-hidden="true"><UserCircle size={21} /></span>
                <div>
                  <strong>{caller.callerId}</strong>
                  <p>Registered {formatDate(caller.registeredAtMs)}</p>
                </div>
                <span className={`state-pill state-pill--${caller.revokedAtMs === null ? "observed" : "attention"}`}>
                  {caller.revokedAtMs === null ? "active" : "revoked"}
                </span>
              </article>
            ))}
          </div>
        )}
      </section>
      <section className="panel" aria-labelledby="projects-heading">
        <div className="panel-title">
          <div><span className="eyebrow">Watched projects</span><h2 id="projects-heading">Projects</h2></div>
          <FolderOpen size={22} aria-hidden="true" />
        </div>
        <div className="project-picker">
          <ProjectMenu
            active={data.project}
            projects={data.catalog}
            open={projectMenuOpen}
            onOpenChange={onProjectMenuOpenChange}
            onSelect={onSelectProject}
          />
          <p className="project-picker-location">{data.project.rootLabel}</p>
        </div>
      </section>
      <Tabs className="panel project-detail" defaultSelectedKey="current">
        <TabList className="flow-inspector-tabs" aria-label="Project detail">
          <Tab id="current" className="flow-inspector-tab">Current</Tab>
          <Tab id="access" className="flow-inspector-tab">Access</Tab>
        </TabList>
        <TabPanel id="current" className="project-detail-panel">
          <CurrentView
            data={data}
            onCopy={onCopy}
            onEvidence={onEvidence}
            onContinue={onContinue}
            onOpenQueue={onOpenQueue}
            onOpenApproval={onOpenApproval}
            onRecoverDaemon={onRecoverDaemon}
            onRefresh={onRefresh}
            onRegisterCaller={onRegisterCaller}
            registrationBusy={registrationBusy}
          />
        </TabPanel>
        <TabPanel id="access" className="project-detail-panel">
          <AccessView
            key={`${fence.projectHandle}:${fence.generation}`}
            data={data}
            bridge={bridge}
            fence={fence}
          />
        </TabPanel>
      </Tabs>
    </main>
  );
}
