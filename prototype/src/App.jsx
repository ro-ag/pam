import { useMemo, useState } from "react";
import {
  ArrowDown,
  BookOpen,
  CaretDown,
  CaretUp,
  Check,
  Circle,
  Copy,
  FileText,
  FolderOpen,
  Gear,
  GitBranch,
  LockSimple,
  MagnifyingGlass,
  Play,
  Power,
  Pulse,
  ShieldCheck,
  Wrench,
  X,
} from "@phosphor-icons/react";

const projects = ["payments-api", "ledger-web", "docs"];

const projectDetails = {
  "payments-api": {
    request: "Investigate failing merge in PR #1842",
    evidence: "CI failure and merge base identified",
    fix: "Resolved conflicting idempotency logic",
    verification: "All checks green on PR #1842",
    goal: "Unblock PR #1842 by repairing the failing merge and restoring green CI.",
    decisions: "Kept idempotency check in service layer; removed duplicate guard in controller.",
    verified: "CI pipeline passed; unit and integration tests green; no regressions detected.",
    next: "Request review from Payments team; monitor staging smoke for 30 minutes.",
    handles: ["evidence://ci/1842/failure", "evidence://git/7ac19f"],
  },
  "ledger-web": {
    request: "Investigate flaky checkout tests in PR #997",
    evidence: "Three retry clusters traced to stale fixtures",
    fix: "Rebuilt the test fixture boundary",
    verification: "Checkout suite passed 20 consecutive runs",
    goal: "Stabilize checkout tests without hiding legitimate failures behind retries.",
    decisions: "Rebuilt fixtures per test run and kept the production retry policy unchanged.",
    verified: "Checkout suite passed 20 consecutive runs on Linux and macOS.",
    next: "Ask Web Platform for review; watch the next two scheduled pipelines.",
    handles: ["evidence://ci/997/flakes", "evidence://git/21d8af"],
  },
  docs: {
    request: "Validate release notes and architecture diagrams",
    evidence: "Two stale links and one diagram drift found",
    fix: "Updated links and regenerated the sequence diagram",
    verification: "Docs build and link check passed",
    goal: "Publish accurate release notes and architecture diagrams for the next merge.",
    decisions: "Kept the public terminology stable and regenerated only the drifted sequence.",
    verified: "Docs build, link check, and diagram snapshot all pass.",
    next: "Request documentation review and attach the evidence pack to the release ticket.",
    handles: ["evidence://docs/links", "evidence://docs/diagram/4b11"],
  },
};

const navItems = [
  { id: "current", label: "Current", icon: Pulse },
  { id: "flows", label: "Flows", icon: GitBranch },
  { id: "access", label: "Access", icon: LockSimple },
];

function StatusDot({ color = "aqua", size = 12 }) {
  return (
    <Circle
      aria-hidden="true"
      className={`status-dot status-dot--${color}`}
      size={size}
      weight="fill"
    />
  );
}

function WindowControls() {
  return (
    <div className="window-controls" aria-label="Window controls">
      <Circle size={16} weight="fill" color="#ff635a" />
      <Circle size={16} weight="fill" color="#f6bd3c" />
      <Circle size={16} weight="fill" color="#2ecf65" />
    </div>
  );
}

function Sidebar({ activeView, daemonOn, onDaemonToggle, onNavigate, project, onProjectChange }) {
  const [projectMenuOpen, setProjectMenuOpen] = useState(false);

  return (
    <aside className="sidebar">
      <WindowControls />

      <div className="brand" aria-label="PAM home">
        <img src="/assets/pam-mark.png" alt="" className="brand__mark" />
        <span className="brand__word">PAM</span>
      </div>

      <div className="project-switcher-wrap">
        <button
          className="project-switcher"
          type="button"
          aria-expanded={projectMenuOpen}
          onClick={() => setProjectMenuOpen((open) => !open)}
        >
          <GitBranch size={20} weight="regular" aria-hidden="true" />
          <span>{project}</span>
          <CaretDown size={17} weight="bold" aria-hidden="true" />
        </button>

        {projectMenuOpen && (
          <div className="project-menu" role="menu">
            {projects.map((name) => (
              <button
                type="button"
                role="menuitem"
                className={name === project ? "is-selected" : ""}
                key={name}
                onClick={() => {
                  onProjectChange(name);
                  setProjectMenuOpen(false);
                }}
              >
                <GitBranch size={17} aria-hidden="true" />
                {name}
                {name === project && <Check size={16} weight="bold" aria-hidden="true" />}
              </button>
            ))}
          </div>
        )}
      </div>

      <nav className="primary-nav" aria-label="Primary navigation">
        {navItems.map(({ id, label, icon: Icon }) => (
          <button
            type="button"
            className={`nav-item ${activeView === id ? "is-active" : ""}`}
            key={id}
            onClick={() => onNavigate(id)}
          >
            <Icon size={21} weight={activeView === id ? "bold" : "regular"} aria-hidden="true" />
            <span>{label}</span>
          </button>
        ))}
      </nav>

      <div className="sidebar__footer">
        <button
          type="button"
          className={`daemon-control ${daemonOn ? "is-on" : "is-off"}`}
          aria-pressed={daemonOn}
          onClick={onDaemonToggle}
        >
          {daemonOn ? <StatusDot color="coral" size={15} /> : <Power size={17} weight="bold" />}
          <span>{daemonOn ? "PAM is on watch" : "Start PAM"}</span>
        </button>

        <div className="utility-nav">
          <button type="button" aria-label="Settings" title="Settings">
            <Gear size={20} />
          </button>
          <button type="button" aria-label="Documentation" title="Documentation">
            <BookOpen size={20} />
          </button>
        </div>
      </div>
    </aside>
  );
}

function TimelineEvent({ icon: Icon, title, description, time, clock, accent = false }) {
  return (
    <div className="timeline-event">
      <div className={`timeline-event__icon ${accent ? "is-coral" : ""}`}>
        <Icon size={24} weight="regular" aria-hidden="true" />
      </div>
      <div className="timeline-event__copy">
        <strong>{title}</strong>
        <span>{description}</span>
      </div>
      <div className="timeline-event__time">
        <span>{time}</span>
        <span>{clock}</span>
      </div>
    </div>
  );
}

function HandoffPanel({ brief, copied, onCopy, onEvidence, onContinue }) {
  return (
    <section className="handoff-panel" aria-labelledby="handoff-title">
      <h2 id="handoff-title">Ready for the next agent</h2>

      <dl className="brief-grid">
        <div>
          <dt>Goal</dt>
          <dd>{brief.goal}</dd>
        </div>
        <div>
          <dt>Decisions</dt>
          <dd>{brief.decisions}</dd>
        </div>
        <div>
          <dt>Verified</dt>
          <dd>{brief.verified}</dd>
        </div>
        <div>
          <dt>Next</dt>
          <dd>{brief.next}</dd>
        </div>
      </dl>

      <div className="provenance">
        <div className="provenance__intro">
          <GitBranch size={20} weight="bold" aria-hidden="true" />
          <strong>Provenance</strong>
          <span>Statements in this brief are grounded in the following evidence.</span>
        </div>
        <div className="evidence-handles">
          <button type="button" onClick={onEvidence}>
            <FileText size={18} aria-hidden="true" />
            <code>{brief.handles[0]}</code>
          </button>
          <button type="button" onClick={onEvidence}>
            <GitBranch size={18} aria-hidden="true" />
            <code>{brief.handles[1]}</code>
          </button>
        </div>
      </div>

      <div className="handoff-actions">
        <button type="button" className={`button button--primary ${copied ? "is-success" : ""}`} onClick={onCopy}>
          {copied ? <Check size={20} weight="bold" /> : <Copy size={20} weight="bold" />}
          {copied ? "Brief copied" : "Copy agent brief"}
        </button>
        <div className="handoff-actions__secondary">
          <button type="button" className="button button--secondary" onClick={onEvidence}>
            <FolderOpen size={20} />
            Open evidence
          </button>
          <button type="button" className="button button--secondary" onClick={onContinue}>
            <Play size={20} />
            Continue flow
          </button>
        </div>
      </div>
    </section>
  );
}

function CurrentView({ project, details, onToast, onEvidence }) {
  const [expanded, setExpanded] = useState(true);
  const [copied, setCopied] = useState(false);

  const copyBrief = async () => {
    const brief = [
      `Goal: ${details.goal}`,
      `Decisions: ${details.decisions}`,
      `Verified: ${details.verified}`,
      `Next: ${details.next}`,
    ].join("\n");

    try {
      await navigator.clipboard.writeText(brief);
    } catch {
      // Clipboard access can be restricted in embedded previews; the UI still
      // confirms the intended interaction for this prototype.
    }
    setCopied(true);
    onToast("Agent brief is ready to paste");
    window.setTimeout(() => setCopied(false), 2400);
  };

  return (
    <main className="main-view">
      <header className="project-header">
        <div>
          <h1>{project}</h1>
          <p>
            <StatusDot color="coral" size={12} />
            PAM is on watch <span>·</span> Qwen local <span>·</span> 8.4 GB
          </p>
        </div>
        <time dateTime="2026-08-18T00:08:00-07:00">August 18, 2026 · 12:08 AM</time>
      </header>

      <section className="timeline" aria-label={`${project} activity timeline`}>
        <TimelineEvent
          icon={ArrowDown}
          title="Request received"
          description={details.request}
          time="24 min ago"
          clock="11:44 PM"
          accent
        />
        <TimelineEvent
          icon={MagnifyingGlass}
          title="Evidence found"
          description={details.evidence}
          time="20 min ago"
          clock="11:48 PM"
        />
        <TimelineEvent
          icon={Wrench}
          title="Fix applied"
          description={details.fix}
          time="12 min ago"
          clock="11:56 PM"
        />

        <article className={`verification-event ${expanded ? "is-expanded" : ""}`}>
          <button
            type="button"
            className="verification-event__summary"
            aria-expanded={expanded}
            onClick={() => setExpanded((open) => !open)}
          >
            <span className="verification-event__icon">
              <Check size={27} weight="bold" aria-hidden="true" />
            </span>
            <span className="verification-event__copy">
              <strong>Verification passed</strong>
              <span>{details.verification}</span>
            </span>
            <span className="verification-event__time">
              <span>4 min ago</span>
              <span>12:04 AM</span>
            </span>
            {expanded ? <CaretUp size={19} weight="bold" /> : <CaretDown size={19} weight="bold" />}
          </button>

          {expanded && (
            <HandoffPanel
              brief={details}
              copied={copied}
              onCopy={copyBrief}
              onEvidence={onEvidence}
              onContinue={() => onToast("Flow continued · watching staging smoke")}
            />
          )}
        </article>
      </section>
    </main>
  );
}

function SecondaryView({ view, onReturn }) {
  const isFlows = view === "flows";
  return (
    <main className="main-view secondary-view">
      <header className="project-header">
        <div>
          <h1>{isFlows ? "Flows" : "Access"}</h1>
          <p>{isFlows ? "Repeatable work, with meaningful feedback." : "Narrow capabilities, visible to the developer."}</p>
        </div>
      </header>

      <section className="secondary-surface">
        {isFlows ? (
          <>
            <div className="secondary-row">
              <Pulse size={24} />
              <div>
                <strong>After merge checks</strong>
                <span>Git · tests · Sonar · Jira</span>
              </div>
              <span className="state-label">Ready</span>
            </div>
            <div className="secondary-row">
              <ShieldCheck size={24} />
              <div>
                <strong>Release confidence</strong>
                <span>Evidence pack · approvals · handoff</span>
              </div>
              <span className="state-label">Draft</span>
            </div>
          </>
        ) : (
          <>
            <div className="secondary-row">
              <GitBranch size={24} />
              <div>
                <strong>GitHub Actions</strong>
                <span>Read runs and logs · rerun with approval</span>
              </div>
              <span className="state-label state-label--aqua">Allowed</span>
            </div>
            <div className="secondary-row">
              <LockSimple size={24} />
              <div>
                <strong>Jira</strong>
                <span>Read tickets · updates require approval</span>
              </div>
              <span className="state-label">Scoped</span>
            </div>
          </>
        )}
        <button type="button" className="button button--secondary return-button" onClick={onReturn}>
          Return to current
        </button>
      </section>
    </main>
  );
}

function EvidenceDrawer({ onClose }) {
  return (
    <div className="drawer-backdrop" role="presentation" onMouseDown={onClose}>
      <aside className="evidence-drawer" role="dialog" aria-modal="true" aria-labelledby="evidence-title" onMouseDown={(event) => event.stopPropagation()}>
        <header>
          <div>
            <span className="eyebrow">Exact source retained</span>
            <h2 id="evidence-title">Evidence</h2>
          </div>
          <button type="button" aria-label="Close evidence" onClick={onClose}>
            <X size={22} weight="bold" />
          </button>
        </header>
        <div className="evidence-record">
          <FileText size={22} />
          <div>
            <code>evidence://ci/1842/failure</code>
            <p>GitHub Actions · integration-test · exit 1</p>
            <pre>Null currency in fixture triggers 500 at CurrencyService.java:142</pre>
          </div>
        </div>
        <div className="evidence-record">
          <GitBranch size={22} />
          <div>
            <code>evidence://git/7ac19f</code>
            <p>Verified patch · 2 files changed · checks green</p>
            <pre>guard currency before invoking conversion pipeline</pre>
          </div>
        </div>
      </aside>
    </div>
  );
}

export function App() {
  const [activeView, setActiveView] = useState("current");
  const [daemonOn, setDaemonOn] = useState(true);
  const [project, setProject] = useState("payments-api");
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [toast, setToast] = useState("");

  const details = useMemo(() => projectDetails[project], [project]);

  const showToast = (message) => {
    setToast(message);
    window.setTimeout(() => setToast(""), 2600);
  };

  return (
    <div className="app-shell">
      <div className="atmosphere" aria-hidden="true" />
      <Sidebar
        activeView={activeView}
        daemonOn={daemonOn}
        onDaemonToggle={() => {
          setDaemonOn((on) => !on);
          showToast(daemonOn ? "PAM is off watch" : "PAM is back on watch");
        }}
        onNavigate={setActiveView}
        project={project}
        onProjectChange={(name) => {
          setProject(name);
          setActiveView("current");
          showToast(`Now watching ${name}`);
        }}
      />

      {activeView === "current" ? (
        <CurrentView project={project} details={details} onToast={showToast} onEvidence={() => setDrawerOpen(true)} />
      ) : (
        <SecondaryView view={activeView} onReturn={() => setActiveView("current")} />
      )}

      {drawerOpen && <EvidenceDrawer onClose={() => setDrawerOpen(false)} />}
      {toast && <div className="toast" role="status">{toast}</div>}
    </div>
  );
}
