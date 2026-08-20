import { useMemo, useState } from "react";
import {
  ArrowDown,
  BookOpen,
  CaretDown,
  CaretUp,
  Check,
  CheckCircle,
  Circle,
  Code,
  Copy,
  FileText,
  FloppyDisk,
  FolderOpen,
  Gear,
  GitBranch,
  GitDiff,
  ListChecks,
  LockSimple,
  MagnifyingGlass,
  Play,
  Power,
  Pulse,
  Wrench,
  WarningCircle,
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

const afterMergeFlow = `schema_version = 2
id = "after-merge-checks"
name = "After merge checks"
description = "Observe the merged revision and verify that the tracked worktree still matches the index."
revision = 1

[outcome]
solved = "Whether every declared after-merge observation and verification completed successfully."
changed = "State changes completed by this flow; this read-only flow is not expected to satisfy this section."
verified = "Whether the tracked worktree was directly verified against the index."
unresolved = "Which observation or verification could not be completed."
blocked = "Which policy, workspace, or execution boundary stopped the flow."

[[steps]]
id = "observe-revision"
description = "Record the exact checked-out revision as evidence."
depends_on = []
condition = { kind = "always" }
retry = { max_attempts = 1, initial_backoff_ms = 0, max_backoff_ms = 0 }
approval = "none"
timeout_seconds = 30
effect = "read_only"
semantic = "observe"
action = { type = "command", program = "git", args = ["rev-parse", "--verify", "HEAD"], working_directory = "." }

[[steps]]
id = "observe-worktree"
description = "Record the bounded porcelain worktree status as evidence."
depends_on = ["observe-revision"]
condition = { kind = "succeeded", step = "observe-revision" }
retry = { max_attempts = 1, initial_backoff_ms = 0, max_backoff_ms = 0 }
approval = "none"
timeout_seconds = 30
effect = "read_only"
semantic = "observe"
action = { type = "command", program = "git", args = ["status", "--porcelain=v1", "--untracked-files=all"], working_directory = "." }

[[steps]]
id = "verify-tracked-worktree"
description = "Verify that tracked worktree files match the index without modifying either."
depends_on = ["observe-worktree"]
condition = { kind = "succeeded", step = "observe-worktree" }
retry = { max_attempts = 1, initial_backoff_ms = 0, max_backoff_ms = 0 }
approval = "none"
timeout_seconds = 30
effect = "read_only"
semantic = "verify"
action = { type = "command", program = "git", args = ["diff", "--quiet"], working_directory = "." }
`;

const releaseConfidenceFlow = `schema_version = 2
id = "release-confidence"
name = "Release confidence"
description = "Draft a release evidence pack and request a bounded publishing approval."
revision = 3

[outcome]
solved = "Whether the release evidence workflow completed."
changed = "Which approved release state was changed."
verified = "Which release facts were directly verified."
unresolved = "Which checks still need investigation."
blocked = "Which approval or connector boundary stopped the flow."

[[steps]]
id = "inspect-release"
description = "Read the release ticket through a connector."
depends_on = []
condition = { kind = "always" }
retry = { max_attempts = 1, initial_backoff_ms = 0, max_backoff_ms = 0 }
approval = "none"
timeout_seconds = 60
effect = "read_only"
semantic = "observe"
action = { type = "connector", connector = "jira", capability = "tickets.read", resource = { kind = "issue", id = "PAM-30" } }
`;

const initialFlowCatalog = [
  {
    id: "after-merge-checks",
    filename: "after-merge-checks.toml",
    source: afterMergeFlow,
    state: "Ready",
  },
  {
    id: "release-confidence",
    filename: "release-confidence.toml",
    source: releaseConfidenceFlow,
    state: "Draft",
  },
];

function quotedValue(source, key) {
  return source.match(new RegExp(`^${key}\\s*=\\s*"([^"]*)"`, "m"))?.[1] ?? "";
}

function scalarValue(source, key) {
  return source.match(new RegExp(`^${key}\\s*=\\s*([^\\n#]+)`, "m"))?.[1]?.trim() ?? "";
}

function inlineValue(source, key) {
  return source.match(new RegExp(`${key}\\s*=\\s*"([^"]*)"`))?.[1] ?? "";
}

function parseStringArray(value) {
  return [...value.matchAll(/"([^"]*)"/g)].map((match) => match[1]);
}

function supportedGitAuthority(args, semantic) {
  const [command, ...options] = args;
  const safeStatus = options.every(
    (option) =>
      ["--short", "-s", "--porcelain", "--no-renames", "--find-renames"].includes(option) ||
      option.startsWith("--porcelain=") ||
      option.startsWith("--untracked-files=") ||
      option.startsWith("--find-renames="),
  );
  const safeRevision =
    options.length > 0 &&
    options.every(
      (option) =>
        [
          "HEAD",
          "--verify",
          "--quiet",
          "-q",
          "--short",
          "--show-toplevel",
          "--show-prefix",
          "--show-cdup",
          "--git-dir",
          "--absolute-git-dir",
          "--is-inside-work-tree",
        ].includes(option) || /^--short=\d+$/.test(option),
    );
  const safeDiff = options.length > 0 && options.includes("--quiet") && options.every((option) => option === "--quiet");
  return (
    (semantic === "observe" && command === "status" && safeStatus) ||
    (semantic === "observe" && command === "rev-parse" && safeRevision) ||
    (semantic === "verify" && command === "diff" && safeDiff)
  );
}

function parseFlowSource(source) {
  const errors = [];
  const schema = Number(scalarValue(source, "schema_version"));
  const id = quotedValue(source, "id");
  const name = quotedValue(source, "name");
  const revision = Number(scalarValue(source, "revision"));
  if (schema !== 2) errors.push("schema_version must be 2");
  if (!/^[a-z0-9][a-z0-9-]{0,63}$/.test(id)) errors.push("id must be a safe lowercase slug");
  if (!name) errors.push("name is required");
  if (!Number.isInteger(revision) || revision < 1) errors.push("revision must be greater than zero");

  const chunks = source.split("[[steps]]").slice(1);
  if (chunks.length === 0) errors.push("at least one step is required");
  const steps = chunks.map((chunk, index) => {
    const stepId = quotedValue(chunk, "id");
    const effect = quotedValue(chunk, "effect");
    const semantic = quotedValue(chunk, "semantic");
    const approval = quotedValue(chunk, "approval") || "none";
    const dependsOn = parseStringArray(scalarValue(chunk, "depends_on"));
    const conditionLine = scalarValue(chunk, "condition");
    const conditionKind = inlineValue(conditionLine, "kind") || "always";
    const conditionStep = inlineValue(conditionLine, "step");
    const retryLine = scalarValue(chunk, "retry");
    const attempts = Number(retryLine.match(/max_attempts\s*=\s*(\d+)/)?.[1] ?? 1);
    const actionLine = scalarValue(chunk, "action");
    const actionType = inlineValue(actionLine, "type");
    const program = inlineValue(actionLine, "program");
    const connector = inlineValue(actionLine, "connector");
    const args = parseStringArray(actionLine.match(/args\s*=\s*(\[[^\]]*\])/)?.[1] ?? "");
    const workingDirectory = inlineValue(actionLine, "working_directory");
    if (!stepId) errors.push(`steps[${index}].id is required`);
    if (!['observe', 'verify', 'change'].includes(semantic)) {
      errors.push(`steps[${index}].semantic must be observe, verify, or change`);
    }
    if (effect === "read_only" && semantic === "change") {
      errors.push(`steps[${index}] cannot claim change from a read-only effect`);
    }
    if (effect === "stateful" && semantic !== "change") {
      errors.push(`steps[${index}] stateful effects must use change semantics`);
    }
    const supportedGit =
      actionType === "command" &&
      program === "git" &&
      workingDirectory === "." &&
      effect === "read_only" &&
      approval === "none" &&
      supportedGitAuthority(args, semantic);
    const authority = supportedGit
      ? { supported: true, label: `git ${args.join(" ")}` }
      : {
          supported: false,
          label:
            actionType === "connector"
              ? `${connector || "connector"} requires unsupported connector authority`
              : `${program || actionType || "action"} is outside the daemon allowlist`,
        };
    return {
      id: stepId || `step-${index + 1}`,
      semantic,
      effect,
      approval,
      attempts,
      dependsOn,
      condition:
        conditionKind === "always"
          ? "Always"
          : `${conditionKind === "failed" ? "If failed" : "If passed"}: ${conditionStep}`,
      authority,
    };
  });

  const known = new Set(steps.map((step) => step.id));
  for (const step of steps) {
    for (const dependency of step.dependsOn) {
      if (!known.has(dependency)) errors.push(`${step.id} depends on unknown step ${dependency}`);
    }
  }
  return { id, name, revision, steps, errors };
}

function lineDiff(before, after) {
  const left = before.replace(/\s+$/, "").split("\n");
  const right = after.replace(/\s+$/, "").split("\n");
  const rows = Array.from({ length: left.length + 1 }, () => Array(right.length + 1).fill(0));
  for (let i = left.length - 1; i >= 0; i -= 1) {
    for (let j = right.length - 1; j >= 0; j -= 1) {
      rows[i][j] = left[i] === right[j] ? rows[i + 1][j + 1] + 1 : Math.max(rows[i + 1][j], rows[i][j + 1]);
    }
  }
  const diff = [];
  let i = 0;
  let j = 0;
  while (i < left.length || j < right.length) {
    if (i < left.length && j < right.length && left[i] === right[j]) {
      i += 1;
      j += 1;
    } else if (j < right.length && (i === left.length || rows[i][j + 1] >= rows[i + 1][j])) {
      diff.push({ kind: "added", line: right[j] });
      j += 1;
    } else {
      diff.push({ kind: "removed", line: left[i] });
      i += 1;
    }
  }
  return diff;
}

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

function FlowEditor({ project, onToast }) {
  const [catalog, setCatalog] = useState(initialFlowCatalog);
  const [selectedId, setSelectedId] = useState(initialFlowCatalog[0].id);
  const [draft, setDraft] = useState(initialFlowCatalog[0].source);
  const [savedSource, setSavedSource] = useState(initialFlowCatalog[0].source);
  const [inspector, setInspector] = useState("plan");
  const parsed = useMemo(() => parseFlowSource(draft), [draft]);
  const saved = useMemo(() => parseFlowSource(savedSource), [savedSource]);
  const diff = useMemo(() => lineDiff(savedSource, draft), [savedSource, draft]);
  const selected = catalog.find((flow) => flow.id === selectedId) ?? catalog[0];
  const changed = draft !== savedSource;
  const validationErrors = [
    ...parsed.errors,
    ...(parsed.id && parsed.id !== selected.id ? ["definition id must match its catalog filename"] : []),
    ...(changed && Number.isInteger(parsed.revision) && parsed.revision <= saved.revision
      ? ["revision must advance before saving edited source"]
      : []),
  ];
  const unsupported = parsed.steps.filter((step) => !step.authority.supported);

  const selectFlow = (flow) => {
    if (changed && !window.confirm("Discard the unsaved flow edits?")) return;
    setSelectedId(flow.id);
    setDraft(flow.source);
    setSavedSource(flow.source);
    setInspector("plan");
  };

  const saveFlow = () => {
    if (validationErrors.length > 0) return;
    setCatalog((flows) =>
      flows.map((flow) =>
        flow.id === selectedId
          ? {
              ...flow,
              source: draft,
              state: unsupported.length === 0 ? "Ready" : "Needs authority",
            }
          : flow,
      ),
    );
    setSavedSource(draft);
    onToast(`Saved .pam/flows/${parsed.id}.toml`);
  };

  return (
    <main className="main-view flow-view">
      <header className="project-header flow-header">
        <div>
          <h1>Flows</h1>
          <p>
            Repeatable work, with meaningful feedback. <span>·</span> {project}
          </p>
        </div>
        <div className="flow-header__state">
          <span>.pam/flows</span>
          <strong>{catalog.length} definitions</strong>
        </div>
      </header>

      <section className="flow-workbench" aria-label="Project flow editor">
        <aside className="flow-catalog" aria-label="Flow catalog">
          <div className="flow-pane-title">
            <div>
              <span className="eyebrow">Project catalog</span>
              <strong>Definitions</strong>
            </div>
            <FileText size={19} aria-hidden="true" />
          </div>
          <div className="flow-catalog__items">
            {catalog.map((flow) => (
              <button
                type="button"
                key={flow.id}
                className={`flow-catalog-item ${flow.id === selectedId ? "is-selected" : ""}`}
                onClick={() => selectFlow(flow)}
              >
                <span className="flow-catalog-item__icon">
                  <GitBranch size={18} weight={flow.id === selectedId ? "bold" : "regular"} />
                </span>
                <span>
                  <strong>{parseFlowSource(flow.source).name || flow.id}</strong>
                  <small>{flow.filename}</small>
                </span>
                <span className={`flow-catalog-item__state ${flow.state === "Ready" ? "is-ready" : ""}`}>
                  {flow.state}
                </span>
              </button>
            ))}
          </div>
          <div className="flow-catalog__note">
            <LockSimple size={16} aria-hidden="true" />
            Direct, ID-matched TOML files only. Symlinks and nested paths are refused.
          </div>
        </aside>

        <section className="flow-source-pane" aria-label="Flow TOML editor">
          <div className="flow-pane-title flow-pane-title--editor">
            <div>
              <span className="eyebrow">Editing</span>
              <strong>{selected.filename}</strong>
            </div>
            <div className="flow-editor-actions">
              <span className={`validation-chip ${validationErrors.length ? "is-invalid" : "is-valid"}`}>
                {validationErrors.length ? <WarningCircle size={15} /> : <CheckCircle size={15} weight="fill" />}
                {validationErrors.length ? `${validationErrors.length} issues` : "Valid schema v2"}
              </span>
              <button
                type="button"
                className="button button--primary flow-save"
                disabled={!changed || validationErrors.length > 0}
                onClick={saveFlow}
              >
                <FloppyDisk size={18} weight="bold" />
                {changed ? "Save flow" : "Saved"}
              </button>
            </div>
          </div>
          <div className="flow-code-wrap">
            <div className="flow-code-meta" aria-hidden="true">
              <Code size={16} />
              TOML
              <span>{draft.split("\n").length} lines</span>
            </div>
            <textarea
              className="flow-code"
              aria-label={`${selected.filename} TOML source`}
              spellCheck="false"
              value={draft}
              onChange={(event) => setDraft(event.target.value)}
            />
          </div>
          {validationErrors.length > 0 && (
            <div className="flow-validation-errors" role="alert">
              {validationErrors.slice(0, 3).map((error) => (
                <span key={error}>
                  <WarningCircle size={15} /> {error}
                </span>
              ))}
            </div>
          )}
        </section>

        <aside className="flow-inspector" aria-label="Flow dry-run and version diff">
          <div className="flow-inspector__tabs" role="tablist" aria-label="Flow inspection mode">
            <button
              type="button"
              role="tab"
              aria-selected={inspector === "plan"}
              className={inspector === "plan" ? "is-active" : ""}
              onClick={() => setInspector("plan")}
            >
              <ListChecks size={17} /> Dry run
            </button>
            <button
              type="button"
              role="tab"
              aria-selected={inspector === "diff"}
              className={inspector === "diff" ? "is-active" : ""}
              onClick={() => setInspector("diff")}
            >
              <GitDiff size={17} /> Version diff
              {diff.length > 0 && <span>{diff.length}</span>}
            </button>
          </div>

          {inspector === "plan" ? (
            <div className="flow-plan">
              <div className="flow-plan__summary">
                <span className="eyebrow">No execution</span>
                <strong>{parsed.steps.length} ordered steps</strong>
                <p>Static plan from the validated document. No command or connector is invoked.</p>
              </div>
              <div className="flow-plan__steps">
                {parsed.steps.map((step, index) => (
                  <article className="flow-plan-step" key={`${step.id}-${index}`}>
                    <div className={`flow-plan-step__number is-${step.semantic}`}>{index + 1}</div>
                    <div>
                      <header>
                        <strong>{step.id}</strong>
                        <span className={`role-chip is-${step.semantic}`}>{step.semantic || "unknown"}</span>
                      </header>
                      <p>{step.condition}</p>
                      <dl>
                        <div><dt>Approval</dt><dd>{step.approval}</dd></div>
                        <div><dt>Attempts</dt><dd>{step.attempts}</dd></div>
                      </dl>
                      <span className={`authority-line ${step.authority.supported ? "is-supported" : "is-unsupported"}`}>
                        {step.authority.supported ? <CheckCircle size={14} weight="fill" /> : <WarningCircle size={14} weight="fill" />}
                        {step.authority.label}
                      </span>
                    </div>
                  </article>
                ))}
              </div>
              <div className={`authority-summary ${unsupported.length ? "has-warning" : ""}`}>
                {unsupported.length ? <WarningCircle size={19} weight="fill" /> : <CheckCircle size={19} weight="fill" />}
                <div>
                  <strong>{unsupported.length ? `${unsupported.length} authority warning${unsupported.length === 1 ? "" : "s"}` : "Executable boundary supported"}</strong>
                  <span>{unsupported.length ? "The daemon will refuse these steps before acceptance." : "Read-only Git only · no shell · no approval required"}</span>
                </div>
              </div>
            </div>
          ) : (
            <div className="flow-diff">
              <div className="flow-plan__summary">
                <span className="eyebrow">Deterministic line diff</span>
                <strong>{changed ? `${diff.length} changed lines` : "Saved version matches"}</strong>
                <p>Compared with the last saved document in stable source order.</p>
              </div>
              <pre aria-label="Version diff">
                {diff.length === 0
                  ? "  No changes"
                  : diff.map((line, index) => (
                      <span className={`is-${line.kind}`} key={`${line.kind}-${index}`}>
                        {line.kind === "added" ? "+ " : "- "}{line.line || " "}{"\n"}
                      </span>
                    ))}
              </pre>
            </div>
          )}
        </aside>
      </section>
    </main>
  );
}

function SecondaryView({ view, project, onReturn, onToast }) {
  const isFlows = view === "flows";
  if (isFlows) return <FlowEditor project={project} onToast={onToast} />;
  return (
    <main className="main-view secondary-view">
      <header className="project-header">
        <div>
          <h1>Access</h1>
          <p>Narrow capabilities, visible to the developer.</p>
        </div>
      </header>

      <section className="secondary-surface">
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
        <SecondaryView
          view={activeView}
          project={project}
          onReturn={() => setActiveView("current")}
          onToast={showToast}
        />
      )}

      {drawerOpen && <EvidenceDrawer onClose={() => setDrawerOpen(false)} />}
      {toast && <div className="toast" role="status">{toast}</div>}
    </div>
  );
}
