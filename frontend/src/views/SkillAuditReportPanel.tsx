import { ArrowClockwise, ChartBar, Play, WarningCircle } from "@phosphor-icons/react";
import { useCallback, useEffect, useRef, useState } from "react";
import { sameFence, withOperation } from "../bridge";
import type {
  CommandFence,
  PamBridge,
  SkillAuditDataDto,
  SkillAuditMultiArtifactFindingDto,
  SkillAuditStaleCandidateDto,
} from "../domain";
import { presentError } from "../state";

type AuditAction = "load" | "run";

function sameAuthority(left: CommandFence, right: CommandFence): boolean {
  return left.projectHandle === right.projectHandle && left.generation === right.generation;
}

function label(value: string): string {
  return value.replaceAll("_", " ");
}

function count(value: number): string {
  return new Intl.NumberFormat().format(value);
}

function observation(value: number): { dateTime?: string; label: string } {
  const date = new Date(value);
  return Number.isNaN(date.valueOf())
    ? { label: "Observation time unavailable" }
    : {
        dateTime: date.toISOString(),
        label: `Observed ${new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(date)}`,
      };
}

function MultiArtifactFindings({
  empty,
  findings,
}: {
  empty: string;
  findings: SkillAuditMultiArtifactFindingDto[];
}) {
  if (findings.length === 0) return <p className="skill-audit-finding-empty">{empty}</p>;
  return (
    <ul className="skill-audit-findings">
      {findings.map((finding, index) => (
        <li key={`${finding.artifactIds.join(":")}:${index}`}>
          <strong>{finding.summary}</strong>
          <span>{finding.artifactIds.join(" · ")}</span>
        </li>
      ))}
    </ul>
  );
}

function StaleFindings({ findings }: { findings: SkillAuditStaleCandidateDto[] }) {
  if (findings.length === 0) return <p className="skill-audit-finding-empty">No stale candidates reported.</p>;
  return (
    <ul className="skill-audit-findings">
      {findings.map((finding, index) => (
        <li key={`${finding.artifactId}:${index}`}>
          <strong>{finding.reason}</strong>
          <span>{finding.artifactId}</span>
        </li>
      ))}
    </ul>
  );
}

function Evaluation({ data }: { data: SkillAuditDataDto }) {
  const { evaluation } = data;
  if (evaluation.status === "no_evaluator") {
    return (
      <section className="skill-audit-evaluation" aria-labelledby="skill-audit-evaluation-heading">
        <div className="skill-audit-section-title">
          <h3 id="skill-audit-evaluation-heading">Evaluation status</h3>
          <span className="state-pill">deterministic only</span>
        </div>
        <p className="skill-audit-fallback">
          Deterministic footprint only — no supported evaluator was available, so PAM did not produce a qualitative verdict.
        </p>
      </section>
    );
  }

  if (evaluation.status === "failed") {
    return (
      <section className="skill-audit-evaluation" aria-labelledby="skill-audit-evaluation-heading">
        <div className="skill-audit-section-title">
          <h3 id="skill-audit-evaluation-heading">Evaluation status</h3>
          <span className="state-pill state-pill--failed">failed</span>
        </div>
        <dl className="skill-audit-failure-facts">
          <div><dt>Evaluator</dt><dd>{label(evaluation.evaluator)}</dd></div>
          <div><dt>Failure</dt><dd>{label(evaluation.failure)}</dd></div>
        </dl>
      </section>
    );
  }

  return (
    <section className="skill-audit-evaluation" aria-labelledby="skill-audit-evaluation-heading">
      <div className="skill-audit-section-title">
        <h3 id="skill-audit-evaluation-heading">Evaluator verdict</h3>
        <span className={`state-pill state-pill--${evaluation.verdict.saturationGrade}`}>{label(evaluation.verdict.saturationGrade)}</span>
      </div>
      <dl className="skill-audit-verdict-summary">
        <div><dt>Evaluator</dt><dd>{label(evaluation.evaluator)}</dd></div>
        <div><dt>Saturation grade</dt><dd>{label(evaluation.verdict.saturationGrade)}</dd></div>
        <div><dt>Overall summary</dt><dd>{evaluation.verdict.overallSummary}</dd></div>
      </dl>
      <div className="skill-audit-verdict-grid">
        <section aria-labelledby="skill-audit-overlaps-heading">
          <h4 id="skill-audit-overlaps-heading">Overlaps</h4>
          <MultiArtifactFindings findings={evaluation.verdict.overlaps} empty="No overlaps reported." />
        </section>
        <section aria-labelledby="skill-audit-conflicts-heading">
          <h4 id="skill-audit-conflicts-heading">Conflicts</h4>
          <MultiArtifactFindings findings={evaluation.verdict.conflicts} empty="No conflicts reported." />
        </section>
        <section aria-labelledby="skill-audit-stale-heading">
          <h4 id="skill-audit-stale-heading">Stale candidates</h4>
          <StaleFindings findings={evaluation.verdict.staleCandidates} />
        </section>
      </div>
    </section>
  );
}

function AuditReport({ data }: { data: SkillAuditDataDto }) {
  const { footprint } = data;
  const observed = observation(data.observedAtMs);
  return (
    <>
      <div className="skill-audit-summary" role="status">
        <div><strong>{count(footprint.allSessionEstimatedTokens)}</strong><span>estimated tokens across agent sessions</span></div>
        <div><strong>{count(footprint.alwaysLoadedArtifactCount)}</strong><span>always-loaded artifacts</span></div>
        <div><strong>{count(footprint.allSessionRawBytes)}</strong><span>raw bytes across agent sessions</span></div>
      </div>
      <div className="skill-audit-meta">
        <span>Estimator: {label(footprint.estimator)}</span>
        <time dateTime={observed.dateTime}>{observed.label}</time>
      </div>
      <div className="skill-audit-totals">
        <section aria-labelledby="skill-audit-agent-totals-heading">
          <h3 id="skill-audit-agent-totals-heading">Per-agent sessions</h3>
          <dl>
            {footprint.originSessions.map((session) => (
              <div key={session.origin}>
                <dt>{label(session.origin)}</dt>
                <dd>{count(session.artifactCount)} artifacts · {count(session.estimatedTokens)} tokens · {count(session.rawBytes)} bytes</dd>
              </div>
            ))}
          </dl>
        </section>
        <section aria-labelledby="skill-audit-scope-totals-heading">
          <h3 id="skill-audit-scope-totals-heading">Scope totals</h3>
          <dl>
            {footprint.scopeTotals.map((scope) => (
              <div key={scope.scope}>
                <dt>{label(scope.scope)}</dt>
                <dd>{count(scope.artifactCount)} artifacts · {count(scope.estimatedTokens)} tokens · {count(scope.rawBytes)} bytes</dd>
              </div>
            ))}
          </dl>
        </section>
      </div>
      <section className="skill-audit-ranked" aria-labelledby="skill-audit-ranked-heading">
        <div className="skill-audit-section-title">
          <h3 id="skill-audit-ranked-heading">Ranked artifacts</h3>
          <span>{count(footprint.rankedArtifactsTotal)} total</span>
        </div>
        {footprint.rankedArtifacts.length === 0 ? (
          <p className="panel-empty">No ranked artifacts were reported.</p>
        ) : (
          <ol>
            {footprint.rankedArtifacts.map((artifact) => (
              <li key={artifact.id}>
                <span className="skill-audit-rank">#{artifact.rank}</span>
                <div className="skill-audit-artifact-copy">
                  <strong>{artifact.name}</strong>
                  <code>{artifact.logicalPath}</code>
                  <span>{label(artifact.kind)} · {label(artifact.scope)} · {label(artifact.origin)} · {label(artifact.loadSemantics)}</span>
                  <small>ID: {artifact.id}</small>
                  <small>Content: {artifact.contentHash}</small>
                </div>
                <div className="skill-audit-artifact-size">
                  <strong>{count(artifact.estimatedTokens)} tokens</strong>
                  <span>{count(artifact.rawBytes)} bytes</span>
                </div>
              </li>
            ))}
          </ol>
        )}
        {footprint.rankedArtifactsTruncated && (
          <p className="skill-inventory-truncated">
            Showing {count(footprint.rankedArtifacts.length)} of {count(footprint.rankedArtifactsTotal)} ranked artifacts. The native response is bounded.
          </p>
        )}
      </section>
      <Evaluation data={data} />
    </>
  );
}

export interface SkillAuditReportPanelProps {
  bridge: PamBridge;
  fence: CommandFence;
}

export function SkillAuditReportPanel({ bridge, fence }: SkillAuditReportPanelProps) {
  const [audit, setAudit] = useState<SkillAuditDataDto | null>(null);
  const [loaded, setLoaded] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [pendingAction, setPendingAction] = useState<AuditAction | null>(null);
  const [failedAction, setFailedAction] = useState<AuditAction>("load");
  const fenceRef = useRef(fence);
  const requestSequence = useRef(0);
  fenceRef.current = fence;

  const isCurrentRequest = useCallback((sequence: number, requestFence: CommandFence) => (
    sequence === requestSequence.current && sameAuthority(requestFence, fenceRef.current)
  ), []);

  const requestAudit = useCallback(async (action: AuditAction) => {
    const sequence = ++requestSequence.current;
    const requestFence = withOperation(fenceRef.current);
    setPendingAction(action);
    setAudit(null);
    setError(null);
    try {
      const response = action === "run"
        ? await bridge.runSkillAudit(requestFence)
        : await bridge.loadSkillAudit(requestFence);
      if (!isCurrentRequest(sequence, requestFence)) return;
      if (!sameFence(requestFence, response.fence)) {
        setFailedAction(action);
        setError("The skill audit response did not match the active project request. Retry audit.");
        setLoaded(true);
        return;
      }
      setAudit(response.data);
      setLoaded(true);
    } catch (requestError) {
      if (isCurrentRequest(sequence, requestFence)) {
        setFailedAction(action);
        setError(presentError(requestError));
        setLoaded(true);
      }
    } finally {
      if (isCurrentRequest(sequence, requestFence)) setPendingAction(null);
    }
  }, [bridge, isCurrentRequest]);

  useEffect(() => {
    void requestAudit("load");
    return () => { requestSequence.current += 1; };
  }, [requestAudit, fence.projectHandle, fence.generation]);

  return (
    <section className="panel skill-audit-panel" aria-labelledby="skill-audit-heading">
      <div className="panel-title skill-audit-title">
        <div><span className="eyebrow">Always-loaded footprint</span><h2 id="skill-audit-heading">Skill audit</h2></div>
        <div>
          {audit && !pendingAction && (
            <button type="button" className="button button--secondary button--small" onClick={() => void requestAudit("run")}>
              <Play size={17} /> Run audit
            </button>
          )}
          <ChartBar size={22} aria-hidden="true" />
        </div>
      </div>
      {pendingAction ? (
        <div className="skill-inventory-state" role="status">
          {pendingAction === "run" ? "Running bounded skill audit…" : "Loading latest skill audit…"}
        </div>
      ) : error ? (
        <div className="skill-inventory-state is-error" role="alert">
          <WarningCircle size={24} />
          <div><strong>Skill audit unavailable</strong><p>{error}</p></div>
          <button type="button" className="button button--secondary" onClick={() => void requestAudit(failedAction)}>
            <ArrowClockwise size={18} /> Retry audit
          </button>
        </div>
      ) : loaded && !audit ? (
        <div className="skill-audit-empty">
          <ChartBar size={30} aria-hidden="true" />
          <div><strong>No saved skill audit</strong><p>Run a bounded audit to measure the current always-loaded agent footprint.</p></div>
          <button type="button" className="button button--primary" onClick={() => void requestAudit("run")}>
            <Play size={18} /> Run audit
          </button>
        </div>
      ) : audit ? <AuditReport data={audit} /> : null}
    </section>
  );
}
