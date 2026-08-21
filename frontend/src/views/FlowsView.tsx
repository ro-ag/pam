import {
  ArrowClockwise,
  FileText,
  FloppyDisk,
  GitBranch,
  ListChecks,
  WarningCircle,
} from "@phosphor-icons/react";
import { useCallback, useEffect, useId, useRef, useState } from "react";
import { Tab, TabList, TabPanel, Tabs } from "react-aria-components";
import { sameFence, withOperation } from "../bridge";
import type {
  CommandFence,
  FlowDocumentDataDto,
  FlowReviewDataDto,
  FlowWorkspaceDataDto,
  PamBridge,
} from "../domain";
import { MAX_FLOW_SOURCE } from "../domain";
import { presentError } from "../state";

function sameAuthority(left: CommandFence, right: CommandFence): boolean {
  return left.projectHandle === right.projectHandle && left.generation === right.generation;
}

export interface FlowsViewProps {
  bridge: PamBridge;
  fence: CommandFence;
  onError: (message: string) => void;
  onToast: (message: string) => void;
}

export function FlowsView({ bridge, fence, onError, onToast }: FlowsViewProps) {
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
              <Tabs
                className="flow-inspector"
                selectedKey={reviewPanel}
                onSelectionChange={(key) => {
                  if (key === "dry-run" || key === "diff") setReviewPanel(key);
                }}
              >
                <TabList className="flow-inspector-tabs" aria-label="Flow review">
                  <Tab id="dry-run" className="flow-inspector-tab">Dry run</Tab>
                  <Tab id="diff" className="flow-inspector-tab">Version diff{acceptedReview.diff.changed ? " · changed" : " · clean"}</Tab>
                </TabList>
                <TabPanel id="dry-run" className="flow-review">
                  {acceptedReview.dryRun.steps.slice(0, 5).map((step) => <p key={`${step.index}:${step.id}`}><span>{step.index + 1}</span><strong>{step.id}</strong><small>{step.semanticRole} · {step.daemonAuthority}</small></p>)}
                </TabPanel>
                <TabPanel id="diff" className="flow-diff">
                  {acceptedReview.diff.lines.length === 0
                    ? <p>No versioned source changes were reported.</p>
                    : acceptedReview.diff.lines.map((line, index) => <pre className={`is-${line.kind}`} key={`${index}:${line.kind}`}>{line.kind === "added" ? "+" : line.kind === "removed" ? "−" : " "} {line.text}</pre>)}
                  {acceptedReview.diff.truncated && <p className="bounded-note">The bounded version diff was truncated.</p>}
                </TabPanel>
              </Tabs>
            )}
          </section>
        </section>
      )}
    </main>
  );
}
