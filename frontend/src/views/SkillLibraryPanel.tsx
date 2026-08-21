import {
  ArrowClockwise,
  BookOpen,
  CheckCircle,
  DownloadSimple,
  Eye,
  GitBranch,
  HardDrives,
  MapPin,
  Play,
  WarningCircle,
} from "@phosphor-icons/react";
import { useCallback, useEffect, useMemo, useRef, useState, type FormEvent } from "react";
import { sameFence, withOperation } from "../bridge";
import type {
  CommandFence,
  PamBridge,
  SkillArtifactDto,
  SkillLibraryActionRequest,
  SkillLibraryActionResultDto,
  SkillLibraryAgentDto,
  SkillLibraryDriftDto,
  SkillLibraryDriftStateDto,
  SkillLibraryEntryDto,
  SkillLibraryKeyDto,
  SkillLibraryPlanItemDto,
  SkillLibraryVersionDto,
} from "../domain";
import { presentError } from "../state";

type MutationAction = Exclude<SkillLibraryActionRequest["action"], "load" | "preview_materialization" | "inspect_drift" | "preview_resync">;
type PreviewKind = "materialization" | "resync";

interface VerifiedPreview {
  kind: PreviewKind;
  key: SkillLibraryKeyDto;
  items: SkillLibraryPlanItemDto[];
}

type DisplayDriftDto = SkillLibraryDriftStateDto | { state: "not_inspected" };

const libraryAgents: SkillLibraryAgentDto[] = ["claude", "codex", "cursor"];

function sameAuthority(left: CommandFence, right: CommandFence): boolean {
  return left.projectHandle === right.projectHandle && left.generation === right.generation;
}

function sameKey(left: SkillLibraryKeyDto, right: SkillLibraryKeyDto): boolean {
  return left.entryId === right.entryId && left.version === right.version && left.agent === right.agent;
}

function keyId(key: SkillLibraryKeyDto): string {
  return `${key.entryId}\u0000${key.version}\u0000${key.agent}`;
}

function label(value: string): string {
  return value.replaceAll("_", " ");
}

function shortDigest(value: string): string {
  const digest = value.startsWith("sha256:") ? value.slice(7) : value;
  return digest.length > 16 ? `${digest.slice(0, 10)}…${digest.slice(-6)}` : digest;
}

function driftLabel(drift: DisplayDriftDto): string {
  return drift.state === "conflict" ? `conflict · ${label(drift.reason)}` : label(drift.state);
}

function stateClass(value: boolean): string {
  return value ? "state-pill--healthy" : "state-pill--not-reported";
}

function driftClass(drift: DisplayDriftDto): string {
  if (drift.state === "clean") return "state-pill--healthy";
  if (drift.state === "not_inspected") return "state-pill--not-reported";
  return "state-pill--attention";
}

function versionFor(
  entries: SkillLibraryEntryDto[],
  key: SkillLibraryKeyDto | null,
): SkillLibraryVersionDto | null {
  if (!key) return null;
  return entries
    .find((entry) => entry.entryId === key.entryId)
    ?.versions.find((version) => version.version === key.version) ?? null;
}

function firstKey(entries: SkillLibraryEntryDto[]): SkillLibraryKeyDto | null {
  const entry = entries[0];
  const version = entry?.versions[0];
  const agent = libraryAgents[0];
  return entry && version && agent ? { entryId: entry.entryId, version: version.version, agent } : null;
}

function resultMatchesRequest(
  request: SkillLibraryActionRequest,
  result: SkillLibraryActionResultDto,
): boolean {
  if (result.schemaVersion !== 1 || result.action !== request.action) return false;
  if (request.action === "load") return true;
  if (request.action === "adopt") {
    return result.action === request.action
      && result.entryId === request.entryId
      && result.artifactId === request.artifactId;
  }
  if (request.action === "install_local" || request.action === "install_git") {
    return result.action === request.action && result.entryId === request.entryId;
  }
  const key: SkillLibraryKeyDto = request;
  if (result.action === "enable") return sameKey(key, result.key) && result.enabled;
  if (result.action === "disable") return sameKey(key, result.key);
  if (result.action === "inspect_drift") return sameKey(key, result.inspection.key);
  if (result.action === "preview_materialization" || result.action === "preview_resync") {
    return result.items.length === 1 && result.items.every((item) => sameKey(key, item.key));
  }
  if (result.action === "apply_materialization" || result.action === "apply_resync") {
    return result.outcomes.length === 1 && result.outcomes.every((outcome) => sameKey(key, outcome.key));
  }
  return false;
}

function refreshedStateMatchesMutation(
  request: SkillLibraryActionRequest,
  result: SkillLibraryActionResultDto,
  entries: SkillLibraryEntryDto[],
): boolean {
  if (request.action === "adopt" || request.action === "install_local" || request.action === "install_git") {
    if (result.action !== request.action) return false;
    return entries.some((entry) => entry.entryId === result.entryId
      && entry.versions.some((version) => version.version === result.version));
  }
  if (request.action === "enable" || request.action === "disable") {
    if (result.action !== request.action) return false;
    const version = versionFor(entries, result.key);
    return request.action === "enable"
      ? Boolean(version?.enabledAgents.includes(result.key.agent))
      : Boolean(version && !version.enabledAgents.includes(result.key.agent));
  }
  if (request.action === "apply_materialization" || request.action === "apply_resync") {
    if (result.action !== request.action) return false;
    return result.outcomes.every((outcome) => {
      const version = versionFor(entries, outcome.key);
      if (!version?.enabledAgents.includes(outcome.key.agent)) return false;
      const managed = version.managedAgents.includes(outcome.key.agent);
      if (request.action === "apply_resync") return outcome.ownershipRecorded && managed;
      return outcome.action === "no_op"
        ? outcome.ownershipRecorded === managed
        : outcome.ownershipRecorded && managed;
    });
  }
  return false;
}

function mutationLabel(action: MutationAction): string {
  const labels: Record<MutationAction, string> = {
    adopt: "Adoption",
    install_local: "Local installation",
    install_git: "Git installation",
    enable: "Enablement",
    disable: "Disablement",
    apply_materialization: "Materialization",
    apply_resync: "Resync",
  };
  return labels[action];
}

function ResultIdentity({ entryId, version, agent }: SkillLibraryKeyDto) {
  return <p>{entryId} · <code title={version}>{shortDigest(version)}</code> · {agent}</p>;
}

function VerifiedOperationResult({ result }: { result: SkillLibraryActionResultDto }) {
  if (result.action === "load" || result.action === "preview_materialization"
    || result.action === "preview_resync" || result.action === "inspect_drift") return null;

  return (
    <section className="skill-library-preview skill-library-result" aria-labelledby="skill-library-result-heading">
      <div><CheckCircle size={20} /><div><h3 id="skill-library-result-heading">Verified operation result</h3>
        {"entryId" in result
          ? <p>{result.entryId} · <code title={result.version}>{shortDigest(result.version)}</code></p>
          : "key" in result
            ? <ResultIdentity {...result.key} />
            : "outcomes" in result && result.outcomes[0]
              ? <ResultIdentity {...result.outcomes[0].key} />
              : null}
      </div></div>
      {"disposition" in result ? (
        <dl>
          <div><dt>Operation</dt><dd>{label(result.action)}</dd></div>
          <div><dt>Disposition</dt><dd>{label(result.disposition)}</dd></div>
        </dl>
      ) : result.action === "enable" ? (
        <dl>
          <div><dt>Operation</dt><dd>{label(result.action)}</dd></div>
          <div><dt>Enabled</dt><dd>{result.enabled ? "yes" : "no"}</dd></div>
          <div><dt>State changed</dt><dd>{result.changed ? "yes" : "no"}</dd></div>
        </dl>
      ) : result.action === "disable" ? (
        <dl>
          <div><dt>Operation</dt><dd>{label(result.action)}</dd></div>
          <div><dt>State changed</dt><dd>{result.stateChanged ? "yes" : "no"}</dd></div>
          <div><dt>Cleanup</dt><dd>{label(result.cleanup)}</dd></div>
        </dl>
      ) : "outcomes" in result ? (
        <><p>Operation: {label(result.action)}</p><ul>{result.outcomes.map((outcome) => (
          <li key={keyId(outcome.key)}>
            <strong>{label(outcome.action)}</strong>
            <code>{outcome.key.agent} fixed destination</code>
            <span>Ownership recorded: {outcome.ownershipRecorded ? "yes" : "no"}</span>
            {outcome.backup
              ? <span>Backup: {outcome.backup.byteLen} bytes · {shortDigest(outcome.backup.digest)}</span>
              : <span>No backup created</span>}
          </li>
        ))}</ul></>
      ) : null}
    </section>
  );
}

function Provenance({ version }: { version: SkillLibraryVersionDto }) {
  if (!version.installation) {
    return <span>Observed adoption · source path not retained</span>;
  }
  if (version.installation.kind === "local") {
    return <span>Local install · source path not retained</span>;
  }
  return (
    <span>
      Git install · commit <code>{shortDigest(version.installation.commit)}</code>
    </span>
  );
}

function LibraryEntries({
  entries,
  inspections,
}: {
  entries: SkillLibraryEntryDto[];
  inspections: Record<string, SkillLibraryDriftDto>;
}) {
  if (entries.length === 0) {
    return <p className="panel-empty">The canonical library has no retained entries yet.</p>;
  }
  return (
    <div className="skill-library-entries" aria-label="Canonical library entries">
      {entries.map((entry) => (
        <article className="skill-library-entry" key={entry.entryId}>
          <header>
            <span className="access-icon"><BookOpen size={20} aria-hidden="true" /></span>
            <div><strong>{entry.entryId}</strong><small>{entry.versions.length} retained version{entry.versions.length === 1 ? "" : "s"}</small></div>
          </header>
          {entry.versions.map((version) => (
            <section className="skill-library-version" key={version.version}>
              <div className="skill-library-version-meta">
                <code title={version.version}>{shortDigest(version.version)}</code>
                <Provenance version={version} />
              </div>
              <div className="skill-library-targets">
                {libraryAgents.map((agent) => {
                  const key = { entryId: entry.entryId, version: version.version, agent };
                  const drift = inspections[keyId(key)]?.state ?? { state: "not_inspected" as const };
                  const enabled = version.enabledAgents.includes(agent);
                  const managed = version.managedAgents.includes(agent);
                  return (
                  <article key={agent}>
                    <strong>{label(agent)}</strong>
                    <dl>
                      <div><dt>Enabled</dt><dd><span className={`state-pill ${stateClass(enabled)}`}>{enabled ? "yes" : "no"}</span></dd></div>
                      <div><dt>Managed</dt><dd><span className={`state-pill ${stateClass(managed)}`}>{managed ? "yes" : "no"}</span></dd></div>
                      <div><dt>Drift</dt><dd><span className={`state-pill ${driftClass(drift)}`}>{driftLabel(drift)}</span></dd></div>
                    </dl>
                  </article>
                  );
                })}
              </div>
            </section>
          ))}
        </article>
      ))}
    </div>
  );
}

export interface SkillLibraryPanelProps {
  bridge: PamBridge;
  fence: CommandFence;
}

export function SkillLibraryPanel({ bridge, fence }: SkillLibraryPanelProps) {
  const [entries, setEntries] = useState<SkillLibraryEntryDto[] | null>(null);
  const [selection, setSelection] = useState<SkillLibraryKeyDto | null>(null);
  const [busy, setBusy] = useState<SkillLibraryActionRequest["action"] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [verifiedResult, setVerifiedResult] = useState<SkillLibraryActionResultDto | null>(null);
  const [preview, setPreview] = useState<VerifiedPreview | null>(null);
  const [inspection, setInspection] = useState<SkillLibraryActionResultDto | null>(null);
  const [inspections, setInspections] = useState<Record<string, SkillLibraryDriftDto>>({});
  const [adoptEntryId, setAdoptEntryId] = useState("");
  const [artifactId, setArtifactId] = useState("");
  const [installMode, setInstallMode] = useState<"local" | "git">("local");
  const [installEntryId, setInstallEntryId] = useState("");
  const [sourcePath, setSourcePath] = useState("");
  const [gitUrl, setGitUrl] = useState("");
  const [artifactPath, setArtifactPath] = useState("");
  const [observedArtifacts, setObservedArtifacts] = useState<SkillArtifactDto[] | null>(null);
  const [inventoryError, setInventoryError] = useState<string | null>(null);
  const fenceRef = useRef(fence);
  const requestSequence = useRef(0);
  const inventorySequence = useRef(0);
  fenceRef.current = fence;

  const isCurrentRequest = useCallback((sequence: number, requestFence: CommandFence) => (
    sequence === requestSequence.current && sameAuthority(requestFence, fenceRef.current)
  ), []);

  const acceptResponse = useCallback((
    sequence: number,
    requestFence: CommandFence,
    action: SkillLibraryActionRequest,
    responseFence: CommandFence,
    result: SkillLibraryActionResultDto,
  ): boolean => {
    if (!isCurrentRequest(sequence, requestFence)) return false;
    if (!sameFence(requestFence, responseFence) || !resultMatchesRequest(action, result)) {
      setError("The library response did not match the exact project request and selection. Refresh the library before continuing.");
      return false;
    }
    return true;
  }, [isCurrentRequest]);

  const load = useCallback(async (clear = false) => {
    const sequence = ++requestSequence.current;
    const requestFence = withOperation(fenceRef.current);
    const action = { action: "load" } as const;
    setBusy("load");
    setError(null);
    if (clear) {
      setEntries(null);
      setSelection(null);
      setPreview(null);
      setInspection(null);
      setInspections({});
      setNotice(null);
      setVerifiedResult(null);
    }
    try {
      const response = await bridge.manageSkillLibrary(requestFence, action);
      if (!acceptResponse(sequence, requestFence, action, response.fence, response.data)) return;
      if (response.data.action !== "load") return;
      const refreshedEntries = response.data.entries;
      setEntries(refreshedEntries);
      setSelection((current) => versionFor(refreshedEntries, current) ? current : firstKey(refreshedEntries));
    } catch (loadError) {
      if (isCurrentRequest(sequence, requestFence)) setError(presentError(loadError));
    } finally {
      if (isCurrentRequest(sequence, requestFence)) setBusy(null);
    }
  }, [acceptResponse, bridge, isCurrentRequest]);

  const loadObservedArtifacts = useCallback(async () => {
    const sequence = ++inventorySequence.current;
    const requestFence = withOperation(fenceRef.current);
    setObservedArtifacts(null);
    setInventoryError(null);
    try {
      const response = await bridge.loadSkillInventory(requestFence);
      if (sequence !== inventorySequence.current || !sameAuthority(requestFence, fenceRef.current)) return;
      if (!sameFence(requestFence, response.fence)) {
        setInventoryError("Observed inventory did not match the active project. Retry Access before adopting.");
        return;
      }
      setObservedArtifacts(response.data.artifacts);
    } catch (loadError) {
      if (sequence === inventorySequence.current && sameAuthority(requestFence, fenceRef.current)) {
        setInventoryError(presentError(loadError));
      }
    }
  }, [bridge]);

  useEffect(() => {
    setAdoptEntryId("");
    setArtifactId("");
    setInstallEntryId("");
    setSourcePath("");
    setGitUrl("");
    setArtifactPath("");
    void load(true);
    void loadObservedArtifacts();
    return () => {
      requestSequence.current += 1;
      inventorySequence.current += 1;
    };
  }, [load, loadObservedArtifacts, fence.projectHandle, fence.generation]);

  const refreshAfterMutation = useCallback(async (
    sequence: number,
    mutationFence: CommandFence,
    action: SkillLibraryActionRequest,
    result: SkillLibraryActionResultDto,
  ): Promise<boolean> => {
    if (!isCurrentRequest(sequence, mutationFence)) return false;
    const refreshFence = withOperation(fenceRef.current);
    const refresh = { action: "load" } as const;
    const response = await bridge.manageSkillLibrary(refreshFence, refresh);
    if (!acceptResponse(sequence, refreshFence, refresh, response.fence, response.data)) return false;
    if (response.data.action !== "load") return false;
    const refreshedEntries = response.data.entries;
    setEntries(refreshedEntries);
    setSelection((current) => versionFor(refreshedEntries, current) ? current : firstKey(refreshedEntries));
    setPreview(null);
    setInspection(null);
    setInspections({});
    if (!refreshedStateMatchesMutation(action, result, refreshedEntries)) {
      setError("The mutation result did not match refreshed durable library state. Inspect the exact target before retrying.");
      return false;
    }
    setVerifiedResult(result);
    setNotice(`${mutationLabel(action.action as MutationAction)} verified against refreshed library state.`);
    return true;
  }, [acceptResponse, bridge, isCurrentRequest]);

  const run = useCallback(async (action: SkillLibraryActionRequest) => {
    const sequence = ++requestSequence.current;
    const requestFence = withOperation(fenceRef.current);
    setBusy(action.action);
    setError(null);
    setNotice(null);
    setVerifiedResult(null);
    try {
      const response = await bridge.manageSkillLibrary(requestFence, action);
      if (!acceptResponse(sequence, requestFence, action, response.fence, response.data)) return;
      if (action.action === "preview_materialization" || action.action === "preview_resync") {
        if (response.data.action !== action.action) return;
        setPreview({
          kind: action.action === "preview_resync" ? "resync" : "materialization",
          key: { entryId: action.entryId, version: action.version, agent: action.agent },
          items: response.data.items,
        });
        setInspection(null);
        return;
      }
      if (action.action === "inspect_drift") {
        setInspection(response.data);
        if (response.data.action === "inspect_drift") {
          const verifiedInspection = response.data.inspection;
          setInspections((current) => ({
            ...current,
            [keyId(verifiedInspection.key)]: verifiedInspection,
          }));
        }
        setPreview(null);
        return;
      }
      if (action.action !== "load") {
        const verified = await refreshAfterMutation(sequence, requestFence, action, response.data);
        if (!verified) return;
        if (action.action === "adopt") {
          setAdoptEntryId("");
          setArtifactId("");
        } else if (action.action === "install_local" || action.action === "install_git") {
          setInstallEntryId("");
          setSourcePath("");
          setGitUrl("");
          setArtifactPath("");
        }
      }
    } catch (runError) {
      if (isCurrentRequest(sequence, requestFence)) setError(presentError(runError));
    } finally {
      if (isCurrentRequest(sequence, requestFence)) setBusy(null);
    }
  }, [acceptResponse, bridge, isCurrentRequest, refreshAfterMutation]);

  const versionOptions = useMemo(() => (
    entries?.find((entry) => entry.entryId === selection?.entryId)?.versions ?? []
  ), [entries, selection?.entryId]);
  const version = versionFor(entries ?? [], selection);
  const enabled = Boolean(selection && version?.enabledAgents.includes(selection.agent));
  const managed = Boolean(selection && version?.managedAgents.includes(selection.agent));
  const drift = selection
    ? inspections[keyId(selection)]?.state ?? { state: "not_inspected" as const }
    : { state: "not_inspected" as const };
  const selectedPreview = preview && selection && sameKey(preview.key, selection) ? preview : null;
  const adoptableArtifacts = observedArtifacts ?? [];
  const selectedArtifact = adoptableArtifacts.find((artifact) => artifact.id === artifactId) ?? null;

  const chooseEntry = (entryId: string) => {
    const entry = entries?.find((candidate) => candidate.entryId === entryId);
    const version = entry?.versions[0];
    const agent = selection?.agent ?? libraryAgents[0];
    setSelection(entry && version && agent ? { entryId, version: version.version, agent } : null);
    setPreview(null);
    setInspection(null);
    setNotice(null);
  };

  const chooseVersion = (versionValue: string) => {
    if (!selection) return;
    const version = versionOptions.find((candidate) => candidate.version === versionValue);
    const agent = selection.agent;
    setSelection(version && agent ? { ...selection, version: version.version, agent } : null);
    setPreview(null);
    setInspection(null);
    setNotice(null);
  };

  const chooseAgent = (agent: SkillLibraryAgentDto) => {
    if (!selection) return;
    setSelection({ ...selection, agent });
    setPreview(null);
    setInspection(null);
    setNotice(null);
  };

  const submitAdopt = (event: FormEvent) => {
    event.preventDefault();
    if (adoptEntryId && artifactId) void run({ action: "adopt", entryId: adoptEntryId, artifactId });
  };

  const submitInstall = (event: FormEvent) => {
    event.preventDefault();
    if (!installEntryId) return;
    if (installMode === "local" && sourcePath) {
      void run({ action: "install_local", entryId: installEntryId, sourcePath });
    } else if (installMode === "git" && gitUrl && artifactPath) {
      void run({ action: "install_git", entryId: installEntryId, url: gitUrl, artifactPath });
    }
  };

  return (
    <section className="panel skill-library-panel" aria-labelledby="skill-library-heading">
      <div className="panel-title skill-library-title">
        <div><span className="eyebrow">Canonical collection</span><h2 id="skill-library-heading">Skill library</h2></div>
        <div><span>{entries?.length ?? 0} entr{entries?.length === 1 ? "y" : "ies"}</span><BookOpen size={22} aria-hidden="true" /></div>
      </div>
      <div className="skill-library-truth" aria-label="Library state definitions">
        <div><strong>Observed</strong><span>Shown in inventory above; detection alone grants no management.</span></div>
        <div><strong>Enabled</strong><span>Selected for this exact project and agent.</span></div>
        <div><strong>Managed</strong><span>Owned only after verified PAM publication.</span></div>
        <div><strong>Drift</strong><span>Read-only comparison with retained canonical bytes.</span></div>
      </div>
      {busy === "load" && !entries ? (
        <div className="skill-library-state" role="status">Loading bounded library metadata…</div>
      ) : error && !entries ? (
        <div className="skill-library-state is-error" role="alert">
          <WarningCircle size={24} aria-hidden="true" />
          <div><strong>Skill library unavailable</strong><p>{error}</p></div>
          <button type="button" className="button button--secondary" onClick={() => void load(true)}><ArrowClockwise size={18} /> Retry library</button>
        </div>
      ) : entries ? <LibraryEntries entries={entries} inspections={inspections} /> : null}

      {entries && (
        <div className="skill-library-workbench">
          <section aria-labelledby="skill-library-import-heading">
            <div className="skill-library-section-title"><div><DownloadSimple size={19} /><h3 id="skill-library-import-heading">Add exact bytes</h3></div><span>Sources stay local to the native operation.</span></div>
            <div className="skill-library-form-grid">
              <form onSubmit={submitAdopt}>
                <header><MapPin size={18} /><strong>Adopt observed artifact</strong></header>
                <label>Library entry ID<input name="adopt-entry-id" value={adoptEntryId} onChange={(event) => setAdoptEntryId(event.target.value)} placeholder="review-changes" required disabled={busy !== null} /></label>
                <label>Observed inventory artifact<select aria-label="Observed inventory artifact" name="artifact-id" value={artifactId} onChange={(event) => setArtifactId(event.target.value)} required disabled={busy !== null || observedArtifacts === null || adoptableArtifacts.length === 0}>
                  <option value="">Select an observed artifact</option>
                  {adoptableArtifacts.map((artifact) => <option value={artifact.id} key={artifact.id}>{artifact.name} · {label(artifact.origin)}</option>)}
                </select></label>
                {selectedArtifact && <p className="skill-library-artifact-identity">Exact observed ID <code>{selectedArtifact.id}</code></p>}
                {inventoryError && <p className="skill-library-form-error" role="alert">Observed inventory unavailable: {inventoryError}</p>}
                {observedArtifacts && adoptableArtifacts.length === 0 && <p>No observed artifacts are available to adopt.</p>}
                <button type="submit" className="button button--secondary" disabled={busy !== null || !adoptEntryId || !artifactId}>Adopt into library</button>
              </form>
              <form onSubmit={submitInstall}>
                <header><GitBranch size={18} /><strong>Install exact source</strong></header>
                <label>Source type<select value={installMode} onChange={(event) => setInstallMode(event.target.value as "local" | "git")} disabled={busy !== null}><option value="local">Local file</option><option value="git">Git revision</option></select></label>
                <label>Library entry ID<input name="install-entry-id" value={installEntryId} onChange={(event) => setInstallEntryId(event.target.value)} placeholder="review-changes" required disabled={busy !== null} /></label>
                {installMode === "local" ? (
                  <label>Local source path<input name="source-path" value={sourcePath} onChange={(event) => setSourcePath(event.target.value)} placeholder="/path/to/SKILL.md" required disabled={busy !== null} /></label>
                ) : (
                  <>
                    <label>Git URL<input name="git-url" value={gitUrl} onChange={(event) => setGitUrl(event.target.value)} placeholder="https://example.com/team/skills.git" required disabled={busy !== null} /></label>
                    <label>Artifact path<input name="git-artifact-path" value={artifactPath} onChange={(event) => setArtifactPath(event.target.value)} placeholder="skills/review/SKILL.md" required disabled={busy !== null} /></label>
                  </>
                )}
                <button type="submit" className="button button--secondary" disabled={busy !== null || !installEntryId || (installMode === "local" ? !sourcePath : !gitUrl || !artifactPath)}>Install into library</button>
              </form>
            </div>
          </section>

          <section aria-labelledby="skill-library-target-heading">
            <div className="skill-library-section-title"><div><HardDrives size={19} /><h3 id="skill-library-target-heading">Manage exact target</h3></div><span>Every action is fenced to the active project generation.</span></div>
            {selection ? (
              <>
                <div className="skill-library-selectors">
                  <label>Entry<select aria-label="Library entry" value={selection.entryId} onChange={(event) => chooseEntry(event.target.value)} disabled={busy !== null}>{entries.map((entry) => <option value={entry.entryId} key={entry.entryId}>{entry.entryId}</option>)}</select></label>
                  <label>Version<select aria-label="Library version" value={selection.version} onChange={(event) => chooseVersion(event.target.value)} disabled={busy !== null}>{versionOptions.map((version) => <option value={version.version} key={version.version}>{shortDigest(version.version)}</option>)}</select></label>
                  <label>Agent<select aria-label="Library agent" value={selection.agent} onChange={(event) => chooseAgent(event.target.value as SkillLibraryAgentDto)} disabled={busy !== null}>{libraryAgents.map((agent) => <option value={agent} key={agent}>{label(agent)}</option>)}</select></label>
                </div>
                {version && (
                  <div className="skill-library-selected-state" role="status">
                    <span className={`state-pill ${stateClass(enabled)}`}>enabled {enabled ? "yes" : "no"}</span>
                    <span className={`state-pill ${stateClass(managed)}`}>managed {managed ? "yes" : "no"}</span>
                    <span className={`state-pill ${driftClass(drift)}`}>drift {driftLabel(drift)}</span>
                  </div>
                )}
                <div className="skill-library-actions">
                  <button type="button" className="button button--secondary" disabled={busy !== null || enabled} onClick={() => void run({ action: "enable", ...selection })}>Enable target</button>
                  <button type="button" className="button button--secondary" disabled={busy !== null || !enabled} onClick={() => void run({ action: "disable", ...selection })}>Disable target</button>
                  <button type="button" className="button button--secondary" disabled={busy !== null || !enabled} onClick={() => void run({ action: "preview_materialization", ...selection })}>Preview materialization</button>
                  <button type="button" className="button button--secondary" disabled={busy !== null} onClick={() => void run({ action: "inspect_drift", ...selection })}><Eye size={17} /> Inspect drift</button>
                  <button type="button" className="button button--secondary" disabled={busy !== null || !enabled || !managed} onClick={() => void run({ action: "preview_resync", ...selection })}>Preview resync</button>
                </div>
              </>
            ) : <p className="panel-empty">Add a library entry before managing an agent target.</p>}
          </section>

          {selectedPreview && (
            <section className="skill-library-preview" aria-labelledby="skill-library-preview-heading">
              <div><Play size={20} /><div><h3 id="skill-library-preview-heading">Verified {selectedPreview.kind} preview</h3><p>{selectedPreview.key.entryId} · {shortDigest(selectedPreview.key.version)} · {selectedPreview.key.agent}</p></div></div>
              {selectedPreview.items.length === 0 ? <p>No filesystem change is required.</p> : (
                <ul>{selectedPreview.items.map((item) => <li key={keyId(item.key)}><strong>{label(item.action)}</strong><code>{item.key.agent} fixed destination</code>{item.existing && <span>Existing: {item.existing.byteLen} bytes · {shortDigest(item.existing.digest)}</span>}{item.backupPlanned && <span>Backup planned before replacement</span>}</li>)}</ul>
              )}
              <button type="button" className="button button--primary" disabled={busy !== null} onClick={() => void run({ action: selectedPreview.kind === "resync" ? "apply_resync" : "apply_materialization", ...selectedPreview.key })}>Apply exact {selectedPreview.kind}</button>
            </section>
          )}

          {inspection?.action === "inspect_drift" && (
            <section className="skill-library-inspection" aria-labelledby="skill-library-inspection-heading">
              <Eye size={20} /><div><h3 id="skill-library-inspection-heading">Verified drift inspection</h3><p>Expected <code>{shortDigest(inspection.inspection.expectedDigest)}</code></p><span className={`state-pill ${driftClass(inspection.inspection.state)}`}>{driftLabel(inspection.inspection.state)}</span></div>
            </section>
          )}
          {verifiedResult && <VerifiedOperationResult result={verifiedResult} />}
          {busy && busy !== "load" && <p className="skill-library-operation" role="status">Waiting for verified {label(busy)} result…</p>}
          {error && entries && <p className="skill-library-message is-error" role="alert"><WarningCircle size={17} />{error}</p>}
          {notice && <p className="skill-library-message" role="status"><CheckCircle size={17} />{notice}</p>}
        </div>
      )}
    </section>
  );
}
