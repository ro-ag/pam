import { EngineCard } from "./EngineCard";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Check, LoaderCircle } from "lucide-react";
import { useEffect, useState } from "react";
import { Badge } from "../components/ui/Badge";
import { Button } from "../components/ui/Button";
import { ConfirmButton } from "../components/ui/ConfirmButton";
import { FailureNote } from "../components/ui/FailureNote";
import { Panel } from "../components/ui/Panel";
import { PageTabs, PagePane } from "../components/ui/PageTabs";
import { PageHeader } from "../components/ui/PageHeader";
import { Section } from "../components/ui/Section";
import { formatBytes, percentOf } from "../lib/bytes";
import {
  modelsCatalog,
  modelsDefaultsSet,
  modelsDelete,
  modelsDownload,
  modelsDownloadCancel,
  modelsDownloadDiscard,
  modelsList,
  modelsLoad,
  modelsStatus,
  modelsTry,
  modelsUnload,
  modelsVerify,
  toBridgeFailure,
  type BridgeFailure,
  type CatalogPreset,
  type GenerateResult,
  type ModelEntry,
  type ModelJob,
  type ModelsStatus,
} from "../lib/ipc";

/**
 * Models — the human's view of the inference layer: running, on
 * disk, on offer, and a box to prove a loaded model answers.
 *
 * Administration is GUI-only by design (spine decision): every
 * control is an `admin.models.*` op no agent, CLI, or MCP call can
 * reach. A model under 18 GB loads and answers but is refused as a
 * tier default — both facts shown before the refusal. Polling uses
 * `admin.models.status` alone, ticking every 2s while busy, else 10s.
 */

/** Poll interval while a job is running or the runtime is loading. */
export const POLL_BUSY_MS = 2_000;

/** Poll interval when nothing is moving. */
export const POLL_IDLE_MS = 10_000;

/** Default token budget for the try box — a wiring check, not an essay. */
const TRY_DEFAULT_MAX_TOKENS = 64;

/** The sentence a `test_only` model carries wherever it is offered. */
export const FLOOR_SENTENCE = "unverified — wiring checks only, never a tier default";

/** The sentence a verified but unqualified model carries wherever it is offered. */
export const UNQUALIFIED_SENTENCE =
  "verified, not qualified — Try only, never a tier default";

/** The admission rule, said plainly, next to the paste-URL form. */
const FLOOR_NOTE =
  "Unverified models load only as test-only; a job needs a verified digest that met the capability gates on this platform.";

/**
 * Why an entry cannot be a tier default, or undefined when it can. The same
 * two refusals the daemon makes (`unverified`, `unqualified`), so the human
 * never has to earn the refusal to learn the rule.
 */
export function admissionBlocker(entry: ModelEntry): string | undefined {
  if (entry.class === "test_only") return FLOOR_SENTENCE;
  if (entry.qualification === null) return UNQUALIFIED_SENTENCE;
  return undefined;
}

/** Empty library, in Pam's voice. */
export const EMPTY_LIBRARY_SENTENCE =
  "No weights on the shelf yet. Pick a model from Downloads and I'll fetch and verify it.";

/** Idle runtime, in Pam's voice. */
export const IDLE_RUNTIME_SENTENCE =
  "Nothing loaded. Memory is yours until a job or a click needs the model.";

/** Why the try box is closed when nothing is in memory. */
const TRY_DISABLED_REASON = "Load a model first — there is nothing to ask.";

/** The model id a preset installs as: `<vendor>/<file stem>`. */
export function presetModelId(preset: CatalogPreset): string {
  return `${preset.vendor}/${preset.file_name.replace(/\.gguf$/, "")}`;
}

/** The running download for `modelId`, if one is in flight. */
export function runningDownload(jobs: ModelJob[], modelId: string): ModelJob | undefined {
  return jobs.find(
    (job) => job.kind === "download" && job.state === "running" && job.model_id === modelId,
  );
}

/** The newest download job for `modelId`, whatever state it reached. */
export function latestDownload(jobs: ModelJob[], modelId: string): ModelJob | undefined {
  return jobs.find((job) => job.kind === "download" && job.model_id === modelId);
}

/** What a settled download says went wrong, or `null` when it did not fail. */
export function downloadFailure(job: ModelJob | undefined): BridgeFailure | null {
  if (!job || job.state !== "failed") return null;
  // The daemon writes `{cause, detail, recovery}`; a row from an older
  // build, or one truncated somehow, still has to say something rather
  // than render an empty box.
  const fallback: BridgeFailure = {
    cause: "download_failed",
    detail: job.detail ?? "the transfer ended without saying why",
    recovery: "Download again — the partial file is kept, so it resumes.",
  };
  if (!job.detail) return fallback;
  try {
    const parsed: unknown = JSON.parse(job.detail);
    if (typeof parsed !== "object" || parsed === null) return fallback;
    const body = parsed as Record<string, unknown>;
    return {
      cause: typeof body.cause === "string" ? body.cause : fallback.cause,
      detail: typeof body.detail === "string" ? body.detail : fallback.detail,
      recovery: typeof body.recovery === "string" ? body.recovery : fallback.recovery,
    };
  } catch {
    return fallback;
  }
}

/** How often the status query should tick, given what it last saw. */
export function pollInterval(status: ModelsStatus | undefined): number {
  if (!status) return POLL_IDLE_MS;
  const working =
    status.runtime.state.state === "loading" ||
    status.jobs.some((job) => job.state === "running");
  return working ? POLL_BUSY_MS : POLL_IDLE_MS;
}

// --- shared row furniture --------------------------------------------------

/** One label/value pair in the runtime card's fact grid. */
function Fact({ label, value }: { label: string; value: string }) {
  return (
    <div className="min-w-0 space-y-0.5">
      <dt className="font-data text-xs text-ink-faint">{label}</dt>
      <dd className="truncate font-data text-sm text-ink tabular-nums">{value}</dd>
    </div>
  );
}

/** The admission badge plus, for anything short of qualified, the reason it is capped. */
function ClassBadge({ entry }: { entry: ModelEntry }) {
  const qualification = entry.qualification;
  if (qualification !== null) {
    return (
      <span className="space-y-1">
        <Badge tone="success">qualified</Badge>
        <span className="block font-sans text-xs text-ink-faint">
          {qualification.contract} · {(qualification.accuracy * 100).toFixed(1)}% ·{" "}
          {qualification.false_passes} false passes · {qualification.decided}
        </span>
      </span>
    );
  }
  if (entry.class === "engine") {
    return (
      <span className="space-y-1">
        <Badge tone="neutral">engine</Badge>
        <span className="block font-sans text-xs text-ink-faint">{UNQUALIFIED_SENTENCE}</span>
      </span>
    );
  }
  return (
    <span className="space-y-1">
      <Badge tone="neutral">test only</Badge>
      <span className="block font-sans text-xs text-ink-faint">{FLOOR_SENTENCE}</span>
    </span>
  );
}

/** What a digest run (or its absence) says about a file. */
function VerifiedBadge({ entry }: { entry: ModelEntry }) {
  const record = entry.verified;
  if (record === null) {
    return <span className="font-data text-xs text-ink-faint">unverified</span>;
  }
  if (record.matches_catalog === true) return <Badge tone="success">verified</Badge>;
  if (record.matches_catalog === false) return <Badge tone="danger">digest mismatch</Badge>;
  return <Badge tone="neutral">hashed</Badge>;
}

// --- 1. runtime ------------------------------------------------------------

function RuntimeCard({
  status,
  models,
  failure,
}: {
  status: ModelsStatus | undefined;
  models: ModelEntry[];
  failure: BridgeFailure | null;
}) {
  const queryClient = useQueryClient();
  const [choice, setChoice] = useState("");
  const [actionFailure, setActionFailure] = useState<BridgeFailure | null>(null);

  const settle = () => void queryClient.invalidateQueries({ queryKey: ["models"] });

  const load = useMutation({
    mutationFn: (modelId: string) => modelsLoad(modelId),
    onMutate: () => setActionFailure(null),
    onError: (error) => setActionFailure(toBridgeFailure(error)),
    onSettled: settle,
  });

  const unload = useMutation({
    mutationFn: () => modelsUnload(),
    onMutate: () => setActionFailure(null),
    onError: (error) => setActionFailure(toBridgeFailure(error)),
    onSettled: settle,
  });

  const runtime = status?.runtime.state;
  const loaded = runtime?.state === "loaded" ? runtime : null;
  const engine = status?.engine;
  // The try box exists to prove wiring, so test-only weights are loadable
  // here on purpose; only the tier defaults enforce verification.
  const selectable = models;
  const pick = choice || selectable[0]?.id || "";

  return (
    <Panel ground="raised" className="space-y-5 p-5">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <p className="font-data text-xs text-ink-faint">in memory</p>
        {runtime?.state === "loaded" && <Badge tone="success">loaded</Badge>}
        {runtime?.state === "loading" && (
          <Badge tone="warning">loading · {runtime.phase}</Badge>
        )}
        {runtime?.state === "idle" && engine?.loaded && <Badge tone="success">engine</Badge>}
        {runtime?.state === "idle" && !engine?.loaded && <Badge tone="neutral">idle</Badge>}
      </div>

      {failure && <FailureNote failure={failure} label="runtime" />}

      {!failure && runtime?.state === "idle" && !engine?.loaded && (
        <p className="font-sans text-sm text-ink-muted">{IDLE_RUNTIME_SENTENCE}</p>
      )}

      {engine?.installed && engine.loaded && (
        <div className="flex flex-wrap items-center gap-4 rounded-card border border-line p-3">
          <Badge tone="accent">engine</Badge>
          <dl className="grid min-w-0 flex-1 grid-cols-2 gap-x-6 gap-y-2 sm:grid-cols-3">
            <Fact label="model" value={engine.loaded.id} />
            <Fact label="context" value={`${engine.loaded.context_length} tokens`} />
            <Fact label="build" value={engine.loaded.build_info} />
          </dl>
        </div>
      )}

      {engine?.installed && !engine.loaded && runtime?.state === "idle" && (
        <p className="font-sans text-sm text-ink-muted">Engine ready, nothing loaded</p>
      )}

      {loaded && (
        <div className="flex flex-wrap items-end justify-between gap-4">
          <dl className="grid min-w-0 flex-1 grid-cols-2 gap-x-6 gap-y-3 sm:grid-cols-3">
            <Fact label="model" value={loaded.id} />
            <Fact label="quant" value={loaded.quant} />
            <Fact label="context" value={`${loaded.context_length} tokens`} />
            <Fact label="weights" value={formatBytes(loaded.weight_bytes)} />
            <Fact label="device" value={loaded.device} />
            <Fact label="architecture" value={loaded.architecture} />
          </dl>
          <div className="space-y-0.5 text-right">
            <p className="font-data text-xs text-ink-faint">last tokens/sec</p>
            <p className="font-display text-title font-semibold text-ink tabular-nums">
              {loaded.last_tokens_per_sec === null
                ? "—"
                : loaded.last_tokens_per_sec.toFixed(1)}
            </p>
          </div>
        </div>
      )}

      <div className="flex flex-wrap items-center gap-2 border-t border-line pt-4">
        <select
          aria-label="model to load"
          value={pick}
          disabled={selectable.length === 0 || load.isPending}
          onChange={(event) => setChoice(event.target.value)}
          className="h-8 min-w-56 rounded-control field-control border border-control-line bg-inset px-2 font-data text-xs text-ink disabled:cursor-not-allowed disabled:opacity-50"
        >
          {selectable.length === 0 && <option value="">nothing installed</option>}
          {selectable.map((model) => (
            <option key={model.id} value={model.id}>
              {model.id}
              {model.class === "test_only" ? " (test only)" : ""}
            </option>
          ))}
        </select>
        <Button
          size="sm"
          disabled={!pick || load.isPending || runtime?.state === "loading"}
          onClick={() => load.mutate(pick)}
        >
          {load.isPending && (
            <LoaderCircle aria-hidden="true" className="size-3.5 animate-spin" />
          )}
          Load
        </Button>
        <Button
          size="sm"
          variant="ghost"
          disabled={(!loaded && !engine?.loaded) || unload.isPending}
          onClick={() => unload.mutate()}
        >
          Unload
        </Button>
        <span className="ml-auto font-data text-xs text-ink-faint">
          {status === undefined
            ? "—"
            : status.idle_unload_min === 0
              ? "stays resident until unloaded"
              : `idle unload after ${status.idle_unload_min} min`}
        </span>
      </div>

      {actionFailure && <FailureNote failure={actionFailure} label="runtime" />}
    </Panel>
  );
}

// --- 2. library ------------------------------------------------------------

function LibraryRow({
  entry,
  defaults,
  busy,
  onLoad,
  onDefault,
  onVerify,
  onDelete,
}: {
  entry: ModelEntry;
  defaults: ModelsStatus["defaults"] | undefined;
  busy: boolean;
  onLoad: () => void;
  onDefault: (tier: "light" | "heavy") => void;
  onVerify: () => void;
  onDelete: () => void;
}) {
  const blocker = admissionBlocker(entry);
  return (
    <tr className="border-t border-line align-top">
      <td className="py-2.5 pr-3">
        <span className="block font-data text-sm text-ink">{entry.id}</span>
        <span className="block font-data text-xs text-ink-faint">
          {defaults?.light === entry.id && "light default · "}
          {defaults?.heavy === entry.id && "heavy default · "}
          {entry.vendor}
        </span>
      </td>
      <td className="py-2.5 pr-3">
        {entry.info ? (
          <span className="font-data text-xs text-ink-muted">{entry.info.quant_label}</span>
        ) : (
          <span className="font-data text-xs text-danger">
            {entry.info_error ?? "header unreadable"}
          </span>
        )}
      </td>
      <td className="py-2.5 pr-3 font-data text-xs text-ink-muted tabular-nums">
        {formatBytes(entry.size_bytes)}
      </td>
      <td className="py-2.5 pr-3">
        <ClassBadge entry={entry} />
      </td>
      <td className="py-2.5 pr-3">
        <VerifiedBadge entry={entry} />
      </td>
      <td className="py-2.5">
        <div className="flex flex-wrap items-center justify-end gap-1.5">
          <Button size="sm" variant="ghost" disabled={busy} onClick={onLoad}>
            Load
          </Button>
          <Button
            size="sm"
            variant="ghost"
            disabled={busy || blocker !== undefined}
            title={blocker}
            onClick={() => onDefault("light")}
          >
            Set light
          </Button>
          <Button
            size="sm"
            variant="ghost"
            disabled={busy || blocker !== undefined}
            title={blocker}
            onClick={() => onDefault("heavy")}
          >
            Set heavy
          </Button>
          <Button size="sm" variant="ghost" disabled={busy} onClick={onVerify}>
            Verify
          </Button>
          <ConfirmButton
            label="Delete"
            confirmLabel="delete it?"
            busy={busy}
            onConfirm={onDelete}
          />
        </div>
      </td>
    </tr>
  );
}

function LibraryTable({
  models,
  modelsDir,
  defaults,
  pending,
  failure,
}: {
  models: ModelEntry[];
  modelsDir: string | undefined;
  defaults: ModelsStatus["defaults"] | undefined;
  pending: boolean;
  failure: BridgeFailure | null;
}) {
  const queryClient = useQueryClient();
  const [actionFailure, setActionFailure] = useState<BridgeFailure | null>(null);
  const [busyId, setBusyId] = useState<string | null>(null);

  const settle = () => {
    setBusyId(null);
    void queryClient.invalidateQueries({ queryKey: ["models"] });
  };
  const onError = (error: unknown) => setActionFailure(toBridgeFailure(error));
  const start = (id: string) => {
    setActionFailure(null);
    setBusyId(id);
  };

  const load = useMutation({
    mutationFn: (modelId: string) => modelsLoad(modelId),
    onError,
    onSettled: settle,
  });
  const verify = useMutation({
    mutationFn: (modelId: string) => modelsVerify(modelId),
    onError,
    onSettled: settle,
  });
  const remove = useMutation({
    mutationFn: (modelId: string) => modelsDelete(modelId),
    onError,
    onSettled: settle,
  });
  const setDefault = useMutation({
    mutationFn: ({ tier, modelId }: { tier: "light" | "heavy"; modelId: string }) =>
      modelsDefaultsSet(tier, modelId),
    onError,
    onSettled: settle,
  });

  return (
    <Panel ground="raised" className="space-y-4 p-5">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <p className="font-data text-xs text-ink-faint">on disk</p>
        {modelsDir && (
          <span className="truncate font-data text-xs text-ink-faint">{modelsDir}</span>
        )}
      </div>

      {failure && <FailureNote failure={failure} label="library" />}

      {!failure && models.length === 0 && !pending && (
        <p className="font-sans text-sm text-ink-muted">{EMPTY_LIBRARY_SENTENCE}</p>
      )}

      {models.length > 0 && (
        <div className="overflow-x-auto">
          <table className="w-full border-collapse">
            <thead>
              <tr className="text-left font-data text-xs text-ink-faint">
                <th className="pb-2 pr-3 font-medium">model</th>
                <th className="pb-2 pr-3 font-medium">quant</th>
                <th className="pb-2 pr-3 font-medium">size</th>
                <th className="pb-2 pr-3 font-medium">class</th>
                <th className="pb-2 pr-3 font-medium">digest</th>
                <th className="pb-2 font-medium" aria-label="actions" />
              </tr>
            </thead>
            <tbody>
              {models.map((entry) => (
                <LibraryRow
                  key={entry.id}
                  entry={entry}
                  defaults={defaults}
                  busy={busyId === entry.id}
                  onLoad={() => {
                    start(entry.id);
                    load.mutate(entry.id);
                  }}
                  onDefault={(tier) => {
                    start(entry.id);
                    setDefault.mutate({ tier, modelId: entry.id });
                  }}
                  onVerify={() => {
                    start(entry.id);
                    verify.mutate(entry.id);
                  }}
                  onDelete={() => {
                    start(entry.id);
                    remove.mutate(entry.id);
                  }}
                />
              ))}
            </tbody>
          </table>
        </div>
      )}

      {actionFailure && <FailureNote failure={actionFailure} label="library" />}
    </Panel>
  );
}

// --- 3. catalog ------------------------------------------------------------

function DownloadProgress({ job, onCancel }: { job: ModelJob; onCancel: () => void }) {
  const pct = percentOf(job.bytes_done, job.bytes_total);
  return (
    <div className="space-y-2">
      <progress
        aria-label="download progress"
        className="h-1.5 w-full accent-accent-strong"
        {...(job.bytes_total === null ? {} : { value: job.bytes_done, max: job.bytes_total })}
      />
      <div className="flex items-center gap-3">
        <span className="font-data text-xs text-ink tabular-nums">
          {pct === null ? formatBytes(job.bytes_done) : `${pct}%`}
        </span>
        <span className="font-data text-xs text-ink-faint tabular-nums">
          {formatBytes(job.bytes_done)}
          {job.bytes_total !== null && ` / ${formatBytes(job.bytes_total)}`}
        </span>
        <Button size="sm" variant="ghost" className="ml-auto" onClick={onCancel}>
          Cancel
        </Button>
      </div>
    </div>
  );
}

function PresetCard({
  preset,
  job,
  busy,
  onDownload,
  onCancel,
  onDiscard,
}: {
  preset: CatalogPreset;
  job: ModelJob | undefined;
  busy: boolean;
  onDownload: () => void;
  onCancel: () => void;
  onDiscard: () => void;
}) {
  const running = job?.state === "running" ? job : undefined;
  const failure = downloadFailure(job);
  // The catalog reports the part file directly, so a resume is offered on
  // the evidence on disk rather than on a job row that may have aged out
  // of the status window.
  const partial = running ? null : preset.partial_bytes;
  const resumable = partial !== null && partial > 0;
  return (
    <div className="space-y-3 rounded-card border border-line p-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0 space-y-0.5">
          <p className="font-data text-sm text-ink">{preset.label}</p>
          <p className="font-data text-xs text-ink-faint tabular-nums">
            {preset.quant} · {preset.params_label} · {formatBytes(preset.size_bytes)} · needs{" "}
            {formatBytes(preset.min_host_ram_bytes)} RAM
          </p>
        </div>
        {preset.installed ? (
          <span className="flex items-center gap-1.5 font-data text-xs text-success">
            <Check aria-hidden="true" className="size-4" />
            installed
          </span>
        ) : running ? null : (
          <div className="flex items-center gap-2">
            <Button size="sm" disabled={busy} onClick={onDownload}>
              {resumable ? "Resume" : "Download"}
            </Button>
            {resumable && (
              <ConfirmButton
                label="Start over"
                confirmLabel="Discard and start over?"
                busy={busy}
                onConfirm={onDiscard}
              />
            )}
          </div>
        )}
      </div>

      {running && <DownloadProgress job={running} onCancel={onCancel} />}

      {failure && <FailureNote failure={failure} label="download" />}

      {job?.state === "cancelled" && !failure && (
        <p className="font-sans text-sm text-ink-muted">You stopped this one.</p>
      )}

      {resumable && (
        <p className="font-data text-xs text-ink-muted tabular-nums">
          {formatBytes(partial)} of {formatBytes(preset.size_bytes)} already here · Resume
          continues, Start over throws those bytes away
        </p>
      )}

      <a
        href={preset.license_url}
        target="_blank"
        rel="noreferrer"
        className="inline-block font-data text-xs text-accent underline underline-offset-2"
      >
        {preset.license_id} license
      </a>
    </div>
  );
}

function CatalogPanel({ jobs }: { jobs: ModelJob[] }) {
  const queryClient = useQueryClient();
  const catalog = useQuery({ queryKey: ["models", "catalog"], queryFn: modelsCatalog });
  const [url, setUrl] = useState("");
  const [vendor, setVendor] = useState("");
  const [actionFailure, setActionFailure] = useState<BridgeFailure | null>(null);

  const settle = () => void queryClient.invalidateQueries({ queryKey: ["models"] });

  const download = useMutation({
    mutationFn: (source: { preset_id: string } | { url: string; vendor: string }) =>
      modelsDownload(source),
    onMutate: () => setActionFailure(null),
    onError: (error) => setActionFailure(toBridgeFailure(error)),
    onSettled: settle,
  });

  const cancel = useMutation({
    mutationFn: (jobId: string) => modelsDownloadCancel(jobId),
    onMutate: () => setActionFailure(null),
    onError: (error) => setActionFailure(toBridgeFailure(error)),
    onSettled: settle,
  });

  const discard = useMutation({
    mutationFn: (source: { preset_id: string }) => modelsDownloadDiscard(source),
    onMutate: () => setActionFailure(null),
    onError: (error) => setActionFailure(toBridgeFailure(error)),
    onSettled: settle,
  });

  const listFailure = catalog.isError ? toBridgeFailure(catalog.error) : null;
  // Presets this machine cannot hold are hidden, not disabled: an offer
  // that can never be taken is noise, not information.
  const presets = (catalog.data?.presets ?? []).filter((preset) => preset.fits_host);

  const inputClasses =
    "h-8 w-full rounded-control field-control border border-control-line bg-inset px-2.5 font-data text-xs text-ink placeholder:text-ink-faint";

  return (
    <Panel ground="raised" className="space-y-4 p-5">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <p className="font-data text-xs text-ink-faint">curated presets</p>
        {catalog.data && (
          <span className="font-data text-xs text-ink-faint tabular-nums">
            host RAM {formatBytes(catalog.data.host_ram_bytes)}
          </span>
        )}
      </div>

      {listFailure && <FailureNote failure={listFailure} label="catalog" />}

      {!listFailure && presets.length === 0 && !catalog.isPending && (
        <p className="font-sans text-sm text-ink-muted">
          Nothing in the catalog fits this machine's memory. The paste-URL box below still
          works, honestly labelled.
        </p>
      )}

      <div className="space-y-3">
        {presets.map((preset) => (
          <PresetCard
            key={preset.id}
            preset={preset}
            job={latestDownload(jobs, presetModelId(preset))}
            busy={download.isPending || discard.isPending}
            onDownload={() => download.mutate({ preset_id: preset.id })}
            onCancel={() => {
              const job = runningDownload(jobs, presetModelId(preset));
              if (job) cancel.mutate(job.id);
            }}
            onDiscard={() => discard.mutate({ preset_id: preset.id })}
          />
        ))}
      </div>

      <form
        className="space-y-2 border-t border-line pt-4"
        onSubmit={(event) => {
          event.preventDefault();
          const trimmedUrl = url.trim();
          const trimmedVendor = vendor.trim();
          if (trimmedUrl && trimmedVendor) {
            download.mutate({ url: trimmedUrl, vendor: trimmedVendor });
          }
        }}
      >
        <p className="font-data text-xs text-ink-faint">paste a URL</p>
        <div className="flex flex-wrap items-end gap-2">
          <label className="min-w-64 flex-1 space-y-1">
            <span className="block font-data text-xs text-ink-faint">gguf url</span>
            <input
              aria-label="gguf url"
              value={url}
              onChange={(event) => setUrl(event.target.value)}
              placeholder="https://…/model.gguf"
              className={inputClasses}
            />
          </label>
          <label className="w-40 space-y-1">
            <span className="block font-data text-xs text-ink-faint">vendor</span>
            <input
              aria-label="vendor"
              value={vendor}
              onChange={(event) => setVendor(event.target.value)}
              placeholder="qwen"
              className={inputClasses}
            />
          </label>
          <Button
            size="sm"
            type="submit"
            disabled={download.isPending || !url.trim() || !vendor.trim()}
          >
            Fetch
          </Button>
        </div>
        <p className="font-sans text-sm text-ink-muted">
          A pasted file arrives with no expected digest, so it stays unverified until you run
          Verify and I know its hash. {FLOOR_NOTE}
        </p>
      </form>

      {actionFailure && <FailureNote failure={actionFailure} label="catalog" />}
    </Panel>
  );
}

// --- 4. try box ------------------------------------------------------------

function TryBox({ status }: { status: ModelsStatus | undefined }) {
  const [prompt, setPrompt] = useState("");
  const [maxTokens, setMaxTokens] = useState(String(TRY_DEFAULT_MAX_TOKENS));
  const [result, setResult] = useState<GenerateResult | null>(null);
  const [failure, setFailure] = useState<BridgeFailure | null>(null);

  const run = useMutation({
    mutationFn: async ({
      modelId,
      text,
      budget,
    }: {
      modelId: string;
      text: string;
      budget: number;
    }) => {
      const reply = await modelsTry(modelId, text, budget);
      if (reply.model?.id !== modelId)
        throw {
          cause: "model_mismatch",
          detail: "The worker did not confirm the requested model identity",
          recovery: "Refresh model status and try again.",
        };
      return reply;
    },
    onMutate: () => {
      setFailure(null);
      setResult(null);
    },
    onSuccess: (reply) => setResult(reply),
    onError: (error) => setFailure(toBridgeFailure(error)),
  });

  const modelId = status?.runtime.state.state === "loaded" ? status.runtime.state.id : null;
  const closed = !modelId || status?.runtime.busy === true;

  return (
    <Panel ground="raised" className="space-y-4 p-5">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <p className="font-data text-xs text-ink-faint">one prompt</p>
        {closed && (
          <span className="font-data text-xs text-ink-faint">{TRY_DISABLED_REASON}</span>
        )}
      </div>

      <textarea
        aria-label="prompt"
        rows={3}
        value={prompt}
        disabled={closed}
        onChange={(event) => setPrompt(event.target.value)}
        placeholder="Say hello in five words."
        className="w-full rounded-control field-control border border-control-line bg-inset p-2.5 font-data text-xs text-ink placeholder:text-ink-faint disabled:cursor-not-allowed disabled:opacity-50"
      />

      <div className="flex flex-wrap items-end gap-2">
        <label className="w-32 space-y-1">
          <span className="block font-data text-xs text-ink-faint">max tokens</span>
          <input
            type="number"
            min={1}
            aria-label="max tokens"
            value={maxTokens}
            disabled={closed}
            onChange={(event) => setMaxTokens(event.target.value)}
            className="h-8 w-full rounded-control field-control border border-control-line bg-inset px-2.5 font-data text-xs text-ink disabled:cursor-not-allowed disabled:opacity-50"
          />
        </label>
        <Button
          size="sm"
          disabled={closed || run.isPending || !prompt.trim()}
          onClick={() =>
            modelId &&
            run.mutate({
              modelId,
              text: prompt.trim(),
              budget: Number(maxTokens) || TRY_DEFAULT_MAX_TOKENS,
            })
          }
        >
          {run.isPending && (
            <LoaderCircle aria-hidden="true" className="size-3.5 animate-spin" />
          )}
          Run
        </Button>
        <span className="font-sans text-sm text-ink-muted">
          Diagnostics, not a chat — this one runs on test-only weights too.
        </span>
      </div>

      {result && (
        <div className="space-y-2">
          <p className="rounded-card border border-line bg-chrome p-3 font-data text-sm whitespace-pre-wrap text-ink">
            {result.text}
          </p>
          <p className="font-data text-xs text-ink-faint tabular-nums">
            {result.model.id} · {result.model.quant} · {result.model.device} · diagnostic only ·{" "}
            {result.prompt_tokens} prompt · {result.completion_tokens} completion ·{" "}
            <span className="text-ink">{result.tokens_per_sec.toFixed(1)} tokens/sec</span>
          </p>
        </div>
      )}

      {failure && <FailureNote failure={failure} label="try" />}
    </Panel>
  );
}

// --- the screen ------------------------------------------------------------

const MODEL_TABS = [
  { id: "runtime", label: "Runtime" },
  { id: "library", label: "Installed" },
  { id: "catalog", label: "Downloads" },
  { id: "test", label: "Test model" },
] as const;

export function ModelsScreen() {
  const [tab, setTab] = useState<(typeof MODEL_TABS)[number]["id"]>("runtime");
  const status = useQuery({
    queryKey: ["models", "status"],
    queryFn: modelsStatus,
    refetchInterval: (query) => pollInterval(query.state.data),
  });
  const library = useQuery({ queryKey: ["models", "list"], queryFn: modelsList });
  const queryClient = useQueryClient();

  // A verify or download answers with a job id and finishes later; the
  // library only changes when that job settles. Re-read it whenever the
  // set of running jobs changes, so a fresh digest badge or a newly
  // installed file appears without leaving the screen.
  const runningJobs = (status.data?.jobs ?? [])
    .filter((job) => job.state === "running")
    .map((job) => job.id)
    .join(",");
  useEffect(() => {
    void queryClient.invalidateQueries({ queryKey: ["models", "list"] });
  }, [runningJobs, queryClient]);

  const statusFailure = status.isError ? toBridgeFailure(status.error) : null;
  const libraryFailure = library.isError ? toBridgeFailure(library.error) : null;
  const models = library.data?.models ?? [];
  const jobs = status.data?.jobs ?? [];

  return (
    <div className="page-workspace">
      <PageHeader>
        <h1 className="font-sans text-title font-semibold text-ink">Models</h1>
        <p className="text-sm text-ink-muted">Local models, runtime and downloads.</p>
      </PageHeader>

      <PageTabs
        id="models"
        label="Model tasks"
        tabs={MODEL_TABS}
        selected={tab}
        onSelect={setTab}
      />
      <PagePane id="models" tab="runtime" active={tab === "runtime"}>
        <Section
          eyebrow="runtime"
          eyebrowExtra={<Badge tone="accent">GUI-only</Badge>}
          title="Runtime"
          blurb="Load or unload a model and see what is in memory."
        >
          <RuntimeCard status={status.data} models={models} failure={statusFailure} />
        </Section>
      </PagePane>
      <PagePane id="models" tab="library" active={tab === "library"}>
        <Section
          eyebrow="library"
          title="Installed models"
          blurb="Every set of weights on disk, with what I know about each one."
        >
          <LibraryTable
            models={models}
            modelsDir={library.data?.models_dir ?? status.data?.models_dir}
            defaults={status.data?.defaults}
            pending={library.isPending}
            failure={libraryFailure}
          />
        </Section>
      </PagePane>
      <PagePane id="models" tab="catalog" active={tab === "catalog"}>
        <Section
          eyebrow="catalog"
          title="Downloads"
          blurb="The models I know how to fetch and verify — only the ones this machine can hold."
        >
          <CatalogPanel jobs={jobs} />
          <EngineCard />
        </Section>
      </PagePane>
      <PagePane id="models" tab="test" active={tab === "test"}>
        <Section
          eyebrow="diagnostics"
          title="Test model"
          blurb="One prompt against whatever is loaded, so you can see it answer before trusting it with a job."
        >
          <TryBox status={status.data} />
        </Section>
      </PagePane>
    </div>
  );
}
