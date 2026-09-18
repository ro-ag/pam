import { SelectField, TextField } from "../components/ui/Fields";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { LoaderCircle } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { Button } from "../components/ui/Button";
import { FailureNote } from "../components/ui/FailureNote";
import { fieldClasses, fieldLabelClasses } from "../components/ui/field";
import { Panel } from "../components/ui/Panel";
import { useRephrasePref } from "../lib/ask/prefs";
import { cn } from "../lib/cn";
import {
  curatorList,
  curatorSet,
  curatorTest,
  modelsDefaultsSet,
  modelsList,
  modelsSettingsSet,
  modelsStatus,
  toBridgeFailure,
  type AgentId,
  type BridgeFailure,
  type ModelEntry,
  type TierReadiness,
} from "../lib/ipc";
import { admissionBlocker } from "./Models";
import { ReadinessLine } from "./Readiness";

/**
 * Settings → Models: the persistent choices, as opposed to the live
 * machinery on `/models`. Three panels — which weights answer which job
 * tier, which vendor agent CLI PAM borrows as its curator, and where the
 * weights live plus how long they stay resident.
 *
 * Admission is enforced twice on purpose: the daemon refuses a `test_only`
 * model as a tier default with cause `unverified` and a verified-but-unmeasured
 * one with cause `unqualified`, and the select here renders those options
 * disabled with the reason in the label — so the human never has to earn the
 * refusal to learn the rule.
 */

/** The tiers a job can ask for; `heavy` falls back to `light`, then none. */
const TIERS = ["light", "heavy"] as const;

type Tier = (typeof TIERS)[number];

/** What each tier is for, in one serif sentence. */
const TIER_SENTENCES: Record<Tier, string> = {
  light: "Classification and short answers — the quick reads.",
  heavy: "Summaries and briefs; falls back to light when this one is empty.",
};

/** Every agent CLI PAM knows how to invoke, in detection order. */
export const CURATOR_AGENTS: readonly AgentId[] = ["claude", "codex", "copilot", "gemini"];

// --- tier defaults ---------------------------------------------------------

function TierSelect({
  tier,
  value,
  models,
  disabled,
  readiness,
  idleUnloadMin,
  onChange,
}: {
  tier: Tier;
  value: string | null;
  models: ModelEntry[];
  disabled: boolean;
  readiness: TierReadiness | undefined;
  idleUnloadMin: number;
  onChange: (modelId: string | null) => void;
}) {
  return (
    <label className="space-y-1.5">
      <span className={fieldLabelClasses}>{tier === "light" ? "Light" : "Heavy"}</span>
      <SelectField
        aria-label={`${tier} tier default`}
        value={value ?? ""}
        disabled={disabled}
        onChange={(event) => onChange(event.target.value === "" ? null : event.target.value)}
        className={cn(fieldClasses, "px-2 disabled:cursor-not-allowed disabled:opacity-70")}
      >
        <option value="">none (deterministic)</option>
        {models.map((model) => {
          const blocker = admissionBlocker(model);
          return (
            <option
              key={model.id}
              value={model.id}
              disabled={blocker !== undefined}
              title={blocker}
            >
              {blocker === undefined ? model.id : `${model.id} — ${blocker}`}
            </option>
          );
        })}
      </SelectField>
      <span className="block font-sans text-sm text-ink-muted">{TIER_SENTENCES[tier]}</span>
      <ReadinessLine readiness={readiness} idleUnloadMin={idleUnloadMin} />
    </label>
  );
}

function TierDefaultsPanel() {
  const queryClient = useQueryClient();
  const status = useQuery({ queryKey: ["models", "status"], queryFn: modelsStatus });
  const library = useQuery({ queryKey: ["models", "list"], queryFn: modelsList });
  const [failure, setFailure] = useState<BridgeFailure | null>(null);

  const setDefault = useMutation({
    mutationFn: ({ tier, modelId }: { tier: Tier; modelId: string | null }) =>
      modelsDefaultsSet(tier, modelId),
    onMutate: () => setFailure(null),
    onError: (error) => setFailure(toBridgeFailure(error)),
    onSettled: () => void queryClient.invalidateQueries({ queryKey: ["models"] }),
  });

  const models = library.data?.models ?? [];
  const defaults = status.data?.defaults;
  const listFailure = library.isError
    ? toBridgeFailure(library.error)
    : status.isError
      ? toBridgeFailure(status.error)
      : null;

  return (
    <Panel ground="raised" className="space-y-4 p-4">
      <p className="font-data text-xs text-ink-faint">Tier defaults</p>

      {listFailure && <FailureNote failure={listFailure} label="models" />}

      {!listFailure && models.length === 0 && !library.isPending && (
        <p className="font-sans text-sm text-ink-muted">
          Nothing installed to point a tier at yet. Every job takes the deterministic path until
          weights exist.
        </p>
      )}

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
        {TIERS.map((tier) => (
          <TierSelect
            key={tier}
            tier={tier}
            value={defaults?.[tier] ?? null}
            models={models}
            disabled={setDefault.isPending || listFailure !== null}
            readiness={status.data?.readiness?.[tier]}
            idleUnloadMin={status.data?.idle_unload_min ?? 0}
            onChange={(modelId) => setDefault.mutate({ tier, modelId })}
          />
        ))}
      </div>

      {failure && <FailureNote failure={failure} label="defaults" />}
    </Panel>
  );
}

// --- ask pam ---------------------------------------------------------------

/**
 * The one model knob that is not the daemon's: whether Ask Pam may hand
 * her finished sentence to the light model for a softer wording. It sits
 * with the other model choices because that is where a human looks for
 * it, but it never leaves the GUI — `localStorage`, like the theme.
 */
function AskPamPanel() {
  const [rephrase, setRephrase] = useRephrasePref();

  return (
    <Panel ground="raised" className="space-y-4 p-4">
      <p className="font-data text-xs text-ink-faint">Ask Pam · local preference</p>

      <div className="flex items-center justify-between gap-3">
        <span className="font-sans text-sm text-ink">
          Rephrase answers with the light model
        </span>
        <Button
          size="sm"
          variant={rephrase ? "primary" : "secondary"}
          role="switch"
          aria-checked={rephrase}
          aria-label="rephrase answers with the light model"
          onClick={() => setRephrase(!rephrase)}
        >
          {rephrase ? "on" : "off"}
        </Button>
      </div>

      <p className="font-sans text-sm text-ink-muted">
        {rephrase
          ? "Every number and name is kept; if the model drops one, the original sentence stands."
          : "Answers are plain sentences built from live state; turn this on to let the light model soften them."}
      </p>
    </Panel>
  );
}

// --- curator ---------------------------------------------------------------

function CuratorPanel() {
  const queryClient = useQueryClient();
  const curator = useQuery({ queryKey: ["curator"], queryFn: curatorList });
  const [result, setResult] = useState<{ reply: string; ms: number } | null>(null);
  const [failure, setFailure] = useState<BridgeFailure | null>(null);

  const pick = useMutation({
    mutationFn: (agent: AgentId | null) => curatorSet(agent),
    onMutate: () => {
      setFailure(null);
      setResult(null);
    },
    onError: (error) => setFailure(toBridgeFailure(error)),
    onSettled: () => void queryClient.invalidateQueries({ queryKey: ["curator"] }),
  });

  const test = useMutation({
    mutationFn: () => curatorTest(),
    onMutate: () => {
      setFailure(null);
      setResult(null);
    },
    onSuccess: (reply) => setResult(reply),
    onError: (error) => setFailure(toBridgeFailure(error)),
  });

  const detected = curator.data?.detected ?? [];
  const selected = curator.data?.selected ?? null;
  const listFailure = curator.isError ? toBridgeFailure(curator.error) : null;

  return (
    <Panel ground="raised" className="space-y-4 p-4">
      <p className="font-data text-xs text-ink-faint">Curator agent</p>
      <p className="font-sans text-sm text-ink-muted">
        A vendor CLI you already pay for, asked one question at a time. PAM holds no API keys —
        it rides your own subscription, or nothing.
      </p>

      {listFailure && <FailureNote failure={listFailure} label="curator" />}

      {!listFailure && detected.length === 0 && !curator.isPending && (
        <p className="font-data text-xs text-ink-muted">
          None found on the daemon&apos;s PATH. PAM looks for {CURATOR_AGENTS.join(", ")}.
        </p>
      )}

      {detected.length > 0 && (
        <div role="radiogroup" aria-label="curator agent" className="space-y-2">
          {detected.map((cli) => {
            const active = selected === cli.id;
            return (
              <label
                key={cli.id}
                className={cn(
                  "flex cursor-pointer items-start gap-3 rounded-card border p-3 transition-colors duration-150",
                  active ? "border-accent-strong bg-accent-soft/40" : "border-line",
                )}
              >
                <input
                  type="radio"
                  name="curator-agent"
                  value={cli.id}
                  checked={active}
                  disabled={pick.isPending}
                  onChange={() => pick.mutate(cli.id)}
                  className="mt-0.5 size-4.5 shrink-0 accent-accent-strong"
                />
                <span className="min-w-0 space-y-0.5">
                  <span className="block font-data text-sm font-medium text-ink">{cli.id}</span>
                  <span className="block truncate font-data text-xs text-ink-faint">
                    {cli.version ?? "version unknown"} · {cli.path}
                  </span>
                </span>
              </label>
            );
          })}
          <label
            className={cn(
              "flex cursor-pointer items-center gap-3 rounded-card border p-3 transition-colors duration-150",
              selected === null ? "border-accent-strong bg-accent-soft/40" : "border-line",
            )}
          >
            <input
              type="radio"
              name="curator-agent"
              value=""
              checked={selected === null}
              disabled={pick.isPending}
              onChange={() => pick.mutate(null)}
              className="size-4.5 shrink-0 accent-accent-strong"
            />
            <span className="font-data text-sm text-ink-muted">none</span>
          </label>
        </div>
      )}

      <div className="flex flex-wrap items-center gap-3 border-t border-line pt-4">
        <Button
          size="sm"
          variant="secondary"
          disabled={selected === null || test.isPending}
          title={selected === null ? "Pick a curator agent first" : undefined}
          onClick={() => test.mutate()}
        >
          {test.isPending && (
            <LoaderCircle aria-hidden="true" className="size-3.5 animate-spin" />
          )}
          Test
        </Button>
        <span className="font-data text-xs text-ink-faint">
          asks it to reply with the single word OK
        </span>
      </div>

      {result && (
        <div className="space-y-1 rounded-card border border-line bg-chrome p-3">
          <p className="font-data text-xs text-ink-faint">
            answered in <span className="text-ink tabular-nums">{result.ms} ms</span>
          </p>
          <p className="font-data text-sm break-words text-ink">{result.reply}</p>
        </div>
      )}

      {failure && <FailureNote failure={failure} label="curator" />}
    </Panel>
  );
}

// --- models directory + idle unload ---------------------------------------

function StoragePanel() {
  const queryClient = useQueryClient();
  const status = useQuery({ queryKey: ["models", "status"], queryFn: modelsStatus });
  const [dir, setDir] = useState("");
  const [minutes, setMinutes] = useState("");
  const [failure, setFailure] = useState<BridgeFailure | null>(null);
  const [note, setNote] = useState<string | null>(null);
  const saving = useRef(false);
  const dirtyDir = useRef(false);
  const dirtyMinutes = useRef(false);

  // The daemon owns both values; the inputs are drafts that start from
  // what it reports and only diverge once the human types.
  const liveDir = status.data?.models_dir;
  const liveMinutes = status.data?.idle_unload_min;
  useEffect(() => {
    if (!dirtyDir.current && liveDir !== undefined) setDir(liveDir);
  }, [liveDir]);
  useEffect(() => {
    if (!dirtyMinutes.current && liveMinutes !== undefined) setMinutes(String(liveMinutes));
  }, [liveMinutes]);

  const apply = useMutation({
    mutationFn: (patch: { models_dir?: string; idle_unload_min?: number }) =>
      modelsSettingsSet(patch),
    onMutate: () => {
      setFailure(null);
      setNote(null);
    },
    onSuccess: (next, patch) => {
      if (patch.models_dir !== undefined) {
        dirtyDir.current = false;
        setDir(next.models_dir);
      }
      if (patch.idle_unload_min !== undefined) {
        dirtyMinutes.current = false;
        setMinutes(String(next.idle_unload_min));
      }
      setNote("saved");
    },
    onError: (error) => setFailure(toBridgeFailure(error)),
    onSettled: async () => {
      try {
        await queryClient.invalidateQueries({ queryKey: ["models"] });
      } finally {
        saving.current = false;
      }
    },
  });

  const busy = !status.isSuccess || status.isFetching || apply.isPending;
  const validMinutes =
    minutes.trim() !== "" && Number.isSafeInteger(Number(minutes)) && Number(minutes) >= 0;
  function change(patch: { models_dir?: string; idle_unload_min?: number }) {
    const current = queryClient.getQueryState(["models", "status"]);
    if (
      saving.current ||
      busy ||
      current?.status !== "success" ||
      current.fetchStatus !== "idle"
    )
      return;
    saving.current = true;
    apply.mutate(patch);
  }

  const inputClasses = fieldClasses;

  return (
    <Panel ground="raised" className="space-y-4 p-4">
      <p className="font-data text-xs text-ink-faint">Storage and residency</p>
      {status.isError && (
        <FailureNote failure={toBridgeFailure(status.error)} label="model settings" />
      )}

      <form
        className="flex flex-wrap items-end gap-2"
        onSubmit={(event) => {
          event.preventDefault();
          const next = dir.trim();
          if (next) change({ models_dir: next });
        }}
      >
        <label className="min-w-0 flex-1 space-y-1">
          <span className={fieldLabelClasses}>Models directory</span>
          <TextField
            aria-label="models directory"
            value={dir}
            disabled={busy}
            onChange={(event) => {
              if (busy || saving.current) return;
              dirtyDir.current = true;
              setDir(event.target.value);
            }}
            placeholder="~/llm"
            className={inputClasses}
          />
        </label>
        <Button
          size="sm"
          type="submit"
          variant="secondary"
          disabled={busy || !dir.trim()}
          title={!dir.trim() ? "Name a directory first" : undefined}
        >
          Apply
        </Button>
      </form>

      <form
        className="flex flex-wrap items-end gap-2 border-t border-line pt-4"
        onSubmit={(event) => {
          event.preventDefault();
          if (validMinutes) change({ idle_unload_min: Number(minutes) });
        }}
      >
        <label className="w-40 space-y-1">
          <span className={fieldLabelClasses}>Idle unload (minutes)</span>
          <TextField
            type="number"
            min={0}
            aria-label="idle unload minutes"
            value={minutes}
            disabled={busy}
            onChange={(event) => {
              if (busy || saving.current) return;
              dirtyMinutes.current = true;
              setMinutes(event.target.value);
            }}
            className={inputClasses}
          />
        </label>
        <Button
          size="sm"
          type="submit"
          variant="secondary"
          disabled={busy || !validMinutes}
          title={!validMinutes ? "Whole minutes, 0 or more" : undefined}
        >
          Apply
        </Button>
        <span className="font-sans text-sm text-ink-muted">
          0 keeps the weights resident until you unload them yourself.
        </span>
      </form>

      {note && <p className="font-data text-xs text-ink-muted">{note}</p>}
      {failure && <FailureNote failure={failure} label="models" />}
    </Panel>
  );
}

// --- the section -----------------------------------------------------------

/** The Models block Settings mounts between Security and Daemon. */
export function SettingsModelsSection() {
  return (
    <div className="settings-grid settings-models">
      <TierDefaultsPanel />
      <AskPamPanel />
      <CuratorPanel />
      <StoragePanel />
    </div>
  );
}
