import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { LoaderCircle } from "lucide-react";
import { useEffect, useState } from "react";
import { Badge } from "../components/ui/Badge";
import { Button } from "../components/ui/Button";
import { FailureNote } from "../components/ui/FailureNote";
import { Panel } from "../components/ui/Panel";
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
} from "../lib/ipc";
import { FLOOR_SENTENCE } from "./Models";

/**
 * Settings → Models: the persistent choices, as opposed to the live
 * machinery on `/models`. Three panels — which weights answer which job
 * tier, which vendor agent CLI PAM borrows as its curator, and where the
 * weights live plus how long they stay resident.
 *
 * The engine floor is enforced twice on purpose: the daemon refuses a
 * `test_only` model as a tier default with cause `below_floor`, and the
 * select here renders those options disabled with the reason in the
 * label — so the human never has to earn the refusal to learn the rule.
 */

/** The tiers a job can ask for; `heavy` falls back to `light`, then none. */
const TIERS = ["light", "heavy"] as const;

type Tier = (typeof TIERS)[number];

/** What each tier is for, in one serif sentence. */
const TIER_SENTENCES: Record<Tier, string> = {
  light: "Classification and short answers — the quick reads.",
  heavy: "Summaries and briefs; when this one is empty I fall back to light.",
};

/** Every agent CLI PAM knows how to invoke, in detection order. */
export const CURATOR_AGENTS: readonly AgentId[] = ["claude", "codex", "copilot", "gemini"];

// --- tier defaults ---------------------------------------------------------

function TierSelect({
  tier,
  value,
  models,
  disabled,
  onChange,
}: {
  tier: Tier;
  value: string | null;
  models: ModelEntry[];
  disabled: boolean;
  onChange: (modelId: string | null) => void;
}) {
  return (
    <label className="space-y-1.5">
      <span className="block font-data text-xs tracking-widest text-ink-faint uppercase">
        {tier}
      </span>
      <select
        aria-label={`${tier} tier default`}
        value={value ?? ""}
        disabled={disabled}
        onChange={(event) => onChange(event.target.value === "" ? null : event.target.value)}
        className="h-8 w-full rounded-control border border-line bg-surface px-2 font-data text-xs text-ink disabled:cursor-not-allowed disabled:opacity-50"
      >
        <option value="">none (deterministic)</option>
        {models.map((model) => (
          <option
            key={model.id}
            value={model.id}
            disabled={model.class === "test_only"}
            title={model.class === "test_only" ? FLOOR_SENTENCE : undefined}
          >
            {model.class === "test_only" ? `${model.id} — ${FLOOR_SENTENCE}` : model.id}
          </option>
        ))}
      </select>
      <span className="block font-voice text-sm text-ink-muted italic">
        {TIER_SENTENCES[tier]}
      </span>
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
    <Panel ground="raised" className="space-y-4 p-5">
      <div className="flex items-center justify-between gap-3">
        <p className="font-data text-xs tracking-widest text-ink-faint uppercase">
          tier defaults
        </p>
        <Badge tone="accent">GUI-only</Badge>
      </div>

      {listFailure && <FailureNote failure={listFailure} label="models" />}

      {!listFailure && models.length === 0 && !library.isPending && (
        <p className="font-voice text-sm text-ink-muted italic">
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
            onChange={(modelId) => setDefault.mutate({ tier, modelId })}
          />
        ))}
      </div>

      {failure && <FailureNote failure={failure} label="defaults" />}
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
    <Panel ground="raised" className="space-y-4 p-5">
      <p className="font-data text-xs tracking-widest text-ink-faint uppercase">
        curator agent
      </p>
      <p className="font-voice text-sm text-ink-muted italic">
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
                  className="mt-1 size-3.5 accent-accent-strong"
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
              className="size-3.5 accent-accent-strong"
            />
            <span className="font-data text-sm text-ink-muted">none</span>
          </label>
        </div>
      )}

      <div className="flex flex-wrap items-center gap-3 border-t border-line pt-4">
        <Button
          size="sm"
          variant="ghost"
          disabled={selected === null || test.isPending}
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

  // The daemon owns both values; the inputs are drafts that start from
  // what it reports and only diverge once the human types.
  const liveDir = status.data?.models_dir;
  const liveMinutes = status.data?.idle_unload_min;
  useEffect(() => {
    if (liveDir !== undefined) setDir(liveDir);
  }, [liveDir]);
  useEffect(() => {
    if (liveMinutes !== undefined) setMinutes(String(liveMinutes));
  }, [liveMinutes]);

  const apply = useMutation({
    mutationFn: (patch: { models_dir?: string; idle_unload_min?: number }) =>
      modelsSettingsSet(patch),
    onMutate: () => {
      setFailure(null);
      setNote(null);
    },
    onSuccess: () => setNote("saved"),
    onError: (error) => setFailure(toBridgeFailure(error)),
    onSettled: () => void queryClient.invalidateQueries({ queryKey: ["models"] }),
  });

  const inputClasses =
    "h-8 w-full rounded-control border border-line bg-surface px-2.5 font-data text-xs text-ink placeholder:text-ink-faint";

  return (
    <Panel ground="raised" className="space-y-4 p-5">
      <p className="font-data text-xs tracking-widest text-ink-faint uppercase">
        storage &amp; residency
      </p>

      <form
        className="flex flex-wrap items-end gap-2"
        onSubmit={(event) => {
          event.preventDefault();
          const next = dir.trim();
          if (next) apply.mutate({ models_dir: next });
        }}
      >
        <label className="min-w-64 flex-1 space-y-1">
          <span className="block font-data text-xs text-ink-faint">models directory</span>
          <input
            aria-label="models directory"
            value={dir}
            onChange={(event) => setDir(event.target.value)}
            placeholder="~/llm"
            className={inputClasses}
          />
        </label>
        <Button size="sm" type="submit" disabled={apply.isPending || !dir.trim()}>
          Apply
        </Button>
      </form>

      <form
        className="flex flex-wrap items-end gap-2 border-t border-line pt-4"
        onSubmit={(event) => {
          event.preventDefault();
          const parsed = Number(minutes);
          if (Number.isInteger(parsed) && parsed >= 0) {
            apply.mutate({ idle_unload_min: parsed });
          }
        }}
      >
        <label className="w-40 space-y-1">
          <span className="block font-data text-xs text-ink-faint">idle unload (minutes)</span>
          <input
            type="number"
            min={0}
            aria-label="idle unload minutes"
            value={minutes}
            onChange={(event) => setMinutes(event.target.value)}
            className={inputClasses}
          />
        </label>
        <Button size="sm" type="submit" variant="ghost" disabled={apply.isPending}>
          Apply
        </Button>
        <span className="font-voice text-sm text-ink-muted italic">
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
    <div className="space-y-4">
      <TierDefaultsPanel />
      <CuratorPanel />
      <StoragePanel />
    </div>
  );
}
