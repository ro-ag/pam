import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { X } from "lucide-react";
import { LandingSettings } from "./LandingSettings";
import { useRef, useState } from "react";
import { Button } from "../components/ui/Button";
import { FailureNote } from "../components/ui/FailureNote";
import { fieldClasses, fieldLabelClasses } from "../components/ui/field";
import { Panel } from "../components/ui/Panel";
import { cn } from "../lib/cn";
import {
  flowsSettingsGet,
  flowsSettingsSet,
  toBridgeFailure,
  type BridgeFailure,
  type FlowSettings,
  type FlowScopePolicy,
  type FlowConnectorScope,
} from "../lib/ipc";

/**
 * Settings → Flows: the two lists that decide what a flow step is even
 * allowed to reach.
 *
 * The allowlist is the whole safety story of a command step: a flow may
 * name any program it likes, and pam runs only the ones on this list.
 * The daemon refuses a shell here (`program_not_allowed`) — a shell is
 * not one program, it is every program — and that refusal renders as it
 * arrives, so the human learns the rule from pam rather than from a
 * silent failure at step time.
 *
 * Extra PATH is the boring other half: the directories a GUI-launched
 * daemon cannot see because it never inherited a login shell's PATH.
 */

/** The list fields grow with the row instead of spanning it. */
const rowFieldClasses = cn(fieldClasses, "w-auto min-w-40 flex-1");

/** One removable chip: the value in the data voice, and a 24px way out. */
function ListChip({
  value,
  label,
  onRemove,
  disabled,
}: {
  value: string;
  label: string;
  onRemove: () => void;
  disabled: boolean;
}) {
  return (
    <span className="inline-flex items-center gap-1 rounded-badge border border-line-strong bg-surface py-0.5 pr-0.5 pl-2.5 font-data text-xs text-ink-muted">
      {value}
      <button
        type="button"
        aria-label={`${label} ${value}`}
        disabled={disabled}
        onClick={() => {
          if (!disabled) onRemove();
        }}
        className="flex size-6 items-center justify-center rounded-badge text-ink-muted transition-colors duration-150 enabled:hover:bg-danger-soft enabled:hover:text-danger disabled:cursor-not-allowed disabled:opacity-70"
      >
        <X aria-hidden="true" className="size-3.5" />
      </button>
    </span>
  );
}

/** One editable list: the chips it holds, and the field that grows it. */
function ListEditor({
  title,
  values,
  addLabel,
  removeLabel,
  placeholder,
  empty,
  busy,
  onChange,
}: {
  title: string;
  values: string[];
  addLabel: string;
  removeLabel: string;
  placeholder: string;
  empty: string;
  busy: boolean;
  onChange: (next: string[]) => boolean;
}) {
  const [draft, setDraft] = useState("");
  return (
    <div className="space-y-3">
      <p className="font-data text-xs text-ink-faint">{title}</p>
      {values.length === 0 ? (
        <p className="font-sans text-sm text-ink-muted">{empty}</p>
      ) : (
        <div className="flex flex-wrap gap-2">
          {values.map((value) => (
            <ListChip
              key={value}
              value={value}
              label={removeLabel}
              disabled={busy}
              onRemove={() => onChange(values.filter((kept) => kept !== value))}
            />
          ))}
        </div>
      )}
      <form
        className="flex flex-wrap items-end gap-2"
        onSubmit={(event) => {
          event.preventDefault();
          const value = draft.trim();
          if (busy || !value) return;
          if (onChange(values.includes(value) ? values : [...values, value])) setDraft("");
        }}
      >
        <label className="min-w-40 flex-1 space-y-1">
          <span className={fieldLabelClasses}>{addLabel}</span>
          <input
            aria-label={addLabel}
            value={draft}
            disabled={busy}
            onChange={(event) => {
              if (!busy) setDraft(event.target.value);
            }}
            placeholder={placeholder}
            className={fieldClasses}
          />
        </label>
        <Button
          size="sm"
          type="submit"
          disabled={busy || !draft.trim()}
          title={!draft.trim() ? "Type a value first" : undefined}
        >
          Add
        </Button>
      </form>
    </div>
  );
}

/**
 * The one directory a build tool may write: an absolute path (or `~/…`)
 * outside every repository, created private by the daemon. Saving sends
 * the trimmed path; clearing sends an explicit `null`, which is how the
 * daemon spells "no directory" — an omitted key leaves it untouched.
 */
function DirectoryEditor({
  value,
  busy,
  onSave,
}: {
  value: string | null;
  busy: boolean;
  onSave: (next: string | null) => boolean;
}) {
  const [draft, setDraft] = useState<string | null>(null);
  const shown = draft ?? value ?? "";
  return (
    <div className="space-y-3">
      <p className="font-data text-xs text-ink-faint">Build output directory</p>
      {value ? (
        <p className="font-sans text-sm text-ink-muted">
          Read-only build steps write their cargo home, target and caches under this private
          directory, one tree per repository.
        </p>
      ) : (
        <p className="font-sans text-sm text-ink-muted">
          No build output directory — cargo and npm steps refuse until one is named. Choose a
          private directory outside every repository.
        </p>
      )}
      <form
        className="flex flex-wrap items-end gap-2"
        onSubmit={(event) => {
          event.preventDefault();
          const next = shown.trim();
          if (busy || !next || next === value) return;
          if (onSave(next)) setDraft(null);
        }}
      >
        <label className="min-w-40 flex-1 space-y-1">
          <span className={fieldLabelClasses}>Directory</span>
          <input
            aria-label="build output directory"
            value={shown}
            disabled={busy}
            onChange={(event) => {
              if (!busy) setDraft(event.target.value);
            }}
            placeholder="e.g. ~/pam-builds"
            className={fieldClasses}
          />
        </label>
        <Button
          size="sm"
          type="submit"
          disabled={busy || !shown.trim() || shown.trim() === value}
          title={
            !shown.trim()
              ? "Name a directory first"
              : shown.trim() === value
                ? "Already saved"
                : undefined
          }
        >
          Save directory
        </Button>
        <Button
          size="sm"
          type="button"
          variant="secondary"
          disabled={busy || !value}
          title={!value ? "No directory is set" : undefined}
          onClick={() => {
            if (!busy && value && onSave(null)) setDraft(null);
          }}
        >
          Clear directory
        </Button>
      </form>
    </div>
  );
}

export function SettingsFlowsSection() {
  const queryClient = useQueryClient();
  const settings = useQuery({ queryKey: ["flow-settings"], queryFn: flowsSettingsGet });
  const [failure, setFailure] = useState<BridgeFailure | null>(null);
  const saving = useRef(false);

  const save = useMutation({
    mutationFn: (patch: Partial<FlowSettings>) => flowsSettingsSet(patch),
    onMutate: async () => {
      setFailure(null);
      await queryClient.cancelQueries({ queryKey: ["flow-settings"] });
    },
    onSuccess: (next) => queryClient.setQueryData(["flow-settings"], next),
    onError: (error) => setFailure(toBridgeFailure(error)),
    onSettled: async () => {
      try {
        await queryClient.invalidateQueries({ queryKey: ["flow-settings"] });
      } finally {
        saving.current = false;
      }
    },
  });

  const busy = !settings.isSuccess || settings.isFetching || save.isPending;
  function change(patch: Partial<FlowSettings>, onSaved?: () => void): boolean {
    const current = queryClient.getQueryState<FlowSettings>(["flow-settings"]);
    // The ref closes the gap before React renders mutation.isPending. Reject
    // stale event closures as well as edits during a failed/pending refresh.
    if (
      saving.current ||
      busy ||
      current?.status !== "success" ||
      current.fetchStatus !== "idle" ||
      current.data !== settings.data
    )
      return false;
    saving.current = true;
    save.mutate(patch, { onSuccess: onSaved });
    return true;
  }

  const listFailure = settings.isError ? toBridgeFailure(settings.error) : null;
  const programs = settings.data?.allowed_programs ?? [];
  const extraPath = settings.data?.extra_path ?? [];
  const artifactsRoot = settings.data?.artifacts_root ?? null;
  const readCaches = settings.data?.read_cache_roots ?? [];

  return (
    <Panel ground="raised" className="space-y-4 p-4">
      {listFailure && (
        <>
          <FailureNote failure={listFailure} label="flow settings" />
          <Button
            size="sm"
            variant="secondary"
            disabled={settings.isFetching}
            onClick={() => void settings.refetch()}
          >
            Retry reading settings
          </Button>
        </>
      )}

      <ListEditor
        title="Allowed programs"
        values={programs}
        addLabel="Program to allow"
        removeLabel="remove program"
        placeholder="e.g. cargo"
        empty="No program is allowed yet, so every command step would refuse."
        busy={busy}
        onChange={(next) => change({ allowed_programs: next })}
      />

      <div className="border-t border-line pt-4">
        <ListEditor
          title="Extra PATH"
          values={extraPath}
          addLabel="Directory to add to PATH"
          removeLabel="remove directory"
          placeholder="e.g. /opt/homebrew/bin"
          empty="Nothing added — steps see only the daemon's own PATH."
          busy={busy}
          onChange={(next) => change({ extra_path: next })}
        />
      </div>

      <div className="border-t border-line pt-4">
        <DirectoryEditor
          value={artifactsRoot}
          busy={busy}
          onSave={(next) => change({ artifacts_root: next })}
        />
      </div>

      <div className="border-t border-line pt-4">
        <ListEditor
          title="Read-only caches"
          values={readCaches}
          addLabel="Cache directory to add"
          removeLabel="remove cache directory"
          placeholder="e.g. ~/.cargo/registry"
          empty="No cache is shared — every build fetches nothing, since steps have no network."
          busy={busy}
          onChange={(next) => change({ read_cache_roots: next })}
        />
      </div>

      {failure && <FailureNote failure={failure} label="flow settings" />}

      <ScopeEditor
        policy={settings.data?.scope_policy ?? EMPTY_SCOPES}
        busy={busy}
        onSave={(scope_policy, onSaved) => change({ scope_policy }, onSaved)}
      />

      <LandingSettings />

      <p className="border-t border-line pt-4 font-sans text-sm text-ink-muted">
        Commands require an allowed program and approved repository. Connector reads also
        require an approved service and target for that repository.
      </p>
    </Panel>
  );
}

const EMPTY_SCOPES: FlowScopePolicy = { version: 1, repositories: [] };
const TARGET_HELP: Record<FlowConnectorScope["connector"], string> = {
  github: "Exact owner/repository, e.g. acme/service",
  jenkins: "Exact job path, e.g. platform/nightly",
  sonarqube: "Exact Sonar project key",
  jira: "Exact Jira project KEY",
  confluence: "Exact numeric page ID",
  sharepoint: "Exact SharePoint site ID",
};

function ScopeEditor({
  policy,
  busy,
  onSave,
}: {
  policy: FlowScopePolicy;
  busy: boolean;
  onSave: (policy: FlowScopePolicy, onSaved: () => void) => boolean;
}) {
  const [draft, setDraft] = useState<{ base: string; policy: FlowScopePolicy } | null>(null);
  const [root, setRoot] = useState("");
  const current = draft?.policy ?? policy;
  const conflict = draft !== null && draft.base !== JSON.stringify(policy);
  function edit(next: FlowScopePolicy) {
    setDraft({ base: draft?.base ?? JSON.stringify(policy), policy: next });
  }
  return (
    <section
      aria-label="approved repository scopes"
      className="space-y-3 border-t border-line pt-4"
    >
      <h3 className="font-data text-xs text-ink-faint">
        Approved repositories and connector scopes
      </h3>
      <p className="text-sm text-ink-muted">
        Empty means deny. Approve each local repository and the service targets it may read.
        Repository paths and service URLs are canonicalized when saved.
      </p>
      {current.repositories.map((repository, index) => (
        <div key={repository.root} className="space-y-3 rounded-control border border-line p-3">
          <ListChip
            value={repository.root}
            label="remove repository"
            disabled={busy}
            onRemove={() =>
              edit({
                ...current,
                repositories: current.repositories.filter((_, i) => i !== index),
              })
            }
          />
          {repository.connectors.map((grant) => (
            <ListChip
              key={grant.connector}
              value={`${grant.connector} · ${grant.base_url} · ${grant.access === "connector_wide" ? "all targets and searches" : grant.targets.join(", ")}`}
              label="remove connector scope"
              disabled={busy}
              onRemove={() =>
                edit({
                  ...current,
                  repositories: current.repositories.map((item, i) =>
                    i === index
                      ? {
                          ...item,
                          connectors: item.connectors.filter(
                            (scope) => scope.connector !== grant.connector,
                          ),
                        }
                      : item,
                  ),
                })
              }
            />
          ))}
          <ConnectorScopeForm
            root={repository.root}
            busy={busy}
            existing={repository.connectors.map((grant) => grant.connector)}
            onAdd={(grant) =>
              edit({
                ...current,
                repositories: current.repositories.map((item, i) =>
                  i === index ? { ...item, connectors: [...item.connectors, grant] } : item,
                ),
              })
            }
          />
        </div>
      ))}
      <form
        className="flex flex-wrap gap-2"
        onSubmit={(event) => {
          event.preventDefault();
          const value = root.trim();
          if (busy || !value || current.repositories.some((item) => item.root === value))
            return;
          edit({
            ...current,
            repositories: [...current.repositories, { root: value, connectors: [] }],
          });
          setRoot("");
        }}
      >
        <input
          aria-label="repository root"
          className={rowFieldClasses}
          value={root}
          disabled={busy}
          placeholder="/absolute/path/to/repository"
          onChange={(event) => setRoot(event.target.value)}
        />
        <Button
          size="sm"
          type="submit"
          disabled={
            busy ||
            !root.trim() ||
            current.repositories.some((item) => item.root === root.trim())
          }
        >
          Add repository
        </Button>
      </form>
      {conflict && (
        <p role="alert" className="text-sm text-danger">
          Saved scopes changed while you were editing. Discard this draft and apply your changes
          to the latest scopes.
        </p>
      )}
      {draft && <p className="text-sm text-ink-muted">Unsaved scope changes</p>}
      <div className="flex gap-2">
        <Button
          size="sm"
          disabled={busy || !draft || conflict}
          onClick={() => onSave(current, () => setDraft(null))}
        >
          Save scopes
        </Button>
        <Button
          size="sm"
          variant="secondary"
          disabled={busy || !draft}
          onClick={() => setDraft(null)}
        >
          Discard scope changes
        </Button>
      </div>
    </section>
  );
}

function ConnectorScopeForm({
  root,
  busy,
  existing,
  onAdd,
}: {
  root: string;
  busy: boolean;
  existing: FlowConnectorScope["connector"][];
  onAdd: (grant: FlowConnectorScope) => void;
}) {
  const [connector, setConnector] = useState<FlowConnectorScope["connector"]>("jenkins");
  const [url, setUrl] = useState("");
  const [targets, setTargets] = useState("");
  const [wide, setWide] = useState(false);
  const names = Object.keys(TARGET_HELP) as FlowConnectorScope["connector"][];
  return (
    <form
      aria-label={`connector scope for ${root}`}
      className="space-y-2"
      onSubmit={(event) => {
        event.preventDefault();
        if (busy || existing.includes(connector) || !url.trim() || (!wide && !targets.trim()))
          return;
        onAdd({
          connector,
          base_url: url.trim(),
          access: wide ? "connector_wide" : "targets",
          targets: wide
            ? []
            : [
                ...new Set(
                  targets
                    .split("\n")
                    .map((value) => value.trim())
                    .filter(Boolean),
                ),
              ],
        });
        setUrl("");
        setTargets("");
        setWide(false);
      }}
    >
      <div className="flex flex-wrap gap-2">
        <select
          aria-label={`connector for ${root}`}
          className={rowFieldClasses}
          value={connector}
          disabled={busy}
          onChange={(event) => {
            setConnector(event.target.value as FlowConnectorScope["connector"]);
            setTargets("");
            setWide(false);
          }}
        >
          {names.map((name) => (
            <option key={name} value={name}>
              {name}
            </option>
          ))}
        </select>
        <input
          aria-label={`service URL for ${root}`}
          className={rowFieldClasses}
          value={url}
          disabled={busy}
          placeholder="https://jenkins.example/"
          onChange={(event) => setUrl(event.target.value)}
        />
      </div>
      <label className="flex min-h-8 cursor-pointer items-center gap-2 text-sm text-ink-muted">
        <input
          type="checkbox"
          className="size-4.5 accent-accent-strong"
          checked={wide}
          disabled={busy}
          onChange={(event) => setWide(event.target.checked)}
        />
        Allow all connector targets and searches for {root}
      </label>
      {!wide && (
        <>
          <p className="text-xs text-ink-muted">
            {TARGET_HELP[connector]}. One per line. Searches require explicit access to all
            connector targets.
          </p>
          <textarea
            aria-label={`exact targets for ${root}`}
            className={cn(fieldClasses, "h-auto min-h-16 py-2")}
            value={targets}
            disabled={busy}
            onChange={(event) => setTargets(event.target.value)}
          />
        </>
      )}
      {existing.includes(connector) && (
        <p className="text-xs text-ink-muted">
          This connector already has a scope. Remove it before replacing it.
        </p>
      )}
      <Button
        size="sm"
        type="submit"
        variant="secondary"
        disabled={
          busy || existing.includes(connector) || !url.trim() || (!wide && !targets.trim())
        }
        title={
          existing.includes(connector)
            ? "This connector already has a scope"
            : !url.trim()
              ? "Enter the service URL first"
              : !wide && !targets.trim()
                ? "List at least one target, or allow all"
                : undefined
        }
      >
        Add connector scope
      </Button>
    </form>
  );
}
