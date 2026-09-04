import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { X } from "lucide-react";
import { useState } from "react";
import { Button } from "../components/ui/Button";
import { FailureNote } from "../components/ui/FailureNote";
import { Panel } from "../components/ui/Panel";
import {
  flowsSettingsGet,
  flowsSettingsSet,
  toBridgeFailure,
  type BridgeFailure,
  type FlowSettings,
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

const fieldClasses =
  "h-8 min-w-40 flex-1 rounded-control field-control border border-control-line bg-inset px-2.5 font-data text-xs text-ink placeholder:text-ink-faint";

/** One removable chip: the value in the data voice, and a way out. */
function ListChip({
  value,
  label,
  onRemove,
}: {
  value: string;
  label: string;
  onRemove: () => void;
}) {
  return (
    <span className="inline-flex items-center gap-1.5 rounded-badge border border-line bg-surface px-2.5 py-0.5 font-data text-xs text-ink-muted">
      {value}
      <button
        type="button"
        aria-label={`${label} ${value}`}
        onClick={onRemove}
        className="text-ink-faint transition-colors duration-150 hover:text-danger"
      >
        <X aria-hidden="true" className="size-3" />
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
  onChange: (next: string[]) => void;
}) {
  const [draft, setDraft] = useState("");
  return (
    <div className="space-y-3">
      <p className="font-data text-xs tracking-widest text-ink-faint uppercase">{title}</p>
      {values.length === 0 ? (
        <p className="font-voice text-sm text-ink-muted italic">{empty}</p>
      ) : (
        <div className="flex flex-wrap gap-2">
          {values.map((value) => (
            <ListChip
              key={value}
              value={value}
              label={removeLabel}
              onRemove={() => onChange(values.filter((kept) => kept !== value))}
            />
          ))}
        </div>
      )}
      <form
        className="flex flex-wrap items-center gap-2"
        onSubmit={(event) => {
          event.preventDefault();
          const value = draft.trim();
          if (!value) return;
          onChange(values.includes(value) ? values : [...values, value]);
          setDraft("");
        }}
      >
        <input
          aria-label={addLabel}
          value={draft}
          onChange={(event) => setDraft(event.target.value)}
          placeholder={placeholder}
          className={fieldClasses}
        />
        <Button size="sm" type="submit" disabled={busy || !draft.trim()}>
          Add
        </Button>
      </form>
    </div>
  );
}

export function SettingsFlowsSection() {
  const queryClient = useQueryClient();
  const settings = useQuery({ queryKey: ["flow-settings"], queryFn: flowsSettingsGet });
  const [failure, setFailure] = useState<BridgeFailure | null>(null);

  const save = useMutation({
    mutationFn: (patch: Partial<FlowSettings>) => flowsSettingsSet(patch),
    onMutate: () => setFailure(null),
    onSuccess: (next) => queryClient.setQueryData(["flow-settings"], next),
    onError: (error) => setFailure(toBridgeFailure(error)),
    onSettled: () => void queryClient.invalidateQueries({ queryKey: ["flow-settings"] }),
  });

  const listFailure = settings.isError ? toBridgeFailure(settings.error) : null;
  const programs = settings.data?.allowed_programs ?? [];
  const extraPath = settings.data?.extra_path ?? [];

  return (
    <Panel ground="raised" className="space-y-5 p-5">
      {listFailure && <FailureNote failure={listFailure} label="flow settings" />}

      <ListEditor
        title="allowed programs"
        values={programs}
        addLabel="program to allow"
        removeLabel="remove program"
        placeholder="program, e.g. cargo"
        empty="No program is allowed yet, so every command step would refuse."
        busy={save.isPending}
        onChange={(next) => save.mutate({ allowed_programs: next })}
      />

      <div className="border-t border-line pt-4">
        <ListEditor
          title="extra PATH"
          values={extraPath}
          addLabel="directory to add to PATH"
          removeLabel="remove directory"
          placeholder="directory, e.g. /opt/homebrew/bin"
          empty="Nothing added — steps see only the daemon's own PATH."
          busy={save.isPending}
          onChange={(next) => save.mutate({ extra_path: next })}
        />
      </div>

      {failure && <FailureNote failure={failure} label="flow settings" />}

      <p className="border-t border-line pt-4 font-voice text-sm text-ink-muted italic">
        A flow may name any program; I run only the ones on this list. That is the whole reason
        a flow file is safe to read and safe to keep.
      </p>
    </Panel>
  );
}
