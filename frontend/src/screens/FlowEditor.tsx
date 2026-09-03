import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { LoaderCircle } from "lucide-react";
import { useEffect, useState } from "react";
import { Button } from "../components/ui/Button";
import { ConfirmButton } from "../components/ui/ConfirmButton";
import { FailureNote } from "../components/ui/FailureNote";
import {
  flowsDelete,
  flowsGet,
  flowsSave,
  toBridgeFailure,
  type BridgeFailure,
  type FlowListEntry,
} from "../lib/ipc";

/**
 * The YAML tab — the whole flow, as text, because that is what a flow
 * is. No form, no wizard: the file is the contract, and a human editing
 * it should see exactly what the daemon will read.
 *
 * There is no Validate button, deliberately. The daemon is the only
 * validator worth trusting (it is the one that will run this), so Save
 * *is* validation: an invalid flow comes back as a refusal naming the
 * YAML path that offended, rendered as the same FailureNote every other
 * screen uses. A second, client-side opinion could only ever be wrong in
 * a new way.
 *
 * A builtin cannot be edited in place — it ships with pam. Saving one
 * clones it into the library under a new id, which then shadows the
 * builtin; deleting that shadow reveals the builtin again, which is why
 * a starter flow can never be lost.
 */

/**
 * Rewrites the top-level `id:` line, so a clone's YAML agrees with the
 * id it is being saved as — the daemon refuses the pair when they differ
 * (`id_mismatch`), and making the human fix that by hand would be a
 * riddle, not a refusal.
 */
export function withId(yaml: string, id: string): string {
  const lines = yaml.split("\n");
  const index = lines.findIndex((line) => /^id:(\s|$)/.test(line));
  if (index === -1) return `id: ${id}\n${yaml}`;
  lines[index] = `id: ${id}`;
  return lines.join("\n");
}

export function FlowEditor({
  entry,
  onSaved,
  onDeleted,
}: {
  entry: FlowListEntry;
  onSaved: (id: string) => void;
  onDeleted: () => void;
}) {
  const queryClient = useQueryClient();
  const detail = useQuery({ queryKey: ["flow", entry.id], queryFn: () => flowsGet(entry.id) });
  const [yaml, setYaml] = useState("");
  const [cloneId, setCloneId] = useState("");
  const [failure, setFailure] = useState<BridgeFailure | null>(null);

  const builtin = entry.source === "builtin";
  const text = detail.data?.yaml;

  // The textarea follows the selected flow; an edit in progress is not
  // carried across a selection change, because it would silently belong
  // to the wrong file.
  useEffect(() => {
    setYaml(text ?? "");
    setCloneId("");
    setFailure(null);
  }, [text, entry.id]);

  const settle = (id: string) => {
    void queryClient.invalidateQueries({ queryKey: ["flows"] });
    void queryClient.invalidateQueries({ queryKey: ["flow", id] });
  };

  const save = useMutation({
    mutationFn: ({ id, body }: { id: string; body: string }) => flowsSave(id, body),
    onMutate: () => setFailure(null),
    onSuccess: (_saved, { id }) => {
      settle(id);
      onSaved(id);
    },
    onError: (error) => setFailure(toBridgeFailure(error)),
  });

  const remove = useMutation({
    mutationFn: () => flowsDelete(entry.id),
    onMutate: () => setFailure(null),
    onSuccess: () => {
      settle(entry.id);
      onDeleted();
    },
    onError: (error) => setFailure(toBridgeFailure(error)),
  });

  const loadFailure = detail.isError ? toBridgeFailure(detail.error) : null;
  const cloneReady = cloneId.trim().length > 0;

  return (
    <div className="space-y-3">
      {loadFailure && <FailureNote failure={loadFailure} label="flow" />}

      <textarea
        aria-label={`${entry.id} yaml`}
        spellCheck={false}
        value={yaml}
        onChange={(event) => setYaml(event.target.value)}
        rows={20}
        className="w-full resize-y rounded-card border border-line bg-chrome p-3 font-data text-xs leading-relaxed text-ink-muted"
      />

      <div className="flex flex-wrap items-center gap-x-4 gap-y-2">
        <p className="font-data text-xs text-ink-faint" title={entry.path ?? entry.digest}>
          {entry.path ?? "ships with pam"}
        </p>
        <span className="flex-1" />

        {builtin && (
          <input
            aria-label="new flow id"
            value={cloneId}
            onChange={(event) => setCloneId(event.target.value)}
            placeholder="new id for your copy"
            className="h-8 w-48 rounded-control border border-line bg-surface px-2.5 font-data text-xs text-ink placeholder:text-ink-faint"
          />
        )}

        <Button
          size="sm"
          disabled={save.isPending || (builtin && !cloneReady)}
          onClick={() => {
            const id = builtin ? cloneId.trim() : entry.id;
            save.mutate({ id, body: builtin ? withId(yaml, id) : yaml });
          }}
        >
          {save.isPending && (
            <LoaderCircle aria-hidden="true" className="size-3.5 animate-spin" />
          )}
          {builtin ? "Clone" : "Save"}
        </Button>

        {!builtin && (
          <ConfirmButton
            label="Delete"
            confirmLabel="delete it?"
            busy={remove.isPending}
            onConfirm={() => remove.mutate()}
          />
        )}
      </div>

      {builtin && (
        <p className="max-w-md font-voice text-sm text-ink-muted italic">
          This one ships with me, so it cannot be edited in place. Give your copy a name and it
          shadows the builtin — delete the copy and the builtin comes back.
        </p>
      )}

      {failure && <FailureNote failure={failure} label="flow" />}
    </div>
  );
}
