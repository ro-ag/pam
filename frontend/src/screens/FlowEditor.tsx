import { Button } from "../components/ui/Button";
import type { FlowListEntry } from "../lib/ipc";

/** The shared flow draft as YAML; library actions own persistence and navigation. */
export function FlowEditor({
  entry,
  yaml,
  showYaml = true,
  onYamlChange,
  saveDisabled,
  busy,
  onSave,
}: {
  entry: FlowListEntry;
  yaml: string;
  showYaml?: boolean;
  onYamlChange: (yaml: string) => void;
  saveDisabled: boolean;
  busy: boolean;
  onSave: () => void;
}) {
  return (
    <div className="space-y-3">
      {showYaml && (
        <textarea
          aria-label={`${entry.id} yaml`}
          spellCheck={false}
          value={yaml}
          disabled={busy}
          onChange={(event) => {
            if (!busy) onYamlChange(event.target.value);
          }}
          rows={20}
          className="w-full resize-y rounded-card border border-line bg-chrome p-3 font-data text-xs leading-relaxed text-ink-muted"
        />
      )}
      <div className="flex flex-wrap items-center gap-x-4 gap-y-2">
        {entry.path && (
          <p className="min-w-0 break-all font-data text-xs text-ink-faint" title={entry.path}>
            {entry.path}
          </p>
        )}
        <span className="flex-1" />
        {entry.source !== "builtin" && (
          <Button
            size="sm"
            disabled={busy || saveDisabled}
            onClick={() => {
              if (!busy && !saveDisabled) onSave();
            }}
          >
            {busy ? "Saving…" : "Save"}
          </Button>
        )}
      </div>
      {entry.source === "builtin" && (
        <p className="max-w-md font-sans text-sm text-ink-muted">
          Use Duplicate in the library actions to make your own copy. The built-in original
          stays available.
        </p>
      )}
    </div>
  );
}
