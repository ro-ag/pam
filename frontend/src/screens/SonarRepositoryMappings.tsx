import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Button } from "../components/ui/Button";
import { FailureNote } from "../components/ui/FailureNote";
import { fieldClasses } from "../components/ui/field";
import { Panel } from "../components/ui/Panel";
import {
  sonarMappingsGet,
  sonarMappingsSet,
  toBridgeFailure,
  type SonarRepositoryMapping,
  type SonarRepositoryMappings,
} from "../lib/ipc";

const key = ["sonar-repository-mappings"];

export function SonarRepositoryMappingsEditor() {
  const client = useQueryClient();
  const query = useQuery({ queryKey: key, queryFn: sonarMappingsGet });
  // A draft retains the revision it was edited against. Refresh cannot silently
  // rebase a save over another administrator's changes.
  const [draft, setDraft] = useState<SonarRepositoryMappings | null>(null);
  const [saved, setSaved] = useState(false);
  const snapshot = draft ?? query.data;
  const save = useMutation({
    mutationFn: sonarMappingsSet,
    onSuccess: async (fresh) => {
      await client.cancelQueries({ queryKey: key });
      client.setQueryData(key, fresh);
      setDraft(null);
      setSaved(true);
    },
    onError: () => {
      void query.refetch();
    },
  });
  const edit = (mappings: SonarRepositoryMapping[]) => {
    if (!snapshot || save.isPending) return;
    setDraft({ revision: snapshot.revision, mappings });
    setSaved(false);
    save.reset();
  };
  const update = (index: number, field: keyof SonarRepositoryMapping, value: string) => {
    if (!snapshot) return;
    edit(
      snapshot.mappings.map((mapping, row) =>
        row === index ? { ...mapping, [field]: value } : mapping,
      ),
    );
  };
  const changedElsewhere = draft && query.data && draft.revision !== query.data.revision;
  return (
    <Panel
      ground="raised"
      className="mt-4 space-y-3 p-4"
      aria-label="Sonar repository mappings"
    >
      <h3 className="font-sans text-sm font-medium">Sonar repository mappings</h3>
      <p className="text-sm text-ink-muted">
        Associate a Sonar server and project with its exact HTTPS source repository for revision
        checks. Access permissions are configured separately in Flows settings.
      </p>
      <p className="font-data text-xs text-ink-faint">
        Up to 64 mappings. Keep the repository path and .git suffix exact.
      </p>
      {query.isError && (
        <FailureNote failure={toBridgeFailure(query.error)} label="Sonar mappings" />
      )}
      {save.isError && (
        <FailureNote failure={toBridgeFailure(save.error)} label="Save mappings" />
      )}
      {changedElsewhere && (
        <p role="status" className="text-sm text-danger">
          Saved mappings changed elsewhere. Your edits are preserved. Reload saved mappings
          before editing the current version.
        </p>
      )}
      {!snapshot && query.isPending && (
        <p className="text-sm text-ink-muted">Loading mappings…</p>
      )}
      {snapshot?.mappings.map((mapping, index) => (
        <div key={index} className="grid gap-2 rounded-control border border-line p-3">
          {(["server", "project", "repository"] as const).map((field) => (
            <label key={field} className="text-xs text-ink-muted">
              {field === "server"
                ? "Sonar server URL"
                : field === "project"
                  ? "Project key"
                  : "HTTPS repository URL"}
              <input
                className={fieldClasses}
                aria-label={`Mapping ${index + 1} ${field}`}
                value={mapping[field]}
                disabled={save.isPending}
                onChange={(event) => update(index, field, event.target.value)}
              />
            </label>
          ))}
          <Button
            size="sm"
            variant="ghost"
            disabled={save.isPending}
            onClick={() => edit(snapshot.mappings.filter((_, row) => row !== index))}
          >
            Remove mapping {index + 1}
          </Button>
        </div>
      ))}
      {snapshot && snapshot.mappings.length === 0 && (
        <p className="text-sm text-ink-muted">No repository mappings saved.</p>
      )}
      <div className="flex flex-wrap gap-2">
        <Button
          size="sm"
          variant="ghost"
          disabled={!snapshot || save.isPending || snapshot.mappings.length >= 64}
          onClick={() =>
            snapshot &&
            edit([...snapshot.mappings, { server: "", project: "", repository: "" }])
          }
        >
          Add mapping
        </Button>
        <Button
          size="sm"
          disabled={!draft || save.isPending || Boolean(changedElsewhere)}
          onClick={() => draft && save.mutate(draft)}
        >
          Save mappings
        </Button>
        <Button
          size="sm"
          variant="ghost"
          disabled={query.isFetching || save.isPending}
          onClick={() => void query.refetch()}
        >
          Refresh mappings
        </Button>
        {draft && (
          <Button
            size="sm"
            variant="ghost"
            disabled={!query.data || query.isFetching || save.isPending}
            onClick={() => {
              setDraft(null);
              setSaved(false);
              save.reset();
            }}
          >
            Reload saved mappings (discard edits)
          </Button>
        )}
      </div>
      {saved && (
        <p role="status" className="text-sm text-ink-muted">
          Mappings saved.
        </p>
      )}
    </Panel>
  );
}
