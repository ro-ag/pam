import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useRef, useState } from "react";
import { Button } from "../components/ui/Button";
import { FailureNote } from "../components/ui/FailureNote";
import { toBridgeFailure, type BridgeFailure } from "../lib/ipc";
import {
  emptyLandingRepository,
  landingGet,
  landingSet,
  type LandingCheck,
  type LandingRepository,
} from "../lib/landing";

const key = ["landing-policy"];
const field =
  "w-full rounded-control border border-control-line bg-inset px-2.5 py-2 font-data text-xs text-ink";
function TextField({
  label,
  value,
  onChange,
  multiline = false,
}: {
  label: string;
  value: string;
  onChange: (value: string) => void;
  multiline?: boolean;
}) {
  return (
    <label className="block space-y-1 text-xs text-ink-muted">
      <span>{label}</span>
      {multiline ? (
        <textarea className={field} value={value} onChange={(e) => onChange(e.target.value)} />
      ) : (
        <input className={field} value={value} onChange={(e) => onChange(e.target.value)} />
      )}
    </label>
  );
}
function CheckEditor({
  check,
  label,
  onChange,
  onRemove,
}: {
  check: LandingCheck;
  label: string;
  onChange: (check: LandingCheck) => void;
  onRemove: () => void;
}) {
  return (
    <div className="space-y-2 border border-line p-3">
      <TextField
        label={`${label} name`}
        value={check.name}
        onChange={(name) => onChange({ ...check, name })}
      />
      <TextField
        label={`${label} program`}
        value={check.argv[0] ?? ""}
        onChange={(program) => onChange({ ...check, argv: [program, ...check.argv.slice(1)] })}
      />
      <TextField
        label={`${label} arguments (one per line)`}
        value={check.argv.slice(1).join("\n")}
        multiline
        onChange={(text) =>
          onChange({
            ...check,
            argv: [check.argv[0] ?? "", ...(text === "" ? [] : text.split("\n"))],
          })
        }
      />
      <label className="block space-y-1 text-xs text-ink-muted">
        {label} timeout (seconds)
        <input
          type="number"
          className={field}
          min={1}
          max={600}
          value={check.timeout_seconds}
          onChange={(e) => onChange({ ...check, timeout_seconds: Number(e.target.value) })}
        />
      </label>
      <Button size="sm" onClick={onRemove}>
        Remove {label.toLowerCase()}
      </Button>
    </div>
  );
}
function RepositoryEditor({
  repository,
  index,
  onChange,
  onRemove,
}: {
  repository: LandingRepository;
  index: number;
  onChange: (repository: LandingRepository) => void;
  onRemove: () => void;
}) {
  const prefix = `Landing repository ${index + 1}`;
  const fields = [
    ["root", "local root"],
    ["repository", "canonical remote URL"],
    ["github_server", "GitHub API URL"],
    ["github_repository", "GitHub owner/repository"],
    ["base", "base branch"],
    ["workspace_root", "private workspace directory"],
  ] as const;
  const lists = [
    ["branches", "allowed branches"],
    ["read_cache_roots", "read-only cache directories (maximum 8)"],
    ["required_checks", "required PR contexts"],
    ["main_checks", "required main contexts"],
  ] as const;
  return (
    <div className="space-y-3 rounded-control border border-line p-3">
      <h4 className="text-sm font-medium text-ink">
        {prefix}: {repository.root || "unsaved"}
      </h4>
      <div className="grid gap-3 sm:grid-cols-2">
        {fields.map(([name, label]) => (
          <TextField
            key={name}
            label={`${prefix} ${label}`}
            value={repository[name]}
            onChange={(value) => onChange({ ...repository, [name]: value })}
          />
        ))}
      </div>
      {lists.map(([name, label]) => (
        <TextField
          key={name}
          label={`${prefix} ${label} (one per line)`}
          value={(repository[name] ?? []).join("\n")}
          multiline
          onChange={(value) => onChange({ ...repository, [name]: value.split("\n") })}
        />
      ))}
      <p className="text-xs text-ink-muted">
        Every listed context must report success for the exact commit. Missing, unknown or
        cancelled checks cannot pass.
      </p>
      <p className="text-xs text-ink-muted">
        Cache access is optional and read-only. List at most eight existing canonical cache
        directories; never the whole home directory, keychains or PAM state. Nothing is added
        automatically. Checks run without network access and write only to their private
        workspace.
      </p>
      <h5 className="text-sm text-ink">Required local checks</h5>
      {repository.checks.map((check, position) => (
        <CheckEditor
          key={position}
          check={check}
          label={`${prefix} check ${position + 1}`}
          onChange={(next) =>
            onChange({
              ...repository,
              checks: repository.checks.map((old, i) => (i === position ? next : old)),
            })
          }
          onRemove={() =>
            onChange({
              ...repository,
              checks: repository.checks.filter((_, i) => i !== position),
            })
          }
        />
      ))}
      <Button
        size="sm"
        disabled={repository.checks.length >= 8}
        onClick={() =>
          onChange({
            ...repository,
            checks: [...repository.checks, { name: "", argv: [""], timeout_seconds: 300 }],
          })
        }
      >
        Add check to landing repository {index + 1}
      </Button>
      <div className="space-y-2">
        {(
          [
            ["push", "Push branch"],
            ["create_pr", "Create pull request"],
            ["merge", "Squash merge"],
            ["sync", "Sync local base branch"],
          ] as const
        ).map(([permission, label]) => (
          <label key={permission} className="flex items-center gap-2 text-sm text-ink">
            <input
              type="checkbox"
              checked={repository.permissions[permission]}
              onChange={(e) =>
                onChange({
                  ...repository,
                  permissions: { ...repository.permissions, [permission]: e.target.checked },
                })
              }
            />
            {prefix}: {label}
          </label>
        ))}
      </div>
      <Button size="sm" onClick={onRemove}>
        Remove landing repository {index + 1}
      </Button>
    </div>
  );
}

/** GUI authority is saved only through an explicit compare-and-swap operation. */
export function LandingSettings() {
  const queryClient = useQueryClient();
  const query = useQuery({ queryKey: key, queryFn: landingGet });
  const [draft, setDraft] = useState<{
    revision: string;
    repositories: LandingRepository[];
  } | null>(null);
  const [failure, setFailure] = useState<BridgeFailure | null>(null);
  const [conflicted, setConflicted] = useState(false);
  const [pending, setPending] = useState(false);
  const pendingRef = useRef(false);
  const current = draft?.repositories ?? query.data?.repositories ?? [];
  const stale = conflicted || (draft !== null && draft.revision !== query.data?.revision);
  const cacheOverflow = current.some(
    (repo) => (repo.read_cache_roots ?? []).filter((path) => path.trim()).length > 8,
  );
  function edit(repositories: LandingRepository[]) {
    if (pendingRef.current || !query.data || stale) return;
    setDraft({ revision: draft?.revision ?? query.data.revision, repositories });
    setFailure(null);
  }
  async function save() {
    if (pendingRef.current || !draft || stale || cacheOverflow) return;
    pendingRef.current = true;
    setPending(true);
    setFailure(null);
    const repositories = draft.repositories.map((repo) => ({
      ...repo,
      read_cache_roots: (repo.read_cache_roots ?? []).map((s) => s.trim()).filter(Boolean),
      branches: repo.branches.map((s) => s.trim()).filter(Boolean),
      required_checks: repo.required_checks.map((s) => s.trim()).filter(Boolean),
      main_checks: repo.main_checks.map((s) => s.trim()).filter(Boolean),
    }));
    try {
      const saved = await landingSet(draft.revision, repositories);
      queryClient.setQueryData(key, saved);
      setDraft(null);
    } catch (error) {
      const failure = toBridgeFailure(error);
      setFailure(failure);
      if (failure.cause === "landing_policy_changed") setConflicted(true);
    } finally {
      pendingRef.current = false;
      setPending(false);
    }
  }
  async function reload() {
    if (pendingRef.current) return;
    pendingRef.current = true;
    setPending(true);
    try {
      const fresh = await landingGet();
      queryClient.setQueryData(key, fresh);
      setDraft(null);
      setConflicted(false);
      setFailure(null);
    } catch (error) {
      setFailure(toBridgeFailure(error));
    } finally {
      pendingRef.current = false;
      setPending(false);
    }
  }
  return (
    <section aria-label="landing policy" className="space-y-3 border-t border-line pt-4">
      <h3 className="text-sm font-medium text-ink">Landing policy</h3>
      <p className="text-sm text-ink-muted">
        Approve exact landing recipes here. New entries permit no mutations until you select
        permissions and save. Existing connector access is still required.
      </p>
      <p className="text-xs text-ink-muted">
        Use existing canonical absolute directories. The private workspace must be owned by you,
        accessible only by you, and separate from every approved repository and PAM state. This
        form does not create directories or install sandbox policy. Workspace isolation is not
        qualified on Windows.
      </p>
      {query.data && (
        <p className="text-xs text-ink-muted">
          Saved landing repositories: {query.data.repositories.length}.{" "}
          {draft ? "Unsaved landing changes" : "Showing saved policy"}
        </p>
      )}
      {(failure || query.error) && (
        <FailureNote label="landing policy" failure={failure ?? toBridgeFailure(query.error)} />
      )}
      {stale && (
        <p role="alert" className="text-sm text-danger">
          Landing policy changed. Reload before editing or saving; reload discards these unsaved
          changes.
        </p>
      )}
      {cacheOverflow && (
        <p role="alert" className="text-sm text-danger">
          Limit each landing recipe to eight read-only cache directories.
        </p>
      )}
      <fieldset disabled={pending || !query.data || stale} className="space-y-3">
        {current.map((repo, index) => (
          <RepositoryEditor
            key={index}
            repository={repo}
            index={index}
            onChange={(next) => edit(current.map((old, i) => (i === index ? next : old)))}
            onRemove={() => edit(current.filter((_, i) => i !== index))}
          />
        ))}
        <Button
          size="sm"
          disabled={current.length >= 32}
          onClick={() => edit([...current, emptyLandingRepository()])}
        >
          Add landing repository
        </Button>
        <Button size="sm" disabled={!draft || cacheOverflow} onClick={() => void save()}>
          Save landing policy
        </Button>
      </fieldset>
      <Button size="sm" disabled={pending} onClick={() => void reload()}>
        Reload landing policy
      </Button>
    </section>
  );
}
