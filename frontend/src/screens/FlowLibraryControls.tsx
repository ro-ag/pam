import { useQueryClient } from "@tanstack/react-query";
import { useCallback, useEffect, useRef, useState, type ReactNode } from "react";
import { Button } from "../components/ui/Button";
import { FailureNote } from "../components/ui/FailureNote";
import { fieldClasses } from "../components/ui/field";
import {
  flowsDelete,
  flowsGet,
  flowsNormalize,
  flowsSave,
  toBridgeFailure,
  type BridgeFailure,
  type FlowListEntry,
} from "../lib/ipc";
import { toRaw } from "./flow-canvas/graph";

export type LibraryDraft = { id: string; yaml: string; dirty: boolean; saveDisabled?: boolean };
type Mode = "new" | "duplicate" | "rename" | "delete";

function FlowDialog({
  title,
  onCancel,
  children,
}: {
  title: string;
  onCancel: () => void;
  children: ReactNode;
}) {
  const ref = useRef<HTMLDialogElement>(null);
  useEffect(() => {
    const dialog = ref.current;
    if (dialog?.showModal) dialog.showModal();
    else dialog?.setAttribute("open", "");
    return () => dialog?.close?.();
  }, []);
  return (
    <dialog
      ref={ref}
      aria-label={title}
      onCancel={(event) => {
        event.preventDefault();
        onCancel();
      }}
      className="m-auto w-full max-w-lg space-y-4 rounded-card border border-line bg-surface-raised p-5 text-ink shadow-xl backdrop:bg-black/40"
    >
      <h2 className="font-display text-lg">{title}</h2>
      {children}
    </dialog>
  );
}

/** Library actions and a single Save/Discard/Cancel gate for every caller. */
export function useFlowLibraryControls({
  entries,
  selected,
  draft,
  ready,
  onSelected,
  onDiscard,
}: {
  entries: FlowListEntry[];
  selected: FlowListEntry | null;
  draft: LibraryDraft | null;
  ready: boolean;
  onSelected: (id: string | null) => void;
  onDiscard: () => void;
}) {
  const client = useQueryClient();
  const locked = useRef(false);
  const [busy, setBusy] = useState(false);
  const [mode, setMode] = useState<Mode | null>(null);
  const [subject, setSubject] = useState<FlowListEntry | null>(null);
  const [id, setId] = useState("");
  const [name, setName] = useState("");
  const [template, setTemplate] = useState("");
  const [program, setProgram] = useState("");
  const [argumentsText, setArgumentsText] = useState("");
  const [failure, setFailure] = useState<BridgeFailure | null>(null);
  const [pending, setPending] = useState<{ proceed: () => void; cancel?: () => void } | null>(
    null,
  );
  const [deleted, setDeleted] = useState<{
    id: string;
    yaml: string;
    revealed: boolean;
  } | null>(null);

  const requestNavigation = useCallback(
    (proceed: () => void, cancel?: () => void) => {
      if (locked.current) {
        cancel?.();
        return;
      }
      if (draft?.dirty && draft.id === selected?.id) setPending({ proceed, cancel });
      else proceed();
    },
    [draft, selected?.id],
  );
  async function perform(action: () => Promise<void>) {
    if (locked.current) return;
    locked.current = true;
    setBusy(true);
    setFailure(null);
    try {
      await action();
      return true;
    } catch (error) {
      setFailure(toBridgeFailure(error));
      return false;
    } finally {
      locked.current = false;
      setBusy(false);
    }
  }
  async function refresh(flowId: string | null) {
    await client.invalidateQueries({ queryKey: ["flows"] });
    if (flowId) await client.invalidateQueries({ queryKey: ["flow", flowId] });
    onDiscard();
    onSelected(flowId);
  }
  function open(next: Mode) {
    requestNavigation(() => {
      setFailure(null);
      setMode(next);
      setSubject(selected);
      setTemplate("");
      setProgram("");
      setArgumentsText("");
      const base = selected?.id ?? "flow";
      let suggested = `${base.slice(0, 54)}-copy`;
      for (let suffix = 2; entries.some((entry) => entry.id === suggested); suffix++)
        suggested = `${base.slice(0, 50)}-copy-${suffix}`;
      setId(next === "rename" ? (selected?.id ?? "") : next === "new" ? "" : suggested);
      setName(
        next === "rename"
          ? (selected?.name ?? "")
          : next === "new"
            ? ""
            : `${selected?.name ?? "Flow"} copy`,
      );
    });
  }
  const cleanId = id.trim(),
    cleanName = name.trim();
  const collision = entries.some(
    (entry) =>
      entry.id !== (mode === "rename" ? subject?.id : undefined) &&
      (entry.id === cleanId ||
        entry.name.trim().toLocaleLowerCase() === cleanName.toLocaleLowerCase()),
  );
  const valid =
    /^[a-z0-9-]{1,64}$/.test(cleanId) &&
    cleanName.length > 0 &&
    new TextEncoder().encode(cleanName).length <= 120 &&
    !collision;
  async function submit() {
    if (!ready || (!subject && mode !== "new") || (!valid && mode !== "delete")) return;
    await perform(async () => {
      if (mode === "delete" && subject) {
        const original = await flowsGet(subject.id);
        const result = await flowsDelete(subject.id);
        setDeleted({ id: subject.id, yaml: original.yaml, revealed: result.revealed_builtin });
        await refresh(result.revealed_builtin ? subject.id : null);
      } else {
        let yaml: string;
        if (mode === "new" && !template) {
          if (!program.trim()) return;
          yaml = `schema: 1\nid: ${cleanId}\nname: ${JSON.stringify(cleanName)}\nsteps:\n  - id: first-step\n    run: [${[
            program.trim(),
            ...argumentsText
              .split("\n")
              .map((value) => value.trim())
              .filter(Boolean),
          ]
            .map((value) => JSON.stringify(value))
            .join(", ")}]\n`;
          const checked = await flowsNormalize({ yaml });
          if (!checked.valid)
            throw {
              cause: "invalid_flow",
              detail: `${checked.error.path}: ${checked.error.message}`,
              recovery: "Correct the first command, then try again.",
            };
          yaml = checked.yaml;
        } else {
          const source = await flowsGet(mode === "new" ? template : subject!.id);
          if (!source.flow)
            throw {
              cause: "invalid_flow",
              detail: source.error ?? "The source flow cannot be parsed.",
              recovery: "Repair and save its YAML before copying or renaming it.",
            };
          const normalized = await flowsNormalize({
            flow: { ...toRaw(source.flow), id: cleanId, name: cleanName },
          });
          if (!normalized.valid)
            throw {
              cause: "invalid_flow",
              detail: `${normalized.error.path}: ${normalized.error.message}`,
              recovery: "Correct the source flow, then try again.",
            };
          yaml = normalized.yaml;
        }
        await flowsSave(cleanId, yaml, mode === "rename" ? {} : { create_only: true });
        await refresh(cleanId);
      }
      setMode(null);
    });
  }
  const saveDraft = () =>
    void perform(async () => {
      if (!draft || draft.id !== selected?.id || draft.saveDisabled) return;
      await flowsSave(draft.id, draft.yaml);
      await refresh(draft.id);
    });
  const cancelMode = () => {
    if (!locked.current) {
      setMode(null);
      setFailure(null);
    }
  };
  const cancelNavigation = () => {
    if (!locked.current) {
      pending?.cancel?.();
      setPending(null);
      setFailure(null);
    }
  };

  const toolbar = (
    <div className="flex flex-wrap gap-2" aria-label="Flow library actions">
      <Button size="sm" disabled={!ready || busy} onClick={() => open("new")}>
        New flow
      </Button>
      <Button
        size="sm"
        variant="ghost"
        disabled={!ready || busy || !selected}
        onClick={() => open("duplicate")}
      >
        Duplicate
      </Button>
      <Button
        size="sm"
        variant="ghost"
        disabled={!ready || busy || !selected}
        onClick={() => open("rename")}
      >
        Rename
      </Button>
      <Button
        size="sm"
        variant="ghost"
        disabled={!ready || busy || !selected || selected.source === "builtin"}
        title={
          selected?.source === "builtin"
            ? "Built-in originals cannot be deleted. Duplicate one to make your own copy."
            : undefined
        }
        onClick={() => open("delete")}
      >
        Delete
      </Button>
    </div>
  );
  const dialogs = (
    <>
      {deleted && (
        <div
          role="status"
          className="space-y-2 rounded-card border border-line p-3 text-sm text-ink-muted"
        >
          <p>
            {deleted.revealed
              ? "Custom override deleted; the built-in original is available again."
              : `Deleted ${deleted.id}.`}{" "}
            Undo is available until you leave Flows or delete another flow.
          </p>
          <Button
            size="sm"
            disabled={busy}
            onClick={() =>
              requestNavigation(
                () =>
                  void perform(async () => {
                    await flowsSave(deleted.id, deleted.yaml, {
                      create_only: true,
                      ...(deleted.revealed ? { allow_builtin_override: true } : {}),
                    });
                    await refresh(deleted.id);
                    setDeleted(null);
                  }),
              )
            }
          >
            Undo delete
          </Button>
        </div>
      )}
      {mode && (
        <FlowDialog
          title={
            mode === "new"
              ? "New flow"
              : mode === "duplicate"
                ? "Duplicate flow"
                : mode === "rename"
                  ? "Rename flow"
                  : "Delete flow"
          }
          onCancel={cancelMode}
        >
          {mode === "delete" ? (
            <p className="text-sm">
              Delete {subject?.name}? If this is a custom override, its built-in original will
              reappear. Undo remains available on this page until you leave Flows or delete
              another flow.
            </p>
          ) : (
            <>
              <label className="block space-y-1 text-sm">
                Flow name
                <input
                  autoFocus
                  aria-label="Flow name"
                  className={fieldClasses}
                  value={name}
                  disabled={busy}
                  onChange={(event) => setName(event.target.value)}
                />
              </label>
              <label className="block space-y-1 text-sm">
                Flow ID
                <input
                  aria-label="Flow ID"
                  className={fieldClasses}
                  value={id}
                  disabled={busy || mode === "rename"}
                  onChange={(event) => setId(event.target.value)}
                />
              </label>
              <p className="text-sm text-ink-muted">
                {mode === "rename"
                  ? "Only the display name changes. The stable ID used by CLI commands and references stays the same. Renaming a built-in creates a custom override; its original is preserved."
                  : "Use a unique name and ID. IDs contain 1–64 lowercase letters, digits or hyphens; names use at most 120 bytes."}
              </p>
              {collision && (
                <p role="alert" className="text-sm text-danger">
                  That ID or name already exists. Choose another; existing flows will not be
                  replaced.
                </p>
              )}
              {mode === "new" && (
                <>
                  <label className="block space-y-1 text-sm">
                    Starting point
                    <select
                      aria-label="Starting point"
                      className={fieldClasses}
                      value={template}
                      disabled={busy}
                      onChange={(event) => setTemplate(event.target.value)}
                    >
                      <option value="">Blank — add a first command</option>
                      {entries
                        .filter((entry) => entry.valid)
                        .map((entry) => (
                          <option key={entry.id} value={entry.id}>
                            {entry.name}
                          </option>
                        ))}
                    </select>
                  </label>
                  {!template && (
                    <label className="block space-y-1 text-sm">
                      First program
                      <input
                        aria-label="First program"
                        placeholder="e.g. git"
                        className={fieldClasses}
                        value={program}
                        disabled={busy}
                        onChange={(event) => setProgram(event.target.value)}
                      />
                      <span className="text-ink-muted">
                        A saved flow needs a step. Add more steps in the editor. Creating it
                        does not run it.
                      </span>
                    </label>
                  )}
                  {!template && (
                    <label className="block space-y-1 text-sm">
                      Arguments (one per line)
                      <textarea
                        aria-label="Arguments (one per line)"
                        className={fieldClasses}
                        value={argumentsText}
                        disabled={busy}
                        onChange={(event) => setArgumentsText(event.target.value)}
                        placeholder={"status\n--short"}
                      />
                    </label>
                  )}
                </>
              )}
            </>
          )}
          {failure && <FailureNote failure={failure} label="flow" />}
          <div className="flex gap-2">
            <Button
              size="sm"
              disabled={
                busy ||
                (mode !== "delete" &&
                  (!valid || (mode === "new" && !template && !program.trim())))
              }
              onClick={() => void submit()}
            >
              {busy
                ? "Working…"
                : mode === "delete"
                  ? "Confirm delete"
                  : mode === "rename"
                    ? "Save name"
                    : "Create flow"}
            </Button>
            <Button size="sm" variant="ghost" disabled={busy} onClick={cancelMode}>
              Cancel
            </Button>
          </div>
        </FlowDialog>
      )}
      {pending && (
        <FlowDialog title="Unsaved flow changes" onCancel={cancelNavigation}>
          <p className="text-sm">
            Save your changes before continuing, discard them, or stay here. Saving a built-in
            creates a custom override; the original remains recoverable by deleting the
            override.
          </p>
          {draft?.saveDisabled && (
            <p className="text-sm text-warning">
              Save becomes available after the latest edits pass validation. Cancel to repair
              any errors in the editor.
            </p>
          )}
          {failure && <FailureNote failure={failure} label="flow" />}
          <div className="flex gap-2">
            <Button
              size="sm"
              disabled={busy || draft?.saveDisabled}
              onClick={async () => {
                if (!draft || draft.saveDisabled) return;
                const proceed = pending.proceed;
                const saved = await perform(async () => {
                  await flowsSave(draft.id, draft.yaml);
                  await refresh(draft.id);
                });
                if (saved) {
                  setPending(null);
                  proceed();
                }
              }}
            >
              Save
            </Button>
            <Button
              size="sm"
              variant="ghost"
              disabled={busy}
              onClick={() => {
                onDiscard();
                const proceed = pending.proceed;
                setPending(null);
                proceed();
              }}
            >
              Discard
            </Button>
            <Button size="sm" variant="ghost" disabled={busy} onClick={cancelNavigation}>
              Cancel
            </Button>
          </div>
        </FlowDialog>
      )}
      {!mode && !pending && failure && <FailureNote failure={failure} label="flow library" />}
    </>
  );
  return {
    toolbar,
    dialogs,
    requestNavigation,
    busy,
    saveDraft,
    isLocked: () => locked.current,
  };
}
