import { useRouter, useRouterState } from "@tanstack/react-router";
import { Columns2, Maximize2, PanelLeftClose, PanelLeftOpen, Trash2, X } from "lucide-react";
import { useEffect, useId, useRef, useState, useSyncExternalStore } from "react";
import { createPortal } from "react-dom";
import {
  applyWorkspace,
  deleteWorkspace,
  saveWorkspace,
  subscribeWorkspace,
  workspaceSnapshot,
  type WorkspaceLayout,
} from "../../lib/workspace";
import { Button, buttonVariants } from "../ui/Button";
import { LiquidGlassBackdrop } from "../ui/LiquidGlassBackdrop";

/** Local viewing preferences only: selecting Build opens Flows but never runs one. */
export function WorkspaceMenu() {
  const router = useRouter();
  const href = useRouterState({ select: (state) => state.location.href });
  const workspace = useSyncExternalStore(subscribeWorkspace, workspaceSnapshot);
  const [open, setOpen] = useState(false);
  const [name, setName] = useState("");
  const [message, setMessage] = useState("");
  const trigger = useRef<HTMLButtonElement>(null);
  const dialog = useRef<HTMLDialogElement>(null);
  const id = useId();
  const close = () => {
    setOpen(false);
  };

  useEffect(() => {
    if (!open) return;
    const element = dialog.current!;
    const opener = trigger.current;
    element.showModal();
    return () => {
      element.close();
      opener?.focus();
    };
  }, [open]);

  const restore = (layout: WorkspaceLayout, destination?: string) => {
    applyWorkspace(layout);
    if (destination) void router.navigate({ href: destination });
    close();
  };

  return (
    <>
      <button
        ref={trigger}
        type="button"
        className={buttonVariants({ variant: "ghost", size: "sm" })}
        aria-haspopup="dialog"
        aria-expanded={open}
        onClick={() => {
          setMessage("");
          setOpen(true);
        }}
      >
        <Columns2 size={15} aria-hidden="true" /> Workspace
      </button>
      {open &&
        createPortal(
          <dialog
            ref={dialog}
            aria-labelledby={`${id}-title`}
            onCancel={close}
            className="workspace-dialog liquid-glass-panel m-auto overflow-hidden rounded-panel border border-line bg-surface p-0 text-ink shadow-xl backdrop:bg-black/40"
          >
            <LiquidGlassBackdrop />
            <div className="workspace-dialog-content">
              <div className="mb-4 flex items-center justify-between">
                <h2 id={`${id}-title`} className="font-display text-lg font-semibold">
                  Workspace
                </h2>
                <Button
                  variant="ghost"
                  size="sm"
                  aria-label="Close workspace controls"
                  onClick={close}
                >
                  <X size={16} aria-hidden="true" />
                </Button>
              </div>
              <p className="mb-3 text-xs text-ink-muted">
                Arrange your view. These presets never run actions.
              </p>
              <div className="grid grid-cols-3 gap-2">
                <Button
                  variant="secondary"
                  onClick={() => restore({ sidebar: "compact", width: "full" }, "/activity")}
                >
                  Monitor
                </Button>
                <Button
                  variant="secondary"
                  onClick={() => restore({ sidebar: "expanded", width: "full" }, "/flows")}
                >
                  Build
                </Button>
                <Button
                  variant="secondary"
                  onClick={() => restore({ sidebar: "expanded", width: "focused" })}
                >
                  Focus
                </Button>
              </div>
              <fieldset className="mt-5">
                <legend className="mb-2 text-xs font-medium text-ink-muted">Sidebar</legend>
                <div className="grid grid-cols-2 gap-2">
                  <Button
                    variant={workspace.sidebar === "expanded" ? "primary" : "secondary"}
                    aria-pressed={workspace.sidebar === "expanded"}
                    onClick={() => applyWorkspace({ ...workspace, sidebar: "expanded" })}
                  >
                    <PanelLeftOpen size={15} aria-hidden="true" /> Expanded
                  </Button>
                  <Button
                    variant={workspace.sidebar === "compact" ? "primary" : "secondary"}
                    aria-pressed={workspace.sidebar === "compact"}
                    onClick={() => applyWorkspace({ ...workspace, sidebar: "compact" })}
                  >
                    <PanelLeftClose size={15} aria-hidden="true" /> Compact
                  </Button>
                </div>
              </fieldset>
              <fieldset className="mt-4">
                <legend className="mb-2 text-xs font-medium text-ink-muted">
                  Content width
                </legend>
                <div className="grid grid-cols-2 gap-2">
                  <Button
                    variant={workspace.width === "full" ? "primary" : "secondary"}
                    aria-pressed={workspace.width === "full"}
                    onClick={() => applyWorkspace({ ...workspace, width: "full" })}
                  >
                    <Maximize2 size={15} aria-hidden="true" /> Full width
                  </Button>
                  <Button
                    variant={workspace.width === "focused" ? "primary" : "secondary"}
                    aria-pressed={workspace.width === "focused"}
                    onClick={() => applyWorkspace({ ...workspace, width: "focused" })}
                  >
                    Focused
                  </Button>
                </div>
              </fieldset>
              <div className="mt-5 border-t border-line pt-4">
                <h3 className="mb-2 text-sm font-medium">
                  Saved layouts{" "}
                  <span className="text-ink-faint">{workspace.saved.length}/8</span>
                </h3>
                {workspace.saved.length === 0 && (
                  <p className="mb-3 text-xs text-ink-muted">
                    Save this screen, its filters, and your layout.
                  </p>
                )}
                <ul className="mb-3 space-y-1">
                  {workspace.saved.map((saved) => (
                    <li key={saved.id} className="flex min-w-0 items-center gap-1">
                      <Button
                        variant="ghost"
                        className="min-w-0 flex-1 justify-start"
                        onClick={() => restore(saved, saved.href)}
                      >
                        <span className="truncate">{saved.name}</span>
                      </Button>
                      <Button
                        variant="ghost"
                        size="sm"
                        aria-label={`Delete layout ${saved.name}`}
                        onClick={() => deleteWorkspace(saved.id)}
                      >
                        <Trash2 size={14} aria-hidden="true" />
                      </Button>
                    </li>
                  ))}
                </ul>
                <form
                  onSubmit={(event) => {
                    event.preventDefault();
                    const error = saveWorkspace(name, href);
                    setMessage(error ?? "Layout saved.");
                    if (!error) setName("");
                  }}
                >
                  <label htmlFor={`${id}-name`} className="mb-1 block text-xs text-ink-muted">
                    Layout name
                  </label>
                  <div className="flex gap-2">
                    <input
                      id={`${id}-name`}
                      value={name}
                      maxLength={40}
                      onChange={(event) => setName(event.target.value)}
                      className="field-control h-8 min-w-0 flex-1 rounded-control border border-control-line bg-surface-raised px-2 text-sm"
                      placeholder="My workspace"
                    />
                    <Button
                      type="submit"
                      disabled={!name.trim() || workspace.saved.length >= 8}
                    >
                      Save
                    </Button>
                  </div>
                </form>
                <p role="status" className="mt-2 text-xs text-ink-muted">
                  {message}
                </p>
              </div>
            </div>
          </dialog>,
          document.body,
        )}
    </>
  );
}
