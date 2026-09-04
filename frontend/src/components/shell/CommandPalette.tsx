import { useQuery } from "@tanstack/react-query";
import { useNavigate } from "@tanstack/react-router";
import { ArrowUpRight, Search, X } from "lucide-react";
import { useEffect, useId, useRef, useState, type KeyboardEvent } from "react";
import { createPortal } from "react-dom";
import { flowsList, modelsList } from "../../lib/ipc";
import { Button } from "../ui/Button";

type Destination = {
  id: string;
  label: string;
  detail: string;
  to: "/" | "/activity" | "/approvals" | "/flows" | "/models" | "/settings";
  hash?: string;
  flow?: string;
};

const pages: Destination[] = [
  { id: "home", label: "Home", detail: "Page · Ask Pam", to: "/" },
  { id: "activity", label: "Activity", detail: "Page · Runs and evidence", to: "/activity" },
  { id: "approvals", label: "Approvals", detail: "Page · Pending decisions", to: "/approvals" },
  { id: "flows", label: "Flows", detail: "Page · CLI-callable actions", to: "/flows" },
  { id: "models", label: "Models", detail: "Page · Local model library", to: "/models" },
  { id: "settings", label: "Settings", detail: "Page · Your preferences", to: "/settings" },
  ...[
    "Appearance",
    "Security",
    "Models",
    "Flows",
    "Connectors",
    "Daemon",
    "Retention",
    "Logs",
  ].map((label): Destination => ({
    id: `settings-${label.toLowerCase()}`,
    label,
    detail: "Settings category",
    to: "/settings",
    hash: label.toLowerCase(),
  })),
];

/** Navigation only: selecting a flow never executes it or changes its definition. */
export function CommandPalette() {
  const [open, setOpen] = useState(false);
  const returnFocus = useRef<HTMLElement | null>(null);

  function show() {
    returnFocus.current = document.activeElement as HTMLElement | null;
    setOpen(true);
  }

  useEffect(() => {
    function shortcut(event: globalThis.KeyboardEvent) {
      if (event.defaultPrevented || event.isComposing || event.altKey) return;
      if (!(event.metaKey || event.ctrlKey) || event.key.toLowerCase() !== "k") return;
      if (open) {
        event.preventDefault();
        setOpen(false);
        return;
      }
      // Do not steal shortcuts from another modal (or an editor inside one).
      if (document.querySelector('dialog[open], [aria-modal="true"]')) return;
      event.preventDefault();
      returnFocus.current = document.activeElement as HTMLElement | null;
      setOpen(true);
    }
    document.addEventListener("keydown", shortcut);
    return () => document.removeEventListener("keydown", shortcut);
  }, [open]);

  return (
    <>
      <Button variant="ghost" size="sm" onClick={show} aria-label="Open command palette">
        <Search size={14} aria-hidden="true" />
        <span className="hidden sm:inline">Jump to…</span>
        <kbd className="hidden font-mono text-micro text-ink-faint sm:inline">
          {/Mac|iPhone|iPad/.test(navigator.platform) ? "⌘K" : "Ctrl K"}
        </kbd>
      </Button>
      {open && (
        <PaletteDialog onClose={() => setOpen(false)} returnFocus={returnFocus.current} />
      )}
    </>
  );
}

function PaletteDialog({
  onClose,
  returnFocus,
}: {
  onClose: () => void;
  returnFocus: HTMLElement | null;
}) {
  const navigate = useNavigate();
  const dialog = useRef<HTMLDialogElement>(null);
  const input = useRef<HTMLInputElement>(null);
  const closeButton = useRef<HTMLButtonElement>(null);
  const id = useId();
  const [search, setSearch] = useState("");
  const [highlighted, setHighlighted] = useState(0);
  // This component only mounts while open. Reuse the screen caches without polling.
  const flows = useQuery({ queryKey: ["flows"], queryFn: flowsList, retry: false });
  const models = useQuery({ queryKey: ["models", "list"], queryFn: modelsList, retry: false });
  const destinations: Destination[] = [
    ...pages,
    ...(flows.data?.flows ?? []).map((flow): Destination => ({
      id: `flow-${flow.id}`,
      label: flow.name,
      detail: `Flow · ${flow.id} · Open, never run`,
      to: "/flows",
      flow: flow.id,
    })),
    ...(models.data?.models ?? []).map((model): Destination => ({
      id: `model-${model.id}`,
      label: model.file_name,
      detail: `Model · ${model.vendor} · Open library`,
      to: "/models",
    })),
  ];
  const words = search.toLocaleLowerCase().trim().split(/\s+/);
  const results = destinations.filter((item) =>
    words.every((word) => `${item.label} ${item.detail}`.toLocaleLowerCase().includes(word)),
  );
  const selected = Math.min(highlighted, Math.max(0, results.length - 1));

  useEffect(() => {
    const element = dialog.current!;
    element.showModal();
    input.current?.focus();
    return () => {
      element.close();
      if (returnFocus?.isConnected) returnFocus.focus();
    };
  }, [returnFocus]);

  useEffect(() => {
    document.getElementById(`${id}-option-${selected}`)?.scrollIntoView({ block: "nearest" });
  }, [id, selected, search]);

  function choose(destination: Destination) {
    onClose();
    void navigate({
      to: destination.to,
      hash: destination.hash ?? "",
      search: destination.flow ? { flow: destination.flow } : {},
    });
  }

  function keyDown(event: KeyboardEvent) {
    if (event.nativeEvent.isComposing) return;
    if (event.key === "Escape") {
      event.preventDefault();
      event.stopPropagation();
      onClose();
    } else if (event.key === "Tab") {
      // Only the search field and dismiss button are tab stops; options use arrows.
      event.preventDefault();
      if (document.activeElement === input.current) closeButton.current?.focus();
      else input.current?.focus();
    } else if (document.activeElement === input.current) {
      if (event.key === "ArrowDown" || event.key === "ArrowUp") {
        event.preventDefault();
        const direction = event.key === "ArrowDown" ? 1 : -1;
        setHighlighted((selected + direction + results.length) % Math.max(1, results.length));
      } else if (event.key === "Enter" && results[selected]) {
        event.preventDefault();
        choose(results[selected]);
      }
    }
  }

  return createPortal(
    <dialog
      ref={dialog}
      aria-labelledby={`${id}-title`}
      aria-describedby={`${id}-hint`}
      aria-modal="true"
      className="m-auto w-full max-w-xl overflow-hidden rounded-panel border border-line bg-surface p-0 text-ink shadow-lg backdrop:bg-black/50"
      onKeyDown={keyDown}
      onCancel={(event) => {
        event.preventDefault();
        onClose();
      }}
      onClick={(event) => {
        if (event.target === event.currentTarget) onClose();
      }}
    >
      <div className="flex items-center justify-between px-4 pt-3">
        <h2 id={`${id}-title`} className="text-sm font-semibold">
          Jump to
        </h2>
        <button
          ref={closeButton}
          type="button"
          aria-label="Close command palette"
          onClick={onClose}
          className="rounded-control p-2 text-ink-muted hover:bg-accent-soft hover:text-ink"
        >
          <X size={16} aria-hidden="true" />
        </button>
      </div>
      <div className="mx-4 mb-3 flex items-center gap-2 rounded-control border border-control-line bg-surface-raised px-3">
        <Search size={16} className="shrink-0 text-ink-muted" aria-hidden="true" />
        <input
          ref={input}
          role="combobox"
          aria-label="Search pages, settings, flows, and models"
          aria-expanded="true"
          aria-controls={`${id}-results`}
          aria-autocomplete="list"
          aria-activedescendant={results.length ? `${id}-option-${selected}` : undefined}
          placeholder="Search pages, settings, flows, models…"
          className="h-11 min-w-0 flex-1 bg-transparent text-sm text-ink outline-none"
          value={search}
          onChange={(event) => {
            setSearch(event.target.value);
            setHighlighted(0);
          }}
        />
      </div>
      <div
        id={`${id}-results`}
        role="listbox"
        aria-label="Destinations"
        className="max-h-80 overflow-y-auto border-t border-line p-2"
      >
        {results.map((destination, index) => (
          <div
            key={destination.id}
            id={`${id}-option-${index}`}
            role="option"
            aria-selected={selected === index}
            onMouseMove={() => setHighlighted(index)}
            onClick={() => choose(destination)}
            className={`flex cursor-pointer items-center justify-between gap-3 rounded-control px-3 py-2 ${selected === index ? "bg-accent-soft text-accent" : "text-ink"}`}
          >
            <span className="min-w-0">
              <span className="block truncate text-sm font-medium">{destination.label}</span>
              <span className="block truncate text-xs text-ink-muted">
                {destination.detail}
              </span>
            </span>
            <ArrowUpRight size={15} aria-hidden="true" className="shrink-0 text-ink-faint" />
          </div>
        ))}
        {!results.length && (
          <p role="status" className="px-3 py-6 text-sm text-ink-muted">
            No matching destinations.
          </p>
        )}
      </div>
      <div className="space-y-1 border-t border-line px-4 py-3 text-xs text-ink-muted">
        <p id={`${id}-hint`}>
          ↑↓ to navigate · Enter to open · Esc to close. Nothing runs here.
        </p>
        {(flows.isError || models.isError) && (
          <p role="status">
            Some library entries are unavailable. Pages and settings still work.
          </p>
        )}
      </div>
    </dialog>,
    document.body,
  );
}
