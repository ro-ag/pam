import { ArrowClockwise, WarningCircle, X } from "@phosphor-icons/react";
import { Dialog, ScrollArea, VisuallyHidden } from "radix-ui";
import {
  type CSSProperties,
  type ReactNode,
  useEffect,
  useId,
  useMemo,
  useRef,
  useState,
} from "react";
import type { ApprovalDecision, EvidenceDataDto } from "../domain";
import { MAX_EVIDENCE_TEXT } from "../domain";
import type { ControlCenterView } from "../selectors";

export interface DrawerProps {
  title: string;
  eyebrow: string;
  onClose: () => void;
  children: ReactNode;
  active?: boolean;
  returnFocusTarget?: HTMLElement | null;
}

export function Drawer({ title, eyebrow, onClose, children, active = true, returnFocusTarget }: DrawerProps) {
  const titleId = useId();
  const returnFocus = useRef<HTMLElement | null>(returnFocusTarget ?? (active && document.activeElement instanceof HTMLElement ? document.activeElement : null));
  const activeRef = useRef(active);
  activeRef.current = active;
  useEffect(() => {
    return () => {
      const target = returnFocus.current;
      if (activeRef.current && target?.isConnected) {
        target.focus();
        requestAnimationFrame(() => {
          if (!target.isConnected) return;
          target.focus();
          requestAnimationFrame(() => {
            if (target.isConnected) target.focus();
          });
        });
      }
    };
  }, []);
  const content = (
    <div className="drawer">
      <VisuallyHidden.Root><Dialog.Description>{eyebrow}</Dialog.Description></VisuallyHidden.Root>
      <header>
        <div><span className="eyebrow">{eyebrow}</span><Dialog.Title id={titleId}>{title}</Dialog.Title></div>
        <Dialog.Close asChild>
          <button className="drawer-close" type="button" aria-label={`Close ${title}`}><X size={21} weight="bold" /></button>
        </Dialog.Close>
      </header>
      <ScrollArea.Root className="drawer-body">
        <ScrollArea.Viewport className="drawer-scroll-viewport">{children}</ScrollArea.Viewport>
        <ScrollArea.Scrollbar className="scrollbar" orientation="vertical"><ScrollArea.Thumb className="scrollbar-thumb" /></ScrollArea.Scrollbar>
      </ScrollArea.Root>
    </div>
  );

  if (!active) {
    return (
      <Dialog.Root open={false}>
        <div className="application-overlay application-overlay--drawer" data-application-overlay-layer="underlay" aria-hidden inert>
          <div className="drawer-modal" role="dialog" aria-labelledby={titleId}>{content}</div>
        </div>
      </Dialog.Root>
    );
  }

  return (
    <Dialog.Root open onOpenChange={(isOpen) => { if (!isOpen) onClose(); }}>
      <Dialog.Portal>
        <Dialog.Overlay className="application-overlay application-overlay--drawer" />
        <Dialog.Content
          className="drawer-modal"
          data-application-overlay-layer="active"
          aria-labelledby={titleId}
          onCloseAutoFocus={(event) => {
            event.preventDefault();
            if (returnFocus.current?.isConnected) returnFocus.current.focus();
          }}
        >
          {content}
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}

export interface EvidenceDrawerProps {
  document: EvidenceDataDto | null;
  loading: boolean;
  error: string | null;
  onRetry?: () => void;
  onClose: () => void;
  active?: boolean;
}

export function EvidenceDrawer({ document, loading, error, onRetry, onClose, active = true }: EvidenceDrawerProps) {
  return (
    <Drawer title="Evidence" eyebrow="Exact bounded source" active={active} onClose={onClose}>
      {loading && <div className="drawer-message" role="status" aria-live="polite"><ArrowClockwise className="is-spinning" size={23} /><p>Loading retained evidence…</p></div>}
      {error && <div className="drawer-message is-error" role="alert"><WarningCircle size={23} /><p>{error}</p>{onRetry && <button type="button" className="button button--secondary" onClick={onRetry}><ArrowClockwise size={18} /> Retry evidence</button>}</div>}
      {document && <article className="evidence-document"><code>{document.handle}</code><h3>{document.truth}</h3><p>{document.mediaType} · {document.sizeBytes.toLocaleString()} bytes · {document.digest}{document.truncated ? " · bounded preview" : ""}</p><pre>{(document.body ?? "This evidence has no text preview.").slice(0, MAX_EVIDENCE_TEXT)}</pre></article>}
    </Drawer>
  );
}

export interface QueueDrawerProps {
  data: ControlCenterView;
  onClose: () => void;
  active?: boolean;
  returnFocusTarget?: HTMLElement | null;
}

export function QueueDrawer({ data, onClose, active = true, returnFocusTarget }: QueueDrawerProps) {
  return (
    <Drawer title="Project queue" eyebrow={`${data.current.queue.length} retained request${data.current.queue.length === 1 ? "" : "s"}`} active={active} returnFocusTarget={returnFocusTarget} onClose={onClose}>
      <div className="queue-list">
        {data.current.queue.length === 0 ? <p className="panel-empty">Nothing is queued for this project.</p> : data.current.queue.map((item, index) => (
          <article key={item.requestId}><span>{index + 1}</span><div><strong>{item.operationKind}</strong><code>{item.requestId}</code></div><span className={`state-pill state-pill--${item.state}`}>{item.state}</span></article>
        ))}
        {data.current.queueTruncated && <p className="bounded-note">Only the bounded queue window is shown.</p>}
      </div>
    </Drawer>
  );
}

export interface ApprovalDrawerProps {
  data: ControlCenterView;
  busy: boolean;
  error: string | null;
  onDecision: (decision: ApprovalDecision) => void;
  onClose: () => void;
  active?: boolean;
}

export function ApprovalDrawer({ data, busy, error, onDecision, onClose, active = true }: ApprovalDrawerProps) {
  const approval = data.current.approval;
  if (!approval) return null;
  return (
    <Drawer title="Approval required" eyebrow="Bounded project effect" active={active} onClose={onClose}>
      <article className="approval-card" aria-busy={busy}><WarningCircle size={28} /><h3>{approval.title}</h3><p>{approval.reason}</p>{error && <p className="approval-error" role="alert">{error}</p>}<dl><div><dt>Effect</dt><dd>{approval.effect}</dd></div><div><dt>Project</dt><dd>{approval.projectName}</dd></div><div><dt>Policy / capability</dt><dd>{approval.policyCapability}</dd></div><div><dt>Expires</dt><dd>{approval.expiresAt}</dd></div><div><dt>Request handle</dt><dd><code>{approval.approvalHandle}</code></dd></div></dl>{busy && <p role="status">Applying the exact decision…</p>}<div><button type="button" className="button button--secondary" disabled={busy} onClick={() => onDecision("deny")}>Deny</button><button type="button" className="button button--primary" disabled={busy} onClick={() => onDecision("approve")}>Approve exact request</button></div></article>
    </Drawer>
  );
}

export interface CommandPaletteCommand {
  id: string;
  label: string;
  description: string;
  shortcut?: string;
}

export interface CommandPaletteProps {
  commands: CommandPaletteCommand[];
  active: boolean;
  returnFocusTarget?: HTMLElement | null;
  onAction: (id: string) => void;
  onClose: () => void;
}

export function CommandPalette({ commands, active, returnFocusTarget, onAction, onClose }: CommandPaletteProps) {
  const [query, setQuery] = useState("");
  const commandListRef = useRef<HTMLDivElement>(null);
  const searchRef = useRef<HTMLInputElement>(null);
  const returnFocus = useRef<HTMLElement | null>(returnFocusTarget ?? (active && document.activeElement instanceof HTMLElement ? document.activeElement : null));
  useEffect(() => () => {
    const target = returnFocus.current;
    if (!target?.isConnected) return;
    target.focus();
    requestAnimationFrame(() => { if (target.isConnected) target.focus(); });
  }, []);
  const filteredCommands = useMemo(() => {
    const needle = query.trim().toLocaleLowerCase();
    if (!needle) return commands;
    return commands.filter((command) => (
      [command.id, command.label, command.description, command.shortcut]
        .some((value) => value?.toLocaleLowerCase().includes(needle))
    ));
  }, [commands, query]);
  const run = (command: CommandPaletteCommand) => {
    onAction(command.id);
  };

  const moveOptionFocus = (current: HTMLElement | null, direction: 1 | -1) => {
    const options = Array.from(commandListRef.current?.querySelectorAll<HTMLElement>('[role="option"]') ?? []);
    if (options.length === 0) return;
    const index = current ? options.indexOf(current) : direction > 0 ? -1 : 0;
    options[(index + direction + options.length) % options.length]?.focus();
  };

  const dialog = (
    <Dialog.Content
      className="command-modal"
      aria-label="Command palette"
      onOpenAutoFocus={(event) => {
        event.preventDefault();
        searchRef.current?.focus();
      }}
    >
      <VisuallyHidden.Root><Dialog.Title>Command palette</Dialog.Title></VisuallyHidden.Root>
      <VisuallyHidden.Root><Dialog.Description>Search and run a PAM command.</Dialog.Description></VisuallyHidden.Root>
      <div className="command-dialog">
        <input
          ref={searchRef}
          className="command-input"
          type="search"
          value={query}
          placeholder="Search commands…"
          aria-label="Search commands"
          onChange={(event) => setQuery(event.currentTarget.value)}
          onKeyDown={(event) => {
            if (event.key !== "ArrowDown" && event.key !== "ArrowUp") return;
            event.preventDefault();
            moveOptionFocus(null, event.key === "ArrowDown" ? 1 : -1);
          }}
        />
        <div ref={commandListRef} className="command-options" role="listbox" aria-label="Commands">
          {filteredCommands.length === 0 ? <p className="command-empty">No matching commands.</p> : filteredCommands.map((command) => (
            <button
              className="command-option"
              type="button"
              role="option"
              aria-selected="false"
              key={command.id}
              onClick={() => run(command)}
              onKeyDown={(event) => {
                if (event.key === "ArrowDown" || event.key === "ArrowUp") {
                  event.preventDefault();
                  moveOptionFocus(event.currentTarget, event.key === "ArrowDown" ? 1 : -1);
                } else if (event.key === "Home" || event.key === "End") {
                  event.preventDefault();
                  const options = commandListRef.current?.querySelectorAll<HTMLElement>('[role="option"]');
                  (event.key === "Home" ? options?.[0] : options?.[options.length - 1])?.focus();
                }
              }}
            >
              <span className="command-option-copy">
                <strong>{command.label}</strong>
                <small>{command.description}</small>
              </span>
              {command.shortcut && <kbd>{command.shortcut}</kbd>}
            </button>
          ))}
        </div>
      </div>
    </Dialog.Content>
  );

  return (
    <Dialog.Root open={active} onOpenChange={(isOpen) => { if (!isOpen && active) onClose(); }}>
      <Dialog.Portal>
        <Dialog.Overlay className="application-overlay application-overlay--command" data-application-overlay-layer={active ? "active" : "underlay"} />
        {dialog}
      </Dialog.Portal>
    </Dialog.Root>
  );
}

export interface StartupShellProps {
  children: ReactNode;
}

type StartupShellStyle = CSSProperties & { "--sidebar-size": string };

const startupShellStyle: StartupShellStyle = { "--sidebar-size": "68px" };

export function StartupShell({ children }: StartupShellProps) {
  return (
    <div className="app-shell startup-shell" style={startupShellStyle}>
      <div className="atmosphere" aria-hidden="true" />
      <aside className="sidebar is-collapsed startup-sidebar" aria-label="PAM identity">
        <div className="brand" aria-label="PAM"><img src="/assets/pam-mark.png" alt="" /></div>
      </aside>
      <div className="resize-separator startup-separator" aria-hidden="true" />
      <section className="workspace startup-workspace">
        <header className="toolbar startup-toolbar"><div className="breadcrumb"><strong>PAM</strong></div></header>
        <main className="canvas startup-body" id="main-content">{children}</main>
      </section>
    </div>
  );
}

export type LoadingScreenProps = Record<string, never>;

export function LoadingScreen(_props: LoadingScreenProps) {
  return (
    <StartupShell>
      <section className="empty-state state-card startup-state-card" role="status" aria-live="polite" aria-busy="true">
        <h1>PAM</h1>
        <p>Finding the last registered project…</p>
      </section>
    </StartupShell>
  );
}

export interface RecoveryScreenProps {
  message: string;
  onRetry: () => void;
}

export function RecoveryScreen({ message, onRetry }: RecoveryScreenProps) {
  return (
    <StartupShell>
      <section className="empty-state state-card startup-state-card is-attention" role="alert">
        <WarningCircle size={38} />
        <h1>PAM needs a moment</h1>
        <p>{message}</p>
        <button type="button" className="button button--primary" onClick={onRetry}><ArrowClockwise size={18} /> Retry safely</button>
      </section>
    </StartupShell>
  );
}
