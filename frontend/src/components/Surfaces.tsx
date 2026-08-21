import { ArrowClockwise, WarningCircle, X } from "@phosphor-icons/react";
import {
  type CSSProperties,
  type ReactNode,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import {
  Button,
  Dialog,
  Heading,
  Input,
  ListBox,
  ListBoxItem,
  Modal,
  ModalOverlay,
  SearchField,
} from "react-aria-components";
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
  return (
    <ModalOverlay
      className="application-overlay application-overlay--drawer"
      data-application-overlay-layer={active ? "active" : "underlay"}
      isOpen
      isDismissable={active}
      isKeyboardDismissDisabled={!active}
      aria-hidden={active ? undefined : true}
      inert={active ? undefined : true}
      onOpenChange={(isOpen) => { if (!isOpen && active) onClose(); }}
    >
      <Modal className="drawer-modal">
        <Dialog className="drawer">
          {({ close }) => (
            <>
              <header>
                <div><span className="eyebrow">{eyebrow}</span><Heading slot="title" level={2}>{title}</Heading></div>
                <Button className="drawer-close" autoFocus={active} aria-label={`Close ${title}`} onPress={() => { if (active) close(); }}><X size={21} weight="bold" /></Button>
              </header>
              <div className="drawer-body">{children}</div>
            </>
          )}
        </Dialog>
      </Modal>
    </ModalOverlay>
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
  onAction: (id: string) => void;
  onClose: () => void;
}

export function CommandPalette({ commands, active, onAction, onClose }: CommandPaletteProps) {
  const [query, setQuery] = useState("");
  const commandListRef = useRef<HTMLDivElement>(null);
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

  return (
    <ModalOverlay
      className="application-overlay application-overlay--command"
      data-application-overlay-layer={active ? "active" : "underlay"}
      isOpen
      isDismissable={active}
      isKeyboardDismissDisabled={!active}
      aria-hidden={active ? undefined : true}
      inert={active ? undefined : true}
      onOpenChange={(isOpen) => { if (!isOpen && active) onClose(); }}
    >
      <Modal className="command-modal">
        <Dialog className="command-dialog" aria-label="Command palette">
          <SearchField
            className="command-search"
            value={query}
            onChange={setQuery}
            aria-label="Search commands"
            autoFocus={active}
            onKeyDown={(event) => {
              if (event.key !== "ArrowDown" && event.key !== "ArrowUp") return;
              const options = commandListRef.current?.querySelectorAll<HTMLElement>('[role="option"]:not([aria-disabled="true"])');
              const target = event.key === "ArrowDown" ? options?.[0] : options?.[options.length - 1];
              if (!target) return;
              event.preventDefault();
              target.focus();
            }}
          >
            <Input className="command-input" placeholder="Search commands…" />
          </SearchField>
          <ListBox
            ref={commandListRef}
            className="command-options"
            aria-label="Commands"
            items={filteredCommands}
            renderEmptyState={() => <p className="command-empty">No matching commands.</p>}
          >
            {(command) => (
              <ListBoxItem className="command-option" id={command.id} textValue={command.label} onAction={() => run(command)}>
                <span className="command-option-copy">
                  <strong>{command.label}</strong>
                  <small>{command.description}</small>
                </span>
                {command.shortcut && <kbd>{command.shortcut}</kbd>}
              </ListBoxItem>
            )}
          </ListBox>
        </Dialog>
      </Modal>
    </ModalOverlay>
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
