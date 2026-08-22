import { WarningCircle } from "@phosphor-icons/react";
import { AnimatePresence, MotionConfig, motion } from "motion/react";
import { Tooltip } from "radix-ui";
import {
  type CSSProperties,
  useCallback,
  useEffect,
  useReducer,
  useRef,
  useState,
} from "react";
import { nextOperationId, sameFence, withOperation } from "./bridge";
import type {
  ApprovalDecision,
  CommandFence,
  PamBridge,
  SnapshotDto,
  ViewId,
} from "./domain";
import { MAX_EVIDENCE_TEXT } from "./domain";
import {
  clampSidebarWidth,
  readPersistedSidebarCollapsed,
  readPersistedSidebarWidth,
  writePersistedSidebarCollapsed,
  writePersistedSidebarWidth,
  type LayoutStorage,
} from "./layout";
import type { AgentBriefView, ProjectView } from "./selectors";
import { selectControlCenter } from "./selectors";
import { ResizeSeparator, Sidebar, Toolbar } from "./components/Shell";
import {
  ApprovalDrawer,
  CommandPalette,
  type CommandPaletteCommand,
  EvidenceDrawer,
  LoadingScreen,
  QueueDrawer,
  RecoveryScreen,
} from "./components/Surfaces";
import { FlowsView } from "./views/FlowsView";
import { AccessView, CurrentView } from "./views/ProjectViews";
import { appReducer, initialState, presentError } from "./state";
import {
  applyPamTheme,
  readPersistedPamTheme,
  readPersistedPamThemeMode,
  writePersistedPamTheme,
  writePersistedPamThemeMode,
  type PamTheme,
  type PamThemeMode,
} from "./theme";
import {
  activeOverlay,
  createOverlayState,
  loadingEvidenceEntry,
  overlayLayer,
  overlayReducer,
  overlayStateForAuthority,
  type OverlayAuthority,
  type OverlayEntry,
} from "./overlays";

interface AppProps {
  bridge: PamBridge;
  initialView?: ViewId;
  initialTheme?: PamTheme;
  initialThemeMode?: PamThemeMode;
}

interface InitialLayout {
  viewportWidth: number;
  compactViewport: boolean;
  desktopSidebarCollapsed: boolean;
  sidebarWidth: number;
  storage: LayoutStorage | null;
}

type ShellStyle = CSSProperties & { "--sidebar-size": string };

function availableStorage(): LayoutStorage | null {
  try {
    return window.localStorage;
  } catch {
    return null;
  }
}

function readInitialLayout(): InitialLayout {
  const viewportWidth = window.innerWidth;
  const compactViewport = window.matchMedia("(max-width: 780px)").matches;
  const storage = availableStorage();
  const desktopSidebarCollapsed = readPersistedSidebarCollapsed(storage);
  return {
    viewportWidth,
    compactViewport,
    desktopSidebarCollapsed,
    sidebarWidth: readPersistedSidebarWidth(storage, viewportWidth),
    storage,
  };
}

function briefText(brief: AgentBriefView): string {
  return [
    brief.title,
    ...brief.sections.map((section) => `${section.label}: ${section.summary}`),
  ].join("\n");
}

function acceptsResponseFence(requestFence: CommandFence, responseFence: CommandFence): boolean {
  return sameFence(requestFence, responseFence) || (
    requestFence.generation === "" &&
    requestFence.projectHandle === responseFence.projectHandle &&
    requestFence.operationId === responseFence.operationId
  );
}

function sameAuthority(left: CommandFence, right: CommandFence): boolean {
  return left.projectHandle === right.projectHandle && left.generation === right.generation;
}

export function App({ bridge, initialView = "current", initialTheme, initialThemeMode }: AppProps) {
  const [initialLayout] = useState(readInitialLayout);
  const [theme, setTheme] = useState<PamTheme>(() => initialTheme ?? readPersistedPamTheme(initialLayout.storage));
  const [themeMode, setThemeMode] = useState<PamThemeMode>(() => initialThemeMode ?? readPersistedPamThemeMode(initialLayout.storage));
  const [viewportWidth, setViewportWidth] = useState(initialLayout.viewportWidth);
  const [compactViewport, setCompactViewport] = useState(initialLayout.compactViewport);
  const [state, dispatch] = useReducer(appReducer, {
    ...initialState,
    activeView: initialView,
    sidebarWidth: initialLayout.sidebarWidth,
    sidebarCollapsed: compactViewport ? true : initialLayout.desktopSidebarCollapsed,
  });
  const [overlays, dispatchOverlay] = useReducer(overlayReducer, null, createOverlayState);
  const [toast, setToast] = useState("");
  const toastTimer = useRef<number | null>(null);
  const evidenceRequestSequence = useRef(0);
  const dataCommandSequence = useRef(0);
  const bootstrapRequestSequence = useRef(0);
  const sidebarRef = useRef<HTMLElement>(null);
  const sidebarToggleRef = useRef<HTMLButtonElement>(null);
  const commandButtonRef = useRef<HTMLButtonElement>(null);
  const queueButtonRef = useRef<HTMLButtonElement>(null);
  const commandReturnFocusRef = useRef<HTMLElement | null>(null);
  const queueReturnFocusRef = useRef<HTMLElement | null>(null);
  const storageRef = useRef(initialLayout.storage);
  const desktopSidebarCollapsedRef = useRef(initialLayout.desktopSidebarCollapsed);
  const previousCompactViewportRef = useRef(initialLayout.compactViewport);
  const fenceRef = useRef(state.activeFence);
  fenceRef.current = state.activeFence;
  const overlayAuthority: OverlayAuthority | null = state.activeFence
    ? {
        projectHandle: state.activeFence.projectHandle,
        generation: state.activeFence.generation,
      }
    : null;
  const approvalHandle = state.data?.current.status === "approval_required"
    ? state.data.current.approval
    : null;
  const approvalKey = overlayAuthority && approvalHandle
    ? `${overlayAuthority.projectHandle}:${overlayAuthority.generation}:${approvalHandle}`
    : null;
  const effectiveOverlays = overlayStateForAuthority(overlays, overlayAuthority);

  useEffect(() => {
    dispatchOverlay({ type: "authority-changed", authority: overlayAuthority });
  }, [overlayAuthority?.generation, overlayAuthority?.projectHandle]);

  useEffect(() => {
    dispatchOverlay({
      type: "sync-approval",
      entry: overlayAuthority && approvalKey
        ? {
            id: `approval:${approvalKey}`,
            kind: "approval",
            authority: overlayAuthority,
            approvalKey,
          }
        : null,
    });
  }, [approvalKey, overlayAuthority?.generation, overlayAuthority?.projectHandle]);

  useEffect(() => () => {
    if (toastTimer.current) window.clearTimeout(toastTimer.current);
  }, []);

  useEffect(() => applyPamTheme(theme, themeMode), [theme, themeMode]);

  useEffect(() => {
    const query = window.matchMedia("(max-width: 780px)");
    const update = () => {
      setViewportWidth(window.innerWidth);
      setCompactViewport(query.matches);
    };
    window.addEventListener("resize", update);
    query.addEventListener("change", update);
    return () => {
      window.removeEventListener("resize", update);
      query.removeEventListener("change", update);
    };
  }, []);

  useEffect(() => {
    const wasCompact = previousCompactViewportRef.current;
    let reconciledCollapsed = state.sidebarCollapsed;
    if (!wasCompact && compactViewport) reconciledCollapsed = true;
    else if (wasCompact && !compactViewport) reconciledCollapsed = desktopSidebarCollapsedRef.current;

    const clampedWidth = clampSidebarWidth(state.sidebarWidth, viewportWidth);
    if (clampedWidth !== state.sidebarWidth) {
      dispatch({ type: "resizeSidebar", width: clampedWidth, viewportWidth });
      dispatch({ type: "setSidebarCollapsed", collapsed: reconciledCollapsed });
    } else if (reconciledCollapsed !== state.sidebarCollapsed) {
      dispatch({ type: "setSidebarCollapsed", collapsed: reconciledCollapsed });
    }
    previousCompactViewportRef.current = compactViewport;
  }, [compactViewport, state.sidebarCollapsed, state.sidebarWidth, viewportWidth]);

  const showToast = useCallback((message: string) => {
    setToast(message);
    if (toastTimer.current) window.clearTimeout(toastTimer.current);
    toastTimer.current = window.setTimeout(() => setToast(""), 2600);
  }, []);

  const selectTheme = useCallback((nextTheme: PamTheme) => {
    applyPamTheme(nextTheme, themeMode);
    setTheme(nextTheme);
    writePersistedPamTheme(storageRef.current, nextTheme);
  }, [themeMode]);

  const selectThemeMode = useCallback((nextMode: PamThemeMode) => {
    applyPamTheme(theme, nextMode);
    setThemeMode(nextMode);
    writePersistedPamThemeMode(storageRef.current, nextMode);
  }, [theme]);

  const bootstrap = useCallback(async () => {
    const sequence = ++bootstrapRequestSequence.current;
    dataCommandSequence.current += 1;
    dispatch({ type: "retry" });
    try {
      const [response, catalog] = await Promise.all([bridge.bootstrap(), bridge.catalog()]);
      if (sequence !== bootstrapRequestSequence.current) return;
      dispatch({ type: "bootstrapSucceeded", response, catalog });
    } catch (error) {
      if (sequence !== bootstrapRequestSequence.current) return;
      const syntheticFence = { projectHandle: "bootstrap", generation: "", operationId: "bootstrap" };
      dispatch({ type: "commandStarted", fence: syntheticFence });
      dispatch({ type: "commandFailed", fence: syntheticFence, message: presentError(error) });
    }
  }, [bridge]);

  useEffect(() => { void bootstrap(); }, [bootstrap]);

  const executeDataCommand = useCallback(async (
    fence: CommandFence,
    command: () => Promise<SnapshotDto>,
    successMessage?: string,
  ) => {
    const sequence = ++dataCommandSequence.current;
    dispatch({ type: "commandStarted", fence });
    try {
      const response = await command();
      if (sequence !== dataCommandSequence.current) return false;
      if (!acceptsResponseFence(fence, response.fence)) {
        dispatch({ type: "commandFailed", fence, message: "The command response did not match the latest project operation. Retry safely." });
        return false;
      }
      dispatch({ type: "commandSucceeded", response });
      if (successMessage) showToast(successMessage);
      return true;
    } catch (error) {
      if (sequence !== dataCommandSequence.current) return false;
      dispatch({ type: "commandFailed", fence, message: presentError(error) });
      return false;
    }
  }, [showToast]);

  const refresh = useCallback(() => {
    if (!fenceRef.current) return;
    const fence = withOperation(fenceRef.current);
    void executeDataCommand(fence, () => bridge.refreshProject(fence), "Project state refreshed");
  }, [bridge, executeDataCommand]);

  const mobileSidebarOpen = compactViewport && !state.sidebarCollapsed;
  const toggleSidebar = useCallback(() => {
    const opening = state.sidebarCollapsed;
    const nextCollapsed = !state.sidebarCollapsed;
    dispatch({ type: "toggleSidebar" });
    if (!compactViewport) {
      desktopSidebarCollapsedRef.current = nextCollapsed;
      writePersistedSidebarCollapsed(storageRef.current, nextCollapsed);
      return;
    }
    window.requestAnimationFrame(() => {
      if (opening) sidebarRef.current?.querySelector<HTMLElement>("button:not(:disabled)")?.focus();
      else sidebarToggleRef.current?.focus();
    });
  }, [compactViewport, state.sidebarCollapsed]);

  const previewSidebarWidth = useCallback((width: number) => {
    dispatch({ type: "resizeSidebar", width, viewportWidth });
  }, [viewportWidth]);

  const commitSidebarWidth = useCallback((width: number) => {
    dispatch({ type: "resizeSidebar", width, viewportWidth });
    writePersistedSidebarWidth(storageRef.current, width, viewportWidth);
  }, [viewportWidth]);

  const closeActiveOverlay = useCallback(() => {
    const current = activeOverlay(effectiveOverlays);
    if (current?.kind === "evidence") evidenceRequestSequence.current += 1;
    dispatchOverlay({ type: "close-top" });
  }, [effectiveOverlays]);

  const openOverlay = useCallback((entry: OverlayEntry, replaceTop = false, reopenApproval = false) => {
    const current = activeOverlay(effectiveOverlays);
    if (replaceTop || current?.kind === "project") {
      dispatchOverlay({ type: "replace-top", entry });
    } else {
      dispatchOverlay({ type: "open", entry, reopenApproval });
    }
  }, [effectiveOverlays]);

  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      if ((event.metaKey || event.ctrlKey) && !event.shiftKey && !event.altKey) {
        if (event.key.toLowerCase() === "k") {
          event.preventDefault();
          if (overlayAuthority && !activeOverlay(effectiveOverlays)) {
            commandReturnFocusRef.current = commandButtonRef.current;
            openOverlay({ id: "command", kind: "command", authority: overlayAuthority });
          }
          return;
        }
        if (activeOverlay(effectiveOverlays)) return;
        const view = event.key === "1" ? "current" : event.key === "2" ? "flows" : event.key === "3" ? "access" : null;
        if (view) { event.preventDefault(); dispatch({ type: "navigate", view }); }
        if (event.key.toLowerCase() === "r") { event.preventDefault(); refresh(); }
      }
      if (event.key === "Escape" && !activeOverlay(effectiveOverlays) && mobileSidebarOpen) toggleSidebar();
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [effectiveOverlays, mobileSidebarOpen, openOverlay, overlayAuthority, refresh, toggleSidebar]);

  if (state.loadState === "loading" && !state.data) return <LoadingScreen />;
  if (!state.data || !state.catalog || !state.activeFence) return <RecoveryScreen message={state.error ?? "The project control center is unavailable."} onRetry={() => void bootstrap()} />;

  const data = selectControlCenter(state.data, state.catalog, bridge.mode === "fixture");
  const pending = state.pendingFence !== null;
  const selectProject = (project: ProjectView) => {
    if (project.handle === data.project.handle) return;
    const operationId = nextOperationId();
    const pendingFence = { projectHandle: project.handle, generation: "", operationId };
    void executeDataCommand(pendingFence, () => bridge.activateProject(project.handle, operationId), `Now watching ${project.name}`);
    if (mobileSidebarOpen) toggleSidebar();
  };
  const toggleDaemon = () => {
    const fence = withOperation(state.activeFence!);
    const stopping = data.daemon.state === "running";
    void executeDataCommand(fence, () => stopping ? bridge.stopDaemon(fence) : bridge.startDaemon(fence), stopping ? "PAM is paused" : "PAM is back on watch");
  };
  const registerGuiCaller = () => {
    const fence = withOperation(state.activeFence!);
    void executeDataCommand(
      fence,
      () => bridge.registerGuiCaller(fence).catch(() => {
        throw new Error("GUI caller registration could not be completed. Retry from this screen.");
      }),
      "GUI caller registered",
    );
  };
  const loadEvidence = async (handle: string) => {
    if (!fenceRef.current || !overlayAuthority) return;
    const requestId = ++evidenceRequestSequence.current;
    const fence = withOperation(fenceRef.current);
    const entryId = `evidence:${handle}`;
    const identity = { entryId, requestId, handle, authority: overlayAuthority };
    openOverlay(loadingEvidenceEntry({ id: entryId, requestId, handle, authority: overlayAuthority }));
    try {
      const response = await bridge.loadEvidence(fence, handle);
      if (requestId !== evidenceRequestSequence.current || !fenceRef.current || !sameAuthority(fence, fenceRef.current)) return;
      if (!sameFence(fence, response.fence)) {
        dispatchOverlay({
          type: "evidence-failed",
          ...identity,
          error: "The active project changed. Reopen this evidence from the refreshed outcome.",
          retryable: false,
        });
        return;
      }
      dispatchOverlay({
        type: "evidence-loaded",
        ...identity,
        document: { ...response.data, body: response.data.body?.slice(0, MAX_EVIDENCE_TEXT) ?? null },
      });
    } catch (error) {
      if (requestId !== evidenceRequestSequence.current || !fenceRef.current || !sameAuthority(fence, fenceRef.current)) return;
      dispatchOverlay({ type: "evidence-failed", ...identity, error: presentError(error) });
    }
  };
  const copyBrief = async (brief: AgentBriefView) => {
    try {
      await navigator.clipboard.writeText(briefText(brief));
      showToast("Agent brief copied");
    } catch {
      showToast("Clipboard access is unavailable");
    }
  };
  const decide = async (decision: ApprovalDecision) => {
    const approval = data.current.approval;
    if (!approval) return;
    const fence = withOperation(state.activeFence!);
    const sequence = ++dataCommandSequence.current;
    dispatch({ type: "commandStarted", fence });
    try {
      const response = await bridge.decideApproval(fence, approval.approvalHandle, decision);
      if (sequence !== dataCommandSequence.current) return;
      if (!acceptsResponseFence(fence, response.snapshot.fence)) {
        dispatch({ type: "commandFailed", fence, message: "The approval response did not match the latest project operation. Retry safely." });
        return;
      }
      dispatch({ type: "commandSucceeded", response: response.snapshot });
      showToast(response.disposition === "approved"
        ? "Exact request approved"
        : response.disposition === "denied"
          ? "Request denied"
          : "Approval expired; request a new challenge");
      closeActiveOverlay();
    } catch (error) {
      if (sequence !== dataCommandSequence.current) return;
      dispatch({ type: "commandFailed", fence, message: presentError(error) });
    }
  };

  const currentOverlay = activeOverlay(effectiveOverlays);
  const applicationOverlayOpen = currentOverlay !== null && currentOverlay.kind !== "project";
  const openQueue = (returnFocusTarget?: HTMLElement) => {
    if (!overlayAuthority) return;
    const activeElement = document.activeElement instanceof HTMLElement && document.activeElement !== document.body
      ? document.activeElement
      : null;
    queueReturnFocusRef.current = returnFocusTarget ?? activeElement ?? queueButtonRef.current;
    openOverlay({ id: "queue", kind: "queue", authority: overlayAuthority });
  };
  const openCommandPalette = (returnFocusTarget?: HTMLElement) => {
    if (!overlayAuthority || currentOverlay) return;
    commandReturnFocusRef.current = returnFocusTarget ?? commandButtonRef.current;
    openOverlay({ id: "command", kind: "command", authority: overlayAuthority });
  };
  const setProjectMenuOpen = (open: boolean) => {
    if (!overlayAuthority) return;
    if (open && !currentOverlay) {
      openOverlay({ id: "project", kind: "project", authority: overlayAuthority });
    } else if (!open) {
      dispatchOverlay({ type: "remove", entryId: "project" });
    }
  };
  const commands: CommandPaletteCommand[] = [
    { id: "view-current", label: "Open Current", description: "Show the selected project's durable activity.", shortcut: "⌘1" },
    { id: "view-flows", label: "Open Flows", description: "Show bounded project flow definitions.", shortcut: "⌘2" },
    { id: "view-access", label: "Open Access", description: "Show reported project capabilities.", shortcut: "⌘3" },
    { id: "open-queue", label: "Open project queue", description: "Inspect the bounded retained request window." },
    { id: "refresh", label: "Refresh project", description: "Request current state from PAM.", shortcut: "⌘R" },
  ];
  const runCommand = (id: string) => {
    const view = id === "view-current" ? "current" : id === "view-flows" ? "flows" : id === "view-access" ? "access" : null;
    if (view) {
      dispatch({ type: "navigate", view });
      closeActiveOverlay();
    } else if (id === "open-queue" && overlayAuthority) {
      queueReturnFocusRef.current = commandReturnFocusRef.current?.isConnected ? commandReturnFocusRef.current : null;
      openOverlay({ id: "queue", kind: "queue", authority: overlayAuthority }, true);
    } else if (id === "refresh") {
      closeActiveOverlay();
      refresh();
    }
  };

  const shellWidth = state.sidebarCollapsed ? 68 : state.sidebarWidth;
  const shellStyle: ShellStyle = { "--sidebar-size": `${shellWidth}px` };
  return (
    <MotionConfig reducedMotion="user">
      <Tooltip.Provider delayDuration={350} skipDelayDuration={150}>
      <div className="app-root" data-theme={theme} data-mode={themeMode}>
      <div className="app-shell" style={shellStyle} inert={applicationOverlayOpen || undefined} aria-hidden={applicationOverlayOpen || undefined}>
        <div className="atmosphere" aria-hidden="true" />
        <a className="skip-link" href="#main-content" tabIndex={mobileSidebarOpen ? -1 : undefined}>Skip to content</a>
        <Sidebar
          containerRef={sidebarRef}
          data={data}
          activeView={state.activeView}
          collapsed={state.sidebarCollapsed}
          pending={pending}
          projectMenuOpen={effectiveOverlays.stack.some(({ kind }) => kind === "project")}
          trapFocus={mobileSidebarOpen}
          onNavigate={(view) => { dispatch({ type: "navigate", view }); if (mobileSidebarOpen) toggleSidebar(); }}
          onProjectMenuOpenChange={setProjectMenuOpen}
          onSelectProject={selectProject}
          onToggleDaemon={toggleDaemon}
          onDismiss={toggleSidebar}
        />
        {mobileSidebarOpen && <button type="button" className="sidebar-scrim" aria-label="Close project sidebar" tabIndex={-1} onClick={toggleSidebar} />}
        <ResizeSeparator collapsed={state.sidebarCollapsed || compactViewport} width={state.sidebarWidth} viewportWidth={viewportWidth} onResizePreview={previewSidebarWidth} onResizeCommit={commitSidebarWidth} onToggle={toggleSidebar} />
        <section className="workspace" inert={mobileSidebarOpen || undefined} aria-hidden={mobileSidebarOpen || undefined}>
          <Toolbar toggleButtonRef={sidebarToggleRef} commandButtonRef={commandButtonRef} queueButtonRef={queueButtonRef} data={data} theme={theme} themeMode={themeMode} collapsed={state.sidebarCollapsed} pending={pending} onToggleSidebar={toggleSidebar} onOpenCommand={openCommandPalette} onRefresh={refresh} onOpenQueue={openQueue} onThemeChange={selectTheme} onThemeModeChange={selectThemeMode} />
          {state.loadState === "recovering" && state.error && <div className="inline-recovery" role="alert"><WarningCircle size={18} /><span>{state.error}</span><button type="button" onClick={refresh}>Retry</button></div>}
          <AnimatePresence mode="wait" initial={false}>
            <motion.div
              className="view-transition"
              key={state.activeView}
              initial={{ opacity: 0, y: 8 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -6 }}
              transition={{ duration: 0.24, ease: [0.33, 1, 0.68, 1] }}
            >
              {state.activeView === "current" && <CurrentView data={data} onCopy={(brief) => void copyBrief(brief)} onEvidence={(handle) => void loadEvidence(handle)} onContinue={() => { dispatch({ type: "navigate", view: "flows" }); showToast("Flow workspace opened"); }} onOpenQueue={openQueue} onOpenApproval={() => { if (approvalKey && overlayAuthority) openOverlay({ id: `approval:${approvalKey}`, kind: "approval", authority: overlayAuthority, approvalKey }, false, true); }} onRecoverDaemon={toggleDaemon} onRefresh={refresh} onRegisterCaller={registerGuiCaller} registrationBusy={pending} />}
              {state.activeView === "flows" && <FlowsView bridge={bridge} fence={state.activeFence} onError={showToast} onToast={showToast} />}
              {state.activeView === "access" && (
                <AccessView
                  key={`${state.activeFence.projectHandle}:${state.activeFence.generation}`}
                  data={data}
                  bridge={bridge}
                  fence={state.activeFence}
                />
              )}
            </motion.div>
          </AnimatePresence>
        </section>
      </div>
      {effectiveOverlays.stack.map((entry) => {
        if (entry.kind === "project") return null;
        const active = overlayLayer(effectiveOverlays, entry.id) === "active";
        if (entry.kind === "queue") return <QueueDrawer active={active} data={data} key={entry.id} returnFocusTarget={queueReturnFocusRef.current} onClose={closeActiveOverlay} />;
        if (entry.kind === "approval") {
          if (!data.current.approval || entry.approvalKey !== approvalKey) return null;
          return <ApprovalDrawer active={active} busy={pending} data={data} error={state.error} key={entry.id} onDecision={(decision) => { void decide(decision); }} onClose={closeActiveOverlay} />;
        }
        if (entry.kind === "evidence") {
          return <EvidenceDrawer active={active} document={entry.document} loading={entry.loading} error={entry.error} key={entry.id} onRetry={entry.retryable ? () => { void loadEvidence(entry.handle); } : undefined} onClose={closeActiveOverlay} />;
        }
        return <CommandPalette active={active} commands={commands} key={entry.id} returnFocusTarget={commandReturnFocusRef.current} onAction={runCommand} onClose={closeActiveOverlay} />;
      })}
      {toast && <div className="toast" role="status">{toast}</div>}
      </div>
      </Tooltip.Provider>
    </MotionConfig>
  );
}
