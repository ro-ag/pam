import type { EvidenceDataDto } from "./domain";

export interface OverlayAuthority {
  projectHandle: string;
  generation: string;
}

interface OverlayEntryBase {
  id: string;
  authority: OverlayAuthority;
}

export interface QueueOverlayEntry extends OverlayEntryBase {
  kind: "queue";
}

export interface ProjectOverlayEntry extends OverlayEntryBase {
  kind: "project";
}

export interface CommandOverlayEntry extends OverlayEntryBase {
  kind: "command";
}

export interface ApprovalOverlayEntry extends OverlayEntryBase {
  kind: "approval";
  approvalKey: string;
}

export interface EvidenceOverlayEntry extends OverlayEntryBase {
  kind: "evidence";
  handle: string;
  requestId: number;
  loading: boolean;
  document: EvidenceDataDto | null;
  error: string | null;
  retryable: boolean;
}

export type OverlayEntry =
  | ProjectOverlayEntry
  | QueueOverlayEntry
  | CommandOverlayEntry
  | ApprovalOverlayEntry
  | EvidenceOverlayEntry;

export interface OverlayState {
  authority: OverlayAuthority | null;
  stack: readonly OverlayEntry[];
  dismissedApprovalKeys: readonly string[];
}

export type OverlayLayer = "active" | "underlay";

interface EvidenceUpdateIdentity {
  entryId: string;
  requestId: number;
  handle: string;
  authority: OverlayAuthority;
}

export type OverlayAction =
  | { type: "authority-changed"; authority: OverlayAuthority | null }
  | { type: "sync-approval"; entry: ApprovalOverlayEntry | null }
  | { type: "open"; entry: OverlayEntry; reopenApproval?: boolean }
  | { type: "replace-top"; entry: OverlayEntry }
  | { type: "remove"; entryId: string; dismissApproval?: boolean }
  | { type: "close-top" }
  | ({ type: "evidence-loaded"; document: EvidenceDataDto } & EvidenceUpdateIdentity)
  | ({ type: "evidence-failed"; error: string; retryable?: boolean } & EvidenceUpdateIdentity);

export function createOverlayState(
  authority: OverlayAuthority | null = null,
): OverlayState {
  return { authority, stack: [], dismissedApprovalKeys: [] };
}

export function loadingEvidenceEntry({
  id,
  authority,
  handle,
  requestId,
}: {
  id: string;
  authority: OverlayAuthority;
  handle: string;
  requestId: number;
}): EvidenceOverlayEntry {
  return {
    id,
    kind: "evidence",
    authority,
    handle,
    requestId,
    loading: true,
    document: null,
    error: null,
    retryable: true,
  };
}

export function activeOverlay(state: OverlayState): OverlayEntry | null {
  return state.stack[state.stack.length - 1] ?? null;
}

export function overlayStateForAuthority(
  state: OverlayState,
  authority: OverlayAuthority | null,
): OverlayState {
  return sameAuthority(state.authority, authority)
    ? state
    : { ...state, authority, stack: [] };
}

export function overlayLayer(
  state: OverlayState,
  entryId: string,
): OverlayLayer | null {
  const index = state.stack.findIndex(({ id }) => id === entryId);
  if (index < 0) return null;
  return index === state.stack.length - 1 ? "active" : "underlay";
}

function sameAuthority(
  left: OverlayAuthority | null,
  right: OverlayAuthority | null,
): boolean {
  return left?.projectHandle === right?.projectHandle
    && left?.generation === right?.generation;
}

function canOpen(state: OverlayState, entry: OverlayEntry): boolean {
  return state.authority !== null
    && sameAuthority(state.authority, entry.authority)
    && (entry.kind !== "approval"
      || !state.dismissedApprovalKeys.includes(entry.approvalKey));
}

function withoutDuplicate(
  stack: readonly OverlayEntry[],
  entry: OverlayEntry,
): OverlayEntry[] {
  return stack.filter((candidate) => candidate.id !== entry.id
    && !(candidate.kind === "approval"
      && entry.kind === "approval"
      && candidate.approvalKey === entry.approvalKey));
}

function closeTop(state: OverlayState): OverlayState {
  const top = activeOverlay(state);
  if (!top) return state;
  const dismissedApprovalKeys = top.kind === "approval"
    && !state.dismissedApprovalKeys.includes(top.approvalKey)
    ? [...state.dismissedApprovalKeys, top.approvalKey]
    : state.dismissedApprovalKeys;
  return {
    ...state,
    stack: state.stack.slice(0, -1),
    dismissedApprovalKeys,
  };
}

function updateEvidence(
  state: OverlayState,
  identity: EvidenceUpdateIdentity,
  update: (entry: EvidenceOverlayEntry) => EvidenceOverlayEntry,
): OverlayState {
  if (!sameAuthority(state.authority, identity.authority)) return state;
  const index = state.stack.findIndex(({ id }) => id === identity.entryId);
  const entry = state.stack[index];
  if (entry?.kind !== "evidence"
    || entry.requestId !== identity.requestId
    || entry.handle !== identity.handle
    || !sameAuthority(entry.authority, identity.authority)) {
    return state;
  }
  const stack = [...state.stack];
  stack[index] = update(entry);
  return { ...state, stack };
}

export function overlayReducer(
  state: OverlayState,
  action: OverlayAction,
): OverlayState {
  switch (action.type) {
    case "authority-changed":
      return sameAuthority(state.authority, action.authority)
        ? state
        : { ...state, authority: action.authority, stack: [] };
    case "sync-approval": {
      const approvals = state.stack.filter(
        (entry): entry is ApprovalOverlayEntry => entry.kind === "approval",
      );
      const matching = action.entry
        ? approvals.find(({ approvalKey }) => approvalKey === action.entry?.approvalKey)
        : undefined;
      const dismissedApprovalKeys = approvals.filter((entry) => entry !== matching).reduce<string[]>(
        (keys, entry) => keys.includes(entry.approvalKey) ? keys : [...keys, entry.approvalKey],
        [...state.dismissedApprovalKeys],
      );
      const withoutApprovals = state.stack.filter(({ kind }) => kind !== "approval");
      const next = { ...state, stack: withoutApprovals, dismissedApprovalKeys };
      if (!action.entry || !canOpen(next, action.entry)) return next;
      return { ...next, stack: [...withoutApprovals, matching ?? action.entry] };
    }
    case "open":
      if (action.entry.kind === "approval" && action.reopenApproval) {
        const approvalKey = action.entry.approvalKey;
        const reopened = {
          ...state,
          dismissedApprovalKeys: state.dismissedApprovalKeys.filter(
            (key) => key !== approvalKey,
          ),
        };
        if (!canOpen(reopened, action.entry)) return state;
        return {
          ...reopened,
          stack: [...withoutDuplicate(reopened.stack, action.entry), action.entry],
        };
      }
      if (!canOpen(state, action.entry)) return state;
      return {
        ...state,
        stack: [...withoutDuplicate(state.stack, action.entry), action.entry],
      };
    case "replace-top": {
      if (!canOpen(state, action.entry)) return state;
      const closed = closeTop(state);
      if (!canOpen(closed, action.entry)) return closed;
      return {
        ...closed,
        stack: [...withoutDuplicate(closed.stack, action.entry), action.entry],
      };
    }
    case "remove": {
      const entry = state.stack.find(({ id }) => id === action.entryId);
      if (!entry) return state;
      const dismissedApprovalKeys = action.dismissApproval
        && entry.kind === "approval"
        && !state.dismissedApprovalKeys.includes(entry.approvalKey)
        ? [...state.dismissedApprovalKeys, entry.approvalKey]
        : state.dismissedApprovalKeys;
      return {
        ...state,
        stack: state.stack.filter(({ id }) => id !== action.entryId),
        dismissedApprovalKeys,
      };
    }
    case "close-top":
      return closeTop(state);
    case "evidence-loaded":
      return updateEvidence(state, action, (entry) => ({
        ...entry,
        loading: false,
        document: action.document,
        error: null,
        retryable: true,
      }));
    case "evidence-failed":
      return updateEvidence(state, action, (entry) => ({
        ...entry,
        loading: false,
        document: null,
        error: action.error,
        retryable: action.retryable ?? true,
      }));
  }
}
