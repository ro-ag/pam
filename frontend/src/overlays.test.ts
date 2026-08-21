import { describe, expect, it } from "vitest";

import type { EvidenceDataDto } from "./domain";
import {
  activeOverlay,
  createOverlayState,
  loadingEvidenceEntry,
  overlayLayer,
  overlayReducer,
  overlayStateForAuthority,
  type ApprovalOverlayEntry,
  type OverlayAuthority,
  type OverlayEntry,
} from "./overlays";

const authorityA: OverlayAuthority = {
  projectHandle: "project-a",
  generation: "generation-a",
};
const authorityB: OverlayAuthority = {
  projectHandle: "project-b",
  generation: "generation-b",
};

function queue(id = "queue", authority = authorityA): OverlayEntry {
  return { id, kind: "queue", authority };
}

function approval(
  approvalKey = "approval-a",
  authority = authorityA,
): ApprovalOverlayEntry {
  return { id: `approval:${approvalKey}`, kind: "approval", approvalKey, authority };
}

function evidenceDocument(handle: string): EvidenceDataDto {
  return {
    handle,
    digest: "sha256:evidence",
    sizeBytes: 24,
    mediaType: "text/plain",
    body: "bounded evidence",
    truncated: false,
    truth: "Observed output",
  };
}

describe("overlay reducer", () => {
  it("orders overlays and restores the previous active entry when the top closes", () => {
    let state = createOverlayState(authorityA);
    state = overlayReducer(state, { type: "open", entry: queue() });
    state = overlayReducer(state, {
      type: "open",
      entry: loadingEvidenceEntry({
        id: "evidence",
        authority: authorityA,
        handle: "evidence-a",
        requestId: 1,
      }),
    });

    expect(state.stack.map(({ id }) => id)).toEqual(["queue", "evidence"]);
    expect(activeOverlay(state)?.id).toBe("evidence");
    expect(overlayLayer(state, "queue")).toBe("underlay");
    expect(overlayLayer(state, "evidence")).toBe("active");

    state = overlayReducer(state, { type: "close-top" });
    expect(activeOverlay(state)?.id).toBe("queue");
    expect(overlayLayer(state, "queue")).toBe("active");
    state = overlayReducer(state, { type: "close-top" });
    expect(activeOverlay(state)).toBeNull();
  });

  it("retains a project menu as an underlay while a modal is active", () => {
    let state = createOverlayState(authorityA);
    state = overlayReducer(state, {
      type: "open",
      entry: { id: "project", kind: "project", authority: authorityA },
    });
    state = overlayReducer(state, { type: "open", entry: approval() });

    expect(overlayLayer(state, "project")).toBe("underlay");
    expect(activeOverlay(state)?.kind).toBe("approval");
    state = overlayReducer(state, { type: "close-top" });
    expect(activeOverlay(state)?.kind).toBe("project");
  });

  it("dismisses a closed approval for the session and refuses to reopen it", () => {
    let state = createOverlayState(authorityA);
    const first = approval();
    state = overlayReducer(state, { type: "open", entry: first });
    state = overlayReducer(state, { type: "close-top" });

    expect(state.dismissedApprovalKeys).toEqual([first.approvalKey]);
    const dismissed = overlayReducer(state, { type: "open", entry: first });
    expect(dismissed).toBe(state);

    const next = approval("approval-b");
    state = overlayReducer(state, { type: "open", entry: next });
    expect(activeOverlay(state)).toEqual(next);
  });

  it("replaces the top overlay for a command transition without disturbing underlays", () => {
    const command: OverlayEntry = {
      id: "command",
      kind: "command",
      authority: authorityA,
    };
    let state = createOverlayState(authorityA);
    state = overlayReducer(state, { type: "open", entry: queue("base") });
    state = overlayReducer(state, { type: "open", entry: queue("transient") });
    state = overlayReducer(state, { type: "replace-top", entry: command });

    expect(state.stack).toEqual([queue("base"), command]);
    expect(activeOverlay(state)).toEqual(command);
  });

  it("clears overlays on authority change and ignores stale opens", () => {
    let state = createOverlayState(authorityA);
    state = overlayReducer(state, { type: "open", entry: queue() });
    state = overlayReducer(state, {
      type: "authority-changed",
      authority: authorityB,
    });

    expect(state.authority).toEqual(authorityB);
    expect(state.stack).toEqual([]);
    const stale = overlayReducer(state, { type: "open", entry: approval("old", authorityA) });
    expect(stale).toBe(state);
    state = overlayReducer(state, { type: "open", entry: queue("new", authorityB) });
    expect(activeOverlay(state)?.id).toBe("new");
  });

  it("derives an empty render stack before a changed authority effect commits", () => {
    let state = createOverlayState(authorityA);
    state = overlayReducer(state, { type: "open", entry: queue() });

    const effective = overlayStateForAuthority(state, authorityB);
    expect(effective.authority).toEqual(authorityB);
    expect(effective.stack).toEqual([]);
    expect(state.stack).toHaveLength(1);
    expect(overlayStateForAuthority(state, authorityA)).toBe(state);
  });

  it("accepts evidence results only for the matching entry, request, handle, and authority", () => {
    let state = createOverlayState(authorityA);
    state = overlayReducer(state, {
      type: "open",
      entry: loadingEvidenceEntry({
        id: "evidence",
        authority: authorityA,
        handle: "evidence-a",
        requestId: 2,
      }),
    });
    const document = evidenceDocument("evidence-a");
    const matching = {
      entryId: "evidence",
      requestId: 2,
      handle: "evidence-a",
      authority: authorityA,
    };

    for (const stale of [
      { ...matching, entryId: "obsolete-entry" },
      { ...matching, requestId: 1 },
      { ...matching, handle: "evidence-b" },
      { ...matching, authority: authorityB },
    ]) {
      expect(overlayReducer(state, {
        type: "evidence-loaded",
        document,
        ...stale,
      })).toBe(state);
    }

    state = overlayReducer(state, {
      type: "evidence-loaded",
      document,
      ...matching,
    });
    expect(activeOverlay(state)).toMatchObject({
      kind: "evidence",
      loading: false,
      document,
      error: null,
    });

    state = overlayReducer(state, {
      type: "open",
      entry: loadingEvidenceEntry({
        id: "evidence",
        authority: authorityA,
        handle: "evidence-a",
        requestId: 3,
      }),
    });
    expect(overlayReducer(state, {
      type: "evidence-failed",
      error: "old request failed",
      ...matching,
    })).toBe(state);
    state = overlayReducer(state, {
      type: "evidence-failed",
      error: "bounded read failed",
      ...matching,
      requestId: 3,
    });
    expect(activeOverlay(state)).toMatchObject({
      loading: false,
      document: null,
      error: "bounded read failed",
    });

    state = overlayReducer(state, { type: "close-top" });
    expect(overlayReducer(state, {
      type: "evidence-loaded",
      document,
      ...matching,
      requestId: 3,
    })).toBe(state);
  });
});
