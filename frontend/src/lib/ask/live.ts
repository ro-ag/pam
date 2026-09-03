import * as ipc from "../ipc";
import type { Sources } from "./sources";

/**
 * The real `Sources`: the Ask router's reads, wired to the bridge.
 *
 * This is the only file in `lib/ask` that knows `../ipc` exists. The
 * router stays a pure library over the interface, the tests inject fakes,
 * and the screen injects this. Every entry is a read — nothing here runs,
 * approves, or writes, and nothing may be added that does.
 *
 * The ipc types are the daemon's full shapes; `Sources` asks for less.
 * Where the two differ it is always ipc being *wider* (extra fields, a
 * narrower `state` union), so the adapters stay one line and `Sources`
 * never grows a field an answer does not read.
 */
export function liveSources(): Sources {
  return {
    daemonStatus: () => ipc.daemonStatus(),
    approvalsPending: () => ipc.approvalsPending(),
    // `Sources` takes `state` as a plain string — the router's own
    // vocabulary — while the bridge wants `RequestStateName`. The daemon
    // is the authority on unknown states, so the value passes through.
    activityList: (filters) =>
      ipc.activityList(filters as Parameters<typeof ipc.activityList>[0]),
    modelsStatus: () => ipc.modelsStatus(),
    retentionGet: () => ipc.retentionGet(),
    serviceStatus: () => ipc.serviceStatus(),
    evidenceStats: (sinceTs) => ipc.evidenceStats(sinceTs),
    flowsList: () => ipc.flowsList(),
    auditRequest: (id) => ipc.auditRequest(id),
    modelsTry: (prompt, maxTokens) => ipc.modelsTry(prompt, maxTokens),
  };
}
